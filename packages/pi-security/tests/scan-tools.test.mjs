// Scan worker tools on a real pi-durable Harness with pi-ai's faux provider: a worker conversation configured with
// the discover role's exact tools calls every source tool (escapes included), sends one invalid and one valid report,
// and the valid one lands in security.result/<conversationId> and ends the run.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { build } from "esbuild";

const packageRoot = resolve(import.meta.dirname, "..");
const outfile = join(packageRoot, "node_modules", ".cache", "pi-security-tests", "scan-tools.mjs");
await build({
  bundle: true,
  stdin: {
    contents: [
      'export * from "./src/durable/scan-tools.ts";',
      'export * from "./src/durable/scan-documents.ts";',
      'export * from "./src/durable/harness.ts";',
      'export * from "./src/durable/run-directory.ts";',
      'export { ConfinedRoot } from "./src/target/confined-root.ts";',
      'export { configure, createRegistry } from "@earendil-works/pi-durable";',
      'export { createModels } from "@earendil-works/pi-ai/models";',
      'export { fauxProvider, fauxAssistantMessage, fauxText, fauxToolCall } from "@earendil-works/pi-ai/providers/faux";',
    ].join("\n"),
    resolveDir: packageRoot,
  },
  format: "esm",
  loader: { ".json": "json" },
  outfile,
  packages: "external",
  platform: "node",
});
const d = await import(outfile);

function sandbox(t) {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "pi-security-tools-")));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const root = join(base, "target");
  mkdirSync(join(root, "src"), { recursive: true });
  mkdirSync(join(root, ".git"), { recursive: true });
  mkdirSync(join(base, "outside"));
  writeFileSync(join(base, "outside", "secret.txt"), "SECRET\n");
  writeFileSync(join(root, "src", "app.py"), "import os\r\nos.system(APP_INPUT)\r\nprint('done')\n");
  writeFileSync(join(root, "src", "blob.bin"), Buffer.from([0x41, 0x50, 0x50, 0x00, 0xff]));
  writeFileSync(join(root, ".git", "HEAD"), "ref: refs/heads/main\n");
  symlinkSync(join(base, "outside", "secret.txt"), join(root, "src", "secret-link.txt"));
  return { base, root };
}

test("role schemas drop workbench identity fields and keep the payload", () => {
  const reduction = d.roleSchema("deep-reducer.schema.json", "reductionInput", ["scanId", "handoffClaimToken", "complete"]);
  assert.deepEqual(Object.keys(reduction.properties).sort(), ["coverage", "findings", "scope", "threatModel"]);
  assert.deepEqual(reduction.required.sort(), ["coverage", "findings"]);
  assert.equal(JSON.stringify(reduction).includes("$ref"), false, "fully dereferenced");
  const standard = d.ROLE_REPORTS.reduce.schema();
  assert.deepEqual(standard.required, ["findings", "rejected"]);
  assert.equal(standard.properties.findings.items.properties.ruleId.pattern, "^[a-z0-9][a-z0-9._/-]*$");
  assert.deepEqual(d.ROLE_REPORTS.threat_model.schema().properties.surfaces.items.required, ["id", "label", "paths"]);
  for (const role of Object.keys(d.ROLE_REPORTS)) {
    const schema = d.ROLE_REPORTS[role].schema();
    assert.equal(schema.properties.scanId, undefined, role);
    assert.equal(JSON.stringify(schema).includes("$ref"), false, role);
  }
});

test("a discover worker uses the source tools and records one schema-valid result", async (t) => {
  const { base, root } = sandbox(t);
  const tools = d.createScanTools({ confined: d.ConfinedRoot.open(root) });
  const models = d.createModels();
  const faux = d.fauxProvider();
  models.setProvider(faux.provider);
  const seen = [];
  const toolResults = (request) => request.messages.filter((message) => message.role === "toolResult").map((message) => ({
    name: message.toolName,
    isError: message.isError === true,
    text: message.content.map((part) => part.text ?? "").join(""),
  }));
  const candidate = {
    cwe_ids: ["CWE-78"],
    locations: [{ path: "src/app.py", start_line: 2, role: "sink" }],
    summary: "Shell command built from input.",
    evidence: "os.system(APP_INPUT)",
  };
  faux.setResponses([
    () =>
      d.fauxAssistantMessage(
        [
          d.fauxToolCall("list_files", {}),
          d.fauxToolCall("read_source", { path: "src/app.py", startLine: 2, endLine: 3 }),
          d.fauxToolCall("read_source", { path: "../outside/secret.txt" }),
          d.fauxToolCall("read_source", { path: join(base, "outside", "secret.txt") }),
          d.fauxToolCall("read_source", { path: "src/secret-link.txt" }),
          d.fauxToolCall("read_source", { path: "src/blob.bin" }),
          d.fauxToolCall("search_source", { query: "app_input" }),
          d.fauxToolCall("git_metadata", {}),
          d.fauxToolCall("get_context", {}),
          d.fauxToolCall("read", { path: "/etc/passwd" }),
        ],
        { stopReason: "toolUse" },
      ),
    (request) => {
      seen.push(toolResults(request));
      return d.fauxAssistantMessage([d.fauxToolCall("report_candidates", { candidates: [{ summary: "missing fields" }] })], { stopReason: "toolUse" });
    },
    (request) => {
      seen.push(toolResults(request));
      return d.fauxAssistantMessage([d.fauxToolCall("report_candidates", { candidates: [candidate] })], { stopReason: "toolUse" });
    },
    (request) => {
      throw new Error("no model request may follow a terminating report");
    },
  ]);

  const registry = d.createRegistry();
  registry.install(tools.extension);
  const run = await d.openRun(d.runPaths(join(base, "state"), d.newRunId()), { models, registry, settings: { extensions: [] } });
  t.after(() => run.close());
  const root_ = await run.harness.root(d.RUN_CONTEXT);
  const conversationId = await root_.commit(async (tx) => {
    Object.assign(await tx.doc(d.TargetDoc), { kind: "git_revision", revision: "a".repeat(40) });
    Object.assign(await tx.doc(d.ScanContextDoc), { scanId: "scan_test", mode: "repository" });
    const created = await tx.createConversation({ ownership: { kind: "conversation", conversationId: root_.id } });
    await d.configure(tx, created.id, {
      model: { provider: "faux", modelId: "faux-1" },
      extensions: [tools.extension],
      tools: tools.toolsFor("discover"),
      instructions: "Discover candidates.",
    });
    return created.id;
  }, d.RUN_CONTEXT);
  const conversation = await run.harness.conversation(conversationId, d.RUN_CONTEXT);
  const submission = await conversation.submit({ type: "input", content: "PACKET src", requestId: "worker:test" }, d.RUN_CONTEXT);
  const settled = await submission.wait(d.RUN_CONTEXT);
  assert.equal(settled.status, "done", JSON.stringify(settled));

  const [first, second] = seen;
  const byName = (name) => first.filter((result) => result.name === name);
  assert.deepEqual(JSON.parse(byName("list_files")[0].text), { files: ["src/app.py", "src/blob.bin"], total: 2 });
  const [read, parent, absolute, link, binary] = byName("read_source");
  assert.deepEqual(JSON.parse(read.text), { path: "src/app.py", startLine: 2, endLine: 3, totalLines: 3, text: "os.system(APP_INPUT)\nprint('done')", truncated: false });
  for (const refused of [parent, absolute, link, binary]) assert.equal(refused.isError, true, refused.text);
  assert.match(link.text, /symbolic link/);
  assert.match(binary.text, /not UTF-8 source text/);
  assert.equal(first.some((result) => result.text.includes("SECRET")), false, "no outside content reached the model");
  assert.deepEqual(JSON.parse(byName("search_source")[0].text), {
    query: "app_input",
    matches: [{ path: "src/app.py", line: 2, text: "os.system(APP_INPUT)" }],
    truncated: false,
    skippedNonText: 1,
  });
  assert.deepEqual(JSON.parse(byName("git_metadata")[0].text), { kind: "git_revision", revision: "a".repeat(40) });
  assert.deepEqual(JSON.parse(byName("get_context")[0].text), { scanId: "scan_test", mode: "repository" });
  assert.equal(byName("read")[0].isError, true, "the built-in read tool is not installed");

  const rejected = second.at(-1);
  assert.equal(rejected.name, "report_candidates");
  assert.equal(rejected.isError, true);

  assert.deepEqual(await run.harness.snapshot(d.ResultFamily, d.resultKey(conversationId), d.RUN_CONTEXT), { role: "discover", payload: { candidates: [candidate] } });
});

test("validateRoleResult applies standard JSON Schema semantics to admitted results", () => {
  const candidate = { cwe_ids: ["CWE-78"], locations: [{ path: "src/app.py", start_line: 2, role: "sink" }], summary: "Shell command.", evidence: "os.system(x)" };
  assert.deepEqual(d.validateRoleResult("discover", { candidates: [candidate] }), { candidates: [candidate] });
  const bad = [
    { candidates: [{ ...candidate, evidence: "   " }] },
    { candidates: [{ ...candidate, summary: undefined }] },
    { candidates: [{ ...candidate, extra: true }] },
    { candidates: [{ ...candidate, locations: [] }] },
    { candidates: "none" },
    {},
  ];
  for (const payload of bad) assert.throws(() => d.validateRoleResult("discover", JSON.parse(JSON.stringify(payload))), undefined, JSON.stringify(payload));
  assert.throws(() => d.validateRoleResult("threat_model", { content: "", scanId: "x" }));
  const model = { content: "Model of the service.", surfaces: [{ id: "http-api", label: "HTTP API", paths: ["src"] }] };
  assert.deepEqual(d.validateRoleResult("threat_model", structuredClone(model)), model);
  for (const surfaces of [[], [{ ...model.surfaces[0], id: "HTTP API" }], [{ ...model.surfaces[0], paths: ["../src"] }], [{ ...model.surfaces[0], paths: [] }]]) {
    assert.throws(() => d.validateRoleResult("threat_model", { ...model, surfaces }), undefined, JSON.stringify(surfaces));
  }
});
