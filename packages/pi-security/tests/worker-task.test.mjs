// The security.worker task on a real Harness with pi-ai's faux provider: role configuration with an exact tool list,
// admission of the recorded result, failure without one, the resolved-agent check (D7), and resuming after the
// process closes mid-request without a second conversation or submission.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { build } from "esbuild";

const packageRoot = resolve(import.meta.dirname, "..");
const outfile = join(packageRoot, "node_modules", ".cache", "pi-security-tests", "worker-task.mjs");
await build({
  bundle: true,
  stdin: {
    contents: [
      'export * from "./src/durable/worker.ts";',
      'export * from "./src/durable/scan-tools.ts";',
      'export * from "./src/durable/scan-documents.ts";',
      'export * from "./src/durable/harness.ts";',
      'export * from "./src/durable/run-directory.ts";',
      'export { ConfinedRoot } from "./src/target/confined-root.ts";',
      'export { createRegistry, defineExtension } from "@earendil-works/pi-durable";',
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

const CANDIDATE = { cwe_ids: ["CWE-78"], locations: [{ path: "src/app.py", start_line: 1, role: "sink" }], summary: "Shell command.", evidence: "os.system(x)" };
const ROLE = { id: "discoverer", report: "discover", model: { provider: "faux", modelId: "faux-1" }, instructions: "Find candidates." };

function workspace(t) {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "pi-security-worker-")));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  mkdirSync(join(base, "target", "src"), { recursive: true });
  writeFileSync(join(base, "target", "src", "app.py"), "os.system(x)\n");
  return { base, paths: d.runPaths(join(base, "state"), d.newRunId()) };
}

/** Open the run with the worker task installed; `responses` script the faux model. */
async function open(base, paths, responses, wrapAgent = (agent) => agent) {
  const tools = d.createScanTools({ confined: d.ConfinedRoot.open(join(base, "target")) });
  const holder = {};
  const worker = d.createWorkerTask({
    tools,
    resolveAgent: async (id, context) => wrapAgent(await (await holder.run.harness.conversation(id, context)).agent(context)),
  });
  const models = d.createModels();
  const faux = d.fauxProvider();
  models.setProvider(faux.provider);
  faux.setResponses(responses);
  const registry = d.createRegistry();
  registry.install(tools.extension);
  registry.install(d.defineExtension({ name: "pi-security-tasks", tasks: [worker] }));
  holder.run = await d.openRun(paths, { models, registry, settings: { extensions: [] } });
  return { run: holder.run, worker, tools };
}

async function startWorker(run, worker, input) {
  const root = await run.harness.root(d.RUN_CONTEXT);
  return root.commit((tx) => tx.createTask(worker, input, { ownership: { kind: "conversation" } }), d.RUN_CONTEXT);
}

const report = () => d.fauxAssistantMessage([d.fauxToolCall("report_candidates", { candidates: [CANDIDATE] })], { stopReason: "toolUse" });

test("a worker configures its role exactly and completes with its admitted result", async (t) => {
  const { base, paths } = workspace(t);
  const { run, worker, tools } = await open(base, paths, [report]);
  t.after(() => run.close());
  const id = await startWorker(run, worker, { role: { ...ROLE, thinking: "low" }, packet: "PACKET src" });
  const settled = await run.harness.waitForTask(id, d.RUN_CONTEXT);
  assert.equal(settled.state.outcome.status, "completed", JSON.stringify(settled.state.outcome));
  const result = settled.state.outcome.result;
  assert.deepEqual(result.payload, { candidates: [CANDIDATE] });
  assert.equal(result.role, "discoverer");
  const agent = await (await run.harness.conversation(result.conversationId, d.RUN_CONTEXT)).agent(d.RUN_CONTEXT);
  assert.deepEqual(agent.tools.map((tool) => tool.name), tools.toolsFor("discover").map((tool) => tool.name));
  assert.equal(agent.thinkingLevel, "low");
  assert.equal(agent.instructions, "Find candidates.");
});

test("a worker whose model never reports fails without a result", async (t) => {
  const { base, paths } = workspace(t);
  const { run, worker } = await open(base, paths, [() => d.fauxAssistantMessage([d.fauxText("Nothing to report.")])]);
  t.after(() => run.close());
  const id = await startWorker(run, worker, { role: ROLE, packet: "PACKET src" });
  const outcome = (await run.harness.waitForTask(id, d.RUN_CONTEXT)).state.outcome;
  assert.equal(outcome.status, "failed");
  assert.match(outcome.error.message, /without a discover result/);
});

test("a result is not admitted from a conversation whose resolved agent drifted", async (t) => {
  const { base, paths } = workspace(t);
  const extra = { name: "bash" };
  const { run, worker } = await open(base, paths, [report], (agent) => ({ ...agent, tools: [...agent.tools, extra] }));
  t.after(() => run.close());
  const id = await startWorker(run, worker, { role: ROLE, packet: "PACKET src" });
  const outcome = (await run.harness.waitForTask(id, d.RUN_CONTEXT)).state.outcome;
  assert.equal(outcome.status, "failed");
  assert.match(outcome.error.message, /offers \[.*bash\] instead of/);
});

test("agentDrift reports every way a resolved agent can differ from its role", () => {
  const tool = (name) => ({ name });
  const expected = ["list_files", "report_candidates"];
  const agent = { model: { provider: "faux", modelId: "faux-1" }, tools: expected.map(tool), callable: expected.map(tool), deferred: [] };
  assert.equal(d.agentDrift(agent, ROLE, expected), undefined);
  assert.match(d.agentDrift({ ...agent, tools: [tool("report_candidates"), tool("list_files")] }, ROLE, expected), /offers/);
  assert.match(d.agentDrift({ ...agent, tools: [tool("list_files")] }, ROLE, expected), /offers/);
  assert.match(d.agentDrift({ ...agent, callable: [...agent.callable, tool("write")] }, ROLE, expected), /can call unexpected tools: write/);
  assert.match(d.agentDrift({ ...agent, deferred: [tool("tool_search")] }, ROLE, expected), /deferred tools: tool_search/);
  assert.match(d.agentDrift({ ...agent, model: { provider: "faux", modelId: "other" } }, ROLE, expected), /faux\/other instead of faux\/faux-1/);
  assert.match(d.agentDrift({ ...agent, model: undefined }, ROLE, expected), /instead of faux\/faux-1/);
});

test("a worker interrupted mid-request resumes its conversation and submission after reopening", async (t) => {
  const { base, paths } = workspace(t);
  let reached;
  const blocked = new Promise((resolveReached) => (reached = resolveReached));
  const first = await open(base, paths, [
    async (_request, options) => {
      reached();
      // Never answers; closing the Harness aborts the request.
      await new Promise((resolveAbort) => options?.signal?.addEventListener("abort", resolveAbort, { once: true }));
      throw new Error("aborted");
    },
  ]);
  const id = await startWorker(first.run, first.worker, { role: ROLE, packet: "PACKET src" });
  first.run.harness.resume();
  await blocked;
  await first.run.close();

  const second = await open(base, paths, [report]);
  t.after(() => second.run.close());
  second.run.harness.resume();
  const settled = await second.run.harness.waitForTask(id, d.RUN_CONTEXT);
  assert.equal(settled.state.outcome.status, "completed", JSON.stringify(settled.state.outcome));
  const root = await second.run.harness.root(d.RUN_CONTEXT);
  const owned = await root.commit(async (tx) => (await tx.scanConversations({ ownerTaskId: id }, 10)).items, d.RUN_CONTEXT);
  assert.deepEqual(owned.map((conversation) => conversation.id), [settled.state.outcome.result.conversationId], "one worker conversation across the restart");
});
