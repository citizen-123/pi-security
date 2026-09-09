import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import test from "node:test";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  stdin: {
    contents: [
      'export { handoffClaimTokenSchema, recoveryHandoffClaimTokenSchema } from "./src/lifecycle/handoff-tools.ts";',
      'export { lifecycleToolJsonSchema, parseLifecycleToolInput } from "./src/lifecycle/catalog.ts";'
    ].join("\n"),
    loader: "ts",
    resolveDir: fileURLToPath(new URL("..", import.meta.url))
  },
  format: "esm",
  platform: "node",
  write: false
});
const {
  handoffClaimTokenSchema,
  lifecycleToolJsonSchema,
  parseLifecycleToolInput,
  recoveryHandoffClaimTokenSchema
} = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);

const lowercaseToken = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
const uppercaseToken = lowercaseToken.toUpperCase();
const lowercaseRecoveryToken = `recovery_${lowercaseToken}`;
const uppercaseRecoveryToken = `recovery_${uppercaseToken}`;

test("handoff token schemas normalize UUID casing before lifecycle command invocation", () => {
  assert.equal(handoffClaimTokenSchema.parse(uppercaseToken), lowercaseToken);
  assert.equal(
    recoveryHandoffClaimTokenSchema.parse(uppercaseRecoveryToken),
    lowercaseRecoveryToken
  );
  assert.equal(
    parseLifecycleToolInput(handoffClaimTokenSchema, uppercaseRecoveryToken),
    lowercaseRecoveryToken
  );

  const jsonSchema = lifecycleToolJsonSchema(handoffClaimTokenSchema);
  assert.match(JSON.stringify(jsonSchema), /recovery_\[0-9a-fA-F\]/u);
});

test("prompt-driven starts bind artifact authority to their owning catalog session", async (t) => {
  const packageRoot = fileURLToPath(new URL("..", import.meta.url));
  const root = await realpath(await mkdtemp(join(tmpdir(), "pi-security-prompt-handoff-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  const previousEnvironment = {
    PI_SECURITY_SCAN_ROOT: process.env.PI_SECURITY_SCAN_ROOT,
    PI_SECURITY_STATE_DIR: process.env.PI_SECURITY_STATE_DIR,
  };
  process.env.PI_SECURITY_SCAN_ROOT = join(root, "scans");
  process.env.PI_SECURITY_STATE_DIR = join(root, "state");
  t.after(() => {
    for (const [key, value] of Object.entries(previousEnvironment)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });
  const targetPath = join(root, "target");
  await mkdir(targetPath);
  await writeFile(join(targetPath, "handler.ts"), "export const query = 'fixed';\n");
  await writeFile(join(targetPath, "unchanged.ts"), "export const trusted = true;\n");
  const execute = promisify(execFile);
  await execute("git", ["init", "-q"], { cwd: targetPath });
  await execute("git", ["add", "."], { cwd: targetPath });
  await execute("git", [
    "-c", "user.name=Pi Security Fixture",
    "-c", "user.email=fixture@example.invalid",
    "commit", "-qm", "base",
  ], { cwd: targetPath });
  const { stdout } = await execute("git", ["rev-parse", "HEAD"], { cwd: targetPath });
  const revision = stdout.trim();
  await writeFile(join(targetPath, "handler.ts"), "export const query = (input) => `SELECT ${input}`;\n");

  const lifecycleBundle = await build({
    bundle: true,
    define: {
      __dirname: JSON.stringify(packageRoot),
    },
    format: "esm",
    platform: "node",
    loader: { ".md": "text" },
    plugins: [{
      name: "prompt-handoff-fixture",
      setup(build_) {
        build_.onResolve(
          { filter: /^@earendil-works\/pi-coding-agent$/ },
          () => ({ path: "pi-coding-agent", namespace: "prompt-handoff-fixture" }),
        );
        build_.onLoad(
          { filter: /^pi-coding-agent$/, namespace: "prompt-handoff-fixture" },
          () => ({
            contents: [
              "export const createAgentSession = () => { throw new Error('unused test stub'); };",
              "export class DefaultResourceLoader {}",
              "export const getAgentDir = () => '';",
              "export class SessionManager {}",
            ].join("\n"),
            loader: "ts",
          }),
        );
        build_.onResolve(
          { filter: /^(test-workbench-response|\.\/src\/execution-boundary\.js)$/ },
          () => ({ path: "workbench-response", namespace: "prompt-handoff-fixture" }),
        );
        build_.onLoad(
          { filter: /^workbench-response$/, namespace: "prompt-handoff-fixture" },
          () => ({
            contents: [
              `export * from ${JSON.stringify(join(packageRoot, "src/execution-boundary.ts"))};`,
              `import { executeTrustedWorkbench as execute } from ${JSON.stringify(join(packageRoot, "src/execution-boundary.ts"))};`,
              "let transform;",
              "export function setWorkbenchResponseTransform(value) { transform = value; }",
              "export function executeTrustedWorkbench(context, operation) {",
              "  const execution = execute(context, operation);",
              "  const result = execution.then((value) => transform",
              "    ? { ...value, stdout: JSON.stringify(transform(JSON.parse(value.stdout))) }",
              "    : value);",
              "  result.child = execution.child;",
              "  return result;",
              "}",
            ].join("\n"),
            loader: "ts",
            resolveDir: packageRoot,
          }),
        );
      },
    }],
    stdin: {
      contents: [
        'export { createPiSecurityLifecycleCatalog } from "./lifecycle.ts";',
        'export { setWorkbenchResponseTransform } from "test-workbench-response";',
      ].join("\n"),
      loader: "ts",
      resolveDir: packageRoot,
    },
    write: false,
  });
  const lifecyclePath = join(root, "lifecycle.mjs");
  await writeFile(lifecyclePath, lifecycleBundle.outputFiles[0].contents);
  const { createPiSecurityLifecycleCatalog, setWorkbenchResponseTransform } =
    await import(pathToFileURL(lifecyclePath).href);
  const owner = "prompt-diff-owner";
  const input = {
    mode: "diff",
    targetPath,
    scope: ".",
    diffTarget: { kind: "working_tree", baseRevision: revision, headRevision: revision },
  };
  const candidate = {
    cwe_ids: ["CWE-89"],
    locations: [{ path: "handler.ts", start_line: 1, role: "sink" }],
    summary: "Input reaches an interpolated query",
    evidence: "The changed handler places input directly in SELECT.",
  };
  const catalogs = [];
  t.after(() => {
    for (const catalog of catalogs) catalog.dispose();
  });
  function catalog() {
    const value = createPiSecurityLifecycleCatalog();
    catalogs.push(value);
    return value;
  }
  async function invoke(tools, name, parameters, sessionId = owner) {
    const tool = tools.tools.find((entry) => entry.name === name);
    assert.ok(tool, name);
    return tool.handler(
      parseLifecycleToolInput(tool.config.inputSchema, parameters),
      { sessionId },
    );
  }
  async function call(tools, name, parameters, sessionId = owner) {
    const result = await invoke(tools, name, parameters, sessionId);
    assert.equal(result.isError, undefined, result.content?.[0]?.text);
    return result.structuredContent;
  }

  const creator = catalog();
  const createdResult = await invoke(creator, "start_pi_security_prompt_only_scan", input);
  assert.equal(createdResult.isError, undefined, createdResult.content?.[0]?.text);
  const created = createdResult.structuredContent;
  assert.equal(created.startDisposition, "created");
  assert.match(created.scanId, /^[0-9a-f-]{36}$/u);
  assert.match(created.handoffClaimToken, /^[0-9a-f-]{36}$/u);
  assert.equal(created.scan.continuationThreadId, owner);
  assert.equal(JSON.stringify(createdResult.content).includes(created.handoffClaimToken), false);
  const discovery = join(created.scanDir, "artifacts", "02_discovery");
  const inventoryPath = join(discovery, "in_scope_files.txt");
  const candidatesPath = join(discovery, "candidate_ledger.jsonl");

  await t.test("the Diff creator writes the bound review inventory and normalized candidates", async () => {
    assert.deepEqual(await call(creator, "prepare_pi_security_review_items", {
      scanId: created.scanId,
    }), { reviewItemsTotal: 1 });
    assert.equal(await readFile(inventoryPath, "utf8"), "handler.ts\n");
    assert.deepEqual(await call(creator, "record_pi_security_discovery_candidates", {
      scanId: created.scanId,
      candidates: [candidate],
    }), { operation: "replace", candidatesRecorded: 1 });
    const rows = (await call(creator, "list_pi_security_candidates", {
      scanId: created.scanId,
    })).rows;
    assert.equal(rows[0].summary, candidate.summary);
    assert.match(rows[0].candidate_id, /^candidate-[a-f0-9]{16}$/u);
    assert.deepEqual(JSON.parse((await readFile(candidatesPath, "utf8")).trim()), rows[0]);
    await call(creator, "update_pi_security_scan_progress", {
      scanId: created.scanId,
      handoffClaimToken: created.handoffClaimToken,
      phase: "discovery",
    });
  });

  await t.test("only an exact owning-thread rejoin authenticates a fresh catalog", async () => {
    creator.dispose();
    const rejoinedCatalog = catalog();
    await call(rejoinedCatalog, "get_pi_security_scan_context", { scanId: created.scanId });
    await assert.rejects(
      invoke(rejoinedCatalog, "prepare_pi_security_review_items", { scanId: created.scanId }),
      /requires its current continuation claim/u,
    );
    const rejoined = await call(rejoinedCatalog, "start_pi_security_prompt_only_scan", input);
    assert.equal(rejoined.startDisposition, "joined");
    assert.equal(rejoined.scanId, created.scanId);
    assert.equal(rejoined.scanDir, created.scanDir);
    assert.equal(rejoined.handoffClaimToken, created.handoffClaimToken);
    assert.equal(rejoined.scan.progress.phase, "discovery");
    assert.deepEqual(await call(rejoinedCatalog, "prepare_pi_security_review_items", {
      scanId: rejoined.scanId,
    }), { reviewItemsTotal: 1 });
    const resumedCandidate = { ...candidate, evidence: "The owning continuation rechecked the changed handler." };
    await call(rejoinedCatalog, "record_pi_security_discovery_candidates", {
      scanId: rejoined.scanId,
      candidates: [resumedCandidate],
    });
    assert.equal(JSON.parse((await readFile(candidatesPath, "utf8")).trim()).evidence, resumedCandidate.evidence);

    const beforeForeignWrite = await readFile(candidatesPath, "utf8");
    await call(rejoinedCatalog, "get_pi_security_scan_context", {
      scanId: rejoined.scanId,
    }, "foreign-thread");
    await assert.rejects(
      invoke(rejoinedCatalog, "prepare_pi_security_review_items", {
        scanId: rejoined.scanId,
      }, "foreign-thread"),
      /requires its current continuation claim/u,
    );
    await assert.rejects(
      invoke(rejoinedCatalog, "record_pi_security_discovery_candidates", {
        scanId: rejoined.scanId,
        candidates: [],
      }, "foreign-thread"),
      /requires its current continuation claim/u,
    );
    assert.equal(await readFile(candidatesPath, "utf8"), beforeForeignWrite);
  });

  await t.test("prompt Standard starts return a claim usable for their semantic draft and completion", async () => {
    const standardCatalog = catalog();
    const standard = await call(standardCatalog, "start_pi_security_prompt_only_scan", {
      mode: "standard",
      targetPath,
      scope: ".",
    }, "prompt-standard-owner");
    const parameters = {
      scanId: standard.scanId,
      handoffClaimToken: standard.handoffClaimToken,
    };
    const draft = await call(standardCatalog, "record_pi_security_scan_draft", {
      ...parameters,
      findings: [],
      coverage: { completeness: "complete", surfaces: [], explicitExclusions: [], deferred: [] },
    }, "prompt-standard-owner");
    assert.equal(draft.status, "draft_written");
    const completed = await call(standardCatalog, "complete_pi_security_scan", parameters, "prompt-standard-owner");
    assert.equal(completed.scan.progress.status, "complete");
    const manifestPath = join(standard.scanDir, "scan-manifest.json");
    const sealed = await readFile(manifestPath, "utf8");
    await assert.rejects(
      invoke(standardCatalog, "record_pi_security_scan_draft", {
        ...parameters,
        findings: [],
        coverage: { completeness: "complete", surfaces: [], explicitExclusions: [], deferred: [] },
      }, "prompt-standard-owner"),
      /not running/u,
    );
    assert.equal(await readFile(manifestPath, "utf8"), sealed);
  });

  for (const [name, corrupt] of [
    ["missing claim", (reply) => { delete reply.scan.handoffClaimToken; }],
    ["malformed claim", (reply) => { reply.scan.handoffClaimToken = "not-a-uuid"; }],
    ["foreign continuation", (reply) => { reply.scan.continuationThreadId = "foreign-thread"; }],
    ["wrong scan mode", (reply) => { reply.scan.mode = "standard"; }],
    ["undelivered handoff", (reply) => { reply.scan.handoffStatus = "pending"; }],
    ["terminal scan", (reply) => { reply.scan.progress.status = "complete"; }],
    ["mismatched workspace identity", (reply) => { reply.workspace.results.scanId = randomUUID(); }],
    ["invalid scan identity", (reply) => { reply.scan.scanId = reply.workspace.results.scanId = "not-a-uuid"; }],
    ["missing artifact directory", (reply) => { reply.scan.scanDir = ""; }],
    ["invalid disposition", (reply) => { reply.startDisposition = "unowned"; }],
    ["new scan outside preflight", (reply) => { reply.startDisposition = "created"; }],
  ]) {
    await t.test(`a ${name} start reply cannot authorize artifact writes`, async () => {
      const rejectedCatalog = catalog();
      const before = await readFile(candidatesPath, "utf8");
      setWorkbenchResponseTransform((reply) => {
        if (reply.startDisposition) corrupt(reply);
        return reply;
      });
      try {
        const rejected = await invoke(rejectedCatalog, "start_pi_security_prompt_only_scan", input);
        assert.equal(rejected.isError, true);
        assert.equal(rejected.structuredContent, undefined);
      } finally {
        setWorkbenchResponseTransform(undefined);
      }
      await assert.rejects(
        invoke(rejectedCatalog, "record_pi_security_discovery_candidates", {
          scanId: created.scanId,
          candidates: [],
        }),
        /requires its current continuation claim/u,
      );
      assert.equal(await readFile(candidatesPath, "utf8"), before);
    });
  }
});
