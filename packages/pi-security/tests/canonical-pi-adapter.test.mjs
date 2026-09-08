import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { build } from "esbuild";

const packageRoot = fileURLToPath(new URL("..", import.meta.url));
const bundle = await build({
  bundle: true,
  stdin: {
    contents: `export * from "./extensions/canonical-runtime.ts";
      export * from "./src/runtime/state-repository.ts";
      export { exitStatusForRun, renderRunJson } from "./src/cli/operations.ts";
      export { parseCliArgs } from "./src/cli/args.ts";
      export { resolveExecutionConfig } from "./src/config/execution-config.ts";`,
    resolveDir: packageRoot,
  },
  format: "esm",
  platform: "node",
  write: false,
});
const adapter = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`,
);

async function cliFixture(t, source) {
  const root = await mkdtemp(path.join(tmpdir(), "pi-security-pi-cli-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const cliPath = path.join(root, "cli.mjs");
  await writeFile(cliPath, source);
  await writeFile(path.join(root, "runtime.mjs"), bundle.outputFiles[0].contents);
  return { cliPath, root };
}

function startTool(port) {
  const tools = new Map();
  adapter.registerCanonicalRuntimeTools({ registerTool(tool) { tools.set(tool.name, tool); } }, port);
  return tools.get("start_pi_security_canonical_scan");
}

test("Pi start exposes durable outcomes despite the CLI's nonzero outcome exit codes", async (t) => {
  const fixture = await cliFixture(t, `
    import { exitStatusForRun, renderRunJson } from "./runtime.mjs";
    const status = process.env.SYNTHETIC_RUN_STATUS;
    const run = {
      id: "synthetic-run", status, phases: [], targetPath: process.cwd(),
      statusReason: status === "completed" ? null : "Synthetic incomplete coverage",
      progress: { coverageConclusion: status === "completed" ? "complete" : "inconclusive" },
    };
    console.log(renderRunJson({ ...run, status: "running" }));
    console.log(renderRunJson(run));
    process.exitCode = exitStatusForRun(status);
  `);
  for (const status of ["completed", "failed", "interrupted", "canceled"]) {
    await t.test(status, async () => {
      const tool = startTool(adapter.createCanonicalCliPort({
        cliPath: fixture.cliPath,
        cwd: fixture.root,
        environment: { ...process.env, SYNTHETIC_RUN_STATUS: status },
      }));
      const result = await tool.execute("synthetic-call", { targetPath: fixture.root });
      assert.equal(result.details.id, "synthetic-run");
      assert.equal(result.details.status, status);
      assert.equal(result.details.progress.coverageConclusion, status === "completed" ? "complete" : "inconclusive");
      assert.equal(result.details.statusReason, status === "completed" ? null : "Synthetic incomplete coverage");
      assert.deepEqual(JSON.parse(result.content[0].text), result.details);
    });
  }
});

test("Pi start does not disguise process failures as successful run observations", async (t) => {
  for (const scenario of [
    { name: "configuration failure", source: 'console.error("Synthetic configuration error"); process.exitCode = 2;', expected: /Synthetic configuration error/u },
    { name: "crash after progress", source: 'console.log(JSON.stringify({ id: "run", status: "running" })); process.exitCode = 1;', expected: (error) => error.code === 1 },
    { name: "empty success", source: "", expected: /returned no state/u },
    { name: "unrelated JSON", source: 'console.log(JSON.stringify({ error: "Synthetic error" }));', expected: /invalid run state/u },
  ]) {
    await t.test(scenario.name, async (t) => {
      const fixture = await cliFixture(t, scenario.source);
      const port = adapter.createCanonicalCliPort({ cliPath: fixture.cliPath });
      await assert.rejects(port.start({ targetPath: fixture.root }), scenario.expected);
    });
  }
});

test("Pi start preserves cancellation as an abort rather than a run result", async (t) => {
  const fixture = await cliFixture(t, 'console.log(JSON.stringify({ id: "run", status: "canceled" })); process.exitCode = 130;');
  const controller = new AbortController();
  controller.abort();
  const port = adapter.createCanonicalCliPort({ cliPath: fixture.cliPath });
  await assert.rejects(port.start({ targetPath: fixture.root }, controller.signal), { name: "AbortError" });
});

test("Pi resolves relative target and configuration paths in the invoking session", async (t) => {
  const fixture = await cliFixture(t, `
    import { readFile } from "node:fs/promises";
    import { join } from "node:path";
    import { parseCliArgs, resolveExecutionConfig, renderRunJson } from "./runtime.mjs";
    const command = parseCliArgs(process.argv.slice(2));
    const config = await resolveExecutionConfig({
      explicitPath: command.configPath, overrides: command.overrides,
    });
    const source = await readFile(join(config.scan.target, "fixture.txt"), "utf8");
    if (source !== "Authorized synthetic source") throw new Error("Wrong scan target");
    if (process.env.SYNTHETIC_PROVIDER_KEY !== "synthetic-test-credential") throw new Error("Missing credential");
    console.log(renderRunJson({
      id: "synthetic-session-run", status: "completed", phases: [],
      progress: { coverageConclusion: "complete" }, targetPath: config.scan.target,
    }));
  `);
  const sessionDirectory = path.join(fixture.root, "session-repository");
  await mkdir(sessionDirectory);
  await writeFile(path.join(sessionDirectory, "scan.toml"), "[scan]\ntarget = '.'\n");
  await writeFile(path.join(sessionDirectory, "fixture.txt"), "Authorized synthetic source");
  const tool = startTool(adapter.createCanonicalCliPort({
    cliPath: fixture.cliPath,
    cwd: fixture.root,
    environment: {
      ...process.env,
      PI_HOME: path.join(fixture.root, "pi-home"),
      SYNTHETIC_PROVIDER_KEY: "synthetic-test-credential",
    },
  }));
  const result = await tool.execute("synthetic-call", { targetPath: ".", configPath: "scan.toml" },
    undefined, undefined, { cwd: sessionDirectory });
  assert.equal(result.details.status, "completed");
  assert.equal(result.details.targetPath, sessionDirectory);
  assert.doesNotMatch(JSON.stringify(result), /synthetic-test-credential/u);
});

test("Pi inspection reconnects committed state without invoking a CLI or exposing execution authority", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "pi-security-pi-observe-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const target = path.join(root, "target");
  await mkdir(target);
  const environment = { ...process.env, PI_SECURITY_STATE_DIR: path.join(root, "pi-home", "security") };
  const repository = new adapter.WorkbenchRuntimeStateRepository(
    adapter.createWorkbenchRuntimeExecutor({ packageRoot, environment }),
  );
  const digest = `sha256:${"a".repeat(64)}`;
  const created = await repository.createRun({
    runId: randomUUID(),
    policyDigest: digest,
    snapshotDigest: digest,
    snapshot: { schemaVersion: 1, resolved: { scan: { target } } },
    targetPath: target,
    workflow: {
      id: "full-repository",
      version: 1,
      phases: [{ id: "preflight", type: "preflight", version: 1, dependencies: [] }],
    },
  });
  const ownership = { runId: created.id, controllerId: "synthetic-controller", claimToken: "synthetic-claim" };
  const running = await repository.claimRun({ ...ownership, expectedVersion: created.version });
  const failed = await repository.transition({
    ...ownership,
    expectedVersion: running.version,
    status: "failed",
    statusReason: "Synthetic provider unavailable",
    progress: { coverageConclusion: "inconclusive" },
    event: { category: "domain", kind: "run.failed", payload: { reason: "Synthetic provider unavailable" }, source: "runtime" },
  });
  // No such executable exists: observation must not launch a scan or need provider credentials.
  // A relative state directory must resolve against the invocation cwd, not the package directory.
  const port = adapter.createCanonicalCliPort({
    cliPath: path.join(packageRoot, "dist", "synthetic-missing-cli.mjs"),
    cwd: root,
    environment: { ...environment, PI_SECURITY_STATE_DIR: path.join("pi-home", "security") },
  });
  const observed = await port.observe({ runId: failed.id, afterSequence: 2 });
  assert.equal(observed.id, failed.id);
  assert.equal(observed.status, "failed");
  assert.equal(observed.statusReason, "Synthetic provider unavailable");
  assert.equal(observed.progress.coverageConclusion, "inconclusive");
  assert.deepEqual(observed.events.map((event) => [event.sequence, event.kind]), [[3, "run.failed"]]);
  assert.equal("controllerId" in observed, false);
  assert.equal("snapshot" in observed, false);
  assert.equal("claimToken" in observed, false);
  assert.deepEqual((await port.observe({ runId: failed.id, afterSequence: 3 })).events, []);
  for (const stateEnvironment of [
    { ...environment, PI_SECURITY_STATE_DIR: undefined, PI_HOME: "pi-home" },
    { ...environment, HOME: root, USERPROFILE: root, PI_SECURITY_STATE_DIR: "~/pi-home/security" },
  ]) {
    const reconnected = adapter.createCanonicalCliPort({
      cliPath: path.join(packageRoot, "dist", "synthetic-missing-cli.mjs"),
      cwd: root,
      environment: stateEnvironment,
    });
    assert.deepEqual(await reconnected.observe({ runId: failed.id, afterSequence: 2 }), observed);
  }
  assert.deepEqual(await repository.getRun(failed.id), failed);
  assert.equal((await repository.listEvents(failed.id)).length, 3);
  await assert.rejects(port.observe({ runId: failed.id, afterSequence: 1.5 }), /non-negative safe integer/u);
});
