import assert from "node:assert/strict";
import { access, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { build } from "esbuild";

const packageRoot = new URL("..", import.meta.url).pathname;
const bundle = await build({
  bundle: true,
  stdin: {
    contents: 'export * from "./src/runtime/state-repository.ts";',
    resolveDir: packageRoot,
  },
  format: "esm",
  platform: "node",
  write: false,
});
const runtime = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`,
);
const DIGEST = `sha256:${"a".repeat(64)}`;

function createInput(targetPath) {
  return {
    policyDigest: DIGEST,
    runId: randomUUID(),
    snapshot: { schemaVersion: 1, resolved: { scan: { target: targetPath } } },
    snapshotDigest: DIGEST,
    targetPath,
    targetRevision: "revision-a",
    workflow: {
      id: "full-repository",
      version: 1,
      phases: [
        { id: "preflight", type: "preflight", version: 1, dependencies: [] },
        { id: "discovery", type: "discovery", version: 1, dependencies: ["preflight"], roleId: "discoverer" },
      ],
    },
  };
}

test("workbench adapter creates, claims, queries, and lists ordered events", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "pi-security-runtime-state-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const target = path.join(root, "target");
  await mkdir(target);
  const repository = new runtime.WorkbenchRuntimeStateRepository(
    runtime.createWorkbenchRuntimeExecutor({ packageRoot, stateDir: path.join(root, "state") }),
  );
  const created = await repository.createRun(createInput(target));
  assert.equal(created.status, "created");
  assert.deepEqual(created.phases.map((phase) => phase.state), ["ready", "pending"]);

  const running = await repository.claimRun({
    claimToken: "synthetic-claim",
    controllerId: "controller-a",
    expectedVersion: created.version,
    runId: created.id,
  });
  assert.equal(running.status, "running");
  assert.equal(running.controllerId, "controller-a");
  const events = await repository.listEvents(created.id, 1);
  assert.deepEqual(events.map((event) => [event.sequence, event.kind]), [[2, "run.started"]]);
  assert.deepEqual(await repository.getRun(created.id), running);
});

test("workbench adapter converts process and response failures to stable errors", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "pi-security-runtime-errors-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const repository = new runtime.WorkbenchRuntimeStateRepository(
    runtime.createWorkbenchRuntimeExecutor({ packageRoot, stateDir: path.join(root, "state") }),
  );
  await assert.rejects(
    repository.getRun(randomUUID()),
    (error) => error instanceof runtime.RuntimeStateRepositoryError
      && error.command === "runtime-get-run"
      && /Unknown workflow run/u.test(error.message),
  );

  const invalid = new runtime.WorkbenchRuntimeStateRepository(async () => ({ invalid: true }));
  await assert.rejects(
    invalid.createRun(createInput(root)),
    (error) => error instanceof runtime.RuntimeStateRepositoryError
      && error.command === "parse-run"
      && /invalid workflow run/u.test(error.message),
  );

  await assert.rejects(
    invalid.recordEvent({
      claimToken: "synthetic-claim",
      controllerId: "controller-a",
      expectedVersion: 1,
      runId: randomUUID(),
      event: { category: "domain", kind: "run.progressed", source: "runtime" },
    }),
    (error) => error instanceof runtime.RuntimeStateRepositoryError
      && error.command === "parse-record-event"
      && /invalid workflow event mutation/u.test(error.message),
  );
  await assert.rejects(
    invalid.listEvents(randomUUID()),
    (error) => error instanceof runtime.RuntimeStateRepositoryError
      && error.command === "parse-list-events"
      && /invalid workflow events/u.test(error.message),
  );
});

test("executor preserves JSON diagnostics when helper stderr is empty", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "pi-security-runtime-json-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "scripts"));
  await writeFile(path.join(root, "scripts", "workbench_db.py"), "print('not-json')\n");
  const execute = runtime.createWorkbenchRuntimeExecutor({ packageRoot: root });
  await assert.rejects(
    execute("runtime-get-run"),
    (error) => error instanceof runtime.RuntimeStateRepositoryError
      && error.command === "runtime-get-run"
      && /JSON/u.test(error.message),
  );
});

test("executor rejects unserializable payloads without launching a helper", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "pi-security-runtime-input-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "scripts"));
  const marker = path.join(root, "spawned");
  await writeFile(
    path.join(root, "scripts", "workbench_db.py"),
    "from pathlib import Path\nPath('spawned').write_text('started')\nprint('{}')\n",
  );
  const execute = runtime.createWorkbenchRuntimeExecutor({ packageRoot: root });
  const payload = {};
  payload.self = payload;
  await assert.rejects(
    execute("runtime-record-event", payload),
    (error) => error instanceof runtime.RuntimeStateRepositoryError
      && error.command === "runtime-record-event"
      && /circular/iu.test(error.message),
  );
  await assert.rejects(access(marker), { code: "ENOENT" });
});
