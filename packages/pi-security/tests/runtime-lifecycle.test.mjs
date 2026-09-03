import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { build } from "esbuild";

const packageRoot = new URL("..", import.meta.url).pathname;
const bundle = await build({
  bundle: true,
  stdin: {
    contents: [
      'export * from "./src/runtime/lifecycle.ts";',
      'export * from "./src/runtime/state-repository.ts";',
    ].join("\n"),
    resolveDir: packageRoot,
  },
  format: "esm",
  platform: "node",
  write: false,
});
const runtime = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`,
);
const DIGEST = `sha256:${"f".repeat(64)}`;

function config(target, model = "fixture-model") {
  return {
    execution: { maxParallel: 2 },
    provenance: {},
    roles: { default: { maxAttempts: 2, model, provider: "fixture", thinking: "medium" } },
    scan: { target, workflow: "full-repository" },
  };
}

function outputFor(context) {
  const outputs = {
    "attack-path": { attackPaths: [] },
    discovery: { candidates: [] },
    preflight: { reviewItemsTotal: 2 },
    publication: {
      artifacts: {
        coverage: "coverage.json",
        findings: "findings.json",
        manifest: "scan-manifest.json",
        report: "report.md",
        sarif: "exports/results.sarif",
      },
    },
    reduction: { findings: [] },
    reporting: { coverage: { surfaces: [] }, findings: [], threatModel: { surfaces: [] } },
    "threat-model": { threatModel: { surfaces: [] } },
    validation: { validations: [] },
  };
  return outputs[context.phase.type];
}

function delivery(context, output = outputFor(context)) {
  return {
    attemptId: `fixture:${context.phase.id}`,
    output,
    phaseId: context.phase.id,
    runId: context.runId,
    schemaVersion: 1,
  };
}

function executors(run = async (context) => delivery(context)) {
  return Object.fromEntries(
    ["preflight", "threat-model", "discovery", "reduction", "validation", "attack-path", "reporting", "publication"]
      .map((type) => [type, run]),
  );
}

async function fixture(t, run) {
  const root = await mkdtemp(path.join(tmpdir(), "pi-security-lifecycle-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const target = path.join(root, "target");
  await mkdir(target);
  const repository = new runtime.WorkbenchRuntimeStateRepository(
    runtime.createWorkbenchRuntimeExecutor({ packageRoot, stateDir: path.join(root, "state") }),
  );
  const lifecycle = new runtime.CanonicalRunLifecycle({ executors: executors(run), repository });
  return { lifecycle, repository, root, target };
}

test("creation validates target before agents, persists the snapshot, and completes with honest coverage", async (t) => {
  let agentCalls = 0;
  const { lifecycle, repository, root, target } = await fixture(t, async (context) => {
    agentCalls += 1;
    return delivery(context);
  });
  await assert.rejects(
    lifecycle.start({
      claimToken: "claim-invalid",
      config: config(path.join(root, "missing")),
      controllerId: "controller-invalid",
    }),
  );
  assert.equal(agentCalls, 0);

  const completed = await lifecycle.start({
    claimToken: "claim-complete",
    config: config(target),
    controllerId: "controller-complete",
    targetRevision: "fixture-revision",
  });
  assert.equal(completed.status, "completed");
  assert.equal(completed.progress.coverageConclusion, "complete");
  assert.equal(completed.controllerId, null);
  assert.equal(completed.phases.every((phase) => phase.state === "completed"), true);
  assert.deepEqual((await repository.getRun(completed.id)).snapshot, completed.snapshot);
});

test("failed runs preserve admitted outputs and cannot claim complete coverage", async (t) => {
  const { lifecycle, repository, target } = await fixture(t, async (context) => {
    if (context.phase.type === "discovery") throw new Error("synthetic discovery failure");
    return delivery(context);
  });
  const failed = await lifecycle.start({
    claimToken: "claim-failed",
    config: config(target),
    controllerId: "controller-failed",
  });
  assert.equal(failed.status, "failed");
  assert.equal(failed.progress.coverageConclusion, "inconclusive");
  assert.deepEqual(failed.phases.find((phase) => phase.id === "threat-model").output, {
    threatModel: { surfaces: [] },
  });
  await assert.rejects(
    repository.transition({
      claimToken: "claim-failed",
      controllerId: "controller-failed",
      event: { category: "domain", kind: "run.completed", source: "runtime" },
      expectedVersion: failed.version,
      progress: { coverageConclusion: "complete" },
      runId: failed.id,
      status: "completed",
    }),
  );
});

test("cancellation aborts active work, waits for settlement, freezes admission, and rejects late output", async (t) => {
  let releaseStart;
  const started = new Promise((resolve) => { releaseStart = resolve; });
  let abortCalls = 0;
  const { repository, target } = await fixture(t);
  const lifecycle = new runtime.CanonicalRunLifecycle({
    abortActiveAttempts: async () => { abortCalls += 1; },
    executors: executors(async (context) => {
      if (context.phase.type !== "threat-model") return delivery(context);
      releaseStart();
      await new Promise((resolve) => context.signal.addEventListener("abort", resolve, { once: true }));
      return delivery(context);
    }),
    repository,
  });
  const ownership = { claimToken: "claim-cancel", controllerId: "controller-cancel" };
  const claimed = await lifecycle.createAndClaim({ ...ownership, config: config(target) });
  const execution = lifecycle.execute(claimed, ownership);
  await started;
  const canceled = await lifecycle.cancel(claimed.id, ownership);
  assert.equal((await execution).id, canceled.id);
  assert.equal(abortCalls, 1);
  assert.equal(canceled.status, "canceled");
  assert.equal(canceled.outputAdmissionFrozen, true);
  assert.equal(canceled.progress.coverageConclusion, "inconclusive");
  const threat = canceled.phases.find((phase) => phase.id === "threat-model");
  assert.equal(threat.output, null);
  await assert.rejects(
    repository.transition({
      ...ownership,
      event: { category: "domain", kind: "phase.completed", phaseId: "threat-model", source: "runtime" },
      expectedVersion: canceled.version,
      phase: {
        expectedVersion: threat.version,
        id: "threat-model",
        output: { threatModel: {} },
        outputDigest: DIGEST,
        state: "completed",
      },
      runId: canceled.id,
    }),
    /ownership does not match|not active|no longer admits/u,
  );
});

test("active interruption settles durably without converting pending work to cancellation", async (t) => {
  let releaseStart;
  const started = new Promise((resolve) => { releaseStart = resolve; });
  const { repository, target } = await fixture(t);
  const lifecycle = new runtime.CanonicalRunLifecycle({
    executors: executors(async (context) => {
      if (context.phase.type !== "threat-model") return delivery(context);
      releaseStart();
      await new Promise((resolve) => context.signal.addEventListener("abort", resolve, { once: true }));
      return delivery(context);
    }),
    repository,
  });
  const ownership = { claimToken: "claim-interrupt", controllerId: "controller-interrupt" };
  const claimed = await lifecycle.createAndClaim({ ...ownership, config: config(target) });
  const execution = lifecycle.execute(claimed, ownership);
  await started;
  const interrupted = await lifecycle.interrupt(claimed.id, ownership, "synthetic process loss");
  assert.equal((await execution).id, interrupted.id);
  assert.equal(interrupted.status, "interrupted");
  assert.equal(interrupted.progress.coverageConclusion, "inconclusive");
  assert.equal(interrupted.phases.find((phase) => phase.id === "threat-model").state, "interrupted");
  assert.equal(interrupted.phases.find((phase) => phase.id === "discovery").state, "pending");
});

test("explicit resume validates fresh execution identity and skips compatible completed phases", async (t) => {
  let preflightCalls = 0;
  const { lifecycle, repository, target } = await fixture(t, async (context) => {
    if (context.phase.type === "preflight") preflightCalls += 1;
    return delivery(context);
  });
  const ownership = { claimToken: "claim-resume", controllerId: "controller-resume" };
  let run = await lifecycle.createAndClaim({ ...ownership, config: config(target), targetRevision: "revision-a" });
  const preflight = run.phases.find((phase) => phase.id === "preflight");
  run = await repository.transition({
    ...ownership,
    event: { category: "domain", kind: "phase.started", phaseId: "preflight", source: "runtime" },
    expectedVersion: run.version,
    phase: { expectedVersion: preflight.version, id: "preflight", inputDigest: DIGEST, state: "running" },
    runId: run.id,
  });
  run = await repository.transition({
    ...ownership,
    event: { category: "domain", kind: "phase.completed", phaseId: "preflight", source: "runtime" },
    expectedVersion: run.version,
    phase: {
      expectedVersion: run.phases.find((phase) => phase.id === "preflight").version,
      id: "preflight",
      output: { reviewItemsTotal: 2 },
      outputDigest: DIGEST,
      state: "completed",
    },
    runId: run.id,
  });
  const interrupted = await lifecycle.interrupt(run.id, ownership, "synthetic process loss");
  await assert.rejects(
    lifecycle.resume({
      ...ownership,
      config: config(target, "different-model"),
      runId: interrupted.id,
      targetRevision: "revision-a",
    }),
    (error) => error.code === "AUTHORITY_MISMATCH",
  );
  assert.equal((await repository.getRun(run.id)).status, "interrupted");

  const resumed = await lifecycle.resume({
    ...ownership,
    config: config(target),
    runId: interrupted.id,
    targetRevision: "revision-a",
  });
  assert.equal(resumed.status, "completed");
  assert.equal(preflightCalls, 0);
  await assert.rejects(
    lifecycle.resume({ ...ownership, config: config(target), runId: resumed.id, targetRevision: "revision-a" }),
    /cannot resume/u,
  );
});

test("failed retry creates a linked run and records validated immutable reuse", async (t) => {
  const { lifecycle, repository, target } = await fixture(t, async (context) => {
    if (context.phase.type === "discovery") throw new Error("synthetic discovery failure");
    return delivery(context);
  });
  const ownership = { claimToken: "claim-source", controllerId: "controller-source" };
  const source = await lifecycle.start({ ...ownership, config: config(target) });
  assert.equal(source.status, "failed");
  const retried = await lifecycle.retry({
    claimToken: "claim-retry",
    controllerId: "controller-retry",
    reusePhaseIds: ["preflight", "threat-model"],
    sourceRunId: source.id,
  });
  assert.notEqual(retried.id, source.id);
  assert.equal(retried.parentRunId, source.id);
  assert.deepEqual(retried.phases.slice(0, 2).map((phase) => phase.state), ["reused", "reused"]);
  assert.equal((await repository.getRun(source.id)).status, "failed");
  const events = await repository.listEvents(retried.id);
  assert.deepEqual(
    events.filter((event) => event.kind === "phase.output_reused").map((event) => event.payload.sourceRunId),
    [source.id, source.id],
  );
});
