import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
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

function digest(value) {
  const serialized = JSON.stringify(value, (_key, entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return entry;
    return Object.fromEntries(Object.entries(entry).sort(([left], [right]) => left.localeCompare(right)));
  });
  return `sha256:${createHash("sha256").update(serialized).digest("hex")}`;
}

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
    reporting: {
      coverage: { completeness: "complete", surfaces: [], explicitExclusions: [], deferred: [] },
      findings: [],
    },
    "threat-model": { threatModel: { summary: "Synthetic repository trust boundaries." } },
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
    threatModel: { summary: "Synthetic repository trust boundaries." },
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

test("phase settlement refreshes the durable run version after executor activity", async (t) => {
  const ownership = { claimToken: "claim-settlement-refresh", controllerId: "controller-settlement-refresh" };
  let repository;
  let activityRecorded = false;
  const { lifecycle, repository: runtimeRepository, target } = await fixture(t, async (context) => {
    if (context.phase.id === "preflight") {
      const current = await repository.getRun(context.runId);
      await repository.recordEvent({
        ...ownership,
        event: {
          category: "activity",
          kind: "fixture.executor_activity",
          phaseId: context.phase.id,
          source: "test",
        },
        expectedVersion: current.version,
        runId: context.runId,
      });
      activityRecorded = true;
    }
    return delivery(context);
  });
  repository = runtimeRepository;

  const completed = await lifecycle.start({ ...ownership, config: config(target) });
  assert.equal(activityRecorded, true);
  assert.equal(completed.status, "completed");
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

test("cancellation after durable phase start does not launch the executor", async (t) => {
  let releaseStart;
  let durableStart;
  const durableStarted = new Promise((resolve) => { durableStart = resolve; });
  const releaseDurableStart = new Promise((resolve) => { releaseStart = resolve; });
  let cancellationStarted;
  const canceling = new Promise((resolve) => { cancellationStarted = resolve; });
  let executorCalls = 0;
  const { repository, target } = await fixture(t);
  const transition = repository.transition.bind(repository);
  repository.transition = async (input) => {
    const transitioned = await transition(input);
    if (input.event.kind === "phase.started") {
      durableStart();
      await releaseDurableStart;
    }
    return transitioned;
  };
  const lifecycle = new runtime.CanonicalRunLifecycle({
    abortActiveAttempts: async () => { cancellationStarted(); },
    executors: executors(async (context) => {
      executorCalls += 1;
      return delivery(context);
    }),
    repository,
  });
  const ownership = { claimToken: "claim-cancel-before-launch", controllerId: "controller-cancel-before-launch" };
  const claimed = await lifecycle.createAndClaim({ ...ownership, config: config(target) });
  const execution = lifecycle.execute(claimed, ownership);
  await durableStarted;
  const cancellation = lifecycle.cancel(claimed.id, ownership);
  await canceling;
  releaseStart();
  const canceled = await cancellation;

  assert.equal((await execution).id, canceled.id);
  assert.equal(canceled.status, "canceled");
  assert.equal(canceled.phases.find((phase) => phase.id === "preflight").state, "canceled");
  assert.equal(executorCalls, 0);
});

test("active interruption aborts attempts and settles without converting pending work to cancellation", async (t) => {
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
  assert.equal(abortCalls, 1);
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
    phase: {
      expectedVersion: preflight.version,
      id: "preflight",
      inputDigest: digest({
        inputs: {},
        phaseType: "preflight",
        policyDigest: run.policyDigest,
        targetPath: run.targetPath,
        targetRevision: run.targetRevision,
      }),
      state: "running",
    },
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
      outputDigest: digest({ reviewItemsTotal: 2 }),
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

test("resume normalizes persisted running phases before scheduling them", async (t) => {
  let preflightCalls = 0;
  const { lifecycle, repository, target } = await fixture(t, async (context) => {
    if (context.phase.id === "preflight") preflightCalls += 1;
    return delivery(context);
  });
  const ownership = { claimToken: "claim-resume-running", controllerId: "controller-resume-running" };
  let run = await lifecycle.createAndClaim({ ...ownership, config: config(target) });
  const preflight = run.phases.find((phase) => phase.id === "preflight");
  run = await repository.transition({
    ...ownership,
    event: { category: "domain", kind: "phase.started", phaseId: "preflight", source: "runtime" },
    expectedVersion: run.version,
    phase: { expectedVersion: preflight.version, id: "preflight", inputDigest: DIGEST, state: "running" },
    runId: run.id,
  });
  const interrupted = await lifecycle.interrupt(run.id, ownership, "synthetic process loss");
  assert.equal(interrupted.phases.find((phase) => phase.id === "preflight").state, "running");

  const resumed = await lifecycle.resume({ ...ownership, config: config(target), runId: interrupted.id });
  assert.equal(resumed.status, "completed");
  assert.equal(preflightCalls, 1);
  assert.equal(resumed.phases.find((phase) => phase.id === "preflight").state, "completed");
  const events = await repository.listEvents(resumed.id);
  assert.equal(
    events.filter((event) => event.kind === "phase.interrupted" && event.phaseId === "preflight").length,
    1,
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

test("resume registers cancellation control before recovery persistence", async (t) => {
  let releaseRecovery;
  let recoveredPhase;
  const recoveryStarted = new Promise((resolve) => { recoveredPhase = resolve; });
  const recoveryReleased = new Promise((resolve) => { releaseRecovery = resolve; });
  let executorCalls = 0;
  const { repository, target } = await fixture(t);
  const lifecycle = new runtime.CanonicalRunLifecycle({
    executors: executors(async (context) => {
      executorCalls += 1;
      return delivery(context);
    }),
    repository,
  });
  const ownership = { claimToken: "claim-resume-control", controllerId: "controller-resume-control" };
  let run = await lifecycle.createAndClaim({ ...ownership, config: config(target) });
  const preflight = run.phases.find((phase) => phase.id === "preflight");
  run = await repository.transition({
    ...ownership,
    event: { category: "domain", kind: "phase.started", phaseId: "preflight", source: "runtime" },
    expectedVersion: run.version,
    phase: { expectedVersion: preflight.version, id: "preflight", inputDigest: DIGEST, state: "running" },
    runId: run.id,
  });
  const interrupted = await lifecycle.interrupt(run.id, ownership, "synthetic process loss");
  const transition = repository.transition.bind(repository);
  repository.transition = async (input) => {
    const transitioned = await transition(input);
    if (input.event.kind === "phase.interrupted") {
      recoveredPhase();
      await recoveryReleased;
    }
    return transitioned;
  };

  const resumption = lifecycle.resume({ ...ownership, config: config(target), runId: interrupted.id });
  await recoveryStarted;
  const cancellation = lifecycle.cancel(interrupted.id, ownership);
  releaseRecovery();
  const canceled = await cancellation;

  assert.equal((await resumption).id, canceled.id);
  assert.equal(canceled.status, "canceled");
  assert.equal(executorCalls, 0);
});

test("inactive interruption verifies its claim before aborting and refreshes after abort activity", async (t) => {
  const ownership = { claimToken: "claim-inactive-interrupt", controllerId: "controller-inactive-interrupt" };
  let abortCalls = 0;
  let repository;
  const { target, repository: runtimeRepository } = await fixture(t);
  const lifecycle = new runtime.CanonicalRunLifecycle({
    abortActiveAttempts: async (runId) => {
      abortCalls += 1;
      const current = await repository.getRun(runId);
      assert.equal(current.status, "running");
      await repository.recordEvent({
        ...ownership,
        event: { category: "activity", kind: "fixture.abort_activity", source: "test" },
        expectedVersion: current.version,
        runId,
      });
    },
    executors: executors(),
    repository: runtimeRepository,
  });
  repository = runtimeRepository;
  const run = await lifecycle.createAndClaim({ ...ownership, config: config(target) });

  await assert.rejects(lifecycle.interrupt(
    run.id,
    { ...ownership, claimToken: "incorrect-claim" },
    "synthetic process loss",
  ));
  assert.equal(abortCalls, 0);
  assert.equal((await repository.getRun(run.id)).status, "running");

  const interrupted = await lifecycle.interrupt(run.id, ownership, "synthetic process loss");
  assert.equal(abortCalls, 1);
  assert.equal(interrupted.status, "interrupted");
});

test("terminal outcome is recomputed after the final durable refresh", async (t) => {
  const ownership = { claimToken: "claim-terminal-refresh", controllerId: "controller-terminal-refresh" };
  let resolveAbortStarted;
  const abortStarted = new Promise((resolve) => { resolveAbortStarted = resolve; });
  let cancellation;
  let completedRefreshes = 0;
  let cancellationRequested = false;
  const { repository, target } = await fixture(t);
  const getRun = repository.getRun.bind(repository);
  let lifecycle;
  repository.getRun = async (runId) => {
    const current = await getRun(runId);
    if (current.phases.every((phase) => phase.state === "completed" || phase.state === "reused")) {
      completedRefreshes += 1;
      if (!cancellationRequested && completedRefreshes === 2) {
        cancellationRequested = true;
        cancellation = lifecycle.cancel(runId, ownership);
        await abortStarted;
      }
    }
    return current;
  };
  lifecycle = new runtime.CanonicalRunLifecycle({
    abortActiveAttempts: async () => { resolveAbortStarted(); },
    executors: executors(),
    repository,
  });

  const terminal = await lifecycle.start({ ...ownership, config: config(target) });
  const canceled = await cancellation;
  assert.equal(cancellationRequested, true);
  assert.equal(terminal.status, "canceled");
  assert.equal(canceled.status, "canceled");
  assert.equal(terminal.progress.coverageConclusion, "inconclusive");
});

test("active controls reject a different claim without stopping the owner", async (t) => {
  let release;
  let started;
  const waiting = new Promise((resolve) => { release = resolve; });
  const launched = new Promise((resolve) => { started = resolve; });
  let aborted = false;
  const { lifecycle, repository, target } = await fixture(t, async (context) => {
    if (context.phase.id === "preflight") {
      context.signal.addEventListener("abort", () => { aborted = true; }, { once: true });
      started();
      await waiting;
    }
    return delivery(context);
  });
  const ownership = { claimToken: "active-claim", controllerId: "active-controller" };
  const run = await lifecycle.createAndClaim({ ...ownership, config: config(target) });
  const execution = lifecycle.execute(run, ownership);
  await launched;
  const wrong = { ...ownership, claimToken: "wrong-claim" };
  try {
    await assert.rejects(lifecycle.cancel(run.id, wrong), /authority/u);
    await assert.rejects(lifecycle.interrupt(run.id, wrong, "synthetic stop"), /authority/u);
    assert.equal(aborted, false);
    assert.equal((await repository.getRun(run.id)).status, "running");
  } finally {
    release();
  }
  assert.equal((await execution).status, "completed");
});

test("cancellation wait rejects when failure persistence is unavailable", async (t) => {
  let started;
  const launched = new Promise((resolve) => { started = resolve; });
  const { lifecycle, repository, target } = await fixture(t, async (context) => {
    started();
    await new Promise((resolve) => context.signal.addEventListener("abort", resolve, { once: true }));
    return delivery(context);
  });
  const ownership = { claimToken: "failure-claim", controllerId: "failure-controller" };
  const run = await lifecycle.createAndClaim({ ...ownership, config: config(target) });
  const execution = lifecycle.execute(run, ownership);
  await launched;
  repository.transition = async () => { throw new Error("synthetic persistence unavailable"); };
  const executionRejected = assert.rejects(execution, /synthetic persistence unavailable/u);
  await assert.rejects(lifecycle.cancel(run.id, ownership), /synthetic persistence unavailable/u);
  await executionRejected;
});

test("retry rejects incompatible policy and tampered reusable output before creating a run", async (t) => {
  const { lifecycle, repository, target } = await fixture(t, async (context) => {
    if (context.phase.id === "discovery") throw new Error("synthetic failure");
    return delivery(context);
  });
  const ownership = { claimToken: "reuse-claim", controllerId: "reuse-controller" };
  const source = await lifecycle.start({ ...ownership, config: config(target) });
  const getRun = repository.getRun.bind(repository);
  let altered = structuredClone(source);
  let created = false;
  repository.getRun = async (id) => id === source.id ? altered : getRun(id);
  repository.createRun = async () => { created = true; throw new Error("unexpected creation"); };
  altered.policyDigest = DIGEST;
  await assert.rejects(lifecycle.retry({ ...ownership, sourceRunId: source.id }), (error) => error.code === "AUTHORITY_MISMATCH");
  altered = structuredClone(source);
  altered.phases.find((phase) => phase.id === "preflight").output = { reviewItemsTotal: 999 };
  await assert.rejects(lifecycle.retry({
    ...ownership,
    sourceRunId: source.id,
    reusePhaseIds: ["preflight"],
  }), /immutable output provenance/u);
  assert.equal(created, false);
  assert.deepEqual(await getRun(source.id), source);
});

test("late cancellation waits for abort settlement before terminal persistence", async (t) => {
  const ownership = { claimToken: "late-claim", controllerId: "late-controller" };
  const { repository, target } = await fixture(t);
  const getRun = repository.getRun.bind(repository);
  const transition = repository.transition.bind(repository);
  let lifecycle;
  let cancellation;
  let refreshes = 0;
  let releaseAbort;
  let abortStarted;
  const aborting = new Promise((resolve) => { abortStarted = resolve; });
  const released = new Promise((resolve) => { releaseAbort = resolve; });
  let abortSettled = false;
  repository.getRun = async (id) => {
    const current = await getRun(id);
    if (current.phases.every((phase) => phase.state === "completed")) {
      refreshes += 1;
      if (refreshes === 2) {
        cancellation = lifecycle.cancel(id, ownership);
        await aborting;
      }
    }
    return current;
  };
  repository.transition = async (input) => {
    if (input.status === "canceled") assert.equal(abortSettled, true);
    return transition(input);
  };
  lifecycle = new runtime.CanonicalRunLifecycle({
    abortActiveAttempts: async () => {
      abortStarted();
      await released;
      abortSettled = true;
    },
    executors: executors(),
    repository,
  });
  const run = await lifecycle.createAndClaim({ ...ownership, config: config(target) });
  const execution = lifecycle.execute(run, ownership);
  await aborting;
  try {
    assert.equal((await getRun(run.id)).status, "running");
  } finally {
    releaseAbort();
  }
  assert.equal((await execution).status, "canceled");
  assert.equal((await cancellation).status, "canceled");
});

test("the first stop outcome wins while active attempts settle", async (t) => {
  let started;
  let abortStarted;
  let releaseAbort;
  const launched = new Promise((resolve) => { started = resolve; });
  const aborting = new Promise((resolve) => { abortStarted = resolve; });
  const released = new Promise((resolve) => { releaseAbort = resolve; });
  const { repository, target } = await fixture(t);
  const lifecycle = new runtime.CanonicalRunLifecycle({
    abortActiveAttempts: async () => { abortStarted(); await released; },
    executors: executors(async (context) => {
      started();
      await new Promise((resolve) => context.signal.addEventListener("abort", resolve, { once: true }));
      return delivery(context);
    }),
    repository,
  });
  const ownership = { claimToken: "stop-claim", controllerId: "stop-controller" };
  const run = await lifecycle.createAndClaim({ ...ownership, config: config(target) });
  const execution = lifecycle.execute(run, ownership);
  await launched;
  const interruption = lifecycle.interrupt(run.id, ownership, "synthetic interruption");
  await aborting;
  const cancellation = lifecycle.cancel(run.id, ownership);
  releaseAbort();
  const terminal = await execution;
  assert.equal(terminal.status, "interrupted");
  assert.equal((await interruption).status, "interrupted");
  assert.equal((await cancellation).status, "interrupted");
  assert.equal(terminal.phases.find((phase) => phase.id === "preflight").state, "interrupted");
});

test("resume validates semantic snapshot identity without pinning provenance or credential source", async (t) => {
  const { lifecycle, target } = await fixture(t);
  const ownership = { claimToken: "semantic-claim", controllerId: "semantic-controller" };
  const original = config(target);
  original.provenance = { "roles.default.model": "explicit" };
  original.roles.default.credential = { kind: "env", env: "SYNTHETIC_TOKEN" };
  const run = await lifecycle.createAndClaim({ ...ownership, config: original });
  await lifecycle.interrupt(run.id, ownership, "synthetic interruption");
  const fresh = config(target);
  fresh.provenance = { "roles.default.model": "cli" };
  fresh.roles.default.credential = { kind: "profile", profile: "synthetic-profile" };
  const resumed = await lifecycle.resume({ ...ownership, config: fresh, runId: run.id });
  assert.equal(resumed.status, "completed");
});
