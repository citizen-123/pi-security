import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { build } from "esbuild";

const packageRoot = new URL("..", import.meta.url).pathname;
const fixture = path.join(packageRoot, "tests", "fixtures", "fake-pi-rpc.mjs");
const bundle = await build({
  bundle: true,
  define: { "import.meta.url": JSON.stringify(new URL("../dist/pi-security-cli.mjs", import.meta.url).href) },
  stdin: {
    contents: 'export * from "./src/rpc/jsonl-client.ts"; export * from "./src/rpc/phase-session.ts";',
    resolveDir: packageRoot,
  },
  format: "esm",
  platform: "node",
  write: false,
});
const rpc = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`,
);

function phaseRequest(request) {
  const { instructions, model, provider, thinking } = request.role;
  return {
    ...request,
    input: {
      evidenceReferences: [],
      scanId: randomUUID(),
      role: { instructions, model, provider, thinking },
      ...request.input,
    },
  };
}

function client(mode, options = {}) {
  return new rpc.JsonlRpcClient({
    command: process.execPath,
    args: [fixture],
    cleanupTimeoutMs: options.cleanupTimeoutMs,
    env: { ...process.env, FAKE_RPC_MODE: mode, ...options.env },
    redact: (text) => text.replaceAll("synthetic-canary", "[REDACTED]"),
    requestTimeoutMs: options.requestTimeoutMs,
  });
}

async function settlesWithin(promise, timeoutMs = 100) {
  return await new Promise((resolve, reject) => {
    const timer = setTimeout(() => resolve(false), timeoutMs);
    promise.then(
      () => {
        clearTimeout(timer);
        resolve(true);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

async function waitForCondition(condition, timeoutMs = 2_000) {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() >= deadline) throw new Error("Timed out waiting for fixture condition.");
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
}

test("JSONL client preserves strict LF framing, correlation, CRLF, and stderr isolation", async (t) => {
  for (const mode of ["split", "crlf"]) {
    const transport = client(mode);
    t.after(() => transport.stop().catch(() => undefined));
    await transport.start();
    const response = await transport.request({ type: "get_messages" });
    assert.equal(response.data.messages[0].content, "synthetic\u2028transcript");
    await transport.stop();
  }

  const stderr = client("stderr");
  await stderr.start();
  await stderr.request({ type: "get_state" });
  assert.equal(stderr.getStderr().trim(), "provider rejected [REDACTED]");
  await stderr.stop();
});

test("JSONL client rejects malformed, uncorrelated, exited, and stalled responses and cleans up", async () => {
  for (const mode of ["malformed", "unknown-id"]) {
    const transport = client(mode);
    await transport.start();
    await assert.rejects(
      transport.request({ type: "get_state" }),
      (error) => error instanceof rpc.JsonlRpcError && error.kind === "protocol",
    );
    await transport.stop();
  }

  const exited = client("exit-before-response");
  await exited.start();
  await assert.rejects(
    exited.request({ type: "get_state" }),
    (error) => error instanceof rpc.JsonlRpcError
      && error.kind === "process"
      && /code 7.*synthetic transport exit/u.test(error.message),
  );
  await exited.waitForExit();

  const duplicate = client("duplicate");
  await duplicate.start();
  await duplicate.request({ type: "get_state" });
  await duplicate.waitForExit();
  await assert.rejects(duplicate.request({ type: "get_state" }), /not running/u);

  const delayed = client(undefined, { env: { FAKE_RPC_EXIT_DELAY_MS: "20" } });
  await delayed.start();
  await delayed.request({ type: "exit" });
  await delayed.waitForExit();

  const stubborn = client("ignore-term", { cleanupTimeoutMs: 20 });
  await stubborn.start();
  await stubborn.stop();
  await stubborn.waitForExit();

  const stalled = client("never-response", { cleanupTimeoutMs: 20, requestTimeoutMs: 20 });
  try {
    await stalled.start();
    const result = await Promise.race([
      stalled.request({ type: "get_state" }).then(
        () => ({ kind: "fulfilled" }),
        (error) => ({ error, kind: "rejected" }),
      ),
      new Promise((resolve) => setTimeout(() => resolve({ kind: "unsettled" }), 100)),
    ]);
    assert.equal(result.kind, "rejected");
    assert.equal(result.error instanceof rpc.JsonlRpcError, true);
    assert.equal(result.error.kind, "process");
    assert.match(result.error.message, /timed out/u);
    await stalled.waitForExit();
  } finally {
    await stalled.stop().catch(() => undefined);
  }

  const unavailable = new rpc.JsonlRpcClient({
    command: path.join(packageRoot, "missing-pi-rpc"),
  });
  await assert.rejects(
    unavailable.start(),
    (error) => error instanceof rpc.JsonlRpcError && error.kind === "process",
  );
  assert.equal(await settlesWithin(unavailable.waitForExit()), true);
});

test("RPC rejects mismatched response commands and invalid error envelopes", async (t) => {
  for (const mode of ["wrong-command", "invalid-error"]) {
    const transport = client(mode, { cleanupTimeoutMs: 20 });
    t.after(() => transport.stop());
    await transport.start();
    await assert.rejects(transport.request({ type: "get_state" }), (error) => error.kind === "protocol");
    await transport.waitForExit();
  }
});

test("protocol failure stops a stubborn child and discards subsequent event frames", async (t) => {
  const transport = client("malformed-ignore-term", { cleanupTimeoutMs: 20 });
  t.after(() => transport.stop());
  const events = [];
  transport.onEvent((event) => events.push(event));
  await transport.start();
  await assert.rejects(transport.request({ type: "get_state" }), (error) => error.kind === "protocol");
  await assert.rejects(transport.request({ type: "get_state" }), (error) => error.kind === "process");
  assert.equal(await settlesWithin(transport.waitForExit(), 1_000), true);
  assert.deepEqual(events, []);
});

test("RPC redacts provider and malformed-frame errors before returning them", async (t) => {
  for (const mode of ["secret-error", "secret-json"]) {
    const transport = client(mode, { cleanupTimeoutMs: 20, requestTimeoutMs: 500 });
    t.after(() => transport.stop());
    await transport.start();
    await assert.rejects(transport.request({ type: "get_state" }), (error) => {
      assert.equal(error instanceof rpc.JsonlRpcError, true);
      assert.equal(error.message.includes("synthetic-canary"), false);
      assert.equal(error.kind, mode === "secret-error" ? "request" : "protocol");
      return true;
    });
  }
});

test("RPC drains the final response before classifying process exit", async (t) => {
  const transport = client("exit-final-response");
  t.after(() => transport.stop());
  await transport.start();
  assert.deepEqual((await transport.request({ type: "exit" })).data, { final: true });
  await transport.waitForExit();
});

class FakeRepository {
  constructor(runId, targetPath, controllerId, options = {}) {
    this.runId = runId;
    this.targetPath = targetPath;
    this.controllerId = controllerId;
    this.activityDelayMs = options.activityDelayMs ?? 0;
    this.beforeGetAgent = options.beforeGetAgent;
    this.activityRecords = 0;
    this.version = 1;
    this.events = [];
    this.attempt = undefined;
    this.agentAttempts = new Map();
    this.agentPhaseIds = new Map();
    this.attemptOwners = new Map();
    this.attemptsById = new Map();
  }

  async startAttempt(input) {
    const attempt = {
      createdAt: "2026-01-01T00:00:00Z",
      details: input.details ?? {},
      failureCategory: null,
      id: input.attemptId,
      ordinal: input.ordinal,
      piSessionId: null,
      status: "starting",
      updatedAt: "2026-01-01T00:00:00Z",
    };
    this.attempt = attempt;
    this.logicalAgentId = input.logicalAgentId;
    this.phaseId = input.phaseId;
    this.agentAttempts.set(input.logicalAgentId, attempt);
    this.agentPhaseIds.set(input.logicalAgentId, input.phaseId);
    this.attemptOwners.set(input.attemptId, input.logicalAgentId);
    this.attemptsById.set(input.attemptId, attempt);
    return this.mutation("starting", attempt, input.logicalAgentId);
  }

  async updateAttempt(input) {
    assert.equal(input.expectedVersion, this.version);
    const attempt = this.attemptsById.get(input.attemptId);
    const logicalAgentId = this.attemptOwners.get(input.attemptId);
    assert.ok(attempt);
    assert.ok(logicalAgentId);
    const updated = {
      ...attempt,
      details: input.details ?? {},
      piSessionId: input.piSessionId ?? null,
      status: input.status,
    };
    this.attempt = updated;
    this.agentAttempts.set(logicalAgentId, updated);
    this.attemptsById.set(input.attemptId, updated);
    this.events.push(input.event);
    return this.mutation(input.status, updated, logicalAgentId);
  }

  async recordEvent(input) {
    assert.equal(input.expectedVersion, this.version);
    if (input.event.source === "pi-rpc") {
      this.activityRecords += 1;
      if (this.activityDelayMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, this.activityDelayMs));
      }
    }
    this.events.push(input.event);
    this.version += 1;
    return { runId: this.runId, sequence: this.events.length, version: this.version };
  }

  async getRun() {
    return {
      controllerId: this.controllerId,
      id: this.runId,
      outputAdmissionFrozen: false,
      status: "running",
      targetPath: this.targetPath,
      version: this.version,
    };
  }

  async getAgent(_runId, logicalAgentId) {
    if (this.beforeGetAgent) await this.beforeGetAgent(logicalAgentId);
    const attempt = this.agentAttempts.get(logicalAgentId);
    assert.ok(attempt);
    return {
      attempts: [attempt],
      id: logicalAgentId,
      phaseId: this.agentPhaseIds.get(logicalAgentId),
      runId: this.runId,
      status: attempt.status,
    };
  }

  mutation(status, attempt = this.attempt, logicalAgentId = this.logicalAgentId) {
    this.version += 1;
    return {
      attemptId: attempt.id,
      logicalAgentId,
      runId: this.runId,
      sequence: this.events.length,
      status,
      version: this.version,
    };
  }
}

test("phase supervisor applies role and capability settings and mediates controls", async () => {
  const runId = randomUUID();
  const logicalAgentId = randomUUID();
  const attemptId = randomUUID();
  const targetPath = path.resolve(packageRoot);
  const repository = new FakeRepository(runId, targetPath, "controller-a");
  const supervisor = new rpc.PhaseSessionSupervisor({
    command: process.execPath,
    commandArgs: [fixture],
    repository,
  });
  const launched = await supervisor.launch(phaseRequest({
    attemptId,
    claimToken: "claim-a",
    controllerId: "controller-a",
    expectedVersion: 1,
    input: {
      artifactRoot: targetPath,
      authority: { artifactRoot: targetPath, targetPath },
      capabilityProfile: { allowDelegation: false, allowTargetMutation: false, tools: ["read", "grep"] },
      evidenceReferences: [],
      outputContract: { type: "object" },
      phaseId: "discovery",
      requiredInputs: { inventory: "sha256:fixture" },
      roleId: "discoverer",
      runId,
      role: {
        instructions: "Return the required structured result.",
        model: "fixture-model",
        provider: "fixture-provider",
        thinking: "high",
      },
      scanId: randomUUID(),
      target: { path: targetPath, revision: "fixture-revision" },
    },
    logicalAgentId,
    maxAttempts: 2,
    ordinal: 1,
    role: {
      credential: { environmentVariable: "FIXTURE_TOKEN", value: "synthetic-secret" },
      instructions: "Return the required structured result.",
      model: "fixture-model",
      provider: "fixture-provider",
      thinking: "high",
    },
  }));
  assert.equal(launched.piSessionId, "fixture-session");
  await new Promise((resolve) => setTimeout(resolve, 20));

  // A phase transition recorded by the controller must not strand a live session on a cached version.
  await repository.recordEvent({
    expectedVersion: repository.version,
    event: { category: "domain", kind: "phase.progress", source: "runtime" },
  });
  const request = {
    claimToken: "claim-a",
    controllerId: "controller-a",
    expectedVersion: repository.version,
    logicalAgentId,
    runId,
    targetPath,
  };
  const status = await supervisor.control(request, { kind: "status" });
  assert.equal(status.state.credentialPresent, true);
  assert.equal(status.state.argv.join(" ").includes("synthetic-secret"), false);
  assert.equal(repository.events.at(-1).kind, "operator.status");

  const transcript = await supervisor.control(
    { ...request, expectedVersion: repository.version },
    { kind: "transcript" },
  );
  assert.equal(transcript.transcript.messages[0].content, "synthetic\u2028transcript");
  await supervisor.control(
    { ...request, expectedVersion: repository.version },
    { kind: "steer", message: "Use the selected evidence." },
  );
  await supervisor.control(
    { ...request, expectedVersion: repository.version },
    { kind: "follow-up", message: "Return the structured result." },
  );
  const interrupted = await supervisor.control(
    { ...request, expectedVersion: repository.version },
    { kind: "interrupt" },
  );
  assert.equal(interrupted.version, repository.version);
  await assert.rejects(
    supervisor.control({ ...request, expectedVersion: repository.version - 1 }, { kind: "status" }),
    /authority does not match/u,
  );
  await assert.rejects(
    supervisor.control({ ...request, expectedVersion: repository.version, targetPath: path.dirname(targetPath) }, { kind: "interrupt" }),
    /authority does not match/u,
  );
  await supervisor.control({ ...request, expectedVersion: repository.version }, { kind: "stop" });
  assert.deepEqual(
    repository.events
      .filter((event) => event.kind.startsWith("operator."))
      .map((event) => event.kind),
    [
      "operator.status",
      "operator.transcript",
      "operator.steer",
      "operator.follow-up",
      "operator.interrupt",
      "operator.stop",
    ],
  );
  assert.equal(repository.events.at(-1).kind, "agent.attempt_canceled");
});

test("phase stop persists cancellation and clears its binding after an abort timeout", async () => {
  const runId = randomUUID();
  const logicalAgentId = randomUUID();
  const attemptId = randomUUID();
  const targetPath = path.resolve(packageRoot);
  const repository = new FakeRepository(runId, targetPath, "controller-a");
  const supervisor = new rpc.PhaseSessionSupervisor({
    command: process.execPath,
    commandArgs: [fixture, "--abort-never-respond"],
    cleanupTimeoutMs: 20,
    repository,
    requestTimeoutMs: 1_000,
  });
  await supervisor.launch(phaseRequest({
    attemptId,
    claimToken: "claim-a",
    controllerId: "controller-a",
    expectedVersion: 1,
    input: {
      artifactRoot: targetPath,
      authority: { artifactRoot: targetPath, targetPath },
      capabilityProfile: { allowDelegation: false, allowTargetMutation: false, tools: ["read", "grep"] },
      outputContract: { type: "object" },
      phaseId: "discovery",
      requiredInputs: {},
      roleId: "discoverer",
      runId,
      target: { path: targetPath, revision: "fixture-revision" },
    },
    logicalAgentId,
    maxAttempts: 1,
    ordinal: 1,
    role: {
      instructions: "Return the required structured result.",
      model: "fixture-model",
      provider: "fixture-provider",
      thinking: "medium",
    },
  }));
  const request = {
    claimToken: "claim-a",
    controllerId: "controller-a",
    expectedVersion: repository.version,
    logicalAgentId,
    runId,
    targetPath,
  };

  const stopped = await supervisor.control(request, { kind: "stop" });
  assert.equal(stopped.version, repository.version);
  assert.equal(repository.attempt.status, "canceled");
  assert.equal(repository.events.at(-1).kind, "agent.attempt_canceled");
  assert.equal(repository.events.some((event) => event.kind === "agent.process_exited"), false);
  await assert.rejects(
    supervisor.control({ ...request, expectedVersion: repository.version }, { kind: "status" }),
    /no bound RPC session/u,
  );
});

test("phase launch returns while prompt activity continues", async () => {
  const runId = randomUUID();
  const logicalAgentId = randomUUID();
  const attemptId = randomUUID();
  const targetPath = path.resolve(packageRoot);
  const repository = new FakeRepository(runId, targetPath, "controller-a", { activityDelayMs: 10 });
  const supervisor = new rpc.PhaseSessionSupervisor({
    command: process.execPath,
    commandArgs: [fixture, "--prompt-activity-flood", "--continuous-activity-flood"],
    repository,
  });
  const launch = supervisor.launch(phaseRequest({
    attemptId,
    claimToken: "claim-a",
    controllerId: "controller-a",
    expectedVersion: 1,
    input: {
      artifactRoot: targetPath,
      authority: { artifactRoot: targetPath, targetPath },
      capabilityProfile: { allowDelegation: false, allowTargetMutation: false, tools: ["read", "grep"] },
      outputContract: { type: "object" },
      phaseId: "discovery",
      requiredInputs: {},
      roleId: "discoverer",
      runId,
      target: { path: targetPath, revision: "fixture-revision" },
    },
    logicalAgentId,
    maxAttempts: 1,
    ordinal: 1,
    role: {
      instructions: "Return the required structured result.",
      model: "fixture-model",
      provider: "fixture-provider",
      thinking: "medium",
    },
  }));
  let launched;
  try {
    await waitForCondition(() => repository.activityRecords > 0, 2_000);
    assert.equal(await settlesWithin(launch, 2_000), true);
    launched = await launch;
    assert.equal(launched.piSessionId, "fixture-session");
  } finally {
    await supervisor.abortRun(runId);
    await launch.catch(() => undefined);
  }
});

test("phase interrupt queues ahead of later activity instead of starving abort", async () => {
  const runId = randomUUID();
  const logicalAgentId = randomUUID();
  const attemptId = randomUUID();
  const targetPath = path.resolve(packageRoot);
  const abortMarker = path.join(tmpdir(), `pi-security-abort-${randomUUID()}`);
  const repository = new FakeRepository(runId, targetPath, "controller-a", { activityDelayMs: 10 });
  const supervisor = new rpc.PhaseSessionSupervisor({
    command: process.execPath,
    commandArgs: [fixture, `--abort-marker=${abortMarker}`, "--continuous-activity-flood"],
    repository,
  });
  const request = {
    claimToken: "claim-a",
    controllerId: "controller-a",
    logicalAgentId,
    runId,
    targetPath,
  };
  await supervisor.launch(phaseRequest({
    attemptId,
    claimToken: request.claimToken,
    controllerId: request.controllerId,
    expectedVersion: 1,
    input: {
      artifactRoot: targetPath,
      authority: { artifactRoot: targetPath, targetPath },
      capabilityProfile: { allowDelegation: false, allowTargetMutation: false, tools: ["read", "grep"] },
      outputContract: { type: "object" },
      phaseId: "discovery",
      requiredInputs: {},
      roleId: "discoverer",
      runId,
      target: { path: targetPath, revision: "fixture-revision" },
    },
    logicalAgentId,
    maxAttempts: 1,
    ordinal: 1,
    role: {
      instructions: "Return the required structured result.",
      model: "fixture-model",
      provider: "fixture-provider",
      thinking: "medium",
    },
  }));
  let interrupt;
  try {
    await supervisor.control(
      { ...request, expectedVersion: repository.version },
      { kind: "steer", message: "start activity flood" },
    );
    repository.activityRecords = 0;
    await waitForCondition(() => repository.activityRecords > 0);
    interrupt = supervisor.control(
      { ...request, expectedVersion: repository.version },
      { kind: "interrupt" },
    );
    await waitForCondition(() => existsSync(abortMarker));
    await interrupt;

    const status = await supervisor.control(
      { ...request, expectedVersion: repository.version },
      { kind: "status" },
    );
    assert.equal(status.state.aborted, true);
  } finally {
    await supervisor.abortRun(runId);
    if (interrupt) await interrupt.catch(() => undefined);
    await rm(abortMarker, { force: true });
  }
});

test("phase sessions share a run version across logical agents", async () => {
  const runId = randomUUID();
  const agentA = randomUUID();
  const agentB = randomUUID();
  const targetPath = path.resolve(packageRoot);
  const repository = new FakeRepository(runId, targetPath, "controller-a", { activityDelayMs: 10 });
  const supervisor = new rpc.PhaseSessionSupervisor({
    command: process.execPath,
    commandArgs: [fixture],
    repository,
  });
  const agents = [
    { attemptId: randomUUID(), logicalAgentId: agentA, ordinal: 1 },
    { attemptId: randomUUID(), logicalAgentId: agentB, ordinal: 2 },
  ];
  const launched = new Set();
  try {
    for (const agent of agents) {
      await supervisor.launch(phaseRequest({
        attemptId: agent.attemptId,
        claimToken: "claim-a",
        controllerId: "controller-a",
        expectedVersion: repository.version,
        input: {
          artifactRoot: targetPath,
          authority: { artifactRoot: targetPath, targetPath },
          capabilityProfile: { allowDelegation: false, allowTargetMutation: false, tools: ["read", "grep"] },
          outputContract: { type: "object" },
          phaseId: "discovery",
          requiredInputs: {},
          roleId: "discoverer",
          runId,
          target: { path: targetPath, revision: "fixture-revision" },
        },
        logicalAgentId: agent.logicalAgentId,
        maxAttempts: 1,
        ordinal: agent.ordinal,
        role: {
          instructions: "Return the required structured result.",
          model: "fixture-model",
          provider: "fixture-provider",
          thinking: "medium",
        },
      }));
      launched.add(agent.logicalAgentId);
    }

    await supervisor.control({
      claimToken: "claim-a",
      controllerId: "controller-a",
      expectedVersion: repository.version,
      logicalAgentId: agentA,
      runId,
      targetPath,
    }, { kind: "steer", message: "start activity flood" });
    repository.activityRecords = 0;
    await waitForCondition(() => repository.activityRecords > 0);

    const interrupted = await supervisor.control({
      claimToken: "claim-a",
      controllerId: "controller-a",
      expectedVersion: repository.version,
      logicalAgentId: agentB,
      runId,
      targetPath,
    }, { kind: "interrupt" });
    assert.equal(interrupted.version, repository.version);
  } finally {
    for (const logicalAgentId of [agentB, agentA]) {
      if (!launched.has(logicalAgentId)) continue;
      await supervisor.control({
        claimToken: "claim-a",
        controllerId: "controller-a",
        expectedVersion: repository.version,
        logicalAgentId,
        runId,
        targetPath,
      }, { kind: "stop" }).catch(() => undefined);
    }
  }
});

test("phase control rejects authority changed during asynchronous authorization", async () => {
  const runId = randomUUID();
  const agentA = randomUUID();
  const agentB = randomUUID();
  const targetPath = path.resolve(packageRoot);
  let signalLookup;
  const lookupReached = new Promise((resolve) => {
    signalLookup = resolve;
  });
  let releaseLookup;
  const lookupReleased = new Promise((resolve) => {
    releaseLookup = resolve;
  });
  let blockLookup = true;
  const repository = new FakeRepository(runId, targetPath, "controller-a", {
    beforeGetAgent: async (logicalAgentId) => {
      if (!blockLookup || logicalAgentId !== agentA) return;
      blockLookup = false;
      signalLookup();
      await lookupReleased;
    },
  });
  const supervisor = new rpc.PhaseSessionSupervisor({
    command: process.execPath,
    commandArgs: [fixture],
    repository,
  });
  const input = {
    artifactRoot: targetPath,
    authority: { artifactRoot: targetPath, targetPath },
    capabilityProfile: { allowDelegation: false, allowTargetMutation: false, tools: ["read", "grep"] },
    outputContract: { type: "object" },
    phaseId: "discovery",
    requiredInputs: {},
    roleId: "discoverer",
    runId,
    target: { path: targetPath, revision: "fixture-revision" },
  };
  await supervisor.launch(phaseRequest({
    attemptId: randomUUID(),
    claimToken: "claim-a",
    controllerId: "controller-a",
    expectedVersion: 1,
    input,
    logicalAgentId: agentA,
    maxAttempts: 1,
    ordinal: 1,
    role: {
      instructions: "Return the required structured result.",
      model: "fixture-model",
      provider: "fixture-provider",
      thinking: "medium",
    },
  }));
  let staleStatus;
  let secondLaunch;
  let secondLaunched = false;
  try {
    staleStatus = supervisor.control({
      claimToken: "claim-a",
      controllerId: "controller-a",
      expectedVersion: repository.version,
      logicalAgentId: agentA,
      runId,
      targetPath,
    }, { kind: "status" });
    assert.equal(await settlesWithin(lookupReached), true);

    secondLaunch = supervisor.launch(phaseRequest({
      attemptId: randomUUID(),
      claimToken: "claim-a",
      controllerId: "controller-a",
      expectedVersion: repository.version,
      input,
      logicalAgentId: agentB,
      maxAttempts: 1,
      ordinal: 2,
      role: {
        instructions: "Return the required structured result.",
        model: "fixture-model",
        provider: "fixture-provider",
        thinking: "medium",
      },
    }));
    await waitForCondition(() => repository.agentAttempts.has(agentB));
    releaseLookup();

    await assert.rejects(staleStatus, /authority does not match/u);
    await secondLaunch;
    secondLaunched = true;
  } finally {
    releaseLookup();
    if (staleStatus) await staleStatus.catch(() => undefined);
    if (secondLaunch && !secondLaunched) {
      secondLaunched = await secondLaunch.then(() => true, () => false);
    }
    if (secondLaunched) {
      await supervisor.control({
        claimToken: "claim-a",
        controllerId: "controller-a",
        expectedVersion: repository.version,
        logicalAgentId: agentB,
        runId,
        targetPath,
      }, { kind: "stop" }).catch(() => undefined);
    }
    await supervisor.control({
      claimToken: "claim-a",
      controllerId: "controller-a",
      expectedVersion: repository.version,
      logicalAgentId: agentA,
      runId,
      targetPath,
    }, { kind: "stop" }).catch(() => undefined);
  }
});

test("phase session binding uses the current run version after queued activity", async () => {
  const runId = randomUUID();
  const agentA = randomUUID();
  const agentB = randomUUID();
  const targetPath = path.resolve(packageRoot);
  const stateRelease = path.join(tmpdir(), `pi-security-state-release-${randomUUID()}`);
  await writeFile(stateRelease, "ready\n");
  const repository = new FakeRepository(runId, targetPath, "controller-a");
  const supervisor = new rpc.PhaseSessionSupervisor({
    command: process.execPath,
    commandArgs: [fixture, `--get-state-release=${stateRelease}`],
    repository,
  });
  const input = {
    artifactRoot: targetPath,
    authority: { artifactRoot: targetPath, targetPath },
    capabilityProfile: { allowDelegation: false, allowTargetMutation: false, tools: ["read", "grep"] },
    outputContract: { type: "object" },
    phaseId: "discovery",
    requiredInputs: {},
    roleId: "discoverer",
    runId,
    target: { path: targetPath, revision: "fixture-revision" },
  };
  let launchedA = false;
  let launchB;
  let launchedB = false;
  try {
    await supervisor.launch(phaseRequest({
      attemptId: randomUUID(),
      claimToken: "claim-a",
      controllerId: "controller-a",
      expectedVersion: 1,
      input,
      logicalAgentId: agentA,
      maxAttempts: 1,
      ordinal: 1,
      role: {
        instructions: "Return the required structured result.",
        model: "fixture-model",
        provider: "fixture-provider",
        thinking: "medium",
      },
    }));
    launchedA = true;
    await rm(stateRelease, { force: true });

    launchB = supervisor.launch(phaseRequest({
      attemptId: randomUUID(),
      claimToken: "claim-a",
      controllerId: "controller-a",
      expectedVersion: repository.version,
      input,
      logicalAgentId: agentB,
      maxAttempts: 1,
      ordinal: 2,
      role: {
        instructions: "Return the required structured result.",
        model: "fixture-model",
        provider: "fixture-provider",
        thinking: "medium",
      },
    }));
    await waitForCondition(() => repository.agentAttempts.has(agentB));
    repository.activityRecords = 0;
    await supervisor.control({
      claimToken: "claim-a",
      controllerId: "controller-a",
      expectedVersion: repository.version,
      logicalAgentId: agentA,
      runId,
      targetPath,
    }, { kind: "steer", message: "start activity flood" });
    await waitForCondition(() => repository.activityRecords > 0);
    await writeFile(stateRelease, "ready\n");

    await launchB;
    launchedB = true;
    assert.equal(repository.agentAttempts.get(agentB).status, "running");
  } finally {
    await writeFile(stateRelease, "ready\n").catch(() => undefined);
    if (launchB && !launchedB) {
      launchedB = await launchB.then(() => true, () => false);
    }
    if (launchedB) {
      await supervisor.control({
        claimToken: "claim-a",
        controllerId: "controller-a",
        expectedVersion: repository.version,
        logicalAgentId: agentB,
        runId,
        targetPath,
      }, { kind: "stop" }).catch(() => undefined);
    }
    if (launchedA) {
      await supervisor.control({
        claimToken: "claim-a",
        controllerId: "controller-a",
        expectedVersion: repository.version,
        logicalAgentId: agentA,
        runId,
        targetPath,
      }, { kind: "stop" }).catch(() => undefined);
    }
    await rm(stateRelease, { force: true });
  }
});

test("phase interrupt bypasses a stalled RPC control on another session", async () => {
  const runId = randomUUID();
  const agentA = randomUUID();
  const agentB = randomUUID();
  const targetPath = path.resolve(packageRoot);
  const abortMarker = path.join(tmpdir(), `pi-security-abort-${randomUUID()}`);
  const stateDelayMarker = path.join(tmpdir(), `pi-security-state-delay-${randomUUID()}`);
  const repository = new FakeRepository(runId, targetPath, "controller-a");
  const supervisor = new rpc.PhaseSessionSupervisor({
    command: process.execPath,
    commandArgs: [
      fixture,
      `--abort-marker=${abortMarker}`,
      "--delay-state-after-initial-ms=200",
      `--state-delay-marker=${stateDelayMarker}`,
    ],
    repository,
  });
  const input = {
    artifactRoot: targetPath,
    authority: { artifactRoot: targetPath, targetPath },
    capabilityProfile: { allowDelegation: false, allowTargetMutation: false, tools: ["read", "grep"] },
    outputContract: { type: "object" },
    phaseId: "discovery",
    requiredInputs: {},
    roleId: "discoverer",
    runId,
    target: { path: targetPath, revision: "fixture-revision" },
  };
  let launchedA = false;
  let launchedB = false;
  let stalledStatus;
  let interrupted;
  try {
    await supervisor.launch(phaseRequest({
      attemptId: randomUUID(),
      claimToken: "claim-a",
      controllerId: "controller-a",
      expectedVersion: repository.version,
      input,
      logicalAgentId: agentA,
      maxAttempts: 1,
      ordinal: 1,
      role: {
        instructions: "Return the required structured result.",
        model: "fixture-model",
        provider: "fixture-provider",
        thinking: "medium",
      },
    }));
    launchedA = true;
    await supervisor.launch(phaseRequest({
      attemptId: randomUUID(),
      claimToken: "claim-a",
      controllerId: "controller-a",
      expectedVersion: repository.version,
      input,
      logicalAgentId: agentB,
      maxAttempts: 1,
      ordinal: 2,
      role: {
        instructions: "Return the required structured result.",
        model: "fixture-model",
        provider: "fixture-provider",
        thinking: "medium",
      },
    }));
    launchedB = true;

    stalledStatus = supervisor.control({
      claimToken: "claim-a",
      controllerId: "controller-a",
      expectedVersion: repository.version,
      logicalAgentId: agentA,
      runId,
      targetPath,
    }, { kind: "status" });
    await waitForCondition(() => existsSync(stateDelayMarker));

    interrupted = supervisor.control({
      claimToken: "claim-a",
      controllerId: "controller-a",
      expectedVersion: repository.version,
      logicalAgentId: agentB,
      runId,
      targetPath,
    }, { kind: "interrupt" });
    await waitForCondition(() => existsSync(abortMarker), 150);
    await interrupted;
  } finally {
    if (stalledStatus) await stalledStatus.catch(() => undefined);
    if (interrupted) await interrupted.catch(() => undefined);
    if (launchedB) {
      await supervisor.control({
        claimToken: "claim-a",
        controllerId: "controller-a",
        expectedVersion: repository.version,
        logicalAgentId: agentB,
        runId,
        targetPath,
      }, { kind: "stop" }).catch(() => undefined);
    }
    if (launchedA) {
      await supervisor.control({
        claimToken: "claim-a",
        controllerId: "controller-a",
        expectedVersion: repository.version,
        logicalAgentId: agentA,
        runId,
        targetPath,
      }, { kind: "stop" }).catch(() => undefined);
    }
    await rm(abortMarker, { force: true });
    await rm(stateDelayMarker, { force: true });
  }
});

test("phase capability ceiling rejects mutating tools before process launch", async () => {
  const runId = randomUUID();
  const targetPath = path.resolve(packageRoot);
  const repository = new FakeRepository(runId, targetPath, "controller-a");
  const supervisor = new rpc.PhaseSessionSupervisor({
    command: process.execPath,
    commandArgs: [fixture],
    repository,
  });
  await assert.rejects(
    supervisor.launch(phaseRequest({
      attemptId: randomUUID(),
      claimToken: "claim-a",
      controllerId: "controller-a",
      expectedVersion: 1,
      input: {
        artifactRoot: targetPath,
        authority: { artifactRoot: targetPath, targetPath },
        capabilityProfile: { allowDelegation: false, allowTargetMutation: false, tools: ["read", "bash"] },
        evidenceReferences: [],
        outputContract: { type: "object" },
        phaseId: "discovery",
        requiredInputs: {},
        roleId: "discoverer",
        runId,
        role: {
          instructions: "Return the required structured result.",
          model: "fixture-model",
          provider: "fixture-provider",
          thinking: "medium",
        },
        target: { path: targetPath, revision: "fixture-revision" },
        scanId: randomUUID(),
      },
      logicalAgentId: randomUUID(),
      maxAttempts: 1,
      ordinal: 1,
      role: {
        instructions: "Return the required structured result.",
        model: "fixture-model",
        provider: "fixture-provider",
        thinking: "medium",
      },
    })),
    (error) => error.code === "POLICY_DENIED",
  );
  assert.equal(repository.attempt, undefined);
});

test("phase launch records failed attempts for startup and request timeouts", async () => {
  const targetPath = path.resolve(packageRoot);
  for (const scenario of [
    { command: path.join(packageRoot, "missing-pi-rpc"), commandArgs: [], expected: /Unable to start/u },
    { command: process.execPath, commandArgs: [fixture, "--never-respond"], expected: /timed out/u },
  ]) {
    const runId = randomUUID();
    const logicalAgentId = randomUUID();
    const attemptId = randomUUID();
    const repository = new FakeRepository(runId, targetPath, "controller-a");
    const supervisor = new rpc.PhaseSessionSupervisor({
      command: scenario.command,
      commandArgs: scenario.commandArgs,
      cleanupTimeoutMs: 20,
      repository,
      requestTimeoutMs: 20,
    });
    await assert.rejects(
      supervisor.launch(phaseRequest({
        attemptId,
        claimToken: "claim-a",
        controllerId: "controller-a",
        expectedVersion: 1,
        input: {
          artifactRoot: targetPath,
          authority: { artifactRoot: targetPath, targetPath },
          capabilityProfile: { allowDelegation: false, allowTargetMutation: false, tools: ["read", "grep"] },
          outputContract: { type: "object" },
          phaseId: "discovery",
          requiredInputs: {},
          roleId: "discoverer",
          runId,
          target: { path: targetPath, revision: "fixture-revision" },
        },
        logicalAgentId,
        maxAttempts: 2,
        ordinal: 1,
        role: {
          instructions: "Return the required structured result.",
          model: "fixture-model",
          provider: "fixture-provider",
          thinking: "medium",
        },
      })),
      (error) => error instanceof rpc.JsonlRpcError
        && error.kind === "process"
        && scenario.expected.test(error.message),
    );
    assert.equal(repository.attempt.status, "failed");
    assert.equal(repository.events.at(-1).kind, "agent.attempt_failed");
    assert.equal(repository.events.at(-1).payload.category, "transport");
  }
});

test("attempt replacement is bounded and excludes authority, policy, contract, and cancellation failures", () => {
  assert.deepEqual(
    rpc.classifyAttemptFailure(new rpc.JsonlRpcError("closed", "process"), 1, 2, false),
    { category: "transport", replace: true },
  );
  assert.deepEqual(
    rpc.classifyAttemptFailure(new rpc.JsonlRpcError("overloaded", "request"), 1, 2, false),
    { category: "provider", replace: true },
  );
  assert.deepEqual(
    rpc.classifyAttemptFailure(Object.assign(new Error("denied"), { code: "POLICY_DENIED" }), 1, 2, false),
    { category: "policy", replace: false },
  );
  assert.deepEqual(
    rpc.classifyAttemptFailure(new Error("canceled"), 1, 2, true),
    { category: "canceled", replace: false },
  );
  assert.deepEqual(
    rpc.classifyAttemptFailure(Object.assign(new Error("mismatch"), { code: "AUTHORITY_MISMATCH" }), 1, 2, false),
    { category: "authority", replace: false },
  );
  assert.deepEqual(
    rpc.classifyAttemptFailure(Object.assign(new Error("schema"), { code: "CONTRACT_INCOMPATIBLE" }), 1, 2, false),
    { category: "contract", replace: false },
  );
  assert.deepEqual(
    rpc.classifyAttemptFailure(new rpc.JsonlRpcError("closed", "protocol"), 2, 2, false),
    { category: "transport", replace: false },
  );
});

test("phase launch rejects a self-consistent foreign target and missing policy before prompt dispatch", async () => {
  const targetPath = path.resolve(packageRoot);
  for (const scenario of ["foreign-target", "missing-policy", "missing-session"]) {
    const runId = randomUUID();
    const repository = new FakeRepository(runId, targetPath, "controller-a");
    const supervisor = new rpc.PhaseSessionSupervisor({
      command: process.execPath,
      commandArgs: [fixture, scenario === "missing-session" ? "--missing-session" : "--missing-policy"],
      repository,
    });
    const selected = scenario === "foreign-target" ? path.dirname(targetPath) : targetPath;
    await assert.rejects(supervisor.launch(phaseRequest({
      attemptId: randomUUID(),
      claimToken: "claim-a",
      controllerId: "controller-a",
      expectedVersion: 1,
      input: {
        artifactRoot: targetPath,
        authority: { artifactRoot: targetPath, targetPath: selected },
        capabilityProfile: { allowDelegation: false, allowTargetMutation: false, tools: ["read"] },
        outputContract: {},
        phaseId: "discovery",
        requiredInputs: {},
        roleId: "discoverer",
        runId,
        target: { path: selected, revision: null },
      },
      logicalAgentId: randomUUID(),
      maxAttempts: 1,
      ordinal: 1,
      role: { instructions: "Inspect synthetic source.", model: "fixture-model", provider: "fixture", thinking: "off" },
    })), (error) => error.code === (scenario === "foreign-target" ? "AUTHORITY_MISMATCH" : "CONTRACT_INCOMPATIBLE"));
    if (scenario === "foreign-target") assert.equal(repository.attempt, undefined);
    else assert.equal(repository.attempt.status, "failed");
    assert.equal(repository.events.some((event) => event.kind === "agent.session_bound"), false);
  }
});

test("RPC redacts transcript and event payloads without letting observers break transport", async (t) => {
  const transport = client("secret-data");
  t.after(() => transport.stop());
  const events = [];
  transport.onEvent(() => { throw new Error("synthetic observer failure"); });
  transport.onEvent((event) => events.push(event));
  await transport.start();
  const response = await transport.request({ type: "get_messages" });
  assert.equal(response.data.messages[0].content, "[REDACTED]");
  assert.equal(events[0].message.content[0].text, "[REDACTED]");
  assert.equal((await transport.request({ type: "get_messages" })).success, true);
});

test("run cancellation drains launching and bound children across admission freeze races", async (t) => {
  for (const stage of ["before-claim", "during-startup", "bound", "frozen-startup", "frozen-bound", "freeze-race"]) {
    const duringStartup = stage.endsWith("startup");
    const bound = !duringStartup && stage !== "before-claim";
    const ownerSettles = stage.startsWith("frozen") || stage === "freeze-race";
    const runId = randomUUID();
    const logicalAgentId = randomUUID();
    const targetPath = path.resolve(packageRoot);
    const startupMarker = path.join(tmpdir(), `pi-security-start-${randomUUID()}`);
    const stateRelease = path.join(tmpdir(), `pi-security-release-${randomUUID()}`);
    const repository = new FakeRepository(runId, targetPath, "controller-a");
    let frozen = false;
    if (ownerSettles) {
      const getRun = repository.getRun.bind(repository);
      const updateAttempt = repository.updateAttempt.bind(repository);
      repository.getRun = async () => ({ ...await getRun(), outputAdmissionFrozen: frozen });
      repository.updateAttempt = async (input) => {
        if (stage === "freeze-race" && input.status === "canceled") frozen = true;
        if (frozen) throw new Error("Output admission is frozen.");
        return await updateAttempt(input);
      };
    }
    let releaseRead;
    let enteredRead;
    const readEntered = new Promise((resolve) => { enteredRead = resolve; });
    const readReleased = new Promise((resolve) => { releaseRead = resolve; });
    if (stage === "before-claim") {
      const getRun = repository.getRun.bind(repository);
      let first = true;
      repository.getRun = async () => {
        if (first) {
          first = false;
          enteredRead();
          await readReleased;
        }
        return await getRun();
      };
    }
    const supervisor = new rpc.PhaseSessionSupervisor({
      command: process.execPath,
      commandArgs: [
        fixture,
        `--startup-marker=${startupMarker}`,
        ...(duringStartup ? [`--get-state-release=${stateRelease}`] : []),
      ],
      cleanupTimeoutMs: 20,
      repository,
    });
    t.after(async () => {
      releaseRead();
      await supervisor.abortRun(runId);
      await Promise.all([startupMarker, stateRelease].map((path) => rm(path, { force: true })));
    });
    const request = {
      attemptId: randomUUID(),
      claimToken: "claim-a",
      controllerId: "controller-a",
      expectedVersion: 1,
      input: {
        artifactRoot: targetPath,
        authority: { artifactRoot: targetPath, targetPath },
        capabilityProfile: { allowDelegation: false, allowTargetMutation: false, tools: ["read"] },
        outputContract: {},
        phaseId: "discovery",
        requiredInputs: {},
        roleId: "discoverer",
        runId,
        target: { path: targetPath, revision: null },
      },
      logicalAgentId,
      maxAttempts: 2,
      ordinal: 1,
      role: { instructions: "Inspect synthetic source.", model: "fixture-model", provider: "fixture", thinking: "off" },
    };
    const launch = supervisor.launch(phaseRequest(request)).then((value) => ({ value }), (error) => ({ error }));
    if (stage === "before-claim") await readEntered;
    else if (duringStartup) await waitForCondition(() => existsSync(startupMarker), 2_000);
    else assert.equal((await launch).value.piSessionId, "fixture-session");
    const statusBeforeAbort = repository.attempt?.status;
    frozen = stage.startsWith("frozen");
    const aborted = supervisor.abortRun(runId);
    const repeatedAbort = supervisor.abortRun(runId);
    if (stage === "before-claim") {
      assert.equal(await settlesWithin(aborted, 20), false);
      assert.equal(await settlesWithin(repeatedAbort, 20), false);
      releaseRead();
    }
    await Promise.all([aborted, repeatedAbort]);
    const result = await launch;
    if (!bound) assert.equal(result.error.code, "CANCELED");
    if (stage === "before-claim") {
      assert.equal(repository.attempt, undefined);
      assert.equal(existsSync(startupMarker), false);
    } else {
      assert.equal(repository.attempt.status, ownerSettles ? statusBeforeAbort : "canceled");
      const pid = Number(await readFile(startupMarker, "utf8"));
      assert.throws(() => process.kill(pid, 0), (error) => error.code === "ESRCH");
    }
    await assert.rejects(supervisor.launch(phaseRequest({ ...request, attemptId: randomUUID(), ordinal: 2 })), (error) => error.code === "CANCELED");
    await assert.rejects(supervisor.control({
      claimToken: "claim-a", controllerId: "controller-a", expectedVersion: repository.version,
      logicalAgentId, runId, targetPath,
    }, { kind: "status" }));
  }
});
