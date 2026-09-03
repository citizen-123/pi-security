import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { build } from "esbuild";

const packageRoot = new URL("..", import.meta.url).pathname;
const fixture = path.join(packageRoot, "tests", "fixtures", "fake-pi-rpc.mjs");
const bundle = await build({
  bundle: true,
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

function client(mode, options = {}) {
  return new rpc.JsonlRpcClient({
    command: process.execPath,
    args: [fixture],
    cleanupTimeoutMs: options.cleanupTimeoutMs,
    env: { ...process.env, FAKE_RPC_MODE: mode, ...options.env },
    redact: (text) => text.replaceAll("synthetic-canary", "[REDACTED]"),
  });
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

test("JSONL client rejects malformed, uncorrelated, and exited responses and cleans up", async () => {
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
});

class FakeRepository {
  constructor(runId, targetPath, controllerId) {
    this.runId = runId;
    this.targetPath = targetPath;
    this.controllerId = controllerId;
    this.version = 1;
    this.events = [];
    this.attempt = undefined;
  }

  async startAttempt(input) {
    this.attempt = {
      createdAt: "2026-01-01T00:00:00Z",
      details: input.details ?? {},
      failureCategory: null,
      id: input.attemptId,
      ordinal: input.ordinal,
      piSessionId: null,
      status: "starting",
      updatedAt: "2026-01-01T00:00:00Z",
    };
    this.logicalAgentId = input.logicalAgentId;
    this.phaseId = input.phaseId;
    return this.mutation("starting");
  }

  async updateAttempt(input) {
    assert.equal(input.expectedVersion, this.version);
    this.attempt = { ...this.attempt, details: input.details ?? {}, piSessionId: input.piSessionId ?? null, status: input.status };
    this.events.push(input.event);
    return this.mutation(input.status);
  }

  async recordEvent(input) {
    assert.equal(input.expectedVersion, this.version);
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

  async getAgent() {
    return {
      attempts: [this.attempt],
      id: this.logicalAgentId,
      phaseId: this.phaseId,
      runId: this.runId,
      status: this.attempt.status,
    };
  }

  mutation(status) {
    this.version += 1;
    return {
      attemptId: this.attempt.id,
      logicalAgentId: this.logicalAgentId,
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
  const launched = await supervisor.launch({
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
  });
  assert.equal(launched.piSessionId, "fixture-session");
  await new Promise((resolve) => setTimeout(resolve, 20));

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
  assert.deepEqual(
    status.state.argv.slice(-14),
    [
      "--mode", "rpc", "--provider", "fixture-provider", "--model", "fixture-model",
      "--thinking", "high", "--name", `${runId}:discovery:1`, "--session-dir", targetPath,
      "--tools", "read,grep",
    ],
  );
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
  await supervisor.control(
    { ...request, expectedVersion: repository.version },
    { kind: "interrupt" },
  );
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
    supervisor.launch({
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
    }),
    (error) => error.code === "POLICY_DENIED",
  );
  assert.equal(repository.attempt, undefined);
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
