import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  stdin: {
    contents: [
      'export * from "./src/cli/args.ts";',
      'export * from "./src/cli/main.ts";',
      'export * from "./src/cli/operations.ts";',
      'export * from "./src/runtime/lifecycle.ts";',
    ].join("\n"),
    resolveDir: new URL("..", import.meta.url).pathname,
  },
  format: "esm",
  platform: "node",
  write: false,
});
const cli = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`,
);

function run(status = "completed") {
  const timestamp = "2026-01-01T00:00:00.000Z";
  return {
    completedAt: status === "running" ? null : timestamp,
    controllerId: status === "running" ? "controller" : null,
    createdAt: timestamp,
    id: "11111111-1111-4111-8111-111111111111",
    outputAdmissionFrozen: status !== "running",
    parentRunId: null,
    phases: [
      {
        dependencies: [], id: "preflight", inputDigest: null, output: { reviewItemsTotal: 3 },
        outputDigest: null, phaseVersion: 1, reusedFromPhaseId: null, reusedFromRunId: null,
        roleId: null, state: "completed", type: "preflight", updatedAt: timestamp, version: 2,
      },
      {
        dependencies: ["preflight"], id: "reporting", inputDigest: null,
        output: { findings: [{ id: "finding-a" }, { id: "finding-b" }] }, outputDigest: null,
        phaseVersion: 1, reusedFromPhaseId: null, reusedFromRunId: null, roleId: "reporter",
        state: status === "completed" ? "completed" : status, type: "reporting", updatedAt: timestamp, version: 2,
      },
    ],
    policyDigest: `sha256:${"a".repeat(64)}`,
    progress: { coverageConclusion: status === "completed" ? "complete" : "inconclusive" },
    scanId: "22222222-2222-4222-8222-222222222222",
    snapshot: {},
    snapshotDigest: `sha256:${"b".repeat(64)}`,
    status,
    statusReason: status === "completed" ? null : `synthetic ${status}`,
    targetPath: "/tmp/synthetic-repository",
    targetRevision: null,
    updatedAt: timestamp,
    version: 4,
    workflow: {},
  };
}

function event(sequence, kind, logicalAgentId = null, schemaVersion = 1) {
  return {
    attemptId: null, category: "activity", correlationId: null, kind, logicalAgentId,
    payload: {}, phaseId: "reporting", runId: run().id, schemaVersion, sequence,
    source: "runtime", timestamp: "2026-01-01T00:00:00.000Z",
  };
}

function harness(result = run()) {
  const calls = [];
  const output = [];
  const errors = [];
  const lifecycle = {
    async cancel(runId, ownership) { calls.push(["cancel", runId, ownership]); return run("canceled"); },
    async execute(claimed, ownership) { calls.push(["execute", claimed.id, ownership]); return run("completed"); },
    async resume(input) { calls.push(["resume", input]); return run("completed"); },
    async retry(input) { calls.push(["retry", input]); return run("running"); },
    async start(input) { calls.push(["start", input]); return result; },
  };
  const repository = {
    async getRun(runId) { calls.push(["getRun", runId]); return result; },
    async listEvents(runId, after) { calls.push(["listEvents", runId, after]); return []; },
  };
  const io = { error: (message) => errors.push(message), output: (message) => output.push(message) };
  const handler = cli.createCliCommandHandler({
    async config(command) { calls.push(["config", command.kind]); return { scan: { target: "/tmp/synthetic-repository" } }; },
    io,
    lifecycle,
    ownership: () => ({ claimToken: "claim", controllerId: "controller" }),
    repository,
    tty: false,
  });
  return { calls, errors, handler, io, output };
}

test("foreground statuses map to deterministic process exits and non-TTY JSON", async () => {
  assert.deepEqual(
    ["completed", "failed", "canceled", "interrupted", "running"].map(cli.exitStatusForRun),
    [0, 1, 130, 75, 75],
  );
  const completed = harness();
  assert.equal(await cli.runCli(["scan", "--target", "."], completed.io, completed.handler), 0);
  assert.equal(JSON.parse(completed.output[0]).status, "completed");

  const preflight = harness();
  preflight.handler = cli.createCliCommandHandler({
    config: async () => { throw new Error("synthetic configuration failure"); },
    io: preflight.io,
    lifecycle: {}, ownership: () => ({}), repository: {}, tty: false,
  });
  assert.equal(await cli.runCli(["scan"], preflight.io, preflight.handler), 2);
  assert.deepEqual(preflight.errors, ["synthetic configuration failure"]);

  const lifecycleFailure = harness();
  lifecycleFailure.handler = cli.createCliCommandHandler({
    config: async () => ({ scan: { target: "/tmp/synthetic-repository" } }),
    io: lifecycleFailure.io,
    lifecycle: { async start() { throw new Error("synthetic lifecycle failure"); } },
    ownership: () => ({}), repository: {}, tty: false,
  });
  assert.equal(await cli.runCli(["scan"], lifecycleFailure.io, lifecycleFailure.handler), 1);
  assert.deepEqual(lifecycleFailure.errors, ["synthetic lifecycle failure"]);

});

test("TTY progress exposes units, agents, findings, phases, and terminal outcome", () => {
  const rendered = cli.renderTtyProgress(run("running"), [
    event(1, "agent.attempt_started", "agent-b"),
    event(2, "agent.session_bound", "agent-a"),
    event(3, "agent.attempt_completed", "agent-b"),
  ]);
  assert.match(rendered, /Phases: 1\/2/u);
  assert.match(rendered, /Active logical agents: agent-a/u);
  assert.match(rendered, /Findings: 2/u);
  assert.match(rendered, /preflight: completed/u);
  assert.match(rendered, /Outcome: synthetic running/u);
});

test("TTY foreground rendering starts before lifecycle execution settles", async () => {
  const calls = [];
  const output = [];
  const running = run("running");
  let current = running;
  const lifecycle = {
    async cancel() { return run("canceled"); },
    async createAndClaim(input) { calls.push(["createAndClaim", input]); return running; },
    async execute() {
      await new Promise((resolve) => setTimeout(resolve, 0));
      current = run("completed");
      return current;
    },
    async resume() { return run("completed"); },
    async retry() { return running; },
    async start() { return current; },
  };
  const handler = cli.createCliCommandHandler({
    config: async () => ({ scan: { target: "/tmp/synthetic-repository" } }),
    foregroundRefreshMs: 0,
    io: { error() {}, output: (message) => output.push(message) },
    lifecycle,
    ownership: () => ({ claimToken: "claim", controllerId: "controller" }),
    repository: {
      async getRun() { return current; },
      async listEvents() { return []; },
    },
    tty: true,
  });
  assert.equal(await cli.runCli(["scan"], { error() {}, output() {} }, handler), 0);
  assert.match(output[0], /Run .*: running/u);
  assert.match(output.at(-1), /Run .*: completed/u);
});

test("TTY resume renders foreground progress before the resumed execution settles", async () => {
  const calls = [];
  const output = [];
  const running = run("running");
  let current = running;
  const lifecycle = {
    async cancel() { return run("canceled"); },
    async execute() {
      calls.push("execute");
      await new Promise((resolve) => setTimeout(resolve, 0));
      current = run("completed");
      return current;
    },
    async resumeAndClaim(input) {
      calls.push(["resumeAndClaim", input]);
      return running;
    },
    async retry() { return running; },
    async start() { return current; },
  };
  const handler = cli.createCliCommandHandler({
    config: async () => ({ scan: { target: "/tmp/synthetic-repository" } }),
    foregroundRefreshMs: 0,
    io: { error() {}, output: (message) => output.push(message) },
    lifecycle,
    ownership: () => ({ claimToken: "claim", controllerId: "controller" }),
    repository: {
      async getRun() { return current; },
      async listEvents() { return []; },
    },
    tty: true,
  });
  assert.equal(await cli.runCli(["run", "resume", run().id], { error() {}, output() {} }, handler), 0);
  assert.match(output[0], /Run .*: running/u);
  assert.match(output.at(-1), /Run .*: completed/u);
});

test("offline JSON inspection reads persisted results even when the event journal is unavailable", async () => {
  const persisted = run("interrupted");
  const output = [];
  const io = { error() {}, output: (message) => output.push(message) };
  const handler = cli.createCliCommandHandler({
    io,
    lifecycle: {},
    ownership() { throw new Error("No live controller"); },
    repository: {
      async getRun() { return persisted; },
      async listEvents() { throw new Error("Event journal unavailable"); },
    },
    tty: false,
  });
  assert.equal(await cli.runCli(["run", "inspect", persisted.id], io, handler), 75);
  const inspected = JSON.parse(output[0]);
  assert.equal(inspected.status, "interrupted");
  assert.deepEqual(inspected.phases.find((phase) => phase.id === "reporting").output, persisted.phases[1].output);
  assert.equal(inspected.statusReason, persisted.statusReason);
});

test("cancel, resume, and retry route through lifecycle ownership", async () => {
  const fixture = harness();
  assert.equal(await cli.runCli(["run", "cancel", run().id], fixture.io, fixture.handler), 130);
  assert.equal(await cli.runCli(["run", "resume", run().id], fixture.io, fixture.handler), 0);
  assert.equal(await cli.runCli(["run", "retry", run().id], fixture.io, fixture.handler), 0);
});

test("event reconnection yields only an ordered compatible continuation", async () => {
  const repository = {
    async getRun() { return run("interrupted"); },
    async listEvents(_runId, after) {
      assert.equal(after, 7);
      return [event(8, "phase.running"), event(9, "run.interrupted")];
    },
  };
  const update = await cli.reconnectRuntimeEvents(repository, run().id, 7);
  assert.deepEqual(update.events.map(({ sequence }) => sequence), [8, 9]);
  await assert.rejects(
    cli.reconnectRuntimeEvents({ ...repository, listEvents: async () => [event(8, "future", null, 2)] }, run().id, 7),
    (error) => error.name === "RuntimeEventCompatibilityError",
  );
  await assert.rejects(
    cli.reconnectRuntimeEvents({ ...repository, listEvents: async () => [event(9, "later"), event(8, "earlier")] }, run().id, 7),
    /ordered continuation/u,
  );

  await assert.rejects(
    cli.reconnectRuntimeEvents({ ...repository, listEvents: async () => [event(8, "first"), event(10, "gap")] }, run().id, 7),
    /ordered continuation/u,
  );
  await assert.rejects(
    cli.reconnectRuntimeEvents({ ...repository, listEvents: async () => [event(9, "gap")] }, run().id, 7),
    /ordered continuation/u,
  );
  await assert.rejects(
    cli.reconnectRuntimeEvents(repository, run().id, Number.NaN),
    (error) => error.name === "RuntimeEventCompatibilityError",
  );
});

test("terminal inspection does not report agents left active by executor loss", () => {
  const events = [event(1, "agent.session_bound", "orphaned-agent")];
  const rendered = cli.renderTtyProgress(run("interrupted"), events);
  assert.match(rendered, /Active logical agents: none/u);
  assert.match(rendered, /Outcome: synthetic interrupted/u);
  assert.doesNotMatch(rendered, /orphaned-agent/u);
});

test("TTY observer disconnection cannot prevent a claimed scan from executing", async () => {
  const terminal = run("completed");
  let persisted = run("running");
  const io = {
    error() { throw new Error("Disconnected stderr"); },
    output() { throw new Error("Disconnected terminal"); },
  };
  const handler = cli.createCliCommandHandler({
    config: async () => ({}),
    io,
    lifecycle: {
      async createAndClaim() { return persisted; },
      async execute() { persisted = terminal; return terminal; },
    },
    ownership: () => ({}),
    repository: {
      async getRun() { return persisted; },
      async listEvents() { return []; },
    },
    tty: true,
  });
  assert.equal(await cli.runCli(["scan"], io, handler), 0);
  assert.equal(persisted.status, "completed");
});

test("a failed foreground event refresh still waits for the durable terminal outcome", async () => {
  let finish;
  let current = run("running");
  let reads = 0;
  const output = [];
  const errors = [];
  const io = { error: (message) => errors.push(message), output: (message) => output.push(message) };
  const handler = cli.createCliCommandHandler({
    config: async () => ({}),
    foregroundRefreshMs: 0,
    io,
    lifecycle: {
      async createAndClaim() { return current; },
      async execute() {
        await new Promise((resolve) => { finish = resolve; });
        current = run("canceled");
        return current;
      },
    },
    ownership: () => ({}),
    repository: {
      async getRun() { return current; },
      async listEvents() {
        if (++reads === 1) return [];
        setTimeout(finish, 0);
        throw new Error("Synthetic event read failure");
      },
    },
    tty: true,
  });
  assert.equal(await cli.runCli(["scan"], io, handler), 130);
  assert.equal(current.status, "canceled");
  assert.match(output.at(-1), /Run .*: canceled/u);
  assert.match(errors[0], /Synthetic event read failure/u);
});

test("a missing target is a preflight exit rather than a workflow failure", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "pi-security-cli-preflight-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const errors = [];
  const io = { error: (message) => errors.push(message), output() {} };
  const handler = cli.createCliCommandHandler({
    config: async () => ({
      execution: { maxParallel: 1 },
      roles: { default: { maxAttempts: 1 } },
      scan: { target: path.join(root, "missing"), workflow: "full-repository" },
    }),
    io,
    lifecycle: new cli.CanonicalRunLifecycle({ repository: {} }),
    ownership: () => ({ claimToken: "claim", controllerId: "controller" }),
    repository: {},
    tty: false,
  });
  assert.equal(await cli.runCli(["scan"], io, handler), 2);
  assert.match(errors[0], /ENOENT/u);
});

test("a stalled progress read cannot hold foreground execution open", { timeout: 5_000 }, async () => {
  const output = [];
  const io = { error() {}, output: (message) => output.push(message) };
  let releaseEvents;
  const pendingEvents = new Promise((resolve) => { releaseEvents = resolve; });
  const handler = cli.createCliCommandHandler({
    config: async () => ({}),
    io,
    lifecycle: {
      async createAndClaim() { return run("running"); },
      async execute() { return run("completed"); },
    },
    ownership: () => ({}),
    repository: {
      async getRun() { return run("completed"); },
      async listEvents() { return pendingEvents; },
    },
    tty: true,
  });
  try {
    assert.equal(await cli.runCli(["scan"], io, handler), 0);
    assert.match(output.at(-1), /Run .*: completed/u);
  } finally {
    releaseEvents([]);
  }
});

test("unrecognized events cannot invent active logical agents", () => {
  const rendered = cli.renderTtyProgress(run("running"), [
    event(1, "constructor", "not-an-active-agent"),
  ]);
  assert.match(rendered, /Active logical agents: none/u);
  assert.doesNotMatch(rendered, /not-an-active-agent/u);
});
