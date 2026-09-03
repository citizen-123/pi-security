import assert from "node:assert/strict";
import test from "node:test";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  stdin: {
    contents: [
      'export * from "./src/cli/args.ts";',
      'export * from "./src/cli/main.ts";',
      'export * from "./src/cli/operations.ts";',
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
  assert.equal(completed.calls[1][0], "start");

  const preflight = harness();
  preflight.handler = cli.createCliCommandHandler({
    config: async () => { throw new Error("synthetic configuration failure"); },
    io: preflight.io,
    lifecycle: {}, ownership: () => ({}), repository: {}, tty: false,
  });
  assert.equal(await cli.runCli(["scan"], preflight.io, preflight.handler), 2);
  assert.deepEqual(preflight.errors, ["synthetic configuration failure"]);
});

test("TTY progress exposes units, agents, findings, phases, and terminal outcome", () => {
  const rendered = cli.renderTtyProgress(run("failed"), [
    event(1, "agent.session_bound", "agent-b"),
    event(2, "agent.session_bound", "agent-a"),
    event(3, "agent.attempt_failed", "agent-b"),
  ]);
  assert.match(rendered, /Phases: 2\/2/u);
  assert.match(rendered, /Active logical agents: agent-a/u);
  assert.match(rendered, /Findings: 2/u);
  assert.match(rendered, /preflight: completed/u);
  assert.match(rendered, /Outcome: synthetic failed/u);
  assert.doesNotMatch(rendered, /working/u);
});

test("inspection reads relational state without a live executor", async () => {
  const fixture = harness(run("interrupted"));
  assert.equal(await cli.runCli(["run", "inspect", run().id], fixture.io, fixture.handler), 75);
  assert.equal(JSON.parse(fixture.output[0]).status, "interrupted");
  assert.deepEqual(fixture.calls.map((call) => call[0]), ["getRun", "listEvents"]);
});

test("cancel, resume, and retry route through lifecycle ownership", async () => {
  const fixture = harness();
  assert.equal(await cli.runCli(["run", "cancel", run().id], fixture.io, fixture.handler), 130);
  assert.equal(await cli.runCli(["run", "resume", run().id], fixture.io, fixture.handler), 0);
  assert.equal(await cli.runCli(["run", "retry", run().id], fixture.io, fixture.handler), 0);
  assert.deepEqual(
    fixture.calls.filter((call) => ["cancel", "resume", "retry", "execute"].includes(call[0])).map((call) => call[0]),
    ["cancel", "resume", "retry", "execute"],
  );
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
});
