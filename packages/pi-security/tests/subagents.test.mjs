import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { build } from "esbuild";

const root = resolve(import.meta.dirname, "..");
const ceilingBundle = await build({
  bundle: true,
  entryPoints: [resolve(root, "../../node_modules/pi-subagents/src/api/capability-ceiling.ts")],
  format: "esm",
  platform: "node",
  write: false,
});
const { resolveCurrentSubagentCapabilityCeiling } = await import(
  `data:text/javascript;base64,${Buffer.from(ceilingBundle.outputFiles[0].contents).toString("base64")}`,
);

class FakeEvents {
  handlers = new Map();
  requests = [];
  sessionId;
  nextRun = 0;

  on(event, handler) {
    const handlers = this.handlers.get(event) ?? new Set();
    handlers.add(handler);
    this.handlers.set(event, handlers);
    return () => handlers.delete(handler);
  }

  emit(event, payload) {
    if (event === "subagents:rpc:v1:request") {
      const observedCeiling = resolveCurrentSubagentCapabilityCeiling(this.sessionId);
      this.requests.push({ ...payload, observedCeiling: structuredClone(observedCeiling) });
      let data;
      if (payload.method === "spawn") {
        data = {
          details: {
            asyncId: `run-${++this.nextRun}`,
            status: "running"
          }
        };
      } else if (payload.method === "resume") {
        data = {
          details: {
            asyncId: `resumed-${++this.nextRun}`,
            status: "running"
          }
        };
      } else {
        data = {
          method: payload.method,
          id: payload.params?.id,
          status: "ok"
        };
      }
      queueMicrotask(() => this.emit(`subagents:rpc:v1:reply:${payload.requestId}`, {
        version: 1,
        requestId: payload.requestId,
        success: true,
        data
      }));
      return;
    }
    for (const handler of this.handlers.get(event) ?? []) handler(payload);
  }
}

test("package exposes bundled subagents before the security extension", async () => {
  const manifest = JSON.parse(await readFile(resolve(root, "package.json"), "utf8"));
  assert.equal(manifest.dependencies["pi-subagents"], "0.62.0");
  assert.deepEqual(manifest.bundledDependencies, ["pi-subagents"]);
  assert.deepEqual(manifest.pi.extensions, [
    "./node_modules/pi-subagents/index.ts",
    "./dist/pi-security-extension.mjs"
  ]);
  assert.deepEqual(manifest.pi.subagents.agents, ["./agents"]);

  const files = (await readdir(resolve(root, "agents"))).sort();
  assert.deepEqual(files, [
    "pi-security-auditor.md",
    "pi-security-reviewer.md",
    "pi-security-scout.md",
    "pi-security-validator.md"
  ]);
  for (const file of files) {
    const definition = await readFile(resolve(root, "agents", file), "utf8");
    assert.match(definition, /^---\nname: pi-security-/);
    assert.match(definition, /tools: read, grep, find, ls/);
    assert.match(definition, /acceptanceRole: read-only/);
    assert.match(definition, /maxSubagentDepth: 0/);
  }
});

async function createHarness() {
  const { default: register } = await import("../dist/pi-security-extension.mjs");
  const tools = new Map();
  const events = new FakeEvents();
  register({
    events,
    registerTool(tool) {
      tools.set(tool.name, tool);
    },
    registerCommand() {},
    sendUserMessage() {},
    on() {}
  });
  return {
    events,
    spawn: tools.get("pi_security_spawn_agents"),
    control: tools.get("pi_security_control_agents")
  };
}

function extensionContext(cwd, sessionId) {
  return {
    cwd,
    sessionManager: { getSessionId: () => sessionId }
  };
}

function taskBatch(count, prefix = "task") {
  return Array.from({ length: count }, (_, index) => ({
    agent: index % 2 === 0 ? "pi-security-scout" : "pi-security-auditor",
    task: `${prefix}-${index}`
  }));
}

test("security subagents retain run provenance and never request global fleet status", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "pi-security-subagents-"));
  const otherRoot = await mkdtemp(join(tmpdir(), "pi-security-subagents-other-"));
  try {
    const { events, spawn, control } = await createHarness();
    assert.ok(spawn);
    assert.ok(control);
    const signal = new AbortController().signal;
    const ownSession = "pi-security-owned-session";
    const ownContext = extensionContext(temporaryRoot, ownSession);
    events.sessionId = ownSession;

    const spawned = await spawn.execute("spawn-call", {
      tasks: [
        { agent: "pi-security-scout", task: "Map authentication entry points." },
        { agent: "pi-security-auditor", task: "Audit the assigned parser surface." }
      ],
      context: "fresh"
    }, signal, undefined, ownContext);
    assert.equal(spawned.details.started, 2);
    assert.equal(spawned.details.enforcementCapabilities.schemaVersion, 1);
    assert.equal(spawned.details.enforcementCapabilities.kind, "availability");
    assert.equal(spawned.details.enforcementCapabilities.supported, true);
    assert.deepEqual(
      spawned.details.enforcementCapabilities.mechanisms.slice(0, 2),
      [
        "pi.fixed-profile-tool-dispatch",
        "target.verified-open-handle",
      ],
    );
    assert.doesNotMatch(
      JSON.stringify(spawned.details.enforcementCapabilities),
      /session|claim|credential|token/iu,
    );
    assert.equal(Object.hasOwn(spawned.details, "sessionId"), false);
    assert.equal(JSON.stringify(spawned).includes(ownSession), false);
    const ownedIds = spawned.details.runs.map((run) => run.id);
    assert.deepEqual(ownedIds, ["run-1", "run-2"]);
    const spawnRequests = events.requests.filter((request) => request.method === "spawn");
    assert.equal(spawnRequests.length, 2);
    assert.ok(spawnRequests.every((request) => request.params.async === true));
    assert.ok(spawnRequests.every((request) => request.params.cwd === temporaryRoot));
    assert.ok(spawnRequests.every((request) => request.observedCeiling?.denyExtensions === true));
    assert.ok(spawnRequests.every((request) => (
      [...request.observedCeiling.allowedTools].sort().join(",") === "find,grep,ls,read"
    )));

    const beforeFleet = events.requests.length;
    const fleet = await control.execute("fleet-call", {
      action: "status"
    }, signal, undefined, ownContext);
    const fleetRequests = events.requests.slice(beforeFleet);
    assert.deepEqual(
      fleetRequests.map((request) => request.params.id).sort(),
      ownedIds.slice().sort()
    );
    assert.ok(fleetRequests.every((request) => request.method === "status"));
    assert.ok(fleetRequests.every((request) => request.params.id));
    assert.deepEqual(
      fleet.details.runs.map((run) => run.id).sort(),
      ownedIds.slice().sort()
    );
    assert.equal(fleet.details.sessionId, ownSession);
    assert.equal(JSON.parse(fleet.content[0].text).sessionId, ownSession);

    const beforeRejected = events.requests.length;
    const rejectedParams = [
      { action: "status", id: "generic-known-run" },
      { action: "steer", id: "generic-known-run", message: "continue" },
      { action: "interrupt", id: "generic-known-run" },
      { action: "stop", id: "generic-known-run" },
      { action: "resume", id: "generic-known-run", message: "continue" }
    ];
    for (const params of rejectedParams) {
      await assert.rejects(
        control.execute("unowned-call", params, signal, undefined, ownContext),
        /not owned by this Pi Security session/
      );
    }
    assert.equal(events.requests.length, beforeRejected);

    events.sessionId = "other-session";
    await assert.rejects(
      control.execute("cross-session-call", {
        action: "status",
        id: ownedIds[0]
      }, signal, undefined, extensionContext(otherRoot, "other-session")),
      /not owned by this Pi Security session/
    );
    assert.equal(events.requests.length, beforeRejected);
    const emptyFleet = await control.execute("empty-fleet-call", {
      action: "status"
    }, signal, undefined, extensionContext(otherRoot, "other-session"));
    assert.deepEqual(emptyFleet.details.runs, []);
    assert.equal(emptyFleet.details.enforcementCapabilities.supported, true);
    assert.equal(emptyFleet.details.sessionId, "other-session");
    assert.equal(JSON.parse(emptyFleet.content[0].text).sessionId, "other-session");
    assert.equal(events.requests.length, beforeRejected);

    events.sessionId = ownSession;
    const controls = [
      { action: "status", id: ownedIds[0], view: "transcript", lines: 20 },
      { action: "steer", id: ownedIds[0], message: "Prioritize the parser." },
      { action: "interrupt", id: ownedIds[0] },
      { action: "stop", id: ownedIds[0] },
      { action: "resume", id: ownedIds[0], message: "Continue readonly review." }
    ];
    const beforeControls = events.requests.length;
    for (const params of controls) {
      await control.execute("owned-control-call", params, signal, undefined, ownContext);
    }
    const controlRequests = events.requests.slice(beforeControls);
    assert.deepEqual(
      controlRequests.map((request) => request.method),
      ["status", "steer", "interrupt", "stop", "resume"]
    );
    assert.ok(controlRequests.every((request) => request.params.id === ownedIds[0]));
    assert.ok(controlRequests.every((request) => request.observedCeiling?.denyExtensions === true));
    assert.ok(controlRequests.every((request) => (
      [...request.observedCeiling.allowedTools].sort().join(",") === "find,grep,ls,read"
    )));

    await control.execute("resumed-status-call", {
      action: "status",
      id: "resumed-3"
    }, signal, undefined, ownContext);
    assert.equal(events.requests.at(-1).params.id, "resumed-3");
  } finally {
    await Promise.all([
      rm(temporaryRoot, { recursive: true, force: true }),
      rm(otherRoot, { recursive: true, force: true })
    ]);
  }
});

test("security subagent delegation budget is shared across repeated and concurrent calls", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "pi-security-budget-"));
  try {
    const { events, spawn } = await createHarness();
    assert.ok(spawn);
    const signal = new AbortController().signal;
    const sessionId = "pi-security-budget-session";
    const context = extensionContext(temporaryRoot, sessionId);
    events.sessionId = sessionId;

    const concurrent = await Promise.allSettled([
      spawn.execute("nine-call", {
        tasks: taskBatch(9, "nine"),
        context: "fresh"
      }, signal, undefined, context),
      spawn.execute("eight-call", {
        tasks: taskBatch(8, "eight"),
        context: "fresh"
      }, signal, undefined, context)
    ]);
    const fulfilled = concurrent.filter((result) => result.status === "fulfilled");
    const rejected = concurrent.filter((result) => result.status === "rejected");
    assert.equal(fulfilled.length, 1);
    assert.equal(rejected.length, 1);
    assert.match(String(rejected[0].reason), /delegation budget is exhausted/);

    const consumed = fulfilled[0].value.details.started;
    assert.ok(consumed === 8 || consumed === 9);
    const remainder = 16 - consumed;
    const finalBatch = await spawn.execute("remaining-call", {
      tasks: taskBatch(remainder, "remaining"),
      context: "fresh"
    }, signal, undefined, context);
    assert.equal(finalBatch.details.started, remainder);
    assert.equal(
      events.requests.filter((request) => request.method === "spawn").length,
      16
    );
    await assert.rejects(
      spawn.execute("over-budget-call", {
        tasks: taskBatch(1, "over"),
        context: "fresh"
      }, signal, undefined, context),
      /delegation budget is exhausted/
    );
    assert.equal(
      events.requests.filter((request) => request.method === "spawn").length,
      16
    );
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});
