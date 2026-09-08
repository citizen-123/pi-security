import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { build } from "esbuild";

const packageRoot = new URL("..", import.meta.url).pathname;
const bundle = await build({
  bundle: true,
  stdin: {
    contents: [
      'export * from "./src/workflow/registry.ts";',
      'export * from "./src/workflow/scheduler.ts";',
      'export * from "./src/workflow/builtin.ts";',
      'export * from "./src/workflow/adapters.ts";',
    ].join("\n"),
    resolveDir: packageRoot,
  },
  format: "esm",
  platform: "node",
  write: false,
});
const workflow = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`,
);
const { z } = await import("zod");

function type(type, inputContracts = {}, outputContract = `${type}.v1`) {
  return {
    attemptPolicy: { maxAttempts: 1 },
    capability: { allowDelegation: false, allowTargetMutation: false, tools: [] },
    executor: "deterministic",
    inputContracts,
    outputContract,
    outputSchema: z.object({ value: z.string() }).strict(),
    type,
    version: 1,
  };
}

function phase(id, typeName, dependencies = [], bindings = {}) {
  return { bindings, dependencies, id, type: typeName, version: 1 };
}

function delivery(context, output = { value: context.phase.id }, attemptId = `attempt:${context.phase.id}`) {
  return { attemptId, output, phaseId: context.phase.id, runId: context.runId, schemaVersion: 1 };
}

test("closed registry rejects invalid graph identities, dependencies, cycles, types, and bindings", () => {
  const registry = new workflow.ClosedPhaseRegistry([
    type("root", {}, "value.v1"),
    type("sink", { input: "value.v1" }, "value.v1"),
  ]);
  assert.throws(
    () => new workflow.ClosedPhaseRegistry([type("root"), type("root")]),
    /Duplicate workflow phase type/u,
  );
  assert.throws(
    () => workflow.validateWorkflow({ id: "bad", version: 1, phases: [phase("same", "root"), phase("same", "root")] }, registry),
    /Duplicate workflow phase identity/u,
  );
  assert.throws(
    () => workflow.validateWorkflow({ id: "bad", version: 1, phases: [phase("sink", "sink", ["missing"], { input: { contract: "value.v1", from: "missing" } })] }, registry),
    /missing dependency/u,
  );
  assert.throws(
    () => workflow.validateWorkflow({ id: "bad", version: 1, phases: [phase("unknown", "foreign")] }, registry),
    /Unknown workflow phase type/u,
  );
  assert.throws(
    () => workflow.validateWorkflow({
      id: "bad",
      version: 1,
      phases: [
        phase("a", "sink", ["b"], { input: { contract: "value.v1", from: "b" } }),
        phase("b", "sink", ["a"], { input: { contract: "value.v1", from: "a" } }),
      ],
    }, registry),
    /dependency cycle/u,
  );
  assert.throws(
    () => workflow.validateWorkflow({
      id: "bad",
      version: 1,
      phases: [
        phase("source", "root"),
        phase("sink", "sink", ["source"], { input: { contract: "wrong.v1", from: "source" } }),
      ],
    }, registry),
    /contract-incompatible/u,
  );
});

test("scheduler executes deterministic fan-out/fan-in within its bound and admits duplicate delivery once", async () => {
  const registry = new workflow.ClosedPhaseRegistry([
    type("root", {}, "value.v1"),
    type("child", { input: "value.v1" }, "value.v1"),
    type("join", { left: "value.v1", right: "value.v1" }, "joined.v1"),
  ]);
  const definition = {
    id: "fanout",
    version: 1,
    phases: [
      phase("root", "root"),
      phase("left", "child", ["root"], { input: { contract: "value.v1", from: "root" } }),
      phase("right", "child", ["root"], { input: { contract: "value.v1", from: "root" } }),
      phase("join", "join", ["left", "right"], {
        left: { contract: "value.v1", from: "left" },
        right: { contract: "value.v1", from: "right" },
      }),
    ],
  };
  let active = 0;
  let peak = 0;
  const execute = async (context) => {
    active += 1;
    peak = Math.max(peak, active);
    await new Promise((resolve) => setTimeout(resolve, context.phase.type === "child" ? 10 : 1));
    active -= 1;
    const result = delivery(context);
    return context.phase.id === "left" ? [result, result] : result;
  };
  const result = await workflow.scheduleWorkflow({
    executors: { child: execute, join: execute, root: execute },
    maxParallel: 2,
    registry,
    runId: randomUUID(),
    workflow: workflow.validateWorkflow(definition, registry),
  });
  assert.equal(result.status, "completed");
  assert.equal(peak, 2);
  assert.deepEqual(result.states, { root: "completed", left: "completed", right: "completed", join: "completed" });
  assert.deepEqual(result.outputs.join, { value: "join" });
});

test("scheduler fails malformed work, skips dependents, preserves independent work, and cancels pending work", async () => {
  const registry = new workflow.ClosedPhaseRegistry([
    type("root", {}, "value.v1"),
    type("child", { input: "value.v1" }, "value.v1"),
  ]);
  const definition = workflow.validateWorkflow({
    id: "failure",
    version: 1,
    phases: [
      phase("root", "root"),
      phase("failed", "child", ["root"], { input: { contract: "value.v1", from: "root" } }),
      phase("independent", "child", ["root"], { input: { contract: "value.v1", from: "root" } }),
      phase("skipped", "child", ["failed"], { input: { contract: "value.v1", from: "failed" } }),
    ],
  }, registry);
  const failed = await workflow.scheduleWorkflow({
    executors: {
      root: async (context) => delivery(context),
      child: async (context) => context.phase.id === "failed"
        ? delivery(context, "free-form completion")
        : delivery(context),
    },
    maxParallel: 2,
    registry,
    runId: randomUUID(),
    workflow: definition,
  });
  assert.equal(failed.status, "failed");
  assert.equal(failed.states.failed, "failed");
  assert.equal(failed.states.independent, "completed");
  assert.equal(failed.states.skipped, "skipped");

  const controller = new AbortController();
  const canceled = await workflow.scheduleWorkflow({
    executors: {
      root: async (context) => {
        controller.abort();
        return delivery(context);
      },
      child: async (context) => delivery(context),
    },
    maxParallel: 1,
    registry,
    runId: randomUUID(),
    signal: controller.signal,
    workflow: definition,
  });
  assert.equal(canceled.status, "canceled");
  assert.deepEqual(Object.values(canceled.states), ["canceled", "canceled", "canceled", "canceled"]);
});

test("phase result validation rejects free-form, absent, malformed, and incompatible output before admission", () => {
  const admission = new workflow.PhaseResultAdmission();
  const expected = { outputSchema: z.object({ value: z.string() }).strict(), phaseId: "phase", runId: "run" };
  assert.throws(() => admission.admit("done", expected));
  assert.throws(() => admission.admit({ attemptId: "a", phaseId: "phase", runId: "run", schemaVersion: 1 }, expected));
  assert.throws(
    () => admission.admit(
      { attemptId: "a", phaseId: "phase", runId: "run", schemaVersion: 1 },
      { ...expected, outputSchema: z.unknown() },
    ),
    (error) => error.code === "CONTRACT_INCOMPATIBLE",
  );
  assert.throws(() => admission.admit({ attemptId: "a", output: { value: 1 }, phaseId: "phase", runId: "run", schemaVersion: 1 }, expected));
  assert.throws(
    () => admission.admit({ attemptId: "a", output: { value: "ok" }, phaseId: "other", runId: "run", schemaVersion: 1 }, expected),
    (error) => error.code === "CONTRACT_INCOMPATIBLE",
  );
  const valid = { attemptId: "a", output: { value: "ok" }, phaseId: "phase", runId: "run", schemaVersion: 1 };
  assert.deepEqual(admission.admit(valid, expected), { accepted: true, output: { value: "ok" } });
  assert.deepEqual(admission.admit(valid, expected), { accepted: false });
});

test("model input packages expose executable output schemas without unbound upstream outputs", () => {
  const outputs = {
    preflight: { reviewItemsTotal: 2 },
    "threat-model": { threatModel: { summary: "Synthetic repository trust boundaries." } },
    discovery: { candidates: [] },
    reduction: { findings: [] },
    validation: { validations: [] },
    "attack-path": { attackPaths: [] },
    reporting: {
      coverage: { completeness: "complete", surfaces: [], explicitExclusions: [], deferred: [] },
      findings: [],
    },
  };
  for (const current of workflow.FULL_REPOSITORY_WORKFLOW.phases.filter((entry) => entry.roleId)) {
    const input = workflow.assemblePhaseInputPackage({
      artifactRoot: "/synthetic/artifacts",
      evidenceReferences: [],
      outputs,
      phase: current,
      role: { instructions: "Return the phase result.", model: "fixture-model", provider: "fixture", thinking: "medium" },
      scanId: "synthetic-scan",
      runId: "synthetic-run",
      target: { path: "/synthetic/repository", revision: "fixture-revision" },
    });
    const contract = JSON.parse(JSON.stringify(input.outputContract));
    const schema = z.fromJSONSchema(contract.schema);
    assert.deepEqual(schema.parse(outputs[current.id]), outputs[current.id]);
    assert.equal(schema.safeParse({}).success, false);
    for (const [name, binding] of Object.entries(current.bindings)) {
      assert.deepEqual(input.requiredInputs[name], outputs[binding.from]);
    }
    assert.equal(Object.hasOwn(input.requiredInputs, "reporting"), false);
  }
});

test("invalid canonical report documents fail reporting without publication or output admission", async () => {
  let published = false;
  const executors = workflow.createBuiltInPhaseExecutors({
    prepareReviewItems: async () => ({ reviewItemsTotal: 0 }),
    publish: async () => { published = true; throw new Error("Invalid report reached publication."); },
    recordAttackPaths: async () => {},
    recordDiscovery: async () => {},
    recordValidations: async () => {},
  }, async (context) => delivery(context, {
    "attack-path": { attackPaths: [] },
    discovery: { candidates: [] },
    reduction: { findings: [] },
    reporting: { coverage: { surfaces: [] }, findings: [{}] },
    "threat-model": { threatModel: { summary: "Synthetic repository trust boundaries." } },
    validation: { validations: [] },
  }[context.phase.type]));
  const result = await workflow.scheduleWorkflow({
    executors,
    maxParallel: 3,
    registry: workflow.BUILT_IN_PHASE_REGISTRY,
    runId: randomUUID(),
    workflow: workflow.VALIDATED_FULL_REPOSITORY_WORKFLOW,
  });
  assert.equal(result.status, "failed");
  assert.equal(result.states.reporting, "failed");
  assert.equal(result.states.publication, "skipped");
  assert.equal(Object.hasOwn(result.outputs, "reporting"), false);
  assert.equal(published, false);
});

test("artifact publication seals a claimed scan before reading completed artifacts", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "pi-security-workflow-publication-"));
  const artifactRoot = join(root, "artifacts");
  const repoRoot = join(root, "repository");
  await Promise.all([mkdir(artifactRoot), mkdir(repoRoot)]);
  t.after(async () => {
    await rm(root, { force: true, recursive: true });
  });

  const scanId = randomUUID();
  const handoffClaimToken = randomUUID();
  const calls = [];
  const scan = {
    contract: {
      diffTarget: null,
      scope: {
        requiredExcludePaths: [],
        requiredIncludePaths: ["."],
      },
      target: {
        allowedKinds: ["git_worktree"],
        displayName: "workflow fixture",
        requiredSnapshotDigest: `pi-security-snapshot/v1:sha256:${"a".repeat(64)}`,
        targetId: "workflow_fixture",
      },
    },
    handoffClaimToken,
    mode: "standard",
    progress: { status: "running" },
    scanDir: artifactRoot,
    scanId,
    status: "running",
    targetPath: repoRoot,
    targetRevision: "fixture-revision",
  };
  const runWorkbench = async (arguments_) => {
    calls.push(arguments_);
    switch (arguments_[0]) {
      case "get-scan":
        return { scan };
      case "write-scan-draft":
        return {};
      case "complete-scan":
        throw new Error("completion rejected by workbench");
      default:
        throw new Error(`unexpected workbench operation: ${arguments_[0]}`);
    }
  };
  const services = workflow.createArtifactWorkflowServices({
    handoffClaimToken,
    packageRoot,
    runWorkbench,
    scanId,
  });

  await assert.rejects(
    services.publish({
      coverage: {
        completeness: "complete",
        deferred: [],
        explicitExclusions: [],
        surfaces: [],
      },
      findings: [],
    }),
    /completion rejected by workbench/u,
  );
  assert.deepEqual(
    calls.map(([operation]) => operation),
    ["get-scan", "write-scan-draft", "complete-scan"],
  );
  assert.deepEqual(calls[2], [
    "complete-scan",
    "--scan-id",
    scanId,
    "--claim-token",
    handoffClaimToken,
  ]);
});

test("synchronous executor failures do not abandon independent phases", async () => {
  const registry = new workflow.ClosedPhaseRegistry([
    type("root", {}, "value.v1"),
    type("child", { input: "value.v1" }),
  ]);
  const result = await workflow.scheduleWorkflow({
    executors: {
      root: (context) => {
        if (context.phase.id === "broken") throw new Error("Synthetic executor failure.");
        return Promise.resolve(delivery(context));
      },
      child: async (context) => delivery(context),
    },
    maxParallel: 2,
    registry,
    runId: randomUUID(),
    workflow: workflow.validateWorkflow({
      id: "sync-failure",
      version: 1,
      phases: [
        phase("broken", "root"),
        phase("independent", "root"),
        phase("dependent", "child", ["broken"], { input: { contract: "value.v1", from: "broken" } }),
      ],
    }, registry),
  });
  assert.equal(result.status, "failed");
  assert.deepEqual(result.states, { broken: "failed", independent: "completed", dependent: "skipped" });
  assert.equal(result.errors.broken, "Synthetic executor failure.");
  assert.deepEqual(result.outputs, { independent: { value: "independent" } });
});

test("progress observer failures cannot turn admitted output into failed work", async () => {
  const registry = new workflow.ClosedPhaseRegistry([type("root")]);
  const result = await workflow.scheduleWorkflow({
    executors: { root: async (context) => delivery(context) },
    maxParallel: 1,
    onStateChange: () => { throw new Error("Synthetic progress failure."); },
    registry,
    runId: randomUUID(),
    workflow: workflow.validateWorkflow({ id: "progress", version: 1, phases: [phase("root", "root")] }, registry),
  });
  assert.equal(result.status, "completed");
  assert.deepEqual(result.outputs, { root: { value: "root" } });
  assert.deepEqual(result.errors, {});
});

test("cancellation prevents starting another ready executor in the same scheduling wave", async () => {
  const registry = new workflow.ClosedPhaseRegistry([type("root")]);
  const controller = new AbortController();
  const started = [];
  const result = await workflow.scheduleWorkflow({
    executors: {
      root: async (context) => {
        started.push(context.phase.id);
        controller.abort();
        return delivery(context);
      },
    },
    maxParallel: 2,
    registry,
    runId: randomUUID(),
    signal: controller.signal,
    workflow: workflow.validateWorkflow({
      id: "cancel-wave", version: 1, phases: [phase("first", "root"), phase("second", "root")],
    }, registry),
  });
  assert.deepEqual(started, ["first"]);
  assert.equal(result.status, "canceled");
  assert.deepEqual(result.states, { first: "canceled", second: "canceled" });
  assert.deepEqual(result.outputs, {});
});

test("a late canceled model result cannot write discovery artifacts", async () => {
  const controller = new AbortController();
  const context = {
    inputs: {},
    phase: workflow.FULL_REPOSITORY_WORKFLOW.phases.find((entry) => entry.id === "discovery"),
    runId: randomUUID(),
    signal: controller.signal,
  };
  let release;
  let recorded = false;
  const modelResult = new Promise((resolve) => { release = resolve; });
  const executors = workflow.createBuiltInPhaseExecutors({
    recordDiscovery: async () => { recorded = true; },
  }, async () => modelResult);
  const execution = executors.discovery(context);
  controller.abort(new Error("Synthetic cancellation."));
  release(delivery(context, { candidates: [] }));
  await assert.rejects(execution, /Synthetic cancellation/u);
  assert.equal(recorded, false);
});

test("an accepted result remains terminal when a malformed duplicate follows", async () => {
  const registry = new workflow.ClosedPhaseRegistry([type("root")]);
  const result = await workflow.scheduleWorkflow({
    executors: {
      root: async (context) => [
        delivery(context),
        delivery(context, { value: 42 }),
      ],
    },
    maxParallel: 1,
    registry,
    runId: randomUUID(),
    workflow: workflow.validateWorkflow({ id: "duplicates", version: 1, phases: [phase("root", "root")] }, registry),
  });
  assert.equal(result.status, "completed");
  assert.deepEqual(result.outputs, { root: { value: "root" } });
  assert.deepEqual(result.errors, {});
});

test("result admission is independent across runs and ignores late completed-phase deliveries", () => {
  const admission = new workflow.PhaseResultAdmission();
  const expected = { outputSchema: z.object({ value: z.string() }), phaseId: "phase", runId: "run-a" };
  const envelope = { attemptId: "attempt", output: { value: "first" }, phaseId: "phase", runId: "run-a", schemaVersion: 1 };
  assert.deepEqual(admission.admit(envelope, expected), { accepted: true, output: { value: "first" } });
  assert.deepEqual(admission.admit({ ...envelope, output: null }, expected), { accepted: false });
  assert.deepEqual(
    admission.admit({ ...envelope, runId: "run-b", output: { value: "second" } }, { ...expected, runId: "run-b" }),
    { accepted: true, output: { value: "second" } },
  );
});

test("prototype-named phase identities retain outputs for their dependents", async () => {
  const registry = new workflow.ClosedPhaseRegistry([
    type("root", {}, "value.v1"),
    type("child", { input: "value.v1" }),
  ]);
  const result = await workflow.scheduleWorkflow({
    executors: {
      root: async (context) => delivery(context),
      child: async (context) => delivery(context, { value: context.inputs.input.value }),
    },
    maxParallel: 1,
    registry,
    runId: randomUUID(),
    workflow: workflow.validateWorkflow({
      id: "phase-identities",
      version: 1,
      phases: [
        phase("__proto__", "root"),
        phase("child", "child", ["__proto__"], { input: { contract: "value.v1", from: "__proto__" } }),
      ],
    }, registry),
  });
  assert.equal(result.status, "completed");
  assert.deepEqual(result.outputs.child, { value: "__proto__" });
  assert.deepEqual(JSON.parse(JSON.stringify(result.outputs))["__proto__"], { value: "__proto__" });
});

test("validated graph execution is isolated from later source definition mutation", async () => {
  const registry = new workflow.ClosedPhaseRegistry([
    type("root", {}, "value.v1"),
    type("child", { input: "value.v1" }),
  ]);
  const source = {
    id: "snapshot",
    version: 1,
    phases: [
      phase("root", "root"),
      phase("child", "child", ["root"], { input: { contract: "value.v1", from: "root" } }),
    ],
  };
  const validated = workflow.validateWorkflow(source, registry);
  source.phases[0].type = "unknown";
  source.phases[1].dependencies.length = 0;
  source.phases[1].bindings.input.from = "missing";
  source.phases.push(phase("extra", "unknown"));
  const result = await workflow.scheduleWorkflow({
    executors: {
      root: async (context) => delivery(context),
      child: async (context) => delivery(context, context.inputs.input),
    },
    maxParallel: 2,
    registry,
    runId: randomUUID(),
    workflow: validated,
  });
  assert.equal(result.status, "completed");
  assert.deepEqual(result.outputs.child, { value: "root" });
  assert.deepEqual(result.states, { root: "completed", child: "completed" });
});

test("inherited properties cannot satisfy required workflow bindings", () => {
  const registry = new workflow.ClosedPhaseRegistry([
    type("root", {}, "value.v1"),
    type("child", { toString: "value.v1" }),
  ]);
  assert.throws(() => workflow.validateWorkflow({
    id: "bindings",
    version: 1,
    phases: [phase("root", "root"), phase("child", "child", ["root"])],
  }, registry), /missing input binding/u);
});

test("executor configuration errors are detected before any phase starts", async () => {
  const registry = new workflow.ClosedPhaseRegistry([
    type("root", {}, "value.v1"),
    type("child", { input: "value.v1" }),
  ]);
  let started = false;
  await assert.rejects(workflow.scheduleWorkflow({
    executors: {
      root: async (context) => { started = true; return delivery(context); },
    },
    maxParallel: 1,
    registry,
    runId: randomUUID(),
    workflow: workflow.validateWorkflow({
      id: "executors",
      version: 1,
      phases: [
        phase("root", "root"),
        phase("child", "child", ["root"], { input: { contract: "value.v1", from: "root" } }),
      ],
    }, registry),
  }), /No workflow executor/u);
  assert.equal(started, false);
});

test("a registry cannot legitimize an unsupported phase version", () => {
  assert.throws(
    () => new workflow.ClosedPhaseRegistry([{ ...type("root"), version: 0 }]),
    /identity and version/u,
  );
});

test("persistence callback failure aborts and drains siblings without reporting durable completion", async () => {
  const registry = new workflow.ClosedPhaseRegistry([type("root")]);
  const definition = workflow.validateWorkflow({
    id: "persistence-failure",
    version: 1,
    phases: [phase("first", "root"), phase("sibling", "root")],
  }, registry);
  let siblingSettled = false;
  const settledStates = [];
  const changes = [];
  await assert.rejects(workflow.scheduleWorkflow({
    executors: {
      root: async (context) => {
        if (context.phase.id === "sibling") {
          await new Promise((resolve) => context.signal.addEventListener("abort", resolve, { once: true }));
          siblingSettled = true;
        }
        return delivery(context);
      },
    },
    maxParallel: 2,
    onPhaseSettled: async (_phase, state) => {
      settledStates.push(state);
      throw new Error("synthetic durable write failure");
    },
    onStateChange: (id, state) => changes.push([id, state]),
    registry,
    runId: randomUUID(),
    workflow: definition,
  }), /synthetic durable write failure/u);
  assert.equal(siblingSettled, true);
  assert.deepEqual(settledStates, ["completed"]);
  assert.equal(changes.some(([, state]) => state === "completed"), false);
});
