import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
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
  assert.throws(() => admission.admit({ attemptId: "a", output: { value: 1 }, phaseId: "phase", runId: "run", schemaVersion: 1 }, expected));
  assert.throws(
    () => admission.admit({ attemptId: "a", output: { value: "ok" }, phaseId: "other", runId: "run", schemaVersion: 1 }, expected),
    (error) => error.code === "CONTRACT_INCOMPATIBLE",
  );
  const valid = { attemptId: "a", output: { value: "ok" }, phaseId: "phase", runId: "run", schemaVersion: 1 };
  assert.deepEqual(admission.admit(valid, expected), { accepted: true, output: { value: "ok" } });
  assert.deepEqual(admission.admit(valid, expected), { accepted: false });
});

test("built-in workflow snapshot, explicit inputs, and fake-agent adapters preserve canonical artifacts", async () => {
  assert.deepEqual(
    workflow.FULL_REPOSITORY_WORKFLOW.phases.map((entry) => [entry.id, entry.type, entry.roleId ?? null]),
    [
      ["preflight", "preflight", null],
      ["threat-model", "threat-model", "threat_modeler"],
      ["discovery", "discovery", "discoverer"],
      ["reduction", "reduction", "reducer"],
      ["validation", "validation", "validator"],
      ["attack-path", "attack-path", "attack_path_analyst"],
      ["reporting", "reporting", "reporter"],
      ["publication", "publication", null],
    ],
  );
  const discovery = workflow.FULL_REPOSITORY_WORKFLOW.phases.find((entry) => entry.id === "discovery");
  const input = workflow.assemblePhaseInputPackage({
    artifactRoot: "/synthetic/artifacts",
    evidenceReferences: ["artifacts/01_threat_model.json"],
    outputs: {
      preflight: { reviewItemsTotal: 2 },
      "threat-model": { threatModel: { surfaces: [] } },
    },
    phase: discovery,
    role: { instructions: "Discover candidates.", model: "fixture-model", provider: "fixture", thinking: "medium" },
    scanId: "synthetic-scan",
    runId: "synthetic-run",
    target: { path: "/synthetic/repository", revision: "fixture-revision" },
  });
  assert.deepEqual(Object.keys(input.requiredInputs), ["inventory", "threatModel"]);
  assert.equal(input.role.model, "fixture-model");
  assert.equal(JSON.stringify(input).includes("transcript"), false);

  const calls = [];
  const artifacts = {
    coverage: "coverage.json",
    findings: "findings.json",
    manifest: "scan-manifest.json",
    report: "report.md",
    sarif: "exports/results.sarif",
  };
  const services = {
    prepareReviewItems: async () => ({ reviewItemsTotal: 2 }),
    publish: async (report) => {
      calls.push(["publication", report]);
      return { artifacts };
    },
    recordAttackPaths: async (output) => calls.push(["attack-path", output]),
    recordDiscovery: async (output) => calls.push(["discovery", output]),
    recordValidations: async (output) => calls.push(["validation", output]),
  };
  const outputByType = {
    "attack-path": { attackPaths: [] },
    discovery: { candidates: [] },
    reduction: { findings: [] },
    reporting: { coverage: { surfaces: [] }, findings: [], threatModel: { surfaces: [] } },
    "threat-model": { threatModel: { surfaces: [] } },
    validation: { validations: [] },
  };
  const runId = randomUUID();
  const executors = workflow.createBuiltInPhaseExecutors(services, async (context) =>
    delivery(context, outputByType[context.phase.type])
  );
  const result = await workflow.scheduleWorkflow({
    executors,
    maxParallel: 3,
    registry: workflow.BUILT_IN_PHASE_REGISTRY,
    runId,
    workflow: workflow.VALIDATED_FULL_REPOSITORY_WORKFLOW,
  });
  assert.equal(result.status, "completed");
  assert.deepEqual(result.outputs.publication, { artifacts });
  assert.deepEqual(calls.map(([kind]) => kind), ["discovery", "validation", "attack-path", "publication"]);
});
