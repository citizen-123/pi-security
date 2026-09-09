import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
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

const freshCandidate = {
  cwe_ids: ["cwe-079", "CWE-79"],
  locations: [
    { path: "src/handler.ts", start_line: 1, role: "source" },
    { path: "src/handler.ts", start_line: 2, role: "sink" },
  ],
  summary: "Request content reaches an HTML response.",
  evidence: "The handler sends the request parameter without escaping.",
};
const preparedOutputs = {
  preflight: { reviewItemsTotal: 1 },
  "threat-model": { threatModel: { summary: "An untrusted HTTP request crosses the HTML response boundary." } },
};
const preparedStates = { preflight: "completed", "threat-model": "completed" };
const workflowWithoutPublication = workflow.validateWorkflow({
  ...workflow.FULL_REPOSITORY_WORKFLOW,
  phases: workflow.FULL_REPOSITORY_WORKFLOW.phases.filter((entry) => entry.id !== "publication"),
}, workflow.BUILT_IN_PHASE_REGISTRY);

async function workflowArtifactFixture(t) {
  const root = await realpath(await mkdtemp(path.join(tmpdir(), "pi-security-workflow-artifacts-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  const repoRoot = path.join(root, "repository");
  const scanRoot = path.join(root, "scan");
  const discoveryRoot = path.join(scanRoot, "artifacts", "02_discovery");
  await Promise.all([
    mkdir(path.join(repoRoot, "src"), { recursive: true, mode: 0o700 }),
    mkdir(discoveryRoot, { recursive: true, mode: 0o700 }),
  ]);
  await Promise.all([
    writeFile(path.join(repoRoot, "src", "handler.ts"), "const input = request.query.name;\nresponse.send(input);\n", { mode: 0o600 }),
    writeFile(path.join(discoveryRoot, "in_scope_files.txt"), "src/handler.ts\n", { mode: 0o600 }),
  ]);
  const scanId = randomUUID();
  const services = workflow.createArtifactWorkflowServices({
    packageRoot,
    scanId,
    runWorkbench: async (args) => {
      assert.deepEqual(args, ["get-scan", "--scan-id", scanId]);
      return { scanId, scanDir: scanRoot, status: "running", targetPath: repoRoot, mode: "standard" };
    },
  });
  return {
    ledgerPath: path.join(discoveryRoot, "candidate_ledger.jsonl"),
    services,
  };
}

function validationRecord(disposition) {
  return {
    disposition,
    method: "Static source-to-sink trace.",
    confidence: "high",
    confidence_rationale: "The request and response are directly connected.",
    rubric: "The source is untrusted and the response is an HTML sink.",
    evidence: freshCandidate.evidence,
    counterevidence_or_proof_gap: "No escaping is present.",
    remaining_uncertainty: "",
  };
}

test("models supply fresh discovery candidates and select canonical IDs without copying evidence", () => {
  const current = workflow.FULL_REPOSITORY_WORKFLOW.phases.find((entry) => entry.id === "discovery");
  const input = workflow.assemblePhaseInputPackage({
    artifactRoot: "/synthetic/artifacts",
    evidenceReferences: [],
    outputs: preparedOutputs,
    phase: current,
    role: { instructions: "Find candidates.", model: "fixture-model", provider: "fixture", thinking: "medium" },
    scanId: "synthetic-scan",
    runId: "synthetic-run",
    target: { path: "/synthetic/repository", revision: null },
  });
  const emittedSchema = z.fromJSONSchema(input.outputContract.schema);
  assert.equal(emittedSchema.safeParse({ candidates: [freshCandidate] }).success, true);
  assert.equal(emittedSchema.safeParse({
    candidates: [{ ...freshCandidate, candidate_id: "model-invented" }],
  }).success, false);
  assert.equal(workflow.BUILT_IN_PHASE_REGISTRY.get("discovery", 1).outputSchema.safeParse({
    candidates: [freshCandidate],
  }).success, false);
  assert.equal(workflow.BUILT_IN_PHASE_REGISTRY.get("reduction", 1).outputSchema.safeParse({
    findings: [{ candidate_id: "model-invented" }],
  }).success, false);
  const selectionSchema = workflow.modelPhaseOutputSchema("reduction", 1);
  assert.equal(selectionSchema.safeParse({
    findings: [{ candidate_id: "existing-canonical-candidate" }],
  }).success, true);
  assert.equal(selectionSchema.safeParse({
    findings: [{ ...freshCandidate, candidate_id: "existing-canonical-candidate" }],
  }).success, false);
});

test("normalized candidates survive reduction and resume with persisted identities and evidence through reporting", async (t) => {
  const fixture = await workflowArtifactFixture(t);
  const runId = randomUUID();
  const first = await workflow.scheduleWorkflow({
    executors: workflow.createBuiltInPhaseExecutors(fixture.services, async (context) => {
      if (context.phase.type === "discovery") {
        return delivery(context, { candidates: [
          freshCandidate,
          { ...freshCandidate, evidence: "A second review confirms the same unescaped response." },
          { ...freshCandidate, instance: "alternate-route" },
        ] });
      }
      assert.equal(context.phase.type, "reduction");
      const rows = (await readFile(fixture.ledgerPath, "utf8")).trim().split("\n").map((line) => JSON.parse(line));
      assert.deepEqual(context.inputs.discovery.candidates, rows);
      assert.equal(rows.length, 2);
      for (const row of rows) {
        assert.equal(typeof row.candidate_id, "string");
        assert.deepEqual(row.cwe_ids, ["CWE-79"]);
        assert.equal(row.locations.every((location) => location.end_line === location.start_line), true);
      }
      return delivery(context, { findings: [{ candidate_id: rows[0].candidate_id }] });
    }),
    initialOutputs: preparedOutputs,
    initialStates: preparedStates,
    maxParallel: 3,
    registry: workflow.BUILT_IN_PHASE_REGISTRY,
    runId,
    workflow: workflow.validateWorkflow({
      ...workflow.FULL_REPOSITORY_WORKFLOW,
      phases: workflow.FULL_REPOSITORY_WORKFLOW.phases.filter((entry) =>
        ["preflight", "threat-model", "discovery", "reduction"].includes(entry.id)),
    }, workflow.BUILT_IN_PHASE_REGISTRY),
  });
  assert.equal(first.status, "completed", JSON.stringify(first.errors));
  const canonical = first.outputs.discovery.candidates;
  assert.deepEqual(first.outputs.reduction.findings, [canonical[0]]);
  const selected = first.outputs.reduction.findings[0];
  const snapshot = JSON.stringify(first.outputs);
  const resumedOutputs = JSON.parse(snapshot);
  const resumed = await workflow.scheduleWorkflow({
    executors: workflow.createBuiltInPhaseExecutors(fixture.services, async (context) => {
      assert.deepEqual(context.inputs.discovery.candidates, canonical);
      if (context.phase.type === "validation") {
        assert.deepEqual(context.inputs.reduction.findings, [selected]);
        return delivery(context, {
          validations: context.inputs.discovery.candidates.map((candidate) => ({
            candidateId: candidate.candidate_id,
            validation: validationRecord(candidate.candidate_id === selected.candidate_id ? "reportable" : "suppressed"),
          })),
        });
      }
      if (context.phase.type === "attack-path") {
        assert.deepEqual(context.inputs.validation.validations.map((update) => update.candidateId), canonical.map((candidate) => candidate.candidate_id));
        return delivery(context, { attackPaths: [{
          candidateId: selected.candidate_id,
          attackPath: {
            decision: "reportable",
            dataflow: selected.evidence,
            reachability: "The HTTP handler sends the supplied request parameter.",
            counterevidence: "No escaping control is present.",
            impact: "high",
            likelihood: "medium",
            severity: "high",
            severity_rationale: "Untrusted markup crosses the response boundary.",
            change_conditions: "Contextual output escaping would remove the issue.",
          },
        }] });
      }
      assert.equal(context.phase.type, "reporting", "Completed discovery and reduction must not rerun on resume.");
      assert.deepEqual(context.inputs.reduction.findings, [selected]);
      assert.equal(context.inputs.attackPaths.attackPaths[0].candidateId, selected.candidate_id);
      assert.equal(context.inputs.validation.validations.length, canonical.length);
      return delivery(context, {
        coverage: { completeness: "complete", surfaces: [], explicitExclusions: [], deferred: [] },
        findings: [{
          ruleId: "xss.unescaped-response",
          title: "Unescaped request content",
          summary: selected.summary,
          severity: { level: "high" },
          confidence: { level: "high", rationale: selected.evidence },
          taxonomy: { category: "xss", cwe: selected.cwe_ids },
          locations: selected.locations.map((location) => ({
            path: location.path, startLine: location.start_line, endLine: location.end_line,
          })),
          remediation: "Escape request content before rendering.",
          provenance: { source: "local_package", candidateId: selected.candidate_id },
        }],
      });
    }),
    initialOutputs: resumedOutputs,
    initialStates: first.states,
    maxParallel: 3,
    registry: workflow.BUILT_IN_PHASE_REGISTRY,
    runId,
    workflow: workflowWithoutPublication,
  });
  assert.equal(resumed.status, "completed", JSON.stringify(resumed.errors));
  const persisted = (await readFile(fixture.ledgerPath, "utf8")).trim().split("\n").map((line) => JSON.parse(line));
  assert.deepEqual(persisted.map(({ validation, attack_path, ...candidate }) => candidate), canonical);
  assert.deepEqual(persisted.map((candidate) => candidate.validation.disposition), ["reportable", "suppressed"]);
  assert.deepEqual(persisted[0].attack_path, resumed.outputs["attack-path"].attackPaths[0].attackPath);
  assert.equal(resumed.outputs.reporting.findings[0].provenance.candidateId, persisted[0].candidate_id);
  assert.equal(JSON.stringify(first.outputs), snapshot);
  assert.equal(JSON.stringify(resumedOutputs), snapshot);
  assert.deepEqual(resumed.outputs.discovery, first.outputs.discovery);
});

test("reduction rejects unknown and duplicate canonical selections without changing the ledger", async (t) => {
  const fixture = await workflowArtifactFixture(t);
  const discovery = await fixture.services.recordDiscovery({
    candidates: [freshCandidate, { ...freshCandidate, instance: "alternate-route" }],
  });
  const before = await readFile(fixture.ledgerPath, "utf8");
  const candidate = discovery.candidates[0];
  const context = {
    inputs: { discovery },
    phase: workflow.FULL_REPOSITORY_WORKFLOW.phases.find((entry) => entry.id === "reduction"),
    runId: randomUUID(),
    signal: new AbortController().signal,
  };
  for (const [findings, expected] of [
    [[{ candidate_id: "model-invented" }], /unknown candidate model-invented/u],
    [[{ candidate_id: candidate.candidate_id }, { candidate_id: candidate.candidate_id }], /repeats candidate/u],
  ]) {
    const executors = workflow.createBuiltInPhaseExecutors(fixture.services, async (execution) =>
      delivery(execution, { findings }));
    await assert.rejects(executors.reduction(context), expected);
    assert.equal(await readFile(fixture.ledgerPath, "utf8"), before);
  }
});

test("empty normalized discovery completes validation, attack paths, and reporting without fabricated candidates", async (t) => {
  const fixture = await workflowArtifactFixture(t);
  const result = await workflow.scheduleWorkflow({
    executors: workflow.createBuiltInPhaseExecutors(fixture.services, async (context) => delivery(context, {
      discovery: { candidates: [] },
      reduction: { findings: [] },
      validation: { validations: [] },
      "attack-path": { attackPaths: [] },
      reporting: {
        coverage: { completeness: "complete", surfaces: [], explicitExclusions: [], deferred: [] },
        findings: [],
      },
    }[context.phase.type])),
    initialOutputs: preparedOutputs,
    initialStates: preparedStates,
    maxParallel: 3,
    registry: workflow.BUILT_IN_PHASE_REGISTRY,
    runId: randomUUID(),
    workflow: workflowWithoutPublication,
  });
  assert.equal(result.status, "completed", JSON.stringify(result.errors));
  assert.equal(await readFile(fixture.ledgerPath, "utf8"), "");
  assert.deepEqual(result.outputs.discovery, { candidates: [] });
  assert.deepEqual(result.outputs.validation, { validations: [] });
  assert.deepEqual(result.outputs.reporting.findings, []);
});

test("invalid canonical report documents fail reporting without publication or output admission", async () => {
  let published = false;
  const executors = workflow.createBuiltInPhaseExecutors({
    prepareReviewItems: async () => ({ reviewItemsTotal: 0 }),
    publish: async () => { published = true; throw new Error("Invalid report reached publication."); },
    recordAttackPaths: async () => {},
    recordDiscovery: async () => ({ candidates: [] }),
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
    recordDiscovery: async () => { recorded = true; return { candidates: [] }; },
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
