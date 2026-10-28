// The security.scan Standard path end to end on a real Harness with pi-ai's faux provider: a synthetic repository is
// bound, inventoried, threat-modeled, discovered, reduced, validated, analyzed, assembled, and sealed; starting the run
// twice creates one orchestrator; a failed threat model fails the scan; a target edited mid-scan is not sealed.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { build } from "esbuild";

const packageRoot = resolve(import.meta.dirname, "..");
const outfile = join(packageRoot, "node_modules", ".cache", "pi-security-tests", "scan-task.mjs");
await build({
  bundle: true,
  stdin: {
    contents: [
      'export * from "./src/durable/scan-task.ts";',
      'export * from "./src/durable/worker.ts";',
      'export * from "./src/durable/scan-tools.ts";',
      'export * from "./src/durable/harness.ts";',
      'export * from "./src/durable/run-directory.ts";',
      'export { ROLE_INSTRUCTIONS } from "./src/scan/instructions.ts";',
      'export { validateContract } from "./src/contract/finalize.ts";',
      'export { ConfinedRoot } from "./src/target/confined-root.ts";',
      'export { createRegistry, defineExtension } from "@earendil-works/pi-durable";',
      'export { createModels } from "@earendil-works/pi-ai/models";',
      'export { fauxProvider, fauxAssistantMessage, fauxText, fauxToolCall } from "@earendil-works/pi-ai/providers/faux";',
    ].join("\n"),
    resolveDir: packageRoot,
  },
  format: "esm",
  loader: { ".json": "json" },
  outfile,
  packages: "external",
  platform: "node",
});
const d = await import(outfile);
const schemaDir = join(packageRoot, "schemas");

const ENV = { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.invalid", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.invalid" };
const git = (cwd, ...args) => assert.equal(spawnSync("git", ["-c", "init.defaultBranch=main", ...args], { cwd, env: ENV }).status, 0, `git ${args.join(" ")}`);

function workspace(t) {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "pi-security-scan-")));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const target = join(base, "service");
  mkdirSync(join(target, "src"), { recursive: true });
  mkdirSync(join(target, "docs"));
  writeFileSync(join(target, "src", "app.py"), "import os\nos.system(request.args['cmd'])\n");
  writeFileSync(join(target, "src", "util.py"), "def helper():\n    return 1\n");
  writeFileSync(join(target, "docs", "guide.md"), "# Guide\n");
  git(target, "init", "-q");
  git(target, "add", ".");
  git(target, "commit", "-qm", "synthetic");
  return { base, target, paths: d.runPaths(join(base, "state"), d.newRunId()) };
}

const MODEL = { provider: "faux", modelId: "faux-1" };
const ROLE_REPORTS = { threat_modeler: "threat_model", discoverer: "discover", reducer: "reduce", validator: "validate", attack_path_analyst: "attack_path" };
const roles = Object.fromEntries(Object.entries(ROLE_REPORTS).map(([id, report]) => [id, { id, report, model: MODEL, instructions: d.ROLE_INSTRUCTIONS[id] }]));

/** The worker's packet: the first user message of its conversation. */
function packetOf(request) {
  const first = request.messages.find((message) => message.role === "user");
  const text = typeof first.content === "string" ? first.content : first.content.map((part) => part.text ?? "").join("");
  const [task, ...json] = text.split("\n\n");
  return { task, body: JSON.parse(json.join("\n\n")) };
}

const call = (name, args) => d.fauxAssistantMessage([d.fauxToolCall(name, args)], { stopReason: "toolUse" });

/** A scripted model that answers every role; `hooks` override or observe a role's answer. */
function router(hooks = {}) {
  const calls = [];
  const step = (request) => {
    const { task, body } = packetOf(request);
    calls.push(task);
    if (task.startsWith("Model the threats")) {
      return hooks.threatModel?.() ?? call("report_threat_model", { content: "# Threat model\n\nRemote clients reach the web handlers in src/.", surfaces: [{ id: "web", label: "Web handlers", paths: ["src/app.py"] }] });
    }
    if (task.startsWith("Discover")) {
      hooks.discover?.(body);
      const candidates = body.packet.files.includes("src/app.py")
        ? [{ cwe_ids: ["CWE-78"], locations: [{ path: "src/app.py", start_line: 2, end_line: 2, role: "sink" }], summary: "Shell command built from a request argument.", evidence: "os.system(request.args['cmd'])" }]
        : [];
      return call("report_candidates", { candidates });
    }
    if (task.startsWith("Reduce")) {
      return call("report_reduction", {
        findings: [
          {
            candidateIds: body.candidates.map((candidate) => candidate.candidate_id),
            ruleId: "command-injection.shell",
            identity: { anchor: "request-cmd-shell" },
            title: "Command injection through the cmd argument",
            summary: "The cmd request argument reaches os.system.",
            taxonomy: { category: "command-injection", cwe: ["CWE-78"] },
            locations: [{ path: "src/app.py", startLine: 2, endLine: 2, role: "sink" }],
            remediation: "Run the command without a shell and allow only known values.",
          },
        ],
        rejected: [],
      });
    }
    if (task.startsWith("Validate")) {
      return call("report_validations", {
        validations: [
          {
            candidateId: body.primaryCandidateId,
            validation: {
              disposition: "reportable",
              method: "Source trace from the request argument to os.system.",
              confidence: "high",
              confidence_rationale: "Direct source trace with no sanitizer.",
              rubric: "source-to-sink",
              evidence: ["src/app.py:2 passes request.args['cmd'] to os.system."],
              counterevidence_or_proof_gap: "",
              remaining_uncertainty: "",
            },
          },
        ],
      });
    }
    if (task.startsWith("Analyze the attack path")) {
      return call("report_attack_paths", {
        attackPaths: [
          {
            candidateId: body.primaryCandidateId,
            attackPath: {
              decision: "reportable",
              dataflow: "request.args['cmd'] flows unchanged into os.system.",
              reachability: "Any client that can send the request.",
              counterevidence: "No allowlist or escaping on the path.",
              impact: "high",
              likelihood: "high",
              severity: "high",
              severity_rationale: "Remote command execution as the service user.",
              change_conditions: "Lower if the route requires an administrator.",
            },
          },
        ],
      });
    }
    throw new Error(`unexpected packet: ${task}`);
  };
  return { calls, steps: Array.from({ length: 200 }, () => step) };
}

async function open(paths, target, steps) {
  const holder = {};
  const tools = d.createScanTools({ confined: d.ConfinedRoot.open(target) });
  const worker = d.createWorkerTask({ tools, resolveAgent: async (id, context) => (await holder.run.harness.conversation(id, context)).agent(context) });
  const scan = d.createScanTask({ worker, schemaDir });
  const models = d.createModels();
  const faux = d.fauxProvider();
  models.setProvider(faux.provider);
  faux.setResponses(steps);
  const registry = d.createRegistry();
  registry.install(tools.extension);
  registry.install(d.defineExtension({ name: "pi-security-tasks", tasks: [worker, scan] }));
  holder.run = await d.openRun(paths, { models, registry, settings: { extensions: [] } });
  return { run: holder.run, scan };
}

const input = (target, paths) => ({ scanId: "scan_e2e_001", target, scope: ".", scanDir: paths.scan, producer: { name: "pi-security", version: "0.2.0" }, roles });

test("a Standard scan runs every phase and seals a valid scan directory", async (t) => {
  const { target, paths } = workspace(t);
  const model = router();
  const { run, scan } = await open(paths, target, model.steps);
  t.after(() => run.close());
  const id = await d.startScan(run.harness, scan, input(target, paths), d.RUN_CONTEXT);
  assert.equal(await d.startScan(run.harness, scan, input(target, paths), d.RUN_CONTEXT), id, "starting twice finds the same orchestrator");
  run.harness.resume();
  const settled = await run.harness.waitForTask(id, d.RUN_CONTEXT);
  assert.equal(settled.state.outcome.status, "completed", JSON.stringify(settled.state.outcome));
  assert.deepEqual(settled.state.outcome.result, { scanDir: paths.scan, findings: 1, completeness: "complete" });
  assert.deepEqual(
    model.calls.map((task) => task.split(" ")[0]).sort(),
    ["Analyze", "Discover", "Discover", "Discover", "Model", "Reduce", "Validate"],
    "one threat model, one discovery per packet (web, docs/, src/ leftovers), one reducer, validator, and analyst",
  );

  const contract = d.validateContract(paths.scan, schemaDir);
  const [finding] = contract.findings.findings;
  assert.equal(finding.title, "Command injection through the cmd argument");
  assert.equal(finding.severity.level, "high");
  assert.equal(contract.manifest.scan.target.kind, "git_worktree");
  assert.deepEqual(contract.coverage.surfaces.map((surface) => [surface.id, surface.disposition]), [
    ["threat-model/web", "reported"],
    ["inventory/1", "no_issue_found"],
    ["inventory/2", "no_issue_found"],
    [finding.extensions.candidateId, "reported"],
  ]);
  assert.match(readFileSync(join(paths.scan, "report.md"), "utf8"), /Remote clients reach the web handlers/);
});

test("a threat model that never reports fails the scan", async (t) => {
  const { target, paths } = workspace(t);
  const model = router({ threatModel: () => d.fauxAssistantMessage([d.fauxText("No surfaces.")]) });
  const { run, scan } = await open(paths, target, model.steps);
  t.after(() => run.close());
  const id = await d.startScan(run.harness, scan, input(target, paths), d.RUN_CONTEXT);
  run.harness.resume();
  const outcome = (await run.harness.waitForTask(id, d.RUN_CONTEXT)).state.outcome;
  assert.equal(outcome.status, "failed");
  assert.match(outcome.error.message, /threat model failed: worker ended without a threat_model result/);
});

test("a target edited during the scan is not sealed", async (t) => {
  const { target, paths } = workspace(t);
  const model = router({ discover: () => writeFileSync(join(target, "src", "util.py"), "def helper():\n    return 2\n") });
  const { run, scan } = await open(paths, target, model.steps);
  t.after(() => run.close());
  const id = await d.startScan(run.harness, scan, input(target, paths), d.RUN_CONTEXT);
  run.harness.resume();
  const outcome = (await run.harness.waitForTask(id, d.RUN_CONTEXT)).state.outcome;
  assert.equal(outcome.status, "failed");
  assert.match(outcome.error.message, /changed while it was being scanned/);
});
