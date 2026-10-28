// Standard scan planning and deterministic report assembly: packets from threat-model surfaces, the reducer's
// accounting, the final-report.md outcome mapping, and assembled drafts the finalizer seals.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { build } from "esbuild";

const packageRoot = resolve(import.meta.dirname, "..");
const bundled = await build({
  bundle: true,
  stdin: {
    contents: ['export * from "./src/scan/standard.ts";', 'export { finalizeScan, validateContract } from "./src/contract/finalize.ts";'].join("\n"),
    resolveDir: packageRoot,
  },
  format: "esm",
  loader: { ".json": "json" },
  platform: "node",
  write: false,
});
const s = await import(`data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].contents).toString("base64")}`);
const schemaDir = join(packageRoot, "schemas");

test("planPackets covers every file once outside surfaces and reports surfaces that match nothing", () => {
  const files = ["README.md", "a/b", "a-b", "api/routes.py", "api/views/user.py", "api/viewsx.py", "lib/parse.c", "lib/util.c", "setup.py"];
  const plan = s.planPackets(files, [
    { id: "http", label: "HTTP API", description: "Routes reachable without login.", paths: ["api/views", "./api/routes.py"] },
    { id: "parser", label: "Parser", paths: ["lib/parse.c", "api/routes.py"] },
    { id: "ghost", label: "Ghost", paths: ["missing"] },
  ]);
  assert.deepEqual(plan.packets, [
    { id: "threat-model/http", label: "HTTP API", description: "Routes reachable without login.", files: ["api/routes.py", "api/views/user.py"] },
    { id: "threat-model/parser", label: "Parser", files: ["api/routes.py", "lib/parse.c"] },
    { id: "inventory/1", label: "Files at the top of the scope no threat-model surface covers", files: ["README.md", "a-b", "setup.py"] },
    { id: "inventory/2", label: "Files in a/ no threat-model surface covers", files: ["a/b"] },
    { id: "inventory/3", label: "Files in api/ no threat-model surface covers", files: ["api/viewsx.py"] },
    { id: "inventory/4", label: "Files in lib/ no threat-model surface covers", files: ["lib/util.c"] },
  ]);
  assert.deepEqual(plan.unmatched.map((surface) => surface.id), ["ghost"]);
  assert.deepEqual(s.planPackets(files, [{ id: "all", label: "All", paths: ["."] }]).packets.map((packet) => [packet.id, packet.files.length]), [["threat-model/all", 9]]);
  assert.throws(() => s.planPackets(files, [{ id: "x", label: "X", paths: ["a"] }, { id: "x", label: "Y", paths: ["b"] }]), /surface x more than once/);
});

test("checkReduction requires every candidate exactly once", () => {
  const ids = ["candidate-1", "candidate-2", "candidate-3"];
  const finding = (...candidateIds) => ({ candidateIds });
  s.checkReduction(ids, { findings: [finding("candidate-2", "candidate-1")], rejected: [{ candidateId: "candidate-3", reason: "test only" }] });
  assert.throws(() => s.checkReduction(ids, { findings: [finding("candidate-1", "candidate-2", "candidate-3", "candidate-9")], rejected: [] }), /unknown candidate candidate-9/);
  assert.throws(() => s.checkReduction(ids, { findings: [finding("candidate-1", "candidate-2")], rejected: [{ candidateId: "candidate-2", reason: "dup" }, { candidateId: "candidate-3", reason: "x" }] }), /candidate-2 a second time/);
  assert.throws(() => s.checkReduction(ids, { findings: [finding("candidate-1")], rejected: [] }), /candidate-2, candidate-3/);
});

test("recordFor takes only the requested candidate's record", () => {
  const update = (candidateId) => ({ candidateId, validation: { disposition: "reportable", id: candidateId } });
  assert.deepEqual(s.recordFor([update("candidate-1")], "validation", "candidate-1"), { disposition: "reportable", id: "candidate-1" });
  assert.throws(() => s.recordFor([update("candidate-1"), update("candidate-2")], "validation", "candidate-1"), /candidate-2 instead of only candidate-1/);
  assert.throws(() => s.recordFor([update("candidate-1"), update("candidate-1")], "validation", "candidate-1"), /got 2/);
  assert.throws(() => s.recordFor([], "validation", "candidate-1"), /got 0/);
});

const validation = (disposition, extra = {}) => ({
  disposition,
  method: "Static trace from the request handler to the shell call.",
  confidence: "high",
  confidence_rationale: "Direct source trace.",
  rubric: "source-to-sink",
  evidence: ["src/app.py:2 passes the parameter to os.system."],
  counterevidence_or_proof_gap: "",
  remaining_uncertainty: "",
  ...extra,
});
const attackPath = (decision, extra = {}) => ({
  decision,
  dataflow: "Query parameter to os.system.",
  reachability: "Any unauthenticated client.",
  counterevidence: "No sanitizer on the path.",
  impact: decision === "ignore" ? "ignore" : "high",
  likelihood: decision === "ignore" ? "ignore" : "high",
  severity: decision === "ignore" ? "ignore" : "high",
  severity_rationale: "Remote command execution.",
  change_conditions: "Lower if the route requires an administrator.",
  ...(decision === "deferred" ? { proof_gap: "Cannot tell whether the route is mounted." } : {}),
  ...extra,
});
const ok = (value) => ({ ok: true, value });
const failed = (error) => ({ ok: false, error });

test("findingOutcome applies the final-report.md mapping in order", () => {
  const cases = [
    [undefined, undefined, { kind: "unresolved", reason: "Validation did not run." }],
    [failed("timeout"), undefined, { kind: "unresolved", reason: "Validation did not complete: timeout" }],
    [ok(validation("deferred", { counterevidence_or_proof_gap: "Needs runtime proof." })), undefined, { kind: "deferred", reason: "Needs runtime proof." }],
    [ok(validation("deferred", { remaining_uncertainty: "Config unknown." })), undefined, { kind: "deferred", reason: "Config unknown." }],
    [ok(validation("not_applicable")), undefined, { kind: "not_applicable", reason: "Direct source trace." }],
    [ok(validation("suppressed", { counterevidence_or_proof_gap: "Input is a constant." })), undefined, { kind: "rejected", reason: "Input is a constant." }],
    [ok(validation("reportable")), undefined, { kind: "unresolved", reason: "Attack-path analysis did not run." }],
    [ok(validation("reportable")), failed("stalled"), { kind: "unresolved", reason: "Attack-path analysis did not complete: stalled" }],
    [ok(validation("reportable")), ok(attackPath("deferred")), { kind: "deferred", reason: "Cannot tell whether the route is mounted." }],
    [ok(validation("reportable")), ok(attackPath("ignore")), { kind: "rejected", reason: "Remote command execution." }],
    [ok(validation("reportable")), ok(attackPath("reportable")), { kind: "finding" }],
  ];
  for (const [v, a, expected] of cases) assert.deepEqual(s.findingOutcome(v, a), expected, JSON.stringify(expected));
});

const candidate = (id, path, line, summary = `Issue ${id}.`) => ({
  candidate_id: id,
  cwe_ids: ["CWE-78"],
  locations: [{ path, start_line: line, end_line: line, role: "sink" }],
  summary,
  evidence: "os.system(value)",
});
const reduced = (candidateIds, anchor, title) => ({
  candidateIds,
  ruleId: "command-injection.shell",
  identity: { anchor },
  title,
  summary: `${title} in the request handler.`,
  taxonomy: { category: "command-injection", cwe: ["CWE-78"] },
  locations: [{ path: "src/app.py", startLine: 2, endLine: 2, role: "sink" }],
  remediation: "Pass arguments as a list without a shell.",
});

function results(overrides = {}) {
  const plan = s.planPackets(["src/app.py", "src/admin.py", "docs/guide.md"], [{ id: "web", label: "Web handlers", paths: ["src"] }]);
  return {
    scanId: "scan_standard_001",
    producer: { name: "pi-security", version: "0.2.0" },
    startedAt: "2026-01-01T00:00:00Z",
    completedAt: "2026-01-01T00:10:00Z",
    target: { kind: "directory_snapshot", targetId: "target_sha256_test", displayName: "service", snapshotDigest: `pi-security-snapshot/v1:sha256:${"0".repeat(64)}` },
    scope: ".",
    threatModel: "# Threat model\n\nUnauthenticated clients reach the web handlers.",
    plan,
    discovery: new Map([["threat-model/web", ok(["candidate-a"])], ["inventory/1", ok([])]]),
    candidates: [candidate("candidate-a", "src/app.py", 2)],
    reduction: { findings: [reduced(["candidate-a"], "shell-call", "Command injection")], rejected: [] },
    validations: new Map([["candidate-a", ok(validation("reportable", { source: "request.args['cmd']", sink: "os.system", preconditions: "Route is mounted." }))]]),
    attackPaths: new Map([["candidate-a", ok(attackPath("reportable"))]]),
    ...overrides,
  };
}

function finalize(t, drafts) {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "pi-security-standard-")));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const scanDir = join(base, "scan");
  mkdirSync(scanDir);
  const sealed = s.finalizeScan(scanDir, { schemaDir, draftDocuments: drafts, env: {}, warn: () => {} });
  s.validateContract(scanDir, schemaDir);
  return { scanDir, ...sealed };
}

test("a fully resolved scan assembles to complete coverage the finalizer seals", (t) => {
  const drafts = s.assembleStandardDraft(results());
  const { scanDir, findings, coverage, manifest } = finalize(t, drafts);
  assert.equal(coverage.completeness, "complete");
  assert.equal(coverage.mode, "repository");
  assert.deepEqual(coverage.surfaces.map((surface) => [surface.id, surface.disposition]), [
    ["threat-model/web", "reported"],
    ["inventory/1", "no_issue_found"],
    ["candidate-a", "reported"],
  ]);
  const [finding] = findings.findings;
  assert.match(finding.findingId, /^.+$/);
  assert.deepEqual(finding.severity, { level: "high", rationale: "Remote command execution.", changeConditions: "Lower if the route requires an administrator." });
  assert.deepEqual(finding.confidence, { level: "high", rationale: "Direct source trace." });
  assert.deepEqual(finding.validation.counterEvidence, ["No sanitizer on the path."]);
  assert.deepEqual(finding.attackPath.dataflow, { summary: "Query parameter to os.system.", source: "request.args['cmd']", sink: "os.system" });
  assert.deepEqual(finding.attackPath.preconditions, ["Route is mounted."]);
  assert.deepEqual(finding.extensions, { candidateId: "candidate-a", candidateIds: ["candidate-a"] });
  assert.deepEqual(manifest.scan.threatModel, { summary: "# Threat model\n\nUnauthenticated clients reach the web handlers." });
  const report = readFileSync(join(scanDir, "report.md"), "utf8");
  assert.match(report, /Command injection/);
  assert.match(report, /Unauthenticated clients reach the web handlers/);
  assert.ok(existsSync(join(scanDir, "exports/results.sarif")));
});

test("unresolved, deferred, rejected, and failed work is honest partial coverage", (t) => {
  const candidates = ["a", "b", "c", "d", "e", "f"].map((letter, index) => candidate(`candidate-${letter}`, "src/app.py", index + 1));
  const drafts = s.assembleStandardDraft(
    results({
      plan: s.planPackets(["src/app.py", "docs/guide.md"], [
        { id: "web", label: "Web handlers", paths: ["src"] },
        { id: "queue", label: "Queue consumer", paths: ["worker"] },
      ]),
      discovery: new Map([["threat-model/web", ok(candidates.map((row) => row.candidate_id))], ["inventory/1", failed("worker stalled")]]),
      candidates,
      reduction: {
        findings: [
          reduced(["candidate-a", "candidate-b"], "shell-call", "Command injection"),
          reduced(["candidate-c"], "eval-call", "Code evaluation"),
          reduced(["candidate-d"], "debug-route", "Debug route"),
          reduced(["candidate-e"], "missing-validation", "Unvalidated input"),
        ],
        rejected: [{ candidateId: "candidate-f", reason: "Duplicate of the shell call with no new location." }],
      },
      validations: new Map([
        ["candidate-a", ok(validation("reportable"))],
        ["candidate-c", ok(validation("deferred", { counterevidence_or_proof_gap: "Needs the runtime configuration." }))],
        ["candidate-d", ok(validation("reportable"))],
      ]),
      attackPaths: new Map([
        ["candidate-a", ok(attackPath("reportable"))],
        ["candidate-d", ok(attackPath("ignore"))],
      ]),
    }),
  );
  const { coverage, findings } = finalize(t, drafts);
  assert.equal(findings.findings.length, 1);
  assert.equal(coverage.completeness, "partial");
  assert.deepEqual(coverage.surfaces.map((surface) => [surface.id, surface.disposition]), [
    ["threat-model/web", "reported"],
    ["inventory/1", "needs_follow_up"],
    ["threat-model/queue", "needs_follow_up"],
    ["candidate-a", "reported"],
    ["candidate-c", "needs_follow_up"],
    ["candidate-d", "rejected"],
    ["candidate-e", "needs_follow_up"],
    ["candidate-f", "rejected"],
  ]);
  assert.deepEqual(coverage.deferred.map((row) => [row.id, row.reason, row.surfaceIds]), [
    ["candidate-c", "Needs the runtime configuration.", ["threat-model/web"]],
    ["candidate-e", "Validation did not run.", ["threat-model/web"]],
  ]);
  assert.match(coverage.surfaces[1].notes, /Discovery did not complete: worker stalled/);
  assert.match(coverage.surfaces[2].notes, /worker/);
});

test("a scan with no candidates runs no reducer and can be complete", (t) => {
  const clean = s.assembleStandardDraft(
    results({ discovery: new Map([["threat-model/web", ok([])], ["inventory/1", ok([])]]), candidates: [], reduction: undefined, validations: new Map(), attackPaths: new Map() }),
  );
  const sealed = finalize(t, clean);
  assert.equal(sealed.coverage.completeness, "complete");
  assert.deepEqual(sealed.coverage.surfaces.map((surface) => surface.disposition), ["no_issue_found", "no_issue_found"]);
  assert.equal(sealed.findings.findings.length, 0);
});
