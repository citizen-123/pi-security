// TypeScript ports checked by tests/parity.test.mjs.
//
// tools: case tool name (argv[0] in tests/parity/cases/*/case.json) ->
//   async (args, { cwd }) => ({ status: "ok" | "rejected", stdout?: string | Buffer })
//   args are argv[1:] with placeholders already substituted. A port reports rejection instead of throwing.
//
// functions: recorded vector function name (tests/parity/vectors/<name>.jsonl) ->
//   (args) => result, where args is the recorded parameter object; throw to reproduce a recorded error.
//   Where Python raised ContractError, the port must throw an error with the same message.
//   Bytes are passed and returned as Buffer/Uint8Array.
//
// Register a port here as part of the change that adds it. Until then its cases and vectors are skipped.
import { build } from "esbuild";

import { existsSync, lstatSync, mkdirSync, mkdtempSync, realpathSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

/** Mirrors the test-module wrappers in tests/test_*_edges.py that turn file contents into a temporary directory. */
function withFiles(files, use) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "pi-security-parity-files-")));
  try {
    for (const [relative, content] of Object.entries(files)) {
      mkdirSync(dirname(join(root, relative)), { recursive: true });
      writeFileSync(join(root, relative), content);
    }
    return use(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

// One bundle for every port, so shared classes such as PyFloat have a single identity.
const ENTRIES = {
  identity: "src/contract/finding-identity.ts",
  candidates: "src/contract/candidates.ts",
  inventory: "src/target/inventory.ts",
  canonical: "src/contract/canonical-json.ts",
  pythonJson: "src/contract/python-json.ts",
  schema: "src/contract/schema.ts",
  sarif: "src/contract/sarif.ts",
  paths: "src/contract/contract-paths.ts",
  exportsModule: "src/contract/exports.ts",
  validation: "src/contract/validation.ts",
  recovery: "src/contract/recovery.ts",
  report: "src/contract/report-projection.ts",
  finalize: "src/contract/finalize.ts",
  patchRisk: "src/contract/patch-risk.ts",
  preflight: "src/config/preflight.ts",
};
const bundled = await build({
  bundle: true,
  stdin: {
    contents: Object.entries(ENTRIES).map(([name, entry]) => `export * as ${name} from "./${entry}";`).join("\n"),
    resolveDir: new URL("../..", import.meta.url).pathname,
  },
  format: "esm",
  platform: "node",
  write: false,
});
const { identity, candidates, inventory, canonical, pythonJson, schema, sarif, paths, exportsModule, validation, recovery, report, finalize, patchRisk, preflight } = await import(
  `data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].contents).toString("base64")}`
);

/** Vector files are Python json.dumps output: parse them keeping int versus float. */
export const parseVectorLine = (line) => pythonJson.parsePythonJson(line);

/** Minimal argparse: options with one value, or every value up to the next option for multi-value options. */
function parseOptions(args, multi = new Set(), flags = new Set()) {
  const options = {};
  for (let index = 0; index < args.length; index++) {
    const name = args[index].replace(/^--/, "");
    if (flags.has(name)) options[name] = true;
    else if (multi.has(name)) {
      options[name] = [];
      while (index + 1 < args.length && !args[index + 1].startsWith("--")) options[name].push(args[++index]);
    } else options[name] = args[++index];
  }
  return options;
}

function atomicWrite(path, bytes) {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}`;
  writeFileSync(temporary, bytes);
  renameSync(temporary, path);
}

export const tools = {
  // CLI shim over generateInventory, mirroring generate_in_scope_files.py main().
  generate_in_scope_files: async (args) => {
    try {
      const options = parseOptions(args);
      const repository = inventory.resolveRepository(options.repo);
      const scope = inventory.resolveScope(repository, options.scope);
      if (!options.out || options.out.includes("\0")) return { status: "rejected" };
      if (existsSync(options.out) && lstatSync(options.out).isSymbolicLink()) return { status: "rejected" };
      const output = resolve(options.out);
      if (existsSync(output) && !statSync(output).isFile()) return { status: "rejected" };
      const diff =
        options["diff-base"] === undefined
          ? undefined
          : { base: options["diff-base"], head: options["diff-head"] ?? "HEAD", mode: options["diff-mode"] ?? "revisions" };
      atomicWrite(output, inventory.generateInventory({ repository, scope, diff }).bytes);
      return { status: "ok" };
    } catch {
      return { status: "rejected" };
    }
  },
  // CLI shim over normalizeCandidateFiles, mirroring normalize_candidates.py main().
  normalize_candidates: async (args) => {
    try {
      const options = parseOptions(args, new Set(["input"]), new Set(["allow-missing-in-scope"]));
      const repoRoot = realpathSync(options["repo-root"]);
      if (!statSync(repoRoot).isDirectory()) return { status: "rejected" };
      const output = resolve(options.out);
      const scopePath = realpathSync(options["in-scope-files"]);
      const inputs = options.input.map((input) => realpathSync(input));
      if (inputs.includes(output) || output === scopePath) return { status: "rejected" };
      const result = candidates.normalizeCandidateFiles({
        inputs,
        repoRoot,
        scopePath,
        allowMissingInScope: options["allow-missing-in-scope"] === true,
      });
      atomicWrite(output, result.jsonl);
      return { status: "ok" };
    } catch {
      return { status: "rejected" };
    }
  },
};

const SCHEMA_DIR = join(new URL("../..", import.meta.url).pathname, "schemas");

/** Run a CLI body: "rejected" for any error, as a nonzero Python exit would be. */
async function cli(body) {
  try {
    return { status: "ok", stdout: (await body()) ?? "" };
  } catch {
    return { status: "rejected" };
  }
}

// CLI shim over finalize.ts, mirroring finalize_scan_contract.py main().
tools.finalize_scan_contract = (args) =>
  cli(() => {
    const options = parseOptions(args, new Set(), new Set(["sarif-only"]));
    const schemaDir = options["schema-dir"] ?? SCHEMA_DIR;
    const sourceRoot = options["source-root"];
    const format = options["export-format"];
    if (format !== undefined && !Object.hasOwn(finalize.EXPORT_PATHS, format)) throw new Error("invalid choice");
    if (options["sarif-only"] && format !== undefined) throw new Error("--sarif-only cannot be combined with --export-format");
    if (options["export-output"] !== undefined && format === undefined) throw new Error("--export-output requires --export-format");
    if (options["sarif-output"] !== undefined && !options["sarif-only"]) throw new Error("--sarif-output requires --sarif-only");
    if (format !== undefined) {
      const contents = finalize.buildFindingsExport(options["scan-dir"], format, schemaDir, sourceRoot);
      if (options["export-output"] === undefined) return contents;
      finalize.writeExportOutput(options["scan-dir"], options["export-output"], format, contents);
    } else if (options["sarif-only"]) {
      const sarif = finalize.buildSarifProjection(options["scan-dir"], schemaDir, sourceRoot);
      if (options["sarif-output"] === undefined) return canonical.jsonBytes(sarif);
      finalize.writeSarifOutput(options["scan-dir"], options["sarif-output"], sarif);
    } else {
      finalize.finalizeScan(options["scan-dir"], { schemaDir, sourceRoot, warn: () => {} });
    }
  });

// CLI shim over patch-risk.ts, mirroring validate_patch_risk_assessment.py main().
tools.validate_patch_risk_assessment = (args) =>
  cli(() => {
    if (args.length !== 1) throw new Error("expected one assessment path");
    const errors = patchRisk.validatePatchRiskAssessment(patchRisk.readPatchRiskAssessment(args[0]), join(SCHEMA_DIR, "patch-risk-assessment.schema.json"));
    if (errors.length > 0) throw new Error(errors.join("\n"));
  });

// CLI shim over preflight.ts, mirroring config_preflight.py main() (argparse: repeated --runtime-check appends).
tools.config_preflight = (args) =>
  cli(() => {
    let profile;
    let cwd = ".";
    const checks = [];
    for (let index = 0; index < args.length; index++) {
      const value = args[++index];
      if (value === undefined) throw new Error(`${args[index - 1]}: expected one argument`);
      if (args[index - 1] === "--profile") profile = value;
      else if (args[index - 1] === "--cwd") cwd = value;
      else if (args[index - 1] === "--runtime-check") checks.push(value);
      else throw new Error(`unrecognized arguments: ${args[index - 1]}`);
    }
    if (!preflight.PREFLIGHT_PROFILES.includes(profile)) throw new Error("--profile: invalid choice");
    return preflight.formatPreflightReport(preflight.evaluatePreflight(profile, cwd, checks));
  });

// CLI shim over validateContract, mirroring validate_scan_contract.py main().
tools.validate_scan_contract = (args) =>
  cli(() => {
    const options = parseOptions(args);
    const receipt = finalize.contractReceipt(finalize.validateContract(options["scan-dir"], SCHEMA_DIR));
    return `${pythonJson.dumpsPython(receipt, { sortKeys: true })}\n`;
  });

export const functions = {
  "finalize_scan_contract._json_bytes": ({ payload }) => canonical.jsonBytes(payload),
  "finalize_scan_contract._loads_json": ({ value }) => canonical.loadsJson(Buffer.isBuffer(value) ? value.toString("utf8") : value),
  "finalize_scan_contract._require_safe_json_value": ({ value, context, validate_strings }) =>
    canonical.requireSafeJsonValue(value, context, validate_strings) ?? null,
  "finalize_scan_contract._validate_schema_node": ({ value, schema: node, context, root_schema }) =>
    schema.validateSchemaNode(value, node, context, root_schema ?? undefined) ?? null,
  "finalize_scan_contract.validate_against_schema": ({ payload, schema_path }) =>
    schema.validateAgainstSchema(payload, schema_path) ?? null,
  "finalize_scan_contract._validate_date_time": ({ value, context }) => schema.validateDateTime(value, context) ?? null,
  "finalize_scan_contract.build_sarif": ({ manifest, findings, source_root }) =>
    sarif.buildSarif(manifest, findings, source_root ?? undefined),
  "finalize_scan_contract._sarif_label": ({ value }) => sarif.sarifLabel(value),
  "finalize_scan_contract._require_safe_relative_path": ({ value, context, allow_dot }) =>
    paths.requireSafeRelativePath(value, context, allow_dot),
  "finalize_scan_contract._require_portable_relative_path": ({ value, context, allow_dot }) =>
    paths.requirePortableRelativePath(value, context, allow_dot),
  "test_sarif_edges.github_line_hashes_of": ({ content, lines }) =>
    withFiles({ "source.txt": content }, (root) => {
      const hashes = sarif.githubLineHashesForSource(root, "source.txt", new Set(lines));
      return hashes === undefined ? [] : [...hashes].sort(([a], [b]) => a - b);
    }),
  "test_sarif_edges.sarif_with_source": ({ manifest, findings, files }) =>
    withFiles(files, (root) => sarif.buildSarif(manifest, findings, root)),
  "finalize_scan_contract.csv_cell": ({ value }) => exportsModule.csvCell(value),
  "finalize_scan_contract.finding_candidate_id": ({ finding }) => exportsModule.findingCandidateId(finding),
  "finalize_scan_contract.build_csv_projection": ({ findings, coverage }) => exportsModule.buildCsvProjection(findings, coverage),
  "finalize_scan_contract._validate_remote": ({ remote, context }) => validation.validateRemote(remote, context) ?? null,
  "finalize_scan_contract._validate_target": ({ target }) => validation.validateTarget(target) ?? null,
  "finalize_scan_contract._validate_location": ({ location, context }) => validation.validateLocation(location, context) ?? null,
  "finalize_scan_contract._validate_finding": ({ finding, context }) => validation.validateFinding(finding, context) ?? null,
  "finalize_scan_contract._validate_manifest": ({ manifest }) => validation.validateManifest(manifest) ?? null,
  "finalize_scan_contract._validate_findings": ({ manifest, findings }) => validation.validateFindings(manifest, findings) ?? null,
  "finalize_scan_contract._validate_completion_binding": ({ manifest, findings, coverage, completion_binding }) =>
    validation.validateCompletionBinding(manifest, findings, coverage, completion_binding) ?? null,
  "finalize_scan_contract._validate_contract_refs": ({ scan }) => validation.validateContractRefs(scan) ?? null,
  "finalize_scan_contract._legacy_sealed_findings_for_validation": ({ findings }) =>
    validation.legacySealedFindingsForValidation(findings),
  "finalize_scan_contract._validate_canonical_schemas_before_projection": ({ manifest, findings, coverage, schema_dir }) =>
    validation.validateCanonicalSchemasBeforeProjection(manifest, findings, coverage, schema_dir) ?? null,
  "report_projection.build_report_markdown": ({ manifest, findings_document, coverage }) =>
    report.buildReportMarkdown(manifest, findings_document, coverage),
  "report_projection.merged_root_cause": ({ value }) => report.mergedRootCause(value),
  "validate_patch_risk_assessment.validate": ({ value }) =>
    patchRisk.validatePatchRiskAssessment(value, join(SCHEMA_DIR, "patch-risk-assessment.schema.json")),
  "test_patch_risk_edges.read_assessment_text": ({ text, tmp_path }) => {
    writeFileSync(join(tmp_path, "assessment.json"), text);
    try {
      return patchRisk.readPatchRiskAssessment(join(tmp_path, "assessment.json"));
    } catch (error) {
      return { error: error.message };
    }
  },
  "finalize_scan_contract._finding_evidence_strength": ({ finding }) => recovery.findingEvidenceStrength(finding),
  "finalize_scan_contract._finding_strength": ({ finding }) => recovery.findingStrength(finding),
  "finalize_scan_contract._recover_unsealed_findings": ({ manifest, findings, schema_dir, scan_dir, warnings }) =>
    recovery.recoverUnsealedFindings(manifest, findings, schema_dir, scan_dir, warnings),
  "finalize_scan_contract._recover_unsealed_coverage": ({ coverage, schema_dir, scan_dir, warnings, discarded_findings }) =>
    recovery.recoverUnsealedCoverage(coverage, schema_dir, scan_dir, warnings, discarded_findings) ?? null,
  "finalize_scan_contract._recover_unsealed_hardening": ({ manifest, scan_dir, warnings }) =>
    recovery.recoverUnsealedHardening(manifest, scan_dir, warnings) ?? null,
  // Python passes manifest["scan"] as scan; decoded separately they would be two objects.
  "finalize_scan_contract._populate_unsealed_manifest_envelope": ({ manifest, completion_binding, $env }) =>
    recovery.populateUnsealedManifestEnvelope(manifest, manifest.scan, completion_binding, {
      env: { PI_SECURITY_STARTED_AT: $env.PI_SECURITY_STARTED_AT ?? undefined },
    }) ?? null,
  "finalize_scan_contract._populate_unsealed_target_binding": ({ target, target_binding }) =>
    recovery.populateUnsealedTargetBinding(target, target_binding) ?? null,
  "finalize_scan_contract._populate_unsealed_artifact_envelope": ({ manifest, findings, coverage, completion_binding }) =>
    recovery.populateUnsealedArtifactEnvelope(manifest, findings, coverage, completion_binding) ?? null,
  "finalize_scan_contract._normalize_unsealed_open_questions": ({ coverage }) => recovery.normalizeUnsealedOpenQuestions(coverage) ?? null,
  "finalize_scan_contract._normalize_unsealed_deep_repository_inventory_strategy": ({ coverage, expected_coverage_mode }) =>
    recovery.normalizeUnsealedDeepRepositoryInventoryStrategy(coverage, expected_coverage_mode) ?? null,
  "finalize_scan_contract._require_derived_writeup_files": ({ scan_dir, findings }) =>
    recovery.requireDerivedWriteupFiles(scan_dir, findings) ?? null,
  "finalize_scan_contract._require_hardening_portfolio_file": ({ scan_dir, scan }) =>
    recovery.requireHardeningPortfolioFile(scan_dir, scan) ?? null,
  "test_contract_validation_edges.validate_coverage_with_files": ({ manifest, coverage, files }) =>
    withFiles(files, (root) => {
      validation.validateCoverage(manifest, coverage, root);
      return coverage;
    }),
  "finalize_scan_contract._fingerprint": ({ target_id, finding }) => identity.fingerprint(target_id, finding),
  "finalize_scan_contract._stable_id": ({ prefix, parts }) => identity.stableId(prefix, ...parts),
  "finalize_scan_contract._derived_finding_identity_rows": ({ manifest, findings }) =>
    identity
      .deriveFindingIdentities(manifest, findings)
      .map((row) => [row.context, row.finding, row.findingId, row.occurrenceId, row.fingerprints]),
};
