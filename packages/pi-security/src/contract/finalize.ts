// Scan finalization: populate and recover an unsealed draft, validate it, seal it with artifact digests, and write the
// canonical documents, report, and SARIF projection. Also the sealed-scan readers behind exports and contract
// validation. Port of _artifact_record through finalize_scan in scripts/finalize_scan_contract.py and of
// validate_contract/receipt in scripts/validate_scan_contract.py.
import { closeSync, fstatSync, lstatSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { contractJsonBytes, jsonBytes, sha256Bytes } from "./canonical-json.js";
import { requirePortableRelativePath } from "./contract-paths.js";
import { ContractError, isJsonObject, requireArray, requireObject, requireString, type JsonObject } from "./contract-error.js";
import { populateFindingIdentities, validateFindingIdentities } from "./finding-identity.js";
import { compareCodePoints, deepCopyJson } from "./python-json.js";
import {
  normalizeUnsealedDeepRepositoryInventoryStrategy,
  normalizeUnsealedOpenQuestions,
  populateUnsealedArtifactEnvelope,
  populateUnsealedManifestEnvelope,
  recoverUnsealedCoverage,
  recoverUnsealedFindings,
  recoverUnsealedHardening,
  requireDerivedWriteupFiles,
  requireHardeningPortfolioFile,
  type EnvelopeOptions
} from "./recovery.js";
import { generateReportMarkdown } from "./report-projection.js";
import { buildCsvProjection } from "./exports.js";
import { buildSarif, validateSarif } from "./sarif.js";
import { openScanLocalFile, readScanLocalJsonBytes, requireScanDirectory, requireScanLocalFile, sha256ScanLocalFile } from "./scan-files.js";
import { removeScanLocalFileIfExists, writeScanLocalBytes, writeScanLocalJson } from "./scan-writes.js";
import { validateAgainstSchema } from "./schema.js";
import {
  legacySealedFindingsForValidation,
  SCHEMA_VERSION,
  validateCanonicalSchemasBeforeProjection,
  validateCompletionBinding,
  validateContractRefs,
  validateCoverage,
  validateFindings,
  validateManifest,
  validateTarget,
  type CompletionBinding
} from "./validation.js";

export const EXPORT_PATHS = { csv: "exports/findings.csv", json: "exports/findings.json", sarif: "exports/results.sarif" } as const;
export type ExportFormat = keyof typeof EXPORT_PATHS;

const errorCode = (error: unknown) => (error as NodeJS.ErrnoException | undefined)?.code;
const isExportFormat = (value: string): value is ExportFormat => Object.hasOwn(EXPORT_PATHS, value);

/** Lexical containment: `path` equals or lies below `root` (both absolute). */
function lexicallyInside(root: string, path: string): string | undefined {
  const inside = relative(root, path);
  if (inside === "") return ".";
  if (isAbsolute(inside) || inside.split(sep)[0] === "..") return undefined;
  return inside.split(sep).join("/");
}

/** _validate_scan_local_output_path */
function validateScanLocalOutputPath(scanDir: string, path: string, relativePath: string): void {
  const parent = dirname(path);
  let resolvedParent: string;
  try {
    resolvedParent = realpathSync(parent);
  } catch {
    throw new ContractError(`${relativePath}: expected a path inside the scan directory`);
  }
  if (lexicallyInside(scanDir, resolvedParent) === undefined) {
    throw new ContractError(`${relativePath}: expected a path inside the scan directory`);
  }
  let metadata;
  try {
    metadata = lstatSync(path);
  } catch {
    // Missing: fine.
  }
  if (resolvedParent !== parent || metadata?.isSymbolicLink()) {
    throw new ContractError(`${relativePath}: expected a non-symlink path inside the scan directory`);
  }
  if (metadata !== undefined && !metadata.isFile()) throw new ContractError(`${relativePath}: expected a regular file`);
}

/** _generate_report_projection: projection errors become contract errors. */
function generateReportProjection(manifest: JsonObject, findings: JsonObject, coverage: JsonObject): Buffer {
  try {
    return generateReportMarkdown(manifest, findings, coverage);
  } catch (error) {
    if ((error as Error).name === "ReportProjectionError" || (error as Error).message.startsWith("'utf-8' codec")) {
      throw new ContractError(`report projection failed: ${(error as Error).message}`);
    }
    throw error;
  }
}

type ArtifactRecord = { mediaType: string; path: string; sha256: string };

function artifactRecord(scanDir: string, relativePath: string, mediaType: string, contents?: Uint8Array): ArtifactRecord {
  const path = requirePortableRelativePath(relativePath, "artifact path");
  if (contents !== undefined) validateScanLocalOutputPath(scanDir, join(scanDir, ...path.split("/")), path);
  return { mediaType, path, sha256: contents !== undefined ? sha256Bytes(contents) : sha256ScanLocalFile(scanDir, path, path) };
}

function coverageReceiptRefs(coverage: JsonObject): string[] {
  const refs = new Set<string>();
  for (const surface of coverage.surfaces as JsonObject[]) {
    for (const ref of (Object.hasOwn(surface, "receiptRefs") ? surface.receiptRefs : []) as string[]) refs.add(ref);
  }
  return [...refs].sort(compareCodePoints);
}

function validateSealedCoverageReceipts(scan: JsonObject, coverage: JsonObject): void {
  const artifactPaths = new Set((scan.artifacts as JsonObject[]).map((artifact) => requirePortableRelativePath(artifact.path as string, "sealed artifact path")));
  for (const ref of coverageReceiptRefs(coverage)) {
    if (!artifactPaths.has(ref)) throw new ContractError(`coverage receipt is missing from sealed artifacts: ${ref}`);
  }
}

/** Require every sealed artifact record to match the file (or the given bytes) it names. */
function validateExistingSeal(scanDir: string, scan: JsonObject, artifactContents: Record<string, Uint8Array> = {}): void {
  const sealedAt = scan.sealedAt ?? null;
  const artifacts = scan.artifacts ?? null;
  if (sealedAt === null && artifacts === null) return;
  if (sealedAt !== (scan.completedAt ?? null)) throw new ContractError("manifest.scan.sealedAt: must match completedAt");
  if (!Array.isArray(artifacts) || artifacts.length === 0) {
    throw new ContractError("manifest.scan.artifacts: sealed manifest requires artifact records");
  }
  const collisionKeys = new Set<string>();
  artifacts.forEach((artifact, index) => {
    const context = `manifest.scan.artifacts[${index}]`;
    if (!isJsonObject(artifact)) throw new ContractError(`${context}: expected an object`);
    const path = requirePortableRelativePath(requireString(artifact, "path", context), `${context}.path`);
    const collisionKey = path.toLowerCase();
    if (collisionKeys.has(collisionKey)) throw new ContractError(`${context}.path: duplicate artifact path`);
    collisionKeys.add(collisionKey);
    const expected = requireString(artifact, "sha256", context);
    const contents = Object.hasOwn(artifactContents, path) ? artifactContents[path] : undefined;
    const actual = contents !== undefined ? sha256Bytes(contents) : sha256ScanLocalFile(scanDir, path, context);
    if (actual !== expected) throw new ContractError(`${context}: sealed artifact changed or is missing`);
  });
}

type SealedScan = { manifest: JsonObject; findings: JsonObject; coverage: JsonObject; findingsBytes: Buffer };

/** _read_sealed_scan: a sealed scan whose seal, documents, and identities all validate. */
function readSealedScan(scanDir: string, schemaDir: string, requiredFor: string): SealedScan {
  const root = requireScanDirectory(scanDir);
  const schemas = schemaDir;
  const { payload: manifest } = readScanLocalJsonBytes(root, "scan-manifest.json", "scan-manifest.json");
  const scan = requireObject(manifest, "scan", "manifest");
  validateContractRefs(scan);
  if ((scan.sealedAt ?? null) === null || (scan.artifacts ?? null) === null) {
    throw new ContractError(`manifest.scan: ${requiredFor} requires a sealed scan`);
  }
  const findingsRef = scan.findingsRef as string;
  const coverageRef = scan.coverageRef as string;
  const { payload: findings, raw: findingsBytes } = readScanLocalJsonBytes(root, findingsRef, findingsRef);
  const { payload: coverage, raw: coverageBytes } = readScanLocalJsonBytes(root, coverageRef, coverageRef);
  validateExistingSeal(root, scan, { [findingsRef]: findingsBytes, [coverageRef]: coverageBytes });
  validateManifest(manifest);
  const findingsForValidation = legacySealedFindingsForValidation(findings);
  validateFindings(manifest, findingsForValidation);
  validateCoverage(manifest, coverage, root);
  validateSealedCoverageReceipts(scan, coverage);
  validateAgainstSchema(manifest, join(schemas, "scan-manifest.schema.json"));
  validateAgainstSchema(findingsForValidation, join(schemas, "findings.schema.json"));
  validateAgainstSchema(coverage, join(schemas, "coverage.schema.json"));
  validateFindingIdentities(manifest, findings);
  return { manifest, findings, coverage, findingsBytes };
}

/** SARIF for a sealed scan; partial or unsuccessful runs carry their deferred work as notifications. */
export function buildSarifProjection(scanDir: string, schemaDir: string, sourceRoot?: string): JsonObject {
  let source: string | undefined;
  if (sourceRoot !== undefined) {
    try {
      source = realpathSync(sourceRoot);
      if (!statSync(source).isDirectory()) source = undefined;
    } catch {
      source = undefined;
    }
    if (source === undefined) throw new ContractError("source root: expected an existing directory");
  }
  const { manifest, findings, coverage } = readSealedScan(scanDir, schemaDir, "SARIF projection");
  const sarif = buildSarif(manifest, findings, source);
  const executionSuccessful = (manifest.scan as JsonObject).status === "completed";
  if (!executionSuccessful || coverage.completeness !== "complete") {
    const run = (sarif.runs as JsonObject[])[0]!;
    (run.properties as JsonObject).piSecurityCoverageCompleteness = coverage.completeness;
    run.invocations = [
      {
        executionSuccessful,
        toolExecutionNotifications: (coverage.deferred as JsonObject[]).map((item) => ({ level: "warning", message: { text: item.reason } }))
      }
    ];
  }
  validateSarif(sarif);
  return sarif;
}

export function writeSarifProjection(scanDir: string, schemaDir: string, sourceRoot?: string): void {
  writeScanLocalJson(scanDir, EXPORT_PATHS.sarif, buildSarifProjection(scanDir, schemaDir, sourceRoot));
}

export function writeSarifOutput(scanDir: string, output: string, sarif: JsonObject): void {
  writeExportOutput(scanDir, output, "sarif", jsonBytes(sarif));
}

/** Export bytes of a sealed scan: SARIF, the sealed findings document as is, or CSV. */
export function buildFindingsExport(scanDir: string, exportFormat: string, schemaDir: string, sourceRoot?: string): Buffer {
  if (!isExportFormat(exportFormat)) throw new ContractError(`unsupported export format: ${exportFormat}`);
  if (exportFormat === "sarif") return jsonBytes(buildSarifProjection(scanDir, schemaDir, sourceRoot));
  if (sourceRoot !== undefined) throw new ContractError("source-root is only supported for SARIF exports");
  const { findings, coverage, findingsBytes } = readSealedScan(scanDir, schemaDir, `${exportFormat.toUpperCase()} export`);
  return exportFormat === "json" ? findingsBytes : buildCsvProjection(findings, coverage);
}

const sameFile = (left: { dev: number; ino: number }, right: { dev: number; ino: number }) => left.dev === right.dev && left.ino === right.ino;

/**
 * Write an export. Inside the scan directory (however the path is spelled) only the format's export path is
 * accepted, and never a sealed artifact; elsewhere the file is written into its existing parent directory.
 */
export function writeExportOutput(scanDir: string, output: string, exportFormat: string, contents: Uint8Array): void {
  if (!isExportFormat(exportFormat)) throw new ContractError(`unsupported export format: ${exportFormat}`);
  const root = requireScanDirectory(scanDir);
  const absolute = resolve(output);
  let relativeOutput = lexicallyInside(root, absolute);
  if (relativeOutput === undefined) {
    const rootMetadata = statSync(root);
    for (let ancestor = dirname(absolute); ; ancestor = dirname(ancestor)) {
      let metadata;
      try {
        metadata = statSync(ancestor);
      } catch (error) {
        if (errorCode(error) !== "ENOENT") throw new ContractError("export output path: unable to inspect output directory");
      }
      if (metadata !== undefined && sameFile(metadata, rootMetadata)) {
        for (let path = ancestor; ; path = dirname(path)) {
          let link = false;
          try {
            link = lstatSync(path).isSymbolicLink();
          } catch {
            // is_symlink() is False when the path cannot be inspected.
          }
          if (link) throw new ContractError("export output path: symbolic links cannot alias the scan directory");
          if (path === dirname(path)) break;
        }
        relativeOutput = lexicallyInside(ancestor, absolute)!;
        break;
      }
      if (ancestor === dirname(ancestor)) break;
    }
    if (relativeOutput === undefined) {
      writeScanLocalBytes(dirname(absolute), basename(absolute), contents, { externalName: true });
      return;
    }
  }
  if (relativeOutput !== EXPORT_PATHS[exportFormat]) {
    throw new ContractError(`${exportFormat.toUpperCase()} output path cannot overwrite a scan artifact`);
  }
  const { payload: manifest } = readScanLocalJsonBytes(root, "scan-manifest.json", "scan-manifest.json");
  const scan = requireObject(manifest, "scan", "manifest");
  const artifactPaths = requireArray(scan, "artifacts", "manifest.scan").flatMap((artifact, index) =>
    isJsonObject(artifact)
      ? [requirePortableRelativePath(requireString(artifact, "path", `manifest.scan.artifacts[${index}]`), `manifest.scan.artifacts[${index}].path`)]
      : []
  );
  let outputMetadata;
  try {
    outputMetadata = lstatSync(absolute);
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw new ContractError(`${relativeOutput}: unable to inspect export output`);
  }
  for (const artifactPath of artifactPaths) {
    if (artifactPath === relativeOutput) {
      throw new ContractError(`${exportFormat.toUpperCase()} output path cannot overwrite a sealed scan artifact`);
    }
    if (outputMetadata === undefined) continue;
    const descriptor = openScanLocalFile(root, artifactPath, `sealed artifact ${artifactPath}`);
    let artifactMetadata;
    try {
      artifactMetadata = fstatSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
    if (sameFile(outputMetadata, artifactMetadata)) {
      throw new ContractError(`${exportFormat.toUpperCase()} output path cannot overwrite a sealed scan artifact`);
    }
  }
  writeScanLocalBytes(root, relativeOutput, contents);
}

export type FinalizeOptions = EnvelopeOptions & {
  /** The package schemas directory. */
  schemaDir: string;
  sourceRoot?: string;
  expectedCoverageMode?: string;
  completionBinding?: CompletionBinding;
  /** Collects recovery warnings; when given, malformed draft parts are recovered instead of rejected. */
  completionWarnings?: string[];
  /** Draft documents to finalize instead of the scan directory's files. */
  draftDocuments?: [JsonObject, JsonObject, JsonObject];
  /** Receives the warning when the automatic SARIF export fails (default: stderr). */
  warn?: (message: string) => void;
};

export type PreparedScanFinalization = {
  scanDir: string;
  schemaDir: string;
  manifest: JsonObject;
  findings: JsonObject;
  coverage: JsonObject;
  wasSealed: boolean;
  reportMarkdown: Buffer;
};

const TERMINAL_STATUSES = new Set(["completed", "failed", "canceled", "interrupted"]);

/** Read, populate, and validate a scan without writing any output files. */
export function prepareScanFinalization(scanDir: string, options: FinalizeOptions): PreparedScanFinalization {
  const root = requireScanDirectory(scanDir);
  const schemaDir = options.schemaDir;
  const binding = options.completionBinding;
  const expectedMode = options.expectedCoverageMode;
  const manifest = options.draftDocuments
    ? deepCopyJson(options.draftDocuments[0])
    : readScanLocalJsonBytes(root, "scan-manifest.json", "scan-manifest.json").payload;
  const scan = requireObject(manifest, "scan", "manifest");
  const wasSealed = (scan.sealedAt ?? null) !== null || (scan.artifacts ?? null) !== null;
  if (!wasSealed) populateUnsealedManifestEnvelope(manifest, scan, binding, options);
  validateContractRefs(scan);
  const findingsRef = scan.findingsRef as string;
  const coverageRef = scan.coverageRef as string;
  let findings: JsonObject;
  let coverage: JsonObject;
  let findingsInput: Uint8Array;
  let coverageInput: Uint8Array;
  if (options.draftDocuments === undefined) {
    ({ payload: findings, raw: findingsInput } = readScanLocalJsonBytes(root, findingsRef, findingsRef));
    ({ payload: coverage, raw: coverageInput } = readScanLocalJsonBytes(root, coverageRef, coverageRef));
  } else {
    findings = deepCopyJson(options.draftDocuments[1]);
    coverage = deepCopyJson(options.draftDocuments[2]);
    findingsInput = jsonBytes(findings);
    coverageInput = jsonBytes(coverage);
  }
  if (!wasSealed) {
    populateUnsealedArtifactEnvelope(manifest, findings, coverage, binding);
    normalizeUnsealedDeepRepositoryInventoryStrategy(coverage, expectedMode);
    normalizeUnsealedOpenQuestions(coverage);
  }

  if (manifest.schemaVersion !== SCHEMA_VERSION) throw new ContractError(`manifest.schemaVersion: expected ${SCHEMA_VERSION}`);
  if (typeof scan.status !== "string" || !TERMINAL_STATUSES.has(scan.status)) {
    throw new ContractError("manifest.scan.status: expected a terminal scan outcome before sealing");
  }
  if (expectedMode !== undefined && binding !== undefined && binding.coverageMode !== expectedMode) {
    throw new ContractError("completion binding coverage mode does not match expected mode");
  }
  if (expectedMode !== undefined && coverage.mode !== expectedMode) {
    throw new ContractError(`coverage.mode: must match selected scan mode ${expectedMode}`);
  }
  validateExistingSeal(root, scan, { [findingsRef]: findingsInput, [coverageRef]: coverageInput });
  scan.sealedAt = requireString(scan, "completedAt", "manifest.scan");
  validateTarget(requireObject(scan, "target", "manifest.scan"));
  validateCompletionBinding(manifest, findings, coverage, binding);
  const findingsForValidation = wasSealed ? legacySealedFindingsForValidation(findings) : findings;
  if (wasSealed) {
    validateFindings(manifest, findingsForValidation);
    validateFindingIdentities(manifest, findings);
  } else if (options.completionWarnings !== undefined) {
    const discarded = recoverUnsealedFindings(manifest, findings, schemaDir, root, options.completionWarnings);
    recoverUnsealedCoverage(coverage, schemaDir, root, options.completionWarnings, discarded);
    recoverUnsealedHardening(manifest, root, options.completionWarnings);
  } else {
    populateFindingIdentities(manifest, findings);
  }
  validateFindings(manifest, findingsForValidation);
  validateCoverage(manifest, coverage, root);
  validateCanonicalSchemasBeforeProjection(manifest, findingsForValidation, coverage, schemaDir);
  requireDerivedWriteupFiles(root, findings);
  requireHardeningPortfolioFile(root, scan);
  if (wasSealed) {
    validateSealedCoverageReceipts(scan, coverage);
    validateManifest(manifest);
    validateAgainstSchema(manifest, join(schemaDir, "scan-manifest.schema.json"));
    validateAgainstSchema(findingsForValidation, join(schemaDir, "findings.schema.json"));
    validateAgainstSchema(coverage, join(schemaDir, "coverage.schema.json"));
    const reportMarkdown = generateReportProjection(manifest, findings, coverage);
    validateScanLocalOutputPath(root, join(root, "report.md"), "report.md");
    return { scanDir: root, schemaDir, manifest, findings, coverage, wasSealed, reportMarkdown };
  }

  const findingsBytes = contractJsonBytes("findings.json", findings);
  const coverageBytes = contractJsonBytes("coverage.json", coverage);
  const reportMarkdown = generateReportProjection(manifest, findings, coverage);
  validateScanLocalOutputPath(root, join(root, "report.md"), "report.md");
  scan.artifacts = [
    artifactRecord(root, "findings.json", "application/json", findingsBytes),
    artifactRecord(root, "coverage.json", "application/json", coverageBytes),
    ...coverageReceiptRefs(coverage).map((ref) => artifactRecord(root, ref, "application/octet-stream"))
  ];
  validateSealedCoverageReceipts(scan, coverage);
  validateManifest(manifest);
  validateAgainstSchema(manifest, join(schemaDir, "scan-manifest.schema.json"));
  validateAgainstSchema(findingsForValidation, join(schemaDir, "findings.schema.json"));
  validateAgainstSchema(coverage, join(schemaDir, "coverage.schema.json"));
  contractJsonBytes("scan-manifest.json", manifest);
  return { scanDir: root, schemaDir, manifest, findings, coverage, wasSealed, reportMarkdown };
}

function writeSarifProjectionIfPossible(scanDir: string, sourceRoot: string | undefined, schemaDir: string, warn: (message: string) => void): void {
  try {
    writeSarifProjection(scanDir, schemaDir, sourceRoot);
  } catch (error) {
    if (!(error instanceof ContractError) && errorCode(error) === undefined) throw error;
    warn(
      `pi-security: warning: automatic SARIF export failed: ${(error as Error).message}. ` +
        "Run `pi-security export <scan-dir> --export-format sarif` to retry."
    );
  }
}

const stderrWarn = (message: string) => process.stderr.write(`${message}\n`);

/** Write a previously validated finalization: documents, report, then the manifest that seals them. */
export function writePreparedScanFinalization(
  prepared: PreparedScanFinalization,
  { sourceRoot, warn = stderrWarn }: Pick<FinalizeOptions, "sourceRoot" | "warn"> = {}
): { manifest: JsonObject; findings: JsonObject; coverage: JsonObject } {
  const { scanDir, schemaDir, manifest, findings, coverage, wasSealed, reportMarkdown } = prepared;
  const scan = requireObject(manifest, "scan", "manifest");
  if (!wasSealed) {
    writeScanLocalJson(scanDir, "findings.json", findings);
    writeScanLocalJson(scanDir, "coverage.json", coverage);
  }
  writeScanLocalBytes(scanDir, "report.md", reportMarkdown);
  removeScanLocalFileIfExists(scanDir, "report.html");
  if (!wasSealed) {
    writeScanLocalJson(scanDir, "scan-manifest.json", manifest);
    validateExistingSeal(scanDir, scan);
  }
  writeSarifProjectionIfPossible(scanDir, sourceRoot, schemaDir, warn);
  return { manifest, findings, coverage };
}

export function finalizeScan(scanDir: string, options: FinalizeOptions) {
  return writePreparedScanFinalization(prepareScanFinalization(scanDir, options), options);
}

// ─── validate_scan_contract.py ──────────────────────────────────────────────

export type ValidatedContract = { scanDir: string; manifest: JsonObject; findings: JsonObject; coverage: JsonObject };

/** Validate a sealed scan contract without changing it. */
export function validateContract(scanDir: string, schemaDir: string): ValidatedContract {
  const expanded = scanDir === "~" || scanDir.startsWith("~/") ? homedir() + scanDir.slice(1) : scanDir;
  const root = requireScanDirectory(realpathSync(expanded));
  const { payload: manifest } = readScanLocalJsonBytes(root, "scan-manifest.json", "scan-manifest.json");
  validateManifest(manifest);
  validateAgainstSchema(manifest, join(schemaDir, "scan-manifest.schema.json"));
  const scan = requireObject(manifest, "scan", "manifest");
  const findingsRef = scan.findingsRef as string;
  const coverageRef = scan.coverageRef as string;
  const { payload: findings, raw: findingsBytes } = readScanLocalJsonBytes(root, findingsRef, findingsRef);
  const { payload: coverage, raw: coverageBytes } = readScanLocalJsonBytes(root, coverageRef, coverageRef);
  validateExistingSeal(root, scan, { [findingsRef]: findingsBytes, [coverageRef]: coverageBytes });
  const findingsForValidation = legacySealedFindingsForValidation(findings);
  validateFindings(manifest, findingsForValidation);
  validateFindingIdentities(manifest, findings);
  validateCoverage(manifest, coverage, root);
  validateSealedCoverageReceipts(scan, coverage);
  validateAgainstSchema(findingsForValidation, join(schemaDir, "findings.schema.json"));
  validateAgainstSchema(coverage, join(schemaDir, "coverage.schema.json"));
  requireScanLocalFile(root, "report.md", "report.md");
  return { scanDir: root, manifest, findings, coverage };
}

export function contractReceipt(validated: ValidatedContract): Record<string, string> {
  const scan = validated.manifest.scan as JsonObject;
  return {
    status: "valid",
    scanDir: validated.scanDir,
    manifestPath: join(validated.scanDir, "scan-manifest.json"),
    findingsPath: join(validated.scanDir, scan.findingsRef as string),
    coveragePath: join(validated.scanDir, scan.coverageRef as string),
    reportPath: join(validated.scanDir, "report.md")
  };
}
