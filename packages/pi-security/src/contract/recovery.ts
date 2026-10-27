// Recovery and population of unsealed scan drafts before sealing. Port of _finding_evidence_strength,
// _finding_strength, _recover_unsealed_findings, _recover_unsealed_coverage, _recover_unsealed_hardening,
// _populate_unsealed_manifest_envelope, _populate_unsealed_target_binding, _populate_unsealed_artifact_envelope,
// _normalize_unsealed_open_questions, _normalize_unsealed_deep_repository_inventory_strategy,
// _require_derived_writeup_files, and _require_hardening_portfolio_file in scripts/finalize_scan_contract.py.
//
// Recovery keeps what can be verified, drops what cannot, and reports each change as a warning; a coverage that lost
// anything is marked partial.
import { join } from "node:path";
import { readContractJsonFile, requireSafeJsonString } from "./canonical-json.js";
import { requirePortableRelativePath } from "./contract-paths.js";
import {
  ContractError,
  isBlank,
  isJsonObject,
  pythonStrip,
  requireArray,
  requireObject,
  requireString,
  type JsonObject
} from "./contract-error.js";
import { populateFindingIdentities } from "./finding-identity.js";
import { deepCopyJson, pythonEquals } from "./python-json.js";
import { mergedCodeEvidence } from "./sarif.js";
import { requireScanLocalFile } from "./scan-files.js";
import { validateDateTime, validateSchemaNode } from "./schema.js";
import { legacySealedFindingsForValidation, SCHEMA_VERSION, validateFinding, type CompletionBinding } from "./validation.js";

const SLUG = /^[a-z0-9][a-z0-9._/-]*$/;
const DISPOSITIONS = new Set(["reported", "no_issue_found", "rejected", "not_applicable", "needs_follow_up"]);
const TARGET_COORDINATE_FIELDS = ["revision", "baseRevision", "headRevision", "snapshotDigest"];
const TARGET_REQUIRED_COORDINATE_FIELDS: Record<string, string[]> = {
  git_revision: ["revision"],
  git_worktree: ["snapshotDigest"],
  git_diff: ["snapshotDigest"],
  directory_snapshot: ["snapshotDigest"]
};
const SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"];
const CONFIDENCE_ORDER = ["low", "medium", "high"];

const isNonEmptyString = (value: unknown): value is string => typeof value === "string" && !isBlank(value);

/** Code evidence items plus distinct embedded root-cause code, as a count. */
export function findingEvidenceStrength(finding: JsonObject): number {
  const evidence = mergedCodeEvidence(finding);
  const seenIds = new Set(evidence.filter((item) => isNonEmptyString(item.id)).map((item) => item.id));
  const seenCodes = new Set(evidence.filter((item) => isNonEmptyString(item.code)).map((item) => item.code));
  let strength = evidence.length;
  for (const sectionName of ["rootCause", "root_cause"]) {
    const section = finding[sectionName];
    if (!isJsonObject(section)) continue;
    for (const evidenceName of ["codeEvidence", "code_evidence"]) {
      const embedded = section[evidenceName];
      if (!Array.isArray(embedded)) continue;
      for (const item of embedded) {
        if (!isJsonObject(item)) continue;
        const code = item.code;
        if (!isNonEmptyString(code) || seenCodes.has(code)) continue;
        const evidenceId = item.id;
        if (isNonEmptyString(evidenceId)) {
          if (seenIds.has(evidenceId)) continue;
          seenIds.add(evidenceId);
        }
        seenCodes.add(code);
        strength += 1;
      }
    }
    const code = section.code;
    if (isNonEmptyString(code) && !seenCodes.has(code)) {
      seenCodes.add(code);
      strength += 1;
    }
  }
  return strength;
}

function levelIndex(order: string[], level: unknown): number {
  const index = order.indexOf(level as string);
  if (index < 0) throw new Error("tuple.index(x): x not in tuple");
  return index;
}

/** Severity, confidence, and evidence ranks, compared in that order. */
export function findingStrength(finding: JsonObject): [number, number, number] {
  return [
    levelIndex(SEVERITY_ORDER, (finding.severity as JsonObject).level),
    levelIndex(CONFIDENCE_ORDER, (finding.confidence as JsonObject).level),
    findingEvidenceStrength(finding)
  ];
}

const atMost = (left: number[], right: number[]) => {
  for (let index = 0; index < left.length; index++) {
    if (left[index] !== right[index]) return left[index]! < right[index]!;
  }
  return true;
};

const contractMessage = (error: unknown) => {
  if (error instanceof ContractError) return error.message;
  throw error;
};

/**
 * Keep the draft findings that validate, normalizing slugs and legacy fields, dropping malformed optional sections,
 * and keeping the strongest of duplicate logical findings. Returns the warnings of discarded findings.
 */
export function recoverUnsealedFindings(
  manifest: JsonObject,
  findings: JsonObject,
  schemaDir: string,
  scanDir: string,
  warnings: string[]
): string[] {
  const schema = readContractJsonFile(join(schemaDir, "findings.schema.json"));
  const properties = requireObject(schema, "properties", "findings.schema");
  const findingArray = requireObject(properties, "findings", "findings.schema.properties");
  const findingSchema = requireObject(findingArray, "items", "findings.schema.properties.findings");
  const findingProperties = requireObject(findingSchema, "properties", "findings.schema.properties.findings.items");
  const writeupSchema = requireObject(findingProperties, "writeup", "findings.schema.properties.findings.items.properties");
  const auxiliarySchemas = Object.fromEntries(
    ["remediationTests", "preventiveControls"].map((name) => [
      name,
      requireObject(findingProperties, name, "findings.schema.properties.findings.items.properties")
    ])
  );
  const scan = requireObject(manifest, "scan", "manifest");
  const scanId = requireString(scan, "id", "manifest.scan");
  if (!pythonEquals(findings.scanId ?? null, scanId)) throw new ContractError("findings.scanId: must match manifest scan id");

  const recovered: JsonObject[] = [];
  const discarded: string[] = [];
  const findingPositions = new Map<string, number>();
  const writeupPaths = new Set<string>();
  for (const [index, draft] of requireArray(findings, "findings", "findings").entries()) {
    const context = `findings.findings[${index}]`;
    let finding: JsonObject;
    let previousPosition: number | undefined;
    const normalizedFields: string[] = [];
    try {
      if (!isJsonObject(draft)) throw new ContractError(`${context}: expected an object`);
      const compatible = (legacySealedFindingsForValidation({ findings: [draft] }).findings as JsonObject[])[0]!;
      if (!pythonEquals(compatible, draft)) normalizedFields.push("legacy finding details");
      finding = compatible;
      const identity = requireObject(finding, "identity", context);
      const fields: [JsonObject, string, string, string][] = [
        [finding, "ruleId", context, "rule identifier"],
        [identity, "anchor", `${context}.identity`, "semantic anchor"]
      ];
      if (Object.hasOwn(identity, "instance")) fields.push([identity, "instance", `${context}.identity`, "instance"]);
      for (const [parent, field, fieldContext, label] of fields) {
        const value = requireString(parent, field, fieldContext);
        if (SLUG.test(value)) continue;
        const normalized = value
          .toLowerCase()
          .replace(/[^a-z0-9._/-]+/g, "-")
          .replace(/^[._/-]+|[._/-]+$/g, "");
        if (!SLUG.test(normalized)) throw new ContractError(`${fieldContext}.${field}: expected a stable lowercase semantic slug`);
        parent[field] = normalized;
        normalizedFields.push(label);
      }

      const severity = finding.severity;
      if (isJsonObject(severity)) {
        const conditions = severity.changeConditions;
        if (Array.isArray(conditions) && conditions.length > 0 && conditions.every(isNonEmptyString)) {
          conditions.forEach((condition, conditionIndex) =>
            requireSafeJsonString(condition, `${context}.severity.changeConditions[${conditionIndex}]`)
          );
          severity.changeConditions = conditions.map(pythonStrip).join(" ");
          normalizedFields.push("severity change conditions");
        }
      }

      populateFindingIdentities(manifest, { scanId, findings: [finding] });
      previousPosition = findingPositions.get(finding.findingId as string);
      validateFinding(finding, context);
      if (Object.hasOwn(finding, "writeup")) {
        try {
          validateSchemaNode(finding.writeup, writeupSchema, `${context}.writeup`);
          const reportPath = (finding.writeup as JsonObject).reportPath as string;
          const previousWriteup = previousPosition === undefined ? undefined : (recovered[previousPosition]!.writeup as JsonObject | undefined);
          if (writeupPaths.has(reportPath) && (previousWriteup === undefined || previousWriteup.reportPath !== reportPath)) {
            throw new ContractError(`${context}.writeup.reportPath: duplicate report path`);
          }
          requireScanLocalFile(scanDir, reportPath, `${context}.writeup.reportPath`);
        } catch (error) {
          const message = contractMessage(error);
          delete finding.writeup;
          warnings.push(`Skipped malformed writeup for finding ${index + 1}: ${message}.`);
        }
      }
      for (const [auxiliary, auxiliarySchema] of Object.entries(auxiliarySchemas)) {
        if (!Object.hasOwn(finding, auxiliary)) continue;
        try {
          validateSchemaNode(finding[auxiliary], auxiliarySchema, `${context}.${auxiliary}`);
        } catch (error) {
          const message = contractMessage(error);
          delete finding[auxiliary];
          warnings.push(`Skipped malformed ${auxiliary} for finding ${index + 1}: ${message}.`);
        }
      }
      validateSchemaNode(finding, findingSchema, context);
    } catch (error) {
      const warning = `Skipped malformed finding ${index + 1}: ${contractMessage(error)}.`;
      warnings.push(warning);
      discarded.push(warning);
      continue;
    }

    if (previousPosition !== undefined) {
      const previous = recovered[previousPosition]!;
      const weaker = atMost(findingStrength(finding), findingStrength(previous));
      const [strongest, earlier] = weaker ? [previous, finding] : [finding, previous];
      if (!pythonEquals(strongest, earlier)) {
        const original = deepCopyJson(earlier);
        const originalProvenance = original.provenance as JsonObject;
        const older = Object.hasOwn(originalProvenance, "previousFindings") ? originalProvenance.previousFindings : [];
        delete originalProvenance.previousFindings;
        const provenance = strongest.provenance as JsonObject;
        if (!Array.isArray(provenance.previousFindings)) provenance.previousFindings = [];
        const history = provenance.previousFindings as unknown[];
        for (const record of [...(Array.isArray(older) ? older : []), original]) {
          if (!history.some((existing) => pythonEquals(existing, record))) history.push(record);
        }
      }
      if (weaker) {
        warnings.push(`Skipped malformed finding ${index + 1}: duplicate logical finding.`);
        continue;
      }
      const previousWriteup = previous.writeup as JsonObject | undefined;
      if (previousWriteup !== undefined) writeupPaths.delete(previousWriteup.reportPath as string);
      recovered[previousPosition] = finding;
      warnings.push(`Recovered finding ${index + 1}: retained stronger duplicate logical finding.`);
    } else {
      findingPositions.set(finding.findingId as string, recovered.length);
      recovered.push(finding);
    }

    if (Object.hasOwn(finding, "writeup")) writeupPaths.add((finding.writeup as JsonObject).reportPath as string);
    if (normalizedFields.length > 0) {
      warnings.push(`Recovered finding ${index + 1}: normalized ${normalizedFields.join(", ")}.`);
    }
  }

  findings.findings = recovered;
  return discarded;
}

/** Keep the coverage records that validate; anything dropped or unverifiable marks the coverage partial. */
export function recoverUnsealedCoverage(
  coverage: JsonObject,
  schemaDir: string,
  scanDir: string,
  warnings: string[],
  discardedFindings: string[]
): void {
  const schema = readContractJsonFile(join(schemaDir, "coverage.schema.json"));
  const properties = requireObject(schema, "properties", "coverage.schema");
  const completeness = coverage.completeness;
  let partial = !["complete", "partial", "unknown"].includes(completeness as string);
  if (partial) warnings.push("Recovered malformed coverage completeness; marked coverage as partial.");
  if (coverage.mode === "deep_repository" && coverage.inventoryStrategy !== "repository") {
    coverage.inventoryStrategy = "repository";
    warnings.push("Recovered malformed Deep Scan inventory strategy; marked coverage as partial.");
    partial = true;
  }

  const surfaceIds = new Set<string>();
  for (const [field, label] of [
    ["surfaces", "coverage surface"],
    ["explicitExclusions", "coverage exclusion"],
    ["deferred", "deferred coverage item"]
  ] as const) {
    const arraySchema = requireObject(properties, field, "coverage.schema.properties");
    const itemSchema = requireObject(arraySchema, "items", `coverage.schema.properties.${field}`);
    const items = coverage[field];
    if (!Array.isArray(items)) {
      warnings.push(`Skipped malformed ${label} records: expected an array.`);
      coverage[field] = [];
      partial = true;
      continue;
    }

    const recovered: JsonObject[] = [];
    for (const [index, item] of items.entries()) {
      const context = `coverage.${field}[${index}]`;
      let surfaceId = "";
      try {
        if (!isJsonObject(item)) throw new ContractError(`${context}: expected an object`);
        if (field === "surfaces") {
          surfaceId = requireString(item, "id", context);
          if (surfaceIds.has(surfaceId)) throw new ContractError(`${context}.id: duplicate surface id`);
          const disposition = item.disposition;
          let surfaceRecovered = false;
          if (typeof disposition !== "string" || !DISPOSITIONS.has(disposition)) {
            warnings.push(`Recovered coverage surface ${index + 1}: the review disposition could not be verified.`);
            item.disposition = "needs_follow_up";
            surfaceRecovered = true;
          }

          let receiptRefs = item.receiptRefs;
          if (!Array.isArray(receiptRefs)) {
            warnings.push(`Skipped malformed receipt references for coverage surface ${index + 1}: expected an array.`);
            receiptRefs = [];
            surfaceRecovered = true;
          }

          const recoveredReceipts: string[] = [];
          for (const [refIndex, ref] of (receiptRefs as unknown[]).entries()) {
            const refContext = `${context}.receiptRefs[${refIndex}]`;
            try {
              if (typeof ref !== "string") throw new ContractError(`${refContext}: expected a string`);
              const normalized = requirePortableRelativePath(ref, refContext);
              if (!normalized.startsWith("artifacts/")) throw new ContractError(`${refContext}: expected a file under artifacts/`);
              requireScanLocalFile(scanDir, normalized, refContext);
              recoveredReceipts.push(normalized);
            } catch (error) {
              warnings.push(`Skipped malformed coverage receipt ${index + 1}.${refIndex + 1}: ${contractMessage(error)}.`);
              surfaceRecovered = true;
            }
          }

          item.receiptRefs = recoveredReceipts;
          if (surfaceRecovered || item.disposition === "needs_follow_up") {
            if (!surfaceRecovered && completeness !== "partial") {
              warnings.push(`Coverage surface ${index + 1} requires follow-up; marked coverage as partial.`);
            }
            item.disposition = "needs_follow_up";
            partial = true;
          }
        }
        validateSchemaNode(item, itemSchema, context);
      } catch (error) {
        warnings.push(`Skipped malformed ${label} ${index + 1}: ${contractMessage(error)}.`);
        partial = true;
        continue;
      }

      if (field === "surfaces") surfaceIds.add(surfaceId);
      recovered.push(item);
    }
    coverage[field] = recovered;
  }

  const deferred = coverage.deferred as JsonObject[];
  if (discardedFindings.length > 0) {
    for (const surface of coverage.surfaces as JsonObject[]) surface.disposition = "needs_follow_up";
    deferred.push(...discardedFindings.map((reason, index) => ({ id: `discarded-finding-${index + 1}`, reason })));
    partial = true;
  }

  if (deferred.length > 0 && completeness !== "partial") {
    if (discardedFindings.length === 0) warnings.push("Coverage has deferred review work; marked coverage as partial.");
    partial = true;
  }
  if (partial) coverage.completeness = "partial";
}

/** Drop a hardening portfolio reference that is malformed or names a missing file. */
export function recoverUnsealedHardening(manifest: JsonObject, scanDir: string, warnings: string[]): void {
  const scan = requireObject(manifest, "scan", "manifest");
  if (!Object.hasOwn(scan, "hardening")) return;
  try {
    const hardening = requireObject(scan, "hardening", "manifest.scan");
    const portfolioPath = requireString(hardening, "portfolioPath", "manifest.scan.hardening");
    if (portfolioPath !== "hardening/hardening.md") {
      throw new ContractError("manifest.scan.hardening.portfolioPath: expected hardening/hardening.md");
    }
    requireHardeningPortfolioFile(scanDir, scan);
  } catch (error) {
    const message = contractMessage(error);
    delete scan.hardening;
    warnings.push(`Skipped malformed hardening portfolio: ${message}.`);
  }
}

export type EnvelopeOptions = {
  /** Environment holding PI_SECURITY_STARTED_AT (default: process.env). */
  env?: Record<string, string | undefined>;
  /** Clock for completedAt (default: the current time). */
  now?: () => Date;
};

/** Python datetime.now(timezone.utc).isoformat() with Z: microseconds, omitted when zero. */
function pythonUtcTimestamp(date: Date): string {
  const [seconds, fraction] = date.toISOString().replace("Z", "").split(".");
  const micros = Number(fraction ?? 0) * 1000;
  return micros === 0 ? `${seconds}Z` : `${seconds}.${String(micros).padStart(6, "0")}Z`;
}

/** Populate non-semantic draft fields owned by finalization or the workbench. `scan` is manifest.scan. */
export function populateUnsealedManifestEnvelope(
  manifest: JsonObject,
  scan: JsonObject,
  binding: CompletionBinding | null | undefined,
  options: EnvelopeOptions = {}
): void {
  manifest.documentType = "pi-security.scan-manifest";
  manifest.schemaVersion = SCHEMA_VERSION;
  scan.status = binding ? (Object.hasOwn(binding, "status") ? binding.status : "completed") : "completed";
  scan.coverageRef = "coverage.json";
  scan.findingsRef = "findings.json";
  if (binding === null || binding === undefined) {
    const startedAt = (options.env ?? process.env).PI_SECURITY_STARTED_AT;
    if (startedAt !== undefined) {
      validateDateTime(startedAt, "PI_SECURITY_STARTED_AT");
      scan.startedAt = startedAt;
      scan.completedAt = pythonUtcTimestamp((options.now ?? (() => new Date()))());
    }
    return;
  }

  scan.id = binding.scanId;
  scan.startedAt = binding.startedAt;
  scan.completedAt = binding.completedAt;
  scan.producer = deepCopyJson(binding.producer);
  if (isJsonObject(scan.target)) populateUnsealedTargetBinding(scan.target, binding.target);
  if (isJsonObject(scan.scope)) Object.assign(scan.scope, deepCopyJson(binding.scope));
}

/** Replace workbench-owned target coordinates without retaining incompatible drafts. */
export function populateUnsealedTargetBinding(target: JsonObject, targetBinding: JsonObject): void {
  const kind = target.kind;
  const required = (typeof kind === "string" && Object.hasOwn(TARGET_REQUIRED_COORDINATE_FIELDS, kind) ? TARGET_REQUIRED_COORDINATE_FIELDS[kind] : undefined) ?? [];
  for (const field of TARGET_COORDINATE_FIELDS) {
    if (!Object.hasOwn(targetBinding, field) && !required.includes(field)) delete target[field];
  }
  Object.assign(target, deepCopyJson(targetBinding));
}

/** Populate deterministic top-level draft fields after refs have been resolved. */
export function populateUnsealedArtifactEnvelope(
  manifest: JsonObject,
  findings: JsonObject,
  coverage: JsonObject,
  binding: CompletionBinding | null | undefined
): void {
  findings.documentType = "pi-security.findings";
  findings.schemaVersion = SCHEMA_VERSION;
  coverage.documentType = "pi-security.coverage";
  coverage.schemaVersion = SCHEMA_VERSION;
  if (binding === null || binding === undefined) return;

  findings.scanId = binding.scanId;
  coverage.scanId = binding.scanId;
  coverage.mode = binding.coverageMode;
  const scan = requireObject(manifest, "scan", "manifest");
  const scope = requireObject(scan, "scope", "manifest.scan");
  if (Object.hasOwn(scope, "includePaths")) coverage.includePaths = deepCopyJson(scope.includePaths);
  if (Object.hasOwn(scope, "excludePaths")) coverage.excludePaths = deepCopyJson(scope.excludePaths);
}

/** Keep only schema-valid optional open-question rows without inventing content. */
export function normalizeUnsealedOpenQuestions(coverage: JsonObject): void {
  const openQuestions = coverage.openQuestions;
  if (!Array.isArray(openQuestions)) {
    delete coverage.openQuestions;
    return;
  }
  const normalized: JsonObject[] = [];
  for (const item of openQuestions) {
    if (typeof item === "string") {
      const question = pythonStrip(item);
      if (question) normalized.push({ question });
      continue;
    }
    if (!isJsonObject(item)) continue;
    const question = item.question;
    if (!isNonEmptyString(question)) continue;
    const row: JsonObject = { ...item, question: pythonStrip(question) };
    if (!isNonEmptyString(row.followUpPrompt)) delete row.followUpPrompt;
    normalized.push(row);
  }
  coverage.openQuestions = normalized;
}

/** Normalize the old Deep workflow label to the ordinary repository inventory. */
export function normalizeUnsealedDeepRepositoryInventoryStrategy(coverage: JsonObject, expectedCoverageMode: string | null | undefined): void {
  if (expectedCoverageMode === "deep_repository" && coverage.inventoryStrategy === "deep_repository_repeated_discovery") {
    coverage.inventoryStrategy = "repository";
  }
}

/** Every finding writeup's report must be a file inside the scan directory. */
export function requireDerivedWriteupFiles(scanDir: string, findings: JsonObject): void {
  const items = Object.hasOwn(findings, "findings") ? findings.findings : [];
  if (!Array.isArray(items)) return;
  items.forEach((finding, index) => {
    if (!isJsonObject(finding) || !isJsonObject(finding.writeup)) return;
    const reportPath = finding.writeup.reportPath;
    if (typeof reportPath === "string") requireScanLocalFile(scanDir, reportPath, `findings[${index}].writeup.reportPath`);
  });
}

/** A hardening portfolio, when referenced, must be a file inside the scan directory. */
export function requireHardeningPortfolioFile(scanDir: string, scan: JsonObject): void {
  const hardening = scan.hardening;
  if (!isJsonObject(hardening)) return;
  const portfolioPath = hardening.portfolioPath;
  if (typeof portfolioPath === "string") requireScanLocalFile(scanDir, portfolioPath, "manifest.scan.hardening.portfolioPath");
}
