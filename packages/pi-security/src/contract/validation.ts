// Contract validation of scan manifests, findings, and coverage. Port of _validate_remote, _validate_target,
// _validate_location, _validate_completion_binding, _validate_finding, _validate_coverage, _validate_manifest,
// _validate_findings, _validate_contract_refs, _legacy_sealed_findings_for_validation, and
// _validate_canonical_schemas_before_projection in scripts/finalize_scan_contract.py.
import { closeSync } from "node:fs";
import { isIPv6 } from "node:net";
import { join } from "node:path";
import { requireSafeJsonValue } from "./canonical-json.js";
import { requirePortableRelativePath, requireSafeRelativePath } from "./contract-paths.js";
import { ContractError, isBlank, isJsonObject, requireArray, requireObject, requireString, type JsonObject } from "./contract-error.js";
import { FINGERPRINT_ALGORITHM } from "./finding-identity.js";
import { compareCodePoints, deepCopyJson, PyFloat, pythonEquals } from "./python-json.js";
import { openScanLocalFile } from "./scan-files.js";
import { validateAgainstSchema } from "./schema.js";

export const SCHEMA_VERSION = "1.0";
const SEVERITIES = new Set(["critical", "high", "medium", "low", "informational"]);
const CONFIDENCES = new Set(["high", "medium", "low"]);
const TARGET_KINDS = new Set(["git_revision", "git_worktree", "git_diff", "directory_snapshot"]);
const DISPOSITIONS = new Set(["reported", "no_issue_found", "rejected", "not_applicable", "needs_follow_up"]);

/** Python isinstance(value, int): booleans are ints too. */
const isPythonIntLike = (value: unknown): value is number | bigint | boolean =>
  typeof value === "boolean" || (typeof value === "number" && Number.isInteger(value)) || typeof value === "bigint";
const asNumber = (value: number | bigint | boolean) => (typeof value === "boolean" ? (value ? 1 : 0) : value);

// ─── urllib.parse.urlsplit ──────────────────────────────────────────────────

type SplitUrl = { scheme: string; netloc: string; query: string; fragment: string };
const SCHEME_CHARS = /^[A-Za-z0-9+\-.]*$/;

function checkBracketedNetloc(netloc: string): void {
  const hostAndPort = netloc.slice(netloc.lastIndexOf("@") + 1);
  const open = hostAndPort.indexOf("[");
  if (open < 0) return;
  if (open > 0) throw new ContractError("Invalid IPv6 URL");
  const close = hostAndPort.indexOf("]", open);
  const host = close < 0 ? hostAndPort.slice(open + 1) : hostAndPort.slice(open + 1, close);
  const port = close < 0 ? "" : hostAndPort.slice(close + 1);
  if (port !== "" && !port.startsWith(":")) throw new ContractError("Invalid IPv6 URL");
  if (host.startsWith("v")) {
    if (!/^v[a-fA-F0-9]+\..+$/s.test(host)) throw new ContractError("IPvFuture address is invalid");
  } else if (!isIPv6(host)) {
    throw new ContractError(`'${host}' does not appear to be an IPv4 or IPv6 address`);
  }
}

/** urllib.parse.urlsplit, for the fields remote validation reads. */
export function urlsplit(input: string): SplitUrl {
  let url = input.replace(/^[\x00-\x20]+/, "").replace(/[\t\r\n]/g, "");
  let scheme = "";
  let netloc = "";
  let query = "";
  let fragment = "";
  const colon = url.indexOf(":");
  if (colon > 0 && /^[A-Za-z]/.test(url) && SCHEME_CHARS.test(url.slice(0, colon))) {
    scheme = url.slice(0, colon).toLowerCase();
    url = url.slice(colon + 1);
  }
  if (url.startsWith("//")) {
    let delimiter = url.length;
    for (const character of "/?#") {
      const index = url.indexOf(character, 2);
      if (index >= 0) delimiter = Math.min(delimiter, index);
    }
    netloc = url.slice(2, delimiter);
    url = url.slice(delimiter);
    if (netloc.includes("[") !== netloc.includes("]")) throw new ContractError("Invalid IPv6 URL");
    if (netloc.includes("[") && netloc.includes("]")) checkBracketedNetloc(netloc);
  }
  const hash = url.indexOf("#");
  if (hash >= 0) {
    fragment = url.slice(hash + 1);
    url = url.slice(0, hash);
  }
  const question = url.indexOf("?");
  if (question >= 0) query = url.slice(question + 1);
  // eslint-disable-next-line no-control-regex
  if (netloc !== "" && !/^[\x00-\x7f]*$/.test(netloc)) checkNonAsciiNetloc(netloc);
  return { scheme, netloc, query, fragment };
}

/** urllib.parse._checknetloc: NFKC normalization must not introduce URL delimiters. */
function checkNonAsciiNetloc(netloc: string): void {
  const stripped = netloc.replace(/[@:#?]/g, "");
  const normalized = stripped.normalize("NFKC");
  if (stripped === normalized) return;
  for (const character of "/?#@:") {
    if (normalized.includes(character)) {
      throw new ContractError(`netloc '${netloc}' contains invalid characters under NFKC normalization`);
    }
  }
}

export function validateRemote(remote: string, context: string): void {
  const parsed = urlsplit(remote);
  if (parsed.scheme === "" || parsed.netloc === "") throw new ContractError(`${context}: expected a sanitized canonical absolute URL`);
  const at = parsed.netloc.lastIndexOf("@");
  const userinfo = at < 0 ? undefined : parsed.netloc.slice(0, at);
  const colon = userinfo?.indexOf(":") ?? -1;
  const username = userinfo === undefined ? "" : colon < 0 ? userinfo : userinfo.slice(0, colon);
  const password = userinfo === undefined || colon < 0 ? "" : userinfo.slice(colon + 1);
  if (username || password || parsed.query || parsed.fragment) {
    throw new ContractError(`${context}: remote URL must not contain credentials, query, or fragment`);
  }
}

// ─── Documents ──────────────────────────────────────────────────────────────

export function validateTarget(target: JsonObject): void {
  const kind = requireString(target, "kind", "scan.target");
  if (!TARGET_KINDS.has(kind)) throw new ContractError(`scan.target.kind: unsupported target kind: ${kind}`);
  requireString(target, "targetId", "scan.target");
  requireString(target, "displayName", "scan.target");
  const remote = target.remote ?? null;
  if (remote !== null) {
    if (typeof remote !== "string") throw new ContractError("scan.target.remote: expected a string");
    validateRemote(remote, "scan.target.remote");
  }
  requireString(target, kind === "git_revision" ? "revision" : "snapshotDigest", "scan.target");
}

export function validateLocation(location: JsonObject, context: string): void {
  requireSafeRelativePath(requireString(location, "path", context), `${context}.path`);
  const start = location.startLine ?? null;
  const end = Object.hasOwn(location, "endLine") ? location.endLine ?? null : start;
  if (!isPythonIntLike(start) || asNumber(start) < 1) throw new ContractError(`${context}.startLine: expected a positive integer`);
  if (!isPythonIntLike(end) || asNumber(end) < asNumber(start)) throw new ContractError(`${context}.endLine: expected an integer >= startLine`);
  const role = location.role ?? null;
  if (role !== null && (typeof role !== "string" || role === "")) throw new ContractError(`${context}.role: expected a non-empty string`);
}

export type CompletionBinding = {
  scanId: string;
  status?: string;
  startedAt: string;
  completedAt: string;
  producer: unknown;
  allowedTargetKinds: string[];
  target: Record<string, unknown>;
  scope: Record<string, unknown>;
  coverageMode: string;
};

/** Verify workbench-owned fields before an unsealed draft is written. */
export function validateCompletionBinding(manifest: JsonObject, findings: JsonObject, coverage: JsonObject, binding: CompletionBinding | null | undefined): void {
  if (binding === null || binding === undefined) return;
  const scan = requireObject(manifest, "scan", "manifest");
  const differs = (left: unknown, right: unknown) => !pythonEquals(left ?? null, right ?? null);
  if (differs(scan.id, binding.scanId)) throw new ContractError("manifest.scan.id: must match the workbench scan");
  if (differs(scan.status, binding.status ?? "completed")) throw new ContractError("manifest.scan.status: must match the workbench outcome");
  if (differs(scan.startedAt, binding.startedAt)) throw new ContractError("manifest.scan.startedAt: must match the workbench scan");
  if (differs(scan.completedAt, binding.completedAt)) throw new ContractError("manifest.scan.completedAt: must match the workbench completion");
  if (differs(scan.producer, binding.producer)) throw new ContractError("manifest.scan.producer: must match the workbench producer");
  const target = requireObject(scan, "target", "manifest.scan");
  if (!binding.allowedTargetKinds.some((kind) => pythonEquals(target.kind ?? null, kind))) {
    throw new ContractError("scan.target.kind: must match the workbench target");
  }
  for (const [key, expected] of Object.entries(binding.target)) {
    if (differs(target[key], expected)) throw new ContractError(`scan.target.${key}: must match the workbench target`);
  }
  const scope = requireObject(scan, "scope", "manifest.scan");
  for (const [key, expected] of Object.entries(binding.scope)) {
    if (differs(scope[key], expected)) throw new ContractError(`manifest.scan.scope.${key}: must match the workbench scan`);
  }
  if (differs(findings.scanId, binding.scanId)) throw new ContractError("findings.scanId: must match the workbench scan");
  if (differs(coverage.scanId, binding.scanId)) throw new ContractError("coverage.scanId: must match the workbench scan");
  if (differs(coverage.mode, binding.coverageMode)) throw new ContractError("coverage.mode: must match the workbench scan");
  for (const [key, expected] of Object.entries(binding.scope)) {
    if (differs(coverage[key], expected)) throw new ContractError(`coverage.${key}: must match the workbench scan`);
  }
}

const isNonEmptyString = (value: unknown): value is string => typeof value === "string" && value !== "";

export function validateFinding(finding: JsonObject, context: string): void {
  for (const key of ["findingId", "occurrenceId", "ruleId", "title", "summary", "remediation"]) requireString(finding, key, context);
  requireObject(finding, "identity", context);
  const fingerprints = requireObject(finding, "fingerprints", context);
  if (!pythonEquals(fingerprints.algorithm ?? null, FINGERPRINT_ALGORITHM)) {
    throw new ContractError(`${context}.fingerprints.algorithm: unsupported algorithm`);
  }
  requireString(fingerprints, "primary", `${context}.fingerprints`);

  const severity = requireObject(finding, "severity", context);
  const level = requireString(severity, "level", `${context}.severity`);
  if (!SEVERITIES.has(level)) throw new ContractError(`${context}.severity.level: unsupported severity: ${level}`);
  const score = severity.score ?? null;
  if (score !== null) {
    const number = score instanceof PyFloat ? score.value : typeof score === "number" || typeof score === "bigint" ? score : undefined;
    if (number === undefined || !(number >= 0 && number <= 10)) {
      throw new ContractError(`${context}.severity.score: expected a number from 0 through 10`);
    }
    requireString(severity, "scoringSystem", `${context}.severity`);
  }

  const confidence = requireObject(finding, "confidence", context);
  const confidenceLevel = requireString(confidence, "level", `${context}.confidence`);
  if (!CONFIDENCES.has(confidenceLevel)) {
    throw new ContractError(`${context}.confidence.level: unsupported confidence: ${confidenceLevel}`);
  }
  requireString(confidence, "rationale", `${context}.confidence`);

  const taxonomy = requireObject(finding, "taxonomy", context);
  requireString(taxonomy, "category", `${context}.taxonomy`);
  const cwe = Object.hasOwn(taxonomy, "cwe") ? taxonomy.cwe : [];
  if (!Array.isArray(cwe) || cwe.some((item) => !isNonEmptyString(item))) {
    throw new ContractError(`${context}.taxonomy.cwe: expected an array of strings`);
  }

  const locations = requireArray(finding, "locations", context);
  if (locations.length === 0) throw new ContractError(`${context}.locations: expected at least one location`);
  locations.forEach((location, index) => {
    if (!isJsonObject(location)) throw new ContractError(`${context}.locations[${index}]: expected an object`);
    validateLocation(location, `${context}.locations[${index}]`);
  });

  const evidenceIds = new Set<string>();
  for (const evidenceKey of ["codeEvidence", "code_evidence"]) {
    if (!Object.hasOwn(finding, evidenceKey)) continue;
    const codeEvidence = finding[evidenceKey];
    if (!Array.isArray(codeEvidence)) throw new ContractError(`${context}.${evidenceKey}: expected an array`);
    codeEvidence.forEach((evidence, index) => {
      const evidenceContext = `${context}.${evidenceKey}[${index}]`;
      if (!isJsonObject(evidence)) throw new ContractError(`${evidenceContext}: expected an object`);
      const evidenceId = requireString(evidence, "id", evidenceContext);
      if (evidenceIds.has(evidenceId)) throw new ContractError(`${evidenceContext}.id: duplicate code-evidence id`);
      evidenceIds.add(evidenceId);
      requireString(evidence, "code", evidenceContext);
    });
  }

  const sections: [string, unknown][] = ["rootCause", "root_cause", "validation", "attackPath"].map((name) => [name, finding[name]]);
  const attackPath = finding.attackPath;
  if (isJsonObject(attackPath)) {
    for (const name of ["dataFlow", "dataflow", "data_flow", "reachability"]) sections.push([`attackPath.${name}`, attackPath[name]]);
  }
  for (const [sectionName, section] of sections) {
    if (!isJsonObject(section)) continue;
    for (const refsKey of ["evidenceRefs", "evidence_refs"]) {
      if (!Object.hasOwn(section, refsKey)) continue;
      const refs = section[refsKey];
      if (!Array.isArray(refs) || refs.some((ref) => !isNonEmptyString(ref))) {
        throw new ContractError(`${context}.${sectionName}.${refsKey}: expected strings`);
      }
      const unknown = [...new Set(refs as string[])].filter((ref) => !evidenceIds.has(ref)).sort(compareCodePoints);
      if (unknown.length > 0) {
        throw new ContractError(`${context}.${sectionName}.${refsKey}: unknown code-evidence ids: ${unknown.join(", ")}`);
      }
    }
  }

  const provenance = requireObject(finding, "provenance", context);
  requireString(provenance, "source", `${context}.provenance`);
  const extensions = finding.extensions ?? null;
  if (extensions !== null && !isJsonObject(extensions)) throw new ContractError(`${context}.extensions: expected an object`);
}

function requireScanLocalFile(scanDir: string, relativePath: string, context: string): void {
  closeSync(openScanLocalFile(scanDir, relativePath, context));
}

/** Validate coverage against the manifest; receipt references are normalized in place and must exist. */
export function validateCoverage(manifest: JsonObject, coverage: JsonObject, scanDir: string): void {
  const scan = requireObject(manifest, "scan", "manifest");
  const scanId = requireString(scan, "id", "manifest.scan");
  if (!pythonEquals(coverage.scanId ?? null, scanId)) throw new ContractError("coverage.scanId: must match manifest scan id");
  requireString(coverage, "mode", "coverage");
  const completeness = requireString(coverage, "completeness", "coverage");
  requireString(coverage, "inventoryStrategy", "coverage");
  const scope = requireObject(scan, "scope", "manifest.scan");
  if (!pythonEquals(coverage.includePaths ?? null, scope.includePaths ?? null)) throw new ContractError("coverage.includePaths: must match manifest scope");
  if (!pythonEquals(coverage.excludePaths ?? null, scope.excludePaths ?? null)) throw new ContractError("coverage.excludePaths: must match manifest scope");
  const surfaceIds = new Set<string>();
  let needsFollowUp = false;
  requireArray(coverage, "surfaces", "coverage").forEach((surface, index) => {
    const context = `coverage.surfaces[${index}]`;
    if (!isJsonObject(surface)) throw new ContractError(`${context}: expected an object`);
    const surfaceId = requireString(surface, "id", context);
    if (surfaceIds.has(surfaceId)) throw new ContractError(`${context}.id: duplicate surface id`);
    surfaceIds.add(surfaceId);
    requireString(surface, "label", context);
    const disposition = requireString(surface, "disposition", context);
    if (!DISPOSITIONS.has(disposition)) throw new ContractError(`${context}.disposition: unsupported disposition: ${disposition}`);
    needsFollowUp ||= disposition === "needs_follow_up";
    const receiptRefs = Object.hasOwn(surface, "receiptRefs") ? surface.receiptRefs : [];
    if (!Array.isArray(receiptRefs)) throw new ContractError(`${context}.receiptRefs: expected an array`);
    receiptRefs.forEach((ref, refIndex) => {
      const refContext = `${context}.receiptRefs[${refIndex}]`;
      if (typeof ref !== "string") throw new ContractError(`${refContext}: expected a string`);
      const normalized = requirePortableRelativePath(ref, refContext);
      if (!normalized.startsWith("artifacts/")) throw new ContractError(`${refContext}: expected a file under artifacts/`);
      receiptRefs[refIndex] = normalized;
      requireScanLocalFile(scanDir, normalized, refContext);
    });
  });
  for (const field of ["explicitExclusions", "deferred"]) {
    if (!Array.isArray(Object.hasOwn(coverage, field) ? coverage[field] : [])) throw new ContractError(`coverage.${field}: expected an array`);
  }
  const deferred = coverage.deferred;
  const hasDeferred = Array.isArray(deferred) ? deferred.length > 0 : Boolean(deferred);
  if (completeness === "complete" && (needsFollowUp || hasDeferred)) {
    throw new ContractError("coverage.completeness: complete coverage cannot have deferred work");
  }
  requireSafeJsonValue(coverage, "coverage.json");
}

export function validateContractRefs(scan: JsonObject): void {
  for (const [field, expected] of [
    ["coverageRef", "coverage.json"],
    ["findingsRef", "findings.json"]
  ] as const) {
    if (requireString(scan, field, "manifest.scan") !== expected) throw new ContractError(`manifest.scan.${field}: expected '${expected}'`);
  }
}

export function validateManifest(manifest: JsonObject): void {
  if (!pythonEquals(manifest.documentType ?? null, "pi-security.scan-manifest")) {
    throw new ContractError("manifest.documentType: expected pi-security.scan-manifest");
  }
  if (!pythonEquals(manifest.schemaVersion ?? null, SCHEMA_VERSION)) throw new ContractError(`manifest.schemaVersion: expected ${SCHEMA_VERSION}`);
  const scan = requireObject(manifest, "scan", "manifest");
  for (const key of ["id", "startedAt", "completedAt", "sealedAt"]) requireString(scan, key, "manifest.scan");
  if (!["completed", "failed", "canceled", "interrupted"].includes(scan.status as string) || typeof scan.status !== "string") {
    throw new ContractError("manifest.scan.status: expected a terminal scan outcome");
  }
  const producer = requireObject(scan, "producer", "manifest.scan");
  requireString(producer, "name", "manifest.scan.producer");
  requireString(producer, "version", "manifest.scan.producer");
  validateTarget(requireObject(scan, "target", "manifest.scan"));
  const scope = requireObject(scan, "scope", "manifest.scan");
  for (const field of ["includePaths", "excludePaths"]) {
    requireArray(scope, field, "manifest.scan.scope").forEach((value, index) => {
      if (typeof value !== "string") throw new ContractError(`manifest.scan.scope.${field}[${index}]: expected a string`);
      requireSafeRelativePath(value, `manifest.scan.scope.${field}[${index}]`, true);
    });
  }
  validateContractRefs(scan);
  const artifacts = requireArray(scan, "artifacts", "manifest.scan");
  if (artifacts.length === 0) throw new ContractError("manifest.scan.artifacts: expected generated artifact records");
  const paths = new Set<string>();
  const collisionKeys = new Set<string>();
  artifacts.forEach((artifact, index) => {
    const context = `manifest.scan.artifacts[${index}]`;
    if (!isJsonObject(artifact)) throw new ContractError(`${context}: expected an object`);
    const path = requirePortableRelativePath(requireString(artifact, "path", context), `${context}.path`);
    const collisionKey = path.toLowerCase();
    if (collisionKeys.has(collisionKey)) throw new ContractError(`${context}.path: duplicate artifact path`);
    paths.add(path);
    collisionKeys.add(collisionKey);
    requireString(artifact, "sha256", context);
    requireString(artifact, "mediaType", context);
  });
  for (const required of ["findings.json", "coverage.json"]) {
    if (!paths.has(required)) throw new ContractError(`manifest.scan.artifacts: missing required artifact: ${required}`);
  }
  requireSafeJsonValue(manifest, "scan-manifest.json");
}

export function validateFindings(manifest: JsonObject, findings: JsonObject): void {
  if (!pythonEquals(findings.documentType ?? null, "pi-security.findings")) throw new ContractError("findings.documentType: expected pi-security.findings");
  if (!pythonEquals(findings.schemaVersion ?? null, SCHEMA_VERSION)) throw new ContractError(`findings.schemaVersion: expected ${SCHEMA_VERSION}`);
  const scanId = requireString(requireObject(manifest, "scan", "manifest"), "id", "manifest.scan");
  if (!pythonEquals(findings.scanId ?? null, scanId)) throw new ContractError("findings.scanId: must match manifest scan id");
  const findingIds = new Set<string>();
  const occurrenceIds = new Set<string>();
  requireArray(findings, "findings", "findings").forEach((finding, index) => {
    const context = `findings.findings[${index}]`;
    if (!isJsonObject(finding)) throw new ContractError(`${context}: expected an object`);
    validateFinding(finding, context);
    const findingId = finding.findingId as string;
    const occurrenceId = finding.occurrenceId as string;
    if (findingIds.has(findingId) || occurrenceIds.has(occurrenceId)) throw new ContractError(`${context}: duplicate finding or occurrence id`);
    findingIds.add(findingId);
    occurrenceIds.add(occurrenceId);
  });
  requireSafeJsonValue(findings, "findings.json");
}

// ─── Legacy sealed findings ─────────────────────────────────────────────────

function filterUnknownLegacyEvidenceRefs(section: JsonObject, evidenceIds: Set<string>): void {
  for (const field of ["evidenceRefs", "evidence_refs"]) {
    const refs = section[field];
    if (Array.isArray(refs)) section[field] = refs.filter((ref) => typeof ref === "string" && !isBlank(ref) && evidenceIds.has(ref));
  }
}

function normalizeLegacyStringListFields(section: JsonObject, fields: readonly string[]): void {
  for (const field of fields) {
    if (!Object.hasOwn(section, field)) continue;
    const value = section[field];
    const normalized =
      typeof value === "string"
        ? isBlank(value) ? [] : [value]
        : Array.isArray(value)
          ? value.filter((item) => typeof item === "string" && !isBlank(item))
          : [];
    if (normalized.length > 0) section[field] = normalized;
    else delete section[field];
  }
}

function removeUnsupportedLegacyScalarFields(section: JsonObject, fields: readonly string[]): void {
  for (const field of fields) {
    if (Object.hasOwn(section, field) && (typeof section[field] !== "string" || section[field] === "")) delete section[field];
  }
}

const evidenceIdsOf = (evidence: unknown[]) =>
  new Set(evidence.filter((item): item is JsonObject => isJsonObject(item) && isNonEmptyString(item.id)).map((item) => item.id as string));

/** A copy of sealed findings with legacy fields reduced to what the current schema accepts. */
export function legacySealedFindingsForValidation(findings: JsonObject): JsonObject {
  const compatible = deepCopyJson(findings);
  const items = compatible.findings;
  if (!Array.isArray(items)) return compatible;
  for (const finding of items) {
    if (!isJsonObject(finding)) continue;
    const canonicalEvidence = Array.isArray(finding.codeEvidence) ? finding.codeEvidence : [];
    const canonicalIds = evidenceIdsOf(canonicalEvidence);
    const legacyEvidence = finding.code_evidence;
    if (Array.isArray(legacyEvidence)) {
      const kept: JsonObject[] = [];
      const seen = new Set(canonicalIds);
      for (const evidence of legacyEvidence) {
        if (!isJsonObject(evidence)) continue;
        const { id, code } = evidence;
        if (typeof id !== "string" || isBlank(id) || typeof code !== "string" || isBlank(code)) continue;
        if (seen.has(id)) continue;
        seen.add(id);
        kept.push(evidence);
      }
      finding.code_evidence = kept;
    } else if (Object.hasOwn(finding, "code_evidence")) {
      delete finding.code_evidence;
    }
    const legacyKept = Array.isArray(finding.code_evidence) ? finding.code_evidence : [];
    const evidenceIds = new Set([...canonicalIds, ...evidenceIdsOf(legacyKept)]);
    for (const [sectionName, listFields] of [
      ["rootCause", ["evidenceRefs", "evidence_refs"]],
      ["root_cause", ["evidenceRefs", "evidence_refs"]],
      ["validation", ["assertions", "counterEvidence", "evidence", "evidenceRefs", "evidence_refs", "limitations"]],
      ["attackPath", ["assumptions", "blindspots", "controls", "evidenceRefs", "evidence_refs", "limitations", "preconditions", "steps"]]
    ] as const) {
      const section = finding[sectionName];
      if (!isJsonObject(section)) continue;
      normalizeLegacyStringListFields(section, listFields);
      filterUnknownLegacyEvidenceRefs(section, evidenceIds);
    }
    const legacyRootCause = finding.root_cause;
    if (isJsonObject(legacyRootCause)) {
      removeUnsupportedLegacyScalarFields(legacyRootCause, ["summary", "code", "language"]);
    } else if (Object.hasOwn(finding, "root_cause") && legacyRootCause !== null && (typeof legacyRootCause !== "string" || legacyRootCause === "")) {
      delete finding.root_cause;
    }
    const validation = finding.validation;
    if (isJsonObject(validation)) removeUnsupportedLegacyScalarFields(validation, ["method", "status", "summary", "disposition", "result"]);
    const attackPath = finding.attackPath;
    if (!isJsonObject(attackPath)) continue;
    removeUnsupportedLegacyScalarFields(attackPath, ["summary"]);
    for (const field of ["dataFlow", "data_flow", "dataflow", "reachability"]) {
      if (!Object.hasOwn(attackPath, field)) continue;
      const detail = attackPath[field];
      if (detail === null || (typeof detail !== "string" && !isJsonObject(detail))) {
        delete attackPath[field];
        continue;
      }
      if (typeof detail === "string") {
        if (detail === "") delete attackPath[field];
        continue;
      }
      const scalarFields = ["summary", "source", "sink", "outcome", ...(field === "reachability" ? ["attacker", "entrypoint"] : [])];
      removeUnsupportedLegacyScalarFields(detail, scalarFields);
      normalizeLegacyStringListFields(detail, ["evidenceRefs", "evidence_refs", "transformations"]);
      filterUnknownLegacyEvidenceRefs(detail, evidenceIds);
      if (field === "reachability") normalizeLegacyStringListFields(detail, ["preconditions"]);
    }
    for (const field of ["impact", "likelihood"]) {
      const detail = attackPath[field];
      if (isJsonObject(detail)) removeUnsupportedLegacyScalarFields(detail, ["level", "rationale", "why"]);
      else if (detail !== undefined && detail !== null && (typeof detail !== "string" || detail === "")) delete attackPath[field];
    }
  }
  return compatible;
}

/** Schema-validate drafts before projection, with placeholder artifact records in the manifest. */
export function validateCanonicalSchemasBeforeProjection(manifest: JsonObject, findings: JsonObject, coverage: JsonObject, schemaDir: string): void {
  const provisional = deepCopyJson(manifest);
  const scan = requireObject(provisional, "scan", "manifest");
  scan.artifacts = [
    { path: "findings.json", sha256: "0".repeat(64), mediaType: "application/json" },
    { path: "coverage.json", sha256: "0".repeat(64), mediaType: "application/json" }
  ];
  validateAgainstSchema(provisional, join(schemaDir, "scan-manifest.schema.json"));
  validateAgainstSchema(findings, join(schemaDir, "findings.schema.json"));
  validateAgainstSchema(coverage, join(schemaDir, "coverage.schema.json"));
}
