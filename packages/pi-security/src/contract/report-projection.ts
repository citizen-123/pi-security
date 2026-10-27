// Markdown report projected from the canonical scan documents. Port of scripts/report_projection.py
// (build_report_markdown and its helpers), byte for byte.
//
// Python semantics kept on purpose: str.split()/strip() whitespace, re's Unicode \s and \d, f-string str() of
// arbitrary values (True, None, reprs), truthiness, bool counting as int, and KeyError where Python indexes with [].
import { isBlank, isJsonObject, pythonStrip, WHITESPACE_CLASS, type JsonObject } from "./contract-error.js";
import { compareCodePoints, hasLoneSurrogate, isPythonInt, pythonEquals, pythonRepr, PyFloat } from "./python-json.js";

export class ReportProjectionError extends Error {
  override name = "ReportProjectionError";
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
const CONFIDENCE_ORDER: Record<string, number> = { high: 0, medium: 1, low: 2 };
const REPORTABLE_SEVERITIES = new Set(["critical", "high", "medium", "low"]);
const DISPOSITION_LABELS: Record<string, string> = {
  reported: "Reported",
  no_issue_found: "No issue found",
  rejected: "Rejected",
  not_applicable: "Not applicable",
  needs_follow_up: "Needs follow-up"
};
const WRITEUP_REPORT_PATH = /^findings\/([a-z0-9][a-z0-9._-]*)\/\1\.md$/;

// ─── Python semantics ───────────────────────────────────────────────────────

const WS = WHITESPACE_CLASS;
const SPLIT = new RegExp(`${WS}+`);
const TRAILING_WHITESPACE = new RegExp(`${WS}+$`);
const BLOCK_START = new RegExp(`^(?:#{1,6}${WS}|[-*+]${WS}|>${WS}|\`\`\`|\\p{Nd}+\\.${WS}|\\|)`, "u");
const INLINE_CODE = /(?<!`)`([^`\n]+)`(?!`)/gu;
const ANNOTATED_TITLE = new RegExp(`^(.+?)${WS}+\\[([^\\[\\]\\n]+)\\]$`, "u");

/** " ".join(value.split()) */
const collapse = (value: string) => value.split(SPLIT).filter(Boolean).join(" ");

/** str(value) as an f-string renders it. */
const str = (value: unknown) => (typeof value === "string" ? value : pythonRepr(value));

/** Python truthiness of a JSON value. */
function truthy(value: unknown): boolean {
  if (value === null || value === undefined || value === false) return false;
  if (value instanceof PyFloat) return value.value !== 0;
  if (typeof value === "number") return value !== 0;
  if (typeof value === "bigint") return value !== 0n;
  if (typeof value === "string" || Array.isArray(value)) return value.length > 0;
  if (typeof value === "object") return Object.keys(value).length > 0;
  return true;
}

/** isinstance(value, int): booleans included. */
const isIntLike = (value: unknown) => typeof value === "boolean" || isPythonInt(value);

const nonBlank = (value: unknown): value is string => typeof value === "string" && !isBlank(value);

/** value[key] on a dict: KeyError when absent. */
function at(value: unknown, key: string): any {
  if (!isJsonObject(value)) throw new TypeError(`${pythonRepr(key)}: not subscriptable`);
  if (!Object.hasOwn(value, key)) throw new Error(`KeyError: ${pythonRepr(key)}`);
  return value[key];
}

/** dict.get(key, fallback) */
const get = (value: JsonObject, key: string, fallback: unknown = null): any => (Object.hasOwn(value, key) ? value[key] : fallback);

/** Iterating a value as Python's for loop would: list items, dict keys, or string characters. */
function iterate(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (typeof value === "string") return [...value];
  if (isJsonObject(value)) return Object.keys(value);
  throw new TypeError(`${pythonRepr(value)} is not iterable`);
}

/** Counter over string keys. */
function counts(values: string[]): Map<string, number> {
  const result = new Map<string, number>();
  for (const value of values) result.set(value, (result.get(value) ?? 0) + 1);
  return result;
}

const unique = <T>(values: T[]) => [...new Set(values)];

// ─── Text rendering ─────────────────────────────────────────────────────────

const escapeMarkdownText = (value: string) => value.replace(/([\\`*[\]<>])/g, "\\$1");

function text(value: unknown, fallback: string): string {
  const candidate = nonBlank(value) ? value : fallback;
  let normalized = collapse(candidate);
  if (!normalized) return "";
  if (BLOCK_START.test(normalized)) normalized = `Text: ${normalized}`;
  let rendered = "";
  let cursor = 0;
  for (const match of normalized.matchAll(INLINE_CODE)) {
    rendered += escapeMarkdownText(normalized.slice(cursor, match.index));
    rendered += `\`${match[1]}\``;
    cursor = match.index! + match[0].length;
  }
  return rendered + escapeMarkdownText(normalized.slice(cursor));
}

function strings(value: unknown): string[] {
  const items = typeof value === "string" ? [value] : Array.isArray(value) ? value : [];
  return items.map((item) => text(item, "")).filter(Boolean);
}

const cell = (value: unknown) => text(value, "none").replaceAll("|", "\\|").replaceAll("\n", "<br>");
const linkLabel = (value: unknown, fallback: string) => cell(value) || cell(fallback);
const bullets = (items: string[], fallback: string) => (items.length > 0 ? items : [fallback]).map((item) => `- ${item}`);

// ─── Deep Scan presentation ─────────────────────────────────────────────────

type GroupEntry = [number, JsonObject, string | null];

function deepReportId(finding: JsonObject): string {
  const extensions = get(finding, "extensions");
  if (isJsonObject(extensions)) {
    if (nonBlank(get(extensions, "reportId"))) return extensions.reportId as string;
    if (nonBlank(get(extensions, "ledgerRowId"))) return extensions.ledgerRowId as string;
  }
  const identity = get(finding, "identity");
  if (isJsonObject(identity) && nonBlank(get(identity, "instance"))) return identity.instance as string;
  const occurrenceId = get(finding, "occurrenceId");
  return nonBlank(occurrenceId) ? occurrenceId : "Unidentified report";
}

function deepCandidateId(finding: JsonObject): string {
  const extensions = get(finding, "extensions");
  if (isJsonObject(extensions) && nonBlank(get(extensions, "candidateId"))) return extensions.candidateId as string;
  return deepReportId(finding);
}

function hasDeepChildMetadata(finding: JsonObject): boolean {
  const extensions = get(finding, "extensions");
  return isJsonObject(extensions) && ["candidateId", "reportId"].some((field) => nonBlank(get(extensions, field)));
}

function usesDeepPresentation(coverage: JsonObject, findings: JsonObject[]): boolean {
  const mode = get(coverage, "mode");
  if (mode === "deep_repository") return true;
  if (mode !== "scoped_path") return false;
  // Scoped deep scans can arrive as scoped_path artifacts; the child ids are the stable deep-scan signal.
  return findings.some(hasDeepChildMetadata);
}

function deepTitleParts(finding: JsonObject): [string, string | null] {
  const title = get(finding, "title");
  if (typeof title !== "string") return ["Untitled finding", null];
  const normalized = collapse(title);
  const match = ANNOTATED_TITLE.exec(normalized);
  if (match === null) return [normalized, null];
  const annotation = match[2]!;
  const recognized = [deepReportId(finding)];
  const extensions = get(finding, "extensions");
  if (isJsonObject(extensions) && nonBlank(get(extensions, "ledgerRowId"))) recognized.push(extensions.ledgerRowId as string);
  if (recognized.some((reportId) => annotation === reportId || annotation.startsWith(`${reportId};`))) return [match[1]!, annotation];
  return [normalized, null];
}

function deepFindingGroups(findings: JsonObject[], writeupPaths: (string | null)[]): GroupEntry[][] {
  const groups = new Map<string, GroupEntry[]>();
  findings.forEach((finding, index) => {
    const key = deepCandidateId(finding);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push([index + 1, finding, writeupPaths[index]!]);
  });
  return [...groups.values()];
}

const deepGroupTitles = (group: GroupEntry[]) => unique(group.map(([, finding]) => cell(deepTitleParts(finding)[0]))).join("<br>");

function deepGroupLevels(group: GroupEntry[], field: string, order: Record<string, number>): string {
  const rank = (level: string) => (Object.hasOwn(order, level) ? order[level]! : Object.keys(order).length);
  const levels = unique(group.map(([, finding]) => at(at(finding, field), "level") as string));
  return levels.sort((left, right) => rank(left) - rank(right)).join("<br>");
}

function deepGroupReportLabels(group: GroupEntry[]): unknown[] {
  const reportIds = group.map(([, finding]) => deepReportId(finding));
  const reportIdCounts = counts(reportIds);
  const labels = group.map(([, finding], index) => {
    const reportId = reportIds[index]!;
    const label = reportIdCounts.get(reportId)! > 1 ? deepTitleParts(finding)[1] : reportId;
    return label || reportId;
  });
  const labelCounts = counts(labels);
  return group.map(([, finding], index) => {
    const label = labels[index]!;
    const identity = get(finding, "identity");
    const chosen = labelCounts.get(label)! > 1 && isJsonObject(identity) ? get(identity, "instance") : label;
    return truthy(chosen) ? chosen : deepReportId(finding);
  });
}

function deepGroupReportLinks(group: GroupEntry[]): string {
  const labels = deepGroupReportLabels(group);
  return group.map(([number], index) => `[${linkLabel(labels[index], "Unidentified report")}](#finding-${number})`).join("<br>");
}

function deepGroupWriteupLinks(group: GroupEntry[]): string {
  const labels = deepGroupReportLabels(group);
  return group
    .map(([, , reportPath], index) => {
      const reportId = linkLabel(labels[index], "Unidentified report");
      return reportPath ? `[Open ${reportId}](${reportPath})` : `${reportId}: inline below`;
    })
    .join("<br>");
}

// ─── Linked documents ───────────────────────────────────────────────────────

function writeupReportPath(finding: JsonObject): string | null {
  const writeup = get(finding, "writeup");
  if (writeup === null) return null;
  if (!isJsonObject(writeup)) throw new ReportProjectionError("finding writeup must be an object");
  const reportPath = get(writeup, "reportPath");
  if (typeof reportPath !== "string" || !WRITEUP_REPORT_PATH.test(reportPath)) {
    throw new ReportProjectionError("finding writeup has an invalid reportPath");
  }
  return reportPath;
}

function hardeningPortfolioPath(scan: JsonObject): string | null {
  const hardening = get(scan, "hardening");
  if (hardening === null) return null;
  if (!isJsonObject(hardening)) throw new ReportProjectionError("scan hardening must be an object");
  const portfolioPath = get(hardening, "portfolioPath");
  if (portfolioPath !== "hardening/hardening.md") throw new ReportProjectionError("scan hardening has an invalid portfolioPath");
  return portfolioPath;
}

// ─── Code evidence ──────────────────────────────────────────────────────────

const hasCode = (item: unknown): item is JsonObject => isJsonObject(item) && nonBlank(get(item, "code"));

function codeEvidenceCatalog(finding: JsonObject): Map<string, JsonObject> {
  const catalog = new Map<string, JsonObject>();
  for (const key of ["codeEvidence", "code_evidence"]) {
    const raw = get(finding, key, []);
    if (!Array.isArray(raw)) continue;
    for (const item of raw) {
      if (hasCode(item) && typeof get(item, "id") === "string" && !catalog.has(item.id as string)) catalog.set(item.id as string, item);
    }
  }
  return catalog;
}

function sectionCodeEvidence(finding: JsonObject, ...sections: JsonObject[]): JsonObject[] {
  const catalog = codeEvidenceCatalog(finding);
  const resolved: JsonObject[] = [];
  for (const section of sections) {
    for (const key of ["evidenceRefs", "evidence_refs"]) {
      let refs = get(section, key, []);
      if (typeof refs === "string") refs = [refs];
      if (Array.isArray(refs)) {
        for (const ref of refs) if (typeof ref === "string" && catalog.has(ref)) resolved.push(catalog.get(ref)!);
      }
    }
    for (const key of ["codeEvidence", "code_evidence"]) {
      const embedded = get(section, key, []);
      if (Array.isArray(embedded)) resolved.push(...embedded.filter(hasCode));
    }
  }
  const seen = new Set<string>();
  return resolved.filter((item) => {
    const key = JSON.stringify([str(get(item, "id", "")), item.code]);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

const ROOT_CAUSE_TEXT_FIELDS = new Set(["cause", "code", "description", "detail", "explanation", "rationale", "summary", "why"]);
const ROOT_CAUSE_SKIPPED_FIELDS = new Set(["evidenceRefs", "evidence_refs", "codeEvidence", "code_evidence", "language"]);

/** The root cause section, merging rootCause and root_cause when both are present. */
export function mergedRootCause(value: JsonObject): [string | null, unknown] {
  const keys = ["rootCause", "root_cause"].filter((key) => Object.hasOwn(value, key));
  if (keys.length === 0) return [null, null];
  if (keys.length === 1) {
    const detail = value[keys[0]!];
    return [keys[0]!, typeof detail === "string" || isJsonObject(detail) ? detail : null];
  }
  const details: JsonObject[] = [];
  for (const key of keys) {
    const detail = value[key];
    if (typeof detail === "string") details.push({ summary: detail });
    else if (isJsonObject(detail)) details.push(detail);
  }
  if (details.length === 0) return [keys[0]!, null];

  const merged: JsonObject = {};
  for (const detail of details) {
    for (const [field, item] of Object.entries(detail)) {
      if (ROOT_CAUSE_SKIPPED_FIELDS.has(field)) continue;
      if (ROOT_CAUSE_TEXT_FIELDS.has(field) && !nonBlank(item)) continue;
      const current = merged[field];
      if (
        !Object.hasOwn(merged, field) ||
        [null, "", [], {}].some((empty) => pythonEquals(current, empty)) ||
        (typeof current === "string" && isBlank(current))
      ) {
        merged[field] = item;
      }
    }
  }

  const evidenceValues = details.flatMap((detail) => ["evidenceRefs", "evidence_refs"].filter((field) => Object.hasOwn(detail, field)).map((field) => detail[field]));
  if (evidenceValues.length > 0) {
    merged.evidenceRefs = unique(evidenceValues.flatMap((evidence) => (Array.isArray(evidence) ? evidence : [evidence])).filter((item) => typeof item === "string"));
  }
  const embedded = details.flatMap((detail) =>
    ["codeEvidence", "code_evidence"].flatMap((field) => (Array.isArray(detail[field]) ? (detail[field] as unknown[]) : []))
  );
  if (embedded.length > 0) merged.codeEvidence = embedded;

  const code = merged.code;
  const matching = nonBlank(code) ? details.filter((detail) => pythonEquals(get(detail, "code"), code)) : details;
  const language = matching.map((detail) => get(detail, "language")).find(nonBlank);
  if (language !== undefined) merged.language = language;
  return [keys[0]!, merged];
}

function rootCauseCodeEvidence(finding: JsonObject, rootCause: JsonObject): JsonObject[] {
  const evidence = sectionCodeEvidence(finding, rootCause);
  const legacyCode = get(rootCause, "code");
  if (!nonBlank(legacyCode) || evidence.some((item) => item.code === legacyCode)) return evidence;
  const rootLocation = iterate(get(finding, "locations", [])).find((location) => isJsonObject(location) && get(location, "role") === "root_control") ?? {};
  return [...evidence, { code: legacyCode, label: "Broken control", language: get(rootCause, "language", ""), location: rootLocation }];
}

function codeEvidenceLocation(item: JsonObject): string {
  const location = get(item, "location");
  if (typeof location === "string") return location;
  const source = isJsonObject(location) ? location : item;
  const path = get(source, "path");
  const start = get(source, "startLine");
  const end = get(source, "endLine", start);
  if (typeof path !== "string" || !path) return "";
  if (!isIntLike(start)) return path;
  return pythonEquals(end, start) ? `${path}:${str(start)}` : `${path}:${str(start)}-${str(end)}`;
}

function codeFence(code: string): string {
  const longest = Math.max(0, ...[...code.matchAll(/`+/g)].map((match) => match[0].length));
  return "`".repeat(Math.max(3, longest + 1));
}

function codeEvidenceLines(evidence: JsonObject[]): string[] {
  const lines: string[] = [];
  evidence.forEach((item, index) => {
    const label = text(get(item, "label"), `Code evidence ${index + 1}`);
    const location = text(codeEvidenceLocation(item), "");
    const explanation = text(get(item, "explanation"), "");
    const rawLanguage = get(item, "language");
    const language = typeof rawLanguage === "string" && /^[A-Za-z0-9_+.-]*$/.test(rawLanguage) ? rawLanguage : "";
    const code = item.code as string;
    const fence = codeFence(code);
    let heading = `**${label}**`;
    if (location) heading += ` — \`${location}\``;
    lines.push("", heading);
    if (explanation) lines.push("", explanation);
    lines.push("", `${fence}${language}`, code, fence);
  });
  return lines;
}

// ─── Summaries ──────────────────────────────────────────────────────────────

function levelMix(findings: JsonObject[], field: string, order: string[]): string {
  const tally = counts(findings.map((finding) => at(at(finding, field), "level") as string));
  return order.filter((level) => tally.get(level)).map((level) => `${level}: ${tally.get(level)}`).join(", ") || "none";
}

function locations(finding: JsonObject): string {
  return iterate(at(finding, "locations"))
    .map((location) => {
      const start = at(location, "startLine");
      const end = get(location as JsonObject, "endLine", start);
      const suffix = pythonEquals(end, start) ? `:${str(start)}` : `:${str(start)}-${str(end)}`;
      return `${str(at(location, "path"))}${suffix}`;
    })
    .join(", ");
}

function compareFindings(left: JsonObject, right: JsonObject): number {
  const rank = (finding: JsonObject) => {
    const level = at(at(finding, "severity"), "level");
    return typeof level === "string" && Object.hasOwn(SEVERITY_ORDER, level) ? SEVERITY_ORDER[level]! : 5;
  };
  return (
    rank(left) - rank(right) ||
    compareCodePoints(get(left, "occurrenceId", "") as string, get(right, "occurrenceId", "") as string) ||
    compareCodePoints(at(left, "title") as string, at(right, "title") as string)
  );
}

function targetScopeLines(target: JsonObject): string[] {
  const lines = [`- Target kind: ${text(get(target, "kind"), "not recorded")}`, `- Target ID: ${text(get(target, "targetId"), "not recorded")}`];
  const baseRevision = text(get(target, "baseRevision"), "");
  const headRevision = text(get(target, "headRevision"), "");
  if (baseRevision || headRevision) lines.push(`- Revision range: ${baseRevision || "unknown"}...${headRevision || "unknown"}`);
  const revision = text(get(target, "revision"), "");
  if (revision) lines.push(`- Revision: ${revision}`);
  const snapshotDigest = text(get(target, "snapshotDigest"), "");
  if (snapshotDigest) lines.push(`- Snapshot digest: ${snapshotDigest}`);
  return lines;
}

function surfaceNotes(surface: JsonObject): string {
  const notes = get(surface, "notes", "No additional canonical notes were recorded.");
  const receiptRefs = get(surface, "receiptRefs", []);
  if (!Array.isArray(receiptRefs) || receiptRefs.length === 0) return cell(notes);
  const evidence = receiptRefs.filter((item) => typeof item === "string").join(", ");
  if (!evidence) return cell(notes);
  return cell(`${str(notes)} Evidence: ${evidence}`);
}

// ─── Finding sections ───────────────────────────────────────────────────────

const objectOrEmpty = (value: unknown): JsonObject => (isJsonObject(value) ? value : {});

function findingSection(number: number, finding: JsonObject): string[] {
  const validation = objectOrEmpty(get(finding, "validation"));
  const [, rawRootCause] = mergedRootCause(finding);
  const rootCause = objectOrEmpty(rawRootCause);
  const attackPath = objectOrEmpty(get(finding, "attackPath"));
  const dataflowSections: JsonObject[] = ["dataFlow", "dataflow", "data_flow"]
    .map((key) => get(attackPath, key))
    .filter((value) => typeof value === "string" || isJsonObject(value))
    .map((value) => (typeof value === "string" ? { summary: value } : value));
  const dataflow: JsonObject = {};
  for (const key of ["summary", "source", "sink", "outcome"]) {
    const section = dataflowSections.find((candidate) => Object.hasOwn(candidate, key) && nonBlank(candidate[key]));
    if (section !== undefined) dataflow[key] = section[key];
  }
  const transformations = unique(
    dataflowSections.flatMap((section) => {
      const value = get(section, "transformations");
      return typeof value === "string" ? [value] : Array.isArray(value) ? value : [];
    })
  ).filter(nonBlank);
  if (transformations.length > 0) dataflow.transformations = transformations;
  const rawReachability = get(attackPath, "reachability");
  const reachability: JsonObject =
    typeof rawReachability === "string" ? { summary: rawReachability } : objectOrEmpty(rawReachability);
  const severity = at(finding, "severity") as JsonObject;
  const confidence = at(finding, "confidence") as JsonObject;
  const validationOutcomes = (
    [
      ["Status", "status"],
      ["Disposition", "disposition"],
      ["Result", "result"]
    ] as const
  )
    .map(([label, key]) => [label, text(get(validation, key), "")] as const)
    .filter(([, value]) => value);
  const validationSummary = text(
    get(validation, "summary"),
    validationOutcomes.length > 0
      ? "Validation outcomes are recorded below."
      : `${str(at(confidence, "rationale"))} Validation details were not recorded separately.`
  );
  const validationEvidence = strings(get(validation, "evidence"));
  const validationAssertions = strings(get(validation, "assertions"));
  const validationCounterevidence = strings(get(validation, "counterEvidence"));
  const validationLimitations = strings(get(validation, "limitations"));
  const rootCauseSummary = text(typeof rawRootCause === "string" ? rawRootCause : get(rootCause, "summary"), "");
  const rootCauseEvidence = rootCauseCodeEvidence(finding, rootCause);
  const validationCodeEvidence = sectionCodeEvidence(finding, validation);
  const dataflowCodeEvidence = sectionCodeEvidence(finding, attackPath, ...dataflowSections);
  const reachabilityCodeEvidence = sectionCodeEvidence(finding, reachability);
  const dataflowSummary = text(
    get(dataflow, "summary"),
    `The canonical finding records the affected path at ${locations(finding)}, but no expanded source-to-sink narrative was recorded.`
  );
  const reachabilitySummary = text(
    get(reachability, "summary"),
    text(get(attackPath, "summary"), "Reachability was not recorded beyond the canonical finding summary and affected locations.")
  );
  const level = at(severity, "level");
  const severityRationale = text(
    get(severity, "rationale"),
    `The scan assigned ${str(level)} severity; no separate canonical severity rationale was recorded.`
  );
  const severityChange = text(get(severity, "changeConditions"), "Additional runtime or deployment evidence could raise or lower this severity.");
  const remediationTests = strings(get(finding, "remediationTests"));
  const preventiveControls = strings(get(finding, "preventiveControls"));
  const attackSteps = strings(get(attackPath, "steps"));
  const taxonomy = at(finding, "taxonomy") as JsonObject;
  const cwes = (at(taxonomy, "cwe") as string[]).join(", ") || "none";
  const title = text(at(finding, "title"), "Untitled finding");
  const lines = [
    `<a id="finding-${number}"></a>`,
    "",
    `### [${number}] ${title}`,
    "",
    "| Field | Value |",
    "| --- | --- |",
    `| Severity | ${cell(level)} |`,
    `| Confidence | ${cell(at(confidence, "level"))} |`,
    `| Confidence rationale | ${cell(at(confidence, "rationale"))} |`,
    `| Category | ${cell(at(taxonomy, "category"))} |`,
    `| CWE | ${cell(cwes)} |`,
    `| Affected lines | ${cell(locations(finding))} |`,
    "",
    "#### Summary",
    "",
    text(at(finding, "summary"), "No canonical finding summary was recorded.")
  ];
  if (rootCauseSummary || rootCauseEvidence.length > 0) {
    lines.push("", "#### Root Cause", "");
    if (rootCauseSummary) lines.push(rootCauseSummary);
    lines.push(...codeEvidenceLines(rootCauseEvidence));
  }
  lines.push("", "#### Validation", "", validationSummary);
  if (truthy(get(validation, "method"))) lines.push("", `Validation method: ${text(validation.method, "not recorded")}`);
  if (validationOutcomes.length > 0) lines.push("", ...validationOutcomes.map(([label, value]) => `- **${label}:** ${value}`));
  lines.push(...codeEvidenceLines(validationCodeEvidence));
  if (validationAssertions.length > 0) lines.push("", "Assertions:", ...bullets(validationAssertions, "None recorded."));
  if (validationEvidence.length > 0) lines.push("", "Evidence:", ...bullets(validationEvidence, "No evidence recorded."));
  if (validationCounterevidence.length > 0) {
    lines.push("", "Counterevidence and remaining uncertainty:", ...bullets(validationCounterevidence, "None recorded."));
  }
  if (validationLimitations.length > 0) lines.push("", "Limitations:", ...bullets(validationLimitations, "None recorded."));
  lines.push("", "#### Dataflow", "", dataflowSummary);
  if (attackSteps.length > 0) lines.push("", "Attack steps:", ...bullets(attackSteps, "None recorded."));
  for (const [label, key] of [
    ["Source", "source"],
    ["Sink", "sink"],
    ["Outcome", "outcome"]
  ]) {
    if (truthy(get(dataflow, key!))) lines.push("", `- **${label}:** ${text(dataflow[key!], "not recorded")}`);
  }
  const transformationLines = strings(get(dataflow, "transformations"));
  if (transformationLines.length > 0) lines.push("", "Transformations:", ...bullets(transformationLines, "None recorded."));
  lines.push(...codeEvidenceLines(dataflowCodeEvidence));
  lines.push("", "#### Reachability", "", reachabilitySummary);
  for (const [label, key] of [
    ["Attacker", "attacker"],
    ["Entry point", "entrypoint"],
    ["Source", "source"],
    ["Sink", "sink"],
    ["Outcome", "outcome"]
  ]) {
    if (truthy(get(reachability, key!))) lines.push("", `- **${label}:** ${text(reachability[key!], "not recorded")}`);
  }
  const preconditions = unique([...strings(get(attackPath, "preconditions")), ...strings(get(reachability, "preconditions"))]);
  if (preconditions.length > 0) lines.push("", "Preconditions:", ...bullets(preconditions, "None recorded."));
  for (const [label, key] of [
    ["Assumptions", "assumptions"],
    ["Existing controls", "controls"],
    ["Blind spots", "blindspots"],
    ["Limitations", "limitations"]
  ]) {
    const values = strings(get(attackPath, key!));
    if (values.length > 0) lines.push("", `${label}:`, ...bullets(values, "None recorded."));
  }
  lines.push(...codeEvidenceLines(reachabilityCodeEvidence));
  lines.push("", "#### Severity", "", `**${capitalize(level as string)}** — ${severityRationale}`, "", severityChange);
  for (const [label, key] of [
    ["Impact", "impact"],
    ["Likelihood", "likelihood"]
  ]) {
    const assessment = get(attackPath, key!);
    if (typeof assessment === "string") {
      const rendered = text(assessment, "");
      if (rendered) lines.push("", `**${label} assessment:** ${rendered}`);
      continue;
    }
    if (!isJsonObject(assessment)) continue;
    const details = (
      [
        ["Level", "level"],
        ["Rationale", "rationale"],
        ["Why", "why"]
      ] as const
    )
      .map(([name, detailKey]) => [name, text(get(assessment, detailKey), "")] as const)
      .filter(([, value]) => value);
    if (details.length > 0) lines.push("", `${label} assessment:`, ...details.map(([name, value]) => `- **${name}:** ${value}`));
  }
  lines.push("", "#### Remediation", "", text(at(finding, "remediation"), "No canonical remediation was recorded."));
  if (remediationTests.length > 0) lines.push("", "Tests:", ...bullets(remediationTests, "No tests recorded."));
  if (preventiveControls.length > 0) lines.push("", "Preventive controls:", ...bullets(preventiveControls, "None recorded."));
  return lines;
}

/** str.capitalize() */
const capitalize = (value: string) => {
  const [first = "", ...rest] = [...value];
  return first.toUpperCase() + rest.join("").toLowerCase();
};

function linkedFindingSection(number: number, finding: JsonObject, reportPath: string): string[] {
  const taxonomy = at(finding, "taxonomy") as JsonObject;
  const confidence = at(finding, "confidence") as JsonObject;
  const cwes = (at(taxonomy, "cwe") as string[]).join(", ") || "none";
  const link = `[detailed technical write-up](${reportPath})`;
  const lines = [
    `<a id="finding-${number}"></a>`,
    "",
    `### [${number}] ${text(at(finding, "title"), "Untitled finding")}`,
    "",
    "| Field | Value |",
    "| --- | --- |",
    `| Severity | ${cell(at(at(finding, "severity"), "level"))} |`,
    `| Confidence | ${cell(at(confidence, "level"))} |`,
    `| Confidence rationale | ${cell(at(confidence, "rationale"))} |`,
    `| Category | ${cell(at(taxonomy, "category"))} |`,
    `| CWE | ${cell(cwes)} |`,
    `| Affected lines | ${cell(locations(finding))} |`
  ];
  for (const heading of ["Summary", "Validation", "Dataflow", "Reachability", "Severity", "Remediation"]) {
    lines.push("", `#### ${heading}`, "", `See the ${link}.`);
  }
  return lines;
}

// ─── Report ─────────────────────────────────────────────────────────────────

const TIME_LIMIT_REASON = "The configured discovery time limit elapsed before any source review completed.";
const COST_LIMIT_REASON = "Validation was deferred because the scan reached its cost limit.";

export function buildReportMarkdown(manifest: JsonObject, findingsDocument: JsonObject, coverage: JsonObject): string {
  const scan = at(manifest, "scan") as JsonObject;
  const target = at(scan, "target") as JsonObject;
  const scope = at(scan, "scope") as JsonObject;
  const threatModel = objectOrEmpty(get(scan, "threatModel"));
  const findings = (iterate(at(findingsDocument, "findings")) as JsonObject[])
    .filter((finding) => REPORTABLE_SEVERITIES.has(at(at(finding, "severity"), "level")))
    .sort(compareFindings);
  const writeupPaths = findings.map(writeupReportPath);
  const duplicates = [...counts(writeupPaths.filter((path): path is string => path !== null))]
    .filter(([, count]) => count > 1)
    .map(([path]) => path)
    .sort(compareCodePoints);
  if (duplicates.length > 0) {
    throw new ReportProjectionError(`reportable findings have duplicate writeup reportPath values: ${duplicates.join(", ")}`);
  }
  const deepPresentation = usesDeepPresentation(coverage, findings);
  const deepGroups = deepPresentation ? deepFindingGroups(findings, writeupPaths) : [];
  const portfolioPath = hardeningPortfolioPath(scan);
  const includePaths = strings(get(coverage, "includePaths", get(scope, "includePaths", [])));
  const excludePaths = strings(get(coverage, "excludePaths", get(scope, "excludePaths", [])));
  const limitations = strings(get(scope, "limitations"));
  const explicitExclusions = get(coverage, "explicitExclusions", []);
  const lines = [
    `# Security Review: ${text(at(target, "displayName"), "Unknown target")}`,
    "",
    "## Scope",
    "",
    text(get(scope, "summary"), "The scan reviewed the canonical include paths and exclusions listed below."),
    "",
    `- Scan mode: ${str(at(coverage, "mode"))}`,
    ...targetScopeLines(target),
    `- Inventory strategy: ${str(at(coverage, "inventoryStrategy"))}`,
    `- Included paths: ${includePaths.join(", ") || "none"}`,
    `- Excluded paths: ${excludePaths.join(", ") || "none"}`,
    `- Runtime or test status: ${text(get(scope, "runtimeStatus"), "not recorded")}`
  ];
  const artifactsReviewed = strings(get(scope, "artifactsReviewed"));
  if (artifactsReviewed.length > 0) lines.push(`- Artifacts reviewed: ${artifactsReviewed.join(", ")}`);
  const context = text(get(scope, "context"), "");
  if (context) lines.push(`- Scan context: ${context}`);
  for (const exclusion of iterate(explicitExclusions)) {
    if (isJsonObject(exclusion)) {
      limitations.push(`Excluded ${text(get(exclusion, "pattern"), "unspecified")}: ${text(get(exclusion, "reason"), "reason not recorded")}`);
    }
  }
  if (limitations.length > 0) lines.push("", "Limitations and exclusions:", ...bullets(limitations, "None recorded."));
  const severityOrder = Object.keys(SEVERITY_ORDER);
  const confidenceOrder = ["high", "medium", "low"];
  const summaryCountLines = deepPresentation
    ? [
        `| Reportable DSS findings | ${deepGroups.length} |`,
        `| Report instances | ${findings.length} |`,
        `| Report severity mix | ${levelMix(findings, "severity", severityOrder)} |`,
        `| Report confidence mix | ${levelMix(findings, "confidence", confidenceOrder)} |`
      ]
    : [
        `| Reportable findings | ${findings.length} |`,
        `| Severity mix | ${levelMix(findings, "severity", severityOrder)} |`,
        `| Confidence mix | ${levelMix(findings, "confidence", confidenceOrder)} |`
      ];
  lines.push(
    "",
    "### Scan Summary",
    "",
    "| Field | Value |",
    "| --- | --- |",
    `| Scan outcome | ${str(get(scan, "status", "completed"))} |`,
    ...summaryCountLines,
    `| Coverage | ${str(at(coverage, "completeness"))} |`,
    `| Validation mode | ${cell(get(scope, "validationMode", "not recorded"))} |`,
    "",
    "Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.",
    "",
    "## Threat Model",
    "",
    text(get(threatModel, "summary"), "No explicit canonical threat-model summary was recorded.")
  );
  for (const [heading, key, fallback] of [
    ["Assets", "assets", "No assets were recorded."],
    ["Trust Boundaries", "trustBoundaries", "No trust boundaries were recorded."],
    ["Attacker Capabilities", "attackerCapabilities", "No attacker capabilities were recorded."],
    ["Security Objectives", "securityObjectives", "No security objectives were recorded."],
    ["Assumptions", "assumptions", "No assumptions were recorded."]
  ]) {
    const values = strings(get(threatModel, key!));
    if (values.length > 0) lines.push("", `### ${heading}`, "", ...bullets(values, fallback!));
  }
  lines.push("", "## Findings", "");
  if (findings.length > 0) {
    if (deepPresentation) {
      lines.push("| Findings | Reports | Severity | Confidence | Detailed write-up |", "| --- | --- | --- | --- | --- |");
      for (const group of deepGroups) {
        lines.push(
          `| ${deepGroupTitles(group)} | ${deepGroupReportLinks(group)} ` +
            `| ${deepGroupLevels(group, "severity", SEVERITY_ORDER)} ` +
            `| ${deepGroupLevels(group, "confidence", CONFIDENCE_ORDER)} ` +
            `| ${deepGroupWriteupLinks(group)} |`
        );
      }
    } else {
      lines.push("| Finding | Severity | Confidence | Detailed write-up |", "| --- | --- | --- | --- |");
      findings.forEach((finding, index) => {
        const number = index + 1;
        const reportPath = writeupPaths[index];
        const findingLink = `[${linkLabel(at(finding, "title"), "Untitled finding")}](#finding-${number})`;
        const writeupLink = reportPath ? `[Open report](${reportPath})` : "inline below";
        lines.push(
          `| ${findingLink} | ${str(at(at(finding, "severity"), "level"))} | ${str(at(at(finding, "confidence"), "level"))} | ${writeupLink} |`
        );
      });
    }
    lines.push(
      "",
      "### Confidence Scale",
      "",
      "| Label | Meaning |",
      "| --- | --- |",
      "| high | Direct evidence supports the finding with no material unresolved blocker. |",
      "| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |",
      "| low | Evidence is incomplete and the item is retained only for explicit follow-up. |"
    );
    findings.forEach((finding, index) => {
      const reportPath = writeupPaths[index];
      lines.push("", ...(reportPath !== null ? linkedFindingSection(index + 1, finding, reportPath!) : findingSection(index + 1, finding)));
    });
  } else {
    const deferred = get(coverage, "deferred", []);
    const partialWith = (predicate: (reason: unknown) => boolean) =>
      get(coverage, "completeness") === "partial" &&
      Array.isArray(deferred) &&
      deferred.some((item) => isJsonObject(item) && predicate(get(item, "reason")));
    const noSourceReview = partialWith((reason) => reason === TIME_LIMIT_REASON);
    const budgetExhausted = partialWith(
      (reason) => typeof reason === "string" && (reason === COST_LIMIT_REASON || reason.startsWith(`${COST_LIMIT_REASON.slice(0, -1)}: `))
    );
    const status = get(objectOrEmpty(get(manifest, "scan", {})), "status");
    const stopped = ["failed", "canceled", "interrupted"].includes(status);
    lines.push(
      "### No findings",
      "",
      stopped
        ? "No findings were retained before the scan stopped. The scan did not complete. No vulnerability conclusion can be drawn."
        : noSourceReview
          ? "No source review completed before the configured time limit. No vulnerability conclusion can be drawn."
          : budgetExhausted
            ? "No findings were validated before the scan reached its cost limit. Review the deferred candidates in Open Questions And Follow Up."
            : "No reportable findings survived the canonical discovery, validation, and reportability gates."
    );
  }
  if (portfolioPath !== null) {
    lines.push(
      "",
      "## Structural Hardening",
      "",
      "The scan also produced derived, unsealed design guidance based on the complete finding collection. These proposals describe options and tradeoffs; they do not indicate that any finding has been remediated.",
      "",
      `[Open the structural hardening portfolio](${portfolioPath})`
    );
  }
  const surfaces = get(coverage, "surfaces", []);
  if (truthy(surfaces)) {
    lines.push("", "## Reviewed Surfaces", "", "| Surface | Risk Area | Outcome | Notes |", "| --- | --- | --- | --- |");
    for (const surface of iterate(surfaces)) {
      if (!isJsonObject(surface)) continue;
      const disposition = get(surface, "disposition");
      const outcome = typeof disposition === "string" && Object.hasOwn(DISPOSITION_LABELS, disposition) ? DISPOSITION_LABELS[disposition] : disposition;
      lines.push(
        `| ${[
          cell(get(surface, "label", get(surface, "id"))),
          cell(get(surface, "riskArea", "not recorded")),
          cell(outcome),
          surfaceNotes(surface)
        ].join(" | ")} |`
      );
    }
  }
  const openQuestions = get(coverage, "openQuestions", []);
  const questions: unknown[] = Array.isArray(openQuestions) ? [...openQuestions] : [];
  const deferred = get(coverage, "deferred", []);
  if (Array.isArray(deferred)) {
    for (const item of deferred) {
      if (!isJsonObject(item)) continue;
      const paths = get(item, "paths", []);
      const surfaceIds = get(item, "surfaceIds", []);
      questions.push({
        question: get(item, "reason", "Deferred review requires follow-up."),
        followUpPrompt: pythonStrip(
          [
            `Review deferred unit ${str(get(item, "id", "unknown"))} and close its stated proof gap.`,
            truthy(get(item, "paths")) ? `Paths: ${(iterate(paths) as string[]).join(", ")}.` : "",
            truthy(get(item, "surfaceIds")) ? `Surfaces: ${(iterate(surfaceIds) as string[]).join(", ")}.` : ""
          ].join(" ")
        )
      });
    }
  }
  if (questions.length > 0) {
    lines.push("", "## Open Questions And Follow Up", "");
    for (const question of questions) {
      if (!isJsonObject(question)) continue;
      lines.push(`- ${text(get(question, "question"), "Unspecified open question.")}`);
      const prompt = text(get(question, "followUpPrompt"), "");
      if (prompt) lines.push(`  - Follow-up prompt: ${prompt}`);
    }
  }
  return `${lines.join("\n").replace(TRAILING_WHITESPACE, "")}\n`;
}

/** generate_report_markdown: the report as UTF-8 bytes. Lone surrogates fail to encode, as in Python. */
export function generateReportMarkdown(manifest: JsonObject, findings: JsonObject, coverage: JsonObject): Buffer {
  const markdown = buildReportMarkdown(manifest, findings, coverage);
  if (hasLoneSurrogate(markdown)) throw new Error("'utf-8' codec can't encode a surrogate: surrogates not allowed");
  return Buffer.from(markdown, "utf8");
}
