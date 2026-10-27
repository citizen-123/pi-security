// SARIF 2.1.0 projection of sealed findings. Port of build_sarif, _validate_sarif, and their helpers (including
// GitHub's primaryLocationLineHash) in scripts/finalize_scan_contract.py.
import { closeSync, readFileSync, realpathSync } from "node:fs";
import { requireSafeRelativePath } from "./contract-paths.js";
import { ContractError, isJsonObject, WHITESPACE_CLASS, type JsonObject } from "./contract-error.js";
import { openScanLocalFile } from "./scan-files.js";
import { compareCodePoints, PyFloat, pythonFloatRepr } from "./python-json.js";

export const SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json";

const SARIF_LEVELS: Record<string, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  informational: "note"
};
const SARIF_SECURITY_SCORES: Record<string, PyFloat> = {
  critical: new PyFloat(9.5),
  high: new PyFloat(8.0),
  medium: new PyFloat(5.0),
  low: new PyFloat(2.0),
  informational: new PyFloat(0.0)
};
const ACRONYMS = new Set(["api", "csrf", "html", "http", "id", "rce", "sql", "ssrf", "url", "xml", "xss"]);
const WHITESPACE_RUN = new RegExp(`${WHITESPACE_CLASS}+`);

type Finding = JsonObject & {
  ruleId: string;
  taxonomy: { category: string; cwe: string[] };
  severity: { level: string; score?: unknown };
  confidence: { level: string };
  locations: Location[];
};
type Location = { path: string; startLine: number; endLine?: number; role?: string };

const sortedUnique = (values: Iterable<string>) => [...new Set(values)].sort(compareCodePoints);

/** str() of a JSON number as Python prints it. */
function pythonNumber(value: unknown): string {
  if (value instanceof PyFloat) return pythonFloatRepr(value.value);
  if (typeof value === "number") return Number.isInteger(value) ? String(value) : pythonFloatRepr(value);
  return String(value);
}

const numberValue = (value: unknown): number => (value instanceof PyFloat ? value.value : Number(value));

export function sarifLabel(value: string): string {
  const words = value.replace(/[-_./]+/g, " ").split(WHITESPACE_RUN).filter((word) => word !== "");
  const label = words.map((word) => (ACRONYMS.has(word.toLowerCase()) ? word.toUpperCase() : word)).join(" ");
  const [first = "", ...rest] = [...label];
  return first.toUpperCase() + rest.join("");
}

function sarifRule(ruleId: string, findings: Finding[]): JsonObject {
  const name = ruleId.split(".").map(sarifLabel).join(": ");
  const categories = sortedUnique(findings.map((finding) => finding.taxonomy.category));
  const cwes = sortedUnique(findings.flatMap((finding) => finding.taxonomy.cwe));
  const tags = new Set(["security", ...categories]);
  for (const cwe of cwes) {
    const match = /^CWE-([0-9]+)$/i.exec(cwe);
    if (match !== null && BigInt(match[1]!) > 0n) tags.add(`external/cwe/cwe-${BigInt(match[1]!).toString().padStart(3, "0")}`);
  }
  let description = `${name}. Categories: ${categories.map(sarifLabel).join(", ")}.`;
  if (cwes.length > 0) description += ` Weaknesses: ${cwes.join(", ")}.`;
  const remediation = sortedUnique(findings.map((finding) => finding.remediation as string)).join("\n\n");
  const properties: JsonObject = { tags: [...tags].sort(compareCodePoints) };
  // GitHub assigns security severity to the shared rule, not each result. max() keeps the first maximal score.
  let score: unknown;
  for (const finding of findings) {
    const candidate = Object.hasOwn(finding.severity, "score") ? finding.severity.score : SARIF_SECURITY_SCORES[finding.severity.level];
    if (score === undefined || numberValue(candidate) > numberValue(score)) score = candidate;
  }
  if (numberValue(score) > 0) properties["security-severity"] = pythonNumber(score);
  return {
    id: ruleId,
    name,
    shortDescription: { text: name },
    fullDescription: { text: description },
    help: {
      text: `${description}\n\nRemediation:\n\n${remediation}`,
      markdown: `${description}\n\n## Remediation\n\n${remediation}`
    },
    properties
  };
}

function sarifFindingMessage(finding: Finding): string {
  const taxonomy = finding.taxonomy;
  const details = [
    finding.title as string,
    finding.summary as string,
    `Severity: ${finding.severity.level}`,
    `Category: ${sarifLabel(taxonomy.category)}`
  ];
  if (taxonomy.cwe.length > 0) details.push(`Weaknesses: ${taxonomy.cwe.join(", ")}`);
  details.push(`Remediation:\n${finding.remediation as string}`);
  for (const [key, label] of [
    ["remediationTests", "Remediation tests"],
    ["preventiveControls", "Preventive controls"]
  ] as const) {
    // Python iterates whatever is there: list items, a string's characters, an object's keys.
    const value = finding[key];
    const items = Array.isArray(value) ? value : typeof value === "string" ? [...value] : isJsonObject(value) ? Object.keys(value) : [];
    if (items.length > 0) details.push(`${label}:\n${items.map((item) => `- ${item}`).join("\n")}`);
  }
  return details.join("\n\n");
}

function primaryLocation(finding: Finding): Location {
  return finding.locations.find((location) => location.role === "root_control") ?? finding.locations[0]!;
}

export function mergedCodeEvidence(finding: JsonObject): JsonObject[] {
  const catalog = new Map<string, JsonObject>();
  for (const key of ["codeEvidence", "code_evidence"]) {
    const evidence = finding[key];
    if (!Array.isArray(evidence)) continue;
    for (const item of evidence) {
      if (!isJsonObject(item)) continue;
      if (typeof item.id === "string" && item.id !== "" && !catalog.has(item.id)) catalog.set(item.id, item);
    }
  }
  return [...catalog.values()];
}

const isLine = (value: unknown): value is number => typeof value === "number" && Number.isInteger(value);

function sarifLocations(finding: Finding): Location[] {
  const primary = primaryLocation(finding);
  const locations: Location[] = [primary, ...finding.locations.filter((location) => location !== primary)];
  for (const evidence of mergedCodeEvidence(finding)) {
    const { path, startLine, endLine } = evidence;
    if (typeof path !== "string" || !isLine(startLine) || startLine < 1) continue;
    let safe: string;
    try {
      safe = requireSafeRelativePath(path, "SARIF evidence location");
    } catch (error) {
      if (error instanceof ContractError) continue;
      throw error;
    }
    locations.push({
      path: safe,
      startLine,
      endLine: isLine(endLine) && endLine >= startLine ? endLine : startLine,
      role: `evidence:${evidence.id as string}`
    });
  }
  const unique = new Map<string, Location>();
  for (const location of locations) {
    const key = JSON.stringify([location.path, location.startLine, location.endLine ?? location.startLine]);
    if (!unique.has(key)) unique.set(key, location);
  }
  return [...unique.values()];
}

/** urllib.parse.quote(value, safe="/"). */
export function pythonQuote(value: string): string {
  let out = "";
  for (const byte of Buffer.from(value, "utf8")) {
    const character = String.fromCharCode(byte);
    out += /[A-Za-z0-9_.\-~/]/.test(character) ? character : `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return out;
}

function sarifLocation(location: Location): JsonObject {
  const result: JsonObject = {
    physicalLocation: {
      artifactLocation: { uri: pythonQuote(location.path) },
      region: { startLine: location.startLine, endLine: location.endLine ?? location.startLine }
    }
  };
  if (location.role) result.message = { text: location.role };
  return result;
}

const MASK = (1n << 64n) - 1n;
const HASH_MOD = 37n;
const BLOCK_SIZE = 100;
const HASH_EOF = 65535;
const FIRST_MOD = HASH_MOD ** BigInt(BLOCK_SIZE) & MASK;

/** GitHub's rolling line hashes over UTF-16 code units, as `primaryLocationLineHash` expects. */
export function githubLineHashes(text: string, requestedLines?: Set<number>): Map<number, string> {
  const window: bigint[] = new Array(BLOCK_SIZE).fill(0n);
  const lineNumbers: number[] = new Array(BLOCK_SIZE).fill(-1);
  const hashCounts = new Map<string, number>();
  const hashes = new Map<number, string>();
  let hashRaw = 0n;
  let index = 0;
  let lineNumber = 0;
  let lineStart = true;
  let previousWasCr = false;

  const outputHash = () => {
    const value = (hashRaw & MASK).toString(16);
    hashCounts.set(value, (hashCounts.get(value) ?? 0) + 1);
    const line = lineNumbers[index]!;
    if (requestedLines === undefined || requestedLines.has(line)) hashes.set(line, `${value}:${hashCounts.get(value)}`);
    lineNumbers[index] = -1;
  };
  const updateHash = (current: number) => {
    const beginning = window[index]!;
    window[index] = BigInt(current);
    hashRaw = (HASH_MOD * hashRaw + BigInt(current) - FIRST_MOD * beginning) & MASK;
    index = (index + 1) % BLOCK_SIZE;
  };
  const processCharacter = (input: number) => {
    let current = input;
    if (current === 0x20 || current === 0x09 || (previousWasCr && current === 0x0a)) {
      previousWasCr = false;
      return;
    }
    if (current === 0x0d) {
      current = 0x0a;
      previousWasCr = true;
    } else previousWasCr = false;
    if (lineNumbers[index] !== -1) outputHash();
    if (lineStart) {
      lineStart = false;
      lineNumber += 1;
      lineNumbers[index] = lineNumber;
    }
    if (current === 0x0a) lineStart = true;
    updateHash(current);
  };

  for (let position = 0; position < text.length; position++) processCharacter(text.charCodeAt(position));
  processCharacter(HASH_EOF);
  for (let step = 0; step < BLOCK_SIZE; step++) {
    if (lineNumbers[index] !== -1) outputHash();
    updateHash(0);
  }
  return hashes;
}

/** Line hashes of a source file, read as Python's text mode reads it; undefined when it cannot be opened safely. */
export function githubLineHashesForSource(sourceRoot: string, relativePath: string, requestedLines: Set<number>): Map<number, string> | undefined {
  let descriptor: number;
  try {
    descriptor = openScanLocalFile(sourceRoot, relativePath, `source file ${relativePath}`);
  } catch {
    return undefined;
  }
  try {
    // UTF-8 with replacement and universal newlines; Python's utf-8 codec keeps a byte-order mark. (The newline
    // translation cannot change a hash, which already treats "\r" and "\r\n" as "\n"; it mirrors Python's text mode.)
    const text = new TextDecoder("utf-8", { ignoreBOM: true }).decode(readFileSync(descriptor)).replace(/\r\n?/g, "\n");
    return githubLineHashes(text, requestedLines);
  } catch {
    return undefined;
  } finally {
    closeSync(descriptor);
  }
}

function lineHashCache(findings: Finding[], sourceRoot: string | undefined): Map<string, string | undefined> {
  const cache = new Map<string, string | undefined>();
  if (sourceRoot === undefined) return cache;
  let root: string;
  try {
    root = realpathSync(sourceRoot);
  } catch {
    return cache;
  }
  const requested = new Map<string, Set<number>>();
  for (const finding of findings) {
    const primary = primaryLocation(finding);
    const path = requireSafeRelativePath(primary.path, "SARIF source location");
    if (!requested.has(path)) requested.set(path, new Set());
    requested.get(path)!.add(primary.startLine);
  }
  for (const [path, lines] of requested) {
    const hashes = githubLineHashesForSource(root, path, lines);
    for (const line of lines) cache.set(JSON.stringify([path, line]), hashes?.get(line));
  }
  return cache;
}

function sarifResult(finding: Finding, ruleIndex: number, cache: Map<string, string | undefined>, hasSource: boolean): JsonObject {
  const properties: JsonObject = {
    category: finding.taxonomy.category,
    confidence: finding.confidence.level,
    findingId: finding.findingId,
    occurrenceId: finding.occurrenceId,
    severity: finding.severity.level
  };
  const extensions = finding.extensions;
  const candidateId = isJsonObject(extensions) ? extensions.candidateId : undefined;
  if (typeof candidateId === "string" && candidateId !== "") properties.candidateId = candidateId;
  const partialFingerprints: JsonObject = { "piSecurity/v1": (finding.fingerprints as JsonObject).primary };
  if (hasSource) {
    const primary = primaryLocation(finding);
    const lineHash = cache.get(JSON.stringify([requireSafeRelativePath(primary.path, "SARIF source location"), primary.startLine]));
    if (lineHash !== undefined) partialFingerprints.primaryLocationLineHash = lineHash;
  }
  return {
    ruleId: finding.ruleId,
    ruleIndex,
    level: SARIF_LEVELS[finding.severity.level],
    message: { text: sarifFindingMessage(finding) },
    locations: sarifLocations(finding).map(sarifLocation),
    partialFingerprints,
    properties
  };
}

export function buildSarif(manifest: JsonObject, findings: JsonObject, sourceRoot?: string): JsonObject {
  const scan = manifest.scan as JsonObject;
  const target = scan.target as JsonObject;
  const ordered = [...(findings.findings as Finding[])].sort((a, b) =>
    compareCodePoints(a.occurrenceId as string, b.occurrenceId as string)
  );
  const byRule = new Map<string, Finding[]>();
  for (const finding of ordered) byRule.set(finding.ruleId, [...(byRule.get(finding.ruleId) ?? []), finding]);
  const ruleIds = [...byRule.keys()].sort(compareCodePoints);
  const ruleIndex = new Map(ruleIds.map((ruleId, index) => [ruleId, index]));
  let hasSource = false;
  if (sourceRoot !== undefined) {
    try {
      realpathSync(sourceRoot);
      hasSource = true;
    } catch {
      hasSource = false;
    }
  }
  const cache = lineHashCache(ordered, hasSource ? sourceRoot : undefined);
  const run: JsonObject = {
    tool: {
      driver: {
        name: "Pi Security",
        version: (scan.producer as JsonObject).version,
        rules: ruleIds.map((ruleId) => sarifRule(ruleId, byRule.get(ruleId)!))
      }
    },
    automationDetails: { id: scan.id },
    results: ordered.map((finding) => sarifResult(finding, ruleIndex.get(finding.ruleId)!, cache, hasSource)),
    properties: { piSecuritySchemaVersion: manifest.schemaVersion, piSecurityTargetKind: target.kind }
  };
  if (target.kind === "git_revision" && target.remote && target.revision) {
    run.versionControlProvenance = [{ repositoryUri: target.remote, revisionId: target.revision }];
  }
  return { $schema: SARIF_SCHEMA, version: "2.1.0", runs: [run] };
}

export function validateSarif(sarif: JsonObject): void {
  if (sarif.version !== "2.1.0") throw new ContractError("SARIF: expected version 2.1.0");
  const runs = sarif.runs;
  if (!Array.isArray(runs) || runs.length !== 1) throw new ContractError("SARIF: expected exactly one run");
  const run = runs[0];
  if (!isJsonObject(run)) throw new ContractError("SARIF: expected a run object");
  const ruleIds = ((run.tool as JsonObject).driver as JsonObject).rules as JsonObject[];
  for (const result of run.results as JsonObject[]) {
    if (!ruleIds.some((rule) => rule.id === result.ruleId)) throw new ContractError("SARIF: result references an unknown rule");
    const fingerprints = result.partialFingerprints;
    if (!fingerprints || (isJsonObject(fingerprints) && Object.keys(fingerprints).length === 0)) {
      throw new ContractError("SARIF: result is missing partialFingerprints");
    }
  }
}

