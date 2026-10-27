// Validate and combine security-scan candidates into deterministic JSONL.
// Port of scripts/normalize_candidates.py, held to the normalize cases in tests/parity.
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readlinkSync, realpathSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, parse, relative, sep } from "node:path";
import { isBlank, isJsonObject, pythonStrip, type JsonObject } from "./contract-error.js";
import {
  compareCodePoints,
  dumpsPython,
  hasLoneSurrogate,
  isPythonInt,
  parsePythonJson,
  pythonRepr
} from "./python-json.js";

/** A candidate rejection. Messages match normalize_candidates.py. */
export class CandidateError extends Error {
  override name = "CandidateError";
}

const WINDOWS = process.platform === "win32";
const ROLES: Record<string, number> = {
  entrypoint: 0,
  "entrypoint/wrapper": 1,
  source: 2,
  root_control: 3,
  sink: 4,
  concrete_implementation: 5,
  evidence: 6
};
const FIELDS = new Set(["candidate_id", "cwe_ids", "locations", "summary", "evidence", "context", "instance"]);
const LOCATION_FIELDS = new Set(["path", "start_line", "end_line", "role"]);
// Python's \d and int() accept every Unicode decimal digit.
const CWE = /^cwe-(\p{Nd}+)$/iu;
const DECIMAL_DIGIT = /\p{Nd}/u;
const WINDOWS_UNSAFE_COMPONENT = /[<>:"|?*\x00-\x1f]|[ .]$|^(?:con|prn|aux|nul|conin\$|conout\$|com[1-9\xb9\xb2\xb3]|lpt[1-9\xb9\xb2\xb3])(?:\..*)?$/iu;
const LETTER = /^\p{L}$/u;

export type CandidateLocation = { path: string; start_line: number; end_line: number; role: string };
export type Candidate = {
  cwe_ids: string[];
  locations: CandidateLocation[];
  summary: string;
  evidence: string;
  context?: string;
  instance?: string;
};
export type CombinedCandidate = Candidate & { candidate_id: string };

const sortedJoin = (values: Iterable<string>) => [...values].sort(compareCodePoints).join(", ");

/** Path of `target` relative to `root` in POSIX form, or undefined when it lies outside. */
function insideRoot(root: string, target: string): string | undefined {
  const inside = relative(root, target);
  if (inside === ".." || inside.startsWith(`..${sep}`) || isAbsolute(inside)) return undefined;
  return inside === "" ? "." : inside.split(sep).join("/");
}

/** PurePosixPath(value).parts without the root: "" and "." components dropped. */
function posixParts(value: string): string[] {
  return value.split("/").filter((part) => part !== "" && part !== ".");
}

function errnoMessage(error: unknown): string {
  const failure = error as NodeJS.ErrnoException;
  if (failure.code === "ENOENT") return `[Errno 2] No such file or directory: ${pythonRepr(failure.path ?? "")}`;
  return failure.message;
}

class MissingFile extends CandidateError {}

function textField(row: JsonObject, field: string, required = true): string | undefined {
  const value = row[field] ?? null;
  if (value === null && !required) return undefined;
  if (typeof value !== "string" || isBlank(value)) throw new CandidateError(`${field}: expected a non-empty string`);
  return pythonStrip(value);
}

function digitValue(character: string): number {
  // Unicode decimal digits come in contiguous runs of ten, starting at zero.
  let start = character.codePointAt(0)!;
  while (DECIMAL_DIGIT.test(String.fromCodePoint(start - 1))) start--;
  return (character.codePointAt(0)! - start) % 10;
}

function cweIds(row: JsonObject): string[] {
  const value = row.cwe_ids;
  if (!Array.isArray(value)) throw new CandidateError("cwe_ids: expected an array");
  const found = new Set<bigint>();
  for (const item of value) {
    if (typeof item !== "string") throw new CandidateError("cwe_ids: expected CWE strings");
    const match = CWE.exec(pythonStrip(item));
    const number = match === null ? 0n : [...match[1]!].reduce((total, digit) => total * 10n + BigInt(digitValue(digit)), 0n);
    if (number < 1n) throw new CandidateError(`cwe_ids: unsupported value ${pythonRepr(item)}`);
    found.add(number);
  }
  return [...found].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)).map((number) => `CWE-${number}`);
}

function windowsPortable(raw: string): boolean {
  if (hasLoneSurrogate(raw) || isBlank(raw) || raw === "." || raw.includes("\\") || raw.includes("\0")) return false;
  const first = [...raw];
  if (first.length >= 2 && LETTER.test(first[0]!) && first[1] === ":") return false;
  if ([...raw].some((character) => character.codePointAt(0)! < 32)) return false;
  if (raw.startsWith("/") || posixParts(raw).includes("..")) return false;
  return !raw.split("/").some((part) => part !== "" && part !== "." && WINDOWS_UNSAFE_COMPONENT.test(part));
}

/** Resolve a repository-relative file, following symlinks, and require it to stay inside repoRoot. */
function relativeFile(value: unknown, repoRoot: string): { relative: string; resolved: string } {
  if (typeof value !== "string" || value === "" || value.includes("\0")) {
    throw new CandidateError("path: expected a non-empty repository-relative path");
  }
  let raw = value;
  if (WINDOWS) {
    raw = raw.replaceAll("\\", "/");
    if (!windowsPortable(raw)) throw new CandidateError("path: expected a repository-relative path without traversal");
  }
  if (raw.startsWith("/") || posixParts(raw).includes("..") || (WINDOWS && /^[A-Za-z]:/.test(raw))) {
    throw new CandidateError("path: expected a repository-relative path without traversal");
  }
  const joined = join(repoRoot, ...posixParts(raw));
  let resolved: string;
  try {
    resolved = realpathSync(joined);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") throw new MissingFile(errnoMessage({ code: "ENOENT", path: joined }));
    throw new CandidateError(errnoMessage(error));
  }
  const inside = insideRoot(repoRoot, resolved);
  if (inside === undefined) throw new CandidateError("path: must resolve inside --repo-root");
  if (!statSync(resolved).isFile()) throw new CandidateError("path: expected a regular file");
  return { relative: inside, resolved };
}

function positiveLine(value: unknown, field: string): number {
  if (!isPythonInt(value) || value < 1) throw new CandidateError(`${field}: expected a positive integer`);
  return Number(value);
}

/** len(bytes.splitlines()): lines end at \n, \r\n, or \r. */
function lineCount(data: Buffer): number {
  let count = 0;
  for (let index = 0; index < data.length; index++) {
    const byte = data[index];
    if (byte === 0x0a || (byte === 0x0d && data[index + 1] !== 0x0a)) count++;
  }
  const last = data[data.length - 1];
  return data.length > 0 && last !== 0x0a && last !== 0x0d ? count + 1 : count;
}

function normalizeLocations(row: JsonObject, repoRoot: string, lineCounts: Map<string, number>): CandidateLocation[] {
  const value = row.locations;
  if (!Array.isArray(value) || value.length === 0) throw new CandidateError("locations: expected a non-empty array");
  const normalized = new Map<string, CandidateLocation>();
  for (const item of value) {
    if (!isJsonObject(item)) throw new CandidateError("locations: expected location objects");
    const unknown = Object.keys(item).filter((key) => !LOCATION_FIELDS.has(key));
    if (unknown.length > 0) throw new CandidateError(`locations: unsupported fields ${sortedJoin(unknown)}`);
    const { relative: path, resolved } = relativeFile(item.path, repoRoot);
    if (isBlank(path) || path.includes("\\") || posixParts(path).some((part) => part.includes(":"))) {
      throw new CandidateError("path: expected a safe repository-relative POSIX path");
    }
    const start = positiveLine(item.start_line, "start_line");
    const end = positiveLine(Object.hasOwn(item, "end_line") ? item.end_line : start, "end_line");
    if (end < start) throw new CandidateError("end_line: must be greater than or equal to start_line");
    if (!lineCounts.has(resolved)) lineCounts.set(resolved, lineCount(readFileSync(resolved)));
    const lines = lineCounts.get(resolved)!;
    if (end > lines) throw new CandidateError(`line range ${start}-${end} exceeds ${path}:${lines}`);
    const role = item.role ?? null;
    if (typeof role !== "string" || !Object.hasOwn(ROLES, role)) {
      throw new CandidateError(`role: unsupported value ${pythonRepr(role)}`);
    }
    normalized.set(JSON.stringify([path, start, end, role]), { path, start_line: start, end_line: end, role });
  }
  return [...normalized.values()].sort(
    (a, b) =>
      ROLES[a.role]! - ROLES[b.role]! ||
      compareCodePoints(a.path, b.path) ||
      a.start_line - b.start_line ||
      a.end_line - b.end_line
  );
}

/** Path.resolve(strict=False): resolve symlinks through existing components and keep the missing remainder. */
function resolveLoose(path: string, seen = new Set<string>()): string {
  const { root } = parse(path);
  const parts = path.slice(root.length).split(sep).filter(Boolean);
  let current = root;
  for (let index = 0; index < parts.length; index++) {
    const next = join(current, parts[index]!);
    let stat;
    try {
      stat = lstatSync(next);
    } catch {
      return join(next, ...parts.slice(index + 1));
    }
    if (!stat.isSymbolicLink()) {
      current = next;
      continue;
    }
    if (seen.has(next)) return join(next, ...parts.slice(index + 1));
    seen.add(next);
    const target = readlinkSync(next);
    current = resolveLoose(isAbsolute(target) ? target : join(dirname(next), target), seen);
  }
  return current;
}

/** Read the in-scope file list, including Python's handling of carriage returns. */
export function readScope(data: Buffer, repoRoot: string, allowMissing = false): Set<string> {
  const contents = new TextDecoder("utf-8", { fatal: true }).decode(data);
  const lines = contents.split("\n");
  const listedRows = new Set(lines);
  const isScopeFile = (value: string) => {
    try {
      relativeFile(value, repoRoot);
      return true;
    } catch (error) {
      if (error instanceof CandidateError) return false;
      throw error;
    }
  };
  const carriageRows = new Map<string, [boolean, boolean]>();
  if (!WINDOWS) {
    for (const line of lines) {
      if (line.endsWith("\r") && line !== "\r" && !carriageRows.has(line)) {
        carriageRows.set(line, [isScopeFile(line), isScopeFile(line.slice(0, -1))]);
      }
    }
  }
  const rows = [...carriageRows.values()];
  const crlfEvidence = lines.some((line) => line === "\r") || rows.some(([literal, stripped]) => stripped && !literal);
  const literalEvidence = rows.some(([literal, stripped]) => literal && !stripped);

  const scope = new Set<string>();
  lines.forEach((original, index) => {
    const number = index + 1;
    let line = original;
    if (WINDOWS || line === "\r") {
      if (line.endsWith("\r")) line = line.slice(0, -1);
    } else if (line.endsWith("\r")) {
      const [literal, stripped] = carriageRows.get(line)!;
      if (stripped && !literal) line = line.slice(0, -1);
      else if (stripped && literal) {
        if (number === lines.length && !contents.endsWith("\n")) {
          // keep
        } else if (listedRows.has(line.slice(0, -1))) {
          // keep
        } else if (crlfEvidence && !literalEvidence) line = line.slice(0, -1);
        else if (literalEvidence && !crlfEvidence) {
          // keep
        } else throw new CandidateError(`in-scope file row ${number}: ambiguous carriage-return paths`);
      } else if (!literal && crlfEvidence) line = line.slice(0, -1);
    }
    if (line === "") return;
    try {
      scope.add(relativeFile(line, repoRoot).relative);
    } catch (error) {
      if (!(error instanceof CandidateError)) throw error;
      if (allowMissing && error instanceof MissingFile) {
        const parts = posixParts(line);
        if (line.startsWith("/") || parts.includes("..") || line.includes("\0")) {
          throw new CandidateError(`in-scope file row ${number}: unsafe deleted path`);
        }
        const inside = insideRoot(repoRoot, resolveLoose(join(repoRoot, ...parts)));
        if (inside === undefined) throw new CandidateError(`in-scope file row ${number}: path escapes repository`);
        scope.add(inside);
        return;
      }
      throw new CandidateError(`in-scope file row ${number}: ${error.message}`);
    }
  });
  return scope;
}

export function normalizeCandidate(
  row: JsonObject,
  repoRoot: string,
  scope: Set<string>,
  lineCounts: Map<string, number>
): Candidate {
  const unknown = Object.keys(row).filter((key) => !FIELDS.has(key));
  if (unknown.length > 0) throw new CandidateError(`unsupported fields ${sortedJoin(unknown)}`);
  if (Object.hasOwn(row, "candidate_id")) textField(row, "candidate_id");
  const locations = normalizeLocations(row, repoRoot, lineCounts);
  if (!locations.some((item) => scope.has(item.path))) {
    throw new CandidateError("locations: expected at least one in-scope file");
  }
  const result: Candidate = {
    cwe_ids: cweIds(row),
    locations,
    summary: textField(row, "summary")!,
    evidence: textField(row, "evidence")!
  };
  const context = textField(row, "context", false);
  if (context !== undefined) result.context = context;
  const instance = textField(row, "instance", false);
  if (instance !== undefined) result.instance = instance;
  return result;
}

function identity(row: Candidate): string {
  return dumpsPython(
    { cwe_ids: row.cwe_ids, locations: row.locations, instance: row.instance ?? null },
    { ensureAscii: false, separators: [",", ":"], sortKeys: true }
  );
}

function mergedText(group: Candidate[], field: "summary" | "evidence" | "context"): string {
  const values = new Set<string>();
  for (const item of group) if (item[field] !== undefined) values.add(item[field]!);
  return [...values].sort(compareCodePoints).join("\n");
}

/** Merge candidates with equal CWEs, locations, and instance; order by identity. */
export function combineCandidates(rows: Candidate[]): CombinedCandidate[] {
  const groups = new Map<string, Candidate[]>();
  for (const row of rows) {
    const key = identity(row);
    groups.set(key, [...(groups.get(key) ?? []), row]);
  }
  return [...groups.entries()]
    .sort(([a], [b]) => compareCodePoints(a, b))
    .map(([key, group]) => {
      const first = group[0]!;
      const result: CombinedCandidate = {
        candidate_id: `candidate-${createHash("sha256").update(key, "utf8").digest("hex").slice(0, 16)}`,
        cwe_ids: first.cwe_ids,
        locations: first.locations,
        summary: mergedText(group, "summary"),
        evidence: mergedText(group, "evidence")
      };
      const context = mergedText(group, "context");
      if (context !== "") result.context = context;
      if (first.instance !== undefined) result.instance = first.instance;
      return result;
    });
}

export function candidatesJsonl(rows: CombinedCandidate[]): Buffer {
  const text = rows
    .map((row) => `${dumpsPython(row, { ensureAscii: false, separators: [",", ":"], sortKeys: true })}\n`)
    .join("");
  return Buffer.from(text, "utf8");
}

/** Python text-mode line iteration: universal newlines, each line keeping its terminator. */
function textLines(text: string): string[] {
  return text.match(/[^\r\n]*(?:\r\n|\r|\n)|[^\r\n]+$/g) ?? [];
}

/** PurePath ordering: component by component, by code point. */
function comparePaths(left: string, right: string): number {
  const a = left.split(sep);
  const b = right.split(sep);
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    const difference = compareCodePoints(a[index]!, b[index]!);
    if (difference !== 0) return difference;
  }
  return a.length - b.length;
}

export type NormalizeResult = { rowCount: number; candidates: CombinedCandidate[]; jsonl: Buffer };

/**
 * normalize_candidates.py without the output write: read each candidate JSONL input (resolved paths), validate every
 * row against the repository and in-scope list, and combine.
 */
export function normalizeCandidateFiles(options: {
  inputs: string[];
  repoRoot: string;
  scopePath: string;
  allowMissingInScope?: boolean;
}): NormalizeResult {
  const scope = readScope(readFileSync(options.scopePath), options.repoRoot, options.allowMissingInScope ?? false);
  const lineCounts = new Map<string, number>();
  const rows: Candidate[] = [];
  for (const source of [...new Set(options.inputs)].sort(comparePaths)) {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(source));
    textLines(text).forEach((line, index) => {
      if (isBlank(line)) return;
      try {
        const row = parsePythonJson(line);
        if (!isJsonObject(row)) throw new CandidateError("expected a JSON object");
        rows.push(normalizeCandidate(row, options.repoRoot, scope, lineCounts));
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new CandidateError(`${source} row ${index + 1}: ${message}`);
      }
    });
  }
  const candidates = combineCandidates(rows);
  return { rowCount: rows.length, candidates, jsonl: candidatesJsonl(candidates) };
}
