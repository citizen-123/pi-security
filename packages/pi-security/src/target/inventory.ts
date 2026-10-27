// The shared, deterministically ordered security-scan file inventory.
// Port of scripts/generate_in_scope_files.py (with the diff selection it reuses from generate_rank_input.py and
// rank_preview.py), held to the inventory cases in tests/parity. Output writing is the caller's.
import { closeSync, lstatSync, openSync, readdirSync, readFileSync, readSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, relative, sep } from "node:path";
import { gitBlobBytes, gitCommand } from "./git.js";

/** The repository, scope, or inventory cannot be used safely. Messages match generate_in_scope_files.py. */
export class InventoryError extends Error {
  override name = "InventoryError";
}

const WINDOWS = process.platform === "win32";

const EXCLUDED_DIRS = new Set([
  ".cache", ".circleci", ".devcontainer", ".git", ".github", ".idea", ".mypy_cache", ".pytest_cache", ".ruff_cache",
  ".tox", ".venv", ".vscode", "__pycache__", "bench", "benchmark", "bintest", "build", "build_config",
  "build_configs", "build-tools", "build_tools", "ci", "coverage", "deps", "dev", "dist", "doc", "docs", "example",
  "examples", "external", "extern", "fixture", "fixtures", "generated", "node_modules", "sample", "samples", "target",
  "test", "tests", "testing", "third-party", "third_party", "tmp", "vendor"
]);

const EXCLUDED_FILENAMES = new Set([
  ".DS_Store", "CHANGELOG", "CHANGELOG.md", "CONTRIBUTING.md", "Dockerfile", "Gemfile", "Gemfile.lock", "LICENSE",
  "LICENSE.md", "Makefile", "NEWS", "NEWS.md", "NOTICE", "README", "README.md", "README.rst", "Rakefile",
  "SECURITY.md", "TODO", "TODO.md", "docker-compose.yml", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"
]);

const TEXT_CODE_EXTENSIONS = new Set([
  ".c", ".cc", ".cfg", ".clj", ".cpp", ".cs", ".css", ".cue", ".cxx", ".dart", ".ex", ".exs", ".go", ".graphql", ".h",
  ".hpp", ".hs", ".html", ".java", ".js", ".json", ".jsx", ".kt", ".kts", ".lua", ".mjs", ".mm", ".php", ".proto",
  ".ps1", ".psd1", ".psm1", ".py", ".rb", ".rs", ".scala", ".sh", ".sql", ".swift", ".toml", ".ts", ".tsx", ".vue",
  ".xml", ".yaml", ".yml"
]);

export type DiffMode = "revisions" | "local-patch";

const NEWLINE = Buffer.from("\n");
const UTF8 = new TextDecoder("utf-8", { fatal: true });

/** PurePosixPath(value).parts without the root. */
const posixParts = (value: string) => value.split("/").filter((part) => part !== "" && part !== ".");

/** Path.expanduser for "~" and "~/..."; other forms are left unchanged. */
function expandUser(value: string): string {
  if (value === "~") return homedir();
  if (value.startsWith("~/")) return join(homedir(), value.slice(2));
  return value;
}

function isInside(root: string, target: string): string | undefined {
  const inside = relative(root, target);
  if (inside === ".." || inside.startsWith(`..${sep}`) || isAbsolute(inside)) return undefined;
  return inside.split(sep).join("/");
}

/** Resolve the repository once so every scope is bound to its real root. */
export function resolveRepository(value: string): string {
  let repository: string;
  try {
    repository = realpathSync(expandUser(value));
  } catch {
    throw new InventoryError(`--repo: cannot resolve repository: ${value}`);
  }
  if (!statSync(repository).isDirectory()) throw new InventoryError(`--repo: expected a directory: ${repository}`);
  return repository;
}

/** Preserve the caller's relative spelling of the scope while rejecting scopes that escape the repository. */
export function resolveScope(repository: string, value: string): string {
  if (value === "" || value.includes("\0")) throw new InventoryError("--scope: expected a non-empty file or directory");
  const requested = expandUser(value);
  if (WINDOWS) {
    const { root } = { root: requested.match(/^(?:[A-Za-z]:)?[\\/]*/)![0] };
    const stream = requested.slice(root.length).split(/[\\/]/).find((part) => part.includes(":"));
    if (stream !== undefined) throw new InventoryError(`--scope: NTFS alternate data streams are not supported: ${stream}`);
  }
  const absolute = isAbsolute(requested);
  let resolved: string;
  try {
    resolved = realpathSync(absolute ? requested : join(repository, requested));
  } catch {
    throw new InventoryError(`--scope: path does not exist: ${value}`);
  }
  const inside = isInside(repository, resolved);
  if (inside === undefined) throw new InventoryError(`--scope: path must remain inside --repo: ${value}`);
  const stat = statSync(resolved);
  if (!stat.isDirectory() && !stat.isFile()) throw new InventoryError(`--scope: expected a file or directory: ${value}`);
  if (absolute) return inside === "" ? "." : inside;
  return value;
}

function prefixFor(scope: string): Buffer {
  return Buffer.from(scope === "." || scope.startsWith("./") ? "./" : "");
}

function pathBuffer(base: string, relativePath: Buffer): Buffer {
  return Buffer.concat([Buffer.from(base), Buffer.from(sep), relativePath]);
}

function isRegularFile(path: Buffer): boolean {
  try {
    return lstatSync(path).isFile();
  } catch {
    return false;
  }
}

/** Tracked files plus non-ignored untracked files. */
function gitInventoryRows(repository: string, scope: string): Buffer[] {
  const result = gitCommand(repository, ["ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", scope]);
  if (result.status !== 0) {
    const detail = result.stderr.toString("utf8").trim();
    const message = `git inventory exited with status ${result.status}`;
    throw new InventoryError(detail === "" ? message : `${message}: ${detail}`);
  }
  const prefix = prefixFor(scope);
  const rows: Buffer[] = [];
  let start = 0;
  while (start < result.stdout.length) {
    let end = result.stdout.indexOf(0, start);
    if (end < 0) end = result.stdout.length;
    const path = result.stdout.subarray(start, end);
    start = end + 1;
    if (path.length === 0 || !isRegularFile(pathBuffer(repository, path))) continue;
    const normalized = WINDOWS ? Buffer.from(path.toString("utf8").replaceAll("\\", "/")) : path;
    rows.push(Buffer.concat([prefix, normalized, NEWLINE]));
  }
  return rows;
}

/** Regular files of a non-Git directory target, without following links. */
function directoryInventoryRows(repository: string, scope: string): Buffer[] {
  const prefix = prefixFor(scope);
  // Path.relative_to is lexical: the caller's spelling of the scope stays in each row.
  const scopeParts = posixParts(scope.replaceAll(sep, "/"));
  const rows: Buffer[] = [];
  const add = (parts: Buffer[]) => {
    if (parts.some((part) => part.equals(Buffer.from(".git")))) return;
    rows.push(Buffer.concat([prefix, Buffer.concat(parts.flatMap((part, index) => (index === 0 ? [part] : [Buffer.from("/"), part]))), NEWLINE]));
  };
  // Not path.join: the filesystem resolves ".." after symlinks, as Python's unnormalized Path does.
  const selected = [repository, ...scopeParts].join(sep);
  const base = scopeParts.map((part) => Buffer.from(part));
  let stat;
  try {
    stat = lstatSync(selected);
  } catch {
    return rows;
  }
  if (statSync(selected).isFile()) {
    if (!stat.isSymbolicLink() && base.length > 0) add(base);
    return rows;
  }
  const walk = (directory: Buffer, parts: Buffer[]) => {
    let entries;
    try {
      entries = readdirSync(directory, { encoding: "buffer", withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const name = entry.name as unknown as Buffer;
      const child = Buffer.concat([directory, Buffer.from(sep), name]);
      const childParts = [...parts, name];
      if (entry.isDirectory()) walk(child, childParts);
      else if (entry.isFile()) add(childParts);
      else if (!entry.isSymbolicLink() && isRegularFile(child)) add(childParts);
    }
  };
  walk(Buffer.from(selected), base);
  return rows;
}

function pathIsExcluded(parts: string[]): boolean {
  const name = parts.at(-1) ?? "";
  if (parts.some((part) => EXCLUDED_DIRS.has(part))) return true;
  if (EXCLUDED_FILENAMES.has(name)) return true;
  return name.endsWith(".min.js") || name.endsWith(".map");
}

/** PurePath.suffix, lowercased. */
function suffix(name: string): string {
  const index = name.lastIndexOf(".");
  return index > 0 && index < name.length - 1 ? name.slice(index).toLowerCase() : "";
}

/** rank_preview.is_binary_sample: a NUL byte, or a NUL code unit in UTF-16 text with a byte-order mark. */
function isBinarySample(data: Buffer): boolean {
  const utf16le = data[0] === 0xff && data[1] === 0xfe;
  const utf16be = data[0] === 0xfe && data[1] === 0xff;
  if (!utf16le && !utf16be) return data.includes(0);
  for (let index = 2; index + 1 < data.length; index += 2) {
    if (data[index] === 0 && data[index + 1] === 0) return true;
  }
  return false;
}

/** rank_preview.preview_for(...)[1]: unreadable files count as binary. */
function workingTreeFileIsBinary(path: Buffer): boolean {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, "r");
    const sample = Buffer.alloc(4096);
    const read = readSync(descriptor, sample, 0, 4096, 0);
    if (isBinarySample(sample.subarray(0, read))) return true;
    return isBinarySample(readFileSync(path));
  } catch {
    return true;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

type Change = { path: Buffer; status: string };

function splitNul(output: Buffer): Buffer[] {
  const fields: Buffer[] = [];
  let start = 0;
  for (let index = 0; index < output.length; index++) {
    if (output[index] === 0) {
      fields.push(output.subarray(start, index));
      start = index + 1;
    }
  }
  fields.push(output.subarray(start));
  return fields;
}

class GitChangeError extends Error {}

function gitOrThrow(repository: string, args: string[]): Buffer {
  const result = gitCommand(repository, args);
  if (result.status !== 0) {
    const detail = result.stderr.toString("utf8").trim();
    throw new GitChangeError(detail === "" ? `git exited with status ${result.status}` : detail);
  }
  return result.stdout;
}

/** Committed changes, skipping symlinks (mode 120000) by the side of the change that exists. */
function committedChangedPaths(repository: string, base: string, head: string): Change[] {
  const fields = splitNul(
    gitOrThrow(repository, ["diff", "--no-ext-diff", "--no-textconv", "--raw", "-z", "--diff-filter=ACMRD", `${base}..${head}`])
  );
  const changed: Change[] = [];
  let index = 0;
  while (index < fields.length - 1) {
    const metadata = fields[index]!.toString("latin1").split(/[ \t\n\r\v\f]+/).filter(Boolean);
    const status = metadata.at(-1)![0]!;
    index += 1;
    if (status === "C" || status === "R") index += 1;
    const path = fields[index]!;
    index += 1;
    const mode = status === "D" ? metadata[0]!.replace(/^:/, "") : metadata[1];
    if (mode !== "120000") changed.push({ path, status });
  }
  return changed;
}

function nameStatusChanges(repository: string, diffArgs: string[]): Change[] {
  const fields = splitNul(
    gitOrThrow(repository, ["diff", "--no-ext-diff", "--no-textconv", "--name-status", "-z", "--diff-filter=ACMRD", ...diffArgs])
  );
  if (fields.length > 0 && fields.at(-1)!.length === 0) fields.pop();
  const changed: Change[] = [];
  let index = 0;
  while (index < fields.length) {
    const status = String.fromCharCode(fields[index]![0]!);
    index += 1;
    if (status === "C" || status === "R") index += 1;
    changed.push({ path: fields[index]!, status });
    index += 1;
  }
  return changed;
}

/** Staged, unstaged, and untracked changes against `base`; later sources win for the same path. */
function localPatchChanges(repository: string, base: string): Change[] {
  const unstaged = nameStatusChanges(repository, [base]);
  const staged = nameStatusChanges(repository, ["--cached", base]);
  const untracked = splitNul(gitOrThrow(repository, ["ls-files", "--others", "--exclude-standard", "-z"]))
    .filter((path) => path.length > 0)
    .map((path) => ({ path, status: "A" }));
  const combined = new Map<string, Change>();
  for (const change of [...staged, ...unstaged, ...untracked]) combined.set(change.path.toString("latin1"), change);
  return [...combined.values()].sort((a, b) => comparePathBytes(a.path, b.path) || (a.status < b.status ? -1 : a.status > b.status ? 1 : 0));
}

/** Path ordering, component by component, on the raw bytes. */
function comparePathBytes(left: Buffer, right: Buffer): number {
  const a = posixParts(left.toString("latin1"));
  const b = posixParts(right.toString("latin1"));
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    const order = Buffer.compare(Buffer.from(a[index]!, "latin1"), Buffer.from(b[index]!, "latin1"));
    if (order !== 0) return order;
  }
  return a.length - b.length;
}

function diffInventoryRows(repository: string, base: string, head: string, mode: DiffMode): Buffer[] {
  const rows = new Map<string, Buffer>();
  try {
    const changed = mode === "revisions" ? committedChangedPaths(repository, base, head) : localPatchChanges(repository, base);
    const eligible = changed
      .map((change) => ({ ...change, parts: posixParts(change.path.toString("utf8")) }))
      .filter(({ parts }) => !pathIsExcluded(parts) && TEXT_CODE_EXTENSIONS.has(suffix(parts.at(-1) ?? "")));
    const revisionPaths = eligible.filter((change) => mode === "revisions" && change.status !== "D");
    const blobs = gitBlobBytes(
      repository,
      revisionPaths.map((change) => Buffer.concat([Buffer.from(`${head}:`), change.path]))
    );
    const blobFor = new Map(revisionPaths.map((change, index) => [change.path.toString("latin1"), blobs[index]!]));

    for (const change of eligible) {
      if (change.status !== "D") {
        if (mode === "revisions") {
          const contents = blobFor.get(change.path.toString("latin1"));
          if (contents === null || contents === undefined) {
            throw new InventoryError(`could not read committed diff blob: ${head}:${change.parts.join("/")}`);
          }
          if (isBinarySample(contents)) continue;
        } else {
          const full = pathBuffer(repository, change.path);
          if (!isRegularFile(full) || workingTreeFileIsBinary(full)) continue;
        }
      }
      // Rows are UTF-8 text: a name that is not valid UTF-8 cannot be written, as in Python.
      let relativePath: string;
      try {
        relativePath = UTF8.decode(change.path);
      } catch {
        throw new InventoryError("Git changes contain a path that is not valid UTF-8");
      }
      relativePath = posixParts(relativePath).join("/");
      if (relativePath.includes("\n") || relativePath.includes("\r")) {
        throw new InventoryError("Git changes contain a path that cannot fit in the file inventory");
      }
      const row = Buffer.from(`${relativePath}\n`, "utf8");
      rows.set(row.toString("latin1"), row);
    }
  } catch (error) {
    if (error instanceof GitChangeError) throw new InventoryError(`could not resolve the selected Git changes: ${error.message}`);
    throw error;
  }
  return [...rows.values()];
}

export type InventoryOptions = {
  /** From resolveRepository. */
  repository: string;
  /** From resolveScope. */
  scope: string;
  /** A changed-file inventory between two revisions, or of the working-tree patch against `base`. */
  diff?: { base: string; head?: string; mode?: DiffMode };
};

/** The inventory as LC_ALL=C sorted rows, and its bytes. */
export function generateInventory(options: InventoryOptions): { rows: Buffer[]; bytes: Buffer } {
  const { repository, scope, diff } = options;
  let rows: Buffer[];
  if (diff === undefined) {
    let isGit = false;
    try {
      statSync(join(repository, ".git"));
      isGit = true;
    } catch {
      isGit = false;
    }
    rows = isGit ? gitInventoryRows(repository, scope) : directoryInventoryRows(repository, scope);
  } else if (scope !== "." && scope !== "./") {
    throw new InventoryError("--scope: diff scans must use the repository root");
  } else {
    rows = diffInventoryRows(repository, diff.base, diff.head ?? "HEAD", diff.mode ?? "revisions");
  }
  rows.sort(Buffer.compare);
  return { rows, bytes: Buffer.concat(rows) };
}
