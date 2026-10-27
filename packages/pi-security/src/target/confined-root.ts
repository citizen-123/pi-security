// Read access to a scan target confined to one root and scope (design D7; the rules of src/execution-boundary.ts).
//
// - Paths are relative to the root, or absolute inside it. `..`, NUL, and Windows drive or UNC forms are refused.
//   Nothing is expanded: `~` names a repository file called `~`.
// - No component of a path may be a symbolic link (or a Windows reparse point): repository content is data, and a link
//   it plants must not reach a file outside the target.
// - Files are opened with O_NOFOLLOW and the opened descriptor must still name the verified path (/proc/self/fd on
//   Linux, device and inode elsewhere), so a path changed between the check and the open is refused.
// - Everything stays inside the scope directory, itself inside the root.
import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readFileSync, realpathSync, statSync, type Stats } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep, win32 } from "node:path";

export type ConfinementErrorCode = "not_found" | "escape" | "symlink" | "not_directory" | "is_directory" | "invalid";

export class ConfinementError extends Error {
  override name = "ConfinementError";
  constructor(
    readonly code: ConfinementErrorCode,
    message: string,
    readonly path?: string
  ) {
    super(message);
  }
}

export type ConfinedEntryKind = "file" | "directory" | "symlink" | "other";
export type ConfinedEntry = {
  /** Root-relative POSIX path. */
  readonly path: string;
  readonly name: string;
  readonly kind: ConfinedEntryKind;
  readonly size: number;
  readonly mtimeMs: number;
};

const kindOf = (metadata: Stats): ConfinedEntryKind =>
  metadata.isSymbolicLink() ? "symlink" : metadata.isFile() ? "file" : metadata.isDirectory() ? "directory" : "other";

function inside(root: string, path: string): boolean {
  const rest = relative(root, path);
  return rest === "" || (!isAbsolute(rest) && rest.split(sep)[0] !== "..");
}

/** The canonical form of the longest existing prefix of `path`, with the missing rest appended. */
function canonicalPrefix(path: string): string {
  const missing: string[] = [];
  let current = resolve(path);
  for (;;) {
    try {
      return join(realpathSync(current), ...missing.reverse());
    } catch {
      const parent = dirname(current);
      if (parent === current) return resolve(path);
      missing.push(basename(current));
      current = parent;
    }
  }
}

/** Whether `path` is the same as or below `root` once symbolic links are resolved, for paths not yet created too. */
export function isInsideDirectory(root: string, path: string): boolean {
  return inside(canonicalPrefix(root), canonicalPrefix(path));
}

export class ConfinedRoot {
  private constructor(
    /** Canonical absolute root. */
    readonly root: string,
    /** Root-relative POSIX scope directory; "." for the whole root. */
    readonly scope: string
  ) {}

  /** Confine reads to `root` (an existing, canonical, non-symlink directory) and, within it, to `scope`. */
  static open(root: string, scope = "."): ConfinedRoot {
    const absolute = resolve(root);
    let metadata: Stats;
    let canonical: string;
    try {
      metadata = lstatSync(absolute);
      canonical = realpathSync(absolute);
    } catch {
      throw new ConfinementError("not_found", `target root does not exist: ${absolute}`, absolute);
    }
    if (metadata.isSymbolicLink() || canonical !== absolute) {
      throw new ConfinementError("symlink", `target root must be a canonical path without symbolic links: ${absolute}`, absolute);
    }
    if (!metadata.isDirectory()) throw new ConfinementError("not_directory", `target root is not a directory: ${absolute}`, absolute);
    const confined = new ConfinedRoot(canonical, ".");
    const resolvedScope = confined.relativePath(scope);
    if (confined.inspect(resolvedScope).kind !== "directory") {
      throw new ConfinementError("not_directory", `target scope is not a directory: ${resolvedScope}`, resolvedScope);
    }
    return new ConfinedRoot(canonical, resolvedScope);
  }

  /** Normalize a request to a root-relative POSIX path, or throw `escape`/`invalid`. Does not touch the file system. */
  relativePath(path: string): string {
    if (typeof path !== "string" || path === "" || path.includes("\0")) throw new ConfinementError("invalid", "expected a non-empty path", path);
    if ((win32.isAbsolute(path) && !isAbsolute(path)) || /^[A-Za-z]:/.test(path)) {
      throw new ConfinementError("escape", `path is outside the target: ${path}`, path);
    }
    if (process.platform === "win32" && path.includes("\\")) throw new ConfinementError("invalid", `use / separators: ${path}`, path);
    const parts = (isAbsolute(path) ? relative(this.root, resolve(path)).split(sep) : path.split("/")).filter((part) => part !== "" && part !== ".");
    // An absolute path outside the root has a leading "..", so this also refuses those.
    if (parts.includes("..")) throw new ConfinementError("escape", `path is outside the target: ${path}`, path);
    const normalized = parts.join("/") || ".";
    if (this.scope !== "." && normalized !== this.scope && !normalized.startsWith(`${this.scope}/`)) {
      throw new ConfinementError("escape", `path is outside the scan scope ${this.scope}: ${normalized}`, normalized);
    }
    return normalized;
  }

  /** Absolute path of a root-relative POSIX path. */
  absolutePath(relativePath: string): string {
    return relativePath === "." ? this.root : join(this.root, ...relativePath.split("/"));
  }

  /** Metadata of a path whose every component is a real file or directory; a symbolic link anywhere is refused. */
  inspect(path: string): ConfinedEntry {
    const normalized = this.relativePath(path);
    const parts = normalized === "." ? [] : normalized.split("/");
    let current = this.root;
    let metadata = lstatSync(this.root);
    for (const [index, part] of parts.entries()) {
      if (!metadata.isDirectory()) throw new ConfinementError("not_directory", `not a directory: ${parts.slice(0, index).join("/")}`, normalized);
      current = join(current, part);
      try {
        metadata = lstatSync(current);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === "ENOENT") throw new ConfinementError("not_found", `no such file or directory: ${normalized}`, normalized);
        if (code === "ENOTDIR") throw new ConfinementError("not_directory", `not a directory: ${normalized}`, normalized);
        throw error;
      }
      if (metadata.isSymbolicLink() || isReparsePoint(current, metadata)) {
        throw new ConfinementError("symlink", `path contains a symbolic link: ${parts.slice(0, index + 1).join("/")}`, normalized);
      }
    }
    return { path: normalized, name: parts.at(-1) ?? ".", kind: kindOf(metadata), size: metadata.size, mtimeMs: metadata.mtimeMs };
  }

  /** The bytes of a regular file, read through a verified descriptor. */
  readFile(path: string): Buffer {
    const entry = this.inspect(path);
    if (entry.kind === "directory") throw new ConfinementError("is_directory", `is a directory: ${entry.path}`, entry.path);
    if (entry.kind !== "file") throw new ConfinementError("invalid", `not a regular file: ${entry.path}`, entry.path);
    const absolute = this.absolutePath(entry.path);
    let descriptor: number;
    try {
      descriptor = openSync(absolute, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ELOOP") throw new ConfinementError("symlink", `path contains a symbolic link: ${entry.path}`, entry.path);
      throw new ConfinementError("not_found", `cannot open ${entry.path}`, entry.path);
    }
    try {
      const opened = fstatSync(descriptor);
      if (!opened.isFile()) throw new ConfinementError("invalid", `not a regular file: ${entry.path}`, entry.path);
      if (!openedNames(descriptor, opened, absolute)) throw new ConfinementError("escape", `changed while it was being opened: ${entry.path}`, entry.path);
      return readFileSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
  }

  /** Entries of a directory in name order; symbolic links are listed as such and never followed. */
  listDir(path: string): ConfinedEntry[] {
    const entry = this.inspect(path);
    if (entry.kind !== "directory") throw new ConfinementError("not_directory", `not a directory: ${entry.path}`, entry.path);
    const absolute = this.absolutePath(entry.path);
    const names = readdirSync(absolute).sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
    const entries: ConfinedEntry[] = [];
    for (const name of names) {
      let metadata: Stats;
      try {
        metadata = lstatSync(join(absolute, name));
      } catch {
        continue;
      }
      const relativePath = entry.path === "." ? name : `${entry.path}/${name}`;
      entries.push({ path: relativePath, name, kind: kindOf(metadata), size: metadata.size, mtimeMs: metadata.mtimeMs });
    }
    return entries;
  }
}

function isReparsePoint(path: string, metadata: Stats): boolean {
  if (process.platform !== "win32" || !metadata.isDirectory()) return false;
  // A junction reports as a directory; its canonical path differs from its own.
  try {
    return realpathSync.native(path).toLowerCase() !== resolve(path).toLowerCase();
  } catch {
    return true;
  }
}

/** Whether an open descriptor still names `absolute`. */
function openedNames(descriptor: number, opened: Stats, absolute: string): boolean {
  if (process.platform === "linux") {
    try {
      return realpathSync(`/proc/self/fd/${descriptor}`) === absolute;
    } catch {
      return false;
    }
  }
  try {
    const named = statSync(absolute);
    return named.dev === opened.dev && named.ino === opened.ino;
  } catch {
    return false;
  }
}
