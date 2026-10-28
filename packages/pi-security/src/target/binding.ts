// The scan target's identity and content binding. Port of stable_target_id (workbench_target_state.py) and of
// worktree_content_digest, directory_content_digest, and their helpers (workbench_target.py).
//
// - targetId: "target_sha256_" + sha256("local-workspace\0" + canonical target path).
// - A Git working tree is bound to HEAD plus a digest of its uncommitted state (the tracked diff against HEAD and every
//   untracked, non-ignored file); a plain directory to a digest of every entry below it. Both digests use
//   length-prefixed fields so no two different states hash alike.
import { createHash, type Hash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, readlinkSync, realpathSync, type Stats } from "node:fs";
import { basename, join, relative, sep } from "node:path";
import { gitCommand } from "./git.js";

export class TargetBindingError extends Error {
  override name = "TargetBindingError";
}

export function stableTargetId(target: string): string {
  return `target_sha256_${createHash("sha256").update(`local-workspace\0${target}`).digest("hex")}`;
}

function field(digest: Hash, label: string, value: Buffer | string): void {
  const labelBytes = Buffer.from(label);
  const valueBytes = typeof value === "string" ? Buffer.from(value) : value;
  const labelLength = Buffer.alloc(4);
  labelLength.writeUInt32BE(labelBytes.length);
  const valueLength = Buffer.alloc(8);
  valueLength.writeBigUInt64BE(BigInt(valueBytes.length));
  digest.update(labelLength).update(labelBytes).update(valueLength).update(valueBytes);
}

const SNAPSHOT_PREFIX = "pi-security-snapshot/v1:sha256:";
const mode = (metadata: Stats) => String(metadata.mode & 0o7777);
const git = (target: string, args: (string | Buffer)[]) => {
  const result = gitCommand(target, args);
  return result.status === 0 ? result.stdout : undefined;
};
const gitText = (target: string, args: string[]) => git(target, args)?.toString("utf8").replace(/\n$/, "");

function fileSha256(path: string): { sha256: Buffer; size: number } {
  const bytes = readFileSync(path);
  return { sha256: createHash("sha256").update(bytes).digest(), size: bytes.length };
}

/** Python sorts Path objects by their parts, which differs from string order ("a/b" before "a-b"). */
function comparePathParts(left: string, right: string): number {
  const a = left.split("/");
  const b = right.split("/");
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    if (a[index] !== b[index]) return Buffer.compare(Buffer.from(a[index]!), Buffer.from(b[index]!));
  }
  return a.length - b.length;
}

/** Every entry below a directory, symbolic links not followed (Path.rglob("*")), as relative POSIX paths. */
function walk(root: string): string[] {
  const out: string[] = [];
  const visit = (relativeDirectory: string) => {
    const absolute = relativeDirectory ? join(root, ...relativeDirectory.split("/")) : root;
    for (const name of readdirSync(absolute)) {
      const relativePath = relativeDirectory ? `${relativeDirectory}/${name}` : name;
      out.push(relativePath);
      const metadata = lstatSync(join(absolute, name));
      if (metadata.isDirectory()) visit(relativePath);
    }
  };
  visit("");
  return out;
}

/** git_directory_snapshot_paths for a repository root: listed files plus the contents of listed directories. */
function gitDirectorySnapshotPaths(root: string): string[] | undefined {
  const top = gitText(root, ["rev-parse", "--show-toplevel"]);
  if (top === undefined) return undefined;
  const listed = git(root, ["ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "."]);
  if (listed === undefined) throw new TargetBindingError("Could not inspect files in the selected Git working tree.");
  const paths = new Set<string>();
  for (const raw of listed.toString("utf8").split("\0").filter(Boolean)) {
    let metadata: Stats;
    try {
      metadata = lstatSync(join(root, ...raw.split("/")));
    } catch {
      continue;
    }
    paths.add(raw);
    if (!metadata.isDirectory()) continue;
    const absolute = join(root, ...raw.split("/"));
    const nestedTop = gitText(absolute, ["rev-parse", "--show-toplevel"]);
    if (nestedTop !== undefined && realpathSync(nestedTop) === realpathSync(absolute)) {
      const nested = gitDirectorySnapshotPaths(absolute);
      if (nested !== undefined) {
        for (const path of nested) paths.add(`${raw}/${path}`);
        continue;
      }
    }
    for (const path of walk(absolute)) if (!path.split("/").includes(".git")) paths.add(`${raw}/${path}`);
  }
  return [...paths].sort((left, right) => Buffer.compare(Buffer.from(join(root, left)), Buffer.from(join(root, right))));
}

/** directory_content_digest: every entry below `target` (Git-listed when it is a repository root). */
export function directoryContentDigest(target: string): string {
  const paths = gitDirectorySnapshotPaths(target) ?? walk(target).sort(comparePathParts);
  const digest = createHash("sha256");
  field(digest, "format", "pi-security-directory/v1");
  for (const relativePath of paths) {
    const absolute = join(target, ...relativePath.split("/"));
    let metadata: Stats;
    try {
      metadata = lstatSync(absolute);
    } catch {
      throw new TargetBindingError(`Could not read local file: ${relativePath}`);
    }
    field(digest, "path", relativePath);
    field(digest, "mode", mode(metadata));
    if (metadata.isSymbolicLink()) {
      field(digest, "kind", "symlink");
      field(digest, "content", readlinkSync(absolute));
    } else if (metadata.isDirectory()) {
      field(digest, "kind", "directory");
    } else if (metadata.isFile()) {
      const { sha256, size } = fileSha256(absolute);
      field(digest, "kind", "file");
      field(digest, "size", String(size));
      field(digest, "content-sha256", sha256);
    } else {
      throw new TargetBindingError(`Unsupported local file type: ${relativePath}`);
    }
  }
  return SNAPSHOT_PREFIX + digest.digest("hex");
}

/** The repository root and the target's pathspec within it. */
export function gitWorktreeContext(target: string): { repository: string; pathspec: string } {
  const top = gitText(target, ["rev-parse", "--show-toplevel"]);
  if (top === undefined) throw new TargetBindingError("Could not inspect the selected Git working tree.");
  const repository = realpathSync(top);
  const inside = relative(repository, realpathSync(target));
  if (inside.split(sep)[0] === "..") throw new TargetBindingError("Scan target must stay inside its Git working tree.");
  return { repository, pathspec: inside.split(sep).join("/") || "." };
}

function submoduleEntries(target: string): { path: string; objectId: string }[] {
  const { repository, pathspec } = gitWorktreeContext(target);
  const staged = git(repository, ["ls-files", "--stage", "-z", "--", pathspec]);
  if (staged === undefined) throw new TargetBindingError("Could not inspect Git submodules in the selected working tree.");
  const entries: { path: string; objectId: string }[] = [];
  for (const record of staged.toString("utf8").split("\0").filter(Boolean)) {
    const tab = record.indexOf("\t");
    const [entryMode, objectId] = record.slice(0, tab).split(" ");
    if (entryMode === "160000") entries.push({ path: join(repository, ...record.slice(tab + 1).split("/")), objectId: objectId! });
  }
  return entries;
}

/** require_clean_submodule_worktrees: initialized submodules must sit at their recorded commit, unmodified. */
function requireCleanSubmodules(target: string): void {
  for (const { path, objectId } of submoduleEntries(target)) {
    const label = relative(target, path).split(sep).join("/");
    try {
      lstatSync(path);
      lstatSync(join(path, ".git"));
    } catch {
      continue;
    }
    const top = gitText(path, ["rev-parse", "--show-toplevel"]);
    let initialized = false;
    try {
      initialized = top !== undefined && realpathSync(top) === realpathSync(path);
    } catch {
      initialized = false;
    }
    if (!initialized) throw new TargetBindingError(`Could not inspect initialized Git submodule contents: ${label}`);
    if (gitText(path, ["rev-parse", "HEAD"]) !== objectId) {
      throw new TargetBindingError(`Initialized Git submodules must be checked out at the revision recorded by the parent repository: ${label}`);
    }
    const status = git(path, ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"]);
    if (status === undefined) throw new TargetBindingError(`Could not inspect Git submodule contents: ${label}`);
    if (status.length > 0) throw new TargetBindingError(`Dirty Git submodules are not supported for remediation integrity checks: ${label}`);
    requireCleanSubmodules(path);
  }
}

/** worktree_content_digest: the tracked diff against HEAD plus every untracked, non-ignored entry. */
export function worktreeContentDigest(target: string): string {
  requireCleanSubmodules(target);
  const { repository, pathspec } = gitWorktreeContext(target);
  const tracked = git(repository, ["diff", "--binary", "--full-index", "--no-ext-diff", "--no-textconv", "--ignore-submodules=none", "HEAD", "--", pathspec]);
  const untracked = git(repository, ["ls-files", "--others", "--exclude-standard", "-z", "--", pathspec]);
  if (tracked === undefined || untracked === undefined) throw new TargetBindingError("Could not snapshot the selected working-tree changes.");
  const digest = createHash("sha256");
  field(digest, "format", "pi-security-snapshot/v1");
  field(digest, "tracked-diff", tracked);
  const names = untracked.toString("utf8").split("\0").filter(Boolean).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  for (const name of names) {
    const absolute = join(repository, ...name.split("/"));
    let metadata: Stats;
    try {
      metadata = lstatSync(absolute);
    } catch {
      throw new TargetBindingError(`Could not read untracked file: ${name}`);
    }
    field(digest, "untracked-path", name);
    field(digest, "untracked-mode", mode(metadata));
    if (metadata.isSymbolicLink()) {
      field(digest, "untracked-kind", "symlink");
      field(digest, "untracked-content", readlinkSync(absolute));
    } else if (metadata.isDirectory()) {
      field(digest, "untracked-kind", "directory");
      field(digest, "untracked-content", directoryContentDigest(realpathSync(absolute)));
    } else if (metadata.isFile()) {
      const { sha256, size } = fileSha256(absolute);
      field(digest, "untracked-kind", "file");
      field(digest, "untracked-size", String(size));
      field(digest, "untracked-content-sha256", sha256);
    } else {
      throw new TargetBindingError(`Unsupported untracked file type: ${name}`);
    }
  }
  return SNAPSHOT_PREFIX + digest.digest("hex");
}

export type TargetBinding =
  | { kind: "git_worktree"; targetId: string; displayName: string; revision: string; snapshotDigest: string }
  | { kind: "directory_snapshot"; targetId: string; displayName: string; snapshotDigest: string };

/** The binding of a Standard scan's target (an existing, canonical directory). */
export function bindTarget(target: string): TargetBinding {
  const canonical = realpathSync(target);
  const common = { targetId: stableTargetId(canonical), displayName: basename(canonical) };
  const revision = gitText(canonical, ["rev-parse", "--verify", "HEAD"]);
  if (revision === undefined) return { kind: "directory_snapshot", ...common, snapshotDigest: directoryContentDigest(canonical) };
  return { kind: "git_worktree", ...common, revision, snapshotDigest: worktreeContentDigest(canonical) };
}
