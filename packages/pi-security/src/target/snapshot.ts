// Working-tree snapshots for Diff scans of uncommitted work (openspec/changes/durable-runtime design D14).
//
// The working tree (tracked files plus untracked, non-ignored files) is written to a commit object so a scan targets
// an immutable commit ID, exactly like a revision diff. The user's index, branch, stash, and files are never touched.
// Repository-local config is untrusted: `git add` and `update-index --add` would run clean filter drivers it names,
// so contents are hashed with `hash-object --no-filters` and entered with `update-index --index-info`, and the commit
// is never signed.
import { lstatSync, mkdtempSync, readlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { gitCommand } from "./git.js";

export class SnapshotError extends Error {
  override name = "SnapshotError";
}

const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
// A fixed identity and date make the snapshot of the same HEAD and contents the same commit.
const COMMIT_ENVIRONMENT = {
  GIT_AUTHOR_NAME: "pi-security",
  GIT_AUTHOR_EMAIL: "pi-security@localhost",
  GIT_AUTHOR_DATE: "1970-01-01T00:00:00Z",
  GIT_COMMITTER_NAME: "pi-security",
  GIT_COMMITTER_EMAIL: "pi-security@localhost",
  GIT_COMMITTER_DATE: "1970-01-01T00:00:00Z"
};

export function snapshotRef(runId: string): string {
  if (!RUN_ID.test(runId) || runId.includes("..") || runId.endsWith(".lock")) {
    throw new SnapshotError(`run id cannot name a Git ref: ${runId}`);
  }
  return `refs/pi-security/snapshots/${runId}`;
}

function git(repository: string, args: (string | Buffer)[], options: { input?: Buffer; env?: Record<string, string> } = {}): Buffer {
  const result = gitCommand(repository, args, options);
  if (result.status !== 0) {
    const detail = result.stderr.toString("utf8").trim();
    throw new SnapshotError(`git ${String(args[0])} failed${detail === "" ? ` with status ${result.status}` : `: ${detail}`}`);
  }
  return result.stdout;
}

function optionalCommit(repository: string, name: string): string | undefined {
  const result = gitCommand(repository, ["rev-parse", "--verify", "--quiet", `${name}^{commit}`]);
  return result.status === 0 ? result.stdout.toString("utf8").trim() : undefined;
}

function nulFields(output: Buffer): Buffer[] {
  const fields: Buffer[] = [];
  let start = 0;
  for (let index = 0; index < output.length; index++) {
    if (output[index] === 0) {
      if (index > start) fields.push(output.subarray(start, index));
      start = index + 1;
    }
  }
  return fields;
}

type Entry = { mode: string; oid?: string; path: Buffer };

/**
 * Snapshot the working tree of `repository` for run `runId` and return the commit ID. The commit is kept reachable
 * from refs/pi-security/snapshots/<runId>; a repeated call for the same run returns the recorded commit, so a resumed
 * run keeps the scope it started with.
 */
export function snapshotWorkingTree(repository: string, runId: string): string {
  const ref = snapshotRef(runId);
  const existing = optionalCommit(repository, ref);
  if (existing !== undefined) return existing;

  const entries = new Map<string, Entry>();
  // Tracked entries keep gitlinks (submodules) as recorded; everything else is read from the working tree.
  for (const field of nulFields(git(repository, ["ls-files", "--cached", "--stage", "-z"]))) {
    const tab = field.indexOf(0x09);
    const [mode, oid] = field.subarray(0, tab).toString("latin1").split(" ");
    const path = field.subarray(tab + 1);
    entries.set(path.toString("latin1"), mode === "160000" ? { mode, oid, path } : { mode: "", path });
  }
  for (const path of nulFields(git(repository, ["ls-files", "--others", "--exclude-standard", "-z"]))) {
    // Untracked nested repositories are listed as "dir/"; they are not part of this repository's tree.
    if (path[path.length - 1] !== 0x2f) entries.set(path.toString("latin1"), { mode: "", path });
  }

  const files: Entry[] = [];
  const links: Entry[] = [];
  const kept: Entry[] = [];
  for (const entry of entries.values()) {
    if (entry.oid !== undefined) {
      kept.push(entry);
      continue;
    }
    let stat;
    try {
      stat = lstatSync(Buffer.concat([Buffer.from(repository + sep), entry.path]));
    } catch {
      continue; // deleted in the working tree
    }
    if (stat.isSymbolicLink()) links.push({ ...entry, mode: "120000" });
    else if (stat.isFile()) files.push({ ...entry, mode: stat.mode & 0o111 ? "100755" : "100644" });
  }
  if (files.some((entry) => entry.path.includes(0x0a))) {
    throw new SnapshotError("cannot snapshot a file whose name contains a newline");
  }

  if (files.length > 0) {
    const input = Buffer.concat(files.flatMap((entry) => [entry.path, Buffer.from("\n")]));
    const oids = git(repository, ["hash-object", "-w", "--no-filters", "--stdin-paths"], { input })
      .toString("utf8")
      .trim()
      .split("\n");
    if (oids.length !== files.length) throw new SnapshotError("git hash-object returned an unexpected number of objects");
    files.forEach((entry, index) => (entry.oid = oids[index]));
  }
  for (const entry of links) {
    const target = readlinkSync(Buffer.concat([Buffer.from(repository + sep), entry.path]), { encoding: "buffer" });
    entry.oid = git(repository, ["hash-object", "-w", "--no-filters", "--stdin"], { input: target }).toString("utf8").trim();
  }

  const temporary = mkdtempSync(join(tmpdir(), "pi-security-snapshot-"));
  try {
    const env = { GIT_INDEX_FILE: join(temporary, "index") };
    const indexInfo = Buffer.concat(
      [...kept, ...files, ...links].flatMap((entry) => [Buffer.from(`${entry.mode} ${entry.oid}\t`), entry.path, Buffer.from([0])])
    );
    git(repository, ["update-index", "-z", "--index-info"], { input: indexInfo, env });
    const tree = git(repository, ["write-tree"], { env }).toString("utf8").trim();
    const head = optionalCommit(repository, "HEAD");
    const parent = head === undefined ? [] : ["-p", head];
    // --no-gpg-sign in case the installed Git applies commit.gpgSign to commit-tree, which would run gpg.program from
    // repository config. Git 2.43 does not; the flag costs nothing either way.
    const commit = git(repository, ["commit-tree", "--no-gpg-sign", tree, ...parent, "-m", "pi-security working-tree snapshot"], {
      env: COMMIT_ENVIRONMENT
    })
      .toString("utf8")
      .trim();
    // An empty old value creates the ref only if it does not exist yet.
    const created = gitCommand(repository, ["update-ref", ref, commit, ""]);
    if (created.status !== 0) {
      const recorded = optionalCommit(repository, ref);
      if (recorded !== undefined) return recorded;
      throw new SnapshotError(`git update-ref failed: ${created.stderr.toString("utf8").trim()}`);
    }
    return commit;
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

/** Remove a run's snapshot ref; the commit becomes unreachable and Git collects it eventually. */
export function deleteSnapshot(repository: string, runId: string): void {
  gitCommand(repository, ["update-ref", "-d", snapshotRef(runId)]);
}
