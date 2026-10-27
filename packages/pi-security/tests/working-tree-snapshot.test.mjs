// Working-tree snapshots (design D14): the snapshot commit holds exactly the working tree, the user's repository state
// is untouched, repository config cannot run programs, and a run keeps the snapshot it started with.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { build } from "esbuild";

const bundled = await build({
  bundle: true,
  stdin: {
    contents: 'export * from "./src/target/snapshot.ts"; export * from "./src/target/inventory.ts";',
    resolveDir: new URL("..", import.meta.url).pathname,
  },
  format: "esm",
  platform: "node",
  write: false,
});
const { snapshotWorkingTree, deleteSnapshot, generateInventory, SnapshotError } = await import(
  `data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].contents).toString("base64")}`
);

const IDENTITY = {
  GIT_AUTHOR_NAME: "Test",
  GIT_AUTHOR_EMAIL: "test@example.invalid",
  GIT_COMMITTER_NAME: "Test",
  GIT_COMMITTER_EMAIL: "test@example.invalid",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
};

function git(repo, ...args) {
  const result = spawnSync("git", ["-C", repo, ...args], { env: { ...process.env, ...IDENTITY } });
  if (result.status !== 0) throw new Error(`git ${args.join(" ")}: ${result.stderr}`);
  return result.stdout.toString("utf8");
}

function write(repo, path, text) {
  mkdirSync(dirname(join(repo, path)), { recursive: true });
  writeFileSync(join(repo, path), text);
}

function makeRepository() {
  const repo = join(mkdtempSync(join(tmpdir(), "pi-security-snapshot-test-")), "repo");
  mkdirSync(repo);
  git(repo, "init", "-q", "-b", "main");
  write(repo, "a.py", "a = 1\n");
  write(repo, "b.py", "b = 1\n");
  write(repo, "deleted.py", "gone = 1\n");
  write(repo, "bin.sh", "#!/bin/sh\necho hi\n");
  chmodSync(join(repo, "bin.sh"), 0o755);
  write(repo, "sub/x.js", "export const x = 1;\n");
  write(repo, ".gitignore", "ignored/\n*.log\n");
  write(repo, ".gitattributes", "*.py filter=evil\n");
  symlinkSync("a.py", join(repo, "link.py"));
  git(repo, "add", "-A");
  git(repo, "commit", "-q", "-m", "base");
  // A stash entry, then uncommitted work of every kind.
  write(repo, "b.py", "b = 2  # stashed\n");
  git(repo, "stash", "-q");
  write(repo, "a.py", "a = 2  # unstaged\n");
  write(repo, "staged.py", "s = 1\n");
  git(repo, "add", "staged.py");
  unlinkSync(join(repo, "deleted.py"));
  write(repo, "u.rb", "puts 1\n");
  write(repo, "ignored/secret.py", "secret = 1\n");
  write(repo, "debug.log", "log\n");
  return repo;
}

function fileDigests(repo) {
  const digests = {};
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      const rel = path.slice(repo.length + 1);
      if (rel === ".git") continue;
      if (entry.isDirectory()) walk(path);
      else if (entry.isSymbolicLink()) digests[rel] = `link:${readFileSync(path, { flag: "r" }).length}`;
      else digests[rel] = createHash("sha256").update(readFileSync(path)).digest("hex");
    }
  };
  walk(repo);
  return digests;
}

function repositoryState(repo) {
  return {
    head: git(repo, "rev-parse", "HEAD"),
    branch: git(repo, "symbolic-ref", "HEAD"),
    index: createHash("sha256").update(readFileSync(join(repo, ".git", "index"))).digest("hex"),
    stash: git(repo, "stash", "list"),
    status: git(repo, "status", "--porcelain=v2", "-z", "--untracked-files=all"),
    refs: git(repo, "for-each-ref", "--format=%(refname) %(objectname)")
      .split("\n")
      .filter((line) => line !== "" && !line.startsWith("refs/pi-security/"))
      .join("\n"),
    files: fileDigests(repo),
  };
}

function treeEntries(repo, commit) {
  const entries = {};
  for (const line of git(repo, "ls-tree", "-r", "-z", commit).split("\0").filter(Boolean)) {
    const [meta, path] = line.split("\t");
    const [mode, , oid] = meta.split(" ");
    entries[path] = { mode, content: git(repo, "cat-file", "blob", oid) };
  }
  return entries;
}

test("the snapshot holds the working tree and leaves the repository untouched", () => {
  const repo = makeRepository();
  // Measured before hostile config is installed: status itself would run a clean filter.
  const before = repositoryState(repo);
  const marker = join(dirname(repo), "executed");
  const hostile = join(dirname(repo), "hostile.sh");
  writeFileSync(hostile, `#!/bin/sh\ntouch ${marker}\ncat\n`);
  chmodSync(hostile, 0o755);
  git(repo, "config", "filter.evil.clean", hostile);
  // Git versions that apply commit.gpgSign to commit-tree would run gpg.program; 2.43 does not.
  git(repo, "config", "commit.gpgSign", "true");
  git(repo, "config", "gpg.program", hostile);

  const commit = snapshotWorkingTree(repo, "run-1");

  assert.equal(existsSync(marker), false, "repository config must not run a program");
  git(repo, "config", "--unset", "filter.evil.clean");
  git(repo, "config", "--unset", "commit.gpgSign");
  git(repo, "config", "--unset", "gpg.program");
  assert.deepEqual(repositoryState(repo), before);

  assert.equal(git(repo, "rev-parse", "refs/pi-security/snapshots/run-1").trim(), commit);
  assert.equal(git(repo, "rev-parse", `${commit}^`).trim(), before.head.trim());
  assert.deepEqual(treeEntries(repo, commit), {
    ".gitattributes": { mode: "100644", content: "*.py filter=evil\n" },
    ".gitignore": { mode: "100644", content: "ignored/\n*.log\n" },
    "a.py": { mode: "100644", content: "a = 2  # unstaged\n" },
    "b.py": { mode: "100644", content: "b = 1\n" },
    "bin.sh": { mode: "100755", content: "#!/bin/sh\necho hi\n" },
    "link.py": { mode: "120000", content: "a.py" },
    "staged.py": { mode: "100644", content: "s = 1\n" },
    "sub/x.js": { mode: "100644", content: "export const x = 1;\n" },
    "u.rb": { mode: "100644", content: "puts 1\n" },
  });
  rmSync(dirname(repo), { recursive: true, force: true });
});

test("a run keeps its snapshot; the same state snapshots to the same commit", () => {
  const repo = makeRepository();
  const first = snapshotWorkingTree(repo, "run-1");
  assert.equal(snapshotWorkingTree(repo, "run-2"), first, "fixed identity and date make snapshots deterministic");
  write(repo, "a.py", "a = 3  # edited during the scan\n");
  assert.equal(snapshotWorkingTree(repo, "run-1"), first, "edits after preflight cannot change a run's scope");
  assert.notEqual(snapshotWorkingTree(repo, "run-3"), first);
  deleteSnapshot(repo, "run-1");
  assert.equal(spawnSync("git", ["-C", repo, "rev-parse", "--verify", "--quiet", "refs/pi-security/snapshots/run-1"]).status, 1);
  rmSync(dirname(repo), { recursive: true, force: true });
});

test("a revision diff against the snapshot equals the local-patch inventory", () => {
  const repo = makeRepository();
  const commit = snapshotWorkingTree(repo, "run-1");
  const viaSnapshot = generateInventory({ repository: repo, scope: ".", diff: { base: "HEAD", head: commit } }).bytes;
  const viaPatch = generateInventory({ repository: repo, scope: ".", diff: { base: "HEAD", mode: "local-patch" } }).bytes;
  assert.equal(viaSnapshot.toString(), viaPatch.toString());
  assert.equal(viaSnapshot.toString(), "a.py\ndeleted.py\nstaged.py\nu.rb\n");
  rmSync(dirname(repo), { recursive: true, force: true });
});

test("a repository without commits snapshots to a root commit", () => {
  const repo = join(mkdtempSync(join(tmpdir(), "pi-security-snapshot-test-")), "repo");
  mkdirSync(repo);
  git(repo, "init", "-q", "-b", "main");
  write(repo, "first.py", "x = 1\n");
  const commit = snapshotWorkingTree(repo, "run-1");
  assert.deepEqual(Object.keys(treeEntries(repo, commit)), ["first.py"]);
  assert.equal(spawnSync("git", ["-C", repo, "rev-parse", "--verify", "--quiet", `${commit}^`]).status, 1);
  assert.equal(spawnSync("git", ["-C", repo, "rev-parse", "--verify", "--quiet", "HEAD"]).status, 1, "HEAD stays unborn");
  rmSync(dirname(repo), { recursive: true, force: true });
});

test("unusable run ids and newline file names are rejected", () => {
  const repo = makeRepository();
  for (const runId of ["", "../escape", "a..b", "run.lock", "with space", "-dash"]) {
    assert.throws(() => snapshotWorkingTree(repo, runId), SnapshotError, runId);
  }
  write(repo, "bad\nname.py", "x\n");
  assert.throws(() => snapshotWorkingTree(repo, "run-1"), SnapshotError);
  rmSync(dirname(repo), { recursive: true, force: true });
});
