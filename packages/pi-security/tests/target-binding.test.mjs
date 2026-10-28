// Target binding parity: stableTargetId, worktreeContentDigest, and directoryContentDigest must equal
// scripts/workbench_target.py and workbench_target_state.py on the same synthetic repositories and directories.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { build } from "esbuild";

const packageRoot = resolve(import.meta.dirname, "..");
const bundled = await build({
  bundle: true,
  stdin: { contents: 'export * from "./src/target/binding.ts";', resolveDir: packageRoot },
  format: "esm",
  platform: "node",
  write: false,
});
const binding = await import(`data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].contents).toString("base64")}`);

const ENV = { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.invalid", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.invalid", GIT_AUTHOR_DATE: "2026-01-01T00:00:00Z", GIT_COMMITTER_DATE: "2026-01-01T00:00:00Z" };
function git(cwd, ...args) {
  const result = spawnSync("git", ["-c", "protocol.file.allow=always", "-c", "init.defaultBranch=main", ...args], { cwd, env: ENV, encoding: "utf8" });
  assert.equal(result.status, 0, `git ${args.join(" ")}: ${result.stderr}`);
  return result.stdout.trim();
}
const write = (path, content, mode) => {
  mkdirSync(resolve(path, ".."), { recursive: true });
  writeFileSync(path, content);
  if (mode !== undefined) chmodSync(path, mode);
};

const PYTHON = `
import json, sys, importlib.util
from pathlib import Path
sys.path.insert(0, sys.argv[1])
def load(name):
    spec = importlib.util.spec_from_file_location(name, f"{sys.argv[1]}/{name}.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
target_module = load("workbench_target"); state = load("workbench_target_state")
out = []
for kind, path in json.loads(sys.argv[2]):
    try:
        if kind == "worktree": value = target_module.worktree_content_digest(Path(path))
        elif kind == "directory": value = target_module.directory_content_digest(Path(path))
        else: value = state.stable_target_id(Path(path))
        out.append({"ok": value})
    except SystemExit as error:
        out.append({"error": str(error)})
print(json.dumps(out))
`;

function python(calls) {
  const result = spawnSync(process.env.PYTHON ?? "python3", ["-c", PYTHON, join(packageRoot, "scripts"), JSON.stringify(calls)], { encoding: "utf8", env: ENV });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

function typescript(calls) {
  return calls.map(([kind, path]) => {
    try {
      const fn = kind === "worktree" ? binding.worktreeContentDigest : kind === "directory" ? binding.directoryContentDigest : binding.stableTargetId;
      return { ok: fn(path) };
    } catch (error) {
      if (error.name !== "TargetBindingError") throw error;
      return { error: error.message };
    }
  });
}

test("target binding digests and IDs match Python on synthetic targets", (t) => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "pi-security-binding-")));
  t.after(() => rmSync(base, { recursive: true, force: true }));

  // A Git repository with tracked changes, untracked files of every kind, a nested repository, and ordering traps.
  const repo = join(base, "repo");
  mkdirSync(repo);
  git(repo, "init", "-q");
  write(join(repo, "src", "app.py"), "print('v1')\n");
  write(join(repo, "run.sh"), "#!/bin/sh\n", 0o755);
  write(join(repo, ".gitignore"), "ignored/\n*.log\n");
  write(join(repo, "a-b"), "dash\n");
  write(join(repo, "a", "b"), "slash\n");
  git(repo, "add", ".");
  git(repo, "commit", "-qm", "base");
  const clean = ["worktree", repo];
  const cleanDigest = typescript([clean])[0];
  write(join(repo, "src", "app.py"), "print('v2')\n");
  write(join(repo, "untracked", "new file.py"), "x = 1\n", 0o640);
  write(join(repo, "untracked", "été.txt"), "unicode\n");
  write(join(repo, "ignored", "secret.txt"), "ignored\n");
  write(join(repo, "debug.log"), "ignored\n");
  symlinkSync("src/app.py", join(repo, "link-to-app"));
  const nested = join(repo, "vendor", "nested");
  mkdirSync(nested, { recursive: true });
  git(nested, "init", "-q");
  write(join(nested, "lib.c"), "int x;\n");
  write(join(nested, "z-y"), "1\n");
  write(join(nested, "z", "y"), "2\n");

  // A plain directory with the same ordering traps.
  const plain = join(base, "plain");
  write(join(plain, "a-b"), "dash\n");
  write(join(plain, "a", "b"), "slash\n");
  write(join(plain, "a", "b-c", "d"), "deep\n");
  write(join(plain, "tool.sh"), "#!/bin/sh\n", 0o700);
  symlinkSync("a-b", join(plain, "link"));
  mkdirSync(join(plain, "empty"));

  // An unborn repository and a repository with a clean, then dirty, submodule.
  const unborn = join(base, "unborn");
  mkdirSync(unborn);
  git(unborn, "init", "-q");
  write(join(unborn, "file.txt"), "unborn\n");
  const sub = join(base, "sub-origin");
  mkdirSync(sub);
  git(sub, "init", "-q");
  write(join(sub, "s.txt"), "sub\n");
  git(sub, "add", ".");
  git(sub, "commit", "-qm", "sub");
  const parent = join(base, "parent");
  mkdirSync(parent);
  git(parent, "init", "-q");
  git(parent, "submodule", "add", "-q", sub, "deps/sub");
  git(parent, "commit", "-qm", "with submodule");

  const calls = [
    ["worktree", repo],
    ["worktree", join(repo, "src")],
    ["directory", plain],
    ["directory", nested],
    ["directory", unborn],
    ["worktree", parent],
    ["id", repo],
    ["id", join(base, "café dir")],
  ];
  assert.deepEqual(typescript(calls), python(calls));
  assert.notDeepEqual(typescript([clean])[0], cleanDigest, "the digest changes with the working tree");

  write(join(parent, "deps", "sub", "s.txt"), "dirty\n");
  const dirty = [["worktree", parent]];
  const [actual] = typescript(dirty);
  assert.deepEqual([actual], python(dirty));
  assert.match(actual.error, /Dirty Git submodules/);
});

test("bindTarget picks git_worktree for a repository with HEAD and directory_snapshot otherwise", (t) => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "pi-security-binding-")));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const repo = join(base, "service");
  mkdirSync(repo);
  git(repo, "init", "-q");
  write(join(repo, "a.txt"), "a\n");
  git(repo, "add", ".");
  git(repo, "commit", "-qm", "a");
  const bound = binding.bindTarget(repo);
  assert.equal(bound.kind, "git_worktree");
  assert.equal(bound.revision, git(repo, "rev-parse", "HEAD"));
  assert.equal(bound.displayName, "service");
  assert.equal(bound.targetId, binding.stableTargetId(repo));
  const plain = join(base, "plain");
  write(join(plain, "x"), "x\n");
  assert.equal(binding.bindTarget(plain).kind, "directory_snapshot");
});
