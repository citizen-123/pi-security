// Target confinement (design D7): ConfinedRoot and the ConfinedEnv adapter refuse every escape (absolute paths,
// `..`, `~`, symbolic links anywhere in a path, the scan scope), refuse writes, watching, and execution, and serve
// permitted reads exactly like pi-durable's stock NodeExecutionEnv. ConfinedRoot.readFile is also raced against a
// directory swapped for a symbolic link.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { build } from "esbuild";

const packageRoot = resolve(import.meta.dirname, "..");
const outfile = join(packageRoot, "node_modules", ".cache", "pi-security-tests", "confined-env.mjs");
await build({
  bundle: true,
  stdin: {
    contents: [
      'export * from "./src/target/confined-root.ts";',
      'export * from "./src/durable/confined-env.ts";',
      'export { NodeExecutionEnv } from "@earendil-works/pi-durable/env/node";',
      'export { BACKGROUND_CONTEXT } from "@earendil-works/chord/context";',
    ].join("\n"),
    resolveDir: packageRoot,
  },
  format: "esm",
  outfile,
  packages: "external",
  platform: "node",
});
const { ConfinedRoot, ConfinedEnv, NodeExecutionEnv, BACKGROUND_CONTEXT: context } = await import(outfile);

/** sandbox/target (the root) with files, plus sandbox/outside holding a secret. */
function sandbox(t) {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "pi-security-confined-")));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const root = join(base, "target");
  for (const directory of ["src/lib", "docs", "outside"]) mkdirSync(join(directory === "outside" ? base : root, directory), { recursive: true });
  writeFileSync(join(base, "outside", "secret.txt"), "SECRET\n");
  writeFileSync(join(root, "src", "app.py"), "print('app')\nsecond line\n");
  writeFileSync(join(root, "src", "lib", "util.py"), "\ufeffdef util():\n    return 1\n");
  writeFileSync(join(root, "docs", "readme.md"), "# Readme\n");
  writeFileSync(join(root, "~"), "a file named tilde\n");
  symlinkSync(join(base, "outside", "secret.txt"), join(root, "src", "secret-link.txt"));
  symlinkSync(join(base, "outside"), join(root, "outside-dir"));
  symlinkSync("app.py", join(root, "src", "inside-link.py"));
  symlinkSync("missing.txt", join(root, "src", "dangling.txt"));
  return { base, root };
}

const ESCAPES = [
  ["../outside/secret.txt", "escape"],
  ["src/../../outside/secret.txt", "escape"],
  ["src/../src/app.py", "escape"],
  ["~/secret.txt", "not_directory"],
  ["C:/Windows/win.ini", "escape"],
  ["src/secret-link.txt", "symlink"],
  ["outside-dir/secret.txt", "symlink"],
  ["outside-dir", "symlink"],
  ["src/inside-link.py", "symlink"],
  ["src/dangling.txt", "symlink"],
  ["src/app.py\0.txt", "invalid"],
  ["", "invalid"],
];

test("ConfinedRoot refuses every escape and reads only real files inside the root", (t) => {
  const { base, root } = sandbox(t);
  const confined = ConfinedRoot.open(root);
  for (const [path, code] of [...ESCAPES, [join(base, "outside", "secret.txt"), "escape"], ["/etc/passwd", "escape"]]) {
    assert.throws(() => confined.readFile(path), (error) => error.name === "ConfinementError" && error.code === code, `${JSON.stringify(path)} should fail with ${code}`);
  }
  assert.equal(confined.readFile("src/app.py").toString(), "print('app')\nsecond line\n");
  assert.equal(confined.readFile("./src//app.py").toString(), "print('app')\nsecond line\n");
  assert.equal(confined.readFile(join(root, "docs", "readme.md")).toString(), "# Readme\n");
  assert.equal(confined.readFile("~").toString(), "a file named tilde\n", "a file literally named ~ is a repository file");
  assert.throws(() => confined.readFile("src"), { code: "is_directory" });
  assert.throws(() => confined.readFile("src/missing.py"), { code: "not_found" });
  assert.throws(() => confined.readFile("src/app.py/x"), { code: "not_directory" });
  assert.deepEqual(
    confined.listDir("src").map(({ name, kind }) => [name, kind]),
    [["app.py", "file"], ["dangling.txt", "symlink"], ["inside-link.py", "symlink"], ["lib", "directory"], ["secret-link.txt", "symlink"]],
  );
  assert.throws(() => confined.listDir("outside-dir"), { code: "symlink" });
});

test("ConfinedRoot confines to its scope and refuses a symlinked or missing root", (t) => {
  const { base, root } = sandbox(t);
  const scoped = ConfinedRoot.open(root, "src");
  assert.equal(scoped.readFile("src/lib/util.py").length > 0, true);
  assert.throws(() => scoped.readFile("docs/readme.md"), { code: "escape" });
  assert.throws(() => scoped.readFile("srcx/file"), { code: "escape" });
  assert.throws(() => ConfinedRoot.open(root, "outside-dir"), { code: "symlink" });
  assert.throws(() => ConfinedRoot.open(root, "src/app.py"), { code: "not_directory" });
  assert.throws(() => ConfinedRoot.open(root, "../outside"), { code: "escape" });
  symlinkSync(root, join(base, "alias"));
  assert.throws(() => ConfinedRoot.open(join(base, "alias")), { code: "symlink" });
  assert.throws(() => ConfinedRoot.open(join(base, "missing")), { code: "not_found" });
});

test("ConfinedRoot.readFile never returns outside content while a directory is swapped for a symlink", async (t) => {
  const { base, root } = sandbox(t);
  mkdirSync(join(root, "swap"));
  writeFileSync(join(root, "swap", "secret.txt"), "inside\n");
  const confined = ConfinedRoot.open(root);
  const script = `
    const { renameSync, symlinkSync, rmSync } = await import("node:fs");
    const dir = ${JSON.stringify(join(root, "swap"))}, kept = dir + ".real";
    const end = Date.now() + 1500;
    while (Date.now() < end) {
      renameSync(dir, kept); symlinkSync(${JSON.stringify(join(base, "outside"))}, dir);
      rmSync(dir); renameSync(kept, dir);
    }
  `;
  const swapper = spawn(process.execPath, ["--input-type=module", "-e", script], { stdio: "inherit" });
  const done = new Promise((resolveDone) => swapper.once("exit", resolveDone));
  t.after(() => swapper.kill("SIGKILL"));
  let reads = 0;
  let refusals = 0;
  let exited = false;
  done.then(() => (exited = true));
  while (!exited) {
    try {
      assert.equal(confined.readFile("swap/secret.txt").toString(), "inside\n");
      reads++;
    } catch (error) {
      assert.equal(error.name, "ConfinementError", String(error));
      refusals++;
    }
    await new Promise((resolveTick) => setImmediate(resolveTick));
  }
  assert.ok(reads > 0 && refusals > 0, `the race was exercised: ${reads} reads, ${refusals} refusals`);
});

test("ConfinedEnv refuses escapes, writes, temporary files, watching, and execution", async (t) => {
  const { base, root } = sandbox(t);
  const env = new ConfinedEnv(ConfinedRoot.open(root));
  const before = readdirSync(root, { recursive: true }).sort();
  for (const [path] of ESCAPES) {
    for (const call of [() => env.readTextFile(path, context), () => env.readBinaryFile(path, context), () => env.fileInfo(path, context), () => env.openBinaryReader(path, undefined, context)]) {
      const result = await call();
      assert.equal(result.ok, false, `${JSON.stringify(path)} should be refused`);
    }
  }
  assert.equal((await env.readTextFile(join(base, "outside", "secret.txt"), context)).ok, false);
  assert.equal((await env.exists("outside-dir/secret.txt", context)).ok, false, "exists does not reveal what a link points to");
  const refusals = [
    env.writeFile("new.txt", "x", context),
    env.writeFile("src/app.py", "x", context),
    env.appendFile("src/app.py", "x", context),
    env.truncateFile("src/app.py", 0, context),
    env.flushFile("src/app.py", context),
    env.renameFile("src/app.py", "src/moved.py", context),
    env.createDir("newdir", undefined, context),
    env.remove("src/app.py", undefined, context),
    env.createTempDir("x", context),
    env.createTempFile(undefined, context),
    env.watch([{ path: "src" }], () => {}, context),
    env.exec(["sh", "-c", "touch pwned"], undefined, context),
    env.exec("touch pwned", undefined, context),
  ];
  for (const result of await Promise.all(refusals)) assert.equal(result.ok, false);
  assert.deepEqual(readdirSync(root, { recursive: true }).sort(), before, "nothing on disk changed");
});

/** Normalize a Result for comparison: values as is (bytes as arrays), errors by code. */
const shape = (result) => (result.ok ? { ok: result.value instanceof Uint8Array ? [...result.value] : result.value } : { error: result.error.code });

test("ConfinedEnv serves permitted reads exactly like NodeExecutionEnv", async (t) => {
  const { root } = sandbox(t);
  const env = new ConfinedEnv(ConfinedRoot.open(root));
  const stock = new NodeExecutionEnv({ cwd: root });
  for (const path of ["src/app.py", "src/lib/util.py", "docs/readme.md", "~", "src/missing.py", "src"]) {
    for (const method of ["readTextFile", "readBinaryFile", "fileInfo", "exists", "canonicalPath"]) {
      assert.deepEqual(shape(await env[method](path, context)), shape(await stock[method](join(root, path), context)), `${method} ${path}`);
    }
    assert.deepEqual(
      shape(await env.readTextLines(path, { maxLines: 1 }, context)),
      shape(await stock.readTextLines(join(root, path), { maxLines: 1 }, context)),
      `readTextLines ${path}`,
    );
  }
  for (const path of [".", "src", "src/lib", "docs"]) {
    const sorted = (result) => (result.ok ? { ok: [...result.value].sort((a, b) => (a.name < b.name ? -1 : 1)) } : shape(result));
    assert.deepEqual(sorted(await env.listDir(path, context)), sorted(await stock.listDir(join(root, path), context)), `listDir ${path}`);
  }
  const reader = (await env.openBinaryReader("src/lib/util.py", undefined, context)).value;
  const stockReader = (await stock.openBinaryReader(join(root, "src/lib/util.py"), { noFollow: true }, context)).value;
  try {
    assert.deepEqual(shape(await reader.read(3, 10, context)), shape(await stockReader.read(3, 10, context)));
    assert.deepEqual(shape(await reader.scanLines({ startLine: 1 }, context)), shape(await stockReader.scanLines({ startLine: 1 }, context)));
  } finally {
    await reader.close(context);
    await stockReader.close(context);
  }
  const lines = (await env.openTextLineReader("src/app.py", context)).value;
  try {
    assert.deepEqual(shape(await lines.readLine(context)), { ok: { text: "print('app')", terminated: true } });
  } finally {
    await lines.close(context);
  }
});

test("isInsideDirectory compares canonical paths, so a symlinked alias still counts as inside", async (t) => {
  const { isInsideDirectory } = await import(outfile);
  const { base, root } = sandbox(t);
  symlinkSync(root, join(base, "alias"));
  assert.equal(isInsideDirectory(root, join(root, "src")), true);
  assert.equal(isInsideDirectory(root, root), true);
  assert.equal(isInsideDirectory(root, join(base, "alias", "runs")), true);
  assert.equal(isInsideDirectory(root, join(base, "outside")), false);
  assert.equal(isInsideDirectory(root, `${root}x`), false);
  assert.equal(isInsideDirectory(join(root, "src"), root), false);
});
