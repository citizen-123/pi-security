// src/durable/: state directory resolution, run IDs, private run directories, the exclusive run lock (across real
// processes), and Harness open/close over run.sqlite.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { hostname, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { build } from "esbuild";

const packageRoot = resolve(import.meta.dirname, "..");
// Bundled to a file inside the package so pi-durable and its workers resolve from node_modules.
const outfile = join(packageRoot, "node_modules", ".cache", "pi-security-tests", "durable-run.mjs");
await build({
  bundle: true,
  stdin: {
    contents: [
      'export * from "./src/durable/run-directory.ts";',
      'export * from "./src/durable/run-lock.ts";',
      'export * from "./src/durable/harness.ts";',
      'export { createRegistry, defineDoc } from "@earendil-works/pi-durable";',
      'export { createModels } from "@earendil-works/pi-ai/models";',
    ].join("\n"),
    resolveDir: packageRoot,
  },
  format: "esm",
  outfile,
  packages: "external",
  platform: "node",
});
const durable = await import(outfile);

const Marker = durable.defineDoc({ kind: "test.marker", version: 1, scope: "session", initial: () => ({}), checkpointWhen: () => false });
const options = () => ({ models: durable.createModels(), registry: durable.createRegistry(), settings: { extensions: [] } });
const mode = (path) => (lstatSync(path).mode & 0o777).toString(8);

function scratch(t) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "pi-security-durable-")));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

function newRun(t) {
  const state = join(scratch(t), "state");
  return durable.runPaths(state, durable.newRunId(new Date("2026-06-01T10:20:30.456Z")));
}

test("the state directory follows PI_SECURITY_STATE_DIR, then PI_HOME", () => {
  assert.equal(durable.resolveStateDirectory({ PI_SECURITY_STATE_DIR: "/srv/state" }, "/work"), "/srv/state");
  assert.equal(durable.resolveStateDirectory({ PI_SECURITY_STATE_DIR: "rel" }, "/work"), "/work/rel");
  assert.equal(durable.resolveStateDirectory({ PI_SECURITY_STATE_DIR: " ", PI_HOME: "/home/u/.pi" }, "/work"), "/home/u/.pi/security");
  assert.match(durable.resolveStateDirectory({}, "/work"), /\/\.pi\/security$/);
  assert.match(durable.resolveStateDirectory({ PI_HOME: "~/custom" }, "/work"), /\/custom\/security$/);
});

test("run IDs sort by creation time and carry an 8-digit short ID", () => {
  const id = durable.newRunId(new Date("2026-06-01T10:20:30.456Z"));
  assert.match(id, /^20260601T102030Z-[0-9a-f]{8}$/);
  assert.equal(durable.shortRunId(id), id.slice(-8));
  for (const bad of ["../x", "20260601T102030Z-0000000", "20260601T102030Z-0000000g", "x"]) {
    assert.throws(() => durable.requireRunId(bad), { name: "RunDirectoryError" });
  }
});

test("a run opens privately, persists across reopen, and releases its lock on close", async (t) => {
  const paths = newRun(t);
  const run = await durable.openRun(paths, options());
  assert.equal(mode(paths.directory), "700");
  assert.equal(mode(join(paths.directory, "..")), "700");
  assert.equal(mode(paths.storage), "600");
  assert.equal(mode(paths.lock), "600");
  const owner = JSON.parse(readFileSync(durable.ownerPath(paths.lock), "utf8"));
  assert.deepEqual([owner.pid, owner.host], [process.pid, hostname()]);
  assert.equal(mode(durable.ownerPath(paths.lock)), "600");
  const root = await run.harness.root(durable.RUN_CONTEXT);
  await root.commit(async (tx) => {
    (await tx.doc(Marker)).value = "first";
  }, durable.RUN_CONTEXT);
  for (const suffix of ["-wal", "-shm"]) {
    if (existsSync(paths.storage + suffix)) assert.equal(mode(paths.storage + suffix), "600", suffix);
  }
  await run.close();
  await run.close();
  assert.equal(existsSync(durable.ownerPath(paths.lock)), false);

  const reopened = await durable.openRun(paths, options());
  try {
    assert.deepEqual(await reopened.harness.snapshot(Marker, durable.RUN_CONTEXT), { value: "first" });
  } finally {
    await reopened.close();
  }
});

test("a second open of a held run fails without touching the holder's lock", async (t) => {
  const paths = newRun(t);
  const run = await durable.openRun(paths, options());
  try {
    await assert.rejects(durable.openRun(paths, options()), (error) => error.name === "RunLockedError" && error.holder.pid === process.pid);
    assert.equal(JSON.parse(readFileSync(durable.ownerPath(paths.lock), "utf8")).token, run.lock.holder.token);
  } finally {
    await run.close();
  }
});

/** Start a process that takes the lock and waits; resolves once the lock is held. */
function holdLockInChild(lockPath) {
  const script = `
    const { acquireRunLock } = await import(${JSON.stringify(outfile)});
    acquireRunLock(${JSON.stringify(lockPath)});
    process.stdout.write("held\\n");
    setInterval(() => {}, 1000);
  `;
  const child = spawn(process.execPath, ["--input-type=module", "--no-warnings", "-e", script], { stdio: ["ignore", "pipe", "inherit"] });
  return new Promise((resolveHeld, reject) => {
    child.stdout.once("data", () => resolveHeld(child));
    child.once("exit", (code) => reject(new Error(`lock holder exited early: ${code}`)));
  });
}

test("a lock held by a live process blocks the run and frees itself when that process is killed", async (t) => {
  const paths = durable.ensureRunDirectory(newRun(t));
  const child = await holdLockInChild(paths.lock);
  t.after(() => child.kill("SIGKILL"));
  await assert.rejects(durable.openRun(paths, options()), (error) => error.name === "RunLockedError" && error.holder.pid === child.pid);
  child.kill("SIGKILL");
  await new Promise((done) => child.once("exit", done));
  const run = await durable.openRun(paths, options());
  try {
    assert.equal(JSON.parse(readFileSync(durable.ownerPath(paths.lock), "utf8")).pid, process.pid);
  } finally {
    await run.close();
  }
});

test("releasing twice is harmless, and a released lock can be taken again", (t) => {
  const paths = durable.ensureRunDirectory(newRun(t));
  const first = durable.acquireRunLock(paths.lock);
  assert.throws(() => durable.acquireRunLock(paths.lock), { name: "RunLockedError" });
  first.release();
  first.release();
  const second = durable.acquireRunLock(paths.lock);
  second.release();
});

test("a symlinked run directory or storage file is refused", async (t) => {
  const root = scratch(t);
  const elsewhere = join(root, "elsewhere");
  mkdirSync(elsewhere);
  const paths = durable.runPaths(join(root, "state"), durable.newRunId());
  mkdirSync(join(paths.directory, ".."), { recursive: true });
  symlinkSync(elsewhere, paths.directory);
  await assert.rejects(durable.openRun(paths, options()), { name: "RunDirectoryError" });

  const second = durable.runPaths(join(root, "state"), durable.newRunId());
  mkdirSync(second.directory, { recursive: true });
  symlinkSync(join(elsewhere, "target.sqlite"), second.storage);
  await assert.rejects(durable.openRun(second, options()), (error) => error.code === "ELOOP");
  assert.equal(existsSync(durable.ownerPath(second.lock)), false, "the lock is released when open fails");
  durable.acquireRunLock(second.lock).release();
  assert.equal(existsSync(join(elsewhere, "target.sqlite")), false);
});

test("an existing state directory with loose permissions is tightened", async (t) => {
  const paths = newRun(t);
  mkdirSync(join(paths.directory, "..", ".."), { recursive: true, mode: 0o755 });
  const run = await durable.openRun(paths, options());
  await run.close();
  assert.equal(mode(join(paths.directory, "..", "..")), "700");
});

test("processes racing for a free lock, or for one whose holder died, leave exactly one holder", async (t) => {
  for (const scenario of ["fresh", "fresh", "dead holder", "dead holder"]) {
    const paths = durable.ensureRunDirectory(newRun(t));
    if (scenario === "dead holder") {
      const holder = await holdLockInChild(paths.lock);
      holder.kill("SIGKILL");
      await new Promise((done) => holder.once("exit", done));
      assert.ok(existsSync(durable.ownerPath(paths.lock)), "a killed holder leaves its owner file behind");
    }
    const script = `
      const { acquireRunLock } = await import(${JSON.stringify(outfile)});
      let held = false;
      try { acquireRunLock(${JSON.stringify(paths.lock)}); held = true; } catch (error) { if (error.name !== "RunLockedError") throw error; }
      process.stdout.write(held ? "held" : "locked");
      // Keep holding until the test has every outcome, so a slow starter cannot take a lock released early.
      setInterval(() => {}, 1000);
    `;
    const racers = Array.from({ length: 8 }, () =>
      spawn(process.execPath, ["--input-type=module", "--no-warnings", "-e", script], { stdio: ["ignore", "pipe", "inherit"] }),
    );
    const outcomes = await Promise.all(
      racers.map((child) => new Promise((done) => {
        child.stdout.once("data", (chunk) => done(String(chunk)));
        child.once("exit", (code) => done(`exit ${code}`));
      })),
    );
    for (const child of racers) child.kill("SIGKILL");
    assert.equal(outcomes.filter((outcome) => outcome === "held").length, 1, `${scenario}: ${outcomes.join(", ")}`);
    assert.equal(outcomes.filter((outcome) => outcome === "locked").length, 7, `${scenario}: ${outcomes.join(", ")}`);
  }
});
