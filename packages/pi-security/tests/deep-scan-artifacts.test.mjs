import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { constants as fsConstants, promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { build } from "esbuild";

const executeFile = promisify(execFile);

const artifacts = await loadArtifactModule();
const windowsArtifacts = await loadArtifactModule("win32");
const {
  archiveDirectory,
  createDeepScanArtifacts,
  ensureDeepScanDirectories,
  readJsonObject,
  requireRegularFile,
  writeJsonAtomic,
  writePrivateFile
} = artifacts;

async function loadArtifactModule(platform) {
  const bundle = await build({
    bundle: true,
    entryPoints: [new URL("../src/deep-scan/artifacts.ts", import.meta.url).pathname],
    format: "esm",
    platform: "node",
    ...(platform
      ? { define: { "process.platform": JSON.stringify(platform) } }
      : {}),
    write: false
  });
  return await import(
    `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
  );
}

const temporaryRoots = [];

try {
  await testDeepArtifactWritesRejectSwappedDirectories();
  await testPostOpenDirectorySwapDoesNotWriteContent();
  await testArtifactReadsAndArchivingRejectSymlinks();
  await testWindowsSafeArtifactBackend();
  await testFifoCandidatesRejectWithoutBlocking();
} finally {
  await Promise.all(temporaryRoots.map((root) => rm(root, { recursive: true, force: true })));
}

async function testDeepArtifactWritesRejectSwappedDirectories() {
  const [scanDir, outside] = await Promise.all([
    fixtureDirectory("pi-security-deep-artifacts-scan-"),
    fixtureDirectory("pi-security-deep-artifacts-outside-")
  ]);
  const artifacts = createDeepScanArtifacts(scanDir);
  await ensureDeepScanDirectories(artifacts);
  await writePrivateFile(path.join(artifacts.workersRoot, "prompt.md"), "private");
  const heartbeat = path.join(artifacts.deepRoot, "heartbeat.json");
  await writeJsonAtomic(heartbeat, { live: true });
  assert.deepEqual(await readJsonObject(heartbeat), { live: true });
  await rm(artifacts.deepRoot, { recursive: true, force: true });
  await symlink(outside, artifacts.deepRoot, "dir");

  await assert.rejects(
    ensureDeepScanDirectories(artifacts),
    /Deep Scan artifact directory/
  );
  await assert.rejects(
    writePrivateFile(path.join(artifacts.deepRoot, "workers", "prompt.md"), "escape"),
    /Deep Scan private file/
  );
  await assert.rejects(
    writeJsonAtomic(path.join(artifacts.deepRoot, "heartbeat.json"), { escaped: true }),
    /Deep Scan JSON artifact/
  );
  assert.deepEqual(await readdir(outside), []);
}


async function testPostOpenDirectorySwapDoesNotWriteContent() {
  const [scanDir, outside] = await Promise.all([
    fixtureDirectory("pi-security-deep-artifacts-race-"),
    fixtureDirectory("pi-security-deep-artifacts-race-outside-")
  ]);
  const parent = path.join(scanDir, "parent");
  const displaced = path.join(outside, "displaced");
  const target = path.join(parent, "private.txt");
  await mkdir(parent);

  const originalOpen = fs.open;
  let swapped = false;
  fs.open = async (...args) => {
    const handle = await originalOpen(...args);
    if (!swapped && String(args[0]).endsWith("/private.txt")) {
      swapped = true;
      await fs.rename(parent, displaced);
      await mkdir(parent);
    }
    return handle;
  };
  try {
    await assert.rejects(
      writePrivateFile(target, "must-not-escape"),
      /changed while its directory handle was open/
    );
  } finally {
    fs.open = originalOpen;
  }

  assert.equal(swapped, true);
  assert.equal(await fs.readFile(path.join(displaced, "private.txt"), "utf8"), "");
  await assert.rejects(fs.lstat(target));
}
async function testArtifactReadsAndArchivingRejectSymlinks() {
  const [scanDir, outside] = await Promise.all([
    fixtureDirectory("pi-security-deep-artifacts-read-"),
    fixtureDirectory("pi-security-deep-artifacts-read-outside-")
  ]);
  const linkedFile = path.join(scanDir, "linked.json");
  const outsideFile = path.join(outside, "outside.json");
  await writeFile(outsideFile, '{"outside":true}\n');
  await symlink(outsideFile, linkedFile, "file");

  await assert.rejects(readJsonObject(linkedFile), /Invalid Deep Scan JSON artifact/);
  await assert.rejects(requireRegularFile(linkedFile, scanDir), /Deep Scan artifact/);

  const source = path.join(scanDir, "source");
  const destination = path.join(scanDir, "archive");
  await mkdir(path.join(outside, "source"));
  await writeFile(path.join(outside, "source", "sentinel.txt"), "outside\n");
  await symlink(path.join(outside, "source"), source, "dir");
  await assert.rejects(archiveDirectory(source, destination), /Deep Scan archive source/);
  assert.equal(await readdir(path.join(outside, "source")).then((entries) => entries.includes("sentinel.txt")), true);
}

async function testWindowsSafeArtifactBackend() {
  const [scanDir, outside] = await Promise.all([
    fixtureDirectory("pi-security-deep-artifacts-windows-scan-"),
    fixtureDirectory("pi-security-deep-artifacts-windows-outside-")
  ]);
  const windows = windowsArtifacts.createDeepScanArtifacts(scanDir);
  const heartbeat = path.join(windows.deepRoot, "heartbeat.json");

  await windowsArtifacts.ensureDeepScanDirectories(windows);
  await windowsArtifacts.writePrivateFile(
    path.join(windows.workersRoot, "prompt.md"),
    "private"
  );
  await windowsArtifacts.writeJsonAtomic(heartbeat, { live: true });
  assert.deepEqual(await windowsArtifacts.readJsonObject(heartbeat), { live: true });
  await windowsArtifacts.requireRegularFile(heartbeat, scanDir);

  await rm(windows.deepRoot, { recursive: true, force: true });
  await symlink(outside, windows.deepRoot, "dir");

  await assert.rejects(
    windowsArtifacts.ensureDeepScanDirectories(windows),
    /Deep Scan artifact directory/
  );
  await assert.rejects(
    windowsArtifacts.writePrivateFile(
      path.join(windows.deepRoot, "workers", "prompt.md"),
      "escape"
    ),
    /Deep Scan private file/
  );
  assert.deepEqual(await readdir(outside), []);
}

async function testFifoCandidatesRejectWithoutBlocking() {
  if (process.platform === "win32") return;
  const scanDir = await fixtureDirectory("pi-security-deep-artifacts-fifo-");
  const fifo = path.join(scanDir, "worker-result.fifo");
  await executeFile("mkfifo", [fifo]);

  await assertFifoRejectedPromptly(
    () => requireRegularFile(fifo, scanDir),
    fifo,
    /Deep Scan artifact/
  );
  await assertFifoRejectedPromptly(
    () => readJsonObject(fifo),
    fifo,
    /Invalid Deep Scan JSON artifact/
  );
}

async function assertFifoRejectedPromptly(operation, fifo, expectedError) {
  const attempt = operation().then(
    () => ({ status: "resolved" }),
    (error) => ({ status: "rejected", error })
  );
  let timeout;
  const deadline = new Promise((resolve) => {
    timeout = setTimeout(() => resolve({ status: "timed_out" }), 250);
  });
  const outcome = await Promise.race([attempt, deadline]);
  clearTimeout(timeout);

  if (outcome.status === "timed_out") {
    const unblocker = await fs.open(
      fifo,
      fsConstants.O_RDWR | fsConstants.O_NONBLOCK
    );
    try {
      await attempt;
    } finally {
      await unblocker.close();
    }
    assert.fail(`FIFO validation blocked before rejecting ${fifo}`);
  }

  assert.equal(outcome.status, "rejected");
  assert.match(outcome.error.message, expectedError);
}

async function fixtureDirectory(prefix) {
  const directory = await mkdtemp(path.join(tmpdir(), prefix));
  temporaryRoots.push(directory);
  return directory;
}
