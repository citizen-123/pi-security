import assert from "node:assert/strict";
import { mkdtemp, mkdir, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  entryPoints: [new URL("../src/deep-scan/artifacts.ts", import.meta.url).pathname],
  format: "esm",
  platform: "node",
  write: false
});
const {
  archiveDirectory,
  createDeepScanArtifacts,
  ensureDeepScanDirectories,
  readJsonObject,
  requireRegularFile,
  writeJsonAtomic,
  writePrivateFile
} = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);

const temporaryRoots = [];

try {
  await testDeepArtifactWritesRejectSwappedDirectories();
  await testPostOpenDirectorySwapDoesNotWriteContent();
  await testArtifactReadsAndArchivingRejectSymlinks();
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

async function fixtureDirectory(prefix) {
  const directory = await mkdtemp(path.join(tmpdir(), prefix));
  temporaryRoots.push(directory);
  return directory;
}
