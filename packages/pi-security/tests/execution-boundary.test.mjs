import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { open, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  stdin: {
    contents: [
      'export * from "./src/execution-boundary.ts";',
      'export { createExecutionPolicyContext } from "./src/execution-policy.ts";',
    ].join("\n"),
    resolveDir: new URL("..", import.meta.url).pathname,
  },
  format: "esm",
  platform: "node",
  write: false,
});
const boundary = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`,
);

test("repository-relative scope rejects Windows path aliases on every host", () => {
  for (const unsafePath of [
    "src/config.ts:private",
    "src/NUL",
    "src/result.json.",
    "src/result.json ",
    "src/COM¹",
    "src/LPT².txt",
    "./COM³",
    "./.",
    "./../outside.ts",
  ]) {
    assert.throws(
      () => boundary.validateRepositoryRelativeScope(unsafePath),
      /unsafe|relative to the bound repository/u,
    );
  }
  assert.equal(
    boundary.validateRepositoryRelativeScope("src/config.ts"),
    "src/config.ts",
  );
  assert.equal(boundary.validateRepositoryRelativeScope("."), ".");
  assert.equal(
    boundary.validateRepositoryRelativeScope("./src/config.ts"),
    "src/config.ts",
  );
});

test("target path opening rejects FIFOs without waiting for a writer", async (t) => {
  if (process.platform === "win32") {
    t.skip("named-pipe behavior is POSIX-specific");
    return;
  }

  const root = await mkdtemp(path.join(tmpdir(), "pi-security-boundary-fifo-"));
  let timer;
  let writer;
  try {
    const targetRoot = path.join(root, "target");
    const artifactRoot = path.join(root, "artifacts");
    await Promise.all([mkdir(targetRoot), mkdir(artifactRoot)]);
    const fifo = path.join(targetRoot, "blocked.pipe");
    await promisify(execFile)("mkfifo", [fifo]);
    const context = boundary.createExecutionPolicyContext({
      profile: "security-readonly",
      target: { root: targetRoot },
      scan: { id: "boundary-fifo-scan", artifactRoot },
    });

    timer = setTimeout(() => {
      writer = open(fifo, "w").then((handle) => handle.close());
    }, 1000);
    const started = Date.now();
    await assert.rejects(
      boundary.openExecutionTargetPath(context, "blocked.pipe", {
        capability: "target.read",
        expected: "file",
      }),
      /not a regular file/u,
    );
    assert.ok(Date.now() - started < 500);
  } finally {
    clearTimeout(timer);
    if (writer) await writer;
    await rm(root, { recursive: true, force: true });
  }
});
