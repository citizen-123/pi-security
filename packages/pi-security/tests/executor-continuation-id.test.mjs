import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { build } from "esbuild";

const packageRoot = resolve(import.meta.dirname, "..");
const bundleRoot = await mkdtemp(join(packageRoot, ".pi-security-executor-module-"));
const bundlePath = join(bundleRoot, "executor.mjs");
await build({
  bundle: true,
  format: "esm",
  loader: { ".md": "text" },
  logLevel: "silent",
  outfile: bundlePath,
  platform: "node",
  stdin: {
    contents: [
      'export { NativePiWorkerExecutor } from "./src/deep-scan/executor.ts";',
      'export { snapshotWorkerExecutionPolicies } from "./src/execution-policy-continuation.ts";',
      'export { createExecutionPolicyContext } from "./src/execution-policy.ts";',
    ].join("\n"),
    loader: "ts",
    resolveDir: packageRoot,
    sourcefile: "executor-continuation-id-test-entry.ts",
  },
  external: ["@earendil-works/pi-coding-agent"],
  target: "node20",
});
const {
  NativePiWorkerExecutor,
  snapshotWorkerExecutionPolicies,
  createExecutionPolicyContext,
} = await import(
  `${new URL(`file://${bundlePath}`).href}?${Date.now()}`,
);

test.after(async () => {
  await rm(bundleRoot, { recursive: true, force: true });
});

test("native executor rejects blank continuation IDs before using worker state", async () => {
  const executor = new NativePiWorkerExecutor();
  for (const resumeContinuationId of ["", " \t\n "]) {
    await assert.rejects(
      executor.validateContinuationPolicy({ resumeContinuationId }),
      /requires a continuation ID/,
    );
    await assert.rejects(
      executor.run({ resumeContinuationId }),
      /requires a non-empty continuation ID/,
    );
  }
});

test("native executor rejects a final continuation state without a final tool result", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-security-continuation-ledger-"));
  const repository = join(root, "repository");
  const workerRoot = join(root, "worker");
  const artifactRoot = join(workerRoot, "output");
  await Promise.all([
    mkdir(repository),
    mkdir(artifactRoot, { recursive: true }),
  ]);
  const source = createExecutionPolicyContext({
    profile: "security-readonly",
    target: { root: repository },
    scan: { id: "00000000-0000-4000-8000-000000000004", artifactRoot: workerRoot },
  });
  const writer = createExecutionPolicyContext({
    profile: "security-artifact-writer",
    target: { root: repository },
    scan: { id: "00000000-0000-4000-8000-000000000004", artifactRoot },
  });
  const continuationId = "ledger-consistency-test";
  await writeFile(join(artifactRoot, "worker-continuation.json"), JSON.stringify({
    version: 3,
    id: continuationId,
    kind: "discovery",
    policy: snapshotWorkerExecutionPolicies({ source, artifactWriter: writer }),
    delegation: { version: 1, children: [] },
    messages: [],
    toolCalls: [],
    finalSubmissionAccepted: true,
  }));
  try {
    await assert.rejects(
      new NativePiWorkerExecutor().validateContinuationPolicy({
        kind: "discovery",
        subagents: 0,
        resumeContinuationId: continuationId,
        artifactContext: {
          root: artifactRoot,
          workerRoot,
          repoRoot: repository,
          scanId: "00000000-0000-4000-8000-000000000004",
          layout: "worker",
        },
        executionContext: source,
        artifactWriterContext: writer,
      }),
      /final submission state/i,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
