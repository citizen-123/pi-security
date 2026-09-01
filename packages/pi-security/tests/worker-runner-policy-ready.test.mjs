import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { build } from "esbuild";

const packageRoot = resolve(import.meta.dirname, "..");
const bundleRoot = await mkdtemp(join(tmpdir(), "pi-security-worker-runner-module-"));
const bundlePath = join(bundleRoot, "worker-runner.mjs");
await build({
  bundle: true,
  format: "esm",
  loader: { ".md": "text" },
  logLevel: "silent",
  outfile: bundlePath,
  platform: "node",
  stdin: {
    contents: 'export { DeepScanWorkerRunner } from "./src/deep-scan/worker-runner.ts";',
    loader: "ts",
    resolveDir: packageRoot,
    sourcefile: "worker-runner-policy-ready-test-entry.ts",
  },
  target: "node20",
});
const { DeepScanWorkerRunner } = await import(
  `${new URL(`file://${bundlePath}`).href}?${Date.now()}`,
);

test.after(async () => {
  await rm(bundleRoot, { recursive: true, force: true });
});

const scanId = "00000000-0000-4000-8000-000000000002";

function completeDraft() {
  return {
    scanId,
    complete: true,
    findings: [],
    coverage: {
      completeness: "complete",
      surfaces: [{ id: "source-review", label: "Repository source", disposition: "no_issue_found" }],
      explicitExclusions: [],
      deferred: [],
    },
  };
}

test("worker runner rejects an executor that returns without policy readiness", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-security-worker-policy-ready-"));
  const targetPath = join(root, "target");
  const scanDir = join(root, "scan");
  const workersRoot = join(scanDir, "artifacts", "deep_discovery", "workers");
  await Promise.all([mkdir(targetPath), mkdir(workersRoot, { recursive: true })]);
  const updates = [];
  const store = {
    async updateWorker(update) {
      updates.push(structuredClone(update));
      return {
        ...update,
        mergeState: "none",
        ...(update.status === "succeeded" ? { completionSequence: 1 } : {}),
      };
    },
  };
  const executor = {
    async validateContinuationPolicy() {},
    async run(request) {
      await writeFile(
        join(request.artifactContext.root, "result.json"),
        `${JSON.stringify(completeDraft())}\n`,
      );
      return { finalResponse: "fixture completed without authenticating policy" };
    },
  };
  const runner = new DeepScanWorkerRunner({
    run: {
      scanId,
      status: "running",
      targetPath,
      scope: ".",
      scanDir,
      config: {
        workers: 1,
        subagents: 0,
        stopAfterNoNew: 1,
        stopAfterConsecutiveErrors: 1,
        maxDiscoveryRuns: 1,
      },
      dispatchedCount: 0,
      noNewStreak: 0,
      consecutiveErrors: 0,
    },
    store,
    executor,
    artifacts: {
      scanDir,
      deepRoot: join(scanDir, "artifacts", "deep_discovery"),
      workersRoot,
      dedupRoot: join(scanDir, "artifacts", "deep_discovery", "dedup"),
    },
    packageRoot,
    clock: { now: () => 0, sleep: async () => {} },
    random: () => 0,
    log: () => {},
    retryDelaysMs: [],
    signal: new AbortController().signal,
  });

  try {
    await assert.rejects(
      runner.runDiscoveryWorker("worker-1", "discovery-0001"),
      /returned without validating its continuation policy/,
    );
    assert.deepEqual(updates.map((update) => update.status), ["queued"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("discovery cancellation after validation is persisted", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-security-worker-cancellation-"));
  const targetPath = join(root, "target");
  const scanDir = join(root, "scan");
  const workersRoot = join(scanDir, "artifacts", "deep_discovery", "workers");
  await Promise.all([mkdir(targetPath), mkdir(workersRoot, { recursive: true })]);
  const updates = [];
  const store = {
    async updateWorker(update) {
      updates.push(structuredClone(update));
      return { ...update, mergeState: "none" };
    },
  };
  let abortChecks = 0;
  const signal = {
    get aborted() {
      abortChecks += 1;
      return abortChecks >= 5;
    },
  };
  const executor = {
    async validateContinuationPolicy() {},
    async run(request) {
      await request.onPolicyReady();
      await writeFile(
        join(request.artifactContext.root, "result.json"),
        `${JSON.stringify(completeDraft())}\n`,
      );
      return { finalResponse: "fixture completed before cancellation" };
    },
  };
  const runner = new DeepScanWorkerRunner({
    run: {
      scanId,
      status: "running",
      targetPath,
      scope: ".",
      scanDir,
      config: {
        workers: 1,
        subagents: 0,
        stopAfterNoNew: 1,
        stopAfterConsecutiveErrors: 1,
        maxDiscoveryRuns: 1,
      },
      dispatchedCount: 0,
      noNewStreak: 0,
      consecutiveErrors: 0,
    },
    store,
    executor,
    artifacts: {
      scanDir,
      deepRoot: join(scanDir, "artifacts", "deep_discovery"),
      workersRoot,
      dedupRoot: join(scanDir, "artifacts", "deep_discovery", "dedup"),
    },
    packageRoot,
    clock: { now: () => 0, sleep: async () => {} },
    random: () => 0,
    log: () => {},
    retryDelaysMs: [],
    signal,
  });

  try {
    const outcome = await runner.runDiscoveryWorker("worker-2", "discovery-0002");
    assert.deepEqual(outcome, {
      type: "discovery",
      status: "canceled",
      workerId: "worker-2",
    });
    assert.deepEqual(updates.map((update) => update.status), [
      "queued",
      "running",
      "canceled",
    ]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("worker runner rejects duplicate policy readiness confirmations", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-security-worker-policy-duplicate-"));
  const targetPath = join(root, "target");
  const artifactDir = join(root, "worker", "output");
  await Promise.all([mkdir(targetPath), mkdir(artifactDir, { recursive: true })]);
  const updates = [];
  const store = {
    async updateWorker(update) {
      updates.push(structuredClone(update));
      return { ...update, mergeState: "none" };
    },
  };
  const runner = new DeepScanWorkerRunner({
    run: {
      scanId,
      status: "running",
      targetPath,
      scope: ".",
      scanDir: root,
      config: {
        workers: 1,
        subagents: 0,
        stopAfterNoNew: 1,
        stopAfterConsecutiveErrors: 1,
        maxDiscoveryRuns: 1,
      },
      dispatchedCount: 0,
      noNewStreak: 0,
      consecutiveErrors: 0,
    },
    store,
    executor: {
      async validateContinuationPolicy() {},
      async run(request) {
        await request.onPolicyReady();
        await request.onPolicyReady();
        return { finalResponse: "unreachable" };
      },
    },
    artifacts: {
      scanDir: root,
      deepRoot: root,
      workersRoot: root,
      dedupRoot: root,
    },
    packageRoot,
    clock: { now: () => 0, sleep: async () => {} },
    random: () => 0,
    log: () => {},
    retryDelaysMs: [],
    signal: new AbortController().signal,
  });

  try {
    const outcome = await runner.runWorkerWithRetries({
      workerId: "worker-3",
      kind: "discovery",
      promptPath: join(root, "worker", "prompt.md"),
      promptRoot: join(root, "worker", "prompts"),
      artifactDir,
      artifactContext: {
        root: artifactDir,
        workerRoot: join(root, "worker"),
        repoRoot: targetPath,
        scanId,
        layout: "worker",
      },
      subagents: 0,
      validate: async () => {},
      beforeRetry: async () => {},
    });
    assert.equal(outcome.status, "failed");
    assert.match(outcome.error.message, /more than once/);
    assert.deepEqual(updates.map((update) => update.status), ["running", "canceled"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
