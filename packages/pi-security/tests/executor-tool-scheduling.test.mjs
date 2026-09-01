import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { build } from "esbuild";

const packageRoot = resolve(import.meta.dirname, "..");
const bundleRoot = await mkdtemp(join(tmpdir(), "pi-security-executor-scheduling-"));
const bundlePath = join(bundleRoot, "executor.mjs");
await build({
  bundle: true,
  format: "esm",
  loader: { ".md": "text" },
  logLevel: "silent",
  outfile: bundlePath,
  platform: "node",
  plugins: [{
    name: "native-session-stub",
    setup(plugin) {
      plugin.onResolve(
        { filter: /^(?:@earendil-works\/pi-coding-agent|native-session-stub)$/ },
        () => ({ path: "native-session-stub", namespace: "native-session-stub" }),
      );
      plugin.onLoad({ filter: /.*/, namespace: "native-session-stub" }, () => ({
        loader: "js",
        contents: `
          let customTools;
          let sessionCreationCount = 0;
          export function getAgentDir() { return "/native-agent"; }
          export class DefaultResourceLoader {
            async reload() {}
          }
          export const SessionManager = { inMemory: () => ({}) };
          export async function createAgentSession(options) {
            sessionCreationCount += 1;
            customTools = options.customTools;
            const session = {
              agent: { state: { messages: [] }, async continue() {} },
              get messages() { return this.agent.state.messages; },
              subscribe() { return () => {}; },
              async prompt() {},
              async waitForIdle() {},
              async abort() {},
              getSessionStats() {
                return { tokens: { input: 0, cacheRead: 0, cacheWrite: 0, output: 0, total: 0 } };
              },
              dispose() {},
            };
            return { session };
          }
          export function capturedCustomTools() { return customTools; }
          export function createdSessionCount() { return sessionCreationCount; }
          export function resetNativeSessionStub() {
            customTools = undefined;
            sessionCreationCount = 0;
          }
        `,
      }));
    },
  }],
  stdin: {
    contents: [
      'export { NativePiWorkerExecutor } from "./src/deep-scan/executor.ts";',
      'export { createExecutionPolicyContext } from "./src/execution-policy.ts";',
      'export { capturedCustomTools, createdSessionCount, resetNativeSessionStub } from "native-session-stub";',
    ].join("\n"),
    loader: "ts",
    resolveDir: packageRoot,
    sourcefile: "executor-tool-scheduling-test-entry.ts",
  },
  target: "node20",
});
const {
  NativePiWorkerExecutor,
  createExecutionPolicyContext,
  capturedCustomTools,
  createdSessionCount,
  resetNativeSessionStub,
} = await import(`${new URL(`file://${bundlePath}`).href}?${Date.now()}`);

test.after(async () => {
  await rm(bundleRoot, { recursive: true, force: true });
});

const scanId = "00000000-0000-4000-8000-000000000003";

async function withWorkerFixture(run) {
  const root = await mkdtemp(join(tmpdir(), "pi-security-executor-scheduling-"));
  const repository = join(root, "repository");
  const workerRoot = join(root, "worker");
  const artifactRoot = join(workerRoot, "output");
  const promptPath = join(workerRoot, "prompt.md");
  await Promise.all([
    mkdir(repository),
    mkdir(artifactRoot, { recursive: true }),
  ]);
  await writeFile(promptPath, "Review the supplied target.\n");
  const executionContext = createExecutionPolicyContext({
    profile: "security-delegating-readonly",
    target: { root: repository },
    scan: { id: scanId, artifactRoot: workerRoot },
    delegation: { budget: 1 },
  });
  const artifactWriterContext = createExecutionPolicyContext({
    profile: "security-artifact-writer",
    target: { root: repository },
    scan: { id: scanId, artifactRoot },
  });
  try {
    return await run({
      kind: "discovery",
      promptPath,
      workingDirectory: artifactRoot,
      subagents: 1,
      signal: new AbortController().signal,
      artifactContext: {
        root: artifactRoot,
        workerRoot,
        repoRoot: repository,
        scanId,
        layout: "worker",
      },
      executionContext,
      artifactWriterContext,
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("native executor stops when policy readiness is canceled", async () => {
  resetNativeSessionStub();
  await withWorkerFixture(async (request) => {
    const controller = new AbortController();
    await assert.rejects(
      new NativePiWorkerExecutor().run({
        ...request,
        signal: controller.signal,
        onPolicyReady: () => controller.abort(),
      }),
      (error) => error?.name === "AbortError",
    );
    assert.equal(createdSessionCount(), 0);
  });
});

test("native executor serializes delegated and artifact-mutating tool calls", async () => {
  resetNativeSessionStub();
  await withWorkerFixture(async (request) => {
    await new NativePiWorkerExecutor().run(request);
    const byName = new Map(capturedCustomTools().map((tool) => [tool.name, tool]));
    assert.equal(byName.get("delegate_security_task").executionMode, "sequential");
    assert.equal(byName.get("record_pi_security_scan_draft").executionMode, "sequential");
    assert.equal(byName.get("read_pi_security_source").executionMode, "parallel");
  });
});
