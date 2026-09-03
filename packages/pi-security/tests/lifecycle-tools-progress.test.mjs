import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { build } from "esbuild";

const packageRoot = new URL("..", import.meta.url).pathname;
const bundle = await build({
  bundle: true,
  plugins: [{
    name: "stub-pi-coding-agent",
    setup(build_) {
      build_.onResolve(
        { filter: /^@earendil-works\/pi-coding-agent$/ },
        () => ({ path: "pi-coding-agent", namespace: "test-stub" }),
      );
      build_.onLoad(
        { filter: /^pi-coding-agent$/, namespace: "test-stub" },
        () => ({
          contents: [
            "export const createAgentSession = () => { throw new Error('unused test stub'); };",
            "export class DefaultResourceLoader {}",
            "export const getAgentDir = () => '';",
            "export class SessionManager {}",
          ].join("\n"),
          loader: "ts",
        }),
      );
    },
  }],
  format: "esm",
  platform: "node",
  loader: { ".md": "text" },
  stdin: {
    contents: [
      'export { registerPiSecurityLifecycleTools } from "./extensions/lifecycle-tools.ts";',
      'export { issuePiLifecycleContext } from "./src/pi-permission-profile.ts";',
      'export { createDeepScanProgressReporter, deepScanProgressText, waitForJoinedDeepScanWithProgress } from "./lifecycle.ts";',
    ].join("\n"),
    loader: "ts",
    resolveDir: packageRoot
  },
  write: false
});
const lifecycleTools = await (async () => {
  const directory = await mkdtemp(join(packageRoot, ".lifecycle-tools-progress-"));
  const path = join(directory, "bundle.mjs");
  try {
    await writeFile(path, bundle.outputFiles[0].contents);
    return await import(pathToFileURL(path).href);
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
})();
const {
  createDeepScanProgressReporter,
  deepScanProgressText,
  issuePiLifecycleContext,
  registerPiSecurityLifecycleTools,
  waitForJoinedDeepScanWithProgress,
} = lifecycleTools;

test("the Deep Scan tool renders structured progress instead of a generic spinner", () => {
  const tools = new Map();
  registerPiSecurityLifecycleTools({
    on() {},
    registerTool(tool) {
      tools.set(tool.name, tool);
    }
  }, issuePiLifecycleContext({
    targetRoot: "/target",
    scanId: "scan",
    artifactRoot: "/artifacts"
  }));

  const deepScan = tools.get("start_pi_security_deep_scan");
  assert.ok(deepScan);
  assert.match(
    deepScan.renderCall().render(160).join("\n"),
    /preparing independent reviews/u
  );
  assert.match(
    deepScan.renderResult({
      content: [{ type: "text", text: "fallback" }],
      details: { statusText: "Deep Scan: 2 independent Standard reviews completed." }
    }, { isPartial: true }).render(160).join("\n"),
    /2 independent Standard reviews completed/u
  );
  const deferred = deepScan.renderResult({
    content: [{ type: "text", text: "fallback" }],
    details: {
      statusText: "Deep Scan: canonical results are saved; durable finalization is pending recovery.",
    },
  }, { isPartial: true }).render(160).join("\n");
  assert.match(deferred, /durable finalization is pending recovery/u);
  assert.doesNotMatch(deferred, /Deep Scan: Deep Scan:/u);
});

test("Deep Scan progress is scoped to one native invocation", () => {
  const statusCalls = [];
  const widgetCalls = [];
  const first = createDeepScanProgressReporter({
    deepScanProgressKey: "pi-security-deep-scan:call-a",
    setStatus(key, text) {
      statusCalls.push([key, text]);
    },
    setWidget(key, lines) {
      widgetCalls.push([key, lines]);
    },
  });
  const second = createDeepScanProgressReporter({
    deepScanProgressKey: "pi-security-deep-scan:call-b",
    setStatus(key, text) {
      statusCalls.push([key, text]);
    },
    setWidget(key, lines) {
      widgetCalls.push([key, lines]);
    },
  });

  first.report({ event: "coordinator_started", scanId: "scan-a" });
  second.report({ event: "coordinator_started", scanId: "scan-b" });
  first.clear();

  assert.deepEqual(statusCalls.at(-1), ["pi-security-deep-scan:call-a", undefined]);
  assert.deepEqual(widgetCalls.at(-1), ["pi-security-deep-scan:call-a", undefined]);
  assert.equal(
    statusCalls.some(([key, text]) =>
      key === "pi-security-deep-scan:call-b" && text === undefined
    ),
    false,
  );
});

test("joined Deep Scan calls relay persisted and deferred finalization status", async () => {
  const progressEvents = [];
  const reporter = createDeepScanProgressReporter({
    deepScanProgressKey: "pi-security-deep-scan:joined-call",
    onUpdate(update) {
      progressEvents.push(update.structuredContent.event);
    },
  });
  const running = {
    scanId: "joined-scan",
    status: "running",
    phase: "discovery",
    targetPath: "/target",
    scope: ".",
    scanDir: "/artifacts",
    config: {
      workers: 1,
      subagents: 0,
      stopAfterNoNew: 1,
      stopAfterConsecutiveErrors: 1,
      maxDiscoveryRuns: 3,
    },
    dispatchedCount: 1,
    noNewStreak: 0,
    consecutiveErrors: 0,
    persistedWorkers: [{
      id: "discovery-1",
      kind: "discovery",
      status: "succeeded",
      promptPath: "/artifacts/prompt.md",
      artifactDir: "/artifacts/worker",
      attempt: 1,
      completionSequence: 1,
      mergeState: "merged",
    }],
  };
  let waits = 0;
  const terminal = await waitForJoinedDeepScanWithProgress({
    coordinator: {
      async wait() {
        waits += 1;
        return waits === 1 ? undefined : {
          ...running,
          status: "succeeded",
          phase: "terminal",
        };
      },
    },
    readRun: async () => running,
    reporter,
    signal: undefined,
  });
  assert.equal(terminal.status, "succeeded");
  assert.deepEqual(progressEvents, ["progress_updated", "coordinator_terminal"]);

  const deferredEvents = [];
  const deferredReporter = createDeepScanProgressReporter({
    deepScanProgressKey: "pi-security-deep-scan:deferred-call",
    onUpdate(update) {
      deferredEvents.push(update.structuredContent.event);
    },
  });
  const deferred = await waitForJoinedDeepScanWithProgress({
    coordinator: { async wait() { return running; } },
    readRun: async () => {
      throw new Error("a terminal coordinator must not poll again");
    },
    reporter: deferredReporter,
    signal: undefined,
  });
  assert.equal(deferred.status, "running");
  assert.deepEqual(deferredEvents, ["coordinator_finalization_deferred"]);
  assert.equal(
    deepScanProgressText({
      event: "coordinator_finalization_deferred",
      scanId: "joined-scan",
    }),
    "Deep Scan: canonical results are saved; durable finalization is pending recovery.",
  );
});
