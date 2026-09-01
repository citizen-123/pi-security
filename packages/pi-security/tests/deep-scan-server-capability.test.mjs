import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { access, chmod, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { build } from "esbuild";

import { promisify } from "node:util";
const packageRoot = resolve(import.meta.dirname, "..");
const execFileAsync = promisify(execFile);
const terminalBundle = await build({
  bundle: true,
  format: "esm",
  loader: { ".md": "text" },
  platform: "node",
  write: false,
  stdin: {
    contents: 'export { deepScanTerminalResult } from "./server.ts";',
    loader: "ts",
    resolveDir: packageRoot,
  },
});
const { deepScanTerminalResult } = await import(
  `data:text/javascript;base64,${Buffer.from(terminalBundle.outputFiles[0].contents).toString("base64")}`,
);

async function runWorkbench(state, args) {
  const { stdout } = await execFileAsync(
    process.env.PYTHON ?? "python3",
    [resolve(packageRoot, "scripts", "workbench_db.py"), ...args],
    {
      encoding: "utf8",
      env: { ...process.env, PI_SECURITY_STATE_DIR: state },
    },
  );
  return JSON.parse(stdout);
}
async function downgradeToPrePolicyFailureSchema(state) {
  const databasePath = join(state, "workbench.sqlite3");
  const source = [
    "import sqlite3, sys",
    "connection = sqlite3.connect(sys.argv[1])",
    "connection.execute('PRAGMA journal_mode = DELETE')",
    "try:",
    "    for column in ('policy_failure_code', 'policy_failure_category', 'policy_failure_reason', 'policy_failure_message'):",
    "        connection.execute(f'ALTER TABLE deep_scan_runs DROP COLUMN {column}')",
    "    connection.execute('DELETE FROM schema_migrations WHERE version = 40')",
    "    connection.commit()",
    "finally:",
    "    connection.close()",
  ].join("\n");
  await execFileAsync(process.env.PYTHON ?? "python3", ["-c", source, databasePath], {
    encoding: "utf8",
  });
}


async function createDeepWorkspace(state, target, threadId, mode = "deep") {
  const workspaceId = randomUUID();
  await runWorkbench(state, [
    "create-workspace",
    "--workspace-id",
    workspaceId,
    ...(threadId ? ["--thread-id", threadId] : []),
    "--target-path",
    target,
    "--target-title",
    "Capability fixture",
    "--target-summary",
    "Capability fixture target.",
  ]);
  const saved = await runWorkbench(state, [
    "save-workspace",
    "--workspace-id",
    workspaceId,
    "--target-path",
    target,
    "--scope",
    ".",
    "--mode",
    mode,
  ]);
  return { workspaceId, saved };
}
async function waitForPath(path) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (await access(path).then(() => true, () => false)) return;
    await delay(10);
  }
  throw new Error(`Timed out waiting for ${path}`);
}


async function rejectUnsupportedDeepScan(clientCapabilities, label) {
  const root = await mkdtemp(join(tmpdir(), `pi-security-${label}-`));
  const target = join(root, "repository");
  const state = join(root, "state");
  const scanRoot = join(root, "scans");
  await mkdir(target);
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve(packageRoot, "dist/server.cjs")],
    env: {
      ...process.env,
      PI_SECURITY_SCAN_ROOT: scanRoot,
      PI_SECURITY_STATE_DIR: state,
    },
  });
  const client = new Client(
    { name: `pi-security-${label}-test`, version: "1.0.0" },
    { capabilities: clientCapabilities },
  );
  try {
    await client.connect(transport);
    const response = await client.callTool({
      name: "start_pi_security_deep_scan",
      arguments: { targetPath: target, scope: "." },
      _meta: { sessionId: `${label}-session` },
    });
    assert.equal(response.isError, true);
    const message = response.content
      .filter((entry) => entry.type === "text")
      .map((entry) => entry.text)
      .join("\n");
    assert.match(message, /requires an MCP 2025-11-25 client that advertises sampling\.tools/u);
    assert.match(message, /Basic sampling without tool use cannot inspect/u);
    assert.equal(
      response.structuredContent.error.code,
      "PI_SECURITY_ENFORCEMENT_UNSUPPORTED",
    );
    assert.deepEqual(response.structuredContent.enforcementCapabilities, {
      schemaVersion: 1,
      kind: "availability",
      supported: false,
      mechanisms: [
        "pi.fixed-profile-tool-dispatch",
        "artifact.canonical-root-binding",
        "workbench.fixed-bundled-command",
        "continuation.exact-policy-reissue",
      ],
      unsupportedReason: [
        "Deep Scan requires an MCP 2025-11-25 client that advertises sampling.tools.",
        "Basic sampling without tool use cannot inspect the coordinator-bound repository.",
        "Use a Standard scan or reconnect with sampling tool support.",
      ].join(" "),
    });
    await assert.rejects(access(join(state, "workbench.sqlite3")), { code: "ENOENT" });
    await assert.rejects(access(scanRoot));
  } finally {
    await client.close().catch(() => {});
    await rm(root, { recursive: true, force: true });
  }
}

test("Deep Scan start rejects a client with no sampling capability before creating a run", async () => {
  await rejectUnsupportedDeepScan({}, "no-sampling");
});

test("Deep Scan start rejects basic sampling without tools before creating a run", async () => {
  await rejectUnsupportedDeepScan({ sampling: {} }, "basic-sampling");
});
test("app scan preflight returns typed not-found without creating state", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-security-missing-state-preflight-"));
  const state = join(root, "missing-parent", "state");
  const scanRoot = join(root, "scans");
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve(packageRoot, "dist/server.cjs")],
    env: {
      ...process.env,
      PI_SECURITY_SCAN_ROOT: scanRoot,
      PI_SECURITY_STATE_DIR: state,
    },
  });
  const client = new Client(
    { name: "pi-security-missing-state-preflight-test", version: "1.0.0" },
    { capabilities: { sampling: { tools: {} } } },
  );
  try {
    await client.connect(transport);
    const response = await client.callTool({
      name: "start_pi_security_scan",
      arguments: { sessionId: randomUUID() },
    });
    assert.equal(response.isError, true);
    assert.deepEqual(response.structuredContent.error, {
      schemaVersion: 1,
      code: "PI_SECURITY_WORKBENCH_STATE_NOT_FOUND",
      category: "workbench_state_not_found",
      retryable: false,
      message: "Pi Security workbench state was not found.",
    });
    await assert.rejects(access(state), { code: "ENOENT" });
    await assert.rejects(access(join(root, "missing-parent")), { code: "ENOENT" });
    await assert.rejects(access(scanRoot), { code: "ENOENT" });
  } finally {
    await client.close().catch(() => {});
    await rm(root, { recursive: true, force: true });
  }
});


test("stale standard snapshot rejects Deep change before creating default root", {
  skip: process.platform === "win32",
}, async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-security-stale-app-preflight-"));
  const target = join(root, "repository");
  const state = join(root, "state");
  const serverTmp = join(root, "server-tmp");
  const wrapperPath = join(root, "gated-python.cjs");
  const preflightMarker = join(root, "preflight-complete");
  const startMarker = join(root, "start-invoked");
  const releaseMarker = join(root, "release-start");
  await Promise.all([mkdir(target), mkdir(serverTmp)]);
  const { workspaceId } = await createDeepWorkspace(
    state,
    target,
    undefined,
    "standard",
  );
  await writeFile(wrapperPath, `#!/usr/bin/env node
const fs = require("node:fs");
const { spawn } = require("node:child_process");
const args = process.argv.slice(2);
const command = args[1];
const sleep = (milliseconds) => new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
(async () => {
  if (command === "start-scan") {
    fs.writeFileSync(process.env.PI_SECURITY_TEST_START_MARKER, "");
    while (!fs.existsSync(process.env.PI_SECURITY_TEST_RELEASE_MARKER)) await sleep(10);
  }
  const child = spawn(process.env.PI_SECURITY_REAL_PYTHON, args, {
    env: process.env,
    stdio: "inherit",
  });
  child.on("exit", (code) => {
    if (command === "get-workspace" && code === 0) {
      fs.writeFileSync(process.env.PI_SECURITY_TEST_PREFLIGHT_MARKER, "");
    }
    process.exit(code ?? 1);
  });
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
`);
  await chmod(wrapperPath, 0o700);
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve(packageRoot, "dist/server.cjs")],
    env: {
      ...process.env,
      PI_SECURITY_PYTHON_COMMAND: wrapperPath,
      PI_SECURITY_REAL_PYTHON: process.env.PYTHON ?? "python3",
      PI_SECURITY_STATE_DIR: state,
      PI_SECURITY_SCAN_ROOT: "",
      PI_SECURITY_TEST_PREFLIGHT_MARKER: preflightMarker,
      PI_SECURITY_TEST_START_MARKER: startMarker,
      PI_SECURITY_TEST_RELEASE_MARKER: releaseMarker,
      TMPDIR: serverTmp,
      TMP: serverTmp,
      TEMP: serverTmp,
    },
  });
  const client = new Client(
    { name: "pi-security-stale-app-preflight-test", version: "1.0.0" },
    { capabilities: { sampling: { tools: {} } } },
  );
  try {
    await client.connect(transport);
    const responsePromise = client.callTool({
      name: "start_pi_security_scan",
      arguments: { sessionId: workspaceId },
    });
    await waitForPath(preflightMarker);
    await runWorkbench(state, [
      "save-workspace",
      "--workspace-id",
      workspaceId,
      "--target-path",
      target,
      "--scope",
      ".",
      "--mode",
      "deep",
    ]);
    await waitForPath(startMarker);
    assert.deepEqual(await readdir(serverTmp), []);
    await writeFile(releaseMarker, "");

    const response = await responsePromise;
    assert.equal(response.isError, true);
    assert.deepEqual(response.structuredContent.error, {
      schemaVersion: 1,
      code: "PI_SECURITY_SETUP_CHANGED",
      category: "setup_changed",
      retryable: true,
      message: "Pi Security setup changed after enforcement preflight. Retry from the current setup.",
    });
    assert.deepEqual(await readdir(serverTmp), []);
    const persisted = await runWorkbench(state, [
      "get-workspace",
      "--workspace-id",
      workspaceId,
    ]);
    assert.equal(Object.hasOwn(persisted, "results"), false);
  } finally {
    await writeFile(releaseMarker, "").catch(() => {});
    await client.close().catch(() => {});
    await rm(root, { recursive: true, force: true });
  }
});


test("headless Deep Scan probes the artifact parent before root or workbench mutation", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-security-headless-preflight-"));
  const target = join(root, "repository");
  const state = join(root, "state");
  const blockedParent = join(root, "blocked-artifact-parent");
  const scanRoot = join(blockedParent, "scans");
  await mkdir(target);
  await writeFile(blockedParent, "must remain a regular file\n");
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve(packageRoot, "dist/server.cjs")],
    env: {
      ...process.env,
      PI_SECURITY_SCAN_ROOT: scanRoot,
      PI_SECURITY_STATE_DIR: state,
    },
  });
  const client = new Client(
    { name: "pi-security-headless-preflight-test", version: "1.0.0" },
    { capabilities: { sampling: { tools: {} } } },
  );
  try {
    await client.connect(transport);
    const response = await client.callTool({
      name: "start_pi_security_deep_scan",
      arguments: { targetPath: target, scope: "." },
      _meta: { sessionId: "headless-preflight-session" },
    });
    assert.equal(response.isError, true);
    assert.equal(
      response.structuredContent.error.code,
      "PI_SECURITY_ENFORCEMENT_UNSUPPORTED",
    );
    assert.match(
      response.structuredContent.enforcementCapabilities.unsupportedReason,
      /canonical scan-bound artifact roots/u,
    );
    assert.equal(await readFile(blockedParent, "utf8"), "must remain a regular file\n");
    await assert.rejects(access(scanRoot));
    await assert.rejects(access(join(state, "workbench.sqlite3")), { code: "ENOENT" });
  } finally {
    await client.close().catch(() => {});
    await rm(root, { recursive: true, force: true });
  }
});


test("Standard app start rejects unsafe root without filesystem or database writes", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-security-standard-root-preflight-"));
  const target = join(root, "repository");
  const state = join(root, "state");
  const blockedParent = join(root, "blocked-artifact-parent");
  const scanRoot = join(blockedParent, "scans");
  await mkdir(target);
  await writeFile(blockedParent, "must remain a regular file\n");
  const { workspaceId } = await createDeepWorkspace(
    state,
    target,
    undefined,
    "standard",
  );
  const databasePath = join(state, "workbench.sqlite3");
  const databaseBefore = await readFile(databasePath);
  const stateEntriesBefore = (await readdir(state)).sort();
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve(packageRoot, "dist/server.cjs")],
    env: {
      ...process.env,
      PI_SECURITY_SCAN_ROOT: scanRoot,
      PI_SECURITY_STATE_DIR: state,
    },
  });
  const client = new Client(
    { name: "pi-security-standard-root-preflight-test", version: "1.0.0" },
    { capabilities: {} },
  );
  try {
    await client.connect(transport);
    const response = await client.callTool({
      name: "start_pi_security_scan",
      arguments: { sessionId: workspaceId },
    });
    assert.equal(response.isError, true);
    assert.equal(
      response.structuredContent.error.code,
      "PI_SECURITY_ENFORCEMENT_UNSUPPORTED",
    );
    assert.match(
      response.structuredContent.enforcementCapabilities.unsupportedReason,
      /canonical scan-bound artifact roots/u,
    );
    assert.equal(await readFile(blockedParent, "utf8"), "must remain a regular file\n");
    await assert.rejects(access(scanRoot));
    assert.deepEqual(await readFile(databasePath), databaseBefore);
    assert.deepEqual((await readdir(state)).sort(), stateEntriesBefore);
  } finally {
    await client.close().catch(() => {});
    await rm(root, { recursive: true, force: true });
  }
});


test("app Deep Scan rejects unsupported enforcement without mutating pre-v40 state", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-security-app-preflight-"));
  const target = join(root, "repository");
  const state = join(root, "state");
  const blockedParent = join(root, "blocked-artifact-parent");
  const scanRoot = join(blockedParent, "scans");
  await mkdir(target);
  await writeFile(blockedParent, "must remain a regular file\n");
  const { workspaceId, saved } = await createDeepWorkspace(state, target);
  await downgradeToPrePolicyFailureSchema(state);
  const databasePath = join(state, "workbench.sqlite3");
  const databaseBefore = await readFile(databasePath);
  const stateEntriesBefore = (await readdir(state)).sort();
  assert.deepEqual(
    stateEntriesBefore.filter((entry) => /-wal$|-shm$|-journal$/u.test(entry)),
    [],
  );
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve(packageRoot, "dist/server.cjs")],
    env: {
      ...process.env,
      PI_SECURITY_SCAN_ROOT: scanRoot,
      PI_SECURITY_STATE_DIR: state,
    },
  });
  const client = new Client(
    { name: "pi-security-app-preflight-test", version: "1.0.0" },
    { capabilities: { sampling: { tools: {} } } },
  );
  try {
    await client.connect(transport);
    const response = await client.callTool({
      name: "start_pi_security_scan",
      arguments: { sessionId: workspaceId },
    });
    assert.equal(response.isError, true);
    assert.equal(
      response.structuredContent.error.code,
      "PI_SECURITY_ENFORCEMENT_UNSUPPORTED",
    );
    assert.match(
      response.structuredContent.enforcementCapabilities.unsupportedReason,
      /canonical scan-bound artifact roots/u,
    );
    assert.equal(await readFile(blockedParent, "utf8"), "must remain a regular file\n");
    await assert.rejects(access(scanRoot));
    assert.deepEqual(await readFile(databasePath), databaseBefore);
    assert.deepEqual((await readdir(state)).sort(), stateEntriesBefore);
    const persisted = await runWorkbench(state, [
      "get-workspace",
      "--workspace-id",
      workspaceId,
    ]);
    assert.equal(Object.hasOwn(persisted, "results"), false);
    assert.equal(persisted.updatedAt, saved.updatedAt);
  } finally {
    await client.close().catch(() => {});
    await rm(root, { recursive: true, force: true });
  }
});

test("app Deep Scan probes its persisted target before creating the scan root", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-security-app-target-preflight-"));
  const target = join(root, "repository");
  const state = join(root, "state");
  const scanRoot = join(root, "scans");
  await mkdir(target);
  const { workspaceId, saved } = await createDeepWorkspace(state, target);
  await rm(target, { recursive: true, force: true });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve(packageRoot, "dist/server.cjs")],
    env: {
      ...process.env,
      PI_SECURITY_SCAN_ROOT: scanRoot,
      PI_SECURITY_STATE_DIR: state,
    },
  });
  const client = new Client(
    { name: "pi-security-app-target-preflight-test", version: "1.0.0" },
    { capabilities: { sampling: { tools: {} } } },
  );
  try {
    await client.connect(transport);
    const response = await client.callTool({
      name: "start_pi_security_scan",
      arguments: { sessionId: workspaceId },
    });
    assert.equal(response.isError, true);
    await assert.rejects(access(scanRoot), { code: "ENOENT" });
    const persisted = await runWorkbench(state, [
      "get-workspace",
      "--workspace-id",
      workspaceId,
    ]);
    assert.equal(Object.hasOwn(persisted, "results"), false);
    assert.equal(persisted.updatedAt, saved.updatedAt);
  } finally {
    await client.close().catch(() => {});
    await rm(root, { recursive: true, force: true });
  }
});

test("Deep Scan rejoin rejects a persisted artifact root outside configured authority without mutation", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-security-rejoin-authority-"));
  const target = join(root, "repository");
  const state = join(root, "state");
  const originalScanRoot = join(root, "original-scans");
  const configuredScanRoot = join(root, "configured-scans");
  const threadId = "rejoin-authority-thread";
  await Promise.all([mkdir(target), mkdir(configuredScanRoot)]);
  const { workspaceId } = await createDeepWorkspace(state, target, threadId);
  const started = await runWorkbench(state, [
    "start-scan",
    "--workspace-id",
    workspaceId,
    "--scan-root",
    originalScanRoot,
  ]);
  const scanId = started.results.scanId;
  const claimToken = randomUUID();
  await runWorkbench(state, [
    "claim-handoff-delivery",
    "--scan-id",
    scanId,
    "--claim-token",
    claimToken,
  ]);
  const databasePath = join(state, "workbench.sqlite3");
  const databaseBefore = await readFile(databasePath);
  assert.deepEqual(await readdir(configuredScanRoot), []);

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve(packageRoot, "dist/server.cjs")],
    env: {
      ...process.env,
      PI_SECURITY_SCAN_ROOT: configuredScanRoot,
      PI_SECURITY_STATE_DIR: state,
    },
  });
  const client = new Client(
    { name: "pi-security-rejoin-authority-test", version: "1.0.0" },
    { capabilities: { sampling: { tools: {} } } },
  );
  try {
    await client.connect(transport);
    const response = await client.callTool({
      name: "start_pi_security_deep_scan",
      arguments: { scanId, handoffClaimToken: claimToken },
      _meta: { sessionId: threadId },
    });
    assert.equal(response.isError, true);
    assert.equal(
      response.structuredContent.error.code,
      "PI_SECURITY_POLICY_RECOVERY_REJECTED",
    );
    assert.equal(
      response.structuredContent.error.category,
      "policy_recovery_rejected",
    );
    assert.equal((await readFile(databasePath)).equals(databaseBefore), true);
    assert.deepEqual(await readdir(configuredScanRoot), []);
  } finally {
    await client.close().catch(() => {});
    await rm(root, { recursive: true, force: true });
  }
});

test("Deep Scan terminal responses retain the compatible scanId shape", () => {
  const base = {
    scanId: "00000000-0000-4000-8000-000000000001",
    targetPath: "/fixture/target",
    scope: ".",
    scanDir: "/fixture/scans/run",
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
  };
  for (const run of [
    { ...base, status: "canceled", error: "fixture canceled failure" },
    { ...base, status: "canceled" },
    { ...base, status: "failed", error: "fixture failure" },
    { ...base, status: "interrupted", error: "fixture interruption" },
  ]) {
    const response = deepScanTerminalResult(run);
    assert.equal(response.structuredContent.scanId, base.scanId);
    assert.equal(response.structuredContent.status, run.status);
  }
});
