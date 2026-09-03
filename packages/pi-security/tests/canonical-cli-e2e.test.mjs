import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { access, chmod, copyFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";

const execFileAsync = promisify(execFile);
const packageRoot = path.resolve(import.meta.dirname, "..");
const cli = path.join(packageRoot, "dist/pi-security-cli.mjs");
const fixtureRpc = path.join(packageRoot, "tests/fixtures/fake-pi-rpc.mjs");
const SECRET = "synthetic-canonical-credential-canary";
const validOutputs = {
  "attack-path": { attackPaths: [] },
  discovery: { candidates: [] },
  reduction: { findings: [] },
  reporting: {
    coverage: { completeness: "complete", deferred: [], explicitExclusions: [], surfaces: [] },
    findings: [],
    threatModel: { summary: "Synthetic repository security boundaries.", surfaces: [] },
  },
  "threat-model": { threatModel: { summary: "Synthetic repository security boundaries.", surfaces: [] } },
  validation: { validations: [] },
};

async function setup(t, credential = false) {
  const root = await mkdtemp(path.join(tmpdir(), "pi-security-cli-e2e-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const target = path.join(root, "repository");
  const bin = path.join(root, "bin");
  const scans = path.join(root, "scans");
  const state = path.join(root, "state");
  const capture = path.join(root, "rpc-capture.jsonl");
  await Promise.all([mkdir(target), mkdir(bin), mkdir(state), mkdir(scans, { mode: 0o700 })]);
  await writeFile(path.join(target, "fixture.py"), "def fixture():\n    return 'synthetic'\n");
  const pi = path.join(bin, "pi");
  await copyFile(fixtureRpc, pi);
  await chmod(pi, 0o755);
  const config = path.join(root, "config.toml");
  await writeFile(config, [
    "[scan]",
    `target = ${JSON.stringify(target)}`,
    'workflow = "full-repository"',
    "[execution]",
    "max_parallel = 2",
    "[roles.default]",
    'provider = "fixture"',
    'model = "fixture-model"',
    'thinking = "medium"',
    "max_attempts = 1",
    ...(credential ? [`credential = { value = ${JSON.stringify(SECRET)} }`] : []),
    "",
  ].join("\n"));
  const environment = {
    ...process.env,
    FAKE_RPC_CAPTURE_FILE: capture,
    FAKE_RPC_PHASE_OUTPUTS: JSON.stringify(validOutputs),
    PATH: `${bin}${path.delimiter}${process.env.PATH ?? ""}`,
    PI_SECURITY_SCAN_ROOT: scans,
    PI_SECURITY_STATE_DIR: state,
  };
  return { capture, config, environment, root, state, target };
}

async function invoke(environment, args) {
  try {
    const result = await execFileAsync(process.execPath, [cli, ...args], {
      encoding: "utf8",
      env: environment,
      maxBuffer: 8 * 1024 * 1024,
      timeout: 60_000,
    });
    return { code: 0, stderr: result.stderr, stdout: result.stdout };
  } catch (error) {
    return { code: error.code, stderr: error.stderr ?? "", stdout: error.stdout ?? "" };
  }
}

function parsed(result) {
  return JSON.parse(result.stdout.trim().split(/\r?\n/u).at(-1));
}

test("packaged CLI completes a fake-RPC scan and excludes credential material everywhere", async (t) => {
  const fixture = await setup(t, true);
  const result = await invoke(fixture.environment, ["scan", "--config", fixture.config]);
  const completed = parsed(result);
  assert.equal(result.code, 0, `${result.stderr}\n${result.stdout}`);
  assert.equal(completed.status, "completed");
  assert.equal(completed.progress.coverageConclusion, "complete");
  assert.equal(completed.phases.every((phase) => phase.state === "completed"), true);
  await rm(fixture.config);
  const captured = await collectText(fixture.root);
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}\n${captured}`, new RegExp(SECRET, "u"));
  assert.match(await readFile(fixture.capture, "utf8"), /"credentialPresent":true/u);
});

test("packaged CLI preserves failed history and executes a linked retry", async (t) => {
  const fixture = await setup(t);
  const failedEnvironment = {
    ...fixture.environment,
    FAKE_RPC_PHASE_OUTPUTS: JSON.stringify({ ...validOutputs, discovery: { malformed: true } }),
  };
  const failedResult = await invoke(failedEnvironment, ["scan", "--config", fixture.config]);
  assert.equal(failedResult.code, 1, failedResult.stderr);
  const failed = parsed(failedResult);
  assert.equal(failed.status, "failed");
  const retriedResult = await invoke(fixture.environment, ["run", "retry", failed.id]);
  const retried = parsed(retriedResult);
  assert.equal(retriedResult.code, 0, `${retried.status}: ${retried.statusReason}`);
  assert.equal(retried.status, "completed");
  assert.equal(retried.parentRunId, failed.id);
  const inspected = parsed(await invoke(fixture.environment, ["run", "inspect", failed.id]));
  assert.equal(inspected.status, "failed");
});

test("packaged CLI reconciles a signaled executor to interrupted and resumes explicitly", async (t) => {
  const fixture = await setup(t);
  const environment = { ...fixture.environment, FAKE_RPC_SETTLE_DELAY_MS: "10000" };
  const child = spawn(process.execPath, [cli, "scan", "--config", fixture.config], {
    env: environment,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
  child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
  await waitForFile(fixture.capture);
  child.kill("SIGHUP");
  const code = await new Promise((resolve) => child.once("exit", resolve));
  assert.equal(code, 75, stderr);
  const interrupted = parsed({ stdout });
  assert.equal(interrupted.status, "interrupted");

  const resumedResult = await invoke(fixture.environment, ["run", "resume", interrupted.id]);
  assert.equal(resumedResult.code, 0, `${resumedResult.stderr}\n${resumedResult.stdout}`);
  const resumed = parsed(resumedResult);
  assert.equal(resumed.id, interrupted.id);
  assert.equal(resumed.status, "completed");
});

test("packaged CLI maps Ctrl-C cancellation to a frozen terminal run", async (t) => {
  const fixture = await setup(t);
  const environment = { ...fixture.environment, FAKE_RPC_SETTLE_DELAY_MS: "10000" };
  const child = spawn(process.execPath, [cli, "scan", "--config", fixture.config], {
    env: environment,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
  child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
  await waitForFile(fixture.capture);
  child.kill("SIGINT");
  const code = await new Promise((resolve) => child.once("exit", resolve));
  assert.equal(code, 130, stderr);
  const canceled = parsed({ stdout });
  assert.equal(canceled.status, "canceled");
  assert.equal(canceled.progress.coverageConclusion, "inconclusive");
});

async function waitForFile(file) {
  for (let index = 0; index < 200; index += 1) {
    try {
      await access(file);
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }
  throw new Error(`Timed out waiting for ${file}`);
}

async function collectText(root) {
  const values = [];
  async function walk(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const current = path.join(directory, entry.name);
      if (entry.isDirectory()) await walk(current);
      else values.push(await readFile(current).catch(() => Buffer.alloc(0)));
    }
  }
  await walk(root);
  return Buffer.concat(values.map((value) => Buffer.isBuffer(value) ? value : Buffer.from(value))).toString("utf8");
}
