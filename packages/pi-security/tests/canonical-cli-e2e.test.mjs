import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { access, chmod, copyFile, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
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
    'provider = "openai"',
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
    PI_HOME: path.join(root, "pi-home"),
  };
  return { capture, config, environment, root, scans, state, target };
}

async function invoke(environment, args) {
  await configureRpc(environment);
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
  return JSON.parse(result.stdout.trim());
}

test("packaged CLI admits schema-only native output and redacts decoded credential material", async (t) => {
  const fixture = await setup(t, true);
  fixture.environment.FAKE_RPC_ECHO_CREDENTIAL = "escaped";
  const result = await invoke(fixture.environment, ["scan", "--config", fixture.config]);
  const completed = parsed(result);
  assert.equal(result.code, 0, `${result.stderr}\n${result.stdout}`);
  assert.equal(completed.status, "completed");
  assert.equal(completed.progress.coverageConclusion, "complete");
  assert.equal(completed.phases.every((phase) => phase.state === "completed"), true);
  assert.equal(completed.phases.find((phase) => phase.id === "threat-model").output.threatModel.summary, "[REDACTED]");
  const sealed = await invokeWorkbench(fixture, ["get-scan", "--scan-id", completed.scanId]);
  assert.equal(sealed.scan.progress.status, "complete");
  await rm(fixture.config);
  const captured = await collectText(fixture.root);
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}\n${captured}`, new RegExp(SECRET, "u"));
  assert.match(await readFile(fixture.capture, "utf8"), /"credentialPresent":true/u);
});

test("packaged CLI publishes a finding using the canonical identity supplied to later phases", async (t) => {
  const fixture = await setup(t);
  await writeFile(path.join(fixture.target, "fixture.py"),
    'def lookup(connection, name):\n    return connection.execute("SELECT email FROM accounts WHERE name = \'" + name + "\'").fetchall()\n');
  const candidateId = "$canonicalCandidateId";
  const evidence = "The caller-controlled name is concatenated into the SQLite query in fixture.py:2.";
  const candidate = {
    summary: "Caller-controlled SQL in account lookup.",
    cwe_ids: ["CWE-89"],
    locations: [{ path: "fixture.py", start_line: 2, role: "sink" }],
    evidence,
  };
  fixture.environment.FAKE_RPC_BIND_CANONICAL_ID = "1";
  fixture.environment.FAKE_RPC_PHASE_OUTPUTS = JSON.stringify({
    ...validOutputs,
    discovery: { candidates: [candidate] },
    reduction: { findings: [{ candidate_id: candidateId }] },
    validation: { validations: [{
      candidateId,
      validation: {
        disposition: "reportable",
        method: "Static source-to-sink trace.",
        confidence: "high",
        confidence_rationale: "The supplied name is inserted directly into SQL.",
        rubric: "Untrusted input crosses a SQL query boundary.",
        evidence,
        counterevidence_or_proof_gap: "The query does not use parameter binding.",
        remaining_uncertainty: "",
      },
    }] },
    "attack-path": { attackPaths: [{
      candidateId,
      attackPath: {
        decision: "reportable",
        dataflow: evidence,
        reachability: "The lookup function accepts the caller-controlled name.",
        counterevidence: "No parameter binding is present.",
        impact: "high",
        likelihood: "medium",
        severity: "high",
        severity_rationale: "Query manipulation can disclose account records.",
        change_conditions: "Parameter binding would remove the issue.",
      },
    }] },
    reporting: {
      ...validOutputs.reporting,
      coverage: {
        completeness: "complete",
        deferred: [],
        explicitExclusions: [],
        surfaces: [{ label: "Account lookup", disposition: "reported", notes: evidence }],
      },
      findings: [{
        ruleId: "sql-injection.account-lookup",
        title: "SQL injection in account lookup",
        summary: candidate.summary,
        severity: { level: "high" },
        confidence: { level: "high", rationale: evidence },
        taxonomy: { category: "sql-injection", cwe: ["CWE-89"] },
        locations: [{ path: "fixture.py", startLine: 2 }],
        remediation: "Bind the name as a query parameter.",
        provenance: { source: "local_package", candidateId },
      }],
    },
  });
  const result = await invoke(fixture.environment, ["scan", "--config", fixture.config]);
  const completed = parsed(result);
  const failures = result.code === 0 ? [] : (await invokeWorkbench(fixture, [
    "runtime-list-events", "--run-id", completed.id,
  ])).events.filter((event) => event.kind === "phase.failed");
  assert.equal(result.code, 0, `${result.stderr}\n${JSON.stringify(failures)}`);
  assert.equal(completed.status, "completed");
  const persisted = await invokeWorkbench(fixture, ["get-scan", "--scan-id", completed.scanId]);
  assert.equal(persisted.scan.progress.status, "complete");
  const scanDir = persisted.scan.scanDir;
  const ledger = (await readFile(path.join(scanDir, "artifacts/02_discovery/candidate_ledger.jsonl"), "utf8"))
    .trim().split("\n").map(JSON.parse);
  assert.equal(ledger.length, 1);
  assert.match(ledger[0].candidate_id, /^candidate-[0-9a-f]+$/u);
  assert.equal(ledger[0].validation.disposition, "reportable");
  assert.equal(ledger[0].attack_path.decision, "reportable");
  const published = JSON.parse(await readFile(path.join(scanDir, "findings.json"), "utf8"));
  assert.equal(published.findings.length, 1);
  assert.equal(published.findings[0].provenance.candidateId, ledger[0].candidate_id);
  const sarif = JSON.parse(await readFile(path.join(scanDir, "exports/results.sarif"), "utf8"));
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, "fixture.py");
});

test("packaged CLI preserves failed history and executes a linked retry", async (t) => {
  const fixture = await setup(t);
  await writeFile(fixture.config, (await readFile(fixture.config, "utf8"))
    + '\n[roles.unused]\ncredential = { value = "synthetic-unused-role-key" }\n');
  const failedEnvironment = {
    ...fixture.environment,
    FAKE_RPC_PHASE_OUTPUTS: JSON.stringify({ ...validOutputs, discovery: { malformed: true } }),
  };
  const failedResult = await invoke(failedEnvironment, ["scan", "--config", fixture.config]);
  assert.equal(failedResult.code, 1, failedResult.stderr);
  const failed = parsed(failedResult);
  assert.equal(failed.status, "failed");
  const events = await invokeWorkbench(fixture, ["runtime-list-events", "--run-id", failed.id]);
  assert.equal(events.events.some((event) => event.phaseId === "discovery" && event.kind === "agent.attempt_failed"), true);
  assert.equal(events.events.some((event) => event.phaseId === "discovery" && event.kind === "agent.attempt_completed"), false);
  const artifactScan = await invokeWorkbench(fixture, ["get-scan", "--scan-id", failed.scanId]);
  assert.equal(artifactScan.scan.progress.status, "failed");
  const firstSession = JSON.parse((await readFile(fixture.capture, "utf8")).trim().split(/\r?\n/u)[0]);
  const failedArtifactRoot = JSON.parse(firstSession.phaseInput).artifactRoot;
  const failedArtifacts = await collectText(failedArtifactRoot);
  const retriedResult = await invoke(fixture.environment, ["run", "retry", failed.id]);
  const retried = parsed(retriedResult);
  assert.equal(retriedResult.code, 0, `${retried.status}: ${retried.statusReason}`);
  assert.equal(retried.status, "completed");
  assert.equal(retried.parentRunId, failed.id);
  assert.equal(typeof retried.scanId, "string");
  assert.notEqual(retried.scanId, failed.scanId);
  assert.equal(await collectText(failedArtifactRoot), failedArtifacts);
  const inspected = parsed(await invoke(fixture.environment, ["run", "inspect", failed.id]));
  assert.equal(inspected.status, "failed");
  assert.equal(inspected.scanId, failed.scanId);
});

test("packaged CLI reconciles a signaled executor to interrupted and resumes explicitly", async (t) => {
  const fixture = await setup(t);
  await writeFile(fixture.config, (await readFile(fixture.config, "utf8")) + "\n[deep_scan]\nworkers = 1\n");
  const result = await signalRun(t, fixture, ["scan", "--config", fixture.config], "SIGHUP");
  assert.equal(result.code, 75, result.stderr);
  const interrupted = parsed(result);
  assert.equal(interrupted.status, "interrupted");

  const resumedResult = await invoke(fixture.environment, ["run", "resume", interrupted.id]);
  assert.equal(resumedResult.code, 0, `${resumedResult.stderr}\n${resumedResult.stdout}`);
  const resumed = parsed(resumedResult);
  assert.equal(resumed.id, interrupted.id);
  assert.equal(resumed.status, "completed");
});

test("packaged CLI maps Ctrl-C cancellation to a frozen terminal run", async (t) => {
  const fixture = await setup(t);
  const result = await signalRun(t, fixture, ["scan", "--config", fixture.config], "SIGINT");
  assert.equal(result.code, 130, result.stderr);
  const canceled = parsed(result);
  assert.equal(canceled.status, "canceled");
  assert.equal(canceled.progress.coverageConclusion, "inconclusive");
});

test("transcript retrieval failure settles the run instead of leaking a live Pi session", async (t) => {
  const fixture = await setup(t);
  const result = await invoke({ ...fixture.environment, FAKE_RPC_FAIL_TRANSCRIPT: "1" }, ["scan", "--config", fixture.config]);
  assert.equal(result.code, 1, `${result.stderr}\n${result.stdout}`);
  assert.equal(parsed(result).status, "failed");
});

test("assistant provider errors cannot admit an otherwise valid phase result", async (t) => {
  const fixture = await setup(t);
  const result = await invoke({ ...fixture.environment, FAKE_RPC_ASSISTANT_ERROR: "1" }, ["scan", "--config", fixture.config]);
  assert.equal(result.code, 1, `${result.stderr}\n${result.stdout}`);
  const failed = parsed(result);
  assert.equal(failed.phases.find((phase) => phase.id === "threat-model").state, "failed");
});


test("native reply admission rejects prose, malformed finals, and model-owned envelopes before completion", async (t) => {
  const valid = JSON.stringify(validOutputs["threat-model"]);
  const replies = [
    ["JSON embedded in prose", `Here is the result:\n${valid}`],
    ["valid commentary cannot rescue a malformed final", [
      {
        type: "text",
        text: valid,
        textSignature: JSON.stringify({ v: 1, id: "msg_commentary", phase: "commentary" }),
      },
      {
        type: "text",
        text: '{"threatModel":',
        textSignature: JSON.stringify({ v: 1, id: "msg_final", phase: "final_answer" }),
      },
    ]],
    ["model cannot submit an execution envelope", JSON.stringify({
      attemptId: "model-selected-attempt",
      output: validOutputs["threat-model"],
      phaseId: "threat-model",
      runId: "model-selected-run",
      schemaVersion: 1,
    })],
  ];
  for (const [name, reply] of replies) {
    await t.test(name, async (t) => {
      const fixture = await setup(t);
      const result = await invoke({
        ...fixture.environment,
        FAKE_RPC_PHASE_REPLIES: JSON.stringify({ "threat-model": reply }),
      }, ["scan", "--config", fixture.config]);
      assert.equal(result.code, 1, `${result.stderr}\n${result.stdout}`);
      const failed = parsed(result);
      assert.equal(failed.status, "failed");
      const phase = failed.phases.find((phase) => phase.id === "threat-model");
      assert.equal(phase.state, "failed");
      assert.equal(phase.output, null);
      const events = await invokeWorkbench(fixture, ["runtime-list-events", "--run-id", failed.id]);
      assert.equal(events.events.some((event) => event.phaseId === phase.id && event.kind === "agent.attempt_failed"), true);
      assert.equal(events.events.some((event) => event.phaseId === phase.id && event.kind === "agent.attempt_completed"), false);
      for (const line of (await readFile(fixture.capture, "utf8")).trim().split(/\r?\n/u)) {
        assert.throws(() => process.kill(JSON.parse(line).pid, 0), (error) => error.code === "ESRCH");
      }
    });
  }
});
test("retry restores an inline credential supplied through ambient config and stays recoverable", async (t) => {
  const fixture = await setup(t, true);
  const failedEnvironment = {
    ...fixture.environment,
    FAKE_RPC_PHASE_OUTPUTS: JSON.stringify({ ...validOutputs, discovery: { malformed: true } }),
  };
  const first = parsed(await invoke(failedEnvironment, ["scan", "--config", fixture.config]));
  const ambient = path.join(fixture.environment.PI_HOME, "pi-security");
  await mkdir(ambient, { recursive: true });
  await copyFile(fixture.config, path.join(ambient, "config.toml"));
  const secondResult = await invoke(failedEnvironment, ["run", "retry", first.id]);
  assert.equal(secondResult.code, 1, secondResult.stderr);
  const second = parsed(secondResult);
  assert.notEqual(second.scanId, first.scanId);
  const finalResult = await invoke(fixture.environment, ["run", "retry", second.id]);
  assert.equal(finalResult.code, 0, `${finalResult.stderr}\n${finalResult.stdout}`);
  assert.equal(parsed(finalResult).parentRunId, second.id);
});

test("resumed and retried foreground executors retain signal handling", async (t) => {
  const fixture = await setup(t);
  const interrupted = await signalRun(t, fixture, ["scan", "--config", fixture.config], "SIGHUP");
  assert.equal(interrupted.code, 75, interrupted.stderr);
  const resumed = await signalRun(t, fixture, ["run", "resume", parsed(interrupted).id], "SIGTERM");
  assert.equal(resumed.code, 75, resumed.stderr);
  assert.equal(parsed(resumed).id, parsed(interrupted).id);
  const failedEnvironment = {
    ...fixture.environment,
    FAKE_RPC_PHASE_OUTPUTS: JSON.stringify({ ...validOutputs, discovery: { malformed: true } }),
  };
  const failed = parsed(await invoke(failedEnvironment, ["scan", "--config", fixture.config]));
  const retried = await signalRun(t, fixture, ["run", "retry", failed.id], "SIGINT");
  assert.equal(retried.code, 130, retried.stderr);
  assert.equal(parsed(retried).parentRunId, failed.id);
});

test("missing recovery credentials leave the interrupted run unchanged", async (t) => {
  const fixture = await setup(t);
  await writeFile(fixture.config, (await readFile(fixture.config, "utf8")) + '\ncredential = { env = "SYNTHETIC_RECOVERY_TOKEN" }\n');
  fixture.environment.SYNTHETIC_RECOVERY_TOKEN = SECRET;
  const stopped = await signalRun(t, fixture, ["scan", "--config", fixture.config], "SIGHUP");
  assert.equal(stopped.code, 75, stopped.stderr);
  const interrupted = parsed(stopped);
  delete fixture.environment.SYNTHETIC_RECOVERY_TOKEN;
  const resumed = await invoke(fixture.environment, ["run", "resume", interrupted.id]);
  assert.equal(resumed.code, 2, resumed.stderr);
  const inspected = parsed(await invoke(fixture.environment, ["run", "inspect", interrupted.id]));
  assert.equal(inspected.status, "interrupted");
  assert.equal(inspected.updatedAt, interrupted.updatedAt);
});

test("canonical scan resolves a symlink target before issuing phase authority", async (t) => {
  const fixture = await setup(t);
  const alias = path.join(fixture.root, "repository-alias");
  await symlink(fixture.target, alias, "dir");
  const result = await invoke(fixture.environment, ["scan", "--config", fixture.config, "--target", alias]);
  assert.equal(result.code, 0, `${result.stderr}\n${result.stdout}`);
  assert.equal(parsed(result).targetPath, fixture.target);
});

test("native model defaults are pinned before the run and retained across resume", async (t) => {
  const fixture = await setup(t);
  await writeFile(fixture.config, (await readFile(fixture.config, "utf8"))
    .replace(/^provider = .*\n/mu, "").replace(/^model = .*\n/mu, ""));
  fixture.environment.FAKE_RPC_DEFAULT_MODEL = JSON.stringify({ provider: "openai", id: "synthetic-first-model" });
  const stopped = await signalRun(t, fixture, ["scan", "--config", fixture.config], "SIGHUP");
  assert.equal(stopped.code, 75, stopped.stderr);
  const interrupted = parsed(stopped);
  const persisted = await invokeWorkbench(fixture, ["runtime-get-run", "--run-id", interrupted.id]);
  assert.equal(persisted.snapshot.resolved.roles.default.provider, "openai");
  assert.equal(persisted.snapshot.resolved.roles.default.model, "synthetic-first-model");
  fixture.environment.FAKE_RPC_DEFAULT_MODEL = JSON.stringify({ provider: "openai", id: "synthetic-later-model" });
  await rm(fixture.capture);
  const resumed = await invoke(fixture.environment, ["run", "resume", interrupted.id]);
  assert.equal(resumed.code, 0, `${resumed.stderr}\n${resumed.stdout}`);
  for (const line of (await readFile(fixture.capture, "utf8")).trim().split(/\r?\n/u)) {
    assert.equal(JSON.parse(JSON.parse(line).phaseInput).role.model, "synthetic-first-model");
  }
});

test("a separate CLI cancellation waits for the owning executor to settle", async (t) => {
  const fixture = await setup(t);
  let cancellation;
  const owner = await signalRun(t, fixture, ["scan", "--config", fixture.config], async () => {
    const capture = JSON.parse((await readFile(fixture.capture, "utf8")).trim().split(/\r?\n/u)[0]);
    const runId = JSON.parse(capture.phaseInput).runId;
    cancellation = await invoke(fixture.environment, ["run", "cancel", runId]);
    assert.equal(cancellation.code, 130, `${cancellation.stderr}\n${cancellation.stdout}`);
    assert.throws(() => process.kill(capture.pid, 0), (error) => error.code === "ESRCH");
  });
  assert.equal(owner.code, 130, `${owner.stderr}\n${owner.stdout}`);
  assert.equal(parsed(owner).id, parsed(cancellation).id);
  assert.equal(parsed(owner).status, "canceled");
});

async function signalRun(t, fixture, args, signal) {
  await rm(fixture.capture, { force: true });
  const environment = { ...fixture.environment, FAKE_RPC_SETTLE_DELAY_MS: "10000" };
  await configureRpc(environment);
  const child = spawn(process.execPath, [cli, ...args], {
    env: environment,
    stdio: ["ignore", "pipe", "pipe"],
  });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
  child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
  const exited = new Promise((resolve) => child.once("close", resolve));
  await waitForFile(fixture.capture, child);
  if (typeof signal === "function") await signal();
  else child.kill(signal);
  const code = await exited;
  return { code, stdout, stderr };
}

async function configureRpc(environment) {
  const source = await readFile(fixtureRpc, "utf8");
  const settings = Object.fromEntries(Object.entries(environment).filter(([key]) => key.startsWith("FAKE_RPC_")));
  const executable = path.join(environment.PATH.split(path.delimiter)[0], "pi");
  await writeFile(executable, source.replace("\n", `\nObject.assign(process.env, ${JSON.stringify(settings)});\n`));
}

async function invokeWorkbench(fixture, args) {
  const python = fixture.environment.PI_SECURITY_PYTHON_COMMAND
    ?? fixture.environment.PYTHON
    ?? (process.platform === "win32" ? "python" : "python3");
  const result = await execFileAsync(python, [path.join(packageRoot, "scripts/workbench_db.py"), ...args], {
    env: fixture.environment,
    encoding: "utf8",
    timeout: 30_000,
  });
  return JSON.parse(result.stdout);
}

async function waitForFile(file, child) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error("RPC fixture terminated before prompt capture.");
    }
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
