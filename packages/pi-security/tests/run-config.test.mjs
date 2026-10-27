// Run configuration (TOML precedence, roles, rejected credential forms), worker role resolution, and model access:
// role credentials applied in memory only, and no credential value stored by a run even when a provider echoes it.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { build } from "esbuild";

// The stub provider listens on loopback; keep the agent proxy out of it.
process.env.NO_PROXY = process.env.no_proxy = "127.0.0.1,localhost";

const packageRoot = resolve(import.meta.dirname, "..");
const outfile = join(packageRoot, "node_modules", ".cache", "pi-security-tests", "run-config.mjs");
await build({
  bundle: true,
  stdin: {
    contents: [
      'export * from "./src/config/run-config.ts";',
      'export * from "./src/durable/models.ts";',
      'export * from "./src/durable/roles.ts";',
      'export * from "./src/durable/harness.ts";',
      'export * from "./src/durable/run-directory.ts";',
      'export { createRegistry } from "@earendil-works/pi-durable";',
    ].join("\n"),
    resolveDir: packageRoot,
  },
  format: "esm",
  outfile,
  packages: "external",
  platform: "node",
});
const d = await import(outfile);

function scratch(t) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "pi-security-config-")));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

test("durations accept d/h/m/s sequences and reject everything else", () => {
  assert.equal(d.parseDuration("15m"), 900_000);
  assert.equal(d.parseDuration("1h30m"), 5_400_000);
  assert.equal(d.parseDuration("2d"), 172_800_000);
  for (const bad of ["", "15", "15 m", "1.5h", "0s", "-1h", "1w"]) assert.throws(() => d.parseDuration(bad), { name: "ConfigError" }, bad);
});

test("configuration resolves defaults, then the ambient file, then --config, then flags", async (t) => {
  const root = scratch(t);
  mkdirSync(join(root, "home", "pi-security"), { recursive: true });
  writeFileSync(
    join(root, "home", "pi-security", "config.toml"),
    '[execution]\nmax_parallel = 2\nstall_timeout = "5m"\n[roles.default]\nprovider = "anthropic"\nmodel = "claude-a"\n[roles.validator]\nthinking = "high"\n[deep_scan]\nstop_after_no_new = 2\n',
  );
  writeFileSync(
    join(root, "explicit.toml"),
    '[scan]\ntarget = "repo"\n[execution]\nmax_duration = "6h"\nmax_cost = 12.5\n[roles.default]\nmodel = "claude-b"\n[remediation.checks]\ntest = ["npm", "test"]\n',
  );
  const env = { PI_HOME: join(root, "home") };
  const defaults = await d.resolveRunConfig({ cwd: root, env: {}, ambientPath: join(root, "missing.toml") });
  assert.deepEqual(defaults, d.defaultRunConfig(root));
  const config = await d.resolveRunConfig({ cwd: root, env, explicitPath: "explicit.toml", overrides: { maxParallel: 8, thinking: "low" } });
  assert.deepEqual(config, {
    scan: { target: join(root, "repo") },
    execution: { maxParallel: 8, stallTimeoutMs: 300_000, maxDurationMs: 21_600_000, maxCostUsd: 12.5 },
    roles: { default: { provider: "anthropic", model: "claude-b", thinking: "low" }, validator: { thinking: "high" } },
    deepScan: { maxDiscoveryRounds: 8, stopAfterNoNew: 2 },
    remediation: { checks: { test: ["npm", "test"] } },
  });
  await assert.rejects(d.resolveRunConfig({ cwd: root, env, explicitPath: "absent.toml" }), /cannot read configuration .*absent\.toml: ENOENT/);
  await assert.rejects(d.resolveRunConfig({ cwd: root, env, overrides: { maxParallel: 65 } }), /--max-parallel/);
});

test("inline and profile credentials, unknown roles and keys, and bad values are rejected with their location", () => {
  const cases = [
    ['[roles.default]\ncredential = { value = "sk-live-123456" }', /roles\.default\.credential: inline credential values are not accepted/],
    ['[roles.default]\ncredential = { profile = "work" }', /credential profiles are not supported/],
    ['[roles.default]\ncredential = { env = "1BAD" }', /expected credential = \{ env = "NAME" \}/],
    ['[roles.default]\ncredential = { env = "KEY", value = "x" }', /inline credential values/],
    ['[roles.reporter]\nmodel = "x"', /at roles\.reporter/],
    ["[execution]\nworkers = 4", /at execution\.workers/],
    ["[execution]\nmax_parallel = 0", /at execution\.max_parallel/],
    ['[execution]\nstall_timeout = "soon"', /at execution\.stall_timeout: invalid duration/],
    ['[remediation.checks]\n"Run Tests" = ["npm"]', /at remediation\.checks/],
    ["[remediation.checks]\ntest = []", /at remediation\.checks\.test/],
    ["[scan\n", /at line 1, column \d+: invalid TOML/],
  ];
  for (const [source, expected] of cases) assert.throws(() => d.parseRunConfigText(source, "test.toml"), expected, source);
});

test("roles inherit the default role, except its credential when they change provider", () => {
  const config = {
    ...d.defaultRunConfig("/w"),
    roles: {
      default: { provider: "anthropic", model: "claude-a", credentialEnv: "ANTHROPIC_KEY", instructions: "Be terse." },
      discoverer: { model: "claude-fast" },
      validator: { provider: "openai", model: "gpt-x" },
    },
  };
  assert.deepEqual(d.effectiveRole(config, "discoverer"), { provider: "anthropic", model: "claude-fast", credentialEnv: "ANTHROPIC_KEY", instructions: "Be terse." });
  assert.deepEqual(d.effectiveRole(config, "validator"), { provider: "openai", model: "gpt-x", instructions: "Be terse." });
  assert.deepEqual(d.workerRole(config, "discoverer", "Find candidates."), {
    id: "discoverer",
    report: "discover",
    model: { provider: "anthropic", modelId: "claude-fast" },
    instructions: "Find candidates.\n\nBe terse.",
  });
});

test("roles without a model fall back to Pi's default model, or fail clearly", () => {
  const empty = d.defaultRunConfig("/w");
  const pi = { provider: "anthropic", model: "claude-pi", thinking: "medium" };
  assert.deepEqual(d.workerRole(empty, "reducer", "Reduce.", pi), { id: "reducer", report: "reduce", model: { provider: "anthropic", modelId: "claude-pi" }, thinking: "medium", instructions: "Reduce." });
  assert.equal(d.workerRole(empty, "reducer", "Reduce.", { ...pi, thinking: "max" }).thinking, undefined, "an unsupported Pi thinking level is not passed on");
  assert.throws(() => d.workerRole(empty, "reducer", "Reduce.", {}), /no model for roles\.reducer/);
  const partial = { ...empty, roles: { default: { provider: "openai" } } };
  assert.throws(() => d.workerRole(partial, "reducer", "Reduce.", pi), /no model for roles\.reducer/, "a role naming only a provider does not borrow Pi's model");
});

test("role credentials become in-memory runtime keys; missing or conflicting ones fail", async (t) => {
  const root = scratch(t);
  writeFileSync(join(root, "auth.json"), JSON.stringify({ anthropic: { type: "api_key", key: "sk-ant-file-0123456789" } }), { mode: 0o600 });
  const config = { ...d.defaultRunConfig(root), roles: { default: { provider: "openai", model: "gpt-x", credentialEnv: "PI_SECURITY_TEST_KEY" } } };
  const { models, secrets } = await d.createRunModels({ config, env: { PI_SECURITY_TEST_KEY: "sk-role-env-9876543210", HOME_DIR: "/home/u" }, agentDir: root });
  assert.deepEqual(models.getProviderAuthStatus("openai"), { configured: true, source: "runtime" });
  assert.ok(secrets.includes("sk-role-env-9876543210") && secrets.includes("sk-ant-file-0123456789"));
  assert.equal(secrets.includes("/home/u"), false, "ordinary environment values are not treated as secrets");
  assert.equal(readFileSync(join(root, "auth.json"), "utf8").includes("sk-role-env"), false, "the role key is not written to auth.json");
  await assert.rejects(d.createRunModels({ config, env: {}, agentDir: root }), /PI_SECURITY_TEST_KEY for roles\.default\.credential is not set/);
  const conflicting = { ...config, roles: { ...config.roles, validator: { credentialEnv: "OTHER_KEY" } } };
  await assert.rejects(d.createRunModels({ config: conflicting, env: { PI_SECURITY_TEST_KEY: "a".repeat(12), OTHER_KEY: "b".repeat(12) }, agentDir: root }), /different credentials/);
  const providerless = { ...d.defaultRunConfig(root), roles: { default: { credentialEnv: "PI_SECURITY_TEST_KEY" } } };
  await assert.rejects(d.createRunModels({ config: providerless, env: { PI_SECURITY_TEST_KEY: "x".repeat(12) }, agentDir: root }), /has no provider/);
});

test("redactSecrets removes longer secrets first", () => {
  assert.equal(d.redactSecrets("key sk-abc-123456 and sk-abc-123456-extended", ["sk-abc-123456", "sk-abc-123456-extended"]), "key [REDACTED] and [REDACTED]");
});

test("a provider error echoing the key is stored redacted, and no run file holds the key", async (t) => {
  const root = scratch(t);
  const CANARY = "sk-pi-security-CANARY-4b8e1d";
  let mode = "401";
  const authorization = [];
  const server = createServer((request, response) => {
    authorization.push(String(request.headers.authorization ?? ""));
    request.resume();
    request.on("end", () => {
      if (mode === "401") {
        response.writeHead(401, { "content-type": "application/json" });
        response.end(JSON.stringify({ error: { message: `Incorrect API key provided: ${CANARY}`, type: "invalid_request_error" } }));
        return;
      }
      response.writeHead(200, { "content-type": "text/event-stream" });
      const chunk = (delta, finish) => `data: ${JSON.stringify({ id: "c1", object: "chat.completion.chunk", created: 0, model: "stub-1", choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
      response.write(chunk({ role: "assistant", content: "Paris." }, null));
      response.write(chunk({}, "stop"));
      response.end("data: [DONE]\n\n");
    });
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  t.after(() => server.close());
  const agentDir = join(root, "agent");
  mkdirSync(agentDir);
  writeFileSync(join(agentDir, "models.json"), JSON.stringify({ providers: { stub: { baseUrl: `http://127.0.0.1:${server.address().port}/v1`, api: "openai-completions", models: [{ id: "stub-1" }] } } }));
  const config = { ...d.defaultRunConfig(root), roles: { default: { provider: "stub", model: "stub-1", credentialEnv: "STUB_KEY" } } };
  const { models } = await d.createRunModels({ config, env: { STUB_KEY: CANARY }, agentDir });
  const paths = d.runPaths(join(root, "state"), d.newRunId());
  const run = await d.openRun(paths, { models, registry: d.createRegistry(), settings: { extensions: [], retry: { enabled: false } } });
  const conversation = await run.harness.root(d.RUN_CONTEXT, { agent: { model: { provider: "stub", modelId: "stub-1" } } });
  const failed = await (await conversation.submit({ type: "input", content: "Capital of France?" }, d.RUN_CONTEXT)).wait(d.RUN_CONTEXT);
  mode = "ok";
  const answered = await (await conversation.submit({ type: "input", content: "Again?" }, d.RUN_CONTEXT)).wait(d.RUN_CONTEXT);
  await run.close();
  assert.equal(failed.status, "unanswered");
  assert.match(failed.detail, /\[REDACTED\]/);
  assert.equal(failed.detail.includes(CANARY), false);
  assert.equal(answered.status, "done", "the normal path still works");
  assert.ok(authorization.every((header) => header === `Bearer ${CANARY}`), "the provider received the role key");
  for (const suffix of ["", "-wal", "-shm"]) {
    let bytes;
    try {
      bytes = readFileSync(paths.storage + suffix);
    } catch {
      continue;
    }
    assert.equal(bytes.includes(CANARY), false, `run.sqlite${suffix} holds the key`);
  }
});
