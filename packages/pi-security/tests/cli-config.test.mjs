import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import test from "node:test";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  stdin: {
    contents: [
      'export * from "./src/cli/args.ts";',
      'export * from "./src/cli/main.ts";',
      'export * from "./src/config/execution-config.ts";',
    ].join("\n"),
    resolveDir: new URL("..", import.meta.url).pathname,
  },
  format: "esm",
  platform: "node",
  write: false,
});
const runtime = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`,
);

test("CLI parser exposes help and rejects unknown or incomplete commands", async () => {
  assert.deepEqual(runtime.parseCliArgs([]), { kind: "help" });
  assert.deepEqual(runtime.parseCliArgs(["run", "inspect", "run-1"]), {
    kind: "run-inspect",
    runId: "run-1",
  });
  assert.throws(() => runtime.parseCliArgs(["unknown"]), /Unknown command/u);
  assert.throws(() => runtime.parseCliArgs(["run", "resume"]), /Missing run ID/u);
  assert.throws(() => runtime.parseCliArgs(["scan", "--config"]), /Missing value/u);

  const output = [];
  const errors = [];
  assert.equal(await runtime.runCli(["--help"], {
    output: (value) => output.push(value),
    error: (value) => errors.push(value),
  }), 0);
  assert.deepEqual(errors, []);
});

test("TOML parser validates workflow, roles, and existing deep scan settings", () => {
  const parsed = runtime.parseExecutionConfigText(`
[scan]
target = "repo"
workflow = "full-repository"

[execution]
max_parallel = 6

[roles.validator]
provider = "provider-a"
model = "model-a"
thinking = "high"
max_attempts = 3
credential = { env = "VALIDATOR_KEY" }

[deep_scan]
workers = "auto"
subagents = 0
`);
  assert.equal(parsed.roles.validator.credential.env, "VALIDATOR_KEY");
  assert.equal(parsed.deep_scan.workers, "auto");
  assert.throws(() => runtime.parseExecutionConfigText("[scan]\nworkflow = \"arbitrary\"\n"));
  assert.throws(() => runtime.parseExecutionConfigText("[roles.validator]\nunknown = true\n"));
});

test("configuration precedence and provenance are deterministic", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "pi-security-config-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const piHome = path.join(root, "pi-home");
  const ambientPath = path.join(piHome, "pi-security", "config.toml");
  const explicitPath = path.join(root, "explicit.toml");
  await mkdir(path.dirname(ambientPath), { recursive: true });
  await writeFile(ambientPath, `
[scan]
target = "ambient-target"
[execution]
max_parallel = 2
[roles.default]
model = "ambient-model"
`);
  await writeFile(explicitPath, `
[scan]
target = "explicit-target"
[execution]
max_parallel = 3
[roles.default]
model = "explicit-model"
`);

  const config = await runtime.resolveExecutionConfig({
    cwd: root,
    env: { PI_HOME: piHome },
    explicitPath,
    overrides: { maxParallel: 5, model: "cli-model" },
  });
  assert.equal(config.scan.target, path.join(root, "explicit-target"));
  assert.equal(config.execution.maxParallel, 5);
  assert.equal(config.roles.default.model, "cli-model");
  assert.equal(config.provenance["scan.target"], "explicit");
  assert.equal(config.provenance["execution.maxParallel"], "cli");
  assert.equal(config.provenance["roles.default.model"], "cli");
  assert.equal(config.provenance["roles.default.maxAttempts"], "default");
});

test("credential values are usable but absent from snapshots and redacted output", async () => {
  const secretA = "synthetic-secret-alpha";
  const secretB = "synthetic-secret-beta";
  const first = await runtime.resolveExecutionConfig({
    cwd: "/tmp/example",
    ambientPath: "/definitely/missing/config.toml",
  });
  first.roles.default.credential = { kind: "inline", value: secretA };
  const second = structuredClone(first);
  second.roles.default.credential = { kind: "inline", value: secretB };

  const firstSnapshot = runtime.createExecutionSnapshot(first);
  const secondSnapshot = runtime.createExecutionSnapshot(second);
  assert.equal(firstSnapshot.digest, secondSnapshot.digest);
  assert.doesNotMatch(JSON.stringify(firstSnapshot), new RegExp(`${secretA}|${secretB}`, "u"));
  assert.deepEqual(firstSnapshot.resolved.roles.default.credential, { source: "inline" });
  assert.deepEqual(await runtime.resolveCredential(first.roles.default.credential), {
    source: "inline",
    value: secretA,
  });
  assert.equal(
    runtime.redactKnownSecrets(`error ${secretA} and ${secretB}`, [secretA, secretB]),
    "error [REDACTED] and [REDACTED]",
  );
  const environmentCredential = structuredClone(first);
  environmentCredential.roles.default.credential = { env: "SYNTHETIC_PROVIDER_TOKEN", kind: "env" };
  assert.deepEqual(
    runtime.createExecutionSnapshot(environmentCredential).resolved.roles.default.credential,
    { env: "SYNTHETIC_PROVIDER_TOKEN", source: "env" },
  );
});

test("environment and profile credentials report only source identity on failure", async () => {
  await assert.rejects(
    runtime.resolveCredential({ env: "MISSING_KEY", kind: "env" }, { env: {} }),
    /MISSING_KEY.*unavailable/u,
  );
  await assert.rejects(
    runtime.resolveCredential({ kind: "profile", profile: "missing-profile" }, { profiles: () => undefined }),
    /missing-profile.*unavailable/u,
  );
});

test("invalid CLI values and run options never reach command execution", async () => {
  for (const args of [
    ["scan", "--target", "   "],
    ["scan", "--provider", "-h"],
    ["run", "cancel", "--config"],
  ]) {
    let invoked = false;
    const code = await runtime.runCli(args, { output() {}, error() {} }, async () => {
      invoked = true;
      return 0;
    });
    assert.equal(code, 2);
    assert.equal(invoked, false);
  }
  assert.deepEqual(runtime.parseCliArgs(["run", "inspect", "--help"]), { kind: "help" });
});

test("invalid config diagnostics do not disclose credential-bearing source or keys", () => {
  const secret = "synthetic-diagnostic-canary";
  for (const source of [
    `[roles.default]\ncredential = { value = "${secret}" }\nmodel =`,
    `[roles.default]\n"${secret}" = true`,
    `[roles."${secret}"]\nmax_attempts = 0`,
  ]) {
    assert.throws(() => runtime.parseExecutionConfigText(source), (error) => {
      assert.equal(error.message.includes(secret), false);
      assert.equal(error.stack.includes(secret), false);
      return true;
    });
  }
});

test("programmatic overrides enforce the same config value constraints", async () => {
  for (const overrides of [
    { maxParallel: 0 },
    { maxParallel: 65 },
    { target: " " },
    { model: " " },
    { thinking: "unsupported" },
    { workflow: "unsupported" },
  ]) {
    await assert.rejects(runtime.resolveExecutionConfig({
      ambientPath: "/definitely/missing/config.toml",
      overrides,
    }));
  }
});

test("legacy settings merge per field and retain auto with provenance", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "pi-security-legacy-config-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(path.join(root, "ambient.toml"), '[deep_scan]\nworkers = 7\nsubagents = 2\n');
  await writeFile(path.join(root, "explicit.toml"), '[deep_scan]\nworkers = "auto"\n');
  const config = await runtime.resolveExecutionConfig({
    cwd: root,
    ambientPath: "ambient.toml",
    explicitPath: "explicit.toml",
  });
  assert.deepEqual(config.legacyDeepScan, { workers: "auto", subagents: 2 });
  assert.equal(config.provenance["legacyDeepScan.workers"], "explicit");
  assert.equal(config.provenance["legacyDeepScan.subagents"], "ambient");
});

test("role names cannot mutate inherited JavaScript objects", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "pi-security-role-config-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(path.join(root, "roles.toml"), '[roles.constructor]\nmodel = "synthetic-role-model"\n');
  const inheritedModel = Object.model;
  const config = await runtime.resolveExecutionConfig({
    cwd: root,
    ambientPath: "roles.toml",
  });
  assert.equal(Object.model, inheritedModel);
  assert.equal(config.roles.constructor.model, "synthetic-role-model");
  assert.equal(config.roles.constructor.maxAttempts, 2);
});

test("snapshot compatibility survives persistence, provenance, and credential replacement", async () => {
  const config = await runtime.resolveExecutionConfig({ ambientPath: "/definitely/missing/config.toml" });
  config.roles.default.credential = { kind: "inline", value: "synthetic-original-credential" };
  const original = runtime.createExecutionSnapshot(config);
  const roundTrip = JSON.parse(JSON.stringify(config));
  roundTrip.provenance["scan.target"] = "cli";
  roundTrip.roles.default.credential = { kind: "env", env: "SYNTHETIC_KEY" };
  assert.equal(runtime.createExecutionSnapshot(roundTrip).digest, original.digest);
  roundTrip.roles.default.model = "different-model";
  assert.notEqual(runtime.createExecutionSnapshot(roundTrip).digest, original.digest);
  config.roles.default.model = "later-config-edit";
  assert.notEqual(original.resolved.roles.default.model, "later-config-edit");
  assert.throws(() => { original.resolved.roles.default.model = "snapshot-edit"; }, TypeError);
  assert.throws(() => { original.resolved.scan.target = "/tmp/different-target"; }, TypeError);
});

test("credential snapshots retain nonsecret references and resolver errors stay secret-free", async () => {
  const config = await runtime.resolveExecutionConfig({ ambientPath: "/definitely/missing/config.toml" });
  config.roles.default.credential = { kind: "env", env: "SYNTHETIC_KEY" };
  config.roles.validator = { maxAttempts: 2, credential: { kind: "profile", profile: "synthetic-profile" } };
  const snapshot = runtime.createExecutionSnapshot(config);
  assert.deepEqual(snapshot.resolved.roles.default.credential, { source: "env", env: "SYNTHETIC_KEY" });
  assert.deepEqual(snapshot.resolved.roles.validator.credential, { source: "profile", profile: "synthetic-profile" });
  await assert.rejects(runtime.resolveCredential({ kind: "env", env: "constructor" }, { env: {} }));
  const secret = "synthetic-profile-error-canary";
  await assert.rejects(runtime.resolveCredential(config.roles.validator.credential, {
    profiles() { throw new Error(`backend echoed ${secret}`); },
  }), (error) => {
    assert.equal(error.message.includes(secret), false);
    assert.equal(error.stack.includes(secret), false);
    return true;
  });
});

test("CLI executes through a bin symlink and imports safely with a virtual argv entry", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "pi-security-cli-entry-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const entry = path.join(root, "cli.mjs");
  await build({
    bundle: true,
    entryPoints: [new URL("../src/cli/main.ts", import.meta.url).pathname],
    format: "esm",
    platform: "node",
    outfile: entry,
  });
  const link = path.join(root, "pi-security");
  await symlink(entry, link);
  const exec = promisify(execFile);
  const { stdout, stderr } = await exec(process.execPath, [link, "--help"]);
  assert.match(stdout, /Usage:/u);
  assert.equal(stderr, "");
  const imported = await exec(process.execPath, ["--input-type=module", "-e",
    `process.argv[1] = ${JSON.stringify(path.join(root, "virtual-entry"))}; await import(${JSON.stringify(pathToFileURL(entry).href)}); console.log("imported");`,
  ]);
  assert.equal(imported.stdout.trim(), "imported");
  assert.equal(imported.stderr, "");
});

test("PI_HOME retains legacy tilde expansion", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "pi-security-home-config-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "pi-security"));
  await writeFile(path.join(root, "pi-security", "config.toml"), '[execution]\nmax_parallel = 9\n');
  const config = await runtime.resolveExecutionConfig({
    cwd: root,
    env: { PI_HOME: `~/${path.relative(homedir(), root)}` },
  });
  assert.equal(config.execution.maxParallel, 9);
  assert.equal(config.provenance["execution.maxParallel"], "ambient");
});
