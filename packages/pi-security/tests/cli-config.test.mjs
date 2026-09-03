import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
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
  assert.match(output.join("\n"), /run resume/u);
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
workers = 2
subagents = 0
`);
  assert.equal(parsed.roles.validator.credential.env, "VALIDATOR_KEY");
  assert.equal(parsed.deep_scan.workers, 2);
  assert.throws(
    () => runtime.parseExecutionConfigText("[scan]\nworkflow = \"arbitrary\"\n"),
    /scan.workflow/u,
  );
  assert.throws(
    () => runtime.parseExecutionConfigText("[roles.validator]\nunknown = true\n"),
    /roles.validator.unknown/u,
  );
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
