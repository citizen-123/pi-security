import assert from "node:assert/strict";
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { build } from "esbuild";

const packageRoot = resolve(import.meta.dirname, "..");
const bundleRoot = await mkdtemp(join(tmpdir(), "pi-security-worker-tools-module-"));
const bundlePath = join(bundleRoot, "worker-tools.mjs");
await build({
  bundle: true,
  format: "esm",
  loader: { ".md": "text" },
  logLevel: "silent",
  outfile: bundlePath,
  platform: "node",
  stdin: {
    contents: [
      'export { createWorkerTools } from "./src/deep-scan/worker-tools.ts";',
      'export { createExecutionPolicyContext } from "./src/execution-policy.ts";',
    ].join("\n"),
    loader: "ts",
    resolveDir: packageRoot,
    sourcefile: "worker-tools-test-entry.ts",
  },
  target: "node20",
});
const { createExecutionPolicyContext, createWorkerTools } = await import(
  `${new URL(`file://${bundlePath}`).href}?${Date.now()}`
);

test.after(async () => {
  await rm(bundleRoot, { recursive: true, force: true });
});

const scanId = "00000000-0000-4000-8000-000000000001";

function validDraft() {
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

async function fixture(subagents = 0) {
  const root = await mkdtemp(join(tmpdir(), "pi-security-worker-tools-"));
  const repository = join(root, "repository");
  const workerRoot = join(root, "worker");
  const artifactRoot = join(workerRoot, "output");
  await mkdir(join(repository, "src"), { recursive: true });
  await mkdir(artifactRoot, { recursive: true });
  await writeFile(
    join(repository, "src", "app.ts"),
    "export function authorize(role: string) {\n  return role === 'admin';\n}\n",
  );
  const artifactContext = {
    root: artifactRoot,
    workerRoot,
    repoRoot: repository,
    scanId,
    layout: "worker",
    scope: ".",
    packageRoot,
    scanRoot: root,
    userContext: "Prioritize authorization boundaries.",
  };
  const executionContext = createExecutionPolicyContext({
    profile: subagents > 0 ? "security-delegating-readonly" : "security-readonly",
    target: { root: repository },
    scan: { id: scanId, artifactRoot: workerRoot },
    ...(subagents > 0 ? { delegation: { budget: subagents } } : {}),
  });
  const artifactWriterContext = createExecutionPolicyContext({
    profile: "security-artifact-writer",
    target: { root: repository },
    scan: { id: scanId, artifactRoot },
  });
  return { root, repository, workerRoot, artifactRoot, artifactContext, executionContext, artifactWriterContext };
}

function parsed(result) {
  return JSON.parse(result.content[0].text);
}

test("native worker tools inspect source and record a schema-bound draft", async () => {
  const entry = await fixture();
  try {
    const tools = await createWorkerTools({
      kind: "discovery",
      artifactContext: entry.artifactContext,
      executionContext: entry.executionContext,
      artifactWriterContext: entry.artifactWriterContext,
    });
    const signal = new AbortController().signal;
    assert.deepEqual(parsed((await tools.execute("list_pi_security_target_files", {}, signal)).result).files, ["src/app.ts"]);
    assert.match(parsed((await tools.execute("read_pi_security_source", { path: "src/app.ts" }, signal)).result).text, /authorize/u);
    assert.equal(parsed((await tools.execute("search_pi_security_source", { query: "admin" }, signal)).result).matches[0].path, "src/app.ts");
    assert.equal(parsed((await tools.execute("get_pi_security_scan_context", {}, signal)).result).scanId, scanId);
    const recorded = await tools.execute("record_pi_security_scan_draft", validDraft(), signal);
    assert.equal(recorded.result.isError, undefined);
    assert.equal(recorded.finalSubmissionAccepted, true);
    assert.deepEqual(JSON.parse(await readFile(join(entry.artifactRoot, "result.json"), "utf8")), validDraft());
  } finally {
    await rm(entry.root, { recursive: true, force: true });
  }
});

test("native worker tools deny traversal, hidden dispatch, and unknown tools", async () => {
  const entry = await fixture();
  try {
    await writeFile(join(entry.root, "outside.txt"), "outside secret\n");
    const tools = await createWorkerTools({
      kind: "discovery",
      artifactContext: entry.artifactContext,
      executionContext: entry.executionContext,
      artifactWriterContext: entry.artifactWriterContext,
    });
    const signal = new AbortController().signal;
    const traversal = await tools.execute("read_pi_security_source", { path: "../outside.txt" }, signal);
    assert.equal(traversal.result.isError, true);
    assert.doesNotMatch(traversal.result.content[0].text, /outside secret/u);
    assert.equal(tools.definitions().some((tool) => tool.name === "delegate_security_task"), false);
    for (const [name, input] of [
      ["delegate_security_task", { task: "hidden" }],
      ["model_supplied_tool", {}],
    ]) {
      const denied = await tools.execute(name, input, signal);
      assert.equal(denied.result.isError, true);
      assert.match(denied.result.content[0].text, /Unknown or unauthorized/u);
    }
    await assert.rejects(access(join(entry.artifactRoot, "result.json")));
  } finally {
    await rm(entry.root, { recursive: true, force: true });
  }
});

test("worker tool binding rejects forged and wrong-profile authority", async () => {
  const entry = await fixture();
  try {
    const base = {
      kind: "discovery",
      artifactContext: entry.artifactContext,
      executionContext: entry.executionContext,
      artifactWriterContext: entry.artifactWriterContext,
    };
    await assert.rejects(
      createWorkerTools({ ...base, executionContext: { ...entry.executionContext } }),
      /execution policy context was not issued/u,
    );
    await assert.rejects(
      createWorkerTools({ ...base, artifactWriterContext: entry.executionContext }),
      /artifact|capability|profile/iu,
    );
    await assert.rejects(access(join(entry.artifactRoot, "result.json")));
  } finally {
    await rm(entry.root, { recursive: true, force: true });
  }
});

test("delegation is advertised only with explicit bounded authority", async () => {
  const entry = await fixture(1);
  try {
    const delegated = await createWorkerTools({
      kind: "discovery",
      artifactContext: entry.artifactContext,
      executionContext: entry.executionContext,
      artifactWriterContext: entry.artifactWriterContext,
      delegationExecutionContext: () => entry.executionContext,
      delegateSecurityTask: async () => ({ ordinal: 1, error: "fixture" }),
    });
    assert.equal(delegated.definitions().some((tool) => tool.name === "delegate_security_task"), true);
  } finally {
    await rm(entry.root, { recursive: true, force: true });
  }
});
