import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { build } from "esbuild";

const packageRoot = new URL("..", import.meta.url).pathname;
const bundle = await build({
  bundle: true,
  entryPoints: [path.join(packageRoot, "extensions/canonical-runtime.ts")],
  format: "esm",
  platform: "node",
  write: false,
});
const adapter = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`,
);

function harness() {
  const tools = new Map();
  return {
    api: { registerTool(tool) { tools.set(tool.name, tool); } },
    tools,
  };
}

test("Pi adapter starts and observes only through the canonical runtime port", async () => {
  const calls = [];
  const runtime = {
    async start(input) { calls.push(["start", input]); return { id: "run-a", status: "completed" }; },
    async observe(input) { calls.push(["observe", input]); return { id: input.runId, status: "interrupted" }; },
  };
  const fixture = harness();
  adapter.registerCanonicalRuntimeTools(fixture.api, runtime);
  assert.deepEqual([...fixture.tools.keys()].sort(), [
    "inspect_pi_security_canonical_run",
    "start_pi_security_canonical_scan",
  ]);
  const startTool = fixture.tools.get("start_pi_security_canonical_scan");
  assert.equal("claimToken" in startTool.parameters.properties, false);
  assert.equal("controllerId" in startTool.parameters.properties, false);
  const started = await startTool.execute("call-start", {
    configPath: "/tmp/synthetic.toml",
    targetPath: "/tmp/synthetic-repository",
  });
  assert.deepEqual(started.details, { id: "run-a", status: "completed" });

  const observed = await fixture.tools.get("inspect_pi_security_canonical_run").execute("call-observe", {
    afterSequence: 4,
    runId: "run-a",
  });
  assert.deepEqual(observed.details, { id: "run-a", status: "interrupted" });
  assert.deepEqual(calls, [
    ["start", { configPath: "/tmp/synthetic.toml", targetPath: "/tmp/synthetic-repository" }],
    ["observe", { afterSequence: 4, runId: "run-a" }],
  ]);
});

test("standard full-repository skill delegates once without owning a phase sequence", async () => {
  const skill = await readFile(path.join(packageRoot, "skills/security-scan/SKILL.md"), "utf8");
  assert.match(skill, /Call `start_pi_security_canonical_scan` once/u);
  assert.match(skill, /runtime owns the phase graph/u);
  assert.doesNotMatch(skill, /^\d+\. .*threat.model|^\d+\. .*discovery|^\d+\. .*validation/gimu);
  assert.match(skill, /Use `\/security-diff-scan`/u);
  assert.match(skill, /Use `\/deep-security-scan`/u);
});
