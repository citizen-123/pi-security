import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

// Exercise the installed Pi loader and native tool definitions, not a mocked ExtensionAPI.
const nativeRoot = import.meta.resolve("@earendil-works/pi-coding-agent");
const { loadExtensions } = await import(new URL("./core/extensions/loader.js", nativeRoot));
const policyPath = fileURLToPath(new URL("../dist/pi-security-rpc-policy.mjs", import.meta.url));

async function loadPolicy(authority) {
  const previous = process.env.PI_SECURITY_RPC_AUTHORITY;
  process.env.PI_SECURITY_RPC_AUTHORITY = JSON.stringify(authority);
  try {
    const loaded = await loadExtensions([policyPath], authority.targetPath);
    assert.deepEqual(loaded.errors, []);
    return loaded.extensions[0];
  } finally {
    if (previous === undefined) delete process.env.PI_SECURITY_RPC_AUTHORITY;
    else process.env.PI_SECURITY_RPC_AUTHORITY = previous;
  }
}

async function execute(extension, name, args, signal = new AbortController().signal) {
  const result = await extension.tools.get(name).definition.execute("synthetic-call", args, signal, undefined, undefined);
  return result.content.filter((item) => item.type === "text").map((item) => item.text).join("\n");
}

test("native-loaded RPC tools read and search approved roots without following escape paths", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "pi-security-rpc-policy-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const targetPath = join(root, "target");
  const artifactRoot = join(root, "artifacts");
  const outside = join(root, "outside");
  await Promise.all([targetPath, artifactRoot, outside].map((path) => mkdir(path)));
  await writeFile(join(targetPath, "source.txt"), "first line\nsynthetic match\nlast line\n");
  await writeFile(join(artifactRoot, "input.txt"), "approved artifact input\n");
  await writeFile(join(outside, "private.txt"), "synthetic-outside-canary\n");
  if (process.platform !== "win32") await symlink(outside, join(targetPath, "escape"));
  const extension = await loadPolicy({ targetPath, artifactRoot, runId: "synthetic-run", tools: ["read", "grep", "find", "ls"] });

  assert.match(await execute(extension, "read", { path: "source.txt", offset: 2, limit: 1 }), /synthetic match/u);
  assert.match(await execute(extension, "read", { path: join(artifactRoot, "input.txt") }), /approved artifact input/u);
  assert.match(await execute(extension, "grep", { pattern: "SYNTHETIC", ignoreCase: true, path: targetPath }), /source\.txt:2:synthetic match/u);
  assert.equal(await execute(extension, "grep", { pattern: "synthetic.*", path: targetPath }), "No matches found");
  await assert.rejects(execute(extension, "grep", { pattern: "(a+)+$", literal: false, path: targetPath }));
  assert.equal((await execute(extension, "find", { pattern: "*.txt", path: targetPath })).trim(), "source.txt");
  assert.match(await execute(extension, "ls", { path: targetPath }), /source\.txt/u);

  const escapedDirectories = [outside, "../outside"];
  if (process.platform !== "win32") escapedDirectories.push("escape");
  for (const directory of escapedDirectories) {
    await assert.rejects(execute(extension, "read", { path: join(directory, "private.txt") }));
    await assert.rejects(execute(extension, "grep", { path: directory, pattern: "canary" }));
    await assert.rejects(execute(extension, "find", { path: directory, pattern: "*" }));
    await assert.rejects(execute(extension, "ls", { path: directory }));
  }
  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(execute(extension, "grep", { path: targetPath, pattern: "match" }, aborted.signal));
});

test("native-loaded RPC policy denies shell and delegation even if requested at runtime", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "pi-security-rpc-capability-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const extension = await loadPolicy({ targetPath: root, artifactRoot: root, runId: "synthetic-run", tools: ["read"] });
  const handler = extension.handlers.get("tool_call")[0];
  for (const toolName of ["bash", "write", "edit", "subagent", "grep"]) {
    assert.equal((await handler({ type: "tool_call", toolName, input: {}, toolCallId: "synthetic" })).block, true);
  }
  const shell = await extension.handlers.get("user_bash")[0]({ type: "user_bash", command: "touch forbidden" });
  assert.equal(shell.result.exitCode, 1);
  assert.equal(extension.tools.has("bash"), false);
});
