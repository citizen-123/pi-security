import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { build } from "esbuild";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const contract = JSON.parse(
  await readFile(resolve(import.meta.dirname, "fixtures/lifecycle-tools.json"), "utf8")
);


const writerBundle = await build({
  bundle: true,
  entryPoints: [resolve(import.meta.dirname, "../artifact-writer-main.ts")],
  format: "esm",
  platform: "node",
  write: false,
});
const { createPiSecurityArtifactWriterServer } = await import(
  "data:text/javascript;base64,"
  + Buffer.from(writerBundle.outputFiles[0].contents).toString("base64")
);
function normalizeInputSchema(value, parentKey = "") {
  if (Array.isArray(value)) {
    const normalized = value.map((item) => normalizeInputSchema(item));
    return parentKey === "required" && normalized.every((item) => typeof item === "string")
      ? normalized.sort()
      : normalized;
  }
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, child]) => [key, normalizeInputSchema(child, key)])
  );
}

async function listTools(root, args, environment) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve(root, "dist/server.cjs"), ...args],
    env: { ...process.env, ...environment }
  });
  const client = new Client({ name: "pi-security-test", version: "1.0.0" });
  try {
    await client.connect(transport);
    return (await client.listTools()).tools;
  } finally {
    await client.close();
  }
}

test("each MCP surface exposes its exact frozen lifecycle contract", async () => {
  const root = resolve(import.meta.dirname, "..");
  const fixture = await mkdtemp(join(tmpdir(), "pi-security-mcp-contract-"));
  const repoRoot = join(fixture, "repository");
  const workerRoot = join(fixture, "worker-output");
  const reducerScanRoot = join(fixture, "scan");
  const reducerRoot = join(reducerScanRoot, "dedup", "output");
  const reducerResult = join(reducerScanRoot, "workers", "worker-1", "result.json");
  await Promise.all([
    mkdir(repoRoot, { recursive: true }),
    mkdir(workerRoot, { recursive: true }),
    mkdir(reducerRoot, { recursive: true }),
    mkdir(resolve(reducerResult, ".."), { recursive: true }),
  ]);
  await writeFile(reducerResult, "{}\n");
  const scanId = "00000000-0000-4000-8000-000000000001";
  const launches = {
    standalone: {
      args: [],
      environment: { PI_SECURITY_STATE_DIR: resolve(root, ".test-state") }
    },
    worker: {
      args: ["--artifact-writer"],
      environment: {
        PI_SECURITY_ARTIFACT_LAYOUT: "worker",
        PI_SECURITY_ARTIFACT_ROOT: workerRoot,
        PI_SECURITY_REPO_ROOT: repoRoot,
        PI_SECURITY_SCAN_ID: scanId,
        PI_SECURITY_SCOPE: ".",
      }
    },
    reducer: {
      args: ["--artifact-writer"],
      environment: {
        PI_SECURITY_ARTIFACT_LAYOUT: "reducer",
        PI_SECURITY_ARTIFACT_ROOT: reducerRoot,
        PI_SECURITY_REDUCER_CONTEXT_JSON: JSON.stringify({
          claimedWorkers: [{ id: "worker-1", resultPath: reducerResult }],
          scanRoot: reducerScanRoot
        }),
        PI_SECURITY_REPO_ROOT: repoRoot,
        PI_SECURITY_SCAN_ID: scanId,
        PI_SECURITY_SCOPE: ".",
      }
    }
  };
  const expectedByName = new Map(contract.tools.map((tool) => [tool.name, tool]));

  try {
    for (const [surface, launch] of Object.entries(launches)) {
      const tools = await listTools(root, launch.args, launch.environment);
      assert.deepEqual(
        tools.map((tool) => tool.name).sort(),
        contract.surfaces[surface],
        `${surface} tool names`
      );
      for (const tool of tools) {
        const expected = expectedByName.get(tool.name);
        assert.deepEqual(tool.annotations, expected.annotations, `${tool.name} annotations`);
        assert.deepEqual(
          tool._meta?.ui?.visibility,
          [expected.audience],
          `${tool.name} visibility`
        );
        assert.deepEqual(
          normalizeInputSchema(tool.inputSchema),
          expected.inputSchema,
          `${tool.name} input schema`
        );
      }
    }
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test("artifact writer bootstrap requires bound scan, scope, and reducer paths", async () => {
  const fixture = await mkdtemp(join(tmpdir(), "pi-security-artifact-bootstrap-"));
  const repoRoot = join(fixture, "repository");
  const workerRoot = join(fixture, "worker-output");
  const scanRoot = join(fixture, "scan");
  const reducerRoot = join(scanRoot, "dedup", "output");
  const outsideResult = join(fixture, "outside-result.json");
  await Promise.all([
    mkdir(repoRoot),
    mkdir(workerRoot),
    mkdir(reducerRoot, { recursive: true }),
  ]);
  await writeFile(outsideResult, "{}\n");
  const scanId = "00000000-0000-4000-8000-000000000001";
  const workerEnvironment = {
    PI_SECURITY_ARTIFACT_LAYOUT: "worker",
    PI_SECURITY_ARTIFACT_ROOT: workerRoot,
    PI_SECURITY_REPO_ROOT: repoRoot,
    PI_SECURITY_SCOPE: ".",
  };
  try {
    await assert.rejects(
      createPiSecurityArtifactWriterServer(workerEnvironment),
      /PI_SECURITY_SCAN_ID/,
    );
    await assert.rejects(
      createPiSecurityArtifactWriterServer({
        ...workerEnvironment,
        PI_SECURITY_SCAN_ID: "not-a-uuid",
      }),
      /invalid_format|UUID|uuid/i,
    );
    await assert.rejects(
      createPiSecurityArtifactWriterServer({
        ...workerEnvironment,
        PI_SECURITY_SCAN_ID: scanId,
        PI_SECURITY_SCOPE: "",
      }),
      /PI_SECURITY_SCOPE/,
    );
    await assert.rejects(
      createPiSecurityArtifactWriterServer({
        ...workerEnvironment,
        PI_SECURITY_SCAN_ID: scanId,
        PI_SECURITY_SCOPE: "/outside",
      }),
      /relative to the bound repository/,
    );
    await assert.rejects(
      createPiSecurityArtifactWriterServer({
        PI_SECURITY_ARTIFACT_LAYOUT: "reducer",
        PI_SECURITY_ARTIFACT_ROOT: reducerRoot,
        PI_SECURITY_REPO_ROOT: repoRoot,
        PI_SECURITY_SCAN_ID: scanId,
        PI_SECURITY_SCOPE: ".",
        PI_SECURITY_REDUCER_CONTEXT_JSON: JSON.stringify({
          scanRoot,
          claimedWorkers: [{ id: "worker-1", resultPath: outsideResult }],
        }),
      }),
      /outside its coordinator-bound root/,
    );
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});
