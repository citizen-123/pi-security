import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { build } from "esbuild";

const compiled = await build({
  bundle: true,
  stdin: {
    contents: [
      'import * as io from "./src/artifact-io.ts";',
      'import * as contextApi from "./src/artifact-context.ts";',
      'import * as schemas from "./src/artifact-schema-loader.ts";',
      'export { io, contextApi, schemas };',
      'export { createExecutionPolicyContext } from "./src/execution-policy.ts";',
    ].join("\n"),
    resolveDir: new URL("..", import.meta.url).pathname,
  },
  format: "esm",
  platform: "node",
  write: false
});
const {
  io,
  contextApi,
  createExecutionPolicyContext,
  schemas,
} = await import(
  "data:text/javascript;base64," + Buffer.from(compiled.outputFiles[0].contents).toString("base64")
);
const fixture = await realpath(
  await mkdtemp(path.join(tmpdir(), "pi-security-artifact-foundation-"))
);
const artifactScanId = "61a20957-1be8-4ccf-8de8-eab4061e8cc3";

async function boundArtifactContext(root, repoRoot, layout = "scan", extra = {}) {
  const executionPolicy = createExecutionPolicyContext({
    profile: "security-artifact-writer",
    target: { root: repoRoot },
    scan: { id: artifactScanId, artifactRoot: root },
  });
  if (layout === "scan") {
    return {
      root: await realpath(root),
      repoRoot: await realpath(repoRoot),
      layout,
      scanId: artifactScanId,
      ...extra,
      executionPolicy,
    };
  }
  return await contextApi.createWorkerArtifactContext({
    root,
    repoRoot,
    layout,
    ...extra,
    scanId: artifactScanId,
    executionPolicy,
  });
}

try {
  await testSchemaSourceOfTruth();
  await testScanContext();
  await testWorkerStandardLayout();
  await testArtifactDestinationSwap();
  await testSafeJsonAndJsonl();
  await testAtomicReplaceAndAppend();
  await testBoundedPagination();
  await testUnsafeArtifacts();
} finally {
  await rm(fixture, { force: true, recursive: true });
}

console.log("Pi Security compact artifact foundation tests passed");

async function testSchemaSourceOfTruth() {
  const common = JSON.parse(await readFile(
    new URL("../schemas/definitions/artifact-common.schema.json", import.meta.url),
    "utf8"
  ));
  const fixtureDocument = {
    $id: "pi-security://schemas/tools/artifact-foundation-fixture.schema.json",
    $defs: {
      request: {
        type: "object",
        properties: {
          path: { $ref: common.$id + "#/$defs/repositoryPath" },
          candidateId: { $ref: common.$id + "#/$defs/candidateId" }
        },
        required: ["path", "candidateId"],
        additionalProperties: false
      }
    }
  };
  const bundled = schemas.bundleArtifactSchema(
    [common, fixtureDocument],
    fixtureDocument.$id,
    "request"
  );
  assert.equal(JSON.stringify(bundled).includes("$ref"), false);
  assert.equal(bundled.properties.path.type, "string");
  assert.equal(bundled.properties.candidateId.type, "string");

  const validator = schemas.loadArtifactZodSchema(
    [common, fixtureDocument],
    fixtureDocument.$id,
    "request"
  );
  for (const repositoryPath of [
    "src/index.ts",
    "./src/index.ts",
    "scope with spaces/café.ts",
    ".hidden/config.ts"
  ]) {
    assert.equal(
      validator.safeParse({ path: repositoryPath, candidateId: "candidate-1" }).success,
      true,
      repositoryPath
    );
  }
  for (const repositoryPath of [
    "/etc/passwd",
    "../outside.ts",
    "src/../outside.ts",
    "src/./outside.ts",
    "src//outside.ts",
    "C:\\outside.ts",
    "src/\0outside.ts"
  ]) {
    assert.equal(
      validator.safeParse({ path: repositoryPath, candidateId: "candidate-1" }).success,
      false,
      repositoryPath
    );
  }
  for (const candidateId of [".", "..", "../candidate", "a/b", "a\\b", "a\0b"]) {
    assert.equal(
      validator.safeParse({ path: "src/index.ts", candidateId }).success,
      false,
      candidateId
    );
  }
  assert.throws(
    () => schemas.bundleArtifactSchema([common], "missing", "request"),
    /Unknown Pi Security schema document/
  );
  assert.throws(
    () => schemas.bundleArtifactSchema([common, common], common.$id, "repositoryPath"),
    /Duplicate Pi Security schema document/
  );
}

async function testScanContext() {
  const root = path.join(fixture, "scan");
  const repoRoot = path.join(fixture, "repository");
  await Promise.all([
    mkdir(root, { recursive: true }),
    mkdir(repoRoot, { recursive: true })
  ]);
  const scanId = "61a20957-1be8-4ccf-8de8-eab4061e8cc3";
  const contract = {
    target: {
      allowedKinds: ["directory_snapshot"],
      targetId: "target-1",
      requiredSnapshotDigest: "sha256:fixture"
    },
    scope: {
      requiredIncludePaths: ["."],
      requiredExcludePaths: []
    }
  };
  const calls = [];
  const runWorkbench = async (args) => {
    calls.push(args);
    return {
      scan: {
        scanId,
        scanDir: root,
        targetPath: repoRoot,
        scope: ".",
        mode: "deep",
        progress: { status: "running" },
        contract,
        handoffClaimToken: "fixture-claim"
      }
    };
  };
  const context = await contextApi.createScanArtifactContext(
    scanId,
    runWorkbench,
    {
      requireRunning: true,
      requireClaim: true,
      handoffClaimToken: "fixture-claim",
      packageRoot: "/fixture/package",
      pythonCommand: "python3"
    }
  );
  assert.deepEqual(calls, [["get-scan", "--scan-id", scanId]]);
  assert.equal(context.root, await realpath(root));
  assert.equal(context.repoRoot, await realpath(repoRoot));
  assert.equal(context.layout, "scan");
  assert.equal(context.scope, ".");
  assert.equal(context.mode, "deep");
  assert.deepEqual(context.targetContract, contract);
  assert.equal(context.targetSnapshotDigest, "sha256:fixture");
  assert.equal(context.handoffClaimToken, "fixture-claim");
  assert.equal(context.packageRoot, "/fixture/package");
  assert.equal(context.pythonCommand, "python3");

  await assert.rejects(
    contextApi.createScanArtifactContext(scanId, runWorkbench, {
      requireClaim: true,
      handoffClaimToken: "different-claim"
    }),
    /different continuation/
  );
  await assert.rejects(
    contextApi.createScanArtifactContext(scanId, async () => ({
      scan: {
        scanId,
        scanDir: root,
        targetPath: repoRoot,
        progress: { status: "completed" }
      }
    }), { requireRunning: true }),
    /not running/
  );
  await assert.rejects(
    contextApi.createScanArtifactContext(scanId, async () => ({
      scan: { scanId: "different", scanDir: root, targetPath: repoRoot }
    })),
    /requested scan identity/
  );
  await assert.rejects(
    contextApi.createScanArtifactContext(scanId, async () => ({
      scan: {
        scanId,
        scanDir: root,
        targetPath: repoRoot,
        mode: "deep",
        progress: { status: "running" }
      }
    }), {
      requireClaim: true,
    }),
    /no authoritative continuation claim/
  );
  const creatorContext = await contextApi.createScanArtifactContext(
    scanId,
    async () => ({
      scan: {
        scanId,
        scanDir: root,
        targetPath: repoRoot,
        mode: "deep",
        progress: { status: "running" }
      }
    }),
    {
      requireClaim: true,
      claimlessWriteAuthorization: "creator",
    }
  );
  assert.equal(creatorContext.scanId, scanId);
  const rejoinedContext = await contextApi.createScanArtifactContext(
    scanId,
    async () => ({
      scan: {
        scanId,
        scanDir: root,
        targetPath: repoRoot,
        mode: "deep",
        progress: { status: "running" }
      }
    }),
    {
      requireClaim: true,
      claimlessWriteAuthorization: "owning_thread_live_rejoin",
    }
  );
  assert.equal(rejoinedContext.scanId, scanId);
}

async function testWorkerStandardLayout() {
  const root = path.join(fixture, "worker", "output");
  const repoRoot = path.join(fixture, "repository");
  await mkdir(root, { recursive: true });
  const context = await boundArtifactContext(root, repoRoot, "worker", {
    scope: ".",
    packageRoot: "/fixture/package",
  });
  const inventory = await io.artifactDestination(
    context,
    ["artifacts", "02_discovery", "in_scope_files.txt"],
    "review_items"
  );
  const candidates = await io.artifactDestination(
    context,
    ["artifacts", "02_discovery", "candidate_ledger.jsonl"],
    "discovery_candidates"
  );
  assert.equal(
    inventory,
    path.join(
      await realpath(root),
      "artifacts",
      "02_discovery",
      "in_scope_files.txt"
    )
  );
  assert.equal(
    candidates,
    path.join(
      await realpath(root),
      "artifacts",
      "02_discovery",
      "candidate_ledger.jsonl"
    )
  );
  assert.equal(context.layout, "worker");
  assert.equal(context.scope, ".");

  const reducerScanRoot = path.join(fixture, "reducer-scan");
  const reducerRoot = path.join(reducerScanRoot, "dedup", "output");
  const workerResult = path.join(reducerScanRoot, "workers", "worker-1", "result.json");
  await mkdir(path.dirname(workerResult), { recursive: true });
  await mkdir(reducerRoot, { recursive: true });
  await writeFile(workerResult, "{}\n");
  const reducerPolicy = createExecutionPolicyContext({
    profile: "security-artifact-writer",
    target: { root: repoRoot },
    scan: { id: artifactScanId, artifactRoot: reducerRoot },
  });
  await assert.rejects(
    contextApi.createWorkerArtifactContext({
      root: reducerRoot,
      repoRoot,
      scanId: artifactScanId,
      deepReducer: {
        scanRoot: reducerScanRoot,
        claimedWorkers: [{ id: "worker-1", resultPath: workerResult }],
      },
      executionPolicy: reducerPolicy,
    }),
    /reducer-bound context/
  );
  const reducer = await contextApi.createWorkerArtifactContext({
    root: reducerRoot,
    repoRoot,
    layout: "reducer",
    scanId: artifactScanId,
    deepReducer: {
      scanRoot: reducerScanRoot,
      claimedWorkers: [
        { id: "worker-1", resultPath: workerResult }
      ]
    },
    executionPolicy: reducerPolicy,
  });
  assert.equal(reducer.layout, "reducer");
  assert.equal(reducer.deepReducer.claimedWorkers[0].id, "worker-1");
}

async function testSafeJsonAndJsonl() {
  const context = await boundArtifactContext(
    path.join(fixture, "scan"),
    path.join(fixture, "repository")
  );
  const components = ["artifacts", "02_discovery", "candidate_ledger.jsonl"];
  const destination = await io.artifactDestination(
    context,
    components,
    "discovery_candidates"
  );
  await io.replaceArtifactJsonl(context, destination, [
    { candidate_id: "one", extension: "preserved" },
    { candidate_id: "two" }
  ]);
  const rowSchema = {
    safeParse(value) {
      return value && typeof value.candidate_id === "string"
        ? { success: true, data: value }
        : { success: false, error: { issues: [
          { path: ["candidate_id"], message: "required" }
        ] } };
    }
  };
  assert.deepEqual(
    await io.readArtifactJsonl(
      context,
      components,
      "discovery_candidates",
      rowSchema
    ),
    [
      { candidate_id: "one", extension: "preserved" },
      { candidate_id: "two" }
    ]
  );

  const manifestComponents = ["scan-manifest.json"];
  const manifest = await io.artifactDestination(
    context,
    manifestComponents,
    "scan_manifest"
  );
  await io.replaceArtifactJson(context, manifest, { scanId: "fixture", extension: true });
  assert.deepEqual(
    await io.readArtifactJsonObject(context, manifestComponents, "scan_manifest"),
    { scanId: "fixture", extension: true }
  );
  await io.replaceArtifactText(context, destination, '{"candidate_id":"valid"}\nnot-json\n');
  await assert.rejects(
    io.readArtifactJsonl(context, components, "discovery_candidates", rowSchema),
    /row 2 is not valid JSON/
  );
  await io.replaceArtifactText(context, destination, '{"other":"missing"}\n');
  await assert.rejects(
    io.readArtifactJsonl(context, components, "discovery_candidates", rowSchema),
    /row 1 does not match its artifact schema: candidate_id: required/
  );
}

async function testAtomicReplaceAndAppend() {
  const context = await boundArtifactContext(
    path.join(fixture, "scan"),
    path.join(fixture, "repository")
  );
  const components = ["artifacts", "02_discovery", "candidate_ledger.jsonl"];
  const destination = await io.artifactDestination(
    context,
    components,
    "discovery_candidates"
  );
  await io.replaceArtifactJsonl(context, destination, []);
  assert.equal(await readFile(destination, "utf8"), "");

  await writeFile(destination, '{"candidate_id":"without-newline"}', "utf8");
  await io.appendArtifactJsonl(context, destination, [{ candidate_id: "appended" }]);
  assert.deepEqual(
    await io.readArtifactJsonl(context, components, "discovery_candidates"),
    [
      { candidate_id: "without-newline" },
      { candidate_id: "appended" }
    ]
  );

  await io.replaceArtifactJsonl(context, destination, []);
  await Promise.all(
    Array.from({ length: 12 }, (_, index) => io.appendArtifactJsonl(context, destination, [{ candidate_id: "concurrent-" + index }]))
  );
  const rows = await io.readArtifactJsonl(
    context,
    components,
    "discovery_candidates"
  );
  assert.equal(rows.length, 12);
  assert.deepEqual(
    rows.map((row) => row.candidate_id).sort(),
    Array.from({ length: 12 }, (_, index) => "concurrent-" + index).sort()
  );
}

async function testBoundedPagination() {
  const rows = [
    { path: "./src/first.ts" },
    { path: "scope with spaces/café.ts" },
    { path: "src/third.ts" }
  ];
  assert.deepEqual(io.paginateArtifactRows(rows, { limit: 2 }, "review_items"), {
    rows: rows.slice(0, 2),
    nextCursor: "2"
  });
  assert.deepEqual(
    io.paginateArtifactRows(rows, { cursor: "2", limit: 2 }, "review_items"),
    { rows: rows.slice(2) }
  );
  assert.throws(
    () => io.paginateArtifactRows(rows, { cursor: "-1" }, "review_items"),
    /non-negative integer/
  );
  assert.throws(
    () => io.paginateArtifactRows(rows, { cursor: "4" }, "review_items"),
    /outside the available rows/
  );
  assert.throws(
    () => io.paginateArtifactRows(rows, { limit: 1001 }, "review_items"),
    /1 through 1000/
  );
}

async function testArtifactDestinationSwap() {
  if (process.platform === "win32") return;
  const context = await boundArtifactContext(
    path.join(fixture, "scan"),
    path.join(fixture, "repository")
  );
  const destination = await io.artifactDestination(
    context,
    ["swap", "result.json"],
    "artifact swap"
  );
  const destinationDirectory = path.dirname(destination);
  const originalDirectory = destinationDirectory + "-original";
  const outsideDirectory = path.join(fixture, "outside-artifacts");
  await mkdir(outsideDirectory);
  await rename(destinationDirectory, originalDirectory);
  await symlink(outsideDirectory, destinationDirectory);
  await assert.rejects(
    io.replaceArtifactJson(context, destination, { escaped: true }),
    /destination directory is not safe/
  );
  await assert.rejects(readFile(path.join(outsideDirectory, "result.json"), "utf8"));
}

async function testUnsafeArtifacts() {
  const context = await boundArtifactContext(
    path.join(fixture, "scan"),
    path.join(fixture, "repository")
  );
  for (const components of [
    [],
    ["..", "outside.json"],
    [".", "outside.json"],
    ["artifacts/02_discovery", "candidate_ledger.jsonl"],
    ["artifacts", "..", "outside.json"],
    ["artifacts", "bad\0name"]
  ]) {
    await assert.rejects(
      io.artifactDestination(context, components, "discovery_candidates"),
      /fixed artifact destination|unsafe/
    );
  }

  await assert.rejects(
    io.artifactDestination(
      {
        root: context.root,
        repoRoot: context.repoRoot,
        layout: "scan",
        scanId: context.scanId,
      },
      ["missing-policy.json"],
      "missing policy"
    ),
    /requires an issued execution policy/
  );

  const outside = path.join(fixture, "outside");
  await mkdir(outside, { recursive: true });
  const symlinkPath = path.join(context.root, "linked");
  await symlink(outside, symlinkPath);
  await assert.rejects(
    io.artifactDestination(
      context,
      ["linked", "candidate_ledger.jsonl"],
      "discovery_candidates"
    ),
    /not a regular directory/
  );

  const linkedFile = path.join(context.root, "linked.json");
  await symlink(
    path.join(outside, "outside.json"),
    linkedFile
  );
  await assert.rejects(
    io.artifactDestination(context, ["linked.json"], "scan_manifest"),
    /not a regular file/
  );
}
