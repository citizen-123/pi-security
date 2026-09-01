import {
  assertExecutionArtifactRoot,
  assertExecutionTargetRoot,
  assertPathInside,
  assertTrustedArtifactContext,
  canonicalBoundDirectory,
  canonicalPathInside,
} from "./execution-boundary.js";
import {
  assertExecutionCapability,
  createExecutionPolicyContext,
  type ExecutionPolicyContext,
} from "./execution-policy.js";
import type {
  ArtifactContext,
  DeepReducerContext,
} from "./artifact-io.js";

export type {
  ArtifactContext,
  DeepReducerContext,
  DeepReducerWorkerContext
} from "./artifact-io.js";

export type RunArtifactWorkbench = (
  arguments_: string[]
) => Promise<Record<string, unknown>>;

export interface ScanArtifactContextOptions {
  requireRunning?: boolean;
  requireClaim?: boolean;
  handoffClaimToken?: string;
  /** Workbench-authenticated claimless Deep creator or owning-thread rejoin. */
  claimlessWriteAuthorization?: "creator" | "owning_thread_live_rejoin";
  packageRoot?: string;
  pythonCommand?: string;
}

export interface WorkerArtifactContextInput {
  root: string;
  repoRoot: string;
  layout?: "worker" | "reducer";
  scanId: string;
  scope?: string;
  packageRoot?: string;
  pythonCommand?: string;
  targetContract?: Readonly<Record<string, unknown>>;
  targetRevision?: string;
  targetSnapshotDigest?: string;
  handoffClaimToken?: string;
  status?: string;
  mode?: string;
  deepReducer?: ArtifactContext["deepReducer"];
  executionPolicy: ExecutionPolicyContext;
}

/**
 * Resolve parent artifacts from their authoritative, persisted workbench scan.
 */
export async function createScanArtifactContext(
  scanId: string,
  runWorkbench: RunArtifactWorkbench,
  options: ScanArtifactContextOptions = {}
): Promise<ArtifactContext> {
  if (!scanId.trim()) {
    throw new Error("Pi Security artifact context requires a scan identity.");
  }

  const result = await runWorkbench(["get-scan", "--scan-id", scanId]);
  const scan = scanRecord(result, scanId);
  const progress = asRecord(scan.progress);
  const status = optionalString(progress?.status)
    ?? optionalString(scan.status);
  if (options.requireRunning && status !== "running") {
    throw new Error(
      "Pi Security scan "
      + scanId
      + " is not running; its artifacts cannot be modified."
    );
  }

  const expectedClaim = optionalString(scan.handoffClaimToken);
  const suppliedClaim = optionalString(options.handoffClaimToken);
  if (suppliedClaim !== undefined && suppliedClaim !== expectedClaim) {
    throw new Error(
      "Pi Security scan "
      + scanId
      + " is owned by a different continuation."
    );
  }
  if (options.requireClaim) {
    const authenticatedClaim = expectedClaim !== undefined
      && suppliedClaim === expectedClaim;
    const authenticatedClaimlessWriter = (
      options.claimlessWriteAuthorization === "creator"
      || options.claimlessWriteAuthorization === "owning_thread_live_rejoin"
    )
      && expectedClaim === undefined
      && optionalString(scan.mode) === "deep";
    if (!authenticatedClaim && !authenticatedClaimlessWriter) {
      throw new Error(
        expectedClaim === undefined
          ? "Pi Security scan " + scanId
            + " has no authoritative continuation claim; only its authenticated creator or owning-thread live rejoin may write artifacts."
          : "Pi Security scan " + scanId
            + " requires its current continuation claim."
      );
    }
  }

  const rawRoot = requireString(
    scan.scanDir,
    "Pi Security scan " + scanId + " has no bound artifact context."
  );
  const rawRepoRoot = requireString(
    scan.targetPath,
    "Pi Security scan " + scanId + " has no bound target context."
  );
  const [root, repoRoot] = await Promise.all([
    canonicalBoundDirectory(rawRoot, "Pi Security scan artifact root"),
    canonicalBoundDirectory(rawRepoRoot, "Pi Security scan target root"),
  ]);
  const executionPolicy = createExecutionPolicyContext({
    profile: "security-artifact-writer",
    target: { root: repoRoot },
    scan: { id: scanId, artifactRoot: root },
  });
  await assertTrustedArtifactContext({
    context: executionPolicy,
    artifactRoot: root,
    targetRoot: repoRoot,
  });
  const targetContract = asRecord(scan.contract);
  const contractTarget = asRecord(targetContract?.target);
  return {
    root,
    repoRoot,
    layout: "scan",
    scanId,
    ...defined("scope", optionalString(scan.scope)),
    ...defined("packageRoot", options.packageRoot),
    ...defined("pythonCommand", options.pythonCommand),
    ...defined("targetContract", targetContract),
    ...defined("targetRevision", optionalString(scan.targetRevision)),
    ...defined(
      "targetSnapshotDigest",
      optionalString(scan.targetSnapshotDigest)
      ?? optionalString(contractTarget?.requiredSnapshotDigest)
    ),
    ...defined("handoffClaimToken", expectedClaim),
    ...defined("status", status),
    ...defined("mode", optionalString(scan.mode)),
    executionPolicy
  };
}

/**
 * Bind a lightweight worker to host-supplied state, never model-supplied paths.
 */
export async function createWorkerArtifactContext(
  input: WorkerArtifactContextInput
): Promise<ArtifactContext> {
  assertExecutionCapability(input.executionPolicy, "scan-artifacts.write");
  if (!input.scanId.trim() || input.executionPolicy.scan.id !== input.scanId) {
    throw new Error("Pi Security worker execution context belongs to a different scan.");
  }
  const layout = input.layout ?? "worker";
  if (layout !== "worker" && layout !== "reducer") {
    throw new Error("Pi Security worker artifact layout is invalid.");
  }
  const [root, repoRoot] = await Promise.all([
    assertExecutionArtifactRoot(input.executionPolicy, input.root),
    assertExecutionTargetRoot(
      input.executionPolicy,
      input.repoRoot,
      "scan-artifacts.write",
    ),
  ]);
  await assertTrustedArtifactContext({
    context: input.executionPolicy,
    artifactRoot: root,
    targetRoot: repoRoot,
  });
  const deepReducer = input.deepReducer
    ? await bindReducerContext(input.deepReducer, root)
    : undefined;
  const context: ArtifactContext = {
    root,
    repoRoot,
    layout,
    scanId: input.scanId,
    ...defined("scope", input.scope),
    ...defined("packageRoot", input.packageRoot),
    ...defined("pythonCommand", input.pythonCommand),
    ...defined("targetContract", input.targetContract),
    ...defined("targetRevision", input.targetRevision),
    ...defined("targetSnapshotDigest", input.targetSnapshotDigest),
    ...defined("handoffClaimToken", input.handoffClaimToken),
    ...defined("status", input.status),
    ...defined("mode", input.mode),
    ...defined("deepReducer", deepReducer),
    executionPolicy: input.executionPolicy
  };
  if (context.deepReducer && layout !== "reducer") {
    throw new Error("Pi Security reducer state requires a reducer-bound context.");
  }
  return context;
}

async function bindReducerContext(
  input: DeepReducerContext,
  artifactRoot: string
): Promise<DeepReducerContext> {
  const scanRoot = await canonicalBoundDirectory(
    input.scanRoot,
    "Pi Security reducer scan root"
  );
  assertPathInside(scanRoot, artifactRoot, "Pi Security reducer output root");
  if (input.claimedWorkers.length === 0) {
    throw new Error("Pi Security reducer context has no claimed workers.");
  }
  const workerIds = new Set<string>();
  const claimedWorkers = [];
  for (const worker of input.claimedWorkers) {
    if (!worker.id.trim() || workerIds.has(worker.id)) {
      throw new Error("Pi Security reducer context has an invalid worker identity.");
    }
    workerIds.add(worker.id);
    const result = await canonicalPathInside(
      scanRoot,
      worker.resultPath,
      "file",
      "Pi Security reducer worker result"
    );
    claimedWorkers.push({ id: worker.id, resultPath: result.absolute });
  }
  const previousReducerResultPath = input.previousReducerResultPath === undefined
    ? undefined
    : (await canonicalPathInside(
      scanRoot,
      input.previousReducerResultPath,
      "file",
      "Pi Security previous reducer result"
    )).absolute;
  return {
    scanRoot,
    claimedWorkers,
    ...defined("previousReducerResultPath", previousReducerResultPath)
  };
}

function scanRecord(
  result: Record<string, unknown>,
  scanId: string
): Record<string, unknown> {
  const nested = asRecord(result.scan);
  const direct = result.scanId === scanId ? result : undefined;
  const scan = nested ?? direct;
  if (!scan || scan.scanId !== scanId) {
    throw new Error(
      "Pi Security workbench did not return the requested scan identity."
    );
  }
  return scan;
}


function requireString(value: unknown, message: string): string {
  const result = optionalString(value);
  if (!result) throw new Error(message);
  return result;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function defined<Key extends string, Value>(
  key: Key,
  value: Value | undefined
): Partial<Record<Key, Value>> {
  return value === undefined ? {} : { [key]: value } as Record<Key, Value>;
}
