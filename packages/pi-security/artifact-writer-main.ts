import { resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as z from "zod/v4";
import {
  createWorkerArtifactContext,
  type DeepReducerContext
} from "./src/artifact-context.js";
import {
  assertExecutionTargetRoot,
  canonicalBoundDirectory,
  canonicalPathInside,
  validateRepositoryRelativeScope,
} from "./src/execution-boundary.js";
import { createExecutionPolicyContext } from "./src/execution-policy.js";
import { registerCompactWorkerArtifactTools } from "./src/server/compact-artifact-tools.js";
import type { LifecycleToolRegistrar } from "./src/server/lifecycle-catalog.js";
import { MCP_APP_VERSION } from "./src/version.js";

/** Build the narrow worker-only MCP from coordinator-inherited state. */
export async function createPiSecurityArtifactWriterServer(
  environment: NodeJS.ProcessEnv = process.env
): Promise<McpServer> {
  const [root, repoRoot] = await Promise.all([
    canonicalBoundDirectory(
      requiredEnvironment(environment, "PI_SECURITY_ARTIFACT_ROOT"),
      "Pi Security worker artifact root",
    ),
    canonicalBoundDirectory(
      requiredEnvironment(environment, "PI_SECURITY_REPO_ROOT"),
      "Pi Security worker target root",
    ),
  ]);
  const scanId = z.string().uuid().parse(
    requiredEnvironment(environment, "PI_SECURITY_SCAN_ID")
  );
  const scope = validateRepositoryRelativeScope(
    requiredEnvironment(environment, "PI_SECURITY_SCOPE")
  );
  const executionPolicy = createExecutionPolicyContext({
    profile: "security-artifact-writer",
    target: { root: repoRoot },
    scan: { id: scanId, artifactRoot: root },
  });
  await assertExecutionTargetRoot(
    executionPolicy,
    repoRoot,
    "scan-artifacts.write",
  );
  await canonicalPathInside(
    repoRoot,
    resolve(repoRoot, scope),
    "directory",
    "Pi Security worker target scope",
    true,
  );
  const layout = environment.PI_SECURITY_ARTIFACT_LAYOUT ?? "worker";
  if (layout !== "worker" && layout !== "reducer") {
    throw new Error("PI_SECURITY_ARTIFACT_LAYOUT must be worker or reducer.");
  }

  const deepReducer = environment.PI_SECURITY_REDUCER_CONTEXT_JSON
    ? parseReducerContext(environment.PI_SECURITY_REDUCER_CONTEXT_JSON)
    : undefined;

  if ((layout === "reducer") !== (deepReducer !== undefined)) {
    throw new Error("A reducer worker requires exactly its coordinator-bound reducer context.");
  }

  const context = await createWorkerArtifactContext({
    root,
    repoRoot,
    layout,
    scanId,
    scope,
    ...(environment.PI_SECURITY_PACKAGE_ROOT
      ? { packageRoot: environment.PI_SECURITY_PACKAGE_ROOT }
      : {}),
    ...(environment.PI_SECURITY_PYTHON_COMMAND
      ? { pythonCommand: environment.PI_SECURITY_PYTHON_COMMAND }
      : {}),
    ...(deepReducer ? { deepReducer } : {}),
    executionPolicy,
  });
  const server = new McpServer({
    name: "pi-security-artifacts",
    version: MCP_APP_VERSION
  });
  registerCompactWorkerArtifactTools(
    server as unknown as LifecycleToolRegistrar,
    context
  );
  return server;
}

function requiredEnvironment(
  environment: NodeJS.ProcessEnv,
  name: string
): string {
  const value = environment[name];
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${name} must be bound by the Pi Security coordinator.`);
  }
  return value;
}

function parseReducerContext(value: string): DeepReducerContext {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch (error) {
    throw new Error("The coordinator-bound Deep reducer context is not valid JSON.", {
      cause: error
    });
  }
  const record = parsed as Record<string, unknown>;
  if (
    !parsed
    || typeof parsed !== "object"
    || Array.isArray(parsed)
    || typeof record.scanRoot !== "string"
    || !Array.isArray(record.claimedWorkers)
    || record.claimedWorkers.some((worker) => (
      !worker
      || typeof worker !== "object"
      || Array.isArray(worker)
      || typeof (worker as Record<string, unknown>).id !== "string"
      || !(worker as Record<string, unknown>).id
      || typeof (worker as Record<string, unknown>).resultPath !== "string"
    ))
    || (
      record.previousReducerResultPath !== undefined
      && typeof record.previousReducerResultPath !== "string"
    )
  ) {
    throw new Error("The coordinator-bound Deep reducer context is incomplete.");
  }
  return parsed as DeepReducerContext;
}
