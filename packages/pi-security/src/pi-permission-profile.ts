import {
  createExecutionPolicyContext,
  ExecutionPolicyDeniedError,
  hasExecutionCapability,
  type ExecutionCapability,
  type ExecutionPolicyContext,
} from "./execution-policy.js";

export const PI_PACKAGED_SECURITY_AGENTS = Object.freeze([
  "pi-security-scout",
  "pi-security-auditor",
  "pi-security-validator",
  "pi-security-reviewer",
] as const);
export type PiPackagedSecurityAgent = typeof PI_PACKAGED_SECURITY_AGENTS[number];

export type PiPermissionSurface =
  | "lifecycle"
  | "workbench"
  | "artifact"
  | "delegation";

export interface PiPermissionBindings {
  readonly targetRoot: string;
  readonly scanId: string;
  readonly artifactRoot: string;
}

const PI_SURFACE_CAPABILITY: Readonly<Record<PiPermissionSurface, ExecutionCapability>> =
  Object.freeze({
    lifecycle: "workbench.execute",
    workbench: "workbench.execute",
    artifact: "scan-artifacts.write",
    delegation: "delegation.create",
  });

const PI_PACKAGED_TOOL_REQUIREMENTS = Object.freeze([
  ["read", "target.read"],
  ["grep", "target.search"],
  ["find", "target.search"],
  ["ls", "target.read"],
] as const satisfies readonly (readonly [string, ExecutionCapability])[]);

export function issuePiLifecycleContext(
  bindings: PiPermissionBindings,
): ExecutionPolicyContext {
  return issuePiArtifactAuthority(bindings);
}

export function issuePiWorkbenchContext(
  bindings: PiPermissionBindings,
): ExecutionPolicyContext {
  return issuePiArtifactAuthority(bindings);
}

export function issuePiArtifactContext(
  bindings: PiPermissionBindings,
): ExecutionPolicyContext {
  return issuePiArtifactAuthority(bindings);
}

export function issuePiDelegatingAgentContext(
  bindings: PiPermissionBindings,
  budget: number,
): ExecutionPolicyContext {
  return createExecutionPolicyContext({
    profile: "security-delegating-readonly",
    target: { root: bindings.targetRoot },
    scan: { id: bindings.scanId, artifactRoot: bindings.artifactRoot },
    delegation: { budget },
  });
}

export function issuePiPackagedAgentContext(
  agent: string,
  bindings: PiPermissionBindings,
): ExecutionPolicyContext {
  assertPiPackagedSecurityAgent(agent);
  return createExecutionPolicyContext({
    profile: "security-readonly",
    target: { root: bindings.targetRoot },
    scan: { id: bindings.scanId, artifactRoot: bindings.artifactRoot },
  });
}

export function piPackagedAgentToolAllowlist(
  context: ExecutionPolicyContext,
): string[] {
  return PI_PACKAGED_TOOL_REQUIREMENTS
    .filter(([, capability]) => hasExecutionCapability(context, capability))
    .map(([name]) => name);
}

export function piPermissionSurfaceAllowed(
  context: ExecutionPolicyContext,
  surface: PiPermissionSurface,
): boolean {
  return hasExecutionCapability(context, PI_SURFACE_CAPABILITY[surface]);
}

export function assertPiPermissionSurface(
  context: ExecutionPolicyContext,
  surface: PiPermissionSurface,
  toolName: string,
): void {
  if (!piPermissionSurfaceAllowed(context, surface)) {
    throw new ExecutionPolicyDeniedError(
      `Pi Security tool ${JSON.stringify(toolName)} is not allowed by its fixed ${surface} profile.`,
    );
  }
}

export function assertPiPackagedSecurityAgent(
  value: string,
): asserts value is PiPackagedSecurityAgent {
  if (!(PI_PACKAGED_SECURITY_AGENTS as readonly string[]).includes(value)) {
    throw new Error(`Unknown packaged Pi Security agent ${JSON.stringify(value)}.`);
  }
}

function issuePiArtifactAuthority(
  bindings: PiPermissionBindings,
): ExecutionPolicyContext {
  return createExecutionPolicyContext({
    profile: "security-artifact-writer",
    target: { root: bindings.targetRoot },
    scan: { id: bindings.scanId, artifactRoot: bindings.artifactRoot },
  });
}
