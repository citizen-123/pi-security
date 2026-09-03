import {
  describeExecutionPolicy,
  type ExecutionCapabilitySet,
  type ExecutionPolicyContext,
  type ExecutionPolicyDescription,
  type ExecutionProfileName,
} from "./execution-policy.js";

export const PI_SECURITY_ENFORCEMENT_UNSUPPORTED =
  "PI_SECURITY_ENFORCEMENT_UNSUPPORTED" as const;
export const PI_SECURITY_POLICY_RECOVERY_REJECTED =
  "PI_SECURITY_POLICY_RECOVERY_REJECTED" as const;

export type PlatformEnforcementMechanism =
  | "platform.posix-open-no-follow"
  | "platform.linux-proc-self-fd"
  | "platform.posix-dev-fd"
  | "platform.windows-reparse-identity";

export type PiEnforcementMechanism =
  | "pi.fixed-profile-tool-dispatch"
  | "pi.worker-session.tools"
  | "target.verified-open-handle"
  | "artifact.canonical-root-binding"
  | "workbench.fixed-bundled-command"
  | "continuation.exact-policy-reissue"
  | PlatformEnforcementMechanism;

export interface EnforcementCapabilityReport {
  readonly schemaVersion: 1;
  /** Availability is a pre-side-effect negotiation; effective means every listed mechanism ran. */
  readonly kind: "availability" | "effective";
  readonly supported: boolean;
  readonly mechanisms: readonly PiEnforcementMechanism[];
  readonly unsupportedReason: string | null;
}

export interface PublicExecutionPolicyDiagnostics {
  readonly schemaVersion: 1;
  readonly profile: ExecutionProfileName;
  readonly capabilities: ExecutionCapabilitySet;
  readonly delegation: Readonly<{
    maxDepth: number;
    remainingBudget: number;
    remainingDepth: number;
    childProfile: ExecutionProfileName | null;
    spent: boolean;
  }>;
}

export interface EffectivePolicyDiagnostics {
  readonly schemaVersion: 1;
  readonly source: PublicExecutionPolicyDiagnostics;
  readonly artifactWriter: PublicExecutionPolicyDiagnostics;
  readonly enforcement: EnforcementCapabilityReport;
}

export interface PiEnforcementAvailability {
  readonly kind: "availability" | "effective";
  readonly piTools: boolean;
  readonly workerSessions?: boolean;
  readonly targetHandles?: boolean;
  readonly artifactRoots?: boolean;
  readonly trustedWorkbench?: boolean;
  readonly continuationPolicy?: boolean;
  readonly platformMechanisms?: readonly PlatformEnforcementMechanism[];
}

const WORKER_SESSIONS_UNSUPPORTED =
  "Deep Scan requires isolated native Pi worker sessions with exact custom-tool allowlists.";

const UNSUPPORTED_REASON = Object.freeze({
  piTools: "Pi Security requires fixed-profile tool registration and direct-dispatch authorization; this host cannot enforce it.",
  workerSessions: WORKER_SESSIONS_UNSUPPORTED,
  targetHandles: "Pi Security requires verified no-follow directory handles for target access; this platform cannot enforce them.",
  artifactRoots: "Pi Security requires canonical scan-bound artifact roots; this host cannot enforce them.",
  trustedWorkbench: "Pi Security requires fixed bundled-workbench dispatch; this host cannot enforce it.",
  continuationPolicy: "Pi Security requires exact continuation-policy reissue; this host cannot enforce it.",
});

/** Describe only closed, host-observed mechanisms in deterministic order. */
export function describePiEnforcementCapabilities(
  input: PiEnforcementAvailability,
): EnforcementCapabilityReport {
  const mechanisms: PiEnforcementMechanism[] = [];
  if (input.piTools) mechanisms.push("pi.fixed-profile-tool-dispatch");
  if (input.workerSessions === true) mechanisms.push("pi.worker-session.tools");
  if (input.targetHandles === true) mechanisms.push("target.verified-open-handle");
  if (input.artifactRoots === true) mechanisms.push("artifact.canonical-root-binding");
  if (input.trustedWorkbench === true) mechanisms.push("workbench.fixed-bundled-command");
  if (input.continuationPolicy === true) mechanisms.push("continuation.exact-policy-reissue");
  for (const mechanism of input.platformMechanisms ?? []) {
    if (!mechanisms.includes(mechanism)) mechanisms.push(mechanism);
  }

  const unsupportedReason = input.piTools === false
    ? UNSUPPORTED_REASON.piTools
    : input.workerSessions === false
      ? UNSUPPORTED_REASON.workerSessions
      : input.targetHandles === false
        ? UNSUPPORTED_REASON.targetHandles
        : input.artifactRoots === false
          ? UNSUPPORTED_REASON.artifactRoots
          : input.trustedWorkbench === false
            ? UNSUPPORTED_REASON.trustedWorkbench
            : input.continuationPolicy === false
              ? UNSUPPORTED_REASON.continuationPolicy
              : null;
  return Object.freeze({
    schemaVersion: 1 as const,
    kind: input.kind,
    supported: unsupportedReason === null,
    mechanisms: Object.freeze(mechanisms),
    unsupportedReason,
  });
}

export function assertPiEnforcementSupported(
  report: EnforcementCapabilityReport,
): void {
  if (report.supported) return;
  throw new EnforcementUnsupportedError(
    report.unsupportedReason ?? "Pi Security cannot enforce the required host capabilities.",
  );
}

export function describeEffectivePolicyDiagnostics(input: {
  readonly source: ExecutionPolicyContext;
  readonly artifactWriter: ExecutionPolicyContext;
  readonly enforcement: EnforcementCapabilityReport;
}): EffectivePolicyDiagnostics {
  if (input.enforcement.kind !== "effective" || !input.enforcement.supported) {
    throw new EnforcementUnsupportedError(
      "Effective policy diagnostics require enforcement mechanisms that were successfully applied.",
    );
  }
  const source = describeExecutionPolicy(input.source);
  const artifactWriter = describeExecutionPolicy(input.artifactWriter);
  return Object.freeze({
    schemaVersion: 1 as const,
    source: publicPolicyProjection(source),
    artifactWriter: publicPolicyProjection(artifactWriter),
    enforcement: input.enforcement,
  });
}

function publicPolicyProjection(
  policy: ExecutionPolicyDescription,
): PublicExecutionPolicyDiagnostics {
  return Object.freeze({
    schemaVersion: 1 as const,
    profile: policy.profile,
    capabilities: policy.capabilities,
    delegation: policy.delegation,
  });
}

export class EnforcementUnsupportedError extends Error {
  readonly code = PI_SECURITY_ENFORCEMENT_UNSUPPORTED;
  readonly category = "unsupported_enforcement" as const;

  constructor(reason: string, options?: ErrorOptions) {
    super(`${PI_SECURITY_ENFORCEMENT_UNSUPPORTED}: ${reason}`, options);
    this.name = "EnforcementUnsupportedError";
  }
}

export type PolicyRecoveryRejectionReason =
  | "legacy_continuation"
  | "profile_mismatch"
  | "invalid_policy"
  | "delegation_mismatch"
  | "binding_mismatch";

export type PolicyEnforcementFailureIdentity =
  | Readonly<{
      schemaVersion: 1;
      code: typeof PI_SECURITY_ENFORCEMENT_UNSUPPORTED;
      category: "unsupported_enforcement";
      message: string;
    }>
  | Readonly<{
      schemaVersion: 1;
      code: typeof PI_SECURITY_POLICY_RECOVERY_REJECTED;
      category: "policy_recovery_rejected";
      reason: PolicyRecoveryRejectionReason;
      message: string;
    }>;

export class PolicyRecoveryRejectedError extends Error {
  readonly code = PI_SECURITY_POLICY_RECOVERY_REJECTED;
  readonly category = "policy_recovery_rejected" as const;

  constructor(
    readonly reason: PolicyRecoveryRejectionReason,
    message: string,
    options?: ErrorOptions,
  ) {
    super(`${PI_SECURITY_POLICY_RECOVERY_REJECTED}: ${message}`, options);
    this.name = "PolicyRecoveryRejectedError";
  }
}

export function isPolicyEnforcementFailure(
  error: unknown,
): error is EnforcementUnsupportedError | PolicyRecoveryRejectedError {
  return error instanceof EnforcementUnsupportedError
    || error instanceof PolicyRecoveryRejectedError;
}

export function describePolicyEnforcementFailure(
  error: unknown,
): PolicyEnforcementFailureIdentity | undefined {
  if (error instanceof PolicyRecoveryRejectedError) {
    return Object.freeze({
      schemaVersion: 1 as const,
      code: error.code,
      category: error.category,
      reason: error.reason,
      message: error.message,
    });
  }
  if (error instanceof EnforcementUnsupportedError) {
    return Object.freeze({
      schemaVersion: 1 as const,
      code: error.code,
      category: error.category,
      message: error.message,
    });
  }
  return undefined;
}
