import type { DeepReducerContext } from "../artifact-io.js";
import type { ExecutionPolicyContext } from "../execution-policy.js";
import type { PersistedWorkerExecutionPolicies } from "../execution-policy-continuation.js";
import type {
  EffectivePolicyDiagnostics,
  EnforcementCapabilityReport,
  PolicyEnforcementFailureIdentity,
} from "../enforcement-capabilities.js";

export type DeepScanTerminalReason = "saturated" | "capped";

export type DeepScanRunStatus =
  | "running"
  | "succeeded"
  | "canceled"
  | "failed"
  | "interrupted";

export type DeepScanWorkerKind = "setup" | "discovery" | "dedup";

export type DeepScanWorkerStatus =
  | "queued"
  | "running"
  | "succeeded"
  | "failed"
  | "canceled";

export type DeepScanMergeState = "none" | "buffered" | "merging" | "merged";

/** Effective configuration and durable run state returned by the workbench. */
export interface DeepScanConfig {
  workers: number;
  subagents: number;
  stopAfterNoNew: number;
  stopAfterConsecutiveErrors: number;
  maxDiscoveryRuns: number;
  maxTimeHours?: number;
}

export interface DeepScanCanonicalArtifacts {
  inScopeFilesPath: string;
  candidateLedgerPath: string;
}

export type DeepScanReducerArtifacts = DeepScanCanonicalArtifacts;

export interface DeepScanRunState {
  scanId: string;
  status: DeepScanRunStatus;
  phase?: "setup" | "discovery" | "reducing" | "terminal";
  coordinatorGeneration?: number;
  createdAt?: string;
  updatedAt?: string;
  targetPath: string;
  scope: string;
  userContext?: string;
  /** Persisted worker preferences selected by the owning host. */
  model?: string;
  reasoningEffort?: string;
  /** Available for coordinators completed in this process. */
  diagnostics?: DeepScanRunDiagnostics;
  scanDir: string;
  config: DeepScanConfig;
  dispatchedCount: number;
  noNewStreak: number;
  consecutiveErrors: number;
  canonicalArtifacts?: DeepScanCanonicalArtifacts;
  manifestPath?: string;
  terminalReason?: DeepScanTerminalReason;
  error?: string;
  policyFailure?: PolicyEnforcementFailureIdentity;
  persistedWorkers?: PersistedDeepScanWorker[];
  persistedDedupInputs?: PersistedDeepScanDedupInput[];
}

export interface PersistedDeepScanDedupInput {
  dedupWorkerId: string;
  discoveryWorkerId: string;
  inputOrder: number;
}

export type DeepScanArtifactWriteAuthorization =
  | "creator"
  | "owning_thread_live_rejoin";

export interface BeginDeepScanResult {
  run: DeepScanRunState;
  shouldStart: boolean;
  startDisposition: "created" | "joined";
  artifactWriteAuthorization?: DeepScanArtifactWriteAuthorization;
}

export interface DeepScanPreflightBindings {
  scanId: string;
  targetPath: string;
  scope: string;
  scanDir: string;
  subagents: number;
  resumableWorkers: PersistedDeepScanWorker[];
}

export interface DeepScanCoordinatorClaim {
  run: DeepScanRunState;
  acquired: boolean;
}

export interface DeepScanCoordinatorLeaseInput {
  scanId: string;
  threadId: string;
  handoffClaimToken?: string;
}

/** Fields supplied when the coordinator changes one worker. */
export interface DeepScanWorkerMutation {
  id: string;
  scanId: string;
  kind: DeepScanWorkerKind;
  status: DeepScanWorkerStatus;
  promptPath: string;
  artifactDir: string;
  attempt: number;
  continuationId?: string;
  resultManifestPath?: string;
  error?: string;
  policyFailure?: PolicyEnforcementFailureIdentity;
  replaceableFailureKind?: DeepScanReplaceableFailureKind;
}

export type DeepScanReplaceableFailureKind =
  | "policy_refusal"
  | "transient_error"
  | "invalid_discovery_artifacts";

/** The authoritative worker record returned after SQLite commits the change. */
export interface PersistedDeepScanWorker {
  id: string;
  kind: DeepScanWorkerKind;
  status: DeepScanWorkerStatus;
  promptPath: string;
  artifactDir: string;
  attempt: number;
  continuationId?: string;
  resultManifestPath?: string;
  completionSequence?: number;
  consecutiveErrors?: number;
  mergeState: DeepScanMergeState;
  error?: string;
}

/** Inputs committed atomically when a reducer finishes. */
export interface DedupCommit {
  id: string;
  scanId: string;
  newFindings: number;
  resultManifestPath: string;
  candidateLedgerPath?: string;
}

/** Durable operations implemented by the Python workbench. */
export interface DeepScanStore {
  preflight(input: {
    scanId: string;
    threadId: string;
    handoffClaimToken?: string;
  }): Promise<DeepScanPreflightBindings>;
  begin(input: {
    scanId?: string;
    targetPath?: string;
    scope?: string;
    userContext?: string;
    handoffClaimToken?: string;
    model?: string;
    reasoningEffort?: string;
    threadId: string;
    scanRoot?: string;
  }): Promise<BeginDeepScanResult>;
  get(scanId: string, threadId: string): Promise<DeepScanRunState>;
  claimCoordinator(input: DeepScanCoordinatorLeaseInput): Promise<DeepScanCoordinatorClaim>;
  heartbeatCoordinator(input: DeepScanCoordinatorLeaseInput): Promise<DeepScanRunState>;
  cancel(scanId: string, threadId: string): Promise<Record<string, unknown>>;
  updateWorker(update: DeepScanWorkerMutation): Promise<PersistedDeepScanWorker>;
  claimDedup(input: {
    id: string;
    scanId: string;
    workerIds: string[];
    promptPath: string;
    artifactDir: string;
  }): Promise<void>;
  commitDedup(commit: DedupCommit): Promise<DeepScanRunState>;
  finish(input: {
    scanId: string;
    reason: DeepScanTerminalReason;
    manifestPath: string;
    stagedManifestPath?: string;
    omittedWorkerIds: string[];
  }): Promise<DeepScanRunState>;
  fail(
    scanId: string,
    message: string,
    status?: "failed" | "interrupted",
    manifestPath?: string,
    stagedManifestPath?: string,
    policyFailure?: PolicyEnforcementFailureIdentity,
  ): Promise<DeepScanRunState>;
  recordStoppedPublicationFailure(
    scanId: string,
    message: string,
    coordinatorGeneration?: number
  ): Promise<DeepScanRunState>;
  updateProgress(input: {
    scanId: string;
    handoffClaimToken?: string;
    phase?: "preflight" | "discovery";
    deepReviewPass?: number;
    reviewItemsTotal?: number;
    reviewItemsCompleted?: number;
  }): Promise<void>;
}

export interface PiWorkerTokenUsage {
  inputTokens?: number;
  cachedInputTokens?: number;
  cacheWriteInputTokens?: number;
  outputTokens?: number;
  reasoningOutputTokens?: number;
  totalTokens?: number;
}

/** Only client-reported token counts are included; missing reports are never estimated. */
export interface PiWorkerUsageDiagnostics extends PiWorkerTokenUsage {
  coverage: "complete" | "partial";
  reportedRequestCount: number;
  missingRequestCount: number;
}

export interface PiWorkerReasoningDiagnostics {
  requested: string | null;
  /** Null means the native worker did not report one applied effort. */
  applied: string | null;
  acknowledgedRequestCount: number;
}

export interface PiWorkerNestedDiagnostics {
  taskCount: number;
  failedTaskCount: number;
  requestCount: number;
  toolCallCount: number;
  toolFailureCount: number;
  elapsedMs: number;
  reportedModels: string[];
  usage: PiWorkerUsageDiagnostics | null;
}

/**
 * Observable native work for one executor tree. Top-level counts and usage
 * include nested tasks; `nested` is the nested subset.
 */
export interface PiWorkerRunDiagnostics {
  requestCount: number;
  toolCallCount: number;
  toolFailureCount: number;
  retryCount: number;
  elapsedMs: number;
  reportedModels: string[];
  reasoning: PiWorkerReasoningDiagnostics;
  usage: PiWorkerUsageDiagnostics | null;
  nested: PiWorkerNestedDiagnostics;
  /** Host-observed mechanisms available even when worker execution never succeeds. */
  enforcementCapabilities?: EnforcementCapabilityReport;
  /** Exact final authority and mechanisms applied by this executor attempt. */
  effectivePolicy?: EffectivePolicyDiagnostics;
}

export interface DeepScanRunDiagnostics extends PiWorkerRunDiagnostics {
  workerCount: number;
  failedWorkerCount: number;
  /** Deterministic unique policies observed across worker executions. */
  effectivePolicies?: EffectivePolicyDiagnostics[];
}

export interface DelegatedSecurityEvidence {
  path: string;
  startLine?: number;
  endLine?: number;
  observation: string;
}

/** Schema-validated, source-scoped evidence returned to the synthesizing parent. */
export interface DelegatedSecurityTaskResult {
  summary: string;
  evidence: DelegatedSecurityEvidence[];
  unresolved: string[];
}

/** Internal marker for a nested executor invocation. */
export interface PiWorkerDelegationContext {
  task: string;
  context?: string;
  depth: number;
}
/** Deterministic, non-secret policy state stored with an application continuation. */
export type PiWorkerContinuationPolicy = PersistedWorkerExecutionPolicies;


/** Host-bound worker and target state; never populate this from model input. */
export interface PiWorkerArtifactContext {
  root: string;
  /** Host-created worker directory containing fixed prompts and isolated output. */
  workerRoot: string;
  repoRoot: string;
  scanId: string;
  layout: "worker" | "reducer";
  scope?: string;
  packageRoot?: string;
  scanRoot?: string;
  userContext?: string;
  targetContract?: Readonly<Record<string, unknown>>;
  targetRevision?: string;
  targetSnapshotDigest?: string;
  deepReducer?: DeepReducerContext;
}

/** Transport-neutral contract for one top-level Pi worker. */
export interface PiWorkerRequest {
  kind: DeepScanWorkerKind;
  promptPath: string;
  workingDirectory: string;
  subagents: number;
  signal: AbortSignal;
  /** Opaque application continuation ID persisted by the worker, never a provider thread ID. */
  resumeContinuationId?: string;
  continuationPrompt?: string;
  artifactContext: PiWorkerArtifactContext;
  /**
   * Fresh issued authority for this exact target and worker scan. On resume it
   * must exactly match the continuation's original profile, bindings, and limits.
   */
  executionContext: ExecutionPolicyContext;
  /** Fresh fixed internal writer authority, compared and reissued on resume. */
  artifactWriterContext: ExecutionPolicyContext;
  /** Present only for a host-created nested worker task. */
  delegation?: PiWorkerDelegationContext;
  /**
   * Confirms that fresh authority and every persisted continuation/delegation
   * policy were reissued successfully. Executors must call this exactly once,
   * before settling tools, writing artifacts, or starting the worker session.
   */
  onPolicyReady?: () => Promise<void> | void;
  /** Receives diagnostics even when worker execution throws. Callback failures are ignored. */
  onDiagnostics?: (diagnostics: PiWorkerRunDiagnostics) => void;
  /** Persist the application continuation ID before the first native request. */
  onContinuationStarted?: (continuationId: string) => Promise<void> | void;
}

export type PiWorkerContinuationValidationRequest = Pick<
  PiWorkerRequest,
  | "kind"
  | "subagents"
  | "resumeContinuationId"
  | "artifactContext"
  | "executionContext"
  | "artifactWriterContext"
>;

export interface PiWorkerResult {
  continuationId?: string;
  finalResponse: string;
  diagnostics?: PiWorkerDiagnostic[];
  runDiagnostics?: PiWorkerRunDiagnostics;
  delegatedResult?: DelegatedSecurityTaskResult;
}

/**
 * Sanitized worker evidence that is safe to persist in SQLite and manifests.
 *
 * Never add raw command text, command output, prompts, or repository paths
 * here. The coordinator only needs stable classifications that explain why a
 * worker could not satisfy its artifact contract.
 */
export interface PiWorkerDiagnostic {
  code: "sandbox_namespace_exhausted" | "file_change_failed" | "artifact_tool_failed";
  message: string;
}

export interface PiWorkerExecutor {
  validateContinuationPolicy(
    request: PiWorkerContinuationValidationRequest,
  ): Promise<void>;
  run(request: PiWorkerRequest): Promise<PiWorkerResult>;
}

export interface DeepScanClock {
  now(): number;
  sleep(delayMs: number, signal: AbortSignal): Promise<void>;
}

export interface DeepScanLogEvent {
  event: string;
  scanId: string;
  workerId?: string;
  kind?: DeepScanWorkerKind;
  attempt?: number;
  continuationId?: string;
  count?: number;
  completed?: number;
  newFindings?: number;
  pass?: number;
  reason?: string;
  total?: number;
}

export type DeepScanLogger = (event: DeepScanLogEvent) => void;
