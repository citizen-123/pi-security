import { randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { createWorkerArtifactContext } from "../artifact-context.js";
import {
  artifactDestination,
  readArtifactJsonObject,
  replaceArtifactJson,
  replaceArtifactText,
  type ArtifactContext,
} from "../artifact-io.js";
import {
  assertExecutionBoundaryTuple,
  openExecutionWorkerInput,
} from "../execution-boundary.js";
import {
  advanceExecutionPolicyState,
  parseExecutionPolicyState,
  parseWorkerExecutionPolicies,
  reissueExecutionPolicyState,
  reissueWorkerExecutionPolicies,
  snapshotExecutionPolicyState,
  snapshotWorkerExecutionPolicies,
  type PersistedExecutionPolicyState,
  type PersistedWorkerExecutionPolicies,
} from "../execution-policy-continuation.js";
import {
  deriveDelegatedExecutionContext,
  type ExecutionPolicyContext,
} from "../execution-policy.js";
import {
  describeEffectivePolicyDiagnostics,
  describePiEnforcementCapabilities,
  isPolicyEnforcementFailure,
  PolicyRecoveryRejectedError,
  type EffectivePolicyDiagnostics,
  type EnforcementCapabilityReport,
} from "../enforcement-capabilities.js";
import {
  issueDeepScanArtifactWriterContext,
  issueDeepScanDelegatedChildAuthority,
} from "./mcp-sampling-policy.js";
import { DeepScanNonRetryableError } from "./errors.js";
import {
  createSamplingTools,
  validateDelegatedSecurityTaskResult,
  type BoundSamplingTools,
  type DelegatedSecurityTaskExecution,
  type SamplingToolDefinition,
  type SamplingToolResult,
} from "./sampling-tools.js";
import type {
  DeepScanWorkerKind,
  DelegatedSecurityTaskResult,
  PiWorkerExecutor,
  PiWorkerContinuationValidationRequest,
  PiWorkerRequest,
  PiWorkerResult,
  PiWorkerRunDiagnostics,
  PiWorkerTokenUsage,
  PiWorkerUsageDiagnostics,
} from "./types.js";

interface SamplingContentBlock extends Record<string, unknown> {
  type: string;
}

interface SamplingTextContent extends SamplingContentBlock {
  type: "text";
  text: string;
}

interface SamplingToolUseContent extends SamplingContentBlock {
  type: "tool_use";
  id: string;
  name: string;
  input: Record<string, unknown>;
}

interface SamplingToolResultContent extends SamplingContentBlock {
  type: "tool_result";
  toolUseId: string;
  content: SamplingToolResult["content"];
  isError?: boolean;
}

export interface SamplingMessage {
  role: "user" | "assistant";
  content: SamplingContentBlock | SamplingContentBlock[];
}

export interface SamplingCreateMessageParams {
  messages: SamplingMessage[];
  tools: SamplingToolDefinition[];
  toolChoice: { mode: "auto" };
  maxTokens: number;
  modelPreferences?: { hints?: Array<{ name: string }> };
  systemPrompt?: string;
  _meta?: Record<string, unknown>;
}

export interface SamplingCreateMessageResult {
  role: "assistant" | "user";
  content: SamplingContentBlock | SamplingContentBlock[];
  model: string;
  stopReason?: string;
  _meta?: Record<string, unknown>;
  usage?: Record<string, unknown>;
}

/** The MCP 2025-11-25 tool-enabled sampling surface used by Deep Scan. */
export interface SamplingClient {
  createMessage(
    params: SamplingCreateMessageParams,
    options?: { signal?: AbortSignal; timeout?: number },
  ): Promise<SamplingCreateMessageResult>;
}

export interface SamplingWorkerSettings {
  model?: string;
  reasoningEffort?: string;
  /** Injectable monotonic-enough clock for deterministic diagnostics. */
  now?: () => number;
}

interface PersistedToolCall {
  toolUseId: string;
  name: string;
  assistantMessageIndex: number;
  contentIndex: number;
  finalSubmissionAccepted: boolean;
  delegatedChildOrdinal?: number;
  result:
    | { location: "pending"; block: SamplingToolResultContent }
    | { location: "message"; messageIndex: number; contentIndex: number };
}

interface SamplingContinuation {
  version: 2;
  id: string;
  kind: DeepScanWorkerKind;
  policy: PersistedWorkerExecutionPolicies;
  delegation: {
    version: 1;
    children: DelegationMarker[];
  };
  messages: SamplingMessage[];
  toolCalls: PersistedToolCall[];
  finalSubmissionAccepted: boolean;
}
interface DelegationMarker {
  ordinal: number;
  task: string;
  context?: string;
  policy: PersistedExecutionPolicyState;
}

type DelegatedChildOutcome =
  | { result: DelegatedSecurityTaskResult; error?: never }
  | { result?: never; error: string };

interface PersistedDelegatedChildOutcome {
  version: 1;
  status: "succeeded" | "failed";
  result?: DelegatedSecurityTaskResult;
  error?: string;
}


const CONTINUATION_FILE = "sampling-continuation.json";
const DELEGATED_OUTCOME_FILE = "delegated-outcome.json";

/**
 * Execute a Deep Scan worker with MCP 2025-11-25 sampling tools. The transcript
 * and completed tool results are persisted by the application, so retries do
 * not depend on a model provider's thread or conversation identifier.
 */
export class SamplingWorkerExecutor implements PiWorkerExecutor {
  private readonly now: () => number;

  constructor(
    private readonly client: SamplingClient,
    private readonly settings: SamplingWorkerSettings = {},
  ) {
    this.now = settings.now ?? Date.now;
  }

  async validateContinuationPolicy(
    request: PiWorkerContinuationValidationRequest,
  ): Promise<void> {
    if (!request.resumeThreadId) {
      throw new Error("Continuation policy validation requires a continuation ID.");
    }
    await assertExecutionBoundaryTuple({
      source: request.executionContext,
      writer: request.artifactWriterContext,
      targetRoot: request.artifactContext.repoRoot,
      artifactRoot: request.artifactContext.root,
      workerRoot: request.artifactContext.workerRoot,
      scanId: request.artifactContext.scanId,
    });
    const continuationContext = await createWorkerArtifactContext({
      root: request.artifactContext.root,
      repoRoot: request.artifactContext.repoRoot,
      layout: request.artifactContext.layout,
      scanId: request.artifactContext.scanId,
      scope: request.artifactContext.scope,
      packageRoot: request.artifactContext.packageRoot,
      targetContract: request.artifactContext.targetContract,
      targetRevision: request.artifactContext.targetRevision,
      targetSnapshotDigest: request.artifactContext.targetSnapshotDigest,
      mode: "deep",
      deepReducer: request.artifactContext.deepReducer,
      executionPolicy: request.artifactWriterContext,
    });
    const continuation = await readContinuation(
      continuationContext,
      request.resumeThreadId,
      request.kind,
    );
    reissueWorkerExecutionPolicies(continuation.policy, {
      source: request.executionContext,
      artifactWriter: request.artifactWriterContext,
    });
    const {
      activeChildOrdinals,
      recoveredDelegationContexts,
    } = reissueDelegationPolicies(
      continuation,
      request,
      false,
    );
    await validateDelegatedContinuationPolicies(
      continuation,
      continuationContext,
      request,
      activeChildOrdinals,
      recoveredDelegationContexts,
    );
  }
  async run(request: PiWorkerRequest): Promise<PiWorkerResult> {
    const diagnostics = new SamplingDiagnosticsCollector(
      this.settings.reasoningEffort,
      this.now,
    );
    try {
      const result = await this.execute(request, diagnostics);
      const runDiagnostics = diagnostics.finish();
      notifyDiagnostics(request, runDiagnostics);
      return { ...result, runDiagnostics };
    } catch (error) {
      notifyDiagnostics(request, diagnostics.finish());
      throw error;
    }
  }

  private async execute(
    request: PiWorkerRequest,
    diagnostics: SamplingDiagnosticsCollector,
  ): Promise<PiWorkerResult> {
    const platformMechanisms = await assertExecutionBoundaryTuple({
      source: request.executionContext,
      writer: request.artifactWriterContext,
      targetRoot: request.artifactContext.repoRoot,
      artifactRoot: request.artifactContext.root,
      workerRoot: request.artifactContext.workerRoot,
      scanId: request.artifactContext.scanId,
    });
    request.signal.throwIfAborted();
    const continuationContext = await createWorkerArtifactContext({
      root: request.artifactContext.root,
      repoRoot: request.artifactContext.repoRoot,
      layout: request.artifactContext.layout,
      scanId: request.artifactContext.scanId,
      scope: request.artifactContext.scope,
      packageRoot: request.artifactContext.packageRoot,
      targetContract: request.artifactContext.targetContract,
      targetRevision: request.artifactContext.targetRevision,
      targetSnapshotDigest: request.artifactContext.targetSnapshotDigest,
      mode: "deep",
      deepReducer: request.artifactContext.deepReducer,
      executionPolicy: request.artifactWriterContext,
    });

    let continuation: SamplingContinuation;
    let executionContext = request.executionContext;
    let artifactWriterContext = request.artifactWriterContext;
    let created = false;
    if (request.resumeThreadId) {
      continuation = await readContinuation(
        continuationContext,
        request.resumeThreadId,
        request.kind,
      );
      const restored = reissueWorkerExecutionPolicies(continuation.policy, {
        source: request.executionContext,
        artifactWriter: request.artifactWriterContext,
      });
      executionContext = restored.source;
      artifactWriterContext = restored.artifactWriter;
    } else {
      const prompt = await readBoundWorkerPrompt(request);
      continuation = {
        version: 2,
        id: randomUUID(),
        kind: request.kind,
        policy: snapshotWorkerExecutionPolicies({
          source: executionContext,
          artifactWriter: artifactWriterContext,
        }),
        delegation: { version: 1, children: [] },
        messages: [{
          role: "user",
          content: {
            type: "text",
            text: initialInstruction(prompt, request.delegation !== undefined),
          },
        }],
        toolCalls: [],
        finalSubmissionAccepted: false,
      };
      created = true;
    }

    const canDelegate = request.kind !== "dedup"
      && request.delegation === undefined
      && request.subagents > 0;
    const {
      activeChildOrdinals,
      recordedChildOrdinals,
      recoveredDelegationContexts,
    } = reissueDelegationPolicies(
      continuation,
      request,
      request.delegation !== undefined,
    );
    await validateDelegatedContinuationPolicies(
      continuation,
      continuationContext,
      request,
      activeChildOrdinals,
      recoveredDelegationContexts,
    );

    let delegatingExecutionContext = executionContext;
    let recoveryDelegationAuthority = continuation.delegation.children.some(
      (candidate) => !recordedChildOrdinals.has(candidate.ordinal),
    )
      ? request.executionContext
      : undefined;
    let tools!: BoundSamplingTools;
    tools = await createSamplingTools({
      kind: request.kind,
      artifactContext: request.artifactContext,
      executionContext,
      artifactWriterContext,
      delegationExecutionContext: () => (
        recoveryDelegationAuthority ?? delegatingExecutionContext
      ),
      delegatedTask: request.delegation !== undefined,
      ...(request.delegation
        ? {
          onDelegatedResultAccepted: async (result, context) => {
            await writeDelegatedChildOutcome(context, { result });
          },
        }
        : {}),
      ...(canDelegate
        ? {
          delegateSecurityTask: async (task, signal): Promise<DelegatedSecurityTaskExecution> => {
            const existingMarker = continuation.delegation.children.find(
              (candidate) => !recordedChildOrdinals.has(candidate.ordinal),
            );
            let marker: DelegationMarker;
            let childExecutionContext: ExecutionPolicyContext;
            if (existingMarker) {
              if (
                existingMarker.task !== task.task
                || (existingMarker.context ?? undefined) !== (task.context ?? undefined)
              ) {
                throw new PolicyRecoveryRejectedError(
                  "delegation_mismatch",
                  "A recoverable delegated child does not match its persisted task marker.",
                );
              }
              marker = existingMarker;
              const recoveredContext = recoveredDelegationContexts.get(marker.ordinal);
              if (!recoveredContext) {
                throw new PolicyRecoveryRejectedError(
                  "invalid_policy",
                  "A persisted delegated child has no reissued execution policy.",
                );
              }
              childExecutionContext = recoveredContext;
            } else {
              if (continuation.delegation.children.length >= request.subagents) {
                throw new Error(
                  `Configured nested security delegation limit (${request.subagents}) is exhausted.`,
                );
              }
              const delegatedContexts = deriveDelegatedExecutionContext(
                delegatingExecutionContext,
              );
              delegatingExecutionContext = delegatedContexts.parent;
              childExecutionContext = delegatedContexts.child;
              marker = {
                ordinal: continuation.delegation.children.length + 1,
                task: task.task,
                ...(task.context ? { context: task.context } : {}),
                policy: snapshotExecutionPolicyState(childExecutionContext),
              };
              continuation.policy = Object.freeze({
                ...continuation.policy,
                source: advanceExecutionPolicyState(
                  continuation.policy.source,
                  delegatingExecutionContext,
                ),
              });
              continuation.delegation = {
                version: 1,
                children: [...continuation.delegation.children, marker],
              };
              // Persist the unspent successor and child authority before the
              // child starts. Recovery never reissues the spent predecessor.
              await writeContinuation(tools.context, continuation);
            }

            let outcome: DelegatedChildOutcome;
            try {
              outcome = await this.runDelegatedTask({
                parent: request,
                parentContext: tools.context,
                executionContext: childExecutionContext,
                marker,
                signal,
                diagnostics,
              });
            } catch (error) {
              if (signal.aborted) {
                signal.throwIfAborted();
                throw error;
              }
              if (isPolicyEnforcementFailure(error)) throw error;
              const message = error instanceof Error ? error.message : String(error);
              outcome = {
                error: `Delegated security task ${marker.ordinal} failed: ${message}`,
              };
            }
            recordedChildOrdinals.add(marker.ordinal);
            recoveryDelegationAuthority = undefined;
            return outcome.error === undefined
              ? { ordinal: marker.ordinal, result: outcome.result }
              : { ordinal: marker.ordinal, error: outcome.error };
          },
        }
        : {}),
    });
    const enforcementAvailability = describePiEnforcementCapabilities({
      kind: "availability",
      piTools: true,
      samplingTools: true,
      targetHandles: true,
      artifactRoots: true,
      ...(request.resumeThreadId ? { continuationPolicy: true } : {}),
      platformMechanisms,
    });
    diagnostics.recordEnforcementCapabilities(enforcementAvailability);
    const effectiveEnforcement: EnforcementCapabilityReport = Object.freeze({
      ...enforcementAvailability,
      kind: "effective" as const,
    });
    const effectivePolicy = () => describeEffectivePolicyDiagnostics({
      source: delegatingExecutionContext,
      artifactWriter: artifactWriterContext,
      enforcement: effectiveEnforcement,
    });

    await request.onPolicyReady?.();
    if (created) {
      await writeContinuation(continuationContext, continuation, true);
      await request.onThreadStarted?.(continuation.id);
    } else {
      await settlePendingToolUses(
        continuation,
        tools,
        request.signal,
        diagnostics,
      );
      if (request.continuationPrompt && canAppendContinuation(continuation)) {
        continuation.messages.push({
          role: "user",
          content: { type: "text", text: request.continuationPrompt },
        });
        await writeContinuation(tools.context, continuation);
      }
    }

    for (;;) {
      request.signal.throwIfAborted();
      diagnostics.recordSamplingRequest();
      const response = await this.client.createMessage({
        messages: continuation.messages,
        tools: tools.definitions(),
        toolChoice: { mode: "auto" },
        maxTokens: 32_000,
        ...(this.settings.model
          ? { modelPreferences: { hints: [{ name: this.settings.model }] } }
          : {}),
        systemPrompt: systemPrompt(
          request.kind,
          request.delegation !== undefined,
          this.settings.reasoningEffort,
        ),
        ...(this.settings.reasoningEffort
          ? { _meta: { reasoningEffort: this.settings.reasoningEffort } }
          : {}),
      }, {
        signal: request.signal,
        timeout: 86_400_000,
      });
      diagnostics.recordSamplingResponse(response);
      diagnostics.recordEffectivePolicy(effectivePolicy);
      request.signal.throwIfAborted();
      const assistant = requireAssistantResponse(response);
      continuation.messages.push(assistant);
      await writeContinuation(tools.context, continuation);

      const toolUses = indexedToolUses(assistant.content);
      if (toolUses.length > 0) {
        await settlePendingToolUses(
          continuation,
          tools,
          request.signal,
          diagnostics,
        );
        continue;
      }
      if (response.stopReason === "toolUse") {
        throw protocolError(
          "MCP sampling stopped for tool use without returning any tool_use content.",
        );
      }
      const finalResponse = textFromContent(assistant.content)
        || (continuation.finalSubmissionAccepted
          ? "Deep Scan artifact submission accepted."
          : "");
      const delegatedResult = tools.delegatedResult();
      return {
        finalResponse,
        threadId: continuation.id,
        ...(request.delegation && delegatedResult ? { delegatedResult } : {}),
      };
    }
  }

  private async runDelegatedTask(input: {
    parent: PiWorkerRequest;
    parentContext: ArtifactContext;
    executionContext: ExecutionPolicyContext;
    marker: DelegationMarker;
    signal: AbortSignal;
    diagnostics: SamplingDiagnosticsCollector;
  }): Promise<DelegatedChildOutcome> {
    input.signal.throwIfAborted();
    const directory = `delegate-${String(input.marker.ordinal).padStart(2, "0")}`;
    const childRoot = join(input.parentContext.root, "delegated-tasks", directory);
    const promptPath = join(childRoot, "prompt.md");
    const artifactWriterContext = issueDeepScanArtifactWriterContext({
      targetRoot: input.executionContext.target.root,
      scanId: input.executionContext.scan.id,
      artifactRoot: childRoot,
    });
    const {
      deepReducer: _deepReducer,
      ...inheritedArtifactContext
    } = input.parent.artifactContext;
    const childRequestArtifactContext = {
      ...inheritedArtifactContext,
      root: childRoot,
      layout: "worker" as const,
    };
    const existingChildRoot = await fs.lstat(childRoot).catch(
      (error: NodeJS.ErrnoException) => {
        if (error.code === "ENOENT") return undefined;
        throw error;
      },
    );
    if (!existingChildRoot) {
      const boundPromptPath = await artifactDestination(
        input.parentContext,
        ["delegated-tasks", directory, "prompt.md"],
        "Deep Scan delegated task prompt",
      );
      if (resolve(boundPromptPath) !== resolve(promptPath)) {
        throw new Error("Deep Scan delegated task prompt binding changed.");
      }
    }
    const childArtifactContext = await createWorkerArtifactContext({
      ...childRequestArtifactContext,
      executionPolicy: artifactWriterContext,
    });
    let childDiagnostics: PiWorkerRunDiagnostics | undefined;
    let nestedRecorded = false;
    try {
      input.signal.throwIfAborted();
      const persisted = await readDelegatedChildOutcome(
        input.executionContext,
        childArtifactContext,
      );
      input.signal.throwIfAborted();
      if (persisted) return persisted;

      const childContinuation = await delegatedChildContinuation(childArtifactContext);
      if (childContinuation) {
        reissueWorkerExecutionPolicies(childContinuation.policy, {
          source: input.executionContext,
          artifactWriter: artifactWriterContext,
        });
      } else {
        await replaceArtifactText(
          childArtifactContext,
          promptPath,
          delegatedTaskPrompt(input.marker),
        );
      }
      const resumeThreadId = childContinuation?.id;
      const child = await this.run({
        kind: "discovery",
        promptPath,
        workingDirectory: childRoot,
        subagents: 0,
        signal: input.signal,
        ...(resumeThreadId
          ? {
            resumeThreadId,
            continuationPrompt: "Continue the scoped investigation and record one validated delegated security result.",
          }
          : {}),
        artifactContext: childRequestArtifactContext,
        executionContext: input.executionContext,
        artifactWriterContext,
        delegation: {
          task: input.marker.task,
          ...(input.marker.context ? { context: input.marker.context } : {}),
          depth: (input.parent.delegation?.depth ?? 0) + 1,
        },
        onDiagnostics: (value) => {
          childDiagnostics = value;
        },
      });
      childDiagnostics = child.runDiagnostics ?? childDiagnostics;
      if (!child.delegatedResult) {
        throw new Error("Nested sampler ended without a validated delegated security result.");
      }
      await writeDelegatedChildOutcome(childArtifactContext, {
        result: child.delegatedResult,
      });
      input.diagnostics.recordNested(childDiagnostics, false);
      nestedRecorded = true;
      return { result: child.delegatedResult };
    } catch (error) {
      if (input.signal.aborted) {
        if (!nestedRecorded) input.diagnostics.recordNested(childDiagnostics, false);
        input.signal.throwIfAborted();
        throw error;
      }
      if (isPolicyEnforcementFailure(error)) throw error;
      const accepted = await readDelegatedChildOutcome(
        input.executionContext,
        childArtifactContext,
      );
      if (accepted?.result) {
        if (!nestedRecorded) input.diagnostics.recordNested(childDiagnostics, false);
        return accepted;
      }
      if (!nestedRecorded) input.diagnostics.recordNested(childDiagnostics, true);
      const message = error instanceof Error ? error.message : String(error);
      const outcome = {
        error: `Delegated security task ${input.marker.ordinal} failed: ${message}`,
      };
      await writeDelegatedChildOutcome(childArtifactContext, outcome);
      return outcome;
    }
  }
}

function reissueDelegationPolicies(
  continuation: SamplingContinuation,
  request: Pick<
    PiWorkerRequest,
    "kind" | "subagents" | "artifactContext"
  >,
  delegatedTask: boolean,
): {
  recordedChildOrdinals: Set<number>;
  activeChildOrdinals: Set<number>;
  recoveredDelegationContexts: Map<number, ExecutionPolicyContext>;
} {
  const canDelegate = request.kind !== "dedup"
    && !delegatedTask
    && request.subagents > 0;
  if (
    continuation.delegation.children.length > request.subagents
    || (!canDelegate && continuation.delegation.children.length > 0)
  ) {
    throw new PolicyRecoveryRejectedError(
      "delegation_mismatch",
      "The saved Deep Scan delegation state exceeds the authoritative worker policy.",
    );
  }
  assertWorkerPolicyLedger(
    continuation.policy,
    continuation.delegation.children.length,
  );
  const recordedChildOrdinals = new Set<number>();
  for (const call of continuation.toolCalls) {
    if (call.delegatedChildOrdinal === undefined) continue;
    if (!continuation.delegation.children.some(
      (marker) => marker.ordinal === call.delegatedChildOrdinal,
    )) {
      throw new PolicyRecoveryRejectedError(
        "invalid_policy",
        "A persisted delegated tool call has no matching child-started marker.",
      );
    }
    if (recordedChildOrdinals.has(call.delegatedChildOrdinal)) {
      throw new PolicyRecoveryRejectedError(
        "invalid_policy",
        "The saved Deep Scan delegation state assigns one child marker to multiple tool calls.",
      );
    }
    recordedChildOrdinals.add(call.delegatedChildOrdinal);
  }
  const recoveredDelegationContexts = new Map<number, ExecutionPolicyContext>();
  for (const [index, marker] of continuation.delegation.children.entries()) {
    if (marker.ordinal !== index + 1) {
      throw new PolicyRecoveryRejectedError(
        "invalid_policy",
        "The saved Deep Scan delegation state has a non-canonical child ordinal.",
      );
    }
    if (recoveredDelegationContexts.has(marker.ordinal)) {
      throw new PolicyRecoveryRejectedError(
        "invalid_policy",
        "The saved Deep Scan delegation state contains a duplicate child marker.",
      );
    }
    assertExactPolicySuccessor(
      marker.policy,
      0,
      "delegated child",
    );
    recoveredDelegationContexts.set(
      marker.ordinal,
      reissueExecutionPolicyState(
        marker.policy,
        issueDeepScanDelegatedChildAuthority({
          targetRoot: request.artifactContext.repoRoot,
          scanId: request.artifactContext.scanId,
          workerRoot: request.artifactContext.workerRoot,
        }),
      ),
    );
  }
  const activeChildOrdinals = reconcileActiveDelegationMarkers(
    continuation,
    recordedChildOrdinals,
  );
  return {
    activeChildOrdinals,
    recordedChildOrdinals,
    recoveredDelegationContexts,
  };
}


function assertWorkerPolicyLedger(
  policy: PersistedWorkerExecutionPolicies,
  delegatedChildren: number,
): void {
  assertExactPolicySuccessor(
    policy.source,
    delegatedChildren,
    "worker source",
  );
  assertExactPolicySuccessor(policy.artifactWriter, 0, "artifact writer");
}

function assertExactPolicySuccessor(
  state: PersistedExecutionPolicyState,
  spentBudget: number,
  label: string,
): void {
  const expectedBudget = state.authority.delegation.remainingBudget - spentBudget;
  if (
    expectedBudget < 0
    || state.effective.delegation.remainingBudget !== expectedBudget
    || state.effective.delegation.remainingDepth
      !== state.authority.delegation.remainingDepth
  ) {
    throw new PolicyRecoveryRejectedError(
      "delegation_mismatch",
      `The saved ${label} policy does not exactly match its delegation ledger.`,
    );
  }
}

function reconcileActiveDelegationMarkers(
  continuation: SamplingContinuation,
  recordedChildOrdinals: ReadonlySet<number>,
): Set<number> {
  const markersByOrdinal = new Map(
    continuation.delegation.children.map((marker) => [marker.ordinal, marker]),
  );
  const callsById = new Map<string, PersistedToolCall>();
  const activeChildOrdinals = new Set<number>();
  for (const call of continuation.toolCalls) {
    if (callsById.has(call.toolUseId)) {
      throw new PolicyRecoveryRejectedError(
        "invalid_policy",
        "The saved Deep Scan transcript contains a duplicate tool call.",
      );
    }
    callsById.set(call.toolUseId, call);
    if (
      call.name === "delegate_security_task"
      && call.delegatedChildOrdinal === undefined
    ) {
      throw new PolicyRecoveryRejectedError(
        "invalid_policy",
        "A persisted delegation tool call has no child marker.",
      );
    }
    if (call.delegatedChildOrdinal === undefined) continue;
    const marker = markersByOrdinal.get(call.delegatedChildOrdinal);
    if (!marker || call.name !== "delegate_security_task") {
      throw new PolicyRecoveryRejectedError(
        "invalid_policy",
        "A persisted delegated child is not bound to a delegation tool call.",
      );
    }
    const message = continuation.messages[call.assistantMessageIndex];
    const use = message?.role === "assistant"
      ? indexedToolUses(message.content).find(
        (candidate) => candidate.contentIndex === call.contentIndex,
      )
      : undefined;
    if (
      !use
      || use.block.id !== call.toolUseId
      || use.block.name !== "delegate_security_task"
    ) {
      throw new PolicyRecoveryRejectedError(
        "delegation_mismatch",
        "A persisted delegated tool call does not match its transcript entry.",
      );
    }
    assertDelegationMarkerInput(marker, use.block.input);
    if (call.result.location === "pending") {
      if (call.assistantMessageIndex !== continuation.messages.length - 1) {
        throw new PolicyRecoveryRejectedError(
          "invalid_policy",
          "A pending delegated tool call is not in the active assistant message.",
        );
      }
      activeChildOrdinals.add(marker.ordinal);
    } else {
      assertDelegatedToolResultMessage(continuation, call);
    }
  }


function assertDelegatedToolResultMessage(
  continuation: SamplingContinuation,
  call: PersistedToolCall,
): void {
  if (call.result.location !== "message") {
    throw new PolicyRecoveryRejectedError(
      "invalid_policy",
      "A completed delegated tool call has invalid result state.",
    );
  }
  if (
    call.assistantMessageIndex === continuation.messages.length - 1
    || call.result.messageIndex !== call.assistantMessageIndex + 1
  ) {
    throw new PolicyRecoveryRejectedError(
      "invalid_policy",
      "A delegated tool call claims completion while its assistant request is still active.",
    );
  }
  const resultMessage = continuation.messages[call.result.messageIndex];
  const resultBlock = resultMessage?.role === "user"
    && Array.isArray(resultMessage.content)
    ? resultMessage.content[call.result.contentIndex]
    : undefined;
  if (
    !resultBlock
    || resultBlock.type !== "tool_result"
    || !("toolUseId" in resultBlock)
    || resultBlock.toolUseId !== call.toolUseId
  ) {
    throw new PolicyRecoveryRejectedError(
      "invalid_policy",
      "A persisted delegated tool call has no matching tool-result message.",
    );
  }
}
  const unrecordedMarkers = continuation.delegation.children.filter(
    (marker) => !recordedChildOrdinals.has(marker.ordinal),
  );
  if (unrecordedMarkers.length > 1) {
    throw new PolicyRecoveryRejectedError(
      "invalid_policy",
      "The saved Deep Scan delegation state contains multiple unrecorded active children.",
    );
  }
  const unrecordedMarker = unrecordedMarkers[0];
  if (!unrecordedMarker) return activeChildOrdinals;
  const latest = continuation.messages.at(-1);
  const firstUnpersistedUse = latest?.role === "assistant"
    ? indexedToolUses(latest.content).find(
      (candidate) => !callsById.has(candidate.block.id),
    )
    : undefined;
  if (
    !firstUnpersistedUse
    || firstUnpersistedUse.block.name !== "delegate_security_task"
  ) {
    throw new PolicyRecoveryRejectedError(
      "invalid_policy",
      "An active delegated child has no pending delegation transcript entry.",
    );
  }
  assertDelegationMarkerInput(
    unrecordedMarker,
    firstUnpersistedUse.block.input,
  );
  activeChildOrdinals.add(unrecordedMarker.ordinal);
  return activeChildOrdinals;
}

function assertDelegationMarkerInput(
  marker: DelegationMarker,
  input: Record<string, unknown>,
): void {
  const keys = Object.keys(input).sort();
  const task = typeof input.task === "string" ? input.task.trim() : "";
  const context = typeof input.context === "string"
    ? input.context.trim()
    : undefined;
  if (
    !task
    || (input.context !== undefined && !context)
    || keys.some((key) => key !== "context" && key !== "task")
  ) {
    throw new PolicyRecoveryRejectedError(
      "invalid_policy",
      "A pending delegation transcript entry has invalid task input.",
    );
  }
  if (
    marker.task !== task
    || (marker.context ?? undefined) !== context
  ) {
    throw new PolicyRecoveryRejectedError(
      "delegation_mismatch",
      "An active delegated child does not match its persisted task marker.",
    );
  }
}

async function validateDelegatedContinuationPolicies(
  continuation: SamplingContinuation,
  parentContext: ArtifactContext,
  request: Pick<
    PiWorkerRequest,
    "artifactContext" | "executionContext"
  >,
  activeChildOrdinals: ReadonlySet<number>,
  recoveredDelegationContexts: ReadonlyMap<number, ExecutionPolicyContext>,
): Promise<void> {
  for (const ordinal of activeChildOrdinals) {
    const marker = continuation.delegation.children.find(
      (candidate) => candidate.ordinal === ordinal,
    );
    const childExecutionContext = recoveredDelegationContexts.get(ordinal);
    if (!marker || !childExecutionContext) {
      throw new PolicyRecoveryRejectedError(
        "invalid_policy",
        "A pending delegated child has no reissued execution policy.",
      );
    }
    const directory = `delegate-${String(marker.ordinal).padStart(2, "0")}`;
    const childRoot = join(parentContext.root, "delegated-tasks", directory);
    const existingChildRoot = await fs.lstat(childRoot).catch(
      (error: NodeJS.ErrnoException) => {
        if (error.code === "ENOENT") return undefined;
        throw error;
      },
    );
    if (!existingChildRoot) continue;
    const artifactWriterContext = issueDeepScanArtifactWriterContext({
      targetRoot: childExecutionContext.target.root,
      scanId: childExecutionContext.scan.id,
      artifactRoot: childRoot,
    });
    const {
      deepReducer: _deepReducer,
      ...inheritedArtifactContext
    } = request.artifactContext;
    const childArtifactContext = await createWorkerArtifactContext({
      ...inheritedArtifactContext,
      root: childRoot,
      layout: "worker",
      executionPolicy: artifactWriterContext,
    });
    const persistedOutcome = await readDelegatedChildOutcome(
      childExecutionContext,
      childArtifactContext,
    );
    if (persistedOutcome) continue;
    const childContinuation = await delegatedChildContinuation(
      childArtifactContext,
    );
    if (!childContinuation) continue;
    reissueWorkerExecutionPolicies(childContinuation.policy, {
      source: childExecutionContext,
      artifactWriter: artifactWriterContext,
    });
    reissueDelegationPolicies(
      childContinuation,
      {
        kind: "discovery",
        subagents: 0,
        artifactContext: {
          ...inheritedArtifactContext,
          root: childRoot,
          layout: "worker",
        },
      },
      true,
    );
  }
}

const TOKEN_USAGE_KEYS = [
  "inputTokens",
  "cachedInputTokens",
  "cacheWriteInputTokens",
  "outputTokens",
  "reasoningOutputTokens",
  "totalTokens",
] as const;


class SamplingDiagnosticsCollector {
  private readonly startedAt: number;
  private samplingRequestCount = 0;
  private toolCallCount = 0;
  private toolFailureCount = 0;
  private retryCount = 0;
  private readonly reportedModels = new Set<string>();
  private readonly appliedReasoning = new Set<string>();
  private appliedReasoningConflict = false;
  private acknowledgedReasoningCount = 0;
  private usageReportCount = 0;
  private readonly usage: PiWorkerTokenUsage = {};
  private nestedTaskCount = 0;
  private nestedFailedTaskCount = 0;
  private nestedSamplingRequestCount = 0;
  private nestedToolCallCount = 0;
  private nestedToolFailureCount = 0;
  private nestedElapsedMs = 0;
  private readonly nestedReportedModels = new Set<string>();
  private nestedUsageReportCount = 0;
  private readonly nestedUsage: PiWorkerTokenUsage = {};
  private finished: PiWorkerRunDiagnostics | undefined;
  private effectivePolicy: (() => EffectivePolicyDiagnostics) | undefined;
  private enforcementCapabilities: EnforcementCapabilityReport | undefined;

  constructor(
    private readonly requestedReasoning: string | undefined,
    private readonly now: () => number,
  ) {
    this.startedAt = now();
  }

  recordEnforcementCapabilities(report: EnforcementCapabilityReport): void {
    this.enforcementCapabilities = report;
  }

  recordEffectivePolicy(describe: () => EffectivePolicyDiagnostics): void {
    this.effectivePolicy ??= describe;
  }

  recordSamplingRequest(): void {
    this.samplingRequestCount += 1;
  }

  recordSamplingResponse(response: SamplingCreateMessageResult): void {
    if (typeof response.model === "string" && response.model.trim()) {
      this.reportedModels.add(response.model.trim());
    }
    const usage = clientReportedUsage(response);
    if (usage) {
      this.usageReportCount += 1;
      addTokenUsage(this.usage, usage);
    }
    const appliedReasoning = acknowledgedReasoningEffort(response);
    if (appliedReasoning) {
      this.acknowledgedReasoningCount += 1;
      this.appliedReasoning.add(appliedReasoning);
    }
  }

  recordToolExecution(failed: boolean): void {
    this.toolCallCount += 1;
    if (failed) this.toolFailureCount += 1;
  }

  recordNested(diagnostics: PiWorkerRunDiagnostics | undefined, failed: boolean): void {
    this.nestedTaskCount += 1;
    if (failed) this.nestedFailedTaskCount += 1;
    if (!diagnostics) return;

    this.samplingRequestCount += diagnostics.samplingRequestCount;
    this.toolCallCount += diagnostics.toolCallCount;
    this.toolFailureCount += diagnostics.toolFailureCount;
    this.retryCount += diagnostics.retryCount;
    this.nestedSamplingRequestCount += diagnostics.samplingRequestCount;
    this.nestedToolCallCount += diagnostics.toolCallCount;
    this.nestedToolFailureCount += diagnostics.toolFailureCount;
    this.nestedElapsedMs += diagnostics.elapsedMs;
    for (const model of diagnostics.reportedModels) this.reportedModels.add(model);
    for (const model of diagnostics.reportedModels) this.nestedReportedModels.add(model);
    if (diagnostics.reasoning.acknowledgedRequestCount > 0) {
      this.acknowledgedReasoningCount += diagnostics.reasoning.acknowledgedRequestCount;
      if (diagnostics.reasoning.applied) {
        this.appliedReasoning.add(diagnostics.reasoning.applied);
      } else {
        this.appliedReasoningConflict = true;
      }
    }
    if (diagnostics.usage) {
      this.usageReportCount += diagnostics.usage.reportedRequestCount;
      addTokenUsage(this.usage, diagnostics.usage);
      this.nestedUsageReportCount += diagnostics.usage.reportedRequestCount;
      addTokenUsage(this.nestedUsage, diagnostics.usage);
    }
  }

  finish(): PiWorkerRunDiagnostics {
    if (this.finished) return this.finished;
    const applied = !this.appliedReasoningConflict && this.appliedReasoning.size === 1
      ? [...this.appliedReasoning][0] ?? null
      : null;
    this.finished = {
      samplingRequestCount: this.samplingRequestCount,
      toolCallCount: this.toolCallCount,
      toolFailureCount: this.toolFailureCount,
      retryCount: this.retryCount,
      elapsedMs: Math.max(0, this.now() - this.startedAt),
      reportedModels: [...this.reportedModels],
      reasoning: {
        requested: this.requestedReasoning?.trim() || null,
        applied,
        acknowledgedRequestCount: this.acknowledgedReasoningCount,
      },
      usage: projectedUsage(
        this.usage,
        this.usageReportCount,
        this.samplingRequestCount,
      ),
      nested: {
        taskCount: this.nestedTaskCount,
        failedTaskCount: this.nestedFailedTaskCount,
        samplingRequestCount: this.nestedSamplingRequestCount,
        toolCallCount: this.nestedToolCallCount,
        toolFailureCount: this.nestedToolFailureCount,
        elapsedMs: this.nestedElapsedMs,
        reportedModels: [...this.nestedReportedModels],
        usage: projectedUsage(
          this.nestedUsage,
          this.nestedUsageReportCount,
          this.nestedSamplingRequestCount,
        ),
      },
      ...(this.enforcementCapabilities
        ? { enforcementCapabilities: this.enforcementCapabilities }
        : {}),
      ...(this.effectivePolicy
        ? { effectivePolicy: this.effectivePolicy() }
        : {}),
    };
    return this.finished;
  }
}

function clientReportedUsage(
  response: SamplingCreateMessageResult,
): PiWorkerTokenUsage | undefined {
  const metadataUsage = isObject(response._meta?.usage) ? response._meta.usage : undefined;
  const raw = isObject(response.usage) ? response.usage : metadataUsage;
  if (!raw) return undefined;
  const usage: PiWorkerTokenUsage = {};
  let present = false;
  for (const key of TOKEN_USAGE_KEYS) {
    const value = raw[key];
    if (value === undefined) continue;
    if (!isNonnegativeInteger(value)) return undefined;
    usage[key] = value;
    present = true;
  }
  return present ? usage : undefined;
}

function acknowledgedReasoningEffort(
  response: SamplingCreateMessageResult,
): string | undefined {
  const metadata = response._meta;
  if (!isObject(metadata)) return undefined;
  const reasoning = isObject(metadata.reasoning) ? metadata.reasoning : undefined;
  for (const value of [
    metadata.reasoningEffortApplied,
    metadata.reasoningEffort,
    reasoning?.applied,
  ]) {
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return undefined;
}

function addTokenUsage(
  destination: PiWorkerTokenUsage,
  source: PiWorkerTokenUsage,
): void {
  for (const key of TOKEN_USAGE_KEYS) {
    const value = source[key];
    if (value !== undefined) destination[key] = (destination[key] ?? 0) + value;
  }
}

function projectedUsage(
  usage: PiWorkerTokenUsage,
  reportedRequestCount: number,
  samplingRequestCount: number,
): PiWorkerUsageDiagnostics | null {
  if (reportedRequestCount === 0) return null;
  const missingRequestCount = Math.max(0, samplingRequestCount - reportedRequestCount);
  return {
    coverage: missingRequestCount === 0 ? "complete" : "partial",
    reportedRequestCount,
    missingRequestCount,
    ...usage,
  };
}

function notifyDiagnostics(
  request: PiWorkerRequest,
  diagnostics: PiWorkerRunDiagnostics,
): void {
  try {
    request.onDiagnostics?.(diagnostics);
  } catch {
    // Diagnostics are optional evidence and must not change worker execution.
  }
}

function delegatedTaskPrompt(input: { task: string; context?: string }): string {
  return [
    "Perform one scoped investigation for a parent Pi Security Deep Scan worker.",
    "",
    "Task:",
    input.task,
    ...(input.context ? ["", "Parent context:", input.context] : []),
    "",
    "The coordinator-bound repository target and scope are authoritative. Return source-backed observations for parent synthesis; do not create or submit a scan draft.",
  ].join("\n");
}


async function readDelegatedChildOutcome(
  executionContext: ExecutionPolicyContext,
  context: ArtifactContext,
): Promise<DelegatedChildOutcome | undefined> {
  let value: Record<string, unknown> | undefined;
  try {
    value = await readOptionalArtifactJson(
      context,
      [DELEGATED_OUTCOME_FILE],
      "Deep Scan delegated child outcome",
    );
  } catch (error) {
    if (isPolicyEnforcementFailure(error)) throw error;
    throw new PolicyRecoveryRejectedError(
      "invalid_policy",
      "The saved delegated child outcome is unavailable or malformed.",
      { cause: error },
    );
  }
  if (!value) return undefined;
  if (value.version !== 1) {
    throw new PolicyRecoveryRejectedError(
      "invalid_policy",
      "The saved delegated child outcome has an invalid version.",
    );
  }
  if (value.status === "failed" && typeof value.error === "string" && value.error) {
    return { error: value.error };
  }
  if (value.status === "succeeded" && isObject(value.result)) {
    try {
      return {
        result: await validateDelegatedSecurityTaskResult(
          executionContext,
          context,
          value.result,
        ),
      };
    } catch (error) {
      if (isPolicyEnforcementFailure(error)) throw error;
      throw new PolicyRecoveryRejectedError(
        "invalid_policy",
        "The saved delegated child result is malformed or violates its bound policy.",
        { cause: error },
      );
    }
  }
  throw new PolicyRecoveryRejectedError(
    "invalid_policy",
    "The saved delegated child outcome has an invalid envelope.",
  );
}

async function writeDelegatedChildOutcome(
  context: ArtifactContext,
  outcome: DelegatedChildOutcome,
): Promise<void> {
  const destination = await artifactDestination(
    context,
    [DELEGATED_OUTCOME_FILE],
    "Deep Scan delegated child outcome",
  );
  const persisted: PersistedDelegatedChildOutcome = outcome.error === undefined
    ? {
      version: 1,
      status: "succeeded",
      result: outcome.result,
    }
    : {
      version: 1,
      status: "failed",
      error: outcome.error,
    };
  await replaceArtifactJson(context, destination, persisted);
}

async function delegatedChildContinuation(
  context: ArtifactContext,
): Promise<SamplingContinuation | undefined> {
  let value: Record<string, unknown> | undefined;
  try {
    value = await readOptionalArtifactJson(
      context,
      [CONTINUATION_FILE],
      "Deep Scan delegated child continuation",
    );
  } catch (error) {
    if (isPolicyEnforcementFailure(error)) throw error;
    throw new PolicyRecoveryRejectedError(
      "invalid_policy",
      "The saved delegated child continuation is unavailable or malformed.",
      { cause: error },
    );
  }
  if (!value) return undefined;
  let continuation: SamplingContinuation;
  try {
    continuation = parseContinuation(value);
  } catch (error) {
    if (isPolicyEnforcementFailure(error)) throw error;
    throw new PolicyRecoveryRejectedError(
      "invalid_policy",
      "The saved delegated child continuation is unavailable or malformed.",
      { cause: error },
    );
  }
  if (continuation.kind !== "discovery") {
    throw new PolicyRecoveryRejectedError(
      "delegation_mismatch",
      "The saved delegated child continuation has an invalid worker kind.",
    );
  }
  return continuation;
}

async function readOptionalArtifactJson(
  context: ArtifactContext,
  components: readonly string[],
  label: string,
): Promise<Record<string, unknown> | undefined> {
  const destination = await artifactDestination(context, components, label);
  const metadata = await fs.lstat(destination).catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return undefined;
    throw error;
  });
  if (!metadata) return undefined;
  return await readArtifactJsonObject(context, components, label);
}

/** Only sampling.tools, not basic sampling, permits Deep Scan source access. */
export function supportsSamplingTools(value: unknown): boolean {
  if (!isObject(value)) return false;
  const sampling = value.sampling;
  return isObject(sampling) && isObject(sampling.tools);
}

async function settlePendingToolUses(
  continuation: SamplingContinuation,
  tools: BoundSamplingTools,
  signal: AbortSignal,
  diagnostics: SamplingDiagnosticsCollector,
): Promise<void> {
  const assistantMessageIndex = continuation.messages.length - 1;
  const message = continuation.messages[assistantMessageIndex];
  if (!message || message.role !== "assistant") return;
  const uses = indexedToolUses(message.content);
  if (uses.length === 0) return;
  const ids = new Set<string>();
  for (const { block } of uses) {
    if (ids.has(block.id)) {
      throw protocolError(`MCP sampling repeated tool_use id ${JSON.stringify(block.id)} in one response.`);
    }
    ids.add(block.id);
  }

  const results: SamplingToolResultContent[] = [];
  const calls: PersistedToolCall[] = [];
  for (const use of uses) {
    signal.throwIfAborted();
    let call = continuation.toolCalls.find((candidate) => candidate.toolUseId === use.block.id);
    if (call) {
      if (
        call.assistantMessageIndex !== assistantMessageIndex
        || call.contentIndex !== use.contentIndex
        || call.name !== use.block.name
      ) {
        if (
          use.block.name === "delegate_security_task"
          || call.name === "delegate_security_task"
          || call.delegatedChildOrdinal !== undefined
        ) {
          throw new PolicyRecoveryRejectedError(
            "delegation_mismatch",
            "A persisted delegated tool call does not match its pending transcript entry.",
          );
        }
        throw protocolError(`MCP sampling reused tool_use id ${JSON.stringify(use.block.id)}.`);
      }
      if (call.result.location !== "pending") {
        if (call.delegatedChildOrdinal !== undefined) {
          throw new PolicyRecoveryRejectedError(
            "invalid_policy",
            "A completed delegated tool call is not followed by its persisted result message.",
          );
        }
        throw continuationError("A completed sampling tool call is not followed by its persisted result message.");
      }
    } else {
      const executed = await tools.execute(use.block.name, use.block.input, signal);
      diagnostics.recordToolExecution(Boolean(executed.result.isError));
      const resultBlock: SamplingToolResultContent = {
        type: "tool_result",
        toolUseId: use.block.id,
        content: executed.result.content,
        ...(executed.result.isError ? { isError: true } : {}),
      };
      call = {
        toolUseId: use.block.id,
        name: use.block.name,
        assistantMessageIndex,
        contentIndex: use.contentIndex,
        finalSubmissionAccepted: executed.finalSubmissionAccepted,
        ...(executed.delegatedChildOrdinal === undefined
          ? {}
          : { delegatedChildOrdinal: executed.delegatedChildOrdinal }),
        result: { location: "pending", block: resultBlock },
      };
      continuation.toolCalls.push(call);
      if (executed.finalSubmissionAccepted) {
        continuation.finalSubmissionAccepted = true;
      }
      await writeContinuation(tools.context, continuation);
    }
    if (call.result.location !== "pending") {
      if (call.delegatedChildOrdinal !== undefined) {
        throw new PolicyRecoveryRejectedError(
          "invalid_policy",
          "A delegated tool call lost its pending result before replay.",
        );
      }
      throw continuationError("A sampling tool call lost its pending result before replay.");
    }
    results.push(call.result.block);
    calls.push(call);
  }

  const resultMessageIndex = continuation.messages.length;
  continuation.messages.push({ role: "user", content: results });
  for (const [contentIndex, call] of calls.entries()) {
    call.result = {
      location: "message",
      messageIndex: resultMessageIndex,
      contentIndex,
    };
  }
  await writeContinuation(tools.context, continuation);
}

function requireAssistantResponse(response: SamplingCreateMessageResult): SamplingMessage {
  if (response.role !== "assistant") {
    throw protocolError("MCP sampling returned a non-assistant response to sampling/createMessage.");
  }
  requireContent(response.content, "MCP sampling response");
  return { role: "assistant", content: response.content };
}

function indexedToolUses(content: SamplingMessage["content"]): Array<{
  block: SamplingToolUseContent;
  contentIndex: number;
}> {
  const blocks = Array.isArray(content) ? content : [content];
  const uses: Array<{ block: SamplingToolUseContent; contentIndex: number }> = [];
  for (const [contentIndex, block] of blocks.entries()) {
    if (!isObject(block) || block.type !== "tool_use") continue;
    if (
      typeof block.id !== "string"
      || !block.id
      || typeof block.name !== "string"
      || !block.name
      || !isObject(block.input)
    ) {
      throw protocolError("MCP sampling returned malformed tool_use content.");
    }
    uses.push({
      block: block as SamplingToolUseContent,
      contentIndex,
    });
  }
  return uses;
}

function textFromContent(content: SamplingMessage["content"]): string {
  const blocks = Array.isArray(content) ? content : [content];
  return blocks
    .filter((block): block is SamplingTextContent => (
      isObject(block) && block.type === "text" && typeof block.text === "string"
    ))
    .map((block) => block.text)
    .join("\n");
}

function canAppendContinuation(continuation: SamplingContinuation): boolean {
  const last = continuation.messages.at(-1);
  return Boolean(
    last
    && last.role === "assistant"
    && indexedToolUses(last.content).length === 0,
  );
}

function initialInstruction(prompt: string, delegatedTask: boolean): string {
  return [
    prompt,
    "",
    delegatedTask ? "MCP DELEGATED SAMPLING TOOL CONTRACT" : "MCP SAMPLING TOOL CONTRACT",
    "Use only the supplied Pi Security sampling tools to inspect source and scan context.",
    "Do not attempt direct filesystem access or a shell. Paths accepted by source tools are relative to the coordinator-bound target.",
    "Call get_pi_security_scan_context before analysis; it supplies the bundled Standard scan guide and any existing threat-model context.",
    delegatedTask
      ? "Return the completed scoped investigation with record_delegate_security_result. The parent owns synthesis and final scan-draft submission."
      : "Submit checkpoints and the final schema-bound artifact with the supplied record tool. Do not return a JSON artifact as text.",
    "After a successful final record tool result, end the turn without another submission.",
  ].join("\n");
}

function systemPrompt(
  kind: DeepScanWorkerKind,
  delegatedTask: boolean,
  reasoningEffort: string | undefined,
): string {
  const purpose = delegatedTask
    ? "Investigate the assigned scoped repository-security task for a parent worker. Use only the supplied target-bound tools and return validated evidence for parent synthesis."
    : kind === "dedup"
      ? "Semantically reduce the assigned Pi Security scan drafts. Use only the supplied reducer tools and obey their schemas."
      : "Perform the requested repository security analysis. Use only the supplied target-bound tools and obey the semantic scan-draft schema.";
  if (!reasoningEffort) return purpose;
  return `${purpose} The host requests reasoning effort ${JSON.stringify(reasoningEffort)}. This is an execution preference, not confirmation that the sampling client applied it.`;
}

async function readContinuation(
  context: ArtifactContext,
  expectedId: string,
  expectedKind: DeepScanWorkerKind,
): Promise<SamplingContinuation> {
  let value: Record<string, unknown>;
  try {
    value = await readArtifactJsonObject(
      context,
      [CONTINUATION_FILE],
      "Deep Scan sampling continuation",
    );
  } catch (error) {
    if (isPolicyEnforcementFailure(error)) throw error;
    throw new DeepScanNonRetryableError(
      "Deep Scan sampling continuation is unavailable or invalid; it cannot be resumed.",
      { cause: error },
    );
  }
  const continuation = parseContinuation(value);
  if (continuation.id !== expectedId) {
    throw new PolicyRecoveryRejectedError(
      "binding_mismatch",
      "The saved Deep Scan sampling continuation has a different identity.",
    );
  }
  if (continuation.kind !== expectedKind) {
    throw new PolicyRecoveryRejectedError(
      "binding_mismatch",
      "The saved Deep Scan sampling continuation belongs to a different worker phase.",
    );
  }
  return continuation;
}

async function writeContinuation(
  context: ArtifactContext,
  continuation: SamplingContinuation,
  createOnly = false,
): Promise<void> {
  const destination = await artifactDestination(
    context,
    [CONTINUATION_FILE],
    "Deep Scan sampling continuation",
  );
  if (createOnly) {
    const existing = await fs.lstat(destination).catch(() => undefined);
    if (existing) {
      throw continuationError("A new Deep Scan worker found an existing sampling continuation.");
    }
  }
  await replaceArtifactJson(context, destination, continuation);
}

async function readBoundWorkerPrompt(request: PiWorkerRequest): Promise<string> {
  const prompt = resolve(request.promptPath);
  const workerRoot = resolve(request.artifactContext.workerRoot);
  const relativePrompt = relative(workerRoot, prompt);
  const retryPrompt = relativePrompt.startsWith(`prompts${sep}`)
    && /^prompts[/\\]attempt-[0-9]{2}\.md$/u.test(relativePrompt);
  const basePrompt = prompt === join(workerRoot, "prompt.md");
  const delegatedPrompt = request.delegation !== undefined
    && prompt === join(resolve(request.artifactContext.root), "prompt.md");
  if (!basePrompt && !retryPrompt && !delegatedPrompt) {
    throw new DeepScanNonRetryableError(
      "Deep Scan prompt is not one of the coordinator-created worker prompts.",
    );
  }
  const opened = await openExecutionWorkerInput(
    request.executionContext,
    prompt,
    "file",
    "Deep Scan worker prompt",
  );
  try {
    return await opened.handle.readFile("utf8");
  } finally {
    await opened.handle.close();
  }
}

function parseContinuation(value: Record<string, unknown>): SamplingContinuation {
  if (value.version === 1) {
    throw new PolicyRecoveryRejectedError(
      "legacy_continuation",
      "Legacy Deep Scan continuation v1 has no enforceable saved policy and cannot be resumed; Pi Security will not downgrade to pathname-only or unbound tool enforcement.",
    );
  }
  if (
    value.version !== 2
    || typeof value.id !== "string"
    || !value.id
    || (value.kind !== "setup" && value.kind !== "discovery" && value.kind !== "dedup")
    || !Array.isArray(value.messages)
    || !Array.isArray(value.toolCalls)
    || typeof value.finalSubmissionAccepted !== "boolean"
  ) {
    throw continuationError("The saved Deep Scan sampling continuation has an invalid envelope.");
  }
  if (
    !isObject(value.delegation)
    || value.delegation.version !== 1
    || !Array.isArray(value.delegation.children)
  ) {
    throw new PolicyRecoveryRejectedError(
      "invalid_policy",
      "The saved Deep Scan delegation state has an invalid envelope.",
    );
  }
  let policy: PersistedWorkerExecutionPolicies;
  try {
    policy = parseWorkerExecutionPolicies(value.policy);
  } catch (error) {
    throw new PolicyRecoveryRejectedError(
      "invalid_policy",
      "The saved Deep Scan execution policy is unavailable, forged, or stale.",
      { cause: error },
    );
  }
  const children: DelegationMarker[] = [];
  for (const [index, rawMarker] of value.delegation.children.entries()) {
    if (
      !isObject(rawMarker)
      || rawMarker.ordinal !== index + 1
      || typeof rawMarker.task !== "string"
      || !rawMarker.task
      || (
        rawMarker.context !== undefined
        && (typeof rawMarker.context !== "string" || !rawMarker.context)
      )
    ) {
      throw new PolicyRecoveryRejectedError(
        "invalid_policy",
        "The saved Deep Scan delegation state has an invalid child marker.",
      );
    }
    let childPolicy: PersistedExecutionPolicyState;
    try {
      childPolicy = parseExecutionPolicyState(rawMarker.policy);
    } catch (error) {
      throw new PolicyRecoveryRejectedError(
        "invalid_policy",
        "The saved Deep Scan delegated child policy is unavailable, forged, or spent.",
        { cause: error },
      );
    }
    children.push({
      ordinal: rawMarker.ordinal,
      task: rawMarker.task,
      ...(typeof rawMarker.context === "string" ? { context: rawMarker.context } : {}),
      policy: childPolicy,
    });
  }
  for (const message of value.messages) {
    if (!isObject(message) || (message.role !== "user" && message.role !== "assistant")) {
      throw continuationError("The saved Deep Scan sampling continuation has an invalid message role.");
    }
    requireContent(message.content, "Saved Deep Scan sampling message");
  }
  for (const rawCall of value.toolCalls) {
    if (!isObject(rawCall) || !validPersistedToolCall(rawCall)) {
      if (
        isObject(rawCall)
        && (
          rawCall.name === "delegate_security_task"
          || rawCall.delegatedChildOrdinal !== undefined
        )
      ) {
        throw new PolicyRecoveryRejectedError(
          "invalid_policy",
          "The saved Deep Scan delegation state has an invalid tool-call record.",
        );
      }
      throw continuationError("The saved Deep Scan sampling continuation has an invalid tool-call record.");
    }
  }
  return {
    version: 2,
    id: value.id,
    kind: value.kind,
    policy,
    delegation: { version: 1, children },
    messages: value.messages as SamplingMessage[],
    toolCalls: value.toolCalls as PersistedToolCall[],
    finalSubmissionAccepted: value.finalSubmissionAccepted,
  };
}

function validPersistedToolCall(value: Record<string, unknown>): boolean {
  if (
    typeof value.toolUseId !== "string"
    || !value.toolUseId
    || typeof value.name !== "string"
    || !value.name
    || !isNonnegativeInteger(value.assistantMessageIndex)
    || !isNonnegativeInteger(value.contentIndex)
    || typeof value.finalSubmissionAccepted !== "boolean"
    || !isObject(value.result)
  ) {
    return false;
  }
  if (
    value.delegatedChildOrdinal !== undefined
    && (
      value.name !== "delegate_security_task"
      || !isNonnegativeInteger(value.delegatedChildOrdinal)
      || value.delegatedChildOrdinal < 1
    )
  ) {
    return false;
  }
  if (value.result.location === "pending") {
    return isToolResultContent(value.result.block);
  }
  return value.result.location === "message"
    && isNonnegativeInteger(value.result.messageIndex)
    && isNonnegativeInteger(value.result.contentIndex);
}

function requireContent(value: unknown, label: string): asserts value is SamplingMessage["content"] {
  const blocks = Array.isArray(value) ? value : [value];
  if (blocks.length === 0 || blocks.some((block) => !isObject(block) || typeof block.type !== "string")) {
    throw continuationError(`${label} has invalid content.`);
  }
}

function isToolResultContent(value: unknown): value is SamplingToolResultContent {
  return Boolean(
    isObject(value)
    && value.type === "tool_result"
    && typeof value.toolUseId === "string"
    && Array.isArray(value.content)
    && value.content.every((block) => (
      isObject(block) && block.type === "text" && typeof block.text === "string"
    )),
  );
}

function isNonnegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function protocolError(message: string): DeepScanNonRetryableError {
  return new DeepScanNonRetryableError(message);
}

function continuationError(message: string): DeepScanNonRetryableError {
  return new DeepScanNonRetryableError(message);
}
