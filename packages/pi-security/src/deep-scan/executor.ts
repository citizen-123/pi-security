import { randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import {
  createAgentSession,
  DefaultResourceLoader,
  getAgentDir,
  SessionManager,
  type AgentSession,
  type CreateAgentSessionOptions,
  type ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import { Type, type TSchema } from "typebox";
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
} from "./worker-policy.js";
import { DeepScanNonRetryableError } from "./errors.js";
import {
  createWorkerTools,
  type BoundWorkerTools,
  type DelegatedSecurityTaskExecution,
  type WorkerToolResult,
  validateDelegatedSecurityTaskResult,
} from "./worker-tools.js";
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

type NativeMessage = AgentSession["messages"][number];

export interface NativeWorkerSettings {
  model?: CreateAgentSessionOptions["model"];
  thinkingLevel?: CreateAgentSessionOptions["thinkingLevel"];
  /** Injectable monotonic-enough clock for deterministic diagnostics. */
  now?: () => number;
}

interface PersistedWorkerToolCall {
  id: string;
  name: string;
  input: Record<string, unknown>;
  finalSubmissionAccepted: boolean;
  delegatedChildOrdinal?: number;
  result: WorkerToolResult;
}

interface WorkerContinuation {
  version: 3;
  id: string;
  kind: DeepScanWorkerKind;
  policy: PersistedWorkerExecutionPolicies;
  delegation: {
    version: 1;
    children: DelegationMarker[];
  };
  messages: NativeMessage[];
  toolCalls: PersistedWorkerToolCall[];
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

const CONTINUATION_FILE = "worker-continuation.json";
const LEGACY_CONTINUATION_FILE = "sampling-continuation.json";
const DELEGATED_OUTCOME_FILE = "delegated-outcome.json";

/** Execute one Deep Scan worker in an isolated native Pi agent session. */
export class NativePiWorkerExecutor implements PiWorkerExecutor {
  private readonly now: () => number;

  constructor(private readonly settings: NativeWorkerSettings = {}) {
    this.now = settings.now ?? Date.now;
  }

  async validateContinuationPolicy(
    request: PiWorkerContinuationValidationRequest,
  ): Promise<void> {
    if (!hasContinuationId(request.resumeContinuationId)) {
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
    const continuationContext = await continuationArtifactContext(request);
    const continuation = await readContinuation(
      continuationContext,
      request.resumeContinuationId,
      request.kind,
    );
    reissueWorkerExecutionPolicies(continuation.policy, {
      source: request.executionContext,
      artifactWriter: request.artifactWriterContext,
    });
    const recovery = reissueDelegationPolicies(continuation, request, false);
    await validateDelegatedContinuationPolicies(
      continuation,
      continuationContext,
      request,
      recovery.activeChildOrdinals,
      recovery.recoveredDelegationContexts,
    );
  }

  async run(request: PiWorkerRequest): Promise<PiWorkerResult> {
    if (
      request.resumeContinuationId !== undefined
      && !hasContinuationId(request.resumeContinuationId)
    ) {
      throw continuationError("Worker execution requires a non-empty continuation ID.");
    }
    const diagnostics = new NativeDiagnosticsCollector(
      this.settings.thinkingLevel,
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
    diagnostics: NativeDiagnosticsCollector,
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
    const continuationContext = await continuationArtifactContext(request);

    let continuation: WorkerContinuation;
    let executionContext = request.executionContext;
    let artifactWriterContext = request.artifactWriterContext;
    const created = request.resumeContinuationId === undefined;
    if (request.resumeContinuationId) {
      continuation = await readContinuation(
        continuationContext,
        request.resumeContinuationId,
        request.kind,
      );
      const restored = reissueWorkerExecutionPolicies(continuation.policy, {
        source: request.executionContext,
        artifactWriter: request.artifactWriterContext,
      });
      executionContext = restored.source;
      artifactWriterContext = restored.artifactWriter;
    } else {
      continuation = {
        version: 3,
        id: randomUUID(),
        kind: request.kind,
        policy: snapshotWorkerExecutionPolicies({
          source: executionContext,
          artifactWriter: artifactWriterContext,
        }),
        delegation: { version: 1, children: [] },
        messages: [],
        toolCalls: [],
        finalSubmissionAccepted: false,
      };
    }

    const canDelegate = request.kind !== "dedup"
      && request.delegation === undefined
      && request.subagents > 0;
    const recovery = reissueDelegationPolicies(
      continuation,
      request,
      request.delegation !== undefined,
    );
    await validateDelegatedContinuationPolicies(
      continuation,
      continuationContext,
      request,
      recovery.activeChildOrdinals,
      recovery.recoveredDelegationContexts,
    );

    let delegatingExecutionContext = executionContext;
    let recoveryDelegationAuthority = continuation.delegation.children.some(
      (candidate) => !recovery.recordedChildOrdinals.has(candidate.ordinal),
    )
      ? request.executionContext
      : undefined;
    let tools!: BoundWorkerTools;
    tools = await createWorkerTools({
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
              (candidate) => !recovery.recordedChildOrdinals.has(candidate.ordinal),
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
              const recoveredContext = recovery.recoveredDelegationContexts.get(marker.ordinal);
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
            recovery.recordedChildOrdinals.add(marker.ordinal);
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
      workerSessions: true,
      targetHandles: true,
      artifactRoots: true,
      ...(request.resumeContinuationId ? { continuationPolicy: true } : {}),
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
    request.signal.throwIfAborted();
    if (created) {
      await writeContinuation(continuationContext, continuation, true);
      await request.onContinuationStarted?.(continuation.id);
    }

    const prompt = await readBoundWorkerPrompt(request);
    const resourceLoader = new DefaultResourceLoader({
      cwd: request.workingDirectory,
      agentDir: getAgentDir(),
      noExtensions: true,
      noSkills: true,
      noPromptTemplates: true,
      noThemes: true,
      noContextFiles: true,
      systemPrompt: systemPrompt(
        request.kind,
        request.delegation !== undefined,
        this.settings.thinkingLevel,
      ),
    });
    await resourceLoader.reload();

    let session: AgentSession | undefined;
    const customTools = createNativeToolDefinitions(
      tools,
      request,
      continuation,
      diagnostics,
    );
    const createdSession = await createAgentSession({
      cwd: request.workingDirectory,
      agentDir: getAgentDir(),
      ...(this.settings.model ? { model: this.settings.model } : {}),
      ...(this.settings.thinkingLevel
        ? { thinkingLevel: this.settings.thinkingLevel }
        : {}),
      noTools: "all",
      tools: customTools.map((tool) => tool.name),
      customTools,
      resourceLoader,
      sessionManager: SessionManager.inMemory(request.workingDirectory),
    });
    session = createdSession.session;
    session.agent.state.messages = [...continuation.messages];
    diagnostics.recordEffectivePolicy(effectivePolicy);

    let persistenceTail = Promise.resolve();
    const persistSession = (): void => {
      continuation.messages = cloneMessages(session!.messages);
      persistenceTail = persistenceTail.then(
        () => writeContinuation(tools.context, continuation),
      );
    };
    const unsubscribe = session.subscribe((event) => {
      diagnostics.recordEvent(event);
      if (
        event.type === "tool_execution_end"
        || event.type === "agent_end"
        || event.type === "agent_settled"
      ) {
        persistSession();
      }
    });
    const abortSession = (): void => {
      void session?.abort();
    };
    request.signal.addEventListener("abort", abortSession, { once: true });

    try {
      request.signal.throwIfAborted();
      if (created || continuation.messages.length === 0) {
        await session.prompt(
          initialInstruction(prompt, request.delegation !== undefined),
          { expandPromptTemplates: false, source: "extension" },
        );
      } else if (request.continuationPrompt) {
        await session.prompt(request.continuationPrompt, {
          expandPromptTemplates: false,
          source: "extension",
        });
      } else if (continuation.finalSubmissionAccepted) {
        // The durable final tool result already completed this worker.
      } else if (session.messages.at(-1)?.role === "toolResult") {
        await session.agent.continue();
      } else {
        await session.prompt(
          "Continue the assigned Pi Security worker task and submit its required final result.",
          { expandPromptTemplates: false, source: "extension" },
        );
      }
      await session.waitForIdle();
      request.signal.throwIfAborted();
      const delegatedResult = tools.delegatedResult();
      return {
        finalResponse: finalAssistantText(session.messages)
          || (continuation.finalSubmissionAccepted
            ? "Deep Scan artifact submission accepted."
            : ""),
        continuationId: continuation.id,
        ...(request.delegation && delegatedResult ? { delegatedResult } : {}),
      };
    } finally {
      request.signal.removeEventListener("abort", abortSession);
      unsubscribe();
      diagnostics.recordSession(session);
      try {
        await persistenceTail;
        continuation.messages = cloneMessages(session.messages);
        await writeContinuation(tools.context, continuation);
      } finally {
        session.dispose();
      }
    }
  }

  private async runDelegatedTask(input: {
    parent: PiWorkerRequest;
    parentContext: ArtifactContext;
    executionContext: ExecutionPolicyContext;
    marker: DelegationMarker;
    signal: AbortSignal;
    diagnostics: NativeDiagnosticsCollector;
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
    const { deepReducer: _deepReducer, ...inheritedArtifactContext } = input.parent.artifactContext;
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
      const persisted = await readDelegatedChildOutcome(
        input.executionContext,
        childArtifactContext,
      );
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
      const child = await this.run({
        kind: "discovery",
        promptPath,
        workingDirectory: childRoot,
        subagents: 0,
        signal: input.signal,
        ...(childContinuation
          ? {
            resumeContinuationId: childContinuation.id,
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
        throw new Error("Nested worker ended without a validated delegated security result.");
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

function createNativeToolDefinitions(
  tools: BoundWorkerTools,
  request: PiWorkerRequest,
  continuation: WorkerContinuation,
  diagnostics: NativeDiagnosticsCollector,
): ToolDefinition[] {
  return tools.definitions().map((definition) => ({
    name: definition.name,
    label: definition.annotations.title,
    description: definition.description,
    parameters: Type.Unsafe(definition.inputSchema as TSchema),
    // The durable ledger and final artifact transitions are single-writer
    // operations. In particular, recovery admits at most one active child.
    executionMode: (
      definition.name === "delegate_security_task"
      || !definition.annotations.readOnlyHint
    ) ? "sequential" : "parallel",
    async execute(toolCallId, params, signal) {
      diagnostics.recordToolCall();
      try {
        const input = params as Record<string, unknown>;
        const existing = continuation.toolCalls.find((call) => call.id === toolCallId);
        if (existing) {
          if (
            existing.name !== definition.name
            || JSON.stringify(existing.input) !== JSON.stringify(input)
          ) {
            throw new PolicyRecoveryRejectedError(
              "invalid_policy",
              "A resumed native tool call does not match its durable ledger.",
            );
          }
          if (existing.result.isError) {
            throw new Error(toolResultText(existing.result));
          }
          return { content: existing.result.content, details: {} };
        }
        const executed = await tools.execute(
          definition.name,
          input,
          signal ?? request.signal,
        );
        const record: PersistedWorkerToolCall = {
          id: toolCallId,
          name: definition.name,
          input,
          finalSubmissionAccepted: executed.finalSubmissionAccepted,
          result: JSON.parse(JSON.stringify(executed.result)) as WorkerToolResult,
          ...(executed.delegatedChildOrdinal === undefined
            ? {}
            : { delegatedChildOrdinal: executed.delegatedChildOrdinal }),
        };
        continuation.toolCalls.push(record);
        continuation.finalSubmissionAccepted ||= executed.finalSubmissionAccepted;
        if (executed.result.isError) {
          throw new Error(toolResultText(executed.result));
        }
        return { content: executed.result.content, details: {} };
      } catch (error) {
        diagnostics.recordToolFailure();
        throw error;
      }
    },
  }));
}

function reissueDelegationPolicies(
  continuation: WorkerContinuation,
  request: Pick<PiWorkerRequest, "kind" | "subagents" | "artifactContext">,
  delegatedTask: boolean,
): {
  recordedChildOrdinals: Set<number>;
  activeChildOrdinals: Set<number>;
  recoveredDelegationContexts: Map<number, ExecutionPolicyContext>;
} {
  const canDelegate = request.kind !== "dedup" && !delegatedTask && request.subagents > 0;
  if (
    continuation.delegation.children.length > request.subagents
    || (!canDelegate && continuation.delegation.children.length > 0)
  ) {
    throw new PolicyRecoveryRejectedError(
      "delegation_mismatch",
      "The saved Deep Scan delegation state exceeds the authoritative worker policy.",
    );
  }
  assertWorkerPolicyLedger(continuation.policy, continuation.delegation.children.length);
  const markers = new Map(
    continuation.delegation.children.map((marker) => [marker.ordinal, marker]),
  );
  const recordedChildOrdinals = new Set<number>();
  const callIds = new Set<string>();
  for (const call of continuation.toolCalls) {
    if (callIds.has(call.id)) {
      throw new PolicyRecoveryRejectedError(
        "invalid_policy",
        "The saved Deep Scan continuation contains a duplicate tool call.",
      );
    }
    callIds.add(call.id);
    if (call.delegatedChildOrdinal === undefined) continue;
    const marker = markers.get(call.delegatedChildOrdinal);
    if (!marker || call.name !== "delegate_security_task") {
      throw new PolicyRecoveryRejectedError(
        "invalid_policy",
        "A persisted delegated child is not bound to a delegation tool call.",
      );
    }
    if (recordedChildOrdinals.has(marker.ordinal)) {
      throw new PolicyRecoveryRejectedError(
        "invalid_policy",
        "The saved Deep Scan delegation state assigns one child marker to multiple tool calls.",
      );
    }
    assertDelegationMarkerInput(marker, call.input);
    recordedChildOrdinals.add(marker.ordinal);
  }
  const recoveredDelegationContexts = new Map<number, ExecutionPolicyContext>();
  for (const [index, marker] of continuation.delegation.children.entries()) {
    if (marker.ordinal !== index + 1 || recoveredDelegationContexts.has(marker.ordinal)) {
      throw new PolicyRecoveryRejectedError(
        "invalid_policy",
        "The saved Deep Scan delegation state has non-canonical child ordinals.",
      );
    }
    assertExactPolicySuccessor(marker.policy, 0, "delegated child");
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
  const activeChildOrdinals = new Set(
    continuation.delegation.children
      .map((marker) => marker.ordinal)
      .filter((ordinal) => !recordedChildOrdinals.has(ordinal)),
  );
  if (activeChildOrdinals.size > 1) {
    throw new PolicyRecoveryRejectedError(
      "invalid_policy",
      "The saved Deep Scan delegation state contains multiple active children.",
    );
  }
  return { recordedChildOrdinals, activeChildOrdinals, recoveredDelegationContexts };
}

function assertWorkerPolicyLedger(
  policy: PersistedWorkerExecutionPolicies,
  delegatedChildren: number,
): void {
  assertExactPolicySuccessor(policy.source, delegatedChildren, "worker source");
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
    || state.effective.delegation.remainingDepth !== state.authority.delegation.remainingDepth
  ) {
    throw new PolicyRecoveryRejectedError(
      "delegation_mismatch",
      `The saved ${label} policy does not exactly match its delegation ledger.`,
    );
  }
}

function assertDelegationMarkerInput(
  marker: DelegationMarker,
  input: Record<string, unknown>,
): void {
  const keys = Object.keys(input).sort();
  const task = typeof input.task === "string" ? input.task.trim() : "";
  const context = typeof input.context === "string" ? input.context.trim() : undefined;
  if (
    !task
    || (input.context !== undefined && !context)
    || keys.some((key) => key !== "context" && key !== "task")
    || marker.task !== task
    || (marker.context ?? undefined) !== context
  ) {
    throw new PolicyRecoveryRejectedError(
      "delegation_mismatch",
      "A delegated child does not match its persisted task marker.",
    );
  }
}

async function validateDelegatedContinuationPolicies(
  continuation: WorkerContinuation,
  parentContext: ArtifactContext,
  request: Pick<PiWorkerRequest, "artifactContext" | "executionContext">,
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
    const { deepReducer: _deepReducer, ...inheritedArtifactContext } = request.artifactContext;
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
    const childContinuation = await delegatedChildContinuation(childArtifactContext);
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

class NativeDiagnosticsCollector {
  private readonly startedAt: number;
  private requestCount = 0;
  private toolCallCount = 0;
  private toolFailureCount = 0;
  private retryCount = 0;
  private readonly models = new Set<string>();
  private usage: PiWorkerTokenUsage = {};
  private usageRecorded = false;
  private usageRequestCount = 0;
  private nestedTaskCount = 0;
  private nestedFailedTaskCount = 0;
  private nestedRequestCount = 0;
  private nestedToolCallCount = 0;
  private nestedToolFailureCount = 0;
  private nestedElapsedMs = 0;
  private readonly nestedModels = new Set<string>();
  private nestedUsage: PiWorkerTokenUsage = {};
  private nestedReportedRequestCount = 0;
  private nestedMissingRequestCount = 0;
  private enforcementCapabilities?: EnforcementCapabilityReport;
  private effectivePolicy?: EffectivePolicyDiagnostics;
  private appliedThinkingLevel: string | undefined;

  constructor(
    private readonly thinkingLevel: NativeWorkerSettings["thinkingLevel"],
    private readonly now: () => number,
  ) {
    this.startedAt = now();
  }

  recordEvent(event: { type: string; message?: unknown }): void {
    if (event.type === "turn_start") this.requestCount += 1;
    if (event.type === "auto_retry_start") this.retryCount += 1;
    const model = isObject(event.message) && typeof event.message.model === "string"
      ? event.message.model
      : undefined;
    if (model) this.models.add(model);
  }

  recordToolCall(): void {
    this.toolCallCount += 1;
  }

  recordToolFailure(): void {
    this.toolFailureCount += 1;
  }

  recordSession(session: AgentSession): void {
    const stats = session.getSessionStats();
    this.usage = {
      inputTokens: stats.tokens.input,
      cachedInputTokens: stats.tokens.cacheRead,
      cacheWriteInputTokens: stats.tokens.cacheWrite,
      outputTokens: stats.tokens.output,
      totalTokens: stats.tokens.total,
    };
    this.usageRecorded = true;
    this.usageRequestCount = session.messages.filter(
      (message) => message.role === "assistant",
    ).length;
    if (session.model?.id) this.models.add(session.model.id);
    if (this.requestCount > 0) this.appliedThinkingLevel = session.thinkingLevel;
  }

  recordNested(value: PiWorkerRunDiagnostics | undefined, failed: boolean): void {
    this.nestedTaskCount += 1;
    if (failed) this.nestedFailedTaskCount += 1;
    if (!value) return;
    this.nestedRequestCount += value.requestCount;
    this.nestedToolCallCount += value.toolCallCount;
    this.nestedToolFailureCount += value.toolFailureCount;
    this.nestedElapsedMs += value.elapsedMs;
    value.reportedModels.forEach((model) => this.nestedModels.add(model));
    if (value.usage) {
      addTokenUsage(this.nestedUsage, value.usage);
      this.nestedReportedRequestCount += value.usage.reportedRequestCount;
      this.nestedMissingRequestCount += value.usage.missingRequestCount;
    }
  }

  recordEnforcementCapabilities(value: EnforcementCapabilityReport): void {
    this.enforcementCapabilities = value;
  }

  recordEffectivePolicy(value: () => EffectivePolicyDiagnostics): void {
    this.effectivePolicy = value();
  }

  finish(): PiWorkerRunDiagnostics {
    const elapsedMs = Math.max(0, this.now() - this.startedAt);
    const ownUsage = this.usageRecorded
      ? projectedUsage(this.usage, this.usageRequestCount, 0)
      : null;
    const combinedUsage = ownUsage ? { ...ownUsage } : null;
    if (combinedUsage && (this.nestedReportedRequestCount || this.nestedMissingRequestCount)) {
      addTokenUsage(combinedUsage, this.nestedUsage);
      combinedUsage.reportedRequestCount += this.nestedReportedRequestCount;
      combinedUsage.missingRequestCount += this.nestedMissingRequestCount;
      combinedUsage.coverage = combinedUsage.missingRequestCount === 0 ? "complete" : "partial";
    }
    return {
      requestCount: this.requestCount + this.nestedRequestCount,
      toolCallCount: this.toolCallCount + this.nestedToolCallCount,
      toolFailureCount: this.toolFailureCount + this.nestedToolFailureCount,
      retryCount: this.retryCount,
      elapsedMs,
      reportedModels: [...new Set([...this.models, ...this.nestedModels])].sort(),
      reasoning: {
        requested: this.thinkingLevel ?? null,
        applied: this.appliedThinkingLevel ?? null,
        acknowledgedRequestCount: this.appliedThinkingLevel ? this.requestCount : 0,
      },
      usage: combinedUsage,
      nested: {
        taskCount: this.nestedTaskCount,
        failedTaskCount: this.nestedFailedTaskCount,
        requestCount: this.nestedRequestCount,
        toolCallCount: this.nestedToolCallCount,
        toolFailureCount: this.nestedToolFailureCount,
        elapsedMs: this.nestedElapsedMs,
        reportedModels: [...this.nestedModels].sort(),
        usage: this.nestedReportedRequestCount || this.nestedMissingRequestCount
          ? {
            ...this.nestedUsage,
            coverage: this.nestedMissingRequestCount === 0 ? "complete" : "partial",
            reportedRequestCount: this.nestedReportedRequestCount,
            missingRequestCount: this.nestedMissingRequestCount,
          }
          : null,
      },
      ...(this.enforcementCapabilities ? { enforcementCapabilities: this.enforcementCapabilities } : {}),
      ...(this.effectivePolicy ? { effectivePolicy: this.effectivePolicy } : {}),
    };
  }
}

function projectedUsage(
  usage: PiWorkerTokenUsage,
  reportedRequestCount: number,
  missingRequestCount: number,
): PiWorkerUsageDiagnostics {
  return {
    ...usage,
    coverage: missingRequestCount === 0 ? "complete" : "partial",
    reportedRequestCount,
    missingRequestCount,
  };
}

function addTokenUsage(
  destination: PiWorkerTokenUsage,
  source: PiWorkerTokenUsage,
): void {
  for (const key of [
    "inputTokens",
    "cachedInputTokens",
    "cacheWriteInputTokens",
    "outputTokens",
    "reasoningOutputTokens",
    "totalTokens",
  ] as const) {
    if (source[key] !== undefined) destination[key] = (destination[key] ?? 0) + source[key];
  }
}

function notifyDiagnostics(request: PiWorkerRequest, diagnostics: PiWorkerRunDiagnostics): void {
  try {
    request.onDiagnostics?.(diagnostics);
  } catch {
    // Diagnostics are optional and cannot stop the worker.
  }
}

function delegatedTaskPrompt(input: { task: string; context?: string }): string {
  return [
    "Investigate this bounded repository-security task for the parent worker:",
    input.task,
    ...(input.context ? ["", "Shared context:", input.context] : []),
  ].join("\n");
}

async function readDelegatedChildOutcome(
  executionContext: ExecutionPolicyContext,
  context: ArtifactContext,
): Promise<DelegatedChildOutcome | undefined> {
  const value = await readOptionalArtifactJson(
    context,
    [DELEGATED_OUTCOME_FILE],
    "delegated security task outcome",
  );
  if (!value) return undefined;
  if (value.version !== 1 || (value.status !== "succeeded" && value.status !== "failed")) {
    throw new DeepScanNonRetryableError("Delegated security task outcome is invalid.");
  }
  if (value.status === "succeeded") {
    return {
      result: await validateDelegatedSecurityTaskResult(
        executionContext,
        context,
        value.result,
      ),
    };
  }
  if (typeof value.error !== "string" || !value.error.trim()) {
    throw new DeepScanNonRetryableError("Failed delegated security task outcome has no error.");
  }
  return { error: value.error };
}

async function writeDelegatedChildOutcome(
  context: ArtifactContext,
  outcome: DelegatedChildOutcome,
): Promise<void> {
  const value: PersistedDelegatedChildOutcome = outcome.error === undefined
    ? { version: 1, status: "succeeded", result: outcome.result }
    : { version: 1, status: "failed", error: outcome.error };
  await replaceArtifactJson(context, DELEGATED_OUTCOME_FILE, value);
}

async function delegatedChildContinuation(
  context: ArtifactContext,
): Promise<WorkerContinuation | undefined> {
  const value = await readOptionalArtifactJson(
    context,
    [CONTINUATION_FILE],
    "delegated worker continuation",
  );
  if (value) return parseContinuation(value);
  const legacy = await readOptionalArtifactJson(
    context,
    [LEGACY_CONTINUATION_FILE],
    "legacy delegated worker continuation",
  );
  return legacy ? migrateLegacyContinuation(legacy) : undefined;
}

async function readOptionalArtifactJson(
  context: ArtifactContext,
  components: readonly string[],
  label: string,
): Promise<Record<string, unknown> | undefined> {
  const path = await artifactDestination(context, components, label);
  const exists = await fs.lstat(path).catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return undefined;
    throw error;
  });
  if (!exists) return undefined;
  return readArtifactJsonObject(context, components, label);
}

function initialInstruction(prompt: string, delegatedTask: boolean): string {
  return [
    prompt,
    "",
    delegatedTask ? "NATIVE PI DELEGATED WORKER CONTRACT" : "NATIVE PI WORKER CONTRACT",
    "Use only the supplied Pi Security worker tools to inspect source and scan context.",
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
  thinkingLevel: NativeWorkerSettings["thinkingLevel"],
): string {
  const purpose = delegatedTask
    ? "Investigate the assigned scoped repository-security task for a parent worker. Use only the supplied target-bound tools and return validated evidence for parent synthesis."
    : kind === "dedup"
      ? "Semantically reduce the assigned Pi Security scan drafts. Use only the supplied reducer tools and obey their schemas."
      : "Perform the requested repository security analysis. Use only the supplied target-bound tools and obey the semantic scan-draft schema.";
  return thinkingLevel
    ? `${purpose} The host selected Pi thinking level ${JSON.stringify(thinkingLevel)}.`
    : purpose;
}

async function continuationArtifactContext(
  request: Pick<PiWorkerRequest, "artifactContext" | "artifactWriterContext">,
): Promise<ArtifactContext> {
  return createWorkerArtifactContext({
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
}

async function readContinuation(
  context: ArtifactContext,
  expectedId: string,
  expectedKind: DeepScanWorkerKind,
): Promise<WorkerContinuation> {
  let continuation: WorkerContinuation;
  const native = await readOptionalArtifactJson(
    context,
    [CONTINUATION_FILE],
    "native worker continuation",
  );
  if (native) {
    continuation = parseContinuation(native);
  } else {
    const legacy = await readOptionalArtifactJson(
      context,
      [LEGACY_CONTINUATION_FILE],
      "legacy worker continuation",
    );
    if (!legacy) {
      throw continuationError("Worker continuation does not exist.");
    }
    continuation = migrateLegacyContinuation(legacy);
    await writeContinuation(context, continuation, true);
    const legacyPath = await artifactDestination(
      context,
      [LEGACY_CONTINUATION_FILE],
      "legacy worker continuation",
    );
    await fs.unlink(legacyPath);
  }
  if (continuation.id !== expectedId || continuation.kind !== expectedKind) {
    throw continuationError("Worker continuation identity does not match the requested worker.");
  }
  return continuation;
}

async function writeContinuation(
  context: ArtifactContext,
  continuation: WorkerContinuation,
  createOnly = false,
): Promise<void> {
  if (!createOnly) {
    await replaceArtifactJson(context, CONTINUATION_FILE, continuation);
    return;
  }
  const destination = await artifactDestination(
    context,
    [CONTINUATION_FILE],
    "native worker continuation",
  );
  await fs.mkdir(dirname(destination), { recursive: true });
  await fs.writeFile(destination, `${JSON.stringify(continuation, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
}

async function readBoundWorkerPrompt(request: PiWorkerRequest): Promise<string> {
  const prompt = await openExecutionWorkerInput(
    request.executionContext,
    request.promptPath,
    "file",
    "Deep Scan worker prompt",
  );
  try {
    const workerRoot = resolve(request.artifactContext.workerRoot);
    const promptPath = resolve(prompt.absolute);
    const relativePrompt = relative(workerRoot, promptPath);
    if (
      relativePrompt === ""
      || relativePrompt === ".."
      || relativePrompt.startsWith(`..${sep}`)
      || resolve(workerRoot, relativePrompt) !== promptPath
    ) {
      throw new Error("Deep Scan worker prompt escaped its host-created worker directory.");
    }
    const source = await prompt.handle.readFile({ encoding: "utf8" });
    if (!source.trim()) throw new Error("Deep Scan worker prompt is empty.");
    return source;
  } finally {
    await prompt.handle.close();
  }
}

function parseContinuation(value: Record<string, unknown>): WorkerContinuation {
  if (
    value.version !== 3
    || typeof value.id !== "string"
    || !value.id
    || (value.kind !== "setup" && value.kind !== "discovery" && value.kind !== "dedup")
    || !Array.isArray(value.messages)
    || !Array.isArray(value.toolCalls)
    || !isObject(value.delegation)
    || value.delegation.version !== 1
    || !Array.isArray(value.delegation.children)
    || typeof value.finalSubmissionAccepted !== "boolean"
  ) {
    throw continuationError("Native worker continuation is invalid.");
  }
  const messages = value.messages.map(parseNativeMessage);
  const toolCalls = value.toolCalls.map(parsePersistedToolCall);
  const acceptedFinalSubmission = toolCalls.some(
    (call) => call.finalSubmissionAccepted,
  );
  if (
    value.finalSubmissionAccepted !== acceptedFinalSubmission
    || toolCalls.some((call) => (
      call.finalSubmissionAccepted && call.result.isError
    ))
  ) {
    throw continuationError(
      "Native worker continuation has an inconsistent final submission state.",
    );
  }
  const children = value.delegation.children.map(parseDelegationMarker);
  return {
    version: 3,
    id: value.id,
    kind: value.kind,
    policy: parseWorkerExecutionPolicies(value.policy),
    delegation: { version: 1, children },
    messages,
    toolCalls,
    finalSubmissionAccepted: value.finalSubmissionAccepted,
  };
}

function migrateLegacyContinuation(value: Record<string, unknown>): WorkerContinuation {
  if (
    value.version !== 2
    || typeof value.id !== "string"
    || !value.id
    || (value.kind !== "setup" && value.kind !== "discovery" && value.kind !== "dedup")
    || !Array.isArray(value.messages)
    || value.messages.length !== 1
    || !Array.isArray(value.toolCalls)
    || value.toolCalls.length !== 0
    || !isObject(value.delegation)
    || value.delegation.version !== 1
    || !Array.isArray(value.delegation.children)
    || value.delegation.children.length !== 0
    || value.finalSubmissionAccepted !== false
  ) {
    throw new PolicyRecoveryRejectedError(
      "legacy_continuation",
      "The saved pre-native worker continuation cannot be migrated safely.",
    );
  }
  const legacyMessage = value.messages[0];
  if (!isObject(legacyMessage) || legacyMessage.role !== "user") {
    throw new PolicyRecoveryRejectedError(
      "legacy_continuation",
      "The saved pre-native worker message history cannot be restored safely.",
    );
  }
  const blocks = Array.isArray(legacyMessage.content)
    ? legacyMessage.content
    : [legacyMessage.content];
  if (
    blocks.length !== 1
    || !isObject(blocks[0])
    || blocks[0].type !== "text"
    || typeof blocks[0].text !== "string"
  ) {
    throw new PolicyRecoveryRejectedError(
      "legacy_continuation",
      "The saved pre-native worker message history cannot be restored safely.",
    );
  }
  const contract = "\n\nMCP SAMPLING TOOL CONTRACT";
  const delegatedContract = "\n\nMCP DELEGATED SAMPLING TOOL CONTRACT";
  const marker = blocks[0].text.includes(delegatedContract)
    ? delegatedContract
    : contract;
  const markerIndex = blocks[0].text.indexOf(marker);
  if (markerIndex < 1) {
    throw new PolicyRecoveryRejectedError(
      "legacy_continuation",
      "The saved pre-native worker message history cannot be restored safely.",
    );
  }
  const prompt = blocks[0].text.slice(0, markerIndex);
  const delegatedTask = marker === delegatedContract;
  return {
    version: 3,
    id: value.id,
    kind: value.kind,
    policy: parseWorkerExecutionPolicies(value.policy),
    delegation: { version: 1, children: [] },
    messages: [{
      role: "user",
      content: [{ type: "text", text: initialInstruction(prompt, delegatedTask) }],
      timestamp: 0,
    }],
    toolCalls: [],
    finalSubmissionAccepted: false,
  };
}

function parseDelegationMarker(value: unknown): DelegationMarker {
  if (
    !isObject(value)
    || !isNonnegativeInteger(value.ordinal)
    || value.ordinal < 1
    || typeof value.task !== "string"
    || !value.task.trim()
    || (value.context !== undefined && (typeof value.context !== "string" || !value.context.trim()))
  ) {
    throw continuationError("Worker continuation has invalid delegation state.");
  }
  return {
    ordinal: value.ordinal,
    task: value.task,
    ...(typeof value.context === "string" ? { context: value.context } : {}),
    policy: parseExecutionPolicyState(value.policy),
  };
}

function parsePersistedToolCall(value: unknown): PersistedWorkerToolCall {
  if (
    !isObject(value)
    || typeof value.id !== "string"
    || !value.id
    || typeof value.name !== "string"
    || !value.name
    || !isObject(value.input)
    || typeof value.finalSubmissionAccepted !== "boolean"
    || (value.delegatedChildOrdinal !== undefined && !isNonnegativeInteger(value.delegatedChildOrdinal))
  ) {
    throw continuationError("Native worker continuation has an invalid tool ledger.");
  }
  const result = parsePersistedWorkerToolResult(value.result);
  return {
    id: value.id,
    name: value.name,
    input: value.input,
    finalSubmissionAccepted: value.finalSubmissionAccepted,
    result,
    ...(typeof value.delegatedChildOrdinal === "number"
      ? { delegatedChildOrdinal: value.delegatedChildOrdinal }
      : {}),
  };
}

function parsePersistedWorkerToolResult(value: unknown): WorkerToolResult {
  if (
    !isObject(value)
    || !Array.isArray(value.content)
    || value.content.some((block) => (
      !isObject(block)
      || block.type !== "text"
      || typeof block.text !== "string"
    ))
    || (value.isError !== undefined && typeof value.isError !== "boolean")
  ) {
    throw continuationError("Native worker continuation has an invalid tool result.");
  }
  return {
    content: value.content as Array<{ type: "text"; text: string }>,
    ...(value.isError === true ? { isError: true } : {}),
  };
}

function parseNativeMessage(value: unknown): NativeMessage {
  if (
    !isObject(value)
    || (value.role !== "user" && value.role !== "assistant" && value.role !== "toolResult")
    || !isSafeJson(value)
  ) {
    throw continuationError("Native worker continuation has an invalid message transcript.");
  }
  return value as unknown as NativeMessage;
}

function cloneMessages(messages: readonly NativeMessage[]): NativeMessage[] {
  return JSON.parse(JSON.stringify(messages)) as NativeMessage[];
}

function finalAssistantText(messages: readonly NativeMessage[]): string {
  const assistant = [...messages].reverse().find((message) => message.role === "assistant");
  if (!assistant || !Array.isArray(assistant.content)) return "";
  return assistant.content
    .filter((block): block is { type: "text"; text: string } => (
      isObject(block) && block.type === "text" && typeof block.text === "string"
    ))
    .map((block) => block.text)
    .join("\n");
}

function toolResultText(result: WorkerToolResult): string {
  return result.content.map((item) => item.text).join("\n");
}

function isSafeJson(value: unknown, seen = new Set<object>()): boolean {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value !== "object" || seen.has(value)) return false;
  seen.add(value);
  const valid = Array.isArray(value)
    ? value.every((item) => isSafeJson(item, seen))
    : Object.getPrototypeOf(value) === Object.prototype
      && Object.values(value).every((item) => isSafeJson(item, seen));
  seen.delete(value);
  return valid;
}

function hasContinuationId(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isNonnegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function continuationError(message: string): DeepScanNonRetryableError {
  return new DeepScanNonRetryableError(message);
}
