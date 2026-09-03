import { createHash, randomUUID } from "node:crypto";
import { realpath, stat } from "node:fs/promises";
import { resolve } from "node:path";
import {
  createExecutionSnapshot,
  type ResolvedExecutionConfig,
} from "../config/execution-config.js";
import {
  BUILT_IN_PHASE_REGISTRY,
  FULL_REPOSITORY_WORKFLOW,
  VALIDATED_FULL_REPOSITORY_WORKFLOW,
} from "../workflow/builtin.js";
import {
  scheduleWorkflow,
  type PhaseExecutor,
  type WorkflowScheduleResult,
} from "../workflow/scheduler.js";
import type { WorkflowPhaseState } from "../workflow/registry.js";
import type {
  OwnedRuntimeOperation,
  RuntimePhaseRecord,
  RuntimeRunRecord,
  RuntimeStateRepository,
} from "./state-repository.js";

export interface RuntimeOwnership {
  claimToken: string;
  controllerId: string;
}

export interface StartCanonicalRunInput extends RuntimeOwnership {
  config: ResolvedExecutionConfig;
  scanId?: string;
  targetRevision?: string;
}

export interface ResumeCanonicalRunInput extends RuntimeOwnership {
  config: ResolvedExecutionConfig;
  runId: string;
  targetRevision?: string;
}

export interface RetryCanonicalRunInput extends RuntimeOwnership {
  reusePhaseIds?: string[];
  scanId?: string;
  sourceRunId: string;
}

export interface CanonicalRunLifecycleOptions {
  abortActiveAttempts?: (runId: string) => Promise<void>;
  executors: Readonly<Record<string, PhaseExecutor>>;
  repository: RuntimeStateRepository;
}

interface ActiveExecution {
  abort: AbortController;
  outcome: "canceled" | "interrupted" | undefined;
  reason: string | undefined;
  settled: Promise<RuntimeRunRecord>;
}

export class CanonicalRunLifecycle {
  readonly #options: CanonicalRunLifecycleOptions;
  readonly #active = new Map<string, ActiveExecution>();

  constructor(options: CanonicalRunLifecycleOptions) {
    this.#options = options;
  }

  async createAndClaim(input: StartCanonicalRunInput): Promise<RuntimeRunRecord> {
    validateConfig(input.config);
    const targetPath = await canonicalTarget(input.config.scan.target);
    const snapshot = createExecutionSnapshot({
      ...input.config,
      scan: { ...input.config.scan, target: targetPath },
    });
    const policyDigest = executionPolicyDigest(snapshot.digest);
    const created = await this.#options.repository.createRun({
      policyDigest,
      runId: randomUUID(),
      scanId: input.scanId,
      snapshot: snapshot as unknown as Record<string, unknown>,
      snapshotDigest: snapshot.digest,
      targetPath,
      targetRevision: input.targetRevision,
      workflow: FULL_REPOSITORY_WORKFLOW as unknown as Record<string, unknown>,
    });
    return await this.#options.repository.claimRun({
      claimToken: input.claimToken,
      controllerId: input.controllerId,
      expectedVersion: created.version,
      runId: created.id,
    });
  }

  async start(input: StartCanonicalRunInput): Promise<RuntimeRunRecord> {
    const claimed = await this.createAndClaim(input);
    return await this.execute(claimed, input);
  }

  async execute(run: RuntimeRunRecord, ownership: RuntimeOwnership): Promise<RuntimeRunRecord> {
    if (run.status !== "running" || run.controllerId !== ownership.controllerId) {
      throw new Error("Canonical run is not owned by this controller.");
    }
    if (this.#active.has(run.id)) throw new Error("Canonical run already has an active executor.");
    const abort = new AbortController();
    let settle!: (run: RuntimeRunRecord) => void;
    let reject!: (error: unknown) => void;
    const settled = new Promise<RuntimeRunRecord>((resolvePromise, rejectPromise) => {
      settle = resolvePromise;
      reject = rejectPromise;
    });
    const active: ActiveExecution = { abort, outcome: undefined, reason: undefined, settled };
    this.#active.set(run.id, active);
    try {
      const terminal = await this.#executeClaimed(run, ownership, active);
      settle(terminal);
      return terminal;
    } catch (error) {
      const current = await this.#options.repository.getRun(run.id);
      if (current.status === "running") {
        const failed = await this.#options.repository.transition({
          ...owned(current, ownership),
          event: {
            category: "domain",
            kind: "run.failed",
            payload: { coverageConclusion: "inconclusive", reason: errorMessage(error) },
            source: "runtime",
          },
          progress: { ...current.progress, coverageConclusion: "inconclusive" },
          status: "failed",
          statusReason: errorMessage(error),
        });
        settle(failed);
        return failed;
      }
      reject(error);
      throw error;
    } finally {
      this.#active.delete(run.id);
    }
  }

  async cancel(runId: string, ownership: RuntimeOwnership): Promise<RuntimeRunRecord> {
    const active = this.#active.get(runId);
    if (!active) throw new Error("Canonical run has no active executor to cancel.");
    const run = await this.#options.repository.getRun(runId);
    if (run.status !== "running" || run.controllerId !== ownership.controllerId) {
      throw new Error("Canonical run cancellation authority does not match.");
    }
    active.outcome = "canceled";
    active.reason = "Canonical run canceled by operator.";
    active.abort.abort(new Error(active.reason));
    await this.#options.abortActiveAttempts?.(runId);
    return await active.settled;
  }

  async interrupt(runId: string, ownership: RuntimeOwnership, reason: string): Promise<RuntimeRunRecord> {
    const active = this.#active.get(runId);
    if (active) {
      const run = await this.#options.repository.getRun(runId);
      if (run.status !== "running" || run.controllerId !== ownership.controllerId) {
        throw new Error("Canonical run interruption authority does not match.");
      }
      active.outcome = "interrupted";
      active.reason = reason;
      active.abort.abort(new Error(reason));
      return await active.settled;
    }
    const run = await this.#options.repository.getRun(runId);
    return await this.#options.repository.transition({
      ...owned(run, ownership),
      event: {
        category: "domain",
        kind: "run.interrupted",
        payload: { coverageConclusion: "inconclusive", reason },
        source: "runtime",
      },
      progress: { ...run.progress, coverageConclusion: "inconclusive" },
      status: "interrupted",
      statusReason: reason,
    });
  }

  async resume(input: ResumeCanonicalRunInput): Promise<RuntimeRunRecord> {
    const run = await this.#options.repository.getRun(input.runId);
    if (run.status !== "interrupted") {
      throw new Error(`Canonical run in state ${run.status} cannot resume.`);
    }
    validateConfig(input.config);
    const targetPath = await canonicalTarget(input.config.scan.target);
    const snapshot = createExecutionSnapshot({
      ...input.config,
      scan: { ...input.config.scan, target: targetPath },
    });
    const policyDigest = executionPolicyDigest(snapshot.digest);
    if (
      run.snapshotDigest !== snapshot.digest ||
      run.policyDigest !== policyDigest ||
      run.targetPath !== targetPath ||
      run.targetRevision !== (input.targetRevision ?? null) ||
      stableJson(run.workflow) !== stableJson(FULL_REPOSITORY_WORKFLOW)
    ) {
      throw Object.assign(new Error("Canonical run resume authority or execution identity changed."), {
        code: "AUTHORITY_MISMATCH",
      });
    }
    validatePersistedOutputs(run);
    const claimed = await this.#options.repository.claimRun({
      claimToken: input.claimToken,
      controllerId: input.controllerId,
      expectedVersion: run.version,
      runId: run.id,
    });
    return await this.execute(claimed, input);
  }

  async retry(input: RetryCanonicalRunInput): Promise<RuntimeRunRecord> {
    const source = await this.#options.repository.getRun(input.sourceRunId);
    if (source.status !== "failed") {
      throw new Error(`Canonical run in state ${source.status} cannot be retried.`);
    }
    const requested = new Set(input.reusePhaseIds ?? []);
    const unknown = [...requested].filter(
      (phaseId) => !VALIDATED_FULL_REPOSITORY_WORKFLOW.order.includes(phaseId)
    );
    if (unknown.length > 0) {
      throw new Error(`Unknown reusable phase: ${unknown.join(", ")}.`);
    }
    const reusePlan: RuntimePhaseRecord[] = [];
    const validated = new Set<string>();
    for (const phaseId of VALIDATED_FULL_REPOSITORY_WORKFLOW.order) {
      if (!requested.has(phaseId)) continue;
      const sourcePhase = phaseRecord(source, phaseId);
      if (
        sourcePhase.state !== "completed" && sourcePhase.state !== "reused" ||
        sourcePhase.output === null ||
        !sourcePhase.outputDigest ||
        !sourcePhase.inputDigest
      ) {
        throw new Error(`Source phase ${phaseId} has no immutable reusable output.`);
      }
      const definition = BUILT_IN_PHASE_REGISTRY.get(sourcePhase.type, sourcePhase.phaseVersion);
      definition.outputSchema.parse(sourcePhase.output);
      const workflowPhase = VALIDATED_FULL_REPOSITORY_WORKFLOW.definition.phases.find(
        (phase) => phase.id === phaseId
      );
      if (!workflowPhase || workflowPhase.dependencies.some((dependency) => !validated.has(dependency))) {
        throw new Error(`Reusable phase ${phaseId} requires its reusable dependency prefix.`);
      }
      reusePlan.push(sourcePhase);
      validated.add(phaseId);
    }
    const created = await this.#options.repository.createRun({
      parentRunId: source.id,
      policyDigest: source.policyDigest,
      runId: randomUUID(),
      scanId: input.scanId,
      snapshot: source.snapshot,
      snapshotDigest: source.snapshotDigest,
      targetPath: source.targetPath,
      targetRevision: source.targetRevision ?? undefined,
      workflow: source.workflow,
    });
    let target = await this.#options.repository.claimRun({
      claimToken: input.claimToken,
      controllerId: input.controllerId,
      expectedVersion: created.version,
      runId: created.id,
    });
    for (const sourcePhase of reusePlan) {
      const phaseId = sourcePhase.id;
      const targetPhase = phaseRecord(target, phaseId);
      target = await this.#options.repository.transition({
        ...owned(target, input),
        event: {
          category: "domain",
          kind: "phase.input_rebound",
          phaseId,
          source: "runtime",
        },
        phase: {
          expectedVersion: targetPhase.version,
          id: phaseId,
          inputDigest: sourcePhase.inputDigest!,
          state: "ready",
        },
      });
      target = await this.#options.repository.reuseOutput({
        ...owned(target, input),
        phaseId,
        sourceOutputDigest: sourcePhase.outputDigest!,
        sourcePhaseId: phaseId,
        sourceRunId: source.id,
        validation: {
          input: true,
          policy: true,
          schema: true,
          target: true,
          type: true,
          version: true,
        },
      });
    }
    return target;
  }

  async #executeClaimed(
    initial: RuntimeRunRecord,
    ownership: RuntimeOwnership,
    execution: ActiveExecution
  ): Promise<RuntimeRunRecord> {
    let current = initial;
    const initialStates: Record<string, WorkflowPhaseState> = {};
    const initialOutputs: Record<string, unknown> = {};
    for (const phase of current.phases) {
      if (phase.state === "completed" || phase.state === "reused") {
        initialStates[phase.id] = "completed";
        initialOutputs[phase.id] = phase.output;
      } else {
        initialStates[phase.id] = "pending";
      }
    }
    let result: WorkflowScheduleResult;
    try {
      result = await scheduleWorkflow({
        executors: this.#options.executors,
        initialOutputs,
        initialStates,
        maxParallel: Number(current.snapshot.resolved && (current.snapshot.resolved as Record<string, unknown>).execution
          ? ((current.snapshot.resolved as Record<string, Record<string, unknown>>).execution.maxParallel ?? 1)
          : 1),
        onPhaseSettled: async (phase, state, output, error) => {
          const persisted = phaseRecord(current, phase.id);
          const persistedState = state === "canceled" && execution.outcome === "interrupted"
            ? "interrupted"
            : state;
          current = await this.#options.repository.transition({
            ...owned(current, ownership),
            event: {
              category: "domain",
              kind: `phase.${persistedState}`,
              payload: error ? { error: errorMessage(error) } : {},
              phaseId: phase.id,
              source: "runtime",
            },
            phase: {
              expectedVersion: persisted.version,
              id: phase.id,
              ...(persistedState === "completed" ? { output, outputDigest: digest(output) } : {}),
              state: persistedState,
            },
          });
        },
        onPhaseStarted: async (phase, inputs) => {
          const persisted = phaseRecord(current, phase.id);
          current = await this.#options.repository.transition({
            ...owned(current, ownership),
            event: {
              category: "domain",
              kind: "phase.started",
              phaseId: phase.id,
              source: "runtime",
            },
            phase: {
              expectedVersion: persisted.version,
              id: phase.id,
              inputDigest: digest({
                inputs,
                phaseType: phase.type,
                policyDigest: current.policyDigest,
                targetPath: current.targetPath,
                targetRevision: current.targetRevision,
              }),
              state: "running",
            },
          });
        },
        registry: BUILT_IN_PHASE_REGISTRY,
        runId: current.id,
        signal: execution.abort.signal,
        workflow: VALIDATED_FULL_REPOSITORY_WORKFLOW,
      });
    } catch (error) {
      if (execution.abort.signal.aborted) {
        result = {
          errors: {},
          outputs: initialOutputs,
          states: Object.fromEntries(current.phases.map((phase) => [phase.id, "canceled"])),
          status: "canceled",
        };
      } else {
        throw error;
      }
    }
    current = await this.#persistUnsettledStates(current, ownership, result, execution.outcome);
    const complete = result.status === "completed"
      && result.states.publication === "completed"
      && Object.values(result.states).every((state) => state === "completed");
    const status = execution.outcome
      ?? (complete ? "completed" : result.status === "completed" ? "failed" : result.status);
    const conclusion = complete ? "complete" : "inconclusive";
    return await this.#options.repository.transition({
      ...owned(current, ownership),
      event: {
        category: "domain",
        kind: `run.${status}`,
        payload: { coverageConclusion: conclusion },
        source: "runtime",
      },
      progress: { ...current.progress, coverageConclusion: conclusion },
      status,
      statusReason: complete ? undefined : execution.reason
        ?? result.errors[Object.keys(result.errors)[0]]
        ?? status,
    });
  }

  async #persistUnsettledStates(
    initial: RuntimeRunRecord,
    ownership: RuntimeOwnership,
    result: WorkflowScheduleResult,
    outcome: ActiveExecution["outcome"]
  ): Promise<RuntimeRunRecord> {
    let current = initial;
    if (outcome === "interrupted") return current;
    for (const phaseId of VALIDATED_FULL_REPOSITORY_WORKFLOW.order) {
      const state = result.states[phaseId];
      const persisted = phaseRecord(current, phaseId);
      if (
        state === "completed" ||
        state === "running" ||
        (state === "canceled" && persisted.state === "canceled") ||
        (state === "skipped" && persisted.state === "skipped")
      ) {
        continue;
      }
      if (state !== "canceled" && state !== "skipped") continue;
      current = await this.#options.repository.transition({
        ...owned(current, ownership),
        event: {
          category: "domain",
          kind: `phase.${state}`,
          phaseId,
          source: "runtime",
        },
        phase: {
          expectedVersion: persisted.version,
          id: phaseId,
          state,
        },
      });
    }
    return current;
  }
}

function validateConfig(config: ResolvedExecutionConfig): void {
  if (config.scan.workflow !== "full-repository") {
    throw new Error(`Unsupported canonical workflow: ${config.scan.workflow}`);
  }
  if (!Number.isInteger(config.execution.maxParallel) || config.execution.maxParallel < 1) {
    throw new Error("Canonical workflow maxParallel must be a positive integer.");
  }
}

async function canonicalTarget(path: string): Promise<string> {
  const target = await realpath(resolve(path));
  if (!(await stat(target)).isDirectory()) throw new Error("Canonical scan target must be a directory.");
  return target;
}

function executionPolicyDigest(snapshotDigest: string): string {
  return digest({
    phasePolicies: VALIDATED_FULL_REPOSITORY_WORKFLOW.definition.phases.map((phase) => {
      const definition = BUILT_IN_PHASE_REGISTRY.get(phase.type, phase.version);
      return {
        capability: definition.capability,
        phase: phase.id,
        roleId: phase.roleId ?? null,
      };
    }),
    snapshotDigest,
    workflowId: FULL_REPOSITORY_WORKFLOW.id,
    workflowVersion: FULL_REPOSITORY_WORKFLOW.version,
  });
}

function validatePersistedOutputs(run: RuntimeRunRecord): void {
  for (const phase of run.phases) {
    if (phase.state !== "completed" && phase.state !== "reused") continue;
    BUILT_IN_PHASE_REGISTRY.get(phase.type, phase.phaseVersion).outputSchema.parse(phase.output);
  }
}

function phaseRecord(run: RuntimeRunRecord, phaseId: string): RuntimePhaseRecord {
  const phase = run.phases.find((candidate) => candidate.id === phaseId);
  if (!phase) throw new Error(`Canonical run is missing phase ${phaseId}.`);
  return phase;
}

function owned(run: RuntimeRunRecord, ownership: RuntimeOwnership): OwnedRuntimeOperation {
  return {
    claimToken: ownership.claimToken,
    controllerId: ownership.controllerId,
    expectedVersion: run.version,
    runId: run.id,
  };
}

function digest(value: unknown): string {
  return `sha256:${createHash("sha256").update(stableJson(value)).digest("hex")}`;
}

function stableJson(value: unknown): string {
  return JSON.stringify(value, (_key, entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return entry;
    return Object.fromEntries(Object.entries(entry).sort(([left], [right]) => left.localeCompare(right)));
  });
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
