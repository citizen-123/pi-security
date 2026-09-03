import type { ZodType } from "zod";
import {
  type ClosedPhaseRegistry,
  type ValidatedWorkflow,
  type WorkflowPhaseDefinition,
  type WorkflowPhaseState,
} from "./registry.js";

export interface PhaseResultEnvelope {
  attemptId: string;
  output: unknown;
  phaseId: string;
  runId: string;
  schemaVersion: 1;
}

export interface PhaseExecutionContext {
  inputs: Record<string, unknown>;
  phase: WorkflowPhaseDefinition;
  runId: string;
  signal: AbortSignal;
}

export type PhaseExecutor = (
  context: PhaseExecutionContext
) => Promise<PhaseResultEnvelope | PhaseResultEnvelope[]>;

export interface WorkflowSchedulerOptions {
  executors: Readonly<Record<string, PhaseExecutor>>;
  maxParallel: number;
  onStateChange?: (phaseId: string, state: WorkflowPhaseState) => void;
  registry: ClosedPhaseRegistry;
  runId: string;
  signal?: AbortSignal;
  workflow: ValidatedWorkflow;
}
export function parsePhaseResultEnvelope(
  envelope: PhaseResultEnvelope,
  expected: { outputSchema: ZodType; phaseId: string; runId: string }
): unknown {
  if (
    envelope.schemaVersion !== 1 ||
    envelope.runId !== expected.runId ||
    envelope.phaseId !== expected.phaseId ||
    typeof envelope.attemptId !== "string" ||
    envelope.attemptId.length === 0
  ) {
    throw Object.assign(new Error("Phase result envelope is incompatible with its execution."), {
      code: "CONTRACT_INCOMPATIBLE",
    });
  }
  return expected.outputSchema.parse(envelope.output);
}


export interface WorkflowScheduleResult {
  errors: Record<string, string>;
  outputs: Record<string, unknown>;
  states: Record<string, WorkflowPhaseState>;
  status: "completed" | "failed" | "canceled";
}

interface SettledExecution {
  deliveries?: PhaseResultEnvelope[];
  error?: unknown;
  phaseId: string;
}

export class PhaseResultAdmission {
  readonly #admittedPhases = new Set<string>();
  readonly #deliveredAttempts = new Set<string>();

  admit(
    envelope: PhaseResultEnvelope,
    expected: { outputSchema: ZodType; phaseId: string; runId: string }
  ): { accepted: boolean; output?: unknown } {
    const output = parsePhaseResultEnvelope(envelope, expected);
    const deliveryKey = `${envelope.phaseId}:${envelope.attemptId}`;
    if (this.#deliveredAttempts.has(deliveryKey) || this.#admittedPhases.has(envelope.phaseId)) {
      return { accepted: false };
    }
    this.#deliveredAttempts.add(deliveryKey);
    this.#admittedPhases.add(envelope.phaseId);
    return { accepted: true, output };
  }
}

export async function scheduleWorkflow(options: WorkflowSchedulerOptions): Promise<WorkflowScheduleResult> {
  if (!Number.isInteger(options.maxParallel) || options.maxParallel < 1) {
    throw new Error("Workflow maxParallel must be a positive integer.");
  }
  const states: Record<string, WorkflowPhaseState> = Object.fromEntries(
    options.workflow.definition.phases.map((phase) => [phase.id, "pending"])
  );
  const outputs: Record<string, unknown> = {};
  const errors: Record<string, string> = {};
  const running = new Map<string, Promise<SettledExecution>>();
  const admission = new PhaseResultAdmission();
  const signal = options.signal ?? new AbortController().signal;

  for (;;) {
    if (signal.aborted) {
      for (const phase of options.workflow.definition.phases) {
        if (states[phase.id] === "pending" || states[phase.id] === "ready") {
          setState(states, phase.id, "canceled", options.onStateChange);
        }
      }
    } else {
      updateReadyAndSkipped(options.workflow, states, options.onStateChange);
    }
    if (!signal.aborted) {
      for (const phaseId of options.workflow.order) {
        if (running.size >= options.maxParallel) break;
        if (states[phaseId] !== "ready") continue;
        const phase = phaseById(options.workflow, phaseId);
        const executor = options.executors[phase.type];
        if (!executor) throw new Error(`No workflow executor is registered for ${phase.type}.`);
        setState(states, phase.id, "running", options.onStateChange);
        const inputs = Object.fromEntries(
          Object.entries(phase.bindings ?? {}).map(([name, binding]) => [name, outputs[binding.from]])
        );
        const execution = executor({ inputs, phase, runId: options.runId, signal })
          .then((result): SettledExecution => ({
            deliveries: Array.isArray(result) ? result : [result],
            phaseId: phase.id,
          }))
          .catch((error: unknown): SettledExecution => ({ error, phaseId: phase.id }));
        running.set(phase.id, execution);
      }
    }

    if (running.size === 0) {
      const unfinished = Object.values(states).some((state) =>
        state === "pending" || state === "ready" || state === "running"
      );
      if (!unfinished) break;
      if (signal.aborted) {
        for (const phase of options.workflow.definition.phases) {
          if (states[phase.id] === "pending" || states[phase.id] === "ready") {
            setState(states, phase.id, "canceled", options.onStateChange);
          }
        }
        break;
      }
      throw new Error("Workflow scheduler stalled with unfinished phases.");
    }

    const settled = await Promise.race(running.values());
    running.delete(settled.phaseId);
    if (signal.aborted) {
      setState(states, settled.phaseId, "canceled", options.onStateChange);
      continue;
    }
    if (settled.error !== undefined) {
      errors[settled.phaseId] = errorMessage(settled.error);
      setState(states, settled.phaseId, "failed", options.onStateChange);
      continue;
    }
    try {
      const phase = phaseById(options.workflow, settled.phaseId);
      const definition = options.registry.get(phase.type, phase.version);
      let accepted = false;
      for (const delivery of settled.deliveries ?? []) {
        const result = admission.admit(delivery, {
          outputSchema: definition.outputSchema,
          phaseId: phase.id,
          runId: options.runId,
        });
        if (!result.accepted) continue;
        outputs[phase.id] = result.output;
        accepted = true;
      }
      if (!accepted) throw new Error("Phase execution produced no admissible structured result.");
      setState(states, phase.id, "completed", options.onStateChange);
    } catch (error) {
      errors[settled.phaseId] = errorMessage(error);
      setState(states, settled.phaseId, "failed", options.onStateChange);
    }
  }

  const status = signal.aborted
    ? "canceled"
    : Object.values(states).includes("failed")
      ? "failed"
      : "completed";
  return { errors, outputs, states, status };
}

function updateReadyAndSkipped(
  workflow: ValidatedWorkflow,
  states: Record<string, WorkflowPhaseState>,
  notify?: (phaseId: string, state: WorkflowPhaseState) => void
): void {
  for (const phaseId of workflow.order) {
    if (states[phaseId] !== "pending") continue;
    const phase = phaseById(workflow, phaseId);
    const dependencyStates = phase.dependencies.map((dependency) => states[dependency]);
    if (dependencyStates.some((state) => state === "failed" || state === "skipped" || state === "canceled")) {
      setState(states, phase.id, "skipped", notify);
    } else if (dependencyStates.every((state) => state === "completed")) {
      setState(states, phase.id, "ready", notify);
    }
  }
}

function phaseById(workflow: ValidatedWorkflow, phaseId: string): WorkflowPhaseDefinition {
  const phase = workflow.definition.phases.find((candidate) => candidate.id === phaseId);
  if (!phase) throw new Error(`Unknown workflow phase: ${phaseId}`);
  return phase;
}

function setState(
  states: Record<string, WorkflowPhaseState>,
  phaseId: string,
  state: WorkflowPhaseState,
  notify?: (phaseId: string, state: WorkflowPhaseState) => void
): void {
  states[phaseId] = state;
  notify?.(phaseId, state);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
