import { z, type ZodType } from "zod";
import type { PhaseCapabilityProfile } from "../rpc/phase-session.js";

export type WorkflowPhaseState =
  | "pending"
  | "ready"
  | "running"
  | "completed"
  | "failed"
  | "canceled"
  | "skipped";

export interface PhaseAttemptPolicy {
  maxAttempts: number;
}

export interface PhaseTypeDefinition {
  attemptPolicy: PhaseAttemptPolicy;
  capability: PhaseCapabilityProfile;
  executor: "deterministic" | "model";
  inputContracts: Record<string, string>;
  outputContract: string;
  outputSchema: ZodType;
  type: string;
  version: number;
}

export interface PhaseInputBinding {
  contract: string;
  from: string;
}

export interface WorkflowPhaseDefinition {
  bindings?: Record<string, PhaseInputBinding>;
  dependencies: string[];
  id: string;
  roleId?: string;
  type: string;
  version: number;
}

export interface WorkflowDefinition {
  id: string;
  phases: WorkflowPhaseDefinition[];
  version: number;
}

export interface ValidatedWorkflow {
  definition: WorkflowDefinition;
  order: string[];
}

export class ClosedPhaseRegistry {
  readonly #definitions: Readonly<Record<string, PhaseTypeDefinition>>;

  constructor(definitions: readonly PhaseTypeDefinition[]) {
    const entries: Array<[string, PhaseTypeDefinition]> = [];
    for (const definition of definitions) {
      const key = phaseTypeKey(definition.type, definition.version);
      if (entries.some(([existing]) => existing === key)) {
        throw new Error(`Duplicate workflow phase type: ${key}`);
      }
      if (!Number.isInteger(definition.attemptPolicy.maxAttempts) || definition.attemptPolicy.maxAttempts < 1) {
        throw new Error(`Workflow phase type ${key} has an invalid attempt policy.`);
      }
      entries.push([key, Object.freeze({
        ...definition,
        attemptPolicy: Object.freeze({ ...definition.attemptPolicy }),
        capability: Object.freeze({
          ...definition.capability,
          tools: Object.freeze([...definition.capability.tools]),
        }),
        inputContracts: Object.freeze({ ...definition.inputContracts }),
      })]);
    }
    this.#definitions = Object.freeze(Object.fromEntries(entries));
  }

  get(type: string, version: number): PhaseTypeDefinition {
    const key = phaseTypeKey(type, version);
    const definition = this.#definitions[key];
    if (!definition) throw new Error(`Unknown workflow phase type: ${key}`);
    return definition;
  }

  has(type: string, version: number): boolean {
    return phaseTypeKey(type, version) in this.#definitions;
  }
}

export function validateWorkflow(
  workflow: WorkflowDefinition,
  registry: ClosedPhaseRegistry
): ValidatedWorkflow {
  if (!workflow.id.trim() || !Number.isInteger(workflow.version) || workflow.version < 1) {
    throw new Error("Workflow identity and version are required.");
  }
  const phases = new Map<string, WorkflowPhaseDefinition>();
  for (const phase of workflow.phases) {
    if (!phase.id.trim()) throw new Error("Workflow phase identity is required.");
    if (phases.has(phase.id)) throw new Error(`Duplicate workflow phase identity: ${phase.id}`);
    registry.get(phase.type, phase.version);
    phases.set(phase.id, phase);
  }
  for (const phase of workflow.phases) {
    const definition = registry.get(phase.type, phase.version);
    for (const dependency of phase.dependencies) {
      if (!phases.has(dependency)) {
        throw new Error(`Workflow phase ${phase.id} has missing dependency ${dependency}.`);
      }
      if (dependency === phase.id) throw new Error(`Workflow phase ${phase.id} depends on itself.`);
    }
    for (const [name, binding] of Object.entries(phase.bindings ?? {})) {
      const source = phases.get(binding.from);
      if (!source || !phase.dependencies.includes(binding.from)) {
        throw new Error(`Workflow phase ${phase.id} binding ${name} has an unavailable source.`);
      }
      const expected = definition.inputContracts[name];
      const sourceContract = registry.get(source.type, source.version).outputContract;
      if (!expected || expected !== binding.contract || sourceContract !== binding.contract) {
        throw new Error(`Workflow phase ${phase.id} binding ${name} is contract-incompatible.`);
      }
    }
    for (const required of Object.keys(definition.inputContracts)) {
      if (!phase.bindings?.[required]) {
        throw new Error(`Workflow phase ${phase.id} is missing input binding ${required}.`);
      }
    }
  }

  const pendingDependencies = new Map(
    workflow.phases.map((phase) => [phase.id, new Set(phase.dependencies)])
  );
  const order: string[] = [];
  while (order.length < workflow.phases.length) {
    const ready = workflow.phases.filter((phase) =>
      !order.includes(phase.id) && pendingDependencies.get(phase.id)?.size === 0
    );
    if (ready.length === 0) throw new Error("Workflow graph contains a dependency cycle.");
    for (const phase of ready) {
      order.push(phase.id);
      for (const dependencies of pendingDependencies.values()) dependencies.delete(phase.id);
    }
  }
  return { definition: workflow, order };
}

export const jsonObjectSchema = z.record(z.string(), z.unknown());

function phaseTypeKey(type: string, version: number): string {
  return `${type}@${version}`;
}
