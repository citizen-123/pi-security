import { candidateAttackPathSchema } from "../artifact-attack-path.js";
import { discoveryCandidatesInputSchema } from "../artifact-discovery.js";
import { candidateValidationRecordSchema } from "../artifact-validation-phase.js";
import {
  issuePiPackagedAgentContext,
  piPackagedAgentToolAllowlist,
} from "../pi-permission-profile.js";
import { z } from "zod";
import type { PhaseInputPackage, PhaseRoleSettings } from "../rpc/phase-session.js";
import {
  ClosedPhaseRegistry,
  type PhaseTypeDefinition,
  type ValidatedWorkflow,
  type WorkflowDefinition,
  type WorkflowPhaseDefinition,
  validateWorkflow,
} from "./registry.js";

const object = z.record(z.string(), z.unknown());
const readOnlyCapability = Object.freeze({
  allowDelegation: false,
  allowTargetMutation: false,
  tools: ["read", "grep", "find", "ls"],
});
const hostCapability = Object.freeze({
  allowDelegation: false,
  allowTargetMutation: false,
  tools: [],
});

const PHASE_TYPES: readonly PhaseTypeDefinition[] = [
  phaseType("preflight", "inventory.v1", {}, z.object({ reviewItemsTotal: z.number().int().nonnegative() }).strict(), "deterministic"),
  phaseType("threat-model", "threat-model.v1", { inventory: "inventory.v1" }, z.object({ threatModel: object }).strict()),
  phaseType("discovery", "discovery.v1", { inventory: "inventory.v1", threatModel: "threat-model.v1" }, discoveryCandidatesInputSchema),
  phaseType("reduction", "reduction.v1", { discovery: "discovery.v1" }, z.object({ findings: z.array(object) }).strict()),
  phaseType(
    "validation",
    "validation.v1",
    { reduction: "reduction.v1" },
    z.object({
      validations: z.array(z.object({
        candidateId: z.string(),
        validation: candidateValidationRecordSchema,
      }).strict()),
    }).strict(),
  ),
  phaseType(
    "attack-path",
    "attack-path.v1",
    { validation: "validation.v1" },
    z.object({
      attackPaths: z.array(z.object({
        attackPath: candidateAttackPathSchema,
        candidateId: z.string(),
      }).strict()),
    }).strict(),
  ),
  phaseType(
    "reporting",
    "report.v1",
    {
      attackPaths: "attack-path.v1",
      reduction: "reduction.v1",
      threatModel: "threat-model.v1",
      validation: "validation.v1",
    },
    z.object({
      coverage: object,
      findings: z.array(object),
      threatModel: object.optional(),
    }).strict(),
  ),
  phaseType(
    "publication",
    "publication.v1",
    { report: "report.v1" },
    z.object({
      artifacts: z.object({
        coverage: z.string(),
        findings: z.string(),
        manifest: z.string(),
        report: z.string(),
        sarif: z.string(),
      }).strict(),
    }).strict(),
    "deterministic",
  ),
];

export const BUILT_IN_PHASE_REGISTRY = new ClosedPhaseRegistry(PHASE_TYPES);

export const FULL_REPOSITORY_WORKFLOW: WorkflowDefinition = Object.freeze({
  id: "full-repository",
  version: 1,
  phases: [
    phase("preflight", "preflight", [], undefined, {}),
    phase("threat-model", "threat-model", ["preflight"], "threat_modeler", {
      inventory: { contract: "inventory.v1", from: "preflight" },
    }),
    phase("discovery", "discovery", ["preflight", "threat-model"], "discoverer", {
      inventory: { contract: "inventory.v1", from: "preflight" },
      threatModel: { contract: "threat-model.v1", from: "threat-model" },
    }),
    phase("reduction", "reduction", ["discovery"], "reducer", {
      discovery: { contract: "discovery.v1", from: "discovery" },
    }),
    phase("validation", "validation", ["reduction"], "validator", {
      reduction: { contract: "reduction.v1", from: "reduction" },
    }),
    phase("attack-path", "attack-path", ["validation"], "attack_path_analyst", {
      validation: { contract: "validation.v1", from: "validation" },
    }),
    phase("reporting", "reporting", ["threat-model", "reduction", "validation", "attack-path"], "reporter", {
      attackPaths: { contract: "attack-path.v1", from: "attack-path" },
      reduction: { contract: "reduction.v1", from: "reduction" },
      threatModel: { contract: "threat-model.v1", from: "threat-model" },
      validation: { contract: "validation.v1", from: "validation" },
    }),
    phase("publication", "publication", ["reporting"], undefined, {
      report: { contract: "report.v1", from: "reporting" },
    }),
  ],
});

export const VALIDATED_FULL_REPOSITORY_WORKFLOW: ValidatedWorkflow = validateWorkflow(
  FULL_REPOSITORY_WORKFLOW,
  BUILT_IN_PHASE_REGISTRY,
);

export function assemblePhaseInputPackage(options: {
  artifactRoot: string;
  evidenceReferences: string[];
  outputs: Readonly<Record<string, unknown>>;
  phase: WorkflowPhaseDefinition;
  role: PhaseRoleSettings;
  scanId: string;
  runId: string;
  target: { path: string; revision: string | null };
}): PhaseInputPackage {
  const definition = BUILT_IN_PHASE_REGISTRY.get(options.phase.type, options.phase.version);
  const requiredInputs = Object.fromEntries(
    Object.entries(options.phase.bindings ?? {}).map(([name, binding]) => {
      if (!(binding.from in options.outputs)) {
        throw new Error(`Phase input ${name} is unavailable from ${binding.from}.`);
      }
      return [name, options.outputs[binding.from]];
    })
  );
  const capabilityProfile = definition.executor === "model"
    ? {
        ...definition.capability,
        tools: piPackagedAgentToolAllowlist(issuePiPackagedAgentContext(
          "pi-security-auditor",
          {
            artifactRoot: options.artifactRoot,
            scanId: options.scanId,
            targetRoot: options.target.path,
          },
        )),
      }
    : definition.capability;
  return {
    artifactRoot: options.artifactRoot,
    authority: { artifactRoot: options.artifactRoot, targetPath: options.target.path },
    capabilityProfile,
    evidenceReferences: [...options.evidenceReferences],
    outputContract: {
      name: definition.outputContract,
      schemaVersion: definition.version,
    },
    phaseId: options.phase.id,
    requiredInputs,
    roleId: options.phase.roleId ?? "deterministic",
    runId: options.runId,
    role: {
      instructions: options.role.instructions,
      model: options.role.model,
      provider: options.role.provider,
      thinking: options.role.thinking,
    },
    scanId: options.scanId,
    target: { ...options.target },
  };
}

function phaseType(
  type: string,
  outputContract: string,
  inputContracts: Record<string, string>,
  outputSchema: PhaseTypeDefinition["outputSchema"],
  executor: PhaseTypeDefinition["executor"] = "model",
): PhaseTypeDefinition {
  return {
    attemptPolicy: { maxAttempts: executor === "model" ? 2 : 1 },
    capability: executor === "model" ? readOnlyCapability : hostCapability,
    executor,
    inputContracts,
    outputContract,
    outputSchema,
    type,
    version: 1,
  };
}

function phase(
  id: string,
  type: string,
  dependencies: string[],
  roleId: string | undefined,
  bindings: NonNullable<WorkflowPhaseDefinition["bindings"]>,
): WorkflowPhaseDefinition {
  return { bindings, dependencies, id, ...(roleId ? { roleId } : {}), type, version: 1 };
}
