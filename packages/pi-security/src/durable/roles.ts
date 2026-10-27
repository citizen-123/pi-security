// Worker roles from configuration (design D5): each scan phase's role resolves to a model and thinking level from its
// [roles.<id>] table over [roles.default], falling back to Pi's default model; configured instructions are appended to
// the role's built-in instructions. Only names reach task input; credentials stay in the ModelRuntime.
import { ConfigError, effectiveRole, type RoleId, type RunConfig, THINKING_LEVELS, type Thinking } from "../config/run-config.js";
import type { PiModelDefaults } from "./models.js";
import type { ReportRole } from "./scan-tools.js";
import type { WorkerRole } from "./worker.js";

export const SCAN_ROLE_REPORTS = {
  threat_modeler: "threat_model",
  discoverer: "discover",
  reducer: "reduce",
  validator: "validate",
  attack_path_analyst: "attack_path"
} as const satisfies Partial<Record<RoleId, ReportRole>>;

export type ScanRoleId = keyof typeof SCAN_ROLE_REPORTS;

export function workerRole(config: RunConfig, id: ScanRoleId, builtInInstructions: string, piDefaults: PiModelDefaults = {}): WorkerRole {
  const role = effectiveRole(config, id);
  const provider = role.provider ?? (role.model === undefined ? piDefaults.provider : undefined);
  const modelId = role.model ?? (role.provider === undefined ? piDefaults.model : undefined);
  if (provider === undefined || modelId === undefined) {
    throw new ConfigError(`no model for roles.${id}: set provider and model in [roles.${id}] or [roles.default], or choose a default model in Pi`);
  }
  const thinking = role.thinking ?? (THINKING_LEVELS as readonly string[]).find((level) => level === piDefaults.thinking);
  return {
    id,
    report: SCAN_ROLE_REPORTS[id],
    model: { provider, modelId },
    ...(thinking === undefined ? {} : { thinking: thinking as Thinking }),
    instructions: role.instructions === undefined ? builtInInstructions : `${builtInInstructions}\n\n${role.instructions}`
  };
}
