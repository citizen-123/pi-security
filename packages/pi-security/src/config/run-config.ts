// Run configuration (design D5, D13; cli-and-pi-surface spec): built-in defaults, then $PI_HOME/pi-security/config.toml,
// then --config, then CLI flags.
//
//   [scan]                 target
//   [execution]            max_parallel (1-64, default 4), stall_timeout (default "15m"), max_duration, max_cost (USD)
//   [roles.<id>]           provider, model, thinking, instructions, credential = { env = "NAME" }
//   [deep_scan]            max_discovery_rounds (default 8), stop_after_no_new (default 4)
//   [remediation.checks]   <name> = ["program", "arg", ...]
//
// Credentials come from Pi's auth.json or provider environment variables; a role may name one environment variable.
// Inline credential values are rejected, so a configuration file never holds a secret and can be stored with a run.
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { resolve } from "node:path";
import { parse as parseToml, TomlError } from "smol-toml";
import { z } from "zod";

export const ROLE_IDS = ["default", "threat_modeler", "discoverer", "reducer", "validator", "attack_path_analyst", "fixer"] as const;
export type RoleId = (typeof ROLE_IDS)[number];
export const THINKING_LEVELS = ["off", "minimal", "low", "medium", "high", "xhigh"] as const;
export type Thinking = (typeof THINKING_LEVELS)[number];

export type RoleConfig = {
  provider?: string;
  model?: string;
  thinking?: Thinking;
  instructions?: string;
  /** Name of the environment variable holding this role's provider API key. */
  credentialEnv?: string;
};

export type RunConfig = {
  scan: { target: string };
  execution: { maxParallel: number; stallTimeoutMs: number; maxDurationMs?: number; maxCostUsd?: number };
  roles: Partial<Record<RoleId, RoleConfig>>;
  deepScan: { maxDiscoveryRounds: number; stopAfterNoNew: number };
  remediation: { checks: Record<string, string[]> };
};

export type RunConfigOverrides = { target?: string; maxParallel?: number; provider?: string; model?: string; thinking?: Thinking };

export class ConfigError extends Error {
  override name = "ConfigError";
}

const DURATION = /^(?:[0-9]+[dhms])+$/;
const UNIT_MS: Record<string, number> = { d: 86_400_000, h: 3_600_000, m: 60_000, s: 1000 };

/** "90s", "15m", "6h", "1h30m", "2d" to milliseconds. */
export function parseDuration(value: string): number {
  if (!DURATION.test(value)) throw new ConfigError(`invalid duration ${JSON.stringify(value)}: use units d, h, m, s, as in "15m" or "1h30m"`);
  let total = 0;
  for (const [, amount, unit] of value.matchAll(/([0-9]+)([dhms])/g)) total += Number(amount) * UNIT_MS[unit!]!;
  if (total === 0) throw new ConfigError(`invalid duration ${JSON.stringify(value)}: must be longer than zero`);
  return total;
}

const text = z.string().trim().min(1);
const credential = z.unknown().superRefine((value, refinement) => {
  const object = value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
  if (object && Object.hasOwn(object, "value")) {
    refinement.addIssue({ code: "custom", message: 'inline credential values are not accepted; use credential = { env = "NAME" } or Pi\'s auth.json' });
  } else if (object && Object.hasOwn(object, "profile")) {
    refinement.addIssue({ code: "custom", message: 'credential profiles are not supported; use credential = { env = "NAME" } or Pi\'s auth.json' });
  } else if (!object || Object.keys(object).length !== 1 || typeof object.env !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(object.env)) {
    refinement.addIssue({ code: "custom", message: 'expected credential = { env = "NAME" } with an environment variable name' });
  }
});
const roleSchema = z
  .object({ provider: text.optional(), model: text.optional(), thinking: z.enum(THINKING_LEVELS).optional(), instructions: text.optional(), credential: credential.optional() })
  .strict();
const documentSchema = z
  .object({
    scan: z.object({ target: text.optional() }).strict().optional(),
    execution: z
      .object({
        max_parallel: z.number().int().min(1).max(64).optional(),
        stall_timeout: z.string().optional(),
        max_duration: z.string().optional(),
        max_cost: z.number().positive().optional()
      })
      .strict()
      .optional(),
    roles: z.partialRecord(z.enum(ROLE_IDS), roleSchema).optional(),
    deep_scan: z
      .object({ max_discovery_rounds: z.number().int().min(1).optional(), stop_after_no_new: z.number().int().min(1).optional() })
      .strict()
      .optional(),
    remediation: z
      .object({ checks: z.record(z.string().regex(/^[a-z0-9][a-z0-9_-]*$/), z.array(text).min(1)).optional() })
      .strict()
      .optional()
  })
  .strict();

type ConfigDocument = z.infer<typeof documentSchema>;

/** Parse and validate one TOML document; `label` names it in errors. */
export function parseRunConfigText(source: string, label = "configuration"): ConfigDocument {
  let parsed: unknown;
  try {
    parsed = parseToml(source);
  } catch (error) {
    const location = error instanceof TomlError ? ` at line ${error.line}, column ${error.column}` : "";
    throw new ConfigError(`cannot parse ${label}${location}: invalid TOML`);
  }
  const result = documentSchema.safeParse(parsed);
  if (!result.success) {
    const issue = result.error.issues[0]!;
    const path = [...issue.path, ...(issue.code === "unrecognized_keys" ? [issue.keys[0]] : [])].join(".") || "<root>";
    throw new ConfigError(`invalid ${label} at ${path}: ${issue.message}`);
  }
  // Durations are checked here so a bad value names its file.
  for (const key of ["stall_timeout", "max_duration"] as const) {
    const value = result.data.execution?.[key];
    if (value !== undefined) {
      try {
        parseDuration(value);
      } catch (error) {
        throw new ConfigError(`invalid ${label} at execution.${key}: ${(error as Error).message}`);
      }
    }
  }
  return result.data;
}

export function defaultRunConfig(cwd: string): RunConfig {
  return {
    scan: { target: cwd },
    execution: { maxParallel: 4, stallTimeoutMs: 15 * 60_000 },
    roles: {},
    deepScan: { maxDiscoveryRounds: 8, stopAfterNoNew: 4 },
    remediation: { checks: {} }
  };
}

function apply(config: RunConfig, document: ConfigDocument, cwd: string): void {
  if (document.scan?.target !== undefined) config.scan.target = resolve(cwd, document.scan.target);
  const execution = document.execution;
  if (execution?.max_parallel !== undefined) config.execution.maxParallel = execution.max_parallel;
  if (execution?.stall_timeout !== undefined) config.execution.stallTimeoutMs = parseDuration(execution.stall_timeout);
  if (execution?.max_duration !== undefined) config.execution.maxDurationMs = parseDuration(execution.max_duration);
  if (execution?.max_cost !== undefined) config.execution.maxCostUsd = execution.max_cost;
  for (const [id, role] of Object.entries(document.roles ?? {}) as [RoleId, z.infer<typeof roleSchema>][]) {
    const current = (config.roles[id] ??= {});
    if (role.provider !== undefined) current.provider = role.provider;
    if (role.model !== undefined) current.model = role.model;
    if (role.thinking !== undefined) current.thinking = role.thinking;
    if (role.instructions !== undefined) current.instructions = role.instructions;
    if (role.credential !== undefined) current.credentialEnv = (role.credential as { env: string }).env;
  }
  if (document.deep_scan?.max_discovery_rounds !== undefined) config.deepScan.maxDiscoveryRounds = document.deep_scan.max_discovery_rounds;
  if (document.deep_scan?.stop_after_no_new !== undefined) config.deepScan.stopAfterNoNew = document.deep_scan.stop_after_no_new;
  Object.assign(config.remediation.checks, document.remediation?.checks ?? {});
}

async function readConfigFile(path: string, label: string, required: boolean): Promise<ConfigDocument | undefined> {
  let source: string;
  try {
    source = await readFile(path, "utf8");
  } catch (error) {
    if (!required && (error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw new ConfigError(`cannot read ${label} ${path}: ${(error as NodeJS.ErrnoException).code ?? (error as Error).message}`);
  }
  return parseRunConfigText(source, `${label} ${path}`);
}

export const ambientConfigPath = (env: NodeJS.ProcessEnv, cwd: string) => {
  const home = env.PI_HOME?.trim() || "~/.pi";
  const expanded = home === "~" ? homedir() : home.startsWith("~/") ? resolve(homedir(), home.slice(2)) : home;
  return resolve(cwd, expanded, "pi-security", "config.toml");
};

export type ResolveRunConfigOptions = { cwd?: string; env?: NodeJS.ProcessEnv; explicitPath?: string; ambientPath?: string; overrides?: RunConfigOverrides };

/** Defaults, then the ambient file (if present), then --config, then CLI overrides (which apply to the default role). */
export async function resolveRunConfig(options: ResolveRunConfigOptions = {}): Promise<RunConfig> {
  const cwd = resolve(options.cwd ?? process.cwd());
  const env = options.env ?? process.env;
  const config = defaultRunConfig(cwd);
  const ambient = await readConfigFile(options.ambientPath ?? ambientConfigPath(env, cwd), "ambient configuration", false);
  if (ambient) apply(config, ambient, cwd);
  if (options.explicitPath !== undefined) {
    const explicitPath = resolve(cwd, options.explicitPath);
    apply(config, (await readConfigFile(explicitPath, "configuration", true))!, cwd);
  }
  const overrides = options.overrides ?? {};
  if (overrides.target !== undefined) config.scan.target = resolve(cwd, overrides.target);
  if (overrides.maxParallel !== undefined) {
    if (!Number.isInteger(overrides.maxParallel) || overrides.maxParallel < 1 || overrides.maxParallel > 64) {
      throw new ConfigError("--max-parallel must be an integer from 1 to 64");
    }
    config.execution.maxParallel = overrides.maxParallel;
  }
  const role = (config.roles.default ??= {});
  if (overrides.provider !== undefined) role.provider = overrides.provider;
  if (overrides.model !== undefined) role.model = overrides.model;
  if (overrides.thinking !== undefined) role.thinking = overrides.thinking;
  if (Object.keys(role).length === 0) delete config.roles.default;
  return config;
}

/**
 * A role's effective settings: the default role's, overridden field by field by the role's own. A role that names its
 * own provider does not inherit the default role's credential, which belongs to the default provider.
 */
export function effectiveRole(config: RunConfig, id: RoleId): RoleConfig {
  const base = { ...config.roles.default };
  const own = config.roles[id] ?? {};
  if (own.provider !== undefined && own.provider !== base.provider) delete base.credentialEnv;
  return { ...base, ...own };
}
