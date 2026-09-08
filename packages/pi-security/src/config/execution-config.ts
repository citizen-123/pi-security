import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { resolve } from "node:path";
import { parse as parseToml, TomlError } from "smol-toml";
import { z } from "zod";

export const BUILT_IN_WORKFLOW = "full-repository" as const;
export const BUILT_IN_ROLE_IDS = [
  "default",
  "threat_modeler",
  "discoverer",
  "reducer",
  "validator",
  "attack_path_analyst",
  "reporter",
] as const;

export type ConfigSource = "default" | "ambient" | "explicit" | "cli";
export type CredentialSource =
  | { kind: "profile"; profile: string }
  | { env: string; kind: "env" }
  | { kind: "inline"; value: string };

export interface RoleExecutionConfig {
  credential?: CredentialSource;
  instructions?: string;
  maxAttempts: number;
  model?: string;
  provider?: string;
  thinking?: "off" | "minimal" | "low" | "medium" | "high" | "xhigh";
}

export interface ResolvedExecutionConfig {
  execution: { maxParallel: number };
  legacyDeepScan?: Record<string, number | "auto">;
  provenance: Record<string, ConfigSource>;
  roles: Record<string, RoleExecutionConfig>;
  scan: { target: string; workflow: typeof BUILT_IN_WORKFLOW };
}

export interface ConfigOverrides {
  maxParallel?: number;
  model?: string;
  provider?: string;
  target?: string;
  thinking?: RoleExecutionConfig["thinking"];
  workflow?: typeof BUILT_IN_WORKFLOW;
}

export interface ResolveExecutionConfigOptions {
  ambientPath?: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  explicitPath?: string;
  overrides?: ConfigOverrides;
}

export interface ResolvedCredential {
  source: Exclude<CredentialSource["kind"], "inline"> | "inline";
  value: string;
}

export interface ExecutionSnapshot {
  digest: string;
  resolved: SanitizedExecutionConfig;
  schemaVersion: 1;
}

export interface SanitizedExecutionConfig {
  execution: ResolvedExecutionConfig["execution"];
  legacyDeepScan?: Record<string, number | "auto">;
  provenance: Record<string, ConfigSource>;
  roles: Record<string, Omit<RoleExecutionConfig, "credential"> & {
    credential?: { source: "inline" } | { source: "env"; env: string } | { source: "profile"; profile: string };
  }>;
  scan: ResolvedExecutionConfig["scan"];
}

const credentialSchema = z.union([
  z.object({ profile: z.string().trim().min(1) }).strict(),
  z.object({ env: z.string().trim().min(1) }).strict(),
  z.object({ value: z.string().min(1) }).strict(),
]);
const thinkingSchema = z.enum(["off", "minimal", "low", "medium", "high", "xhigh"]);
const roleSchema = z.object({
  credential: credentialSchema.optional(),
  instructions: z.string().trim().min(1).optional(),
  max_attempts: z.number().int().min(1).max(10).optional(),
  model: z.string().trim().min(1).optional(),
  provider: z.string().trim().min(1).optional(),
  thinking: thinkingSchema.optional(),
}).strict();
const deepScanSchema = z.object({
  max_discovery_runs: z.number().int().positive().optional(),
  max_time_hours: z.number().positive().optional(),
  stop_after_consecutive_errors: z.number().int().positive().optional(),
  stop_after_no_new: z.number().int().positive().optional(),
  subagents: z.number().int().nonnegative().optional(),
  workers: z.union([z.number().int().positive(), z.literal("auto")]).optional(),
}).strict();
const documentSchema = z.object({
  deep_scan: deepScanSchema.optional(),
  execution: z.object({ max_parallel: z.number().int().positive().max(64).optional() }).strict().optional(),
  roles: z.record(z.string().trim().min(1), roleSchema).optional(),
  scan: z.object({
    target: z.string().trim().min(1).optional(),
    workflow: z.literal(BUILT_IN_WORKFLOW).optional(),
  }).strict().optional(),
}).strict();

type ConfigDocument = z.infer<typeof documentSchema>;

const DEFAULT_ROLE: RoleExecutionConfig = { maxAttempts: 2 };

export function parseExecutionConfigText(text: string, label = "configuration"): ConfigDocument {
  let parsed: unknown;
  try {
    parsed = parseToml(text);
  } catch (error) {
    const location = error instanceof TomlError ? ` at line ${error.line}, column ${error.column}` : "";
    throw new Error(`Cannot parse ${label}${location}: invalid TOML.`);
  }
  return validateDocument(parsed, label);
}

function validateDocument(parsed: unknown, label: string): ConfigDocument {
  const result = documentSchema.safeParse(parsed);
  if (!result.success) {
    const issue = result.error.issues[0];
    const issuePath = [...(issue?.path ?? [])].map((part, index) =>
      index === 1 && issue?.path[0] === "roles" && !BUILT_IN_ROLE_IDS.includes(part as typeof BUILT_IN_ROLE_IDS[number])
        ? "<role>"
        : String(part),
    );
    if (issue?.code === "unrecognized_keys") issuePath.push("<unknown>");
    const path = issuePath.length ? issuePath.join(".") : "<root>";
    throw new Error(`Invalid ${label} at ${path}: ${issue?.code ?? "invalid value"}.`);
  }
  return result.data;
}

export async function resolveExecutionConfig(
  options: ResolveExecutionConfigOptions = {},
): Promise<ResolvedExecutionConfig> {
  const cwd = resolve(options.cwd ?? process.cwd());
  const env = options.env ?? process.env;
  const ambientPath = options.ambientPath === undefined
    ? resolve(resolvePiHome(env, cwd), "pi-security/config.toml")
    : resolve(cwd, options.ambientPath);
  const provenance: Record<string, ConfigSource> = {
    "execution.maxParallel": "default",
    "roles.default.maxAttempts": "default",
    "scan.target": "default",
    "scan.workflow": "default",
  };
  const merged: MutableConfig = {
    execution: { maxParallel: 4 },
    roles: Object.assign(Object.create(null) as Record<string, RoleExecutionConfig>, { default: { ...DEFAULT_ROLE } }),
    scan: { target: cwd, workflow: BUILT_IN_WORKFLOW },
  };

  const ambient = await readOptionalConfig(ambientPath, "ambient configuration");
  if (ambient) applyDocument(merged, ambient, "ambient", provenance);
  if (options.explicitPath) {
    const explicitPath = resolve(cwd, options.explicitPath);
    const explicit = parseExecutionConfigText(
      await readRequiredFile(explicitPath, "explicit configuration"),
      `explicit configuration ${explicitPath}`,
    );
    applyDocument(merged, explicit, "explicit", provenance);
  }
  applyOverrides(merged, options.overrides ?? {}, provenance);
  merged.scan.target = resolve(cwd, merged.scan.target);
  return { ...merged, provenance };
}

export function sanitizeExecutionConfig(config: ResolvedExecutionConfig): SanitizedExecutionConfig {
  return {
    execution: { ...config.execution },
    ...(config.legacyDeepScan ? { legacyDeepScan: { ...config.legacyDeepScan } } : {}),
    provenance: { ...config.provenance },
    roles: Object.fromEntries(Object.entries(config.roles).map(([id, role]) => [id, {
      instructions: role.instructions,
      maxAttempts: role.maxAttempts,
      model: role.model,
      provider: role.provider,
      thinking: role.thinking,
      ...(role.credential ? { credential: sanitizeCredential(role.credential) } : {}),
    }])),
    scan: { ...config.scan },
  };
}

function sanitizeCredential(credential: CredentialSource): NonNullable<SanitizedExecutionConfig["roles"][string]["credential"]> {
  if (credential.kind === "env") return { source: "env", env: credential.env };
  if (credential.kind === "profile") return { source: "profile", profile: credential.profile };
  return { source: "inline" };
}

export function createExecutionSnapshot(config: ResolvedExecutionConfig): ExecutionSnapshot {
  const resolved = sanitizeExecutionConfig(config);
  return deepFreeze({
    digest: executionSnapshotDigest(resolved),
    resolved,
    schemaVersion: 1 as const,
  });
}

export function executionSnapshotDigest(resolved: SanitizedExecutionConfig): string {
  const { provenance: _provenance, roles, ...settings } = resolved;
  const semanticRoles = Object.fromEntries(Object.entries(roles).map(([id, { credential: _credential, ...role }]) => [id, role]));
  return `sha256:${createHash("sha256").update(stableJson({ ...settings, roles: semanticRoles })).digest("hex")}`;
}

export async function resolveCredential(
  credential: CredentialSource | undefined,
  options: {
    env?: NodeJS.ProcessEnv;
    profiles?: (name: string) => Promise<string | undefined> | string | undefined;
  } = {},
): Promise<ResolvedCredential | undefined> {
  if (!credential) return undefined;
  if (credential.kind === "inline") return { source: "inline", value: credential.value };
  if (credential.kind === "env") {
    const value = (options.env ?? process.env)[credential.env];
    if (typeof value !== "string" || !value) throw new Error(`Credential environment variable ${credential.env} is unavailable.`);
    return { source: "env", value };
  }
  let value: string | undefined;
  try {
    value = await options.profiles?.(credential.profile);
  } catch {
    throw new Error(`Credential profile ${credential.profile} could not be resolved.`);
  }
  if (typeof value !== "string" || !value) throw new Error(`Credential profile ${credential.profile} is unavailable.`);
  return { source: "profile", value };
}

export function redactKnownSecrets(value: string, secrets: readonly string[]): string {
  return secrets
    .filter((secret) => secret.length > 0)
    .sort((a, b) => b.length - a.length)
    .reduce((redacted, secret) => redacted.split(secret).join("[REDACTED]"), value);
}

interface MutableConfig {
  execution: { maxParallel: number };
  legacyDeepScan?: Record<string, number | "auto">;
  roles: Record<string, RoleExecutionConfig>;
  scan: { target: string; workflow: typeof BUILT_IN_WORKFLOW };
}

function applyDocument(
  target: MutableConfig,
  document: ConfigDocument,
  source: ConfigSource,
  provenance: Record<string, ConfigSource>,
): void {
  if (document.scan?.target !== undefined) set(target.scan, "target", document.scan.target, "scan.target", source, provenance);
  if (document.scan?.workflow !== undefined) set(target.scan, "workflow", document.scan.workflow, "scan.workflow", source, provenance);
  if (document.execution?.max_parallel !== undefined) set(target.execution, "maxParallel", document.execution.max_parallel, "execution.maxParallel", source, provenance);
  for (const [roleId, role] of Object.entries(document.roles ?? {})) {
    const isNewRole = target.roles[roleId] === undefined;
    const current = target.roles[roleId] ?? { ...DEFAULT_ROLE };
    target.roles[roleId] = current;
    if (isNewRole) provenance[`roles.${roleId}.maxAttempts`] = "default";
    if (role.provider !== undefined) set(current, "provider", role.provider, `roles.${roleId}.provider`, source, provenance);
    if (role.model !== undefined) set(current, "model", role.model, `roles.${roleId}.model`, source, provenance);
    if (role.thinking !== undefined) set(current, "thinking", role.thinking, `roles.${roleId}.thinking`, source, provenance);
    if (role.instructions !== undefined) set(current, "instructions", role.instructions, `roles.${roleId}.instructions`, source, provenance);
    if (role.max_attempts !== undefined) set(current, "maxAttempts", role.max_attempts, `roles.${roleId}.maxAttempts`, source, provenance);
    if (role.credential !== undefined) {
      const credential = normalizeCredential(role.credential);
      set(current, "credential", credential, `roles.${roleId}.credential`, source, provenance);
    }
  }
  if (document.deep_scan) {
    target.legacyDeepScan ??= {};
    for (const [key, value] of Object.entries(document.deep_scan)) {
      if (value !== undefined) set(target.legacyDeepScan, key, value, `legacyDeepScan.${key}`, source, provenance);
    }
  }
}

function applyOverrides(
  target: MutableConfig,
  overrides: ConfigOverrides,
  provenance: Record<string, ConfigSource>,
): void {
  applyDocument(target, validateDocument({
    scan: { target: overrides.target, workflow: overrides.workflow },
    execution: { max_parallel: overrides.maxParallel },
    roles: { default: { provider: overrides.provider, model: overrides.model, thinking: overrides.thinking } },
  }, "CLI overrides"), "cli", provenance);
}

function normalizeCredential(value: z.infer<typeof credentialSchema>): CredentialSource {
  if ("profile" in value) return { kind: "profile", profile: value.profile };
  if ("env" in value) return { env: value.env, kind: "env" };
  return { kind: "inline", value: value.value };
}

async function readOptionalConfig(path: string, label: string): Promise<ConfigDocument | undefined> {
  try {
    return parseExecutionConfigText(await readFile(path, "utf8"), `${label} ${path}`);
  } catch (error) {
    if (isMissingFile(error)) return undefined;
    throw error;
  }
}

async function readRequiredFile(path: string, label: string): Promise<string> {
  try {
    return await readFile(path, "utf8");
  } catch (error) {
    throw new Error(`Cannot read ${label} at ${path}: ${safeErrorMessage(error)}`);
  }
}

function resolvePiHome(env: NodeJS.ProcessEnv, cwd: string | undefined): string {
  const configured = env.PI_HOME?.trim() || resolve(homedir(), ".pi");
  const home = configured === "~" ? homedir()
    : configured.startsWith("~/") ? resolve(homedir(), configured.slice(2))
    : configured;
  return resolve(cwd ?? process.cwd(), home);
}

function set<T extends object, K extends keyof T>(
  target: T,
  key: K,
  value: T[K],
  path: string,
  source: ConfigSource,
  provenance: Record<string, ConfigSource>,
): void {
  target[key] = value;
  provenance[path] = source;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).filter((key) => object[key] !== undefined).sort().map((key) => `${JSON.stringify(key)}:${stableJson(object[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function safeErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isMissingFile(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && error.code === "ENOENT");
}
