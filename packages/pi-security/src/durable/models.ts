// Model access for runs (design D5): pi-coding-agent's ModelRuntime over Pi's auth.json and models.json, with role
// credentials from named environment variables applied as in-memory runtime API keys (never written to auth.json),
// wrapped in a decorator that removes every known credential value from what pi-durable stores.
//
// Provider error bodies are persisted verbatim (spike 0.2: a 401 echoing the key put it in run.sqlite), so error and
// done events and completeSimple/fetchDeferred results are redacted. OAuth tokens refreshed after the run starts are not
// in the known set (design Open Question 1).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { type AssistantMessage, type AssistantMessageEventStream, createAssistantMessageEventStream, type Models } from "@earendil-works/pi-ai";
import { getAgentDir, ModelRuntime } from "@earendil-works/pi-coding-agent";
import { ConfigError, effectiveRole, ROLE_IDS, type RunConfig } from "../config/run-config.js";

export const REDACTED = "[REDACTED]";
/** Shorter values are too likely to occur in ordinary text to redact safely. */
const MIN_SECRET_LENGTH = 8;
const CREDENTIAL_NAME = /(?:API_?KEY|TOKEN|SECRET|PASSWORD|ACCESS_?KEY|CREDENTIAL|AUTH)/i;

/** Remove every known secret from `text`, longest first so a secret containing another is removed whole. */
export function redactSecrets(text: string, secrets: readonly string[]): string {
  return [...secrets].sort((left, right) => right.length - left.length).reduce((current, secret) => current.split(secret).join(REDACTED), text);
}

/** A Models whose stored outputs (error and done events, completed messages) carry no known secret. */
export function redactingModels<M extends object>(models: M, secrets: readonly string[]): M {
  const known = [...new Set(secrets.filter((secret) => secret.length >= MIN_SECRET_LENGTH))];
  if (known.length === 0) return models;
  const fix = (message: AssistantMessage): AssistantMessage =>
    message.errorMessage === undefined ? message : { ...message, errorMessage: redactSecrets(message.errorMessage, known) };
  const wrapStream = (source: AssistantMessageEventStream) => {
    const target = createAssistantMessageEventStream();
    void (async () => {
      for await (const event of source) {
        if (event.type === "error") target.push({ ...event, error: fix(event.error) });
        else if (event.type === "done") target.push({ ...event, message: fix(event.message) });
        else target.push(event);
      }
      target.end();
    })();
    return target;
  };
  return new Proxy(models, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      if (typeof value !== "function") return value;
      if (property === "streamSimple" || property === "streamDeferred" || property === "stream") {
        return (...args: unknown[]) => wrapStream(value.apply(target, args));
      }
      if (property === "completeSimple" || property === "fetchDeferred" || property === "complete") {
        return async (...args: unknown[]) => fix(await value.apply(target, args));
      }
      return value.bind(target);
    }
  });
}

/** Every string of at least MIN_SECRET_LENGTH in a parsed auth.json: keys, access and refresh tokens. */
function authFileSecrets(path: string): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return [];
  }
  const found: string[] = [];
  const visit = (value: unknown) => {
    if (typeof value === "string" && value.length >= MIN_SECRET_LENGTH) found.push(value);
    else if (Array.isArray(value)) value.forEach(visit);
    else if (value !== null && typeof value === "object") Object.values(value).forEach(visit);
  };
  visit(parsed);
  return found;
}

export type RunModels = { readonly models: Models; readonly secrets: readonly string[] };

export type CreateRunModelsOptions = {
  readonly config: RunConfig;
  readonly env?: NodeJS.ProcessEnv;
  /** Pi's agent directory holding auth.json and models.json; default pi-coding-agent's getAgentDir(). */
  readonly agentDir?: string;
};

/** ModelRuntime for a run, role credentials applied, behind the redacting decorator. */
export async function createRunModels({ config, env = process.env, agentDir = getAgentDir() }: CreateRunModelsOptions): Promise<RunModels> {
  const authPath = join(agentDir, "auth.json");
  const runtime = await ModelRuntime.create({ authPath, modelsPath: join(agentDir, "models.json"), refreshOnCreate: false });
  const secrets = [...authFileSecrets(authPath)];
  const keyByProvider = new Map<string, { role: string; variable: string }>();
  for (const id of ROLE_IDS) {
    const role = effectiveRole(config, id);
    if (role.credentialEnv === undefined) continue;
    if (role.provider === undefined) throw new ConfigError(`roles.${id}.credential names ${role.credentialEnv} but the role has no provider`);
    const value = env[role.credentialEnv];
    if (typeof value !== "string" || value === "") throw new ConfigError(`environment variable ${role.credentialEnv} for roles.${id}.credential is not set`);
    const previous = keyByProvider.get(role.provider);
    if (previous !== undefined && previous.variable !== role.credentialEnv) {
      throw new ConfigError(`roles ${previous.role} and ${id} give provider ${role.provider} different credentials (${previous.variable}, ${role.credentialEnv})`);
    }
    keyByProvider.set(role.provider, { role: id, variable: role.credentialEnv });
    await runtime.setRuntimeApiKey(role.provider, value);
    secrets.push(value);
  }
  for (const [name, value] of Object.entries(env)) {
    if (value !== undefined && CREDENTIAL_NAME.test(name)) secrets.push(value);
  }
  return { models: redactingModels(runtime as unknown as Models, secrets), secrets };
}

export type PiModelDefaults = { provider?: string; model?: string; thinking?: string };

/** Pi's default model from <agentDir>/settings.json, for roles that name none. */
export function readPiModelDefaults(agentDir: string = getAgentDir()): PiModelDefaults {
  try {
    const settings = JSON.parse(readFileSync(join(agentDir, "settings.json"), "utf8"));
    const pick = (key: string) => (typeof settings?.[key] === "string" && settings[key].trim() ? (settings[key] as string) : undefined);
    return { provider: pick("defaultProvider"), model: pick("defaultModel"), thinking: pick("defaultThinkingLevel") };
  } catch {
    return {};
  }
}
