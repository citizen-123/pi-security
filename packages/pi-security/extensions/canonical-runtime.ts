import { execFile } from "node:child_process";
import { dirname, resolve } from "node:path";
import { promisify } from "node:util";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { exitStatusForRun, reconnectRuntimeEvents, renderRunJson } from "../src/cli/operations.js";
import {
  createWorkbenchRuntimeExecutor,
  WorkbenchRuntimeStateRepository,
  type RuntimeRunStatus,
} from "../src/runtime/state-repository.js";

const execFileAsync = promisify(execFile);

export interface CanonicalRuntimeInvocation {
  configPath?: string;
  targetPath: string;
}

export interface CanonicalRuntimeObservation {
  afterSequence?: number;
  runId: string;
}

export interface CanonicalRuntimePort {
  observe(input: CanonicalRuntimeObservation, signal?: AbortSignal): Promise<unknown>;
  start(input: CanonicalRuntimeInvocation, signal?: AbortSignal): Promise<unknown>;
}

export function registerCanonicalRuntimeTools(pi: ExtensionAPI, runtime: CanonicalRuntimePort): void {
  pi.registerTool({
    name: "start_pi_security_canonical_scan",
    label: "Start Canonical Pi Security Scan",
    description: "Run the canonical full-repository workflow. The runtime, not this Pi session, owns phase transitions.",
    parameters: Type.Object({
      targetPath: Type.String({ description: "Repository directory to scan." }),
      configPath: Type.Optional(Type.String({ description: "Optional Pi Security TOML configuration path." })),
    }),
    async execute(_toolCallId, params, signal, _onUpdate, context) {
      const input = context ? {
        ...params,
        targetPath: resolve(context.cwd, params.targetPath),
        ...(params.configPath ? { configPath: resolve(context.cwd, params.configPath) } : {}),
      } : params;
      return toolResult(await runtime.start(input, signal));
    },
  });
  pi.registerTool({
    name: "inspect_pi_security_canonical_run",
    label: "Inspect Canonical Pi Security Run",
    description: "Observe canonical persisted run state and committed events without phase-transition authority.",
    parameters: Type.Object({
      runId: Type.String({ description: "Canonical workflow run ID." }),
      afterSequence: Type.Optional(Type.Integer({ minimum: 0, description: "Last committed event sequence already observed." })),
    }),
    async execute(_toolCallId, params, signal) {
      return toolResult(await runtime.observe(params, signal));
    },
  });
}

export function createCanonicalCliPort(options: {
  cliPath: string;
  cwd?: string;
  environment?: NodeJS.ProcessEnv;
}): CanonicalRuntimePort {
  const runtimeEnvironment = (): NodeJS.ProcessEnv => {
    const environment = { ...(options.environment ?? process.env) };
    for (const key of ["PI_HOME", "PI_SECURITY_STATE_DIR"]) {
      const value = environment[key];
      // Leave home expansion to Python, using the child environment's home.
      if (value && !value.startsWith("~")) environment[key] = resolve(options.cwd ?? process.cwd(), value);
    }
    return environment;
  };
  const invoke = async (args: string[], signal?: AbortSignal): Promise<unknown> => {
    let stdout: string;
    try {
      ({ stdout } = await execFileAsync(process.execPath, [options.cliPath, ...args], {
        cwd: options.cwd,
        encoding: "utf8",
        env: runtimeEnvironment(),
        maxBuffer: 4 * 1024 * 1024,
        signal,
      }));
    } catch (error) {
      // A durable failed, canceled, or interrupted run is still an inspectable result.
      // Spawn failures, aborts, and CLI errors without a matching run outcome are not.
      if (error && typeof error === "object" && "code" in error && typeof error.code === "number"
        && "stdout" in error && typeof error.stdout === "string") {
        try {
          const result = parseRunResult(error.stdout);
          if (exitStatusForRun(result.status) === error.code) return result;
        } catch {
          // Preserve the original process failure rather than a secondary parse error.
        }
      }
      throw error;
    }
    return parseRunResult(stdout);
  };
  return {
    observe: async ({ afterSequence = 0, runId }, signal) => {
      signal?.throwIfAborted();
      if (!Number.isSafeInteger(afterSequence) || afterSequence < 0) {
        throw new Error("Event sequence must be a non-negative safe integer.");
      }
      const cwd = options.cwd ?? process.cwd();
      const repository = new WorkbenchRuntimeStateRepository(createWorkbenchRuntimeExecutor({
        environment: runtimeEnvironment(),
        packageRoot: resolve(dirname(resolve(cwd, options.cliPath)), ".."),
      }));
      const { events, run } = await reconnectRuntimeEvents(repository, runId, afterSequence);
      signal?.throwIfAborted();
      // Use the CLI's public projection; raw records include controller and execution metadata.
      return { ...JSON.parse(renderRunJson(run)), events };
    },
    start: async ({ configPath, targetPath }, signal) => await invoke([
      "scan",
      "--target",
      targetPath,
      ...(configPath ? ["--config", configPath] : []),
    ], signal),
  };
}

function parseRunResult(stdout: string): Record<string, unknown> & { id: string; status: RuntimeRunStatus } {
  const line = stdout.trim().split(/\r?\n/u).at(-1);
  if (!line) throw new Error("Canonical runtime returned no state.");
  const value: unknown = JSON.parse(line);
  if (!value || typeof value !== "object" || !("id" in value) || typeof value.id !== "string"
    || !("status" in value) || typeof value.status !== "string"
    || !["created", "running", "interrupted", "completed", "failed", "canceled"].includes(value.status)) {
    throw new Error("Canonical runtime returned an invalid run state.");
  }
  return value as Record<string, unknown> & { id: string; status: RuntimeRunStatus };
}

function toolResult(value: unknown): { content: [{ type: "text"; text: string }]; details: unknown } {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    details: value,
  };
}
