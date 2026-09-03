import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

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
    async execute(_toolCallId, params, signal) {
      return toolResult(await runtime.start(params, signal));
    },
  });
  pi.registerTool({
    name: "inspect_pi_security_canonical_run",
    label: "Inspect Canonical Pi Security Run",
    description: "Observe canonical persisted run state and committed events without phase-transition authority.",
    parameters: Type.Object({
      runId: Type.String({ description: "Canonical workflow run ID." }),
      afterSequence: Type.Optional(Type.Number({ minimum: 0, description: "Last committed event sequence already observed." })),
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
  const invoke = async (args: string[], signal?: AbortSignal): Promise<unknown> => {
    const { stdout } = await execFileAsync(process.execPath, [options.cliPath, ...args], {
      cwd: options.cwd,
      encoding: "utf8",
      env: options.environment ?? process.env,
      maxBuffer: 4 * 1024 * 1024,
      signal,
    });
    const line = stdout.trim().split(/\r?\n/u).at(-1);
    if (!line) throw new Error("Canonical runtime returned no state.");
    return JSON.parse(line) as unknown;
  };
  return {
    observe: async ({ runId }, signal) => await invoke(["run", "inspect", runId], signal),
    start: async ({ configPath, targetPath }, signal) => await invoke([
      "scan",
      "--target",
      targetPath,
      ...(configPath ? ["--config", configPath] : []),
    ], signal),
  };
}

function toolResult(value: unknown): { content: [{ type: "text"; text: string }]; details: unknown } {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    details: value,
  };
}
