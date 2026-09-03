import { BUILT_IN_WORKFLOW, type ConfigOverrides } from "../config/execution-config.js";

export type CliCommand =
  | { kind: "help" }
  | { configPath?: string; kind: "scan"; overrides: ConfigOverrides }
  | { kind: "run-cancel"; runId: string }
  | { kind: "run-inspect"; runId: string }
  | { kind: "run-resume"; runId: string }
  | { kind: "run-retry"; runId: string };

export class CliUsageError extends Error {
  readonly exitCode = 2;

  constructor(message: string) {
    super(message);
    this.name = "CliUsageError";
  }
}

export class CliExitError extends Error {
  constructor(message: string, readonly exitCode: number) {
    super(message);
    this.name = "CliExitError";
  }
}

export const CLI_HELP = `Usage:
  pi-security scan [--config <path>] [--target <path>] [--provider <id>] [--model <id>] [--thinking <level>] [--max-parallel <count>]
  pi-security run inspect <run-id>
  pi-security run cancel <run-id>
  pi-security run resume <run-id>
  pi-security run retry <run-id>
  pi-security --help

Commands:
  scan          Run the built-in full-repository security workflow
  run inspect   Inspect persisted run state
  run cancel    Cancel an active run
  run resume    Explicitly resume an interrupted run
  run retry     Create a linked retry for a failed run

Configuration precedence:
  defaults < ambient config < explicit --config < CLI overrides
`;

export function parseCliArgs(args: readonly string[]): CliCommand {
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h" || args[0] === "help") {
    return { kind: "help" };
  }
  if (args[0] === "scan") return parseScanArgs(args.slice(1));
  if (args[0] === "run") return parseRunArgs(args.slice(1));
  throw new CliUsageError(`Unknown command: ${args[0]}`);
}

function parseScanArgs(args: readonly string[]): CliCommand {
  const overrides: ConfigOverrides = {};
  let configPath: string | undefined;
  for (let index = 0; index < args.length; index += 1) {
    const option = args[index];
    if (option === "--help" || option === "-h") return { kind: "help" };
    const value = requiredOptionValue(args, index, option);
    index += 1;
    switch (option) {
      case "--config":
        configPath = value;
        break;
      case "--target":
        overrides.target = value;
        break;
      case "--provider":
        overrides.provider = value;
        break;
      case "--model":
        overrides.model = value;
        break;
      case "--thinking":
        if (!["off", "minimal", "low", "medium", "high", "xhigh"].includes(value)) {
          throw new CliUsageError(`Invalid --thinking value: ${value}`);
        }
        overrides.thinking = value as NonNullable<ConfigOverrides["thinking"]>;
        break;
      case "--max-parallel": {
        const count = Number(value);
        if (!Number.isInteger(count) || count < 1 || count > 64) {
          throw new CliUsageError("--max-parallel must be an integer from 1 through 64.");
        }
        overrides.maxParallel = count;
        break;
      }
      case "--workflow":
        if (value !== BUILT_IN_WORKFLOW) {
          throw new CliUsageError(`Unsupported workflow: ${value}`);
        }
        overrides.workflow = BUILT_IN_WORKFLOW;
        break;
      default:
        throw new CliUsageError(`Unknown scan option: ${option}`);
    }
  }
  return { configPath, kind: "scan", overrides };
}

function parseRunArgs(args: readonly string[]): CliCommand {
  const action = args[0];
  if (action === "--help" || action === "-h") return { kind: "help" };
  if (!action || !["inspect", "cancel", "resume", "retry"].includes(action)) {
    throw new CliUsageError(action ? `Unknown run command: ${action}` : "Missing run command.");
  }
  const runId = args[1]?.trim();
  if (!runId) throw new CliUsageError(`Missing run ID for run ${action}.`);
  if (args.length > 2) throw new CliUsageError(`Unexpected argument for run ${action}: ${args[2]}`);
  return { kind: `run-${action}` as Exclude<CliCommand["kind"], "help" | "scan">, runId };
}

function requiredOptionValue(args: readonly string[], index: number, option: string): string {
  if (!option.startsWith("--")) throw new CliUsageError(`Unexpected scan argument: ${option}`);
  const value = args[index + 1];
  if (!value || value.startsWith("--")) throw new CliUsageError(`Missing value for ${option}.`);
  return value;
}
