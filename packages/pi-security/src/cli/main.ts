import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { CanonicalPreflightError } from "../runtime/lifecycle.js";
import { CLI_HELP, CliExitError, CliUsageError, parseCliArgs, type CliCommand } from "./args.js";
import { createDefaultCliCommandHandler } from "./default.js";

export interface CliIo {
  error(message: string): void;
  output(message: string): void;
}

export type CliCommandHandler = (command: Exclude<CliCommand, { kind: "help" }>) => Promise<number>;

export const consoleIo: CliIo = {
  error(message) {
    process.stderr.write(`${message}\n`);
  },
  output(message) {
    process.stdout.write(`${message}\n`);
  },
};

export async function runCli(
  args: readonly string[],
  io: CliIo = consoleIo,
  handler: CliCommandHandler = commandUnavailable,
): Promise<number> {
  try {
    const command = parseCliArgs(args);
    if (command.kind === "help") {
      io.output(CLI_HELP.trimEnd());
      return 0;
    }
    return await handler(command);
  } catch (error) {
    if (error instanceof CanonicalPreflightError) {
      io.error(error.message);
      return 2;
    }
    if (error instanceof CliUsageError) {
      io.error(error.message);
      io.error("Run pi-security --help for usage.");
      return error.exitCode;
    }
    if (error instanceof CliExitError) {
      io.error(error.message);
      return error.exitCode;
    }
    io.error(error instanceof Error ? error.message : String(error));
    return 1;
  }
}

async function commandUnavailable(command: Exclude<CliCommand, { kind: "help" }>): Promise<number> {
  throw new Error(`The ${command.kind} runtime command is unavailable.`);
}

function isDirectEntry(): boolean {
  if (!process.argv[1]) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
  } catch {
    return false;
  }
}

if (isDirectEntry()) {
  process.exitCode = await runCli(process.argv.slice(2), consoleIo, createDefaultCliCommandHandler(consoleIo));
}
