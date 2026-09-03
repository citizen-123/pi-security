import { pathToFileURL } from "node:url";
import { CLI_HELP, CliExitError, CliUsageError, parseCliArgs, type CliCommand } from "./args.js";

export interface CliIo {
  error(message: string): void;
  output(message: string): void;
}

export type CliCommandHandler = (command: Exclude<CliCommand, { kind: "help" }>) => Promise<number>;

const consoleIo: CliIo = {
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

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await runCli(process.argv.slice(2));
}
