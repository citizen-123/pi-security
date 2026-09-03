import { randomUUID } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { resolveExecutionConfig } from "../config/execution-config.js";
import { DefaultCanonicalRuntimeGateway } from "../runtime/default-gateway.js";
import type { CliIo } from "./main.js";
import { createCliCommandHandler } from "./operations.js";

export function createDefaultCliCommandHandler(io: CliIo) {
  const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const gateway = new DefaultCanonicalRuntimeGateway({ packageRoot });
  const ownership = Object.freeze({
    claimToken: randomUUID(),
    controllerId: randomUUID(),
  });
  return createCliCommandHandler({
    config: async (command) => await resolveExecutionConfig({
      ...(command.kind === "scan" ? {
        explicitPath: command.configPath,
        overrides: command.overrides,
      } : {}),
    }),
    io,
    lifecycle: gateway,
    ownership: () => ownership,
    repository: gateway.repository,
  });
}
