import * as z from "zod/v4";

export type LifecycleToolRawShape = Record<string, z.ZodType>;
export type LifecycleToolInputSchema = z.ZodType | LifecycleToolRawShape;

type LifecycleToolInput<Schema extends LifecycleToolInputSchema> =
  Schema extends z.ZodType
    ? z.output<Schema>
    : Schema extends LifecycleToolRawShape
      ? z.output<z.ZodObject<Schema>>
      : never;

export interface LifecycleToolConfig<Schema extends LifecycleToolInputSchema = LifecycleToolInputSchema> {
  title: string;
  description: string;
  inputSchema: Schema;
  annotations: {
    readOnlyHint: boolean;
    destructiveHint: boolean;
    idempotentHint: boolean;
    openWorldHint: boolean;
  };
  _meta: Record<string, unknown>;
}

export type LifecycleToolHandler = (
  input: unknown,
  requestContext: unknown
) => Promise<unknown>;

export interface LifecycleToolRegistration {
  name: string;
  config: LifecycleToolConfig;
  handler: LifecycleToolHandler;
}

export interface LifecycleToolRegistrar {
  registerTool<Schema extends LifecycleToolInputSchema>(
    name: string,
    config: LifecycleToolConfig<Schema>,
    handler: (
      input: LifecycleToolInput<Schema>,
      requestContext: unknown
    ) => Promise<unknown>
  ): void;
}

export interface LifecycleProtocolServer {
  onclose?: () => void;
  getClientCapabilities(): {
    elicitation?: { form?: unknown };
    sampling?: { tools?: unknown };
  } | undefined;
  elicitInput(
    request: unknown,
    options?: { timeout?: number; signal?: AbortSignal }
  ): Promise<{
    action: "accept" | "decline" | "cancel";
    content?: unknown;
  }>;
}

export interface LifecycleRegistrationServer extends LifecycleToolRegistrar {
  server: LifecycleProtocolServer;
  sendLoggingMessage(message: unknown): Promise<void>;
}

export interface LifecycleToolCatalog {
  tools: readonly LifecycleToolRegistration[];
  dispose(): void;
}

/** Collect canonical registrations without binding them to a transport. */
export function createLifecycleCatalogServer(): {
  registrations: LifecycleToolRegistration[];
  server: LifecycleRegistrationServer;
} {
  const registrations: LifecycleToolRegistration[] = [];
  const protocolServer: LifecycleProtocolServer = {
    getClientCapabilities: () => ({}),
    async elicitInput() {
      throw new Error("This host does not support MCP form elicitation.");
    }
  };
  const server: LifecycleRegistrationServer = {
    server: protocolServer,
    async sendLoggingMessage() {},
    registerTool(name, config, handler) {
      registrations.push({
        name,
        config: config as LifecycleToolConfig,
        handler: handler as LifecycleToolHandler
      });
    }
  };
  return { registrations, server };
}
/** Apply the canonical MCP input parser before a transport-neutral handler runs. */
export function parseLifecycleToolInput(
  schema: LifecycleToolInputSchema,
  input: unknown
): unknown {
  return lifecycleToolZodSchema(schema).parse(input);
}

/** Emit the same draft-7 input schema the MCP SDK derives from canonical Zod registrations. */
export function lifecycleToolJsonSchema(
  schema: LifecycleToolInputSchema
): Record<string, unknown> {
  const objectSchema = lifecycleToolZodSchema(schema);
  return z.toJSONSchema(objectSchema, {
    target: "draft-7",
    io: "input"
  }) as Record<string, unknown>;
}

function lifecycleToolZodSchema(schema: LifecycleToolInputSchema): z.ZodType {
  return isRawShape(schema) ? z.object(schema) : schema;
}

function isRawShape(schema: LifecycleToolInputSchema): schema is LifecycleToolRawShape {
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) return false;
  if ("_def" in schema || "_zod" in schema || typeof Reflect.get(schema, "parse") === "function") {
    return false;
  }
  return Object.values(schema).every((value) =>
    Boolean(
      value
      && typeof value === "object"
      && (
        "_def" in value
        || "_zod" in value
        || typeof Reflect.get(value, "parse") === "function"
      )
    )
  );
}
