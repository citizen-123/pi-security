import * as z from "zod/v4";
import type { CreateAgentSessionOptions } from "@earendil-works/pi-coding-agent";

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

export interface LifecycleUserInputQuestion {
  header: string;
  id: string;
  options: Array<{ description: string; label: string }>;
  question: string;
}

export interface LifecycleRequestContext {
  sessionId?: string;
  signal?: AbortSignal;
  onUpdate?: (result: unknown) => void;
  setStatus?: (key: string, text: string | undefined) => void;
  setWidget?: (key: string, lines: string[] | undefined) => void;
  /** UI key scoped to one native Deep Scan tool invocation. */
  deepScanProgressKey?: string;
  model?: CreateAgentSessionOptions["model"];
  modelId?: string;
  thinkingLevel?: CreateAgentSessionOptions["thinkingLevel"];
  resolveModel?: (
    modelId: string,
  ) => CreateAgentSessionOptions["model"] | undefined;
  requestUserInput?: (
    questions: readonly LifecycleUserInputQuestion[],
    signal?: AbortSignal,
  ) => Promise<{
    status: "accepted" | "declined" | "cancelled" | "unavailable";
    answers?: Record<string, string>;
  }>;
}

export type LifecycleToolHandler = (
  input: unknown,
  requestContext: LifecycleRequestContext
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
      requestContext: LifecycleRequestContext
    ) => Promise<unknown>
  ): void;
  onDispose(handler: () => void): void;
}

export interface LifecycleCatalogCollector extends LifecycleToolRegistrar {
  dispose(): void;
}

export interface LifecycleToolCatalog {
  tools: readonly LifecycleToolRegistration[];
  dispose(): void;
}

/** Collect canonical registrations without binding them to a transport. */
export function createLifecycleCatalogCollector(): {
  registrations: LifecycleToolRegistration[];
  registrar: LifecycleCatalogCollector;
} {
  const registrations: LifecycleToolRegistration[] = [];
  const disposalHandlers: Array<() => void> = [];
  const registrar: LifecycleCatalogCollector = {
    registerTool(name, config, handler) {
      registrations.push({
        name,
        config: config as LifecycleToolConfig,
        handler: handler as LifecycleToolHandler
      });
    },
    onDispose(handler) {
      disposalHandlers.push(handler);
    },
    dispose() {
      for (const handler of disposalHandlers.splice(0).reverse()) handler();
    }
  };
  return { registrations, registrar };
}
/** Apply the canonical lifecycle input parser before a handler runs. */
export function parseLifecycleToolInput(
  schema: LifecycleToolInputSchema,
  input: unknown
): unknown {
  return lifecycleToolZodSchema(schema).parse(input);
}

/** Emit the draft-7 input schema consumed by Pi's native tool registry. */
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
