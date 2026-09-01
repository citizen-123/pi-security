import type {
  AgentToolResult,
  ExtensionAPI
} from "@earendil-works/pi-coding-agent";
import { Type, type TSchema } from "typebox";
import type { ExecutionPolicyContext } from "../src/execution-policy.js";
import {
  assertPiPermissionSurface,
  piPermissionSurfaceAllowed
} from "../src/pi-permission-profile.js";
import { createPiSecurityLifecycleCatalog } from "../server.js";
import {
  lifecycleToolJsonSchema,
  parseLifecycleToolInput
} from "../src/server/lifecycle-catalog.js";

type JsonObject = Record<string, unknown>;

/** Register the canonical managed lifecycle on Pi's native tool transport. */
export function registerPiSecurityLifecycleTools(
  pi: ExtensionAPI,
  executionContext: ExecutionPolicyContext
): void {
  if (!piPermissionSurfaceAllowed(executionContext, "lifecycle")) return;
  const catalog = createPiSecurityLifecycleCatalog();
  for (const tool of catalog.tools) {
    pi.registerTool({
      name: tool.name,
      label: tool.config.title,
      description: tool.config.description,
      parameters: Type.Unsafe(
        lifecycleToolJsonSchema(tool.config.inputSchema) as TSchema
      ),
      async execute(_toolCallId, params, signal, _onUpdate, context) {
        assertPiPermissionSurface(executionContext, "lifecycle", tool.name);
        const sessionId = context.sessionManager.getSessionId();
        const input = parseLifecycleToolInput(tool.config.inputSchema, params);
        const result = await tool.handler(input, {
          sessionId,
          signal,
          _meta: {
            sessionId,
            ...(context.model ? { model: context.model.id } : {})
          }
        });
        return piToolResult(result);
      }
    });
  }
  pi.on("session_shutdown", () => {
    catalog.dispose();
  });
}

function piToolResult(result: unknown): AgentToolResult<unknown> {
  if (!isJsonObject(result) || !Array.isArray(result.content)) {
    throw new Error("Pi Security lifecycle handler returned an invalid tool result.");
  }
  if (!result.content.every((item) =>
    isJsonObject(item)
    && item.type === "text"
    && typeof item.text === "string"
  )) {
    throw new Error("Pi Security lifecycle handler returned unsupported content.");
  }
  const content = result.content as Array<{ type: "text"; text: string }>;
  if (result.isError === true) {
    throw new Error(content.map((item) => item.text).join("\n"));
  }
  return {
    content,
    details: result.structuredContent ?? {}
  };
}

function isJsonObject(value: unknown): value is JsonObject {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}
