import type {
  AgentToolResult,
  ExtensionAPI,
  CreateAgentSessionOptions,
} from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type, type TSchema } from "typebox";
import type { ExecutionPolicyContext } from "../src/execution-policy.js";
import {
  assertPiPermissionSurface,
  piPermissionSurfaceAllowed
} from "../src/pi-permission-profile.js";
import { createPiSecurityLifecycleCatalog } from "../lifecycle.js";
import {
  lifecycleToolJsonSchema,
  parseLifecycleToolInput
} from "../src/lifecycle/catalog.js";

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
      ...deepScanToolRenderer(tool.name),
      async execute(_toolCallId, params, signal, onUpdate, context) {
        assertPiPermissionSurface(executionContext, "lifecycle", tool.name);
        const sessionId = context.sessionManager.getSessionId();
        const input = parseLifecycleToolInput(tool.config.inputSchema, params);
        const result = await tool.handler(input, {
          sessionId,
          signal,
          onUpdate: (update) => onUpdate?.(piToolResult(update)),
          setStatus: context.hasUI
            ? (key, text) => context.ui.setStatus(key, text)
            : undefined,
          setWidget: context.hasUI
            ? (key, lines) => context.ui.setWidget(key, lines)
            : undefined,
          model: context.model,
          modelId: context.model?.id,
          thinkingLevel: currentThinkingLevel(context.sessionManager.getEntries()),
          resolveModel: (modelId) => context.modelRegistry
            .getAvailable()
            .find((model) => model.id === modelId),
          requestUserInput: context.hasUI
            ? async (questions, requestSignal) => {
              const answers: Record<string, string> = {};
              for (const question of questions) {
                const options = question.options.map(
                  (option) => `${option.label} — ${option.description}`,
                );
                const selected = await context.ui.select(
                  `${question.header}: ${question.question}`,
                  options,
                  { signal: requestSignal },
                );
                if (!selected) {
                  return {
                    status: requestSignal?.aborted ? "cancelled" : "declined",
                  };
                }
                const index = options.indexOf(selected);
                if (index < 0) return { status: "unavailable" };
                answers[question.id] = question.options[index]!.label;
              }
              return { status: "accepted", answers };
            }
            : undefined,
        });
        return piToolResult(result);
      }
    });
  }
  pi.on("session_shutdown", () => {
    catalog.dispose();
  });
}

function deepScanToolRenderer(name: string) {
  if (name !== "start_pi_security_deep_scan") return {};
  return {
    renderCall() {
      return new Text("Deep Scan: preparing independent reviews…", 0, 0);
    },
    renderResult(
      result: AgentToolResult<unknown>,
      { isPartial }: { isPartial: boolean }
    ) {
      const details = isJsonObject(result.details) ? result.details : undefined;
      const statusText = typeof details?.statusText === "string"
        ? details.statusText
        : result.content.find((item) => item.type === "text")?.text
          ?? "Deep Scan is running.";
      return new Text(
        isPartial ? `Deep Scan: ${statusText}` : statusText,
        0,
        0
      );
    }
  };
}

function currentThinkingLevel(
  entries: readonly unknown[],
): CreateAgentSessionOptions["thinkingLevel"] {
  for (const entry of [...entries].reverse()) {
    if (!isJsonObject(entry) || entry.type !== "thinking_level_change") continue;
    switch (entry.thinkingLevel) {
      case "off":
        return undefined;
      case "minimal":
      case "low":
      case "medium":
      case "high":
      case "xhigh":
        return entry.thinkingLevel;
    }
  }
  return undefined;
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
