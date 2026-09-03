import type { AgentToolResult } from "@earendil-works/pi-coding-agent";

type JsonObject = Record<string, unknown>;

export function deepScanToolRenderer(name: string) {
  if (name !== "start_pi_security_deep_scan") return {};
  return {
    renderCall() {
      const text = "Deep Scan: preparing independent reviews…";
      return {
        render(width: number) {
          return [text.slice(0, Math.max(0, width))];
        },
        invalidate() {
        }
      };
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
      const text = isPartial && !statusText.startsWith("Deep Scan:")
        ? `Deep Scan: ${statusText}`
        : statusText;
      return {
        render(width: number) {
          return [text.slice(0, Math.max(0, width))];
        },
        invalidate() {
        }
      };
    }
  };
}

function isJsonObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
