import { randomUUID } from "node:crypto";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const REQUEST_EVENT = "subagents:rpc:v1:request";
const REPLY_EVENT_PREFIX = "subagents:rpc:v1:reply:";
const REQUEST_TIMEOUT_MS = 15_000;

export type SubagentRpcMethod =
  | "ping"
  | "status"
  | "spawn"
  | "steer"
  | "interrupt"
  | "stop"
  | "resume";

interface RpcReply {
  version: 1;
  requestId: string;
  success: boolean;
  data?: unknown;
  error?: {
    code?: string;
    message?: string;
  };
}

export async function requestSubagentRpc(
  pi: ExtensionAPI,
  method: SubagentRpcMethod,
  params: Record<string, unknown>,
  signal?: AbortSignal
): Promise<unknown> {
  if (signal?.aborted) {
    throw signal.reason instanceof Error ? signal.reason : new Error("Subagent request aborted.");
  }

  const requestId = randomUUID();
  const replyEvent = `${REPLY_EVENT_PREFIX}${requestId}`;
  return await new Promise<unknown>((resolve, reject) => {
    let settled = false;
    const cleanup = (): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      unsubscribe();
      signal?.removeEventListener("abort", onAbort);
    };
    const fail = (error: Error): void => {
      cleanup();
      reject(error);
    };
    const onAbort = (): void => {
      fail(signal?.reason instanceof Error ? signal.reason : new Error("Subagent request aborted."));
    };
    const unsubscribe = pi.events.on(replyEvent, (payload: unknown) => {
      if (!payload || typeof payload !== "object" || Array.isArray(payload)) return;
      const reply = payload as Partial<RpcReply>;
      if (reply.version !== 1 || reply.requestId !== requestId) return;
      if (!reply.success) {
        const code = reply.error?.code?.trim();
        const message = reply.error?.message?.trim() || "pi-subagents rejected the request.";
        fail(new Error(code ? `${code}: ${message}` : message));
        return;
      }
      cleanup();
      resolve(reply.data);
    });
    const timer = setTimeout(() => {
      fail(new Error(
        "pi-subagents did not answer its in-process RPC. Reload Pi and verify the bundled extension is enabled."
      ));
    }, REQUEST_TIMEOUT_MS);
    signal?.addEventListener("abort", onAbort, { once: true });

    try {
      pi.events.emit(REQUEST_EVENT, {
        version: 1,
        requestId,
        method,
        params
      });
    } catch (error) {
      fail(error instanceof Error ? error : new Error(String(error)));
    }
  });
}
