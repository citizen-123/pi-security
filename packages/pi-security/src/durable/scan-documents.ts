// Session documents scan tools read and write (design D3). Results live in a session-scoped family keyed by the
// worker's conversation ID, committed by the role's report tool together with its result, so they outlive the worker
// task and its tool calls.
import { defineDoc, defineDocFamily } from "@earendil-works/pi-durable";

type Json = string | number | boolean | null | Json[] | { [key: string]: Json };

/** What get_context returns: the scan's identity, scope, focus, and the guidance workers follow. Set by the orchestrator. */
export const ScanContextDoc = defineDoc<{ [key: string]: Json }>({
  kind: "security.context",
  version: 1,
  scope: "session",
  initial: () => ({}),
  checkpointWhen: () => false
});

/** What git_metadata returns: the scan target resolved at preflight with fixed-argument Git (D14). */
export const TargetDoc = defineDoc<{ [key: string]: Json }>({
  kind: "security.target",
  version: 1,
  scope: "session",
  initial: () => ({}),
  checkpointWhen: () => false
});

export type RoleResult = { role?: string; payload?: { [key: string]: Json } };

/** One worker's schema-valid report, keyed by its conversation ID. */
export const ResultFamily = defineDocFamily<RoleResult, null>({
  kind: "security.result",
  version: 1,
  scope: "session",
  family: true,
  initial: () => ({}),
  checkpointWhen: () => false
});

export const resultKey = (conversationId: number | string) => String(conversationId);
