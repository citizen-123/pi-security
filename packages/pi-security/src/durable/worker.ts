// The security.worker task (design D3, D7): one role, one packet, one owned conversation, one admitted result.
//
//   open  create a conversation owned by this task, configured for the role with an exact tool list (an unset tool
//         list would enable every registered tool), and commit its ID in the checkpoint.
//   run   submit the packet with requestId "worker:<taskId>" (a rerun after a crash finds the same submission), wait,
//         then admit the result only if the conversation's resolved agent still offers exactly the role's tools and
//         model, and the recorded payload re-validates.
//
// A worker that ends without an admissible result fails; the orchestrator applies the phase's failure policy (D6).
import type { Context } from "@earendil-works/chord";
import { configure, defineTask, type Agent, type ConversationId, type TaskId } from "@earendil-works/pi-durable";
import type { JsonObject } from "../contract/contract-error.js";
import { ResultFamily, resultKey } from "./scan-documents.js";
import { type createScanTools, type ReportRole, validateRoleResult } from "./scan-tools.js";

export type ThinkingLevel = "off" | "minimal" | "low" | "medium" | "high" | "xhigh";

/** A worker role as stored in task input: names only, no credentials. */
export type WorkerRole = {
  readonly id: string;
  readonly report: ReportRole;
  readonly model: { readonly provider: string; readonly modelId: string };
  readonly thinking?: ThinkingLevel;
  readonly instructions: string;
};

export type WorkerInput = { readonly role: WorkerRole; readonly packet: string };
export type WorkerState = { readonly phase: "open" } | { readonly phase: "run"; readonly conversationId: number };
export type WorkerResult = { readonly conversationId: number; readonly role: string; readonly report: ReportRole; readonly payload: JsonObject };

export type WorkerOptions = {
  readonly tools: ReturnType<typeof createScanTools>;
  /** The conversation's agent resolved with the current registry and settings: `harness.conversation(id).agent()`. */
  readonly resolveAgent: (conversationId: ConversationId, context: Context) => Promise<Agent>;
};

/** Why a resolved agent may not be trusted with this role's result, or undefined when it matches. */
export function agentDrift(agent: Agent, role: WorkerRole, expectedTools: readonly string[]): string | undefined {
  const offered = agent.tools.map((tool) => tool.name);
  if (offered.join("\n") !== expectedTools.join("\n")) {
    return `worker conversation offers [${offered.join(", ")}] instead of [${expectedTools.join(", ")}]`;
  }
  const callable = agent.callable.map((tool) => tool.name).filter((name) => !expectedTools.includes(name));
  if (callable.length > 0) return `worker conversation can call unexpected tools: ${callable.join(", ")}`;
  if (agent.deferred.length > 0) return `worker conversation has deferred tools: ${agent.deferred.map((tool) => tool.name).join(", ")}`;
  if (agent.model?.provider !== role.model.provider || agent.model?.modelId !== role.model.modelId) {
    return `worker conversation uses ${agent.model?.provider}/${agent.model?.modelId} instead of ${role.model.provider}/${role.model.modelId}`;
  }
  return undefined;
}

export function createWorkerTask({ tools, resolveAgent }: WorkerOptions) {
  return defineTask<WorkerInput, WorkerState, WorkerResult>({
    name: "security.worker",
    version: 1,
    initial: () => ({ phase: "open" }),
    phases: {
      open: async (task, runtime, context) => {
        const { role } = task.input;
        await runtime.commit(async (tx) => {
          const created = await tx.createConversation({ ownership: { kind: "task", taskId: task.id } });
          await configure(tx, created.id, {
            model: role.model,
            ...(role.thinking === undefined ? {} : { thinkingLevel: role.thinking }),
            extensions: [tools.extension],
            tools: tools.toolsFor(role.report),
            instructions: role.instructions
          });
          return { status: "running", checkpoint: { phase: "run", conversationId: created.id as unknown as number } };
        }, context);
      },
      run: async (task, runtime, context) => {
        const { role, packet } = task.input;
        const conversationId = (task.state.checkpoint as Extract<WorkerState, { phase: "run" }>).conversationId as unknown as ConversationId;
        const conversation = await runtime.conversation(conversationId, context);
        const fail = (message: string) =>
          runtime.commit(() => ({ status: "terminal", outcome: { status: "failed", error: { message } } }), context);
        if (conversation === undefined) return fail("worker conversation is missing");
        const submission = await conversation.submit({ type: "input", content: packet, requestId: `worker:${task.id}` }, context);
        const settled = await submission.wait(context);
        const drift = agentDrift(await resolveAgent(conversationId, context), role, tools.toolsFor(role.report).map((tool) => tool.name));
        if (drift !== undefined) return fail(drift);
        const recorded = await runtime.snapshot(ResultFamily, resultKey(conversationId as unknown as number), context);
        if (recorded?.payload === undefined || recorded.role !== role.report) {
          return fail(`worker ended without a ${role.report} result (submission ${settled.status})`);
        }
        let payload: JsonObject;
        try {
          payload = validateRoleResult(role.report, recorded.payload);
        } catch (error) {
          return fail(`worker result failed validation: ${(error as Error).message}`);
        }
        await runtime.commit(
          () => ({
            status: "terminal",
            outcome: { status: "completed", result: { conversationId: conversationId as unknown as number, role: role.id, report: role.report, payload } }
          }),
          context
        );
      }
    },
    abort: (_task, runtime, context) => runtime.commit(() => ({ status: "terminal", outcome: { status: "aborted" } }), context)
  });
}

export type WorkerTask = ReturnType<typeof createWorkerTask>;
export type WorkerTaskId = TaskId<WorkerResult>;
