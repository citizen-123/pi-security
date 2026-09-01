import { registerSubagentCapabilityCeiling } from "pi-subagents/capability-ceiling";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import {
  canonicalBoundDirectory,
  probeDirectoryHandleEnforcement,
} from "../src/execution-boundary.js";
import {
  deriveDelegatedExecutionContext,
  describeExecutionPolicy,
  type ExecutionPolicyContext
} from "../src/execution-policy.js";
import {
  assertPiEnforcementSupported,
  describePiEnforcementCapabilities,
  type EnforcementCapabilityReport,
} from "../src/enforcement-capabilities.js";
import {
  PI_PACKAGED_SECURITY_AGENTS,
  assertPiPackagedSecurityAgent,
  assertPiPermissionSurface,
  issuePiDelegatingAgentContext,
  piPackagedAgentToolAllowlist,
  piPermissionSurfaceAllowed,
  type PiPackagedSecurityAgent
} from "../src/pi-permission-profile.js";
import { requestSubagentRpc, type SubagentRpcMethod } from "./subagent-rpc.js";

const securityAgentSchema = Type.Union([
  Type.Literal("pi-security-scout"),
  Type.Literal("pi-security-auditor"),
  Type.Literal("pi-security-validator"),
  Type.Literal("pi-security-reviewer")
]);

interface PiSecuritySessionAuthority {
  targetRoot: string;
  successor: ExecutionPolicyContext;
}

interface PiSecurityRunAuthority {
  id: string;
  sessionId: string;
  targetRoot: string;
  agent: PiPackagedSecurityAgent;
  context: ExecutionPolicyContext;
}

const PI_SECURITY_SESSION_DELEGATION_BUDGET = 16;
interface PiSecurityExtensionContext {
  cwd: string;
  sessionManager: {
    getSessionId(): unknown;
  };
}

export function registerSecuritySubagentTools(
  pi: ExtensionAPI,
  registrationContext: ExecutionPolicyContext
): void {
  if (!piPermissionSurfaceAllowed(registrationContext, "delegation")) return;
  const sessions = new Map<string, PiSecuritySessionAuthority>();
  const runs = new Map<string, PiSecurityRunAuthority>();

  pi.registerTool({
    name: "pi_security_spawn_agents",
    label: "Spawn Pi Security Agents",
    description: "Start one or more bundled read-only Pi Security agents concurrently. Returns asynchronous run IDs for status, steering, stopping, and resuming.",
    parameters: Type.Object({
      tasks: Type.Array(Type.Object({
        agent: Type.Optional(securityAgentSchema),
        task: Type.String({ minLength: 1, maxLength: 100000, description: "Complete target, scope, evidence, and expected-output instructions for this child." })
      }), { minItems: 1, maxItems: 16 }),
      context: Type.Optional(Type.Union([
        Type.Literal("fresh"),
        Type.Literal("fork")
      ], { description: "Fresh context is the safe default; fork only when the child needs the current conversation." }))
    }),
    async execute(_toolCallId, params, signal, _onUpdate, ctx) {
      const identity = await resolvePiSecuritySession(ctx);
      let session = sessions.get(identity.sessionId);
      if (!session) {
        session = {
          targetRoot: identity.targetRoot,
          successor: issuePiDelegatingAgentContext({
            targetRoot: identity.targetRoot,
            scanId: identity.sessionId,
            artifactRoot: identity.targetRoot
          }, PI_SECURITY_SESSION_DELEGATION_BUDGET)
        };
        sessions.set(identity.sessionId, session);
      } else if (session.targetRoot !== identity.targetRoot) {
        throw new Error("The active Pi session is already bound to a different canonical target.");
      }

      if (!Array.isArray(params.tasks) || params.tasks.length === 0) {
        throw new Error("Pi Security subagent spawning requires at least one task.");
      }
      const agents = params.tasks.map((task) => {
        const agent = task.agent ?? "pi-security-auditor";
        assertPiPackagedSecurityAgent(agent);
        return agent;
      });
      const available = describeExecutionPolicy(session.successor).delegation.remainingBudget;
      if (params.tasks.length > available) {
        throw new Error(
          `Pi Security session delegation budget is exhausted: ${available} of `
          + `${PI_SECURITY_SESSION_DELEGATION_BUDGET} launches remain.`
        );
      }

      const reservations = params.tasks.map((task, index) => {
        assertPiPermissionSurface(
          session!.successor,
          "delegation",
          "pi_security_spawn_agents"
        );
        const transition = deriveDelegatedExecutionContext(session!.successor);
        // No await occurs between deriving a child and replacing the only
        // host-owned successor. Concurrent calls can observe only this successor.
        session!.successor = transition.parent;
        return {
          index,
          task,
          agent: agents[index],
          context: transition.child
        };
      });
      const ceiling = registerReadonlyCeiling(
        identity.sessionId,
        reservations[0]!.context
      );
      try {
        const results = await Promise.all(reservations.map(async (reservation) => {
          try {
            const data = await requestSubagentRpc(pi, "spawn", {
              agent: reservation.agent,
              task: reservation.task.task,
              async: true,
              context: params.context ?? "fresh",
              cwd: identity.targetRoot
            }, signal);
            const id = spawnedRunId(data);
            if (!id) {
              throw new Error("pi-subagents started a run without returning a durable run id.");
            }
            if (runs.has(id)) {
              throw new Error(`pi-subagents returned duplicate run id ${JSON.stringify(id)}.`);
            }
            runs.set(id, {
              id,
              sessionId: identity.sessionId,
              targetRoot: identity.targetRoot,
              agent: reservation.agent,
              context: reservation.context
            });
            return {
              index: reservation.index,
              agent: reservation.agent,
              id,
              success: true as const,
              data
            };
          } catch (error) {
            return {
              index: reservation.index,
              agent: reservation.agent,
              success: false as const,
              error: error instanceof Error ? error.message : String(error)
            };
          }
        }));
        const started = results.filter((run) => run.success).length;
        const details = {
          started,
          requested: results.length,
          runs: results,
          enforcementCapabilities: identity.enforcementCapabilities,
        };
        return {
          content: [{
            type: "text" as const,
            text: started === results.length
              ? `Started ${started} Pi Security subagent${started === 1 ? "" : "s"}.`
              : `Started ${started} of ${results.length} Pi Security subagents. Inspect failed rows before continuing.`
          }],
          details,
          ...(started === 0 ? { isError: true } : {})
        };
      } finally {
        ceiling.dispose();
      }
    }
  });

  pi.registerTool({
    name: "pi_security_control_agents",
    label: "Control Pi Security Agents",
    description: "Read fleet status or steer, interrupt, stop, or resume an asynchronous Pi Security subagent run.",
    parameters: Type.Object({
      action: Type.Union([
        Type.Literal("status"),
        Type.Literal("steer"),
        Type.Literal("interrupt"),
        Type.Literal("stop"),
        Type.Literal("resume")
      ]),
      id: Type.Optional(Type.String({ minLength: 1, maxLength: 512, description: "Asynchronous run ID. Optional only for fleet status." })),
      index: Type.Optional(Type.Integer({ minimum: 0 })),
      message: Type.Optional(Type.String({ minLength: 1, maxLength: 100000 })),
      mode: Type.Optional(Type.Union([
        Type.Literal("steer"),
        Type.Literal("follow_up"),
        Type.Literal("auto")
      ])),
      view: Type.Optional(Type.Union([
        Type.Literal("fleet"),
        Type.Literal("transcript")
      ])),
      lines: Type.Optional(Type.Integer({ minimum: 1, maximum: 500 }))
    }),
    async execute(_toolCallId, params, signal, _onUpdate, ctx) {
      const identity = await resolvePiSecuritySession(ctx);
      const boundSession = sessions.get(identity.sessionId);
      if (boundSession && boundSession.targetRoot !== identity.targetRoot) {
        throw new Error("The active Pi session is already bound to a different canonical target.");
      }
      if (params.action !== "status" && !params.id) {
        throw new Error(`${params.action} requires an asynchronous run id.`);
      }
      if ((params.action === "steer" || params.action === "resume") && !params.message?.trim()) {
        throw new Error(`${params.action} requires a non-empty message.`);
      }

      if (!params.id) {
        const owned = [...runs.values()].filter((run) => (
          run.sessionId === identity.sessionId
          && run.targetRoot === identity.targetRoot
        ));
        if (owned.length === 0) {
          const details = {
            version: 1,
            sessionId: identity.sessionId,
            runs: [],
            enforcementCapabilities: identity.enforcementCapabilities,
          };
          return {
            content: [{ type: "text" as const, text: JSON.stringify(details) }],
            details
          };
        }
        const ceiling = registerReadonlyCeiling(
          identity.sessionId,
          owned[0]!.context
        );
        try {
          const statuses = await Promise.all(owned.map(async (run) => {
            try {
              const data = await requestSubagentRpc(pi, "status", {
                id: run.id,
                ...(params.view ? { view: params.view } : {}),
                ...(params.lines === undefined ? {} : { lines: params.lines })
              }, signal);
              return { id: run.id, agent: run.agent, success: true as const, data };
            } catch (error) {
              return {
                id: run.id,
                agent: run.agent,
                success: false as const,
                error: error instanceof Error ? error.message : String(error)
              };
            }
          }));
          const details = {
            version: 1,
            sessionId: identity.sessionId,
            runs: statuses,
            enforcementCapabilities: identity.enforcementCapabilities,
          };
          return {
            content: [{ type: "text" as const, text: JSON.stringify(details) }],
            details
          };
        } finally {
          ceiling.dispose();
        }
      }

      const run = runs.get(params.id);
      if (
        !run
        || run.sessionId !== identity.sessionId
        || run.targetRoot !== identity.targetRoot
      ) {
        throw new Error("The requested subagent run is not owned by this Pi Security session.");
      }
      const method = params.action as SubagentRpcMethod;
      const ceiling = registerReadonlyCeiling(
        identity.sessionId,
        run.context
      );
      try {
        const data = await requestSubagentRpc(pi, method, {
          id: run.id,
          ...(params.index === undefined ? {} : { index: params.index }),
          ...(params.message ? { message: params.message } : {}),
          ...(params.mode ? { mode: params.mode } : {}),
          ...(params.view ? { view: params.view } : {}),
          ...(params.lines === undefined ? {} : { lines: params.lines })
        }, signal);
        if (params.action === "resume") {
          const resumedId = spawnedRunId(data);
          if (resumedId && resumedId !== run.id) {
            if (runs.has(resumedId)) {
              throw new Error(
                `pi-subagents returned duplicate run id ${JSON.stringify(resumedId)}.`
              );
            }
            runs.set(resumedId, { ...run, id: resumedId });
          }
        }
        return {
          content: [{
            type: "text" as const,
            text: typeof data === "string" ? data : JSON.stringify(data ?? null)
          }],
          details: data
        };
      } finally {
        ceiling.dispose();
      }
    }
  });

  pi.on("session_shutdown", () => {
    sessions.clear();
    runs.clear();
  });
}

async function resolvePiSecuritySession(
  context: PiSecurityExtensionContext
): Promise<{
  sessionId: string;
  targetRoot: string;
  enforcementCapabilities: EnforcementCapabilityReport;
}> {
  const sessionId = context.sessionManager.getSessionId();
  if (typeof sessionId !== "string" || !sessionId) {
    throw new Error("Pi Security subagent tools require an active session.");
  }
  const targetRoot = await canonicalBoundDirectory(
    context.cwd,
    "Pi Security session target"
  );
  const platformMechanisms = await probeDirectoryHandleEnforcement(
    targetRoot,
    "Pi Security session target",
  );
  const enforcementCapabilities = describePiEnforcementCapabilities({
    kind: "availability",
    piTools: true,
    targetHandles: true,
    platformMechanisms,
  });
  assertPiEnforcementSupported(enforcementCapabilities);
  return { sessionId, targetRoot, enforcementCapabilities };
}

function registerReadonlyCeiling(
  sessionId: string,
  context: ExecutionPolicyContext
) {
  return registerSubagentCapabilityCeiling({
    sessionId,
    source: "pi-security",
    ceiling: {
      allowedTools: piPackagedAgentToolAllowlist(context),
      allowedAgents: [...PI_PACKAGED_SECURITY_AGENTS],
      denyExtensions: true
    }
  });
}

function spawnedRunId(value: unknown): string | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const response = value as {
    id?: unknown;
    runId?: unknown;
    asyncId?: unknown;
    details?: unknown;
  };
  if (typeof response.id === "string" && response.id) return response.id;
  if (typeof response.runId === "string" && response.runId) return response.runId;
  if (typeof response.asyncId === "string" && response.asyncId) return response.asyncId;
  if (!response.details || typeof response.details !== "object" || Array.isArray(response.details)) {
    return undefined;
  }
  const details = response.details as { asyncId?: unknown; runId?: unknown };
  if (typeof details.asyncId === "string" && details.asyncId) return details.asyncId;
  if (typeof details.runId === "string" && details.runId) return details.runId;
  return undefined;
}
