import { resolve } from "node:path";
import type {
  RuntimeLogicalAgentRecord,
  RuntimeStateRepository,
} from "../runtime/state-repository.js";
import { JsonlRpcClient, JsonlRpcError, type RpcEvent } from "./jsonl-client.js";

export interface PhaseCapabilityProfile {
  allowDelegation: boolean;
  allowTargetMutation: boolean;
  tools: string[];
}

export interface PhaseInputPackage {
  artifactRoot: string;
  authority: {
    artifactRoot: string;
    targetPath: string;
  };
  capabilityProfile: PhaseCapabilityProfile;
  outputContract: Record<string, unknown>;
  phaseId: string;
  requiredInputs: Record<string, unknown>;
  roleId: string;
  runId: string;
  target: {
    path: string;
    revision: string | null;
  };
}

export interface PhaseCredential {
  environmentVariable: string;
  value: string;
}

export interface PhaseRoleSettings {
  credential?: PhaseCredential;
  instructions: string;
  model: string;
  provider: string;
  thinking: "off" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max";
}

export interface LaunchPhaseSessionInput {
  attemptId: string;
  claimToken: string;
  controllerId: string;
  expectedVersion: number;
  input: PhaseInputPackage;
  logicalAgentId: string;
  maxAttempts: number;
  ordinal: number;
  role: PhaseRoleSettings;
}

export interface AgentControlRequest {
  claimToken: string;
  controllerId: string;
  expectedVersion: number;
  logicalAgentId: string;
  runId: string;
  targetPath: string;
}

export type AgentControl =
  | { kind: "status" }
  | { kind: "transcript" }
  | { kind: "steer"; message: string }
  | { kind: "follow-up"; message: string }
  | { kind: "interrupt" }
  | { kind: "stop" };

export interface PhaseSessionSupervisorOptions {
  command?: string;
  commandArgs?: string[];
  cwd?: string;
  environment?: NodeJS.ProcessEnv;
  repository: RuntimeStateRepository;
}

interface BoundSession {
  attemptId: string;
  authority: PhaseInputPackage["authority"];
  activity: Promise<void>;
  claimToken: string;
  client: JsonlRpcClient;
  controllerId: string;
  logicalAgentId: string;
  phaseId: string;
  runId: string;
}

export interface AttemptFailureDecision {
  category: "transport" | "provider" | "policy" | "authority" | "contract" | "canceled" | "unknown";
  replace: boolean;
}

export class PhaseSessionSupervisor {
  readonly #options: PhaseSessionSupervisorOptions;
  readonly #sessions = new Map<string, BoundSession>();

  constructor(options: PhaseSessionSupervisorOptions) {
    this.#options = options;
  }

  async launch(request: LaunchPhaseSessionInput): Promise<{ piSessionId: string; version: number }> {
    validatePhaseInput(request.input);
    if (this.#sessions.has(request.logicalAgentId)) {
      throw new Error("Logical agent already has an active RPC session.");
    }
    const started = await this.#options.repository.startAttempt({
      attemptId: request.attemptId,
      claimToken: request.claimToken,
      controllerId: request.controllerId,
      details: {
        capabilityProfile: request.input.capabilityProfile,
        roleId: request.input.roleId,
        targetPath: request.input.target.path,
      },
      expectedVersion: request.expectedVersion,
      logicalAgentId: request.logicalAgentId,
      ordinal: request.ordinal,
      phaseId: request.input.phaseId,
      runId: request.input.runId,
    });
    const credential = request.role.credential?.value;
    const client = new JsonlRpcClient({
      command: this.#options.command ?? "pi",
      args: buildPiArguments(this.#options.commandArgs ?? [], request),
      cwd: this.#options.cwd ?? request.input.target.path,
      env: buildEnvironment(this.#options.environment ?? process.env, request.role.credential),
      redact: (text) => credential ? text.split(credential).join("[REDACTED]") : text,
    });
    const binding: BoundSession = {
      attemptId: request.attemptId,
      authority: request.input.authority,
      activity: Promise.resolve(),
      claimToken: request.claimToken,
      client,
      controllerId: request.controllerId,
      logicalAgentId: request.logicalAgentId,
      phaseId: request.input.phaseId,
      runId: request.input.runId,
    };
    try {
      await client.start();
      const state = await client.request({ type: "get_state" });
      const piSessionId = readSessionId(state.data);
      await this.#options.repository.updateAttempt({
        attemptId: request.attemptId,
        claimToken: request.claimToken,
        controllerId: request.controllerId,
        details: {
          capabilityProfile: request.input.capabilityProfile,
          roleId: request.input.roleId,
          sessionFile: readOptionalString(state.data, "sessionFile"),
          targetPath: request.input.target.path,
        },
        event: {
          attemptId: request.attemptId,
          category: "domain",
          kind: "agent.session_bound",
          logicalAgentId: request.logicalAgentId,
          payload: { piSessionId },
          phaseId: request.input.phaseId,
          source: "runtime",
        },
        expectedVersion: started.version,
        piSessionId,
        runId: request.input.runId,
        status: "running",
      });
      this.#sessions.set(request.logicalAgentId, binding);
      client.onEvent((event) => {
        binding.activity = binding.activity
          .then(() => this.#recordActivity(binding, event))
          .catch(() => undefined);
      });
      void this.#monitorExit(binding);
      await client.request({
        type: "prompt",
        message: `${request.role.instructions}\n\nPhase input:\n${JSON.stringify(request.input)}`,
      });
      await binding.activity;
      const current = await this.#options.repository.getRun(request.input.runId);
      return { piSessionId, version: current.version };
    } catch (error) {
      this.#sessions.delete(request.logicalAgentId);
      await client.stop().catch(() => undefined);
      const decision = classifyAttemptFailure(error, request.ordinal, request.maxAttempts, false);
      const run = await this.#options.repository.getRun(request.input.runId).catch(() => undefined);
      if (run?.status === "running") {
        await this.#options.repository.updateAttempt({
          attemptId: request.attemptId,
          claimToken: request.claimToken,
          controllerId: request.controllerId,
          details: { message: safeErrorMessage(error, credential) },
          event: {
            attemptId: request.attemptId,
            category: "domain",
            kind: "agent.attempt_failed",
            logicalAgentId: request.logicalAgentId,
            payload: { category: decision.category, replace: decision.replace },
            phaseId: request.input.phaseId,
            source: "runtime",
          },
          expectedVersion: run.version,
          failureCategory: decision.category,
          runId: request.input.runId,
          status: "failed",
        }).catch(() => undefined);
      }
      throw error;
    }
  }

  async control(request: AgentControlRequest, control: AgentControl): Promise<unknown> {
    const binding = await this.#authorize(request);

    const mutation = await this.#options.repository.recordEvent({
      claimToken: request.claimToken,
      controllerId: request.controllerId,
      event: {
        attemptId: binding.attemptId,
        category: "activity",
        kind: `operator.${control.kind}`,
        logicalAgentId: binding.logicalAgentId,
        payload: control.kind === "steer" || control.kind === "follow-up" ? { supplied: true } : {},
        phaseId: binding.phaseId,
        source: "operator",
      },
      expectedVersion: request.expectedVersion,
      runId: request.runId,
    });
    if (control.kind === "status") {
      return {
        runtimeVersion: mutation.version,
        state: (await binding.client.request({ type: "get_state" })).data,
      };
    }
    if (control.kind === "transcript") {
      return {
        runtimeVersion: mutation.version,
        transcript: (await binding.client.request({ type: "get_messages" })).data,
      };
    }
    if (control.kind === "steer") {
      return (await binding.client.request({ type: "steer", message: control.message })).data;
    }
    if (control.kind === "follow-up") {
      return (await binding.client.request({ type: "follow_up", message: control.message })).data;
    }
    await binding.client.request({ type: "abort" });
    if (control.kind === "stop") {
      this.#sessions.delete(binding.logicalAgentId);
      await binding.client.stop();
      const settled = await this.#options.repository.updateAttempt({
        attemptId: binding.attemptId,
        claimToken: binding.claimToken,
        controllerId: binding.controllerId,
        details: { stoppedByOperator: true },
        event: {
          attemptId: binding.attemptId,
          category: "domain",
          kind: "agent.attempt_canceled",
          logicalAgentId: binding.logicalAgentId,
          phaseId: binding.phaseId,
          source: "runtime",
        },
        expectedVersion: mutation.version,
        runId: binding.runId,
        status: "canceled",
      });
      return { version: settled.version };
    }
    return { version: mutation.version };
  }

  async #authorize(request: AgentControlRequest): Promise<BoundSession> {
    const binding = this.#sessions.get(request.logicalAgentId);
    if (!binding) throw new Error("Logical agent has no bound RPC session.");
    await binding.activity;
    const run = await this.#options.repository.getRun(request.runId);
    if (
      run.controllerId !== request.controllerId ||
      run.targetPath !== resolve(request.targetPath) ||
      run.status !== "running" ||
      run.version !== request.expectedVersion
    ) {
      throw new Error("Agent control authority does not match the active run.");
    }
    const agent = await this.#options.repository.getAgent(request.runId, request.logicalAgentId);
    const attempt = activeAttempt(agent);
    if (
      binding.runId !== request.runId ||
      binding.attemptId !== attempt.id ||
      binding.authority.targetPath !== run.targetPath ||
      binding.controllerId !== request.controllerId ||
      binding.claimToken !== request.claimToken
    ) {
      throw new Error("Agent control does not match the bound RPC session authority.");
    }
    return binding;
  }

  async #recordActivity(binding: BoundSession, event: RpcEvent): Promise<void> {
    if (!isMeaningfulActivity(event.type)) return;
    const run = await this.#options.repository.getRun(binding.runId);
    if (run.status !== "running" || run.outputAdmissionFrozen) return;
    await this.#options.repository.recordEvent({
      claimToken: binding.claimToken,
      controllerId: binding.controllerId,
      event: {
        attemptId: binding.attemptId,
        category: "activity",
        kind: `pi.${event.type}`,
        logicalAgentId: binding.logicalAgentId,
        payload: summarizeActivity(event),
        phaseId: binding.phaseId,
        source: "pi-rpc",
      },
      expectedVersion: run.version,
      runId: binding.runId,
    }).catch(() => undefined);
  }

  async #monitorExit(binding: BoundSession): Promise<void> {
    await binding.client.waitForExit();
    await binding.activity;
    if (this.#sessions.get(binding.logicalAgentId) !== binding) return;
    this.#sessions.delete(binding.logicalAgentId);
    const run = await this.#options.repository.getRun(binding.runId).catch(() => undefined);
    if (!run || run.status !== "running" || run.outputAdmissionFrozen) return;
    await this.#options.repository.updateAttempt({
      attemptId: binding.attemptId,
      claimToken: binding.claimToken,
      controllerId: binding.controllerId,
      details: { stderr: binding.client.getStderr() },
      event: {
        attemptId: binding.attemptId,
        category: "domain",
        kind: "agent.process_exited",
        logicalAgentId: binding.logicalAgentId,
        phaseId: binding.phaseId,
        source: "runtime",
      },
      expectedVersion: run.version,
      failureCategory: "transport",
      runId: binding.runId,
      status: "interrupted",
    }).catch(() => undefined);
  }
}

export function classifyAttemptFailure(
  error: unknown,
  ordinal: number,
  maxAttempts: number,
  canceled: boolean
): AttemptFailureDecision {
  if (canceled) return { category: "canceled", replace: false };
  if (error instanceof JsonlRpcError) {
    const category = error.kind === "request" ? "provider" : "transport";
    return { category, replace: ordinal < maxAttempts };
  }
  const code = error && typeof error === "object" && "code" in error ? String(error.code) : "";
  switch (code) {
    case "POLICY_DENIED":
      return { category: "policy", replace: false };
    case "AUTHORITY_MISMATCH":
      return { category: "authority", replace: false };
    case "CONTRACT_INCOMPATIBLE":
      return { category: "contract", replace: false };
    default:
      return { category: "unknown", replace: false };
  }
}

function buildPiArguments(base: string[], request: LaunchPhaseSessionInput): string[] {
  const capability = request.input.capabilityProfile;
  const toolArguments = capability.tools.length > 0
    ? ["--tools", capability.tools.join(",")]
    : ["--no-tools"];
  return [
    ...base,
    "--mode", "rpc",
    "--provider", request.role.provider,
    "--model", request.role.model,
    "--thinking", request.role.thinking,
    "--name", `${request.input.runId}:${request.input.phaseId}:${request.ordinal}`,
    "--session-dir", request.input.artifactRoot,
    ...toolArguments,
  ];
}

function buildEnvironment(environment: NodeJS.ProcessEnv, credential?: PhaseCredential): NodeJS.ProcessEnv {
  const result = { ...environment };
  if (credential) result[credential.environmentVariable] = credential.value;
  return result;
}

function validatePhaseInput(input: PhaseInputPackage): void {
  if (resolve(input.target.path) !== resolve(input.authority.targetPath)) {
    throw Object.assign(new Error("Phase target does not match issued authority."), { code: "AUTHORITY_MISMATCH" });
  }
  if (resolve(input.artifactRoot) !== resolve(input.authority.artifactRoot)) {
    throw Object.assign(new Error("Phase artifact root does not match issued authority."), { code: "AUTHORITY_MISMATCH" });
  }
  if (input.capabilityProfile.allowDelegation) {
    throw Object.assign(new Error("P0 phase sessions cannot delegate authority."), { code: "POLICY_DENIED" });
  }
  if (
    !input.capabilityProfile.allowTargetMutation &&
    input.capabilityProfile.tools.some((tool) => tool === "bash" || tool === "edit" || tool === "write")
  ) {
    throw Object.assign(new Error("Read-only phase includes a mutating tool capability."), { code: "POLICY_DENIED" });
  }
}

function readSessionId(data: unknown): string {
  const sessionId = readOptionalString(data, "sessionId");
  if (!sessionId) throw new JsonlRpcError("Pi RPC state omitted its session identity.", "protocol");
  return sessionId;
}

function readOptionalString(data: unknown, key: string): string | null {
  if (!data || typeof data !== "object" || Array.isArray(data)) return null;
  const value = (data as Record<string, unknown>)[key];
  return typeof value === "string" && value.length > 0 ? value : null;
}

function activeAttempt(agent: RuntimeLogicalAgentRecord) {
  const attempt = agent.attempts.at(-1);
  if (!attempt || attempt.status !== "running") {
    throw new Error("Logical agent has no active attempt.");
  }
  return attempt;
}

function isMeaningfulActivity(type: string): boolean {
  return type === "agent_start" || type === "agent_end" || type === "agent_settled"
    || type === "tool_execution_start" || type === "tool_execution_end"
    || type === "auto_retry_start" || type === "auto_retry_end";
}

function summarizeActivity(event: RpcEvent): Record<string, unknown> {
  const summary: Record<string, unknown> = {};
  for (const key of ["toolName", "success", "sessionId", "attempt", "delayMs"]) {
    const value = event[key];
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      summary[key] = value;
    }
  }
  return summary;
}

function safeErrorMessage(error: unknown, credential?: string): string {
  const message = error instanceof Error ? error.message : String(error);
  return credential ? message.split(credential).join("[REDACTED]") : message;
}
