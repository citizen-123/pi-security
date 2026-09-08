import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type {
  RuntimeLogicalAgentRecord,
  RuntimeStateRepository,
} from "../runtime/state-repository.js";
import { JsonlRpcClient, JsonlRpcError, type RpcEvent } from "./jsonl-client.js";

export interface PhaseCapabilityProfile {
  allowDelegation: boolean;
  allowTargetMutation: boolean;
  tools: readonly string[];
}

export interface PhaseInputPackage {
  artifactRoot: string;
  authority: {
    artifactRoot: string;
    targetPath: string;
  };
  capabilityProfile: PhaseCapabilityProfile;
  evidenceReferences: string[];
  outputContract: Record<string, unknown>;
  phaseId: string;
  requiredInputs: Record<string, unknown>;
  roleId: string;
  runId: string;
  role: {
    instructions: string;
    model?: string;
    provider?: string;
    thinking: PhaseRoleSettings["thinking"];
  };
  scanId: string;
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
  model?: string;
  provider?: string;
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
  cleanupTimeoutMs?: number;
  environment?: NodeJS.ProcessEnv;
  requestTimeoutMs?: number;
  repository: RuntimeStateRepository;
}

interface RunSessionState {
  activity: Promise<void>;
  authorityGeneration: number;
  version: number;
}

interface StartingSession {
  canceled: boolean;
  client?: JsonlRpcClient;
  cleanupError?: unknown;
  finished: Promise<void>;
  logicalAgentId: string;
  runId: string;
}

interface BoundSession {
  acceptActivity: boolean;
  attemptId: string;
  authority: PhaseInputPackage["authority"];
  activity: Promise<void>;
  claimToken: string;
  client: JsonlRpcClient;
  controllerId: string;
  logicalAgentId: string;
  phaseId: string;
  runId: string;
  runState: RunSessionState;
}

export interface AttemptFailureDecision {
  category: "transport" | "provider" | "policy" | "authority" | "contract" | "canceled" | "unknown";
  replace: boolean;
}

export class PhaseSessionSupervisor {
  readonly #options: PhaseSessionSupervisorOptions;
  readonly #sessions = new Map<string, BoundSession>();
  readonly #runStates = new Map<string, RunSessionState>();
  readonly #launches = new Map<string, StartingSession>();
  readonly #canceledRuns = new Set<string>();
  readonly #runAborts = new Map<string, Promise<void>>();

  constructor(options: PhaseSessionSupervisorOptions) {
    this.#options = options;
  }

  async launch(request: LaunchPhaseSessionInput): Promise<{ piSessionId: string; version: number }> {
    if (this.#canceledRuns.has(request.input.runId)) {
      throw Object.assign(new Error("Workflow run was canceled before launch."), { code: "CANCELED" });
    }
    if (this.#sessions.has(request.logicalAgentId) || this.#launches.has(request.logicalAgentId)) {
      throw new Error("Logical agent already has an active RPC session.");
    }
    let finish!: () => void;
    const launch: StartingSession = {
      canceled: false,
      finished: new Promise<void>((resolve) => { finish = resolve; }),
      logicalAgentId: request.logicalAgentId,
      runId: request.input.runId,
    };
    this.#launches.set(request.logicalAgentId, launch);
    try {
      return await this.#launchSession(request, launch);
    } finally {
      this.#launches.delete(request.logicalAgentId);
      finish();
    }
  }

  async abortRun(runId: string): Promise<void> {
    let aborting = this.#runAborts.get(runId);
    if (!aborting) {
      aborting = this.#abortRun(runId);
      this.#runAborts.set(runId, aborting);
    }
    await aborting;
  }

  async #abortRun(runId: string): Promise<void> {
    this.#canceledRuns.add(runId);
    const launches = [...this.#launches.values()].filter((launch) => launch.runId === runId);
    const bindings = [...this.#sessions.values()].filter((binding) => binding.runId === runId);
    const launchingAgents = new Set(launches.map((launch) => launch.logicalAgentId));
    const clients = new Set<JsonlRpcClient>();
    for (const launch of launches) {
      launch.canceled = true;
      if (launch.client) clients.add(launch.client);
    }
    for (const binding of bindings) {
      binding.acceptActivity = false;
      this.#sessions.delete(binding.logicalAgentId);
      clients.add(binding.client);
    }
    const stopped = await Promise.allSettled([...clients].map((client) => client.stop()));
    await Promise.all(launches.map((launch) => launch.finished));
    const settled = await Promise.allSettled(bindings.filter((binding) => !launchingAgents.has(binding.logicalAgentId)).map((binding) => (
      this.#queueRun(binding, async () => {
        const run = await this.#options.repository.getRun(binding.runId);
        if (run.status !== "running" || run.outputAdmissionFrozen) return;
        const agent = await this.#options.repository.getAgent(binding.runId, binding.logicalAgentId);
        if (agent.attempts.find((attempt) => attempt.id === binding.attemptId)?.status === "canceled") return;
        const canceled = await this.#options.repository.updateAttempt({
          attemptId: binding.attemptId,
          claimToken: binding.claimToken,
          controllerId: binding.controllerId,
          details: { canceledWithRun: true },
          event: {
            attemptId: binding.attemptId,
            category: "domain",
            kind: "agent.attempt_canceled",
            logicalAgentId: binding.logicalAgentId,
            phaseId: binding.phaseId,
            source: "runtime",
          },
          expectedVersion: run.version,
          runId: binding.runId,
          status: "canceled",
        }).catch(async (error: unknown) => {
          const current = await this.#options.repository.getRun(binding.runId);
          if (!current.outputAdmissionFrozen) throw error;
          return undefined;
        });
        if (canceled) this.#advanceRunState(binding.runState, canceled.version, true);
      })
    )));
    const errors = [...stopped, ...settled].flatMap((result) => result.status === "rejected" ? [result.reason] : []);
    for (const launch of launches) {
      if (launch.cleanupError !== undefined) errors.push(launch.cleanupError);
    }
    if (errors.length > 0) throw new AggregateError(errors, "Unable to finish canceling all phase sessions.");
  }

  async #launchSession(request: LaunchPhaseSessionInput, launch: StartingSession): Promise<{ piSessionId: string; version: number }> {
    validatePhaseInput(request.input, request.role);
    const ownedRun = await this.#options.repository.getRun(request.input.runId);
    this.#throwIfCanceled(launch);
    if (
      ownedRun.targetPath !== resolve(request.input.target.path)
      || (this.#options.cwd !== undefined && resolve(this.#options.cwd) !== ownedRun.targetPath)
    ) {
      throw Object.assign(new Error("Phase target does not match the persisted run target."), {
        code: "AUTHORITY_MISMATCH",
      });
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
    const runState = this.#runStateFor(request.input.runId, started.version);
    const credential = request.role.credential?.value;
    const client = new JsonlRpcClient({
      command: this.#options.command ?? "pi",
      args: buildPiArguments(this.#options.commandArgs ?? [], request),
      cleanupTimeoutMs: this.#options.cleanupTimeoutMs,
      cwd: this.#options.cwd ?? request.input.target.path,
      env: {
        ...buildEnvironment(
          this.#options.environment ?? process.env,
          request.role.credential,
        ),
        PI_SECURITY_RPC_AUTHORITY: JSON.stringify({
          artifactRoot: resolve(request.input.authority.artifactRoot),
          runId: request.input.runId,
          targetPath: resolve(request.input.authority.targetPath),
          tools: request.input.capabilityProfile.tools,
        }),
      },
      redact: (text) => credential ? text.split(credential).join("[REDACTED]") : text,
      requestTimeoutMs: this.#options.requestTimeoutMs,
    });
    const binding: BoundSession = {
      acceptActivity: true,
      attemptId: request.attemptId,
      authority: {
        artifactRoot: resolve(request.input.authority.artifactRoot),
        targetPath: resolve(request.input.authority.targetPath),
      },
      activity: Promise.resolve(),
      claimToken: request.claimToken,
      client,
      controllerId: request.controllerId,
      logicalAgentId: request.logicalAgentId,
      phaseId: request.input.phaseId,
      runId: request.input.runId,
      runState,
    };
    launch.client = client;
    try {
      this.#throwIfCanceled(launch);
      await client.start();
      const commands = await client.request({ type: "get_commands" });
      const installed = commands.data && typeof commands.data === "object" && "commands" in commands.data
        ? commands.data.commands : undefined;
      if (!Array.isArray(installed) || !installed.some((command) => (
        command && typeof command === "object" && command.name === "pi-security-policy-ready"
      ))) {
        throw Object.assign(new Error("The phase RPC tool policy did not load."), { code: "CONTRACT_INCOMPATIBLE" });
      }
      const state = await client.request({ type: "get_state" });
      const piSessionId = readSessionId(state.data);
      await this.#queueRun(binding, async () => {
        const boundVersion = runState.version;
        const sessionBound = await this.#options.repository.updateAttempt({
          attemptId: request.attemptId,
          claimToken: request.claimToken,
          controllerId: request.controllerId,
          details: {
            capabilityProfile: request.input.capabilityProfile,
            roleId: request.input.roleId,
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
          expectedVersion: boundVersion,
          piSessionId,
          runId: request.input.runId,
          status: "running",
        });
        this.#advanceRunState(runState, sessionBound.version, true);
      });
      this.#throwIfCanceled(launch);
      this.#sessions.set(request.logicalAgentId, binding);
      client.onEvent((event) => {
        if (!isMeaningfulActivity(event.type)) return;
        void this.#queueRun(binding, () => this.#recordActivity(binding, event)).catch(() => undefined);
      });
      void this.#monitorExit(binding).catch(() => undefined);
      await client.request({
        type: "prompt",
        message: `${request.role.instructions}\n\nPhase input:\n${JSON.stringify(request.input)}`,
      });
      const activity = runState.activity;
      await activity;
      this.#throwIfCanceled(launch);
      return { piSessionId, version: runState.version };
    } catch (error) {
      binding.acceptActivity = false;
      this.#sessions.delete(request.logicalAgentId);
      await client.stop().catch((error: unknown) => { launch.cleanupError = error; });
      const decision = classifyAttemptFailure(error, request.ordinal, request.maxAttempts, launch.canceled);
      await this.#queueRun(binding, async () => {
        const run = await this.#options.repository.getRun(request.input.runId).catch(() => undefined);
        if (!run || run.status !== "running" || run.outputAdmissionFrozen) return;
        const failed = await this.#options.repository.updateAttempt({
          attemptId: request.attemptId,
          claimToken: request.claimToken,
          controllerId: request.controllerId,
          details: { message: safeErrorMessage(error, credential) },
          event: {
            attemptId: request.attemptId,
            category: "domain",
            kind: launch.canceled ? "agent.attempt_canceled" : "agent.attempt_failed",
            logicalAgentId: request.logicalAgentId,
            payload: { category: decision.category, replace: decision.replace },
            phaseId: request.input.phaseId,
            source: "runtime",
          },
          expectedVersion: run.version,
          failureCategory: decision.category,
          runId: request.input.runId,
          status: launch.canceled ? "canceled" : "failed",
        }).catch(async (error: unknown) => {
          if (launch.canceled) {
            const current = await this.#options.repository.getRun(request.input.runId);
            if (!current.outputAdmissionFrozen) launch.cleanupError = error;
          }
          return undefined;
        });
        if (failed) this.#advanceRunState(runState, failed.version, true);
      });
      this.#throwIfCanceled(launch);
      throw error;
    }
  }

  async control(request: AgentControlRequest, control: AgentControl): Promise<unknown> {
    const binding = this.#sessions.get(request.logicalAgentId);
    if (!binding) throw new Error("Logical agent has no bound RPC session.");
    const authorityGeneration = binding.runState.authorityGeneration;
    const expectedVersion = request.expectedVersion;
    if (binding.runState.version > expectedVersion) {
      throw new Error("Agent control authority does not match the active run.");
    }
    const prepared = await this.#queueRun(binding, async () => {
      if (binding.runState.authorityGeneration !== authorityGeneration) {
        throw new Error("Agent control authority does not match the active run.");
      }
      const authorizedVersion = Math.max(binding.runState.version, expectedVersion);
      const authorized = await this.#authorize(request, authorizedVersion);
      if (
        this.#sessions.get(request.logicalAgentId) !== binding
        || binding.runState.authorityGeneration !== authorityGeneration
      ) {
        throw new Error("Agent control authority does not match the active run.");
      }
      const mutation = await this.#options.repository.recordEvent({
        claimToken: request.claimToken,
        controllerId: request.controllerId,
        event: {
          attemptId: authorized.attemptId,
          category: "activity",
          kind: `operator.${control.kind}`,
          logicalAgentId: authorized.logicalAgentId,
          payload: control.kind === "steer" || control.kind === "follow-up" ? { supplied: true } : {},
          phaseId: authorized.phaseId,
          source: "operator",
        },
        expectedVersion: authorizedVersion,
        runId: request.runId,
      });
      this.#advanceRunState(authorized.runState, mutation.version, true);
      if (control.kind === "stop") {
        authorized.acceptActivity = false;
      }
      return { authorized, version: mutation.version };
    });
    const { authorized } = prepared;
    if (control.kind === "status") {
      return {
        runtimeVersion: prepared.version,
        state: (await authorized.client.request({ type: "get_state" })).data,
      };
    }
    if (control.kind === "transcript") {
      return {
        runtimeVersion: prepared.version,
        transcript: (await authorized.client.request({ type: "get_messages" })).data,
      };
    }
    if (control.kind === "steer") {
      return (await authorized.client.request({ type: "steer", message: control.message })).data;
    }
    if (control.kind === "follow-up") {
      return (await authorized.client.request({ type: "follow_up", message: control.message })).data;
    }
    if (control.kind === "interrupt") {
      await authorized.client.request({ type: "abort" });
      const activity = authorized.runState.activity;
      await activity;
      return { version: authorized.runState.version };
    }
    await authorized.client.request({ type: "abort" }).catch(() => undefined);
    await authorized.client.stop();
    return await this.#queueRun(authorized, async () => {
      const run = await this.#options.repository.getRun(authorized.runId);
      const agent = await this.#options.repository.getAgent(authorized.runId, authorized.logicalAgentId);
      if (agent.attempts.find((attempt) => attempt.id === authorized.attemptId)?.status === "canceled") {
        this.#sessions.delete(authorized.logicalAgentId);
        return { version: run.version };
      }
      const settled = await this.#options.repository.updateAttempt({
        attemptId: authorized.attemptId,
        claimToken: authorized.claimToken,
        controllerId: authorized.controllerId,
        details: { stoppedByOperator: true },
        event: {
          attemptId: authorized.attemptId,
          category: "domain",
          kind: "agent.attempt_canceled",
          logicalAgentId: authorized.logicalAgentId,
          phaseId: authorized.phaseId,
          source: "runtime",
        },
        expectedVersion: run.version,
        runId: authorized.runId,
        status: "canceled",
      });
      this.#advanceRunState(authorized.runState, settled.version, true);
      this.#sessions.delete(authorized.logicalAgentId);
      return { version: settled.version };
    });
  }

  #throwIfCanceled(launch: StartingSession): void {
    if (launch.canceled) throw Object.assign(new Error("Phase launch was canceled."), { code: "CANCELED" });
  }

  #queueRun<T>(binding: BoundSession, operation: () => Promise<T>): Promise<T> {
    // This barrier is shared by every session in a run, so later activity cannot starve an abort.
    const queued = binding.runState.activity.then(operation);
    const settled = queued.then(() => undefined, () => undefined);
    binding.runState.activity = settled;
    binding.activity = settled;
    return queued;
  }

  #runStateFor(runId: string, version: number): RunSessionState {
    const existing = this.#runStates.get(runId);
    if (existing) {
      this.#advanceRunState(existing, version, true);
      return existing;
    }
    const state: RunSessionState = {
      activity: Promise.resolve(),
      authorityGeneration: 0,
      version,
    };
    this.#runStates.set(runId, state);
    return state;
  }

  #advanceRunState(state: RunSessionState, version: number, authorityMutation: boolean): void {
    if (version <= state.version) return;
    state.version = version;
    if (authorityMutation) state.authorityGeneration += 1;
  }

  async #authorize(request: AgentControlRequest, expectedVersion: number): Promise<BoundSession> {
    const binding = this.#sessions.get(request.logicalAgentId);
    if (!binding || !binding.acceptActivity) throw new Error("Logical agent has no bound RPC session.");
    const run = await this.#options.repository.getRun(request.runId);
    if (
      run.controllerId !== request.controllerId ||
      run.targetPath !== resolve(request.targetPath) ||
      run.status !== "running" ||
      run.version !== expectedVersion
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

  async #drainActivity(binding: BoundSession): Promise<void> {
    for (;;) {
      const activity = binding.activity;
      await activity;
      if (activity === binding.activity) return;
    }
  }

  async #recordActivity(binding: BoundSession, event: RpcEvent): Promise<void> {
    if (!binding.acceptActivity || !isMeaningfulActivity(event.type)) return;
    const run = await this.#options.repository.getRun(binding.runId);
    if (
      run.status !== "running"
      || run.outputAdmissionFrozen
    ) {
      return;
    }
    this.#advanceRunState(binding.runState, run.version, true);
    const mutation = await this.#options.repository.recordEvent({
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
    if (mutation) this.#advanceRunState(binding.runState, mutation.version, false);
  }

  async #monitorExit(binding: BoundSession): Promise<void> {
    await binding.client.waitForExit();
    await this.#drainActivity(binding);
    if (this.#sessions.get(binding.logicalAgentId) !== binding || !binding.acceptActivity) return;
    binding.acceptActivity = false;
    this.#sessions.delete(binding.logicalAgentId);
    await this.#queueRun(binding, async () => {
      const run = await this.#options.repository.getRun(binding.runId).catch(() => undefined);
      if (!run || run.status !== "running" || run.outputAdmissionFrozen) return;
      const interrupted = await this.#options.repository.updateAttempt({
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
      if (interrupted) this.#advanceRunState(binding.runState, interrupted.version, true);
    });
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
  return [
    ...base,
    "--mode", "rpc",
    "--no-extensions",
    "--no-approve",
    "--no-context-files",
    "--no-skills",
    "--no-prompt-templates",
    "--no-tools",
    "--extension", fileURLToPath(new URL("./pi-security-rpc-policy.mjs", import.meta.url)),
    ...(request.role.provider ? ["--provider", request.role.provider] : []),
    ...(request.role.model ? ["--model", request.role.model] : []),
    "--thinking", request.role.thinking,
    "--name", `${request.input.runId}:${request.input.phaseId}:${request.ordinal}`,
    "--no-session",
  ];
}

function buildEnvironment(
  environment: NodeJS.ProcessEnv,
  credential?: PhaseCredential,
): NodeJS.ProcessEnv {
  const result = { ...environment };
  // Native Pi prefers this token over ANTHROPIC_API_KEY; an explicit role key must win.
  if (credential?.environmentVariable === "ANTHROPIC_API_KEY") delete result.ANTHROPIC_OAUTH_TOKEN;
  if (credential) result[credential.environmentVariable] = credential.value;
  return result;
}

function validatePhaseInput(input: PhaseInputPackage, role: PhaseRoleSettings): void {
  if (resolve(input.target.path) !== resolve(input.authority.targetPath)) {
    throw Object.assign(new Error("Phase target does not match issued authority."), { code: "AUTHORITY_MISMATCH" });
  }
  if (resolve(input.artifactRoot) !== resolve(input.authority.artifactRoot)) {
    throw Object.assign(new Error("Phase artifact root does not match issued authority."), { code: "AUTHORITY_MISMATCH" });
  }
  if (
    input.role.instructions !== role.instructions ||
    input.role.model !== role.model ||
    input.role.provider !== role.provider ||
    input.role.thinking !== role.thinking
  ) {
    throw Object.assign(new Error("Phase role settings do not match the issued input package."), { code: "AUTHORITY_MISMATCH" });
  }
  if (input.capabilityProfile.allowDelegation) {
    throw Object.assign(new Error("P0 phase sessions cannot delegate authority."), { code: "POLICY_DENIED" });
  }
  if (input.capabilityProfile.tools.some((tool) => !["read", "grep", "find", "ls"].includes(tool))) {
    throw Object.assign(new Error("P0 phase sessions support only bound read/search tools."), { code: "POLICY_DENIED" });
  }
}

function readSessionId(data: unknown): string {
  const sessionId = readOptionalString(data, "sessionId");
  if (!sessionId) {
    throw Object.assign(new Error("Pi RPC state omitted its session identity."), { code: "CONTRACT_INCOMPATIBLE" });
  }
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
