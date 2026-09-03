import { createHash, randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { createScanArtifactContext, type RunArtifactWorkbench } from "../artifact-context.js";
import { resolveCredential, type ResolvedExecutionConfig, type RoleExecutionConfig } from "../config/execution-config.js";
import {
  PhaseSessionSupervisor,
  classifyAttemptFailure,
  type AgentControlRequest,
  type PhaseRoleSettings,
} from "../rpc/phase-session.js";
import { assemblePhaseInputPackage } from "../workflow/builtin.js";
import {
  createArtifactWorkflowServices,
  createBuiltInPhaseExecutors,
  type ModelPhaseRunner,
} from "../workflow/adapters.js";
import type { PhaseExecutionContext, PhaseResultEnvelope } from "../workflow/scheduler.js";
import type { CliLifecycle } from "../cli/operations.js";
import { CanonicalRunLifecycle, type RuntimeOwnership } from "./lifecycle.js";
import {
  WorkbenchRuntimeStateRepository,
  createWorkbenchRuntimeExecutor,
  type RuntimeRunRecord,
  type RuntimeStateRepository,
  type WorkbenchExecutor,
} from "./state-repository.js";

export interface DefaultCanonicalRuntimeOptions {
  environment?: NodeJS.ProcessEnv;
  packageRoot: string;
  piCommand?: string;
  piCommandArgs?: string[];
  stateDir?: string;
}

export class DefaultCanonicalRuntimeGateway implements CliLifecycle {
  readonly #environment: NodeJS.ProcessEnv;
  readonly #packageRoot: string;
  readonly #piCommand: string | undefined;
  readonly #piCommandArgs: string[] | undefined;
  readonly #repository: RuntimeStateRepository;
  readonly #workbench: WorkbenchExecutor;
  readonly #active = new Map<string, CanonicalRunLifecycle>();

  constructor(options: DefaultCanonicalRuntimeOptions) {
    this.#environment = options.environment ?? process.env;
    this.#packageRoot = options.packageRoot;
    this.#piCommand = options.piCommand;
    this.#piCommandArgs = options.piCommandArgs;
    this.#workbench = createWorkbenchRuntimeExecutor({
      environment: this.#environment,
      packageRoot: this.#packageRoot,
      stateDir: options.stateDir,
    });
    this.#repository = new WorkbenchRuntimeStateRepository(this.#workbench);
  }

  get repository(): RuntimeStateRepository {
    return this.#repository;
  }

  async start(input: Parameters<CliLifecycle["start"]>[0]): Promise<RuntimeRunRecord> {
    const configuredScanRoot = this.#environment.PI_SECURITY_SCAN_ROOT?.trim();
    const scan = asRecord(await this.#workbench("start-headless-standard-scan", undefined, [
      "--thread-id", input.controllerId,
      "--target-path", input.config.scan.target,
      "--scope", ".",
      ...(configuredScanRoot ? ["--scan-root", resolve(configuredScanRoot)] : []),
    ]));
    const scanRecord = asRecord(scan.scan);
    const scanId = requiredString(scanRecord, "scanId");
    const handoffClaimToken = optionalString(scanRecord, "handoffClaimToken");
    const lifecycle = await this.#lifecycle(input.config, scanId, input, handoffClaimToken);
    const claimed = await lifecycle.createAndClaim({ ...input, scanId });
    this.#active.set(claimed.id, lifecycle);
    const cancel = () => { void lifecycle.cancel(claimed.id, input).catch(() => undefined); };
    const interrupt = () => {
      void lifecycle.interrupt(claimed.id, input, "Foreground executor received a termination signal.")
        .catch(() => undefined);
    };
    process.once("SIGINT", cancel);
    process.once("SIGHUP", interrupt);
    process.once("SIGTERM", interrupt);
    try {
      return await lifecycle.execute(claimed, input);
    } finally {
      process.removeListener("SIGINT", cancel);
      process.removeListener("SIGHUP", interrupt);
      process.removeListener("SIGTERM", interrupt);
      this.#active.delete(claimed.id);
    }
  }

  async execute(run: RuntimeRunRecord, ownership: RuntimeOwnership): Promise<RuntimeRunRecord> {
    const lifecycle = this.#active.get(run.id);
    if (!lifecycle) throw new Error("Canonical run has no executor in this foreground process.");
    return await lifecycle.execute(run, ownership);
  }

  async cancel(runId: string, ownership: RuntimeOwnership): Promise<RuntimeRunRecord> {
    const lifecycle = this.#active.get(runId);
    if (!lifecycle) throw new Error("Canonical run has no executor in this foreground process.");
    return await lifecycle.cancel(runId, ownership);
  }

  async resume(input: Parameters<CliLifecycle["resume"]>[0]): Promise<RuntimeRunRecord> {
    const run = await this.#repository.getRun(input.runId);
    if (!run.scanId) throw new Error("Canonical run has no artifact scan identity.");
    const config = snapshotConfig(run, input.config);
    const lifecycle = await this.#lifecycle(
      config,
      run.scanId,
      input,
      await this.#handoffClaimToken(run.scanId),
    );
    return await lifecycle.resume({ ...input, config });
  }

  async retry(input: Parameters<CliLifecycle["retry"]>[0]): Promise<RuntimeRunRecord> {
    const source = await this.#repository.getRun(input.sourceRunId);
    if (!source.scanId) throw new Error("Canonical run has no artifact scan identity.");
    const config = snapshotConfig(source);
    const lifecycle = await this.#lifecycle(
      config,
      source.scanId,
      input,
      await this.#handoffClaimToken(source.scanId),
    );
    const run = await lifecycle.retry(input);
    this.#active.set(run.id, lifecycle);
    return run;
  }

  async #lifecycle(
    config: ResolvedExecutionConfig,
    scanId: string,
    ownership: RuntimeOwnership,
    handoffClaimToken?: string,
  ): Promise<CanonicalRunLifecycle> {
    const runWorkbench: RunArtifactWorkbench = async (args) => asRecord(
      await this.#workbench(args[0], undefined, args.slice(1)),
    );
    const artifact = await createScanArtifactContext(scanId, runWorkbench, {
      handoffClaimToken,
      packageRoot: this.#packageRoot,
      requireClaim: Boolean(handoffClaimToken),
      requireRunning: true,
    });
    let supervisor: PhaseSessionSupervisor;

    const model = this.#modelRunner(config, scanId, artifact.root, ownership, () => supervisor);
    const services = createArtifactWorkflowServices({
      handoffClaimToken,
      packageRoot: this.#packageRoot,
      runWorkbench,
      scanId,
    });
    supervisor = new PhaseSessionSupervisor({
      command: this.#piCommand,
      commandArgs: this.#piCommandArgs,
      environment: this.#environment,
      repository: this.#repository,
    });
    return new CanonicalRunLifecycle({
      abortActiveAttempts: async (runId) => {
        for (const phase of (await this.#repository.getRun(runId)).phases) {
          const logicalAgentId = stableLogicalAgentId(runId, phase.id);
          const agent = await this.#repository.getAgent(runId, logicalAgentId).catch(() => undefined);
          if (!agent?.attempts.some((attempt) => attempt.status === "running")) continue;
          const current = await this.#repository.getRun(runId);
          await supervisor.control(controlRequest(current, logicalAgentId, ownership), { kind: "stop" })
            .catch(() => undefined);
        }
      },
      executors: createBuiltInPhaseExecutors(services, model),
      repository: this.#repository,
    });
  }
  async #handoffClaimToken(scanId: string): Promise<string | undefined> {
    const result = asRecord(await this.#workbench("get-scan", undefined, ["--scan-id", scanId]));
    return optionalString(asRecord(result.scan), "handoffClaimToken");
  }

  #modelRunner(
    config: ResolvedExecutionConfig,
    scanId: string,
    artifactRoot: string,
    ownership: RuntimeOwnership,
    getSupervisor: () => PhaseSessionSupervisor,
  ): ModelPhaseRunner {
    return async (context) => {
      const configured = config.roles[context.phase.roleId ?? "default"] ?? config.roles.default;
      const role = await phaseRole(configured);
      const logicalAgentId = stableLogicalAgentId(context.runId, context.phase.id);
      const input = assemblePhaseInputPackage({
        artifactRoot,
        evidenceReferences: [],
        outputs: upstreamOutputs(context),
        phase: context.phase,
        role,
        runId: context.runId,
        scanId,
        target: { path: config.scan.target, revision: null },
      });
      const previous = await this.#repository.getAgent(context.runId, logicalAgentId).catch(() => undefined);
      const baseOrdinal = previous?.attempts.length ?? 0;
      let lastError: unknown;
      for (let attempt = 1; attempt <= configured.maxAttempts; attempt += 1) {
        const ordinal = baseOrdinal + attempt;
        const run = await this.#repository.getRun(context.runId);
        const attemptId = randomUUID();
        try {
          await getSupervisor().launch({
            attemptId,
            claimToken: ownership.claimToken,
            controllerId: ownership.controllerId,
            expectedVersion: run.version,
            input,
            logicalAgentId,
            maxAttempts: baseOrdinal + configured.maxAttempts,
            ordinal,
            role,
          });
          const current = await this.#repository.getRun(context.runId);
          const completed = await getSupervisor().complete(
            controlRequest(current, logicalAgentId, ownership),
          );
          return parseTranscriptEnvelope(completed.transcript);
        } catch (error) {
          lastError = error;
          if (!classifyAttemptFailure(
            error,
            ordinal,
            baseOrdinal + configured.maxAttempts,
            context.signal.aborted,
          ).replace) throw error;
        }
      }
      throw lastError;
    };
  }
}


function controlRequest(run: RuntimeRunRecord, logicalAgentId: string, ownership: RuntimeOwnership): AgentControlRequest {
  return {
    ...ownership,
    expectedVersion: run.version,
    logicalAgentId,
    runId: run.id,
    targetPath: run.targetPath,
  };
}

async function phaseRole(config: RoleExecutionConfig): Promise<PhaseRoleSettings> {
  const credential = await resolveCredential(config.credential);
  return {
    ...(credential ? { credential: { environmentVariable: "PI_SECURITY_ROLE_CREDENTIAL", value: credential.value } } : {}),
    instructions: config.instructions ?? "Complete this phase and return only the required JSON result envelope.",
    model: config.model,
    provider: config.provider,
    thinking: config.thinking ?? "medium",
  };
}

function upstreamOutputs(context: PhaseExecutionContext): Record<string, unknown> {
  return Object.fromEntries(Object.entries(context.phase.bindings ?? {}).map(([name, binding]) => [
    binding.from,
    context.inputs[name],
  ]));
}

function parseTranscriptEnvelope(value: unknown): PhaseResultEnvelope {
  const transcript = asRecord(value);
  const messages = transcript.messages;
  if (!Array.isArray(messages)) throw new Error("Pi RPC transcript has no messages.");
  const assistant = [...messages].reverse().map(asRecord).find((message) => message.role === "assistant");
  const content = assistant && typeof assistant.content === "string" ? assistant.content.trim() : "";
  const fenced = content.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/u)?.[1] ?? content;
  return asRecord(JSON.parse(fenced)) as unknown as PhaseResultEnvelope;
}

function snapshotConfig(
  run: RuntimeRunRecord,
  supplied?: ResolvedExecutionConfig,
): ResolvedExecutionConfig {
  const resolved = asRecord(asRecord(run.snapshot).resolved);
  const roles = Object.fromEntries(Object.entries(asRecord(resolved.roles)).map(([id, value]) => {
    const { credential, ...role } = asRecord(value);
    const source = credential ? asRecord(credential) : undefined;
    const restored = source?.source === "env" && typeof source.env === "string"
      ? { env: source.env, kind: "env" as const }
      : source?.source === "profile" && typeof source.profile === "string"
        ? { kind: "profile" as const, profile: source.profile }
        : source?.source === "inline"
          ? supplied?.roles[id]?.credential?.kind === "inline"
            ? supplied.roles[id].credential
            : missingInlineCredential(id)
          : undefined;
    return [id, restored ? { ...role, credential: restored } : role];
  }));
  return {
    execution: asRecord(resolved.execution) as unknown as ResolvedExecutionConfig["execution"],
    provenance: asRecord(resolved.provenance) as unknown as ResolvedExecutionConfig["provenance"],
    roles: roles as unknown as ResolvedExecutionConfig["roles"],
    scan: asRecord(resolved.scan) as unknown as ResolvedExecutionConfig["scan"],
  };
}

function missingInlineCredential(roleId: string): never {
  throw new Error(`Inline credential is unavailable for role '${roleId}'; supply it through the execution config.`);
}

function asRecord(value: unknown): Record<string, any> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Expected an object response.");
  return value as Record<string, any>;
}

function requiredString(value: Record<string, unknown>, key: string): string {
  const field = value[key];
  if (typeof field !== "string" || !field) throw new Error(`Workbench response has no ${key}.`);
  return field;
}

function optionalString(value: Record<string, unknown>, key: string): string | undefined {
  return typeof value[key] === "string" && value[key] ? value[key] as string : undefined;
}

function stableLogicalAgentId(runId: string, phaseId: string): string {
  const hex = createHash("sha256").update(`${runId}\0${phaseId}`).digest("hex").slice(0, 32);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-8${hex.slice(17, 20)}-${hex.slice(20)}`;
}
