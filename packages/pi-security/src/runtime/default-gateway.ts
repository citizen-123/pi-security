import { createHash, randomUUID } from "node:crypto";
import { realpath, stat } from "node:fs/promises";
import { resolve } from "node:path";
import { createScanArtifactContext, type RunArtifactWorkbench } from "../artifact-context.js";
import { redactKnownSecrets, resolveCredential, resolveExecutionConfig, type ResolvedExecutionConfig, type RoleExecutionConfig } from "../config/execution-config.js";
import {
  PhaseSessionSupervisor,
  classifyAttemptFailure,
  type AgentControlRequest,
  type PhaseRoleSettings,
} from "../rpc/phase-session.js";
import { JsonlRpcClient, JsonlRpcError } from "../rpc/jsonl-client.js";
import { assemblePhaseInputPackage, BUILT_IN_PHASE_REGISTRY, FULL_REPOSITORY_WORKFLOW } from "../workflow/builtin.js";
import {
  createArtifactWorkflowServices,
  createBuiltInPhaseExecutors,
  type ModelPhaseRunner,
} from "../workflow/adapters.js";
import { parsePhaseResultEnvelope, type PhaseExecutionContext, type PhaseResultEnvelope } from "../workflow/scheduler.js";
import type { CliLifecycle } from "../cli/operations.js";
import { CanonicalPreflightError, CanonicalRunLifecycle, type RuntimeOwnership } from "./lifecycle.js";
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
    this.#environment = { ...(options.environment ?? process.env) };
    for (const name of ["PI_HOME", "PI_SECURITY_STATE_DIR"]) {
      const value = this.#environment[name];
      if (value && !value.startsWith("~")) this.#environment[name] = resolve(value);
    }
    this.#packageRoot = options.packageRoot;
    this.#piCommand = options.piCommand;
    this.#piCommandArgs = options.piCommandArgs;
    this.#workbench = createWorkbenchRuntimeExecutor({
      environment: this.#environment,
      packageRoot: this.#packageRoot,
      stateDir: options.stateDir && !options.stateDir.startsWith("~") ? resolve(options.stateDir) : options.stateDir,
    });
    this.#repository = new WorkbenchRuntimeStateRepository(this.#workbench);
  }

  get repository(): RuntimeStateRepository {
    return this.#repository;
  }

  async start(input: Parameters<CliLifecycle["start"]>[0]): Promise<RuntimeRunRecord> {
    return await this.execute(await this.createAndClaim(input), input);
  }

  async createAndClaim(input: Parameters<CliLifecycle["start"]>[0]): Promise<RuntimeRunRecord> {
    let target: string;
    try {
      target = await realpath(input.config.scan.target);
      if (!(await stat(target)).isDirectory()) throw new Error("Canonical scan target must be a directory.");
    } catch (error) {
      throw new CanonicalPreflightError("Canonical scan target must be an existing directory.", { cause: error });
    }
    const config = await this.#resolveModelDefaults({
      ...input.config,
      scan: { ...input.config.scan, target },
    });
    const roles = await this.#resolveRoles(config);
    const { scanId, handoffClaimToken } = await this.#startScan(config, input);
    const lifecycle = await this.#lifecycle(config, scanId, input, handoffClaimToken, roles);
    const claimed = await lifecycle.createAndClaim({ ...input, config, scanId });
    this.#active.set(claimed.id, lifecycle);
    return claimed;
  }

  async execute(run: RuntimeRunRecord, ownership: RuntimeOwnership): Promise<RuntimeRunRecord> {
    const lifecycle = this.#active.get(run.id);
    if (!lifecycle) throw new Error("Canonical run has no executor in this foreground process.");
    return await this.#foreground(run.id, lifecycle, ownership, () => lifecycle.execute(run, ownership));
  }

  async cancel(runId: string, ownership: RuntimeOwnership): Promise<RuntimeRunRecord> {
    const lifecycle = this.#active.get(runId) ?? new CanonicalRunLifecycle({
      executors: {},
      repository: this.#repository,
    });
    return await lifecycle.cancel(runId, ownership);
  }

  async resume(input: Parameters<CliLifecycle["resume"]>[0]): Promise<RuntimeRunRecord> {
    return await this.execute(await this.resumeAndClaim(input), input);
  }

  async resumeAndClaim(input: Parameters<CliLifecycle["resume"]>[0]): Promise<RuntimeRunRecord> {
    const run = await this.#repository.getRun(input.runId);
    if (!run.scanId) throw new Error("Canonical run has no artifact scan identity.");
    const config = snapshotConfig(run, input.config);
    const roles = await this.#resolveRoles(config);
    const lifecycle = await this.#lifecycle(
      config,
      run.scanId,
      input,
      await this.#handoffClaimToken(run.scanId),
      roles,
    );
    const claimed = await lifecycle.resumeAndClaim({ ...input, config });
    this.#active.set(claimed.id, lifecycle);
    return claimed;
  }

  async retry(input: Parameters<CliLifecycle["retry"]>[0]): Promise<RuntimeRunRecord> {
    const source = await this.#repository.getRun(input.sourceRunId);
    if (source.status !== "failed") {
      throw new Error(`Canonical run in state ${source.status} cannot be retried.`);
    }
    const config = snapshotConfig(source, await resolveExecutionConfig({ env: this.#environment }));
    const roles = await this.#resolveRoles(config);
    const { scanId, handoffClaimToken } = await this.#startScan(config, input);
    const lifecycle = await this.#lifecycle(config, scanId, input, handoffClaimToken, roles);
    const run = await lifecycle.retry({ ...input, scanId });
    this.#active.set(run.id, lifecycle);
    return run;
  }

  async #startScan(config: ResolvedExecutionConfig, ownership: RuntimeOwnership): Promise<{
    handoffClaimToken?: string;
    scanId: string;
  }> {
    const configuredScanRoot = this.#environment.PI_SECURITY_SCAN_ROOT?.trim();
    const result = asRecord(await this.#workbench("start-headless-standard-scan", undefined, [
      "--thread-id", ownership.controllerId,
      "--target-path", config.scan.target,
      "--scope", ".",
      ...(configuredScanRoot ? ["--scan-root", resolve(configuredScanRoot)] : []),
    ]));
    const scan = asRecord(result.scan);
    return { scanId: requiredString(scan, "scanId"), handoffClaimToken: optionalString(scan, "handoffClaimToken") };
  }

  async #foreground(
    runId: string,
    lifecycle: CanonicalRunLifecycle,
    ownership: RuntimeOwnership,
    execute: () => Promise<RuntimeRunRecord>,
  ): Promise<RuntimeRunRecord> {
    this.#active.set(runId, lifecycle);
    let stopping: Promise<unknown> | undefined;
    const stop = (kind: "cancel" | "interrupt") => {
      stopping ??= (kind === "cancel"
        ? lifecycle.cancel(runId, ownership)
        : lifecycle.interrupt(runId, ownership, "Foreground executor received a termination signal."));
      void stopping.catch(() => undefined);
    };
    const cancel = () => stop("cancel");
    const interrupt = () => stop("interrupt");
    process.on("SIGINT", cancel);
    process.on("SIGHUP", interrupt);
    process.on("SIGTERM", interrupt);
    try {
      const run = await execute();
      await stopping;
      if (run.scanId && run.status === "failed") {
        const claim = await this.#handoffClaimToken(run.scanId);
        await this.#workbench("fail-scan", undefined, [
          "--scan-id", run.scanId,
          "--message", run.statusReason ?? "Canonical execution failed.",
          ...(claim ? ["--claim-token", claim] : []),
        ]);
      } else if (run.scanId && run.status === "canceled") {
        await this.#workbench("cancel-scan", undefined, ["--scan-id", run.scanId]);
      }
      return run;
    } finally {
      process.removeListener("SIGINT", cancel);
      process.removeListener("SIGHUP", interrupt);
      process.removeListener("SIGTERM", interrupt);
      this.#active.delete(runId);
    }
  }

  async #resolveModelDefaults(config: ResolvedExecutionConfig): Promise<ResolvedExecutionConfig> {
    const roles = { ...config.roles };
    const selections = new Map<string, { model: string; provider: string }>();
    for (const phase of FULL_REPOSITORY_WORKFLOW.phases) {
      if (!phase.roleId) continue;
      const id = roles[phase.roleId] ? phase.roleId : "default";
      const role = roles[id];
      if (role.provider && role.model) continue;
      const key = JSON.stringify([role.provider, role.model, role.credential]);
      let selected = selections.get(key);
      if (!selected) {
        const credential = await resolveCredential(role.credential, { env: this.#environment }).catch((error: unknown) => {
          throw new CanonicalPreflightError(error instanceof Error ? error.message : "Cannot resolve native model credentials.", { cause: error });
        });
        const environment = { ...this.#environment };
        const variable = role.provider && Object.hasOwn(PROVIDER_CREDENTIAL_ENV, role.provider)
          ? PROVIDER_CREDENTIAL_ENV[role.provider] : undefined;
        if (credential && variable) {
          environment[variable] = credential.value;
          if (variable === "ANTHROPIC_API_KEY") delete environment.ANTHROPIC_OAUTH_TOKEN;
        }
        const client = new JsonlRpcClient({
          command: this.#piCommand ?? "pi",
          args: [
            ...(this.#piCommandArgs ?? []),
            "--mode", "rpc",
            "--no-tools", "--no-extensions", "--no-approve", "--no-context-files",
            "--no-skills", "--no-prompt-templates", "--no-session",
            ...(role.provider ? ["--provider", role.provider] : []),
            ...(role.model ? ["--model", role.model] : []),
          ],
          cwd: config.scan.target,
          env: environment,
          redact: (text) => redactKnownSecrets(text, credential ? [credential.value] : []),
        });
        try {
          await client.start();
          const state = asRecord((await client.request({ type: "get_state" })).data);
          const model = asRecord(state.model);
          selected = { model: requiredString(model, "id"), provider: requiredString(model, "provider") };
          if (role.provider && selected.provider !== role.provider) {
            throw new Error("Pi selected a different provider than the configured role.");
          }
          selections.set(key, selected);
        } finally {
          await client.stop();
        }
      }
      roles[id] = { ...role, ...selected };
    }
    return { ...config, roles };
  }

  async #resolveRoles(config: ResolvedExecutionConfig): Promise<Record<string, PhaseRoleSettings>> {
    const roleIds = new Set(FULL_REPOSITORY_WORKFLOW.phases
      .filter((phase) => phase.roleId)
      .map((phase) => config.roles[phase.roleId!] ? phase.roleId! : "default"));
    return Object.fromEntries(await Promise.all([...roleIds].map(async (id) => [
      id, await phaseRole(config.roles[id], this.#environment),
    ])));
  }

  async #lifecycle(
    config: ResolvedExecutionConfig,
    scanId: string,
    ownership: RuntimeOwnership,
    handoffClaimToken: string | undefined,
    roles: Record<string, PhaseRoleSettings>,
  ): Promise<CanonicalRunLifecycle> {
    const runWorkbench: RunArtifactWorkbench = async (args) => asRecord(
      await this.#workbench(args[0], undefined, args.slice(1)),
    );
    const artifact = await createScanArtifactContext(scanId, runWorkbench, {
      handoffClaimToken,
      packageRoot: this.#packageRoot,
      requireClaim: Boolean(handoffClaimToken),
      requireRunning: false,
    });
    let supervisor: PhaseSessionSupervisor;

    const model = this.#modelRunner(config, scanId, artifact.root, ownership, () => supervisor, roles);
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
      abortActiveAttempts: (runId) => supervisor.abortRun(runId),
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
    roles: Record<string, PhaseRoleSettings>,
  ): ModelPhaseRunner {
    return async (context) => {
      const configured = config.roles[context.phase.roleId ?? "default"] ?? config.roles.default;
      const role = roles[context.phase.roleId ?? "default"] ?? roles.default;
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
        context.signal.throwIfAborted();
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
          let envelope!: PhaseResultEnvelope;
          await getSupervisor().complete(
            controlRequest(current, logicalAgentId, ownership),
            (transcript) => {
              envelope = parseTranscriptEnvelope(transcript, role.credential?.value);
              parsePhaseResultEnvelope(envelope, {
                outputSchema: BUILT_IN_PHASE_REGISTRY.get(context.phase.type, context.phase.version).outputSchema,
                phaseId: context.phase.id,
                runId: context.runId,
              });
            },
          );
          return envelope;
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

async function phaseRole(config: RoleExecutionConfig, environment: NodeJS.ProcessEnv): Promise<PhaseRoleSettings> {
  const environmentVariable = config.provider && Object.hasOwn(PROVIDER_CREDENTIAL_ENV, config.provider)
    ? PROVIDER_CREDENTIAL_ENV[config.provider] : undefined;
  const credential = await resolveCredential(config.credential, { env: environment }).catch((error: unknown) => {
    throw new CanonicalPreflightError(error instanceof Error ? error.message : "Cannot resolve phase credentials.", { cause: error });
  });
  if (credential && !environmentVariable) {
    throw new CanonicalPreflightError("An explicit role credential requires a provider with a supported API-key environment variable.");
  }
  return {
    ...(credential ? { credential: { environmentVariable: environmentVariable!, value: credential.value } } : {}),
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

function parseTranscriptEnvelope(value: unknown, credential?: string): PhaseResultEnvelope {
  const transcript = asRecord(value);
  const messages = transcript.messages;
  if (!Array.isArray(messages)) throw new Error("Pi RPC transcript has no messages.");
  const assistant = messages.findLast((message) => message && typeof message === "object" && message.role === "assistant");
  if (assistant?.stopReason === "error" || assistant?.stopReason === "aborted") {
    throw new JsonlRpcError(
      redactKnownSecrets(assistant.errorMessage || "Pi RPC assistant did not complete successfully.", credential ? [credential] : []),
      "request",
    );
  }
  const content = typeof assistant?.content === "string"
    ? assistant.content.trim()
    : Array.isArray(assistant?.content)
      ? assistant.content.filter((block: Record<string, unknown>) => block?.type === "text" && typeof block.text === "string")
        .map((block: { text: string }) => block.text).join("").trim()
      : "";
  const fenced = content.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/u)?.[1] ?? content;
  try {
    return asRecord(JSON.parse(fenced, (_key, entry: unknown) => {
      if (!credential) return entry;
      if (typeof entry === "string") return redactKnownSecrets(entry, [credential]);
      if (entry && typeof entry === "object" && !Array.isArray(entry)) {
        return Object.fromEntries(Object.entries(entry).map(([key, value]) => [
          redactKnownSecrets(key, [credential]), value,
        ]));
      }
      return entry;
    })) as unknown as PhaseResultEnvelope;
  } catch {
    throw Object.assign(new Error("Pi RPC assistant did not return a valid JSON result envelope."), { code: "CONTRACT_INCOMPATIBLE" });
  }
}

function snapshotConfig(
  run: RuntimeRunRecord,
  supplied?: ResolvedExecutionConfig,
): ResolvedExecutionConfig {
  const resolved = asRecord(asRecord(run.snapshot).resolved);
  const persistedRoles = asRecord(resolved.roles);
  const activeRoleIds = new Set(FULL_REPOSITORY_WORKFLOW.phases
    .filter((phase) => phase.roleId)
    .map((phase) => persistedRoles[phase.roleId!] ? phase.roleId! : "default"));
  const roles = Object.fromEntries(Object.entries(persistedRoles).map(([id, value]) => {
    const { credential, ...role } = asRecord(value);
    const source = credential ? asRecord(credential) : undefined;
    const restored = source?.source === "env" && typeof source.env === "string"
      ? { env: source.env, kind: "env" as const }
      : source?.source === "profile" && typeof source.profile === "string"
        ? { kind: "profile" as const, profile: source.profile }
        : source?.source === "inline"
          ? supplied?.roles[id]?.credential?.kind === "inline"
            ? supplied.roles[id].credential
            : activeRoleIds.has(id) ? missingInlineCredential(id) : undefined
          : undefined;
    return [id, restored ? { ...role, credential: restored } : role];
  }));
  for (const phase of FULL_REPOSITORY_WORKFLOW.phases) {
    if (!phase.roleId) continue;
    const role = roles[phase.roleId] ?? roles.default;
    if (typeof role.provider !== "string" || typeof role.model !== "string") {
      throw new CanonicalPreflightError("Canonical run has unpinned model defaults; start a new scan instead of changing its execution identity.");
    }
  }
  return {
    execution: asRecord(resolved.execution) as unknown as ResolvedExecutionConfig["execution"],
    ...(resolved.legacyDeepScan ? { legacyDeepScan: asRecord(resolved.legacyDeepScan) as ResolvedExecutionConfig["legacyDeepScan"] } : {}),
    provenance: asRecord(resolved.provenance) as unknown as ResolvedExecutionConfig["provenance"],
    roles: roles as unknown as ResolvedExecutionConfig["roles"],
    scan: asRecord(resolved.scan) as unknown as ResolvedExecutionConfig["scan"],
  };
}

function missingInlineCredential(roleId: string): never {
  throw new CanonicalPreflightError(`Inline credential is unavailable for role '${roleId}'; supply it through the execution config.`);
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

const PROVIDER_CREDENTIAL_ENV: Readonly<Record<string, string>> = Object.freeze({
  "ant-ling": "ANT_LING_API_KEY",
  anthropic: "ANTHROPIC_API_KEY",
  "azure-openai-responses": "AZURE_OPENAI_API_KEY",
  cerebras: "CEREBRAS_API_KEY",
  "cloudflare-ai-gateway": "CLOUDFLARE_API_KEY",
  "cloudflare-workers-ai": "CLOUDFLARE_API_KEY",
  deepseek: "DEEPSEEK_API_KEY",
  fireworks: "FIREWORKS_API_KEY",
  "github-copilot": "COPILOT_GITHUB_TOKEN",
  google: "GEMINI_API_KEY",
  "google-vertex": "GOOGLE_CLOUD_API_KEY",
  groq: "GROQ_API_KEY",
  huggingface: "HF_TOKEN",
  "kimi-coding": "KIMI_API_KEY",
  minimax: "MINIMAX_API_KEY",
  "minimax-cn": "MINIMAX_CN_API_KEY",
  mistral: "MISTRAL_API_KEY",
  moonshotai: "MOONSHOT_API_KEY",
  "moonshotai-cn": "MOONSHOT_API_KEY",
  nvidia: "NVIDIA_API_KEY",
  openai: "OPENAI_API_KEY",
  opencode: "OPENCODE_API_KEY",
  "opencode-go": "OPENCODE_API_KEY",
  openrouter: "OPENROUTER_API_KEY",
  "qwen-token-plan": "QWEN_TOKEN_PLAN_API_KEY",
  "qwen-token-plan-cn": "QWEN_TOKEN_PLAN_CN_API_KEY",
  radius: "RADIUS_API_KEY",
  together: "TOGETHER_API_KEY",
  "vercel-ai-gateway": "AI_GATEWAY_API_KEY",
  xai: "XAI_API_KEY",
  xiaomi: "XIAOMI_API_KEY",
  "xiaomi-token-plan-ams": "XIAOMI_TOKEN_PLAN_AMS_API_KEY",
  "xiaomi-token-plan-cn": "XIAOMI_TOKEN_PLAN_CN_API_KEY",
  "xiaomi-token-plan-sgp": "XIAOMI_TOKEN_PLAN_SGP_API_KEY",
  zai: "ZAI_API_KEY",
  "zai-coding-cn": "ZAI_CODING_CN_API_KEY",
});
