import type { ResolvedExecutionConfig } from "../config/execution-config.js";
import type {
  ResumeCanonicalRunInput,
  RetryCanonicalRunInput,
  RuntimeOwnership,
  StartCanonicalRunInput,
} from "../runtime/lifecycle.js";
import type {
  RuntimeEvent,
  RuntimeRunRecord,
  RuntimeRunStatus,
  RuntimeStateRepository,
} from "../runtime/state-repository.js";
import { CliExitError, type CliCommand } from "./args.js";
import type { CliCommandHandler, CliIo } from "./main.js";

export const CLI_EXIT_STATUS = Object.freeze({
  canceled: 130,
  completed: 0,
  configuration: 2,
  failed: 1,
  interrupted: 75,
} as const);

export interface CliLifecycle {
  cancel(runId: string, ownership: RuntimeOwnership): Promise<RuntimeRunRecord>;
  createAndClaim?(input: StartCanonicalRunInput): Promise<RuntimeRunRecord>;
  resumeAndClaim?(input: ResumeCanonicalRunInput): Promise<RuntimeRunRecord>;
  execute(run: RuntimeRunRecord, ownership: RuntimeOwnership): Promise<RuntimeRunRecord>;
  resume(input: ResumeCanonicalRunInput): Promise<RuntimeRunRecord>;
  retry(input: RetryCanonicalRunInput): Promise<RuntimeRunRecord>;
  start(input: StartCanonicalRunInput): Promise<RuntimeRunRecord>;
}

export interface CliRuntimeDependencies {
  config(command: Extract<CliCommand, { kind: "scan" }> | Extract<CliCommand, { kind: "run-resume" }>): Promise<ResolvedExecutionConfig>;
  foregroundRefreshMs?: number;
  io: CliIo;
  lifecycle: CliLifecycle;
  ownership(): RuntimeOwnership;
  repository: RuntimeStateRepository;
  tty?: boolean;
}

export class RuntimeEventCompatibilityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RuntimeEventCompatibilityError";
  }
}
export function createCliCommandHandler(dependencies: CliRuntimeDependencies): CliCommandHandler {
  return async (command) => {
    const tty = dependencies.tty ?? Boolean(process.stdout.isTTY);
    switch (command.kind) {
      case "scan": {
        const config = await resolveCliConfig(dependencies, command);
        const ownership = dependencies.ownership();
        const input = {
          ...ownership,
          config,
        };
        if (!dependencies.lifecycle.createAndClaim) {
          const run = await dependencies.lifecycle.start(input);
          renderRun(dependencies.io, run, [], tty);
          return exitStatusForRun(run.status);
        }
        const claimed = await dependencies.lifecycle.createAndClaim(input);
        const run = await executeForegroundRun(dependencies, claimed, ownership, tty);
        renderRun(dependencies.io, run, [], tty);
        return exitStatusForRun(run.status);
      }
      case "run-inspect": {
        if (!tty) {
          const run = await dependencies.repository.getRun(command.runId);
          renderRun(dependencies.io, run, [], false);
          return exitStatusForRun(run.status);
        }
        const update = await reconnectRuntimeEvents(dependencies.repository, command.runId);
        renderRun(dependencies.io, update.run, update.events, tty);
        return exitStatusForRun(update.run.status);
      }
      case "run-cancel": {
        const run = await dependencies.lifecycle.cancel(command.runId, dependencies.ownership());
        renderRun(dependencies.io, run, [], tty);
        return exitStatusForRun(run.status);
      }
      case "run-resume": {
        const config = await resolveCliConfig(dependencies, command);
        const ownership = dependencies.ownership();
        const input = { ...ownership, config, runId: command.runId };
        if (!dependencies.lifecycle.resumeAndClaim) {
          const run = await dependencies.lifecycle.resume(input);
          renderRun(dependencies.io, run, [], tty);
          return exitStatusForRun(run.status);
        }
        const claimed = await dependencies.lifecycle.resumeAndClaim(input);
        const run = await executeForegroundRun(dependencies, claimed, ownership, tty);
        renderRun(dependencies.io, run, [], tty);
        return exitStatusForRun(run.status);
      }
      case "run-retry": {
        const ownership = dependencies.ownership();
        const claimed = await dependencies.lifecycle.retry({
          ...ownership,
          sourceRunId: command.runId,
        });
        const run = await executeForegroundRun(dependencies, claimed, ownership, tty);
        renderRun(dependencies.io, run, [], tty);
        return exitStatusForRun(run.status);
      }
    }
  };
}

async function resolveCliConfig(
  dependencies: CliRuntimeDependencies,
  command: Extract<CliCommand, { kind: "scan" }> | Extract<CliCommand, { kind: "run-resume" }>,
): Promise<ResolvedExecutionConfig> {
  try {
    return await dependencies.config(command);
  } catch (error) {
    throw new CliExitError(
      error instanceof Error ? error.message : String(error),
      CLI_EXIT_STATUS.configuration,
    );
  }
}

async function executeForegroundRun(
  dependencies: CliRuntimeDependencies,
  claimed: RuntimeRunRecord,
  ownership: RuntimeOwnership,
  tty: boolean,
): Promise<RuntimeRunRecord> {
  if (!tty) return await dependencies.lifecycle.execute(claimed, ownership);

  const events: RuntimeEvent[] = [];
  let afterSequence = 0;
  let finished = false;
  let renderedVersion = claimed.version;
  const renderUpdate = async (): Promise<boolean> => {
    try {
      const update = await reconnectRuntimeEvents(dependencies.repository, claimed.id, afterSequence);
      if (finished) return false;
      events.push(...update.events);
      afterSequence = events.at(-1)?.sequence ?? afterSequence;
      if (update.run.version !== renderedVersion || update.events.length > 0) {
        dependencies.io.output(renderTtyProgress(update.run, events));
        renderedVersion = update.run.version;
      }
      return true;
    } catch (error) {
      if (!finished) reportObservationError(dependencies.io, error);
      return false;
    }
  };

  renderRun(dependencies.io, claimed, [], true);
  const execution = dependencies.lifecycle.execute(claimed, ownership).then(
    (run) => ({ run }),
    (error: unknown) => ({ error }),
  );
  let refresh: Promise<boolean> | undefined = renderUpdate();
  let timer: NodeJS.Timeout | undefined;
  try {
    for (;;) {
      const outcome: boolean | Awaited<typeof execution> = await (refresh ? Promise.race([execution, refresh]) : execution);
      if (typeof outcome === "boolean") {
        refresh = outcome
          ? new Promise<void>((resolve) => {
            timer = setTimeout(resolve, dependencies.foregroundRefreshMs ?? 100);
          }).then(renderUpdate)
          : undefined;
        continue;
      }
      if ("error" in outcome) throw outcome.error;
      return outcome.run;
    }
  } finally {
    finished = true;
    clearTimeout(timer);
  }
}


export function exitStatusForRun(status: RuntimeRunStatus): number {
  switch (status) {
    case "completed": return CLI_EXIT_STATUS.completed;
    case "canceled": return CLI_EXIT_STATUS.canceled;
    case "interrupted": return CLI_EXIT_STATUS.interrupted;
    case "created":
    case "running": return CLI_EXIT_STATUS.interrupted;
    case "failed": return CLI_EXIT_STATUS.failed;
  }
}

export async function reconnectRuntimeEvents(
  repository: Pick<RuntimeStateRepository, "getRun" | "listEvents">,
  runId: string,
  afterSequence = 0,
): Promise<{ events: RuntimeEvent[]; run: RuntimeRunRecord }> {
  if (!Number.isSafeInteger(afterSequence) || afterSequence < 0) {
    throw new RuntimeEventCompatibilityError("Runtime event cursor must be a nonnegative safe integer.");
  }
  const events = await repository.listEvents(runId, afterSequence);
  let previous = afterSequence;
  for (const event of events) {
    if (event.schemaVersion !== 1) {
      throw new RuntimeEventCompatibilityError(
        `Runtime event ${event.sequence} uses unsupported schema version ${event.schemaVersion}.`,
      );
    }
    if (event.runId !== runId || event.sequence !== previous + 1) {
      throw new RuntimeEventCompatibilityError("Runtime events are not a canonical ordered continuation.");
    }
    previous = event.sequence;
  }
  return { events, run: await repository.getRun(runId) };
}

export function renderRun(io: CliIo, run: RuntimeRunRecord, events: readonly RuntimeEvent[], tty: boolean): void {
  if (!tty) {
    io.output(renderRunJson(run));
    return;
  }
  try {
    io.output(renderTtyProgress(run, events));
  } catch (error) {
    reportObservationError(io, error);
  }
}

function reportObservationError(io: CliIo, error: unknown): void {
  try {
    io.error(`Progress observation failed: ${error instanceof Error ? error.message : String(error)}`);
  } catch {
    // A disconnected observer must not change the durable run outcome.
  }
}

export function renderRunJson(run: RuntimeRunRecord): string {
  return JSON.stringify({
    completedAt: run.completedAt,
    createdAt: run.createdAt,
    id: run.id,
    parentRunId: run.parentRunId,
    phases: run.phases.map((phase) => ({
      id: phase.id,
      output: phase.output,
      state: phase.state,
      type: phase.type,
      updatedAt: phase.updatedAt,
    })),
    progress: run.progress,
    scanId: run.scanId,
    status: run.status,
    statusReason: run.statusReason,
    targetPath: run.targetPath,
    updatedAt: run.updatedAt,
  });
}

export function renderTtyProgress(run: RuntimeRunRecord, events: readonly RuntimeEvent[]): string {
  const completeStates = new Set(["completed", "reused", "failed", "canceled", "interrupted", "skipped"]);
  const completed = run.phases.filter((phase) => completeStates.has(phase.state)).length;
  const activeAgents = run.status === "running" ? activeLogicalAgents(events) : [];
  const findingCount = findFindingCount(run);
  const lines = [
    `Run ${run.id}: ${run.status}`,
    `Phases: ${completed}/${run.phases.length}`,
    `Active logical agents: ${activeAgents.length > 0 ? activeAgents.join(", ") : "none"}`,
    `Findings: ${findingCount ?? "unavailable"}`,
    ...run.phases.map((phase) => `  ${phase.id}: ${phase.state}`),
  ];
  if (run.statusReason) lines.push(`Outcome: ${run.statusReason}`);
  return lines.join("\n");
}
const ACTIVE_AGENT_EVENTS: Record<string, true> = {
  "agent.attempt_started": true,
  "agent.session_bound": true,
  "attempt.started": true,
  "attempt.running": true,
  "session.started": true,
};

const INACTIVE_AGENT_EVENTS: Record<string, true> = {
  "agent.attempt_canceled": true,
  "agent.attempt_completed": true,
  "agent.attempt_failed": true,
  "agent.process_exited": true,
  "attempt.completed": true,
  "attempt.failed": true,
  "attempt.canceled": true,
  "attempt.interrupted": true,
};

function activeLogicalAgents(events: readonly RuntimeEvent[]): string[] {
  const state = new Map<string, boolean>();
  for (const event of events) {
    if (!event.logicalAgentId) continue;
    if (Object.hasOwn(ACTIVE_AGENT_EVENTS, event.kind)) {
      state.set(event.logicalAgentId, true);
    } else if (Object.hasOwn(INACTIVE_AGENT_EVENTS, event.kind)) {
      state.set(event.logicalAgentId, false);
    }
  }
  return [...state].filter(([, active]) => active).map(([id]) => id).sort();
}

function findFindingCount(run: RuntimeRunRecord): number | undefined {
  const report = run.phases.find((phase) => phase.id === "reporting")?.output;
  if (!report || typeof report !== "object" || !("findings" in report)) return undefined;
  return Array.isArray(report.findings) ? report.findings.length : undefined;
}
