import { randomUUID } from "node:crypto";
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
  execute(run: RuntimeRunRecord, ownership: RuntimeOwnership): Promise<RuntimeRunRecord>;
  resume(input: ResumeCanonicalRunInput): Promise<RuntimeRunRecord>;
  retry(input: RetryCanonicalRunInput): Promise<RuntimeRunRecord>;
  start(input: StartCanonicalRunInput): Promise<RuntimeRunRecord>;
}

export interface CliRuntimeDependencies {
  config(command: Extract<CliCommand, { kind: "scan" }> | Extract<CliCommand, { kind: "run-resume" }>): Promise<ResolvedExecutionConfig>;
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
    switch (command.kind) {
      case "scan": {
        let config: ResolvedExecutionConfig;
        let run: RuntimeRunRecord;
        try {
          config = await dependencies.config(command);
          run = await dependencies.lifecycle.start({
            ...dependencies.ownership(),
            config,
            scanId: randomUUID(),
          });
        } catch (error) {
          throw new CliExitError(
            error instanceof Error ? error.message : String(error),
            CLI_EXIT_STATUS.configuration,
          );
        }
        renderRun(dependencies.io, run, [], dependencies.tty ?? Boolean(process.stdout.isTTY));
        return exitStatusForRun(run.status);
      }
      case "run-inspect": {
        const update = await reconnectRuntimeEvents(dependencies.repository, command.runId);
        renderRun(dependencies.io, update.run, update.events, dependencies.tty ?? Boolean(process.stdout.isTTY));
        return exitStatusForRun(update.run.status);
      }
      case "run-cancel": {
        const run = await dependencies.lifecycle.cancel(command.runId, dependencies.ownership());
        renderRun(dependencies.io, run, [], dependencies.tty ?? Boolean(process.stdout.isTTY));
        return exitStatusForRun(run.status);
      }
      case "run-resume": {
        const config = await dependencies.config(command);
        const run = await dependencies.lifecycle.resume({
          ...dependencies.ownership(),
          config,
          runId: command.runId,
        });
        renderRun(dependencies.io, run, [], dependencies.tty ?? Boolean(process.stdout.isTTY));
        return exitStatusForRun(run.status);
      }
      case "run-retry": {
        const ownership = dependencies.ownership();
        const claimed = await dependencies.lifecycle.retry({
          ...ownership,
          sourceRunId: command.runId,
        });
        const run = await dependencies.lifecycle.execute(claimed, ownership);
        renderRun(dependencies.io, run, [], dependencies.tty ?? Boolean(process.stdout.isTTY));
        return exitStatusForRun(run.status);
      }
    }
  };
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
  const [run, events] = await Promise.all([
    repository.getRun(runId),
    repository.listEvents(runId, afterSequence),
  ]);
  let previous = afterSequence;
  for (const event of events) {
    if (event.schemaVersion !== 1) {
      throw new RuntimeEventCompatibilityError(
        `Runtime event ${event.sequence} uses unsupported schema version ${event.schemaVersion}.`,
      );
    }
    if (event.runId !== runId || event.sequence <= previous) {
      throw new RuntimeEventCompatibilityError("Runtime events are not a canonical ordered continuation.");
    }
    previous = event.sequence;
  }
  return { events, run };
}

export function renderRun(io: CliIo, run: RuntimeRunRecord, events: readonly RuntimeEvent[], tty: boolean): void {
  io.output(tty ? renderTtyProgress(run, events) : renderRunJson(run));
}

export function renderRunJson(run: RuntimeRunRecord): string {
  return JSON.stringify({
    completedAt: run.completedAt,
    createdAt: run.createdAt,
    id: run.id,
    parentRunId: run.parentRunId,
    phases: run.phases.map((phase) => ({
      id: phase.id,
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
  const activeAgents = activeLogicalAgents(events);
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
function activeLogicalAgents(events: readonly RuntimeEvent[]): string[] {
  const state = new Map<string, boolean>();
  for (const event of events) {
    if (!event.logicalAgentId) continue;
    if (["agent.session_bound", "attempt.started", "attempt.running", "session.started"].includes(event.kind)) {
      state.set(event.logicalAgentId, true);
    } else if (
      ["agent.attempt_canceled", "agent.attempt_failed", "agent.process_exited", "attempt.completed",
        "attempt.failed", "attempt.canceled", "attempt.interrupted"].includes(event.kind)
    ) {
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
