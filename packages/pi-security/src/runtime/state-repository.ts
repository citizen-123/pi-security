import { execFile } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { missingPythonHelperMessage, resolvePythonCommand } from "../python_command.js";

export type RuntimeRunStatus = "created" | "running" | "interrupted" | "completed" | "failed" | "canceled";
export type RuntimePhaseState = "pending" | "ready" | "running" | "completed" | "failed" | "interrupted" | "canceled" | "skipped" | "reused";

export interface RuntimeEvent {
  attemptId: string | null;
  category: "domain" | "activity";
  correlationId: string | null;
  kind: string;
  logicalAgentId: string | null;
  payload: Record<string, unknown>;
  phaseId: string | null;
  runId: string;
  schemaVersion: number;
  sequence: number;
  source: string;
  timestamp: string;
}

export interface RuntimePhaseRecord {
  dependencies: string[];
  id: string;
  inputDigest: string | null;
  output: unknown;
  outputDigest: string | null;
  phaseVersion: number;
  reusedFromPhaseId: string | null;
  reusedFromRunId: string | null;
  roleId: string | null;
  state: RuntimePhaseState;
  type: string;
  updatedAt: string;
  version: number;
}

export interface RuntimeRunRecord {
  completedAt: string | null;
  controllerId: string | null;
  createdAt: string;
  id: string;
  outputAdmissionFrozen: boolean;
  parentRunId: string | null;
  phases: RuntimePhaseRecord[];
  policyDigest: string;
  progress: Record<string, unknown>;
  scanId: string | null;
  snapshot: Record<string, unknown>;
  snapshotDigest: string;
  status: RuntimeRunStatus;
  statusReason: string | null;
  targetPath: string;
  targetRevision: string | null;
  updatedAt: string;
  version: number;
  workflow: Record<string, unknown>;
}

export interface CreateRuntimeRunInput {
  parentRunId?: string;
  policyDigest: string;
  runId: string;
  scanId?: string;
  snapshot: Record<string, unknown>;
  snapshotDigest: string;
  targetPath: string;
  targetRevision?: string;
  workflow: Record<string, unknown>;
}

export interface OwnedRuntimeOperation {
  claimToken: string;
  controllerId: string;
  expectedVersion: number;
  runId: string;
}

export interface RuntimeStateRepository {
  claimRun(input: OwnedRuntimeOperation): Promise<RuntimeRunRecord>;
  createRun(input: CreateRuntimeRunInput): Promise<RuntimeRunRecord>;
  getRun(runId: string): Promise<RuntimeRunRecord>;
  listEvents(runId: string, afterSequence?: number): Promise<RuntimeEvent[]>;
  recordEvent(input: OwnedRuntimeOperation & { event: RuntimeEventInput }): Promise<{ runId: string; sequence: number; version: number }>;
  reuseOutput(input: ReuseRuntimeOutputInput): Promise<RuntimeRunRecord>;
  transition(input: TransitionRuntimeInput): Promise<RuntimeRunRecord>;
}

export interface RuntimeEventInput {
  attemptId?: string;
  category: "domain" | "activity";
  correlationId?: string;
  kind: string;
  logicalAgentId?: string;
  payload?: Record<string, unknown>;
  phaseId?: string;
  source: string;
}

export interface TransitionRuntimeInput extends OwnedRuntimeOperation {
  event: RuntimeEventInput;
  phase?: {
    expectedVersion: number;
    id: string;
    inputDigest?: string;
    output?: unknown;
    outputDigest?: string;
    state: RuntimePhaseState;
  };
  progress?: Record<string, unknown>;
  status?: RuntimeRunStatus;
  statusReason?: string;
}

export interface ReuseRuntimeOutputInput extends OwnedRuntimeOperation {
  phaseId: string;
  sourceOutputDigest: string;
  sourcePhaseId: string;
  sourceRunId: string;
  validation: Record<string, unknown>;
}

export type WorkbenchExecutor = (command: string, payload?: Record<string, unknown>, args?: readonly string[]) => Promise<unknown>;

const phaseSchema = z.object({
  dependencies: z.array(z.string()),
  id: z.string(),
  inputDigest: z.string().nullable(),
  output: z.unknown(),
  outputDigest: z.string().nullable(),
  phaseVersion: z.number().int().positive(),
  reusedFromPhaseId: z.string().nullable(),
  reusedFromRunId: z.string().nullable(),
  roleId: z.string().nullable(),
  state: z.enum(["pending", "ready", "running", "completed", "failed", "interrupted", "canceled", "skipped", "reused"]),
  type: z.string(),
  updatedAt: z.string(),
  version: z.number().int().positive(),
}).strict();
const runSchema = z.object({
  completedAt: z.string().nullable(),
  controllerId: z.string().nullable(),
  createdAt: z.string(),
  id: z.string().uuid(),
  outputAdmissionFrozen: z.boolean(),
  parentRunId: z.string().uuid().nullable(),
  phases: z.array(phaseSchema),
  policyDigest: z.string(),
  progress: z.record(z.string(), z.unknown()),
  scanId: z.string().uuid().nullable(),
  snapshot: z.record(z.string(), z.unknown()),
  snapshotDigest: z.string(),
  status: z.enum(["created", "running", "interrupted", "completed", "failed", "canceled"]),
  statusReason: z.string().nullable(),
  targetPath: z.string(),
  targetRevision: z.string().nullable(),
  updatedAt: z.string(),
  version: z.number().int().positive(),
  workflow: z.record(z.string(), z.unknown()),
}).strict();
const eventSchema = z.object({
  attemptId: z.string().nullable(),
  category: z.enum(["domain", "activity"]),
  correlationId: z.string().nullable(),
  kind: z.string(),
  logicalAgentId: z.string().nullable(),
  payload: z.record(z.string(), z.unknown()),
  phaseId: z.string().nullable(),
  runId: z.string().uuid(),
  schemaVersion: z.number().int().positive(),
  sequence: z.number().int().positive(),
  source: z.string(),
  timestamp: z.string(),
}).strict();

export class WorkbenchRuntimeStateRepository implements RuntimeStateRepository {
  constructor(private readonly execute: WorkbenchExecutor) {}

  async createRun(input: CreateRuntimeRunInput): Promise<RuntimeRunRecord> {
    return parseRun(await this.execute("runtime-create-run", input as unknown as Record<string, unknown>));
  }

  async claimRun(input: OwnedRuntimeOperation): Promise<RuntimeRunRecord> {
    return parseRun(await this.execute("runtime-claim-run", input as unknown as Record<string, unknown>));
  }

  async transition(input: TransitionRuntimeInput): Promise<RuntimeRunRecord> {
    return parseRun(await this.execute("runtime-transition", input as unknown as Record<string, unknown>));
  }

  async recordEvent(input: OwnedRuntimeOperation & { event: RuntimeEventInput }): Promise<{ runId: string; sequence: number; version: number }> {
    const schema = z.object({ runId: z.string().uuid(), sequence: z.number().int().positive(), version: z.number().int().positive() }).strict();
    return schema.parse(await this.execute("runtime-record-event", input as unknown as Record<string, unknown>));
  }

  async reuseOutput(input: ReuseRuntimeOutputInput): Promise<RuntimeRunRecord> {
    return parseRun(await this.execute("runtime-reuse-output", input as unknown as Record<string, unknown>));
  }

  async getRun(runId: string): Promise<RuntimeRunRecord> {
    return parseRun(await this.execute("runtime-get-run", undefined, ["--run-id", runId]));
  }

  async listEvents(runId: string, afterSequence = 0): Promise<RuntimeEvent[]> {
    const result = z.object({ events: z.array(eventSchema), runId: z.string().uuid() }).strict().parse(
      await this.execute("runtime-list-events", undefined, ["--run-id", runId, "--after-sequence", String(afterSequence)]),
    );
    return result.events;
  }
}

export class RuntimeStateRepositoryError extends Error {
  constructor(message: string, readonly command: string) {
    super(message);
    this.name = "RuntimeStateRepositoryError";
  }
}

export function createWorkbenchRuntimeExecutor(options: {
  environment?: NodeJS.ProcessEnv;
  packageRoot?: string;
  stateDir?: string;
} = {}): WorkbenchExecutor {
  const packageRoot = options.packageRoot
    ?? resolve(dirname(fileURLToPath(import.meta.url)), "../..");
  const workbenchPath = join(packageRoot, "scripts", "workbench_db.py");
  const execFileAsync = promisify(execFile);
  return async (command, payload, args = []) => {
    const pythonCommand = await resolvePythonCommand({ environment: options.environment });
    const environment = { ...(options.environment ?? process.env) };
    if (options.stateDir) environment.PI_SECURITY_STATE_DIR = options.stateDir;
    const execution = execFileAsync(pythonCommand, [workbenchPath, command, ...args], {
      cwd: packageRoot,
      encoding: "utf8" as const,
      env: environment,
      maxBuffer: 4 * 1024 * 1024,
      timeout: 30_000,
    });
    if (payload !== undefined) {
      execution.child.stdin?.on("error", () => undefined);
      execution.child.stdin?.end(JSON.stringify(payload));
    }
    try {
      const { stdout } = await execution;
      return JSON.parse(stdout) as unknown;
    } catch (error) {
      const missing = missingPythonHelperMessage(error, pythonCommand);
      const stderr = error && typeof error === "object" && "stderr" in error && typeof error.stderr === "string"
        ? error.stderr.trim()
        : "";
      throw new RuntimeStateRepositoryError(missing ?? stderr ?? (error instanceof Error ? error.message : String(error)), command);
    }
  };
}

function parseRun(value: unknown): RuntimeRunRecord {
  try {
    return runSchema.parse(value);
  } catch (error) {
    throw new RuntimeStateRepositoryError(
      `Workbench returned an invalid workflow run: ${error instanceof Error ? error.message : String(error)}`,
      "parse-run",
    );
  }
}
