// The security.scan orchestrator task, Standard path (design D3, D6):
//
//   preflight    bind the target (D14), publish TargetDoc and ScanContextDoc, fix startedAt
//   inventory    list the in-scope files
//   threatModel  start the threat-model worker
//   plan         admit the threat model (failure fails the scan), plan packets, start one discovery worker each
//   reduce       normalize discovery results into candidates; start the reducer, or skip to report with none
//   validate     check the reduction (one retry, then the scan fails); start one validator per finding
//   attackPath   admit validations; start one analyst per reportable finding
//   report       admit attack paths; assemble the draft documents deterministically
//   publish      refuse a target that changed since preflight, then finalize and seal the scan directory
//
// Every phase reruns after a crash, so each is idempotent: worker tasks are created in the commit that records their
// IDs, and everything a later phase needs is in the checkpoint. Task 4.2 replaces the all-at-once fan-out with lanes.
import type { Context } from "@earendil-works/chord";
import { defineDoc, defineTask, type Harness, type TaskId, type TaskOutcome, type TaskRuntime, type Tx } from "@earendil-works/pi-durable";
import { type Candidate, CandidateError, type CombinedCandidate, combineCandidates, normalizeCandidate, readScope } from "../contract/candidates.js";
import type { JsonObject } from "../contract/contract-error.js";
import { prepareScanFinalization, writePreparedScanFinalization } from "../contract/finalize.js";
import {
  attackPathPacket,
  discoveryPacket,
  reductionPacket,
  threatModelPacket,
  validationPacket
} from "../scan/instructions.js";
import {
  assembleStandardDraft,
  checkReduction,
  findingKey,
  type Outcome,
  type Plan,
  planPackets,
  recordFor,
  type Reduction,
  StandardScanError,
  type ThreatSurface
} from "../scan/standard.js";
import { bindTarget, type TargetBinding } from "../target/binding.js";
import { generateInventory, resolveRepository, resolveScope } from "../target/inventory.js";
import type { ScanRoleId } from "./roles.js";
import { ensurePrivateDirectory } from "./run-directory.js";
import { ScanContextDoc, TargetDoc } from "./scan-documents.js";
import type { WorkerInput, WorkerResult, WorkerRole, WorkerTask } from "./worker.js";

export type ScanInput = {
  readonly scanId: string;
  /** The canonical target directory. */
  readonly target: string;
  /** The inventory scope within the target, "." for all of it. */
  readonly scope: string;
  /** Where the sealed scan is written. */
  readonly scanDir: string;
  readonly producer: { readonly name: string; readonly version: string };
  readonly roles: Readonly<Record<ScanRoleId, WorkerRole>>;
};

export type ScanResult = { readonly scanDir: string; readonly findings: number; readonly completeness: string };

type Waiting = Record<string, number>;
/** What the phases accumulate; each phase adds what later phases need. */
type ScanData = {
  startedAt?: string;
  binding?: TargetBinding;
  files?: string[];
  threatModel?: string;
  plan?: Plan;
  discovery?: Record<string, Outcome<string[]>>;
  candidates?: CombinedCandidate[];
  reduction?: Reduction;
  reducerAttempt?: number;
  validations?: Record<string, Outcome<JsonObject>>;
  attackPaths?: Record<string, Outcome<JsonObject>>;
  drafts?: [JsonObject, JsonObject, JsonObject];
};
type Phase = "preflight" | "inventory" | "threatModel" | "plan" | "reduce" | "validate" | "attackPath" | "report" | "publish";
export type ScanState = { [P in Phase]: { readonly phase: P; readonly data: ScanData; readonly waiting?: Waiting } }[Phase];

/** The run's orchestrator, recorded in the commit that creates it so starting a run is idempotent (D3). */
export const RunDoc = defineDoc<{ scanTaskId?: number }>({
  kind: "security.run",
  version: 1,
  scope: "session",
  initial: () => ({}),
  checkpointWhen: () => false
});

const timestamp = (milliseconds: number) => new Date(milliseconds).toISOString().replace(/\.\d{3}Z$/, "Z");
const message = (error: unknown) => (error instanceof Error ? error.message : String(error));
const outcomeError = (outcome: TaskOutcome<WorkerResult>) =>
  outcome.status === "failed" ? outcome.error.message : outcome.status === "completed" ? "completed" : `worker ${outcome.status}`;

export type ScanTaskOptions = {
  readonly worker: WorkerTask;
  /** The package schemas directory, for finalization. */
  readonly schemaDir: string;
};

type Runtime = TaskRuntime<ScanInput, ScanState, ScanResult, object>;

export function createScanTask({ worker, schemaDir }: ScanTaskOptions) {
  /** Create one worker per entry in the commit that records them; skip to `next` when there are none. */
  async function fanOut(tx: Tx, owner: TaskId, roles: ScanInput["roles"], role: ScanRoleId, packets: [string, string][], next: Phase, data: ScanData) {
    if (packets.length === 0) return { status: "running" as const, checkpoint: { phase: next, data } };
    const waiting: Waiting = {};
    for (const [key, packet] of packets) {
      const input: WorkerInput = { role: roles[role], packet };
      waiting[key] = (await tx.createTask(worker, input, { ownership: { kind: "task", taskId: owner } })) as unknown as number;
    }
    return { status: "waiting" as const, checkpoint: { phase: next, data, waiting }, on: Object.values(waiting) as unknown as TaskId[], policy: "allSettled" as const };
  }

  /** The settled worker outcomes of the phase's wait, by key. */
  async function settled(runtime: Runtime, waiting: Waiting | undefined, context: Context): Promise<Map<string, TaskOutcome<WorkerResult>>> {
    const entries = Object.entries(waiting ?? {});
    if (entries.length === 0) return new Map();
    const outcomes = await runtime.outcomes(entries.map(([, id]) => id as unknown as TaskId<WorkerResult>), context);
    return new Map(entries.map(([key], index) => [key, outcomes[index]!]));
  }

  const fail = (runtime: Runtime, error: string, context: Context) =>
    runtime.commit(() => ({ status: "terminal", outcome: { status: "failed", error: { message: error } } }), context);

  return defineTask<ScanInput, ScanState, ScanResult>({
    name: "security.scan",
    version: 1,
    initial: () => ({ phase: "preflight", data: {} }),
    phases: {
      preflight: async (task, runtime, context) => {
        const { scanId, target, scope } = task.input;
        let binding: TargetBinding;
        try {
          binding = bindTarget(target);
        } catch (error) {
          return fail(runtime, `cannot bind the scan target: ${message(error)}`, context);
        }
        await runtime.commit(async (tx) => {
          Object.assign(await tx.doc(TargetDoc), binding);
          Object.assign(await tx.doc(ScanContextDoc), { scanId, mode: scope === "." ? "repository" : "scoped_path", scope });
          return { status: "running", checkpoint: { phase: "inventory", data: { startedAt: timestamp(runtime.now()), binding } } };
        }, context);
      },
      inventory: async (task, runtime, context) => {
        let files: string[];
        try {
          const repository = resolveRepository(task.input.target);
          const { rows } = generateInventory({ repository, scope: resolveScope(repository, task.input.scope) });
          // Rows are "./<path>\n"; packets and coverage use plain target-relative paths.
          files = rows.map((row) => row.toString("utf8").replace(/\n$/, "").replace(/^\.\//, ""));
        } catch (error) {
          return fail(runtime, `cannot inventory the scan target: ${message(error)}`, context);
        }
        const data = { ...task.state.checkpoint.data, files };
        await runtime.commit(() => ({ status: "running", checkpoint: { phase: "threatModel", data } }), context);
      },
      threatModel: async (task, runtime, context) => {
        const { data } = task.state.checkpoint;
        await runtime.commit(
          (tx) => fanOut(tx, task.id, task.input.roles, "threat_modeler", [["threat_model", threatModelPacket(task.input.scope, data.files!.length)]], "plan", data),
          context
        );
      },
      plan: async (task, runtime, context) => {
        const { data, waiting } = task.state.checkpoint;
        const outcome = (await settled(runtime, waiting, context)).get("threat_model")!;
        if (outcome.status !== "completed") return fail(runtime, `threat model failed: ${outcomeError(outcome)}`, context);
        const payload = outcome.result.payload as { content: string; surfaces: ThreatSurface[] };
        let plan: Plan;
        try {
          plan = planPackets(data.files!, payload.surfaces);
        } catch (error) {
          return fail(runtime, `threat model failed: ${message(error)}`, context);
        }
        const next = { ...data, threatModel: payload.content, plan };
        await runtime.commit(async (tx) => {
          Object.assign(await tx.doc(ScanContextDoc), { threatModel: payload.content });
          return fanOut(tx, task.id, task.input.roles, "discoverer", plan.packets.map((item) => [item.id, discoveryPacket(item)]), "reduce", next);
        }, context);
      },
      reduce: async (task, runtime, context) => {
        const { data, waiting } = task.state.checkpoint;
        const outcomes = await settled(runtime, waiting, context);
        const repository = resolveRepository(task.input.target);
        const inScope = readScope(Buffer.from(data.files!.map((file) => `./${file}\n`).join("")), repository);
        const lineCounts = new Map<string, number>();
        const discovery: Record<string, Outcome<string[]>> = {};
        const rows: Candidate[] = [];
        for (const item of data.plan!.packets) {
          const outcome = outcomes.get(item.id)!;
          if (outcome.status !== "completed") {
            discovery[item.id] = { ok: false, error: outcomeError(outcome) };
            continue;
          }
          try {
            const normalized = (outcome.result.payload.candidates as JsonObject[]).map((row) => normalizeCandidate(row, repository, inScope, lineCounts));
            discovery[item.id] = { ok: true, value: [...new Set(normalized.map((row) => combineCandidates([row])[0]!.candidate_id))] };
            rows.push(...normalized);
          } catch (error) {
            if (!(error instanceof CandidateError)) throw error;
            discovery[item.id] = { ok: false, error: `candidate rejected: ${error.message}` };
          }
        }
        const candidates = combineCandidates(rows);
        const next: ScanData = { ...data, discovery, candidates, reducerAttempt: 1 };
        await runtime.commit(
          (tx) => fanOut(tx, task.id, task.input.roles, "reducer", candidates.length === 0 ? [] : [["reduce", reductionPacket(candidates)]], candidates.length === 0 ? "report" : "validate", next),
          context
        );
      },
      validate: async (task, runtime, context) => {
        const { data, waiting } = task.state.checkpoint;
        const outcome = (await settled(runtime, waiting, context)).get("reduce")!;
        let reduction: Reduction | undefined;
        let error = outcomeError(outcome);
        if (outcome.status === "completed") {
          try {
            checkReduction(data.candidates!.map((candidate) => candidate.candidate_id), outcome.result.payload as unknown as Reduction);
            reduction = outcome.result.payload as unknown as Reduction;
          } catch (caught) {
            if (!(caught instanceof StandardScanError)) throw caught;
            error = caught.message;
          }
        }
        if (reduction === undefined) {
          if (data.reducerAttempt! >= 2) return fail(runtime, `reduction failed twice: ${error}`, context);
          const retry = { ...data, reducerAttempt: data.reducerAttempt! + 1 };
          await runtime.commit((tx) => fanOut(tx, task.id, task.input.roles, "reducer", [["reduce", reductionPacket(data.candidates!)]], "validate", retry), context);
          return;
        }
        const byId = new Map(data.candidates!.map((candidate) => [candidate.candidate_id, candidate]));
        const packets = reduction.findings.map((finding): [string, string] => [
          findingKey(finding),
          validationPacket(finding, finding.candidateIds.map((id) => byId.get(id)!))
        ]);
        const next = { ...data, reduction };
        await runtime.commit((tx) => fanOut(tx, task.id, task.input.roles, "validator", packets, "attackPath", next), context);
      },
      attackPath: async (task, runtime, context) => {
        const { data, waiting } = task.state.checkpoint;
        const validations = admit(await settled(runtime, waiting, context), "validations", "validation");
        const packets: [string, string][] = [];
        for (const finding of data.reduction?.findings ?? []) {
          const validation = validations[findingKey(finding)];
          if (validation?.ok && validation.value.disposition === "reportable") packets.push([findingKey(finding), attackPathPacket(finding, validation.value)]);
        }
        const next = { ...data, validations };
        await runtime.commit((tx) => fanOut(tx, task.id, task.input.roles, "attack_path_analyst", packets, "report", next), context);
      },
      report: async (task, runtime, context) => {
        const { data, waiting } = task.state.checkpoint;
        const attackPaths = admit(await settled(runtime, waiting, context), "attackPaths", "attackPath");
        const drafts = assembleStandardDraft({
          scanId: task.input.scanId,
          producer: { ...task.input.producer },
          startedAt: data.startedAt!,
          completedAt: timestamp(runtime.now()),
          target: { ...data.binding! },
          scope: task.input.scope,
          threatModel: data.threatModel!,
          plan: data.plan!,
          discovery: new Map(Object.entries(data.discovery!)),
          candidates: data.candidates!,
          ...(data.reduction === undefined ? {} : { reduction: data.reduction }),
          validations: new Map(Object.entries(data.validations ?? {})),
          attackPaths: new Map(Object.entries(attackPaths))
        });
        await runtime.commit(() => ({ status: "running", checkpoint: { phase: "publish", data: { ...data, attackPaths, drafts } } }), context);
      },
      publish: async (task, runtime, context) => {
        const { data } = task.state.checkpoint;
        let current: TargetBinding;
        try {
          current = bindTarget(task.input.target);
        } catch (error) {
          return fail(runtime, `cannot re-bind the scan target: ${message(error)}`, context);
        }
        if (JSON.stringify(current) !== JSON.stringify(data.binding)) return fail(runtime, "the scan target changed while it was being scanned", context);
        ensurePrivateDirectory(task.input.scanDir);
        const prepared = prepareScanFinalization(task.input.scanDir, { schemaDir, draftDocuments: data.drafts!, env: {} });
        const { findings, coverage } = writePreparedScanFinalization(prepared, { warn: (warning) => runtime.report(new Error(warning)) });
        const result: ScanResult = {
          scanDir: task.input.scanDir,
          findings: (findings.findings as unknown[]).length,
          completeness: coverage.completeness as string
        };
        await runtime.commit(() => ({ status: "terminal", outcome: { status: "completed", result } }), context);
      }
    },
    abort: (_task, runtime, context) => runtime.commit(() => ({ status: "terminal", outcome: { status: "aborted" } }), context)
  });
}

/** Per finding key, the one record its worker reported for that key, or why there is none. */
function admit(outcomes: Map<string, TaskOutcome<WorkerResult>>, list: string, field: "validation" | "attackPath"): Record<string, Outcome<JsonObject>> {
  const admitted: Record<string, Outcome<JsonObject>> = {};
  for (const [key, outcome] of outcomes) {
    if (outcome.status !== "completed") {
      admitted[key] = { ok: false, error: outcomeError(outcome) };
      continue;
    }
    try {
      admitted[key] = { ok: true, value: recordFor(outcome.result.payload[list] as JsonObject[], field, key) };
    } catch (error) {
      if (!(error instanceof StandardScanError)) throw error;
      admitted[key] = { ok: false, error: error.message };
    }
  }
  return admitted;
}

export type ScanTask = ReturnType<typeof createScanTask>;

/** Start the run's scan, or return the one already started: the creation and its record commit together. */
export async function startScan(harness: Harness, scan: ScanTask, input: ScanInput, context: Context): Promise<TaskId<ScanResult>> {
  const root = await harness.root(context);
  const id = await root.commit(async (tx) => {
    const run = await tx.doc(RunDoc);
    if (run.scanTaskId !== undefined) return run.scanTaskId;
    const created = await tx.createTask(scan, input, { ownership: { kind: "conversation" } });
    run.scanTaskId = created as unknown as number;
    return run.scanTaskId;
  }, context);
  return id as unknown as TaskId<ScanResult>;
}
