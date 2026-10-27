// Spike: a security.scan orchestrator with security.worker children on pi-durable 1.4.0.
// Throwaway code for openspec/changes/durable-runtime tasks 0.1, 0.3, and 0.5.
import { BACKGROUND_CONTEXT } from "@earendil-works/chord/context";
import { Type } from "@earendil-works/pi-ai";
import { createModels } from "@earendil-works/pi-ai/models";
import {
	type FauxResponseStep,
	fauxAssistantMessage,
	fauxProvider,
	fauxText,
	fauxToolCall,
} from "@earendil-works/pi-ai/providers/faux";
import {
	configure,
	type ConversationId,
	createRegistry,
	defineDoc,
	defineExtension,
	defineTask,
	defineTool,
	Harness,
	type TaskId,
} from "@earendil-works/pi-durable";
import { openNodeSqliteStorage } from "@earendil-works/pi-durable/storage/sqlite/node";

export const context = BACKGROUND_CONTEXT;

// ─── Scripted model ─────────────────────────────────────────────────────────
// Packets look like "PACKET p07 latency=120 [hang] [stream=N]". The model answers a packet by calling
// report_candidates with 1-3 candidates derived from the packet ID, and answers the tool result with "done".

export function hash(text: string): number {
	let h = 2166136261;
	for (const ch of text) h = Math.imul(h ^ ch.charCodeAt(0), 16777619) >>> 0;
	return h;
}

export function candidatesFor(packet: string) {
	const count = (hash(packet) % 3) + 1;
	return Array.from({ length: count }, (_, i) => ({ id: `${packet}-c${i}`, title: `Candidate ${i} in ${packet}` }));
}

function lastText(request: Parameters<Extract<FauxResponseStep, Function>>[0]) {
	const last = request.messages.findLast((message) => message.role !== "system")!;
	const content = typeof last.content === "string" ? [{ type: "text" as const, text: last.content }] : last.content;
	const text = content.flatMap((part) => (part.type === "text" ? [part.text] : [])).join("");
	return { role: last.role, text, isError: last.role === "toolResult" && last.isError === true };
}

export const stats = { modelCalls: 0, reportCalls: 0 };

const route: FauxResponseStep = async (request, options) => {
	stats.modelCalls++;
	const { role, text, isError } = lastText(request);
	if (role === "toolResult" && !isError) return fauxAssistantMessage([fauxText("done")]);
	// The packet is in the first user message of the worker conversation.
	const first = request.messages.find((message) => message.role === "user")!;
	const packetText = typeof first.content === "string" ? first.content : first.content.map((p) => ("text" in p ? p.text : "")).join("");
	const packet = /PACKET (\S+)/.exec(packetText)![1]!;
	const latency = Number(/latency=(\d+)/.exec(packetText)?.[1] ?? "0");
	if (/\bhang\b/.test(packetText)) {
		// Never answers until aborted.
		await new Promise<void>((resolve) => options?.signal?.addEventListener("abort", () => resolve(), { once: true }));
		throw new Error("aborted");
	}
	const stream = Number(/stream=(\d+)/.exec(packetText)?.[1] ?? "0");
	if (latency > 0) await new Promise((resolve) => setTimeout(resolve, latency));
	if (stream > 0) {
		// A long streamed preamble before the tool call: exercises pi.live progress for the stall monitor.
		return fauxAssistantMessage([fauxText("x".repeat(stream)), fauxToolCall("report_candidates", { packet, candidates: candidatesFor(packet) })], {
			stopReason: "toolUse",
		});
	}
	return fauxAssistantMessage([fauxToolCall("report_candidates", { packet, candidates: candidatesFor(packet) })], {
		stopReason: "toolUse",
	});
};

export function createFauxModels(tokensPerSecond?: number) {
	const models = createModels();
	const faux = fauxProvider(tokensPerSecond === undefined ? {} : { tokensPerSecond });
	models.setProvider(faux.provider);
	faux.setResponses(Array.from({ length: 100_000 }, () => route));
	return models;
}

export const MODEL = { provider: "faux", modelId: "faux-1" };

// ─── State ──────────────────────────────────────────────────────────────────

type Candidate = { id: string; title: string };

/** Session-scoped results: outlive the worker tasks that wrote them. */
export const Results = defineDoc<{ byPacket: Record<string, { conversationId: number; candidates: Candidate[]; writes: number }> }>({
	kind: "spike.results",
	version: 1,
	scope: "session",
	initial: () => ({ byPacket: {} }),
	checkpointWhen: () => false,
});

/** Audit: every worker conversation creation, committed with the creation itself. */
export const Audit = defineDoc<{ conversations: { packet: string; taskId: number; conversationId: number }[] }>({
	kind: "spike.audit",
	version: 1,
	scope: "session",
	initial: () => ({ conversations: [] }),
	checkpointWhen: () => false,
});

/** The run's orchestrator ID, set in the same commit that creates it, so run creation is idempotent. */
export const RunDoc = defineDoc<{ scanId?: number }>({
	kind: "spike.run",
	version: 1,
	scope: "session",
	initial: () => ({}),
	checkpointWhen: () => false,
});

// ─── Tools ──────────────────────────────────────────────────────────────────

const reportCandidates = defineTool({
	name: "report_candidates",
	description: "Report the security candidates found for this packet. Call once.",
	parameters: Type.Object({
		packet: Type.String(),
		candidates: Type.Array(Type.Object({ id: Type.String(), title: Type.String() })),
	}),
	// Idempotent: overwrites the packet's entry, so a rerun after a crash is harmless.
	replay: "safe",
	execute: async (args, api, toolContext) => {
		stats.reportCalls++;
		await api.commit(async (tx) => {
			const results = await tx.doc(Results);
			const previous = results.byPacket[args.packet];
			results.byPacket[args.packet] = {
				conversationId: api.conversationId as number,
				candidates: args.candidates,
				writes: (previous?.writes ?? 0) + 1,
			};
		}, toolContext);
		return { output: [{ type: "text", text: `Recorded ${args.candidates.length} candidates.` }], control: { terminate: true } };
	},
});

export const WorkerTools = defineExtension({ name: "spike-worker-tools", tools: [reportCandidates] });

// ─── Tasks ──────────────────────────────────────────────────────────────────

type WorkerInput = { packet: string; prompt: string };
type WorkerState = { phase: "open" } | { phase: "run"; conversationId: ConversationId };
type WorkerResult = { packet: string; candidates: number; startedAt: number; endedAt: number };

export const Worker = defineTask<WorkerInput, WorkerState, WorkerResult>({
	name: "security.worker",
	version: 1,
	initial: () => ({ phase: "open" }),
	phases: {
		open: async (task, runtime, taskContext) => {
			await runtime.commit(async (tx) => {
				const created = await tx.createConversation({ ownership: { kind: "task", taskId: task.id } });
				await configure(tx, created.id, {
					model: MODEL,
					extensions: [WorkerTools],
					tools: [reportCandidates],
					instructions: "You are a discovery worker. Report candidates with report_candidates.",
				});
				(await tx.doc(Audit)).conversations.push({ packet: task.input.packet, taskId: task.id as number, conversationId: created.id as number });
				return { status: "running", checkpoint: { phase: "run", conversationId: created.id } };
			}, taskContext);
		},
		run: async (task, runtime, taskContext) => {
			const startedAt = runtime.now();
			const conversation = (await runtime.conversation(task.state.checkpoint.conversationId, taskContext))!;
			const submission = await conversation.submit(
				{ type: "input", content: task.input.prompt, requestId: `worker:${task.id}` },
				taskContext,
			);
			const settled = await submission.wait(taskContext);
			const results = await runtime.snapshot(Results, taskContext);
			const entry = results?.byPacket[task.input.packet];
			await runtime.commit(
				() =>
					settled.status === "done" && entry !== undefined
						? {
								status: "terminal",
								outcome: {
									status: "completed",
									result: { packet: task.input.packet, candidates: entry.candidates.length, startedAt, endedAt: runtime.now() },
								},
							}
						: { status: "terminal", outcome: { status: "failed", error: { message: `no result (${settled.status})` } } },
				taskContext,
			);
		},
	},
	abort: (_task, runtime, taskContext) => runtime.commit(() => ({ status: "terminal", outcome: { status: "aborted" } }), taskContext),
});

type ScanInput = { packets: string[]; maxParallel: number };
type ScanState =
	| { phase: "wave"; next: number; done: WorkerResult[]; failed: string[] }
	| { phase: "collect"; next: number; wave: TaskId<WorkerResult>[]; done: WorkerResult[]; failed: string[] };
export type ScanResult = { done: WorkerResult[]; failed: string[]; waves: number };

export const Scan = defineTask<ScanInput, ScanState, ScanResult>({
	name: "security.scan",
	version: 1,
	initial: () => ({ phase: "wave", next: 0, done: [], failed: [] }),
	phases: {
		wave: async (task, runtime, taskContext) => {
			const { next, done, failed } = task.state.checkpoint;
			if (next >= task.input.packets.length) {
				const waves = Math.ceil(task.input.packets.length / task.input.maxParallel);
				await runtime.commit(() => ({ status: "terminal", outcome: { status: "completed", result: { done, failed, waves } } }), taskContext);
				return;
			}
			await runtime.commit(async (tx) => {
				const slice = task.input.packets.slice(next, next + task.input.maxParallel);
				const wave: TaskId<WorkerResult>[] = [];
				for (const prompt of slice) {
					const packet = /PACKET (\S+)/.exec(prompt)![1]!;
					wave.push(await tx.createTask(Worker, { packet, prompt }, { ownership: { kind: "task", taskId: task.id } }));
				}
				return {
					status: "waiting",
					checkpoint: { phase: "collect", next: next + slice.length, wave, done, failed },
					on: wave,
					policy: "allSettled",
				};
			}, taskContext);
		},
		collect: async (task, runtime, taskContext) => {
			const { next, wave, done, failed } = task.state.checkpoint;
			const outcomes = await runtime.outcomes(wave, taskContext);
			const records = await Promise.all(wave.map((id) => runtime.getTask(id, taskContext)));
			const nextDone = [...done];
			const nextFailed = [...failed];
			outcomes.forEach((outcome, i) => {
				if (outcome.status === "completed") nextDone.push(outcome.result);
				else nextFailed.push(`${(records[i]!.input as WorkerInput).packet}:${outcome.status}`);
			});
			await runtime.commit(() => ({ status: "running", checkpoint: { phase: "wave", next, done: nextDone, failed: nextFailed } }), taskContext);
		},
	},
	abort: (_task, runtime, taskContext) => runtime.commit(() => ({ status: "terminal", outcome: { status: "aborted" } }), taskContext),
});

// ─── Lanes: a sliding window from failFast/allSettled joins only ─────────────
// max_parallel lane tasks each claim the next packet from a session queue in the same commit that creates its worker,
// wait on that one worker, record its outcome, and claim again. No polling, no "any settled" join needed.

export const Queue = defineDoc<{ packets: string[]; next: number; done: WorkerResult[]; failed: string[] }>({
	kind: "spike.queue",
	version: 1,
	scope: "session",
	initial: () => ({ packets: [], next: 0, done: [], failed: [] }),
	checkpointWhen: () => false,
});

type LaneState = { phase: "claim" } | { phase: "collect"; worker: TaskId<WorkerResult>; packet: string };

export const Lane = defineTask<null, LaneState, null>({
	name: "security.lane",
	version: 1,
	initial: () => ({ phase: "claim" }),
	phases: {
		claim: async (task, runtime, taskContext) => {
			await runtime.commit(async (tx) => {
				const queue = await tx.doc(Queue);
				if (queue.next >= queue.packets.length) return { status: "terminal", outcome: { status: "completed", result: null } };
				const prompt = queue.packets[queue.next++]!;
				const packet = /PACKET (\S+)/.exec(prompt)![1]!;
				const worker = await tx.createTask(Worker, { packet, prompt }, { ownership: { kind: "task", taskId: task.id } });
				return { status: "waiting", checkpoint: { phase: "collect", worker, packet }, on: [worker], policy: "allSettled" };
			}, taskContext);
		},
		collect: async (task, runtime, taskContext) => {
			const { worker, packet } = task.state.checkpoint;
			const [outcome] = await runtime.outcomes([worker], taskContext);
			await runtime.commit(async (tx) => {
				const queue = await tx.doc(Queue);
				if (outcome!.status === "completed") queue.done.push(outcome!.result);
				else queue.failed.push(`${packet}:${outcome!.status}`);
				return { status: "running", checkpoint: { phase: "claim" } };
			}, taskContext);
		},
	},
	abort: (_task, runtime, taskContext) => runtime.commit(() => ({ status: "terminal", outcome: { status: "aborted" } }), taskContext),
});

type LaneScanState = { phase: "start" } | { phase: "finish"; lanes: TaskId<null>[] };

export const LaneScan = defineTask<ScanInput, LaneScanState, ScanResult>({
	name: "security.scan-lanes",
	version: 1,
	initial: () => ({ phase: "start" }),
	phases: {
		start: async (task, runtime, taskContext) => {
			await runtime.commit(async (tx) => {
				const queue = await tx.doc(Queue);
				queue.packets = task.input.packets;
				const lanes: TaskId<null>[] = [];
				for (let i = 0; i < Math.min(task.input.maxParallel, task.input.packets.length); i++) {
					lanes.push(await tx.createTask(Lane, null, { ownership: { kind: "task", taskId: task.id } }));
				}
				return { status: "waiting", checkpoint: { phase: "finish", lanes }, on: lanes, policy: "allSettled" };
			}, taskContext);
		},
		finish: async (_task, runtime, taskContext) => {
			const queue = (await runtime.snapshot(Queue, taskContext))!;
			await runtime.commit(
				() => ({ status: "terminal", outcome: { status: "completed", result: { done: queue.done, failed: queue.failed, waves: 0 } } }),
				taskContext,
			);
		},
	},
	abort: (_task, runtime, taskContext) => runtime.commit(() => ({ status: "terminal", outcome: { status: "aborted" } }), taskContext),
});

export const ScanExtension = defineExtension({ name: "spike-scan", tasks: [Scan, Worker, Lane, LaneScan] });

// ─── Host ───────────────────────────────────────────────────────────────────

export function createSpikeRegistry() {
	const registry = createRegistry();
	registry.install(WorkerTools);
	registry.install(ScanExtension);
	return registry;
}

/** Open SQLite storage, optionally SIGKILLing the process right after the Nth commit is durable. */
export async function openStorage(path: string, crashAfter?: number) {
	const storage = await openNodeSqliteStorage(path);
	if (crashAfter === undefined) return { storage, commits: () => 0 };
	let commits = 0;
	const commit = storage.commit.bind(storage);
	(storage as { commit: typeof storage.commit }).commit = async (...args: Parameters<typeof storage.commit>) => {
		const seq = await commit(...args);
		commits++;
		if (commits === crashAfter) process.kill(process.pid, "SIGKILL");
		return seq;
	};
	return { storage, commits: () => commits };
}

export async function openHarness(storage: Parameters<typeof Harness.open>[0], tokensPerSecond?: number) {
	return Harness.open(
		storage,
		{
			models: createFauxModels(tokensPerSecond),
			registry: createSpikeRegistry(),
			settings: { extensions: [] },
			onReport: (error, info) => {
				if (process.env.SPIKE_VERBOSE) console.error("report", info.type, String(error));
			},
		},
		context,
	);
}

export function packets(count: number, latency: (i: number) => number, extra: (i: number) => string = () => "") {
	return Array.from({ length: count }, (_, i) => `PACKET p${String(i).padStart(2, "0")} latency=${latency(i)}${extra(i)}`);
}
