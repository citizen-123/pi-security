// Task 0.5: can a stall monitor see each worker's progress without reading transcripts?
// pi-durable 1.4.0 stores no timestamps on entries or pi.live, so the monitor is host-side and in memory: it observes
// the task graph for workers, watches each worker conversation's view, stamps every change with the host clock,
// and aborts a worker whose conversation has not changed for STALL_MS. After a restart every worker gets a fresh
// stamp, which is correct: a new process has made no progress yet either.
import { MemoryStorage, type Harness, type TaskGraph } from "@earendil-works/pi-durable";
import { context, LaneScan, openHarness, packets, type ScanResult } from "./scan.ts";

const STALL_MS = 1500;

class StallMonitor {
	readonly #harness: Harness;
	readonly #workers = new Map<number, { last: number; stop: () => void }>();
	readonly aborted: number[] = [];
	readonly maxQuietMs = new Map<number, number>();
	#graph?: { stop(): Promise<unknown> };
	#timer?: NodeJS.Timeout;

	constructor(harness: Harness) {
		this.#harness = harness;
	}

	async start() {
		// pi-durable 1.4.0 (published) offers watches; the synchronous observeTaskGraph/observeConversation API on
		// upstream main is unreleased.
		const graph = await this.#harness.watchTaskGraph(context);
		this.#graph = graph;
		await this.#sync(graph.value);
		graph.start(async (value) => this.#sync(value));
		this.#timer = setInterval(() => this.#check(), 100);
	}

	async stop() {
		clearInterval(this.#timer);
		await this.#graph?.stop();
		for (const worker of this.#workers.values()) worker.stop();
	}

	async #sync(graph: TaskGraph) {
		const live = new Set<number>();
		for (const node of Object.values(graph.tasks)) {
			if (node.kind !== "security.worker" || node.conversations.length === 0) continue;
			const id = node.id as number;
			live.add(id);
			if (this.#workers.has(id)) continue;
			const entry = { last: Date.now(), stop: () => undefined as unknown };
			this.#workers.set(id, entry);
			const conversation = await this.#harness.conversation(node.conversations[0]!, context);
			const watch = await conversation!.watch(context);
			entry.stop = () => void watch.stop();
			watch.start(async () => {
				const now = Date.now();
				this.maxQuietMs.set(id, Math.max(this.maxQuietMs.get(id) ?? 0, now - entry.last));
				entry.last = now;
			});
		}
		for (const [id, entry] of this.#workers) {
			if (!live.has(id)) {
				entry.stop();
				this.#workers.delete(id);
			}
		}
	}

	#check() {
		const now = Date.now();
		for (const [id, entry] of this.#workers) {
			if (now - entry.last > STALL_MS && !this.aborted.includes(id)) {
				this.aborted.push(id);
				void this.#harness.abortTask(id as never, context);
			}
		}
	}
}

// tokensPerSecond 200: the 4000-character preamble of p02 streams for about 5 s, longer than STALL_MS.
const harness = await openHarness(new MemoryStorage(), 200);
const monitor = new StallMonitor(harness);
await monitor.start();
const root = await harness.root(context);
const input = {
	packets: packets(3, () => 50, (i) => (i === 1 ? " hang" : i === 2 ? " stream=4000" : "")),
	maxParallel: 3,
};
const started = Date.now();
const id = await root.commit((tx) => tx.createTask(LaneScan, input, { ownership: { kind: "conversation" } }), context);
const settled = await harness.waitForTask<ScanResult>(id, context);
await monitor.stop();
await harness.close(context);
const outcome = settled.state.outcome;
console.log(
	JSON.stringify(
		{
			wallMs: Date.now() - started,
			outcome: outcome.status,
			done: outcome.status === "completed" ? outcome.result.done.map((d) => [d.packet, d.endedAt - d.startedAt]) : undefined,
			failed: outcome.status === "completed" ? outcome.result.failed : undefined,
			abortedWorkerTaskIds: monitor.aborted,
			maxQuietMsPerWorker: Object.fromEntries(monitor.maxQuietMs),
		},
		null,
		1,
	),
);
