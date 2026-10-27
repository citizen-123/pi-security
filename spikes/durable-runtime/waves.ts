// Task 0.3: wave fan-out cost. 64 workers with random latency, max_parallel 8, in-memory storage.
// Compares the measured wave schedule with a simulated sliding window over the same durations.
import { MemoryStorage } from "@earendil-works/pi-durable";
import { context, hash, LaneScan, openHarness, packets, Scan, type ScanResult } from "./scan.ts";

const COUNT = 64;
const PARALLEL = 8;

async function measure(seed: string, task: typeof Scan | typeof LaneScan) {
	// Long-tailed latency: most workers 200-1000 ms, one in eight 2000-4000 ms.
	const latency = (i: number) => {
		const h = hash(`${seed}:${i}`);
		return h % 8 === 0 ? 2000 + (h % 2000) : 200 + (h % 800);
	};
	const harness = await openHarness(new MemoryStorage());
	const root = await harness.root(context);
	const started = Date.now();
	const id = await root.commit(
		(tx) => tx.createTask(task as typeof Scan, { packets: packets(COUNT, latency), maxParallel: PARALLEL }, { ownership: { kind: "conversation" } }),
		context,
	);
	const settled = await harness.waitForTask<ScanResult>(id, context);
	const wall = Date.now() - started;
	await harness.close(context);
	if (settled.state.outcome.status !== "completed") throw new Error("scan failed");
	const durations = settled.state.outcome.result.done.map((d) => d.endedAt - d.startedAt);
	const busy = durations.reduce((a, b) => a + b, 0);
	// Sliding window: each worker starts as soon as any slot frees, in packet order.
	const ordered = settled.state.outcome.result.done.sort((a, b) => a.packet.localeCompare(b.packet)).map((d) => d.endedAt - d.startedAt);
	const slots = Array<number>(PARALLEL).fill(0);
	for (const d of ordered) {
		slots.sort((a, b) => a - b);
		slots[0]! += d;
	}
	const sliding = Math.max(...slots);
	return { wall, sliding, utilization: busy / (wall * PARALLEL), slidingUtilization: busy / (sliding * PARALLEL) };
}

for (const seed of ["a", "b", "c"]) {
	const waves = await measure(seed, Scan);
	const lanes = await measure(seed, LaneScan);
	console.log(
		`seed ${seed}: waves ${waves.wall} ms (${(waves.utilization * 100).toFixed(0)}% slot use) | lanes ${lanes.wall} ms (${(lanes.utilization * 100).toFixed(0)}%) | simulated ideal ${waves.sliding} ms`,
	);
}
