// Run or resume one spike scan in a directory, then print a JSON summary.
//   node --experimental-strip-types run.ts <dir> [--packets N] [--parallel P] [--crash-after N]
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { Audit, context, openHarness, openStorage, packets, LaneScan, Results, RunDoc, Scan, type ScanResult, stats } from "./scan.ts";

const { positionals, values } = parseArgs({
	allowPositionals: true,
	options: {
		packets: { type: "string", default: "3" },
		parallel: { type: "string", default: "2" },
		"crash-after": { type: "string" },
		latency: { type: "string", default: "5" },
		lanes: { type: "boolean", default: false },
	},
});
const dir = positionals[0]!;
mkdirSync(dir, { recursive: true });
const dbPath = join(dir, "run.sqlite");
const crashAfter = values["crash-after"] === undefined ? undefined : Number(values["crash-after"]);

const { storage, commits } = await openStorage(dbPath, crashAfter ?? Number.MAX_SAFE_INTEGER);
const harness = await openHarness(storage);
const root = await harness.root(context);

// Idempotent run creation: a crash before this commit leaves no scan; after it, the stored ID is reused.
const latency = Number(values.latency);
const input = { packets: packets(Number(values.packets), () => latency), maxParallel: Number(values.parallel) };
const scanId = await root.commit(async (tx) => {
	const run = await tx.doc(RunDoc);
	if (run.scanId === undefined) run.scanId = (await tx.createTask(values.lanes ? (LaneScan as unknown as typeof Scan) : Scan, input, { ownership: { kind: "conversation" } })) as number;
	return run.scanId;
}, context);
const settled = await harness.waitForTask<ScanResult>(scanId as never, context);
const results = await harness.snapshot(Results, context);
const audit = await harness.snapshot(Audit, context);
const usage = await harness.usage(context);
await harness.close(context);

const outcome = settled.state.outcome;
console.log(
	JSON.stringify({
		outcome: outcome.status,
		scan: outcome.status === "completed" ? { done: outcome.result.done.map((d) => [d.packet, d.candidates]).sort(), failed: outcome.result.failed } : undefined,
		results: Object.fromEntries(Object.entries(results?.byPacket ?? {}).map(([k, v]) => [k, { candidates: v.candidates.map((c) => c.id), writes: v.writes }]).sort()),
		audit: audit?.conversations.map((c) => c.packet).sort(),
		commits: commits(),
		modelCalls: stats.modelCalls,
		reportCalls: stats.reportCalls,
		usageModels: Object.keys(usage.models),
	}),
);
