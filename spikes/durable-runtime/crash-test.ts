// Task 0.1: kill the process right after every commit of a baseline scan, resume, and compare.
//   node --experimental-strip-types crash-test.ts <scratch-dir> [--packets N] [--parallel P]
import { execFileSync, spawnSync } from "node:child_process";
import { rmSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";

const { positionals, values } = parseArgs({ allowPositionals: true, options: { packets: { type: "string", default: "3" }, parallel: { type: "string", default: "2" }, lanes: { type: "boolean", default: false } } });
const scratch = positionals[0]!;
const node = ["--experimental-strip-types", "--no-warnings", join(import.meta.dirname, "run.ts")];
const shape = ["--packets", values.packets!, "--parallel", values.parallel!, ...(values.lanes ? ["--lanes"] : [])];

function run(dir: string, extra: string[] = []) {
	const result = spawnSync(process.execPath, [...node, dir, ...shape, ...extra], { encoding: "utf8", timeout: 60_000 });
	return { signal: result.signal, status: result.status, stdout: result.stdout.trim(), stderr: result.stderr.trim() };
}
// Report-tool reruns are expected (at-least-once, idempotent writes); compare outputs without the write counter.
const key = (summary: any) =>
	JSON.stringify({ scan: summary.scan, results: Object.fromEntries(Object.entries(summary.results).map(([k, v]: [string, any]) => [k, v.candidates])), audit: summary.audit });

const baseDir = join(scratch, "baseline");
rmSync(baseDir, { recursive: true, force: true });
const base = JSON.parse(run(baseDir).stdout);
console.log(`baseline: ${base.commits} commits, ${base.modelCalls} model calls`);

const failures: string[] = [];
let extraModelCalls = 0;
const reruns: number[] = [];
for (let n = 1; n <= base.commits; n++) {
	const dir = join(scratch, `crash-${n}`);
	rmSync(dir, { recursive: true, force: true });
	const crashed = run(dir, ["--crash-after", String(n)]);
	if (crashed.signal !== "SIGKILL") failures.push(`n=${n}: expected SIGKILL, got ${crashed.signal ?? crashed.status} ${crashed.stderr.slice(0, 300)}`);
	const resumed = run(dir);
	if (resumed.status !== 0) {
		failures.push(`n=${n}: resume failed ${resumed.status} ${resumed.stderr.slice(0, 500)}`);
		continue;
	}
	const summary = JSON.parse(resumed.stdout);
	const writes = Object.values(summary.results as Record<string, { writes: number }>).map((r) => r.writes);
	if (key(summary) !== key(base)) failures.push(`n=${n}: outputs differ\n  base:    ${key(base)}\n  resumed: ${key(summary)}`);
	if (writes.some((w) => w !== 1)) reruns.push(n);
	extraModelCalls += summary.modelCalls;
	rmSync(dir, { recursive: true, force: true });
}
console.log(`crash points: ${base.commits}, failures: ${failures.length}, model calls made by resumed processes: ${extraModelCalls}`);
console.log(`crash points where the idempotent report tool reran: ${reruns.join(", ") || "none"}`);
for (const failure of failures) console.log(failure);
process.exitCode = failures.length === 0 ? 0 : 1;
