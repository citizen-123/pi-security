// Task 0.2: pi-coding-agent's ModelRuntime as pi-durable's Models, with credentials from a Pi auth.json.
// A local OpenAI-compatible stub stands in for the provider: it records the Authorization header and answers.
// Then the run storage is searched for the credential bytes.
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ModelRuntime } from "@earendil-works/pi-coding-agent";
import { AssistantEntry, createRegistry, Harness } from "@earendil-works/pi-durable";
import { openNodeSqliteStorage } from "@earendil-works/pi-durable/storage/sqlite/node";
import { redactingModels } from "./redacting-models.ts";
import { context } from "./scan.ts";

const CANARY = "sk-spike-CANARY-7f3a9c1e5b";
const seen: string[] = [];

const server = createServer((request, response) => {
	seen.push(String(request.headers.authorization ?? ""));
	request.resume();
	request.on("end", () => {
		if (process.env.SPIKE_ECHO_401) {
			response.writeHead(401, { "content-type": "application/json" });
			response.end(JSON.stringify({ error: { message: `Incorrect API key provided: ${CANARY}`, type: "invalid_request_error" } }));
			return;
		}
		response.writeHead(200, { "content-type": "text/event-stream" });
		const chunk = (delta: object, finish: string | null) =>
			`data: ${JSON.stringify({ id: "c1", object: "chat.completion.chunk", created: 0, model: "stub-1", choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
		response.write(chunk({ role: "assistant", content: "Paris." }, null));
		response.write(chunk({}, "stop"));
		response.end("data: [DONE]\n\n");
	});
});
await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
const port = (server.address() as { port: number }).port;

const dir = mkdtempSync(join(tmpdir(), "pi-security-spike-models-"));
const authPath = join(dir, "auth.json");
const modelsPath = join(dir, "models.json");
writeFileSync(authPath, JSON.stringify({ stub: { type: "api_key", key: CANARY } }), { mode: 0o600 });
writeFileSync(
	modelsPath,
	JSON.stringify({ providers: { stub: { baseUrl: `http://127.0.0.1:${port}/v1`, api: "openai-completions", models: [{ id: "stub-1" }] } } }),
);

const runtime = await ModelRuntime.create({ authPath, modelsPath, refreshOnCreate: false });
// SPIKE_REDACT: wrap with a decorator that knows the credential values (here, the canary from auth.json).
const models = process.env.SPIKE_REDACT ? redactingModels(runtime, [CANARY]) : runtime;
const dbPath = join(dir, "run.sqlite");
const harness = await Harness.open(
	await openNodeSqliteStorage(dbPath),
	{ models, registry: createRegistry(), settings: { retry: { enabled: false } } },
	context,
);
const root = await harness.root(context, { agent: { model: { provider: "stub", modelId: "stub-1" } } });
const settled = await (await root.submit({ type: "input", content: "Capital of France?" }, context)).wait(context);
let answer: unknown = settled.status === "done" ? undefined : settled;
if (settled.status === "done" && settled.type === "input") {
	const entry = await root.commit((tx) => tx.entry(AssistantEntry, settled.answer), context);
	answer = entry?.model?.[0];
}
await harness.close(context);
server.close();

// Search every file SQLite may have written (WAL included) for the credential.
const files = ["run.sqlite", "run.sqlite-wal", "run.sqlite-shm"].map((f) => join(dir, f));
const leaked = files.filter((file) => {
	try {
		return readFileSync(file).includes(CANARY);
	} catch {
		return false;
	}
});
console.log(
	JSON.stringify(
		{
			status: settled.status,
			answer,
			providerSawBearer: seen.map((h) => (h === `Bearer ${CANARY}` ? "Bearer <canary>" : h || "<none>")),
			canaryInRunStorage: leaked,
		},
		null,
		1,
	),
);
