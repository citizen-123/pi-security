#!/usr/bin/env node

let input = Buffer.alloc(0);
let sessionId = "fixture-session";
if (process.env.FAKE_RPC_MODE === "ignore-term") {
  process.on("SIGTERM", () => undefined);
}
let streaming = false;

process.stdin.on("data", (chunk) => {
  input = Buffer.concat([input, chunk]);
  for (;;) {
    const newline = input.indexOf(0x0a);
    if (newline < 0) return;
    let record = input.subarray(0, newline);
    input = input.subarray(newline + 1);
    if (record.at(-1) === 0x0d) record = record.subarray(0, -1);
    handle(JSON.parse(record.toString("utf8")));
  }
});

function emit(value, mode = process.env.FAKE_RPC_MODE) {
  const line = `${JSON.stringify(value)}\n`;
  if (mode === "split") {
    const middle = Math.max(1, Math.floor(line.length / 2));
    process.stdout.write(line.slice(0, middle));
    setImmediate(() => process.stdout.write(line.slice(middle)));
    return;
  }
  if (mode === "crlf") {
    process.stdout.write(line.replace(/\n$/, "\r\n"));
    return;
  }
  process.stdout.write(line);
}

function response(command, data) {
  if (process.env.FAKE_RPC_MODE === "exit-before-response") {
    process.stderr.write("synthetic transport exit\n");
    process.exit(7);
  }
  if (process.env.FAKE_RPC_MODE === "unknown-id") {
    emit({ type: "response", id: "foreign", command: command.type, success: true, data });
    return;
  }
  if (process.env.FAKE_RPC_MODE === "stderr") {
    process.stderr.write("provider rejected synthetic-canary\n");
  }
  if (process.env.FAKE_RPC_MODE === "malformed") {
    process.stdout.write("{not-json}\n");
    return;
  }
  const value = { type: "response", id: command.id, command: command.type, success: true, data };
  emit(value);
  if (process.env.FAKE_RPC_MODE === "duplicate") emit(value);
}
function handle(command) {
  switch (command.type) {
    case "get_state":
      response(command, {
        model: { provider: "fixture", id: "fixture-model" },
        thinkingLevel: "medium",
        isStreaming: streaming,
        sessionFile: "/synthetic/session.jsonl",
        sessionId,
        argv: process.argv.slice(2),
        credentialPresent: Boolean(process.env.FIXTURE_TOKEN)
      });
      break;
    case "get_messages":
      response(command, { messages: [{ role: "assistant", content: "synthetic\u2028transcript" }] });
      break;
    case "prompt":
      streaming = true;
      response(command);
      emit({ type: "agent_start", sessionId });
      emit({ type: "agent_settled", sessionId, result: { status: "ok" } });
      streaming = false;
      break;
    case "new_session":
      sessionId = "fixture-session-2";
      response(command, { cancelled: false });
      break;
    case "steer":
    case "follow_up":
    case "abort":
      response(command);
      break;
    case "exit":
      response(command);
      setTimeout(() => {
        process.exit(Number(process.env.FAKE_RPC_EXIT_CODE ?? 0));
      }, Number(process.env.FAKE_RPC_EXIT_DELAY_MS ?? 0));
      process.stdin.unref();
      break;
    default:
      emit({
        type: "response",
        id: command.id,
        command: command.type,
        success: false,
        error: `unsupported fixture command: ${command.type}`
      });
  }
}
