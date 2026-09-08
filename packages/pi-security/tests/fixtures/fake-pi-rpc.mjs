#!/usr/bin/env node
import { appendFileSync, existsSync, writeFileSync } from "node:fs";

let input = Buffer.alloc(0);
let sessionId = "fixture-session";
if (["ignore-term", "malformed-ignore-term"].includes(process.env.FAKE_RPC_MODE)) {
  process.on("SIGTERM", () => undefined);
}
let streaming = false;
let lastPrompt;
let aborted = false;
let activityTimer;
let stateRequests = 0;

function stopActivityFlood() {
  if (!activityTimer) return;
  clearInterval(activityTimer);
  activityTimer = undefined;
}

function startActivityFlood() {
  if (activityTimer) return;
  let emitted = 0;
  activityTimer = setInterval(() => {
    emit({ type: "tool_execution_start", sessionId, toolName: "read" });
    emit({ type: "tool_execution_end", sessionId, toolName: "read", success: true });
    emitted += 1;
    if (emitted === 20 && !process.argv.includes("--continuous-activity-flood")) stopActivityFlood();
  }, 1);
}

function argumentValue(prefix) {
  const argument = process.argv.find((value) => value.startsWith(prefix));
  return argument?.slice(prefix.length);
}

const startupMarker = argumentValue("--startup-marker=");
if (startupMarker) writeFileSync(startupMarker, String(process.pid));

function recordAbort() {
  const marker = argumentValue("--abort-marker=");
  if (marker) writeFileSync(marker, "aborted\n");
}

function respondToState(command, data) {
  const releasePath = argumentValue("--get-state-release=");
  if (releasePath && !existsSync(releasePath)) {
    const releaseTimer = setInterval(() => {
      if (!existsSync(releasePath)) return;
      clearInterval(releaseTimer);
      response(command, data);
    }, 1);
    return;
  }
  const delayMs = Number(argumentValue("--delay-state-after-initial-ms=") ?? 0);
  if (stateRequests > 1 && delayMs > 0) {
    const marker = argumentValue("--state-delay-marker=");
    if (marker) writeFileSync(marker, "waiting\n");
    setTimeout(() => response(command, data), delayMs);
    return;
  }
  response(command, data);
}

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
  if (process.env.FAKE_RPC_MODE === "secret-data") {
    emit({ type: "message_end", message: { content: [{ text: "synthetic-canary" }] } });
    emit({ type: "response", id: command.id, command: command.type, success: true, data: { messages: [{ content: "synthetic-canary" }] } });
    return;
  }
  if (process.env.FAKE_RPC_MODE === "never-response" || process.argv.includes("--never-respond")) {
    return;
  }
  if (process.env.FAKE_RPC_MODE === "exit-before-response") {
    process.stderr.write("synthetic transport exit\n");
    process.exit(7);
  }
  if (process.env.FAKE_RPC_MODE === "unknown-id") {
    emit({ type: "response", id: "foreign", command: command.type, success: true, data });
    return;
  }
  if (process.env.FAKE_RPC_MODE === "wrong-command") {
    emit({ type: "response", id: command.id, command: "abort", success: true, data });
    return;
  }
  if (process.env.FAKE_RPC_MODE === "invalid-error") {
    emit({ type: "response", id: command.id, command: command.type, success: false, error: { message: "bad" } });
    return;
  }
  if (process.env.FAKE_RPC_MODE === "secret-error") {
    emit({ type: "response", id: command.id, command: command.type, success: false, error: "provider rejected synthetic-canary" });
    return;
  }
  if (process.env.FAKE_RPC_MODE === "secret-json") {
    process.stdout.write("synthetic-canary is not JSON\n");
    return;
  }
  if (process.env.FAKE_RPC_MODE === "stderr") {
    process.stderr.write("provider rejected synthetic-canary\n");
  }
  if (["malformed", "malformed-ignore-term"].includes(process.env.FAKE_RPC_MODE)) {
    process.stdout.write("{not-json}\n");
    emit({ type: "agent_start", sessionId }, "normal");
    return;
  }
  const value = { type: "response", id: command.id, command: command.type, success: true, data };
  emit(value);
  if (process.env.FAKE_RPC_MODE === "duplicate") emit(value);
}
function handle(command) {
  switch (command.type) {
    case "get_commands":
      response(command, { commands: process.argv.includes("--missing-policy") ? [] : [{ name: "pi-security-policy-ready" }] });
      break;
    case "get_state": {
      stateRequests += 1;
      const defaultModel = process.env.FAKE_RPC_DEFAULT_MODEL
        ? JSON.parse(process.env.FAKE_RPC_DEFAULT_MODEL)
        : { provider: "fixture", id: "fixture-model" };
      const providerIndex = process.argv.indexOf("--provider");
      const modelIndex = process.argv.indexOf("--model");
      respondToState(command, {
        model: {
          provider: providerIndex >= 0 ? process.argv[providerIndex + 1] : defaultModel.provider,
          id: modelIndex >= 0 ? process.argv[modelIndex + 1] : defaultModel.id,
        },
        thinkingLevel: "medium",
        isStreaming: streaming,
        sessionFile: "/synthetic/session.jsonl",
        sessionId: process.argv.includes("--missing-session") ? undefined : sessionId,
        argv: process.argv.slice(2),
        aborted,
        credentialPresent: Boolean(process.env.FIXTURE_TOKEN),
      });
      break;
    }
    case "get_messages": {
      const marker = argumentValue("--messages-marker=");
      if (marker) writeFileSync(marker, "requested\n");
      if (process.argv.includes("--messages-never-respond")) return;
      if (process.env.FAKE_RPC_FAIL_TRANSCRIPT === "1") {
        emit({ type: "response", id: command.id, command: command.type, success: false, error: "Synthetic transcript retrieval failure." });
        break;
      }
      const outputs = process.env.FAKE_RPC_PHASE_OUTPUTS
        ? JSON.parse(process.env.FAKE_RPC_PHASE_OUTPUTS)
        : undefined;
      const input = lastPrompt?.match(/Phase input:\n(.*)$/su)?.[1];
      const phase = input ? JSON.parse(input) : undefined;
      let content = outputs && phase
        ? JSON.stringify({
            attemptId: `fixture:${phase.phaseId}`,
            output: process.env.FAKE_RPC_ECHO_CREDENTIAL && phase.phaseId === "threat-model"
              ? { threatModel: { summary: process.env.OPENAI_API_KEY } }
              : outputs[phase.phaseId],
            phaseId: phase.phaseId,
            runId: phase.runId,
            schemaVersion: 1,
          })
        : "synthetic\u2028transcript";
      if (process.env.FAKE_RPC_ECHO_CREDENTIAL === "escaped" && process.env.OPENAI_API_KEY) {
        content = content.replaceAll(process.env.OPENAI_API_KEY,
          [...process.env.OPENAI_API_KEY].map((character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`).join(""));
      }
      response(command, { messages: [{
        role: "assistant",
        content: outputs ? [{ type: "thinking", thinking: "Synthetic private reasoning." }, { type: "text", text: content }] : content,
        stopReason: process.env.FAKE_RPC_ASSISTANT_ERROR === "1" ? "error" : "stop",
        ...(process.env.FAKE_RPC_ASSISTANT_ERROR === "1" ? { errorMessage: "Synthetic provider failure." } : {}),
      }] });
      break;
    }
    case "prompt":
      lastPrompt = command.message;
      if (process.env.FAKE_RPC_CAPTURE_FILE) {
        appendFileSync(process.env.FAKE_RPC_CAPTURE_FILE, `${JSON.stringify({
          argv: process.argv.slice(2),
          pid: process.pid,
          credentialPresent: Boolean(process.env.OPENAI_API_KEY),
          phaseInput: command.message.match(/Phase input:\n(.*)$/su)?.[1] ?? null,
        })}\n`);
      }
      streaming = true;
      response(command);
      emit({ type: "agent_start", sessionId });
      setTimeout(() => {
        emit({ type: "agent_settled", sessionId, result: { status: "ok" } });
        streaming = false;
      }, Number(process.env.FAKE_RPC_SETTLE_DELAY_MS ?? 0));
      if (process.argv.includes("--prompt-activity-flood")) startActivityFlood();
      break;
    case "new_session":
      sessionId = "fixture-session-2";
      response(command, { cancelled: false });
      break;
    case "steer":
      response(command);
      if (command.message === "start activity flood") startActivityFlood();
      break;
    case "follow_up":
      response(command);
      break;
    case "abort":
      aborted = true;
      recordAbort();
      stopActivityFlood();
      if (
        process.env.FAKE_RPC_MODE === "abort-never-response"
        || process.argv.includes("--abort-never-respond")
      ) {
        return;
      }
      emit({ type: "agent_settled", sessionId, aborted: true });
      response(command);
      break;
    case "exit":
      if (process.env.FAKE_RPC_MODE === "exit-final-response") {
        const line = `${JSON.stringify({ type: "response", id: command.id, command: command.type, success: true, data: { final: true } })}\n`;
        process.stdout.write(line, () => process.exit(0));
        return;
      }
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
