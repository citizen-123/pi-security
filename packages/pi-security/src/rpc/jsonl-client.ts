import { randomUUID } from "node:crypto";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";

export interface JsonlRpcClientOptions {
  command: string;
  args?: string[];
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  redact?: (text: string) => string;
  cleanupTimeoutMs?: number;
}

export interface RpcResponse {
  type: "response";
  id: string;
  command: string;
  success: boolean;
  data?: unknown;
  error?: string;
}

export interface RpcEvent {
  type: string;
  [key: string]: unknown;
}

interface PendingRequest {
  resolve: (response: RpcResponse) => void;
  reject: (error: Error) => void;
}

export class JsonlRpcError extends Error {
  constructor(
    message: string,
    readonly kind: "protocol" | "process" | "request"
  ) {
    super(message);
    this.name = "JsonlRpcError";
  }
}

export class JsonlRpcClient {
  readonly #options: JsonlRpcClientOptions;
  readonly #pending = new Map<string, PendingRequest>();
  readonly #listeners = new Set<(event: RpcEvent) => void>();
  #process: ChildProcessWithoutNullStreams | undefined;
  #stdout = Buffer.alloc(0);
  #stderr = "";
  #exit: Promise<void> | undefined;
  #resolveExit: (() => void) | undefined;
  #closed = false;

  constructor(options: JsonlRpcClientOptions) {
    this.#options = options;
  }

  async start(): Promise<void> {
    if (this.#process || this.#closed) {
      throw new JsonlRpcError("RPC client cannot be started more than once.", "process");
    }
    const child = spawn(this.#options.command, this.#options.args ?? [], {
      cwd: this.#options.cwd,
      env: this.#options.env,
      stdio: ["pipe", "pipe", "pipe"]
    });
    this.#process = child;
    this.#exit = new Promise<void>((resolve) => {
      this.#resolveExit = resolve;
    });
    child.stdout.on("data", (chunk: Buffer) => this.#acceptStdout(chunk));
    child.stderr.on("data", (chunk: Buffer) => {
      this.#stderr += chunk.toString("utf8");
    });
    child.once("exit", (code, signal) => this.#handleExit(code, signal));
    await new Promise<void>((resolve, reject) => {
      child.once("spawn", resolve);
      child.once("error", reject);
    }).catch((error: unknown) => {
      throw new JsonlRpcError(`Unable to start RPC process: ${errorMessage(error)}`, "process");
    });
  }

  onEvent(listener: (event: RpcEvent) => void): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  async request(command: Record<string, unknown>): Promise<RpcResponse> {
    const child = this.#process;
    if (!child || this.#closed || !child.stdin.writable) {
      throw new JsonlRpcError("RPC process is not running.", "process");
    }
    if (typeof command.type !== "string" || command.type === "response") {
      throw new JsonlRpcError("RPC command type is invalid.", "request");
    }
    const id = randomUUID();
    const response = new Promise<RpcResponse>((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
    });
    child.stdin.write(`${JSON.stringify({ ...command, id })}\n`, (error) => {
      if (!error) return;
      const pending = this.#pending.get(id);
      this.#pending.delete(id);
      pending?.reject(new JsonlRpcError(`Unable to write RPC command: ${error.message}`, "process"));
    });
    return await response;
  }

  getStderr(): string {
    return this.#redact(this.#stderr);
  }
  async waitForExit(): Promise<void> {
    if (!this.#exit) throw new JsonlRpcError("RPC process has not started.", "process");
    await this.#exit;
  }

  async stop(signal: NodeJS.Signals = "SIGTERM"): Promise<void> {
    const child = this.#process;
    if (!child || this.#closed) return;
    child.stdin.end();
    child.kill(signal);
    const exit = this.#exit;
    if (!exit) return;
    let timer: NodeJS.Timeout | undefined;
    await Promise.race([
      exit,
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, this.#options.cleanupTimeoutMs ?? 5_000);
      }),
    ]);
    clearTimeout(timer);
    if (!this.#closed) {
      child.kill("SIGKILL");
      await exit;
    }
  }

  #acceptStdout(chunk: Buffer): void {
    this.#stdout = Buffer.concat([this.#stdout, chunk]);
    for (;;) {
      const newline = this.#stdout.indexOf(0x0a);
      if (newline < 0) return;
      let record = this.#stdout.subarray(0, newline);
      this.#stdout = this.#stdout.subarray(newline + 1);
      if (record.at(-1) === 0x0d) record = record.subarray(0, -1);
      this.#acceptRecord(record);
    }
  }

  #acceptRecord(record: Buffer): void {
    try {
      if (record.length === 0) throw new Error("empty record");
      const text = new TextDecoder("utf-8", { fatal: true }).decode(record);
      const value: unknown = JSON.parse(text);
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("record is not an object");
      }
      const message = value as Record<string, unknown>;
      if (message.type !== "response") {
        if (typeof message.type !== "string") throw new Error("event type is missing");
        for (const listener of this.#listeners) listener(message as RpcEvent);
        return;
      }
      this.#acceptResponse(message);
    } catch (error) {
      this.#failProtocol(`Invalid RPC stdout record: ${errorMessage(error)}`);
    }
  }

  #acceptResponse(message: Record<string, unknown>): void {
    if (
      typeof message.id !== "string" ||
      typeof message.command !== "string" ||
      typeof message.success !== "boolean"
    ) {
      throw new Error("response envelope is invalid");
    }
    const pending = this.#pending.get(message.id);
    if (!pending) throw new Error(`response correlation is unknown: ${message.id}`);
    this.#pending.delete(message.id);
    const response = message as unknown as RpcResponse;
    if (!response.success) {
      pending.reject(new JsonlRpcError(response.error || `RPC command ${response.command} failed.`, "request"));
      return;
    }
    pending.resolve(response);
  }

  #failProtocol(message: string): void {
    const error = new JsonlRpcError(message, "protocol");
    this.#rejectPending(error);
    this.#process?.kill("SIGTERM");
  }

  #handleExit(code: number | null, signal: NodeJS.Signals | null): void {
    if (this.#closed) return;
    this.#closed = true;
    const trailing = this.#stdout.length > 0 ? " with an unterminated stdout record" : "";
    const detail = signal ? `signal ${signal}` : `code ${code ?? "unknown"}`;
    const stderr = this.getStderr().trim();
    const suffix = stderr ? `: ${stderr}` : "";
    this.#rejectPending(new JsonlRpcError(`RPC process exited with ${detail}${trailing}${suffix}`, "process"));
    this.#resolveExit?.();
    this.#listeners.clear();
    this.#process = undefined;
  }

  #rejectPending(error: Error): void {
    for (const pending of this.#pending.values()) pending.reject(error);
    this.#pending.clear();
  }

  #redact(text: string): string {
    return this.#options.redact ? this.#options.redact(text) : text;
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
