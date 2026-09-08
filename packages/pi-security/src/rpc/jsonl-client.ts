import { randomUUID } from "node:crypto";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";

export interface JsonlRpcClientOptions {
  command: string;
  args?: string[];
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  redact?: (text: string) => string;
  cleanupTimeoutMs?: number;
  requestTimeoutMs?: number;
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
  command: string;
  resolve: (response: RpcResponse) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
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
  #failed = false;
  #stopping: Promise<void> | undefined;
  #closeTimer: NodeJS.Timeout | undefined;

  constructor(options: JsonlRpcClientOptions) {
    this.#options = options;
  }

  async start(): Promise<void> {
    if (this.#process || this.#closed || this.#stopping) {
      throw new JsonlRpcError("RPC client cannot be started more than once.", "process");
    }
    this.#exit = new Promise<void>((resolve) => {
      this.#resolveExit = resolve;
    });
    let child: ChildProcessWithoutNullStreams;
    try {
      child = spawn(this.#options.command, this.#options.args ?? [], {
        cwd: this.#options.cwd,
        env: this.#options.env,
        stdio: ["pipe", "pipe", "pipe"]
      });
    } catch (error) {
      this.#handleProcessError(error);
      throw this.#error(`Unable to start RPC process: ${errorMessage(error)}`, "process");
    }
    this.#process = child;
    child.stdin.on("error", (error) => this.#handleProcessError(error));
    child.stdout.on("error", (error) => this.#handleProcessError(error));
    child.stderr.on("error", (error) => this.#handleProcessError(error));
    child.stdout.on("data", (chunk: Buffer) => this.#acceptStdout(chunk));
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => {
      this.#stderr += chunk;
    });
    child.once("close", (code, signal) => this.#handleExit(code, signal));
    child.once("exit", () => {
      // Drain final frames before closing, without waiting forever on inherited pipes.
      this.#closeTimer = setTimeout(() => {
        child.stdout.destroy();
        child.stderr.destroy();
      }, this.#options.cleanupTimeoutMs ?? 5_000);
    });
    child.once("error", (error) => this.#handleProcessError(error));
    await new Promise<void>((resolve, reject) => {
      function cleanup(): void {
        child.off("spawn", onSpawn);
        child.off("error", onError);
        child.off("exit", onExit);
      }
      function onSpawn(): void {
        cleanup();
        resolve();
      }
      function onError(error: Error): void {
        cleanup();
        reject(error);
      }
      function onExit(code: number | null, signal: NodeJS.Signals | null): void {
        cleanup();
        reject(new Error(`RPC process exited before startup with ${signal ? `signal ${signal}` : `code ${code ?? "unknown"}`}.`));
      }
      child.once("spawn", onSpawn);
      child.once("error", onError);
      child.once("exit", onExit);
    }).catch((error: unknown) => {
      throw this.#error(`Unable to start RPC process: ${errorMessage(error)}`, "process");
    });
  }

  onEvent(listener: (event: RpcEvent) => void): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  async request(command: Record<string, unknown>): Promise<RpcResponse> {
    const child = this.#process;
    if (!child || this.#closed || this.#failed || this.#stopping || !child.stdin.writable) {
      throw new JsonlRpcError("RPC process is not running.", "process");
    }
    if (typeof command.type !== "string" || command.type === "response") {
      throw new JsonlRpcError("RPC command type is invalid.", "request");
    }
    const id = randomUUID();
    const timeoutMs = this.#options.requestTimeoutMs ?? 30_000;
    let record: string;
    try {
      record = `${JSON.stringify({ ...command, id })}\n`;
    } catch (error) {
      throw this.#error(`Unable to encode RPC command: ${errorMessage(error)}`, "request");
    }
    const response = new Promise<RpcResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        const pending = this.#takePending(id);
        if (!pending) return;
        pending.reject(this.#error(
          `RPC command ${command.type} timed out after ${timeoutMs}ms.`,
          "process"
        ));
        this.#failed = true;
        this.#rejectPending(this.#error("RPC process stopped after a request timeout.", "process"));
        void this.stop().catch(() => undefined);
      }, timeoutMs);
      this.#pending.set(id, { command: command.type as string, resolve, reject, timer });
    });
    try {
      child.stdin.write(record, (error) => {
        if (!error) return;
        this.#handleProcessError(error);
      });
    } catch (error) {
      this.#handleProcessError(error);
    }
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
    this.#stopping ??= this.#stopProcess(signal);
    await this.#stopping;
  }

  async #stopProcess(signal: NodeJS.Signals): Promise<void> {
    const child = this.#process;
    if (!child || this.#closed) {
      if (this.#exit) await this.#exit;
      return;
    }
    this.#rejectPending(this.#error("RPC process is stopping.", "process"));
    child.stdin.destroy();
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
      // Inherited pipes must not keep cleanup waiting after the RPC child exits.
      child.stdout.destroy();
      child.stderr.destroy();
      await exit;
    }
  }

  #acceptStdout(chunk: Buffer): void {
    if (this.#closed || this.#failed) return;
    this.#stdout = Buffer.concat([this.#stdout, chunk]);
    for (;;) {
      const newline = this.#stdout.indexOf(0x0a);
      if (newline < 0) return;
      let record = this.#stdout.subarray(0, newline);
      this.#stdout = this.#stdout.subarray(newline + 1);
      if (record.at(-1) === 0x0d) record = record.subarray(0, -1);
      this.#acceptRecord(record);
      if (this.#failed) {
        this.#stdout = Buffer.alloc(0);
        return;
      }
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
        const type = message.type;
        this.#redactPayload(message);
        message.type = type;
        for (const listener of this.#listeners) {
          try {
            listener(message as RpcEvent);
          } catch {
            // Observer failures are not malformed process traffic.
          }
        }
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
      typeof message.success !== "boolean" ||
      (message.error !== undefined && typeof message.error !== "string")
    ) {
      throw new Error("response envelope is invalid");
    }
    const pending = this.#pending.get(message.id);
    if (!pending) throw new Error(`response correlation is unknown: ${message.id}`);
    if (message.command !== pending.command) throw new Error("response command does not match request");
    if (message.success) message.data = this.#redactPayload(message.data);
    this.#takePending(message.id);
    const response = message as unknown as RpcResponse;
    if (!response.success) {
      pending.reject(this.#error(response.error || `RPC command ${response.command} failed.`, "request"));
      return;
    }
    pending.resolve(response);
  }

  #failProtocol(message: string): void {
    if (this.#failed || this.#closed) return;
    this.#failed = true;
    this.#rejectPending(this.#error(message, "protocol"));
    void this.stop().catch(() => undefined);
  }

  #handleExit(code: number | null, signal: NodeJS.Signals | null): void {
    if (this.#closed) return;
    this.#closed = true;
    clearTimeout(this.#closeTimer);
    const trailing = this.#stdout.length > 0 ? " with an unterminated stdout record" : "";
    const detail = signal ? `signal ${signal}` : `code ${code ?? "unknown"}`;
    const stderr = this.getStderr().trim();
    const suffix = stderr ? `: ${stderr}` : "";
    this.#rejectPending(this.#error(`RPC process exited with ${detail}${trailing}${suffix}`, "process"));
    this.#resolveExit?.();
    this.#resolveExit = undefined;
    this.#listeners.clear();
    this.#process = undefined;
  }

  #handleProcessError(error: unknown): void {
    if (this.#closed || this.#failed) return;
    this.#failed = true;
    this.#rejectPending(this.#error(`RPC process failed: ${errorMessage(error)}`, "process"));
    if (!this.#process?.pid) {
      this.#handleExit(null, null);
      return;
    }
    void this.stop().catch(() => undefined);
  }

  #takePending(id: string): PendingRequest | undefined {
    const pending = this.#pending.get(id);
    if (!pending) return undefined;
    this.#pending.delete(id);
    clearTimeout(pending.timer);
    return pending;
  }

  #rejectPending(error: Error): void {
    for (const pending of this.#pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.#pending.clear();
  }

  #redactPayload(value: unknown): unknown {
    if (!this.#options.redact) return value;
    if (typeof value === "string") return this.#redact(value);
    const remaining: unknown[] = [value];
    while (remaining.length > 0) {
      const item = remaining.pop();
      if (!item || typeof item !== "object") continue;
      const record = item as Record<string, unknown>; // Only parsed JSON objects/arrays reach this boundary.
      for (const key of Object.keys(record)) {
        const child = record[key];
        if (typeof child === "string") record[key] = this.#redact(child);
        else if (child && typeof child === "object") remaining.push(child);
      }
    }
    return value;
  }

  #error(message: string, kind: JsonlRpcError["kind"]): JsonlRpcError {
    return new JsonlRpcError(this.#redact(message), kind);
  }

  #redact(text: string): string {
    return this.#options.redact ? this.#options.redact(text) : text;
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
