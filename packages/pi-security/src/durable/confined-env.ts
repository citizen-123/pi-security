// The ExecutionEnv every scan conversation gets (design D7): reads of the scan target through ConfinedRoot, and
// nothing else. Writes, removals, temporary files, watching, and command execution are refused.
//
// Each read verifies its path through ConfinedRoot (inside root and scope, no symbolic link in any component) and is
// then served by pi-durable's NodeExecutionEnv with symbolic links never followed, so permitted reads behave exactly
// like the stock environment. A path swapped by another process between the check and the read is not caught here;
// that needs a concurrent same-user process, which AGENTS.md trusts, while links planted in the repository are static
// and refused. Package tools read through ConfinedRoot.readFile, which also verifies the opened descriptor; this
// adapter keeps any tool that expects an environment inside the same boundary.
import type { Context } from "@earendil-works/chord";
import {
  type BinaryReader,
  type DirReader,
  type ExecutionEnv,
  ExecutionError,
  FileError,
  type FileErrorCode,
  type FileInfo,
  type FileWatcher,
  type Result,
  type ShellExecResult,
  type TextLineReader,
  err
} from "@earendil-works/pi-durable/env";
import { NodeExecutionEnv } from "@earendil-works/pi-durable/env/node";
import { ConfinedRoot, ConfinementError, type ConfinementErrorCode } from "../target/confined-root.js";

const CODES: Record<ConfinementErrorCode, FileErrorCode> = {
  not_found: "not_found",
  escape: "permission_denied",
  symlink: "permission_denied",
  not_directory: "not_directory",
  is_directory: "is_directory",
  invalid: "invalid"
};

const refused = <T>(what: string, path?: string): Result<T, FileError> =>
  err(new FileError("permission_denied", `${what} is not allowed: the scan target is read-only`, path));

export class ConfinedEnv implements ExecutionEnv {
  readonly id: string;
  cwd: string;
  private readonly node: NodeExecutionEnv;

  constructor(readonly confined: ConfinedRoot) {
    this.id = `pi-security-confined:${confined.root}`;
    this.cwd = confined.root;
    this.node = new NodeExecutionEnv({ cwd: confined.root, shellEnv: {} });
  }

  /** Verify a path; on success the absolute path to hand to the stock environment. */
  private verify(path: string, allowMissing = false): Result<string, FileError> {
    try {
      const entry = this.confined.inspect(path);
      return { ok: true, value: this.confined.absolutePath(entry.path) };
    } catch (error) {
      if (!(error instanceof ConfinementError)) throw error;
      if (allowMissing && error.code === "not_found") return { ok: true, value: this.confined.absolutePath(this.confined.relativePath(path)) };
      return err(new FileError(CODES[error.code], error.message, path));
    }
  }

  private async read<T>(path: string, use: (absolute: string) => Promise<Result<T, FileError>>): Promise<Result<T, FileError>> {
    const verified = this.verify(path);
    return verified.ok ? use(verified.value) : verified;
  }

  async absolutePath(path: string, _context: Context): Promise<Result<string, FileError>> {
    try {
      return { ok: true, value: this.confined.absolutePath(this.confined.relativePath(path)) };
    } catch (error) {
      if (!(error instanceof ConfinementError)) throw error;
      return err(new FileError(CODES[error.code], error.message, path));
    }
  }

  joinPath(parts: string[], context: Context): Promise<Result<string, FileError>> {
    return this.node.joinPath(parts, context);
  }

  readTextFile(path: string, context: Context) {
    return this.read(path, (absolute) => this.node.readTextFile(absolute, context));
  }

  openTextLineReader(path: string, context: Context): Promise<Result<TextLineReader, FileError>> {
    return this.read(path, (absolute) => this.node.openTextLineReader(absolute, context));
  }

  readTextLines(path: string, options: { maxLines?: number } | undefined, context: Context) {
    return this.read(path, (absolute) => this.node.readTextLines(absolute, options, context));
  }

  readBinaryFile(path: string, context: Context) {
    return this.read(path, (absolute) => this.node.readBinaryFile(absolute, context));
  }

  openBinaryReader(path: string, _options: { noFollow?: boolean } | undefined, context: Context): Promise<Result<BinaryReader, FileError>> {
    return this.read(path, (absolute) => this.node.openBinaryReader(absolute, { noFollow: true }, context));
  }

  fileInfo(path: string, context: Context): Promise<Result<FileInfo, FileError>> {
    return this.read(path, (absolute) => this.node.fileInfo(absolute, context));
  }

  listDir(path: string, context: Context): Promise<Result<FileInfo[], FileError>> {
    return this.read(path, (absolute) => this.node.listDir(absolute, context));
  }

  openDirReader(path: string, context: Context): Promise<Result<DirReader, FileError>> {
    return this.read(path, (absolute) => this.node.openDirReader(absolute, context));
  }

  async canonicalPath(path: string, _context: Context): Promise<Result<string, FileError>> {
    // With no symbolic link in any component, the verified path is canonical.
    return this.verify(path);
  }

  async exists(path: string, _context: Context): Promise<Result<boolean, FileError>> {
    const verified = this.verify(path);
    if (verified.ok) return { ok: true, value: true };
    return verified.error.code === "not_found" ? { ok: true, value: false } : verified;
  }

  async writeFile(path: string) {
    return refused<void>("writing", path);
  }
  async appendFile(path: string) {
    return refused<void>("appending", path);
  }
  async truncateFile(path: string) {
    return refused<void>("truncating", path);
  }
  async flushFile(path: string) {
    return refused<void>("flushing", path);
  }
  async renameFile(sourcePath: string) {
    return refused<void>("renaming", sourcePath);
  }
  async createDir(path: string) {
    return refused<void>("creating directories", path);
  }
  async remove(path: string) {
    return refused<void>("removing", path);
  }
  async createTempDir() {
    return refused<string>("creating temporary directories");
  }
  async createTempFile() {
    return refused<string>("creating temporary files");
  }
  async watch(): Promise<Result<FileWatcher, FileError>> {
    return err(new FileError("not_supported", "watching is not available in a scan run"));
  }
  async exec(): Promise<Result<ShellExecResult, ExecutionError>> {
    return err(new ExecutionError("shell_unavailable", "command execution is not available in a scan run"));
  }
  async cleanup(): Promise<void> {}
}

/** HarnessOptions.env for a run over `root`: every conversation gets the same confined, read-only environment. */
export function confinedEnvFactory(root: string, scope = "."): () => ConfinedEnv {
  const env = new ConfinedEnv(ConfinedRoot.open(root, scope));
  return () => env;
}
