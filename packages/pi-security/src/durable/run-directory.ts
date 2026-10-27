// Run directories under the pi-security state directory (design D2):
//
//   $PI_SECURITY_STATE_DIR (default $PI_HOME/security, PI_HOME default ~/.pi)
//     runs/<run-id>/   0700: run.lock, run.sqlite (0600, WAL files inherit its mode), scan/, worktree/
//
// Run storage holds every tool output, including repository content, so directories are private to the user.
import { randomBytes } from "node:crypto";
import { chmodSync, closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

export class RunDirectoryError extends Error {
  override name = "RunDirectoryError";
}

const RUN_ID = /^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$/;

const expandHome = (value: string) => (value === "~" ? homedir() : value.startsWith("~/") ? join(homedir(), value.slice(2)) : value);

/** The state directory: PI_SECURITY_STATE_DIR, else $PI_HOME/security. Relative values resolve against `cwd`. */
export function resolveStateDirectory(env: NodeJS.ProcessEnv = process.env, cwd: string = process.cwd()): string {
  const explicit = env.PI_SECURITY_STATE_DIR?.trim();
  if (explicit) return resolve(cwd, expandHome(explicit));
  return resolve(cwd, expandHome(env.PI_HOME?.trim() || "~/.pi"), "security");
}

/** A new run ID: UTC creation time, then 8 random hex digits (the run's short ID). Sorts by creation time. */
export function newRunId(now: Date = new Date()): string {
  const stamp = now.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
  return `${stamp}-${randomBytes(4).toString("hex")}`;
}

export function requireRunId(value: string): string {
  if (!RUN_ID.test(value)) throw new RunDirectoryError(`invalid run id: ${JSON.stringify(value)}`);
  return value;
}

/** The run's short ID, used where a full ID is too long (fix branch names). */
export const shortRunId = (runId: string) => requireRunId(runId).slice(-8);

/** Create `path` (and missing parents) as a private directory; an existing one must be a real directory. */
export function ensurePrivateDirectory(path: string): string {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const metadata = lstatSync(path);
  if (!metadata.isDirectory()) throw new RunDirectoryError(`${path}: expected a directory, not a symlink or file`);
  if (process.platform !== "win32" && (metadata.mode & 0o077) !== 0) chmodSync(path, 0o700);
  return path;
}

/** Create `path` as an empty 0600 file if missing; an existing one must be a regular file. */
export function ensurePrivateFile(path: string): string {
  const descriptor = openSync(path, constants.O_RDWR | constants.O_CREAT | (constants.O_NOFOLLOW ?? 0), 0o600);
  try {
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile()) throw new RunDirectoryError(`${path}: expected a regular file`);
    if (process.platform !== "win32" && (metadata.mode & 0o077) !== 0) chmodSync(path, 0o600);
  } finally {
    closeSync(descriptor);
  }
  return path;
}

export type RunPaths = {
  readonly runId: string;
  readonly directory: string;
  readonly lock: string;
  readonly storage: string;
  readonly scan: string;
  readonly worktree: string;
};

export function runPaths(stateDirectory: string, runId: string): RunPaths {
  const directory = join(stateDirectory, "runs", requireRunId(runId));
  return {
    runId,
    directory,
    lock: join(directory, "run.lock"),
    storage: join(directory, "run.sqlite"),
    scan: join(directory, "scan"),
    worktree: join(directory, "worktree")
  };
}

/** Create the run directory (and the state directory above it) privately. */
export function ensureRunDirectory(paths: RunPaths): RunPaths {
  ensurePrivateDirectory(resolve(paths.directory, "..", ".."));
  ensurePrivateDirectory(resolve(paths.directory, ".."));
  ensurePrivateDirectory(paths.directory);
  return paths;
}
