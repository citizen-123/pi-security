// The run's exclusive writer lock (design D2). pi-durable allows one process per storage and has no cross-process
// lock of its own, so the lock is taken before Harness.open and released after close.
//
// `run.lock` is a SQLite file held in an open EXCLUSIVE transaction: SQLite's operating-system file lock, which the
// kernel releases when the holding process exits however it exits. There is no stale lock to detect or break, and a
// second connection fails at once, in this process or another. `run.owner` records who holds it, for messages only.
import { randomBytes } from "node:crypto";
import { readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { DatabaseSync } from "node:sqlite";
import { ensurePrivateFile } from "./run-directory.js";

export type RunLockHolder = { readonly pid: number; readonly host: string; readonly startedAt: string; readonly token: string };

export class RunLockedError extends Error {
  override name = "RunLockedError";
  constructor(
    readonly path: string,
    readonly holder: RunLockHolder | undefined
  ) {
    super(
      holder === undefined
        ? `run is open in another process (${path})`
        : `run is open in process ${holder.pid} on ${holder.host}, started ${holder.startedAt} (${path})`
    );
  }
}

export type RunLock = { readonly path: string; readonly holder: RunLockHolder; release(): void };

const SQLITE_BUSY = 5;
export const ownerPath = (lockPath: string) => lockPath.replace(/\.lock$/, ".owner");

function readOwner(path: string): RunLockHolder | undefined {
  try {
    const value = JSON.parse(readFileSync(path, "utf8"));
    return Number.isSafeInteger(value?.pid) && typeof value.host === "string" && typeof value.startedAt === "string" ? value : undefined;
  } catch {
    return undefined;
  }
}

/** Take the run lock or throw RunLockedError. */
export function acquireRunLock(path: string, now: Date = new Date()): RunLock {
  ensurePrivateFile(path);
  const database = new DatabaseSync(path);
  try {
    database.exec("PRAGMA busy_timeout = 0");
    database.exec("BEGIN EXCLUSIVE");
  } catch (error) {
    database.close();
    if ((error as { errcode?: number }).errcode === SQLITE_BUSY) throw new RunLockedError(path, readOwner(ownerPath(path)));
    throw error;
  }
  const holder: RunLockHolder = { pid: process.pid, host: hostname(), startedAt: now.toISOString(), token: randomBytes(16).toString("hex") };
  const owner = ownerPath(path);
  writeFileSync(owner, `${JSON.stringify(holder)}\n`, { mode: 0o600 });
  let released = false;
  return {
    path,
    holder,
    release: () => {
      if (released) return;
      released = true;
      // The owner file goes first, while the lock still keeps any new holder from writing its own.
      if (readOwner(owner)?.token === holder.token) unlinkSync(owner);
      database.exec("ROLLBACK");
      database.close();
    }
  };
}
