// Opening and closing a run's durable Harness (design D2, D12). Every import from pi-durable and chord lives under
// src/durable/, against the exactly pinned 1.4.0 published types.
//
// Order: lock, private run directory, storage, Harness.open; close in reverse. Harness.close closes storage too.
import { BACKGROUND_CONTEXT } from "@earendil-works/chord/context";
import { Harness, type HarnessOptions, type ToolRegistration } from "@earendil-works/pi-durable";
import { openNodeSqliteStorage } from "@earendil-works/pi-durable/storage/sqlite/node";
import { ensurePrivateFile, ensureRunDirectory, type RunPaths } from "./run-directory.js";
import { acquireRunLock, type RunLock } from "./run-lock.js";

export { Harness };
export type { HarnessOptions };

/** The context for host-initiated durable calls: the CLI process owns the run for its whole lifetime. */
export const RUN_CONTEXT = BACKGROUND_CONTEXT;

export type OpenRun = {
  readonly paths: RunPaths;
  readonly harness: Harness;
  readonly lock: RunLock;
  /** Close the Harness (and its storage), then release the lock. Safe to call more than once. */
  close(): Promise<void>;
};

/**
 * Open a run as its only writer. Throws RunLockedError when another live process holds the run. Scheduling stays off
 * until the caller calls `harness.resume()` or a call that asks for progress.
 */
export async function openRun<Tool extends ToolRegistration>(paths: RunPaths, options: HarnessOptions<Tool>): Promise<OpenRun> {
  ensureRunDirectory(paths);
  const lock = acquireRunLock(paths.lock);
  let harness: Harness | undefined;
  try {
    // SQLite gives the WAL and shared-memory files the database file's mode, so creating it 0600 covers all three.
    ensurePrivateFile(paths.storage);
    const storage = await openNodeSqliteStorage(paths.storage);
    try {
      harness = await Harness.open(storage, options, RUN_CONTEXT);
    } catch (error) {
      await storage.close(RUN_CONTEXT).catch(() => {});
      throw error;
    }
  } catch (error) {
    lock.release();
    throw error;
  }
  let closing: Promise<void> | undefined;
  const opened = harness;
  return {
    paths,
    harness: opened,
    lock,
    close: () =>
      (closing ??= (async () => {
        try {
          await opened.close(RUN_CONTEXT);
        } finally {
          lock.release();
        }
      })())
  };
}
