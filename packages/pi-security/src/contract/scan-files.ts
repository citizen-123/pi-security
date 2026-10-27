// Scan-local file access that never follows symbolic links out of a verified directory.
// Port of the read side of scripts/finalize_scan_contract.py (_require_scan_directory,
// open_scan_local_file_descriptor).
//
// Python walks each component with openat(O_NOFOLLOW). Node has no openat, so a file is opened by full path with
// O_NOFOLLOW (guarding the last component) and the opened descriptor's real path must equal the requested path
// exactly, which rejects symlinked parent directories too. Where /proc/self/fd is unavailable the check uses
// realpath plus the opened file's device and inode, as src/execution-boundary.ts does.
import { closeSync, constants, fstatSync, lstatSync, openSync, readlinkSync, realpathSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { requirePortableRelativePath } from "./contract-paths.js";
import { ContractError } from "./contract-error.js";

const caseInsensitive = process.platform === "win32" || process.platform === "darwin";
const normcase = (path: string) => (process.platform === "win32" ? path.toLowerCase() : path);

/** An existing, canonical, non-symlink directory. */
export function requireScanDirectory(scanDir: string): string {
  const absolute = resolve(scanDir);
  const fail = (message = "scan directory: expected an existing non-symlink directory") => new ContractError(message);
  let metadata;
  try {
    metadata = lstatSync(absolute);
  } catch {
    throw fail();
  }
  if (!metadata.isDirectory()) throw fail();
  let canonical: string;
  try {
    canonical = realpathSync(absolute);
  } catch {
    throw fail();
  }
  if (normcase(canonical) !== normcase(absolute)) throw fail("scan directory: expected a canonical non-symlink directory");
  return canonical;
}

function insideDirectory(root: string, path: string): boolean {
  const inside = relative(root, path);
  return inside === "" || (inside !== ".." && !inside.startsWith(`..${sep}`) && !isAbsolute(inside));
}

function openedRealPath(descriptor: number, requested: string): string | undefined {
  if (process.platform === "linux") {
    try {
      return realpathSync(`/proc/self/fd/${descriptor}`);
    } catch {
      return undefined;
    }
  }
  try {
    const canonical = realpathSync(requested);
    const opened = fstatSync(descriptor);
    const current = statSync(canonical);
    return current.dev === opened.dev && current.ino === opened.ino ? canonical : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Open a regular file inside `scanDir` for reading. The caller owns the returned descriptor. Messages match
 * open_scan_local_file_descriptor.
 */
export function openScanLocalFile(scanDir: string, relativePath: string, context: string): number {
  const root = requireScanDirectory(scanDir);
  const normalized = requirePortableRelativePath(relativePath, context);
  const requested = join(root, ...normalized.split("/"));
  let descriptor: number;
  try {
    descriptor = openSync(requested, constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_NONBLOCK ?? 0));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ELOOP") {
      // A symlink as the last component: say whether it would have stayed inside the scan directory.
      try {
        const target = readlinkSync(requested);
        const absolute = isAbsolute(target) ? target : join(dirname(requested), target);
        if (insideDirectory(root, resolve(absolute))) {
          throw new ContractError(`${context}: expected a regular non-symlink file`);
        }
      } catch (inner) {
        if (inner instanceof ContractError) throw inner;
      }
    }
    throw new ContractError(`${context}: expected a file inside the scan directory`);
  }
  try {
    const real = openedRealPath(descriptor, requested);
    if (real === undefined || (caseInsensitive ? real.toLowerCase() !== requested.toLowerCase() : real !== requested)) {
      throw new ContractError(`${context}: expected a file inside the scan directory`);
    }
    if (!fstatSync(descriptor).isFile()) throw new ContractError(`${context}: expected a regular non-symlink file`);
    return descriptor;
  } catch (error) {
    closeSync(descriptor);
    throw error;
  }
}

/** _require_scan_local_file: a regular file inside `scanDir`. */
export function requireScanLocalFile(scanDir: string, relativePath: string, context: string): void {
  closeSync(openScanLocalFile(scanDir, relativePath, context));
}
