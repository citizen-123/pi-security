// Scan-local and external output writes that never follow symbolic links out of a verified directory. Port of
// write_scan_local_bytes, external_output_path, write_external_output_bytes, _remove_scan_local_file_if_exists, and
// _write_scan_local_json in scripts/finalize_scan_contract.py.
//
// Python holds a descriptor for each directory and works relative to it (openat, mkdirat, renameat, unlinkat), so a
// directory swapped for a symlink after it was checked cannot redirect a write. Node has no *at calls, but on Linux a
// path through /proc/self/fd/N resolves to the held directory itself, which gives the same guarantee. Elsewhere the
// held directory's canonical path is used after checking that it still names the same device and inode; a
// concurrent swap between that check and the operation is not detected there.
import { randomBytes } from "node:crypto";
import { closeSync, constants, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { contractJsonBytes } from "./canonical-json.js";
import { requirePortableRelativePath, windowsUnsafePathComponent } from "./contract-paths.js";
import { ContractError } from "./contract-error.js";
import { requireScanDirectory } from "./scan-files.js";

const DIRECTORY_FLAGS = constants.O_RDONLY | (constants.O_DIRECTORY ?? 0) | (constants.O_NOFOLLOW ?? 0);
const errorCode = (error: unknown) => (error as NodeJS.ErrnoException).code;

/** An open directory and a path that reaches it. */
type HeldDirectory = { fd: number; canonical: string };

function heldPath(directory: HeldDirectory): string {
  if (process.platform === "linux") return `/proc/self/fd/${directory.fd}`;
  const opened = fstatSync(directory.fd);
  const named = lstatSync(directory.canonical);
  if (!named.isDirectory() || named.dev !== opened.dev || named.ino !== opened.ino) {
    throw new ContractError("scan directory: changed while it was being opened");
  }
  return directory.canonical;
}

/** _open_verified_scan_directory without an expected identity. */
function openVerifiedScanDirectory(scanDir: string): HeldDirectory {
  let fd: number;
  let observed;
  try {
    observed = lstatSync(resolve(scanDir));
    const canonical = requireScanDirectory(scanDir);
    fd = openSync(canonical, DIRECTORY_FLAGS);
    const opened = fstatSync(fd);
    if (opened.dev !== observed.dev || opened.ino !== observed.ino) {
      closeSync(fd);
      throw new ContractError("scan directory: changed while it was being opened");
    }
    return { fd, canonical };
  } catch (error) {
    if (error instanceof ContractError) throw error;
    throw new ContractError("scan directory: expected an existing non-symlink directory");
  }
}

/** _open_scan_local_directory: descend through `parts`, optionally creating them, never following a symlink. */
function openScanLocalDirectory(root: HeldDirectory, parts: string[], create: boolean): HeldDirectory {
  // os.dup: reopen the held directory as "<path>/." (the /proc/self/fd/N link itself would fail O_NOFOLLOW).
  let current: HeldDirectory = { fd: openSync(`${heldPath(root)}/.`, DIRECTORY_FLAGS), canonical: root.canonical };
  try {
    for (const part of parts) {
      const base = heldPath(current);
      if (create) {
        try {
          mkdirSync(join(base, part), 0o700);
        } catch (error) {
          if (errorCode(error) !== "EEXIST") throw error;
        }
      }
      const next = { fd: openSync(join(base, part), DIRECTORY_FLAGS), canonical: join(current.canonical, part) };
      closeSync(current.fd);
      current = next;
    }
    return current;
  } catch (error) {
    closeSync(current.fd);
    throw error;
  }
}

/** PurePosixPath(value).parts for a relative value: empty and "." components dropped. */
const posixParts = (value: string) => value.split("/").filter((part) => part !== "" && part !== ".");

/** Atomically write `payload` to a regular file inside `scanDir`, creating missing parent directories. */
export function writeScanLocalBytes(scanDir: string, relativePath: string, payload: Uint8Array, { externalName = false } = {}): void {
  const root = requireScanDirectory(scanDir);
  let parts: string[];
  if (externalName) {
    parts = posixParts(relativePath);
    if (parts.length === 0 || parts.some((part) => part === ".." || part.includes("\0"))) {
      throw new ContractError("external output path: expected a safe file name");
    }
    if (process.platform === "win32" && parts.some(windowsUnsafePathComponent)) {
      throw new ContractError("external output path: expected a portable file name");
    }
  } else {
    relativePath = requirePortableRelativePath(relativePath, "scan-local output path");
    parts = relativePath.split("/");
  }
  const name = parts.at(-1)!;
  const held = openVerifiedScanDirectory(root);
  let parent: HeldDirectory | undefined;
  let temporary: string | undefined;
  try {
    try {
      parent = openScanLocalDirectory(held, parts.slice(0, -1), true);
    } catch (error) {
      if (error instanceof ContractError) throw error;
      throw new ContractError(`${relativePath}: expected a path inside the scan directory`);
    }
    const base = heldPath(parent);
    const target = join(base, name);
    let metadata;
    try {
      metadata = lstatSync(target);
    } catch (error) {
      if (errorCode(error) !== "ENOENT") throw error;
    }
    if (metadata !== undefined) {
      if (!metadata.isFile()) throw new ContractError(`${relativePath}: expected a regular non-symlink file`);
      let existing: number | undefined;
      try {
        existing = openSync(target, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
      } catch (error) {
        if (!["ENOENT", "EACCES", "EPERM"].includes(errorCode(error) ?? "")) throw error;
      }
      if (existing !== undefined) {
        try {
          const opened = fstatSync(existing);
          if (!opened.isFile()) throw new ContractError(`${relativePath}: expected a regular non-symlink file`);
          if (opened.dev !== metadata.dev || opened.ino !== metadata.ino) {
            throw new ContractError(`${relativePath}: changed while it was being opened`);
          }
        } finally {
          closeSync(existing);
        }
      }
    }
    temporary = join(base, `.${basename(name)}.${randomBytes(8).toString("hex")}.tmp`);
    const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
    try {
      for (let offset = 0; offset < payload.length; ) offset += writeSync(fd, payload, offset);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(temporary, target);
    temporary = undefined;
  } finally {
    if (temporary !== undefined) {
      try {
        unlinkSync(temporary);
      } catch (error) {
        if (errorCode(error) !== "ENOENT") throw error;
      }
    }
    if (parent !== undefined) closeSync(parent.fd);
    closeSync(held.fd);
  }
}

/** external_output_path: absolute and lexically normalized, with `~` expanded, without resolving symlinks. */
export function externalOutputPath(output: string): string {
  if (output.includes("\0")) throw new ContractError("external output path: expected a valid path");
  const expanded = output === "~" || output.startsWith("~/") ? homedir() + output.slice(1) : output;
  return resolve(expanded);
}

/** Atomically write an external output without following swapped parent links. */
export function writeExternalOutputBytes(output: string, payload: Uint8Array): void {
  const absolute = externalOutputPath(output);
  let parent = dirname(absolute);
  const missing: string[] = [];
  for (;;) {
    let metadata;
    try {
      metadata = lstatSync(parent);
    } catch (error) {
      if (errorCode(error) !== "ENOENT") throw new ContractError("external output path: unable to inspect output directory");
      if (parent === dirname(parent)) throw new ContractError("external output path: no existing directory ancestor");
      missing.push(basename(parent));
      parent = dirname(parent);
      continue;
    }
    if (!metadata.isDirectory()) throw new ContractError("external output path: expected a non-symlink directory parent");
    break;
  }
  writeScanLocalBytes(parent, [...missing.reverse(), basename(absolute)].join("/"), payload, { externalName: true });
}

/** Remove a scan-local regular file or symlink if present; anything else is refused. */
export function removeScanLocalFileIfExists(scanDir: string, relativePath: string): void {
  const root = requireScanDirectory(scanDir);
  const normalized = requirePortableRelativePath(relativePath, "scan-local cleanup path");
  const parts = normalized.split("/");
  const held = openVerifiedScanDirectory(root);
  let parent: HeldDirectory | undefined;
  try {
    parent = openScanLocalDirectory(held, parts.slice(0, -1), false);
    const target = join(heldPath(parent), parts.at(-1)!);
    let metadata;
    try {
      metadata = lstatSync(target);
    } catch (error) {
      if (errorCode(error) === "ENOENT") return;
      throw error;
    }
    if (!metadata.isFile() && !metadata.isSymbolicLink()) {
      throw new ContractError(`${normalized}: expected a regular file or symlink`);
    }
    unlinkSync(target);
  } finally {
    if (parent !== undefined) closeSync(parent.fd);
    closeSync(held.fd);
  }
}

/** _write_scan_local_json: canonical contract JSON for `relativePath`. */
export function writeScanLocalJson(scanDir: string, relativePath: string, payload: unknown): void {
  writeScanLocalBytes(scanDir, relativePath, contractJsonBytes(relativePath, payload));
}
