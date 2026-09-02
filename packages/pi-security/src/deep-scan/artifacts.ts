import { randomUUID } from "node:crypto";
import { constants as fsConstants, promises as fs, type Stats } from "node:fs";
import type { FileHandle } from "node:fs/promises";
import { dirname, isAbsolute, join, parse, relative, resolve, sep } from "node:path";
import {
  assertPathInside,
  canonicalBoundDirectory,
} from "../execution-boundary.js";

export interface DeepScanArtifacts {
  scanDir: string;
  deepRoot: string;
  workersRoot: string;
  dedupRoot: string;
}

export interface DiscoveryArtifacts {
  resultPath: string;
}

interface SecureParent {
  handle: FileHandle;
  path: string;
  expectedParentPath: string;
}

export function createDeepScanArtifacts(scanDir: string): DeepScanArtifacts {
  const deepRoot = join(scanDir, "artifacts", "deep_discovery");
  return {
    scanDir,
    deepRoot,
    workersRoot: join(deepRoot, "workers"),
    dedupRoot: join(deepRoot, "dedup")
  };
}

export function discoveryArtifacts(artifactDir: string): DiscoveryArtifacts {
  return {
    resultPath: join(artifactDir, "result.json")
  };
}

export async function ensureDeepScanDirectories(artifacts: DeepScanArtifacts): Promise<void> {
  const scanDir = await canonicalBoundDirectory(artifacts.scanDir, "Deep Scan artifact root");
  const expected = createDeepScanArtifacts(scanDir);
  if (
    resolve(artifacts.deepRoot) !== expected.deepRoot
    || resolve(artifacts.workersRoot) !== expected.workersRoot
    || resolve(artifacts.dedupRoot) !== expected.dedupRoot
  ) {
    throw new Error("Deep Scan artifact directories do not match their authoritative scan root.");
  }
  for (const path of [expected.deepRoot, expected.workersRoot, expected.dedupRoot]) {
    assertPathInside(scanDir, path, "Deep Scan artifact directory");
    const parent = await openSecureParent(
      join(path, ".deep-scan-directory-probe"),
      true,
      "Deep Scan artifact directory"
    );
    try {
      await assertSecureParentStillBound(parent, "Deep Scan artifact directory");
    } finally {
      await parent.handle.close();
    }
  }
}

export async function writePrivateFile(path: string, content: string): Promise<void> {
  const parent = await openSecureParent(path, true, "Deep Scan private file");
  try {
    await assertSecureParentStillBound(parent, "Deep Scan private file");
    const file = await fs.open(
      parent.path,
      secureOpenFlags(
        fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL,
        false,
        "Deep Scan private file"
      ),
      0o600
    );
    try {
      await assertSecureParentStillBound(parent, "Deep Scan private file");
      await file.writeFile(content, { encoding: "utf8" });
    } finally {
      await file.close();
    }
  } finally {
    await parent.handle.close();
  }
}

export async function writeJsonAtomic(path: string, payload: unknown): Promise<void> {
  const parent = await openSecureParent(path, true, "Deep Scan JSON artifact");
  const temporaryPath = join(
    dirname(parent.path),
    `.${randomUUID()}.tmp`
  );
  let temporaryCreated = false;
  try {
    await assertSecureParentStillBound(parent, "Deep Scan JSON artifact");
    const temporary = await fs.open(
      temporaryPath,
      secureOpenFlags(
        fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL,
        false,
        "Deep Scan JSON artifact"
      ),
      0o600
    );
    temporaryCreated = true;
    try {
      await assertSecureParentStillBound(parent, "Deep Scan JSON artifact");
      await temporary.writeFile(`${JSON.stringify(payload, null, 2)}\n`, {
        encoding: "utf8"
      });
    } finally {
      await temporary.close();
    }
    await assertSecureParentStillBound(parent, "Deep Scan JSON artifact");
    await fs.rename(temporaryPath, parent.path);
  } catch (error) {
    if (temporaryCreated) await fs.rm(temporaryPath, { force: true }).catch(() => undefined);
    throw error;
  } finally {
    await parent.handle.close();
  }
}

export async function readJsonObject(path: string): Promise<Record<string, unknown>> {
  let parsed: unknown;
  try {
    const parent = await openSecureParent(path, false, "Deep Scan JSON artifact");
    try {
      await assertSecureParentStillBound(parent, "Deep Scan JSON artifact");
      const file = await openSecureReadFile(parent, "Deep Scan JSON artifact");
      try {
        await assertSecureParentStillBound(parent, "Deep Scan JSON artifact");
        if (!(await file.stat()).isFile()) {
          throw new Error("Deep Scan JSON artifact is not a regular file.");
        }
        parsed = JSON.parse(await file.readFile({ encoding: "utf8" }));
      } finally {
        await file.close();
      }
    } finally {
      await parent.handle.close();
    }
  } catch (error) {
    throw new Error(`Invalid Deep Scan JSON artifact ${path}: ${errorMessage(error)}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`Deep Scan JSON artifact must contain an object: ${path}`);
  }
  return parsed as Record<string, unknown>;
}

export async function requireRegularFile(
  path: string,
  root: string,
  requireContent = true
): Promise<void> {
  const rootPath = await canonicalBoundDirectory(root, "Deep Scan artifact root");
  const requestedPath = absolutePath(path, "Deep Scan artifact");
  assertPathInside(
    rootPath,
    requestedPath,
    `Deep Scan artifact escaped its scan directory: ${path}`,
    true,
  );
  const parent = await openSecureParent(requestedPath, false, "Deep Scan artifact");
  try {
    await assertSecureParentStillBound(parent, "Deep Scan artifact");
    const file = await openSecureReadFile(parent, "Deep Scan artifact");
    try {
      await assertSecureParentStillBound(parent, "Deep Scan artifact");
      const fileStat = await file.stat();
      if (!fileStat.isFile() || (requireContent && fileStat.size === 0)) {
        throw new Error(`Deep Scan artifact is not a valid regular file: ${path}`);
      }
      const resolvedPath = await fs.realpath(parent.path);
      assertPathInside(
        rootPath,
        resolvedPath,
        `Deep Scan artifact escaped its scan directory: ${path}`,
        true,
      );
      assertCanonicalPath(path, resolvedPath);
    } finally {
      await file.close();
    }
  } finally {
    await parent.handle.close();
  }
}

export async function archiveDirectory(source: string, destination: string): Promise<void> {
  const sourcePath = absolutePath(source, "Deep Scan archive source");
  const destinationPath = absolutePath(destination, "Deep Scan archive destination");
  if (sourcePath === destinationPath) {
    throw new Error("Deep Scan archive source and destination must differ.");
  }
  const sourceParent = await openSecureParent(sourcePath, false, "Deep Scan archive source");
  try {
    const destinationParent = await openSecureParent(
      destinationPath,
      true,
      "Deep Scan archive destination"
    );
    try {
      await assertSecureParentStillBound(sourceParent, "Deep Scan archive source");
      await assertSecureParentStillBound(destinationParent, "Deep Scan archive destination");
      const sourceMetadata = await fs.lstat(sourceParent.path).catch((error: unknown) => {
        if (isMissing(error)) return undefined;
        throw error;
      });
      if (sourceMetadata && (sourceMetadata.isSymbolicLink() || !sourceMetadata.isDirectory())) {
        throw new Error(`Deep Scan archive source is not a regular directory: ${source}`);
      }
      await assertSecureParentStillBound(sourceParent, "Deep Scan archive source");
      await assertSecureParentStillBound(destinationParent, "Deep Scan archive destination");
      await fs.rm(destinationParent.path, { recursive: true, force: true });
      if (sourceMetadata) {
        try {
          await assertSecureParentStillBound(sourceParent, "Deep Scan archive source");
          await assertSecureParentStillBound(destinationParent, "Deep Scan archive destination");
          await fs.rename(sourceParent.path, destinationParent.path);
        } catch (error) {
          if (!isMissing(error)) throw error;
        }
      }
      await assertSecureParentStillBound(sourceParent, "Deep Scan archive source");
      await createSecureDirectory(sourceParent.path, "Deep Scan archive source");
      const restored = await openSecureDirectory(sourceParent.path, "Deep Scan archive source");
      await restored.close();
    } finally {
      await destinationParent.handle.close();
    }
  } finally {
    await sourceParent.handle.close();
  }
}

async function openSecureParent(
  path: string,
  createParents: boolean,
  label: string
): Promise<SecureParent> {
  const absolute = absolutePath(path, label);
  const root = parse(absolute).root;
  const components = relative(root, absolute).split(sep).filter(Boolean);
  const name = components.pop();
  if (!name) throw new Error(`${label} must not be a filesystem root.`);

  let directory = await openSecureDirectory(root, label);
  let directoryPath = root;
  try {
    for (const component of components) {
      const childPath = process.platform === "win32"
        ? join(directoryPath, component)
        : join(descriptorDirectoryPath(directory, label), component);
      if (createParents) await createSecureDirectory(childPath, label);
      const child = await openSecureDirectory(childPath, label);
      if (process.platform === "win32") {
        try {
          await assertWindowsDirectoryStillBound(directory, directoryPath, label);
        } catch (error) {
          await child.close();
          throw error;
        }
      }
      await directory.close();
      directory = child;
      directoryPath = childPath;
    }
    return {
      handle: directory,
      path: join(
        process.platform === "win32"
          ? directoryPath
          : descriptorDirectoryPath(directory, label),
        name
      ),
      expectedParentPath: dirname(absolute)
    };
  } catch (error) {
    await directory.close();
    throw error;
  }
}

async function assertSecureParentStillBound(parent: SecureParent, label: string): Promise<void> {
  if (process.platform === "win32") {
    await assertWindowsDirectoryStillBound(parent.handle, parent.expectedParentPath, label);
    return;
  }
  const current = await openSecureParent(
    join(parent.expectedParentPath, ".deep-scan-parent-probe"),
    false,
    label
  );
  try {
    const [expectedMetadata, currentMetadata] = await Promise.all([
      parent.handle.stat(),
      current.handle.stat()
    ]);
    if (
      expectedMetadata.dev !== currentMetadata.dev
      || expectedMetadata.ino !== currentMetadata.ino
    ) {
      throw new Error(`${label} changed while its directory handle was open.`);
    }
  } finally {
    await current.handle.close();
  }
}

async function openSecureDirectory(path: string, label: string): Promise<FileHandle> {
  if (process.platform === "win32") {
    return await openWindowsSecureDirectory(path, label);
  }
  let directory: FileHandle;
  try {
    directory = await fs.open(
      path,
      secureOpenFlags(fsConstants.O_RDONLY, true, label, true)
    );
  } catch (error) {
    throw new Error(`${label} cannot be opened safely.`, { cause: error });
  }
  try {
    if (!(await directory.stat()).isDirectory()) {
      throw new Error(`${label} is not a regular directory.`);
    }
    return directory;
  } catch (error) {
    await directory.close();
    throw error;
  }
}

async function createSecureDirectory(path: string, label: string): Promise<void> {
  try {
    await fs.mkdir(path, { mode: 0o700 });
  } catch (error) {
    if (isAlreadyExists(error)) return;
    throw new Error(`${label} cannot create a directory safely.`, { cause: error });
  }
}

function secureOpenFlags(
  base: number,
  directory: boolean,
  label: string,
  nonBlockingRead = false
): number {
  if (process.platform === "win32") return base;
  const noFollow = fsConstants.O_NOFOLLOW;
  const directoryOnly = fsConstants.O_DIRECTORY;
  if (
    !Number.isInteger(noFollow)
    || noFollow === 0
    || (directory && (!Number.isInteger(directoryOnly) || directoryOnly === 0))
  ) {
    throw new Error(`${label} requires no-follow directory-handle support.`);
  }
  const nonBlocking = fsConstants.O_NONBLOCK;
  if (
    nonBlockingRead
    && (!Number.isInteger(nonBlocking) || nonBlocking === 0)
  ) {
    throw new Error(`${label} requires nonblocking pre-stat open support.`);
  }
  return base
    | noFollow
    | (directory ? directoryOnly : 0)
    | (nonBlockingRead ? nonBlocking : 0);
}

function descriptorDirectoryPath(handle: FileHandle, label: string): string {
  const root = process.platform === "linux"
    ? "/proc/self/fd"
    : process.platform === "win32"
      ? undefined
      : "/dev/fd";
  if (!root) throw new Error(`${label} requires descriptor-backed directory paths.`);
  return join(root, String(handle.fd));
}

async function openSecureReadFile(
  parent: SecureParent,
  label: string
): Promise<FileHandle> {
  if (process.platform !== "win32") {
    try {
      return await fs.open(
        parent.path,
        secureOpenFlags(fsConstants.O_RDONLY, false, label, true)
      );
    } catch (error) {
      throw new Error(`${label} cannot be opened safely.`, { cause: error });
    }
  }
  const before = await safeWindowsPathIdentity(parent.path, label);
  let file: FileHandle;
  try {
    file = await fs.open(parent.path, fsConstants.O_RDONLY);
  } catch (error) {
    throw new Error(`${label} cannot be opened safely.`, { cause: error });
  }
  try {
    const opened = await file.stat();
    assertSameIdentity(before.metadata, opened, label);
    await assertSecureParentStillBound(parent, label);
    const after = await safeWindowsPathIdentity(parent.path, label);
    assertSameIdentity(opened, after.metadata, label);
    return file;
  } catch (error) {
    await file.close();
    throw error;
  }
}

async function openWindowsSecureDirectory(path: string, label: string): Promise<FileHandle> {
  const before = await safeWindowsPathIdentity(path, label);
  if (!before.metadata.isDirectory()) {
    throw new Error(`${label} is not a regular directory.`);
  }
  let directory: FileHandle;
  try {
    directory = await fs.open(before.canonicalPath, fsConstants.O_RDONLY);
  } catch (error) {
    throw new Error(`${label} cannot be opened safely.`, { cause: error });
  }
  try {
    const opened = await directory.stat();
    if (!opened.isDirectory()) {
      throw new Error(`${label} is not a regular directory.`);
    }
    assertSameIdentity(before.metadata, opened, label);
    const after = await safeWindowsPathIdentity(before.canonicalPath, label);
    assertSameIdentity(opened, after.metadata, label);
    return directory;
  } catch (error) {
    await directory.close();
    throw error;
  }
}

async function assertWindowsDirectoryStillBound(
  expected: FileHandle,
  path: string,
  label: string
): Promise<void> {
  const current = await openWindowsSecureDirectory(path, label);
  try {
    const [expectedMetadata, currentMetadata] = await Promise.all([
      expected.stat(),
      current.stat()
    ]);
    assertSameIdentity(
      expectedMetadata,
      currentMetadata,
      `${label} changed while its directory handle was open.`
    );
  } finally {
    await current.close();
  }
}

interface WindowsPathIdentity {
  canonicalPath: string;
  metadata: Stats;
}

async function safeWindowsPathIdentity(
  path: string,
  label: string
): Promise<WindowsPathIdentity> {
  const metadata = await fs.lstat(path).catch(() => undefined);
  if (!metadata || metadata.isSymbolicLink()) {
    throw new Error(`${label} is a reparse point and cannot be accessed.`);
  }
  const canonicalPath = await fs.realpath(path).catch(() => undefined);
  if (
    !canonicalPath
    || resolve(path).toLowerCase() !== resolve(canonicalPath).toLowerCase()
  ) {
    throw new Error(`${label} is a reparse point and cannot be accessed.`);
  }
  return { canonicalPath, metadata };
}

function assertSameIdentity(expected: Stats, actual: Stats, label: string): void {
  if (expected.dev !== actual.dev || expected.ino !== actual.ino) {
    throw new Error(label);
  }
}


function absolutePath(path: string, label: string): string {
  if (typeof path !== "string" || !path || !isAbsolute(path)) {
    throw new Error(`${label} must be an absolute path.`);
  }
  return resolve(path);
}

function assertCanonicalPath(path: string, resolvedPath: string): void {
  if (relative(resolve(path), resolvedPath) === "") return;
  throw new Error(`Deep Scan artifact must use a canonical non-symlink path: ${path}`);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isAlreadyExists(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && error.code === "EEXIST");
}

function isMissing(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && error.code === "ENOENT");
}
