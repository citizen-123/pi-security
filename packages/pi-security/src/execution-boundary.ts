import {
  constants as fsConstants,
  promises as fs,
  type Dirent,
  type Stats,
} from "node:fs";
import type { FileHandle } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep, win32 } from "node:path";
import {
  assertExecutionCapability,
  type ExecutionPolicyContext,
} from "./execution-policy.js";
import {
  EnforcementUnsupportedError,
  type PlatformEnforcementMechanism,
} from "./enforcement-capabilities.js";

export type BoundPathKind = "file" | "directory" | "any";

export interface ResolvedExecutionPath {
  absolute: string;
  relative: string;
  metadata?: Stats;
}

export interface OpenedExecutionPath extends ResolvedExecutionPath {
  handle: FileHandle;
  metadata: Stats;
}
export class UnsupportedDirectoryHandleEnforcementError
  extends EnforcementUnsupportedError {
  constructor(label: string) {
    super(
      `${label} cannot be enforced securely on this platform: `
      + "verified no-follow directory handles are unsupported.",
    );
    this.name = "UnsupportedDirectoryHandleEnforcementError";
  }
}


interface TargetPathOptions {
  capability: "target.read" | "target.search" | "target.git";
  expected: BoundPathKind;
  scope?: string;
  label?: string;
}

interface ScanPathOptions {
  expected?: BoundPathKind;
  allowMissing?: boolean;
  allowRoot?: boolean;
  label?: string;
}

/** Run only the bundled application workbench, never a target command. */
export function executeTrustedWorkbench<Value>(
  context: ExecutionPolicyContext,
  operation: () => Value,
): Value {
  assertExecutionCapability(context, "workbench.execute");
  return operation();
}

/** Resolve one model-facing repository path under its issued target and scope. */
export async function resolveExecutionTargetPath(
  context: ExecutionPolicyContext,
  input: string,
  options: TargetPathOptions,
): Promise<ResolvedExecutionPath> {
  const opened = await openExecutionTargetPath(context, input, options);
  try {
    return {
      absolute: opened.absolute,
      relative: opened.relative,
      metadata: opened.metadata,
    };
  } finally {
    await opened.handle.close();
  }
}

/**
 * Open one target path and validate the opened inode, not a pathname checked
 * before I/O. Callers must keep the returned handle open through their read.
 */
export async function openExecutionTargetPath(
  context: ExecutionPolicyContext,
  input: string,
  options: TargetPathOptions,
): Promise<OpenedExecutionPath> {
  assertExecutionCapability(context, options.capability);
  const label = options.label ?? "The requested target path";
  const relativeInput = requireRepositoryRelativePath(input, label);
  const root = await canonicalBoundDirectory(
    context.target.root,
    "Pi Security execution target root",
  );
  const scope = await resolveTargetScope(root, options.scope ?? ".", label);
  const requested = resolve(root, relativeInput);
  assertPathInside(root, requested, label, true);
  assertPathInside(scope, requested, label, true);
  return await openVerifiedPath(root, scope, requested, options.expected, label);
}

/**
 * Open a host-created worker input under the auxiliary scan root carried by an
 * issued source context. This is intentionally read-only and does not grant a
 * source worker the scan-artifact writer capability.
 */
export async function openExecutionWorkerInput(
  context: ExecutionPolicyContext,
  input: string,
  expected: BoundPathKind,
  label: string,
): Promise<OpenedExecutionPath> {
  assertExecutionCapability(context, "target.read");
  if (typeof input !== "string" || !input || !isAbsolute(input)) {
    throw new Error(`${label} must be an absolute path.`);
  }
  const root = await canonicalBoundDirectory(
    context.scan.artifactRoot,
    "Pi Security execution worker input root",
  );
  const requested = resolve(input);
  assertPathInside(root, requested, label, true);
  return await openVerifiedPath(root, root, requested, expected, label);
}

/** Enumerate only after every child is revalidated through its root-bound path. */
export async function readOpenedDirectory(
  opened: OpenedExecutionPath,
  label: string,
  validateChild: (entry: Dirent) => Promise<void>,
  platform: NodeJS.Platform = process.platform,
): Promise<Dirent[]> {
  assertExpectedKind(opened.metadata, "directory", label);
  await assertOpenedDirectoryIdentity(opened, label, platform);
  let entries: Dirent[];
  try {
    if (platform === "win32") {
      entries = await fs.readdir(opened.absolute, { withFileTypes: true });
    } else {
      const descriptorPath = await secureDirectoryDescriptorPath(
        opened.handle,
        opened.metadata,
        label,
        platform,
      );
      entries = await fs.readdir(descriptorPath, { withFileTypes: true });
    }
  } catch (error) {
    throw new Error(`${label} cannot be read through its verified handle.`, {
      cause: error,
    });
  }

  const childIdentities = new Map<string, Stats>();
  for (const entry of entries) {
    if (platform === "win32") {
      childIdentities.set(
        entry.name,
        await safeWindowsEntryIdentity(opened.absolute, entry.name, label),
      );
    }
    await validateChild(entry);
  }
  if (platform === "win32") {
    for (const [name, expected] of childIdentities) {
      const current = await safeWindowsEntryIdentity(opened.absolute, name, label);
      assertSameIdentity(expected, current, `${label} child ${JSON.stringify(name)}`);
    }
  }
  await assertOpenedDirectoryIdentity(opened, label, platform);
  return entries;
}

/** Verify that an application artifact path remains under the issued scan root. */
export async function resolveExecutionScanPath(
  context: ExecutionPolicyContext,
  input: string,
  options: ScanPathOptions = {},
): Promise<ResolvedExecutionPath> {
  assertExecutionCapability(context, "scan-artifacts.write");
  const label = options.label ?? "Pi Security scan artifact path";
  if (typeof input !== "string" || !input || !isAbsolute(input)) {
    throw new Error(`${label} must be an absolute path.`);
  }
  if (
    typeof context.scan.artifactRoot !== "string"
    || !context.scan.artifactRoot
    || !isAbsolute(context.scan.artifactRoot)
  ) {
    throw new Error("Pi Security execution scan artifact root must be an absolute directory.");
  }
  const requestedRoot = resolve(context.scan.artifactRoot);
  const requested = resolve(input);
  assertPathInside(requestedRoot, requested, label, options.allowRoot ?? false);
  const root = await canonicalBoundDirectory(
    requestedRoot,
    "Pi Security execution scan artifact root",
  );
  assertPathInside(root, requested, label, options.allowRoot ?? false);
  const inspected = await inspectBoundPath(
    root,
    requested,
    label,
    options.allowMissing ?? false,
  );
  if (inspected.metadata) {
    assertExpectedKind(inspected.metadata, options.expected ?? "any", label);
  }
  return {
    absolute: inspected.canonical ?? requested,
    relative: repositoryRelativePath(root, inspected.canonical ?? requested),
    ...(inspected.metadata ? { metadata: inspected.metadata } : {}),
  };
}

/** Verify that an artifact context is exactly the issued writer destination. */
export async function assertExecutionArtifactRoot(
  context: ExecutionPolicyContext,
  artifactRoot: string,
): Promise<string> {
  assertExecutionCapability(context, "scan-artifacts.write");
  if (
    typeof artifactRoot !== "string"
    || !isAbsolute(artifactRoot)
    || resolve(artifactRoot) !== resolve(context.scan.artifactRoot)
  ) {
    throw new Error("Pi Security execution context is bound to a different artifact root.");
  }
  const [expected, actual] = await Promise.all([
    canonicalBoundDirectory(
      context.scan.artifactRoot,
      "Pi Security execution scan artifact root",
    ),
    canonicalBoundDirectory(artifactRoot, "Pi Security artifact context root"),
  ]);
  if (actual !== expected) {
    throw new Error("Pi Security execution context is bound to a different artifact root.");
  }
  return actual;
}

/** Verify that a host artifact context and an issued target name the same root. */
export async function assertExecutionTargetRoot(
  context: ExecutionPolicyContext,
  targetRoot: string,
  capability: "target.read" | "target.search" | "target.git" | "scan-artifacts.write"
    = "target.read",
): Promise<string> {
  assertExecutionCapability(context, capability);
  if (
    typeof context.target.root !== "string"
    || !isAbsolute(context.target.root)
    || typeof targetRoot !== "string"
    || !isAbsolute(targetRoot)
  ) {
    throw new Error("Pi Security target bindings must be absolute directories.");
  }
  if (resolve(targetRoot) !== resolve(context.target.root)) {
    throw new Error("Pi Security execution context is bound to a different target root.");
  }
  const [expected, actual] = await Promise.all([
    canonicalBoundDirectory(context.target.root, "Pi Security execution target root"),
    canonicalBoundDirectory(targetRoot, "Pi Security host target root"),
  ]);
  if (actual !== expected) {
    throw new Error("Pi Security execution context is bound to a different target root.");
  }
  return actual;
}

/** Bind source, writer, and host state as one per-scan execution tuple. */
export async function assertExecutionBoundaryTuple(input: {
  source: ExecutionPolicyContext;
  writer: ExecutionPolicyContext;
  targetRoot: string;
  artifactRoot: string;
  workerRoot: string;
  scanId: string;
}): Promise<readonly PlatformEnforcementMechanism[]> {
  assertExecutionCapability(input.source, "target.read");
  assertExecutionCapability(input.writer, "scan-artifacts.write");
  if (
    input.source.scan.id !== input.scanId
    || input.writer.scan.id !== input.scanId
    || input.source.scan.id !== input.writer.scan.id
  ) {
    throw new Error("Pi Security execution contexts belong to different scans.");
  }
  await assertExecutionTargetRoot(input.source, input.targetRoot);
  await assertExecutionTargetRoot(input.writer, input.targetRoot, "scan-artifacts.write");
  await assertExecutionArtifactRoot(input.writer, input.artifactRoot);
  await assertExactWorkerRoot(input.source, input.workerRoot);
  const [targetMechanisms, artifactMechanisms] = await Promise.all([
    probeDirectoryHandleEnforcement(input.targetRoot, "Pi Security target root"),
    probeDirectoryHandleEnforcement(input.artifactRoot, "Pi Security artifact root"),
  ]);
  return Object.freeze([
    ...new Set([...targetMechanisms, ...artifactMechanisms]),
  ]);
}

/**
 * Artifact roots are coordinator-owned state outside the untrusted target. The
 * model has no target-write or target-execute capability, so it cannot mutate
 * these directories between validation and a fixed artifact operation.
 */
export async function assertTrustedArtifactContext(input: {
  context: ExecutionPolicyContext;
  artifactRoot: string;
  targetRoot: string;
}): Promise<string> {
  const [artifactRoot, targetRoot] = await Promise.all([
    assertExecutionArtifactRoot(input.context, input.artifactRoot),
    assertExecutionTargetRoot(
      input.context,
      input.targetRoot,
      "scan-artifacts.write",
    ),
  ]);
  if (isPathInside(targetRoot, artifactRoot, true) || isPathInside(artifactRoot, targetRoot, true)) {
    throw new Error("Pi Security artifact state must be outside the untrusted scan target.");
  }
  return artifactRoot;
}

/** Canonicalize an absolute, existing directory without accepting a symlink root. */
export async function canonicalBoundDirectory(
  value: string,
  label: string,
): Promise<string> {
  if (typeof value !== "string" || !value || !isAbsolute(value)) {
    throw new Error(`${label} must be an absolute directory.`);
  }
  const requested = resolve(value);
  const metadata = await fs.lstat(requested).catch(() => undefined);
  if (!metadata || metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error(`${label} is not a safe regular directory.`);
  }
  const canonical = await fs.realpath(requested).catch(() => undefined);
  if (!canonical) throw new Error(`${label} cannot be resolved.`);
  return canonical;
}

/**
 * Prove the actual host can preserve directory identity through an opened
 * handle. The probe opens and closes the existing directory without writes.
 */
export async function probeDirectoryHandleEnforcement(
  value: string,
  label: string,
): Promise<readonly PlatformEnforcementMechanism[]> {
  if (
    process.platform !== "win32"
    && (!Number.isInteger(fsConstants.O_NOFOLLOW) || fsConstants.O_NOFOLLOW === 0)
  ) {
    throw new UnsupportedDirectoryHandleEnforcementError(label);
  }
  const root = await canonicalBoundDirectory(value, label);
  const opened = await openVerifiedPath(root, root, root, "directory", label);
  try {
    return Object.freeze(process.platform === "win32"
      ? ["platform.windows-reparse-identity"] as const
      : process.platform === "linux"
        ? [
            "platform.posix-open-no-follow",
            "platform.linux-proc-self-fd",
          ] as const
        : [
            "platform.posix-open-no-follow",
            "platform.posix-dev-fd",
          ] as const);
  } finally {
    await opened.handle.close();
  }
}

/** Canonicalize an existing path under a trusted root without following symlinks. */
export async function canonicalPathInside(
  rootInput: string,
  pathInput: string,
  expected: BoundPathKind,
  label: string,
  allowRoot = false,
): Promise<ResolvedExecutionPath> {
  const root = await canonicalBoundDirectory(rootInput, `${label} root`);
  if (typeof pathInput !== "string" || !pathInput || !isAbsolute(pathInput)) {
    throw new Error(`${label} must be an absolute path.`);
  }
  const requested = resolve(pathInput);
  assertPathInside(root, requested, label, allowRoot);
  const inspected = await inspectBoundPath(root, requested, label, false);
  assertExpectedKind(inspected.metadata!, expected, label);
  return {
    absolute: inspected.canonical!,
    relative: repositoryRelativePath(root, inspected.canonical!),
    metadata: inspected.metadata,
  };
}

export function assertPathInside(
  root: string,
  path: string,
  label: string,
  allowRoot = false,
): void {
  if (isPathInside(root, path, allowRoot)) return;
  throw new Error(`${label} is outside its coordinator-bound root.`);
}

export function repositoryRelativePath(root: string, path: string): string {
  const value = relative(root, path).split(sep).join("/");
  return value || ".";
}

/** Validate one explicit repository-relative scope without touching the target. */
export function validateRepositoryRelativeScope(input: string): string {
  return requireRepositoryRelativePath(input, "Pi Security target scope");
}

async function assertExactWorkerRoot(
  context: ExecutionPolicyContext,
  workerRoot: string,
): Promise<void> {
  if (
    typeof workerRoot !== "string"
    || !isAbsolute(workerRoot)
    || resolve(workerRoot) !== resolve(context.scan.artifactRoot)
  ) {
    throw new Error("Pi Security source context is bound to a different worker root.");
  }
  const [expected, actual] = await Promise.all([
    canonicalBoundDirectory(context.scan.artifactRoot, "Pi Security source worker root"),
    canonicalBoundDirectory(workerRoot, "Pi Security host worker root"),
  ]);
  if (expected !== actual) {
    throw new Error("Pi Security source context is bound to a different worker root.");
  }
}

async function resolveTargetScope(
  root: string,
  input: string,
  label: string,
): Promise<string> {
  if (
    typeof input !== "string"
    || !input
    || (win32.isAbsolute(input) && !isAbsolute(input))
  ) {
    throw new Error(`${label} has an invalid coordinator-bound scope.`);
  }
  const requested = isAbsolute(input) ? resolve(input) : resolve(root, input);
  assertPathInside(root, requested, label, true);
  const inspected = await inspectBoundPath(root, requested, label, false);
  assertExpectedKind(inspected.metadata!, "directory", `${label} scope`);
  return inspected.canonical!;
}

async function openVerifiedPath(
  root: string,
  scope: string,
  requested: string,
  expected: BoundPathKind,
  label: string,
): Promise<OpenedExecutionPath> {
  const flags = fsConstants.O_RDONLY
    | fsConstants.O_NOFOLLOW
    | (expected === "directory" ? fsConstants.O_DIRECTORY : 0);
  let handle: FileHandle;
  try {
    handle = await fs.open(requested, flags);
  } catch (error) {
    throw new Error(`${label} cannot be opened safely.`, { cause: error });
  }
  try {
    const metadata = await handle.stat();
    assertExpectedKind(metadata, expected, label);
    const canonical = await canonicalOpenedPath(handle, requested, metadata, label);
    assertPathInside(root, canonical, label, true);
    assertPathInside(scope, canonical, label, true);
    return {
      absolute: canonical,
      relative: repositoryRelativePath(root, canonical),
      metadata,
      handle,
    };
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function canonicalOpenedPath(
  handle: FileHandle,
  requested: string,
  metadata: Stats,
  label: string,
): Promise<string> {
  if (metadata.isDirectory() && process.platform !== "win32") {
    const descriptorPath = await secureDirectoryDescriptorPath(
      handle,
      metadata,
      label,
      process.platform,
    );
    const descriptorCanonical = await fs.realpath(descriptorPath).catch(() => undefined);
    if (!descriptorCanonical) {
      throw new UnsupportedDirectoryHandleEnforcementError(label);
    }
    return descriptorCanonical;
  }
  const descriptorCandidates = process.platform === "linux"
    ? [`/proc/self/fd/${handle.fd}`]
    : process.platform === "win32"
      ? []
      : [`/dev/fd/${handle.fd}`];
  for (const descriptorPath of descriptorCandidates) {
    const descriptorCanonical = await fs.realpath(descriptorPath).catch(() => undefined);
    if (descriptorCanonical) return descriptorCanonical;
  }

  const canonical = await fs.realpath(requested).catch(() => undefined);
  if (!canonical) throw new Error(`${label} cannot be resolved.`);
  if (process.platform === "win32") {
    const requestedMetadata = await fs.lstat(requested).catch(() => undefined);
    if (
      !requestedMetadata
      || requestedMetadata.isSymbolicLink()
      || !samePlatformPath(requested, canonical, "win32")
    ) {
      throw new Error(`${label} is a reparse point and cannot be accessed.`);
    }
  }
  const current = await fs.stat(canonical).catch(() => undefined);
  if (!current || current.dev !== metadata.dev || current.ino !== metadata.ino) {
    throw new Error(`${label} changed while it was being opened.`);
  }
  return canonical;
}

async function secureDirectoryDescriptorPath(
  handle: FileHandle,
  metadata: Stats,
  label: string,
  platform: NodeJS.Platform,
): Promise<string> {
  const candidates = platform === "linux"
    ? [`/proc/self/fd/${handle.fd}`]
    : platform === "win32"
      ? []
      : [`/dev/fd/${handle.fd}`];
  for (const candidate of candidates) {
    const descriptor = await fs.stat(candidate).catch(() => undefined);
    if (
      descriptor?.isDirectory()
      && descriptor.dev === metadata.dev
      && descriptor.ino === metadata.ino
    ) {
      return candidate;
    }
  }
  throw new UnsupportedDirectoryHandleEnforcementError(label);
}

async function assertOpenedDirectoryIdentity(
  opened: OpenedExecutionPath,
  label: string,
  platform: NodeJS.Platform,
): Promise<void> {
  const current = await safeDirectoryPathIdentity(opened.absolute, label, platform);
  assertSameIdentity(opened.metadata, current, label);
  const flags = fsConstants.O_RDONLY
    | fsConstants.O_NOFOLLOW
    | (fsConstants.O_DIRECTORY ?? 0);
  let reopened: FileHandle;
  try {
    reopened = await fs.open(opened.absolute, flags);
  } catch (error) {
    throw new Error(`${label} changed while its directory handle was open.`, {
      cause: error,
    });
  }
  try {
    const reopenedMetadata = await reopened.stat();
    assertExpectedKind(reopenedMetadata, "directory", label);
    assertSameIdentity(opened.metadata, reopenedMetadata, label);
  } finally {
    await reopened.close();
  }
}

async function safeDirectoryPathIdentity(
  path: string,
  label: string,
  platform: NodeJS.Platform,
): Promise<Stats> {
  const metadata = await fs.lstat(path).catch(() => undefined);
  if (!metadata || metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error(`${label} changed or became a reparse point.`);
  }
  const canonical = await fs.realpath(path).catch(() => undefined);
  if (!canonical) throw new Error(`${label} cannot be resolved.`);
  if (platform === "win32" && !samePlatformPath(path, canonical, platform)) {
    throw new Error(`${label} is a reparse point and cannot be enumerated.`);
  }
  return metadata;
}

async function safeWindowsEntryIdentity(
  directory: string,
  name: string,
  label: string,
): Promise<Stats> {
  const path = join(directory, name);
  const metadata = await fs.lstat(path).catch(() => undefined);
  if (
    !metadata
    || metadata.isSymbolicLink()
    || (!metadata.isFile() && !metadata.isDirectory())
  ) {
    throw new Error(`${label} child ${JSON.stringify(name)} is an unsafe reparse point.`);
  }
  const canonical = await fs.realpath(path).catch(() => undefined);
  if (!canonical || !samePlatformPath(path, canonical, "win32")) {
    throw new Error(`${label} child ${JSON.stringify(name)} is an unsafe reparse point.`);
  }
  return metadata;
}

function assertSameIdentity(expected: Stats, actual: Stats, label: string): void {
  if (expected.dev !== actual.dev || expected.ino !== actual.ino) {
    throw new Error(`${label} changed while it was being enumerated.`);
  }
}

function samePlatformPath(
  left: string,
  right: string,
  platform: NodeJS.Platform,
): boolean {
  const normalizedLeft = resolve(left);
  const normalizedRight = resolve(right);
  return platform === "win32"
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight;
}

async function inspectBoundPath(
  root: string,
  requested: string,
  label: string,
  allowMissing: boolean,
): Promise<{ canonical?: string; metadata?: Stats }> {
  const child = relative(root, requested);
  let current = root;
  for (const component of child ? child.split(sep) : []) {
    current = join(current, component);
    const metadata = await fs.lstat(current).catch(() => undefined);
    if (!metadata) {
      if (allowMissing) return {};
      throw new Error(`${label} does not exist.`);
    }
    if (metadata.isSymbolicLink()) {
      throw new Error(`${label} contains a symbolic link and cannot be accessed.`);
    }
  }
  const metadata = await fs.lstat(requested).catch(() => undefined);
  if (!metadata) {
    if (allowMissing) return {};
    throw new Error(`${label} does not exist.`);
  }
  if (metadata.isSymbolicLink()) {
    throw new Error(`${label} is a symbolic link and cannot be accessed.`);
  }
  const canonical = await fs.realpath(requested).catch(() => undefined);
  if (!canonical) throw new Error(`${label} cannot be resolved.`);
  assertPathInside(root, canonical, label, true);
  return { canonical, metadata };
}

function requireRepositoryRelativePath(input: string, label: string): string {
  if (
    typeof input !== "string"
    || !input
    || input.length > 4096
    || isAbsolute(input)
    || win32.isAbsolute(input)
    || input.includes("\\")
    || input.includes("\0")
    || /[\u0000-\u001f\u007f]/u.test(input)
    || input.endsWith("/")
    || input.includes("//")
  ) {
    throw new Error(`${label} must be relative to the bound repository.`);
  }
  if (input === ".") return input;
  const components = input.replace(/^\.\//u, "").split("/");
  if (components.some((component) => component === "" || component === "." || component === "..")) {
    throw new Error(`${label} contains unsafe traversal.`);
  }
  return components.join("/");
}

function isPathInside(root: string, path: string, allowRoot: boolean): boolean {
  const child = relative(root, path);
  return (allowRoot && child === "")
    || (child !== ""
      && !isAbsolute(child)
      && child !== ".."
      && !child.startsWith(`..${sep}`));
}

function assertExpectedKind(metadata: Stats, expected: BoundPathKind, label: string): void {
  if (expected === "file" && !metadata.isFile()) {
    throw new Error(`${label} is not a regular file.`);
  }
  if (expected === "directory" && !metadata.isDirectory()) {
    throw new Error(`${label} is not a directory.`);
  }
  if (expected === "any" && !metadata.isFile() && !metadata.isDirectory()) {
    throw new Error(`${label} is not a regular file or directory.`);
  }
}
