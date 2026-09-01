import { randomUUID } from "node:crypto";
import { constants as fsConstants, promises as fs } from "node:fs";
import { dirname, join } from "node:path";
import {
  assertPathInside,
  assertTrustedArtifactContext,
} from "./execution-boundary.js";
import type { ExecutionPolicyContext } from "./execution-policy.js";

export interface DeepReducerWorkerContext {
  id: string;
  resultPath: string;
}

export interface DeepReducerContext {
  scanRoot: string;
  claimedWorkers: DeepReducerWorkerContext[];
  previousReducerResultPath?: string;
}

/**
 * Host-bound artifact state. Never construct this object from model tool input.
 */
export interface ArtifactContext {
  root: string;
  repoRoot: string;
  layout: "scan" | "worker" | "reducer";
  scanId: string;
  scope?: string;
  packageRoot?: string;
  pythonCommand?: string;
  targetContract?: Readonly<Record<string, unknown>>;
  targetRevision?: string;
  targetSnapshotDigest?: string;
  handoffClaimToken?: string;
  status?: string;
  mode?: string;
  deepReducer?: DeepReducerContext;
  executionPolicy: ExecutionPolicyContext;
}

export interface ArtifactPage {
  cursor?: string;
  limit?: number;
}

export interface ArtifactPageResult<Row> {
  rows: Row[];
  nextCursor?: string;
}

export interface ArtifactRowSchema<Row> {
  safeParse(value: unknown):
    | { success: true; data: Row }
    | { success: false; error?: unknown };
}

/**
 * Components are fixed, internal operation constants, not model-facing paths.
 */
export async function readArtifactText(
  context: ArtifactContext,
  components: readonly string[],
  label: string
): Promise<string> {
  validateArtifactComponents(components, label);
  const root = await requireArtifactRoot(context, label);
  let current = root;

  for (const [index, component] of components.entries()) {
    current = join(current, component);
    const metadata = await fs.lstat(current).catch(() => undefined);
    if (!metadata) {
      throw new Error(label + ": the requested artifact is unavailable.");
    }
    const isLast = index === components.length - 1;
    if (
      metadata.isSymbolicLink()
      || (isLast ? !metadata.isFile() : !metadata.isDirectory())
    ) {
      throw new Error(label + ": the requested artifact is not a safe regular file.");
    }
  }

  const canonical = await fs.realpath(current).catch(() => undefined);
  if (!canonical) {
    throw new Error(label + ": the requested artifact escaped its bound context.");
  }
  assertPathInside(root, canonical, label);
  try {
    return await fs.readFile(canonical, "utf8");
  } catch {
    throw new Error(label + ": the requested artifact cannot be read.");
  }
}

export async function readArtifactJsonObject(
  context: ArtifactContext,
  components: readonly string[],
  label: string
): Promise<Record<string, unknown>> {
  const source = await readArtifactText(context, components, label);
  let value: unknown;
  try {
    value = JSON.parse(source);
  } catch {
    throw new Error(label + ": stored JSON is malformed.");
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(label + ": stored JSON must contain an object.");
  }
  return value as Record<string, unknown>;
}

export async function readArtifactJsonl<Row = Record<string, unknown>>(
  context: ArtifactContext,
  components: readonly string[],
  label: string,
  rowSchema?: ArtifactRowSchema<Row>
): Promise<Row[]> {
  const source = await readArtifactText(context, components, label);
  const rows: Row[] = [];
  for (const [index, line] of source.split(/\r?\n/u).entries()) {
    if (!line.trim()) continue;

    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch {
      throw new Error(label + ": row " + (index + 1) + " is not valid JSON.");
    }
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      throw new Error(label + ": row " + (index + 1) + " must be a JSON object.");
    }
    if (!rowSchema) {
      rows.push(value as Row);
      continue;
    }

    const parsed = rowSchema.safeParse(value);
    if (!parsed.success) {
      throw new Error(
        label
        + ": row "
        + (index + 1)
        + " does not match its artifact schema"
        + formatRowSchemaError(parsed.error)
      );
    }
    rows.push(parsed.data);
  }
  return rows;
}

export function paginateArtifactRows<Row>(
  rows: readonly Row[],
  page: ArtifactPage,
  label: string
): ArtifactPageResult<Row> {
  const cursor = page.cursor ?? "0";
  if (!/^(?:0|[1-9][0-9]*)$/u.test(cursor)) {
    throw new Error(label + ": cursor must be a non-negative integer string.");
  }
  const start = Number(cursor);
  if (!Number.isSafeInteger(start) || start > rows.length) {
    throw new Error(label + ": cursor is outside the available rows.");
  }

  const limit = page.limit ?? 200;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) {
    throw new Error(label + ": limit must be an integer from 1 through 1000.");
  }

  const end = Math.min(rows.length, start + limit);
  return {
    rows: rows.slice(start, end),
    ...(end < rows.length ? { nextCursor: String(end) } : {})
  };
}

/**
 * Resolve one operation-owned destination inside its bound scan or worker root.
 */
export async function artifactDestination(
  context: ArtifactContext,
  components: readonly string[],
  label: string
): Promise<string> {
  validateArtifactComponents(components, label);
  const root = await requireArtifactRoot(context, label);
  let directory = root;

  for (const component of components.slice(0, -1)) {
    directory = join(directory, component);
    let metadata = await inspectOptionalPath(directory, label);
    if (!metadata) {
      try {
        await fs.mkdir(directory, { mode: 0o700 });
      } catch (error) {
        if (!isNodeError(error) || error.code !== "EEXIST") {
          throw new Error(label + ": destination directory cannot be created.");
        }
      }
      metadata = await inspectOptionalPath(directory, label);
    }
    if (!metadata || metadata.isSymbolicLink() || !metadata.isDirectory()) {
      throw new Error(label + ": destination directory is not a regular directory.");
    }
    const canonical = await fs.realpath(directory).catch(() => undefined);
    if (!canonical) {
      throw new Error(label + ": destination escaped its bound context.");
    }
    assertPathInside(root, canonical, label);
  }

  const destination = join(root, ...components);
  assertPathInside(root, destination, label);
  const metadata = await inspectOptionalPath(destination, label);
  if (metadata && (metadata.isSymbolicLink() || !metadata.isFile())) {
    throw new Error(label + ": destination is not a regular file.");
  }
  return destination;
}

export async function replaceArtifactText(
  context: ArtifactContext,
  path: string,
  content: string
): Promise<void> {
  await requireArtifactWritePath(context, path);
  await withArtifactLock(path, async () => {
    const temporary = join(dirname(path), "." + randomUUID() + ".tmp");
    try {
      await fs.writeFile(temporary, content, {
        encoding: "utf8",
        mode: 0o600,
        flag: "wx"
      });
      await fs.rename(temporary, path);
    } finally {
      await fs.rm(temporary, { force: true });
    }
  });
}

export async function replaceArtifactJson(
  context: ArtifactContext,
  path: string,
  value: unknown
): Promise<void> {
  await replaceArtifactText(context, path, JSON.stringify(value, null, 2) + "\n");
}

export async function replaceArtifactJsonl(
  context: ArtifactContext,
  path: string,
  rows: readonly unknown[]
): Promise<void> {
  const content = rows.length
    ? rows.map((row) => JSON.stringify(row)).join("\n") + "\n"
    : "";
  await replaceArtifactText(context, path, content);
}

export async function appendArtifactJsonl(
  context: ArtifactContext,
  path: string,
  rows: readonly unknown[]
): Promise<void> {
  await requireArtifactWritePath(context, path);
  if (rows.length === 0) return;
  const content = rows.map((row) => JSON.stringify(row)).join("\n") + "\n";
  await withArtifactLock(path, async () => {
    const handle = await fs.open(
      path,
      fsConstants.O_RDWR
      | fsConstants.O_CREAT
      | fsConstants.O_APPEND
      | fsConstants.O_NOFOLLOW,
      0o600
    );
    try {
      const metadata = await handle.stat();
      if (!metadata.isFile()) {
        throw new Error("Artifact append requires a regular file.");
      }
      let prefix = "";
      if (metadata.size > 0) {
        const finalByte = Buffer.alloc(1);
        await handle.read(finalByte, 0, 1, metadata.size - 1);
        if (finalByte[0] !== 0x0a) prefix = "\n";
      }
      await handle.appendFile(prefix + content, "utf8");
    } finally {
      await handle.close();
    }
  });
}

async function withArtifactLock(
  path: string,
  action: () => Promise<void>
): Promise<void> {
  const lockPath = path + ".lock";
  let lock: fs.FileHandle | undefined;
  for (let attempt = 0; attempt < 500; attempt += 1) {
    try {
      lock = await fs.open(
        lockPath,
        fsConstants.O_WRONLY
        | fsConstants.O_CREAT
        | fsConstants.O_EXCL
        | fsConstants.O_NOFOLLOW,
        0o600
      );
      break;
    } catch (error) {
      if (!isNodeError(error) || error.code !== "EEXIST") throw error;
      await new Promise<void>((done) => setTimeout(done, 20));
    }
  }
  if (!lock) {
    throw new Error("Timed out waiting for the artifact write lock.");
  }
  try {
    await action();
  } finally {
    await lock.close();
    await fs.rm(lockPath, { force: true });
  }
}

function validateArtifactComponents(
  components: readonly string[],
  label: string
): void {
  if (components.length === 0) {
    throw new Error(label + ": a fixed artifact destination is required.");
  }
  for (const component of components) {
    if (
      !component
      || component === "."
      || component === ".."
      || component.includes("/")
      || component.includes("\\")
      || component.includes("\0")
    ) {
      throw new Error(label + ": the artifact destination is unsafe.");
    }
  }
}

async function requireArtifactRoot(
  context: ArtifactContext,
  label: string
): Promise<string> {
  if (!context.executionPolicy) {
    throw new Error(label + ": artifact context requires an issued execution policy.");
  }
  if (!context.scanId || context.executionPolicy.scan.id !== context.scanId) {
    throw new Error(label + ": artifact context belongs to a different scan.");
  }
  return await assertTrustedArtifactContext({
    context: context.executionPolicy,
    artifactRoot: context.root,
    targetRoot: context.repoRoot,
  });
}

async function requireArtifactWritePath(
  context: ArtifactContext,
  path: string
): Promise<void> {
  const root = await requireArtifactRoot(context, "Artifact write");
  assertPathInside(root, path, "Artifact write");
  const parent = dirname(path);
  const parentMetadata = await fs.lstat(parent).catch(() => undefined);
  if (!parentMetadata || parentMetadata.isSymbolicLink() || !parentMetadata.isDirectory()) {
    throw new Error("Artifact write destination directory is not safe.");
  }
  const canonicalParent = await fs.realpath(parent).catch(() => undefined);
  if (!canonicalParent) {
    throw new Error("Artifact write destination directory cannot be resolved.");
  }
  assertPathInside(root, canonicalParent, "Artifact write", true);
  const metadata = await fs.lstat(path).catch(() => undefined);
  if (metadata && (metadata.isSymbolicLink() || !metadata.isFile())) {
    throw new Error("Artifact write destination is not a regular file.");
  }
}

async function inspectOptionalPath(
  path: string,
  label: string
): Promise<Awaited<ReturnType<typeof fs.lstat>> | undefined> {
  try {
    return await fs.lstat(path);
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return undefined;
    throw new Error(label + ": artifact path cannot be inspected.");
  }
}

function formatRowSchemaError(error: unknown): string {
  if (!isRecord(error) || !Array.isArray(error.issues)) return ".";
  const issue: unknown = error.issues[0];
  if (!isRecord(issue)) return ".";
  const issuePath = Array.isArray(issue.path)
    ? issue.path.map(String).join(".")
    : "";
  const message = typeof issue.message === "string" ? issue.message : "";
  if (!issuePath && !message) return ".";
  return ": " + (issuePath ? issuePath + ": " : "") + message;
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
