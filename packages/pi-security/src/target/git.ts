// Fixed-argument Git for target inspection. Port of git_command and git_blob_bytes in scripts/workbench_target.py.
import { spawnSync } from "node:child_process";

// Variables that would point Git at another repository, index, or object store.
const GIT_REPOSITORY_ENVIRONMENT = [
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_CEILING_DIRECTORIES",
  "GIT_COMMON_DIR",
  "GIT_DIR",
  "GIT_DISCOVERY_ACROSS_FILESYSTEM",
  "GIT_INDEX_FILE",
  "GIT_NAMESPACE",
  "GIT_OBJECT_DIRECTORY",
  "GIT_WORK_TREE"
];

export type GitResult = { status: number; stdout: Buffer; stderr: Buffer };

/**
 * Run git in `target`. Repository-local config is untrusted, so fsmonitor (which can name an executable) is disabled.
 * A missing git executable reports status 127, like any failed probe.
 */
export function gitCommand(target: string, args: (string | Buffer)[], options: { input?: Buffer } = {}): GitResult {
  const environment: NodeJS.ProcessEnv = { ...process.env, GIT_LITERAL_PATHSPECS: "1" };
  for (const name of GIT_REPOSITORY_ENVIRONMENT) delete environment[name];
  const command = ["-c", "core.fsmonitor=false", "-c", "i18n.logOutputEncoding=UTF-8", "-C", target];
  const result = spawnSync("git", [...command, ...args] as string[], {
    env: environment,
    input: options.input,
    maxBuffer: Number.MAX_SAFE_INTEGER
  });
  if (result.error !== undefined) {
    if ((result.error as NodeJS.ErrnoException).code === "ENOENT") {
      return { status: 127, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
    }
    throw result.error;
  }
  return { status: result.status ?? 1, stdout: result.stdout, stderr: result.stderr };
}

/** Read blobs in order with one NUL-framed `git cat-file --batch -Z`; null for a missing object or any failure. */
export function gitBlobBytes(target: string, objectNames: Buffer[]): (Buffer | null)[] {
  if (objectNames.length === 0) return [];
  const request = Buffer.concat(objectNames.flatMap((name) => [name, Buffer.from([0])]));
  const result = gitCommand(target, ["cat-file", "--batch", "-Z"], { input: request });
  if (result.status !== 0) return objectNames.map(() => null);
  try {
    return decodeBatchBlobs(result.stdout, objectNames.length);
  } catch {
    return objectNames.map(() => null);
  }
}

function decodeBatchBlobs(output: Buffer, count: number): (Buffer | null)[] {
  const blobs: (Buffer | null)[] = [];
  let offset = 0;
  for (let index = 0; index < count; index++) {
    const end = output.indexOf(0, offset);
    if (end < 0) throw new Error("missing NUL terminator");
    const header = output.subarray(offset, end).toString("latin1");
    offset = end + 1;
    // "<oid> blob <size>"; anything else (for example "<name> missing") is not a blob.
    const fields = header.split(" ");
    if (fields.length < 3 || fields.at(-2) !== "blob") {
      blobs.push(null);
      continue;
    }
    const sizeText = fields.at(-1)!;
    if (!/^\+?\d+$/.test(sizeText.trim())) throw new Error("invalid blob size");
    const size = Number(sizeText.trim());
    if (output[offset + size] !== 0) throw new Error("missing blob terminator");
    blobs.push(output.subarray(offset, offset + size));
    offset += size + 1;
  }
  return blobs;
}
