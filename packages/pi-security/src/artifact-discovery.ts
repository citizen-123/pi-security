import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import type * as z from "zod/v4";
import discoveryCandidateDefinitions from "../schemas/definitions/discovery-candidate.schema.json" with { type: "json" };
import discoveryCandidatesToolSchema from "../schemas/tools/discovery-candidates.schema.json" with { type: "json" };
import type { ArtifactContext } from "./artifact-context.js";
import {
  artifactDestination,
  paginateArtifactRows,
  readArtifactJsonl,
  readArtifactText
} from "./artifact-io.js";
import {
  loadArtifactZodSchema,
  type SchemaDocument
} from "./artifact-schema-loader.js";
import { candidateSchemaV1 } from "./deep-scan/artifact-contracts.js";
import { missingPythonHelperMessage, resolvePythonCommand } from "./python_command.js";

const execFileAsync = promisify(execFile);
const discoveryComponents = ["artifacts", "02_discovery"] as const;
const discoveryLabel = "discovery candidates";
const discoverySchemaDocuments = [
  discoveryCandidateDefinitions,
  discoveryCandidatesToolSchema
] as SchemaDocument[];

export type RawDiscoveryLocationRole =
  | "entrypoint"
  | "entrypoint/wrapper"
  | "source"
  | "root_control"
  | "sink"
  | "concrete_implementation"
  | "evidence";

export interface RawDiscoveryLocation {
  path: string;
  start_line: number;
  end_line?: number;
  role: RawDiscoveryLocationRole;
}

export interface RawDiscoveryCandidate {
  cwe_ids: string[];
  locations: RawDiscoveryLocation[];
  summary: string;
  evidence: string;
  context?: string;
  instance?: string;
}

export interface DiscoveryCandidatesInput {
  candidates: RawDiscoveryCandidate[];
}

export interface ListPiSecurityCandidatesInput {
  cursor?: string;
  limit?: number;
}

export type CompactDiscoveryCandidate = z.infer<typeof candidateSchemaV1>
  & Record<string, unknown>;

/** Every exposed validator is derived from the checked-in JSON Schema source. */
export const rawDiscoveryLocationSchema = loadArtifactZodSchema(
  discoverySchemaDocuments,
  discoveryCandidateDefinitions.$id,
  "rawDiscoveryLocation"
) as z.ZodType<RawDiscoveryLocation>;

export const rawDiscoveryCandidateSchema = loadArtifactZodSchema(
  discoverySchemaDocuments,
  discoveryCandidateDefinitions.$id,
  "rawDiscoveryCandidate"
) as z.ZodType<RawDiscoveryCandidate>;

export const compactDiscoveryCandidateSchema = loadArtifactZodSchema(
  discoverySchemaDocuments,
  discoveryCandidateDefinitions.$id,
  "discoveryCandidate"
) as z.ZodType<CompactDiscoveryCandidate>;

export const discoveryCandidatesInputSchema = loadArtifactZodSchema(
  discoverySchemaDocuments,
  discoveryCandidatesToolSchema.$id,
  "recordDiscoveryCandidatesInput"
) as z.ZodType<DiscoveryCandidatesInput>;

export const workbenchDiscoveryCandidatesInputSchema = loadArtifactZodSchema(
  discoverySchemaDocuments,
  discoveryCandidatesToolSchema.$id,
  "workbenchRecordDiscoveryCandidatesInput"
) as z.ZodType<DiscoveryCandidatesInput & { scanId: string }>;

export const listPiSecurityCandidatesInputSchema = loadArtifactZodSchema(
  discoverySchemaDocuments,
  discoveryCandidatesToolSchema.$id,
  "listCandidatesInput"
) as z.ZodType<ListPiSecurityCandidatesInput>;

export const workbenchListPiSecurityCandidatesInputSchema = loadArtifactZodSchema(
  discoverySchemaDocuments,
  discoveryCandidatesToolSchema.$id,
  "workbenchListCandidatesInput"
) as z.ZodType<ListPiSecurityCandidatesInput & { scanId: string }>;

export interface RecordPiSecurityDiscoveryCandidatesResult {
  operation: "replace";
  candidatesRecorded: number;
}

export interface ListPiSecurityCandidatesResult {
  rows: CompactDiscoveryCandidate[];
  nextCursor?: string;
}

/**
 * Invoke the shared discovery normalizer. Its candidate and inventory inputs
 * are copied into a private temporary directory before the subprocess runs.
 */
export async function recordPiSecurityDiscoveryCandidates(
  input: DiscoveryCandidatesInput,
  context: ArtifactContext
): Promise<RecordPiSecurityDiscoveryCandidatesResult> {
  const { candidates } = discoveryCandidatesInputSchema.parse(input);
  const packageRoot = context.packageRoot?.trim();
  if (!packageRoot) {
    throw new Error(
      "discovery candidates: the package runtime is not bound to this scan; "
      + "restore the scan context before retrying."
    );
  }

  const inventoryComponents = [...discoveryComponents, "in_scope_files.txt"];
  const candidateComponents = [...discoveryComponents, "candidate_ledger.jsonl"];

  // Snapshot the context-bound inventory before passing it to the subprocess.
  const inventory = await readArtifactText(
    context,
    inventoryComponents,
    "discovery review inventory"
  );
  const destination = await artifactDestination(context, candidateComponents, discoveryLabel);
  const temporaryDirectory = await fs.mkdtemp(
    join(tmpdir(), "pi-security-discovery-candidates-")
  );
  const temporaryInput = join(temporaryDirectory, "candidates.jsonl");
  const temporaryInventory = join(temporaryDirectory, "in_scope_files.txt");

  try {
    await fs.chmod(temporaryDirectory, 0o700);
    const content = candidates.length === 0
      ? ""
      : `${candidates.map((candidate) => JSON.stringify(candidate)).join("\n")}\n`;
    await fs.writeFile(temporaryInput, content, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600
    });
    await fs.writeFile(temporaryInventory, inventory, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600
    });

    const pythonCommand = context.pythonCommand ?? await resolvePythonCommand();
    try {
      await execFileAsync(
        pythonCommand,
        [
          join(packageRoot, "scripts", "normalize_candidates.py"),
          "--input",
          temporaryInput,
          "--out",
          destination,
          "--repo-root",
          context.repoRoot,
          "--in-scope-files",
          temporaryInventory,
          ...(context.mode === "diff" ? ["--allow-missing-in-scope"] : [])
        ],
        {
          cwd: packageRoot,
          encoding: "utf8",
          shell: false
        }
      );
    } catch (error) {
      throw discoveryNormalizationError(error, pythonCommand, [
        [temporaryInput, "candidate input"],
        [temporaryDirectory, "private candidate input"],
        [temporaryInventory, "the assigned review inventory"],
        [destination, "the candidate set"],
        [context.repoRoot, "the repository"],
        [packageRoot, "the package runtime"]
      ]);
    }

    const normalized = await readArtifactJsonl(
      context,
      candidateComponents,
      discoveryLabel,
      candidateSchemaV1
    );
    return {
      operation: "replace",
      candidatesRecorded: normalized.length
    };
  } finally {
    await fs.rm(temporaryDirectory, { recursive: true, force: true }).catch(() => undefined);
  }
}

/** Read the actual compact ledger, including records added by later shared phases. */
export async function listPiSecurityCandidates(
  input: ListPiSecurityCandidatesInput,
  context: ArtifactContext
): Promise<ListPiSecurityCandidatesResult> {
  const page = listPiSecurityCandidatesInputSchema.parse(input);
  const rows = await readArtifactJsonl(
    context,
    [...discoveryComponents, "candidate_ledger.jsonl"],
    discoveryLabel,
    compactDiscoveryCandidateSchema
  );
  return paginateArtifactRows(rows, page, discoveryLabel);
}

function discoveryNormalizationError(
  error: unknown,
  pythonCommand: string,
  privateValues: Array<readonly [string, string]>
): Error {
  const pythonMessage = missingPythonHelperMessage(error, pythonCommand);
  if (pythonMessage) {
    return new Error(`${discoveryLabel}: ${pythonMessage}`, { cause: error });
  }

  const stderr = error && typeof error === "object" && "stderr" in error
    ? error.stderr
    : undefined;
  let detail = typeof stderr === "string"
    ? stderr.trim()
    : Buffer.isBuffer(stderr)
      ? stderr.toString("utf8").trim()
      : "";

  if (!detail) {
    return new Error(
      `${discoveryLabel}: normalization could not be confirmed; `
      + "read the current candidate set before retrying.",
      { cause: error }
    );
  }

  for (const [source, replacement] of [...privateValues].sort(
    ([left], [right]) => right.length - left.length
  )) {
    if (source) detail = detail.replaceAll(source, replacement);
  }
  detail = detail.replace(/^normalize_candidates:\s*/u, "");
  return new Error(`${discoveryLabel}: ${detail}`, { cause: error });
}
