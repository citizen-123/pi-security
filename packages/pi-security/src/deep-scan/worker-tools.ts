import { promises as fs, type Dirent } from "node:fs";
import { createInterface } from "node:readline";
import { join } from "node:path";
import * as z from "zod/v4";
import commonSchema from "../../schemas/definitions/artifact-common.schema.json" with { type: "json" };
import reducerSchema from "../../schemas/tools/deep-reducer.schema.json" with { type: "json" };
import scanDraftSchema from "../../schemas/tools/scan-draft.schema.json" with { type: "json" };
import {
  createWorkerArtifactContext,
  type ArtifactContext,
} from "../artifact-context.js";
import {
  getPiSecurityDeepReducerInputs,
  recordPiSecurityDeepReduction,
} from "../artifact-deep-reducer.js";
import {
  parsePersistedScanDraft,
  recordPiSecurityWorkerScanDraft,
  type ScanDraftInput,
} from "../artifact-scan-draft.js";
import {
  bundleArtifactSchema,
  loadArtifactZodSchema,
  type ArtifactSchemaObject,
  type SchemaDocument,
} from "../artifact-schema-loader.js";
import { readArtifactJsonObject } from "../artifact-io.js";
import {
  assertExecutionArtifactRoot,
  assertExecutionBoundaryTuple,
  assertExecutionTargetRoot,
  openExecutionTargetPath,
  readOpenedDirectory,
  resolveExecutionTargetPath,
  type OpenedExecutionPath,
} from "../execution-boundary.js";
import { isPolicyEnforcementFailure } from "../enforcement-capabilities.js";
import {
  assertExecutionCapability,
  type ExecutionPolicyContext,
} from "../execution-policy.js";
import { requireRegularFile } from "./artifacts.js";
import {
  bindWorkerPolicy,
  type WorkerPolicyRequirement,
} from "./worker-policy.js";
import type {
  DelegatedSecurityTaskResult,
  PiWorkerArtifactContext,
  DeepScanWorkerKind,
} from "./types.js";

const schemaDocuments = [commonSchema, scanDraftSchema, reducerSchema] as SchemaDocument[];
const repositoryPathSchema = loadArtifactZodSchema(
  [commonSchema as SchemaDocument],
  commonSchema.$id,
  "repositoryPath",
) as z.ZodType<string>;

const pageSchema = {
  cursor: z.string().regex(/^(?:0|[1-9][0-9]*)$/u).optional(),
  limit: z.number().int().min(1).max(1000).optional(),
};
const listInputSchema = z.object({
  directory: z.string().min(1).max(4096).optional(),
  recursive: z.boolean().optional(),
  ...pageSchema,
}).strict();
const readInputSchema = z.object({
  path: z.string().min(1).max(4096),
  startLine: z.number().int().min(1).optional(),
  endLine: z.number().int().min(1).optional(),
}).strict();
const searchInputSchema = z.object({
  query: z.string().min(1),
  path: z.string().min(1).max(4096).optional(),
  caseSensitive: z.boolean().optional(),
  maxResults: z.number().int().min(1).max(1000).optional(),
}).strict();
const emptyInputSchema = z.object({}).strict();
const delegateTaskInputSchema = z.object({
  task: z.string().trim().min(1),
  context: z.string().trim().min(1).optional(),
}).strict();
const delegatedEvidenceSchema = z.object({
  path: repositoryPathSchema,
  startLine: z.number().int().min(1).optional(),
  endLine: z.number().int().min(1).optional(),
  observation: z.string().trim().min(1),
}).strict().superRefine((value, refinement) => {
  if (
    value.startLine !== undefined
    && value.endLine !== undefined
    && value.endLine < value.startLine
  ) {
    refinement.addIssue({
      code: "custom",
      message: "endLine must be greater than or equal to startLine.",
      path: ["endLine"],
    });
  }
});
const delegatedResultInputSchema = z.object({
  summary: z.string().trim().min(1),
  evidence: z.array(delegatedEvidenceSchema).default([]),
  unresolved: z.array(z.string().trim().min(1)).default([]),
}).strict();

export interface WorkerToolDefinition {
  name: string;
  description: string;
  inputSchema: ArtifactSchemaObject & { type: "object" };
  annotations: {
    title: string;
    readOnlyHint: boolean;
    destructiveHint: boolean;
    idempotentHint: boolean;
    openWorldHint: boolean;
  };
}

export interface WorkerToolResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}
export type DelegatedSecurityTaskExecution =
  | { ordinal: number; result: DelegatedSecurityTaskResult; error?: never }
  | { ordinal: number; result?: never; error: string };


export interface ExecutedWorkerTool {
  result: WorkerToolResult;
  finalSubmissionAccepted: boolean;
  delegatedChildOrdinal?: number;
}

export interface BoundWorkerTools {
  context: ArtifactContext;
  definitions(): WorkerToolDefinition[];
  delegatedResult(): DelegatedSecurityTaskResult | undefined;
  execute(
    name: string,
    input: Record<string, unknown>,
    signal: AbortSignal,
  ): Promise<ExecutedWorkerTool>;
}


const sourceToolAnnotations = (title: string): WorkerToolDefinition["annotations"] => ({
  title,
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
});

const submissionToolAnnotations = (title: string): WorkerToolDefinition["annotations"] => ({
  title,
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
});

/** Bind the exact tools advertised inside one native Pi worker session. */
export async function createWorkerTools(input: {
  kind: DeepScanWorkerKind;
  executionContext: ExecutionPolicyContext;
  artifactWriterContext: ExecutionPolicyContext;
  artifactContext: PiWorkerArtifactContext;
  delegationExecutionContext?: () => ExecutionPolicyContext;
  delegatedTask?: boolean;
  delegateSecurityTask?: (
    task: z.output<typeof delegateTaskInputSchema>,
    signal: AbortSignal,
  ) => Promise<DelegatedSecurityTaskExecution>;
  onDelegatedResultAccepted?: (
    result: DelegatedSecurityTaskResult,
    context: ArtifactContext,
  ) => Promise<void>;
}): Promise<BoundWorkerTools> {
  await assertExecutionBoundaryTuple({
    source: input.executionContext,
    writer: input.artifactWriterContext,
    targetRoot: input.artifactContext.repoRoot,
    artifactRoot: input.artifactContext.root,
    workerRoot: input.artifactContext.workerRoot,
    scanId: input.artifactContext.scanId,
  });
  const context = await createWorkerArtifactContext({
    root: input.artifactContext.root,
    repoRoot: input.artifactContext.repoRoot,
    layout: input.artifactContext.layout,
    scanId: input.artifactContext.scanId,
    scope: input.artifactContext.scope,
    packageRoot: input.artifactContext.packageRoot,
    targetContract: input.artifactContext.targetContract,
    targetRevision: input.artifactContext.targetRevision,
    targetSnapshotDigest: input.artifactContext.targetSnapshotDigest,
    mode: "deep",
    deepReducer: input.artifactContext.deepReducer,
    executionPolicy: input.artifactWriterContext,
  });
  const commonDefinitions: WorkerToolDefinition[] = input.kind === "dedup"
    ? []
    : [
      {
        name: "list_pi_security_target_files",
        description: "List regular source files under the coordinator-bound scan target. Paths are target-relative; symlinks are never followed.",
        inputSchema: jsonInputSchema(listInputSchema),
        annotations: sourceToolAnnotations("List target files"),
      },
      {
        name: "read_pi_security_source",
        description: "Read a bounded line range from one regular file inside the coordinator-bound scan target.",
        inputSchema: jsonInputSchema(readInputSchema),
        annotations: sourceToolAnnotations("Read target source"),
      },
      {
        name: "search_pi_security_source",
        description: "Search regular target files for a literal source string without invoking a shell. Results include target-relative paths and line numbers.",
        inputSchema: jsonInputSchema(searchInputSchema),
        annotations: sourceToolAnnotations("Search target source"),
      },
      {
        name: "get_pi_security_repository_metadata",
        description: "Read coordinator-bound repository, snapshot, and target-scoped Git diff metadata. This tool does not modify the repository.",
        inputSchema: jsonInputSchema(emptyInputSchema),
        annotations: sourceToolAnnotations("Get repository metadata"),
      },
    ];
  const contextDefinition: WorkerToolDefinition = {
    name: "get_pi_security_scan_context",
    description: "Read the authoritative scan identity, scope, user focus, current threat model, and bundled Standard scan guidance for this worker.",
    inputSchema: jsonInputSchema(emptyInputSchema),
    annotations: sourceToolAnnotations("Get scan context"),
  };
  const reducerDefinitions: WorkerToolDefinition[] = input.kind === "dedup"
    ? [{
      name: "get_pi_security_deep_reducer_inputs",
      description: "Read the complete validated Standard scan drafts assigned to this reducer and the previous aggregate, if one exists.",
      inputSchema: jsonInputSchema(emptyInputSchema),
      annotations: sourceToolAnnotations("Get Deep reducer inputs"),
    }]
    : [];
  const delegationDefinitions: WorkerToolDefinition[] = input.delegateSecurityTask
    ? [{
      name: "delegate_security_task",
      description: "Delegate one bounded repository-security investigation to an isolated nested worker. The child inherits this worker's authoritative target and scope; its validated evidence is returned for parent synthesis.",
      inputSchema: jsonInputSchema(delegateTaskInputSchema),
      annotations: sourceToolAnnotations("Delegate security task"),
    }]
    : [];
  const submissionDefinition: WorkerToolDefinition = input.delegatedTask
    ? {
      name: "record_delegate_security_result",
      description: "Validate and return the completed scoped investigation to the parent worker. The parent owns all final synthesis and scan-draft submission.",
      inputSchema: jsonInputSchema(delegatedResultInputSchema),
      annotations: submissionToolAnnotations("Record delegated security result"),
    }
    : input.kind === "dedup"
      ? {
        name: "record_pi_security_deep_reduction",
        description: "Validate and record the reducer's complete aggregate using the existing Deep reduction artifact contract.",
        inputSchema: bundleArtifactSchema(
          schemaDocuments,
          reducerSchema.$id,
          "reductionInput",
        ) as WorkerToolDefinition["inputSchema"],
        annotations: submissionToolAnnotations("Record Deep reduction"),
      }
      : {
        name: "record_pi_security_scan_draft",
        description: "Validate and record this worker's semantic scan draft. Set complete:false for a checkpoint and complete:true for the final draft.",
        inputSchema: bundleArtifactSchema(
          schemaDocuments,
          scanDraftSchema.$id,
          "scanDraftInput",
        ) as WorkerToolDefinition["inputSchema"],
        annotations: submissionToolAnnotations("Record scan draft"),
      };
  let delegatedResult: DelegatedSecurityTaskResult | undefined;
  const definitions = [
    ...commonDefinitions,
    contextDefinition,
    ...reducerDefinitions,
    ...delegationDefinitions,
    submissionDefinition,
  ];
  const policy = bindWorkerPolicy({
    source: () => input.executionContext,
    artifactWriter: () => input.artifactWriterContext,
    delegation: input.delegationExecutionContext ?? (() => input.executionContext),
    tools: definitions.map((definition) => ({
      definition,
      available: true,
      requirements: workerPolicyRequirements(definition.name),
    })),
  });

  return {
    context,
    definitions: () => policy.definitions(),
    delegatedResult: () => delegatedResult,
    async execute(name, rawInput, signal) {
      signal.throwIfAborted();
      try {
        policy.assertAuthorized(name);
        let value: unknown;
        let finalSubmissionAccepted = false;
        let delegatedChildOrdinal: number | undefined;
        switch (name) {
          case "list_pi_security_target_files":
            requireDiscovery(input.kind, name);
            value = await listTargetFiles(
              input.executionContext,
              context,
              listInputSchema.parse(rawInput),
              signal,
            );
            break;
          case "read_pi_security_source":
            requireDiscovery(input.kind, name);
            value = await readTargetSource(
              input.executionContext,
              context,
              readInputSchema.parse(rawInput),
              signal,
            );
            break;
          case "search_pi_security_source":
            requireDiscovery(input.kind, name);
            value = await searchTargetSource(
              input.executionContext,
              context,
              searchInputSchema.parse(rawInput),
              signal,
            );
            break;
          case "get_pi_security_repository_metadata":
            requireDiscovery(input.kind, name);
            emptyInputSchema.parse(rawInput);
            value = await repositoryMetadata(input.executionContext, context, signal);
            break;
          case "get_pi_security_scan_context":
            emptyInputSchema.parse(rawInput);
            value = await scanContext(
              input.executionContext,
              context,
              input.artifactContext,
              input.kind,
              signal,
            );
            break;
          case "delegate_security_task":
            requireDiscovery(input.kind, name);
            if (!input.delegateSecurityTask) {
              throw new Error("Nested security delegation is not available to this worker.");
            }
            {
              const delegated = await input.delegateSecurityTask(
                delegateTaskInputSchema.parse(rawInput),
                signal,
              );
              delegatedChildOrdinal = delegated.ordinal;
              if (delegated.error !== undefined) {
                return {
                  result: {
                    content: [{ type: "text", text: delegated.error }],
                    isError: true,
                  },
                  finalSubmissionAccepted: false,
                  delegatedChildOrdinal,
                };
              }
              value = delegated.result;
            }
            break;
          case "get_pi_security_deep_reducer_inputs":
            requireReducer(input.kind, name);
            emptyInputSchema.parse(rawInput);
            assertExecutionCapability(input.executionContext, "target.read");
            value = await getPiSecurityDeepReducerInputs(context);
            break;
          case "record_pi_security_scan_draft": {
            requireDiscovery(input.kind, name);
            if (input.delegatedTask) {
              throw new Error(`${name} is not available to a delegated security task.`);
            }
            await assertExecutionArtifactRoot(
              input.artifactWriterContext,
              context.root,
            );
            const draft = rawInput as unknown as ScanDraftInput;
            value = await recordPiSecurityWorkerScanDraft(context, draft);
            finalSubmissionAccepted = draft.complete !== false;
            break;
          }
          case "record_delegate_security_result":
            requireDiscovery(input.kind, name);
            if (!input.delegatedTask) {
              throw new Error(`${name} is available only to a delegated security task.`);
            }
            if (delegatedResult) {
              throw new Error("A delegated security result has already been accepted.");
            }
            {
              const accepted = await validateDelegatedSecurityTaskResult(
                input.executionContext,
                context,
                delegatedResultInputSchema.parse(rawInput),
              );
              await assertExecutionArtifactRoot(
                input.artifactWriterContext,
                context.root,
              );
              await input.onDelegatedResultAccepted?.(accepted, context);
              delegatedResult = accepted;
            }
            value = { accepted: true };
            finalSubmissionAccepted = true;
            break;
          case "record_pi_security_deep_reduction":
            requireReducer(input.kind, name);
            await assertExecutionArtifactRoot(
              input.artifactWriterContext,
              context.root,
            );
            value = await recordPiSecurityDeepReduction(context, rawInput);
            finalSubmissionAccepted = true;
            break;
          default:
            throw new Error(`Unknown Pi Security worker tool ${JSON.stringify(name)}.`);
        }
        signal.throwIfAborted();
        return {
          result: textToolResult(value),
          finalSubmissionAccepted,
          ...(delegatedChildOrdinal === undefined ? {} : { delegatedChildOrdinal }),
        };
      } catch (error) {
        signal.throwIfAborted();
        if (isPolicyEnforcementFailure(error)) throw error;
        return {
          result: {
            content: [{ type: "text", text: publicToolError(error) }],
            isError: true,
          },
          finalSubmissionAccepted: false,
        };
      }
    },
  };
}

export async function validateDelegatedSecurityTaskResult(
  executionContext: ExecutionPolicyContext,
  context: ArtifactContext,
  input: unknown,
): Promise<DelegatedSecurityTaskResult> {
  assertExecutionCapability(executionContext, "target.read");
  const parsed = delegatedResultInputSchema.parse(input);
  const evidence = [];
  for (const item of parsed.evidence) {
    const target = await resolveExecutionTargetPath(
      executionContext,
      item.path,
      {
        capability: "target.read",
        expected: "file",
        scope: context.scope,
      },
    );
    evidence.push({
      path: target.relative,
      ...(item.startLine === undefined ? {} : { startLine: item.startLine }),
      ...(item.endLine === undefined ? {} : { endLine: item.endLine }),
      observation: item.observation,
    });
  }
  return {
    summary: parsed.summary,
    evidence,
    unresolved: [...parsed.unresolved],
  };
}

async function listTargetFiles(
  executionContext: ExecutionPolicyContext,
  context: ArtifactContext,
  input: z.output<typeof listInputSchema>,
  signal: AbortSignal,
): Promise<{ files: string[]; nextCursor?: string }> {
  const files: string[] = [];
  await collectTargetFiles(
    executionContext,
    context,
    input.directory ?? ".",
    input.recursive ?? true,
    "target.read",
    files,
    signal,
  );
  files.sort((left, right) => left.localeCompare(right));
  const cursor = Number(input.cursor ?? "0");
  if (cursor > files.length) throw new Error("Target file cursor is outside the available results.");
  const limit = input.limit ?? 200;
  const end = Math.min(files.length, cursor + limit);
  return {
    files: files.slice(cursor, end),
    ...(end < files.length ? { nextCursor: String(end) } : {}),
  };
}

async function collectTargetFiles(
  executionContext: ExecutionPolicyContext,
  context: ArtifactContext,
  directory: string,
  recursive: boolean,
  capability: "target.read" | "target.search",
  files: string[],
  signal: AbortSignal,
): Promise<void> {
  signal.throwIfAborted();
  const opened = await openExecutionTargetPath(executionContext, directory, {
    capability,
    expected: "directory",
    scope: context.scope,
  });
  const directoryRelative = opened.relative;
  let entries: Dirent[];
  try {
    entries = await readOpenedDirectory(
      opened,
      "The requested target directory",
      async (entry) => {
        signal.throwIfAborted();
        const inputPath = directoryRelative === "."
          ? entry.name
          : `${directoryRelative}/${entry.name}`;
        const child = await openExecutionTargetPath(executionContext, inputPath, {
          capability,
          expected: "any",
          scope: context.scope,
        });
        await child.handle.close();
      },
    );
  } finally {
    await opened.handle.close();
  }
  entries.sort((left, right) => left.name.localeCompare(right.name));
  for (const entry of entries) {
    signal.throwIfAborted();
    const inputPath = directoryRelative === "."
      ? entry.name
      : `${directoryRelative}/${entry.name}`;
    const child = await openExecutionTargetPath(executionContext, inputPath, {
      capability,
      expected: "any",
      scope: context.scope,
    });
    const isDirectory = child.metadata.isDirectory();
    const isFile = child.metadata.isFile();
    const childRelative = child.relative;
    await child.handle.close();
    if (isDirectory) {
      if (recursive) {
        await collectTargetFiles(
          executionContext,
          context,
          childRelative,
          true,
          capability,
          files,
          signal,
        );
      }
    } else if (isFile) {
      files.push(childRelative);
    }
  }
}

async function readTargetSource(
  executionContext: ExecutionPolicyContext,
  context: ArtifactContext,
  input: z.output<typeof readInputSchema>,
  signal: AbortSignal,
): Promise<{ path: string; startLine: number; endLine: number; text: string; truncated: boolean }> {
  const target = await openExecutionTargetPath(executionContext, input.path, {
    capability: "target.read",
    expected: "file",
    scope: context.scope,
  });
  const startLine = input.startLine ?? 1;
  const requestedEnd = input.endLine ?? startLine + 399;
  if (requestedEnd < startLine) throw new Error("endLine must be greater than or equal to startLine.");
  if (requestedEnd - startLine >= 1000) {
    throw new Error("A source read can return at most 1000 lines; request another range to continue.");
  }

  const lines: string[] = [];
  let currentLine = 0;
  let lastLine = startLine - 1;
  let sawAnotherLine = false;
  const stream = target.handle.createReadStream({ encoding: "utf8", autoClose: false });
  const reader = createInterface({ input: stream, crlfDelay: Infinity });
  try {
    for await (const line of reader) {
      signal.throwIfAborted();
      currentLine += 1;
      if (line.includes("\0")) throw new Error("The requested target file is not UTF-8 source text.");
      if (currentLine < startLine) continue;
      if (currentLine > requestedEnd) {
        sawAnotherLine = true;
        break;
      }
      lines.push(line);
      lastLine = currentLine;
    }
  } finally {
    reader.close();
    stream.destroy();
    await target.handle.close();
  }
  return {
    path: target.relative,
    startLine,
    endLine: lastLine,
    text: lines.join("\n"),
    truncated: sawAnotherLine,
  };
}

async function searchTargetSource(
  executionContext: ExecutionPolicyContext,
  context: ArtifactContext,
  input: z.output<typeof searchInputSchema>,
  signal: AbortSignal,
): Promise<{
  query: string;
  matches: Array<{ path: string; line: number; text: string }>;
  truncated: boolean;
}> {
  const start = await openExecutionTargetPath(executionContext, input.path ?? ".", {
    capability: "target.search",
    expected: "any",
    scope: context.scope,
  });
  const files: string[] = [];
  if (start.metadata.isFile()) {
    files.push(start.relative);
    await start.handle.close();
  } else {
    const startRelative = start.relative;
    await start.handle.close();
    await collectTargetFiles(
      executionContext,
      context,
      startRelative,
      true,
      "target.search",
      files,
      signal,
    );
  }
  files.sort((left, right) => left.localeCompare(right));

  const query = input.caseSensitive ? input.query : input.query.toLocaleLowerCase();
  const maximum = input.maxResults ?? 100;
  const matches: Array<{ path: string; line: number; text: string }> = [];
  let truncated = false;
  for (const path of files) {
    signal.throwIfAborted();
    const target = await openExecutionTargetPath(executionContext, path, {
      capability: "target.search",
      expected: "file",
      scope: context.scope,
    });
    const stream = target.handle.createReadStream({ encoding: "utf8", autoClose: false });
    const reader = createInterface({ input: stream, crlfDelay: Infinity });
    let lineNumber = 0;
    let binary = false;
    try {
      for await (const line of reader) {
        signal.throwIfAborted();
        lineNumber += 1;
        if (line.includes("\0")) {
          binary = true;
          break;
        }
        const candidate = input.caseSensitive ? line : line.toLocaleLowerCase();
        if (!candidate.includes(query)) continue;
        if (matches.length === maximum) {
          truncated = true;
          break;
        }
        matches.push({
          path: target.relative,
          line: lineNumber,
          text: line,
        });
      }
    } finally {
      reader.close();
      stream.destroy();
      await target.handle.close();
    }
    if (truncated) break;
    if (binary) continue;
  }
  return { query: input.query, matches, truncated };
}

async function repositoryMetadata(
  executionContext: ExecutionPolicyContext,
  context: ArtifactContext,
  signal: AbortSignal,
): Promise<Record<string, unknown>> {
  assertExecutionCapability(executionContext, "target.git");
  await assertExecutionTargetRoot(executionContext, context.repoRoot, "target.git");
  signal.throwIfAborted();
  const base = {
    scope: context.scope ?? ".",
    ...(context.targetRevision ? { targetRevision: context.targetRevision } : {}),
    ...(context.targetSnapshotDigest
      ? { targetSnapshotDigest: context.targetSnapshotDigest }
      : {}),
    ...(context.targetContract?.diffTarget
      ? { diffTarget: context.targetContract.diffTarget }
      : {}),
  };
  const gitEntry = await openOptionalGitPath(
    executionContext,
    ".git",
    "any",
    signal,
  );
  if (!gitEntry) return { ...base, isGitRepository: false };
  if (gitEntry.metadata.isFile()) {
    try {
      const pointer = await readSmallOpenedText(
        gitEntry,
        "Pi Security Git directory pointer",
      );
      const isGitRepository = /^gitdir:\s*\S+/imu.test(pointer);
      return {
        ...base,
        isGitRepository,
        ...(isGitRepository
          ? unavailableWorkingTreeMetadata("external_git_directory")
          : {}),
      };
    } finally {
      await gitEntry.handle.close();
    }
  }

  const validateGitChild = async (entry: Dirent): Promise<void> => {
    const child = await openOptionalGitPath(
      executionContext,
      `.git/${entry.name}`,
      "any",
      signal,
    );
    if (!child) {
      throw new Error(
        `Pi Security Git control child ${JSON.stringify(entry.name)} is unsafe.`,
      );
    }
    await child.handle.close();
  };
  try {
    await readOpenedDirectory(
      gitEntry,
      "Pi Security Git control directory",
      validateGitChild,
    );
    const head = await readGitControlFile(
      executionContext,
      ".git/HEAD",
      signal,
    );
    const metadata = head === undefined
      ? {
          ...base,
          isGitRepository: true,
          ...unavailableWorkingTreeMetadata("unreadable_git_head"),
        }
      : {
          ...base,
          isGitRepository: true,
          ...await parseGitHead(executionContext, head, signal),
          ...unavailableWorkingTreeMetadata(
            "disabled_for_untrusted_git_configuration",
          ),
        };
    signal.throwIfAborted();
    await readOpenedDirectory(
      gitEntry,
      "Pi Security Git control directory",
      validateGitChild,
    );
    return metadata;
  } finally {
    await gitEntry.handle.close();
  }
}

async function parseGitHead(
  executionContext: ExecutionPolicyContext,
  source: string,
  signal: AbortSignal,
): Promise<{ headRevision?: string; branch?: string }> {
  const head = source.trim();
  if (isGitObjectId(head)) return { headRevision: head.toLowerCase() };
  if (!head.startsWith("ref: ")) return {};
  const reference = head.slice("ref: ".length).trim();
  if (!isSafeGitReference(reference)) return {};
  const loose = await readGitControlFile(
    executionContext,
    `.git/${reference}`,
    signal,
  );
  const packed = loose === undefined
    ? await readGitControlFile(executionContext, ".git/packed-refs", signal)
    : undefined;
  const revision = loose?.trim() ?? packedReference(packed, reference);
  return {
    ...(revision && isGitObjectId(revision)
      ? { headRevision: revision.toLowerCase() }
      : {}),
    ...(reference.startsWith("refs/heads/")
      ? { branch: reference.slice("refs/heads/".length) }
      : {}),
  };
}

async function openOptionalGitPath(
  executionContext: ExecutionPolicyContext,
  path: string,
  expected: "file" | "directory" | "any",
  signal: AbortSignal,
): Promise<OpenedExecutionPath | undefined> {
  signal.throwIfAborted();
  try {
    return await openExecutionTargetPath(executionContext, path, {
      capability: "target.git",
      expected,
      scope: ".",
      label: "Pi Security Git control path",
    });
  } catch (error) {
    if (isPolicyEnforcementFailure(error)) throw error;
    return undefined;
  }
}

async function readGitControlFile(
  executionContext: ExecutionPolicyContext,
  path: string,
  signal: AbortSignal,
): Promise<string | undefined> {
  const opened = await openOptionalGitPath(
    executionContext,
    path,
    "file",
    signal,
  );
  if (!opened) return undefined;
  try {
    return await readSmallOpenedText(opened, "Pi Security Git control file");
  } finally {
    await opened.handle.close();
  }
}

async function readSmallOpenedText(
  opened: OpenedExecutionPath,
  label: string,
): Promise<string> {
  const maximumBytes = 1024 * 1024;
  if (opened.metadata.size > maximumBytes) {
    throw new Error(`${label} exceeds the bounded metadata size.`);
  }
  const buffer = Buffer.allocUnsafe(maximumBytes + 1);
  const { bytesRead } = await opened.handle.read(
    buffer,
    0,
    buffer.length,
    0,
  );
  if (bytesRead > maximumBytes) {
    throw new Error(`${label} exceeds the bounded metadata size.`);
  }
  return buffer.subarray(0, bytesRead).toString("utf8");
}

function isGitObjectId(value: string): boolean {
  return /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/iu.test(value);
}

function isSafeGitReference(value: string): boolean {
  return value.startsWith("refs/")
    && !value.includes("\\")
    && !value.includes("\0")
    && value.split("/").every((part) => (
      part !== ""
      && part !== "."
      && part !== ".."
      && !part.startsWith(".")
    ))
    && /^[A-Za-z0-9_./-]+$/u.test(value);
}

function packedReference(
  source: string | undefined,
  reference: string,
): string | undefined {
  if (!source) return undefined;
  for (const line of source.split(/\r?\n/u)) {
    if (!line || line.startsWith("#") || line.startsWith("^")) continue;
    const separator = line.indexOf(" ");
    if (separator < 0 || line.slice(separator + 1) !== reference) continue;
    const revision = line.slice(0, separator);
    return isGitObjectId(revision) ? revision : undefined;
  }
  return undefined;
}

function unavailableWorkingTreeMetadata(reason: string): Record<string, unknown> {
  return {
    workingTree: null,
    unstagedDiff: null,
    stagedDiff: null,
    workingTreeInspection: {
      available: false,
      reason,
    },
  };
}

async function scanContext(
  executionContext: ExecutionPolicyContext,
  context: ArtifactContext,
  assigned: PiWorkerArtifactContext,
  kind: DeepScanWorkerKind,
  signal: AbortSignal,
): Promise<Record<string, unknown>> {
  assertExecutionCapability(executionContext, "target.read");
  await assertExecutionTargetRoot(executionContext, context.repoRoot, "target.read");
  signal.throwIfAborted();
  let guide: string | undefined;
  if (assigned.packageRoot && kind !== "dedup") {
    guide = await fs.readFile(join(assigned.packageRoot, "references", "core-scan.md"), "utf8");
  }
  let currentThreatModel: Record<string, unknown> | undefined;
  const resultMetadata = await fs.lstat(join(context.root, "result.json")).catch(() => undefined);
  if (resultMetadata) {
    const current = parsePersistedScanDraft(await readArtifactJsonObject(
      context,
      ["result.json"],
      "worker scan context",
    ));
    currentThreatModel = current.threatModel;
  }
  let falsePositiveFeedback: unknown;
  if (assigned.scanRoot && kind !== "dedup") {
    const path = join(
      assigned.scanRoot,
      "artifacts",
      "01_context",
      "false_positive_feedback.json",
    );
    const metadata = await fs.lstat(path).catch(() => undefined);
    if (metadata) {
      await requireRegularFile(path, assigned.scanRoot);
      const source = await fs.readFile(path, "utf8");
      falsePositiveFeedback = JSON.parse(source) as unknown;
    }
  }
  signal.throwIfAborted();
  return {
    scanId: context.scanId,
    workerKind: kind,
    scope: context.scope ?? ".",
    userContext: assigned.userContext ?? null,
    threatModel: currentThreatModel ?? null,
    ...(guide === undefined ? {} : { standardScanGuide: guide }),
    ...(falsePositiveFeedback === undefined ? {} : { falsePositiveFeedback }),
  };
}


function workerPolicyRequirements(name: string): readonly WorkerPolicyRequirement[] {
  switch (name) {
    case "list_pi_security_target_files":
    case "read_pi_security_source":
    case "get_pi_security_scan_context":
    case "get_pi_security_deep_reducer_inputs":
      return [{ authority: "source", capability: "target.read" }];
    case "search_pi_security_source":
      return [{ authority: "source", capability: "target.search" }];
    case "get_pi_security_repository_metadata":
      return [{ authority: "source", capability: "target.git" }];
    case "delegate_security_task":
      return [{ authority: "delegation", capability: "delegation.create" }];
    case "record_delegate_security_result":
      return [
        { authority: "source", capability: "target.read" },
        { authority: "artifactWriter", capability: "scan-artifacts.write" },
      ];
    case "record_pi_security_scan_draft":
    case "record_pi_security_deep_reduction":
      return [{ authority: "artifactWriter", capability: "scan-artifacts.write" }];
    default:
      throw new Error(`Unknown Pi Security worker tool definition ${JSON.stringify(name)}.`);
  }
}

function jsonInputSchema(schema: z.ZodType): WorkerToolDefinition["inputSchema"] {
  return z.toJSONSchema(schema, { target: "draft-7", io: "input" }) as WorkerToolDefinition["inputSchema"];
}

function textToolResult(value: unknown): WorkerToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
  };
}

function publicToolError(error: unknown): string {
  if (error instanceof z.ZodError) {
    return `Invalid tool input: ${z.prettifyError(error)}`;
  }
  return error instanceof Error ? error.message : String(error);
}

function requireDiscovery(kind: DeepScanWorkerKind, name: string): void {
  if (kind === "dedup") throw new Error(`${name} is not available to a Deep reducer.`);
}

function requireReducer(kind: DeepScanWorkerKind, name: string): void {
  if (kind !== "dedup") throw new Error(`${name} is available only to a Deep reducer.`);
}

