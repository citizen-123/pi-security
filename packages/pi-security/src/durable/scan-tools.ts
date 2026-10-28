// The tools scan workers get (design D7): five read-only source tools over the confined target, and one report tool
// per role. Built-in read/write/edit/bash are never installed in scan runs.
//
// Source tools read only through ConfinedRoot. git_metadata returns the target binding the orchestrator resolved at
// preflight (D14) instead of parsing the untrusted repository's .git. Report tools take the role's checked-in schema as
// their parameters, so pi-durable validates the payload (standard JSON Schema semantics, through pi-ai) before the tool
// runs and returns a rejection to the model; the tool commits it to security.result/<conversationId> and ends the run.
// The finalizer's Python-compatible validator is not used here: it applies `pattern` with fullmatch, as the Python
// scripts do, which these schemas (`"pattern": "\\S"` for non-blank text) do not intend.
import { Type } from "@earendil-works/pi-ai";
import { validateToolArguments } from "@earendil-works/pi-ai/utils/validation";
import { defineExtension, defineTool, type ToolExecutionResult, type ToolRegistration } from "@earendil-works/pi-durable";
import commonSchema from "../../schemas/definitions/artifact-common.schema.json" with { type: "json" };
import discoveryCandidateSchema from "../../schemas/definitions/discovery-candidate.schema.json" with { type: "json" };
import attackPathsSchema from "../../schemas/tools/candidate-attack-paths.schema.json" with { type: "json" };
import validationsSchema from "../../schemas/tools/candidate-validations.schema.json" with { type: "json" };
import reducerSchema from "../../schemas/tools/deep-reducer.schema.json" with { type: "json" };
import discoveryCandidatesSchema from "../../schemas/tools/discovery-candidates.schema.json" with { type: "json" };
import scanDraftSchema from "../../schemas/tools/scan-draft.schema.json" with { type: "json" };
import standardScanSchema from "../../schemas/tools/standard-scan.schema.json" with { type: "json" };
import { bundleArtifactSchema, type SchemaDocument } from "../artifact-schema-loader.js";
import { ContractError, type JsonObject } from "../contract/contract-error.js";
import { ConfinedRoot, ConfinementError, type ConfinedEntry } from "../target/confined-root.js";
import { ResultFamily, resultKey, ScanContextDoc, TargetDoc } from "./scan-documents.js";

const text = (value: unknown, isError = false): ToolExecutionResult => ({
  output: [{ type: "text", text: typeof value === "string" ? value : JSON.stringify(value, null, 2) }],
  ...(isError ? { isError: true } : {})
});

/** A refused or failed request comes back to the model as an error result it can act on. */
async function guarded(run: () => Promise<unknown> | unknown): Promise<ToolExecutionResult> {
  try {
    return text(await run());
  } catch (error) {
    if (error instanceof ConfinementError || error instanceof ContractError || error instanceof ToolInputError) return text(error.message, true);
    throw error;
  }
}

class ToolInputError extends Error {
  override name = "ToolInputError";
}

const byteOrder = (left: string, right: string) => Buffer.compare(Buffer.from(left), Buffer.from(right));

/** UTF-8 text of a source file split into lines (\n, \r\n, or \r); binary or non-UTF-8 files are refused. */
function sourceLines(confined: ConfinedRoot, path: string): { path: string; lines: string[] } {
  const entry = confined.inspect(path);
  const bytes = confined.readFile(entry.path);
  let decoded: string;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new ToolInputError(`not UTF-8 source text: ${entry.path}`);
  }
  if (decoded.includes("\0")) throw new ToolInputError(`not UTF-8 source text: ${entry.path}`);
  const lines = decoded.split(/\r\n|\n|\r/);
  if (lines.at(-1) === "") lines.pop();
  return { path: entry.path, lines };
}

/** Regular files below a directory (or the file itself), in byte order; symbolic links and .git are skipped. */
function regularFiles(confined: ConfinedRoot, path: string, recursive: boolean): string[] {
  const start = confined.inspect(path);
  if (start.kind === "file") return [start.path];
  const files: string[] = [];
  const walk = (directory: string) => {
    for (const entry of confined.listDir(directory) as ConfinedEntry[]) {
      if (entry.name === ".git") continue;
      if (entry.kind === "file") files.push(entry.path);
      else if (entry.kind === "directory" && recursive) walk(entry.path);
    }
  };
  walk(start.path);
  return files.sort(byteOrder);
}

export type SourceToolsOptions = { readonly confined: ConfinedRoot };

export function createSourceTools({ confined }: SourceToolsOptions) {
  const listFiles = defineTool({
    name: "list_files",
    description:
      "List regular files in the scan target, in byte order, a page at a time. Paths are target-relative; symbolic links and .git are skipped.",
    parameters: Type.Object({
      directory: Type.Optional(Type.String({ minLength: 1, description: "Target-relative directory; default the whole scope." })),
      recursive: Type.Optional(Type.Boolean({ description: "Include subdirectories; default true." })),
      cursor: Type.Optional(Type.Integer({ minimum: 0, description: "Where the previous page stopped (its nextCursor)." })),
      limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 1000, description: "Files per page; default 200." }))
    }),
    replay: "safe",
    execute: (args) =>
      guarded(() => {
        const files = regularFiles(confined, args.directory ?? confined.scope, args.recursive ?? true);
        const cursor = args.cursor ?? 0;
        if (cursor > files.length) throw new ToolInputError(`cursor ${cursor} is past the ${files.length} files`);
        const end = Math.min(files.length, cursor + (args.limit ?? 200));
        return { files: files.slice(cursor, end), total: files.length, ...(end < files.length ? { nextCursor: end } : {}) };
      })
  });

  const readSource = defineTool({
    name: "read_source",
    description: "Read a range of lines, at most 1000, from one UTF-8 source file in the scan target. Lines are numbered from 1.",
    parameters: Type.Object({
      path: Type.String({ minLength: 1 }),
      startLine: Type.Optional(Type.Integer({ minimum: 1, description: "First line; default 1." })),
      endLine: Type.Optional(Type.Integer({ minimum: 1, description: "Last line; default startLine + 399." }))
    }),
    replay: "safe",
    execute: (args) =>
      guarded(() => {
        const startLine = args.startLine ?? 1;
        const endLine = args.endLine ?? startLine + 399;
        if (endLine < startLine) throw new ToolInputError("endLine must be at least startLine");
        if (endLine - startLine >= 1000) throw new ToolInputError("a read returns at most 1000 lines; request another range to continue");
        const { path, lines } = sourceLines(confined, args.path);
        const selected = lines.slice(startLine - 1, endLine);
        return {
          path,
          startLine,
          endLine: startLine - 1 + selected.length,
          totalLines: lines.length,
          text: selected.join("\n"),
          truncated: lines.length > endLine
        };
      })
  });

  const searchSource = defineTool({
    name: "search_source",
    description:
      "Search UTF-8 source files in the scan target for a literal string (no regular expressions, no shell). Returns paths and line numbers.",
    parameters: Type.Object({
      query: Type.String({ minLength: 1 }),
      path: Type.Optional(Type.String({ minLength: 1, description: "File or directory to search; default the whole scope." })),
      caseSensitive: Type.Optional(Type.Boolean({ description: "Default false." })),
      maxResults: Type.Optional(Type.Integer({ minimum: 1, maximum: 1000, description: "Default 100." }))
    }),
    replay: "safe",
    execute: (args) =>
      guarded(() => {
        const fold = (value: string) => (args.caseSensitive ? value : value.toLowerCase());
        const query = fold(args.query);
        const maximum = args.maxResults ?? 100;
        const matches: { path: string; line: number; text: string }[] = [];
        let skipped = 0;
        for (const file of regularFiles(confined, args.path ?? confined.scope, true)) {
          let lines: string[];
          try {
            lines = sourceLines(confined, file).lines;
          } catch (error) {
            if (!(error instanceof ToolInputError)) throw error;
            skipped++;
            continue;
          }
          for (const [index, line] of lines.entries()) {
            if (!fold(line).includes(query)) continue;
            if (matches.length === maximum) return { query: args.query, matches, truncated: true, skippedNonText: skipped };
            matches.push({ path: file, line: index + 1, text: line });
          }
        }
        return { query: args.query, matches, truncated: false, skippedNonText: skipped };
      })
  });

  const gitMetadata = defineTool({
    name: "git_metadata",
    description: "The scan target's repository coordinates: target kind, revisions, snapshot digest, and for diff scans the changed files.",
    parameters: Type.Object({}),
    replay: "safe",
    execute: (_args, api, context) => guarded(async () => (await api.snapshot(TargetDoc, context)) ?? {})
  });

  const getContext = defineTool({
    name: "get_context",
    description: "The scan's identity, scope, user focus, threat model, and the guidance for this scan.",
    parameters: Type.Object({}),
    replay: "safe",
    execute: (_args, api, context) => guarded(async () => (await api.snapshot(ScanContextDoc, context)) ?? {})
  });

  return { listFiles, readSource, searchSource, gitMetadata, getContext, all: [listFiles, readSource, searchSource, gitMetadata, getContext] };
}

// ─── Report tools ────────────────────────────────────────────────────────────

const SCHEMA_DOCUMENTS = [
  commonSchema,
  discoveryCandidateSchema,
  attackPathsSchema,
  validationsSchema,
  reducerSchema,
  discoveryCandidatesSchema,
  scanDraftSchema,
  standardScanSchema
] as SchemaDocument[];

/** A role's payload schema: the checked-in definition, fully dereferenced, without workbench identity fields. */
export function roleSchema(document: string, definition: string, omit: readonly string[] = []): JsonObject {
  const schema = structuredClone(bundleArtifactSchema(SCHEMA_DOCUMENTS, `pi-security://schemas/tools/${document}`, definition)) as JsonObject;
  const properties = schema.properties as JsonObject;
  for (const field of omit) delete properties[field];
  if (Array.isArray(schema.required)) schema.required = schema.required.filter((field) => !omit.includes(field as string));
  return schema;
}

export const ROLE_REPORTS = {
  threat_model: { tool: "report_threat_model", schema: () => roleSchema("standard-scan.schema.json", "reportThreatModelInput") },
  discover: { tool: "report_candidates", schema: () => roleSchema("discovery-candidates.schema.json", "recordDiscoveryCandidatesInput") },
  reduce: { tool: "report_reduction", schema: () => roleSchema("standard-scan.schema.json", "reportReductionInput") },
  validate: { tool: "report_validations", schema: () => roleSchema("candidate-validations.schema.json", "input", ["scanId"]) },
  attack_path: { tool: "report_attack_paths", schema: () => roleSchema("candidate-attack-paths.schema.json", "input", ["scanId"]) }
} as const;

export type ReportRole = keyof typeof ROLE_REPORTS;

/** The report tool of `role`: commit the (already validated) result with the tool result, and end the worker's run. */
export function createReportTool(role: ReportRole): ToolRegistration {
  const { tool, schema: build } = ROLE_REPORTS[role];
  const schema = build();
  return defineTool({
    name: tool,
    description: `Record this worker's complete ${role.replace("_", " ")} result. Call it once, at the end; a rejected call explains what to fix.`,
    parameters: Type.Unsafe<JsonObject>(schema),
    // Overwrites the worker's one result by key, so a rerun after a crash is harmless.
    replay: "safe",
    execute: async (args, api, context) => {
      await api.commit(async (tx) => {
        const result = await tx.doc(ResultFamily, resultKey(api.conversationId as unknown as number), null);
        result.role = role;
        result.payload = structuredClone(args) as never;
      }, context);
      return { ...text(`Recorded the ${role.replace("_", " ")} result.`), control: { terminate: true } };
    }
  });
}

export type ScanToolsOptions = SourceToolsOptions;

/** The scan tool extension: install it in the run's registry; configure each worker with its role's exact tool list. */
export function createScanTools(options: ScanToolsOptions) {
  const source = createSourceTools(options);
  const reports = Object.fromEntries((Object.keys(ROLE_REPORTS) as ReportRole[]).map((role) => [role, createReportTool(role)])) as Record<
    ReportRole,
    ToolRegistration
  >;
  const extension = defineExtension({ name: "pi-security-scan-tools", tools: [...source.all, ...Object.values(reports)] });
  /** The exact tools a worker of `role` is offered. */
  const toolsFor = (role: ReportRole) => [...source.all, reports[role]];
  return { source, reports, extension, toolsFor };
}

/**
 * Re-validate an admitted result with the validator pi-durable applied to the report call (D3: the orchestrator checks
 * every result it admits). Returns the validated payload, or throws with the validator's message.
 */
export function validateRoleResult(role: ReportRole, payload: unknown): JsonObject {
  const { tool } = ROLE_REPORTS[role];
  return validateToolArguments(createReportTool(role), { type: "toolCall", id: "admission", name: tool, arguments: payload as never });
}
