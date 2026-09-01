import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as z from "zod/v4";
import {
  assertPathInside,
  canonicalBoundDirectory,
  executeTrustedWorkbench,
  probeDirectoryHandleEnforcement,
} from "./src/execution-boundary.js";
import {
  createExecutionPolicyContext,
  type ExecutionPolicyContext,
} from "./src/execution-policy.js";
import {
  assertPiEnforcementSupported,
  describePiEnforcementCapabilities,
  describePolicyEnforcementFailure,
  EnforcementUnsupportedError,
  PolicyRecoveryRejectedError,
  type EnforcementCapabilityReport,
  type PlatformEnforcementMechanism,
} from "./src/enforcement-capabilities.js";
import { missingPythonHelperMessage, resolvePythonCommand } from "./src/python_command.js";
import type { ScanResults } from "./src/types.js";
import { MCP_APP_VERSION } from "./src/version.js";
import {
  handoffClaimTokenSchema,
  recoveryHandoffClaimTokenSchema,
  registerScanHandoffTools
} from "./src/server/handoff-tools.js";
import { registerCompactArtifactTools } from "./src/server/compact-artifact-tools.js";
import {
  createLifecycleCatalogServer,
  type LifecycleRegistrationServer,
  type LifecycleToolCatalog
} from "./src/server/lifecycle-catalog.js";
import { createScanArtifactContext } from "./src/artifact-context.js";
import { recordPiSecurityScanDraftViaWorkbench } from "./src/artifact-scan-draft.js";
import {
  DeepScanCoordinatorRegistry,
  DeepScanStartLock,
  startOrJoinDeepScanCoordinator,
  validateResumableWorkerPolicies,
} from "./src/deep-scan/registry.js";
import {
  SamplingWorkerExecutor,
  supportsSamplingTools,
  type SamplingClient
} from "./src/deep-scan/executor.js";
import { WorkbenchDeepScanStore } from "./src/deep-scan/store.js";
import type { DeepScanRunState } from "./src/deep-scan/types.js";

const execFileAsync = promisify(execFile);
const CONFIGURED_SCAN_ROOT = process.env.PI_SECURITY_SCAN_ROOT?.trim();
const CONFIGURED_WORKBENCH_STATE_DIR = process.env.PI_SECURITY_STATE_DIR?.trim();
const MODULE_DIRECTORY = typeof __dirname === "string"
  ? __dirname
  : dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = basename(MODULE_DIRECTORY) === "dist"
  ? resolve(MODULE_DIRECTORY, "..")
  : MODULE_DIRECTORY;
const USER_INPUT_WAIT_TIMEOUT_MS = 14 * 60 * 1000;
const WORKBENCH_COMMANDS_WITHOUT_DATABASE = new Set(["inspect-target", "inspect-setup"]);
const READ_ONLY_PREFLIGHT_ENV = "PI_SECURITY_WORKBENCH_READ_ONLY_PREFLIGHT";
const READ_ONLY_PREFLIGHT_NOT_FOUND_EXIT = 66;
const READ_ONLY_PREFLIGHT_NOT_FOUND_CODE = "PI_SECURITY_WORKBENCH_STATE_NOT_FOUND";
const WORKBENCH_SETUP_CHANGED_EXIT = 75;
const WORKBENCH_SETUP_CHANGED_CODE = "PI_SECURITY_SETUP_CHANGED";

type JsonObject = Record<string, unknown>;
export class WorkbenchStateNotFoundError extends Error {
  readonly code = READ_ONLY_PREFLIGHT_NOT_FOUND_CODE;

  constructor(options?: ErrorOptions) {
    super("Pi Security workbench state was not found.", options);
    this.name = "WorkbenchStateNotFoundError";
  }
}
export class WorkbenchSetupChangedError extends Error {
  readonly code = WORKBENCH_SETUP_CHANGED_CODE;
  readonly category = "setup_changed";
  readonly retryable = true;

  constructor(options?: ErrorOptions) {
    super(
      "Pi Security setup changed after enforcement preflight. Retry from the current setup.",
      options,
    );
    this.name = "WorkbenchSetupChangedError";
  }
}



let defaultScanRoot: Promise<string> | undefined;
let reservedDefaultScanRoot: string | undefined;
let fallbackWorkbenchStateDir: Promise<string> | undefined;
let fallbackWorkbenchStateLogged = false;
let persistentWorkbenchStateSucceeded = false;
let workbenchStateSelectionTail: Promise<void> = Promise.resolve();
let trustedServerExecutionContext: Promise<ExecutionPolicyContext> | undefined;
let trustedPreflightExecutionContext: Promise<ExecutionPolicyContext> | undefined;

const userContextSchema = z.string().trim().min(1);
const editableUserContextSchema = z.string().trim();

async function scanRootPathWithoutCreating(): Promise<string> {
  if (CONFIGURED_SCAN_ROOT) return CONFIGURED_SCAN_ROOT;
  if (defaultScanRoot) return await defaultScanRoot;
  reservedDefaultScanRoot ??= join(tmpdir(), `pi-security-scans-${randomUUID()}`);
  return reservedDefaultScanRoot;
}

async function scanRoot(): Promise<string> {
  if (CONFIGURED_SCAN_ROOT) return CONFIGURED_SCAN_ROOT;
  if (!defaultScanRoot) {
    const root = await scanRootPathWithoutCreating();
    defaultScanRoot = fs.mkdir(root, { recursive: true, mode: 0o700 }).then(() => root);
  }
  return await defaultScanRoot;
}

async function scanRootEnforcementProbePath(): Promise<string> {
  if (defaultScanRoot) return await defaultScanRoot;
  try {
    return await nearestExistingDirectory(
      CONFIGURED_SCAN_ROOT ?? tmpdir(),
      "Pi Security scan-root preflight",
    );
  } catch (error) {
    throw new EnforcementUnsupportedError(
      "Pi Security requires a safe existing directory ancestor for scan artifacts; configure PI_SECURITY_SCAN_ROOT beneath a regular directory.",
      { cause: error },
    );
  }
}

async function nearestExistingDirectory(value: string, label: string): Promise<string> {
  let candidate = resolve(value);
  for (;;) {
    const metadata = await fs.lstat(candidate).catch((error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return undefined;
      throw error;
    });
    if (metadata) {
      if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
        throw new Error(`${label} nearest existing path is not a safe regular directory.`);
      }
      return candidate;
    }
    const parent = dirname(candidate);
    if (parent === candidate) {
      throw new Error(`${label} has no existing directory ancestor.`);
    }
    candidate = parent;
  }
}

async function assertPersistedScanRootAuthority(scanDir: string): Promise<void> {
  if (!CONFIGURED_SCAN_ROOT) return;
  let configuredRoot: string;
  let persistedRoot: string;
  try {
    [configuredRoot, persistedRoot] = await Promise.all([
      canonicalBoundDirectory(
        CONFIGURED_SCAN_ROOT,
        "Pi Security configured scan-root authority",
      ),
      canonicalBoundDirectory(
        scanDir,
        "Pi Security persisted Deep Scan artifact root",
      ),
    ]);
  } catch (error) {
    throw new EnforcementUnsupportedError(
      "Pi Security cannot safely resolve the configured and persisted Deep Scan artifact roots.",
      { cause: error },
    );
  }
  try {
    assertPathInside(
      configuredRoot,
      persistedRoot,
      "Pi Security persisted Deep Scan artifact root",
    );
  } catch (error) {
    throw new PolicyRecoveryRejectedError(
      "binding_mismatch",
      "The persisted Deep Scan artifact root is outside the current configured scan-root authority.",
      { cause: error },
    );
  }
}

function serverExecutionContext(): Promise<ExecutionPolicyContext> {
  trustedServerExecutionContext ??= (async () => {
    const configuredRoot = await scanRoot();
    await fs.mkdir(configuredRoot, { recursive: true, mode: 0o700 });
    const artifactRoot = await canonicalBoundDirectory(
      configuredRoot,
      "Pi Security scan root",
    );
    return createExecutionPolicyContext({
      profile: "security-artifact-writer",
      target: { root: artifactRoot },
      scan: { id: "pi-security-server", artifactRoot },
    });
  })();
  return trustedServerExecutionContext;
}

function preflightExecutionContext(): Promise<ExecutionPolicyContext> {
  trustedPreflightExecutionContext ??= (async () => {
    const artifactRoot = await canonicalBoundDirectory(
      PACKAGE_ROOT,
      "Pi Security bundled workbench root",
    );
    return createExecutionPolicyContext({
      profile: "security-artifact-writer",
      target: { root: artifactRoot },
      scan: { id: "pi-security-preflight", artifactRoot },
    });
  })();
  return trustedPreflightExecutionContext;
}

interface WorkspaceState extends JsonObject {
  id: string;
  mode?: "diff" | "standard" | "deep";
  targetPath?: string;
  results?: ScanResults & JsonObject;
  setup: {
    submitted: boolean;
  };
}

const diffTargetSchema = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("working_tree"),
    baseRevision: z.string().trim().min(1).max(512).optional(),
    contentDigest: z.string().trim().min(1).max(128).optional(),
    headRevision: z.string().trim().min(1).max(512).optional()
  }).strict(),
  z.object({
    kind: z.literal("commit"),
    baseRevision: z.string().trim().min(1).max(512).optional(),
    headRevision: z.string().trim().min(1).max(512)
  }).strict(),
  z.object({
    kind: z.literal("range"),
    baseRevision: z.string().trim().min(1).max(512),
    headRevision: z.string().trim().min(1).max(512)
  }).strict()
]);
const currentScanPreflightCheckSchema = z.object({
  capability: z.string().trim().min(1).max(128),
  reason: z.string().trim().min(1).max(1200),
  severity: z.enum(["block", "warn", "suggest"]),
  status: z.enum(["pass", "fail", "unknown"])
}).strict();
const openSchema = {
  diffTarget: diffTargetSchema.optional().describe("Exact local Git revisions for Review changes mode."),
  mode: z.enum(["diff", "standard", "deep"]).optional().describe("Initial scan mode inferred from the user's request."),
  scope: z.string().trim().min(1).max(4096).optional().describe("Optional directory inside targetPath. Use '.' or omit it for the whole target. Target-relative paths are preferred; absolute paths inside targetPath are normalized."),
  sessionId: z.string().uuid().optional().describe("Existing workspace ID to reopen without changing its setup. When provided, omit all other fields."),
  targetPath: z.string().trim().min(1).max(4096).optional().describe("Optional resolved local target path."),
  targetSummary: z.string().trim().min(1).max(2400).optional().describe("Optional bounded target/security context."),
  targetTitle: z.string().trim().min(1).max(200).optional().describe("Optional human-readable target name."),
  userContext: userContextSchema.optional().describe("Optional security focus supplied by the user.")
};
const sessionSchema = { sessionId: z.string().uuid() };
const startScanSchema = {
  ...sessionSchema,
  model: z.string().trim().min(1).max(200).optional(),
  reasoningEffort: z.string().trim().min(1).max(32).optional()
};
const startPromptOnlyScanSchema = {
  diffTarget: diffTargetSchema.optional().describe("Exact local Git revisions for Review changes mode."),
  mode: z.enum(["diff", "standard"]).describe("Prompt-driven scan mode. Deep Scan uses start_pi_security_deep_scan instead."),
  scope: z.string().trim().min(1).max(4096).describe("Directory inside targetPath. Use '.' for the whole target."),
  targetPath: z.string().trim().min(1).max(4096).describe("Resolved local target path."),
  targetSummary: z.string().trim().min(1).max(2400).optional().describe("Optional bounded target or change-set context."),
  userContext: userContextSchema.optional().describe("Optional security focus supplied by the user.")
};
const startHeadlessStandardScanSchema = {
  targetPath: z.string().trim().min(1).max(4096).describe("Resolved local target path."),
  scope: z.string().trim().min(1).max(4096).optional().describe("Optional directory inside targetPath. Omit it or use '.' for the whole target."),
  targetSummary: z.string().trim().max(2400).optional().describe("Optional bounded target context."),
  userContext: editableUserContextSchema.optional().describe("Optional security focus supplied by the user.")
};
type PromptOnlyScanInput = {
  diffTarget?: z.output<typeof diffTargetSchema>;
  mode: "diff" | "standard";
  scope: string;
  targetPath: string;
  targetSummary?: string;
  userContext?: string;
};
const userInputOptionSchema = z.object({
  description: z.string().trim().min(1).max(1200),
  label: z.string().trim().min(1).max(200)
}).strict();
const userInputQuestionSchema = z.object({
  header: z.string().trim().min(1).max(64),
  id: z.string().regex(
    /^[a-z][a-z0-9_]{0,63}$/,
    "Question IDs must use snake_case and start with a lowercase letter."
  ).refine(
    (id) => !["constructor", "prototype"].includes(id),
    "Question IDs must not use reserved object property names."
  ),
  options: z.array(userInputOptionSchema).min(2).max(3),
  question: z.string().trim().min(1).max(1200)
}).strict().superRefine((question, context) => {
  const labels = new Set<string>();
  for (const [index, option] of question.options.entries()) {
    if (labels.has(option.label)) {
      context.addIssue({
        code: "custom",
        message: "Option labels must be unique within a question.",
        path: ["options", index, "label"]
      });
    }
    labels.add(option.label);
  }
});
const userInputQuestionsSchema = z.array(userInputQuestionSchema).min(1).max(3).superRefine(
  (questions, context) => {
    const ids = new Set<string>();
    for (const [index, question] of questions.entries()) {
      if (ids.has(question.id)) {
        context.addIssue({
          code: "custom",
          message: "Question IDs must be unique.",
          path: [index, "id"]
        });
      }
      ids.add(question.id);
    }
  }
);
const requestUserInputSchema = {
  questions: userInputQuestionsSchema.describe(
    "One to three non-sensitive multiple-choice questions for an interactive Pi Security workflow."
  )
};
const targetInspectionSchema = {
  targetPath: z.string().trim().min(1).max(4096)
};
const submissionSchema = {
  diffTarget: diffTargetSchema.optional(),
  mode: z.enum(["diff", "standard", "deep"]),
  scope: z.string().trim().min(1).max(4096),
  sessionId: z.string().uuid(),
  targetPath: z.string().trim().min(1).max(4096),
  targetSummary: z.string().trim().max(2400).optional(),
  userContext: editableUserContextSchema.optional()
};
const setupInspectionSchema = {
  diffTarget: diffTargetSchema.optional(),
  mode: z.enum(["diff", "standard", "deep"]),
  scope: z.string().trim().min(1).max(4096),
  targetPath: z.string().trim().min(1).max(4096)
};
const scanSchema = { scanId: z.string().uuid() };
const startDeepScanSchema = {
  scanId: z.string().uuid().optional()
    .describe("Existing app-created or previously returned Deep Scan ID."),
  targetPath: z.string().trim().min(1).max(4096).optional()
    .describe("Resolved local target path for a first terminal or headless Deep Scan call."),
  scope: z.string().trim().min(1).max(4096).optional()
    .describe("Scope inside targetPath. Deep Scan currently requires the whole target."),
  userContext: editableUserContextSchema.optional()
    .describe("Optional security focus supplied by the user."),
  handoffClaimToken: handoffClaimTokenSchema.optional()
    .describe("Existing Deep Scan continuation claim. Pass the same token on every scanId resume, including after an MCP server restart.")
};
const continuationMutationClaimSchema = {
  handoffClaimToken: handoffClaimTokenSchema.optional().describe("Opaque continuation token returned by the native launcher. Pass it on every progress, completion, or failure update after a resume.")
};
const scanContextUpdateSchema = {
  ...scanSchema,
  ...continuationMutationClaimSchema,
  userContext: editableUserContextSchema.describe("Complete replacement context for the running scan. Pass an empty string to clear it.")
};
const appScanContextUpdateSchema = {
  ...scanSchema,
  userContext: editableUserContextSchema
};
const phaseProgressUnitSchema = z.enum([
  "checks",
  "threat_surfaces",
  "review_receipts",
  "candidate_findings",
  "validated_findings",
  "report_artifacts"
]);
const progressSchema = {
  deepReviewPass: z.number().int().positive().optional()
    .describe("Current Deep Scan discovery pass. Send it when starting each pass together with that pass's total and zero completed items."),
  phase: z.enum(["preflight", "threat_model", "discovery", "validation", "attack_path", "reporting"])
    .optional()
    .describe("Current workflow phase. Send it immediately when the scan enters a new phase so persisted progress advances."),
  phaseItemsCompleted: z.number().int().nonnegative().optional()
    .describe("Completed authoritative coverage, receipts, or artifacts for the current phase. Increase it only after the corresponding work product exists."),
  phaseItemsTotal: z.number().int().nonnegative().optional()
    .describe("Expected authoritative coverage, receipts, or artifacts for the current phase. Increase it before newly discovered work begins."),
  phaseProgressUnit: phaseProgressUnitSchema.optional()
    .describe("What phaseItemsTotal and phaseItemsCompleted count for the current phase."),
  preflightChecks: z.array(currentScanPreflightCheckSchema).max(32).optional()
    .describe("Current standard or diff scan preflight results. Project every helper results entry to capability, reason, severity, and status only. The server derives the item counts and visible block/warn attention items."),
  reportableFindingsCount: z.number().int().nonnegative().optional(),
  reviewItemsCompleted: z.number().int().nonnegative().optional()
    .describe("Cumulative completed reviews or coverage surfaces in the current discovery pass. Increment only after the corresponding review is complete."),
  reviewItemsTotal: z.number().int().nonnegative().optional()
    .describe("Expected reviews or coverage surfaces in the current discovery pass. Increase it before assigning newly discovered work."),
  scanId: z.string().uuid(),
  ...continuationMutationClaimSchema
};
const failSchema = {
  ...continuationMutationClaimSchema,
  message: z.string().trim().min(1).max(2400),
  scanId: z.string().uuid()
};
const completeScanSchema = {
  ...scanSchema,
  ...continuationMutationClaimSchema
};
const occurrenceIdSchema = z.string().trim().min(1).max(256);
const scanReadSchema = {
  ...scanSchema,
  occurrenceId: occurrenceIdSchema.optional().describe("Optional finding occurrence to include even when it is outside the bounded findings prefix.")
};
const scanContextSchema = {
  ...scanReadSchema,
  handoffClaimToken: handoffClaimTokenSchema.optional().describe("Opaque delivery token returned by the native scan launcher. Pass it once so Pi can acknowledge that this continuation received the scan.")
};
const findingTriageSchema = {
  closeReason: z.enum(["already_fixed", "wont_fix", "false_positive"]).optional(),
  note: z.string().trim().max(2400).optional(),
  occurrenceId: occurrenceIdSchema,
  status: z.enum(["open", "closed"])
};
const findingRemediationSchema = {
  actionToken: z.string().uuid(),
  baseRevision: z.string().trim().min(1).max(512).optional(),
  expectedVersion: z.number().int().positive(),
  occurrenceId: occurrenceIdSchema,
  patchDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/).optional(),
  patchPath: z.string().trim().min(1).max(4096).optional(),
  requestId: z.string().uuid(),
  state: z.enum(["generated", "applied", "verifying", "verified", "failed"]),
  summary: z.string().trim().max(2400).optional(),
  verificationSummary: z.string().trim().max(2400).optional()
};
const findingRemediationRequestSchema = {
  actionToken: z.string().uuid(),
  occurrenceId: occurrenceIdSchema,
  requestId: z.string().uuid()
};
const findingRemediationActionRequestSchema = {
  action: z.enum(["apply", "verify"]),
  actionToken: z.string().uuid(),
  expectedVersion: z.number().int().positive(),
  occurrenceId: occurrenceIdSchema,
  requestId: z.string().uuid()
};
const findingRemediationClaimSchema = {
  actionToken: z.string().uuid(),
  occurrenceId: occurrenceIdSchema,
  requestId: z.string().uuid()
};
const findingsExportSchema = {
  format: z.enum(["csv", "json", "sarif"]),
  scanId: z.string().uuid()
};
const collectionPageSchema = {
  limit: z.number().int().positive().max(50).optional(),
  offset: z.number().int().nonnegative().optional()
};
const findingCollectionFiltersSchema = {
  query: z.string().trim().max(512).optional(),
  severity: z.enum(["critical", "high", "medium", "low", "informational"]).optional(),
  status: z.enum(["open", "closed"]).optional()
};
const targetCollectionFiltersSchema = {
  query: z.string().trim().max(512).optional(),
  targetId: z.string().trim().min(1).max(256).optional()
};
const findingsPageSchema = {
  ...collectionPageSchema,
  ...findingCollectionFiltersSchema,
  scanId: z.string().uuid()
};
const globalFindingsPageSchema = {
  ...findingCollectionFiltersSchema,
  limit: z.number().int().positive().max(20).optional(),
  offset: z.number().int().nonnegative().optional(),
  targetId: z.string().trim().min(1).max(256).optional()
};
const scanListSchema = {
  ...collectionPageSchema,
  ...targetCollectionFiltersSchema,
  mode: z.enum(["diff", "standard", "deep"]).optional(),
  status: z.enum(["running", "complete", "failed", "canceled"]).optional()
};
const repositoryListSchema = {
  ...collectionPageSchema,
  ...targetCollectionFiltersSchema,
  status: z.enum(["scanned", "not_scanned", "open_findings"]).optional()
};
export function createPiSecurityServer(): McpServer {
  const server = new McpServer(
    { name: "pi-security", version: MCP_APP_VERSION },
    { capabilities: { logging: {} } }
  );
  registerPiSecurityLifecycleTools(server as unknown as LifecycleRegistrationServer);
  return server;
}

export function createPiSecurityLifecycleCatalog(): LifecycleToolCatalog {
  const catalog = createLifecycleCatalogServer();
  registerPiSecurityLifecycleTools(catalog.server);
  return {
    tools: catalog.registrations,
    dispose() {
      catalog.server.server.onclose?.();
    }
  };
}

function registerPiSecurityLifecycleTools(server: LifecycleRegistrationServer): void {
  const deepScanCoordinators = new DeepScanCoordinatorRegistry();
  const deepScanStartLock = new DeepScanStartLock();
  const deepScanExecutionContexts = new Map<string, ExecutionPolicyContext>();
  const bindDeepScanExecutionContext = (
    scanId: string,
    targetRoot: string,
    artifactRoot: string,
  ): void => {
    deepScanExecutionContexts.set(scanId, createExecutionPolicyContext({
      profile: "security-artifact-writer",
      target: { root: targetRoot },
      scan: { id: scanId, artifactRoot },
    }));
  };
  const deepScanStore = new WorkbenchDeepScanStore(
    runWorkbench,
    async (scanId) => (
      deepScanExecutionContexts.get(scanId ?? "")
      ?? await serverExecutionContext()
    ),
    runPreflightWorkbench,
  );
  const authenticatedArtifactClaims = new Map<string, {
    claimToken: string;
    threadId: string;
  }>();
  server.server.onclose = () => deepScanCoordinators.shutdown("mcp_transport_closed");
  const appMeta = { ui: { visibility: ["app"] as const } };
  const modelActionMeta = { ui: { visibility: ["model"] as const } };

  server.registerTool("start_pi_security_standard_scan", {
    title: "Start or Join Pi Security Standard Scan",
    description: "Headless and CLI only. Start or rejoin a Standard security scan. Do not use for desktop scans, Review changes, Deep Scan, or an existing externally managed scan. Use the returned authoritative scanId, scanDir, and handoffClaimToken throughout preflight, reporting, and completion.",
    inputSchema: startHeadlessStandardScanSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: modelActionMeta
  }, async ({ targetPath, scope, targetSummary, userContext }, extra) => {
    const threadId = threadIdFromExtra(extra);
    if (!threadId) {
      return toolErrorResult("Starting a Standard scan requires the owning host session context.");
    }
    const started = await startHeadlessStandardScan(
      { targetPath, scope, targetSummary, userContext },
      threadId,
      piModelSettingsFromExtra(extra)
    );
    const scan = isJsonObject(started.scan) ? started.scan : undefined;
    const progress = isJsonObject(scan?.progress) ? scan.progress : undefined;
    const workspace = isJsonObject(started.workspace) ? started.workspace : undefined;
    const workspaceResults = isJsonObject(workspace?.results) ? workspace.results : undefined;
    const scanId = scan?.scanId;
    const scanDir = scan?.scanDir;
    const handoffClaimToken = scan?.handoffClaimToken;
    if (
      (started.startDisposition !== "created" && started.startDisposition !== "joined")
      || typeof scanId !== "string"
      || !z.string().uuid().safeParse(scanId).success
      || typeof handoffClaimToken !== "string"
      || !z.string().uuid().safeParse(handoffClaimToken).success
      || typeof scanDir !== "string"
      || !scanDir.trim()
      || scan?.mode !== "standard"
      || scan.handoffStatus !== "delivered"
      || scan.continuationThreadId !== threadId
      || progress?.status !== "running"
      || (started.startDisposition === "created" && progress.phase !== "preflight")
      || workspaceResults?.scanId !== scanId
    ) {
      return toolErrorResult(
        "Pi Security returned malformed Standard scan ownership; no headless scan can continue."
      );
    }
    authenticatedArtifactClaims.set(scanId, {
      claimToken: handoffClaimToken,
      threadId
    });
    return {
      content: [{
        type: "text" as const,
        text: `${started.startDisposition === "created" ? "Started" : "Rejoined"} Standard scan ${scanId}. When the scan is in preflight, complete security_scan preflight before reviewing the target or creating a goal. Preserve the returned handoffClaimToken for scan progress, the semantic draft, and completion.`
      }],
      structuredContent: {
        ...redactHandoffClaimToken(started),
        scanId,
        scanDir,
        handoffClaimToken
      }
    };
  });

  server.registerTool("start_pi_security_prompt_only_scan", {
    title: "Start Pi Security Prompt-Only Scan",
    description: "Start or rejoin a Standard or diff Pi Security scan from its owning conversation. Use the returned authoritative scanId and scanDir. Standard and diff scans save progress checkpoints before their final semantic draft; the workbench writes the unsealed canonical artifacts. Complete the same scan once. Deep Scan uses start_pi_security_deep_scan instead.",
    inputSchema: startPromptOnlyScanSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: modelActionMeta
  }, async ({ mode, targetPath, scope, targetSummary, userContext, diffTarget }, extra) => {
    if (mode === "diff" && !diffTarget) {
      return toolErrorResult("Review changes prompt-only scans require diffTarget.");
    }
    if (mode === "standard" && diffTarget) {
      return toolErrorResult("Standard prompt-only scans must omit diffTarget.");
    }
    if (mode === "diff" && !wholeTargetScope(scope, targetPath)) {
      return toolErrorResult("Review changes prompt-only scans require the whole target; use scope '.'.");
    }
    const threadId = threadIdFromExtra(extra);
    if (!threadId) {
      return toolErrorResult("Starting a prompt-only scan requires the owning host session context.");
    }
    const promptOnly = await startPromptOnlyScan(
      { mode, targetPath, scope, targetSummary, userContext, diffTarget },
      threadId,
      piModelSettingsFromExtra(extra)
    );
    return promptOnlyScanResult(promptOnly);
  });

  server.registerTool("request_pi_security_user_input", {
    title: "Request Pi Security User Input",
    description: "Fallback for interactive Pi Security workflows when the host-native request_user_input tool is unavailable. Presents one to three non-sensitive multiple-choice questions through standard MCP form elicitation and waits for the user's response. Never call this tool in headless, automation, or other non-interactive sessions.",
    inputSchema: requestUserInputSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    _meta: modelActionMeta
  }, async ({ questions }, extra) => {
    const signal = abortSignalFromExtra(extra);
    if (!server.server.getClientCapabilities()?.elicitation?.form) {
      return userInputToolResult("unavailable");
    }
    try {
      const result = await server.server.elicitInput(
        buildUserInputElicitation(questions),
        {
          timeout: USER_INPUT_WAIT_TIMEOUT_MS,
          ...(signal ? { signal } : {})
        }
      );
      if (result.action !== "accept") {
        return userInputToolResult(result.action === "decline" ? "declined" : "cancelled");
      }
      if (!isJsonObject(result.content)) {
        throw new Error("Accepted user input did not contain structured answers.");
      }
      const answers: Record<string, string> = {};
      for (const question of questions) {
        const answer = result.content[question.id];
        if (
          typeof answer !== "string" ||
          !question.options.some((option) => option.label === answer)
        ) {
          throw new Error(`User input did not contain a valid answer for ${question.id}.`);
        }
        answers[question.id] = answer;
      }
      return userInputToolResult("accepted", answers);
    } catch (error) {
      if (signal?.aborted) throw error;
      await logUserInputFailure(server, error);
      return userInputToolResult("unavailable");
    }
  });

  server.registerTool("open_pi_security_workspace", {
    title: "Open Pi Security",
    description: "App-only. Create a native Pi Security workspace with the target and requested standard, diff, or deep mode, or reopen one owned by this thread by passing only sessionId. Scope is inside targetPath; use '.' or omit scope for the whole target.",
    inputSchema: openSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    _meta: appMeta
  }, async (input, extra) => {
    if (input.sessionId && Object.entries(input).some(([key, value]) => key !== "sessionId" && value !== undefined)) {
      throw new Error("sessionId only reopens an existing workspace; omit it to create a workspace with different setup fields.");
    }
    const mode = input.mode ?? (input.diffTarget ? "diff" : "standard");
    if (input.diffTarget && mode !== "diff") {
      throw new Error("diffTarget requires mode 'diff'.");
    }
    if ((mode === "diff" || mode === "deep") && !wholeTargetScope(input.scope, input.targetPath)) {
      throw new Error(`${mode === "deep" ? "Deep Scan" : "Review changes"} requires the whole target; use scope '.'.`);
    }
    const threadId = threadIdFromExtra(extra);
    if (!threadId && !input.sessionId) {
      return openWorkspaceResult(await createWorkspace({ ...input, mode }));
    }
    if (!threadId) {
      throw new Error("Thread metadata is required to create or reopen a Pi Security workspace.");
    }
    return openWorkspaceResult(
      input.sessionId
        ? await getWorkspace(input.sessionId, threadId)
        : await createWorkspace({ ...input, mode }, threadId)
    );
  });

  server.registerTool("inspect_pi_security_target", {
    title: "Inspect Pi Security Target",
    description: "App-only. Validate a local target directory and derive its display and Git metadata without saving setup.",
    inputSchema: targetInspectionSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ targetPath }) => {
    const target = await runWorkbench(["inspect-target", "--target-path", targetPath]);
    return {
      content: [{ type: "text" as const, text: "Validated the local Pi Security target." }],
      structuredContent: { target }
    };
  });

  server.registerTool("inspect_pi_security_setup", {
    title: "Validate Pi Security Setup",
    description: "App-only. Resolve and validate the complete local target, scope, mode, and exact Git change set without saving setup.",
    inputSchema: setupInspectionSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ targetPath, scope, mode, diffTarget }, extra) => {
    if (mode === "deep" && !supportsSamplingTools(server.server.getClientCapabilities())) {
      return toolErrorResult(deepScanSamplingToolsCapabilityMessage());
    }
    const setup = await runWorkbench([
      "inspect-setup",
      "--target-path",
      targetPath,
      "--scope",
      scope,
      "--mode",
      mode,
      ...diffTargetArgs(diffTarget)
    ]);
    return {
      content: [{ type: "text" as const, text: "Validated the local Pi Security setup." }],
      structuredContent: { setup }
    };
  });

  server.registerTool("submit_pi_security_setup", {
    title: "Save Pi Security Setup",
    description: "App-only. Validate and save bounded target, scope, mode, and optional context selections.",
    inputSchema: submissionSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ sessionId, targetPath, scope, mode, targetSummary, userContext, diffTarget }) => {
    return workspaceResult(await runWorkbench([
      "save-workspace",
      "--workspace-id",
      sessionId,
      "--target-path",
      targetPath,
      "--scope",
      scope,
      "--mode",
      mode,
      ...definedArg("--target-summary", targetSummary),
      ...(userContext ? ["--user-context-stdin"] : []),
      ...diffTargetArgs(diffTarget)
    ], userContext) as WorkspaceState);
  });

  server.registerTool("start_pi_security_scan", {
    title: "Start Pi Security Scan",
    description: "App-only. Create a scan record and its local artifact directory before Pi analysis begins.",
    inputSchema: startScanSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    _meta: appMeta
  }, async ({ sessionId, model, reasoningEffort }) => {
    try {
    const existingWorkspace = await getWorkspace(
      sessionId,
      undefined,
      runPreflightWorkbench,
    );
    const expectedMode = existingWorkspace.mode;
    const expectedTargetPath = existingWorkspace.targetPath;
    if (
      expectedMode === undefined
      || typeof expectedTargetPath !== "string"
      || !expectedTargetPath.trim()
    ) {
      throw new Error("Save the Pi Security setup before starting the scan.");
    }
    const startScan = async (
      root: string,
      executionContext: ExecutionPolicyContext,
    ): Promise<WorkspaceState> => {
      const workspace = await runStartScanWorkbench([
        "start-scan",
        "--workspace-id",
        sessionId,
        "--expected-mode",
        expectedMode,
        "--expected-target-path",
        expectedTargetPath,
        ...optionalArg("--model", model),
        ...optionalArg("--reasoning-effort", reasoningEffort),
        "--scan-root",
        root,
        ...(!CONFIGURED_SCAN_ROOT ? ["--private-scan-root"] : []),
      ], executionContext) as WorkspaceState;
      await serverExecutionContext();
      return workspace;
    };
    if (existingWorkspace.mode !== "deep") {
      let artifactMechanisms: readonly PlatformEnforcementMechanism[] = [];
      try {
        const artifactProbePath = await scanRootEnforcementProbePath();
        artifactMechanisms = await probeDirectoryHandleEnforcement(
          artifactProbePath,
          "Pi Security app scan artifact-root parent preflight",
        );
        const executionContext = createExecutionPolicyContext({
          profile: "security-artifact-writer",
          target: { root: artifactProbePath },
          scan: { id: "pi-security-app-start", artifactRoot: artifactProbePath },
        });
        return workspaceResult(await startScan(
          await scanRootPathWithoutCreating(),
          executionContext,
        ));
      } catch (error) {
        if (!(error instanceof EnforcementUnsupportedError)) throw error;
        return unsupportedEnforcementToolResult(describePiEnforcementCapabilities({
          kind: "availability",
          piTools: true,
          artifactRoots: false,
          trustedWorkbench: true,
          continuationPolicy: true,
          platformMechanisms: artifactMechanisms,
        }));
      }
    }
    if (!supportsSamplingTools(server.server.getClientCapabilities())) {
      return unsupportedEnforcementToolResult(describePiEnforcementCapabilities({
        kind: "availability",
        piTools: true,
        samplingTools: false,
        artifactRoots: true,
        trustedWorkbench: true,
        continuationPolicy: true,
      }));
    }
    let targetMechanisms: readonly PlatformEnforcementMechanism[] = [];
    let artifactMechanisms: readonly PlatformEnforcementMechanism[] = [];
    try {
      const workspace = await deepScanStartLock.run(async () => {
        targetMechanisms = await probeDirectoryHandleEnforcement(
          expectedTargetPath,
          "Pi Security app Deep Scan target preflight",
        );
        const artifactProbePath = await scanRootEnforcementProbePath();
        artifactMechanisms = await probeDirectoryHandleEnforcement(
          artifactProbePath,
          "Pi Security app Deep Scan artifact-root parent preflight",
        );
        const startExecutionContext = createExecutionPolicyContext({
          profile: "security-artifact-writer",
          target: { root: artifactProbePath },
          scan: { id: "pi-security-app-start", artifactRoot: artifactProbePath },
        });
        const enforcementCapabilities = describePiEnforcementCapabilities({
          kind: "availability",
          piTools: true,
          samplingTools: true,
          targetHandles: true,
          artifactRoots: true,
          trustedWorkbench: true,
          continuationPolicy: true,
          platformMechanisms: [
            ...new Set([...targetMechanisms, ...artifactMechanisms]),
          ],
        });
        assertPiEnforcementSupported(enforcementCapabilities);
        // Starting the scan and creating its root are one post-negotiation commit.
        return await startScan(
          await scanRootPathWithoutCreating(),
          startExecutionContext,
        );
      });
      return workspaceResult(workspace);
    } catch (error) {
      if (!(error instanceof EnforcementUnsupportedError)) throw error;
      return unsupportedEnforcementToolResult(describePiEnforcementCapabilities({
        kind: "availability",
        piTools: true,
        samplingTools: true,
        targetHandles: targetMechanisms.length > 0,
        artifactRoots: artifactMechanisms.length > 0,
        trustedWorkbench: true,
        continuationPolicy: true,
        platformMechanisms: [
          ...new Set([...targetMechanisms, ...artifactMechanisms]),
        ],
      }));
    }
    } catch (error) {
      if (
        error instanceof WorkbenchSetupChangedError
        || error instanceof WorkbenchStateNotFoundError
      ) {
        return workbenchPreflightErrorResult(error);
      }
      throw error;
    }
  });

  server.registerTool("start_pi_security_deep_scan", {
    title: "Start or Join Pi Security Deep Scan",
    description: "Run or rejoin independent Standard security scans and semantically merge their validated findings. Pass scanId and its handoffClaimToken to resume, or targetPath to start headlessly. The call blocks until the aggregate draft is ready, fails, or is canceled. On success, manifestPath identifies the canonical parent scan-manifest.json; call complete_pi_security_scan once.",
    inputSchema: startDeepScanSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: modelActionMeta
  }, async ({ scanId, targetPath, scope, userContext, handoffClaimToken }, extra) => {
    const samplingAvailable = supportsSamplingTools(server.server.getClientCapabilities());
    if (!samplingAvailable) {
      return unsupportedEnforcementToolResult(describePiEnforcementCapabilities({
        kind: "availability",
        piTools: true,
        samplingTools: false,
        artifactRoots: true,
        trustedWorkbench: true,
        continuationPolicy: true,
      }));
    }
    const hasScanId = scanId !== undefined;
    const hasTarget = targetPath !== undefined;
    const normalizedUserContext = userContext || undefined;
    if (hasScanId === hasTarget) {
      return toolErrorResult("Pass exactly one Deep Scan identity: either scanId, or targetPath for a first terminal/headless call.");
    }
    if (hasScanId && (scope !== undefined || normalizedUserContext !== undefined)) {
      return toolErrorResult("When scanId is present, omit targetPath, scope, and userContext; the persisted scan is authoritative.");
    }
    if (hasTarget && !wholeTargetScope(scope, targetPath)) {
      return toolErrorResult("Deep Scan currently requires the whole target; use scope '.'.");
    }
    if (hasTarget && handoffClaimToken !== undefined) {
      return toolErrorResult("handoffClaimToken is only valid with an existing Deep Scan ID.");
    }
    const threadId = threadIdFromExtra(extra);
    if (!threadId) {
      return toolErrorResult("Starting or joining a Deep Scan requires the owning host session context.");
    }
    const modelSettings = piModelSettingsFromExtra(extra);
    const continuationPolicyValidator = new SamplingWorkerExecutor(
      server.server as LifecycleRegistrationServer["server"] & SamplingClient,
    );
    let targetMechanisms: readonly PlatformEnforcementMechanism[] = [];
    let artifactMechanisms: readonly PlatformEnforcementMechanism[] = [];
    const preparation = await deepScanStartLock.run(async () => {
      let scanRootForBegin: string | undefined;
      let persistedExecutionBinding: {
        scanId: string;
        targetPath: string;
        scanDir: string;
      } | undefined;
      if (hasTarget) {
        const authoritativeTarget = targetPath!;
        targetMechanisms = await probeDirectoryHandleEnforcement(
          authoritativeTarget,
          "Pi Security Deep Scan target preflight",
        );
        const artifactProbePath = await scanRootEnforcementProbePath();
        artifactMechanisms = await probeDirectoryHandleEnforcement(
          artifactProbePath,
          "Pi Security Deep Scan artifact-root parent preflight",
        );
        // Root creation is the commit point and occurs only after every
        // enforcement gate above has succeeded.
        scanRootForBegin = await scanRoot();
      } else {
        const bindings = await deepScanStore.preflight({
          scanId: scanId!,
          threadId,
          handoffClaimToken,
        });
        const authoritativeTarget = bindings.targetPath;
        const authoritativeArtifactRoot = bindings.scanDir;
        await assertPersistedScanRootAuthority(authoritativeArtifactRoot);
        [targetMechanisms, artifactMechanisms] = await Promise.all([
          probeDirectoryHandleEnforcement(
            authoritativeTarget,
            "Pi Security Deep Scan persisted target preflight",
          ),
          probeDirectoryHandleEnforcement(
            authoritativeArtifactRoot,
            "Pi Security Deep Scan persisted artifact-root preflight",
          ),
        ]);
        await validateResumableWorkerPolicies(
          bindings,
          continuationPolicyValidator,
          PACKAGE_ROOT,
        );
        persistedExecutionBinding = bindings;
      }
      const enforcementCapabilities = describePiEnforcementCapabilities({
        kind: "availability",
        piTools: true,
        samplingTools: true,
        targetHandles: true,
        artifactRoots: true,
        trustedWorkbench: true,
        continuationPolicy: true,
        platformMechanisms: [
          ...new Set([...targetMechanisms, ...artifactMechanisms]),
        ],
      });
      assertPiEnforcementSupported(enforcementCapabilities);
      if (persistedExecutionBinding) {
        bindDeepScanExecutionContext(
          persistedExecutionBinding.scanId,
          persistedExecutionBinding.targetPath,
          persistedExecutionBinding.scanDir,
        );
      }
      const begun = await deepScanStore.begin({
        scanId,
        targetPath,
        scope: hasTarget ? scope ?? "." : undefined,
        userContext: normalizedUserContext,
        handoffClaimToken,
        threadId,
        ...modelSettings,
        ...(scanRootForBegin ? { scanRoot: scanRootForBegin } : {}),
      });
      bindDeepScanExecutionContext(
        begun.run.scanId,
        begun.run.targetPath,
        begun.run.scanDir,
      );
      if (handoffClaimToken) {
        authenticatedArtifactClaims.set(begun.run.scanId, {
          claimToken: handoffClaimToken,
          threadId
        });
      }
      const immediate = deepScanTerminalResult(begun.run, enforcementCapabilities);
      if (immediate) return { begun, immediate, enforcementCapabilities };
      const started = await startOrJoinDeepScanCoordinator({
        begin: begun,
        registry: deepScanCoordinators,
        options: {
          store: deepScanStore,
          executor: new SamplingWorkerExecutor(
            server.server as LifecycleRegistrationServer["server"] & SamplingClient,
            {
              ...(begun.run.model ? { model: begun.run.model } : {}),
              ...(begun.run.reasoningEffort
                ? { reasoningEffort: begun.run.reasoningEffort }
                : {})
            }
          ),
          packageRoot: PACKAGE_ROOT,
          log: logDeepScanEvent,
          handoffClaimToken,
          threadId,
          onComplete: async (draft, signal) => {
            const context = await createScanArtifactContext(
              begun.run.scanId,
              runWorkbench,
              {
                requireRunning: true,
                requireClaim: true,
                handoffClaimToken,
                claimlessWriteAuthorization:
                  handoffClaimToken === undefined
                    ? begun.artifactWriteAuthorization
                    : undefined,
                packageRoot: PACKAGE_ROOT
              }
            );
            await recordPiSecurityScanDraftViaWorkbench(context, {
              ...draft,
              ...(handoffClaimToken === undefined ? {} : { handoffClaimToken })
            }, runWorkbench, signal);
          },
          onStopped: async (run) => {
            await runWorkbench([
              "preserve-scan-results", "--scan-id", run.scanId,
              "--thread-id", threadId,
              ...optionalArg("--claim-token", handoffClaimToken),
              ...optionalArg("--coordinator-generation", run.coordinatorGeneration?.toString())
            ]);
          }
        }
      });
      return { begun, ...started, enforcementCapabilities };
    }).catch((error: unknown) => ({
      invocationFailure: error instanceof EnforcementUnsupportedError
        ? unsupportedEnforcementToolResult(describePiEnforcementCapabilities({
            kind: "availability",
            piTools: true,
            samplingTools: true,
            targetHandles: targetMechanisms.length > 0,
            artifactRoots: artifactMechanisms.length > 0,
            trustedWorkbench: true,
            continuationPolicy: true,
            platformMechanisms: [
              ...new Set([...targetMechanisms, ...artifactMechanisms]),
            ],
          }))
        : error instanceof WorkbenchStateNotFoundError
          ? workbenchPreflightErrorResult(error)
        : toolErrorResult(
            deepScanInvocationFailureMessage(error),
            policyFailureStructuredContent(error),
          )
    }));
    if ("invocationFailure" in preparation) return preparation.invocationFailure;
    if ("immediate" in preparation) return preparation.immediate;
    const { begun, coordinator, joined, enforcementCapabilities } = preparation;
    if (joined) {
      logDeepScanEvent({ event: "coordinator_joined", scanId: begun.run.scanId });
    }
    const terminal = await coordinator.wait(abortSignalFromExtra(extra));
    const result = deepScanTerminalResult(terminal, enforcementCapabilities);
    if (!result) {
      return toolErrorResult(deepScanInvocationFailureMessage(
        new Error(`Deep Scan ${terminal.scanId} ended without a terminal result.`)
      ));
    }
    return result;
  });

  const cancelSecurityScan = async (scanId: string, threadId?: string) => {
    const args = [
      "cancel-scan",
      "--scan-id",
      scanId,
      ...optionalArg("--thread-id", threadId)
    ];
    let workspace: Awaited<ReturnType<typeof runWorkbench>> | undefined;
    if (threadId && deepScanCoordinators.get(scanId)) {
      await deepScanStore.get(scanId, threadId);
    }
    const canceledLocally = await deepScanCoordinators.cancelAndWait(
      scanId,
      "user_canceled_scan",
      async () => { workspace = await runWorkbench(args); }
    );
    if (!canceledLocally) workspace = await runWorkbench(args);
    if (workspace === undefined) {
      throw new Error(`Canceling scan ${scanId} did not return its workspace.`);
    }
    return workspaceResult(workspace as unknown as WorkspaceState);
  };

  server.registerTool("cancel_pi_security_scan", {
    title: "Cancel Pi Security Scan",
    description: "Stop a running scan from its owning host session, prevent further progress or completion updates, and cancel any active deterministic Deep Scan sampling workers.",
    inputSchema: scanSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    _meta: modelActionMeta
  }, async ({ scanId }, extra) => {
    const threadId = threadIdFromExtra(extra);
    if (!threadId) {
      return toolErrorResult("Open the scan's continuation thread and try again, or cancel it from the Pi Security workbench.");
    }
    return cancelSecurityScan(scanId, threadId);
  });

  server.registerTool("cancel_pi_security_scan_from_app", {
    title: "Cancel Pi Security Scan From App",
    description: "App-only. Stop a running scan from the native Pi Security workbench, prevent further progress or completion updates, and cancel any active deterministic Deep Scan sampling workers.",
    inputSchema: scanSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ scanId }) => cancelSecurityScan(scanId));

  server.registerTool("recover_pi_security_scan_results", {
    title: "Recover Pi Security Scan Results",
    description: "App-only. Explicitly validate and republish retained checkpoints for one stopped scan, updating its artifacts, finding index, and counts.",
    inputSchema: scanSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ scanId }) => scanActionResult(
    await runWorkbench(["recover-scan-results", "--scan-id", scanId]),
    "Recovered retained Pi Security scan results."
  ));

  registerScanHandoffTools(server, { appMeta, runWorkbench, workspaceResult });

  server.registerTool("get_pi_security_scan", {
    title: "Get Pi Security Scan",
    description: "App-only. Read package-owned scan state for local security monitoring without claiming a pending Pi handoff.",
    inputSchema: scanReadSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ scanId, occurrenceId }) => scanActionResult(
    await runWorkbench([
      "get-scan",
      "--scan-id",
      scanId,
      ...optionalArg("--occurrence-id", occurrenceId)
    ]),
    "Loaded Pi Security scan state."
  ));

  server.registerTool("list_pi_security_scans", {
    title: "List Pi Security Scans",
    description: "App-only. Read persisted package-owned scan summaries for local security navigation.",
    inputSchema: scanListSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ limit, mode, offset, query, status, targetId }) => scanActionResult(
    await runWorkbench([
      "list-scans",
      ...optionalArg("--query", query),
      ...optionalArg("--target-id", targetId),
      ...optionalArg("--status", status),
      ...optionalArg("--mode", mode),
      ...optionalNumberArg("--offset", offset),
      ...optionalNumberArg("--limit", limit)
    ]),
    "Loaded Pi Security scan summaries."
  ));

  server.registerTool("list_pi_security_global_findings", {
    title: "List Pi Security Global Findings",
    description: "App-only. Read the latest package-owned finding occurrence for each stable repository target and finding identity.",
    inputSchema: globalFindingsPageSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ limit, offset, query, severity, status, targetId }) => scanActionResult(
    await runWorkbench([
      "list-global-findings",
      ...optionalArg("--query", query),
      ...optionalArg("--severity", severity),
      ...optionalArg("--status", status),
      ...optionalArg("--target-id", targetId),
      ...optionalNumberArg("--offset", offset),
      ...optionalNumberArg("--limit", limit)
    ]),
    "Loaded Pi Security global findings."
  ));

  server.registerTool("list_pi_security_repositories", {
    title: "List Pi Security Repositories",
    description: "App-only. Read package-owned repository summaries and their latest scan state.",
    inputSchema: repositoryListSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ limit, offset, query, status, targetId }) => scanActionResult(
    await runWorkbench([
      "list-repositories",
      ...optionalArg("--query", query),
      ...optionalArg("--target-id", targetId),
      ...optionalArg("--status", status),
      ...optionalNumberArg("--offset", offset),
      ...optionalNumberArg("--limit", limit)
    ]),
    "Loaded Pi Security repositories."
  ));

  server.registerTool("get_pi_security_scan_context", {
    title: "Get Pi Security Scan Context",
    description: "Load the authoritative target, mode, optional user context, artifact directory, live progress, and optional selected finding for a launched scan. Validated legacy finding details may be migrated.",
    inputSchema: scanContextSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: modelActionMeta
  }, async ({ scanId, occurrenceId, handoffClaimToken }, extra) => {
    const threadId = threadIdFromExtra(extra);
    if (handoffClaimToken) {
      await runWorkbench([
        "mark-handoff-delivered",
        "--scan-id",
        scanId,
        "--claim-token",
        handoffClaimToken,
        ...optionalArg("--thread-id", threadId)
      ]);
    }
    const scanContext = await runWorkbench([
      "get-scan",
      "--scan-id",
      scanId,
      ...optionalArg("--occurrence-id", occurrenceId)
    ]);
    const scan = isJsonObject(scanContext.scan) ? scanContext.scan : undefined;
    if (!handoffClaimToken && scan?.handoffStatus === "pending") {
      const detail = typeof scan.handoffClaimToken === "string"
        ? "Pass the handoffClaimToken returned by the Pi Security scan launcher."
        : "Claim the pending Pi Security scan handoff before loading its context.";
      throw new Error(`This Pi Security scan handoff has not been delivered. ${detail}`);
    }
    if (
      handoffClaimToken
      && threadId
      && scan?.handoffStatus === "delivered"
      && scan.handoffClaimToken === handoffClaimToken
      && (
        scan.continuationThreadId === threadId
        || recoveryHandoffClaimTokenSchema.safeParse(handoffClaimToken).success
      )
    ) {
      authenticatedArtifactClaims.set(scanId, {
        claimToken: handoffClaimToken,
        threadId
      });
    }
    return scanActionResult(
      redactHandoffClaimToken(scanContext),
      "Loaded Pi Security scan context."
    );
  });

  const updateRunningScanContext = async (input: {
    claimToken?: string;
    scanId: string;
    threadId?: string;
    userContext: string;
    workspaceId?: string;
  }) => {
    const updated = await runWorkbench([
      "update-scan-context",
      "--scan-id",
      input.scanId,
      "--user-context-stdin",
      ...definedArg("--workspace-id", input.workspaceId),
      ...definedArg("--thread-id", input.threadId),
      ...optionalArg("--claim-token", input.claimToken)
    ], input.userContext);
    return scanActionResult(updated, "Updated Pi Security scan context.");
  };

  server.registerTool("update_pi_security_scan_context", {
    title: "Update Pi Security Scan Context",
    description: "Replace the context for a running scan. The next phase uses the new value; workers in the current phase keep their original context.",
    inputSchema: scanContextUpdateSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: modelActionMeta
  }, async ({ scanId, userContext, handoffClaimToken }, extra) => {
    const threadId = threadIdFromExtra(extra);
    if (!threadId) {
      return toolErrorResult("Updating scan context requires the owning host session.");
    }
    return updateRunningScanContext({
      claimToken: handoffClaimToken,
      scanId,
      threadId,
      userContext
    });
  });

  server.registerTool("update_pi_security_scan_context_from_app", {
    title: "Update Pi Security Scan Context From App",
    description: "App-only. Replace the context for the running scan attached to this workspace.",
    inputSchema: appScanContextUpdateSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ scanId, userContext }) => {
    const current = await runWorkbench(["get-scan", "--scan-id", scanId]);
    const workspace = isJsonObject(current.workspace) ? current.workspace : undefined;
    if (typeof workspace?.id !== "string") {
      return toolErrorResult("Updating scan context requires its owning workspace.");
    }
    return updateRunningScanContext({
      scanId,
      userContext,
      workspaceId: workspace.id
    });
  });

  server.registerTool("update_pi_security_scan_progress", {
    title: "Update Pi Security Scan Progress",
    description: "Record a meaningful live scan phase or coverage milestone in the Pi Security workbench.",
    inputSchema: progressSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: modelActionMeta
  }, async ({ scanId, deepReviewPass, phase, phaseItemsTotal, phaseItemsCompleted, phaseProgressUnit, preflightChecks, reviewItemsTotal, reviewItemsCompleted, reportableFindingsCount, handoffClaimToken }, extra) => {
    const modelSettings = piModelSettingsFromExtra(extra);
    const current = await runWorkbench(["get-scan", "--scan-id", scanId]);
    const scan = isJsonObject(current.scan) ? current.scan : undefined;
    const progress = scan && isJsonObject(scan.progress) ? scan.progress : undefined;
    if (
      progress?.status === "running"
      && typeof scan?.handoffClaimToken === "string"
      && scan.handoffClaimToken !== handoffClaimToken
    ) {
      return toolErrorResult("Scan updates are owned by another continuation.");
    }
    if (scan?.mode === "deep" && progress?.phase === "preflight" && progress.status === "running") {
      return scanActionResult(
        redactHandoffClaimToken(current),
        "Deep Scan is still preparing. Discovery progress begins after its setup worker succeeds."
      );
    }
    if (preflightChecks !== undefined && (
      phaseItemsTotal !== undefined
      || phaseItemsCompleted !== undefined
      || phaseProgressUnit !== undefined
    )) {
      throw new Error(
        "preflightChecks derives phaseItemsTotal, phaseItemsCompleted, and phaseProgressUnit; omit those fields."
      );
    }
    const preflightIssues = preflightChecks?.filter((check) =>
      (check.severity === "block" || check.severity === "warn")
      && (check.status === "fail" || check.status === "unknown")
    );
    const derivedPhaseItemsTotal = preflightChecks?.length ?? phaseItemsTotal;
    const derivedPhaseItemsCompleted = preflightChecks
      ? preflightChecks.filter((check) => check.status !== "unknown").length
      : phaseItemsCompleted;
    const derivedPhaseProgressUnit = preflightChecks ? "checks" : phaseProgressUnit;
    const serializedPreflightIssues = preflightIssues
      ? JSON.stringify(preflightIssues)
      : undefined;
    return scanActionResult(await runWorkbench([
      "update-progress",
      "--scan-id",
      scanId,
      ...(scan?.mode === "deep" ? deepScanStore.coordinatorLeaseArgs(scanId) : []),
      ...optionalArg("--model", modelSettings.model),
      ...optionalArg("--reasoning-effort", modelSettings.reasoningEffort),
      ...optionalArg("--claim-token", handoffClaimToken),
      ...optionalNumberArg("--deep-review-pass", deepReviewPass),
      ...optionalArg("--phase", phase),
      ...optionalNumberArg("--phase-items-total", derivedPhaseItemsTotal),
      ...optionalNumberArg("--phase-items-completed", derivedPhaseItemsCompleted),
      ...optionalArg("--phase-progress-unit", derivedPhaseProgressUnit),
      ...(serializedPreflightIssues ? ["--preflight-issues-json-stdin"] : []),
      ...optionalNumberArg("--review-items-total", reviewItemsTotal),
      ...optionalNumberArg("--review-items-completed", reviewItemsCompleted),
      ...optionalNumberArg("--reportable-findings-count", reportableFindingsCount)
    ], serializedPreflightIssues), "Updated Pi Security scan progress.");
  });

  server.registerTool("complete_pi_security_scan", {
    title: "Complete Pi Security Scan",
    description: "Finalization only: validate and seal already-authored scan-manifest.json, findings.json, and coverage.json, generate report.md, index findings, and mark the scan complete. For an app-backed running scan, scan-manifest.json is an unsealed draft and must omit scan.sealedAt and scan.artifacts; this tool supplies the exact workbench timestamps, seal, artifact digests, and derived finding identities. Call only after those canonical files exist; this tool does not create missing artifacts or run skipped phases. If it fails, surface the exact error and stop the current response without retrying completion or returning a final, no-findings, structured, or benchmark response.",
    inputSchema: completeScanSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: modelActionMeta
  }, async ({ scanId, handoffClaimToken }) => {
    try {
      return scanActionResult(await runWorkbench([
        "complete-scan",
        "--scan-id",
        scanId,
        ...optionalArg("--claim-token", handoffClaimToken)
      ]), "Validated and indexed the completed Pi Security scan.");
    } catch (error) {
      throw new Error(completionFailureMessage(error));
    }
  });

  server.registerTool("fail_pi_security_scan", {
    title: "Fail Pi Security Scan",
    description: "Permanently mark a launched Pi Security scan as failed only after a confirmed unrecoverable blocker. For explicit user cancellation, use cancel_pi_security_scan instead. This terminal action cannot be resumed; incomplete or otherwise resumable work must remain running.",
    inputSchema: failSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    _meta: modelActionMeta
  }, async ({ scanId, message, handoffClaimToken }) => {
    const failed = await runWorkbench([
      "fail-scan",
      "--scan-id",
      scanId,
      "--message",
      message,
      ...optionalArg("--claim-token", handoffClaimToken)
    ]);
    deepScanCoordinators.failExternallyPersisted(scanId, message);
    return scanActionResult(failed, "Recorded the Pi Security scan failure.");
  });

  server.registerTool("set_pi_security_finding_triage", {
    title: "Update Pi Security Finding Status",
    description: "App-only. Persist a completed finding's local open or closed triage status. Closed findings require one bounded close reason; reopening clears it.",
    inputSchema: findingTriageSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ occurrenceId, status, closeReason, note }) => scanActionResult(await runWorkbench([
    "set-finding-triage",
    "--occurrence-id",
    occurrenceId,
    "--status",
    status,
    ...optionalArg("--close-reason", closeReason),
    ...definedArg("--note", note)
  ]), "Updated the local Pi Security finding status."));

  server.registerTool("request_pi_security_finding_remediation", {
    title: "Request Pi Security Finding Remediation",
    description: "App-only. Queue a completed finding for Pi remediation before sending the host a generate or regenerate request.",
    inputSchema: findingRemediationRequestSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ occurrenceId, requestId, actionToken }) => scanActionResult(await runWorkbench([
    "request-finding-remediation",
    "--occurrence-id",
    occurrenceId,
    "--request-id",
    requestId,
    "--action-token",
    actionToken
  ]), "Queued the local Pi Security finding remediation request."));

  server.registerTool("request_pi_security_finding_remediation_action", {
    title: "Request Pi Security Finding Remediation Action",
    description: "App-only. Durably claim an apply or verify handoff before asking Pi to perform the local working-tree operation.",
    inputSchema: findingRemediationActionRequestSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ occurrenceId, requestId, expectedVersion, action, actionToken }) => scanActionResult(await runWorkbench([
    "request-finding-remediation-action",
    "--occurrence-id",
    occurrenceId,
    "--request-id",
    requestId,
    "--expected-version",
    String(expectedVersion),
    "--action",
    action,
    "--action-token",
    actionToken
  ]), `Queued the local Pi Security finding remediation ${action} request.`));

  server.registerTool("claim_pi_security_finding_remediation_resend", {
    title: "Claim Pi Security Finding Remediation Resend",
    description: "App-only. Atomically take ownership of an unowned or stale remediation host request before resending it.",
    inputSchema: findingRemediationClaimSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ occurrenceId, requestId, actionToken }) => scanActionResult(await runWorkbench([
    "claim-finding-remediation-resend",
    "--occurrence-id",
    occurrenceId,
    "--request-id",
    requestId,
    "--action-token",
    actionToken
  ]), "Claimed the local Pi Security finding remediation resend."));

  server.registerTool("release_pi_security_finding_remediation_claim", {
    title: "Release Pi Security Finding Remediation Claim",
    description: "App-only. Release a locally owned remediation host request after message delivery fails.",
    inputSchema: findingRemediationClaimSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ occurrenceId, requestId, actionToken }) => scanActionResult(await runWorkbench([
    "release-finding-remediation-claim",
    "--occurrence-id",
    occurrenceId,
    "--request-id",
    requestId,
    "--action-token",
    actionToken
  ]), "Released the local Pi Security finding remediation claim."));

  server.registerTool("cancel_pi_security_finding_remediation_request", {
    title: "Cancel Pi Security Finding Remediation Request",
    description: "App-only. Roll back an owned remediation request after the user declines its host follow-up.",
    inputSchema: findingRemediationClaimSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ occurrenceId, requestId, actionToken }) => scanActionResult(await runWorkbench([
    "cancel-finding-remediation-request",
    "--occurrence-id",
    occurrenceId,
    "--request-id",
    requestId,
    "--action-token",
    actionToken
  ]), "Canceled the local Pi Security finding remediation request."));

  server.registerTool("mark_pi_security_finding_remediation_delivered", {
    title: "Mark Pi Security Finding Remediation Delivered",
    description: "App-only. Seal host-message delivery ownership before Pi starts a remediation worker.",
    inputSchema: findingRemediationClaimSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ occurrenceId, requestId, actionToken }) => scanActionResult(await runWorkbench([
    "mark-finding-remediation-delivered",
    "--occurrence-id",
    occurrenceId,
    "--request-id",
    requestId,
    "--action-token",
    actionToken
  ]), "Marked the local Pi Security finding remediation request as delivered."));

  server.registerTool("set_pi_security_finding_remediation", {
    title: "Update Pi Security Finding Remediation",
    description: "Persist the bounded local remediation workflow state for a completed finding. The UI may mark a request as queued; Pi records generated, applied, verifying, verified, or failed states after performing the corresponding work.",
    inputSchema: findingRemediationSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    _meta: modelActionMeta
  }, async ({ occurrenceId, requestId, actionToken, expectedVersion, state, summary, patchPath, patchDigest, baseRevision, verificationSummary }) => scanActionResult(await runWorkbench([
    "set-finding-remediation",
    "--occurrence-id",
    occurrenceId,
    "--request-id",
    requestId,
    ...optionalArg("--action-token", actionToken),
    "--expected-version",
    String(expectedVersion),
    "--state",
    state,
    ...definedArg("--summary", summary),
    ...definedArg("--patch-path", patchPath),
    ...definedArg("--patch-digest", patchDigest),
    ...definedArg("--base-revision", baseRevision),
    ...definedArg("--verification-summary", verificationSummary)
  ]), "Updated the local Pi Security finding remediation state."));

  server.registerTool("export_pi_security_findings", {
    title: "Export Pi Security Findings",
    description: "App-only. Export retained local findings from completed, failed, or canceled scans as canonical JSON, deterministic SARIF, or a CSV projection. Exported files remain inside the sealed scan directory.",
    inputSchema: findingsExportSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ scanId, format }) => scanActionResult(await runWorkbench([
    "export-findings",
    "--scan-id",
    scanId,
    "--format",
    format
  ]), `Exported Pi Security findings as ${format.toUpperCase()}.`));

  server.registerTool("list_pi_security_findings", {
    title: "List Pi Security Findings",
    description: "App-only. Load one bounded page of indexed findings for a completed local scan, migrating validated legacy finding details when needed.",
    inputSchema: findingsPageSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ limit, offset, query, scanId, severity, status }) => scanActionResult(await runWorkbench([
    "list-findings",
    "--scan-id",
    scanId,
    ...optionalArg("--query", query),
    ...optionalArg("--severity", severity),
    ...optionalArg("--status", status),
    ...optionalNumberArg("--offset", offset),
    ...optionalNumberArg("--limit", limit)
  ]), "Loaded a local Pi Security findings page."));

  registerCompactArtifactTools(server, {
    runWorkbench,
    packageRoot: PACKAGE_ROOT,
    resolveHandoffClaimToken: (scanId, requestContext) => {
      const claim = authenticatedArtifactClaims.get(scanId);
      return claim && claim.threadId === threadIdFromExtra(requestContext)
        ? claim.claimToken
        : undefined;
    }
  });

}

async function createWorkspace(input: {
  diffTarget?: z.infer<typeof diffTargetSchema>;
  mode?: "diff" | "standard" | "deep";
  scope?: string;
  targetPath?: string;
  targetSummary?: string;
  targetTitle?: string;
  userContext?: string;
}, threadId?: string): Promise<WorkspaceState> {
  return await runWorkbench([
    "create-workspace",
    "--workspace-id",
    randomUUID(),
    ...optionalArg("--thread-id", threadId),
    ...optionalArg("--mode", input.mode),
    ...optionalArg("--target-path", input.targetPath),
    ...optionalArg("--target-title", input.targetTitle),
    ...optionalArg("--target-summary", input.targetSummary),
    ...optionalArg("--scope", input.scope),
    ...(input.userContext ? ["--user-context-stdin"] : []),
    ...diffTargetArgs(input.diffTarget)
  ], input.userContext) as WorkspaceState;
}

async function getWorkspace(
  workspaceId: string,
  threadId?: string,
  runner: typeof runWorkbench = runWorkbench,
): Promise<WorkspaceState> {
  return await runner([
    "get-workspace",
    "--workspace-id",
    workspaceId,
    ...optionalArg("--thread-id", threadId),
  ]) as WorkspaceState;
}

async function startPromptOnlyScan(
  input: PromptOnlyScanInput,
  threadId: string,
  modelSettings: { model?: string; reasoningEffort?: string } = {}
): Promise<JsonObject> {
  const { mode, targetPath, scope, targetSummary, userContext, diffTarget } = input;
  return await runWorkbench([
    "start-prompt-only-scan",
    "--thread-id",
    threadId,
    "--target-path",
    targetPath,
    "--scope",
    scope,
    "--mode",
    mode,
    ...optionalArg("--model", modelSettings.model),
    ...optionalArg("--reasoning-effort", modelSettings.reasoningEffort),
    ...optionalArg("--target-summary", targetSummary),
    ...(userContext ? ["--user-context-stdin"] : []),
    ...diffTargetArgs(diffTarget),
    "--scan-root",
    await scanRoot()
  ], userContext);
}

async function startHeadlessStandardScan(
  input: {
    targetPath: string;
    scope?: string;
    targetSummary?: string;
    userContext?: string;
  },
  threadId: string,
  modelSettings: { model?: string; reasoningEffort?: string } = {}
): Promise<JsonObject> {
  return await runWorkbench([
    "start-headless-standard-scan",
    "--thread-id",
    threadId,
    "--target-path",
    input.targetPath,
    "--scope",
    input.scope ?? ".",
    ...optionalArg("--model", modelSettings.model),
    ...optionalArg("--reasoning-effort", modelSettings.reasoningEffort),
    ...optionalArg("--target-summary", input.targetSummary),
    ...(input.userContext ? ["--user-context-stdin"] : []),
    "--scan-root",
    await scanRoot()
  ], input.userContext);
}

function wholeTargetScope(scope: string | undefined, targetPath: string | undefined): boolean {
  if (scope === undefined || scope === ".") return true;
  return Boolean(targetPath && resolve(scope) === resolve(targetPath));
}

function openWorkspaceResult(workspace: WorkspaceState) {
  const result = workspaceResult(workspace);
  if (result.structuredContent.workspace.results) {
    delete result.structuredContent.workspace.results.handoffClaimToken;
  }
  return result;
}

function redactHandoffClaimToken(result: JsonObject) {
  const scan = isJsonObject(result.scan) ? result.scan : undefined;
  if (scan) {
    delete scan.handoffClaimToken;
  }
  const workspace = isJsonObject(result.workspace) ? result.workspace : undefined;
  const workspaceResults = workspace && isJsonObject(workspace.results)
    ? workspace.results
    : undefined;
  if (workspaceResults) {
    delete workspaceResults.handoffClaimToken;
  }
  return result;
}

function workspaceResult(workspace: WorkspaceState) {
  const results = workspace.results;
  const setupSummary = workspace.setup.submitted
    ? "Pi Security setup is saved."
    : "Waiting for bounded scan setup choices.";
  const resultsSummary = results && typeof results.scanDir === "string"
    ? ` Scan state is attached at ${results.scanDir}.`
    : "";
  return {
    content: [{ type: "text" as const, text: `${setupSummary}${resultsSummary}` }],
    structuredContent: { workspace }
  };
}

function promptOnlyScanResult(promptOnly: JsonObject) {
  const startDisposition = promptOnly.startDisposition;
  const scan = isJsonObject(promptOnly.scan) ? promptOnly.scan : undefined;
  const workspace = isJsonObject(promptOnly.workspace) ? promptOnly.workspace : undefined;
  const workspaceResults = isJsonObject(workspace?.results) ? workspace.results : undefined;
  const scanId = scan?.scanId;
  const scanDir = scan?.scanDir;
  if (
    (startDisposition !== "created" && startDisposition !== "joined") ||
    !z.string().uuid().safeParse(scanId).success ||
    typeof scanDir !== "string" ||
    !scanDir.trim() ||
    scan?.handoffStatus !== "delivered" ||
    workspaceResults?.scanId !== scanId
  ) {
    return toolErrorResult(
      "Pi Security prompt-only scan returned malformed context; no prompt-driven scan was started."
    );
  }
  const disposition = startDisposition === "joined" ? "Rejoined" : "Started";
  return {
    content: [{
      type: "text" as const,
      text: `${disposition} prompt-driven scan ${scanId}. Use the returned scanId and scanDir for every phase. Author scan-manifest.json as an unsealed draft: omit scan.sealedAt and scan.artifacts because completion supplies the exact workbench timestamps, seal, artifact digests, and derived finding identities. Then call complete_pi_security_scan once to index the completed findings.`
    }],
    structuredContent: promptOnly
  };
}

function scanActionResult(result: JsonObject, summary: string) {
  return {
    content: [{ type: "text" as const, text: summary }],
    structuredContent: result
  };
}

function toolErrorResult(message: string, structuredContent?: JsonObject) {
  return {
    content: [{ type: "text" as const, text: message }],
    ...(structuredContent ? { structuredContent } : {}),
    isError: true
  };
}

function unsupportedEnforcementToolResult(
  report: EnforcementCapabilityReport
) {
  const error = new EnforcementUnsupportedError(
    report.unsupportedReason
      ?? "Pi Security cannot enforce the required host capabilities."
  );
  return toolErrorResult(error.message, {
    error: {
      schemaVersion: 1,
      code: error.code,
      category: error.category,
      message: error.message
    },
    enforcementCapabilities: report
  });
}
function workbenchPreflightErrorResult(
  error: WorkbenchSetupChangedError | WorkbenchStateNotFoundError,
) {
  return toolErrorResult(error.message, {
    error: {
      schemaVersion: 1,
      code: error.code,
      category: error instanceof WorkbenchSetupChangedError
        ? error.category
        : "workbench_state_not_found",
      retryable: error instanceof WorkbenchSetupChangedError,
      message: error.message,
    },
  });
}


function policyFailureStructuredContent(
  error: unknown,
  persisted?: DeepScanRunState["policyFailure"],
): JsonObject | undefined {
  const failure = persisted ?? describePolicyEnforcementFailure(error);
  return failure ? { error: { ...failure } } : undefined;
}

function deepScanSamplingToolsCapabilityMessage(): string {
  return [
    "Deep Scan requires an MCP 2025-11-25 client that advertises sampling.tools.",
    "Basic sampling without tool use cannot inspect the coordinator-bound repository.",
    "Use a Standard scan or reconnect with sampling tool support."
  ].join(" ");
}

function buildUserInputElicitation(
  questions: z.infer<typeof userInputQuestionsSchema>
) {
  const isSingleQuestion = questions.length === 1;
  return {
    mode: "form" as const,
    message: isSingleQuestion
      ? questions[0]!.question
      : "Pi Security needs your input before it can continue.",
    requestedSchema: {
      type: "object" as const,
      properties: Object.fromEntries(questions.map((question) => [
        question.id,
        {
          type: "string" as const,
          title: question.header,
          oneOf: question.options.map((option) => ({
            const: option.label,
            title: option.label
          }))
        }
      ])),
      required: questions.map((question) => question.id)
    }
  };
}

function userInputToolResult(
  status: "accepted" | "declined" | "cancelled" | "unavailable",
  answers?: Record<string, string>
) {
  const text = status === "accepted"
    ? `The user answered the Pi Security question: ${JSON.stringify(answers)}.`
    : status === "declined"
      ? "The user declined the Pi Security input request. Do not infer an answer."
      : status === "cancelled"
        ? "The Pi Security input request was cancelled. Do not infer an answer."
        : "Structured Pi Security input is unavailable in this host. Use the documented plain-chat fallback.";
  return {
    content: [{ type: "text" as const, text }],
    structuredContent: {
      status,
      ...(answers ? { answers } : {})
    }
  };
}

async function logUserInputFailure(
  server: Pick<LifecycleRegistrationServer, "sendLoggingMessage">,
  error: unknown
): Promise<void> {
  const errorData = boundedErrorData(error);
  try {
    await server.sendLoggingMessage({
      level: "warning",
      logger: "pi-security.user-input",
      data: {
        event: "elicitation_failed",
        error: errorData
      }
    });
  } catch {
    console.warn(
      "Pi Security user-input elicitation failed:",
      JSON.stringify(errorData)
    );
  }
}

function boundedErrorData(error: unknown): { message: string; name: string } {
  const name = error instanceof Error && error.name.trim() ? error.name : "UnknownError";
  const message = error instanceof Error
    ? error.message
    : typeof error === "string"
      ? error
      : "Unknown user-input elicitation failure.";
  return {
    name: name.slice(0, 128),
    message: message.slice(0, 1000)
  };
}

export function deepScanTerminalResult(
  run: DeepScanRunState,
  enforcementCapabilities?: EnforcementCapabilityReport
) {
  if (run.status === "succeeded") {
    if (!run.manifestPath) return undefined;
    return {
      content: [{
        type: "text" as const,
        text: `Deep Scan discovery completed. Independent Standard scans have already performed validation and attack-path analysis and have been consolidated into the canonical scan-manifest.json, findings.json, and coverage.json under ${run.scanDir}. The returned manifestPath is the canonical scan-manifest.json, not a legacy discovery manifest. Any instructions requiring parent candidate listing, centralized validation, attack-path analysis, or another draft apply only to the old discovery-only workflow and must be skipped. The authoritative scan ID is ${run.scanId}. Immediately call complete_pi_security_scan once using that scan ID to seal and publish the scan. Return output only after completion succeeds and generated report.md exists. If completion fails, surface that exact error and return no final, no-findings, structured, or benchmark response.`
      }],
      structuredContent: {
        manifestPath: run.manifestPath,
        diagnostics: run.diagnostics ?? null,
        ...(enforcementCapabilities ? { enforcementCapabilities } : {})
      }
    };
  }
  if (run.status === "canceled") {
    if (run.error?.trim()) {
      return toolErrorResult(deepScanFailureMessage(run), {
        status: run.status,
        scanId: run.scanId,
        ...(enforcementCapabilities ? { enforcementCapabilities } : {}),
        ...(policyFailureStructuredContent(undefined, run.policyFailure) ?? {}),
      });
    }
    return {
      content: [{ type: "text" as const, text: `Deep Scan ${run.scanId} was canceled. Saved findings and pending candidates remain available in the scan's retained results. Do not start additional scan work or claim complete coverage.` }],
      structuredContent: {
        status: "canceled",
        scanId: run.scanId,
        ...(enforcementCapabilities ? { enforcementCapabilities } : {})
      }
    };
  }
  if (run.status === "failed" || run.status === "interrupted") {
    return toolErrorResult(deepScanFailureMessage(run), {
      status: run.status,
      scanId: run.scanId,
      ...(enforcementCapabilities ? { enforcementCapabilities } : {}),
      ...(policyFailureStructuredContent(undefined, run.policyFailure) ?? {}),
    });
  }
  return undefined;
}

function logDeepScanEvent(event: {
  event: string;
  scanId: string;
  workerId?: string;
  kind?: string;
  attempt?: number;
  count?: number;
  completed?: number;
  newFindings?: number;
  pass?: number;
  reason?: string;
  threadId?: string;
  total?: number;
}): void {
  console.error(JSON.stringify({ component: "pi_security_deep_scan", ...event }));
}
async function runPreflightWorkbench(
  args: string[],
  input?: string
): Promise<JsonObject> {
  const executionContext = await preflightExecutionContext();
  let pythonCommand: string | undefined;
  try {
    pythonCommand = await resolvePythonCommand();
    const stateDir = CONFIGURED_WORKBENCH_STATE_DIR
      ?? (fallbackWorkbenchStateDir ? await fallbackWorkbenchStateDir : undefined);
    return await executeWorkbench(
      executionContext,
      pythonCommand,
      args,
      stateDir,
      input,
      true,
    );
  } catch (error) {


    if (execErrorExitCode(error) === READ_ONLY_PREFLIGHT_NOT_FOUND_EXIT) {
      throw new WorkbenchStateNotFoundError({ cause: error });
    }
    const launchError = pythonCommand
      ? missingPythonHelperMessage(error, pythonCommand)
      : undefined;
    if (launchError) throw new Error(launchError);
    if (isExecError(error) && error.stderr.trim()) {
      throw new Error(error.stderr.trim(), { cause: error });
    }
    throw error;
  }
}
async function runStartScanWorkbench(
  args: string[],
  executionContext: ExecutionPolicyContext,
): Promise<JsonObject> {
  let pythonCommand: string | undefined;
  try {
    pythonCommand = await resolvePythonCommand();
    return await executeWorkbenchWithStateSelection(
      executionContext,
      pythonCommand,
      args,
    );
  } catch (error) {
    if (execErrorExitCode(error) === WORKBENCH_SETUP_CHANGED_EXIT) {
      throw new WorkbenchSetupChangedError({ cause: error });
    }
    const launchError = pythonCommand
      ? missingPythonHelperMessage(error, pythonCommand)
      : undefined;
    if (launchError) throw new Error(launchError);
    if (isExecError(error) && error.stderr.trim()) {
      throw new Error(error.stderr.trim(), { cause: error });
    }
    throw error;
  }
}


async function runWorkbench(
  args: string[],
  input?: string
): Promise<JsonObject> {
  const executionContext = await serverExecutionContext();
  let pythonCommand: string | undefined;
  try {
    pythonCommand = await resolvePythonCommand();
    return await executeWorkbenchWithStateSelection(
      executionContext,
      pythonCommand,
      args,
      input,
    );
  } catch (error) {
    if (execErrorExitCode(error) === WORKBENCH_SETUP_CHANGED_EXIT) {
      throw new WorkbenchSetupChangedError({ cause: error });
    }
    const launchError = pythonCommand
      ? missingPythonHelperMessage(error, pythonCommand)
      : undefined;
    if (launchError) {
      throw new Error(launchError);
    }
    if (isExecError(error) && error.stderr.trim()) {
      throw new Error(error.stderr.trim(), { cause: error });
    }
    throw error;
  }
}

async function executeWorkbenchWithStateSelection(
  executionContext: ExecutionPolicyContext,
  pythonCommand: string,
  args: string[],
  input?: string
): Promise<JsonObject> {
  if (WORKBENCH_COMMANDS_WITHOUT_DATABASE.has(args[0] ?? "")) {
    return await executeWorkbench(executionContext, pythonCommand, args, undefined, input);
  }
  if (CONFIGURED_WORKBENCH_STATE_DIR) {
    return await executeWorkbench(executionContext, pythonCommand, args, undefined, input);
  }
  if (fallbackWorkbenchStateDir) {
    return await executeWorkbench(
      executionContext,
      pythonCommand,
      args,
      await fallbackWorkbenchStateDir,
      input,
    );
  }
  if (persistentWorkbenchStateSucceeded) {
    return await executeWorkbench(executionContext, pythonCommand, args, undefined, input);
  }
  return await withWorkbenchStateSelectionLock(async () => {
    if (fallbackWorkbenchStateDir) {
      return await executeWorkbench(
        executionContext,
        pythonCommand,
        args,
        await fallbackWorkbenchStateDir,
        input,
      );
    }
    if (persistentWorkbenchStateSucceeded) {
      return await executeWorkbench(executionContext, pythonCommand, args, undefined, input);
    }
    try {
      const result = await executeWorkbench(
        executionContext,
        pythonCommand,
        args,
        undefined,
        input,
      );
      persistentWorkbenchStateSucceeded = true;
      return result;
    } catch (error) {
      if (!isUnwritableSqliteOpenError(error)) throw error;
      const fallbackStateDir = await pinFallbackWorkbenchStateDir();
      logWorkbenchStateFallback();
      return await executeWorkbench(
        executionContext,
        pythonCommand,
        args,
        fallbackStateDir,
        input,
      );
    }
  });
}

async function withWorkbenchStateSelectionLock<T>(operation: () => Promise<T>): Promise<T> {
  const predecessor = workbenchStateSelectionTail;
  let release!: () => void;
  workbenchStateSelectionTail = new Promise<void>((resolvePromise) => {
    release = resolvePromise;
  });
  await predecessor;
  try {
    return await operation();
  } finally {
    release();
  }
}

async function executeWorkbench(
  executionContext: ExecutionPolicyContext,
  pythonCommand: string,
  args: string[],
  stateDir?: string,
  input?: string,
  readOnlyPreflight = false,
): Promise<JsonObject> {
  const userContextIndex = args.indexOf("--user-context");
  const userContext = userContextIndex === -1 ? undefined : args[userContextIndex + 1];
  const workbenchArgs = [...args];
  if (userContextIndex !== -1) {
    workbenchArgs.splice(userContextIndex, 2, "--user-context-stdin");
  }
  const workbenchInput = input ?? userContext;
  const environment = { ...process.env };
  delete environment[READ_ONLY_PREFLIGHT_ENV];
  if (stateDir) environment.PI_SECURITY_STATE_DIR = stateDir;
  if (readOnlyPreflight) environment[READ_ONLY_PREFLIGHT_ENV] = "1";
  const execution = executeTrustedWorkbench(
    executionContext,
    () => execFileAsync(pythonCommand, [workbenchScriptPath(), ...workbenchArgs], {
      cwd: PACKAGE_ROOT,
      env: environment,
      encoding: "utf8" as const,
      maxBuffer: 4 * 1024 * 1024,
      timeout: [
        "begin-deep-scan",
        "claim-deep-scan-dedup",
        "commit-deep-scan-dedup",
        "complete-scan",
        "export-findings",
        "finish-deep-scan",
        "get-scan",
        "get-deep-scan",
        "get-workspace",
        "inspect-setup",
        "list-findings",
        "preserve-scan-results",
        "recover-scan-results",
        "request-finding-remediation",
        "request-finding-remediation-action",
        "save-workspace",
        "set-finding-triage",
        "set-finding-remediation",
        "start-headless-standard-scan",
        "start-prompt-only-scan",
        "start-scan",
        "upsert-deep-scan-worker"
      ].includes(args[0] ?? "") ? 300_000 : 30_000
    }),
  );
  if (workbenchInput !== undefined) {
    execution.child.stdin!.on("error", () => {
      // The workbench may exit before consuming stdin; surface its process error.
    });
    execution.child.stdin!.end(workbenchInput);
  }
  const { stdout } = await execution;
  const result = JSON.parse(stdout) as unknown;
  if (!isJsonObject(result)) {
    throw new Error("Pi Security workbench helper returned invalid JSON.");
  }
  return result;
}

async function pinFallbackWorkbenchStateDir(): Promise<string> {
  fallbackWorkbenchStateDir ??= (async () => {
    const stateDir = join(await scanRoot(), "workbench-state");
    await fs.mkdir(stateDir, { recursive: true, mode: 0o700 });
    return stateDir;
  })();
  return await fallbackWorkbenchStateDir;
}

function logWorkbenchStateFallback(): void {
  if (fallbackWorkbenchStateLogged) return;
  fallbackWorkbenchStateLogged = true;
  console.error(JSON.stringify({
    component: "pi_security_workbench",
    event: "state_fallback_pinned",
    reason: "persistent_sqlite_unwritable"
  }));
}

function workbenchScriptPath(): string {
  return join(PACKAGE_ROOT, "scripts", "workbench_db.py");
}

function optionalArg(name: string, value: string | undefined): string[] {
  return value ? [name, value] : [];
}

function definedArg(name: string, value: string | undefined): string[] {
  return value === undefined ? [] : [name, value];
}

function optionalNumberArg(name: string, value: number | undefined): string[] {
  return value === undefined ? [] : [name, String(value)];
}

function diffTargetArgs(target: z.infer<typeof diffTargetSchema> | undefined): string[] {
  if (!target) return [];
  return [
    "--diff-target-kind",
    target.kind,
    ...optionalArg("--diff-base-revision", "baseRevision" in target ? target.baseRevision : undefined),
    ...optionalArg("--diff-head-revision", "headRevision" in target ? target.headRevision : undefined),
    ...optionalArg("--diff-content-digest", "contentDigest" in target ? target.contentDigest : undefined)
  ];
}

function isJsonObject(value: unknown): value is JsonObject {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function threadIdFromExtra(extra: unknown): string | undefined {
  if (!isJsonObject(extra)) return undefined;
  if (typeof extra.sessionId === "string" && extra.sessionId.trim()) {
    return extra.sessionId.trim();
  }
  const requestInfo = isJsonObject(extra.requestInfo) ? extra.requestInfo : undefined;
  const metadata = isJsonObject(requestInfo?._meta)
    ? requestInfo._meta
    : isJsonObject(extra._meta)
      ? extra._meta
      : undefined;
  for (const key of ["sessionId", "session_id", "threadId", "thread_id"]) {
    const value = metadata?.[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  const session = isJsonObject(metadata?.session) ? metadata.session : undefined;
  if (typeof session?.id === "string" && session.id.trim()) return session.id.trim();
  return undefined;
}

function piModelSettingsFromExtra(extra: unknown): {
  model?: string;
  reasoningEffort?: string;
} {
  if (!isJsonObject(extra)) return {};
  const requestInfo = isJsonObject(extra.requestInfo) ? extra.requestInfo : undefined;
  const metadata = isJsonObject(requestInfo?._meta)
    ? requestInfo._meta
    : isJsonObject(extra._meta)
      ? extra._meta
      : undefined;
  const model = typeof metadata?.model === "string"
    ? metadata.model.trim()
    : undefined;
  const reasoningEffort = typeof metadata?.reasoningEffort === "string"
    ? metadata.reasoningEffort.trim()
    : undefined;
  return {
    ...(model ? { model } : {}),
    ...(reasoningEffort ? { reasoningEffort } : {})
  };
}

function abortSignalFromExtra(extra: unknown): AbortSignal | undefined {
  if (!isJsonObject(extra)) return undefined;
  return extra.signal instanceof AbortSignal ? extra.signal : undefined;
}

function execErrorExitCode(error: unknown): number | undefined {
  if (!error || typeof error !== "object" || !("code" in error)) return undefined;
  return typeof error.code === "number" ? error.code : undefined;
}

function isExecError(error: unknown): error is { stderr: string } {
  return Boolean(error && typeof error === "object" && "stderr" in error && typeof error.stderr === "string");
}

function completionFailureMessage(error: unknown): string {
  const diagnostic = error instanceof Error && error.message.trim()
    ? error.message.trim()
    : String(error);
  return [
    "Pi Security scan completion failed.",
    diagnostic,
    "Stop the current response and surface this exact MCP error.",
    "Do not retry completion or return a final, no-findings, structured, or benchmark response."
  ].join("\n");
}

function deepScanInvocationFailureMessage(error: unknown): string {
  const diagnostic = error instanceof Error && error.message.trim()
    ? error.message.trim()
    : String(error);
  return [
    "Pi Security Deep Scan discovery did not start or rejoin.",
    diagnostic,
    "Stop the current response and surface this exact MCP error.",
    "Do not call start_pi_security_deep_scan again in this response.",
    "Do not call get_pi_security_scan_context in this response.",
    "Do not call complete_pi_security_scan in this response.",
    "Do not start a replacement Deep Scan, call cancel, return a final or no-findings result, satisfy a structured output schema, or emit benchmark JSON."
  ].join("\n");
}

function deepScanFailureMessage(run: DeepScanRunState): string {
  const manifest = run.manifestPath ? ` Failure manifest: ${run.manifestPath}.` : "";
  const diagnostic = `${run.error ?? `Deep Scan ${run.scanId} ${run.status}.`}${manifest}`;
  return [
    diagnostic,
    "This is a terminal failure of this logical Deep Scan; no successful discovery manifest was returned.",
    "Stop further scanning and surface this exact stable MCP failure. Read the existing scan context to report saved findings and pending candidates separately, with incomplete coverage.",
    "Do not call start_pi_security_deep_scan again in this response.",
    "Do not call complete_pi_security_scan in this response.",
    "Do not start a replacement Deep Scan, call cancel for this terminal scan, claim a successful or no-findings scan, satisfy a successful-scan output schema, or emit benchmark JSON."
  ].join("\n");
}

function isUnwritableSqliteOpenError(error: unknown): boolean {
  const diagnostic = isExecError(error)
    ? error.stderr
    : error instanceof Error
      ? error.message
      : "";
  return /sqlite3\.OperationalError:\s*unable to open database file/i.test(diagnostic);
}
