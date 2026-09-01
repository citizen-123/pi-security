import type { LifecycleRequestContext, LifecycleToolRegistrar } from "./catalog.js";
import type { ZodType } from "zod/v4";
import {
  createScanArtifactContext,
  type ArtifactContext,
  type RunArtifactWorkbench
} from "../artifact-context.js";
import { assertExecutionCapability } from "../execution-policy.js";
import {
  listPiSecurityReviewItems,
  preparePiSecurityReviewItems,
  prepareReviewItemsInputSchema,
  reviewItemsReaderInputSchema
} from "../artifact-inventory.js";
import {
  listPiSecurityCandidates,
  recordPiSecurityDiscoveryCandidates,
  workbenchDiscoveryCandidatesInputSchema,
  workbenchListPiSecurityCandidatesInputSchema
} from "../artifact-discovery.js";
import {
  candidateValidationsInputSchema,
  recordPiSecurityCandidateValidations
} from "../artifact-validation-phase.js";
import {
  candidateAttackPathsInputSchema,
  recordPiSecurityCandidateAttackPaths
} from "../artifact-attack-path.js";
import {
  deepReducerInputsInputSchema,
  deepReductionInputSchema,
  getPiSecurityDeepReducerInputs,
  recordPiSecurityDeepReduction
} from "../artifact-deep-reducer.js";
import {
  completedScanInputSchema,
  getPiSecurityCompletedScan,
  recordPiSecurityScanDraftViaWorkbench,
  recordPiSecurityWorkerScanDraft,
  scanDraftInputSchema,
  type ScanDraftInput
} from "../artifact-scan-draft.js";

type JsonRecord = Record<string, unknown>;

export interface CompactArtifactToolOptions {
  runWorkbench: RunArtifactWorkbench;
  packageRoot: string;
  resolveHandoffClaimToken?: (
    scanId: string,
    requestContext?: LifecycleRequestContext
  ) => string | undefined;
}

const modelOnlyMeta = {
  ui: { visibility: ["model"] as const }
};

const readingAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
};

const writingAnnotations = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
};

/** Prepare diff inventories and read existing diff or Deep inventories. */
export function registerReviewItemTools(
  registrar: LifecycleToolRegistrar,
  options: CompactArtifactToolOptions
): void {
  registerCompactTool(registrar, {
    name: "prepare_pi_security_review_items",
    title: "Prepare Pi Security Review Items",
    description: "Generate the changed-file inventory for a diff scan.",
    inputSchema: prepareReviewItemsInputSchema,
    readOnly: false,
    handler: async (value, requestContext) => {
      const input = prepareReviewItemsInputSchema.parse(value);
      return preparePiSecurityReviewItems(
        await phaseScanContext(input, options, requestContext, "diff")
      );
    }
  });

  registerCompactTool(registrar, {
    name: "list_pi_security_review_items",
    title: "List Pi Security Review Items",
    description: "Read one page of the diff or Deep scan discovery inventory.",
    inputSchema: reviewItemsReaderInputSchema,
    readOnly: true,
    handler: async (value, requestContext) => {
      const input = reviewItemsReaderInputSchema.parse(value);
      return listPiSecurityReviewItems(
        await phaseScanContext(input, options, requestContext),
        input
      );
    }
  });
}

/** Record diff candidates and read existing diff or Deep candidates. */
export function registerDiscoveryCandidateTools(
  registrar: LifecycleToolRegistrar,
  options: CompactArtifactToolOptions
): void {
  const writerSchema = workbenchDiscoveryCandidatesInputSchema;
  const readerSchema = workbenchListPiSecurityCandidatesInputSchema;

  registerCompactTool(registrar, {
    name: "record_pi_security_discovery_candidates",
    title: "Record Pi Security Discovery Candidates",
    description: "Normalize and replace the selected diff scan's candidates.",
    inputSchema: writerSchema,
    readOnly: false,
    handler: async (value, requestContext) => {
      const input = writerSchema.parse(value);
      return recordPiSecurityDiscoveryCandidates(
        { candidates: input.candidates },
        await phaseScanContext(input, options, requestContext, "diff")
      );
    }
  });

  registerCompactTool(registrar, {
    name: "list_pi_security_candidates",
    title: "List Pi Security Candidates",
    description: "Read one page of diff or Deep scan discovery candidates.",
    inputSchema: readerSchema,
    readOnly: true,
    handler: async (value, requestContext) => {
      const input = readerSchema.parse(value);
      return listPiSecurityCandidates(
        {
          ...(input.cursor === undefined ? {} : { cursor: input.cursor }),
          ...(input.limit === undefined ? {} : { limit: input.limit })
        },
        await phaseScanContext(input, options, requestContext)
      );
    }
  });
}

/** Record centralized validation results for a diff or Deep scan. */
export function registerCandidateValidationTools(
  registrar: LifecycleToolRegistrar,
  options: CompactArtifactToolOptions
): void {
  registerCompactTool(registrar, {
    name: "record_pi_security_candidate_validations",
    title: "Record Pi Security Candidate Validations",
    description: "Record the diff or Deep scan candidate validation results.",
    inputSchema: candidateValidationsInputSchema,
    readOnly: false,
    handler: async (value, requestContext) => {
      const input = candidateValidationsInputSchema.parse(value);
      return recordPiSecurityCandidateValidations(
        await phaseScanContext(input, options, requestContext),
        { validations: input.validations }
      );
    }
  });
}

/** Record centralized attack-path results for a diff or Deep scan. */
export function registerCandidateAttackPathTools(
  registrar: LifecycleToolRegistrar,
  options: CompactArtifactToolOptions
): void {
  registerCompactTool(registrar, {
    name: "record_candidate_attack_paths",
    title: "Record Pi Security Candidate Attack Paths",
    description: "Record the diff or Deep scan candidate attack-path results.",
    inputSchema: candidateAttackPathsInputSchema,
    readOnly: false,
    handler: async (value, requestContext) => {
      const input = candidateAttackPathsInputSchema.parse(value);
      return recordPiSecurityCandidateAttackPaths(
        await phaseScanContext(input, options, requestContext),
        { attackPaths: input.attackPaths }
      );
    }
  });
}

/** Register draft construction and read-only completed scan retrieval. */
export function registerScanDraftTools(
  registrar: LifecycleToolRegistrar,
  options: CompactArtifactToolOptions
): void {
  registerCompactTool(registrar, {
    name: "record_pi_security_scan_draft",
    title: "Record Pi Security Scan Draft",
    description: "Save semantic findings and coverage as an unsealed draft. Use complete:false for progress checkpoints, then complete:true for the final result; keep unvalidated candidates in coverage.deferred.",
    inputSchema: scanDraftInputSchema,
    readOnly: false,
    handler: async (value, requestContext) => {
      const input = scanDraftInputSchema.parse(value);
      return recordPiSecurityScanDraftViaWorkbench(
        await scanContext(input, options, true, requestContext),
        input,
        options.runWorkbench,
        signalFromRequestContext(requestContext)
      );
    }
  });

  registerCompactTool(registrar, {
    name: "get_pi_security_completed_scan",
    title: "Get Completed Pi Security Scan",
    description: "Read the selected scan's existing completed, sealed canonical documents.",
    inputSchema: completedScanInputSchema,
    readOnly: true,
    handler: async (value, requestContext) => {
      const input = completedScanInputSchema.parse(value);
      return getPiSecurityCompletedScan(
        await scanContext(input, options, false, requestContext),
        input
      );
    }
  });
}

function signalFromRequestContext(requestContext: unknown): AbortSignal | undefined {
  if (typeof requestContext !== "object" || requestContext === null) return undefined;
  const signal = Reflect.get(requestContext, "signal");
  return signal instanceof AbortSignal ? signal : undefined;
}

/** Keep each vertical operation independently reviewable and registered. */
export function registerCompactArtifactTools(
  registrar: LifecycleToolRegistrar,
  options: CompactArtifactToolOptions
): void {
  registerReviewItemTools(registrar, options);
  registerDiscoveryCandidateTools(registrar, options);
  registerCandidateValidationTools(registrar, options);
  registerCandidateAttackPathTools(registrar, options);
  registerScanDraftTools(registrar, options);
}

/** Expose only the operations appropriate to the inherited worker phase. */
export function registerCompactWorkerArtifactTools(
  registrar: LifecycleToolRegistrar,
  context: ArtifactContext
): void {
  if (context.layout === "worker") {
    registerCompactTool(registrar, {
      name: "record_pi_security_scan_draft",
      title: "Record Pi Security Scan Draft",
      description: "Save this Standard worker's semantic findings and coverage. Use complete:false for progress checkpoints, then complete:true for its final result; keep unvalidated candidates in coverage.deferred.",
      inputSchema: scanDraftInputSchema,
      readOnly: false,
      handler: async (value) => {
        assertExecutionCapability(
          context.executionPolicy,
          "scan-artifacts.write",
        );
        return await recordPiSecurityWorkerScanDraft(
          context,
          value as ScanDraftInput
        );
      }
    });
    return;
  }

  if (context.layout !== "reducer") {
    throw new Error("The lightweight artifact registrar requires a bound discovery or reducer worker.");
  }

  registerCompactTool(registrar, {
    name: "get_pi_security_deep_reducer_inputs",
    title: "Get Pi Security Deep Reducer Inputs",
    description: "Read the complete Standard scan results assigned to this reducer.",
    inputSchema: deepReducerInputsInputSchema,
    readOnly: true,
    handler: async () => {
      assertExecutionCapability(
        context.executionPolicy,
        "scan-artifacts.write",
      );
      return await getPiSecurityDeepReducerInputs(context);
    }
  });

  registerCompactTool(registrar, {
    name: "record_pi_security_deep_reduction",
    title: "Record Pi Security Deep Reduction",
    description: "Record this reducer's complete aggregated Standard scan result.",
    inputSchema: deepReductionInputSchema,
    readOnly: false,
    handler: async (value) => {
      assertExecutionCapability(
        context.executionPolicy,
        "scan-artifacts.write",
      );
      return await recordPiSecurityDeepReduction(
        context,
        value as ScanDraftInput
      );
    }
  });
}

interface CompactToolRegistration {
  name: string;
  title: string;
  description: string;
  inputSchema: ZodType;
  readOnly: boolean;
  handler: (value: unknown, requestContext: LifecycleRequestContext) => Promise<object>;
}

function registerCompactTool(
  registrar: LifecycleToolRegistrar,
  registration: CompactToolRegistration
): void {
  registrar.registerTool(registration.name, {
    title: registration.title,
    description: registration.description,
    inputSchema: registration.inputSchema,
    annotations: registration.readOnly ? readingAnnotations : writingAnnotations,
    _meta: modelOnlyMeta
  }, async (input: unknown, requestContext: LifecycleRequestContext) => {
    const value = await registration.handler(input, requestContext);
    return {
      content: [{ type: "text" as const, text: JSON.stringify(value) }],
      structuredContent: value as JsonRecord
    };
  });
}

async function scanContext(
  input: { scanId: string; handoffClaimToken?: string },
  options: CompactArtifactToolOptions,
  requireRunning = true,
  requestContext?: LifecycleRequestContext
): Promise<ArtifactContext> {
  return createScanArtifactContext(input.scanId, options.runWorkbench, {
    requireRunning,
    requireClaim: true,
    handoffClaimToken: input.handoffClaimToken
      ?? options.resolveHandoffClaimToken?.(input.scanId, requestContext),
    packageRoot: options.packageRoot,
  });
}

async function phaseScanContext(
  input: { scanId: string; handoffClaimToken?: string },
  options: CompactArtifactToolOptions,
  requestContext?: LifecycleRequestContext,
  requiredMode?: "diff"
): Promise<ArtifactContext> {
  const context = await scanContext(input, options, true, requestContext);
  if (context.mode !== "deep" && context.mode !== "diff") {
    throw new Error("This operation is only available for Deep or diff scans.");
  }
  if (requiredMode && context.mode !== requiredMode) {
    throw new Error("This operation is only available for diff scans.");
  }
  return context;
}
