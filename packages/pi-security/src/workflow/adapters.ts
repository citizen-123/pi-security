import {
  createScanArtifactContext,
  type RunArtifactWorkbench,
} from "../artifact-context.js";
import { recordPiSecurityCandidateAttackPaths } from "../artifact-attack-path.js";
import {
  compactDiscoveryCandidateSchema,
  type CompactDiscoveryCandidate,
  recordPiSecurityDiscoveryCandidates,
} from "../artifact-discovery.js";
import { preparePiSecurityReviewItems } from "../artifact-inventory.js";
import { readArtifactJsonl } from "../artifact-io.js";
import {
  getPiSecurityCompletedScan,
  recordPiSecurityScanDraftViaWorkbench,
  type ScanDraftInput,
} from "../artifact-scan-draft.js";
import { recordPiSecurityCandidateValidations } from "../artifact-validation-phase.js";
import { modelPhaseOutputSchema } from "./builtin.js";
import {
  parsePhaseResultEnvelope,
  type PhaseExecutionContext,
  type PhaseExecutor,
  type PhaseResultEnvelope,
} from "./scheduler.js";

type DiscoveryOutput = Parameters<typeof recordPiSecurityDiscoveryCandidates>[0];
type CanonicalDiscoveryOutput = { candidates: CompactDiscoveryCandidate[] };
type ValidationOutput = Parameters<typeof recordPiSecurityCandidateValidations>[1];
type AttackPathOutput = Parameters<typeof recordPiSecurityCandidateAttackPaths>[1];

export interface ArtifactWorkflowServices {
  prepareReviewItems(): Promise<{ reviewItemsTotal: number }>;
  publish(report: {
    coverage: Record<string, unknown>;
    findings: Record<string, unknown>[];
    threatModel?: Record<string, unknown>;
  }): Promise<{ artifacts: CanonicalArtifactReferences }>;
  recordAttackPaths(output: AttackPathOutput): Promise<void>;
  recordDiscovery(output: DiscoveryOutput): Promise<CanonicalDiscoveryOutput>;
  recordValidations(output: ValidationOutput): Promise<void>;
}

export interface CanonicalArtifactReferences {
  coverage: string;
  findings: string;
  manifest: string;
  report: string;
  sarif: string;
}

export type ModelPhaseRunner = (context: PhaseExecutionContext) => Promise<PhaseResultEnvelope>;

export function createBuiltInPhaseExecutors(
  services: ArtifactWorkflowServices,
  runModel: ModelPhaseRunner
): Readonly<Record<string, PhaseExecutor>> {
  const model = (
    accept?: (output: unknown, context: PhaseExecutionContext) => Promise<unknown>,
  ): PhaseExecutor => async (context) => {
    context.signal.throwIfAborted();
    const delivery = await runModel(context);
    context.signal.throwIfAborted();
    const output = parsePhaseResultEnvelope(delivery, {
      outputSchema: modelPhaseOutputSchema(context.phase.type, context.phase.version),
      phaseId: context.phase.id,
      runId: context.runId,
    });
    return { ...delivery, output: accept ? await accept(output, context) : output };
  };

  return Object.freeze({
    "attack-path": model(async (output) => {
      await services.recordAttackPaths(output as AttackPathOutput);
      return output;
    }),
    discovery: model((output) => services.recordDiscovery(output as DiscoveryOutput)),
    preflight: async (context) => {
      context.signal.throwIfAborted();
      return hostDelivery(context, await services.prepareReviewItems());
    },
    publication: async (context) => {
      context.signal.throwIfAborted();
      const report = context.inputs.report as {
        coverage: Record<string, unknown>;
        findings: Record<string, unknown>[];
        threatModel?: Record<string, unknown>;
      };
      return hostDelivery(context, await services.publish(report));
    },
    reduction: model(async (output, context) => {
      const discovery = context.inputs.discovery as CanonicalDiscoveryOutput;
      const reduction = output as { findings: { candidate_id: string }[] };
      const candidates = new Map<string, CompactDiscoveryCandidate>();
      for (const candidate of discovery.candidates) candidates.set(candidate.candidate_id, candidate);
      const findings: CompactDiscoveryCandidate[] = [];
      const selectedIds = new Set<string>();
      for (const finding of reduction.findings) {
        const candidate = candidates.get(finding.candidate_id);
        if (!candidate) {
          throw new Error(`Reduction names unknown candidate ${finding.candidate_id}.`);
        }
        if (selectedIds.has(finding.candidate_id)) {
          throw new Error(`Reduction repeats candidate ${finding.candidate_id}.`);
        }
        selectedIds.add(finding.candidate_id);
        findings.push(candidate);
      }
      return { findings };
    }),
    reporting: model(),
    "threat-model": model(),
    validation: model(async (output) => {
      await services.recordValidations(output as ValidationOutput);
      return output;
    }),
  });
}

export function createArtifactWorkflowServices(options: {
  handoffClaimToken?: string;
  packageRoot: string;
  runWorkbench: RunArtifactWorkbench;
  scanId: string;
}): ArtifactWorkflowServices {
  const context = (requireRunning: boolean) => createScanArtifactContext(
    options.scanId,
    options.runWorkbench,
    {
      handoffClaimToken: options.handoffClaimToken,
      packageRoot: options.packageRoot,
      requireClaim: Boolean(options.handoffClaimToken),
      requireRunning,
    },
  );
  return {
    async prepareReviewItems() {
      return await preparePiSecurityReviewItems(await context(true));
    },
    async recordDiscovery(output) {
      const discoveryContext = await context(true);
      await recordPiSecurityDiscoveryCandidates(output, discoveryContext);
      return {
        candidates: await readArtifactJsonl(
          discoveryContext,
          ["artifacts", "02_discovery", "candidate_ledger.jsonl"],
          "discovery candidates",
          compactDiscoveryCandidateSchema,
        ),
      };
    },
    async recordValidations(output) {
      await recordPiSecurityCandidateValidations(await context(true), output);
    },
    async recordAttackPaths(output) {
      await recordPiSecurityCandidateAttackPaths(await context(true), output);
    },
    async publish(report) {
      const input: ScanDraftInput = {
        complete: true,
        coverage: report.coverage,
        findings: report.findings,
        handoffClaimToken: options.handoffClaimToken,
        scanId: options.scanId,
        threatModel: report.threatModel,
      };
      const existing = await context(false);
      if (existing.status !== "complete") {
        await recordPiSecurityScanDraftViaWorkbench(
          await context(true),
          input,
          options.runWorkbench,
        );
        await options.runWorkbench([
          "complete-scan",
          "--scan-id",
          options.scanId,
          ...(options.handoffClaimToken ? ["--claim-token", options.handoffClaimToken] : []),
        ]);
      }
      await getPiSecurityCompletedScan(
        await context(false),
        { handoffClaimToken: options.handoffClaimToken, scanId: options.scanId },
      );
      return {
        artifacts: {
          coverage: "coverage.json",
          findings: "findings.json",
          manifest: "scan-manifest.json",
          report: "report.md",
          sarif: "exports/results.sarif",
        },
      };
    },
  };
}

function hostDelivery(context: PhaseExecutionContext, output: unknown): PhaseResultEnvelope {
  return {
    attemptId: `host:${context.phase.id}`,
    output,
    phaseId: context.phase.id,
    runId: context.runId,
    schemaVersion: 1,
  };
}
