import {
  createScanArtifactContext,
  type RunArtifactWorkbench,
} from "../artifact-context.js";
import { recordPiSecurityCandidateAttackPaths } from "../artifact-attack-path.js";
import { recordPiSecurityDiscoveryCandidates } from "../artifact-discovery.js";
import { preparePiSecurityReviewItems } from "../artifact-inventory.js";
import {
  getPiSecurityCompletedScan,
  recordPiSecurityScanDraftViaWorkbench,
  type ScanDraftInput,
} from "../artifact-scan-draft.js";
import { recordPiSecurityCandidateValidations } from "../artifact-validation-phase.js";
import { BUILT_IN_PHASE_REGISTRY } from "./builtin.js";
import {
  parsePhaseResultEnvelope,
  type PhaseExecutionContext,
  type PhaseExecutor,
  type PhaseResultEnvelope,
} from "./scheduler.js";

type DiscoveryOutput = Parameters<typeof recordPiSecurityDiscoveryCandidates>[0];
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
  recordDiscovery(output: DiscoveryOutput): Promise<void>;
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
  const model = (sideEffect?: (output: unknown) => Promise<void>): PhaseExecutor => async (context) => {
    const delivery = await runModel(context);
    const definition = BUILT_IN_PHASE_REGISTRY.get(context.phase.type, context.phase.version);
    const output = parsePhaseResultEnvelope(delivery, {
      outputSchema: definition.outputSchema,
      phaseId: context.phase.id,
      runId: context.runId,
    });
    if (sideEffect) await sideEffect(output);
    return { ...delivery, output };
  };

  return Object.freeze({
    "attack-path": model((output) => services.recordAttackPaths(output as AttackPathOutput)),
    discovery: model((output) => services.recordDiscovery(output as DiscoveryOutput)),
    preflight: async (context) => hostDelivery(context, await services.prepareReviewItems()),
    publication: async (context) => {
      const report = context.inputs.report as {
        coverage: Record<string, unknown>;
        findings: Record<string, unknown>[];
        threatModel?: Record<string, unknown>;
      };
      return hostDelivery(context, await services.publish(report));
    },
    reduction: model(),
    reporting: model(),
    "threat-model": model(),
    validation: model((output) => services.recordValidations(output as ValidationOutput)),
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
      await recordPiSecurityDiscoveryCandidates(output, await context(true));
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
      await recordPiSecurityScanDraftViaWorkbench(
        await context(true),
        input,
        options.runWorkbench,
      );
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
