import {
  createExecutionPolicyContext,
  describeExecutionPolicy,
  ExecutionPolicyDeniedError,
  hasExecutionCapability,
  type ExecutionCapability,
  type ExecutionPolicyContext,
} from "../execution-policy.js";

export type SamplingPolicyAuthority = "source" | "artifactWriter" | "delegation";

export interface SamplingPolicyRequirement {
  readonly authority: SamplingPolicyAuthority;
  readonly capability: ExecutionCapability;
}

export interface SamplingPolicyTool<Definition extends { name: string }> {
  readonly definition: Definition;
  readonly available: boolean;
  readonly requirements: readonly SamplingPolicyRequirement[];
}

export interface BoundMcpSamplingPolicy<Definition extends { name: string }> {
  definitions(): Definition[];
  assertAuthorized(name: string): void;
}

/** Bind advertised definitions and direct dispatch to the same issued authorities. */
export function bindMcpSamplingPolicy<Definition extends { name: string }>(input: {
  readonly source: () => ExecutionPolicyContext;
  readonly artifactWriter: () => ExecutionPolicyContext;
  readonly delegation: () => ExecutionPolicyContext;
  readonly tools: readonly SamplingPolicyTool<Definition>[];
}): BoundMcpSamplingPolicy<Definition> {
  const known = new Map<string, SamplingPolicyTool<Definition>>();
  for (const tool of input.tools) {
    if (known.has(tool.definition.name)) {
      throw new Error(`Duplicate Pi Security sampling tool ${JSON.stringify(tool.definition.name)}.`);
    }
    if (tool.requirements.length === 0) {
      throw new Error(`Pi Security sampling tool ${JSON.stringify(tool.definition.name)} has no policy requirement.`);
    }
    known.set(tool.definition.name, tool);
  }

  const contextFor = (authority: SamplingPolicyAuthority): ExecutionPolicyContext => {
    switch (authority) {
      case "source": return input.source();
      case "artifactWriter": return input.artifactWriter();
      case "delegation": return input.delegation();
    }
  };
  const allowed = (tool: SamplingPolicyTool<Definition>): boolean => tool.available
    && tool.requirements.every((requirement) => hasExecutionCapability(
      contextFor(requirement.authority),
      requirement.capability,
    ));

  // Resolve every supplied authority now so a forged context cannot create a
  // seemingly valid empty surface and fail only after sampling begins.
  describeExecutionPolicy(input.source());
  describeExecutionPolicy(input.artifactWriter());
  describeExecutionPolicy(input.delegation());

  return Object.freeze({
    definitions(): Definition[] {
      return [...known.values()]
        .filter(allowed)
        .map((tool) => tool.definition);
    },
    assertAuthorized(name: string): void {
      const tool = known.get(name);
      if (!tool || !allowed(tool)) {
        throw new ExecutionPolicyDeniedError(
          `Unknown or unauthorized Pi Security sampling tool ${JSON.stringify(name)}.`,
        );
      }
    },
  });
}

/** Issue a host-selected Deep Scan source role; callers cannot provide a profile name. */
export function issueDeepScanSourceContext(input: {
  readonly targetRoot: string;
  readonly scanId: string;
  readonly workerRoot: string;
  readonly delegationBudget: number;
}): ExecutionPolicyContext {
  return createExecutionPolicyContext({
    profile: input.delegationBudget > 0
      ? "security-delegating-readonly"
      : "security-readonly",
    target: { root: input.targetRoot },
    scan: { id: input.scanId, artifactRoot: input.workerRoot },
    ...(input.delegationBudget > 0
      ? { delegation: { budget: input.delegationBudget } }
      : {}),
  });
}

/** Issue the fixed internal artifact role; no caller or serialized value selects it. */
export function issueDeepScanArtifactWriterContext(input: {
  readonly targetRoot: string;
  readonly scanId: string;
  readonly artifactRoot: string;
}): ExecutionPolicyContext {
  return createExecutionPolicyContext({
    profile: "security-artifact-writer",
    target: { root: input.targetRoot },
    scan: { id: input.scanId, artifactRoot: input.artifactRoot },
  });
}

/** Reconstruct the only role a persisted delegated child is allowed to have. */
export function issueDeepScanDelegatedChildAuthority(input: {
  readonly targetRoot: string;
  readonly scanId: string;
  readonly workerRoot: string;
}): ExecutionPolicyContext {
  return createExecutionPolicyContext({
    profile: "security-readonly",
    target: { root: input.targetRoot },
    scan: { id: input.scanId, artifactRoot: input.workerRoot },
  });
}
