import {
  EXECUTION_CAPABILITIES,
  createExecutionPolicyContext,
  describeExecutionPolicy,
  type ExecutionCapabilitySet,
  type ExecutionPolicyContext,
  type ExecutionPolicyDescription,
} from "./execution-policy.js";
import {
  PolicyRecoveryRejectedError,
} from "./enforcement-capabilities.js";

export interface PersistedExecutionPolicyState {
  readonly schemaVersion: 1;
  /** The exact fresh authority the host must present again on recovery. */
  readonly authority: ExecutionPolicyDescription;
  /** The current unspent successor after any durable delegation transitions. */
  readonly effective: ExecutionPolicyDescription;
}

export interface PersistedWorkerExecutionPolicies {
  readonly schemaVersion: 1;
  readonly source: PersistedExecutionPolicyState;
  readonly artifactWriter: PersistedExecutionPolicyState;
}

export function snapshotExecutionPolicyState(
  context: ExecutionPolicyContext,
): PersistedExecutionPolicyState {
  const description = unspentDescription(context, "Execution policy");
  return Object.freeze({
    schemaVersion: 1 as const,
    authority: description,
    effective: description,
  });
}

export function advanceExecutionPolicyState(
  persisted: PersistedExecutionPolicyState,
  successor: ExecutionPolicyContext,
): PersistedExecutionPolicyState {
  const state = parseExecutionPolicyState(persisted);
  const effective = unspentDescription(successor, "Execution policy successor");
  assertSameAuthority(state.authority, effective, false);
  if (
    effective.delegation.remainingBudget > state.effective.delegation.remainingBudget
    || effective.delegation.remainingDepth > state.effective.delegation.remainingDepth
  ) {
    throw new Error("An execution-policy successor cannot restore spent delegation authority.");
  }
  return Object.freeze({
    schemaVersion: 1 as const,
    authority: state.authority,
    effective,
  });
}

export function reissueExecutionPolicyState(
  persisted: unknown,
  authoritative: ExecutionPolicyContext,
): ExecutionPolicyContext {
  let state: PersistedExecutionPolicyState;
  try {
    state = parseExecutionPolicyState(persisted);
  } catch (error) {
    if (error instanceof PolicyRecoveryRejectedError) throw error;
    throw new PolicyRecoveryRejectedError(
      "invalid_policy",
      "The saved execution policy is invalid and cannot be reissued.",
      { cause: error },
    );
  }
  const authority = unspentDescription(authoritative, "Authoritative execution policy");
  if (!sameDescription(state.authority, authority)) {
    throw new PolicyRecoveryRejectedError(
      "profile_mismatch",
      "The saved execution policy does not match the authoritative profile, bindings, or delegation limits; recovery refuses an authority downgrade.",
    );
  }
  return issueDescription(state.effective);
}

export function parseExecutionPolicyState(
  value: unknown,
): PersistedExecutionPolicyState {
  const record = exactRecord(
    value,
    ["schemaVersion", "authority", "effective"],
    "Saved execution policy state",
  );
  if (record.schemaVersion !== 1) {
    throw new Error("The saved execution policy state has an invalid version.");
  }
  const authority = parseDescription(record.authority, "Saved execution policy authority");
  const effective = parseDescription(record.effective, "Saved effective execution policy");
  assertSameAuthority(authority, effective, false);
  if (
    effective.delegation.remainingBudget > authority.delegation.remainingBudget
    || effective.delegation.remainingDepth > authority.delegation.remainingDepth
  ) {
    throw new Error("The saved effective policy exceeds its authoritative delegation limits.");
  }
  return Object.freeze({
    schemaVersion: 1 as const,
    authority,
    effective,
  });
}

export function snapshotWorkerExecutionPolicies(input: {
  source: ExecutionPolicyContext;
  artifactWriter: ExecutionPolicyContext;
}): PersistedWorkerExecutionPolicies {
  return Object.freeze({
    schemaVersion: 1 as const,
    source: snapshotExecutionPolicyState(input.source),
    artifactWriter: snapshotExecutionPolicyState(input.artifactWriter),
  });
}

export function parseWorkerExecutionPolicies(
  value: unknown,
): PersistedWorkerExecutionPolicies {
  const record = exactRecord(
    value,
    ["schemaVersion", "source", "artifactWriter"],
    "Saved worker execution policies",
  );
  if (record.schemaVersion !== 1) {
    throw new Error("The saved worker execution policies have an invalid version.");
  }
  return Object.freeze({
    schemaVersion: 1 as const,
    source: parseExecutionPolicyState(record.source),
    artifactWriter: parseExecutionPolicyState(record.artifactWriter),
  });
}

export function reissueWorkerExecutionPolicies(
  persisted: unknown,
  authoritative: {
    source: ExecutionPolicyContext;
    artifactWriter: ExecutionPolicyContext;
  },
): { source: ExecutionPolicyContext; artifactWriter: ExecutionPolicyContext } {
  let policies: PersistedWorkerExecutionPolicies;
  try {
    policies = parseWorkerExecutionPolicies(persisted);
  } catch (error) {
    if (error instanceof PolicyRecoveryRejectedError) throw error;
    throw new PolicyRecoveryRejectedError(
      "invalid_policy",
      "The saved worker execution policies are invalid and cannot be reissued.",
      { cause: error },
    );
  }
  return Object.freeze({
    source: reissueExecutionPolicyState(policies.source, authoritative.source),
    artifactWriter: reissueExecutionPolicyState(
      policies.artifactWriter,
      authoritative.artifactWriter,
    ),
  });
}

function parseDescription(value: unknown, label: string): ExecutionPolicyDescription {
  const record = exactRecord(
    value,
    ["schemaVersion", "profile", "target", "scan", "capabilities", "delegation"],
    label,
  );
  if (record.schemaVersion !== 1 || typeof record.profile !== "string") {
    throw new Error(`${label} has an invalid profile envelope.`);
  }
  const target = exactRecord(record.target, ["root"], `${label} target`);
  const scan = exactRecord(record.scan, ["id", "artifactRoot"], `${label} scan`);
  const delegation = exactRecord(
    record.delegation,
    ["maxDepth", "remainingBudget", "remainingDepth", "childProfile", "spent"],
    `${label} delegation`,
  );
  const capabilitiesRecord = exactRecord(
    record.capabilities,
    [...EXECUTION_CAPABILITIES],
    `${label} capabilities`,
  );
  if (
    typeof target.root !== "string"
    || typeof scan.id !== "string"
    || typeof scan.artifactRoot !== "string"
    || !nonNegativeInteger(delegation.maxDepth)
    || !nonNegativeInteger(delegation.remainingBudget)
    || !nonNegativeInteger(delegation.remainingDepth)
    || (delegation.childProfile !== null && typeof delegation.childProfile !== "string")
    || delegation.spent !== false
  ) {
    throw new Error(`${label} is invalid or represents a spent delegation predecessor.`);
  }
  const capabilities = Object.fromEntries(EXECUTION_CAPABILITIES.map((capability) => {
    const allowed = capabilitiesRecord[capability];
    if (typeof allowed !== "boolean") {
      throw new Error(`${label} has an invalid capability matrix.`);
    }
    return [capability, allowed];
  })) as ExecutionCapabilitySet;
  const claimed = {
    schemaVersion: 1 as const,
    profile: record.profile,
    target: { root: target.root },
    scan: { id: scan.id, artifactRoot: scan.artifactRoot },
    capabilities,
    delegation: {
      maxDepth: delegation.maxDepth,
      remainingBudget: delegation.remainingBudget,
      remainingDepth: delegation.remainingDepth,
      childProfile: delegation.childProfile,
      spent: false,
    },
  } as ExecutionPolicyDescription;
  const issued = issueDescription(claimed);
  const canonical = describeExecutionPolicy(issued);
  if (!sameDescription(claimed, canonical)) {
    throw new Error(`${label} is not a canonical built-in execution policy.`);
  }
  return canonical;
}

function issueDescription(description: ExecutionPolicyDescription): ExecutionPolicyContext {
  return createExecutionPolicyContext({
    profile: description.profile,
    target: description.target,
    scan: description.scan,
    delegation: {
      budget: description.delegation.remainingBudget,
      depth: description.delegation.remainingDepth,
    },
  });
}

function unspentDescription(
  context: ExecutionPolicyContext,
  label: string,
): ExecutionPolicyDescription {
  const description = describeExecutionPolicy(context);
  if (description.delegation.spent) {
    throw new Error(`${label} is a spent delegation predecessor and cannot be persisted or restored.`);
  }
  return description;
}

function assertSameAuthority(
  authority: ExecutionPolicyDescription,
  candidate: ExecutionPolicyDescription,
  includeDelegationState: boolean,
): void {
  if (
    authority.profile !== candidate.profile
    || authority.target.root !== candidate.target.root
    || authority.scan.id !== candidate.scan.id
    || authority.scan.artifactRoot !== candidate.scan.artifactRoot
    || authority.delegation.maxDepth !== candidate.delegation.maxDepth
    || authority.delegation.childProfile !== candidate.delegation.childProfile
    || EXECUTION_CAPABILITIES.some(
      (capability) => authority.capabilities[capability] !== candidate.capabilities[capability],
    )
    || (includeDelegationState && (
      authority.delegation.remainingBudget !== candidate.delegation.remainingBudget
      || authority.delegation.remainingDepth !== candidate.delegation.remainingDepth
    ))
  ) {
    throw new Error("Saved execution policy profile or bindings do not match its authority.");
  }
}

function sameDescription(
  left: ExecutionPolicyDescription,
  right: ExecutionPolicyDescription,
): boolean {
  try {
    assertSameAuthority(left, right, true);
    return left.schemaVersion === right.schemaVersion
      && left.delegation.spent === right.delegation.spent;
  } catch {
    return false;
  }
}

function exactRecord(
  value: unknown,
  keys: readonly string[],
  label: string,
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
  const record = value as Record<string, unknown>;
  const ownKeys = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (
    ownKeys.length !== expected.length
    || ownKeys.some((key, index) => key !== expected[index])
  ) {
    throw new Error(`${label} has unknown or missing fields.`);
  }
  return record;
}

function nonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
