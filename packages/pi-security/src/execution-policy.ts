const EXECUTION_CAPABILITY_METADATA = Object.freeze([
  "target.read",
  "target.search",
  "target.git",
  "scan-artifacts.write",
  "workbench.execute",
  "network.access",
  "target.execute",
  "target.write",
  "delegation.create"
] as const);

export const EXECUTION_CAPABILITIES = EXECUTION_CAPABILITY_METADATA;
export type ExecutionCapability = typeof EXECUTION_CAPABILITY_METADATA[number];

const EXECUTION_PROFILE_METADATA = Object.freeze([
  "security-readonly",
  "security-delegating-readonly",
  "security-artifact-writer"
] as const);

export const EXECUTION_PROFILE_NAMES = EXECUTION_PROFILE_METADATA;
export type ExecutionProfileName = typeof EXECUTION_PROFILE_METADATA[number];
export type ExecutionCapabilitySet = Readonly<Record<ExecutionCapability, boolean>>;

export const PI_SECURITY_POLICY_DENIED = "PI_SECURITY_POLICY_DENIED" as const;

export class ExecutionPolicyDeniedError extends Error {
  readonly code = PI_SECURITY_POLICY_DENIED;
  readonly category = "policy_denied" as const;

  constructor(message: string, options?: ErrorOptions) {
    super(`${PI_SECURITY_POLICY_DENIED}: ${message}`, options);
    this.name = "ExecutionPolicyDeniedError";
  }
}

export interface ExecutionPolicyProfile {
  readonly name: ExecutionProfileName;
  readonly capabilities: ExecutionCapabilitySet;
  readonly delegation: Readonly<{
    maxDepth: number;
    childProfile: ExecutionProfileName | null;
  }>;
}

export interface PolicyBoundTargetContext {
  readonly root: string;
}

export interface PolicyBoundScanContext {
  readonly id: string;
  readonly artifactRoot: string;
}

export interface ExecutionDelegationContext {
  readonly remainingBudget: number;
  readonly remainingDepth: number;
  readonly childProfile: ExecutionProfileName | null;
}

export interface ExecutionPolicyContext {
  readonly profile: ExecutionPolicyProfile;
  readonly target: PolicyBoundTargetContext;
  readonly scan: PolicyBoundScanContext;
  readonly delegation: ExecutionDelegationContext;
}

export interface CreateExecutionPolicyContextInput {
  readonly profile: string;
  readonly target: PolicyBoundTargetContext;
  readonly scan: PolicyBoundScanContext;
  /** Authoritative per-run limits; omitted budget fails closed at zero. */
  readonly delegation?: Readonly<{ budget?: number; depth?: number }>;
}

export interface DelegatedExecutionPolicyContexts {
  /** This is the only context authorized for subsequent sibling derivations. */
  readonly parent: ExecutionPolicyContext;
  readonly child: ExecutionPolicyContext;
}

export interface ExecutionPolicyDescription {
  readonly schemaVersion: 1;
  readonly profile: ExecutionProfileName;
  readonly target: PolicyBoundTargetContext;
  readonly scan: PolicyBoundScanContext;
  readonly capabilities: ExecutionCapabilitySet;
  readonly delegation: Readonly<{
    maxDepth: number;
    remainingBudget: number;
    remainingDepth: number;
    childProfile: ExecutionProfileName | null;
    spent: boolean;
  }>;
}

interface IssuedExecutionContext {
  readonly profile: ExecutionPolicyProfile;
  readonly target: PolicyBoundTargetContext;
  readonly scan: PolicyBoundScanContext;
  readonly delegation: ExecutionDelegationContext;
}

const ISSUED_CONTEXTS = new WeakMap<object, IssuedExecutionContext>();
const SPENT_DELEGATION_CONTEXTS = new WeakSet<object>();

const readOnlyCapabilities = (): ExecutionCapabilitySet => Object.freeze({
  "target.read": true,
  "target.search": true,
  "target.git": true,
  "scan-artifacts.write": false,
  "workbench.execute": false,
  "network.access": false,
  "target.execute": false,
  "target.write": false,
  "delegation.create": false
});

const delegatingReadOnlyCapabilities = (): ExecutionCapabilitySet => Object.freeze({
  ...readOnlyCapabilities(),
  "delegation.create": true
});

const artifactWriterCapabilities = (): ExecutionCapabilitySet => Object.freeze({
  "target.read": false,
  "target.search": false,
  "target.git": false,
  "scan-artifacts.write": true,
  "workbench.execute": true,
  "network.access": false,
  "target.execute": false,
  "target.write": false,
  "delegation.create": false
});

function profile(
  name: ExecutionProfileName,
  capabilities: ExecutionCapabilitySet,
  maxDepth: number,
  childProfile: ExecutionProfileName | null
): ExecutionPolicyProfile {
  return Object.freeze({
    name,
    capabilities,
    delegation: Object.freeze({ maxDepth, childProfile })
  });
}

export const BUILT_IN_EXECUTION_PROFILES = Object.freeze({
  "security-readonly": profile("security-readonly", readOnlyCapabilities(), 0, null),
  "security-delegating-readonly": profile(
    "security-delegating-readonly",
    delegatingReadOnlyCapabilities(),
    1,
    "security-readonly"
  ),
  "security-artifact-writer": profile(
    "security-artifact-writer",
    artifactWriterCapabilities(),
    0,
    null
  )
}) satisfies Readonly<Record<ExecutionProfileName, ExecutionPolicyProfile>>;

/** Resolve only the closed set of built-in profiles. */
export function getExecutionPolicyProfile(name: string): ExecutionPolicyProfile {
  const primitiveName = nonEmptyPrimitiveString(name, "Execution profile name");
  if (
    !isExecutionProfileName(primitiveName)
    || !Object.prototype.hasOwnProperty.call(BUILT_IN_EXECUTION_PROFILES, primitiveName)
  ) {
    throw new Error(
      `Unknown Pi Security execution profile: ${JSON.stringify(primitiveName)}.`
    );
  }
  return BUILT_IN_EXECUTION_PROFILES[primitiveName];
}

/** Bind an immutable, provenance-tracked policy to one target and scan. */
export function createExecutionPolicyContext(
  input: CreateExecutionPolicyContextInput
): ExecutionPolicyContext {
  const inputRecord = recordInput(input, "Execution policy context");
  const selectedProfile = getExecutionPolicyProfile(
    ownDataValue(inputRecord, "profile", "Execution profile") as string
  );
  const targetInput = recordInput(
    ownDataValue(inputRecord, "target", "Execution target"),
    "Execution target"
  );
  const scanInput = recordInput(
    ownDataValue(inputRecord, "scan", "Execution scan"),
    "Execution scan"
  );
  const targetRoot = nonEmptyPrimitiveString(
    ownDataValue(targetInput, "root", "Execution target root"),
    "Execution target root"
  );
  const scanId = nonEmptyPrimitiveString(
    ownDataValue(scanInput, "id", "Execution scan id"),
    "Execution scan id"
  );
  const artifactRoot = nonEmptyPrimitiveString(
    ownDataValue(scanInput, "artifactRoot", "Execution scan artifact root"),
    "Execution scan artifact root"
  );

  const delegationInputValue = optionalOwnDataValue(inputRecord, "delegation");
  const delegationInput = delegationInputValue === undefined
    ? undefined
    : recordInput(delegationInputValue, "Execution delegation limits");
  const remainingBudget = nonNegativeInteger(
    delegationInput === undefined
      ? 0
      : optionalOwnDataValue(delegationInput, "budget") ?? 0,
    "Delegation budget"
  );
  const remainingDepth = nonNegativeInteger(
    delegationInput === undefined
      ? selectedProfile.delegation.maxDepth
      : optionalOwnDataValue(delegationInput, "depth")
        ?? selectedProfile.delegation.maxDepth,
    "Delegation depth"
  );
  if (remainingDepth > selectedProfile.delegation.maxDepth) {
    throw new Error(
      `Execution profile ${JSON.stringify(selectedProfile.name)} allows delegation depth `
      + `${selectedProfile.delegation.maxDepth}, not ${remainingDepth}.`
    );
  }
  if (!selectedProfile.capabilities["delegation.create"] && remainingBudget > 0) {
    throw new Error(
      `Execution profile ${JSON.stringify(selectedProfile.name)} cannot be granted a delegation budget.`
    );
  }

  return issueContext(
    selectedProfile,
    Object.freeze({ root: targetRoot }),
    Object.freeze({ id: scanId, artifactRoot }),
    {
      remainingBudget,
      remainingDepth,
      childProfile: selectedProfile.delegation.childProfile
    }
  );
}

/** Query an issued context; unknown capability values fail closed. */
export function hasExecutionCapability(
  context: ExecutionPolicyContext,
  capability: ExecutionCapability
): boolean {
  const state = issuedContext(context);
  return effectiveCapability(state, context, capability);
}

export function assertExecutionCapability(
  context: ExecutionPolicyContext,
  capability: ExecutionCapability
): void {
  const state = issuedContext(context);
  if (effectiveCapability(state, context, capability)) return;
  if (!isExecutionCapability(capability)) {
    throw new ExecutionPolicyDeniedError("Unknown Pi Security execution capability.");
  }
  throw new ExecutionPolicyDeniedError(
    `Execution profile ${JSON.stringify(state.profile.name)} does not allow `
    + `${JSON.stringify(capability)} in this context.`
  );
}

/**
 * Derive one child as an atomic, single-use immutable transition. A requested
 * role is checked for escalation, while the profile's fixed child role remains
 * authoritative.
 */
export function deriveDelegatedExecutionContext(
  parent: ExecutionPolicyContext,
  requestedProfileName?: string
): DelegatedExecutionPolicyContexts {
  const parentState = issuedContext(parent);
  if (SPENT_DELEGATION_CONTEXTS.has(parent)) {
    throw new Error("This execution context's delegation state was already spent.");
  }
  const requestedProfile = requestedProfileName === undefined
    ? undefined
    : getExecutionPolicyProfile(requestedProfileName);

  if (parentState.delegation.remainingDepth === 0) {
    throw new Error(
      `Execution profile ${JSON.stringify(parentState.profile.name)} delegation depth is exhausted.`
    );
  }
  if (parentState.delegation.remainingBudget === 0) {
    throw new Error(
      `Execution profile ${JSON.stringify(parentState.profile.name)} delegation budget is exhausted.`
    );
  }
  if (
    !parentState.profile.capabilities["delegation.create"]
    || parentState.delegation.childProfile === null
  ) {
    throw new Error(
      `Execution profile ${JSON.stringify(parentState.profile.name)} does not allow delegation.`
    );
  }

  const childProfile = getExecutionPolicyProfile(parentState.delegation.childProfile);
  assertNoCapabilityEscalation(parentState.profile, childProfile, "Configured child profile");
  if (requestedProfile) {
    assertNoCapabilityEscalation(
      parentState.profile,
      requestedProfile,
      "Requested child profile"
    );
  }

  const nextBudget = parentState.delegation.remainingBudget - 1;
  SPENT_DELEGATION_CONTEXTS.add(parent);
  const nextParent = issueContext(
    parentState.profile,
    parentState.target,
    parentState.scan,
    {
      remainingBudget: nextBudget,
      remainingDepth: parentState.delegation.remainingDepth,
      childProfile: parentState.profile.delegation.childProfile
    }
  );
  const child = issueContext(
    childProfile,
    parentState.target,
    parentState.scan,
    {
      remainingBudget: 0,
      remainingDepth: Math.min(
        parentState.delegation.remainingDepth - 1,
        childProfile.delegation.maxDepth
      ),
      childProfile: childProfile.delegation.childProfile
    }
  );
  return Object.freeze({ parent: nextParent, child });
}

/** Return a plain, deeply immutable diagnostic contract with stable key order. */
export function describeExecutionPolicy(
  context: ExecutionPolicyContext
): ExecutionPolicyDescription {
  const state = issuedContext(context);
  return Object.freeze({
    schemaVersion: 1 as const,
    profile: state.profile.name,
    target: state.target,
    scan: state.scan,
    capabilities: state.profile.capabilities,
    delegation: Object.freeze({
      maxDepth: state.profile.delegation.maxDepth,
      remainingBudget: state.delegation.remainingBudget,
      remainingDepth: state.delegation.remainingDepth,
      childProfile: state.delegation.childProfile,
      spent: SPENT_DELEGATION_CONTEXTS.has(context)
    })
  });
}

export function serializeExecutionPolicy(context: ExecutionPolicyContext): string {
  return JSON.stringify(describeExecutionPolicy(context));
}

function issueContext(
  selectedProfile: ExecutionPolicyProfile,
  target: PolicyBoundTargetContext,
  scan: PolicyBoundScanContext,
  delegation: ExecutionDelegationContext
): ExecutionPolicyContext {
  const delegationSnapshot = Object.freeze({ ...delegation });
  const context = Object.freeze({
    profile: selectedProfile,
    target,
    scan,
    delegation: delegationSnapshot
  });
  ISSUED_CONTEXTS.set(context, Object.freeze({
    profile: selectedProfile,
    target,
    scan,
    delegation: delegationSnapshot
  }));
  return context;
}

function issuedContext(context: unknown): IssuedExecutionContext {
  if ((typeof context !== "object" && typeof context !== "function") || context === null) {
    throw new Error("Pi Security execution policy context was not issued by this module.");
  }
  const state = ISSUED_CONTEXTS.get(context);
  if (!state) {
    throw new Error("Pi Security execution policy context was not issued by this module.");
  }
  return state;
}

function effectiveCapability(
  state: IssuedExecutionContext,
  context: object,
  capability: unknown
): boolean {
  if (
    !isExecutionCapability(capability)
    || !Object.prototype.hasOwnProperty.call(state.profile.capabilities, capability)
    || state.profile.capabilities[capability] !== true
  ) {
    return false;
  }
  if (capability !== "delegation.create") return true;
  return !SPENT_DELEGATION_CONTEXTS.has(context)
    && state.delegation.remainingBudget > 0
    && state.delegation.remainingDepth > 0
    && state.delegation.childProfile !== null;
}

function isExecutionCapability(value: unknown): value is ExecutionCapability {
  return typeof value === "string"
    && EXECUTION_CAPABILITY_METADATA.includes(value as ExecutionCapability);
}

function isExecutionProfileName(value: string): value is ExecutionProfileName {
  return EXECUTION_PROFILE_METADATA.includes(value as ExecutionProfileName);
}

function assertNoCapabilityEscalation(
  parent: ExecutionPolicyProfile,
  child: ExecutionPolicyProfile,
  label: string
): void {
  const capability = EXECUTION_CAPABILITY_METADATA.find(
    (candidate) => child.capabilities[candidate] === true
      && parent.capabilities[candidate] !== true
  );
  if (capability) {
    throw new Error(
      `${label} ${JSON.stringify(child.name)} would escalate `
      + `${JSON.stringify(capability)} beyond ${JSON.stringify(parent.name)}.`
    );
  }
}

function recordInput(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object with own data properties.`);
  }
  return value as Record<string, unknown>;
}

function ownDataValue(
  input: Record<string, unknown>,
  key: string,
  label: string
): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(input, key);
  if (!descriptor || !("value" in descriptor)) {
    throw new Error(`${label} must be supplied as an own data property.`);
  }
  return descriptor.value;
}

function optionalOwnDataValue(
  input: Record<string, unknown>,
  key: string
): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(input, key);
  if (!descriptor) return undefined;
  if (!("value" in descriptor)) {
    throw new Error(`${key} must be supplied as an own data property.`);
  }
  return descriptor.value;
}

function nonEmptyPrimitiveString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${label} must be a non-empty primitive string.`);
  }
  return value;
}

function nonNegativeInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer.`);
  }
  return value;
}
