import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { build } from "esbuild";

const packageRoot = resolve(import.meta.dirname, "..");
const bundleRoot = await mkdtemp(join(tmpdir(), "pi-security-policy-adapters-"));
const bundlePath = join(bundleRoot, "adapters.mjs");
await build({
  bundle: true,
  format: "esm",
  logLevel: "silent",
  outfile: bundlePath,
  platform: "node",
  stdin: {
    contents: [
      'export * from "./src/pi-permission-profile.ts";',
      'export * from "./src/execution-policy-continuation.ts";',
      'export * from "./src/deep-scan/mcp-sampling-policy.ts";',
      'export * from "./src/enforcement-capabilities.ts";',
      'export * from "./src/execution-policy.ts";'
    ].join("\n"),
    loader: "ts",
    resolveDir: packageRoot,
    sourcefile: "host-policy-adapters-test-entry.ts"
  },
  target: "node20"
});
const adapter = await import(`${new URL(`file://${bundlePath}`).href}?${Date.now()}`);

test.after(async () => {
  await rm(bundleRoot, { recursive: true, force: true });
});

const targetRoot = resolve(bundleRoot, "target");
const artifactRoot = resolve(bundleRoot, "artifacts");
const scanId = "adapter-test-scan";
const bindings = { targetRoot, artifactRoot, scanId };

function description(context) {
  return adapter.describeExecutionPolicy(context);
}

test("Pi adapter maps only fixed host roles and derives packaged tools from capabilities", () => {
  assert.equal(description(adapter.issuePiLifecycleContext(bindings)).profile, "security-artifact-writer");
  assert.equal(description(adapter.issuePiWorkbenchContext(bindings)).profile, "security-artifact-writer");
  assert.equal(description(adapter.issuePiArtifactContext({
    ...bindings,
    profile: "security-readonly"
  })).profile, "security-artifact-writer");

  for (const agent of adapter.PI_PACKAGED_SECURITY_AGENTS) {
    const context = adapter.issuePiPackagedAgentContext(agent, bindings);
    assert.equal(description(context).profile, "security-readonly");
    assert.deepEqual(adapter.piPackagedAgentToolAllowlist(context), ["read", "grep", "find", "ls"]);
  }
  assert.throws(
    () => adapter.issuePiPackagedAgentContext("model-selected-artifact-writer", bindings),
    /Unknown packaged Pi Security agent/
  );

  const delegating = adapter.issuePiDelegatingAgentContext(bindings, 2);
  assert.equal(description(delegating).profile, "security-delegating-readonly");
  assert.equal(adapter.piPermissionSurfaceAllowed(delegating, "delegation"), true);
  assert.equal(adapter.piPermissionSurfaceAllowed(delegating, "artifact"), false);
});

test("continuation policy is canonical, exact, and restores only an unspent successor", () => {
  const authority = adapter.issueDeepScanSourceContext({
    targetRoot,
    scanId,
    workerRoot: artifactRoot,
    delegationBudget: 2
  });
  let state = adapter.snapshotExecutionPolicyState(authority);
  const delegated = adapter.deriveDelegatedExecutionContext(authority);
  assert.throws(
    () => adapter.snapshotExecutionPolicyState(authority),
    /spent delegation predecessor/
  );
  state = adapter.advanceExecutionPolicyState(state, delegated.parent);

  const freshAuthority = adapter.issueDeepScanSourceContext({
    targetRoot,
    scanId,
    workerRoot: artifactRoot,
    delegationBudget: 2
  });
  const restored = adapter.reissueExecutionPolicyState(state, freshAuthority);
  assert.equal(description(restored).delegation.remainingBudget, 1);
  assert.equal(description(restored).delegation.spent, false);
  assert.throws(
    () => adapter.advanceExecutionPolicyState(state, freshAuthority),
    /cannot restore spent delegation authority/
  );

  const differentTarget = adapter.issueDeepScanSourceContext({
    targetRoot: resolve(bundleRoot, "other-target"),
    scanId,
    workerRoot: artifactRoot,
    delegationBudget: 2
  });
  assert.throws(
    () => adapter.reissueExecutionPolicyState(state, differentTarget),
    /does not match the authoritative profile, bindings, or delegation limits/
  );
  const differentScan = adapter.issueDeepScanSourceContext({
    targetRoot,
    scanId: "different-scan",
    workerRoot: artifactRoot,
    delegationBudget: 2
  });
  assert.throws(
    () => adapter.reissueExecutionPolicyState(state, differentScan),
    /does not match the authoritative profile, bindings, or delegation limits/
  );
  const downgraded = adapter.createExecutionPolicyContext({
    profile: "security-readonly",
    target: { root: targetRoot },
    scan: { id: scanId, artifactRoot }
  });
  assert.throws(
    () => adapter.reissueExecutionPolicyState(state, downgraded),
    /does not match the authoritative profile, bindings, or delegation limits/
  );
  const readonlyState = adapter.snapshotExecutionPolicyState(downgraded);
  assert.throws(
    () => adapter.reissueExecutionPolicyState(readonlyState, freshAuthority),
    /does not match the authoritative profile, bindings, or delegation limits/
  );

  const forged = structuredClone(state);
  forged.effective.capabilities["target.write"] = true;
  assert.throws(
    () => adapter.reissueExecutionPolicyState(forged, freshAuthority),
    (error) => error.code === "PI_SECURITY_POLICY_RECOVERY_REJECTED"
      && error.reason === "invalid_policy",
  );
});

test("MCP adapter keeps advertised tools and direct dispatch on the same authority", () => {
  const source = adapter.issueDeepScanSourceContext({
    targetRoot,
    scanId,
    workerRoot: artifactRoot,
    delegationBudget: 0
  });
  const writer = adapter.issueDeepScanArtifactWriterContext({ targetRoot, scanId, artifactRoot });
  const policy = adapter.bindMcpSamplingPolicy({
    source: () => source,
    artifactWriter: () => writer,
    delegation: () => source,
    tools: [
      {
        definition: { name: "visible_read" },
        available: true,
        requirements: [{ authority: "source", capability: "target.read" }]
      },
      {
        definition: { name: "hidden_delegate" },
        available: true,
        requirements: [{ authority: "delegation", capability: "delegation.create" }]
      }
    ]
  });
  assert.deepEqual(policy.definitions().map((tool) => tool.name), ["visible_read"]);
  policy.assertAuthorized("visible_read");
  assert.throws(() => policy.assertAuthorized("hidden_delegate"), /Unknown or unauthorized/);
  assert.throws(() => policy.assertAuthorized("unknown"), /Unknown or unauthorized/);

  const forged = structuredClone(source);
  assert.throws(
    () => adapter.bindMcpSamplingPolicy({
      source: () => forged,
      artifactWriter: () => writer,
      delegation: () => forged,
      tools: [{
        definition: { name: "forged_read" },
        available: true,
        requirements: [{ authority: "source", capability: "target.read" }]
      }]
    }),
    /not issued by this module/
  );
});

test("enforcement failures stay typed and effective diagnostics redact bindings", () => {
  const unavailable = adapter.describePiEnforcementCapabilities({
    kind: "availability",
    piTools: true,
    targetHandles: false,
    artifactRoots: true,
    trustedWorkbench: true,
    continuationPolicy: true
  });
  assert.equal(unavailable.supported, false);
  assert.deepEqual(unavailable.mechanisms, [
    "pi.fixed-profile-tool-dispatch",
    "artifact.canonical-root-binding",
    "workbench.fixed-bundled-command",
    "continuation.exact-policy-reissue"
  ]);

  let committed = 0;
  let unsupported;
  try {
    adapter.assertPiEnforcementSupported(unavailable);
    committed += 1;
  } catch (error) {
    unsupported = error;
  }
  assert.equal(committed, 0);
  assert.equal(unsupported.code, "PI_SECURITY_ENFORCEMENT_UNSUPPORTED");
  assert.equal(unsupported.category, "unsupported_enforcement");
  assert.deepEqual(adapter.describePolicyEnforcementFailure(unsupported), {
    schemaVersion: 1,
    code: "PI_SECURITY_ENFORCEMENT_UNSUPPORTED",
    category: "unsupported_enforcement",
    message: unsupported.message
  });

  const source = adapter.issueDeepScanSourceContext({
    targetRoot,
    scanId,
    workerRoot: artifactRoot,
    delegationBudget: 0
  });
  const writer = adapter.issueDeepScanArtifactWriterContext({
    targetRoot,
    scanId,
    artifactRoot
  });
  const platformMechanism = process.platform === "win32"
    ? "platform.windows-reparse-identity"
    : process.platform === "linux"
      ? "platform.linux-proc-self-fd"
      : "platform.posix-dev-fd";
  const effective = adapter.describePiEnforcementCapabilities({
    kind: "effective",
    piTools: true,
    samplingTools: true,
    targetHandles: true,
    artifactRoots: true,
    trustedWorkbench: true,
    continuationPolicy: true,
    platformMechanisms: [platformMechanism]
  });
  const diagnostics = adapter.describeEffectivePolicyDiagnostics({
    source,
    artifactWriter: writer,
    enforcement: effective
  });
  assert.deepEqual(Object.keys(diagnostics), [
    "schemaVersion",
    "source",
    "artifactWriter",
    "enforcement"
  ]);
  assert.deepEqual(Object.keys(diagnostics.source), [
    "schemaVersion",
    "profile",
    "capabilities",
    "delegation"
  ]);
  assert.equal(diagnostics.source.profile, "security-readonly");
  assert.equal(diagnostics.artifactWriter.profile, "security-artifact-writer");
  const publicDiagnostics = JSON.stringify(diagnostics);
  for (const secret of [targetRoot, artifactRoot, scanId]) {
    assert.equal(publicDiagnostics.includes(secret), false);
  }
  assert.equal(Object.hasOwn(diagnostics.source, "target"), false);
  assert.equal(Object.hasOwn(diagnostics.source, "scan"), false);

  const recovery = new adapter.PolicyRecoveryRejectedError(
    "binding_mismatch",
    "fixture binding mismatch"
  );
  assert.deepEqual(adapter.describePolicyEnforcementFailure(recovery), {
    schemaVersion: 1,
    code: "PI_SECURITY_POLICY_RECOVERY_REJECTED",
    category: "policy_recovery_rejected",
    reason: "binding_mismatch",
    message: recovery.message
  });
  assert.throws(
    () => adapter.assertExecutionCapability(source, "target.write"),
    (error) => error.code === "PI_SECURITY_POLICY_DENIED"
      && error.category === "policy_denied"
  );
});
