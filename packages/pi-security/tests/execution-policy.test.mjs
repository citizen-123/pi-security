import assert from "node:assert/strict";
import test from "node:test";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  entryPoints: [new URL("../src/execution-policy.ts", import.meta.url).pathname],
  format: "esm",
  platform: "node",
  write: false
});
const policy = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);

const target = { root: "/target/repository" };
const scan = { id: "scan-123", artifactRoot: "/state/scans/scan-123" };

const readOnlyCapabilities = {
  "target.read": true,
  "target.search": true,
  "target.git": true,
  "scan-artifacts.write": false,
  "workbench.execute": false,
  "network.access": false,
  "target.execute": false,
  "target.write": false,
  "delegation.create": false
};

function contextInput(profile = "security-readonly") {
  return { profile, target: { ...target }, scan: { ...scan } };
}

test("built-in profiles and exported metadata are exact and frozen", () => {
  assert.deepEqual(policy.EXECUTION_PROFILE_NAMES, [
    "security-readonly",
    "security-delegating-readonly",
    "security-artifact-writer"
  ]);
  assert.deepEqual(policy.EXECUTION_CAPABILITIES, Object.keys(readOnlyCapabilities));
  assert.deepEqual(policy.BUILT_IN_EXECUTION_PROFILES, {
    "security-readonly": {
      name: "security-readonly",
      capabilities: readOnlyCapabilities,
      delegation: { maxDepth: 0, childProfile: null }
    },
    "security-delegating-readonly": {
      name: "security-delegating-readonly",
      capabilities: { ...readOnlyCapabilities, "delegation.create": true },
      delegation: { maxDepth: 1, childProfile: "security-readonly" }
    },
    "security-artifact-writer": {
      name: "security-artifact-writer",
      capabilities: {
        ...readOnlyCapabilities,
        "target.read": false,
        "target.search": false,
        "target.git": false,
        "scan-artifacts.write": true,
        "workbench.execute": true
      },
      delegation: { maxDepth: 0, childProfile: null }
    }
  });
  assert.equal(Object.isFrozen(policy.EXECUTION_PROFILE_NAMES), true);
  assert.equal(Object.isFrozen(policy.EXECUTION_CAPABILITIES), true);
  assert.throws(
    () => policy.EXECUTION_PROFILE_NAMES.push("security-admin"),
    TypeError
  );
  assert.throws(
    () => policy.EXECUTION_CAPABILITIES.push("network.admin"),
    TypeError
  );
});

test("profile factories reject unknown, empty, and boxed profile names", () => {
  for (const name of [
    "security-remediator",
    "",
    "   ",
    new String("security-readonly"),
    { toJSON: () => "security-readonly" },
    null,
    1
  ]) {
    assert.throws(() => policy.getExecutionPolicyProfile(name), /execution profile/i);
  }
  assert.throws(
    () => policy.createExecutionPolicyContext(contextInput("provider-admin")),
    /Unknown Pi Security execution profile/
  );
});

test("context issuance accepts only own non-empty primitive bindings", () => {
  for (const input of [
    { ...contextInput(), target: { root: "" } },
    { ...contextInput(), target: { root: "  " } },
    { ...contextInput(), target: { root: new String(target.root) } },
    { ...contextInput(), scan: { ...scan, id: "" } },
    { ...contextInput(), scan: { ...scan, id: { toJSON: () => scan.id } } },
    { ...contextInput(), scan: { ...scan, artifactRoot: "\t" } },
    { ...contextInput(), scan: { ...scan, artifactRoot: { toJSON: () => scan.artifactRoot } } }
  ]) {
    assert.throws(
      () => policy.createExecutionPolicyContext(input),
      /non-empty primitive string/
    );
  }

  let accessorCalled = false;
  const accessorInput = contextInput();
  Object.defineProperty(accessorInput.target, "root", {
    enumerable: true,
    get() {
      accessorCalled = true;
      return target.root;
    }
  });
  assert.throws(
    () => policy.createExecutionPolicyContext(accessorInput),
    /own data property/
  );
  assert.equal(accessorCalled, false);

  let aliasCalled = false;
  const alias = {
    toJSON() {
      aliasCalled = true;
      return target.root;
    },
    toString() {
      aliasCalled = true;
      return target.root;
    }
  };
  assert.throws(
    () => policy.createExecutionPolicyContext({
      ...contextInput(),
      target: { root: alias }
    }),
    /non-empty primitive string/
  );
  assert.equal(aliasCalled, false);
});

test("issued profiles and bound contexts are deeply immutable copies", () => {
  const input = {
    ...contextInput("security-delegating-readonly"),
    delegation: { budget: 2 }
  };
  const context = policy.createExecutionPolicyContext(input);
  const original = policy.serializeExecutionPolicy(context);

  input.target.root = "/different-target";
  input.scan.artifactRoot = "/different-artifacts";
  input.delegation.budget = 99;

  assert.equal(policy.serializeExecutionPolicy(context), original);
  for (const value of [
    policy.BUILT_IN_EXECUTION_PROFILES,
    context,
    context.profile,
    context.profile.capabilities,
    context.profile.delegation,
    context.target,
    context.scan,
    context.delegation,
    policy.describeExecutionPolicy(context),
    policy.describeExecutionPolicy(context).delegation
  ]) {
    assert.equal(Object.isFrozen(value), true);
  }
  assert.throws(() => {
    context.profile.capabilities["target.write"] = true;
  }, TypeError);
  assert.equal(policy.hasExecutionCapability(context, "target.write"), false);
});

test("every context consumer rejects hand-built and spread-cloned contexts", () => {
  const issued = policy.createExecutionPolicyContext(contextInput());
  const impostors = [
    { ...issued },
    {
      profile: issued.profile,
      target: issued.target,
      scan: issued.scan,
      delegation: issued.delegation
    }
  ];
  const consumers = [
    (context) => policy.hasExecutionCapability(context, "target.read"),
    (context) => policy.assertExecutionCapability(context, "target.read"),
    (context) => policy.deriveDelegatedExecutionContext(context),
    (context) => policy.describeExecutionPolicy(context),
    (context) => policy.serializeExecutionPolicy(context)
  ];

  for (const impostor of impostors) {
    for (const consume of consumers) {
      assert.throws(() => consume(impostor), /was not issued by this module/);
    }
  }
  for (const consume of consumers) {
    assert.throws(() => consume(null), /was not issued by this module/);
  }
});

test("capability lookup is a primitive closed-set own-property check", () => {
  const context = policy.createExecutionPolicyContext({
    ...contextInput("security-delegating-readonly"),
    delegation: { budget: 1 }
  });
  assert.equal(policy.hasExecutionCapability(context, "target.read"), true);
  assert.equal(policy.hasExecutionCapability(context, "delegation.create"), true);
  assert.equal(policy.hasExecutionCapability(context, "network.access"), false);
  assert.doesNotThrow(() => policy.assertExecutionCapability(context, "target.git"));

  for (const capability of [
    "__proto__",
    "prototype",
    "constructor",
    "toString",
    "target.read.extra",
    new String("target.read"),
    { toString: () => "target.read" },
    null,
    1,
    Symbol("target.read")
  ]) {
    assert.equal(policy.hasExecutionCapability(context, capability), false);
    assert.throws(
      () => policy.assertExecutionCapability(context, capability),
      /Unknown Pi Security execution capability/
    );
  }
});

test("delegation is an atomic single-use transition without branching", () => {
  const root = policy.createExecutionPolicyContext({
    ...contextInput("security-delegating-readonly"),
    delegation: { budget: 2, depth: 1 }
  });
  const first = policy.deriveDelegatedExecutionContext(root);

  assert.equal(root.delegation.remainingBudget, 2);
  assert.equal(first.parent.delegation.remainingBudget, 1);
  assert.equal(policy.hasExecutionCapability(root, "delegation.create"), false);
  assert.equal(policy.hasExecutionCapability(first.parent, "delegation.create"), true);
  assert.equal(policy.describeExecutionPolicy(root).delegation.spent, true);
  assert.throws(
    () => policy.assertExecutionCapability(root, "delegation.create"),
    /does not allow "delegation.create"/
  );
  assert.throws(
    () => policy.deriveDelegatedExecutionContext(root),
    /delegation state was already spent/
  );

  const second = policy.deriveDelegatedExecutionContext(first.parent);
  assert.equal(policy.hasExecutionCapability(first.parent, "delegation.create"), false);
  assert.equal(second.parent.delegation.remainingBudget, 0);
  assert.equal(policy.hasExecutionCapability(second.parent, "delegation.create"), false);
  assert.throws(
    () => policy.deriveDelegatedExecutionContext(second.parent),
    /delegation budget is exhausted/
  );
  assert.throws(
    () => policy.deriveDelegatedExecutionContext(first.child),
    /delegation depth is exhausted/
  );
});

test("failed child checks do not spend delegation and child roles are coerced", () => {
  const parent = policy.createExecutionPolicyContext({
    ...contextInput("security-delegating-readonly"),
    delegation: { budget: 1 }
  });
  assert.throws(
    () => policy.deriveDelegatedExecutionContext(parent, "security-artifact-writer"),
    /would escalate "scan-artifacts.write"/
  );
  assert.equal(policy.hasExecutionCapability(parent, "delegation.create"), true);
  assert.equal(policy.describeExecutionPolicy(parent).delegation.spent, false);
  assert.throws(
    () => policy.deriveDelegatedExecutionContext(parent, "unknown-child"),
    /Unknown Pi Security execution profile/
  );
  assert.equal(policy.hasExecutionCapability(parent, "delegation.create"), true);

  const derived = policy.deriveDelegatedExecutionContext(
    parent,
    "security-delegating-readonly"
  );
  assert.equal(derived.child.profile.name, "security-readonly");
  assert.deepEqual(derived.child.delegation, {
    remainingBudget: 0,
    remainingDepth: 0,
    childProfile: null
  });
  assert.throws(
    () => policy.createExecutionPolicyContext({
      ...contextInput("security-readonly"),
      delegation: { budget: 1 }
    }),
    /cannot be granted a delegation budget/
  );
});

test("serialized policy descriptions are deterministic and ledger-aware", () => {
  const context = policy.createExecutionPolicyContext(contextInput());
  const expected = {
    schemaVersion: 1,
    profile: "security-readonly",
    target,
    scan,
    capabilities: readOnlyCapabilities,
    delegation: {
      maxDepth: 0,
      remainingBudget: 0,
      remainingDepth: 0,
      childProfile: null,
      spent: false
    }
  };

  assert.deepEqual(policy.describeExecutionPolicy(context), expected);
  assert.equal(policy.serializeExecutionPolicy(context), JSON.stringify(expected));
  assert.equal(
    policy.serializeExecutionPolicy(context),
    policy.serializeExecutionPolicy(context)
  );
});
