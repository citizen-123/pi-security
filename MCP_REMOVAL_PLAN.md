# Native Pi Security and MCP Removal Plan

## Problem

MCP currently serves two roles that can be handled natively by Pi:

1. It publishes lifecycle/workbench tools to external MCP clients.
2. Its `sampling/createMessage` transport runs Deep Scan discovery and reducer workers.

Neither role is required for native Pi. The Deep Scan coordinator already depends on the transport-neutral `PiWorkerExecutor` interface, not directly on MCP.

Separately, 18 known skill invocations still use Codex's `$skill-name` syntax instead of Pi's `/skill-name` syntax.

## Decision

Make Pi Security extension-only:

- Replace `SamplingWorkerExecutor` with a native Pi implementation.
- Preserve the existing coordinator, persistence, retries, reducers, security policies, artifacts, reports, and lifecycle operations.
- Move the complete lifecycle catalog behind native Pi tools.
- Delete the stdio MCP server and `@modelcontextprotocol/sdk`.
- Replace all known `$skill-name` invocations with `/skill-name`.
- Remove generic MCP-host compatibility and the `pi-security-mcp` command. This is the only intended feature removal; scanning behavior inside Pi remains intact.

Do not approximate Deep Scan with “spawn several agents and summarize.” Keep its durable coordinator and map/reduce behavior.

## Phase 1 — Freeze the native behavior contract

Before changing transport code:

1. Expand `packages/pi-security/tests/pi-extension-lifecycle.test.mjs` to assert that the native extension exposes every lifecycle/workbench operation currently in the canonical catalog.
2. Record the expected native tool names, annotations, input schemas, and visibility in `packages/pi-security/tests/fixtures/lifecycle-tools.json`.
3. Preserve behavioral coverage for:
   - Standard scans
   - Diff scans
   - Deep Scan
   - scan history and recovery
   - findings and repository queries
   - triage and feedback
   - remediation
   - JSON, SARIF, and report generation
   - cancellation and failure transitions
4. Keep coordinator unit tests executor-independent. They should continue testing `PiWorkerExecutor`, not an MCP implementation.

**Gate:** Native lifecycle contract accounts for every tool before the MCP registrar is removed.

## Phase 2 — Separate lifecycle logic from MCP registration

`packages/pi-security/server.ts` currently mixes the canonical lifecycle catalog with `McpServer` registration.

Refactor it into transport-neutral lifecycle code:

1. Extract the lifecycle catalog and handlers into a native module such as `src/lifecycle-catalog.ts` and the existing focused modules under `src/server/`.
2. Define an internal request context containing only actual product authority:
   - Pi session identity
   - scan identity
   - target binding
   - artifact binding
   - cancellation signal
   - handoff claim, when applicable
3. Remove MCP request objects, protocol metadata, and client capability objects from handler signatures.
4. Register the same catalog directly through the Pi extension.
5. Replace MCP elicitation behavior with native Pi interaction:
   - use Pi UI input when available;
   - otherwise ask for the same structured information through normal chat;
   - preserve validation and cancellation behavior.
6. Keep lifecycle handler logic shared. Avoid separate “native” and “MCP-compatible” implementations.

**Gate:** Native extension lifecycle parity passes without instantiating `McpServer`.

## Phase 3 — Implement `NativePiWorkerExecutor`

Add a production implementation of the existing `PiWorkerExecutor` interface.

The implementation should use Pi's native agent SDK:

- `createAgentSession`
- `SessionManager.inMemory`
- explicit custom tools
- explicit system prompt/resource loader
- selected model and thinking level
- agent/session events for usage and diagnostics

### Worker construction

For every discovery or reducer worker:

1. Create a new isolated in-memory Pi session.
2. Provide only the worker-specific custom tools.
3. Disable or omit every generic built-in tool.
4. Bind the session to immutable authority for:
   - exact target root and snapshot
   - scan ID
   - worker ID
   - artifact root
   - worker kind
   - delegation budget
5. Use the existing discovery and reducer templates.
6. Drive the session until:
   - the schema-bound final submission succeeds;
   - cancellation occurs;
   - timeout occurs; or
   - a typed terminal policy failure occurs.
7. Return the existing `PiWorkerResult` shape, including usage and diagnostics.

### Continuation and recovery

Persist application-owned worker state rather than provider conversation IDs:

- serialized Pi message history;
- model and thinking configuration;
- worker attempt;
- accepted tool-call ledger;
- delegation markers;
- final-submission state;
- usage accumulated so far.

Restore message history through `session.agent.state.messages`.

Continuation validation must happen before starting the restored model session. Unsafe or incompatible state must retain the existing typed recovery rejection behavior.

### Cancellation and diagnostics

Map existing coordinator behavior onto Pi events:

- `AbortSignal` cancels the active session.
- Model usage feeds existing token accounting.
- Tool calls feed existing execution diagnostics.
- Refusals and terminal model errors retain current retry classification.
- Optional event/logging failures must not terminate the scan.

**Gate:** The same coordinator tests pass with `NativePiWorkerExecutor`, and no production path instantiates `SamplingWorkerExecutor`.

## Phase 4 — Make worker tools transport-neutral

Refactor:

- `src/deep-scan/sampling-tools.ts`
- `src/deep-scan/mcp-sampling-policy.ts`

Suggested clean cutover:

- `sampling-tools.ts` → `worker-tools.ts`
- `mcp-sampling-policy.ts` → `worker-policy.ts`

Changes:

1. Replace MCP tool-definition types with Pi custom-tool definitions.
2. Keep all current input schemas and handler implementations.
3. Preserve the closed capability set:
   - target-relative listing
   - bounded source reads
   - literal source search
   - Git/snapshot metadata
   - scan context
   - checkpoint and final-draft recording
   - reducer input and result recording
   - bounded nested delegation
4. Continue issuing separate immutable contexts for:
   - source-reading workers;
   - artifact writers;
   - delegated read-only children.
5. Preserve the rule that no worker receives:
   - target writes;
   - target execution;
   - arbitrary shell access;
   - network access;
   - unrestricted filesystem reads.
6. Keep direct dispatch authorization separate from tool advertisement. A missing or unknown tool must remain unusable even if the model fabricates a call.

**Gate:** Target confinement, artifact confinement, delegation limits, and unknown-tool denial pass through native Pi sessions.

## Phase 5 — Wire Deep Scan into the native extension

Move ownership of the Deep Scan runtime from the MCP server process to the Pi extension runtime.

1. Instantiate the existing `DeepScanCoordinatorRegistry` from the extension.
2. Construct `NativePiWorkerExecutor` from the current Pi runtime/session context.
3. Route native Deep Scan start/join calls through `startOrJoinDeepScanCoordinator`.
4. Preserve:
   - one live coordinator per scan;
   - durable coordinator leases;
   - remote/restart observation;
   - setup phase;
   - discovery waves;
   - retry delays;
   - no-new-findings saturation;
   - worker caps;
   - reducer ordering;
   - cancellation;
   - final publication.
5. Keep SQLite/workbench state authoritative across extension or Pi restarts.
6. Ensure resumed scans reissue authority rather than trusting serialized capability objects.
7. Keep Standard and Diff paths unchanged except for lifecycle registration plumbing.

**Gate:** `/deep-security-scan` works directly in Pi without starting a sidecar process or configuring an MCP server.

## Phase 6 — Migrate persisted Deep Scan state

Current persisted state contains MCP-named protocol identity:

- workflow marker such as `deep-scan-mcp/v1`;
- enforcement mechanism `mcp.sampling.tools`;
- sampling-oriented continuation fields.

Perform a one-way native migration:

1. Introduce a native workflow version, for example `deep-scan-native/v1`.
2. Replace `mcp.sampling.tools` with a native mechanism such as `pi.worker-session.tools`.
3. Migrate an existing continuation only when:
   - target and artifact bindings still match;
   - tool policy is equivalent;
   - message history can be restored;
   - delegation state is canonical;
   - no MCP-only opaque state is required.
4. Reject incompatible continuations with the existing typed policy recovery failure.
5. Do not retain dual MCP/native execution branches or deprecated mechanism aliases after migration.
6. Test existing running, interrupted, and completed scans separately.

**Gate:** Compatible Deep Scans survive upgrade and restart; incompatible authority is rejected before model or tool execution.

## Phase 7 — Remove the MCP implementation completely

After native Deep Scan parity:

### Delete runtime entrypoints

- `packages/pi-security/main.ts`
- `packages/pi-security/server.ts` after lifecycle extraction
- `packages/pi-security/artifact-writer-main.ts` if it exists only for the MCP subprocess
- `packages/pi-security/src/modelcontextprotocol-sdk.d.ts`
- MCP-only server registration and adapter modules
- MCP capability negotiation and protocol-specific elicitation code

### Delete protocol-only tests

Only after transplanting behavioral assertions into native tests:

- `packages/pi-security/tests/mcp.test.mjs`
- `packages/pi-security/tests/deep-scan-server-capability.test.mjs`
- `packages/pi-security/tests/deep-scan-sampling.test.mjs`
- MCP-specific portions of `packages/pi-security/tests/host-policy-adapters.test.mjs`

Coordinator, artifact, workbench, policy, and recovery tests remain.

### Update package manifests

In both root and package manifests:

- remove `@modelcontextprotocol/sdk`;
- remove the `pi-security-mcp` binary;
- remove `dist/server.cjs` from `files`;
- remove server entrypoints from packaging expectations;
- retain only the Pi extension distribution.

### Update the build

Change `packages/pi-security/scripts-build.mjs` to build only:

```text
dist/pi-security-extension.mjs
```

Remove:

- `main.ts` bundling;
- `dist/server.cjs`;
- executable banner;
- executable `chmod`.

Update `.npmignore` and package-content tests accordingly.

**Gate:** Installed package contains no MCP binary, SDK, server bundle, protocol declaration, or MCP runtime import.

## Phase 8 — Convert skill invocation syntax

Replace exactly the known skill invocations:

```text
$skill-name
```

with:

```text
/skill-name
```

Affected locations:

- `packages/pi-security/references/final-report.md`
- `packages/pi-security/skills/attack-path-analysis/SKILL.md`
- `packages/pi-security/skills/deep-security-scan/SKILL.md`
- `packages/pi-security/skills/security-diff-scan/SKILL.md`
- `packages/pi-security/skills/threat-model/SKILL.md`
- `packages/pi-security/skills/triage-finding/SKILL.md`
- `packages/pi-security/skills/triage-finding/references/github-rest-intake.md`
- `packages/pi-security/skills/triage-finding/references/ticket-intake.md`
- `packages/pi-security/skills/triage-finding/references/triage-result-contract.md`
- `packages/pi-security/skills/validation/SKILL.md`
- `packages/pi-security/src/scan-handoff.ts`

There are currently 18 known references across these 11 files.

Do not perform a blind `$...` replacement. Preserve unrelated syntax:

- JSON Schema `$schema`
- JSON Schema `$ref`
- PowerShell `$env:PYTHON`
- shell variables
- template placeholders

Update generated handoff instructions in `src/scan-handoff.ts` so native continuations explicitly say, for example:

```text
Use /deep-security-scan
```

**Gate:** No `$<known-skill>` invocation remains, and schema/shell syntax is unchanged.

## Phase 9 — Documentation and public API cleanup

Update:

- root `README.md`
- `packages/pi-security/README.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- help and setup inspection output
- capability matrix
- environment-variable documentation

Remove claims about:

- generic MCP clients;
- `pi-security-mcp`;
- stdio configuration;
- MCP sampling negotiation;
- server-to-client sampling;
- MCP Deep Scan prerequisites.

Document instead:

- Pi extension installation;
- native Standard, Diff, and Deep scans;
- native worker-session requirements;
- `/skill-name` invocation syntax;
- scan state and output configuration.

Retain “MCP” only where it is part of the security domain being scanned, such as guidance for auditing an unrelated MCP server. Remove it as a Pi Security transport or product dependency.

## Verification matrix

### Static checks

Require zero production/package matches for:

- `@modelcontextprotocol/sdk`
- `McpServer`
- `SamplingWorkerExecutor`
- `sampling/createMessage`
- `mcp.sampling.tools`
- `pi-security-mcp`
- `dist/server.cjs`

Require zero known `$skill-name` invocations.

Allow MCP terminology only in security-analysis guidance describing MCP targets or vulnerabilities.

### Behavioral tests

#### Standard and Diff

- exact target selection;
- exact Git diff binding;
- threat modeling;
- concurrent read-only subagents;
- semantic checkpoints;
- incomplete coverage;
- findings, report, and SARIF output;
- cancellation and failure;
- resume/rejoin.

#### Deep Scan

- new scan;
- concurrent start/join;
- extension/Pi restart;
- interrupted worker resume;
- discovery retries;
- saturation;
- worker cap;
- cancellation;
- reducer ordering;
- retained findings;
- incomplete coverage;
- model and thinking configuration;
- token usage;
- bounded nested delegation;
- continuation-policy recovery;
- target and artifact confinement;
- final completion and publication.

#### Lifecycle features

- scan history;
- repository and finding queries;
- triage;
- feedback;
- remediation and retry/cancellation;
- exports;
- setup inspection;
- progress;
- archive and recovery.

### Package and runtime checks

Run from the repository root:

```bash
npm run typecheck
npm test
npm run test:pack
```

Then smoke-test the actual Pi extension against a synthetic repository:

```text
/security-scan
/security-diff-scan
/deep-security-scan
```

Confirm that Deep Scan starts and completes with no MCP configuration, sidecar process, stdio server, or protocol negotiation.

## Completion criterion

Done means:

- all scanning modes and lifecycle features work through native Pi;
- Deep Scan preserves its durable coordinator and security invariants;
- compatible persisted scans resume after migration;
- the package has no MCP runtime or dependency;
- `pi-security-mcp` no longer exists;
- every skill invocation uses `/skill-name`;
- documentation describes only the native Pi architecture.
