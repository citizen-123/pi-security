## Context

See `proposal.md` for motivation. Pi Security currently exposes Pi skills and extension lifecycle tools rather than a package `bin`. Standard and diff workflows are coordinated by the host Pi session and skill instructions; Deep Scan has a TypeScript coordinator with native in-process sessions. `lifecycle.ts` is the main TypeScript facade over the bundled Python `workbench_db.py`, while artifact modules also invoke Python normalization and inventory helpers. Local SQLite and scan artifacts already enforce target identity, lifecycle, coverage, finding, remediation, continuation, and permission-profile contracts that this change must preserve.

Pi process RPC is a JSONL stdin/stdout protocol separate from the existing `subagent-rpc.ts` bridge. The RPC client supports prompts, steering, follow-up, abort, session operations, model/thinking settings, usage statistics, and events. The new runtime must supervise that process boundary without allowing Pi sessions, prompts, or UI adapters to become workflow authorities.

## Goals / Non-Goals

**Goals:**

- Establish one TypeScript control plane usable by the standalone CLI and later by the full TUI, Pi widgets, executor service, and additional workflow families.
- Prove an end-to-end built-in full-repository workflow with phase-scoped Pi RPC sessions, typed handoffs, durable state, ordered events, foreground progress, cancellation, inspection, explicit resume, and linked retry.
- Preserve current target, artifact, continuation, permission-profile, and completed-coverage protections.
- Introduce clean repository and adapter boundaries that permit later bounded Python-to-TypeScript cutovers without dual orchestration.

**Non-Goals:**

- Public user composition of workflow graphs or arbitrary prompt/script phase types.
- Standard/diff/deep feature parity beyond keeping their current entry points operational.
- A full-screen attachable TUI, central state service, remote/distributed execution, or hidden local daemon.
- Triage, ranking, remediation, target mutation, automated apply, local branch integration, or remote publication.
- Replacing SQLite or removing the Python runtime in this change.

## Decisions

### 1. The runtime, not an agent session, owns orchestration

Introduce a workflow runtime that owns phase readiness, scheduling, concurrency, output admission, attempts, cancellation, and terminal outcomes. Front ends issue commands and render state; Pi sessions perform bounded phase work. This prevents prompt text or a long-lived lead conversation from becoming an unpersisted second state machine.

Alternative: retain a primary Pi session that decides delegation and phase progression. Rejected because it conflicts with deterministic configuration, phase-specific models, durable resume, and consistent CLI/TUI behavior.

### 2. Use an internal typed DAG with a closed phase registry

Represent the P0 built-in workflow as a versioned acyclic graph. Each phase instance has a stable ID, registered phase type/version, dependencies, role reference, input bindings, and lifecycle state. Each phase type defines its input/output schemas, executor kind, capability ceiling, and attempt policy.

The initial graph contains deterministic preflight and publication operations plus model-executed threat-model, discovery, reduction, validation, attack-path, and narrative-reporting work. Parallel discovery and validation are multiple logical agents under their parent phase. Deterministic projection remains code rather than consuming model calls.

The graph is internal in P0. Later public phase composition can expose the same model after contracts stabilize. Arbitrary user code, shell commands, and unregistered phase executors are excluded.

### 3. Use phase-scoped Pi RPC sessions

Every model-executed phase or worker receives a new Pi RPC session with an explicit input package: run and phase identity, assigned role, target and artifact authority, scoped upstream typed outputs, selected evidence references, capability profile, and required output schema. Completed phases hand off validated data and artifacts, not private conversation history.

Persist separate identities for logical agents, execution attempts, and provider/Pi sessions. Replaceable transport/provider failures create a new attempt under the same logical agent. Policy denial, authority mismatch, deterministic schema incompatibility, and cancellation are not treated as transient replacement failures.

Alternative: one persistent lead session. Rejected because context growth, hidden state, and one model selection would undermine role and phase isolation.

### 4. Route every agent control through the runtime

Status, transcript inspection, steering, follow-up, interrupt, stop, and resume commands resolve a runtime-owned logical agent before invoking Pi RPC. The runtime verifies run ownership, target binding, active attempt, phase state, and issued authority. Steering is persisted as provenance so an operator-influenced run is distinguishable from config-only execution.

The existing `subagent-rpc.ts` ownership checks and Deep continuation checks are patterns to retain, not transports to conflate with process RPC.

### 5. Resolve TOML into a provenance-aware immutable snapshot

Configuration resolution order is built-in defaults, ambient user config, explicit `--config`, then supported non-secret CLI overrides. Values carry source metadata through validation. The built-in workflow refers to named roles containing provider, model, thinking level, instructions, attempt settings, and credential source. Phase capability policy remains independent and cannot be expanded by role configuration.

Credentials support profile references, environment references, and inline TOML literals. CLI secret flags are not exposed. Parsing produces a secret-aware in-memory representation and a sanitized persistable snapshot. Known credential values are redacted before errors, events, diagnostics, reports, or activity data cross the executor boundary. Raw config files are never copied or rewritten.

Resume reads execution semantics from the persisted snapshot. Credential material must be resolved again when absent; re-supplying a credential is allowed, but changing provider/model/workflow/policy requires a new run.

### 6. Keep relational state authoritative and add ordered journals

Extend the existing SQLite/workbench boundary with workflow-run, phase, logical-agent, attempt, execution-snapshot, run-link, and event records. During P0, schema mutations and correctness-critical state/event transactions remain behind the existing Python workbench facade so TypeScript does not introduce a second SQLite writer or an early database-driver cutover.

Every domain transition and its run-local monotonically sequenced event commit in one transaction. Activity events record meaningful agent, tool, usage, and operator actions with correlation identifiers. High-volume presentation deltas remain ephemeral. Optional renderers and future exporters consume committed state/events after the transaction and cannot block execution.

Alternative: full event sourcing. Rejected because existing relational state is mature and replay migrations would add risk without improving the P0 user contract.

### 7. Separate attempt retry, run resume, and failed-run retry

An attempt retry replaces one transiently failed phase session. An explicit resume reclaims the same nonterminal interrupted run under its persisted snapshot. Retrying a terminal failed run creates a new linked run. Completed and canceled runs never resume.

Completed outputs are reusable only after validating phase type/version, input digest, target/revision, capability and policy compatibility, and output schema. Reuse is recorded with source run/phase/output provenance; it is not a silent cache hit.

A foreground process loss reconciles an owned running run to interrupted. Resume requires exact authority and one atomic controller claim. A live run owned by another controller cannot be adopted.

### 8. Use a durable cancellation barrier

Cancellation first stops scheduling, then aborts active RPC sessions, waits for attempt settlement, persists admissible outputs and failure details, freezes canonical output acceptance, and finally marks the run canceled. Late transport events may be retained diagnostically but cannot mutate phase, finding, coverage, or run state.

Ctrl-C requests this cancellation path when the foreground executor can handle it. Unexpected process termination remains interruption, not cancellation.

### 9. Keep P0 execution foreground-only

The standalone CLI adds a package `bin` and initially hosts the executor in process. The basic command surface is a scan-start command plus run inspect, cancel, resume, and retry operations. A TTY renderer shows current phase, workers, available completed/total units, findings, and terminal outcome; non-TTY output remains deterministic and scriptable.

No hidden daemon is started. The future durable executor service will host the same runtime abstraction under an external supervisor rather than requiring a P0 process model rewrite.

### 10. Migrate entry points without retaining duplicate workflow authority

The CLI uses the canonical runtime directly. Existing Pi skills and extension tools remain available. Where the P0 full-repository path is adapted, the skill becomes a thin invocation/rendering adapter and no longer owns a separate phase sequence. Diff and Deep behavior not migrated in this change continues through the existing implementation and is explicitly outside P0 parity.

The temporary Python workbench adapter remains an internal repository implementation. New TypeScript code depends on typed runtime repositories, not on Python command details, so later components can cut over one at a time and delete obsolete bridge commands.

### 11. Verify observable contracts at their boundaries

Use fake Pi RPC child processes to test framing, event handling, steering, abort, malformed messages, process loss, and replacement without model-provider access. Use temporary repositories and state directories for CLI behavior. Preserve existing artifact and lifecycle fixtures for completed/incomplete coverage, target identity, and output validation. Credential tests use synthetic tokens and assert absence across persisted state, events, rendered output, errors, and process arguments.

Package tests verify the executable, required assets, and unchanged current Node/Python requirements. Existing standard, diff, Deep, and workbench suites remain required because this change must not regress uncovered paths.

## Risks / Trade-offs

- [Two orchestration paths remain temporarily for uncovered diff/deep behavior] -> Keep the boundary explicit, adapt only the P0 full-repository path, and schedule clean follow-on cutovers rather than sharing mutable workflow logic between prompt and runtime coordinators.
- [The Python workbench facade may become a bottleneck for new transactional records] -> Add narrow batch-oriented commands behind a typed repository interface and keep domain transitions atomic inside one workbench invocation.
- [Pi RPC protocol or child-process failures can strand ownership] -> Persist attempt/session identity before dispatch, classify process exit separately from phase failure, and require explicit ownership reconciliation before resume.
- [Activity recording can increase database write volume] -> Persist meaningful completed actions rather than token deltas, batch activity writes where transaction semantics allow, and keep presentation events ephemeral.
- [Inline credentials can leak through provider/tool output] -> Maintain secret-aware values and redact known secrets at every executor egress; use synthetic secret canaries in behavioral tests.
- [A new public CLI/config surface can freeze accidental choices] -> Keep P0 commands and fields limited to the built-in workflow, document precedence and defaults, reject unknown fields, and update help/schema/docs/tests atomically.
- [Incomplete runs may appear successful because they retained findings] -> Preserve distinct completed, failed, canceled, and interrupted outcomes and permit complete coverage claims only for completed runs.

## Migration Plan

1. Add the CLI package entry, command parser, config resolver, runtime interfaces, and fake RPC test harness without redirecting existing skills.
2. Add workbench schema migrations and typed repository operations for execution snapshots, workflow runs, phases, logical agents, attempts, links, progress, and ordered events.
3. Implement Pi RPC process supervision, phase input/output validation, runtime-mediated controls, and attempt classification.
4. Implement the versioned built-in full-repository graph and its deterministic/model phase executors against existing artifact and permission-profile contracts.
5. Add foreground rendering and inspect/cancel/resume/retry commands, then exercise complete, failed, canceled, interrupted, resumed, and linked-retry scenarios.
6. Adapt the covered standard full-repository Pi entry point to the canonical runtime without changing diff/deep behavior.
7. Update public help, configuration schema/examples, README, package contents, and tests; run the project typecheck, test, and package checks.

Rollback removes the new CLI entry and runtime/schema additions while leaving existing skill entry points and legacy scan records intact. Database migrations must be additive for P0 so older installed code can ignore new tables; no rollback may delete user scan state.
