## 1. CLI and Configuration Foundation

- [x] 1.1 Add the `pi-security` package executable and command parser for scan start plus run inspect, cancel, resume, and retry; verify CLI help, unknown-command, and missing-argument behavior with a focused Node CLI test.
- [x] 1.2 Add the TOML configuration parser and typed schema for the built-in workflow, named roles, provider/model/thinking settings, target, attempt settings, and credential sources; verify valid and invalid examples with focused configuration tests.
- [x] 1.3 Implement deterministic defaults, ambient config, explicit `--config`, and supported non-secret CLI override resolution with per-field provenance; verify precedence and direct CLI-to-config field mapping in configuration tests.
- [x] 1.4 Implement secret-aware literal, environment, and profile credential resolution plus sanitized configuration projection; verify synthetic secrets never appear in projections, errors, process arguments, or serialized snapshots.
- [x] 1.5 Add immutable resolved-execution snapshot construction and execution-significant digests that exclude credential material; verify changing workflow/model/policy fields changes compatibility while changing or redacting a credential value does not persist or hash the secret.

## 2. Durable Runtime State

- [x] 2.1 Add additive workbench migrations for workflow runs, phase instances, logical agents, attempts, sanitized snapshots, run links, progress, controller claims, and ordered events; verify fresh setup and upgrade from the existing schema with workbench migration tests.
- [x] 2.2 Extend the Python workbench facade with narrow transactional operations for creating a run and phases, claiming a controller, transitioning lifecycle state, recording outputs, and appending the matching domain event; verify each transition and event commit atomically under success and injected failure.
- [x] 2.3 Add typed TypeScript repository interfaces and the temporary workbench-backed adapter so runtime code does not depend on Python command shapes; verify adapter contract tests cover state round trips and stable typed failures.
- [x] 2.4 Add run-state, progress, and ordered-event queries including events after a run-local sequence; verify reconnect returns canonical state and later events in sequence order without replaying activity history.
- [x] 2.5 Implement run-link and validated output-reuse records; verify a compatible output retains source run/phase/digest provenance and incompatible type, version, input, target, or policy identities are rejected.

## 3. Pi RPC Supervision

- [x] 3.1 Add a fake Pi RPC executable/fixture supporting prompts, events, controls, malformed frames, delayed exit, and process loss; verify the fixture drives tests without provider or network access.
- [x] 3.2 Implement the JSONL Pi process RPC transport with strict request correlation, stdout framing, stderr diagnostics, exit classification, and bounded cleanup; verify valid traffic, malformed messages, duplicate responses, stderr output, and unexpected exit behavior.
- [x] 3.3 Implement phase-scoped session launch using resolved role model/thinking/credential settings and issued target/artifact capability profiles; verify the fake process receives expected non-secret settings and cannot obtain capabilities beyond the phase ceiling.
- [x] 3.4 Persist logical-agent, attempt, and Pi-session identities before dispatch and record meaningful session, message, tool, and usage activity; verify retries keep the logical identity while allocating distinct attempts and session IDs.
- [x] 3.5 Route status, transcript, steering, follow-up, interrupt, and stop through runtime ownership checks; verify valid controls reach the bound fake session and foreign, stale, or cross-target controls are rejected before RPC dispatch.
- [x] 3.6 Implement replaceable versus non-replaceable attempt classification and bounded replacement; verify provider/transport failures can replace within policy while policy denial, invalid authority, schema incompatibility, and cancellation cannot.

## 4. Typed Workflow Runtime

- [x] 4.1 Define versioned phase types, phase instances, input/output bindings, lifecycle states, capability ceilings, and attempt policies in a closed registry; verify duplicate IDs, missing dependencies, cycles, incompatible bindings, and unknown phase types fail graph validation.
- [x] 4.2 Implement the deterministic DAG scheduler with dependency readiness, bounded parallel workers, output admission, and terminal aggregation; verify sequential, fan-out/fan-in, failure, skip, cancellation, and duplicate-completion scenarios.
- [x] 4.3 Define the versioned built-in full-repository workflow covering preflight, threat model, discovery, reduction, validation, attack path, reporting, and publication; verify its graph, role bindings, and required phase contracts through a snapshot test.
- [x] 4.4 Implement explicit phase input-package assembly from target identity, role, scoped upstream typed outputs, evidence references, artifact authority, and output schema; verify completed private Pi transcripts are not required by downstream phases.
- [x] 4.5 Implement structured phase-result parsing and schema validation before state admission; verify free-form completion text, process success without output, malformed data, and duplicate delivery cannot complete a phase.
- [x] 4.6 Connect deterministic preflight/publication and model-executed threat-model, discovery, reduction, validation, attack-path, and narrative-reporting phase adapters to existing artifact and permission-profile contracts; verify an end-to-end fake-agent run publishes the existing manifest, findings, coverage, report, and SARIF contract.

## 5. Run Lifecycle and Recovery

- [ ] 5.1 Implement scan creation that validates config and target, persists the immutable snapshot and workflow before agent launch, then atomically claims foreground controller ownership; verify invalid preflight starts no agent and concurrent claims have one winner.
- [ ] 5.2 Implement completed, failed, canceled, and interrupted outcomes while preserving admissible evidence and honest coverage semantics; verify only completed runs can publish a complete coverage conclusion.
- [ ] 5.3 Implement the cancellation barrier that stops scheduling, aborts attempts, awaits settlement, persists admissible state, freezes output admission, and marks cancellation terminal; verify late fake-agent output cannot mutate canonical state.
- [ ] 5.4 Reconcile unexpected foreground process/session loss to an interrupted run and implement explicit compatible resume using the persisted snapshot and freshly validated authority; verify completed/canceled/failed runs and mismatched target, role, model, policy, or capability state cannot resume in place.
- [ ] 5.5 Implement failed-run retry as creation of a new linked run with optional explicitly validated immutable output reuse; verify the failed run remains unchanged and reuse events identify every accepted source output.

## 6. CLI Progress and Operations

- [ ] 6.1 Implement foreground scan execution and exit-status mapping for completed, failed, canceled, interrupted, and configuration/preflight failures; verify each outcome through CLI subprocess tests using the fake RPC executable.
- [ ] 6.2 Implement the TTY progress renderer showing phase states, active logical agents, meaningful completed/total units, finding counts, unavailable values, and terminal outcome; verify rendered snapshots never fall back to a generic working-only display.
- [ ] 6.3 Implement deterministic non-TTY output and run inspection from relational state without a live executor; verify completed and interrupted runs can be inspected and parsed after their originating process exits.
- [ ] 6.4 Wire CLI cancel, explicit resume, and linked retry to the runtime command layer; verify commands enforce ownership/state/version rules and never mutate terminal history incorrectly.
- [ ] 6.5 Implement event reconnection after a supplied run sequence for CLI consumers; verify missed committed events are delivered once in canonical order and unsupported event versions produce a compatibility error.

## 7. Pi Adapter and Compatibility

- [ ] 7.1 Add a Pi extension adapter for starting and observing the covered canonical full-repository workflow without giving widgets or the invoking session phase-transition authority; verify lifecycle tool tests show commands route through the runtime.
- [ ] 7.2 Update the `/security-scan` skill so the covered full-repository path delegates orchestration to the canonical runtime while retaining its existing user-facing invocation; verify artifact/skill tests contain no independent duplicate phase sequence for that path.
- [ ] 7.3 Preserve existing diff and Deep entry points on their current implementations until their follow-on cutovers; verify the existing diff, Deep coordinator, continuation, policy, and artifact integration tests remain green.
- [ ] 7.4 Preserve the temporary Python workbench and current Node/Python engine requirements in package contents; verify package tests include the new executable and still include every existing required runtime asset.

## 8. Documentation and End-to-End Verification

- [ ] 8.1 Document CLI commands, TOML precedence, role settings, credential forms and redaction, foreground ownership, terminal outcomes, cancellation, explicit resume, and linked retry in package and root user documentation; verify every documented command appears in generated CLI help.
- [ ] 8.2 Add synthetic end-to-end fixtures for completed, failed, canceled, interrupted/resumed, and failed/retried full-repository runs; verify each scenario exercises the packaged CLI against a temporary repository and fake Pi RPC process.
- [ ] 8.3 Add credential-canary coverage across SQLite state, domain/activity events, artifacts, reports, rendered output, errors, and child-process arguments; verify the synthetic credential is absent from every captured durable and user-facing output.
- [ ] 8.4 Run `npm run typecheck` from the repository root and resolve every reported TypeScript error.
- [ ] 8.5 Run `npm test` from the repository root and resolve every Node and Python behavioral regression.
- [ ] 8.6 Run `npm run test:pack` from the repository root and verify both publication archives contain the CLI and required assets without tests, caches, state, or undeclared files.
