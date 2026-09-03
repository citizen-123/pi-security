## Why

Pi Security currently has no standalone CLI, and scan orchestration is split across host-led skill prompts, extension lifecycle tools, and the Deep Scan coordinator. A canonical TypeScript runtime is needed so CLI execution, future TUI surfaces, Pi widgets, configurable roles and phases, telemetry, and later workflows share one authoritative control plane instead of duplicating scan semantics.

## What Changes

- Add a standalone `pi-security` CLI whose runtime owns scan orchestration and drives Pi agent processes through Pi's JSONL RPC mode.
- Deliver one built-in full-repository workflow covering deterministic preflight, threat modeling, parallel discovery, reduction, validation, attack-path analysis, reporting, and publication.
- Run model work in phase-scoped Pi RPC sessions with runtime-owned logical agent and attempt identities, typed inputs and outputs, bounded replacement attempts, and operator control through the runtime.
- Add TOML execution configuration with deterministic precedence, field provenance, role-specific provider/model/thinking selection, credential references, environment references, and explicitly permitted inline credentials.
- Persist a sanitized immutable execution snapshot. Credential values remain executor-local and MUST NOT enter state, events, reports, diagnostics, or process arguments.
- Add a hybrid state and event model: existing relational state remains authoritative while ordered domain and activity events support progress, audit, reconnection, and future exporters.
- Add foreground execution, informative terminal progress, durable cancellation, run inspection, and explicit resume of compatible interrupted runs. Failed-run retry creates a new linked run rather than rewriting terminal history.
- Keep existing standard, diff, and deep skill entry points operational during this change. They may adapt to the canonical runtime where covered, but diff/deep parity, public workflow composition, full TUI, triage, remediation, central storage, executor-service mode, and final Python removal remain follow-on changes.
- Preserve the current Node.js and Python runtime requirements for this P0 slice; the Python workbench remains a temporary internal state/artifact adapter until later bounded TypeScript cutovers.

## Capabilities

### New Capabilities

- `canonical-scan-execution`: Standalone full-repository scan execution, typed workflow lifecycle, terminal outcomes, cancellation, inspection, resume, and linked retry behavior.
- `execution-configuration`: TOML configuration resolution, role execution settings, value provenance, immutable sanitized snapshots, and credential-source handling.
- `rpc-agent-control`: Runtime-owned phase-scoped Pi RPC sessions, logical agent attempts, operator controls, output validation, and recovery boundaries.
- `run-observability`: Ordered transactional domain events, activity events, progress snapshots, and informative CLI rendering without making exporters correctness-critical.

### Modified Capabilities

<!-- No existing OpenSpec capability requirements are modified; the current spec tree is empty. -->

## Impact

- Adds a public CLI command surface and package `bin` entry, requiring matching help, documentation, schemas, and packaging tests.
- Introduces a TypeScript orchestration/configuration/event layer around the existing lifecycle, artifact, permission-profile, Deep Scan, and Python workbench boundaries.
- Extends local SQLite state with workflow-run, phase, attempt, snapshot, linkage, and ordered-event records while preserving existing scan, finding, artifact, and policy invariants.
- Adds Pi process RPC supervision alongside the existing in-process Pi extension integration; existing skills and widgets become secondary adapters rather than independent orchestration authorities.
- Requires behavioral tests for the public CLI and configuration contracts, phase/output validation, RPC process lifecycle, cancellation/interruption/resume, event ordering, credential redaction, and completed-versus-incomplete coverage semantics.
- Does not add central services, remote execution, target mutation, arbitrary user-defined phases, automatic remediation, or a Python-free package in this change.
