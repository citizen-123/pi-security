## Why

Pi Security runs three independent orchestration engines: skill-driven Standard/Diff scans through `pi-subagents`, the canonical CLI workflow through `pi --mode rpc` child processes, and the Deep Scan coordinator through in-process `createAgentSession`. Each engine owns its own attempts, leases, heartbeats, continuation files, cancellation barriers, and resume logic, and every state mutation crosses a `python3 workbench_db.py` subprocess. Roughly two thirds of the TypeScript and half of the Python exist to emulate durable execution.

`@earendil-works/pi-durable` provides that machinery directly: atomic commits of transcript entries, documents, and task state; durable task trees with owned children, `waiting` joins, durable sleeps, bottom-up abort, crash recovery with restart limits, and `requestId` admission deduplication. Rebuilding on it replaces the three engines with one task graph and lets the codebase shrink to security method, confinement, and deterministic artifact production.

This change supersedes `openspec/changes/canonical-cli-runtime`.

## What Changes

- **BREAKING**: Replace all scan orchestration with one pi-durable Harness per run. Standard, Diff, and Deep become modes of a single `security.scan` orchestrator task. Remediation (fix, verify) becomes durable runs as well.
- **BREAKING**: Replace the Python workbench and every `workbench_*` subprocess with TypeScript. Run state lives in the run's durable SQLite; cross-run finding identity, triage, and remediation live in a TypeScript findings ledger. Deterministic Python (finalizer, SARIF, report projection, candidate normalization, inventory, finding identity) is ported to TypeScript behind a golden-file parity gate, then deleted.
- **BREAKING**: Replace the 46 lifecycle tools, `pi_security_workbench`, `pi_security_spawn_agents`, and `pi_security_control_agents` with a small CLI and a thin Pi extension (about six tools) that starts runs and observes them read-only.
- **BREAKING**: No migration of `~/.pi/security/workbench.sqlite3`. Old scan directories remain readable files.
- Resolve model credentials through `pi-coding-agent`'s exported `ModelRuntime` (Pi `auth.json`, OAuth refresh, `models.json`, provider environment variables), with TOML role overrides for provider, model, and thinking.
- Deep Scan changes strategy: the threat model partitions the target into focus areas, and discovery runs (area × lens) packets in repeated rounds until a configured number of rounds admits no new candidates.
- Fix runs work in an isolated `git worktree` on a new branch under the run directory, may write only inside it, and may execute only operator-allowlisted test commands with a scrubbed environment.
- Keep the scan-directory output contract: `scan-manifest.json` (sealed), `findings.json`, `coverage.json`, `report.md`, `exports/results.sarif`, `exports/findings.{json,csv}`.
- Pin `@earendil-works/pi-durable` to an exact version and confine its API to one internal adapter module.

## Capabilities

### New Capabilities

- `durable-scan-runtime`: Per-run Harness, run identity, orchestrator and worker task model, resume, cancellation, crash-loop parking, bounded fan-out, deadlines, and progress observation.
- `scan-modes`: Standard, Diff, and Deep semantics as parameters of one orchestrator, including Deep saturation rules.
- `execution-confinement`: Confined execution environment, tool surfaces per role, credential isolation, transcript redaction, and storage permissions.
- `findings-ledger`: Cross-run finding identity, occurrences, triage, and remediation linkage; publication from runs into the ledger; exports.
- `remediation-runs`: Fix and verify runs in isolated worktrees with allowlisted command execution.
- `cli-and-pi-surface`: Public CLI commands, configuration, exit codes, and the thin Pi extension.

### Modified Capabilities

<!-- The spec tree has no archived capabilities; canonical-cli-runtime was never archived and is superseded. -->

## Impact

- Deletes `src/deep-scan/`, `src/runtime/`, `src/rpc/`, `src/workflow/`, `src/lifecycle/`, `extensions/lifecycle-tools.ts`, `extensions/subagent-*.ts`, the `pi-subagents` bundle, and all of `scripts/` after parity.
- Adds dependencies: `@earendil-works/pi-durable` (exact pin), `@earendil-works/pi-ai`, `@earendil-works/chord`. Moves `@earendil-works/pi-coding-agent` to `^1.4.0` for `ModelRuntime`.
- Removes the Python runtime requirement for users. Python test suites remain only as the parity oracle until cutover.
- Public API changes require updated README, help text, schemas, and package-content tests in the same change set.
- pi-durable is experimental and ships breaking changes between minor releases; upgrades are explicit, adapter-scoped work.
