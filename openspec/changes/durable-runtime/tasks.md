## 0. Spike (throwaway, before committing to the design)

- [ ] 0.1 Build a faux-provider prototype: one `security.scan` orchestrator with three `security.worker` children that own conversations and report through a schema tool. Kill the process at each commit boundary and resume; confirm no duplicate workers or results.
- [ ] 0.2 Confirm `ModelRuntime.create()` from `pi-coding-agent` works as `HarnessOptions.models` with a real `auth.json` (API key and OAuth), and that the resulting provider requests carry no credential into stored entries.
- [ ] 0.3 Measure wave fan-out (D4) on 64 faux workers with random latency; record slot idle time to decide whether an `anySettled` join is worth asking upstream for.
- [ ] 0.4 Review the spike results with the maintainer and amend `design.md` before continuing.

## 1. Parity oracle (before any porting)

- [ ] 1.1 Build synthetic fixture repositories and scan directories covering Standard, Diff, and Deep outputs, including findings with every severity, coverage gaps, merged provenance, and non-ASCII paths.
- [ ] 1.2 Add a parity harness that runs a Python entry point and its TypeScript port on the same input and compares normalized JSON, SARIF bytes, CSV bytes, and fingerprints.

## 2. Domain port (TypeScript, each with parity tests)

- [ ] 2.1 Finding identity, fingerprints, and dedupe (`workbench_findings.py`, `workbench_finding_index.py`).
- [ ] 2.2 Candidate normalization (`normalize_candidates.py`).
- [ ] 2.3 Git-aware inventory and diff file lists (`generate_in_scope_files.py`, `workbench_target.py` fixed-argument git).
- [ ] 2.4 Finalizer, manifest sealing, schema validation, SARIF, and exports (`finalize_scan_contract.py`, `validate_scan_contract.py`).
- [ ] 2.5 Report projection (`report_projection.py`).
- [ ] 2.6 Preflight (`config_preflight.py`) and the patch-risk validator in `skills/assess-patch-risk`.

## 3. Runtime foundation

- [ ] 3.1 `src/durable/`: the adapter module, exact version pin, Harness open/close, run lock, and `0700`/`0600` run directories.
- [ ] 3.2 Confined environment: port `execution-boundary.ts` rules into an `ExecutionEnv`; run durable's `registerEnvConformance` plus escape tests (symlink, `..`, absolute, fd swap).
- [ ] 3.3 Package tools (`list_files`, `read_source`, `search_source`, `git_metadata`, `get_context`) and per-role `report_*` tools writing session-scoped result documents.
- [ ] 3.4 `security.worker` task and role configuration, including the resolved-agent check (D7).
- [ ] 3.5 Configuration: TOML resolution and roles; `ModelRuntime` wiring; reject inline credentials.

## 4. Scan orchestration

- [ ] 4.1 `security.scan` Standard path, end to end on the faux provider.
- [ ] 4.2 Waves, phase failure policy (D6), and honest coverage.
- [ ] 4.3 Diff scope.
- [ ] 4.4 Deep rounds, reducer provenance accounting, and saturation.
- [ ] 4.5 Deadline watchdog, cancel requests from viewers, and parked-task retry.
- [ ] 4.6 Crash-injection suite: kill at every commit boundary of 4.1, 4.3, and 4.4, then resume and compare outputs.
- [ ] 4.7 Port worker prompts from `references/`, `templates/deep-scan/`, and the skill method into role instructions and prompt sections.

## 5. Ledger and remediation

- [ ] 5.1 `ledger.sqlite` schema, idempotent publication, concurrent-publisher test, triage events, and exports.
- [ ] 5.2 `security.fix`: worktree preparation, confined write and edit tools, `run_check` with scrubbed environment, and patch output.
- [ ] 5.3 `security.verify` and remediation status updates.

## 6. Surface and cutover

- [ ] 6.1 CLI commands, help, exit codes, `--json`, `--detach`, and `run watch` rendering.
- [ ] 6.2 Thin Pi extension with six tools and slash commands; remove `pi-subagents`.
- [ ] 6.3 Delete the superseded TypeScript (`src/deep-scan`, `src/runtime`, `src/rpc`, `src/workflow`, `src/lifecycle`, old extensions) and `openspec/changes/canonical-cli-runtime`.
- [ ] 6.4 Delete `scripts/` and the Python tests once every parity test passes, in one dedicated commit.
- [ ] 6.5 README, package README, schemas, `package.json` files list, and `test:pack` updates.
- [ ] 6.6 Run `npm run typecheck`, `npm test`, and `npm run test:pack`, plus one live-model scan of a synthetic fixture repository.
