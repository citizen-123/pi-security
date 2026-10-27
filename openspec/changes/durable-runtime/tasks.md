## 0. Spike (throwaway, before committing to the design)

- [x] 0.1 Build a faux-provider prototype: one `security.scan` orchestrator with three `security.worker` children that own conversations and report through a schema tool. Kill the process at each commit boundary and resume; confirm no duplicate workers or results. Done: 279 crash points, 0 failures (`spikes/durable-runtime/RESULTS.md`).
- [x] 0.2 Confirm `ModelRuntime.create()` from `pi-coding-agent` works as `HarnessOptions.models` with a real `auth.json` (API key and OAuth), and that the resulting provider requests carry no credential into stored entries. Done for API keys; found and fixed error-body leakage with a redacting `Models` decorator. OAuth untested.
- [x] 0.3 Measure wave fan-out (D4) on 64 faux workers with random latency; record slot idle time to decide whether an `anySettled` join is worth asking upstream for. Done: waves 2.3–2.4× slower; lanes match the ideal, so no upstream join is needed.
- [x] 0.4 Confirm the stall watchdog can read each worker's last progress time (newest entry, `pi.live` updates) from a background task without loading whole transcripts. Done: no stored timestamps exist; a host-side in-memory monitor over watches works.
- [ ] 0.5 Review the spike results with the maintainer (`design.md` amended: D2/D3 idempotent creation and host stall monitor, D4 lanes, D5 redacting `Models`, D12 published-API note).
- [ ] 0.6 Manually verify OAuth credentials through `ModelRuntime` with a real `auth.json`.

## 1. Parity oracle (before any porting)

- [x] 1.1 Build synthetic fixture repositories and scan directories covering Standard, Diff, and Deep outputs, including findings with every severity, coverage gaps, merged provenance, and non-ASCII paths. Done: 81 curated cases across six scripts (`packages/pi-security/tests/parity/`), including number-formatting, code-point-ordering, and canonical-JSON traps.
- [x] 1.2 Add a parity harness that runs a Python entry point and its TypeScript port on the same input and compares normalized JSON, SARIF bytes, CSV bytes, and fingerprints. Done: Python goldens (`oracle.py`), recorded function vectors from the pytest suite (`record_vectors.py`), and `tests/parity.test.mjs` for ports, self-tested against the goldens through Python.

## 2. Domain port (TypeScript, each with parity tests)

- [ ] 2.1 Finding identity, fingerprints, and dedupe (`workbench_findings.py`, `workbench_finding_index.py`).
- [ ] 2.2 Candidate normalization (`normalize_candidates.py`).
- [ ] 2.3 Git-aware inventory and diff file lists (`generate_in_scope_files.py`, `workbench_target.py` fixed-argument git), plus the working-tree snapshot commit (D14) with tests that the user's index, branch, and stash are untouched.
- [ ] 2.4 Finalizer, manifest sealing, schema validation, SARIF, and exports (`finalize_scan_contract.py`, `validate_scan_contract.py`).
- [ ] 2.5 Report projection (`report_projection.py`).
- [ ] 2.6 Preflight (`config_preflight.py`) and the patch-risk validator in `skills/assess-patch-risk`.

## 3. Runtime foundation

- [ ] 3.1 `src/durable/`: the adapter module, exact version pin, Harness open/close, run lock, and `0700`/`0600` run directories.
- [ ] 3.2 Confined environment: port `execution-boundary.ts` rules into an `ExecutionEnv`; run durable's `registerEnvConformance` plus escape tests (symlink, `..`, absolute, fd swap).
- [ ] 3.3 Package tools (`list_files`, `read_source`, `search_source`, `git_metadata`, `get_context`) and per-role `report_*` tools writing session-scoped result documents.
- [ ] 3.4 `security.worker` task and role configuration, including the resolved-agent check (D7).
- [ ] 3.5 Configuration: TOML resolution and roles; `ModelRuntime` wiring behind the redacting `Models` decorator; reject inline credentials.

## 4. Scan orchestration

- [ ] 4.1 `security.scan` Standard path, end to end on the faux provider.
- [ ] 4.2 Lanes and the queue document, phase failure policy (D6), and honest coverage.
- [ ] 4.3 Diff scope.
- [ ] 4.4 Deep rounds, reducer provenance accounting, and saturation.
- [ ] 4.5 Host stall monitor with one replacement per worker, `max_cost`, the `security.deadline` task for `max_duration`, cancel requests from viewers, and parked-task retry.
- [ ] 4.6 Crash-injection suite: kill at every commit boundary of 4.1, 4.3, and 4.4, then resume and compare outputs.
- [ ] 4.7 Port worker prompts from `references/`, `templates/deep-scan/`, and the skill method into role instructions and prompt sections.

## 5. Ledger and remediation

- [ ] 5.1 `ledger.sqlite` schema, idempotent publication, concurrent-publisher test, triage events, and exports.
- [ ] 5.2 `security.fix`: worktree preparation, confined write and edit tools, `run_check` with scrubbed environment, commit, and patch output.
- [ ] 5.3 In-run verification phases, `--no-verify`, the standalone `verify` re-check run, verdict history, and a concurrent-fixes-of-one-finding test.

## 6. Surface and cutover

- [ ] 6.1 CLI commands, help, exit codes, `--json`, `--detach`, and `run watch` rendering.
- [ ] 6.2 Thin Pi extension with six tools and direct slash commands; the `triage-finding` skill; delete the other skills and remove `pi-subagents`.
- [ ] 6.3 Delete the superseded TypeScript (`src/deep-scan`, `src/runtime`, `src/rpc`, `src/workflow`, `src/lifecycle`, old extensions) and `openspec/changes/canonical-cli-runtime`.
- [ ] 6.4 Delete `scripts/` and the Python tests once every parity test passes, in one dedicated commit.
- [ ] 6.5 README, package README, schemas, `package.json` files list, and `test:pack` updates.
- [ ] 6.6 Run `npm run typecheck`, `npm test`, and `npm run test:pack`, plus one live-model scan of a synthetic fixture repository.
