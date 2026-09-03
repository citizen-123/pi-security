# Pi Security

Standalone security scanning workbench and native Pi extension package. Analysis runs in Pi; lifecycle state, artifact validation, reports, findings, triage, remediation, and exports are deterministic local operations.

## Requirements

- Node.js 22.19 or newer
- Python 3.11 or newer for the bundled workbench
- Git for Git-aware targets and diff scans

No model-provider CLI or SDK, provider account or API key, or hosted security service is required.

## Install in Pi

```sh
pi install npm:pi-security
```

The package loads bundled `pi-subagents` before Pi Security, registers the managed scan lifecycle and lower-level `pi_security_workbench` tool, and provides:

```text
/security-scan [optional focus]
/security-diff-scan [optional focus]
/deep-security-scan [optional focus]
```

All three modes work as soon as the package loads. No separate transport or server configuration is required.

Every lifecycle tool and the low-level workbench uses the same Python resolution order: `PI_SECURITY_PYTHON_COMMAND`, then `PYTHON`, then Pi's executable cached primary runtime when present, then `python3` on Unix-like systems or `python` on Windows. Interactive lifecycle questions use Pi's native UI and fall back to normal chat when no interactive UI is available.

## Capability matrix

| Capability | Standard | Diff | Deep |
| --- | --- | --- | --- |
| Source boundary | Requested repository scope | Exact local Git change set plus authorized supporting code | Requested repository scope |
| Execution | Current Pi session and bundled read-only subagents | Current Pi session and bundled read-only subagents | Isolated native Pi worker sessions |
| Continuation | Managed scan handoff | Managed scan handoff | Durable per-worker native message history |
| Delegation | Bundled subagent fleet | Bundled subagent fleet | Optional one-level, bounded readonly child workers |
| Outputs | Report, SARIF, findings, coverage | Report, SARIF, findings, coverage | Aggregated report, SARIF, findings, coverage |

Standard and Diff retain their existing host-led behavior. Deep uses the active Pi model and reasoning configuration while enforcing a fixed per-worker tool allowlist.

## Permission-profile layer

Pi Security treats repository contents, model output, lifecycle arguments, and saved artifacts as data. Authority comes only from an immutable context issued inside the package and bound to one target root, scan ID, and artifact root. Consumers reject hand-built, spread-cloned, inherited, accessor-backed, boxed-string, and unknown-profile inputs rather than reconstructing authority from their shape.

### Built-in profiles

The profile set and capability names are closed:

| Capability | `security-readonly` | `security-delegating-readonly` | `security-artifact-writer` |
| --- | ---: | ---: | ---: |
| `target.read` | Yes | Yes | No |
| `target.search` | Yes | Yes | No |
| `target.git` | Yes | Yes | No |
| `scan-artifacts.write` | No | No | Yes |
| `workbench.execute` | No | No | Yes |
| `network.access` | No | No | No |
| `target.execute` | No | No | No |
| `target.write` | No | No | No |
| `delegation.create` | No | Yes | No |

- `security-readonly` supplies target-bound list/read/search and fixed Git metadata access. It cannot write scan artifacts or start another worker.
- `security-delegating-readonly` adds only host-budgeted delegation. Its maximum depth is one, every derived child is forcibly `security-readonly`, and each parent transition is atomic and single-use. A failed validation does not spend the budget; replaying a spent predecessor cannot branch it.
- `security-artifact-writer` can write trusted workbench and scan artifacts under its exact scan-bound artifact root and can dispatch the fixed bundled workbench. It cannot read, search, execute, or modify target source and cannot delegate.

No profile grants `network.access`, `target.execute`, or `target.write`.

### Pi adapters

The Pi extension does not accept a profile name from a command or tool call:

- lifecycle, low-level workbench, and artifact registrations use fixed `security-artifact-writer` contexts;
- each packaged scout/auditor/validator/reviewer receives `security-readonly` and the derived `read`, `grep`, `find`, and `ls` tool allowlist;
- `pi_security_spawn_agents` uses a host-owned `security-delegating-readonly` successor and reserves one readonly child atomically per accepted task;
- spawned run IDs are recorded against the creating Pi Security session and canonical target. Fleet and targeted status, transcript, steer, interrupt, stop, and resume operations reject unowned or cross-session IDs before sending a subagent RPC.

Deep Scan chooses `security-readonly` when delegation is disabled and `security-delegating-readonly` when the configured child budget is positive. The artifact writer and every delegated child are separately reissued as fixed `security-artifact-writer` and `security-readonly` contexts. A single requirement table controls both tools advertised to a native worker session and authorization at direct dispatch, so an omitted or unknown tool cannot be invoked through a hidden call.

### Path, Git, and platform enforcement

Model-facing target paths must be non-empty repository-relative paths inside both the issued target and coordinator scope. Absolute paths, Windows absolute aliases, control characters, backslashes, empty components, and `.`/`..` traversal components are rejected. Existing files and directories are opened without following symlinks; the opened object, not a previously checked pathname, is consumed. Directory identity is checked before and after enumeration and each returned child is reopened under the same root and scope.

The platform report names the mechanism actually used:

- `platform.posix-open-no-follow` plus `platform.linux-proc-self-fd` on Linux;
- `platform.posix-open-no-follow` plus `platform.posix-dev-fd` on other supported POSIX hosts;
- `platform.windows-reparse-identity` on Windows, with reparse-point and identity checks around enumeration.

Artifact roots are canonical, scan-bound coordinator state outside the untrusted target. Static symlinks and path swaps are rejected; a file already opened through a verified handle continues to refer to that opened file rather than a replacement pathname. Git metadata calls use fixed arguments and disable repository-configured `fsmonitor`, external-diff, text-conversion, pager, clean-filter, and process-filter helper sinks. If safe working-tree inspection cannot be provided under those rules, metadata reports it unavailable instead of running a helper.

Required mechanisms are checked before the guarded state commit. An unsupported target handle, artifact root, fixed-workbench, continuation, or native-worker requirement returns `PI_SECURITY_ENFORCEMENT_UNSUPPORTED` without creating or adopting the guarded scan or dispatching a worker. Pi Security never downgrades to pathname-only checks.

### Capability sandbox, not an OS process sandbox

These profiles constrain which Pi Security operations can be reached; they do not claim to install a general cross-platform OS process sandbox or firewall around the connected host. Scan profiles never run target code and expose no general target process execution, target mutation, or network capability. `workbench.execute` means only a package-selected Python command with a fixed bundled workbench script and validated arguments. Because target processes are not part of the scan design, Pi Security does not advertise unsupported per-process network controls.

### Continuation recovery and stable failures

Native worker continuation version 3 stores an application-owned continuation ID, worker kind, canonical Pi messages and tool results, exact source and writer policy snapshots, and bounded delegation state. On resume, fresh host authority must exactly match the saved profile, target root, scan ID, artifact root, capability matrix, and original delegation limits. Only the saved unspent successor is reissued. Delegated child policy, ordinal, task/context marker, and accepted result reference are checked before the parent is advanced.

Compatible legacy version 2 continuations migrate to the native format when they contain no pending protocol tool request. Older records, pending requests, continuation ID/kind mismatches, authority/profile changes, budget or depth restoration, malformed or stale child markers, and missing/foreign result references are rejected before worker execution, artifact mutation, continuation adoption, or replacement dispatch.

The stable policy errors are:

| Code | Category | Meaning |
| --- | --- | --- |
| `PI_SECURITY_POLICY_DENIED` | `policy_denied` | An issued profile does not allow the requested capability, or the capability/tool is unknown. |
| `PI_SECURITY_ENFORCEMENT_UNSUPPORTED` | `unsupported_enforcement` | The host or platform cannot apply a required mechanism. |
| `PI_SECURITY_POLICY_RECOVERY_REJECTED` | `policy_recovery_rejected` | Saved continuation authority cannot be safely reissued. |

Recovery rejection adds one of `legacy_continuation`, `profile_mismatch`, `invalid_policy`, `delegation_mismatch`, or `binding_mismatch`. Trusted enforcement/recovery failures are persisted as a typed `policyFailure` with `schemaVersion`, `code`, `category`, optional recovery `reason`, and `message` in the same failure transition as the worker/run state. Rejoin returns that same terminal identity without worker execution, heartbeats, or replacement dispatch. An ordinary error that merely copies a policy-code string is not promoted to a trusted policy failure.

### Diagnostics

`enforcementCapabilities` is a non-secret report with:

- `schemaVersion: 1`;
- `kind: "availability"` before work, or `kind: "effective"` only after the listed mechanisms were applied;
- `supported`;
- ordered `mechanisms`;
- `unsupportedReason`, which is `null` when supported.

Mechanism names are `pi.fixed-profile-tool-dispatch`, `pi.worker-session.tools`, `target.verified-open-handle`, `artifact.canonical-root-binding`, `workbench.fixed-bundled-command`, `continuation.exact-policy-reissue`, and the applicable platform mechanism above.

After a native worker response has run under the applied policy, worker diagnostics may include `effectivePolicy`:

```text
{
  schemaVersion,
  source: { schemaVersion, profile, capabilities, delegation },
  artifactWriter: { schemaVersion, profile, capabilities, delegation },
  enforcement: enforcementCapabilities
}
```

Each `capabilities` object contains the nine closed-set booleans shown in the profile table. Each `delegation` object contains `maxDepth`, `remainingBudget`, `remainingDepth`, `childProfile`, and `spent`.

The public source/writer projections deliberately omit target roots, artifact roots, scan IDs, handoff claims, credentials, and continuation tokens. An attempt that fails before effective enforcement reports availability only and does not claim an effective policy.

## Standard and diff behavior

Standard and diff scans do not make model-provider calls from the workbench. The connected Pi session reads and searches the authorized local source, performs the audit, and records schema-bound semantic drafts. The Python workbench validates and seals `scan-manifest.json`, `findings.json`, and `coverage.json`, then generates `report.md` and SARIF without model access.

Standard scans audit the requested repository scope. Diff scans first bind an exact local Git change set and keep discovery, validation, and attack-path decisions scoped to that review. Both retain explicit incomplete coverage rather than inventing results.

In Pi, the skills prefer `pi_security_spawn_agents` and `pi_security_control_agents`. If bundled orchestration is unavailable, they may use a host-provided generic subagent tool and then perform the documented sequential parent-agent fallback. This fallback does not turn the local workbench into a model executor.

## Bundled subagents

`pi-subagents` is a pinned, bundled runtime dependency. No separate extension install or agent-file copy is required. The package publishes these read-only profiles from `agents/`:

| Agent | Purpose |
| --- | --- |
| `pi-security-scout` | Map architecture, entry points, trust boundaries, and investigation packets. |
| `pi-security-auditor` | Investigate assigned source surfaces and return evidence-backed candidates. |
| `pi-security-validator` | Independently validate candidates and attack paths. |
| `pi-security-reviewer` | Review proposed findings, coverage, severity, and false positives. |

The profiles inherit repository instructions, use read-only source discovery tools, run with fresh context by default, and cannot spawn nested Pi agents. User and project profiles retain normal higher discovery precedence and may override packaged profiles by name.

- `pi_security_spawn_agents({ tasks, context? })` starts up to 16 packaged agents concurrently and returns asynchronous run records.
- `pi_security_control_agents({ action, id?, index?, message?, mode?, view?, lines? })` provides fleet or targeted status, transcript tails, steering, interruption, stopping, and resumption.


## Native Deep Scan

Each native discovery worker receives only coordinator-bound local tools:

- target-relative file listing, bounded source reads, and literal source search;
- repository/snapshot/Git metadata and authoritative scan context;
- schema-bound checkpoint and final-draft recording;
- optional bounded `delegate_security_task` calls when `deep_scan.subagents` is greater than zero.

Reducers receive scan context, validated reducer inputs, and a schema-bound reduction recorder rather than source tools. Paths remain bound to the authorized target, and source-tool symlinks are not followed.

The executor persists native Pi messages, completed tool results, and an application-owned continuation ID in worker artifacts. Retries and resumes restore that state without relying on a provider conversation or thread identifier. A top-level worker may create at most the configured number of delegated investigations; delegated children run with `subagents: 0`, so delegation is one level deep rather than recursive. The default is disabled (`subagents = 0`).

### Model, reasoning, and usage reporting

Deep workers use the active Pi model and requested reasoning effort. Diagnostics record the requested and applied native settings.

Token counts come from native Pi session statistics or, for host-led scans, the optional host session database. Coverage is reported as complete, partial, or unavailable according to the sessions that supplied counts. Missing counts are never inferred, converted to zero, or used to estimate cost. Nested Deep Scan usage is included in executor-tree totals and also reported as a nested subset.

## Standalone canonical CLI

The package exposes `pi-security`:

```sh
pi-security scan --target /absolute/repository/path
pi-security scan --config /absolute/pi-security.toml
pi-security run inspect <run-id>
pi-security run cancel <run-id>
pi-security run resume <run-id>
pi-security run retry <run-id>
```

The built-in `full-repository` workflow runs in the foreground. The canonical runtime alone advances phases and admits outputs. Non-TTY output is one deterministic JSON run record; TTY output includes phase units, active logical agents, available finding counts, and the terminal reason. Exit codes are completed `0`, failed `1`, configuration/preflight `2`, interrupted `75`, and canceled `130`.

Ctrl-C stops scheduling, aborts active attempts, waits for settlement, freezes admission, and records terminal cancellation. A handled foreground process-loss signal records interruption instead. `run resume` claims and continues the same interrupted run only when its target, snapshot, workflow, policy, capabilities, and admitted outputs remain compatible. `run retry` leaves failed history immutable and executes a new linked run.

Configuration precedence is defaults, ambient `$PI_HOME/pi-security/config.toml`, explicit `--config`, then supported non-secret CLI overrides. `[roles.<name>]` accepts provider, model, thinking, instructions, attempt policy, and exactly one credential form: `{ env = \"NAME\" }`, `{ profile = \"name\" }`, or `{ value = \"literal\" }`. Secret flags are not accepted. Credential values are memory-only and excluded from arguments, persisted snapshots, events, artifacts, rendering, and compatibility digests.

## State and configuration

Defaults:

- Workbench state: `$PI_HOME/security/workbench.sqlite3`, with `PI_HOME` defaulting to `~/.pi`
- Deep Scan settings: `$PI_HOME/pi-security/config.toml`
- Managed scan output: a private temporary directory unless `PI_SECURITY_SCAN_ROOT` is set

Supported environment variables:

- `PI_HOME`
- `PI_SECURITY_STATE_DIR`
- `PI_SECURITY_SCAN_ROOT`
- `PI_SECURITY_DEEP_SCAN_CONFIG_PATH`
- `PI_SECURITY_PYTHON_COMMAND`
- `PI_SECURITY_SESSION_DB` for optional host-supplied token-usage attribution

Deep Scan configuration is optional:

```toml
[deep_scan]
workers = 4
subagents = 0
stop_after_no_new = 2
stop_after_consecutive_errors = 3
max_discovery_runs = 12
max_time_hours = 4
```

The capability preflight reads no harness or provider configuration. It accepts only the target directory, profile, and explicitly observed runtime capabilities.

## Direct workbench use

Every lifecycle operation is backed by the bundled Python workbench:

```sh
python3 scripts/workbench_db.py inspect-target --target-path /absolute/repository/path
python3 scripts/workbench_db.py --help
```

Runtime Python dependencies are bundled source modules or the Python standard library. Python packages in `requirements-test.txt` are development/test dependencies, not an installation step for end users.

## Removed integrations

Legacy provider-specific CLI/SDK executors, credential discovery, provider configuration probing, hosted-service paths, and generic protocol transports are intentionally not part of standalone Pi Security. Native Pi is the supported execution surface. An unavailable capability produces a clear local error; it never silently invokes a removed integration.

## Development

Install Node dependencies, create an isolated Python environment, and install the declared test dependencies (`pytest`, `jsonschema`, and `referencing`). The development test runner uses the same `PI_SECURITY_PYTHON_COMMAND`, `PYTHON`, Pi runtime cache, and platform-default resolution order as production lifecycle tools.

macOS and Linux:

```sh
npm install
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-test.txt
export PYTHON="$PWD/.venv/bin/python"
npm run typecheck
npm run test:pack
npm test
```

Windows PowerShell:

```powershell
npm install
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-test.txt
$env:PYTHON = (Resolve-Path .venv\Scripts\python.exe).Path
npm run typecheck
npm run test:pack
npm test
```

`npm run test:pack` builds the native Pi extension bundle, verifies that it contains the permission-profile names, stable policy codes, and continuation-enforcement marker, creates actual npm `.tgz` archives for both publication roots, and inspects their tar entries against the runtime allowlist. The root archive must retain `packages/pi-security/package.json`, which scan completion reads for the producer version. Required assets and bundled `pi-subagents` metadata/agent files must be present, while Python bytecode, caches, databases, scan state, temporary files, evaluation inputs, tests, raw extension/source TypeScript, and Python test inputs must be absent. Runtime Python workbench scripts remain included. Archives and isolated npm caches are removed after inspection. `npm test` builds once, runs the Node contract suites (including both pack assertions), and then runs all Python workbench tests. The repository does not install Python test dependencies automatically.
