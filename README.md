# Pi Security

Pi Security is a local, agent-driven security scanner for [Pi](https://pi.dev). It helps Pi inspect a repository, validate potential vulnerabilities, and produce durable security artifacts without requiring a provider-specific security service, SDK, account, or hosted API.

It includes:

- Standard whole-repository security scans
- Git diff security reviews
- Native, multi-worker Deep Scans
- Bundled read-only security subagents
- Threat modeling and evidence-based finding validation
- Local scan history and finding storage
- Markdown reports and SARIF output
- Triage, feedback, export, and remediation workflows
- Target-bound permission profiles and fail-closed recovery

Analysis runs in the connected agent harness. Scan state, artifact validation, reports, and lifecycle operations remain deterministic local processes.

## Quick start with Pi

### 1. Install the package

Install directly from this repository:

```sh
pi install git:github.com/citizen-123/pi-security
```

After the package is published to npm, it can also be installed with:

```sh
pi install npm:pi-security
```

Pi loads the bundled subagent runtime and Pi Security extension automatically. No separate server configuration is required.

### 2. Open Pi in the repository you want to review

```sh
cd /path/to/your/repository
pi
```

### 3. Start a scan

Review the repository:

```text
/security-scan
```

Add an optional focus when you want the audit to prioritize a subsystem or threat:

```text
/security-scan authentication, session handling, and authorization boundaries
```

Review the current Git change set:

```text
/security-diff-scan
```

Or focus the diff review:

```text
/security-diff-scan untrusted input reaching command execution
```

Pi Security maps the target, builds a threat model, delegates non-overlapping read-only investigations, validates candidates independently, deduplicates findings, and produces the final local artifacts.

## Standalone CLI

Start the canonical full-repository workflow in the foreground:

```sh
pi-security scan --target /path/to/repository
pi-security scan --config /path/to/pi-security.toml
```

Inspect durable state or operate on an existing run:

```sh
pi-security run inspect <run-id>
pi-security run cancel <run-id>
pi-security run resume <run-id>
pi-security run retry <run-id>
```

`scan` owns the executor in its foreground process. Exit status is `0` for completed, `1` for failed, `2` for configuration or preflight failure, `75` for interrupted, and `130` for canceled. Ctrl-C uses the cancellation barrier; other handled termination reconciles the run as interrupted. Resume continues the same compatible interrupted run. Retry creates a new run linked to failed history.

## Scan modes

### Standard Scan

A repository-wide audit scheduled by the canonical runtime. It can be invoked from the current Pi session or the standalone `pi-security` CLI.

### Diff Scan

Reviews an exact Git change set and the supporting code needed to understand it. Use it before merging a branch or when reviewing a security-sensitive patch.

### Deep Scan

Runs isolated native Pi worker sessions with constrained source tools, durable continuations, bounded nested delegation, and schema-validated results. Start one with:

```text
/deep-security-scan
```

An optional focus uses the same slash-command syntax:

```text
/deep-security-scan authentication boundaries
```

## What gets written

Pi Security keeps its operational data local.

Default locations:

- Workbench database: `$PI_HOME/security/workbench.sqlite3`
- Deep Scan configuration: `$PI_HOME/pi-security/config.toml`
- Managed scan output: a private temporary directory unless `PI_SECURITY_SCAN_ROOT` is set

`PI_HOME` defaults to `~/.pi`.

A completed managed scan can contain:

- `scan-manifest.json` — sealed scan identity and artifact hashes
- `findings.json` — validated findings
- `coverage.json` — reviewed and deferred scope
- `report.md` — human-readable report
- SARIF output for compatible code-scanning tools

## Bundled security agents

The package includes four read-only agents:

- `pi-security-scout` — maps architecture, entry points, and trust boundaries
- `pi-security-auditor` — investigates assigned attack surfaces
- `pi-security-validator` — validates candidates and attack paths independently
- `pi-security-reviewer` — checks severity, coverage, consistency, and false positives

Standard and Diff scans can run these agents concurrently. The parent agent retains responsibility for source verification, synthesis, deduplication, and the final report.

## Permission model

Pi Security uses a capability sandbox rather than relying on prompt instructions alone:

- Scan agents may read and search only inside the bound target.
- Scan agents cannot write to the target, execute target code, or use network tools.
- Artifact writers can write only to the bound private scan directory and invoke fixed bundled workbench operations.
- Delegation is host-issued, bounded, and limited to read-only children.
- Paths are consumed through verified handles with traversal, symlink, reparse-point, and replacement checks.
- Continuations are revalidated before state changes, artifact writes, ownership claims, or model requests.

This is not a general-purpose OS process sandbox. Pi Security avoids running untrusted target commands altogether. If the host cannot apply a required enforcement mechanism, the operation fails instead of silently using weaker behavior.

## Configuration

Supported environment variables:

- `PI_HOME`
- `PI_SECURITY_STATE_DIR`
- `PI_SECURITY_SCAN_ROOT`
- `PI_SECURITY_DEEP_SCAN_CONFIG_PATH`
- `PI_SECURITY_PYTHON_COMMAND`
- `PI_SECURITY_SESSION_DB` for optional host-supplied token-usage attribution

Python resolution order:

1. `PI_SECURITY_PYTHON_COMMAND`
2. `PYTHON`
3. Pi's cached primary runtime, when executable
4. `python3` on Unix-like systems or `python` on Windows

Canonical configuration resolves in this order: built-in defaults, `$PI_HOME/pi-security/config.toml`, explicit `--config`, then non-secret CLI overrides. Role tables support `provider`, `model`, `thinking`, `instructions`, `max_attempts`, and one credential source:

```toml
[scan]
target = "/path/to/repository"
workflow = "full-repository"

[execution]
max_parallel = 4

[roles.default]
provider = "provider-id"
model = "model-id"
thinking = "medium"
max_attempts = 2
credential = { env = "PROVIDER_TOKEN" } # or { profile = "name" } / { value = "literal" }
```

There are no CLI secret flags. Credential values remain memory-only, are redacted from errors and child arguments, and are excluded from snapshots and execution digests. Prefer environment or profile sources over inline literals.

Optional Deep Scan configuration:

```toml
[deep_scan]
workers = 4
subagents = 0
stop_after_no_new = 2
stop_after_consecutive_errors = 3
max_discovery_runs = 12
max_time_hours = 4
```

## Requirements

- Node.js 22.19 or newer
- Python 3.11 or newer
- Git for Git-aware targets and Diff scans
- A Pi installation

## Development

The package implementation lives in [`packages/pi-security`](packages/pi-security). See its [detailed README](packages/pi-security/README.md) for development environment setup, test commands, direct workbench usage, native lifecycle behavior, schemas, packaging checks, and advanced configuration.

The short development flow is:

```sh
npm install
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r packages/pi-security/requirements-test.txt
npm run typecheck
npm test
```

Windows PowerShell setup is documented in the package README.

## License

Apache License 2.0. See [`packages/pi-security/LICENSE`](packages/pi-security/LICENSE).
