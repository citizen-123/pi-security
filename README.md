# Pi Security

Pi Security is a local, agent-driven security scanner for [Pi](https://pi.dev) and MCP-compatible clients. It helps an AI coding agent inspect a repository, validate potential vulnerabilities, and produce durable security artifacts without requiring a provider-specific security service, CLI, SDK, account, or API key.

It includes:

- Standard whole-repository security scans
- Git diff security reviews
- Tool-enabled, multi-worker Deep Scans over MCP
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

Pi loads the bundled subagent runtime and Pi Security extension automatically. You do not need to configure the MCP server for Standard or Diff scans.

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

## Scan modes

### Standard Scan

A repository-wide audit driven by the current Pi session. Use it for a new codebase, a broad security review, or investigation of a specific attack surface.

### Diff Scan

Reviews an exact Git change set and the supporting code needed to understand it. Use it before merging a branch or when reviewing a security-sensitive patch.

### Deep Scan

Runs server-owned sampling workers with constrained source tools, durable continuations, bounded nested delegation, and schema-validated results. Deep Scan requires an MCP client that advertises MCP 2025-11-25 `sampling.tools`; basic MCP sampling is not sufficient.

Deep Scan is available through the optional stdio MCP server described below. Standard and Diff scans do not require MCP sampling.

## What gets written

Pi Security keeps its operational data local.

Default locations:

- Workbench database: `$PI_HOME/security/workbench.sqlite3`
- Deep Scan configuration: `$PI_HOME/pi-security/config.toml`
- MCP scan output: a private temporary directory unless `PI_SECURITY_SCAN_ROOT` is set

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

## Optional MCP server

Use the stdio server with a generic MCP host or for Deep Scan.

### Build and run

```sh
npm install
npm run build
pi-security-mcp
```

Example client configuration:

```json
{
  "mcpServers": {
    "pi-security": {
      "command": "pi-security-mcp",
      "env": {
        "PI_SECURITY_STATE_DIR": "/absolute/path/to/private/state",
        "PI_SECURITY_SCAN_ROOT": "/absolute/path/to/private/scans"
      }
    }
  }
}
```

The server exposes target inspection, Standard/Diff/Deep scan lifecycle operations, progress, artifact recording, completion and recovery, finding queries, exports, triage, remediation, feedback, and compact worker/reducer operations.

An MCP host that can call server tools does not necessarily support Deep Scan. It must also accept server-initiated, tool-enabled sampling requests.

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

- Node.js 20 or newer
- Python 3.11 or newer
- Git for Git-aware targets and Diff scans
- A Pi installation for the native commands, or an MCP-compatible host for the stdio server

## Development

The package implementation lives in [`packages/pi-security`](packages/pi-security). See its [detailed README](packages/pi-security/README.md) for development environment setup, test commands, direct workbench usage, transport behavior, schemas, packaging checks, and advanced configuration.

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
