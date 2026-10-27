## Purpose

Defines the public CLI, configuration, and Pi extension for v0.2.

## ADDED Requirements

### Requirement: CLI commands
The CLI SHALL provide:

- `scan [target] [--mode standard|diff|deep] [--base REV] [--head REV] [--config FILE] [--provider ID] [--model ID] [--thinking LEVEL] [--max-parallel N] [--detach] [--json]`
- `run list|inspect|watch|cancel|resume|retry-task <run-id> [task-id]`
- `findings list|show|export [--run ID] [--format json|csv|sarif]`
- `triage <finding-id> --status STATUS [--reason TEXT]`
- `fix <finding-id> [--base REV]`
- `verify <fix-run-id>`

Exit codes SHALL be 0 completed, 1 failed, 2 usage or configuration error, 75 interrupted, 130 canceled.

#### Scenario: Help
- **WHEN** `pi-security --help` runs
- **THEN** every command above is listed with its flags

### Requirement: Configuration
Configuration SHALL resolve as built-in defaults, then `$PI_HOME/pi-security/config.toml`, then `--config`, then CLI flags. Sections: `[scan]`, `[execution]`, `[roles.<id>]`, `[deep_scan]`, `[remediation.checks]`. Inline credential values SHALL be rejected.

#### Scenario: Inline credential
- **WHEN** a config file contains `credential = { value = "..." }`
- **THEN** configuration fails with exit code 2 and the value is not echoed

### Requirement: Thin Pi extension
The Pi extension SHALL expose `security_scan`, `security_run`, `security_cancel`, `security_findings`, `security_triage`, and `security_fix`, and SHALL run no scan work in the Pi process.

#### Scenario: Start a scan from Pi
- **WHEN** the model calls `security_scan`
- **THEN** a detached CLI process owns the run and the tool returns its run ID
