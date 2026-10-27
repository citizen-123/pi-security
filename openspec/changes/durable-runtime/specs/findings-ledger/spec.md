## Purpose

Defines cross-run finding identity, triage, remediation linkage, and exports.

## ADDED Requirements

### Requirement: Stable finding identity
Finding fingerprints SHALL be computed by the TypeScript port of the current fingerprint algorithm and SHALL equal the Python output for the same inputs.

#### Scenario: Parity
- **WHEN** the parity suite runs the Python and TypeScript implementations on the same fixture findings
- **THEN** every fingerprint is identical

### Requirement: Idempotent publication
Publishing a run into the ledger SHALL be idempotent per run.

#### Scenario: Crash after publication
- **WHEN** the process dies after writing the ledger but before the orchestrator commits its outcome, and the run is resumed
- **THEN** the ledger contains each occurrence exactly once

### Requirement: Concurrent publishers
Separate processes SHALL be able to publish runs into the ledger concurrently without lost or duplicated writes.

#### Scenario: Two scans finish together
- **WHEN** two runs publish at the same time
- **THEN** both runs' occurrences are present and shared findings have one identity row

### Requirement: Triage history
Triage changes SHALL be appended as events with status, reason, author, and time, and the current status SHALL be the latest event.

#### Scenario: Reopen
- **WHEN** a finding marked `false_positive` is set back to `open`
- **THEN** both events remain in history and the current status is `open`

### Requirement: Exports
The CLI SHALL export ledger or run findings as JSON, CSV, or SARIF 2.1.0, matching the current output formats.

#### Scenario: SARIF export
- **WHEN** a run's findings are exported as SARIF
- **THEN** the document validates against the SARIF 2.1.0 schema and matches the Python output for the same findings
