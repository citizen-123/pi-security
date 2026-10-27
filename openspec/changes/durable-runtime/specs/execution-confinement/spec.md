## Purpose

Defines what agents in a run can read, write, and execute, and how credentials and stored transcripts are protected.

## ADDED Requirements

### Requirement: Confined environment
Every tool in a run SHALL reach files only through the run's confined environment. It SHALL accept only repository-relative paths, SHALL refuse absolute paths, `..` segments, and symlinks at any component, and SHALL verify the identity of each opened file descriptor.

#### Scenario: Symlink escape
- **WHEN** a worker reads a target path that is a symlink to a file outside the target
- **THEN** the read fails with a policy error and no content is returned

### Requirement: Closed role tool sets
Each role SHALL have a fixed tool list set when its conversation is created. Scan roles SHALL NOT receive write, edit, or shell tools. The orchestrator SHALL refuse a worker result if the worker's resolved tools differ from its role's list.

#### Scenario: Drifted configuration
- **WHEN** a worker conversation's resolved agent includes a tool outside its role's list
- **THEN** its result is refused and the worker fails with a policy error

### Requirement: Credential isolation
Credential values SHALL NOT be written to run storage, the ledger, scan outputs, logs, process arguments, or child process environments. Executed commands SHALL start from an empty environment plus an explicit minimal set.

#### Scenario: Provider echoes the key in an error
- **WHEN** a provider rejects a request with an error body containing the API key
- **THEN** the stored error contains `[REDACTED]` in place of the key and no run storage file contains the key

#### Scenario: Provider key in the parent environment
- **WHEN** `OPENAI_API_KEY` is set in the CLI's environment and a fix run executes an allowlisted check
- **THEN** the check's environment does not contain `OPENAI_API_KEY`

### Requirement: Stored data permissions
Run directories SHALL be created with mode `0700` and their files with mode `0600` on POSIX systems.

#### Scenario: New run
- **WHEN** a run directory is created
- **THEN** other users cannot read its storage or outputs
