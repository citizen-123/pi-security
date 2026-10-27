## Purpose

Defines how every Pi Security run executes on pi-durable: run identity, ownership, the orchestrator and worker task model, resume, cancellation, deadlines, crash-loop handling, and progress observation.

## ADDED Requirements

### Requirement: One Harness per run
Each run SHALL have its own directory containing an exclusive writer lock and one pi-durable SQLite storage. A process SHALL acquire the lock before opening the storage for writing and SHALL release it only after the Harness has closed.

#### Scenario: Second writer refused
- **WHEN** a process tries to resume a run whose lock is held by a live process
- **THEN** it exits with a usage error naming the holder and does not open the storage for writing

#### Scenario: Stale lock on the same host
- **WHEN** the lock names a process ID on the same host that no longer exists
- **THEN** the lock is replaced and the run resumes

### Requirement: Orchestrator task owns progression
Run progression SHALL be decided only by the `security.scan`, `security.fix`, or `security.verify` orchestrator task. Model output SHALL reach run state only through a role's report tool, and the orchestrator SHALL validate every admitted result against its schema.

#### Scenario: Invalid worker result
- **WHEN** a worker's conversation ends without a schema-valid result document
- **THEN** the worker task fails and the orchestrator applies that phase's failure policy

### Requirement: Crash-safe resume
After a process dies, reopening a run SHALL continue from the last committed checkpoint without repeating completed worker tasks or duplicating admitted results.

#### Scenario: Crash during discovery
- **WHEN** the process is killed while discovery workers are running and the run is resumed
- **THEN** completed workers are not rerun, running workers resume their existing conversations, and the final outputs equal those of an uninterrupted run with the same faux model responses

#### Scenario: Crash loop
- **WHEN** a task is cut off by restarts `restartLimit` times without new progress
- **THEN** the task is parked, `run inspect` shows it as blocked, and `run retry-task` can run it again

### Requirement: Bounded fan-out
The orchestrator SHALL NOT have more than `max_parallel` worker tasks live at once.

#### Scenario: Large packet set
- **WHEN** discovery has more packets than `max_parallel`
- **THEN** workers are created in successive waves of at most `max_parallel`

### Requirement: Cancellation and deadline
Cancelling a run SHALL abort the orchestrator, aborting its workers bottom-up, and SHALL end the run `canceled`. A configured deadline SHALL end the run `interrupted` with reason `deadline`. Neither outcome SHALL claim complete coverage.

#### Scenario: Cancel from a viewer
- **WHEN** a read-only viewer requests cancellation of a run owned by another process
- **THEN** the owning process aborts the orchestrator and the run ends `canceled` with admitted findings preserved as incomplete coverage

### Requirement: Read-only observation
Viewers SHALL observe a run by opening its storage read-only and SHALL NOT be able to write to it.

#### Scenario: Watch a running scan
- **WHEN** `pi-security run watch` attaches to a running scan
- **THEN** it renders the live task graph and phase progress without acquiring the writer lock
