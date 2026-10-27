## Purpose

Defines how every Pi Security run executes on pi-durable: run identity, ownership, the orchestrator and worker task model, resume, cancellation, stall detection, run limits, crash-loop handling, and progress observation.

## ADDED Requirements

### Requirement: One Harness per run
Each run SHALL have its own directory containing an exclusive writer lock and one pi-durable SQLite storage. A process SHALL acquire the lock before opening the storage for writing and SHALL release it only after the Harness has closed.

#### Scenario: Second writer refused
- **WHEN** a process tries to resume a run whose lock is held by a live process
- **THEN** it exits with a usage error naming the holder and does not open the storage for writing

#### Scenario: Holder died
- **WHEN** the process holding a run's lock was killed
- **THEN** the lock is free, with no stale state to break, and the run resumes

### Requirement: Orchestrator task owns progression
Run progression SHALL be decided only by the run's orchestrator task (`security.scan`, `security.fix`, or `security.verify`). Model output SHALL reach run state only through a role's report tool, and the orchestrator SHALL validate every admitted result against its schema.

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
- **THEN** a new worker starts as soon as any running worker settles, and at most `max_parallel` workers are live at any time

#### Scenario: Idempotent run creation
- **WHEN** the process dies before or after the commit that creates the orchestrator, and the run is started or resumed again
- **THEN** exactly one orchestrator exists for the run

### Requirement: Cancellation
Cancelling a run SHALL abort the orchestrator, aborting its workers bottom-up, and SHALL end the run `canceled` without claiming complete coverage.

#### Scenario: Cancel from a viewer
- **WHEN** a read-only viewer requests cancellation of a run owned by another process
- **THEN** the owning process aborts the orchestrator and the run ends `canceled` with admitted findings preserved as incomplete coverage

### Requirement: Stall detection
A worker with no progress for `stall_timeout` SHALL be aborted and re-created once. A second stall SHALL be a worker failure under that phase's failure policy. Streaming model output and tool output SHALL count as progress.

#### Scenario: Hung provider stream
- **WHEN** a worker's model request produces nothing for longer than `stall_timeout`
- **THEN** the worker is aborted and a replacement worker starts with the same packet

#### Scenario: Long but active worker
- **WHEN** a worker keeps streaming output for longer than `stall_timeout`
- **THEN** it is not aborted

### Requirement: Optional run limits
Runs SHALL have no wall-clock limit by default. When `max_duration` or `max_cost` is configured and exceeded, the run SHALL end `interrupted` with reason `duration_limit` or `cost_limit`, keep admitted evidence, and mark coverage incomplete.

#### Scenario: Cost limit
- **WHEN** a run's summed usage cost exceeds `max_cost`
- **THEN** the orchestrator is aborted and the run ends `interrupted` with reason `cost_limit`

### Requirement: Read-only observation
Viewers SHALL observe a run without opening its storage for writing and without acquiring the writer lock. (The mechanism is an open question in design D11: pi-durable 1.4.0 has no read-only open.)

#### Scenario: Watch a running scan
- **WHEN** `pi-security run watch` attaches to a running scan
- **THEN** it renders the live task graph and phase progress without acquiring the writer lock
