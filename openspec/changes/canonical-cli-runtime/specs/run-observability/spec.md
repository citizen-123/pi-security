## Purpose

Defines durable ordered execution events, complete action records, reconnectable progress, and informative terminal rendering for canonical workflow runs.

## ADDED Requirements

### Requirement: Relational state remains authoritative
Canonical run, phase, finding, coverage, and policy state SHALL remain in transactional relational records. Events SHALL describe committed transitions and activity but SHALL NOT be the sole source required to reconstruct correctness-critical state.

#### Scenario: Read current state
- **WHEN** a client inspects a run after reconnecting or after executor loss
- **THEN** it obtains canonical lifecycle and result state from the relational records without replaying every activity event

### Requirement: Ordered domain event journal
Every run SHALL have an append-only domain event journal with a monotonically increasing sequence unique within that run. A canonical state transition and its corresponding domain event SHALL commit atomically.

#### Scenario: Commit phase completion
- **WHEN** a validated phase output is committed
- **THEN** the phase state change and its ordered completion event become visible together

#### Scenario: Reconnect after sequence
- **WHEN** a client requests run events after a previously observed sequence
- **THEN** the runtime returns committed later events in canonical sequence order without requiring timestamp-based ordering

### Requirement: Meaningful activity records
The runtime SHALL record meaningful agent, attempt, tool, usage, and operator-control actions with correlation to their run and phase. Transient presentation deltas SHALL NOT be required in the durable domain journal.

#### Scenario: Tool call lifecycle
- **WHEN** a phase agent starts and finishes or fails a tool call
- **THEN** activity records identify the correlated phase, logical agent, attempt, tool action, outcome, and available duration

#### Scenario: Agent attempt replacement
- **WHEN** a logical agent receives multiple execution attempts
- **THEN** activity records preserve each attempt and its terminal reason under the same logical agent identity

### Requirement: Observable progress
The runtime SHALL maintain progress snapshots derived from committed workflow state and events. The foreground CLI SHALL display the active phase, completed and pending phases, active logical agents, meaningful work counts when available, and terminal outcome instead of a generic working indicator.

#### Scenario: Multi-worker discovery progress
- **WHEN** discovery workers are active concurrently
- **THEN** the CLI identifies the discovery phase and reports worker states and available completed-versus-total work counts

#### Scenario: Incomplete progress data
- **WHEN** a phase cannot supply a meaningful total or usage count
- **THEN** the CLI reports that value as unavailable rather than zero or an invented estimate

### Requirement: Observation cannot block execution
Optional rendering, progress delivery, and future telemetry consumers SHALL NOT participate in the correctness-critical transaction after events are committed. Their failure SHALL NOT fail or roll back the scan.

#### Scenario: Renderer disconnects
- **WHEN** the terminal renderer disconnects after the runtime commits an event
- **THEN** the workflow continues and a later client can recover current state and missed events

#### Scenario: Activity sink fails
- **WHEN** an optional activity sink cannot accept an event
- **THEN** canonical run execution continues and the sink failure is reported independently without changing the domain transition

### Requirement: Sensitive data is excluded from observations
Domain events, activity records, progress snapshots, and terminal rendering SHALL exclude credentials, continuation tokens, action claims, and private authority material. Tool and provider activity SHALL be sanitized before durable or user-facing publication.

#### Scenario: Event payload contains known secret
- **WHEN** an activity payload contains a known credential or opaque control token
- **THEN** the stored and rendered payload redacts the secret while preserving non-secret action identity and outcome

### Requirement: Versioned event contracts
Durable event envelopes SHALL include a schema version, run identity, run-local sequence, timestamp, event kind, source, and correlation identifiers applicable to the event. Consumers SHALL reject unsupported required semantics rather than silently misinterpreting them.

#### Scenario: Consume supported event version
- **WHEN** a CLI client reads an event version it supports
- **THEN** it can order and correlate the event using the envelope independently of event-specific payload fields

#### Scenario: Consume unsupported event version
- **WHEN** a client encounters an event whose required envelope semantics it does not support
- **THEN** it reports the compatibility error and does not present the event as successfully interpreted
