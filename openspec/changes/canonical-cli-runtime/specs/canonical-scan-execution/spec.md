## Purpose

Defines the standalone, runtime-owned full-repository scan lifecycle and the durable outcomes operators can inspect, cancel, resume, or retry.

## ADDED Requirements

### Requirement: Standalone full-repository scan
Pi Security SHALL expose a standalone CLI that starts one built-in full-repository security workflow without requiring an interactive Pi session. The canonical runtime SHALL determine phase scheduling and completion; agent messages and front-end adapters SHALL NOT independently advance the workflow.

#### Scenario: Complete configured scan
- **WHEN** an operator starts the built-in full-repository workflow with a valid target and execution configuration
- **THEN** the runtime executes preflight, threat modeling, discovery, reduction, validation, attack-path analysis, reporting, and publication under one durable run identity

#### Scenario: Existing Pi entry points remain available
- **WHEN** this change is installed as a Pi package
- **THEN** the existing standard, diff, and deep skill entry points remain available while uncovered behavior continues through its existing implementation

### Requirement: Typed phase lifecycle
The runtime SHALL persist the resolved built-in workflow and SHALL track every phase instance through explicit lifecycle states. A phase SHALL be completed only after its output satisfies the registered phase contract.

#### Scenario: Valid phase output
- **WHEN** a phase execution returns output satisfying its required schema and completion conditions
- **THEN** the runtime atomically records the validated output and completes the phase

#### Scenario: Invalid phase output
- **WHEN** a phase execution reports success but its required output is missing or invalid
- **THEN** the runtime does not complete the phase and applies the phase's bounded attempt policy

### Requirement: Honest terminal outcomes
A run SHALL terminate as completed, failed, canceled, or interrupted. Only a completed run SHALL support a complete coverage conclusion; every other terminal or suspended outcome SHALL retain admissible evidence while representing coverage as incomplete or inconclusive.

#### Scenario: Completed coverage
- **WHEN** every required workflow phase completes and publication succeeds
- **THEN** the run is completed and may publish the workflow's validated coverage conclusion

#### Scenario: Stopped scan retains evidence
- **WHEN** a run fails, is canceled, or is interrupted after recording admissible findings or coverage evidence
- **THEN** the evidence remains inspectable and the runtime does not present absence of additional findings as a completed security conclusion

### Requirement: Durable cancellation
The runtime SHALL stop admitting new work, abort active agent attempts, wait for their settlement, persist admissible final state, and freeze canonical output acceptance before marking a run canceled.

#### Scenario: Operator cancels an active run
- **WHEN** an authorized operator cancels a running scan
- **THEN** the runtime performs the cancellation barrier and records a terminal canceled outcome

#### Scenario: Late output after cancellation
- **WHEN** an agent emits output after the run's cancellation freeze boundary
- **THEN** that output cannot change canonical phase, finding, coverage, or run state

### Requirement: Explicit inspection and resume
The CLI SHALL allow operators to inspect durable run state without a live Pi session. An interrupted run SHALL resume only through an explicit command after the runtime validates persisted execution identity, authority, target state, and reusable outputs.

#### Scenario: Resume compatible interrupted run
- **WHEN** an operator explicitly resumes an interrupted run whose persisted workflow, authority, target, policy, and validated outputs remain compatible
- **THEN** one controller claims the same run and continues from the first unsatisfied phase without rerunning compatible completed phases

#### Scenario: Reject terminal resume
- **WHEN** an operator attempts to resume a completed, failed, or canceled run
- **THEN** the runtime rejects the request without changing that run's history

#### Scenario: Inspect without active executor
- **WHEN** an operator inspects a completed, failed, canceled, or interrupted run with no active executor
- **THEN** the CLI reports its persisted phases, progress, outputs, and terminal or suspension reason

### Requirement: Linked retry after failure
Retrying a failed run SHALL create a new run linked to the failed run. The runtime SHALL NOT mutate a failed run back into a nonterminal state, and reused immutable outputs SHALL retain explicit source provenance.

#### Scenario: Retry failed run
- **WHEN** an operator retries a failed run
- **THEN** the runtime creates a new run with a link to the failed run and leaves the failed run unchanged

#### Scenario: Reuse compatible output
- **WHEN** a new linked run can reuse a prior immutable phase output with matching phase type, version, inputs, target, and policy constraints
- **THEN** the runtime validates the output and records an explicit reuse relationship before satisfying the new phase
