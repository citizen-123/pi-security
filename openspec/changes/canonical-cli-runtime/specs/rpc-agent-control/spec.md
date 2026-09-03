## Purpose

Defines runtime ownership, isolation, identity, control, validation, and recovery behavior for phase-scoped Pi agent sessions driven through RPC.

## ADDED Requirements

### Requirement: Phase-scoped Pi RPC execution
The runtime SHALL launch model work in phase-scoped Pi RPC sessions. Each session SHALL receive an explicit phase input package and SHALL NOT own workflow scheduling or terminal run decisions.

#### Scenario: Launch phase session
- **WHEN** a model-executed phase becomes ready
- **THEN** the runtime starts a Pi RPC session with the phase identity, assigned role settings, target and artifact authority, required upstream inputs, and output contract

#### Scenario: Complete one phase
- **WHEN** a phase-scoped session finishes
- **THEN** later phases receive validated typed outputs and selected evidence references rather than depending on the completed session's private conversation state

### Requirement: Logical agent and attempt identities
The runtime SHALL assign stable logical agent identities independently of disposable Pi process and session identities. Every execution or replacement SHALL have a distinct attempt identity linked to its logical agent.

#### Scenario: Replace transport-failed attempt
- **WHEN** a replaceable provider or transport failure occurs within the phase's attempt policy
- **THEN** the runtime may launch a new Pi session under a new attempt identity while preserving the logical agent identity

#### Scenario: Non-replaceable failure
- **WHEN** an attempt fails because of policy denial, invalid authority, cancellation, or deterministic contract incompatibility
- **THEN** the runtime does not replace the attempt as though it were a transient provider failure

### Requirement: Runtime-mediated agent control
Status, transcript inspection, steering, follow-up, interruption, and stop operations SHALL be routed through the runtime. The runtime SHALL validate run ownership, target binding, phase state, and operator authority before sending a Pi RPC control operation.

#### Scenario: Steer active agent
- **WHEN** an authorized operator steers an active logical agent attempt
- **THEN** the runtime records the control request and forwards it to the bound Pi RPC session

#### Scenario: Reject foreign session control
- **WHEN** a control request names a session or logical agent outside the caller's run, target, or authority
- **THEN** the runtime rejects the request before sending any RPC operation

#### Scenario: User steering affects provenance
- **WHEN** an operator supplies steering or follow-up content during a run
- **THEN** the run records that intervention and does not claim its result was determined solely by the original configuration

### Requirement: Phase output validation
The runtime SHALL validate structured phase output before admitting it to canonical state or downstream inputs. Free-form completion text, process exit success, or an RPC completion event alone SHALL NOT satisfy a phase contract.

#### Scenario: Malformed structured result
- **WHEN** a Pi session exits successfully but returns a result that fails the phase output schema
- **THEN** the runtime records the failed attempt and follows the bounded phase attempt policy without publishing the malformed result

#### Scenario: Valid result admitted once
- **WHEN** an attempt returns a valid phase result
- **THEN** the runtime admits that result once under its phase and attempt identity and ignores duplicate completion delivery

### Requirement: Exact authority on recovery
An interrupted active session SHALL be reattached or replaced only when the runtime validates the persisted run, logical agent, role, target, scan artifact root, capability profile, and delegation constraints against newly issued host authority.

#### Scenario: Compatible session reattachment
- **WHEN** an interrupted run is explicitly resumed and its Pi session remains available under exactly compatible authority and identity
- **THEN** the runtime may reattach to that session and continue the same attempt

#### Scenario: Authority mismatch on resume
- **WHEN** target, artifact root, capability profile, delegation limits, or run ownership differs from the persisted attempt
- **THEN** the runtime rejects reattachment before agent execution or artifact mutation

### Requirement: Runtime-enforced capability ceiling
The phase type SHALL set the maximum target, artifact, tool, execution, mutation, and delegation capabilities for every Pi session. Model output, repository content, role configuration, and front-end input SHALL NOT grant additional authority.

#### Scenario: Agent requests unavailable capability
- **WHEN** an agent requests a tool or operation outside its phase-issued capability profile
- **THEN** the runtime denies the operation and records the policy result without substituting an unguarded tool
