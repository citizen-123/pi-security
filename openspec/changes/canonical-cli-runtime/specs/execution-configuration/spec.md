## Purpose

Defines deterministic TOML execution configuration, role-specific model settings, source provenance, sanitized persistence, and supported credential forms.

## ADDED Requirements

### Requirement: Deterministic configuration resolution
The CLI SHALL resolve execution settings from built-in defaults, ambient user configuration, an explicitly referenced TOML configuration, and supported CLI overrides in documented precedence order. Every CLI override SHALL map to the same semantic field used by configuration files.

#### Scenario: Explicit configuration overrides ambient settings
- **WHEN** the same ordinary execution field is set by ambient and explicitly referenced configuration
- **THEN** the explicitly referenced value is selected and its source is recorded as explicit configuration

#### Scenario: CLI overrides a non-secret field
- **WHEN** a supported non-secret CLI option and configuration file set the same field
- **THEN** the CLI value is selected and persisted at the corresponding resolved configuration path

#### Scenario: Invalid configuration
- **WHEN** configuration contains an invalid value, unknown required reference, or unsupported combination
- **THEN** the CLI reports the relevant configuration path and does not start agent execution

### Requirement: Configured execution roles
The execution configuration SHALL support named roles with provider, model, thinking-level, and credential-source settings. The built-in workflow SHALL bind model-executed phases to named roles while phase types retain authority over tools, target access, and required outputs.

#### Scenario: Different roles use different models
- **WHEN** the threat-model and validation phases reference roles with different valid provider or model settings
- **THEN** the runtime launches each phase session with its assigned resolved role settings

#### Scenario: Role cannot escalate phase permissions
- **WHEN** role instructions or role configuration request a tool or mutation capability not permitted by the phase type
- **THEN** the runtime denies that capability and does not expand the phase's execution authority

### Requirement: Immutable execution snapshot
Before agent execution, the runtime SHALL persist a sanitized snapshot containing the resolved workflow, role identities and non-secret settings, target identity, configuration provenance, phase contracts, and policy identities. Resume SHALL use this snapshot rather than re-resolving current execution settings.

#### Scenario: Configuration changes after start
- **WHEN** ambient or explicit configuration changes after a run starts
- **THEN** the running or resumed run continues under its persisted execution snapshot

#### Scenario: Execution-significant override during resume
- **WHEN** an operator attempts to resume with a different workflow, role, provider, model, thinking level, target revision, or policy
- **THEN** the runtime rejects in-place resume and requires a new linked run

### Requirement: Supported credential sources
A role credential SHALL support a named credential reference, an environment-variable reference, or a literal value in configuration. Credential fields SHALL NOT be accepted as command-line arguments.

#### Scenario: Credential profile resolves
- **WHEN** a configured credential profile is available to the executor
- **THEN** the runtime supplies that credential to the assigned Pi session without copying its value into the execution snapshot

#### Scenario: Inline credential executes locally
- **WHEN** a local execution config contains a literal credential
- **THEN** the executor may use the literal for its Pi session while all persisted and displayed configuration substitutes a redacted credential descriptor

#### Scenario: Missing credential on resume
- **WHEN** an interrupted run is explicitly resumed but its credential source is no longer available
- **THEN** the runtime leaves the run interrupted and reports a non-secret credential-resolution error

### Requirement: Credential confidentiality
Credential values SHALL NOT be persisted in relational state, events, reports, artifacts, diagnostics, process arguments, configuration displays, or model prompts. Errors and activity records SHALL redact known credential values before crossing the executor boundary.

#### Scenario: Inspect run configured with literal credential
- **WHEN** an operator inspects a run that used an inline credential
- **THEN** the inspection identifies the credential source as inline without revealing the value

#### Scenario: Provider or tool echoes a credential
- **WHEN** a provider response, tool argument, tool result, or error contains a known credential value
- **THEN** durable activity output and user-facing diagnostics redact that value

### Requirement: Explicit configuration remains external
The runtime SHALL NOT rewrite, copy into scan artifacts, or persist the complete contents of an explicitly referenced configuration file. Configuration identity and integrity metadata SHALL be derived from a sanitized representation that excludes credential material.

#### Scenario: Persist configured run
- **WHEN** a run starts from an explicitly referenced config containing a literal credential
- **THEN** the state contains the sanitized resolved execution snapshot and no copy or hash of the individual secret
