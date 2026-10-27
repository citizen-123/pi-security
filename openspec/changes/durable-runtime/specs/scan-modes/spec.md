## Purpose

Defines Standard, Diff, and Deep scans as modes of one orchestrator.

## ADDED Requirements

### Requirement: Shared phase pipeline
All scan modes SHALL run `preflight, inventory, threatModel, plan, discover, reduce, validate, attackPath, report, publish`. Modes SHALL differ only in inventory scope and in how `plan` and `discover` iterate.

#### Scenario: Standard scan
- **WHEN** a Standard scan runs
- **THEN** the inventory covers the full target, `plan` produces one packet per focus area, and discovery runs one round

### Requirement: Diff scope
A Diff scan SHALL bind its scope to a base and head revision resolved to commit IDs at preflight. Discovery packets SHALL cover changed files and their direct dependents. The scope SHALL NOT change after preflight.

#### Scenario: Base moves during a scan
- **WHEN** the base branch advances while a Diff scan is running
- **THEN** the scan keeps the commit IDs resolved at preflight

### Requirement: Working-tree Diff snapshot
A Diff scan given a base without a head SHALL snapshot the working tree (tracked changes plus untracked, non-ignored files) into a commit object at preflight, using a temporary index, and SHALL scan that commit. The user's index, branch, stash, and files SHALL NOT change.

#### Scenario: Edits during a working-tree scan
- **WHEN** the user edits files while a working-tree Diff scan runs
- **THEN** the scan's scope remains the snapshot taken at preflight

#### Scenario: User state untouched
- **WHEN** a working-tree Diff scan starts
- **THEN** `git status`, the index, and `git stash list` are identical before and after preflight

### Requirement: Deep saturation
A Deep scan SHALL repeat `plan` and `discover` rounds over (focus area × lens) packets. The reducer SHALL merge each round into the candidate set. The scan SHALL stop discovering when `stop_after_no_new` consecutive rounds admit no new candidate, when `max_discovery_rounds` (default 8) is reached, or when a run limit ends the run. The stop reason SHALL be recorded in coverage.

#### Scenario: Saturation
- **WHEN** two consecutive rounds admit no new candidates and `stop_after_no_new = 2`
- **THEN** discovery stops with reason `saturated` and the run proceeds to validation

#### Scenario: Round cap
- **WHEN** `max_discovery_rounds` rounds have run without saturation
- **THEN** discovery stops with reason `capped` and coverage records that saturation was not reached

### Requirement: Reducer provenance
Every reduced finding SHALL list the source candidate IDs it merges, and every admitted candidate SHALL be accounted for exactly once as merged, kept, or rejected with a reason.

#### Scenario: Unaccounted candidate
- **WHEN** a reducer result omits an admitted candidate
- **THEN** the result is rejected as schema-invalid
