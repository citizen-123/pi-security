## Purpose

Defines durable fix and verify runs.

## ADDED Requirements

### Requirement: Isolated worktree
A fix run SHALL work only in a git worktree on a new branch under its run directory. It SHALL NOT modify the user's working tree, index, or current branch.

#### Scenario: Fix run completes
- **WHEN** a fix run finishes
- **THEN** the user's checkout is unchanged, the fix branch holds one commit, and `fix.patch` is written to the run directory

#### Scenario: Resume after crash during prepare
- **WHEN** the process dies after creating the worktree and the run is resumed
- **THEN** the existing worktree and branch are reused, not recreated

### Requirement: Allowlisted checks
A fixer SHALL execute commands only by naming a check configured in `[remediation.checks]`. Checks SHALL run as argv without a shell, in the worktree, with a scrubbed environment.

#### Scenario: Unknown check
- **WHEN** the fixer requests a check that is not configured
- **THEN** the tool returns an error and nothing is executed

#### Scenario: No checks configured
- **WHEN** no checks are configured
- **THEN** the fixer has no execution tool and the fix is recorded as `untested`

### Requirement: Verification inside the fix run
A fix run SHALL verify its own fix before finishing, unless started with `--no-verify`. Verification SHALL Diff-scan the fix commit against its base and re-validate the original finding. The verdict SHALL be `verified`, `not_fixed`, or `regressed`, or `unverified` when verification was skipped, and SHALL be recorded in the ledger with the fix.

#### Scenario: Fix introduces a new finding
- **WHEN** the Diff scan of a fix commit reports a new finding
- **THEN** the verdict is `regressed` and the new finding is linked to the fix run

#### Scenario: Skipped verification
- **WHEN** a fix run is started with `--no-verify`
- **THEN** it finishes with verdict `unverified` and no Diff scan runs

### Requirement: Re-verification
`pi-security verify <fix-run-id>` SHALL start a separate run with the same verification phases and SHALL append its verdict to the finding's remediation history.

#### Scenario: Re-verify after the base moves
- **WHEN** a user re-verifies an older fix run
- **THEN** a new verdict is recorded and the earlier verdict stays in history

### Requirement: Independent concurrent fixes
Fix runs SHALL be independent, so users can run any number of them, sequentially or in parallel, including several runs for the same finding.

#### Scenario: Two fixes for one finding
- **WHEN** two fix runs for the same finding run at the same time
- **THEN** each has its own worktree and a distinct branch, and both verdicts are recorded
