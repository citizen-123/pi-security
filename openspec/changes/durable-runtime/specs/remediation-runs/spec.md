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

### Requirement: Verification
A verify run SHALL Diff-scan the fix branch against its base and re-validate the original finding. Its outcome SHALL update the finding's remediation status in the ledger to `verified`, `not_fixed`, or `regressed`.

#### Scenario: Fix introduces a new finding
- **WHEN** the Diff scan of a fix branch reports a new finding
- **THEN** the remediation status is `regressed` and the new finding is linked to the fix run
