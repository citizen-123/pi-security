# Security Review: example/parity-repo

## Scope

The scan reviewed the canonical include paths and exclusions listed below.

- Scan mode: repository
- Target kind: git_worktree
- Target ID: target_sha256_parity
- Revision: deadbeef
- Snapshot digest: pi-security-snapshot/v1:sha256:0000000000000000000000000000000000000000000000000000000000000000
- Inventory strategy: repository
- Included paths: src/
- Excluded paths: none
- Runtime or test status: not recorded

### Scan Summary

| Field | Value |
| --- | --- |
| Scan outcome | completed |
| Reportable findings | 1 |
| Severity mix | high: 1 |
| Confidence mix | high: 1 |
| Coverage | complete |
| Validation mode | not recorded |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

No explicit canonical threat-model summary was recorded.

## Findings

| Finding | Severity | Confidence | Detailed write-up |
| --- | --- | --- | --- |
| [Unsafe archive extraction](#finding-1) | high | high | inline below |

### Confidence Scale

| Label | Meaning |
| --- | --- |
| high | Direct evidence supports the finding with no material unresolved blocker. |
| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |
| low | Evidence is incomplete and the item is retained only for explicit follow-up. |

<a id="finding-1"></a>

### [1] Unsafe archive extraction

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | high |
| Confidence rationale | Direct source trace. |
| Category | path-traversal |
| CWE | CWE-20 |
| Affected lines | src/extract.py:41-43 |

#### Summary

Summary for Unsafe archive extraction.

#### Validation

Direct source trace. Validation details were not recorded separately.

#### Dataflow

The canonical finding records the affected path at src/extract.py:41-43, but no expanded source-to-sink narrative was recorded.

#### Reachability

Reachability was not recorded beyond the canonical finding summary and affected locations.

#### Severity

**High** — The scan assigned high severity; no separate canonical severity rationale was recorded.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Fix unsafe archive extraction.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| Request input | not recorded | Reported | No additional canonical notes were recorded. |
