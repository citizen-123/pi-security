# Security Review: example/parity-repo

## Scope

The scan reviewed the canonical include paths and exclusions listed below.

- Scan mode: deep_repository
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
| Reportable DSS findings | 2 |
| Report instances | 3 |
| Report severity mix | high: 1, medium: 1, low: 1 |
| Report confidence mix | high: 3 |
| Coverage | complete |
| Validation mode | not recorded |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

No explicit canonical threat-model summary was recorded.

## Findings

| Findings | Reports | Severity | Confidence | Detailed write-up |
| --- | --- | --- | --- | --- |
| Copy without bounds check | [DSS-001-COPY-a](#finding-1)<br>[DSS-001-COPY-b](#finding-2) | high<br>medium | high | DSS-001-COPY-a: inline below<br>DSS-001-COPY-b: inline below |
| Session token from weak randomness | [DSS-002](#finding-3) | low | high | DSS-002: inline below |

### Confidence Scale

| Label | Meaning |
| --- | --- |
| high | Direct evidence supports the finding with no material unresolved blocker. |
| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |
| low | Evidence is incomplete and the item is retained only for explicit follow-up. |

<a id="finding-1"></a>

### [1] Copy without bounds check \[DSS-001-COPY-a\]

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | high |
| Confidence rationale | Direct source trace. |
| Category | memory |
| CWE | CWE-20 |
| Affected lines | src/buffer.c:77-79 |

#### Summary

Summary for Copy without bounds check \[DSS-001-COPY-a\].

#### Validation

Direct source trace. Validation details were not recorded separately.

#### Dataflow

The canonical finding records the affected path at src/buffer.c:77-79, but no expanded source-to-sink narrative was recorded.

#### Reachability

Reachability was not recorded beyond the canonical finding summary and affected locations.

#### Severity

**High** — The scan assigned high severity; no separate canonical severity rationale was recorded.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Fix copy without bounds check \[dss-001-copy-a\].

<a id="finding-2"></a>

### [2] Copy without bounds check \[DSS-001-COPY-b\]

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Direct source trace. |
| Category | memory |
| CWE | CWE-20 |
| Affected lines | src/buffer.c:77-79 |

#### Summary

Summary for Copy without bounds check \[DSS-001-COPY-a\].

#### Validation

Direct source trace. Validation details were not recorded separately.

#### Dataflow

The canonical finding records the affected path at src/buffer.c:77-79, but no expanded source-to-sink narrative was recorded.

#### Reachability

Reachability was not recorded beyond the canonical finding summary and affected locations.

#### Severity

**Medium** — The scan assigned medium severity; no separate canonical severity rationale was recorded.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Fix copy without bounds check \[dss-001-copy-a\].

<a id="finding-3"></a>

### [3] Session token from weak randomness

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Direct source trace. |
| Category | crypto |
| CWE | CWE-20 |
| Affected lines | src/session.js:8-10 |

#### Summary

Summary for Session token from weak randomness.

#### Validation

Direct source trace. Validation details were not recorded separately.

#### Dataflow

The canonical finding records the affected path at src/session.js:8-10, but no expanded source-to-sink narrative was recorded.

#### Reachability

Reachability was not recorded beyond the canonical finding summary and affected locations.

#### Severity

**Low** — The scan assigned low severity; no separate canonical severity rationale was recorded.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Fix session token from weak randomness.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| Request input | not recorded | Reported | No additional canonical notes were recorded. |
