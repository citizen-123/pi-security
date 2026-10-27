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
| Reportable findings | 4 |
| Severity mix | critical: 1, high: 1, medium: 1, low: 1 |
| Confidence mix | high: 4 |
| Coverage | complete |
| Validation mode | not recorded |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

No explicit canonical threat-model summary was recorded.

## Findings

| Finding | Severity | Confidence | Detailed write-up |
| --- | --- | --- | --- |
| [Injection reaches sink (critical)](#finding-1) | critical | high | inline below |
| [Injection reaches sink (high)](#finding-2) | high | high | inline below |
| [Injection reaches sink (medium)](#finding-3) | medium | high | inline below |
| [Injection reaches sink (low)](#finding-4) | low | high | inline below |

### Confidence Scale

| Label | Meaning |
| --- | --- |
| high | Direct evidence supports the finding with no material unresolved blocker. |
| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |
| low | Evidence is incomplete and the item is retained only for explicit follow-up. |

<a id="finding-1"></a>

### [1] Injection reaches sink (critical)

| Field | Value |
| --- | --- |
| Severity | critical |
| Confidence | high |
| Confidence rationale | Direct source trace. |
| Category | injection |
| CWE | CWE-89 |
| Affected lines | src/module_0.py:5-7, src/module_0.py:100 |

#### Summary

Summary for Injection reaches sink (critical).

#### Validation

Validation outcomes are recorded below.

- **Status:** validated
- **Disposition:** reported
- **Result:** Confirmed with a trace.

#### Dataflow

The canonical finding records the affected path at src/module_0.py:5-7, src/module_0.py:100, but no expanded source-to-sink narrative was recorded.

Attack steps:
- Send a crafted request.
- The handler forwards it to the query.

#### Reachability

Reachability was not recorded beyond the canonical finding summary and affected locations.

- **Source:** HTTP body.

- **Sink:** SQL execution.

Assumptions:
- The endpoint is public.

#### Severity

**Critical** — The scan assigned critical severity; no separate canonical severity rationale was recorded.

Additional runtime or deployment evidence could raise or lower this severity.

Impact assessment:
- **Level:** critical
- **Rationale:** Data exposure.
- **Why:** Unparameterized query.

**Likelihood assessment:** Likely for unauthenticated callers.

#### Remediation

Fix injection reaches sink (critical).

<a id="finding-2"></a>

### [2] Injection reaches sink (high)

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | high |
| Confidence rationale | Direct source trace. |
| Category | injection |
| CWE | CWE-89, CWE-20 |
| Affected lines | src/module_1.py:15-17, src/module_1.py:101 |

#### Summary

Summary for Injection reaches sink (high).

#### Validation

Validation outcomes are recorded below.

- **Status:** validated
- **Disposition:** reported
- **Result:** Confirmed with a trace.

#### Dataflow

The canonical finding records the affected path at src/module_1.py:15-17, src/module_1.py:101, but no expanded source-to-sink narrative was recorded.

Attack steps:
- Send a crafted request.
- The handler forwards it to the query.

#### Reachability

Reachability was not recorded beyond the canonical finding summary and affected locations.

- **Source:** HTTP body.

- **Sink:** SQL execution.

Assumptions:
- The endpoint is public.

#### Severity

**High** — The scan assigned high severity; no separate canonical severity rationale was recorded.

Additional runtime or deployment evidence could raise or lower this severity.

Impact assessment:
- **Level:** high
- **Rationale:** Data exposure.
- **Why:** Unparameterized query.

**Likelihood assessment:** Likely for unauthenticated callers.

#### Remediation

Fix injection reaches sink (high).

<a id="finding-3"></a>

### [3] Injection reaches sink (medium)

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Direct source trace. |
| Category | injection |
| CWE | CWE-89 |
| Affected lines | src/module_2.py:25-27, src/module_2.py:102 |

#### Summary

Summary for Injection reaches sink (medium).

#### Validation

Direct source trace. Validation details were not recorded separately.

#### Dataflow

The canonical finding records the affected path at src/module_2.py:25-27, src/module_2.py:102, but no expanded source-to-sink narrative was recorded.

#### Reachability

Reachability was not recorded beyond the canonical finding summary and affected locations.

#### Severity

**Medium** — The scan assigned medium severity; no separate canonical severity rationale was recorded.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Fix injection reaches sink (medium).

<a id="finding-4"></a>

### [4] Injection reaches sink (low)

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Direct source trace. |
| Category | injection |
| CWE | CWE-89, CWE-20 |
| Affected lines | src/module_3.py:35-37, src/module_3.py:103 |

#### Summary

Summary for Injection reaches sink (low).

#### Validation

Direct source trace. Validation details were not recorded separately.

#### Dataflow

The canonical finding records the affected path at src/module_3.py:35-37, src/module_3.py:103, but no expanded source-to-sink narrative was recorded.

#### Reachability

Reachability was not recorded beyond the canonical finding summary and affected locations.

#### Severity

**Low** — The scan assigned low severity; no separate canonical severity rationale was recorded.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Fix injection reaches sink (low).

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| Request input | not recorded | Reported | No additional canonical notes were recorded. |
