# Pi Security

Pi-native security scanning with an optional stdio MCP transport. The package contains the local workbench, schemas, skills, report generation, findings database, triage/remediation workflows, and MCP server. It does not require a model-provider CLI or SDK, provider account or API key, or hosted security service.

## Install in Pi

```sh
pi install git:github.com/<owner>/<repository>
```

After npm publication:

```sh
pi install npm:pi-security
```

Pi loads the bundled `pi-subagents` extension first and then Pi Security. Standard and diff scans work through the native extension immediately after package load:

```text
/security-scan [optional focus]
/security-diff-scan [optional focus]
```

No separate MCP server entry is needed for this Pi lifecycle. The stdio server is an optional transport for other MCP hosts and for Deep Scan hosts that implement tool-enabled sampling.

## Capability matrix

| Capability | Native Pi package | Generic MCP client |
| --- | --- | --- |
| Standard scan | Yes. The skill uses Pi's local source tools, bundled read-only subagents, and local lifecycle/artifact tools. | Lifecycle tools are available, but the client must drive the audit and provide local source access. No MCP sampling is required. |
| Diff scan | Yes. Same native lifecycle, scoped to an exact local Git change set. | Lifecycle tools are available; the client must provide local source and Git access. No MCP sampling is required. |
| Deep Scan | Not through the native extension alone. Run the optional MCP server from a compatible host. | Yes only when the client advertises MCP 2025-11-25 `sampling.tools`. Basic sampling is insufficient. |
| Local state, validation, reports, SARIF, triage, and remediation | Included | Included over stdio |
| Pi subagent fleet | Bundled and configured | Not supplied by MCP transport; Deep Scan has its own bounded sampling delegation when enabled. |

An MCP connector that can call server tools is not necessarily equivalent to an MCP client with `sampling.tools`. If it cannot accept server-initiated, tool-enabled sampling requests, Standard and diff lifecycle operations remain available but Deep Scan is not.

## Permission profiles and enforcement

Every policy context is issued by Pi Security, bound to one target root, scan ID, and artifact root, and checked for module provenance. A tool argument, serialized continuation, cloned object, or repository file cannot select or manufacture a profile.

| Capability | `security-readonly` | `security-delegating-readonly` | `security-artifact-writer` |
| --- | ---: | ---: | ---: |
| `target.read` | Yes | Yes | No |
| `target.search` | Yes | Yes | No |
| `target.git` | Yes | Yes | No |
| `scan-artifacts.write` | No | No | Yes |
| `workbench.execute` | No | No | Yes |
| `delegation.create` | No | Yes, with a host-issued budget and one-level depth | No |
| `network.access` | No | No | No |
| `target.execute` | No | No | No |
| `target.write` | No | No | No |

The Pi adapter fixes lifecycle, workbench, and artifact operations to `security-artifact-writer`; packaged audit agents receive `security-readonly`; and the coordinator alone receives bounded `security-delegating-readonly` authority whose children are forced back to `security-readonly`. Pi run control is restricted to run IDs created by the same Pi Security session and canonical target. The MCP adapter similarly chooses the source profile from host configuration, issues a separate fixed artifact writer, and uses the same capability requirements for both advertised tools and direct dispatch.

This is a **capability sandbox**, not a claim of a cross-platform OS process sandbox. Scan profiles expose no general target command execution, target writes, or network tools. `workbench.execute` authorizes only fixed bundled-workbench dispatch, and artifact writes are limited to trusted workbench and scan artifacts under the bound artifact root outside the target. Git-aware reads use fixed metadata operations with repository-configured helper sinks disabled.

Target paths must be repository-relative and remain inside the bound target and scope. Existing paths are opened without following symlinks and consumed through verified handles; directory identity is checked during enumeration. Linux uses no-follow opens plus `/proc/self/fd`, other supported POSIX hosts use `/dev/fd`, and Windows rejects reparse-point changes and rechecks file identity. If the host cannot enforce its required handle or root mechanism, Pi Security returns `PI_SECURITY_ENFORCEMENT_UNSUPPORTED` before the guarded state commit. There is no fallback to pathname-only enforcement.

Deep Scan continuation v2 stores application-owned policy state. Recovery reissues the exact profile, target/scan bindings, capabilities, and remaining delegation state from fresh host authority before sampling or artifact writes. Legacy v1 state, mismatched continuation IDs or kinds, altered profiles or budgets, stale delegation predecessors, and forged child markers/results fail closed with `PI_SECURITY_POLICY_RECOVERY_REJECTED`.

The policy layer uses these stable codes:

- `PI_SECURITY_POLICY_DENIED` (`policy_denied`) for a capability denial;
- `PI_SECURITY_ENFORCEMENT_UNSUPPORTED` (`unsupported_enforcement`) when the host cannot apply a required mechanism;
- `PI_SECURITY_POLICY_RECOVERY_REJECTED` (`policy_recovery_rejected`) for rejected recovery, with reason `legacy_continuation`, `profile_mismatch`, `invalid_policy`, `delegation_mismatch`, or `binding_mismatch`.

Public `enforcementCapabilities` diagnostics contain `schemaVersion`, `kind` (`availability` or `effective`), `supported`, `mechanisms`, and `unsupportedReason`. Successful worker diagnostics may also contain `effectivePolicy` with `schemaVersion`, public `source` and `artifactWriter` projections (`profile`, `capabilities`, and `delegation`), and the effective enforcement report. These projections intentionally omit target paths, artifact paths, scan IDs, claims, credentials, and continuation tokens.

## Bundled subagents

The package publishes four read-only profiles:

- `pi-security-scout` — attack-surface and repository mapping
- `pi-security-auditor` — focused vulnerability investigation
- `pi-security-validator` — independent validation and attack-path review
- `pi-security-reviewer` — final false-positive and consistency review

Standard and diff scan skills start these agents concurrently through `pi_security_spawn_agents`. `pi_security_control_agents` provides fleet or targeted status, transcript tails, steering, interruption, stopping, and resumption. Project or user profiles with the same names retain normal `pi-subagents` discovery precedence.

## Optional MCP server

```sh
npm install
npm run build
pi-security-mcp
```

Example stdio configuration:

```json
{
  "mcpServers": {
    "pi-security": {
      "command": "pi-security-mcp",
      "env": {
        "PI_SECURITY_STATE_DIR": "/absolute/path/to/private/state",
        "PI_SECURITY_SCAN_ROOT": "/absolute/path/to/private/scans"
      }
    }
  }
}
```

Deep Scan supplies target-bound list, read, literal-search, repository-metadata, scan-context, and schema-bound record tools to each sampling request. The server persists its own continuation transcript and can run a configured, bounded layer of nested sampling tasks; it does not depend on provider thread identifiers.

Model and reasoning settings are requests, not proof that a sampling client applied them. Pi Security reports applied reasoning only when the client acknowledges it, and reports only client- or host-supplied token usage as complete, partial, or unavailable. It never estimates missing usage.

Legacy provider-specific executors and provider-configuration discovery are intentionally absent. There is no hidden provider fallback when native tools or MCP sampling capabilities are unavailable.

## Requirements

- Node.js 20 or newer
- Python 3.11 or newer for the local workbench
- Git for Git-aware targets and diff scans

All native lifecycle and low-level workbench calls resolve Python consistently: `PI_SECURITY_PYTHON_COMMAND`, then `PYTHON`, then Pi's cached primary runtime when executable, then the platform default.

See [`packages/pi-security/README.md`](packages/pi-security/README.md) for the detailed transport behavior, state/configuration, direct workbench use, and development setup.
