# Capability Preflight

Run preflight after resolving the authoritative target and before substantive analysis:

```text
<python_command> <package_dir>/scripts/config_preflight.py --profile <capability-profile> --cwd <scan-working-directory> [--runtime-check <name>=<true|false>]...
```

Profiles are `security_scan`, `security_diff_scan`, and `deep_security_scan`.

Derive runtime checks from the active host's actual tool surface. Useful checks include `delegation_available`, `goal_tools_available`, and `user_input_available`. Missing optional capabilities produce an `unknown` suggestion and use the workflow's single-agent or plain-chat fallback; they do not block the scan. An inaccessible target is blocking.

The helper never reads model-provider credentials, harness configuration, global settings, or project trust files. It returns one JSON object:

```json
{
  "profile": "security_scan",
  "status": "ready",
  "results": [
    {
      "capability": "target_access",
      "reason": "Scan working directory is available: /repo",
      "severity": "block",
      "status": "pass"
    }
  ]
}
```

Publish every returned result to durable scan progress when that tool is available. Continue only when `status` is `ready`. If target access is blocked, surface the exact reason without creating replacement scan state or widening scope.
