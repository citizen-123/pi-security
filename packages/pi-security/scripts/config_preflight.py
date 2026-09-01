#!/usr/bin/env python3
"""Evaluate explicit host capabilities without reading harness configuration."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

PROFILES = {
    "security_scan",
    "security_diff_scan",
    "deep_security_scan",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate Pi Security capabilities supplied by the active host."
    )
    parser.add_argument("--profile", choices=sorted(PROFILES), required=True)
    parser.add_argument("--cwd", default=".")
    parser.add_argument(
        "--runtime-check",
        action="append",
        default=[],
        metavar="NAME=BOOL",
        help="Observed host capability. Repeat for each relevant capability.",
    )
    return parser.parse_args()


def parse_runtime_checks(values: list[str]) -> dict[str, bool]:
    checks: dict[str, bool] = {}
    for value in values:
        name, separator, raw = value.partition("=")
        if not separator or not name or raw.lower() not in {"true", "false"}:
            raise SystemExit(f"Invalid --runtime-check {value!r}; expected NAME=true or NAME=false.")
        checks[name] = raw.lower() == "true"
    return checks


def main() -> None:
    args = parse_args()
    cwd = Path(args.cwd).expanduser().resolve()
    results: list[dict[str, str]] = []
    if cwd.is_dir():
        results.append(
            {
                "capability": "target_access",
                "reason": f"Scan working directory is available: {cwd}",
                "severity": "block",
                "status": "pass",
            }
        )
    else:
        results.append(
            {
                "capability": "target_access",
                "reason": f"Scan working directory is not an accessible directory: {cwd}",
                "severity": "block",
                "status": "fail",
            }
        )

    for name, available in sorted(parse_runtime_checks(args.runtime_check).items()):
        results.append(
            {
                "capability": name,
                "reason": (
                    f"The active host reports {name} is available."
                    if available
                    else f"The active host reports {name} is unavailable; use the documented single-agent fallback."
                ),
                "severity": "suggest",
                "status": "pass" if available else "unknown",
            }
        )

    blocked = any(result["severity"] == "block" and result["status"] == "fail" for result in results)
    print(
        json.dumps(
            {
                "profile": args.profile,
                "status": "blocked" if blocked else "ready",
                "results": results,
            },
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
