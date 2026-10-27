"""The parity cases and goldens must match the current Python implementation.

A failure means either the case builder changed without regenerating cases, or Python behavior changed. Both change
the contract the TypeScript ports are held to, so regenerate deliberately (see tests/parity/README.md).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PARITY_DIR = Path(__file__).resolve().parent / "parity"


def run(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(PARITY_DIR / script), *args],
        capture_output=True,
        text=True,
        timeout=600,
    )


def test_cases_match_builder() -> None:
    result = run("build_cases.py", "--check")
    assert result.returncode == 0, result.stderr


def test_python_matches_goldens() -> None:
    result = run("oracle.py")
    assert result.returncode == 0, result.stderr
