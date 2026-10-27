"""Edge cases of the finalizer's CSV projection.

Besides checking Python behavior, these calls feed tests/parity/record_vectors.py, which records them as vectors the
TypeScript port (src/contract/exports.ts) must reproduce byte for byte.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


def load_finalizer() -> ModuleType:
    script = Path(__file__).resolve().parent.parent / "scripts" / "finalize_scan_contract.py"
    spec = importlib.util.spec_from_file_location("finalize_scan_contract", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FINALIZER = load_finalizer()
FULLWIDTH = [chr(0xFF1D), chr(0xFF0B), chr(0xFF0D), chr(0xFF20)]


@pytest.mark.parametrize(
    "value",
    [
        "plain", "=SUM(A1)", "+1", "-1", "@cmd", "  =padded", "\t=tab", "\rcr", "\nlf", chr(0x3000) + "=ideographic",
        chr(0x1C) + "+fs", *(prefix + "x" for prefix in FULLWIDTH), "a=b", "", None, 5, 2.5,
    ],
)
def test_csv_cell(value: Any) -> None:
    FINALIZER.csv_cell(value)


def finding(occurrence: str, **extra: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "occurrenceId": "occ_" + occurrence,
        "findingId": "csf_" + occurrence,
        "title": "Title " + occurrence,
        "summary": "Summary",
        "severity": {"level": "high"},
        "confidence": {"level": "low"},
        "remediation": "Fix.",
        "locations": [{"path": "src/a.py", "startLine": 3}],
    }
    value.update(extra)
    return value


@pytest.mark.parametrize(
    "findings, coverage",
    [
        ([], {"mode": "repository"}),
        (
            [
                finding("a", title='Quote " and, comma', summary="multi\nline\r\nsummary", remediation="=HYPERLINK()"),
                finding("b", locations=[{"path": "src/x,y.py", "startLine": 1, "endLine": 4}, {"path": "src/root.py", "startLine": 9, "role": "root_control"}]),
                finding("c", title=" leading and trailing space ", summary="", remediation=chr(0xFF1D) + "1+1"),
                finding("d", title="dépôt " + chr(0x1F511)),
            ],
            {"mode": "repository"},
        ),
        (
            [
                finding("a", provenance={"candidateId": "DSS-1"}, extensions={"candidateId": "ignored"}),
                finding("b", provenance={"candidateId": "  "}, extensions={"reportId": "R-2"}),
                finding("c", extensions={"ledgerRowId": "L-3"}),
                finding("d", extensions={"candidateId": " ", "reportId": "", "ledgerRowId": "-L4"}),
                finding("e"),
            ],
            {"mode": "deep_repository"},
        ),
        ([finding("a", extensions={"reportId": "R-1"})], {"mode": "scoped_path"}),
        ([finding("a", extensions={"ledgerRowId": "L-1"})], {"mode": "scoped_path"}),
    ],
)
def test_build_csv_projection(findings: list[dict[str, Any]], coverage: dict[str, Any]) -> None:
    FINALIZER.build_csv_projection({"findings": findings}, coverage)
