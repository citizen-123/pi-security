"""Edge cases of finding identity in the finalizer.

Besides checking Python behavior, these calls feed tests/parity/record_vectors.py, which records them as vectors the
TypeScript port (src/contract/finding-identity.ts) must reproduce, including error messages.
"""

from __future__ import annotations

import copy
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
IDEOGRAPHIC_SPACE = chr(0x3000)
FILE_SEPARATOR = chr(0x1C)
ZERO_WIDTH_NO_BREAK = chr(0xFEFF)
LONE_SURROGATE = chr(0xDCFF)


def finding(**identity: Any) -> dict[str, Any]:
    return {"ruleId": "injection.sql", "identity": {"anchor": "query-concat", **identity}}


def manifest(scan_id: str = "scan_edges", target_id: str = "target_edges") -> dict[str, Any]:
    return {"scan": {"id": scan_id, "target": {"targetId": target_id}}}


@pytest.mark.parametrize(
    "target_id, value",
    [
        ("target_edges", finding()),
        ("target_edges", finding(instance="second")),
        ("target_edges", finding(instance="")),
        ("target_edges", finding(anchor="a/b.c_d-e9")),
        ("cible_dépôt_" + chr(0x65E5) + chr(0x1F511), finding()),
        ("target" + chr(0) + "with-nul", finding()),
    ],
)
def test_fingerprint_accepts(target_id: str, value: dict[str, Any]) -> None:
    fingerprint = FINALIZER._fingerprint(target_id, value)
    assert fingerprint.startswith("pi-security/v1:sha256:")


@pytest.mark.parametrize(
    "value, message",
    [
        ({"ruleId": "injection.sql"}, "finding.identity: expected an object"),
        ({"ruleId": "injection.sql", "identity": ["query-concat"]}, "finding.identity: expected an object"),
        ({"ruleId": "injection.sql", "identity": {}}, "finding.identity.anchor: expected a non-empty string"),
        (finding(anchor=""), "finding.identity.anchor: expected a non-empty string"),
        (finding(anchor="   "), "finding.identity.anchor: expected a non-empty string"),
        (finding(anchor=IDEOGRAPHIC_SPACE), "finding.identity.anchor: expected a non-empty string"),
        (finding(anchor=FILE_SEPARATOR), "finding.identity.anchor: expected a non-empty string"),
        (finding(anchor=ZERO_WIDTH_NO_BREAK), "finding.identity.anchor: expected a stable lowercase semantic slug"),
        (finding(anchor=7), "finding.identity.anchor: expected a non-empty string"),
        (finding(anchor="Query"), "finding.identity.anchor: expected a stable lowercase semantic slug"),
        (finding(anchor="-query"), "finding.identity.anchor: expected a stable lowercase semantic slug"),
        (finding(anchor="query\n"), "finding.identity.anchor: expected a stable lowercase semantic slug"),
        (finding(anchor="query concat"), "finding.identity.anchor: expected a stable lowercase semantic slug"),
        (finding(instance=None), "finding.identity.instance: expected a string"),
        (finding(instance=3), "finding.identity.instance: expected a string"),
        (finding(instance="Second"), "finding.identity.instance: expected a stable lowercase semantic slug"),
        (finding(instance=" "), "finding.identity.instance: expected a stable lowercase semantic slug"),
        ({"identity": {"anchor": "query-concat"}}, "finding.ruleId: expected a non-empty string"),
        ({**finding(), "ruleId": "Injection.SQL"}, "finding.ruleId: expected a stable lowercase rule slug"),
        ({**finding(), "ruleId": IDEOGRAPHIC_SPACE}, "finding.ruleId: expected a non-empty string"),
    ],
)
def test_fingerprint_rejects(value: dict[str, Any], message: str) -> None:
    with pytest.raises(FINALIZER.ContractError, match=f"^{message.replace('.', '[.]')}$"):
        FINALIZER._fingerprint("target_edges", value)


def test_fingerprint_rejects_unencodable_target() -> None:
    with pytest.raises(UnicodeEncodeError):
        FINALIZER._fingerprint("target" + LONE_SURROGATE, finding())


@pytest.mark.parametrize(
    "prefix, parts",
    [("csf", ()), ("csf", ("a",)), ("occ", ("scan", "pi-security/v1:sha256:00")), ("x", ("dépôt", chr(0x1F511), ""))],
)
def test_stable_id(prefix: str, parts: tuple[str, ...]) -> None:
    assert FINALIZER._stable_id(prefix, *parts).startswith(f"{prefix}_")


def test_derived_rows_for_siblings() -> None:
    findings = {"scanId": "scan_edges", "findings": [finding(), finding(instance="second")]}
    rows = FINALIZER._derived_finding_identity_rows(manifest(), findings)
    assert len({row[2] for row in rows}) == 2


@pytest.mark.parametrize(
    "manifest_value, findings_value, message",
    [
        (manifest(), {"scanId": "scan_edges", "findings": [finding(), finding()]},
         "findings.findings[1]: duplicate occurrence identity; use identity.instance to split siblings"),
        (manifest(), {"scanId": "scan_other", "findings": []}, "findings.scanId: must match manifest scan id"),
        (manifest(), {"scanId": "scan_edges", "findings": {}}, "findings.findings: expected an array"),
        (manifest(), {"scanId": "scan_edges", "findings": ["x"]}, "findings.findings[0]: expected an object"),
        ({}, {"scanId": "scan_edges", "findings": []}, "manifest.scan: expected an object"),
        ({"scan": {"id": "scan_edges", "target": {}}}, {"scanId": "scan_edges", "findings": []},
         "scan.target.targetId: expected a non-empty string"),
        ({"scan": {"id": " ", "target": {"targetId": "t"}}}, {"scanId": " ", "findings": []},
         "manifest.scan.id: expected a non-empty string"),
    ],
)
def test_derived_rows_reject(manifest_value: dict[str, Any], findings_value: dict[str, Any], message: str) -> None:
    with pytest.raises(FINALIZER.ContractError) as raised:
        FINALIZER._derived_finding_identity_rows(copy.deepcopy(manifest_value), copy.deepcopy(findings_value))
    assert str(raised.value) == message
