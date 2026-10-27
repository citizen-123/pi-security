"""Edge cases of the finalizer's contract validation.

Besides checking Python behavior, these calls feed tests/parity/record_vectors.py, which records them as vectors the
TypeScript port (src/contract/validation.ts) must reproduce, including error messages.
"""

from __future__ import annotations

import copy
import importlib.util
import tempfile
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


def call(function: Any, *args: Any) -> None:
    try:
        function(*args)
    except (FINALIZER.ContractError, ValueError):
        pass


def validate_coverage_with_files(manifest: dict[str, Any], coverage: dict[str, Any], files: dict[str, bytes]) -> dict[str, Any]:
    """_validate_coverage with a scan directory holding `files`; returns the coverage it normalized in place."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory).resolve()
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        FINALIZER._validate_coverage(manifest, coverage, root)
    return coverage


@pytest.mark.parametrize(
    "remote",
    [
        "https://github.com/example/repo", "ssh://git@host/repo", "https://user:pw@host/r", "https://@host/r",
        "https://:@host/r", "https://host/r?", "https://host/r?q=1", "https://host/r#", "https://host/r#frag",
        "  https://host/r", "ht\ttps://host/r", "https://ho\nst/r", "git@github.com:example/repo.git", "/local/path",
        "https://[::1]/r", "https://[::1/r", "https://x[::1]/r", "https://[v1.fe]/r", "https://[1.2.3.4]/r",
        "https://[::1]x/r", "https://ex" + chr(0xFF20) + "mple.com/r", "https://exämple.com/r", "HTTPS://Host/r",
        "1http://host/r", "https:", "https:///path",
    ],
)
def test_validate_remote(remote: str) -> None:
    call(FINALIZER._validate_remote, remote, "scan.target.remote")


TARGET = {"kind": "git_worktree", "targetId": "t", "displayName": "d", "snapshotDigest": "s"}


@pytest.mark.parametrize(
    "target",
    [
        TARGET,
        {**TARGET, "kind": "git_revision", "revision": "abc"},
        {**TARGET, "kind": "git_revision"},
        {**TARGET, "kind": "svn"},
        {**TARGET, "remote": None},
        {**TARGET, "remote": 5},
        {**TARGET, "remote": "https://u:p@h/r"},
        {**TARGET, "displayName": " "},
        {**TARGET, "kind": "directory_snapshot", "snapshotDigest": ""},
    ],
)
def test_validate_target(target: dict[str, Any]) -> None:
    call(FINALIZER._validate_target, copy.deepcopy(target))


@pytest.mark.parametrize(
    "location",
    [
        {"path": "src/a.py", "startLine": 1},
        {"path": "src/a.py", "startLine": True},
        {"path": "src/a.py", "startLine": True, "endLine": False},
        {"path": "src/a.py", "startLine": 2, "endLine": 1},
        {"path": "src/a.py", "startLine": 2, "endLine": None},
        {"path": "src/a.py", "startLine": 2.0},
        {"path": "src/a.py", "startLine": 0},
        {"path": "src/a.py"},
        {"path": "src/a.py", "startLine": 1, "role": ""},
        {"path": "src/a.py", "startLine": 1, "role": 3},
        {"path": "src/a.py", "startLine": 1, "role": None},
        {"path": "../a.py", "startLine": 1},
        {"path": "", "startLine": 1},
    ],
)
def test_validate_location(location: dict[str, Any]) -> None:
    call(FINALIZER._validate_location, copy.deepcopy(location), "f.locations[0]")


FINDING = {
    "findingId": "csf_1", "occurrenceId": "occ_1", "ruleId": "r", "title": "t", "summary": "s", "remediation": "r",
    "identity": {"anchor": "a"}, "fingerprints": {"algorithm": "pi-security/v1", "primary": "p"},
    "severity": {"level": "high"}, "confidence": {"level": "high", "rationale": "r"},
    "taxonomy": {"category": "c"}, "locations": [{"path": "a.py", "startLine": 1}], "provenance": {"source": "s"},
}


def variant(**changes: Any) -> dict[str, Any]:
    value = copy.deepcopy(FINDING)
    for key, item in changes.items():
        if item is None and key.endswith("_delete"):
            value.pop(key.removesuffix("_delete"))
        else:
            value[key] = item
    return value


@pytest.mark.parametrize(
    "finding",
    [
        FINDING,
        variant(fingerprints={"algorithm": "v0", "primary": "p"}),
        variant(severity={"level": "severe"}),
        variant(severity={"level": "high", "score": 10, "scoringSystem": "x"}),
        variant(severity={"level": "high", "score": 10.5, "scoringSystem": "x"}),
        variant(severity={"level": "high", "score": True, "scoringSystem": "x"}),
        variant(severity={"level": "high", "score": 5}),
        variant(severity={"level": "high", "score": None}),
        variant(confidence={"level": "certain", "rationale": "r"}),
        variant(taxonomy={"category": "c", "cwe": ["CWE-1", ""]}),
        variant(taxonomy={"category": "c", "cwe": None}),
        variant(locations=[]),
        variant(locations=["x"]),
        variant(codeEvidence=[{"id": "E1", "code": "x"}, {"id": "E1", "code": "y"}]),
        variant(codeEvidence={}),
        variant(codeEvidence=[{"id": "E1", "code": "x"}], code_evidence=[{"id": "E2", "code": "y"}],
                rootCause={"evidenceRefs": ["E1", "E2"]}, attackPath={"dataFlow": {"evidence_refs": ["E2"]}}),
        variant(codeEvidence=[{"id": "E1", "code": "x"}], validation={"evidenceRefs": ["Z9", "E1", "B2", "Z9"]}),
        variant(codeEvidence=[{"id": "E1", "code": "x"}], attackPath={"reachability": {"evidenceRefs": [""]}}),
        variant(rootCause="a string section"),
        variant(provenance={"source": ""}),
        variant(extensions=[]),
        variant(extensions=None),
    ],
)
def test_validate_finding(finding: dict[str, Any]) -> None:
    call(FINALIZER._validate_finding, copy.deepcopy(finding), "findings.findings[0]")


SCAN = {
    "id": "s1", "startedAt": "a", "completedAt": "b", "sealedAt": "c", "status": "completed",
    "producer": {"name": "pi-security", "version": "0.1.0"}, "target": TARGET,
    "scope": {"includePaths": ["."], "excludePaths": []}, "coverageRef": "coverage.json", "findingsRef": "findings.json",
    "artifacts": [
        {"path": "findings.json", "sha256": "x", "mediaType": "application/json"},
        {"path": "coverage.json", "sha256": "x", "mediaType": "application/json"},
    ],
}


def manifest_with(**changes: Any) -> dict[str, Any]:
    return {"documentType": "pi-security.scan-manifest", "schemaVersion": "1.0", "scan": {**copy.deepcopy(SCAN), **changes}}


@pytest.mark.parametrize(
    "manifest",
    [
        manifest_with(),
        {**manifest_with(), "schemaVersion": 1.0},
        manifest_with(status="running"),
        manifest_with(scope={"includePaths": [".", "src/./x"], "excludePaths": [3]}),
        manifest_with(coverageRef="cov.json"),
        manifest_with(artifacts=[]),
        manifest_with(artifacts=[*SCAN["artifacts"], {"path": "Findings.JSON", "sha256": "x", "mediaType": "m"}]),
        manifest_with(artifacts=[SCAN["artifacts"][0]]),
        manifest_with(artifacts=[*SCAN["artifacts"], {"path": "artifacts/con.txt", "sha256": "x", "mediaType": "m"}]),
    ],
)
def test_validate_manifest(manifest: dict[str, Any]) -> None:
    call(FINALIZER._validate_manifest, copy.deepcopy(manifest))


@pytest.mark.parametrize(
    "findings",
    [
        {"documentType": "pi-security.findings", "schemaVersion": "1.0", "scanId": "s1", "findings": [FINDING]},
        {"documentType": "pi-security.findings", "schemaVersion": "1.0", "scanId": "s1", "findings": [FINDING, variant(findingId="csf_2")]},
        {"documentType": "pi-security.findings", "schemaVersion": "1.0", "scanId": "other", "findings": []},
        {"documentType": "x", "schemaVersion": "1.0", "scanId": "s1", "findings": []},
    ],
)
def test_validate_findings(findings: dict[str, Any]) -> None:
    call(FINALIZER._validate_findings, manifest_with(), copy.deepcopy(findings))


COVERAGE = {
    "scanId": "s1", "mode": "repository", "completeness": "complete", "inventoryStrategy": "repository",
    "includePaths": ["."], "excludePaths": [], "surfaces": [], "explicitExclusions": [], "deferred": [],
}


@pytest.mark.parametrize(
    "coverage, files",
    [
        (COVERAGE, {}),
        ({**COVERAGE, "includePaths": [".", "x"]}, {}),
        ({**COVERAGE, "surfaces": [{"id": "a", "label": "A", "disposition": "reported", "receiptRefs": ["artifacts//r.txt", "./artifacts/r.txt"]}]},
         {"artifacts/r.txt": b"r"}),
        ({**COVERAGE, "surfaces": [{"id": "a", "label": "A", "disposition": "reported", "receiptRefs": ["artifacts/missing.txt"]}]}, {}),
        ({**COVERAGE, "surfaces": [{"id": "a", "label": "A", "disposition": "reported", "receiptRefs": ["other/r.txt"]}]}, {"other/r.txt": b"r"}),
        ({**COVERAGE, "surfaces": [{"id": "a", "label": "A", "disposition": "needs_follow_up"}]}, {}),
        ({**COVERAGE, "completeness": "partial", "surfaces": [{"id": "a", "label": "A", "disposition": "needs_follow_up"}]}, {}),
        ({**COVERAGE, "deferred": [{"id": "d", "reason": "r"}]}, {}),
        ({**COVERAGE, "surfaces": [{"id": "a", "label": "A", "disposition": "x"}]}, {}),
        ({**COVERAGE, "surfaces": [{"id": "a", "label": "A", "disposition": "reported"}, {"id": "a", "label": "B", "disposition": "reported"}]}, {}),
        ({**COVERAGE, "explicitExclusions": None}, {}),
    ],
)
def test_validate_coverage(coverage: dict[str, Any], files: dict[str, bytes]) -> None:
    try:
        validate_coverage_with_files(manifest_with(), copy.deepcopy(coverage), files)
    except FINALIZER.ContractError:
        pass


BINDING = {
    "scanId": "s1", "startedAt": "a", "completedAt": "b", "producer": {"name": "pi-security", "version": "0.1.0"},
    "target": {"targetId": "t"}, "allowedTargetKinds": ["git_worktree"], "scope": {"includePaths": ["."], "excludePaths": []},
    "coverageMode": "repository",
}


@pytest.mark.parametrize(
    "binding",
    [None, BINDING, {**BINDING, "status": "failed"}, {**BINDING, "producer": {"version": "0.1.0", "name": "pi-security"}},
     {**BINDING, "allowedTargetKinds": ["git_diff"]}, {**BINDING, "target": {"targetId": "other"}},
     {**BINDING, "scope": {"includePaths": ["src"]}}, {**BINDING, "coverageMode": "diff"}, {**BINDING, "startedAt": "z"}],
)
def test_validate_completion_binding(binding: dict[str, Any] | None) -> None:
    call(FINALIZER._validate_completion_binding, manifest_with(), {"scanId": "s1"}, copy.deepcopy(COVERAGE), copy.deepcopy(binding))


@pytest.mark.parametrize(
    "finding",
    [
        variant(code_evidence=[{"id": "E1", "code": "x"}, {"id": "E1", "code": "dup"}, {"id": " ", "code": "x"}, {"id": "E2"}, "junk"],
                codeEvidence=[{"id": "C1", "code": "c"}],
                rootCause={"evidenceRefs": ["C1", "E1", "E9", "", 3]},
                root_cause={"summary": "", "code": 4, "language": "py", "evidence_refs": "E1"},
                validation={"method": None, "status": "ok", "assertions": "one", "limitations": [" ", "x", 2], "evidence": ""},
                attackPath={"summary": 5, "steps": "do it", "dataFlow": None, "data_flow": "", "dataflow": 7,
                            "reachability": {"attacker": "", "entrypoint": "e", "preconditions": "p", "evidenceRefs": ["E1", "Q"]},
                            "impact": {"level": 3, "why": "w"}, "likelihood": ""}),
        variant(code_evidence="not a list", root_cause=""),
        variant(root_cause=None, attackPath={"impact": 5, "likelihood": "likely"}),
        variant(root_cause=7),
    ],
)
def test_legacy_sealed_findings_for_validation(finding: dict[str, Any]) -> None:
    FINALIZER._legacy_sealed_findings_for_validation({"findings": [copy.deepcopy(finding), "not a finding"]})
