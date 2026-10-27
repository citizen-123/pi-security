"""Edge cases of the finalizer's unsealed draft recovery and envelope population.

Besides checking Python behavior, these calls feed tests/parity/record_vectors.py, which records them, with the
arguments they change, as vectors the TypeScript port (src/contract/recovery.ts) must reproduce.
"""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

import pytest


def load_finalizer() -> ModuleType:
    script = Path(__file__).resolve().parent.parent / "scripts" / "finalize_scan_contract.py"
    spec = importlib.util.spec_from_file_location("finalize_scan_contract", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FINALIZER = load_finalizer()
SCHEMAS = Path(__file__).resolve().parent.parent / "schemas"

MANIFEST: dict[str, Any] = {
    "documentType": "pi-security.scan-manifest",
    "schemaVersion": "1.0",
    "scan": {
        "id": "scan_edge",
        "producer": {"name": "pi-security", "version": "0.1.0"},
        "status": "completed",
        "startedAt": "2026-05-31T18:00:00Z",
        "completedAt": "2026-05-31T18:09:00Z",
        "target": {
            "kind": "git_worktree",
            "targetId": "target_example",
            "revision": "deadbeef",
            "snapshotDigest": "pi-security-snapshot/v1:sha256:" + "0" * 64,
        },
        "scope": {"includePaths": ["src/"], "excludePaths": []},
        "coverageRef": "coverage.json",
        "findingsRef": "findings.json",
    },
}


def finding(**extra: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "ruleId": "path-traversal.archive-extraction",
        "identity": {"anchor": "archive-entry-write"},
        "title": "Archive entries escape the output directory",
        "summary": "A crafted entry path reaches a write without containment.",
        "severity": {"level": "high"},
        "confidence": {"level": "medium", "rationale": "Traced by hand."},
        "taxonomy": {"category": "path-traversal", "cwe": ["CWE-22"]},
        "locations": [{"path": "src/extract.py", "startLine": 4, "endLine": 6, "role": "sink"}],
        "remediation": "Reject entries that resolve outside the root.",
        "validation": None,
        "attackPath": None,
        "provenance": {"source": "local_package"},
        "extensions": {},
    }
    value.update(extra)
    return value


def evidence(identifier: str, code: str) -> dict[str, Any]:
    return {
        "id": identifier,
        "label": "Write",
        "path": "src/extract.py",
        "startLine": 5,
        "code": code,
        "explanation": "Writes the entry.",
    }


def scan_dir(root: Path, files: dict[str, str] | None = None, directories: tuple[str, ...] = ()) -> Path:
    for relative, content in (files or {}).items():
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        (root / relative).write_text(content, encoding="utf-8")
    for relative in directories:
        (root / relative).mkdir(parents=True)
    return root.resolve()


REPORT = "findings/archive/archive.md"


def recover_findings(tmp_path: Path, items: list[Any], files: dict[str, str] | None = None, **kwargs: Any) -> None:
    findings = {"scanId": "scan_edge", "findings": items}
    warnings: list[str] = []
    try:
        FINALIZER._recover_unsealed_findings(
            copy.deepcopy(MANIFEST), findings, SCHEMAS, scan_dir(tmp_path, files, **kwargs), warnings
        )
    except FINALIZER.ContractError:
        pass


@pytest.mark.parametrize(
    "items",
    [
        ["not an object"],
        [finding(ruleId="Path Traversal: Archive!")],
        [finding(ruleId="---")],
        [finding(ruleId="")],
        [finding(identity={"anchor": "Archive Entry/Write.", "instance": "Entry #2"})],
        [finding(identity={"anchor": "ok", "instance": "!!!"})],
        [finding(identity="anchor")],
        [finding(severity={"level": "high", "changeConditions": ["  If exposed. ", "If remote."]})],
        [finding(severity={"level": "high", "changeConditions": []})],
        [finding(severity={"level": "high", "changeConditions": ["ok", " "]})],
        [finding(severity={"level": "severe"})],
        [finding(remediationTests=["one", ""], preventiveControls="none")],
        [finding(remediationTests=["one"], preventiveControls=["two"])],
        [finding(codeEvidence=[{"id": "x"}])],
        [finding(), finding()],
        [finding(), finding(severity={"level": "critical"})],
        [finding(severity={"level": "critical"}), finding(severity={"level": "low"})],
        [
            finding(provenance={"source": "local_package", "previousFindings": [{"title": "older"}]}),
            finding(confidence={"level": "high", "rationale": "Reproduced."}),
        ],
        [
            finding(),
            finding(codeEvidence=[evidence("write", "open(path, 'wb')")]),
            finding(codeEvidence=[evidence("write", "open(path, 'wb')"), evidence("check", "if ok:")]),
        ],
        [finding(provenance={"source": "local_package", "previousFindings": "bad"}), finding(severity={"level": "critical"})],
        [
            finding(provenance={"source": "local_package", "previousFindings": [{"title": "shared"}]}),
            finding(
                severity={"level": "critical"},
                provenance={"source": "local_package", "previousFindings": [{"title": "shared"}]},
            ),
        ],
        [finding(), finding(identity={"anchor": "other-anchor"})],
    ],
)
def test_recover_unsealed_findings(tmp_path: Path, items: list[Any]) -> None:
    recover_findings(tmp_path, items)


@pytest.mark.parametrize(
    "items, files, directories",
    [
        ([finding(writeup={"reportPath": REPORT})], {REPORT: "# Archive\n"}, ()),
        ([finding(writeup={"reportPath": REPORT})], {}, ()),
        ([finding(writeup={"reportPath": REPORT})], {}, (REPORT,)),
        ([finding(writeup={"reportPath": "report.md"})], {"report.md": "x"}, ()),
        ([finding(writeup={})], {}, ()),
        (
            [finding(writeup={"reportPath": REPORT}), finding(identity={"anchor": "b"}, writeup={"reportPath": REPORT})],
            {REPORT: "# Archive\n"},
            (),
        ),
        (
            [finding(writeup={"reportPath": REPORT}), finding(severity={"level": "critical"}, writeup={"reportPath": REPORT})],
            {REPORT: "# Archive\n"},
            (),
        ),
        (
            [
                finding(writeup={"reportPath": REPORT}),
                finding(severity={"level": "critical"}, writeup={"reportPath": "findings/other/other.md"}),
                finding(identity={"anchor": "c"}, writeup={"reportPath": REPORT}),
            ],
            {REPORT: "# Archive\n", "findings/other/other.md": "# Other\n"},
            (),
        ),
    ],
)
def test_recover_unsealed_findings_writeups(
    tmp_path: Path, items: list[Any], files: dict[str, str], directories: tuple[str, ...]
) -> None:
    recover_findings(tmp_path, items, files, directories=directories)


def test_recover_unsealed_findings_scan_id_mismatch(tmp_path: Path) -> None:
    with pytest.raises(FINALIZER.ContractError):
        FINALIZER._recover_unsealed_findings(
            copy.deepcopy(MANIFEST), {"scanId": "other", "findings": []}, SCHEMAS, scan_dir(tmp_path), []
        )


def coverage(**extra: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "scanId": "scan_edge",
        "mode": "repository",
        "completeness": "complete",
        "inventoryStrategy": "repository",
        "surfaces": [{"id": "s1", "label": "Archive", "disposition": "reported", "receiptRefs": []}],
        "explicitExclusions": [],
        "deferred": [],
    }
    value.update(extra)
    return value


def surface(identifier: str = "s1", **extra: Any) -> dict[str, Any]:
    value: dict[str, Any] = {"id": identifier, "label": "Archive", "disposition": "reported", "receiptRefs": []}
    value.update(extra)
    return value


@pytest.mark.parametrize(
    "value, discarded",
    [
        (coverage(), []),
        (coverage(completeness="mostly"), []),
        (coverage(completeness="partial", surfaces=[surface(disposition="needs_follow_up")]), []),
        (coverage(surfaces=[surface(disposition="needs_follow_up")]), []),
        (coverage(surfaces=[surface(disposition="done")]), []),
        (coverage(surfaces=[surface(disposition=None)]), []),
        (coverage(surfaces=[surface(), surface()]), []),
        (coverage(surfaces=[surface(id="")]), []),
        (coverage(surfaces=["s1"]), []),
        (coverage(surfaces=[surface(label="")]), []),
        (coverage(surfaces=[surface(receiptRefs="artifacts/a.txt")]), []),
        (
            coverage(
                surfaces=[
                    surface(
                        receiptRefs=[
                            "artifacts/receipt.txt",
                            "./artifacts/receipt.txt",
                            "notes/receipt.txt",
                            "artifacts/missing.txt",
                            "../artifacts/receipt.txt",
                            7,
                            "artifacts/dir",
                        ]
                    )
                ]
            ),
            [],
        ),
        (coverage(surfaces=None, explicitExclusions="none", deferred={}), []),
        (coverage(explicitExclusions=[{"pattern": "vendor/", "reason": "Third party."}, {"pattern": "x"}]), []),
        (coverage(deferred=[{"id": "d1", "reason": "Later."}]), []),
        (coverage(completeness="partial", deferred=[{"id": "d1", "reason": "Later."}]), []),
        (coverage(deferred=[{"id": "d1"}]), []),
        (coverage(), ["Skipped malformed finding 1: bad."]),
        (coverage(deferred=[{"id": "d1", "reason": "Later."}]), ["Skipped malformed finding 1: bad.", "Skipped 2."]),
        (coverage(mode="deep_repository", inventoryStrategy="deep_repository_repeated_discovery"), []),
        (coverage(mode="deep_repository"), []),
        (coverage(mode="deep_repository", completeness="unknown", inventoryStrategy=None), []),
    ],
)
def test_recover_unsealed_coverage(tmp_path: Path, value: dict[str, Any], discarded: list[str]) -> None:
    directory = scan_dir(tmp_path, {"artifacts/receipt.txt": "ok\n"}, directories=("artifacts/dir",))
    FINALIZER._recover_unsealed_coverage(value, SCHEMAS, directory, [], discarded)


@pytest.mark.parametrize(
    "hardening, files, directories",
    [
        (None, {}, ()),
        ({"portfolioPath": "hardening/hardening.md"}, {"hardening/hardening.md": "# Hardening\n"}, ()),
        ({"portfolioPath": "hardening/hardening.md"}, {}, ()),
        ({"portfolioPath": "hardening/hardening.md"}, {}, ("hardening/hardening.md",)),
        ({"portfolioPath": "hardening/other.md"}, {"hardening/other.md": "x"}, ()),
        ({"portfolioPath": ""}, {}, ()),
        ("hardening/hardening.md", {}, ()),
    ],
)
def test_recover_unsealed_hardening(
    tmp_path: Path, hardening: Any, files: dict[str, str], directories: tuple[str, ...]
) -> None:
    manifest = copy.deepcopy(MANIFEST)
    if hardening is not None:
        manifest["scan"]["hardening"] = hardening
    FINALIZER._recover_unsealed_hardening(manifest, scan_dir(tmp_path, files, directories), [])


BINDING: dict[str, Any] = {
    "scanId": "scan_bound",
    "startedAt": "2026-06-01T10:00:00Z",
    "completedAt": "2026-06-01T10:30:00Z",
    "producer": {"name": "pi-security", "version": "0.2.0"},
    "allowedTargetKinds": ["git_worktree"],
    "target": {"kind": "git_worktree", "targetId": "target_bound", "snapshotDigest": "pi-security-snapshot/v1:sha256:" + "1" * 64},
    "scope": {"includePaths": ["lib/"], "excludePaths": ["lib/vendor/"]},
    "coverageMode": "scoped_path",
}


def binding(**extra: Any) -> dict[str, Any]:
    value = copy.deepcopy(BINDING)
    value.update(extra)
    return value


@pytest.mark.parametrize(
    "mutate, value, started_at",
    [
        (lambda scan: None, None, None),
        (lambda scan: None, None, "not-a-timestamp"),
        (lambda scan: None, binding(), None),
        (lambda scan: None, binding(status="interrupted"), "2026-06-01T10:00:00Z"),
        (lambda scan: scan.pop("target"), binding(), None),
        (lambda scan: scan.update(target="worktree", scope=None), binding(), None),
        (lambda scan: scan.update(scope=["src/"]), binding(), None),
        (lambda scan: scan["target"].update(kind="git_revision", baseRevision="abc"), binding(), None),
        (lambda scan: scan["target"].update(kind="git_diff", headRevision="abc"), binding(), None),
        (lambda scan: scan["target"].update(kind=7), binding(), None),
        (lambda scan: scan["target"].update(kind="unknown"), binding(), None),
        (lambda scan: None, binding(target={"kind": "git_revision", "revision": "cafe"}), None),
    ],
)
def test_populate_unsealed_manifest_envelope(
    monkeypatch: pytest.MonkeyPatch,
    mutate: Callable[[dict[str, Any]], Any],
    value: dict[str, Any] | None,
    started_at: str | None,
) -> None:
    if started_at is None:
        monkeypatch.delenv("PI_SECURITY_STARTED_AT", raising=False)
    else:
        monkeypatch.setenv("PI_SECURITY_STARTED_AT", started_at)
    manifest = copy.deepcopy(MANIFEST)
    mutate(manifest["scan"])
    try:
        FINALIZER._populate_unsealed_manifest_envelope(manifest, manifest["scan"], value)
    except FINALIZER.ContractError:
        pass


@pytest.mark.parametrize(
    "scope, value",
    [
        ({"includePaths": ["src/"], "excludePaths": []}, None),
        ({"includePaths": ["src/"], "excludePaths": []}, binding()),
        ({}, binding()),
        ({"excludePaths": ["tests/"]}, binding()),
        ({"includePaths": None, "excludePaths": None}, binding()),
    ],
)
def test_populate_unsealed_artifact_envelope(scope: dict[str, Any], value: dict[str, Any] | None) -> None:
    manifest = copy.deepcopy(MANIFEST)
    manifest["scan"]["scope"] = scope
    FINALIZER._populate_unsealed_artifact_envelope(manifest, {"findings": []}, {"mode": "repository"}, value)


@pytest.mark.parametrize(
    "open_questions",
    [
        None,
        "Is the parser reachable?",
        [],
        ["  Is the parser reachable?  ", "", "   ", 7, None],
        [chr(0x1C) + "Separator padded?" + chr(0x1F), chr(0xFEFF) + "Byte order mark kept?", chr(0x1C)],
        [{"question": chr(0x85) + "Next line padded?" + chr(0x3000), "followUpPrompt": chr(0x1D)}],
        [
            {"question": "  Who calls it? ", "followUpPrompt": "Trace callers.", "extra": 1},
            {"followUpPrompt": "first", "question": "Order kept?"},
            {"question": "Blank prompt?", "followUpPrompt": "  "},
            {"question": "Non-string prompt?", "followUpPrompt": 3},
            {"question": " "},
            {"question": 5},
            {},
            ["nested"],
        ],
    ],
)
def test_normalize_unsealed_open_questions(open_questions: Any) -> None:
    value: dict[str, Any] = {"mode": "repository"}
    if open_questions is not None:
        value["openQuestions"] = open_questions
    FINALIZER._normalize_unsealed_open_questions(value)


@pytest.mark.parametrize(
    "strategy, expected_mode",
    [
        ("deep_repository_repeated_discovery", "deep_repository"),
        ("deep_repository_repeated_discovery", "repository"),
        ("deep_repository_repeated_discovery", None),
        ("repository", "deep_repository"),
    ],
)
def test_normalize_unsealed_deep_repository_inventory_strategy(strategy: str, expected_mode: str | None) -> None:
    FINALIZER._normalize_unsealed_deep_repository_inventory_strategy(
        {"inventoryStrategy": strategy}, expected_coverage_mode=expected_mode
    )


@pytest.mark.parametrize(
    "value",
    [
        finding(),
        finding(severity={"level": "informational"}, confidence={"level": "low"}),
        finding(codeEvidence=[evidence("a", "x = 1"), evidence("b", "y = 2")]),
        finding(codeEvidence=[evidence("a", "x = 1")], rootCause={"summary": "s", "code": "x = 1"}),
        finding(codeEvidence=[evidence("a", "x = 1")], rootCause={"summary": "s", "code": "z = 3"}),
        finding(
            codeEvidence=[evidence("a", "x = 1")],
            rootCause={
                "summary": "s",
                "codeEvidence": [
                    {"id": "a", "code": "new code"},
                    {"id": "b", "code": "x = 1"},
                    {"id": "c", "code": "c = 3"},
                    {"id": " ", "code": "d = 4"},
                    {"code": "d = 4"},
                    {"id": "e", "code": " "},
                    "not an object",
                ],
                "code": "c = 3",
            },
            root_cause={"code_evidence": [{"code": "f = 5"}], "code": "g = 6"},
        ),
        finding(rootCause="a string root cause"),
    ],
)
def test_finding_strength(value: dict[str, Any]) -> None:
    FINALIZER._finding_strength(value)


@pytest.mark.parametrize(
    "items, files, directories",
    [
        ([finding(writeup={"reportPath": REPORT})], {REPORT: "x"}, ()),
        ([finding(writeup={"reportPath": REPORT})], {}, ()),
        ([finding(writeup={"reportPath": REPORT})], {}, (REPORT,)),
        ([finding(writeup={"reportPath": 5}), finding(writeup="x"), "not an object"], {}, ()),
        ([finding(writeup={"reportPath": "../outside.md"})], {}, ()),
    ],
)
def test_require_derived_writeup_files(
    tmp_path: Path, items: list[Any], files: dict[str, str], directories: tuple[str, ...]
) -> None:
    try:
        FINALIZER._require_derived_writeup_files(scan_dir(tmp_path, files, directories), {"findings": items})
    except FINALIZER.ContractError:
        pass
