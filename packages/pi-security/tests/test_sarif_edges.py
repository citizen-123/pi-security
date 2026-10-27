"""Edge cases of the finalizer's SARIF projection.

Besides checking Python behavior, these calls feed tests/parity/record_vectors.py. github_line_hashes_of and
sarif_with_source are recorded by their inputs, so the TypeScript port (src/contract/sarif.ts) is held to real-file
line hashes without the vectors depending on temporary paths.
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


def github_line_hashes_of(content: bytes, lines: list[int]) -> list[list[Any]]:
    """Hash a file holding `content` through the real source-reading path; pairs sorted by line."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory).resolve()
        (root / "source.txt").write_bytes(content)
        hashes = FINALIZER._github_line_hashes_for_source(root, "source.txt", set(lines))
    return [] if hashes is None else [[line, hashes[line]] for line in sorted(hashes)]


def sarif_with_source(manifest: dict[str, Any], findings: dict[str, Any], files: dict[str, bytes]) -> dict[str, Any]:
    """build_sarif with a source root holding `files`."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory).resolve()
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        return FINALIZER.build_sarif(manifest, findings, root)


LINES = [
    b"",
    b"one line without newline",
    b"a\nb\nc\n",
    b"  indented\twith\ttabs  \n\nnext\n",
    b"crlf\r\nline\r\n",
    b"lone\rcarriage\rreturns",
    b"\xef\xbb\xbfbom first line\n",
    b"bad \xff byte\nok\n",
    b"emoji \xf0\x9f\x94\x91 here\n",
    b"dup\ndup\ndup\n",
    b"".join(b"line %d with some text to fill the window\n" % i for i in range(250)),
]


@pytest.mark.parametrize("content", LINES)
def test_github_line_hashes(content: bytes) -> None:
    github_line_hashes_of(content, list(range(1, 260)))


def manifest(kind: str = "git_worktree", **target: Any) -> dict[str, Any]:
    return {
        "schemaVersion": "1.0",
        "scan": {
            "id": "scan_sarif",
            "producer": {"name": "pi-security", "version": "0.1.0"},
            "target": {"kind": kind, "targetId": "t", **target},
        },
    }


def finding(rule: str, occurrence: str, level: str = "high", **extra: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "ruleId": rule,
        "findingId": "csf_" + occurrence,
        "occurrenceId": "occ_" + occurrence,
        "fingerprints": {"algorithm": "pi-security/v1", "primary": "pi-security/v1:sha256:" + occurrence},
        "title": "Title " + occurrence,
        "summary": "Summary " + occurrence,
        "severity": {"level": level},
        "confidence": {"level": "medium"},
        "taxonomy": {"category": "path-traversal", "cwe": ["CWE-22"]},
        "locations": [{"path": "src/app.py", "startLine": 2}],
        "remediation": "Fix " + occurrence + ".",
    }
    value.update(extra)
    return value


SARIF_CASES: list[tuple[dict[str, Any], list[dict[str, Any]]]] = [
    (manifest(), []),
    (
        manifest("git_revision", remote="https://example.invalid/repo", revision="abc"),
        [finding("api.sql-injection_url/xss", "b"), finding("api.sql-injection_url/xss", "a", "medium")],
    ),
    (
        manifest(),
        [
            finding("r.one", "a", severity={"level": "high", "score": 8}),
            finding("r.one", "b", severity={"level": "high", "score": 8.0}),
            finding("r.two", "c", severity={"level": "high", "score": 8.0}),
            finding("r.two", "d", severity={"level": "critical"}),
            finding("r.three", "e", "informational"),
            finding("r.four", "f", severity={"level": "low", "score": 0}),
        ],
    ),
    (
        manifest(),
        [
            finding(
                "cwe.tags",
                "a",
                taxonomy={"category": "zeta_cat.one", "cwe": ["CWE-7", "cwe-0079", "CWE-1234", "CWE-0", "not-a-cwe"]},
                remediationTests=["one", "two"],
                preventiveControls="ab",
                extensions={"candidateId": "DSS-9"},
            )
        ],
    ),
    (
        manifest(),
        [
            finding(
                "evidence.locations",
                "a",
                locations=[
                    {"path": "src/first.py", "startLine": 1, "role": "sink"},
                    {"path": "src/root cause é#?.py", "startLine": 5, "endLine": 7, "role": "root_control"},
                    {"path": "src/first.py", "startLine": 1, "endLine": 1},
                    {"path": "src/it's (1)!*~.py", "startLine": 9},
                ],
                codeEvidence=[
                    {"id": "E1", "path": "src/ev.py", "startLine": 3, "endLine": 2},
                    {"id": "E1", "path": "src/ignored-duplicate-id.py", "startLine": 1},
                    {"id": "E2", "path": "../escape.py", "startLine": 1},
                    {"id": "E3", "path": "src/ev.py", "startLine": True},
                    {"id": "E4", "path": "src/ev.py", "startLine": 0},
                    {"id": "", "path": "src/no-id.py", "startLine": 1},
                    {"id": "E5", "path": "src/./ev2.py", "startLine": 4, "endLine": 9},
                    "not an object",
                ],
                code_evidence=[{"id": "E6", "path": "src/snake.py", "startLine": 8}],
            )
        ],
    ),
]


@pytest.mark.parametrize("manifest_value, findings_value", SARIF_CASES)
def test_build_sarif(manifest_value: dict[str, Any], findings_value: list[dict[str, Any]]) -> None:
    FINALIZER.build_sarif(copy.deepcopy(manifest_value), {"findings": copy.deepcopy(findings_value)})


@pytest.mark.parametrize(
    "files",
    [
        {"src/app.py": b"line one\nline two\nline three\n"},
        {"src/app.py": b"line one\r\nline two\r\n"},
        {},
        {"src/other.py": b"x\n"},
    ],
)
def test_build_sarif_with_source(files: dict[str, bytes]) -> None:
    findings = {"findings": [finding("r.one", "a"), finding("r.one", "b", locations=[{"path": "src/app.py", "startLine": 3}])]}
    sarif_with_source(manifest(), findings, files)


@pytest.mark.parametrize(
    "value",
    ["sql-injection", "api_url.xss/csrf", "  spaced  out  ", "", "élan vital", "x" + chr(0x1C) + "y", "ID", "html.HTTP"],
)
def test_sarif_label(value: str) -> None:
    FINALIZER._sarif_label(value)


@pytest.mark.parametrize(
    "value",
    ["src/a.py", "./src//a.py", "src/a.py/", ".", "", " ", "/abs", "../up", "a/../b", "C:x", "é:x", "a\\b", "a\x01b", "con.txt", "a/nul", "x.", "x ", "dir/com" + chr(0xB9)],
)
def test_relative_paths(value: str) -> None:
    for check in (FINALIZER._require_safe_relative_path, FINALIZER._require_portable_relative_path):
        try:
            check(value, "p")
        except FINALIZER.ContractError:
            pass
