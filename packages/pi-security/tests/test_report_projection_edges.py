"""Edge cases of the Markdown report projection.

Besides checking Python behavior, these calls feed tests/parity/record_vectors.py, which records them as vectors the
TypeScript port (src/contract/report-projection.ts) must reproduce byte for byte.
"""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

import pytest


def load_projection() -> ModuleType:
    path = Path(__file__).resolve().parent.parent / "scripts" / "report_projection.py"
    spec = importlib.util.spec_from_file_location("report_projection", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROJECTION = load_projection()
FS, NEL, BOM, ARABIC_THREE = chr(0x1C), chr(0x85), chr(0xFEFF), chr(0x663)


def finding(occurrence: str = "occ_1", **extra: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "occurrenceId": occurrence,
        "title": "Parser boundary",
        "summary": "Input reaches the parser.",
        "severity": {"level": "high"},
        "confidence": {"level": "high", "rationale": "Direct trace."},
        "taxonomy": {"category": "parser", "cwe": ["CWE-20"]},
        "locations": [{"path": "src/parser.py", "startLine": 10}],
        "remediation": "Bound the input.",
    }
    value.update(extra)
    return value


def evidence(identifier: Any, code: str, **extra: Any) -> dict[str, Any]:
    value: dict[str, Any] = {"id": identifier, "label": "Read", "path": "src/parser.py", "startLine": 10, "code": code}
    value.update(extra)
    return value


def documents(
    findings: list[dict[str, Any]], coverage: dict[str, Any] | None = None, scan: dict[str, Any] | None = None
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    manifest_scan: dict[str, Any] = {
        "target": {"displayName": "example/repo", "kind": "git_worktree", "targetId": "target_example"},
        "scope": {"includePaths": ["src/"], "excludePaths": []},
    }
    manifest_scan.update(scan or {})
    base_coverage: dict[str, Any] = {
        "mode": "repository",
        "inventoryStrategy": "repository",
        "completeness": "complete",
        "surfaces": [],
        "explicitExclusions": [],
        "deferred": [],
    }
    base_coverage.update(coverage or {})
    return {"scan": manifest_scan}, {"findings": copy.deepcopy(findings)}, base_coverage


CASES: dict[str, tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = {
    "python whitespace collapses": documents(
        [finding(title=f"Parser{FS}boundary{NEL}split", summary=f"Ends with a byte order mark{BOM}")]
    ),
    "unicode digits start an ordered list": documents([finding(summary=f"{ARABIC_THREE}. first step")]),
    "non-string values in f-strings": documents(
        [
            finding(
                confidence={"level": "high", "rationale": None},
                locations=[{"path": 5, "startLine": True, "endLine": 1}, {"path": "src/b.py", "startLine": 2, "endLine": None}],
            )
        ],
        coverage={
            "surfaces": [
                {"id": "s1", "label": "Parser", "disposition": "reported", "notes": None, "receiptRefs": ["artifacts/r.txt"]},
                {"id": "s2", "disposition": "custom_state", "riskArea": 7, "receiptRefs": [3]},
                "not a surface",
            ]
        },
    ),
    "code evidence locations": documents(
        [
            finding(
                codeEvidence=[
                    evidence("a", "first()", startLine=True),
                    evidence("b", "second()", startLine="10"),
                    evidence("c", "third()", location="src/parser.py:40"),
                    evidence("d", "fourth()", location={"path": "src/other.py", "startLine": 3, "endLine": 5}),
                    evidence("e", "fifth()", path=""),
                ],
                rootCause={"summary": "Unbounded read.", "evidenceRefs": ["a", "b", "c", "d", "e", "a", "missing"]},
            )
        ]
    ),
    "code fences and languages": documents(
        [
            finding(
                codeEvidence=[
                    evidence("a", "x = '```'\ny = '````'", language="python"),
                    evidence("b", "plain", language="c++; rm"),
                    evidence("c", "typed", language=["ts"]),
                ],
                validation={"summary": "Checked.", "evidenceRefs": "a", "codeEvidence": [evidence("b", "plain", language="c++; rm")]},
            )
        ]
    ),
    "legacy root cause code": documents(
        [
            finding(
                codeEvidence=[evidence("a", "read(buffer)")],
                rootCause={"summary": "Same code.", "evidenceRefs": ["a"], "code": "read(buffer)"},
            ),
            finding(
                "occ_2",
                locations=[{"path": "src/a.py", "startLine": 1}, {"path": "src/root.py", "startLine": 7, "endLine": 9, "role": "root_control"}],
                rootCause={"summary": "Different code.", "code": "check(size)", "language": "c"},
            ),
        ]
    ),
    "merged root causes": documents(
        [
            finding(
                rootCause={"summary": "  ", "code": "a()", "references": [], "evidenceRefs": "x"},
                root_cause={"summary": "From snake case.", "code": "b()", "language": "go", "references": ["r"], "evidence_refs": ["x", "y"]},
                codeEvidence=[evidence("x", "x()"), evidence("y", "y()")],
            ),
            finding("occ_2", rootCause="Only a string.", root_cause={"code": "z()", "language": "rust"}),
            finding("occ_3", rootCause=None, root_cause=7),
        ]
    ),
    "ordering by occurrence and title": documents(
        [
            finding("occ_b", title="Alpha"),
            finding("occ_a", title="Beta"),
            finding("occ_a", title="Aardvark", severity={"level": "critical"}),
            finding("occ_c", severity={"level": "informational"}),
        ]
    ),
    "attack path details": documents(
        [
            finding(
                attackPath={
                    "summary": "Reachable from the upload endpoint.",
                    "reachability": {"summary": "Public.", "attacker": 5, "entrypoint": "POST /upload", "sink": "", "preconditions": ["Logged in", "Logged in"]},
                    "preconditions": "Logged in",
                    "dataFlow": "Body to parser.",
                    "data_flow": {"source": "request body", "transformations": ["decode", "decode", " "], "sink": "parse()"},
                    "dataflow": {"transformations": "decode"},
                    "steps": ["Upload", ""],
                    "impact": {"level": "high", "why": "Crash."},
                    "likelihood": "Likely.",
                    "controls": ["Size limit"],
                },
                validation={"method": 0, "status": "confirmed", "assertions": ["Crashes"], "limitations": "No fuzzing."},
            )
        ]
    ),
    "revision ranges": documents([], scan={"target": {"displayName": "example/repo", "headRevision": "abc123"}}),
    "deferred follow-up prompts": documents(
        [],
        coverage={
            "completeness": "partial",
            "deferred": [
                {"id": "d1", "reason": "Needs runtime proof.", "paths": "src/", "surfaceIds": ["s1", "s2"]},
                {"reason": "Validation was deferred because the scan reached its cost limit: 3 candidates."},
                {"id": 4},
                "not an item",
            ],
            "openQuestions": ["skipped string", {"question": f"Trailing mark{BOM}", "followUpPrompt": "  "}],
        },
    ),
    # Python's rstrip keeps a final byte order mark; it is not whitespace there.
    "final line ends with a byte order mark": documents([], coverage={"openQuestions": [{"question": f"Last{BOM}"}]}),
    "time limit with no review": documents(
        [],
        coverage={
            "completeness": "partial",
            "deferred": [{"id": "t", "reason": "The configured discovery time limit elapsed before any source review completed."}],
        },
    ),
    "deep groups": documents(
        [
            finding("occ_1", title="Overflow [R-1]", severity={"level": "low"}, extensions={"candidateId": "DSS-1", "reportId": "R-1"}),
            finding("occ_2", title="Overflow [R-1; second]", confidence={"level": "low", "rationale": "Weak."}, extensions={"candidateId": "DSS-1", "reportId": "R-1"}, identity={"instance": "second-site"}),
            finding("occ_3", title="Overflow [R-1; second]", extensions={"candidateId": "DSS-1", "reportId": "R-1"}, identity={"instance": 0}),
            finding("occ_4", title="Leak [L-9]", extensions={"candidateId": "DSS-2", "ledgerRowId": "L-9"}),
            finding("occ_5", title="Other [unrelated]", extensions={"reportId": "R-5"}, writeup={"reportPath": "findings/other/other.md"}),
        ],
        coverage={"mode": "scoped_path"},
    ),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_build_report_markdown(name: str) -> None:
    PROJECTION.build_report_markdown(*copy.deepcopy(CASES[name]))


@pytest.mark.parametrize(
    "value",
    [
        {},
        {"rootCause": "text"},
        {"root_cause": 5},
        {"rootCause": None, "root_cause": None},
        {"rootCause": {"summary": "", "references": []}, "root_cause": {"summary": "b", "references": ["x"], "notes": {}}},
        {"rootCause": {"why": " ", "extra": None, "empty": {}}, "root_cause": {"why": "because", "extra": 0, "empty": {"a": 1}}},
        {"rootCause": {"evidence_refs": "a", "codeEvidence": [1]}, "root_cause": {"evidenceRefs": ["a", 2, "b"], "code_evidence": "x"}},
        {"rootCause": {"code": "a", "language": "c"}, "root_cause": {"code": "b", "language": "go"}},
        {"rootCause": {"code": " ", "language": " "}, "root_cause": {"language": "go"}},
    ],
)
def test_merged_root_cause(value: dict[str, Any]) -> None:
    PROJECTION.merged_root_cause(copy.deepcopy(value))


def mutate(change: Callable[[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]], None]) -> tuple[Any, ...]:
    value = copy.deepcopy(CASES["ordering by occurrence and title"])
    change(value)
    return value


@pytest.mark.parametrize(
    "value",
    [
        mutate(lambda docs: docs[0]["scan"].pop("target")),
        mutate(lambda docs: docs[2].pop("inventoryStrategy")),
        mutate(lambda docs: docs[1]["findings"][0].pop("title")),
        mutate(lambda docs: docs[1]["findings"][0]["confidence"].pop("rationale")),
    ],
)
def test_build_report_markdown_missing_keys(value: tuple[Any, ...]) -> None:
    with pytest.raises((KeyError, TypeError)):
        PROJECTION.build_report_markdown(*value)
