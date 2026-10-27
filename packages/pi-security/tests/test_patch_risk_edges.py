"""Edge cases of the patch-risk assessment validator.

Besides checking Python behavior, these calls feed tests/parity/record_vectors.py, which records them as vectors the
TypeScript port (src/contract/patch-risk.ts) must reproduce, error messages included.
"""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

import pytest

from test_patch_risk_contract import assessment


def load_validator() -> ModuleType:
    path = Path(__file__).resolve().parent.parent / "skills" / "assess-patch-risk" / "scripts" / "validate_patch_risk_assessment.py"
    spec = importlib.util.spec_from_file_location("validate_patch_risk_assessment", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VALIDATOR = load_validator()


def read_assessment_text(text: str, tmp_path: Path) -> Any:
    """read_object on a file holding `text`; a ValueError comes back as its message so vectors compare it."""
    path = tmp_path / "assessment.json"
    path.write_bytes(text.encode("utf-8", "surrogatepass"))
    try:
        return VALIDATOR.read_object(str(path))
    except ValueError as error:
        return {"error": str(error)}


@pytest.mark.parametrize(
    "text",
    [
        '{"a": 1}',
        '{"a": 1, "a": 2}',
        '{"outer": {"k": 1, "k": 2}, "x": [}',
        '{"x": [}, "a": 1, "a": 2',
        "[]",
        '"text"',
        "",
        "{\r\n  \"a\": 1,\r\n  \"b\": ]\r\n}",
        "{\r  \"a\": tru\r}",
        chr(0xFEFF) + "{}",
        '{"a": NaN, "b": -Infinity}',
        '{"a": 1.0, "b": 10000000000000000000000}',
        '{"a": "\\ud800"}',
    ],
)
def test_read_object(text: str, tmp_path: Path) -> None:
    read_assessment_text(text, tmp_path)


def change(edit: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    value = assessment()
    edit(value)
    return value


def auto(edit: Callable[[dict[str, Any]], None] = lambda value: None) -> dict[str, Any]:
    def apply(value: dict[str, Any]) -> None:
        value["workflowLabel"] = "auto_merge_candidate"
        value["impact"]["rating"] = "low"
        edit(value)

    return change(apply)


def setting(path: str, item: Any) -> Callable[[dict[str, Any]], None]:
    def edit(value: dict[str, Any]) -> None:
        *parents, last = path.split(".")
        target = value
        for parent in parents:
            target = target[parent]
        target[last] = item

    return edit


UNKNOWN = {"summary": "Ownership is unresolved.", "decisionCritical": True}
MINOR_UNKNOWN = {"summary": "A log line may change.", "decisionCritical": False}
PLAN = [{"question": "Who owns it?", "action": "Read the mapping.", "outcomes": {"supported": "merge", "contradicted": "no_op", "unavailable": "hold_for_evidence"}}]
FAILED = [{"name": "unit tests", "status": "failed", "protects": "The caller."}]


def recommend(recommendation: str, label: str | None = None, **fields: Any) -> dict[str, Any]:
    value = assessment()
    value["recommendation"] = recommendation
    value["workflowLabel"] = label or recommendation
    value.update(copy.deepcopy(fields))
    return value


@pytest.mark.parametrize(
    "value",
    [
        assessment(),
        auto(),
        change(setting("schemaVersion", 2)),
        change(lambda value: value.pop("unknowns")),
        change(setting("extra", True)),
        change(setting("patch.sourceType", "worktree")),
        change(setting("confidence.rating", "medium")),
        change(setting("workflowLabel", "hold_for_evidence")),
        change(setting("applicability.status", "unknown")),
        change(setting("unknowns", [UNKNOWN, MINOR_UNKNOWN])),
        change(setting("unknowns", [MINOR_UNKNOWN])),
        change(lambda value: value["materialBoundaries"][0].update(result="unresolved")),
        change(lambda value: value["materialBoundaries"][0].update(result="contradicted")),
        change(setting("validation", FAILED)),
        change(setting("evidencePlan", PLAN)),
        recommend("hold_for_evidence"),
        recommend("hold_for_evidence", unknowns=[UNKNOWN], evidencePlan=PLAN),
        recommend("hold_for_evidence", unknowns=[UNKNOWN], evidencePlan=PLAN, validation=FAILED),
        recommend("hold_for_evidence", "merge", unknowns=[UNKNOWN], evidencePlan=PLAN),
        recommend("no_op"),
        recommend("no_op", applicability={"status": "duplicate", "rationale": "Same as another patch."}),
        recommend("no_op", applicability={"status": "wrong_owner", "rationale": "Another team."}, unknowns=[UNKNOWN]),
        change(setting("applicability", {"status": "superseded", "rationale": "Replaced."})),
        recommend("revise"),
        recommend("revise", validation=FAILED),
        recommend("revise", materialBoundaries=[{**assessment()["materialBoundaries"][0], "result": "contradicted"}]),
        recommend("block", regressionLikelihood={"rating": "critical", "rationale": "Breaks callers."}),
        recommend("block", "revise", validation=FAILED),
        auto(setting("impact.rating", "moderate")),
        auto(setting("regressionLikelihood.rating", "moderate")),
        auto(setting("regressionProtection.rating", "partial")),
        auto(setting("regressionProtection.exactHeadChecksPassed", False)),
        auto(setting("recoverability.rating", "managed")),
        auto(setting("confidence.rating", "moderate")),
        auto(setting("applicability.status", "unknown")),
        auto(setting("affectedRuntimeRoots", [])),
        auto(setting("statusQuoRisk.rating", "unknown")),
        auto(setting("autoMergeExclusions", ["public_contract"])),
        auto(setting("unknowns", [MINOR_UNKNOWN])),
        auto(setting("validation", [{"name": "smoke", "status": "skipped", "protects": "Startup."}])),
        auto(lambda value: value.update(impact={"rating": "high", "rationale": "Wide."}, confidence={"rating": "low", "rationale": "Guess."}, unknowns=[UNKNOWN])),
    ],
)
def test_validate(value: dict[str, Any]) -> None:
    VALIDATOR.validate(copy.deepcopy(value))
