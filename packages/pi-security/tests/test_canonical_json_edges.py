"""Edge cases of canonical contract JSON in the finalizer.

Besides checking Python behavior, these calls feed tests/parity/record_vectors.py, which records them as vectors the
TypeScript port (src/contract/canonical-json.ts) must reproduce byte for byte.
"""

from __future__ import annotations

import importlib.util
import math
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
LONE_SURROGATE = chr(0xDCFF)
TEXT = (
    "ascii "
    + "".join(chr(code) for code in range(0x20))
    + chr(0x7F)
    + ' "quotes" \\backslash '
    + chr(0xE9)
    + chr(0x2028)
    + chr(0x65E5)
    + chr(0x1F511)
)

PAYLOADS: list[Any] = [
    {"floats": [7.0, -0.0, 0.0, 1e16, 1e15, 1e-05, 0.0001, 5e-324, 1.7976931348623157e308, 0.1 + 0.2, 2.5, -3.75]},
    {"ints": [0, -1, 2**53 - 1, -(2**53 - 1), 9007199254740993]},
    {"text": TEXT, TEXT: "key"},
    {"surrogate": "bad" + LONE_SURROGATE},
    {"nested": {"empty_list": [], "empty_object": {}, "list": [[], [{}], [1, [2, [3]]]]}},
    {chr(0x1F600): 1, chr(0xFF5E): 2, "z": 3, "A": 4, "": 5},
    [True, False, None, "x"],
    "top-level string",
    42,
]


@pytest.mark.parametrize("payload", PAYLOADS)
def test_json_bytes(payload: Any) -> None:
    encoded = FINALIZER._json_bytes(payload)
    assert encoded.endswith(b"\n")
    assert all(byte < 0x80 for byte in encoded)


@pytest.mark.parametrize("payload", [{"value": math.nan}, {"value": math.inf}, [-math.inf]])
def test_json_bytes_rejects_non_finite(payload: Any) -> None:
    with pytest.raises(FINALIZER.ContractError, match="cannot encode canonical JSON"):
        FINALIZER._json_bytes(payload)


@pytest.mark.parametrize(
    "payload, message",
    [
        ({"ok": [1, 2.5, "text", None, True]}, None),
        ({"value": 2**53 - 1}, None),
        ({"value": 2**53}, "doc.<property>: unsafe integer-valued JSON numbers are not supported"),
        ({"value": [-(2**53)]}, "doc.<property>[0]: unsafe integer-valued JSON numbers are not supported"),
        ({"value": 9007199254740992.0}, "doc.<property>: unsafe integer-valued JSON numbers are not supported"),
        ({"value": 9007199254740991.0}, None),
        ({"value": 1e300}, "doc.<property>: unsafe integer-valued JSON numbers are not supported"),
        ({"value": 1.5e300}, "doc.<property>: unsafe integer-valued JSON numbers are not supported"),
        ({"text": "bad" + LONE_SURROGATE}, "doc.<property>: expected well-formed Unicode JSON strings"),
        ({"bad" + LONE_SURROGATE: 1}, "doc: expected well-formed Unicode JSON strings"),
        ([{"deep": [["bad" + LONE_SURROGATE]]}], "doc[0].<property>[0][0]: expected well-formed Unicode JSON strings"),
    ],
)
def test_require_safe_json_value(payload: Any, message: str | None) -> None:
    if message is None:
        FINALIZER._require_safe_json_value(payload, "doc")
    else:
        with pytest.raises(FINALIZER.ContractError) as raised:
            FINALIZER._require_safe_json_value(payload, "doc")
        assert str(raised.value) == message


def test_require_safe_json_value_can_skip_strings() -> None:
    FINALIZER._require_safe_json_value({"text": "bad" + LONE_SURROGATE}, "doc", validate_strings=False)


@pytest.mark.parametrize(
    "text",
    [
        '{"a": 1, "b": 1.0, "c": -0, "d": 1e2, "e": 1E-3, "f": 2.50}',
        '{"dup": 1, "dup": 2}',
        '["\\udcff", "\\ud83d\\ude00", "\\u00e9"]',
        '{"big": 123456789012345678901234567890}',
        '  [1, 2]  ',
    ],
)
def test_loads_json(text: str) -> None:
    FINALIZER._loads_json(text)


@pytest.mark.parametrize("text", ['{"a": NaN}', "[Infinity]", "-Infinity", "{bad}", "[1,]"])
def test_loads_json_rejects(text: str) -> None:
    with pytest.raises(ValueError):
        FINALIZER._loads_json(text)
