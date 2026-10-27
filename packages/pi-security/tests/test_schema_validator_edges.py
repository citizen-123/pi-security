"""Edge cases of the finalizer's JSON Schema subset and RFC 3339 check.

Besides checking Python behavior, these calls feed tests/parity/record_vectors.py, which records them as vectors the
TypeScript port (src/contract/schema.ts) must reproduce, including error messages.
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
SCHEMAS = Path(__file__).resolve().parent.parent / "schemas"
CR = chr(13)
LF = chr(10)
FILE_SEPARATOR = chr(0x1C)
ZERO_WIDTH_NO_BREAK = chr(0xFEFF)
EMOJI = chr(0x1F511)

CASES: list[tuple[Any, dict[str, Any]]] = [
    # Python's "." matches CR but not LF; "$" also matches before a final LF.
    ("a" + CR + "b", {"type": "string", "pattern": "^a.b$"}),
    ("a" + LF + "b", {"type": "string", "pattern": "^a.b$"}),
    ("ab" + LF, {"type": "string", "pattern": "^ab$"}),
    ("ab" + LF, {"type": "string", "pattern": "^(?!.*b$).*" + LF}),
    ("x/", {"type": "string", "pattern": "^(?!.*/$).+$"}),
    # re.fullmatch: an unanchored pattern must still match the whole string.
    ("text", {"type": "string", "pattern": "\\S"}),
    ("t", {"type": "string", "pattern": "\\S"}),
    (FILE_SEPARATOR, {"type": "string", "pattern": "\\S"}),
    (ZERO_WIDTH_NO_BREAK, {"type": "string", "pattern": "\\S"}),
    ("  cwe-0079 ", {"type": "string", "pattern": "^\\s*[Cc][Ww][Ee]-0*[1-9][0-9]*\\s*$"}),
    (FILE_SEPARATOR + "CWE-79", {"type": "string", "pattern": "^\\s*[Cc][Ww][Ee]-0*[1-9][0-9]*\\s*$"}),
    ("findings/a-b/a-b.md", {"type": "string", "pattern": "^findings/([a-z0-9][a-z0-9._-]*)/\\1\\.md$"}),
    ("findings/a-b/a-c.md", {"type": "string", "pattern": "^findings/([a-z0-9][a-z0-9._-]*)/\\1\\.md$"}),
    ("com" + chr(0xB9) + ".txt", {"type": "string", "pattern": "^(?![Cc][Oo][Mm][1-9\\u00b9\\u00b2\\u00b3])[^/]+$"}),
    # minLength counts code points.
    (EMOJI, {"type": "string", "minLength": 2}),
    (EMOJI + EMOJI, {"type": "string", "minLength": 2}),
    ("", {"type": "string", "minLength": 0}),
    # int and float: 7.0 is a number but not an integer, yet equals 7 for const and enum.
    (7.0, {"type": "integer"}),
    (7, {"type": "integer"}),
    (7.0, {"type": "number", "const": 7}),
    (7, {"enum": [7.0, "x"]}),
    (True, {"enum": [1]}),
    (True, {"type": "integer"}),
    (1, {"const": True}),
    ({"a": [1, 2.0]}, {"const": {"a": [1.0, 2]}}),
    ({"a": 1, "b": 2}, {"const": {"b": 2, "a": 1}}),
    ({"a": 1}, {"const": {"a": 1, "b": 2}}),
    ([1, 1.0], {"type": "array", "uniqueItems": True}),
    ([1, True], {"type": "array", "uniqueItems": True}),
    (2.5, {"minimum": 2.5, "maximum": 3}),
    (2.4999, {"minimum": 2.5}),
    (9007199254740993, {"maximum": 9007199254740992.0}),
    (None, {"type": ["string", "null"]}),
    (3, {"type": ["string", "null"]}),
    ("x", {"const": "y"}),
    ({"k": [1, {"z": None}]}, {"enum": ["a"]}),
    # Arrays.
    ([], {"type": "array", "minItems": 1}),
    ([1, 2, 3], {"type": "array", "maxItems": 2}),
    ([1, "a", "b"], {"type": "array", "contains": {"type": "string"}, "minContains": 2, "maxContains": 2}),
    ([1, 2], {"type": "array", "contains": {"type": "string"}}),
    (["a", "b", "c"], {"type": "array", "contains": {"type": "string"}, "maxContains": 2}),
    ([1, "x"], {"type": "array", "items": {"type": "integer"}}),
    # Objects, if/then, allOf (objects only), keywords Python ignores.
    ({"kind": "a"}, {"type": "object", "if": {"properties": {"kind": {"const": "a"}}}, "then": {"required": ["extra"]}}),
    ({"kind": "b"}, {"type": "object", "if": {"properties": {"kind": {"const": "a"}}}, "then": {"required": ["extra"]}}),
    ("not an object", {"allOf": [{"required": ["x"]}]}),
    ({}, {"allOf": [{"required": ["x"]}]}),
    ("anything", {"anyOf": [{"type": "integer"}], "oneOf": [{"type": "integer"}], "maxLength": 1}),
    ({"a": 1}, {"type": "object", "minProperties": 2}),
    ({"a": 1, "b": "x"}, {"type": "object", "properties": {"a": {"type": "integer"}}, "additionalProperties": False}),
    ({"a": 1, "b": "x"}, {"type": "object", "properties": {"a": {"type": "integer"}}, "additionalProperties": {"type": "integer"}}),
    ({"__proto__": 1}, {"type": "object", "additionalProperties": False}),
    # References.
    (5, {"$defs": {"a/b": {"type": "string"}, "c~d": {"type": "integer"}}, "$ref": "#/$defs/c~0d"}),
    (5, {"$defs": {"a/b": {"type": "string"}}, "$ref": "#/$defs/a~1b"}),
    (5, {"$ref": "#/$defs/missing"}),
    (5, {"$ref": "other.json#/x"}),
    (5, {"$defs": {"x": 1}, "$ref": "#/$defs/x"}),
    ({"n": {"n": None}}, {"type": "object", "properties": {"n": {"$ref": "#"}}, "additionalProperties": False}),
    # date-time format.
    ("2026-05-31T18:00:00Z", {"type": "string", "format": "date-time"}),
    ("2026-02-29T00:00:00Z", {"type": "string", "format": "date-time"}),
]


@pytest.mark.parametrize("value, schema", CASES)
def test_validate_schema_node(value: Any, schema: dict[str, Any]) -> None:
    try:
        FINALIZER._validate_schema_node(value, schema, "doc")
    except FINALIZER.ContractError:
        pass


@pytest.mark.parametrize(
    "value",
    [
        "2026-05-31T18:00:00Z",
        "2026-05-31t18:00:00z",
        "2026-05-31T18:00:00.123456789123Z",
        "2024-02-29T00:00:00Z",
        "2000-02-29T00:00:00Z",
        "1900-02-29T00:00:00Z",
        "2026-02-29T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "2026-05-31T24:00:00Z",
        "2026-05-31T23:59:60Z",
        "2026-05-31T18:60:00Z",
        "0000-01-01T00:00:00Z",
        "0001-01-01T00:00:00Z",
        "9999-12-31T23:59:59+23:59",
        "2026-05-31T18:00:00+24:00",
        "2026-05-31T18:00:00-24:00",
        "2026-05-31T18:00:00+05:60",
        "2026-05-31T18:00:00+05:99",
        "2026-05-31T18:00:00+23:60",
        "2026-05-31T18:00:00-00:00",
        "2026-05-31T18:00:00",
        "2026-05-31T18:00:00.Z",
        chr(0x0662) + chr(0x0660) + chr(0x0662) + chr(0x0666) + "-05-31T18:00:00Z",
        "2026-05-31T18:00:00Z" + LF,
    ],
)
def test_validate_date_time(value: str) -> None:
    try:
        FINALIZER._validate_date_time(value, "doc.at")
    except FINALIZER.ContractError:
        pass


@pytest.mark.parametrize(
    "schema_name, payload",
    [
        ("coverage.schema.json", {"documentType": "pi-security.coverage"}),
        ("coverage.schema.json", []),
        ("findings.schema.json", {"documentType": "pi-security.findings", "schemaVersion": "1.0", "scanId": "s", "findings": []}),
    ],
)
def test_validate_against_schema(schema_name: str, payload: Any) -> None:
    try:
        FINALIZER.validate_against_schema(payload, SCHEMAS / schema_name)
    except FINALIZER.ContractError:
        pass
