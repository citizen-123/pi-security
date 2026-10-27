#!/usr/bin/env python3
"""Record input/output vectors of pure Python functions while the existing pytest suite runs.

The suite already exercises far more edge cases of report rendering, SARIF, fingerprints, stable IDs, and canonical
JSON than the curated cases do. This script runs it in-process with a sys.monitoring tool attached to
the functions in TARGETS, captures each call's arguments (at entry, before any mutation) and its return value or
raised error, and writes deduplicated vectors to tests/parity/vectors/<module>.<function>.jsonl. TypeScript ports of
these functions must reproduce every vector.

Calls are matched by code object (file and qualified name), so modules the tests load repeatedly through
importlib are all observed. Calls whose arguments are not JSON-representable, or that mention a temporary path,
are skipped because they would not be reproducible.

Requires Python 3.12+ and the packages in requirements-test.txt.

Usage: record_vectors.py [--check] [PYTEST_ARGS...]
  By default the test modules in SOURCE_TESTS run; vectors are only written from a passing run.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import shutil
import sys
import tempfile
import threading
from datetime import date
from pathlib import Path, PurePath
from typing import Any

PARITY_DIR = Path(__file__).resolve().parent
PACKAGE_ROOT = PARITY_DIR.parent.parent
VECTORS_DIR = PARITY_DIR / "vectors"
SCRIPTS = PACKAGE_ROOT / "scripts"

# (script file, qualified name). Arguments are recorded under the function's own parameter names.
TARGETS: set[tuple[str, str]] = {
    ("report_projection.py", "build_report_markdown"),
    ("finalize_scan_contract.py", "build_sarif"),
    ("finalize_scan_contract.py", "_fingerprint"),
    ("finalize_scan_contract.py", "_stable_id"),
    ("finalize_scan_contract.py", "_derived_finding_identity_rows"),
    ("finalize_scan_contract.py", "_json_bytes"),
    ("finalize_scan_contract.py", "_loads_json"),
    ("finalize_scan_contract.py", "_require_safe_json_value"),
    ("finalize_scan_contract.py", "validate_against_schema"),
    ("finalize_scan_contract.py", "_validate_schema_node"),
    ("finalize_scan_contract.py", "_validate_date_time"),
    ("finalize_scan_contract.py", "_sarif_label"),
    ("finalize_scan_contract.py", "csv_cell"),
    ("finalize_scan_contract.py", "finding_candidate_id"),
    ("finalize_scan_contract.py", "build_csv_projection"),
    ("finalize_scan_contract.py", "_require_safe_relative_path"),
    ("finalize_scan_contract.py", "_require_portable_relative_path"),
    # Test-module wrappers that take file contents instead of temporary paths.
    ("test_sarif_edges.py", "github_line_hashes_of"),
    ("test_sarif_edges.py", "sarif_with_source"),
}
# Calls to record, by a predicate on the call's arguments. The validator recurses with root_schema set; only the
# outermost calls are vectors.
TARGET_FILTERS = {
    ("finalize_scan_contract.py", "_validate_schema_node"): lambda arguments: arguments.get("root_schema") is None,
}
# CSV export and candidate merging are reached only through subprocesses in the suite; the curated cases cover them.
TARGET_FILES = {
    str((PACKAGE_ROOT / "tests" if file.startswith("test_") else SCRIPTS) / file) for file, _ in TARGETS
}

# Only calls made from these test modules are recorded: they use fixed fixtures. Workbench-flow tests reach the
# same functions with wall-clock timestamps and random UUIDs, which would make vectors unreproducible.
SOURCE_TESTS = {
    "test_finalize_scan_contract.py",
    "test_finding_identity_edges.py",
    "test_canonical_json_edges.py",
    "test_schema_validator_edges.py",
    "test_sarif_edges.py",
    "test_csv_export_edges.py",
    "test_report_projection.py",
    "test_sarif_projection.py",
    "test_scan_contract_examples.py",
    "test_validate_scan_contract.py",
    "test_portable_artifact_paths.py",
}
TESTS_DIR = PACKAGE_ROOT / "tests"
# Size-limit tests build multi-megabyte documents; they check limits, not rendering, and would bloat the repository.
MAX_VECTOR_BYTES = 256 * 1024
UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
TOOL_ID = 4


class Unrepresentable(Exception):
    pass


def encode(value: Any) -> Any:
    """JSON form of a value; bytes become {"$bytes": base64}. Raises Unrepresentable otherwise."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise Unrepresentable("non-finite float")
        return value
    if isinstance(value, bytes):
        return {"$bytes": base64.b64encode(value).decode("ascii")}
    if isinstance(value, PurePath):
        # Package files are recorded relative to the package root, so vectors do not depend on the checkout path.
        try:
            return {"$path": Path(value).resolve().relative_to(PACKAGE_ROOT).as_posix()}
        except ValueError:
            raise Unrepresentable("path outside the package") from None
    # Exact types only: iterating a test's instrumented subclass would change what the test observes.
    if type(value) in (list, tuple):
        return [encode(item) for item in value]
    if type(value) is dict:
        if not all(isinstance(key, str) for key in value):
            raise Unrepresentable("non-string key")
        if "$bytes" in value or "$path" in value:
            raise Unrepresentable("reserved key")
        return {key: encode(item) for key, item in value.items()}
    raise Unrepresentable(type(value).__name__)


class Recorder:
    def __init__(self) -> None:
        self.stacks = threading.local()
        self.vectors: dict[str, dict[str, Any]] = {}
        self.skipped: dict[str, int] = {}
        self.temp_markers = [tempfile.gettempdir(), "/private/var/folders", "pytest-of-"]
        self.failures: list[str] = []
        self.today = date.today().isoformat()

    def target(self, code: Any) -> tuple[str, ...] | None:
        """Parameter names of a target function's code object, or None for any other code."""
        if code.co_filename not in TARGET_FILES or (Path(code.co_filename).name, code.co_qualname) not in TARGETS:
            return None
        count = code.co_argcount + code.co_kwonlyargcount
        count += bool(code.co_flags & 0x04) + bool(code.co_flags & 0x08)  # *args, **kwargs
        return code.co_varnames[:count]

    def stack(self) -> list[Any]:
        if not hasattr(self.stacks, "items"):
            self.stacks.items = []
        return self.stacks.items

    # Callbacks must never raise: an exception would propagate into the code under test.
    def on_start(self, code: Any, offset: int) -> Any:
        try:
            return self._start(code, sys._getframe(1))
        except Exception as error:  # noqa: BLE001
            self.failures.append(f"start {code.co_qualname}: {error!r}")
            return None

    def _start(self, code: Any, frame: Any) -> Any:
        params = self.target(code)
        if params is None:
            return sys.monitoring.DISABLE
        try:
            caller = frame.f_back
            while caller is not None and Path(caller.f_code.co_filename).parent != TESTS_DIR:
                caller = caller.f_back
            if caller is None or Path(caller.f_code.co_filename).name not in SOURCE_TESTS:
                raise Unrepresentable("not called from a fixed-fixture test module")
            predicate = TARGET_FILTERS.get((Path(code.co_filename).name, code.co_qualname))
            if predicate is not None and not predicate(frame.f_locals):
                raise Unrepresentable("filtered")
            args = {name: encode(frame.f_locals[name]) for name in params}
            text = json.dumps(args, sort_keys=True)
            if len(text) > MAX_VECTOR_BYTES:
                raise Unrepresentable("larger than MAX_VECTOR_BYTES")
            if any(marker in text for marker in self.temp_markers):
                raise Unrepresentable("temporary path")
            if self.today in text or UUID4.search(text):
                raise Unrepresentable("run date or random UUID")
            entry: Any = (code, args)
        except Unrepresentable as reason:
            entry = (code, None)
            if str(reason) != "filtered":
                key = f"{Path(code.co_filename).stem}.{code.co_qualname}: {reason}"
                self.skipped[key] = self.skipped.get(key, 0) + 1
        self.stack().append(entry)
        return None

    def finish(self, code: Any, outcome: dict[str, Any]) -> None:
        stack = self.stack()
        if not stack or stack[-1][0] is not code:
            return
        _, args = stack.pop()
        if args is None:
            return
        name = f"{Path(code.co_filename).stem}.{code.co_qualname}"
        vector = {"function": name, "args": args, **outcome}
        # ensure_ascii keeps lone surrogates (tests use them) as \uXXXX escapes, which JSON.parse restores.
        key = hashlib.sha256(json.dumps(vector, sort_keys=True).encode()).hexdigest()
        self.vectors[key] = vector

    def on_return(self, code: Any, offset: int, value: Any) -> Any:
        try:
            return self._return(code, value)
        except Exception as error:  # noqa: BLE001
            self.failures.append(f"return {code.co_qualname}: {error!r}")
            return None

    def _return(self, code: Any, value: Any) -> Any:
        if self.target(code) is None:
            return sys.monitoring.DISABLE
        try:
            outcome = {"result": encode(value)}
            if len(json.dumps(outcome["result"])) > MAX_VECTOR_BYTES:
                raise Unrepresentable("result larger than MAX_VECTOR_BYTES")
        except Unrepresentable:
            stack = self.stack()
            if stack and stack[-1][0] is code:
                stack.pop()
            return None
        self.finish(code, outcome)
        return None

    def on_unwind(self, code: Any, offset: int, error: BaseException) -> None:
        try:
            if self.target(code) is not None:
                self.finish(code, {"error": {"type": type(error).__name__, "message": str(error)}})
        except Exception as failure:  # noqa: BLE001
            self.failures.append(f"unwind {code.co_qualname}: {failure!r}")


def record(pytest_args: list[str]) -> tuple[dict[str, list[dict[str, Any]]], dict[str, int], int]:
    import pytest

    recorder = Recorder()
    monitoring = sys.monitoring
    monitoring.use_tool_id(TOOL_ID, "pi-security-parity")
    events = monitoring.events
    monitoring.register_callback(TOOL_ID, events.PY_START, recorder.on_start)
    monitoring.register_callback(TOOL_ID, events.PY_RETURN, recorder.on_return)
    monitoring.register_callback(TOOL_ID, events.PY_UNWIND, recorder.on_unwind)
    monitoring.set_events(TOOL_ID, events.PY_START | events.PY_RETURN | events.PY_UNWIND)
    try:
        status = pytest.main(["-q", "-p", "no:cacheprovider", *pytest_args])
    finally:
        monitoring.set_events(TOOL_ID, 0)
        monitoring.free_tool_id(TOOL_ID)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for key in sorted(recorder.vectors):
        vector = recorder.vectors[key]
        grouped.setdefault(vector["function"], []).append(vector)
    if recorder.failures:
        print("recorder errors:\n  " + "\n  ".join(recorder.failures[:20]), file=sys.stderr)
        status = status or 1
    return grouped, recorder.skipped, int(status)


def write(grouped: dict[str, list[dict[str, Any]]], directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for function, vectors in sorted(grouped.items()):
        text = "".join(json.dumps(v, sort_keys=True) + "\n" for v in vectors)
        (directory / f"{function}.jsonl").write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="Fail if vectors/ differs from a fresh recording.")
    parser.add_argument("pytest_args", nargs="*", help="Pytest selection (default: the whole tests/ directory).")
    args = parser.parse_args()
    if sys.version_info < (3, 12):
        print("record_vectors.py needs Python 3.12+ (sys.monitoring)", file=sys.stderr)
        return 2
    grouped, skipped, status = record(args.pytest_args or [str(TESTS_DIR / name) for name in sorted(SOURCE_TESTS)])
    if status != 0:
        print(f"pytest exited with status {status}; vectors not written", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as temporary:
        staged = Path(temporary) / "vectors"
        write(grouped, staged)
        if args.check:
            current = {p.name: p.read_bytes() for p in VECTORS_DIR.glob("*.jsonl")} if VECTORS_DIR.exists() else {}
            fresh = {p.name: p.read_bytes() for p in staged.glob("*.jsonl")}
            if current != fresh:
                print("tests/parity/vectors is out of date; run record_vectors.py", file=sys.stderr)
                return 1
            print("vectors match a fresh recording")
            return 0
        shutil.rmtree(VECTORS_DIR, ignore_errors=True)
        shutil.copytree(staged, VECTORS_DIR)
    for function, vectors in sorted(grouped.items()):
        print(f"{function}: {len(vectors)} vectors")
    for reason, count in sorted(skipped.items()):
        print(f"skipped {count}: {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
