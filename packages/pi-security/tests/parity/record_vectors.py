#!/usr/bin/env python3
"""Record input/output vectors of pure Python functions while the existing pytest suite runs.

The suite already exercises far more edge cases of report rendering, SARIF, CSV, fingerprints, canonical JSON, and
candidate merging than the curated cases do. This script runs it in-process with a sys.monitoring tool attached to
the functions in TARGETS, captures each call's arguments (at entry, before any mutation) and its return value or
raised error, and writes deduplicated vectors to tests/parity/vectors/<module>.<function>.jsonl. TypeScript ports of
these functions must reproduce every vector.

Calls are matched by code object (file and qualified name), so modules the tests load repeatedly through
importlib are all observed. Calls whose arguments are not JSON-representable, or that mention a temporary path,
are skipped because they would not be reproducible.

Requires Python 3.12+ and the packages in requirements-test.txt.

Usage: record_vectors.py [--check]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

PARITY_DIR = Path(__file__).resolve().parent
PACKAGE_ROOT = PARITY_DIR.parent.parent
VECTORS_DIR = PARITY_DIR / "vectors"
SCRIPTS = PACKAGE_ROOT / "scripts"

# (script file, qualified name, parameters to record)
TARGETS: dict[tuple[str, str], tuple[str, ...]] = {
    ("report_projection.py", "build_report_markdown"): ("manifest", "findings", "coverage"),
    ("finalize_scan_contract.py", "build_sarif"): ("manifest", "findings", "source_root"),
    ("finalize_scan_contract.py", "build_csv_projection"): ("findings", "coverage"),
    ("finalize_scan_contract.py", "_fingerprint"): ("target_id", "finding"),
    ("finalize_scan_contract.py", "_stable_id"): ("prefix", "parts"),
    ("finalize_scan_contract.py", "_json_bytes"): ("payload",),
    ("normalize_candidates.py", "combine"): ("rows",),
    ("normalize_candidates.py", "identity"): ("row",),
    ("normalize_candidates.py", "cwe_ids"): ("row",),
}
TARGET_FILES = {str(SCRIPTS / file) for file, _ in TARGETS}
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
    if isinstance(value, (list, tuple)):
        return [encode(item) for item in value]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise Unrepresentable("non-string key")
        if "$bytes" in value:
            raise Unrepresentable("reserved key")
        return {key: encode(item) for key, item in value.items()}
    raise Unrepresentable(type(value).__name__)


class Recorder:
    def __init__(self) -> None:
        self.stacks = threading.local()
        self.vectors: dict[str, dict[str, Any]] = {}
        self.skipped: dict[str, int] = {}
        self.temp_markers = [tempfile.gettempdir(), "/private/var/folders", "pytest-of-"]

    def target(self, code: Any) -> tuple[str, ...] | None:
        if code.co_filename not in TARGET_FILES:
            return None
        return TARGETS.get((Path(code.co_filename).name, code.co_qualname))

    def stack(self) -> list[Any]:
        if not hasattr(self.stacks, "items"):
            self.stacks.items = []
        return self.stacks.items

    def on_start(self, code: Any, offset: int) -> Any:
        params = self.target(code)
        if params is None:
            return sys.monitoring.DISABLE
        frame = sys._getframe(1)
        try:
            args = {name: encode(frame.f_locals[name]) for name in params}
            text = json.dumps(args, sort_keys=True, ensure_ascii=False)
            if any(marker in text for marker in self.temp_markers):
                raise Unrepresentable("temporary path")
            entry: Any = (code, args)
        except Unrepresentable as reason:
            entry = (code, None)
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
        key = hashlib.sha256(json.dumps(vector, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        self.vectors[key] = vector

    def on_return(self, code: Any, offset: int, value: Any) -> Any:
        if self.target(code) is None:
            return sys.monitoring.DISABLE
        try:
            outcome = {"result": encode(value)}
        except Unrepresentable:
            self.stack().pop()
            return None
        self.finish(code, outcome)
        return None

    def on_unwind(self, code: Any, offset: int, error: BaseException) -> None:
        if self.target(code) is None:
            return
        self.finish(code, {"error": {"type": type(error).__name__, "message": str(error)}})


def record() -> tuple[dict[str, list[dict[str, Any]]], dict[str, int], int]:
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
        status = pytest.main(
            [str(PACKAGE_ROOT / "tests"), "-q", "-p", "no:cacheprovider"],
        )
    finally:
        monitoring.set_events(TOOL_ID, 0)
        monitoring.free_tool_id(TOOL_ID)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for key in sorted(recorder.vectors):
        vector = recorder.vectors[key]
        grouped.setdefault(vector["function"], []).append(vector)
    return grouped, recorder.skipped, int(status)


def write(grouped: dict[str, list[dict[str, Any]]], directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for function, vectors in sorted(grouped.items()):
        text = "".join(json.dumps(v, sort_keys=True, ensure_ascii=False) + "\n" for v in vectors)
        (directory / f"{function}.jsonl").write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="Fail if vectors/ differs from a fresh recording.")
    args = parser.parse_args()
    if sys.version_info < (3, 12):
        print("record_vectors.py needs Python 3.12+ (sys.monitoring)", file=sys.stderr)
        return 2
    grouped, skipped, status = record()
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
