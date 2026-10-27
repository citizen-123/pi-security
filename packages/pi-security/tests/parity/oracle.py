#!/usr/bin/env python3
"""Run the Python implementation over every parity case and write or check its goldens.

For each tests/parity/cases/<suite>/<case>/:
  1. copy input/ to a fresh work directory and build case.json["git"], if present;
  2. run each step: the Python entry point named by argv[0] with the remaining argv; a rejected step ends the case;
  3. record goldens/<suite>/<case>/result.json (each step's status, and its stdout when the step's "stdout" is
     "compare") and goldens/<suite>/<case>/tree/ (every file in the work directory afterwards, .git excluded).

The absolute work directory is replaced by <WORK> in recorded text so goldens do not depend on where they ran.
TypeScript ports are checked against these goldens by tests/parity.test.mjs, so the goldens stay the contract
after the Python code is deleted.

Usage: oracle.py [--write] [--case PREFIX]
  default  check: rerun Python and fail on any difference from the goldens (fixture or Python drift)
  --write  replace the goldens with the current Python output
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

PARITY_DIR = Path(__file__).resolve().parent
PACKAGE_ROOT = PARITY_DIR.parent.parent
CASES_DIR = PARITY_DIR / "cases"
GOLDENS_DIR = PARITY_DIR / "goldens"

ENTRY_POINTS = {
    "finalize_scan_contract": PACKAGE_ROOT / "scripts" / "finalize_scan_contract.py",
    "validate_scan_contract": PACKAGE_ROOT / "scripts" / "validate_scan_contract.py",
    "normalize_candidates": PACKAGE_ROOT / "scripts" / "normalize_candidates.py",
    "generate_in_scope_files": PACKAGE_ROOT / "scripts" / "generate_in_scope_files.py",
    "config_preflight": PACKAGE_ROOT / "scripts" / "config_preflight.py",
    "validate_patch_risk_assessment": PACKAGE_ROOT
    / "skills"
    / "assess-patch-risk"
    / "scripts"
    / "validate_patch_risk_assessment.py",
}

# Fixed identity and clock for repositories built from case.json["git"]; the TypeScript harness uses the same values.
GIT_ENV = {
    "GIT_AUTHOR_NAME": "Parity Author",
    "GIT_AUTHOR_EMAIL": "parity@example.invalid",
    "GIT_COMMITTER_NAME": "Parity Author",
    "GIT_COMMITTER_EMAIL": "parity@example.invalid",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
}


def git(repo: Path, *args: str, date: str | None = None) -> None:
    env = {**os.environ, **GIT_ENV}
    if date is not None:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = date
    subprocess.run(["git", "-C", str(repo), *args], check=True, env=env, capture_output=True)


def apply_files(repo: Path, change: dict[str, Any]) -> None:
    for relative, text in change.get("write", {}).items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    for encoded, text in change.get("write_raw", {}).items():
        path = os.fsencode(repo) + b"/" + base64.b64decode(encoded)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(text.encode("utf-8"))
    for relative, encoded in change.get("write_bytes", {}).items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(base64.b64decode(encoded))
    for relative in change.get("delete", []):
        (repo / relative).unlink()


def build_git(work: Path, spec: dict[str, Any]) -> None:
    """Commits get dates 2026-01-01T00:00:0NZ in order, so commit IDs are deterministic."""
    repo = work / spec["path"]
    repo.mkdir(parents=True, exist_ok=True)
    git(repo, "init", "-q", "-b", "main")
    for index, commit in enumerate(spec.get("commits", [])):
        apply_files(repo, commit)
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", commit.get("message", f"commit {index}"), date=f"2026-01-01T00:00:{index:02d}Z")
    worktree = spec.get("worktree")
    if worktree is not None:
        apply_files(repo, worktree)
        for relative in worktree.get("stage", []):
            git(repo, "add", "--", relative)


def make_symlinks(work: Path, links: dict[str, str]) -> None:
    for relative, target in links.items():
        path = work / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)


def parity_append(path: str, text: str) -> int:
    """Harness step that tampers with a file: appends text."""
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(text)
    return 0


def substitute(value: str, work: Path) -> str:
    return value.replace("{work}", str(work)).replace("{schemas}", str(PACKAGE_ROOT / "schemas"))


def normalize_text(data: bytes, work: Path) -> bytes:
    return data.replace(str(work).encode(), b"<WORK>")


def run_case(case_dir: Path, work: Path) -> dict[str, Any]:
    spec = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
    shutil.copytree(case_dir / "input", work, dirs_exist_ok=True)
    if "git" in spec:
        build_git(work, spec["git"])
    make_symlinks(work, spec.get("symlinks", {}))
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1", "TZ": "UTC", "LC_ALL": "C.UTF-8"}
    steps: list[dict[str, Any]] = []
    for step in spec["steps"]:
        argv = [substitute(item, work) for item in step["argv"]]
        if argv[0] == "parity_append":
            steps.append({"status": "ok" if parity_append(argv[1], argv[2]) == 0 else "rejected", "stderr": ""})
            continue
        completed = subprocess.run(
            [sys.executable, "-I", str(ENTRY_POINTS[argv[0]]), *argv[1:]],
            cwd=work,
            env=env,
            capture_output=True,
            timeout=120,
        )
        record: dict[str, Any] = {"status": "ok" if completed.returncode == 0 else "rejected"}
        if step.get("stdout") == "compare":
            record["stdout"] = normalize_text(completed.stdout, work).decode("utf-8")
        # Reference only: ports are not required to reproduce Python's error text.
        record["stderr"] = normalize_text(completed.stderr, work).decode("utf-8", "replace")
        steps.append(record)
        if record["status"] != "ok":
            break
    return {"steps": steps}


def golden_name(relative: bytes) -> str:
    """A path for the golden tree: names that are not valid UTF-8 are percent-escaped and marked .rawpath."""
    try:
        return relative.decode("utf-8")
    except UnicodeDecodeError:
        escaped = "".join(chr(byte) if byte < 0x80 and byte != 0x25 else f"%{byte:02X}" for byte in relative)
        return escaped + ".rawpath"


def capture_tree(work: Path, destination: Path) -> None:
    root = os.fsencode(work)
    for directory, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name != b".git" and not os.path.islink(os.path.join(directory, name)))
        entries = sorted(filenames) + sorted(
            name for name in os.listdir(directory) if os.path.islink(os.path.join(directory, name)) and os.path.isdir(os.path.join(directory, name))
        )
        for name in entries:
            full = os.path.join(directory, name)
            relative = os.path.relpath(full, root)
            target = destination / golden_name(relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            if os.path.islink(full):
                target.with_name(target.name + ".symlink").write_bytes(os.readlink(full))
            elif os.path.isfile(full):
                target.write_bytes(normalize_text(Path(os.fsdecode(full)).read_bytes(), work))


def golden_files(directory: Path) -> dict[str, bytes]:
    if not directory.exists():
        return {}
    return {str(p.relative_to(directory)): p.read_bytes() for p in sorted(directory.rglob("*")) if p.is_file()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--case", default="", help="Only cases whose name starts with this prefix.")
    args = parser.parse_args()

    case_dirs = sorted(p.parent for p in CASES_DIR.rglob("case.json"))
    names = [str(d.relative_to(CASES_DIR)) for d in case_dirs]
    selected = [(d, n) for d, n in zip(case_dirs, names) if n.startswith(args.case)]
    if args.write and not args.case:
        # Drop goldens of cases that no longer exist.
        for stale in sorted(p.parent for p in GOLDENS_DIR.rglob("result.json")):
            if str(stale.relative_to(GOLDENS_DIR)) not in names:
                shutil.rmtree(stale)

    failures: list[str] = []
    for case_dir, name in selected:
        with tempfile.TemporaryDirectory(prefix="pi-security-parity-") as temporary:
            work = Path(temporary).resolve() / "work"
            work.mkdir()
            result = run_case(case_dir, work)
            staged = Path(temporary) / "golden"
            capture_tree(work, staged / "tree")
            (staged / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            golden = GOLDENS_DIR / name
            if args.write:
                shutil.rmtree(golden, ignore_errors=True)
                shutil.copytree(staged, golden)
                print(f"wrote {name}: {' -> '.join(step['status'] for step in result['steps'])}")
                continue
            expected, actual = golden_files(golden), golden_files(staged)
            if expected != actual:
                changed = sorted(k for k in expected.keys() | actual.keys() if expected.get(k) != actual.get(k))
                failures.append(f"{name}: {', '.join(changed)}")
    if failures:
        print("Python output differs from goldens:\n  " + "\n  ".join(failures), file=sys.stderr)
        return 1
    if not args.write:
        print(f"{len(selected)} cases match their goldens")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
