#!/usr/bin/env python3
"""Generate the shared, deterministically ordered security-scan file inventory."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


# Some hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from finalize_scan_contract import ContractError, external_output_path, write_external_output_bytes
from workbench_target import git_command

class InventoryError(ValueError):
    """Raised when the repository, scope, or inventory cannot be used safely."""


def windows_stream_component(path: Path) -> str | None:
    """Return the first NTFS alternate-data-stream component."""

    if os.name != "nt":
        return None
    return next(
        (component for component in path.parts if component != path.anchor and ":" in component),
        None,
    )


def resolve_repository(value: str) -> Path:
    """Resolve the repository once so every scope is bound to its real root."""
    try:
        repository = Path(value).expanduser().resolve(strict=True)
    except (OSError, ValueError) as error:
        raise InventoryError(f"--repo: cannot resolve repository: {value}") from error
    if not repository.is_dir():
        raise InventoryError(f"--repo: expected a directory: {repository}")
    return repository


def resolve_scope(repository: Path, value: str) -> str:
    """Preserve the caller's relative path spelling while rejecting escaped scopes."""
    if not value or "\0" in value:
        raise InventoryError("--scope: expected a non-empty file or directory")

    requested = Path(value).expanduser()
    stream = windows_stream_component(requested)
    if stream is not None:
        raise InventoryError(f"--scope: NTFS alternate data streams are not supported: {stream}")
    scope = requested if requested.is_absolute() else repository / requested
    try:
        resolved = scope.resolve(strict=True)
    except (OSError, ValueError) as error:
        raise InventoryError(f"--scope: path does not exist: {value}") from error

    try:
        relative = resolved.relative_to(repository)
    except ValueError as error:
        raise InventoryError(f"--scope: path must remain inside --repo: {value}") from error

    if not resolved.is_dir() and not resolved.is_file():
        raise InventoryError(f"--scope: expected a file or directory: {value}")

    if requested.is_absolute():
        return relative.as_posix() if relative.parts else "."
    return value


def resolve_output(value: str) -> Path:
    """Reject direct symlink outputs while preserving a no-follow write path."""
    if not value or "\0" in value:
        raise InventoryError("--out: expected an inventory file path")
    requested = Path(value).expanduser()
    if requested.is_symlink():
        raise InventoryError("--out: refusing to replace a symbolic link")
    try:
        output = external_output_path(requested)
    except ContractError as error:
        raise InventoryError(f"--out: {error}") from error
    if output.exists() and not output.is_file():
        raise InventoryError(f"--out: expected a regular file path: {output}")
    return output


def generate_in_scope_files(repository: Path, scope: str, output: Path) -> int:
    """Atomically write a Git-aware inventory sorted as ``LC_ALL=C``."""
    rows = (
        git_inventory_rows(repository, scope)
        if (repository / ".git").exists()
        else directory_inventory_rows(repository, scope)
    )
    return write_inventory(output, sorted(rows))


def git_inventory_rows(repository: Path, scope: str) -> list[bytes]:
    """List tracked files plus non-ignored untracked files without ripgrep."""
    try:
        result = git_command(
            repository,
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            scope,
            text=False,
        )
    except OSError as error:
        raise InventoryError(f"could not run git inventory: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        message = f"git inventory exited with status {result.returncode}"
        if detail:
            message = f"{message}: {detail}"
        raise InventoryError(message)

    prefix = b"./" if scope == "." or scope.startswith("./") else b""
    rows: list[bytes] = []
    for path in result.stdout.split(b"\0"):
        if not path:
            continue
        candidate = repository / os.fsdecode(path)
        if candidate.is_file() and not candidate.is_symlink():
            normalized = path.replace(b"\\", b"/") if os.name == "nt" else path
            rows.append(prefix + normalized + b"\n")
    return rows


def directory_inventory_rows(repository: Path, scope: str) -> list[bytes]:
    """List regular files for non-Git directory targets without following links."""
    selected = repository / scope
    candidates = [selected] if selected.is_file() else selected.rglob("*")
    prefix = b"./" if scope == "." or scope.startswith("./") else b""
    rows: list[bytes] = []
    for candidate in candidates:
        try:
            relative = candidate.relative_to(repository)
        except ValueError:
            continue
        if ".git" in relative.parts or candidate.is_symlink() or not candidate.is_file():
            continue
        rows.append(prefix + os.fsencode(relative.as_posix()) + b"\n")
    return rows


def committed_changed_paths(repository: Path, base: str, head: str) -> list[tuple[Path, str]]:
    result = git_command(
        repository,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--raw",
        "-z",
        "--diff-filter=ACMRD",
        f"{base}..{head}",
        text=False,
    )
    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, result.args, output=result.stdout, stderr=result.stderr
        )
    fields = result.stdout.split(b"\0")
    changed: list[tuple[Path, str]] = []
    index = 0
    while index < len(fields) - 1:
        metadata = fields[index].split()
        status = chr(metadata[-1][0])
        index += 1
        if status in {"C", "R"}:
            index += 1
        path = os.fsdecode(fields[index])
        index += 1
        selected_mode = metadata[0].removeprefix(b":") if status == "D" else metadata[1]
        if selected_mode != b"120000":
            changed.append((repository / path, status))
    return changed


def generate_diff_in_scope_files(
    repository: Path,
    base: str,
    head: str,
    mode: str,
    output: Path,
) -> int:
    """Reuse the existing diff selection without generating previews or duplicate worklists."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from generate_rank_input import git_changed_paths, path_is_excluded
    from rank_preview import (
        DEFAULT_PREVIEW_BYTES,
        TEXT_CODE_EXTENSIONS,
        is_binary_sample,
        preview_for,
    )
    from workbench_target import git_blob_bytes

    rows: list[bytes] = []
    try:
        changed = (
            committed_changed_paths(repository, base, head)
            if mode == "revisions"
            else git_changed_paths(repository, base, head, mode)
        )
        eligible = [
            (path, status)
            for path, status in changed
            if not path_is_excluded(path.relative_to(repository))
            and path.suffix.lower() in TEXT_CODE_EXTENSIONS
        ]
        revision_paths = [
            path.relative_to(repository)
            for path, status in eligible
            if mode == "revisions" and status != "D"
        ]
        revision_blobs = dict(
            zip(
                revision_paths,
                git_blob_bytes(
                    repository,
                    [f"{head}:{path.as_posix()}" for path in revision_paths],
                ),
            )
        )

        for path, status in eligible:
            relative = path.relative_to(repository)
            if status != "D":
                if mode == "revisions":
                    contents = revision_blobs[relative]
                    if contents is None:
                        raise InventoryError(
                            f"could not read committed diff blob: {head}:{relative.as_posix()}"
                        )
                    if is_binary_sample(contents):
                        continue
                elif (
                    path.is_symlink()
                    or not path.is_file()
                    or preview_for(path, DEFAULT_PREVIEW_BYTES)[1]
                ):
                    continue
            relative_path = relative.as_posix()
            if "\n" in relative_path or "\r" in relative_path:
                raise InventoryError(
                    "Git changes contain a path that cannot fit in the file inventory"
                )
            rows.append(f"{relative_path}\n".encode())
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", None)
        if isinstance(detail, bytes):
            detail = detail.decode("utf-8", errors="replace")
        message = detail.strip() if isinstance(detail, str) and detail.strip() else str(error)
        raise InventoryError(f"could not resolve the selected Git changes: {message}") from error

    return write_inventory(output, sorted(set(rows)))


def write_inventory(output: Path, rows: list[bytes]) -> int:
    """Atomically replace an inventory without following swapped output parents."""
    try:
        write_external_output_bytes(output, b"".join(rows))
    except ContractError as error:
        raise InventoryError(f"--out: {error}") from error
    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="Repository root.")
    parser.add_argument("--scope", required=True, help="File or directory within the repository.")
    parser.add_argument("--out", required=True, help="Destination for the file inventory.")
    parser.add_argument("--diff-base", help="Authoritative Git base for a changed-file inventory.")
    parser.add_argument("--diff-head", default="HEAD", help="Authoritative Git head revision.")
    parser.add_argument(
        "--diff-mode",
        choices=("revisions", "local-patch"),
        default="revisions",
        help="Use committed revisions or the current staged and unstaged patch.",
    )
    args = parser.parse_args()

    try:
        repository = resolve_repository(args.repo)
        scope = resolve_scope(repository, args.scope)
        output = resolve_output(args.out)
        if args.diff_base is None:
            count = generate_in_scope_files(repository, scope, output)
        elif scope not in (".", "./"):
            raise InventoryError("--scope: diff scans must use the repository root")
        else:
            count = generate_diff_in_scope_files(
                repository,
                args.diff_base,
                args.diff_head,
                args.diff_mode,
                output,
            )
    except (OSError, ValueError) as error:
        print(f"generate_in_scope_files: {error}", file=sys.stderr)
        raise SystemExit(2) from error

    print(f"Recorded {count} in-scope files.")


if __name__ == "__main__":
    main()
