from __future__ import annotations

import errno
import importlib
from pathlib import Path

import pytest


def load_deep_scan(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    return importlib.import_module("deep_scan_workbench")


def test_publication_copy_survives_unavailable_hardlinks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    deep = load_deep_scan(monkeypatch)
    contract = importlib.import_module("finalize_scan_contract")
    source = tmp_path / "snapshot.jsonl"
    publication = tmp_path / "publication.jsonl"
    source.write_bytes(b'{"finding":"synthetic"}\n')

    def reject_hardlink(*args, **kwargs):
        raise OSError(errno.ENOTSUP, "hardlinks are unavailable")

    monkeypatch.setattr(contract.os, "link", reject_hardlink)
    deep.create_publication_copy(tmp_path, source, publication)
    assert publication.read_bytes() == source.read_bytes()
    assert not publication.samefile(source)
    assert deep.publication_matches_snapshot(publication, source)
    publication.write_bytes(b'{"finding":"different"}\n')
    assert not deep.publication_matches_snapshot(publication, source)
    publication.unlink()
    assert not deep.publication_matches_snapshot(publication, source)


def test_publication_copy_rejects_swapped_destination_parent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    deep = load_deep_scan(monkeypatch)
    scan_dir = tmp_path / "scan"
    source = scan_dir / "workers" / "candidate_ledger.jsonl"
    destination_parent = scan_dir / "artifacts" / "02_discovery"
    destination = destination_parent / ".candidate_ledger.jsonl.publish"
    source.parent.mkdir(parents=True)
    destination_parent.mkdir(parents=True)
    source.write_text('{"candidate":"trusted"}\n', encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    destination_parent.rename(tmp_path / "parked-discovery")
    try:
        destination_parent.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"creating a symbolic link requires host support: {error}")

    with pytest.raises(SystemExit, match="publication copy failed"):
        deep.create_publication_copy(scan_dir, source, destination)

    assert not (outside / destination.name).exists()


def test_publication_rollback_and_cleanup_reject_swapped_destination_parent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    deep = load_deep_scan(monkeypatch)
    scan_dir = tmp_path / "scan"
    staged = scan_dir / "workers" / "candidate_ledger.jsonl"
    discovery = scan_dir / "artifacts" / "02_discovery"
    output = discovery / "candidate_ledger.jsonl"
    staged.parent.mkdir(parents=True)
    discovery.mkdir(parents=True)
    staged.write_text('{"candidate":"new"}\n', encoding="utf-8")
    output.write_text('{"candidate":"old"}\n', encoding="utf-8")
    promotion = deep.promote_staged_file(scan_dir, str(staged), str(output))
    backup = promotion[2]
    assert backup is not None
    outside = tmp_path / "outside"
    outside.mkdir()
    discovery.rename(tmp_path / "parked-discovery")
    try:
        discovery.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"creating a symbolic link requires host support: {error}")
    outside_output = outside / output.name
    outside_backup = outside / backup.name
    outside_output.write_text('{"candidate":"outside"}\n', encoding="utf-8")
    outside_backup.write_text('{"candidate":"outside-backup"}\n', encoding="utf-8")

    with pytest.raises(SystemExit, match="artifact rollback failed"):
        deep.rollback_staged_file(scan_dir, promotion)
    with pytest.raises(SystemExit, match="artifact cleanup failed"):
        deep.finish_staged_file(scan_dir, promotion)

    assert outside_output.read_text(encoding="utf-8") == '{"candidate":"outside"}\n'
    assert outside_backup.read_text(encoding="utf-8") == '{"candidate":"outside-backup"}\n'
