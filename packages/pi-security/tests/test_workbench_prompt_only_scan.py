from __future__ import annotations

import argparse
import json
import os
import runpy
import sqlite3
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

import pytest

from test_workbench_db import (
    SCRIPT,
    create_saved_workspace,
    initialize_git_repository,
    run_workbench,
    write_completed_contract,
)


def start_prompt_only_scan(
    state_dir: Path,
    target: Path,
    scan_root: Path,
    *,
    thread_id: str = "thread-prompt-only-scan",
    scope: str = ".",
    mode: str = "standard",
    target_summary: str = "Prompt-only scan",
    user_context: str = "Inspect authentication boundaries",
    extra_args: tuple[str, ...] = (),
) -> dict[str, object]:
    return run_workbench(
        state_dir,
        "start-prompt-only-scan",
        "--thread-id",
        thread_id,
        "--target-path",
        str(target),
        "--scope",
        scope,
        "--mode",
        mode,
        "--target-summary",
        target_summary,
        "--user-context",
        user_context,
        "--scan-root",
        str(scan_root),
        *extra_args,
    )


def start_headless_standard_scan(
    state_dir: Path,
    target: Path,
    scan_root: Path,
    *,
    thread_id: str = "thread-headless-standard-scan",
    scope: str = ".",
    target_summary: str = "Headless standard scan",
    user_context: str = "Inspect authentication boundaries",
) -> dict[str, object]:
    return run_workbench(
        state_dir,
        "start-headless-standard-scan",
        "--thread-id",
        thread_id,
        "--target-path",
        str(target),
        "--scope",
        scope,
        "--target-summary",
        target_summary,
        "--user-context",
        user_context,
        "--scan-root",
        str(scan_root),
    )


def test_headless_standard_scan_starts_without_setup_opt_out(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "fixture.py").write_text("print('fixture')\n")

    started = start_headless_standard_scan(state_dir, target, tmp_path / "scans")
    scan = started["scan"]
    workspace = started["workspace"]
    assert started["startDisposition"] == "created"
    assert scan["mode"] == "standard"
    assert scan["progress"]["status"] == "running"
    assert scan["progress"]["phase"] == "preflight"
    assert scan["handoffStatus"] == "delivered"
    assert scan["continuationThreadId"] == "thread-headless-standard-scan"
    assert str(uuid.UUID(str(scan["handoffClaimToken"]))) == scan["handoffClaimToken"]
    assert workspace["setup"] == {"submitted": True}
    assert workspace["results"]["scanId"] == scan["scanId"]


def test_headless_standard_scan_preserves_url_user_context(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "fixture.py").write_text("print('fixture')\n")
    user_context = (
        "Repository: https://github.com/example/security-review\n"
        "OAuth issuer: https://accounts.example.test"
    )

    started = start_headless_standard_scan(
        state_dir,
        target,
        tmp_path / "scans",
        user_context=user_context,
    )

    assert started["scan"]["userContext"] == user_context
    assert started["workspace"]["userContext"] == user_context


def test_headless_standard_scan_joins_only_the_owning_thread(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "fixture.py").write_text("print('fixture')\n")
    scan_root = tmp_path / "scans"

    first = start_headless_standard_scan(state_dir, target, scan_root)
    joined = start_headless_standard_scan(state_dir, target, scan_root)
    other = start_headless_standard_scan(
        state_dir, target, scan_root, thread_id="thread-headless-other"
    )

    assert first["startDisposition"] == "created"
    assert joined["startDisposition"] == "joined"
    assert joined["scan"]["scanId"] == first["scan"]["scanId"]
    assert joined["scan"]["handoffClaimToken"] == first["scan"]["handoffClaimToken"]
    assert other["startDisposition"] == "created"
    assert other["scan"]["scanId"] != first["scan"]["scanId"]
    assert other["scan"]["handoffClaimToken"] != first["scan"]["handoffClaimToken"]


def test_headless_standard_scan_serializes_concurrent_starts(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "fixture.py").write_text("print('fixture')\n")
    run_workbench(state_dir, "database-info")

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda _: start_headless_standard_scan(state_dir, target, tmp_path / "scans"),
                range(2),
            )
        )

    assert {result["startDisposition"] for result in results} == {"created", "joined"}
    assert len({result["scan"]["scanId"] for result in results}) == 1


def test_prompt_only_scan_starts_without_persisted_opt_out(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    scan_root = tmp_path / "scans"
    started = start_prompt_only_scan(state_dir, target, scan_root)
    assert started["startDisposition"] == "created"


def test_prompt_only_scan_creates_submitted_delivered_scan(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "fixture.py").write_text("print('fixture')\n")
    started = start_prompt_only_scan(state_dir, target, tmp_path / "scans")
    assert started["startDisposition"] == "created"
    scan = started["scan"]
    workspace = started["workspace"]
    assert scan["scanId"]
    assert scan["mode"] == "standard"
    assert scan["progress"]["status"] == "running"
    assert scan["handoffStatus"] == "delivered"
    assert scan["continuationThreadId"] == "thread-prompt-only-scan"
    assert str(uuid.UUID(str(scan["handoffClaimToken"]))) == scan["handoffClaimToken"]
    assert workspace["id"]
    assert workspace["setup"] == {"submitted": True}
    assert workspace["results"]["scanId"] == scan["scanId"]

    joined = start_prompt_only_scan(state_dir, target, tmp_path / "scans")
    assert joined["startDisposition"] == "joined"
    assert joined["scan"]["scanId"] == scan["scanId"]
    assert joined["scan"]["handoffClaimToken"] == scan["handoffClaimToken"]


def test_prompt_only_standard_phase_uses_latest_persisted_scan_context(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()

    started = start_prompt_only_scan(state_dir, target, tmp_path / "scans")
    scan_id = str(started["scan"]["scanId"])
    claim_token = str(started["scan"]["handoffClaimToken"])
    updated_context = "Prioritize password-reset token validation."
    updated = run_workbench(
        state_dir,
        "update-scan-context",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-prompt-only-scan",
        "--claim-token",
        claim_token,
        "--user-context",
        updated_context,
    )
    assert updated["scan"]["userContext"] == updated_context

    next_phase = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--claim-token",
        claim_token,
        "--phase",
        "discovery",
    )
    assert next_phase["scan"]["progress"]["phase"] == "discovery"
    assert next_phase["scan"]["userContext"] == updated_context


def test_setup_scan_reuses_checked_target_metadata(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    namespace = runpy.run_path(str(SCRIPT), run_name="setup_scan_target_identity_test")
    start = namespace["start_scan"]
    start_globals = start.__globals__
    real_scan_target_identity = start_globals["scan_target_identity"]
    observed_metadata: list[os.stat_result | None] = []

    def record_target_identity(
        target_path: Path,
        diff_target: dict[str, str] | None,
        *,
        metadata: os.stat_result | None = None,
    ) -> tuple[str, str | None, int | str, int | str]:
        observed_metadata.append(metadata)
        if metadata is None:
            return real_scan_target_identity(target_path, diff_target)
        return real_scan_target_identity(target_path, diff_target, metadata=metadata)

    args = argparse.Namespace(
        model=None,
        reasoning_effort=None,
        scan_root=str(tmp_path / "scans"),
        workspace_id=str(saved["id"]),
    )
    with (
        mock.patch.dict(os.environ, {"PI_SECURITY_STATE_DIR": str(state_dir)}),
        mock.patch.dict(
            start_globals,
            {"scan_target_identity": record_target_identity},
        ),
    ):
        connection = start_globals["connect"]()
        try:
            started = start(connection, args)
        finally:
            connection.close()

    assert len(observed_metadata) == 1
    metadata = observed_metadata[0]
    assert metadata is not None
    scan_id = str(started["results"]["scanId"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        identity = connection.execute(
            "SELECT target_device, target_inode FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
    serialize_identity = start_globals["serialize_filesystem_identity"]
    assert identity == (
        serialize_identity(metadata.st_dev),
        serialize_identity(metadata.st_ino),
    )


def test_prompt_only_scan_does_not_join_setup_owned_scans(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    scan_root = tmp_path / "scans"
    saved = create_saved_workspace(
        state_dir,
        target,
        thread_id="thread-prompt-only-scan",
    )
    pending = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        str(saved["id"]),
        "--scan-root",
        str(scan_root),
    )
    assert pending["results"]["handoffStatus"] == "pending"
    prompt_only = start_prompt_only_scan(state_dir, target, scan_root)
    assert prompt_only["startDisposition"] == "created"
    assert prompt_only["scan"]["handoffStatus"] == "delivered"
    assert prompt_only["scan"]["scanId"] != pending["results"]["scanId"]


@pytest.mark.parametrize("diff_kind", ("working_tree", "commit"))
def test_prompt_only_diff_scan_validates_and_persists_canonical_diff_identity(
    tmp_path: Path, diff_kind: str,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    base = head = initialize_git_repository(target)
    (target / "README.md").write_text("changed fixture\n")
    extra_args = ("--diff-target-kind", diff_kind)
    if diff_kind == "commit":
        subprocess.run(["git", "commit", "-qam", "Changed fixture"], cwd=target, check=True)
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=target, check=True, capture_output=True, text=True
        ).stdout.strip()
        extra_args += ("--diff-head-revision", head)
    started = start_prompt_only_scan(
        state_dir,
        target,
        tmp_path / "scans",
        thread_id="thread-diff",
        mode="diff",
        extra_args=extra_args,
    )
    scan = started["scan"]
    assert scan["diffTarget"]["kind"] == diff_kind
    assert scan["diffTarget"]["baseRevision"] == base
    assert scan["diffTarget"]["headRevision"] == head
    assert started["workspace"]["diffTarget"] == scan["diffTarget"]
    assert scan["continuationThreadId"] == "thread-diff"
    assert str(uuid.UUID(str(scan["handoffClaimToken"]))) == scan["handoffClaimToken"]

    joined = start_prompt_only_scan(
        state_dir,
        target,
        tmp_path / "scans",
        thread_id="thread-diff",
        mode="diff",
        extra_args=extra_args,
    )
    assert joined["startDisposition"] == "joined"
    assert joined["scan"]["scanId"] == scan["scanId"]
    assert joined["scan"]["handoffClaimToken"] == scan["handoffClaimToken"]

    if diff_kind == "working_tree":
        (target / "README.md").write_text("a different change\n")
    else:
        extra_args = ("--diff-target-kind", "commit", "--diff-head-revision", base)
    changed = start_prompt_only_scan(
        state_dir,
        target,
        tmp_path / "scans",
        thread_id="thread-diff",
        mode="diff",
        extra_args=extra_args,
    )
    assert changed["startDisposition"] == "created"
    assert changed["scan"]["scanId"] != scan["scanId"]
    assert changed["scan"]["handoffClaimToken"] != scan["handoffClaimToken"]
    assert changed["scan"]["diffTarget"] != scan["diffTarget"]


@pytest.mark.parametrize("legacy_thread", (None, "thread-prompt-only-scan"))
def test_prompt_scan_legacy_claim_requires_exact_owning_workspace_rejoin(
    tmp_path: Path, legacy_thread: str | None,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "fixture.py").write_text("print('fixture')\n")
    scan_root = tmp_path / "scans"
    started = start_prompt_only_scan(state_dir, target, scan_root)
    scan_id = str(started["scan"]["scanId"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET handoff_claim_token = NULL, continuation_thread_id = ? WHERE id = ?",
            (legacy_thread, scan_id),
        )

    inspected = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)
    assert inspected["scan"]["handoffClaimToken"] is None
    attempted_claim = run_workbench(
        state_dir,
        "claim-handoff-delivery",
        "--scan-id",
        scan_id,
        "--claim-token",
        str(uuid.uuid4()),
    )
    assert attempted_claim["results"]["handoffClaimToken"] is None
    mismatched = start_prompt_only_scan(state_dir, target, scan_root, scope="src")
    foreign = start_prompt_only_scan(
        state_dir, target, scan_root, thread_id="thread-foreign"
    )
    assert mismatched["startDisposition"] == foreign["startDisposition"] == "created"
    assert mismatched["scan"]["scanId"] != scan_id
    assert foreign["scan"]["scanId"] != scan_id
    unclaimed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)
    assert unclaimed["scan"]["handoffClaimToken"] is None
    assert unclaimed["scan"]["continuationThreadId"] == legacy_thread

    with ThreadPoolExecutor(max_workers=2) as pool:
        headless = pool.submit(
            start_headless_standard_scan,
            state_dir,
            target,
            scan_root,
            thread_id="thread-prompt-only-scan",
            target_summary="Prompt-only scan",
        )
        prompt = pool.submit(start_prompt_only_scan, state_dir, target, scan_root)
        migrated, rejoined = headless.result(), prompt.result()

    assert migrated["startDisposition"] == rejoined["startDisposition"] == "joined"
    assert migrated["scan"]["scanId"] == rejoined["scan"]["scanId"] == scan_id
    claim_token = migrated["scan"]["handoffClaimToken"]
    assert str(uuid.UUID(str(claim_token))) == claim_token
    assert rejoined["scan"]["handoffClaimToken"] == claim_token
    assert migrated["scan"]["continuationThreadId"] == "thread-prompt-only-scan"
    assert rejoined["scan"]["continuationThreadId"] == "thread-prompt-only-scan"


@pytest.mark.parametrize(
    ("continuation_thread", "claimed"),
    ((None, True), ("thread-foreign", True), ("thread-foreign", False)),
)
def test_prompt_scan_does_not_adopt_a_nonowning_continuation(
    tmp_path: Path, continuation_thread: str | None, claimed: bool,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    started = start_prompt_only_scan(state_dir, target, tmp_path / "scans")
    scan_id = str(started["scan"]["scanId"])
    original_token = started["scan"]["handoffClaimToken"] if claimed else None
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET handoff_claim_token = ?, continuation_thread_id = ? WHERE id = ?",
            (original_token, continuation_thread, scan_id),
        )

    restarted = start_prompt_only_scan(state_dir, target, tmp_path / "scans")
    assert restarted["startDisposition"] == "created"
    assert restarted["scan"]["scanId"] != scan_id
    assert restarted["scan"]["handoffClaimToken"] != original_token
    rejected = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--claim-token",
        str(restarted["scan"]["handoffClaimToken"]),
        "--phase",
        "discovery",
        check=False,
    )
    assert rejected["returncode"] != 0
    retained = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert retained["handoffClaimToken"] == original_token
    assert retained["continuationThreadId"] == continuation_thread
    assert retained["progress"]["phase"] == "preflight"


@pytest.mark.parametrize("mode", ("standard", "diff"))
def test_prompt_scan_requires_its_claim_for_progress_drafts_and_completion(
    tmp_path: Path, mode: str,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    if mode == "diff":
        initialize_git_repository(target)
    else:
        target.mkdir()
    (target / "README.md").write_text("changed fixture\n")
    extra_args = ("--diff-target-kind", "working_tree") if mode == "diff" else ()
    started = start_prompt_only_scan(
        state_dir, target, tmp_path / "scans", mode=mode, extra_args=extra_args
    )
    scan = started["scan"]
    scan_id, scan_dir = str(scan["scanId"]), Path(str(scan["scanDir"]))
    claim_token = str(scan["handoffClaimToken"])
    foreign = start_prompt_only_scan(
        state_dir,
        target,
        tmp_path / "scans",
        thread_id="thread-foreign",
        mode=mode,
        extra_args=extra_args,
    )
    assert foreign["scan"]["scanId"] != scan_id
    assert foreign["scan"]["handoffClaimToken"] != claim_token
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        relative_path="README.md",
        **(
            {
                "target_kind": "git_diff",
                "diff_base_revision": scan["diffTarget"]["baseRevision"],
                "diff_head_revision": scan["diffTarget"]["headRevision"],
                "snapshot_digest": scan["diffTarget"]["contentDigest"],
                "coverage_mode": "working_tree",
            }
            if mode == "diff"
            else {}
        ),
    )
    canonical = {
        filename: (scan_dir / filename).read_bytes()
        for filename in ("scan-manifest.json", "findings.json", "coverage.json")
    }
    draft = {
        key: json.loads(canonical[filename])
        for key, filename in (
            ("manifest", "scan-manifest.json"),
            ("findings", "findings.json"),
            ("coverage", "coverage.json"),
        )
    }
    draft["findings"]["findings"][0]["title"] = "Claimed scan finding"
    (scan_dir / "drafts").mkdir()
    draft_path = scan_dir / "drafts" / f"{uuid.uuid4()}.json"
    draft_path.write_text(json.dumps(draft))
    for token in (None, str(foreign["scan"]["handoffClaimToken"])):
        claim_args = ("--claim-token", token) if token is not None else ()
        for command, arguments in (
            ("update-progress", ("--phase", "discovery")),
            ("write-scan-draft", ("--draft-path", str(draft_path))),
            ("prepare-scan-completion", ()),
            ("complete-scan", ()),
        ):
            rejected = run_workbench(
                state_dir, command, "--scan-id", scan_id, *arguments, *claim_args, check=False
            )
            assert rejected["returncode"] != 0, (command, token)
    unchanged = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert unchanged["progress"]["status"] == "running"
    assert unchanged["progress"]["phase"] == "preflight"
    assert {
        filename: (scan_dir / filename).read_bytes() for filename in canonical
    } == canonical

    progressed = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        "discovery",
        "--claim-token",
        claim_token,
    )
    assert progressed["scan"]["progress"]["phase"] == "discovery"
    run_workbench(
        state_dir,
        "write-scan-draft",
        "--scan-id",
        scan_id,
        "--draft-path",
        str(draft_path),
        "--claim-token",
        claim_token,
    )
    assert json.loads((scan_dir / "findings.json").read_text())["findings"][0]["title"] == (
        "Claimed scan finding"
    )
    prepared = run_workbench(
        state_dir, "prepare-scan-completion", "--scan-id", scan_id, "--claim-token", claim_token
    )
    assert prepared["scan"]["progress"]["status"] == "running"
    prepared_artifacts = {
        filename: (scan_dir / filename).read_bytes() for filename in canonical
    }
    completed = run_workbench(
        state_dir, "complete-scan", "--scan-id", scan_id, "--claim-token", claim_token
    )
    assert completed["scan"]["progress"]["status"] == "complete"
    assert {
        filename: (scan_dir / filename).read_bytes() for filename in canonical
    } == prepared_artifacts
    assert completed["scan"]["findings"][0]["title"] == "Claimed scan finding"
    sealed = (scan_dir / "scan-manifest.json").read_bytes()
    late_draft = run_workbench(
        state_dir,
        "write-scan-draft",
        "--scan-id",
        scan_id,
        "--draft-path",
        str(draft_path),
        "--claim-token",
        claim_token,
        check=False,
    )
    assert late_draft["returncode"] != 0
    restarted = start_prompt_only_scan(
        state_dir, target, tmp_path / "scans", mode=mode, extra_args=extra_args
    )
    assert restarted["startDisposition"] == "created"
    assert restarted["scan"]["scanId"] != scan_id
    assert restarted["scan"]["handoffClaimToken"] != claim_token
    assert (scan_dir / "scan-manifest.json").read_bytes() == sealed
