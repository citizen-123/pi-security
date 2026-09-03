from __future__ import annotations

import sqlite3
import sys
import uuid
from argparse import Namespace
from pathlib import Path
from typing import Any

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import deep_scan_workbench as workbench  # noqa: E402


class ExistingRunConnection:
    def __init__(self, workflow_version: str) -> None:
        self.statements: list[str] = []
        self.workflow_version = workflow_version

    def execute(self, statement: str, parameters: object = None) -> "ExistingRunConnection":
        self.statements.append(statement)
        if statement.lstrip().startswith("UPDATE deep_scan_runs SET workflow_version"):
            assert isinstance(parameters, tuple)
            self.workflow_version = str(parameters[0])
        return self

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass

    def fetchone(self) -> dict[str, str]:
        return {
            "scan_id": "00000000-0000-4000-8000-000000000001",
            "workflow_version": self.workflow_version,
        }


@pytest.mark.parametrize(
    ("persisted_workflow", "expected_statement_count"),
    (("deep-scan-native/v1", 3), ("deep-scan-mcp/v1", 5)),
)
def test_joined_deep_scan_migrates_workflow_without_replacing_model_settings(
    monkeypatch: pytest.MonkeyPatch,
    persisted_workflow: str,
    expected_statement_count: int,
) -> None:
    scan_id = "00000000-0000-4000-8000-000000000001"
    scan: dict[str, Any] = {
        "id": scan_id,
        "workspace_id": "workspace-1",
        "mode": "deep",
        "status": "running",
        "recipe_json": None,
        "handoff_status": "delivered",
        "deep_scan_owner_thread_id": "thread-1",
    }
    connection = ExistingRunConnection(persisted_workflow)
    monkeypatch.setattr(workbench, "require_scan", lambda _connection, _scan_id: scan)
    monkeypatch.setattr(
        workbench,
        "require_workspace",
        lambda _connection, _workspace_id: {"id": "workspace-1", "thread_id": "thread-1"},
    )
    monkeypatch.setattr(
        workbench,
        "require_owned_scan",
        lambda _connection, _scan_id, _thread_id: (scan, {"id": "workspace-1"}),
    )
    monkeypatch.setattr(workbench, "require_current_continuation", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(workbench, "now", lambda: "2026-09-01T00:00:00Z")
    monkeypatch.setattr(
        workbench,
        "deep_scan_result",
        lambda _connection, _scan_id, *, start_disposition, artifact_write_authorization: {
            "startDisposition": start_disposition,
        },
    )

    result = workbench.begin_deep_scan_for_scan(
        connection,  # type: ignore[arg-type]
        scan_id,
        "thread-1",
        Namespace(
            claim_token=None,
            model="replacement-model",
            reasoning_effort="replacement-effort",
            available_parallelism=1,
            workflow_version=workbench.DEEP_SCAN_WORKFLOW_VERSION,
        ),
    )

    assert result == {"startDisposition": "joined"}
    assert len(connection.statements) == expected_statement_count
    assert connection.statements[0] == "BEGIN IMMEDIATE"
    assert "SELECT scan_id FROM deep_scan_runs" in connection.statements[1]
    assert "SELECT * FROM deep_scan_runs" in connection.statements[2]
    assert connection.workflow_version == workbench.DEEP_SCAN_WORKFLOW_VERSION
    assert all("UPDATE scans" not in statement for statement in connection.statements)


@pytest.mark.parametrize("status", ("running", "interrupted", "succeeded"))
def test_compatible_legacy_workflow_migrates_for_every_persisted_state(status: str) -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE deep_scan_runs (
            scan_id TEXT PRIMARY KEY,
            workflow_version TEXT NOT NULL,
            status TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    scan_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"pi-security-{status}"))
    connection.execute(
        "INSERT INTO deep_scan_runs VALUES (?, 'deep-scan-mcp/v1', ?, 'before')",
        (scan_id, status),
    )

    migrated = workbench.ensure_deep_scan_run(
        connection,
        {"id": scan_id},
        {},
        workbench.DEEP_SCAN_WORKFLOW_VERSION,
        "after",
    )

    assert migrated["workflow_version"] == "deep-scan-native/v1"
    assert migrated["status"] == status
    assert migrated["updated_at"] == "after"


def test_incompatible_persisted_workflow_is_rejected() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE deep_scan_runs (
            scan_id TEXT PRIMARY KEY,
            workflow_version TEXT NOT NULL,
            status TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    scan_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "pi-security-incompatible"))
    connection.execute(
        "INSERT INTO deep_scan_runs VALUES (?, 'unknown-workflow/v1', 'interrupted', 'before')",
        (scan_id,),
    )

    with pytest.raises(SystemExit, match="incompatible with this native runtime"):
        workbench.ensure_deep_scan_run(
            connection,
            {"id": scan_id},
            {},
            workbench.DEEP_SCAN_WORKFLOW_VERSION,
            "after",
        )
