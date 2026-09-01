from __future__ import annotations

import sys
from argparse import Namespace
from pathlib import Path
from typing import Any

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import deep_scan_workbench as workbench  # noqa: E402


class ExistingRunConnection:
    def __init__(self) -> None:
        self.statements: list[str] = []

    def execute(self, statement: str, _parameters: object = None) -> "ExistingRunConnection":
        self.statements.append(statement)
        return self

    def fetchone(self) -> dict[str, str]:
        return {"scan_id": "00000000-0000-4000-8000-000000000001"}


def test_joined_deep_scan_does_not_replace_persisted_model_settings(
    monkeypatch: pytest.MonkeyPatch,
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
    connection = ExistingRunConnection()
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
    monkeypatch.setattr(
        workbench,
        "deep_scan_result",
        lambda _connection, _scan_id, *, start_disposition: {
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
            workflow_version="deep-scan-mcp/v1",
        ),
    )

    assert result == {"startDisposition": "joined"}
    assert len(connection.statements) == 1
    assert "SELECT scan_id FROM deep_scan_runs" in connection.statements[0]
    assert all("UPDATE scans" not in statement for statement in connection.statements)
