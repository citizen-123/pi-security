from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path

from workbench_test_support import run_workbench

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
INPUT_DIGEST = "sha256:" + "c" * 64
OUTPUT_DIGEST = "sha256:" + "d" * 64


def runtime_payload(
    target: Path,
    *,
    run_id: str | None = None,
    parent_run_id: str | None = None,
    policy_digest: str = DIGEST_A,
) -> dict[str, object]:
    return {
        "runId": run_id or str(uuid.uuid4()),
        **({"parentRunId": parent_run_id} if parent_run_id else {}),
        "workflow": {
            "id": "full-repository",
            "version": 1,
            "phases": [
                {
                    "id": "preflight",
                    "type": "preflight",
                    "version": 1,
                    "dependencies": [],
                },
                {
                    "id": "discovery",
                    "type": "discovery",
                    "version": 1,
                    "roleId": "discoverer",
                    "dependencies": ["preflight"],
                },
            ],
        },
        "snapshot": {"schemaVersion": 1, "resolved": {"scan": {"target": str(target)}}},
        "snapshotDigest": DIGEST_A,
        "targetPath": str(target),
        "targetRevision": "revision-a",
        "policyDigest": policy_digest,
    }


def invoke(state_dir: Path, command: str, payload: dict[str, object]) -> dict[str, object]:
    return run_workbench(state_dir, command, input_text=json.dumps(payload))


def test_runtime_schema_migrates_fresh_and_existing_databases(tmp_path: Path) -> None:
    fresh = tmp_path / "fresh"
    run_workbench(fresh, "database-info")
    with sqlite3.connect(fresh / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone() == (42,)
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'workflow_%'"
            )
        }
    assert tables == {
        "workflow_attempts",
        "workflow_events",
        "workflow_logical_agents",
        "workflow_output_reuse",
        "workflow_phases",
        "workflow_runs",
    }

    upgraded = tmp_path / "upgraded"
    run_workbench(upgraded, "database-info")
    database = upgraded / "workbench.sqlite3"
    with sqlite3.connect(database) as connection:
        for table in tables:
            connection.execute(f"DROP TABLE {table}")
        connection.execute("DELETE FROM schema_migrations WHERE version = 42")
    run_workbench(upgraded, "database-info")
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone() == (42,)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_runtime_transitions_commit_state_and_ordered_events_atomically(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    created = invoke(state_dir, "runtime-create-run", runtime_payload(target))
    run_id = created["id"]
    assert created["status"] == "created"
    assert [phase["state"] for phase in created["phases"]] == ["ready", "pending"]

    claim = {
        "runId": run_id,
        "expectedVersion": created["version"],
        "controllerId": "controller-a",
        "claimToken": "synthetic-claim-a",
    }
    running = invoke(state_dir, "runtime-claim-run", claim)
    assert running["status"] == "running"
    assert running["version"] == 2

    invalid = {
        **claim,
        "expectedVersion": running["version"],
        "phase": {
            "id": "preflight",
            "state": "running",
            "expectedVersion": 1,
            "inputDigest": INPUT_DIGEST,
        },
        "event": {"kind": "phase.started", "source": "runtime"},
    }
    failed = run_workbench(
        state_dir,
        "runtime-transition",
        check=False,
        input_text=json.dumps(invalid),
    )
    assert failed["returncode"] != 0
    unchanged = run_workbench(state_dir, "runtime-get-run", "--run-id", run_id)
    assert unchanged["version"] == 2
    assert unchanged["phases"][0]["state"] == "ready"

    started = invoke(
        state_dir,
        "runtime-transition",
        {
            **claim,
            "expectedVersion": 2,
            "phase": {
                "id": "preflight",
                "state": "running",
                "expectedVersion": 1,
                "inputDigest": INPUT_DIGEST,
            },
            "event": {
                "category": "domain",
                "kind": "phase.started",
                "source": "runtime",
                "phaseId": "preflight",
            },
        },
    )
    completed = invoke(
        state_dir,
        "runtime-transition",
        {
            **claim,
            "expectedVersion": started["version"],
            "phase": {
                "id": "preflight",
                "state": "completed",
                "expectedVersion": 2,
                "output": {"supported": True},
                "outputDigest": OUTPUT_DIGEST,
            },
            "event": {
                "category": "domain",
                "kind": "phase.completed",
                "source": "runtime",
                "phaseId": "preflight",
            },
        },
    )
    events = run_workbench(
        state_dir,
        "runtime-list-events",
        "--run-id",
        run_id,
        "--after-sequence",
        "1",
    )["events"]
    assert [event["sequence"] for event in events] == [2, 3, 4]
    assert [event["kind"] for event in events] == ["run.started", "phase.started", "phase.completed"]
    assert completed["phases"][0]["output"] == {"supported": True}


def test_runtime_controller_claim_is_optimistic_and_private(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    created = invoke(state_dir, "runtime-create-run", runtime_payload(target))
    first = invoke(
        state_dir,
        "runtime-claim-run",
        {
            "runId": created["id"],
            "expectedVersion": 1,
            "controllerId": "controller-a",
            "claimToken": "secret-claim-token",
        },
    )
    assert first["controllerId"] == "controller-a"
    assert "secret-claim-token" not in json.dumps(first)
    losing = run_workbench(
        state_dir,
        "runtime-claim-run",
        check=False,
        input_text=json.dumps(
            {
                "runId": created["id"],
                "expectedVersion": 1,
                "controllerId": "controller-b",
                "claimToken": "other-token",
            }
        ),
    )
    assert losing["returncode"] != 0


def complete_source_phase(
    state_dir: Path, target: Path
) -> tuple[dict[str, object], dict[str, object]]:
    created = invoke(state_dir, "runtime-create-run", runtime_payload(target))
    ownership = {
        "runId": created["id"],
        "expectedVersion": 1,
        "controllerId": f"controller-{created['id']}",
        "claimToken": f"claim-{created['id']}",
    }
    running = invoke(state_dir, "runtime-claim-run", ownership)
    started = invoke(
        state_dir,
        "runtime-transition",
        {
            **ownership,
            "expectedVersion": running["version"],
            "phase": {
                "id": "preflight",
                "state": "running",
                "expectedVersion": 1,
                "inputDigest": INPUT_DIGEST,
            },
            "event": {"category": "domain", "kind": "phase.started", "source": "runtime"},
        },
    )
    completed = invoke(
        state_dir,
        "runtime-transition",
        {
            **ownership,
            "expectedVersion": started["version"],
            "phase": {
                "id": "preflight",
                "state": "completed",
                "expectedVersion": 2,
                "output": {"supported": True},
                "outputDigest": OUTPUT_DIGEST,
            },
            "event": {"category": "domain", "kind": "phase.completed", "source": "runtime"},
        },
    )
    return completed, ownership


def test_runtime_output_reuse_requires_matching_provenance(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    source, _ = complete_source_phase(state_dir, target)
    target_created = invoke(
        state_dir,
        "runtime-create-run",
        runtime_payload(target, parent_run_id=source["id"]),
    )
    ownership = {
        "runId": target_created["id"],
        "expectedVersion": 1,
        "controllerId": "target-controller",
        "claimToken": "target-claim",
    }
    target_running = invoke(state_dir, "runtime-claim-run", ownership)
    prepared = invoke(
        state_dir,
        "runtime-transition",
        {
            **ownership,
            "expectedVersion": target_running["version"],
            "phase": {
                "id": "preflight",
                "state": "ready",
                "expectedVersion": 1,
                "inputDigest": INPUT_DIGEST,
            },
            "event": {"category": "domain", "kind": "phase.input_bound", "source": "runtime"},
        },
    )
    reused = invoke(
        state_dir,
        "runtime-reuse-output",
        {
            **ownership,
            "expectedVersion": prepared["version"],
            "phaseId": "preflight",
            "sourceRunId": source["id"],
            "sourcePhaseId": "preflight",
            "sourceOutputDigest": OUTPUT_DIGEST,
            "validation": {"type": True, "version": True, "input": True, "target": True},
        },
    )
    assert reused["phases"][0]["state"] == "reused"
    assert reused["phases"][0]["reusedFromRunId"] == source["id"]
    events = run_workbench(
        state_dir, "runtime-list-events", "--run-id", reused["id"]
    )["events"]
    assert events[-1]["kind"] == "phase.output_reused"

    incompatible = invoke(
        state_dir,
        "runtime-create-run",
        runtime_payload(target, parent_run_id=source["id"], policy_digest=DIGEST_B),
    )
    incompatible_owner = {
        "runId": incompatible["id"],
        "expectedVersion": 1,
        "controllerId": "incompatible-controller",
        "claimToken": "incompatible-claim",
    }
    incompatible = invoke(state_dir, "runtime-claim-run", incompatible_owner)
    incompatible = invoke(
        state_dir,
        "runtime-transition",
        {
            **incompatible_owner,
            "expectedVersion": incompatible["version"],
            "phase": {
                "id": "preflight",
                "state": "ready",
                "expectedVersion": 1,
                "inputDigest": INPUT_DIGEST,
            },
            "event": {"category": "domain", "kind": "phase.input_bound", "source": "runtime"},
        },
    )
    denied = run_workbench(
        state_dir,
        "runtime-reuse-output",
        check=False,
        input_text=json.dumps(
            {
                **incompatible_owner,
                "expectedVersion": incompatible["version"],
                "phaseId": "preflight",
                "sourceRunId": source["id"],
                "sourcePhaseId": "preflight",
                "sourceOutputDigest": OUTPUT_DIGEST,
                "validation": {},
            }
        ),
    )
    assert denied["returncode"] != 0
    unchanged = run_workbench(
        state_dir, "runtime-get-run", "--run-id", incompatible["id"]
    )
    assert unchanged["phases"][0]["state"] == "ready"
