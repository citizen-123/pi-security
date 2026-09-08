from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import closing
from pathlib import Path

import pytest

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


def terminal_runtime_payload(target: Path) -> dict[str, object]:
    payload = runtime_payload(target)
    payload["workflow"] = {
        "id": "terminal-workflow",
        "version": 1,
        "phases": [
            {
                "id": "preflight",
                "type": "preflight",
                "version": 1,
                "dependencies": [],
            },
            {
                "id": "publication",
                "type": "publication",
                "version": 1,
                "dependencies": ["preflight"],
            },
        ],
    }
    return payload


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
        "event": {
            "kind": "phase.started",
            "source": "runtime",
            "phaseId": "preflight",
        },
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

    mismatched_phase_event = run_workbench(
        state_dir,
        "runtime-transition",
        check=False,
        input_text=json.dumps(
            {
                **claim,
                "expectedVersion": running["version"],
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
                    "phaseId": "discovery",
                },
            }
        ),
    )
    assert mismatched_phase_event["returncode"] != 0
    unchanged = run_workbench(state_dir, "runtime-get-run", "--run-id", run_id)
    assert unchanged["version"] == running["version"]
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


def test_runtime_phase_requires_resolved_dependencies_before_every_running_transition(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    created = invoke(state_dir, "runtime-create-run", runtime_payload(target))
    ownership = {
        "runId": created["id"],
        "expectedVersion": created["version"],
        "controllerId": "dependency-controller",
        "claimToken": "dependency-claim",
    }
    running = invoke(state_dir, "runtime-claim-run", ownership)

    blocked = run_workbench(
        state_dir,
        "runtime-transition",
        check=False,
        input_text=json.dumps(
            {
                **ownership,
                "expectedVersion": running["version"],
                "phase": {
                    "id": "discovery",
                    "state": "running",
                    "expectedVersion": 1,
                    "inputDigest": INPUT_DIGEST,
                },
                "event": {
                    "category": "domain",
                    "kind": "phase.started",
                    "source": "runtime",
                    "phaseId": "discovery",
                },
            }
        ),
    )
    assert blocked["returncode"] != 0
    unchanged = run_workbench(state_dir, "runtime-get-run", "--run-id", created["id"])
    assert unchanged["version"] == running["version"]
    assert unchanged["phases"][1]["state"] == "pending"
    assert [
        event["kind"]
        for event in run_workbench(
            state_dir, "runtime-list-events", "--run-id", created["id"]
        )["events"]
    ] == ["run.created", "run.started"]

    discovery_ready = invoke(
        state_dir,
        "runtime-transition",
        {
            **ownership,
            "expectedVersion": unchanged["version"],
            "phase": {
                "id": "discovery",
                "state": "ready",
                "expectedVersion": 1,
            },
            "event": {
                "category": "domain",
                "kind": "phase.ready",
                "source": "runtime",
                "phaseId": "discovery",
            },
        },
    )
    ready_blocked = run_workbench(
        state_dir,
        "runtime-transition",
        check=False,
        input_text=json.dumps(
            {
                **ownership,
                "expectedVersion": discovery_ready["version"],
                "phase": {
                    "id": "discovery",
                    "state": "running",
                    "expectedVersion": 2,
                    "inputDigest": INPUT_DIGEST,
                },
                "event": {
                    "category": "domain",
                    "kind": "phase.started",
                    "source": "runtime",
                    "phaseId": "discovery",
                },
            }
        ),
    )
    assert ready_blocked["returncode"] != 0
    unchanged = run_workbench(state_dir, "runtime-get-run", "--run-id", created["id"])
    assert unchanged["version"] == discovery_ready["version"]
    assert unchanged["phases"][1]["state"] == "ready"

    preflight_started = invoke(
        state_dir,
        "runtime-transition",
        {
            **ownership,
            "expectedVersion": unchanged["version"],
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
    preflight_completed = invoke(
        state_dir,
        "runtime-transition",
        {
            **ownership,
            "expectedVersion": preflight_started["version"],
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
    assert [phase["state"] for phase in preflight_completed["phases"]] == [
        "completed",
        "ready",
    ]
    discovery_started = invoke(
        state_dir,
        "runtime-transition",
        {
            **ownership,
            "expectedVersion": preflight_completed["version"],
            "phase": {
                "id": "discovery",
                "state": "running",
                "expectedVersion": 2,
                "inputDigest": INPUT_DIGEST,
            },
            "event": {
                "category": "domain",
                "kind": "phase.started",
                "source": "runtime",
                "phaseId": "discovery",
            },
        },
    )
    assert [phase["state"] for phase in discovery_started["phases"]] == [
        "completed",
        "running",
    ]


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
            **ownership,
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
            "event": {
                "category": "domain",
                "kind": "phase.input_bound",
                "source": "runtime",
                "phaseId": "preflight",
            },
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

    dependency_started = invoke(
        state_dir,
        "runtime-transition",
        {
            **ownership,
            "expectedVersion": reused["version"],
            "phase": {
                "id": "discovery",
                "state": "running",
                "expectedVersion": 1,
                "inputDigest": INPUT_DIGEST,
            },
            "event": {
                "category": "domain",
                "kind": "phase.started",
                "source": "runtime",
                "phaseId": "discovery",
            },
        },
    )
    assert dependency_started["phases"][1]["state"] == "running"

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
            "event": {
                "category": "domain",
                "kind": "phase.input_bound",
                "source": "runtime",
                "phaseId": "preflight",
            },
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


def test_runtime_completed_outcome_requires_every_phase_publication_and_coverage(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    created = invoke(state_dir, "runtime-create-run", terminal_runtime_payload(target))
    ownership = {
        "runId": created["id"],
        "expectedVersion": created["version"],
        "controllerId": "terminal-controller",
        "claimToken": "terminal-claim",
    }
    running = invoke(state_dir, "runtime-claim-run", ownership)

    incomplete = run_workbench(
        state_dir,
        "runtime-transition",
        check=False,
        input_text=json.dumps(
            {
                **ownership,
                "expectedVersion": running["version"],
                "status": "completed",
                "progress": {"coverageConclusion": "complete"},
                "event": {"category": "domain", "kind": "run.completed", "source": "runtime"},
            }
        ),
    )
    assert incomplete["returncode"] != 0
    unchanged = run_workbench(state_dir, "runtime-get-run", "--run-id", created["id"])
    assert unchanged["status"] == "running"
    assert unchanged["version"] == running["version"]

    preflight_started = invoke(
        state_dir,
        "runtime-transition",
        {
            **ownership,
            "expectedVersion": unchanged["version"],
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
    preflight_completed = invoke(
        state_dir,
        "runtime-transition",
        {
            **ownership,
            "expectedVersion": preflight_started["version"],
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
    publication_ready = invoke(
        state_dir,
        "runtime-transition",
        {
            **ownership,
            "expectedVersion": preflight_completed["version"],
            "phase": {
                "id": "publication",
                "state": "ready",
                "expectedVersion": 1,
            },
            "event": {
                "category": "domain",
                "kind": "phase.ready",
                "source": "runtime",
                "phaseId": "publication",
            },
        },
    )
    publication_started = invoke(
        state_dir,
        "runtime-transition",
        {
            **ownership,
            "expectedVersion": publication_ready["version"],
            "phase": {
                "id": "publication",
                "state": "running",
                "expectedVersion": 2,
                "inputDigest": INPUT_DIGEST,
            },
            "event": {
                "category": "domain",
                "kind": "phase.started",
                "source": "runtime",
                "phaseId": "publication",
            },
        },
    )
    publication_completed = invoke(
        state_dir,
        "runtime-transition",
        {
            **ownership,
            "expectedVersion": publication_started["version"],
            "phase": {
                "id": "publication",
                "state": "completed",
                "expectedVersion": 3,
                "output": {"published": True},
                "outputDigest": OUTPUT_DIGEST,
            },
            "event": {
                "category": "domain",
                "kind": "phase.completed",
                "source": "runtime",
                "phaseId": "publication",
            },
        },
    )

    missing_coverage = run_workbench(
        state_dir,
        "runtime-transition",
        check=False,
        input_text=json.dumps(
            {
                **ownership,
                "expectedVersion": publication_completed["version"],
                "status": "completed",
                "progress": {"coverageConclusion": "inconclusive"},
                "event": {"category": "domain", "kind": "run.completed", "source": "runtime"},
            }
        ),
    )
    assert missing_coverage["returncode"] != 0
    premature_coverage = run_workbench(
        state_dir,
        "runtime-transition",
        check=False,
        input_text=json.dumps(
            {
                **ownership,
                "expectedVersion": publication_completed["version"],
                "progress": {"coverageConclusion": "complete"},
                "event": {
                    "category": "domain",
                    "kind": "run.coverage_recorded",
                    "source": "runtime",
                },
            }
        ),
    )
    assert premature_coverage["returncode"] != 0
    assert run_workbench(state_dir, "runtime-get-run", "--run-id", created["id"]) == publication_completed

    # Runs persisted before the coverage guard must still be interruptible.
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE workflow_runs SET progress_json = ? WHERE id = ?",
            (json.dumps({"coverageConclusion": "complete"}), created["id"]),
        )
    interrupted = invoke(
        state_dir,
        "runtime-transition",
        {
            **ownership,
            "expectedVersion": publication_completed["version"],
            "status": "interrupted",
            "event": {
                "category": "domain",
                "kind": "run.interrupted",
                "source": "runtime",
            },
        },
    )
    assert interrupted["status"] == "interrupted"
    assert interrupted["progress"] == {"coverageConclusion": "inconclusive"}
    assert interrupted["phases"] == publication_completed["phases"]
    resumed = invoke(
        state_dir,
        "runtime-claim-run",
        {
            **ownership,
            "expectedVersion": interrupted["version"],
        },
    )
    assert resumed["status"] == "running"
    assert resumed["progress"] == {"coverageConclusion": "inconclusive"}

    completed = invoke(
        state_dir,
        "runtime-transition",
        {
            **ownership,
            "expectedVersion": resumed["version"],
            "status": "completed",
            "progress": {"coverageConclusion": "complete"},
            "event": {"category": "domain", "kind": "run.completed", "source": "runtime"},
        },
    )
    assert completed["status"] == "completed"
    assert completed["completedAt"] is not None
    assert completed["controllerId"] is None
    assert completed["progress"] == {"coverageConclusion": "complete"}


def test_runtime_phase_transitions_preserve_terminal_output_and_reuse_provenance(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    created = invoke(state_dir, "runtime-create-run", runtime_payload(target))
    ownership = {
        "runId": created["id"],
        "expectedVersion": created["version"],
        "controllerId": "phase-controller",
        "claimToken": "phase-claim",
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
            **ownership,
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

    regressed = run_workbench(
        state_dir,
        "runtime-transition",
        check=False,
        input_text=json.dumps(
            {
                **ownership,
                "expectedVersion": completed["version"],
                "phase": {
                    "id": "preflight",
                    "state": "running",
                    "expectedVersion": 3,
                },
                "event": {
                    "category": "domain",
                    "kind": "phase.restarted",
                    "source": "runtime",
                    "phaseId": "preflight",
                },
            }
        ),
    )
    assert regressed["returncode"] != 0
    unproven_reuse = run_workbench(
        state_dir,
        "runtime-transition",
        check=False,
        input_text=json.dumps(
            {
                **ownership,
                "expectedVersion": completed["version"],
                "phase": {
                    "id": "discovery",
                    "state": "reused",
                    "expectedVersion": 1,
                    "output": {"unverified": True},
                    "outputDigest": OUTPUT_DIGEST,
                },
                "event": {
                    "category": "domain",
                    "kind": "phase.output_reused",
                    "source": "runtime",
                    "phaseId": "discovery",
                },
            }
        ),
    )
    assert unproven_reuse["returncode"] != 0
    unchanged = run_workbench(state_dir, "runtime-get-run", "--run-id", created["id"])
    assert unchanged["version"] == completed["version"]
    assert unchanged["phases"][0]["state"] == "completed"
    assert unchanged["phases"][0]["output"] == {"supported": True}
    assert unchanged["phases"][1]["state"] == "pending"
    assert unchanged["phases"][1]["reusedFromRunId"] is None
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM workflow_output_reuse WHERE run_id = ?",
            (created["id"],),
        ).fetchone() == (0,)


def test_runtime_output_reuse_rolls_back_when_target_phase_is_not_reusable(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    source, _ = complete_source_phase(state_dir, target)
    created = invoke(
        state_dir,
        "runtime-create-run",
        runtime_payload(target, parent_run_id=source["id"]),
    )
    ownership = {
        "runId": created["id"],
        "expectedVersion": created["version"],
        "controllerId": "reuse-controller",
        "claimToken": "reuse-claim",
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
            "event": {
                "category": "domain",
                "kind": "phase.started",
                "source": "runtime",
                "phaseId": "preflight",
            },
        },
    )
    events_before = run_workbench(
        state_dir, "runtime-list-events", "--run-id", created["id"]
    )["events"]
    rejected = run_workbench(
        state_dir,
        "runtime-reuse-output",
        check=False,
        input_text=json.dumps(
            {
                **ownership,
                "expectedVersion": started["version"],
                "phaseId": "preflight",
                "sourceRunId": source["id"],
                "sourcePhaseId": "preflight",
                "sourceOutputDigest": OUTPUT_DIGEST,
                "validation": {"type": True, "version": True, "input": True, "target": True},
            }
        ),
    )
    assert rejected["returncode"] != 0
    unchanged = run_workbench(state_dir, "runtime-get-run", "--run-id", created["id"])
    assert unchanged["version"] == started["version"]
    assert unchanged["phases"][0]["state"] == "running"
    assert unchanged["phases"][0]["output"] is None
    assert unchanged["phases"][0]["reusedFromRunId"] is None
    assert run_workbench(
        state_dir, "runtime-list-events", "--run-id", created["id"]
    )["events"] == events_before
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM workflow_output_reuse WHERE run_id = ?",
            (created["id"],),
        ).fetchone() == (0,)


def test_runtime_events_validate_phase_agent_and_attempt_bindings(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    created = invoke(state_dir, "runtime-create-run", runtime_payload(target))
    ownership = {
        "runId": created["id"],
        "expectedVersion": created["version"],
        "controllerId": "event-controller",
        "claimToken": "event-claim",
    }
    running = invoke(state_dir, "runtime-claim-run", ownership)
    foreign = invoke(state_dir, "runtime-create-run", runtime_payload(target))
    logical_agent_id = str(uuid.uuid4())
    attempt_id = str(uuid.uuid4())
    foreign_agent_id = str(uuid.uuid4())
    foreign_attempt_id = str(uuid.uuid4())
    timestamp = "2026-09-03T00:00:00Z"
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            """
            INSERT INTO workflow_logical_agents (
                id, run_id, phase_id, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (logical_agent_id, created["id"], "preflight", "running", timestamp, timestamp),
        )
        connection.execute(
            """
            INSERT INTO workflow_attempts (
                id, logical_agent_id, ordinal, status, details_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (attempt_id, logical_agent_id, 1, "running", "{}", timestamp, timestamp),
        )
        connection.execute(
            """
            INSERT INTO workflow_logical_agents (
                id, run_id, phase_id, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (foreign_agent_id, foreign["id"], "preflight", "running", timestamp, timestamp),
        )
        connection.execute(
            """
            INSERT INTO workflow_attempts (
                id, logical_agent_id, ordinal, status, details_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (foreign_attempt_id, foreign_agent_id, 1, "running", "{}", timestamp, timestamp),
        )

    def reject_event(event: dict[str, object]) -> None:
        rejected = run_workbench(
            state_dir,
            "runtime-record-event",
            check=False,
            input_text=json.dumps(
                {
                    **ownership,
                    "expectedVersion": running["version"],
                    "event": event,
                }
            ),
        )
        assert rejected["returncode"] != 0


    reject_event(
        {
            "category": "activity",
            "kind": "agent.activity",
            "source": "runtime",
            "phaseId": "unknown-phase",
        }
    )
    reject_event(
        {
            "category": "activity",
            "kind": "agent.activity",
            "source": "runtime",
            "phaseId": "preflight",
            "logicalAgentId": foreign_agent_id,
            "attemptId": foreign_attempt_id,
        }
    )
    reject_event(
        {
            "category": "activity",
            "kind": "agent.activity",
            "source": "runtime",
            "phaseId": "discovery",
            "logicalAgentId": logical_agent_id,
            "attemptId": attempt_id,
        }
    )
    reject_event(
        {
            "category": "activity",
            "kind": "agent.activity",
            "source": "runtime",
            "phaseId": "preflight",
            "logicalAgentId": logical_agent_id,
            "attemptId": foreign_attempt_id,
        }
    )
    reject_event(
        {
            "category": "activity",
            "kind": "agent.activity",
            "source": "runtime",
            "attemptId": attempt_id,
        }
    )
    unchanged = run_workbench(state_dir, "runtime-get-run", "--run-id", created["id"])
    assert unchanged["version"] == running["version"]
    assert [
        event["kind"]
        for event in run_workbench(
            state_dir, "runtime-list-events", "--run-id", created["id"]
        )["events"]
    ] == ["run.created", "run.started"]

    recorded = invoke(
        state_dir,
        "runtime-record-event",
        {
            **ownership,
            "expectedVersion": unchanged["version"],
            "event": {
                "category": "activity",
                "kind": "agent.activity",
                "source": "runtime",
                "phaseId": "preflight",
                "logicalAgentId": logical_agent_id,
                "attemptId": attempt_id,
            },
        },
    )
    assert recorded == {
        "runId": created["id"],
        "sequence": 3,
        "version": running["version"] + 1,
    }


def test_runtime_get_run_reads_one_database_snapshot(
    tmp_path: Path, workbench_api, workbench_schema
) -> None:
    state = workbench_api["runtime_state"]
    clock = lambda: "2026-09-03T00:00:00Z"
    database = tmp_path / "runtime.sqlite3"
    with closing(sqlite3.connect(database)) as reader, closing(
        sqlite3.connect(database)
    ) as writer:
        workbench_schema.backup(reader)
        reader.row_factory = writer.row_factory = sqlite3.Row
        reader.execute("PRAGMA journal_mode = WAL")
        created = state.create_run(writer, runtime_payload(tmp_path), clock)
        ownership = {
            "runId": created["id"],
            "controllerId": "snapshot-controller",
            "claimToken": "snapshot-claim",
            "expectedVersion": created["version"],
        }
        running = state.claim_run(writer, ownership, clock)
        committed = []

        def advance_between_queries(statement: str) -> None:
            if not statement.startswith("SELECT * FROM workflow_phases"):
                return
            reader.set_trace_callback(None)
            committed.append(
                state.transition(
                    writer,
                    {
                        **ownership,
                        "expectedVersion": running["version"],
                        "phase": {"id": "preflight", "expectedVersion": 1, "state": "running"},
                        "progress": {"activePhase": "preflight"},
                        "event": {
                            "category": "domain",
                            "kind": "phase.started",
                            "source": "runtime",
                            "phaseId": "preflight",
                        },
                    },
                    clock,
                )
            )

        reader.set_trace_callback(advance_between_queries)
        observed = state.get_run(reader, created["id"])
        assert observed == running
        assert state.get_run(reader, created["id"]) == committed[0]
        assert committed[0]["phases"][0]["state"] == "running"
        assert committed[0]["version"] == running["version"] + 1


def test_runtime_mutation_response_does_not_adopt_a_later_controller_claim(
    tmp_path: Path, workbench_api, workbench_schema
) -> None:
    state = workbench_api["runtime_state"]
    clock = lambda: "2026-09-03T00:00:00Z"
    payload = runtime_payload(tmp_path)
    database = tmp_path / "runtime.sqlite3"
    ownership = {
        "runId": payload["runId"],
        "controllerId": "next-controller",
        "claimToken": "next-claim",
        "expectedVersion": 1,
    }

    class ClaimAfterCommit(sqlite3.Connection):
        claim_after_commit = False

        def commit(self) -> None:
            super().commit()
            if self.claim_after_commit:
                self.claim_after_commit = False
                state.claim_run(writer, ownership, clock)

    with closing(sqlite3.connect(database, factory=ClaimAfterCommit)) as creator, closing(
        sqlite3.connect(database)
    ) as writer:
        workbench_schema.backup(creator)
        creator.row_factory = writer.row_factory = sqlite3.Row
        creator.execute("PRAGMA journal_mode = WAL")
        creator.claim_after_commit = True
        created = state.create_run(creator, payload, clock)
        assert created["status"] == "created"
        assert created["version"] == 1
        assert created["controllerId"] is None
        durable = state.get_run(writer, payload["runId"])
        assert durable["status"] == "running"
        assert durable["version"] == 2
        assert durable["controllerId"] == ownership["controllerId"]


def test_runtime_reuse_rejects_unbound_input_identity(
    tmp_path: Path, workbench_api, workbench_db
) -> None:
    state = workbench_api["runtime_state"]
    clock = lambda: "2026-09-03T00:00:00Z"
    source = state.create_run(workbench_db, runtime_payload(tmp_path), clock)
    ownership = {
        "runId": source["id"],
        "controllerId": "source-controller",
        "claimToken": "source-claim",
        "expectedVersion": source["version"],
    }
    source = state.claim_run(workbench_db, ownership, clock)
    for phase_state, output in (
        ("running", {}),
        ("completed", {"output": {"supported": True}, "outputDigest": OUTPUT_DIGEST}),
    ):
        source = state.transition(
            workbench_db,
            {
                **ownership,
                "expectedVersion": source["version"],
                "phase": {
                    "id": "preflight",
                    "state": phase_state,
                    "expectedVersion": source["phases"][0]["version"],
                    **output,
                },
                "event": {
                    "category": "domain",
                    "kind": f"phase.{phase_state}",
                    "source": "runtime",
                    "phaseId": "preflight",
                },
            },
            clock,
        )
    target = state.create_run(
        workbench_db, runtime_payload(tmp_path, parent_run_id=source["id"]), clock
    )
    ownership = {**ownership, "runId": target["id"], "expectedVersion": target["version"]}
    target = state.claim_run(workbench_db, ownership, clock)
    before_events = state.list_events(workbench_db, target["id"], 0)
    with pytest.raises(SystemExit, match="input digests"):
        state.reuse_output(
            workbench_db,
            {
                **ownership,
                "expectedVersion": target["version"],
                "phaseId": "preflight",
                "sourceRunId": source["id"],
                "sourcePhaseId": "preflight",
                "sourceOutputDigest": OUTPUT_DIGEST,
                "validation": {},
            },
            clock,
        )
    assert state.get_run(workbench_db, target["id"]) == target
    assert state.list_events(workbench_db, target["id"], 0) == before_events
    assert workbench_db.execute("SELECT COUNT(*) FROM workflow_output_reuse").fetchone()[0] == 0


def test_runtime_transition_requires_domain_event_and_rolls_back_journal_failure(
    tmp_path: Path, workbench_api, workbench_db
) -> None:
    state = workbench_api["runtime_state"]
    clock = lambda: "2026-09-03T00:00:00Z"
    created = state.create_run(workbench_db, runtime_payload(tmp_path), clock)
    ownership = {
        "runId": created["id"],
        "controllerId": "event-controller",
        "claimToken": "event-claim",
        "expectedVersion": created["version"],
    }
    running = state.claim_run(workbench_db, ownership, clock)
    transition = {
        **ownership,
        "expectedVersion": running["version"],
        "phase": {"id": "preflight", "expectedVersion": 1, "state": "running"},
        "progress": {"activePhase": "preflight"},
        "event": {
            "category": "activity",
            "kind": "phase.started",
            "source": "runtime",
            "phaseId": "preflight",
        },
    }
    events = state.list_events(workbench_db, created["id"], 0)
    with pytest.raises(SystemExit, match="event.category"):
        state.transition(workbench_db, transition, clock)
    assert state.get_run(workbench_db, created["id"]) == running
    assert state.list_events(workbench_db, created["id"], 0) == events

    workbench_db.execute(
        """
        CREATE TRIGGER reject_runtime_event BEFORE INSERT ON workflow_events
        BEGIN SELECT RAISE(ABORT, 'synthetic journal failure'); END
        """
    )
    transition["event"]["category"] = "domain"
    with pytest.raises(sqlite3.IntegrityError, match="synthetic journal failure"):
        state.transition(workbench_db, transition, clock)
    assert state.get_run(workbench_db, created["id"]) == running
    assert state.list_events(workbench_db, created["id"], 0) == events


def test_runtime_rejects_non_hex_digest_identity(
    tmp_path: Path, workbench_api, workbench_db
) -> None:
    state = workbench_api["runtime_state"]
    payload = {
        **runtime_payload(tmp_path),
        "snapshotDigest": "sha256:" + "a" * 31 + "_" + "a" * 32,
    }
    with pytest.raises(SystemExit, match="sha256 digest"):
        state.create_run(workbench_db, payload, lambda: "2026-09-03T00:00:00Z")
    assert workbench_db.execute("SELECT COUNT(*) FROM workflow_runs").fetchone()[0] == 0
    assert workbench_db.execute("SELECT COUNT(*) FROM workflow_events").fetchone()[0] == 0


def test_runtime_rejects_cyclic_workflow_before_persistence(
    tmp_path: Path, workbench_api, workbench_db
) -> None:
    state = workbench_api["runtime_state"]
    payload = runtime_payload(tmp_path)
    payload["workflow"]["phases"][0]["dependencies"] = ["discovery"]
    with pytest.raises(SystemExit, match="acyclic"):
        state.create_run(workbench_db, payload, lambda: "2026-09-03T00:00:00Z")
    assert workbench_db.execute("SELECT COUNT(*) FROM workflow_runs").fetchone()[0] == 0
    assert workbench_db.execute("SELECT COUNT(*) FROM workflow_phases").fetchone()[0] == 0
    assert workbench_db.execute("SELECT COUNT(*) FROM workflow_events").fetchone()[0] == 0


def test_runtime_rejects_self_parent_link(
    tmp_path: Path, workbench_api, workbench_db
) -> None:
    state = workbench_api["runtime_state"]
    payload = runtime_payload(tmp_path)
    payload["parentRunId"] = payload["runId"]
    with pytest.raises(SystemExit, match="own parent"):
        state.create_run(workbench_db, payload, lambda: "2026-09-03T00:00:00Z")
    assert workbench_db.execute("SELECT COUNT(*) FROM workflow_runs").fetchone()[0] == 0
    assert workbench_db.execute("SELECT COUNT(*) FROM workflow_events").fetchone()[0] == 0


@pytest.mark.skipif(os.name == "nt", reason="Windows normalizes trailing spaces in directory names")
def test_runtime_preserves_target_path_whitespace(
    tmp_path: Path, workbench_api, workbench_db
) -> None:
    intended_target = tmp_path / "repository "
    intended_target.mkdir()
    (tmp_path / "repository").mkdir()
    created = workbench_api["runtime_state"].create_run(
        workbench_db,
        runtime_payload(intended_target),
        lambda: "2026-09-03T00:00:00Z",
    )
    assert created["targetPath"] == str(intended_target.resolve())
    assert created["targetPath"] == created["snapshot"]["resolved"]["scan"]["target"]


def test_runtime_persists_logical_agents_attempts_sessions_and_activity(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    created = invoke(state_dir, "runtime-create-run", runtime_payload(target))
    ownership = {
        "runId": created["id"],
        "expectedVersion": created["version"],
        "controllerId": "agent-controller",
        "claimToken": "agent-claim",
    }
    running = invoke(state_dir, "runtime-claim-run", ownership)
    logical_agent_id = str(uuid.uuid4())
    attempt_id = str(uuid.uuid4())
    started = invoke(
        state_dir,
        "runtime-start-attempt",
        {
            **ownership,
            "expectedVersion": running["version"],
            "phaseId": "preflight",
            "logicalAgentId": logical_agent_id,
            "attemptId": attempt_id,
            "ordinal": 1,
            "details": {"roleId": "deterministic-preflight"},
        },
    )
    assert started["status"] == "starting"
    bound = invoke(
        state_dir,
        "runtime-update-attempt",
        {
            **ownership,
            "expectedVersion": started["version"],
            "attemptId": attempt_id,
            "status": "running",
            "piSessionId": "synthetic-pi-session",
            "details": {"providerSessionId": "synthetic-provider-session"},
            "event": {
                "category": "activity",
                "kind": "agent.session_bound",
                "source": "runtime",
                "phaseId": "preflight",
                "logicalAgentId": logical_agent_id,
                "attemptId": attempt_id,
                "correlationId": "synthetic-correlation",
            },
        },
    )
    agent = run_workbench(
        state_dir,
        "runtime-get-agent",
        "--run-id",
        created["id"],
        "--logical-agent-id",
        logical_agent_id,
    )
    assert agent["id"] == logical_agent_id
    assert agent["attempts"] == [
        {
            "id": attempt_id,
            "ordinal": 1,
            "piSessionId": "synthetic-pi-session",
            "status": "running",
            "failureCategory": None,
            "details": {"providerSessionId": "synthetic-provider-session"},
            "createdAt": agent["attempts"][0]["createdAt"],
            "updatedAt": agent["attempts"][0]["updatedAt"],
        }
    ]
    events = run_workbench(
        state_dir, "runtime-list-events", "--run-id", created["id"]
    )["events"]
    assert events[-1]["sequence"] == 4
    assert events[-1]["correlationId"] == "synthetic-correlation"

    duplicate = run_workbench(
        state_dir,
        "runtime-start-attempt",
        check=False,
        input_text=json.dumps(
            {
                **ownership,
                "expectedVersion": bound["version"],
                "phaseId": "preflight",
                "logicalAgentId": logical_agent_id,
                "attemptId": str(uuid.uuid4()),
                "ordinal": 2,
            }
        ),
    )
    assert duplicate["returncode"] != 0
    unchanged = run_workbench(state_dir, "runtime-get-run", "--run-id", created["id"])
    assert unchanged["version"] == bound["version"]
    failed = invoke(
        state_dir,
        "runtime-update-attempt",
        {
            **ownership,
            "expectedVersion": unchanged["version"],
            "attemptId": attempt_id,
            "status": "failed",
            "failureCategory": "transport",
            "event": {
                "category": "domain",
                "kind": "agent.attempt_failed",
                "source": "runtime",
                "phaseId": "preflight",
                "logicalAgentId": logical_agent_id,
                "attemptId": attempt_id,
            },
        },
    )
    replacement_id = str(uuid.uuid4())
    replacement = invoke(
        state_dir,
        "runtime-start-attempt",
        {
            **ownership,
            "expectedVersion": failed["version"],
            "phaseId": "preflight",
            "logicalAgentId": logical_agent_id,
            "attemptId": replacement_id,
            "ordinal": 2,
        },
    )
    replacement = invoke(
        state_dir,
        "runtime-update-attempt",
        {
            **ownership,
            "expectedVersion": replacement["version"],
            "attemptId": replacement_id,
            "status": "running",
            "piSessionId": "synthetic-pi-session-2",
            "event": {
                "category": "domain",
                "kind": "agent.session_bound",
                "source": "runtime",
                "phaseId": "preflight",
                "logicalAgentId": logical_agent_id,
                "attemptId": replacement_id,
            },
        },
    )
    replaced_agent = run_workbench(
        state_dir,
        "runtime-get-agent",
        "--run-id",
        created["id"],
        "--logical-agent-id",
        logical_agent_id,
    )
    assert replaced_agent["id"] == logical_agent_id
    assert [attempt["id"] for attempt in replaced_agent["attempts"]] == [
        attempt_id,
        replacement_id,
    ]
    assert [attempt["piSessionId"] for attempt in replaced_agent["attempts"]] == [
        "synthetic-pi-session",
        "synthetic-pi-session-2",
    ]
    assert replacement["version"] == failed["version"] + 2


def test_attempt_updates_bind_events_and_preserve_session_and_retry_order(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    created = invoke(state_dir, "runtime-create-run", runtime_payload(target))
    ownership = {
        "runId": created["id"],
        "controllerId": "synthetic-controller",
        "claimToken": "synthetic-claim",
    }
    current = invoke(state_dir, "runtime-claim-run", {**ownership, "expectedVersion": 1})
    agents = [str(uuid.uuid4()), str(uuid.uuid4())]
    attempts = [str(uuid.uuid4()), str(uuid.uuid4())]
    for agent, attempt in zip(agents, attempts):
        current = invoke(state_dir, "runtime-start-attempt", {
            **ownership, "expectedVersion": current["version"], "phaseId": "preflight",
            "logicalAgentId": agent, "attemptId": attempt, "ordinal": 1,
        })
    event = {"category": "domain", "kind": "agent.session_bound", "source": "runtime"}
    mismatch = run_workbench(state_dir, "runtime-update-attempt", check=False, input_text=json.dumps({
        **ownership, "expectedVersion": current["version"], "attemptId": attempts[0],
        "status": "running", "piSessionId": "synthetic-session",
        "event": {**event, "logicalAgentId": agents[1], "attemptId": attempts[1]},
    }))
    assert mismatch["returncode"] != 0
    agent = run_workbench(state_dir, "runtime-get-agent", "--run-id", created["id"], "--logical-agent-id", agents[0])
    assert agent["attempts"][0]["status"] == "starting"
    current = invoke(state_dir, "runtime-update-attempt", {
        **ownership, "expectedVersion": current["version"], "attemptId": attempts[0],
        "status": "running", "piSessionId": "synthetic-session", "event": event,
    })
    recorded = run_workbench(state_dir, "runtime-list-events", "--run-id", created["id"])["events"][-1]
    assert (recorded["phaseId"], recorded["logicalAgentId"], recorded["attemptId"]) == (
        "preflight", agents[0], attempts[0],
    )
    rebind = run_workbench(state_dir, "runtime-update-attempt", check=False, input_text=json.dumps({
        **ownership, "expectedVersion": current["version"], "attemptId": attempts[0],
        "status": "failed", "piSessionId": "foreign-session", "event": event,
    }))
    assert rebind["returncode"] != 0
    current = invoke(state_dir, "runtime-update-attempt", {
        **ownership, "expectedVersion": current["version"], "attemptId": attempts[0],
        "status": "failed", "event": event,
    })
    replacement = {
        **ownership, "expectedVersion": current["version"], "phaseId": "preflight",
        "logicalAgentId": agents[0], "attemptId": str(uuid.uuid4()),
    }
    skipped = run_workbench(state_dir, "runtime-start-attempt", check=False, input_text=json.dumps({
        **replacement, "ordinal": 4,
    }))
    assert skipped["returncode"] != 0
    invoke(state_dir, "runtime-start-attempt", {**replacement, "ordinal": 2})
    agent = run_workbench(state_dir, "runtime-get-agent", "--run-id", created["id"], "--logical-agent-id", agents[0])
    assert [attempt["ordinal"] for attempt in agent["attempts"]] == [1, 2]
    assert agent["attempts"][0]["piSessionId"] == "synthetic-session"
