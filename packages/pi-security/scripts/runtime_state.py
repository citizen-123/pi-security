"""Transactional persistence for canonical Pi Security workflow runs."""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Callable

RUN_STATUSES = frozenset({"created", "running", "interrupted", "completed", "failed", "canceled"})
TERMINAL_RUN_STATUSES = frozenset({"completed", "failed", "canceled"})
PHASE_STATES = frozenset(
    {"pending", "ready", "running", "completed", "failed", "interrupted", "canceled", "skipped", "reused"}
)
RUN_TRANSITIONS = {
    "created": frozenset({"running", "failed", "canceled"}),
    "running": frozenset({"interrupted", "completed", "failed", "canceled"}),
    "interrupted": frozenset({"running", "failed", "canceled"}),
    "completed": frozenset(),
    "failed": frozenset(),
    "canceled": frozenset(),
}
PHASE_TRANSITIONS = {
    "pending": frozenset({"ready", "running", "skipped", "canceled"}),
    "ready": frozenset({"ready", "running", "skipped", "canceled"}),
    "running": frozenset({"completed", "failed", "interrupted", "canceled"}),
    "interrupted": frozenset({"running", "failed", "canceled"}),
    "failed": frozenset(),
    "completed": frozenset(),
    "canceled": frozenset(),
    "skipped": frozenset(),
    "reused": frozenset(),
}



def create_run(
    connection: sqlite3.Connection,
    payload: dict[str, Any],
    clock: Callable[[], str],
) -> dict[str, Any]:
    run_id = require_uuid(payload.get("runId"), "runId")
    parent_run_id = optional_uuid(payload.get("parentRunId"), "parentRunId")
    if parent_run_id == run_id:
        raise SystemExit("Workflow run cannot be its own parent.")
    scan_id = optional_uuid(payload.get("scanId"), "scanId")
    workflow = require_object(payload.get("workflow"), "workflow")
    snapshot = require_object(payload.get("snapshot"), "snapshot")
    phases = require_list(workflow.get("phases"), "workflow.phases")
    workflow_id = require_text(workflow.get("id"), "workflow.id")
    workflow_version = require_positive_int(workflow.get("version"), "workflow.version")
    snapshot_digest = require_digest(payload.get("snapshotDigest"), "snapshotDigest")
    policy_digest = require_digest(payload.get("policyDigest"), "policyDigest")
    target_path_value = payload.get("targetPath")
    require_text(target_path_value, "targetPath")
    target_path = str(Path(target_path_value).expanduser().resolve())
    target_revision = optional_text(payload.get("targetRevision"), "targetRevision")
    timestamp = clock()

    seen: set[str] = set()
    normalized_phases: list[dict[str, Any]] = []
    for index, phase_value in enumerate(phases):
        phase = require_object(phase_value, f"workflow.phases[{index}]")
        phase_id = require_text(phase.get("id"), f"workflow.phases[{index}].id")
        if phase_id in seen:
            raise SystemExit(f"Duplicate workflow phase ID: {phase_id}")
        seen.add(phase_id)
        dependencies = require_string_list(
            phase.get("dependencies", []), f"workflow.phases[{index}].dependencies"
        )
        normalized_phases.append(
            {
                "id": phase_id,
                "type": require_text(phase.get("type"), f"workflow.phases[{index}].type"),
                "version": require_positive_int(
                    phase.get("version"), f"workflow.phases[{index}].version"
                ),
                "roleId": optional_text(phase.get("roleId"), f"workflow.phases[{index}].roleId"),
                "dependencies": dependencies,
                "state": "ready" if not dependencies else "pending",
            }
        )
    for phase in normalized_phases:
        missing = [dependency for dependency in phase["dependencies"] if dependency not in seen]
        if missing:
            raise SystemExit(
                f"Workflow phase {phase['id']} depends on unknown phase {missing[0]}."
            )
    dependents: dict[str, list[str]] = {phase["id"]: [] for phase in normalized_phases}
    pending_dependencies = {
        phase["id"]: len(phase["dependencies"]) for phase in normalized_phases
    }
    for phase in normalized_phases:
        for dependency in phase["dependencies"]:
            dependents[dependency].append(phase["id"])
    ready = [phase_id for phase_id, count in pending_dependencies.items() if count == 0]
    for phase_id in ready:
        for dependent in dependents[phase_id]:
            pending_dependencies[dependent] -= 1
            if pending_dependencies[dependent] == 0:
                ready.append(dependent)
    if len(ready) != len(normalized_phases):
        raise SystemExit("Workflow phase dependencies must be acyclic.")

    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            """
            INSERT INTO workflow_runs (
                id, scan_id, parent_run_id, workflow_id, workflow_version,
                workflow_json, snapshot_json, snapshot_digest, target_path,
                target_revision, policy_digest, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'created', ?, ?)
            """,
            (
                run_id,
                scan_id,
                parent_run_id,
                workflow_id,
                workflow_version,
                canonical_json(workflow),
                canonical_json(snapshot),
                snapshot_digest,
                target_path,
                target_revision,
                policy_digest,
                timestamp,
                timestamp,
            ),
        )
        for phase in normalized_phases:
            connection.execute(
                """
                INSERT INTO workflow_phases (
                    run_id, phase_id, phase_type, phase_version, role_id,
                    dependencies_json, state, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    phase["id"],
                    phase["type"],
                    phase["version"],
                    phase["roleId"],
                    canonical_json(phase["dependencies"]),
                    phase["state"],
                    timestamp,
                    timestamp,
                ),
            )
        append_event(
            connection,
            run_id,
            {
                "category": "domain",
                "kind": "run.created",
                "source": "runtime",
                "payload": {"workflowId": workflow_id, "workflowVersion": workflow_version},
            },
            timestamp,
        )
        result = get_run(connection, run_id)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return result


def claim_run(
    connection: sqlite3.Connection,
    payload: dict[str, Any],
    clock: Callable[[], str],
) -> dict[str, Any]:
    run_id = require_uuid(payload.get("runId"), "runId")
    controller_id = require_text(payload.get("controllerId"), "controllerId")
    claim_token = require_text(payload.get("claimToken"), "claimToken")
    expected_version = require_positive_int(payload.get("expectedVersion"), "expectedVersion")
    timestamp = clock()
    connection.execute("BEGIN IMMEDIATE")
    try:
        run = require_run(connection, run_id)
        if run["version"] != expected_version:
            raise SystemExit("Workflow run version changed before controller claim.")
        if run["status"] not in {"created", "interrupted"}:
            raise SystemExit(f"Workflow run in state {run['status']} cannot be claimed.")
        if run["controller_id"] is not None:
            raise SystemExit("Workflow run already has a controller owner.")
        validate_run_outcome(connection, run_id, "running")
        changed = connection.execute(
            """
            UPDATE workflow_runs
            SET status = 'running', controller_id = ?, controller_claim_token = ?,
                version = version + 1, updated_at = ?
            WHERE id = ? AND version = ? AND controller_id IS NULL
            """,
            (controller_id, claim_token, timestamp, run_id, expected_version),
        ).rowcount
        if changed != 1:
            raise SystemExit("Workflow run controller claim lost a concurrent update.")
        append_event(
            connection,
            run_id,
            {
                "category": "domain",
                "kind": "run.started" if run["status"] == "created" else "run.resumed",
                "source": "runtime",
                "payload": {"controllerId": controller_id},
            },
            timestamp,
        )
        result = get_run(connection, run_id)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return result


def transition(
    connection: sqlite3.Connection,
    payload: dict[str, Any],
    clock: Callable[[], str],
) -> dict[str, Any]:
    run_id = require_uuid(payload.get("runId"), "runId")
    expected_version = require_positive_int(payload.get("expectedVersion"), "expectedVersion")
    controller_id = require_text(payload.get("controllerId"), "controllerId")
    claim_token = require_text(payload.get("claimToken"), "claimToken")
    event = require_object(payload.get("event"), "event")
    require_choice(event.get("category"), {"domain"}, "event.category")
    timestamp = clock()
    connection.execute("BEGIN IMMEDIATE")
    try:
        run = require_owned_run(
            connection, run_id, expected_version, controller_id, claim_token
        )
        phase_change = payload.get("phase")
        if phase_change is not None:
            phase_change = require_object(phase_change, "phase")
            phase_id = require_text(phase_change.get("id"), "phase.id")
            if optional_text(event.get("phaseId"), "event.phaseId") != phase_id:
                raise SystemExit(
                    "Workflow phase transition event must name the transitioning phase."
                )
            update_phase(connection, run, phase_change, timestamp)
        progress = payload.get("progress")
        if progress is not None:
            require_object(progress, "progress")
            if progress.get("coverageConclusion") == "complete" and payload.get("status") != "completed":
                raise SystemExit("Only a completed workflow run may claim complete coverage.")
            connection.execute(
                "UPDATE workflow_runs SET progress_json = ? WHERE id = ?",
                (canonical_json(progress), run_id),
            )
        next_status = payload.get("status")
        status_reason = optional_text(payload.get("statusReason"), "statusReason")
        completed_at: str | None = None
        controller_after: str | None = controller_id
        claim_after: str | None = claim_token
        frozen = int(run["output_admission_frozen"])
        if next_status is not None:
            next_status = require_choice(next_status, RUN_STATUSES, "status")
            if next_status not in RUN_TRANSITIONS[run["status"]]:
                raise SystemExit(
                    f"Workflow run cannot transition from {run['status']} to {next_status}."
                )
            if next_status in TERMINAL_RUN_STATUSES:
                completed_at = timestamp
                controller_after = None
                claim_after = None
            elif next_status == "interrupted":
                controller_after = None
                claim_after = None
            if next_status == "canceled":
                frozen = 1
        else:
            next_status = run["status"]
        validate_run_outcome(connection, run_id, next_status)
        connection.execute(
            """
            UPDATE workflow_runs
            SET status = ?, status_reason = ?, progress_json = COALESCE(progress_json, '{}'),
                controller_id = ?, controller_claim_token = ?, output_admission_frozen = ?,
                version = version + 1, updated_at = ?, completed_at = ?
            WHERE id = ? AND version = ?
            """,
            (
                next_status,
                status_reason,
                controller_after,
                claim_after,
                frozen,
                timestamp,
                completed_at,
                run_id,
                expected_version,
            ),
        )
        append_event(connection, run_id, event, timestamp)
        result = get_run(connection, run_id)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return result


def record_event(
    connection: sqlite3.Connection,
    payload: dict[str, Any],
    clock: Callable[[], str],
) -> dict[str, Any]:
    run_id = require_uuid(payload.get("runId"), "runId")
    expected_version = require_positive_int(payload.get("expectedVersion"), "expectedVersion")
    controller_id = require_text(payload.get("controllerId"), "controllerId")
    claim_token = require_text(payload.get("claimToken"), "claimToken")
    timestamp = clock()
    connection.execute("BEGIN IMMEDIATE")
    try:
        require_owned_run(connection, run_id, expected_version, controller_id, claim_token)
        sequence = append_event(
            connection,
            run_id,
            require_object(payload.get("event"), "event"),
            timestamp,
        )
        connection.execute(
            "UPDATE workflow_runs SET version = version + 1, updated_at = ? WHERE id = ?",
            (timestamp, run_id),
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return {"runId": run_id, "sequence": sequence, "version": expected_version + 1}


def reuse_output(
    connection: sqlite3.Connection,
    payload: dict[str, Any],
    clock: Callable[[], str],
) -> dict[str, Any]:
    run_id = require_uuid(payload.get("runId"), "runId")
    source_run_id = require_uuid(payload.get("sourceRunId"), "sourceRunId")
    phase_id = require_text(payload.get("phaseId"), "phaseId")
    source_phase_id = require_text(payload.get("sourcePhaseId"), "sourcePhaseId")
    expected_version = require_positive_int(payload.get("expectedVersion"), "expectedVersion")
    controller_id = require_text(payload.get("controllerId"), "controllerId")
    claim_token = require_text(payload.get("claimToken"), "claimToken")
    source_digest = require_digest(payload.get("sourceOutputDigest"), "sourceOutputDigest")
    validation = require_object(payload.get("validation"), "validation")
    timestamp = clock()
    connection.execute("BEGIN IMMEDIATE")
    try:
        target_run = require_owned_run(
            connection, run_id, expected_version, controller_id, claim_token
        )
        source_run = require_run(connection, source_run_id)
        target_phase = require_phase(connection, run_id, phase_id)
        source_phase = require_phase(connection, source_run_id, source_phase_id)
        if source_phase["state"] not in {"completed", "reused"}:
            raise SystemExit("Source workflow phase has no reusable completed output.")
        if source_phase["output_digest"] != source_digest:
            raise SystemExit("Source workflow phase output digest changed.")
        if target_phase["phase_type"] != source_phase["phase_type"]:
            raise SystemExit("Reusable phase type does not match the target phase.")
        if target_phase["phase_version"] != source_phase["phase_version"]:
            raise SystemExit("Reusable phase version does not match the target phase.")
        if target_phase["input_digest"] is None or source_phase["input_digest"] is None:
            raise SystemExit("Reusable phase requires known source and target input digests.")
        if target_phase["input_digest"] != source_phase["input_digest"]:
            raise SystemExit("Reusable phase input digest does not match the target phase.")
        for column, label in (
            ("target_path", "target"),
            ("target_revision", "target revision"),
            ("policy_digest", "policy"),
        ):
            if target_run[column] != source_run[column]:
                raise SystemExit(f"Reusable phase {label} does not match the target run.")
        changed = connection.execute(
            """
            UPDATE workflow_phases
            SET state = 'reused', output_json = ?, output_digest = ?,
                reused_from_run_id = ?, reused_from_phase_id = ?,
                version = version + 1, updated_at = ?
            WHERE run_id = ? AND phase_id = ? AND state IN ('pending', 'ready')
            """,
            (
                source_phase["output_json"],
                source_digest,
                source_run_id,
                source_phase_id,
                timestamp,
                run_id,
                phase_id,
            ),
        ).rowcount
        if changed != 1:
            raise SystemExit("Workflow output reuse lost a concurrent phase update.")
        connection.execute(
            """
            INSERT INTO workflow_output_reuse (
                run_id, phase_id, source_run_id, source_phase_id,
                source_output_digest, validation_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                phase_id,
                source_run_id,
                source_phase_id,
                source_digest,
                canonical_json(validation),
                timestamp,
            ),
        )
        append_event(
            connection,
            run_id,
            {
                "category": "domain",
                "kind": "phase.output_reused",
                "source": "runtime",
                "phaseId": phase_id,
                "payload": {
                    "sourceRunId": source_run_id,
                    "sourcePhaseId": source_phase_id,
                    "sourceOutputDigest": source_digest,
                    "validation": validation,
                },
            },
            timestamp,
        )
        connection.execute(
            "UPDATE workflow_runs SET version = version + 1, updated_at = ? WHERE id = ?",
            (timestamp, run_id),
        )
        result = get_run(connection, run_id)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return result


def get_run(connection: sqlite3.Connection, run_id_value: Any) -> dict[str, Any]:
    run_id = require_uuid(run_id_value, "runId")
    # Keep the run version/progress and phases on one snapshot, including when
    # this query is nested inside a mutation's transaction.
    connection.execute("SAVEPOINT runtime_get_run")
    try:
        run = require_run(connection, run_id)
        phases = connection.execute(
            "SELECT * FROM workflow_phases WHERE run_id = ? ORDER BY rowid", (run_id,)
        ).fetchall()
        return {
            "id": run["id"],
            "scanId": run["scan_id"],
            "parentRunId": run["parent_run_id"],
            "workflow": json.loads(run["workflow_json"]),
            "snapshot": json.loads(run["snapshot_json"]),
            "snapshotDigest": run["snapshot_digest"],
            "targetPath": run["target_path"],
            "targetRevision": run["target_revision"],
            "policyDigest": run["policy_digest"],
            "status": run["status"],
            "statusReason": run["status_reason"],
            "progress": json.loads(run["progress_json"]),
            "controllerId": run["controller_id"],
            "outputAdmissionFrozen": bool(run["output_admission_frozen"]),
            "version": run["version"],
            "createdAt": run["created_at"],
            "updatedAt": run["updated_at"],
            "completedAt": run["completed_at"],
            "phases": [phase_result(phase) for phase in phases],
        }
    finally:
        connection.execute("RELEASE SAVEPOINT runtime_get_run")


def list_events(connection: sqlite3.Connection, run_id_value: Any, after: Any) -> dict[str, Any]:
    run_id = require_uuid(run_id_value, "runId")
    require_run(connection, run_id)
    after_sequence = require_non_negative_int(after, "afterSequence")
    rows = connection.execute(
        """
        SELECT * FROM workflow_events
        WHERE run_id = ? AND sequence > ?
        ORDER BY sequence
        """,
        (run_id, after_sequence),
    ).fetchall()
    return {
        "runId": run_id,
        "events": [
            {
                "schemaVersion": row["schema_version"],
                "runId": row["run_id"],
                "sequence": row["sequence"],
                "timestamp": row["created_at"],
                "category": row["category"],
                "kind": row["kind"],
                "source": row["source"],
                "phaseId": row["phase_id"],
                "logicalAgentId": row["logical_agent_id"],
                "attemptId": row["attempt_id"],
                "correlationId": row["correlation_id"],
                "payload": json.loads(row["payload_json"]),
            }
            for row in rows
        ],
    }


def update_phase(
    connection: sqlite3.Connection,
    run: sqlite3.Row,
    change: dict[str, Any],
    timestamp: str,
) -> None:
    if run["output_admission_frozen"]:
        raise SystemExit("Workflow run no longer admits phase output.")
    phase_id = require_text(change.get("id"), "phase.id")
    state = require_choice(change.get("state"), PHASE_STATES, "phase.state")
    phase = require_phase(connection, run["id"], phase_id)
    expected_phase_version = require_positive_int(
        change.get("expectedVersion"), "phase.expectedVersion"
    )
    if phase["version"] != expected_phase_version:
        raise SystemExit("Workflow phase version changed before transition.")
    if state not in PHASE_TRANSITIONS[phase["state"]]:
        raise SystemExit(
            f"Workflow phase cannot transition from {phase['state']} to {state}."
        )
    if state == "running":
        for dependency_id in json.loads(phase["dependencies_json"]):
            dependency = require_phase(connection, run["id"], dependency_id)
            if dependency["state"] not in {"completed", "reused"}:
                raise SystemExit(
                    f"Workflow phase {phase_id} cannot start before dependency "
                    f"{dependency_id} is completed or reused."
                )
    output = change.get("output")
    output_digest = change.get("outputDigest")
    input_digest = change.get("inputDigest")
    if output is not None:
        output_digest = require_digest(output_digest, "phase.outputDigest")
    elif output_digest is not None:
        raise SystemExit("phase.outputDigest requires phase.output.")
    if state in {"completed", "reused"} and output is None:
        raise SystemExit(f"Workflow phase state {state} requires output.")
    changed = connection.execute(
        """
        UPDATE workflow_phases
        SET state = ?, input_digest = COALESCE(?, input_digest), output_json = ?,
            output_digest = ?, version = version + 1, updated_at = ?
        WHERE run_id = ? AND phase_id = ? AND version = ?
        """,
        (
            state,
            optional_digest(input_digest, "phase.inputDigest"),
            canonical_json(output) if output is not None else None,
            output_digest,
            timestamp,
            run["id"],
            phase_id,
            expected_phase_version,
        ),
    ).rowcount
    if changed != 1:
        raise SystemExit("Workflow phase transition lost a concurrent update.")


def validate_run_outcome(
    connection: sqlite3.Connection,
    run_id: str,
    next_status: str,
) -> None:
    persisted_run = require_run(connection, run_id)
    progress_object = require_object(json.loads(persisted_run["progress_json"]), "progress")
    conclusion = progress_object.get("coverageConclusion")
    if next_status != "completed":
        if conclusion == "complete":
            progress_object["coverageConclusion"] = "inconclusive"
            connection.execute(
                "UPDATE workflow_runs SET progress_json = ? WHERE id = ?",
                (canonical_json(progress_object), run_id),
            )
        return
    incomplete = connection.execute(
        """
        SELECT COUNT(*) FROM workflow_phases
        WHERE run_id = ? AND state NOT IN ('completed', 'reused')
        """,
        (run_id,),
    ).fetchone()[0]
    publication = connection.execute(
        """
        SELECT 1 FROM workflow_phases
        WHERE run_id = ? AND phase_type = 'publication'
            AND state IN ('completed', 'reused')
        """,
        (run_id,),
    ).fetchone()
    if incomplete or publication is None:
        raise SystemExit("Workflow run cannot complete before every phase and publication.")
    if conclusion != "complete":
        raise SystemExit("Completed workflow run requires a complete coverage conclusion.")


def append_event(
    connection: sqlite3.Connection,
    run_id: str,
    event: dict[str, Any],
    timestamp: str,
) -> int:
    category = require_choice(event.get("category"), {"domain", "activity"}, "event.category")
    kind = require_text(event.get("kind"), "event.kind")
    source = require_text(event.get("source"), "event.source")
    payload = require_object(event.get("payload", {}), "event.payload")
    phase_id = optional_text(event.get("phaseId"), "event.phaseId")
    logical_agent_id = optional_uuid(event.get("logicalAgentId"), "event.logicalAgentId")
    attempt_id = optional_uuid(event.get("attemptId"), "event.attemptId")
    correlation_id = optional_text(event.get("correlationId"), "event.correlationId")
    validate_event_bindings(
        connection, run_id, phase_id, logical_agent_id, attempt_id
    )
    sequence = connection.execute(
        "SELECT COALESCE(MAX(sequence), 0) + 1 FROM workflow_events WHERE run_id = ?",
        (run_id,),
    ).fetchone()[0]
    connection.execute(
        """
        INSERT INTO workflow_events (
            run_id, sequence, schema_version, category, kind, source, phase_id,
            logical_agent_id, attempt_id, correlation_id, payload_json, created_at
        ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            sequence,
            category,
            kind,
            source,
            phase_id,
            logical_agent_id,
            attempt_id,
            correlation_id,
            canonical_json(payload),
            timestamp,
        ),
    )
    return sequence


def validate_event_bindings(
    connection: sqlite3.Connection,
    run_id: str,
    phase_id: str | None,
    logical_agent_id: str | None,
    attempt_id: str | None,
) -> None:
    if phase_id is not None:
        require_phase(connection, run_id, phase_id)
    if logical_agent_id is None:
        if attempt_id is not None:
            raise SystemExit("Attempt event binding requires a logical agent identity.")
        return
    if phase_id is None:
        raise SystemExit("Event logical agent binding requires a workflow phase identity.")
    agent = connection.execute(
        """
        SELECT * FROM workflow_logical_agents WHERE id = ? AND run_id = ?
        """,
        (logical_agent_id, run_id),
    ).fetchone()
    if agent is None or agent["phase_id"] != phase_id:
        raise SystemExit("Event logical agent binding does not match the workflow phase.")
    if attempt_id is None:
        return
    attempt = connection.execute(
        """
        SELECT 1 FROM workflow_attempts WHERE id = ? AND logical_agent_id = ?
        """,
        (attempt_id, logical_agent_id),
    ).fetchone()
    if attempt is None:
        raise SystemExit("Event attempt binding does not match the logical agent.")


def require_owned_run(
    connection: sqlite3.Connection,
    run_id: str,
    expected_version: int,
    controller_id: str,
    claim_token: str,
) -> sqlite3.Row:
    run = require_run(connection, run_id)
    if run["version"] != expected_version:
        raise SystemExit("Workflow run version changed before operation.")
    if run["controller_id"] != controller_id or run["controller_claim_token"] != claim_token:
        raise SystemExit("Workflow run controller ownership does not match.")
    if run["status"] != "running":
        raise SystemExit(f"Workflow run in state {run['status']} is not active.")
    return run


def require_run(connection: sqlite3.Connection, run_id: str) -> sqlite3.Row:
    row = connection.execute("SELECT * FROM workflow_runs WHERE id = ?", (run_id,)).fetchone()
    if row is None:
        raise SystemExit(f"Unknown workflow run: {run_id}")
    return row


def require_phase(connection: sqlite3.Connection, run_id: str, phase_id: str) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM workflow_phases WHERE run_id = ? AND phase_id = ?",
        (run_id, phase_id),
    ).fetchone()
    if row is None:
        raise SystemExit(f"Unknown workflow phase: {phase_id}")
    return row


def phase_result(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["phase_id"],
        "type": row["phase_type"],
        "phaseVersion": row["phase_version"],
        "roleId": row["role_id"],
        "dependencies": json.loads(row["dependencies_json"]),
        "inputDigest": row["input_digest"],
        "output": json.loads(row["output_json"]) if row["output_json"] is not None else None,
        "outputDigest": row["output_digest"],
        "state": row["state"],
        "reusedFromRunId": row["reused_from_run_id"],
        "reusedFromPhaseId": row["reused_from_phase_id"],
        "version": row["version"],
        "updatedAt": row["updated_at"],
    }


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(value, allow_nan=False, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError) as error:
        raise SystemExit(f"Runtime payload must be finite JSON: {error}") from error


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SystemExit(f"{label} must be an object.")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise SystemExit(f"{label} must be an array.")
    return value


def require_string_list(value: Any, label: str) -> list[str]:
    entries = require_list(value, label)
    if not all(isinstance(entry, str) and entry.strip() for entry in entries):
        raise SystemExit(f"{label} must contain non-empty strings.")
    return [entry.strip() for entry in entries]


def require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SystemExit(f"{label} must be a non-empty string.")
    return value.strip()


def optional_text(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return require_text(value, label)


def require_uuid(value: Any, label: str) -> str:
    text = require_text(value, label)
    try:
        return str(uuid.UUID(text))
    except ValueError as error:
        raise SystemExit(f"{label} must be a UUID.") from error


def optional_uuid(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return require_uuid(value, label)


def require_positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise SystemExit(f"{label} must be a positive integer.")
    return value


def require_non_negative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SystemExit(f"{label} must be a non-negative integer.")
    return value


def require_choice(value: Any, choices: set[str] | frozenset[str], label: str) -> str:
    text = require_text(value, label)
    if text not in choices:
        raise SystemExit(f"{label} must be one of: {', '.join(sorted(choices))}.")
    return text


def require_digest(value: Any, label: str) -> str:
    text = require_text(value, label)
    if (
        not text.startswith("sha256:")
        or len(text) != 71
        or any(character not in "0123456789abcdefABCDEF" for character in text[7:])
    ):
        raise SystemExit(f"{label} must be a sha256 digest.")
    return text.lower()


def optional_digest(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return require_digest(value, label)
