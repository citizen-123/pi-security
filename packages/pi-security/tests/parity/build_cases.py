#!/usr/bin/env python3
"""Write the curated parity cases under tests/parity/cases/.

Each case is a directory holding case.json and an input/ tree. The oracle copies input/ to a fresh work directory,
optionally builds a Git repository from case.json["git"], runs each of case.json["steps"] in order in that directory
(argv placeholders: {work}, {schemas}), and captures every step's status, stdout where the step asks for it, and
every file left in the work directory.

Usage: build_cases.py [--check]
"""

from __future__ import annotations

import argparse
import base64
import copy
import filecmp
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

CASES_DIR = Path(__file__).resolve().parent / "cases"
SNAPSHOT = "pi-security-snapshot/v1:sha256:" + "0" * 64

# ─── Finalizer documents ────────────────────────────────────────────────────


def manifest(scan_id: str = "scan_parity_001", **target: Any) -> dict[str, Any]:
    return {
        "documentType": "pi-security.scan-manifest",
        "schemaVersion": "1.0",
        "scan": {
            "id": scan_id,
            "producer": {"name": "pi-security", "version": "0.1.0"},
            "status": "completed",
            "startedAt": "2026-05-31T18:00:00Z",
            "completedAt": "2026-05-31T18:09:00Z",
            "target": {
                "kind": "git_worktree",
                "targetId": "target_sha256_parity",
                "displayName": "example/parity-repo",
                "remote": "https://github.com/example/parity-repo",
                "revision": "deadbeef",
                "snapshotDigest": SNAPSHOT,
                **target,
            },
            "scope": {"includePaths": ["src/"], "excludePaths": []},
            "coverageRef": "coverage.json",
            "findingsRef": "findings.json",
        },
    }


def finding(
    rule: str,
    anchor: str,
    title: str,
    level: str,
    path: str = "src/app.py",
    line: int = 10,
    **extra: Any,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "ruleId": rule,
        "identity": {"anchor": anchor},
        "title": title,
        "summary": f"Summary for {title}.",
        "severity": {"level": level},
        "confidence": {"level": "high", "rationale": "Direct source trace."},
        "taxonomy": {"category": rule.split(".")[0], "cwe": ["CWE-20"]},
        "locations": [{"path": path, "startLine": line, "endLine": line + 2, "role": "sink"}],
        "remediation": f"Fix {title.lower()}.",
        "validation": None,
        "attackPath": None,
        "provenance": {"source": "local_package"},
        "extensions": {},
    }
    value.update(extra)
    return value


def findings(scan_id: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    return {"documentType": "pi-security.findings", "schemaVersion": "1.0", "scanId": scan_id, "findings": items}


def coverage(scan_id: str, **fields: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "documentType": "pi-security.coverage",
        "schemaVersion": "1.0",
        "scanId": scan_id,
        "mode": "repository",
        "completeness": "complete",
        "inventoryStrategy": "repository",
        "includePaths": ["src/"],
        "excludePaths": [],
        "surfaces": [
            {"id": "surface_input", "label": "Request input", "disposition": "reported", "receiptRefs": []}
        ],
        "explicitExclusions": [],
        "deferred": [],
    }
    value.update(fields)
    return value


def finalize_case(name: str, description: str, docs: tuple[dict, dict, dict], extra_files: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """A finalization case plus one export case per format over the same input."""
    m, f, c = docs
    files = {
        "scan/scan-manifest.json": json_text(m),
        "scan/findings.json": json_text(f),
        "scan/coverage.json": json_text(c),
        **(extra_files or {}),
    }
    finalize = {"argv": ["finalize_scan_contract", "--scan-dir", "{work}/scan"], "stdout": "ignore"}
    cases = [{"name": f"finalize/{name}", "description": description, "steps": [finalize], "files": files}]
    for fmt in ("json", "csv", "sarif"):
        cases.append(
            {
                "name": f"export-{fmt}/{name}",
                "description": f"{fmt.upper()} export after finalizing: {description}",
                "steps": [
                    finalize,
                    {"argv": ["finalize_scan_contract", "--scan-dir", "{work}/scan", "--export-format", fmt], "stdout": "compare"},
                ],
                "files": files,
            }
        )
    return cases


def json_text(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def finalize_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    sid = "scan_parity_001"

    # Standard, one finding.
    cases += finalize_case(
        "standard-single",
        "Standard repository scan with one high finding.",
        (
            manifest(sid),
            findings(sid, [finding("path-traversal.archive-extraction", "archive-entry-write", "Unsafe archive extraction", "high", "src/extract.py", 41)]),
            coverage(sid),
        ),
    )

    # Every severity, several locations and CWEs, populated validation and attack path.
    levels = ["critical", "high", "medium", "low", "informational"]
    items = []
    for index, level in enumerate(levels):
        item = finding(
            f"injection.case-{level}",
            f"sink-{level}",
            f"Injection reaches sink ({level})",
            level,
            f"src/module_{index}.py",
            5 + index * 10,
        )
        item["taxonomy"]["cwe"] = ["CWE-89", "CWE-20"][: 1 + index % 2]
        item["locations"].append({"path": f"src/module_{index}.py", "startLine": 100 + index, "role": "source"})
        if level in ("critical", "high"):
            item["severity"].update({"score": 9.1 if level == "critical" else 7.5, "scoringSystem": "CVSS:3.1"})
            item["validation"] = {"status": "validated", "disposition": "reported", "result": "Confirmed with a trace."}
            item["attackPath"] = {
                "steps": ["Send a crafted request.", "The handler forwards it to the query."],
                "impact": {"level": level, "rationale": "Data exposure.", "why": "Unparameterized query."},
                "likelihood": "Likely for unauthenticated callers.",
                "reachability": {"source": "HTTP body.", "sink": "SQL execution."},
                "assumptions": ["The endpoint is public."],
            }
        items.append(item)
    cases += finalize_case(
        "all-severities",
        "Five findings covering every severity, multiple locations, validation and attack paths.",
        (manifest(sid), findings(sid, items), coverage(sid)),
    )

    # Same rule, distinct instances: identity.instance participates in the fingerprint.
    twin_a = finding("auth.missing-check", "admin-route-without-auth", "Admin route lacks authorization", "high", "src/routes.py", 12)
    twin_a["identity"]["instance"] = "delete-user"
    twin_b = copy.deepcopy(twin_a)
    twin_b["identity"]["instance"] = "reset-password"
    twin_b["title"] = "Admin route lacks authorization (reset)"
    twin_b["locations"][0].update({"startLine": 40, "endLine": 42})
    cases += finalize_case(
        "identity-instances",
        "Two findings sharing rule and anchor, distinguished by identity.instance.",
        (manifest(sid), findings(sid, [twin_a, twin_b]), coverage(sid)),
    )

    # Diff scan.
    did = "scan_parity_diff"
    cases += finalize_case(
        "diff",
        "Diff scan over a git_diff target.",
        (
            manifest(did, kind="git_diff"),
            findings(did, [finding("ssrf.unvalidated-url", "fetch-user-url", "Server fetches user-supplied URL", "medium", "src/fetch.py", 22)]),
            coverage(did, mode="diff", inventoryStrategy="diff"),
        ),
    )

    # Deep scan: candidate-grouped reports with merged provenance.
    deep_id = "scan_parity_deep"
    deep_a = finding("memory.unchecked-length", "copy-without-bounds", "Copy without bounds check [DSS-001-COPY-a]", "high", "src/buffer.c", 77)
    deep_a["extensions"] = {"candidateId": "DSS-001", "ledgerRowId": "R01W01-COPY", "reportId": "DSS-001-COPY-a"}
    deep_a["identity"]["instance"] = "variant-a"
    deep_a["provenance"] = {"source": "local_package", "sourceFindingIds": ["W01-F3", "W04-F1"]}
    deep_b = copy.deepcopy(deep_a)
    deep_b["identity"]["instance"] = "variant-b"
    deep_b["title"] = "Copy without bounds check [DSS-001-COPY-b]"
    deep_b["severity"]["level"] = "medium"
    deep_b["extensions"]["reportId"] = "DSS-001-COPY-b"
    deep_b["provenance"]["sourceFindingIds"] = ["W02-F7"]
    deep_c = finding("crypto.weak-random", "token-from-math-random", "Session token from weak randomness", "low", "src/session.js", 8)
    deep_c["extensions"] = {"candidateId": "DSS-002", "reportId": "DSS-002"}
    cases += finalize_case(
        "deep",
        "Deep scan with candidate-grouped report instances and merged source finding IDs.",
        (
            manifest(deep_id),
            findings(deep_id, [deep_a, deep_b, deep_c]),
            coverage(deep_id, mode="deep_repository"),
        ),
    )

    # Partial coverage: interrupted run, deferred units, follow-up surfaces, exclusions.
    pid = "scan_parity_partial"
    partial_manifest = manifest(pid)
    partial_manifest["scan"]["status"] = "interrupted"
    cases += finalize_case(
        "partial-coverage",
        "Interrupted scan with deferred units, needs_follow_up surfaces, and explicit exclusions.",
        (
            partial_manifest,
            findings(pid, [finding("xss.reflected", "search-echo", "Search term reflected unescaped", "medium", "src/search.py", 30)]),
            coverage(
                pid,
                completeness="partial",
                surfaces=[
                    {"id": "surface_search", "label": "Search", "disposition": "reported", "receiptRefs": []},
                    {"id": "surface_upload", "label": "Uploads", "disposition": "needs_follow_up", "receiptRefs": []},
                    {"id": "surface_static", "label": "Static assets", "disposition": "not_applicable", "receiptRefs": []},
                ],
                explicitExclusions=[{"pattern": "vendor/**", "reason": "Third-party code."}],
                deferred=[
                    {
                        "id": "candidate-upload",
                        "reason": "Validation was deferred because the scan reached its cost limit.",
                        "paths": ["src/upload.py"],
                    }
                ],
            ),
        ),
    )

    # No findings, complete.
    nid = "scan_parity_none"
    cases += finalize_case(
        "no-findings",
        "Complete scan with no findings.",
        (
            manifest(nid),
            findings(nid, []),
            coverage(nid, surfaces=[{"id": "surface_input", "label": "Request input", "disposition": "no_issue_found", "receiptRefs": []}]),
        ),
    )

    # Non-ASCII paths and Markdown/HTML-hostile text.
    uid = "scan_parity_unicode"
    hostile = finding(
        "injection.template",
        "template-render-unescaped",
        "Template | renders <script> & `raw` input [link](x)",
        "high",
        "src/vues/électron_日本.py",
        3,
    )
    hostile["summary"] = "Line one.\n## Not a heading\n```\nfenced\n```"
    hostile["remediation"] = "Escape output; see <b>docs</b> | table."
    # Number and ordering traps: Python writes 7.0 where JSON.stringify writes 7, and Python orders strings by code
    # point where JavaScript's default sort uses UTF-16 code units (they disagree above U+FFFF).
    trap_a = finding("crypto.static-key", "hardcoded-key-🔑", "Hardcoded key 🔑 in config", "high", "src/keys.py", 2)
    trap_a["identity"]["anchor"] = "hardcoded-key"
    trap_a["severity"].update({"score": 7.0, "scoringSystem": "CVSS:3.1"})
    trap_b = finding("crypto.static-key", "hardcoded-key", "Hardcoded key ～ in fallback", "medium", "src/keys.py", 20)
    trap_b["identity"]["instance"] = "fallback"
    trap_b["severity"].update({"score": 5.25, "scoringSystem": "CVSS:3.1"})
    tid = "scan_parity_traps"
    cases += finalize_case(
        "number-and-ordering-traps",
        "Integral float score (7.0), fractional score, and titles with characters above and below U+FFFF.",
        (manifest(tid), findings(tid, [trap_a, trap_b]), coverage(tid)),
    )

    cases += finalize_case(
        "unicode-and-markup",
        "Non-ASCII paths and titles containing Markdown and HTML metacharacters.",
        (
            manifest(uid, displayName="exemple/dépôt"),
            findings(uid, [hostile]),
            coverage(uid, includePaths=["src/"]),
        ),
    )

    # Rejections: the finalizer must refuse these.
    rid = "scan_parity_reject"
    bad_anchor = finding("injection.sql", "Not A Slug", "Bad anchor", "high")
    cases += reject_case("reject-bad-anchor", "identity.anchor that is not a lowercase slug.", (manifest(rid), findings(rid, [bad_anchor]), coverage(rid)))
    cases += reject_case(
        "reject-scan-id-mismatch",
        "findings.scanId differs from the manifest scan id.",
        (manifest(rid), findings("scan_other", [finding("injection.sql", "query", "Query", "high")]), coverage(rid)),
    )
    escape = finding("injection.sql", "query", "Query", "high", "../outside.py")
    cases += reject_case("reject-unsafe-location", "Location path escaping the repository.", (manifest(rid), findings(rid, [escape]), coverage(rid)))
    return cases


def reject_case(name: str, description: str, docs: tuple[dict, dict, dict]) -> list[dict[str, Any]]:
    m, f, c = docs
    return [
        {
            "name": f"finalize/{name}",
            "description": f"Must reject: {description}",
            "steps": [{"argv": ["finalize_scan_contract", "--scan-dir", "{work}/scan"], "stdout": "ignore"}],
            "files": {"scan/scan-manifest.json": json_text(m), "scan/findings.json": json_text(f), "scan/coverage.json": json_text(c)},
        }
    ]


# ─── Validate a sealed scan ─────────────────────────────────────────────────


def validate_cases() -> list[dict[str, Any]]:
    sid = "scan_parity_validate"
    docs = (manifest(sid), findings(sid, [finding("injection.sql", "query-concat", "Query built by concatenation", "high", "src/db.py", 4)]), coverage(sid))
    files = {"scan/scan-manifest.json": json_text(docs[0]), "scan/findings.json": json_text(docs[1]), "scan/coverage.json": json_text(docs[2])}
    finalize = {"argv": ["finalize_scan_contract", "--scan-dir", "{work}/scan"], "stdout": "ignore"}
    validate = {"argv": ["validate_scan_contract", "--scan-dir", "{work}/scan"], "stdout": "compare"}
    return [
        {"name": "validate/sealed", "description": "Receipt for a freshly sealed scan.", "steps": [finalize, validate], "files": files},
        {"name": "validate/unsealed", "description": "Must reject: validating a scan that was never sealed.", "steps": [validate], "files": files},
        {
            "name": "validate/tampered",
            "description": "Must reject: findings.json changed after sealing.",
            "steps": [finalize, {"argv": ["parity_append", "{work}/scan/findings.json", " "], "stdout": "ignore"}, validate],
            "files": files,
        },
    ]


# ─── Candidate normalization ────────────────────────────────────────────────


def lines(count: int) -> str:
    return "".join(f"line {number}\n" for number in range(1, count + 1))


def candidate(**fields: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "cwe_ids": ["CWE-89"],
        "locations": [{"path": "src/db.py", "start_line": 3, "end_line": 4, "role": "sink"}],
        "summary": "Query concatenates request input.",
        "evidence": "db.py builds SQL with +.",
    }
    value.update(fields)
    return value


def jsonl(rows: list[Any]) -> str:
    return "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)


REPO_FILES = {
    "repo/src/db.py": lines(20),
    "repo/src/auth.py": lines(40),
    "repo/src/vues/électron_日本.py": lines(10),
    "repo/docs/readme.md": lines(5),
}


def normalize_case(name: str, description: str, inputs: dict[str, list[Any]], scope: str, extra: dict[str, Any] | None = None, flags: list[str] | None = None) -> dict[str, Any]:
    files = {**REPO_FILES, "scope.txt": scope}
    for input_name, rows in inputs.items():
        files[input_name] = jsonl(rows) if isinstance(rows, list) else rows
    case = {
        "name": f"normalize/{name}",
        "description": description,
        "steps": [
            {
                "argv": [
                    "normalize_candidates",
                    "--input",
                    *[f"{{work}}/{n}" for n in inputs],
                    "--out",
                    "{work}/out.jsonl",
                    "--repo-root",
                    "{work}/repo",
                    "--in-scope-files",
                    "{work}/scope.txt",
                    *(flags or []),
                ],
                "stdout": "ignore",
            }
        ],
        "files": files,
    }
    extra = dict(extra or {})
    case["files"].update(extra.pop("extra_files", {}))
    case.update(extra)
    return case


def normalize_cases() -> list[dict[str, Any]]:
    scope = "src/db.py\nsrc/auth.py\nsrc/vues/électron_日本.py\n"
    cases = [
        normalize_case(
            "merge-and-order",
            "Duplicate identities across two inputs merge; locations dedupe and sort by role; CWE forms normalize.",
            {
                "a.jsonl": [
                    candidate(cwe_ids=["cwe-89", "CWE-0089 ", "CWE-20"], locations=[
                        {"path": "src/db.py", "start_line": 3, "end_line": 4, "role": "sink"},
                        {"path": "src/auth.py", "start_line": 10, "role": "source"},
                        {"path": "src/db.py", "start_line": 3, "end_line": 4, "role": "sink"},
                        {"path": "./src/auth.py", "start_line": 1, "end_line": 2, "role": "entrypoint"},
                    ], context="Admin only."),
                    candidate(summary="  Second summary.  ", locations=[{"path": "src/auth.py", "start_line": 30, "end_line": 40, "role": "evidence"}]),
                ],
                "b.jsonl": [
                    candidate(cwe_ids=["CWE-20", "CWE-89"], summary="Another view of the same query.", evidence="Seen by worker B.", locations=[
                        {"path": "src/auth.py", "start_line": 1, "end_line": 2, "role": "entrypoint"},
                        {"path": "src/auth.py", "start_line": 10, "end_line": 10, "role": "source"},
                        {"path": "src/db.py", "start_line": 3, "end_line": 4, "role": "sink"},
                    ], context="Admin only."),
                    candidate(candidate_id="worker-b-7", instance="second-call", locations=[{"path": "src/db.py", "start_line": 3, "end_line": 4, "role": "sink"}]),
                ],
            },
            scope,
        ),
        normalize_case(
            "unicode-ordering",
            "Merged texts and identities ordered by code point, including characters above U+FFFF.",
            {
                "a.jsonl": [
                    candidate(summary="～ fullwidth tilde", evidence="e1"),
                    candidate(summary="\U0001f600 emoji", evidence="e2"),
                    candidate(summary="plain ascii", evidence="e3"),
                    candidate(cwe_ids=["CWE-79"], summary="Écho non échappé", evidence="dans électron", locations=[{"path": "src/vues/électron_日本.py", "start_line": 2, "end_line": 9, "role": "sink"}]),
                    candidate(cwe_ids=["CWE-79"], summary="instance \U0001f600", evidence="x", instance="\U0001f600-variant", locations=[{"path": "src/db.py", "start_line": 1, "role": "sink"}]),
                    candidate(cwe_ids=["CWE-79"], summary="instance fullwidth", evidence="y", instance="～-variant", locations=[{"path": "src/db.py", "start_line": 1, "role": "sink"}]),
                ]
            },
            scope,
        ),
        normalize_case(
            "crlf-scope",
            "In-scope list with CRLF line endings.",
            {"a.jsonl": [candidate()]},
            "src/db.py\r\nsrc/auth.py\r\n",
        ),
        normalize_case(
            "out-of-scope-location-kept",
            "A candidate with one in-scope and one out-of-scope location is kept with both.",
            {"a.jsonl": [candidate(locations=[
                {"path": "src/db.py", "start_line": 3, "role": "sink"},
                {"path": "docs/readme.md", "start_line": 1, "end_line": 5, "role": "evidence"},
            ])]},
            scope,
        ),
        normalize_case(
            "symlink-inside-repo",
            "A location through an in-repository symlink is recorded as its target.",
            {"a.jsonl": [candidate(locations=[{"path": "src/link.py", "start_line": 3, "role": "sink"}])]},
            scope,
            {"symlinks": {"repo/src/link.py": "db.py"}},
        ),
        normalize_case(
            "allow-missing-deleted-scope-path",
            "Diff inventory listing a deleted file is accepted with --allow-missing-in-scope.",
            {"a.jsonl": [candidate()]},
            scope + "src/deleted.py\n",
            flags=["--allow-missing-in-scope"],
        ),
    ]
    # Traps a port must reproduce: Python ints vs floats, universal newlines in JSONL, Unicode digits in CWE ids,
    # null end_line, names that start with "..", and line counts with bare carriage returns.
    cr = chr(13)
    cases += [
        normalize_case(
            "python-semantics",
            "Unicode-digit CWE ids, file named ..notes.py, CR-only line endings counted as lines, explicit null context.",
            {"a.jsonl": [
                candidate(cwe_ids=["CWE-" + chr(0x0668) + chr(0x0669), "cwe-" + chr(0xFF17) + chr(0xFF19)], context=None, locations=[
                    {"path": "src/..notes.py", "start_line": 1, "role": "evidence"},
                    {"path": "src/cr_only.py", "start_line": 3, "end_line": 3, "role": "sink"},
                ]),
            ]},
            scope + "src/..notes.py\nsrc/cr_only.py\n",
            {"extra_files": {"repo/src/..notes.py": lines(2), "repo/src/cr_only.py": "a" + cr + "b" + cr + "c"}},
        ),
        normalize_case(
            "blank-lines-and-whitespace",
            "Blank and whitespace-only JSONL lines are skipped; text fields are stripped of Python whitespace.",
            {"a.jsonl": "\n   \n" + json.dumps(candidate(summary=chr(0x3000) + "Padded summary" + chr(0x1C))) + "\n\n"},
            scope,
        ),
    ]
    rejects = {
        "reject-line-out-of-range": [candidate(locations=[{"path": "src/db.py", "start_line": 19, "end_line": 21, "role": "sink"}])],
        "reject-unknown-field": [candidate(severity="high")],
        "reject-no-in-scope-location": [candidate(locations=[{"path": "docs/readme.md", "start_line": 1, "role": "sink"}])],
        "reject-bad-role": [candidate(locations=[{"path": "src/db.py", "start_line": 1, "role": "caller"}])],
        "reject-traversal": [candidate(locations=[{"path": "../outside.py", "start_line": 1, "role": "sink"}])],
        "reject-bad-cwe": [candidate(cwe_ids=["CWE-0"])],
        "reject-blank-summary": [candidate(summary="   ")],
        "reject-bool-line": [candidate(locations=[{"path": "src/db.py", "start_line": True, "role": "sink"}])],
        "reject-symlink-escape": [candidate(locations=[{"path": "src/escape.py", "start_line": 1, "role": "sink"}])],
        "reject-missing-scope-path": None,
        "reject-float-line": '{"cwe_ids": ["CWE-89"], "locations": [{"path": "src/db.py", "start_line": 3.0, "role": "sink"}], "summary": "s", "evidence": "e"}\n',
        "reject-null-end-line": [candidate(locations=[{"path": "src/db.py", "start_line": 3, "end_line": None, "role": "sink"}])],
        "reject-bare-cr-splits-row": '{"cwe_ids": ["CWE-89"],' + cr + '"locations": [{"path": "src/db.py", "start_line": 3, "role": "sink"}], "summary": "s", "evidence": "e"}\n',
        "reject-lone-surrogate-summary": '{"cwe_ids": ["CWE-89"], "locations": [{"path": "src/db.py", "start_line": 3, "role": "sink"}], "summary": "bad \\udcff", "evidence": "e"}\n',
        "reject-null-candidate-id": [candidate(candidate_id=None)],
        "reject-dangling-deleted-scope-escape": None,
    }
    for name, rows in rejects.items():
        if name == "reject-missing-scope-path":
            cases.append(normalize_case(name, "Must reject: in-scope list names a missing file without --allow-missing-in-scope.", {"a.jsonl": [candidate()]}, scope + "src/deleted.py\n"))
            continue
        if name == "reject-dangling-deleted-scope-escape":
            cases.append(normalize_case(
                name,
                "Must reject: a deleted in-scope path that is a dangling symlink pointing outside the repository.",
                {"a.jsonl": [candidate()]},
                scope + "src/gone.py\n",
                {"symlinks": {"repo/src/gone.py": "../../elsewhere/gone.py"}},
                flags=["--allow-missing-in-scope"],
            ))
            continue
        extra = {"symlinks": {"repo/src/escape.py": "../../outside.py"}} if name == "reject-symlink-escape" else None
        case = normalize_case(name, f"Must reject: {name.removeprefix('reject-').replace('-', ' ')}.", {"a.jsonl": rows}, scope, extra)
        if name == "reject-symlink-escape":
            case["files"]["outside.py"] = lines(5)
        cases.append(case)
    return cases


# ─── File inventory ─────────────────────────────────────────────────────────


def inventory_case(name: str, description: str, git_spec: dict[str, Any] | None, args: list[str], files: dict[str, str] | None = None, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    case = {
        "name": f"inventory/{name}",
        "description": description,
        "steps": [{"argv": ["generate_in_scope_files", "--repo", "{work}/repo", "--out", "{work}/inventory.txt", *args], "stdout": "ignore"}],
        "files": files or {},
    }
    if git_spec is not None:
        case["git"] = {"path": "repo", **git_spec}
    case.update(extra or {})
    return case


def inventory_cases() -> list[dict[str, Any]]:
    base_commit = {
        "message": "base",
        "write": {
            "src/app.py": "print('app')\n",
            "src/util/helpers.js": "export const x = 1;\n",
            "src/vues/électron_日本.py": "x = 1\n",
            "src/space name.ts": "let a = 1;\n",
            "docs/guide.md": "# Guide\n",
            "node_modules/pkg/index.js": "module.exports = 1;\n",
            "assets/logo.bin": "\x00\x01binary\x00",
            "CHANGELOG.md": "# Changes\n",
            ".gitignore": "ignored/\n*.log\n",
        },
    }
    change_commit = {
        "message": "change",
        "write": {
            "src/app.py": "print('app v2')\n",
            "src/new_module.go": "package main\n",
            "src/data.bin.py": "\x00\x00\x00binary-looking\x00",
            "dist/bundle.min.js": "var a=1;\n",
            "src/renamed_helpers.js": "export const x = 1;\n",
            "README.txt": "not code\n",
        },
        "delete": ["src/util/helpers.js", "src/space name.ts"],
    }
    worktree = {
        "write": {"src/app.py": "print('app v3')\n", "src/untracked.rb": "puts 1\n", "ignored/secret.py": "x\n", "debug.log": "log\n", "src/staged.py": "y = 2\n"},
        "delete": ["docs/guide.md"],
        "stage": ["src/staged.py"],
    }
    two_commits = {"commits": [base_commit, change_commit]}
    # Traps: non-UTF-8 names, UTF-16 binary detection, symlink changes, suffix rules, unnormalized scopes.
    raw_name = base64.b64encode(b"src/caf\xe9_latin1.py").decode("ascii")
    trap_base = {
        "message": "trap base",
        # UTF-8 byte order and UTF-16 order disagree for these two names.
        "write": {"src/keep.py": "x = 1\n", "sub/b.js": "b\n", "sub/c.py": "c\n", "src/target.py": "t\n",
                  "src/" + chr(0xFF5E) + ".py": "w\n", "src/" + chr(0x1F600) + ".py": "e\n"},
    }
    trap_change = {
        "message": "trap change",
        "write": {
            ".py": "hidden\n",
            "src/UPPER.PY": "u = 1\n",
            "src/lib.min.js": "var a;\n",
            "src/app.js.map": "{}\n",
            "src/trailing.": "dot\n",
        },
        "write_raw": {raw_name: "latin1 = 1\n"},
    }
    trap_commits = {"commits": [trap_base, trap_change]}
    return [
        inventory_case("git-full", "Tracked plus non-ignored untracked files, sorted bytewise, symlinks skipped.", {**two_commits, "worktree": worktree}, ["--scope", "."], extra={"symlinks": {"repo/src/link.py": "app.py"}}),
        inventory_case("git-scoped-dir", "Inventory restricted to one directory.", {"commits": [base_commit]}, ["--scope", "src"]),
        inventory_case("git-scoped-file", "Inventory of a single file.", {"commits": [base_commit]}, ["--scope", "src/app.py"]),
        inventory_case("diff-revisions", "Committed diff: adds, modifies, deletes, renames; excluded dirs, minified files, binaries and non-code files filtered.", two_commits, ["--scope", ".", "--diff-base", "HEAD~1", "--diff-head", "HEAD"]),
        inventory_case("diff-local-patch", "Working-tree patch: staged, unstaged, untracked, and deleted changes against HEAD.", {**two_commits, "worktree": worktree}, ["--scope", ".", "--diff-base", "HEAD", "--diff-mode", "local-patch"]),
        inventory_case(
            "directory-snapshot",
            "Non-Git directory: every regular file, symlinks skipped.",
            None,
            ["--scope", "."],
            files={"repo/a.py": "a\n", "repo/sub/b.js": "b\n", "repo/sub/ünï.txt": "c\n"},
            extra={"symlinks": {"repo/sub/link.js": "b.js"}},
        ),
        inventory_case("git-raw-names", "Git inventory keeps file names that are not valid UTF-8 as raw bytes.", trap_commits, ["--scope", "."]),
        inventory_case("reject-diff-raw-name", "Must reject: a diff inventory row whose name is not valid UTF-8.", trap_commits, ["--scope", ".", "--diff-base", "HEAD~1", "--diff-head", "HEAD"]),
        inventory_case(
            "diff-suffix-rules",
            "Leading-dot names have no suffix, suffixes are case-insensitive, minified and map files are excluded.",
            {"commits": [trap_base, {**trap_change, "write_raw": {}}]},
            ["--scope", ".", "--diff-base", "HEAD~1", "--diff-head", "HEAD"],
        ),
        inventory_case(
            "diff-symlink-and-utf16",
            "Working-tree patch: a new symlink is skipped; UTF-16 text with a BOM is kept, UTF-16 with a NUL unit is binary.",
            {"commits": [trap_base], "worktree": {"write_bytes": {
                "src/utf16_text.py": base64.b64encode(b"\xff\xfe" + "plain text\n".encode("utf-16-le")).decode("ascii"),
                "src/utf16_binary.py": base64.b64encode(b"\xff\xfe" + "nul\x00here\n".encode("utf-16-le")).decode("ascii"),
                "src/utf8_binary.py": base64.b64encode(b"head" + b"\x00" * 3 + b"tail\n").decode("ascii"),
            }}},
            ["--scope", ".", "--diff-base", "HEAD", "--diff-mode", "local-patch"],
            extra={"symlinks": {"repo/src/link_to_target.py": "target.py"}},
        ),
        inventory_case("git-unnormalized-scope", "Git inventory with a scope spelled ./sub/../sub.", trap_commits, ["--scope", "./sub/../sub"]),
        inventory_case(
            "directory-unnormalized-scope",
            "Directory inventory keeps the caller's spelling of a scope like ./sub/../sub in every row.",
            None,
            ["--scope", "./sub/../sub"],
            files={"repo/sub/b.js": "b\n", "repo/sub/deeper/c.py": "c\n"},
        ),
        inventory_case("reject-diff-with-scope", "Must reject: diff inventory with a non-root scope.", {"commits": [base_commit]}, ["--scope", "src", "--diff-base", "HEAD"]),
        inventory_case("reject-scope-escape", "Must reject: scope outside the repository.", {"commits": [base_commit]}, ["--scope", "../"]),
        inventory_case("reject-unknown-revision", "Must reject: diff base that does not exist.", {"commits": [base_commit]}, ["--scope", ".", "--diff-base", "no-such-ref"]),
    ]


# ─── Preflight ──────────────────────────────────────────────────────────────


def preflight_cases() -> list[dict[str, Any]]:
    def case(name: str, description: str, args: list[str], **extra: Any) -> dict[str, Any]:
        return {
            "name": f"preflight/{name}",
            "description": description,
            "steps": [{"argv": ["config_preflight", *args], "stdout": "compare"}],
            "files": {"target/.keep": "", "file.txt": "not a directory\n"},
            **extra,
        }

    return [
        case("ready", "Accessible target and mixed runtime checks.", ["--profile", "security_scan", "--cwd", "{work}/target", "--runtime-check", "subagents=true", "--runtime-check", "browser=FALSE"]),
        case("blocked", "Missing target directory blocks the scan.", ["--profile", "deep_security_scan", "--cwd", "{work}/missing"]),
        case("reject-bad-check", "Must reject: malformed runtime check.", ["--profile", "security_diff_scan", "--cwd", "{work}/target", "--runtime-check", "subagents"]),
        case("symlinked-cwd", "A symlinked working directory is reported by its resolved path.", ["--profile", "security_scan", "--cwd", "{work}/link"], symlinks={"link": "target"}),
        case(
            "missing-then-parent",
            "A missing component followed by .. still resolves the symlink after it.",
            ["--profile", "security_scan", "--cwd", "{work}/missing/../link/./"],
            symlinks={"link": "target"},
        ),
        case("dangling-symlink", "A dangling symlink is reported by the path it names.", ["--profile", "security_scan", "--cwd", "{work}/dangling"], symlinks={"dangling": "gone/deeper"}),
        case("symlink-loop", "A symlink loop is reported without resolving.", ["--profile", "security_scan", "--cwd", "{work}/loop-a"], symlinks={"loop-a": "loop-b", "loop-b": "loop-a"}),
        case("file-cwd", "A file is not an accessible working directory.", ["--profile", "security_scan", "--cwd", "{work}/file.txt"]),
        case("symlink-twice", "A symlink traversed twice reuses its resolved target.", ["--profile", "security_scan", "--cwd", "{work}/link/../link"], symlinks={"link": "target"}),
        case("absolute-symlink", "An absolute symlink target restarts resolution at the root.", ["--profile", "security_scan", "--cwd", "{work}/root"], symlinks={"root": "/"}),
        case(
            "repeated-and-unicode-checks",
            "A repeated check keeps its last value; checks sort by code point; non-ASCII names are escaped.",
            ["--profile", "security_scan", "--cwd", "{work}/target", "--runtime-check", "zeta=true", "--runtime-check", "zeta=false",
             "--runtime-check", "\u00e9cole=TrUe", "--runtime-check", "Alpha=false", "--runtime-check", "eq=true"],
        ),
        case("reject-empty-name", "Must reject: a runtime check without a name.", ["--profile", "security_scan", "--cwd", "{work}/target", "--runtime-check", "=true"]),
        case("reject-extra-equals", "Must reject: a value that is not exactly true or false.", ["--profile", "security_scan", "--cwd", "{work}/target", "--runtime-check", "a=b=true"]),
        case("reject-unknown-profile", "Must reject: an unknown profile.", ["--profile", "fast_scan", "--cwd", "{work}/target"]),
    ]


# ─── Patch-risk assessment ──────────────────────────────────────────────────


def patch_risk_assessment() -> dict[str, Any]:
    # Mirrors tests/test_patch_risk_contract.py::assessment.
    return {
        "schemaVersion": 1,
        "patch": {"repository": "example/project", "sourceType": "pull_request_diff", "base": "a" * 40, "head": "b" * 40, "changedFiles": ["src/request.ts"], "sha256": "c" * 64},
        "recommendation": "merge",
        "workflowLabel": "human_review_required",
        "impact": {"rating": "moderate", "rationale": "A bounded caller can fail."},
        "regressionLikelihood": {"rating": "low", "rationale": "The changed path and its caller are covered."},
        "regressionProtection": {"rating": "strong", "rationale": "Focused and integration checks passed at the exact head.", "exactHeadChecksPassed": True},
        "recoverability": {"rating": "easy", "rationale": "A revert is isolated."},
        "confidence": {"rating": "high", "rationale": "Runtime callers are known."},
        "applicability": {"status": "confirmed", "rationale": "The path is deployed."},
        "statusQuoRisk": {"rating": "moderate", "rationale": "The defect remains."},
        "autoMergeExclusions": [],
        "affectedRuntimeRoots": ["service.request"],
        "materialBoundaries": [
            {
                "id": "request-contract",
                "invariant": "Supported requests retain their existing response contract.",
                "runtimeRoot": "service.request",
                "counterexample": "A supported request takes the changed branch.",
                "legitimateControl": "A supported request takes the unchanged branch.",
                "result": "supported",
            }
        ],
        "validation": [{"name": "focused request tests", "status": "passed", "protects": "Changed behavior through the production caller."}],
        "unknowns": [],
        "evidencePlan": [],
    }


def patch_risk_cases() -> list[dict[str, Any]]:
    def case(name: str, description: str, text: str) -> dict[str, Any]:
        return {
            "name": f"patch-risk/{name}",
            "description": description,
            "steps": [{"argv": ["validate_patch_risk_assessment", "{work}/assessment.json"], "stdout": "compare"}],
            "files": {"assessment.json": text},
        }

    base = patch_risk_assessment()
    auto = copy.deepcopy(base)
    auto["workflowLabel"] = "auto_merge_candidate"
    auto["impact"]["rating"] = "low"
    auto_excluded = copy.deepcopy(auto)
    auto_excluded["autoMergeExclusions"] = ["public_contract"]
    auto_no_root = copy.deepcopy(auto)
    auto_no_root["affectedRuntimeRoots"] = []
    critical_unknown = copy.deepcopy(base)
    critical_unknown["unknowns"] = [{"summary": "Deployment ownership is unresolved.", "decisionCritical": True}]
    hold = copy.deepcopy(base)
    hold.update({"recommendation": "hold_for_evidence", "workflowLabel": "hold_for_evidence"})
    hold["unknowns"] = [{"summary": "The rollout target is unavailable.", "decisionCritical": True}]
    hold_with_plan = copy.deepcopy(hold)
    hold_with_plan["evidencePlan"] = [
        {
            "question": "Does the changed configuration own the rollout target?",
            "action": "Inspect the checked-in deployment mapping.",
            "outcomes": {"supported": "merge", "contradicted": "no_op", "unavailable": "hold_for_evidence"},
        }
    ]
    unknown_applicability = copy.deepcopy(base)
    unknown_applicability["applicability"] = {"status": "unknown", "rationale": "Deployment unknown."}
    no_op = copy.deepcopy(base)
    no_op["recommendation"] = "no_op"
    no_op["workflowLabel"] = "no_op"
    return [
        case("merge-human-review", "Supported human-review merge.", json_text(base)),
        case("auto-merge-low-risk", "Strict low-risk auto-merge candidate.", json_text(auto)),
        case("reject-auto-merge-excluded", "Must reject: auto-merge with an exclusion.", json_text(auto_excluded)),
        case("reject-auto-merge-no-runtime-root", "Must reject: auto-merge without affected runtime roots.", json_text(auto_no_root)),
        case("reject-critical-unknown", "Must reject: merge with a decision-critical unknown.", json_text(critical_unknown)),
        case("hold-with-evidence-plan", "Hold for evidence with a bounded evidence plan.", json_text(hold_with_plan)),
        case("reject-hold-without-plan", "Must reject: hold for evidence without an evidence plan.", json_text(hold)),
        case("reject-unknown-applicability", "Must reject: merge with unknown applicability.", json_text(unknown_applicability)),
        case("reject-no-op-applicable", "Must reject: no_op on applicable code.", json_text(no_op)),
        case("reject-duplicate-key", "Must reject: duplicate JSON object keys.", '{"schemaVersion": 1, "schemaVersion": 1}\n'),
        case("reject-not-object", "Must reject: top-level array.", "[]\n"),
    ]


# ─── Writer ─────────────────────────────────────────────────────────────────


def all_cases() -> list[dict[str, Any]]:
    return finalize_cases() + validate_cases() + normalize_cases() + inventory_cases() + preflight_cases() + patch_risk_cases()


def write_cases(root: Path) -> None:
    names = set()
    for case in all_cases():
        name = case["name"]
        if name in names:
            raise SystemExit(f"duplicate case {name}")
        names.add(name)
        directory = root / name
        (directory / "input").mkdir(parents=True)
        for relative, text in case["files"].items():
            path = directory / "input" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        spec = {key: value for key, value in case.items() if key not in ("files", "name")}
        (directory / "case.json").write_text(json_text(spec), encoding="utf-8")


def trees_equal(left: Path, right: Path) -> bool:
    comparison = filecmp.dircmp(left, right)
    if comparison.left_only or comparison.right_only or comparison.funny_files:
        return False
    _, mismatch, errors = filecmp.cmpfiles(left, right, comparison.common_files, shallow=False)
    if mismatch or errors:
        return False
    return all(trees_equal(left / sub, right / sub) for sub in comparison.common_dirs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="Fail if cases/ differs from the builder output.")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as temporary:
        staged = Path(temporary) / "cases"
        staged.mkdir()
        write_cases(staged)
        if args.check:
            if not CASES_DIR.exists() or not trees_equal(staged, CASES_DIR):
                print("tests/parity/cases is out of date; run build_cases.py", file=sys.stderr)
                return 1
            return 0
        shutil.rmtree(CASES_DIR, ignore_errors=True)
        shutil.copytree(staged, CASES_DIR)
    print(f"Wrote {len(all_cases())} cases to {CASES_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
