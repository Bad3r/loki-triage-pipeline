from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import get_project_paths, load_runtime_config
from .db import connect, ensure_schema, record_case_verdict
from .utils import format_table



def _connection(project_root: Path | None = None):
    paths = get_project_paths(project_root)
    conn = connect(paths.db_path)
    ensure_schema(conn)
    return conn



def queue(statuses: list[str] | None = None, project_root: Path | None = None) -> list[dict[str, Any]]:
    conn = _connection(project_root)
    try:
        params: list[Any] = []
        status_clause = ""
        if statuses:
            placeholders = ",".join("?" for _ in statuses)
            status_clause = f"WHERE c.current_disposition IN ({placeholders})"
            params.extend(statuses)
        rows = conn.execute(
            f"""
            WITH case_metrics AS (
                SELECT
                    co.case_id,
                    COUNT(*) AS occurrences,
                    COUNT(DISTINCT co.host) AS hosts,
                    MAX(co.occurrence_ts) AS last_seen
                FROM case_occurrences co
                GROUP BY co.case_id
            ),
            case_rules AS (
                SELECT cm.case_id, GROUP_CONCAT(DISTINCT f.rule_key) AS matched_rules
                FROM case_memberships cm
                JOIN findings f ON f.id = cm.finding_id
                GROUP BY cm.case_id
            )
            SELECT
                c.id AS case_id,
                c.priority,
                c.severity,
                c.current_disposition,
                c.title,
                m.occurrences,
                m.hosts,
                m.last_seen,
                r.matched_rules
            FROM cases c
            JOIN case_metrics m ON m.case_id = c.id
            LEFT JOIN case_rules r ON r.case_id = c.id
            {status_clause}
            ORDER BY
                CASE c.priority
                    WHEN 'critical' THEN 5
                    WHEN 'high' THEN 4
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 2
                    ELSE 1
                END DESC,
                m.last_seen DESC,
                c.id ASC
            """,
            params,
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()



def queue_table(statuses: list[str] | None = None, project_root: Path | None = None) -> str:
    rows = queue(statuses, project_root)
    return format_table(
        rows,
        [
            ("case_id", "Case"),
            ("priority", "Priority"),
            ("severity", "Severity"),
            ("current_disposition", "Disposition"),
            ("occurrences", "Occ"),
            ("hosts", "Hosts"),
            ("last_seen", "Last Seen"),
            ("matched_rules", "Rules"),
            ("title", "Title"),
        ],
    )



def show_case(case_id: int, project_root: Path | None = None) -> dict[str, Any]:
    paths = get_project_paths(project_root)
    runtime_config = load_runtime_config(paths)
    lookup_profile = str(runtime_config.vt_config.get("profile", "public_safe"))
    conn = connect(paths.db_path)
    ensure_schema(conn)
    try:
        case_row = conn.execute(
            "SELECT * FROM cases WHERE id = ?",
            (case_id,),
        ).fetchone()
        if not case_row:
            raise KeyError(f"Case {case_id} was not found")
        verdicts = conn.execute(
            "SELECT decision_ts, disposition, reason, analyst, run_id, source FROM case_verdicts WHERE case_id = ? ORDER BY decision_ts DESC",
            (case_id,),
        ).fetchall()
        members = conn.execute(
            """
            SELECT
                f.id AS finding_id,
                f.rule_key,
                f.title,
                f.severity,
                f.priority,
                COUNT(fo.id) AS occurrences,
                COUNT(DISTINCT fo.host) AS hosts,
                MAX(fo.occurrence_ts) AS last_seen
            FROM case_memberships cm
            JOIN findings f ON f.id = cm.finding_id
            LEFT JOIN finding_occurrences fo ON fo.finding_id = f.id
            WHERE cm.case_id = ?
            GROUP BY f.id
            ORDER BY
                CASE f.priority
                    WHEN 'critical' THEN 5
                    WHEN 'high' THEN 4
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 2
                    ELSE 1
                END DESC,
                last_seen DESC,
                f.id ASC
            """,
            (case_id,),
        ).fetchall()
        occurrences = conn.execute(
            """
            SELECT run_id, host, occurrence_ts, severity, event_type, event_kind, artifact_path,
                   sha256, context_fingerprint, state_for_host_run, score,
                   source_path, source_line_start, source_line_end
            FROM case_occurrences
            WHERE case_id = ?
            ORDER BY occurrence_ts DESC, id DESC
            LIMIT 50
            """,
            (case_id,),
        ).fetchall()
        vt_row = conn.execute(
            "SELECT result_status, summary_json, error_text, lookup_ts FROM vt_lookups WHERE sha256 = ? AND lookup_profile = ?",
            (case_row["sha256"], lookup_profile),
        ).fetchone()
        vt_summary = None
        if vt_row:
            vt_summary = dict(vt_row)
            vt_summary["summary"] = (
                json.loads(str(vt_row["summary_json"]))
                if vt_row["result_status"] == "ok" and vt_row["summary_json"]
                else None
            )
            vt_summary.pop("summary_json", None)
        return {
            "case": dict(case_row),
            "verdicts": [dict(row) for row in verdicts],
            "members": [dict(row) for row in members],
            "occurrences": [dict(row) for row in occurrences],
            "vt_summary": vt_summary,
        }
    finally:
        conn.close()



def set_case_verdict(
    case_id: int,
    disposition: str,
    reason: str,
    analyst: str,
    run_id: str | None = None,
    project_root: Path | None = None,
) -> None:
    conn = _connection(project_root)
    try:
        record_case_verdict(conn, case_id, disposition, reason, analyst, run_id)
        conn.commit()
    finally:
        conn.close()



def show_finding(finding_id: int, project_root: Path | None = None) -> dict[str, Any]:
    return show_case(finding_id, project_root)



def set_finding_verdict(
    finding_id: int,
    disposition: str,
    reason: str,
    analyst: str,
    run_id: str | None = None,
    project_root: Path | None = None,
) -> None:
    set_case_verdict(finding_id, disposition, reason, analyst, run_id, project_root)
