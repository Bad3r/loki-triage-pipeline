from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import get_project_paths
from .db import connect, ensure_schema, record_verdict
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
            status_clause = f"WHERE f.current_disposition IN ({placeholders})"
            params.extend(statuses)
        rows = conn.execute(
            f"""
            SELECT
                f.id AS finding_id,
                f.priority,
                f.severity,
                f.current_disposition,
                f.title,
                COUNT(fo.id) AS occurrences,
                COUNT(DISTINCT fo.host) AS hosts,
                MAX(fo.occurrence_ts) AS last_seen
            FROM findings f
            JOIN finding_occurrences fo ON fo.finding_id = f.id
            {status_clause}
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
            ("finding_id", "ID"),
            ("priority", "Priority"),
            ("severity", "Severity"),
            ("current_disposition", "Disposition"),
            ("occurrences", "Occ"),
            ("hosts", "Hosts"),
            ("last_seen", "Last Seen"),
            ("title", "Title"),
        ],
    )



def show_finding(finding_id: int, project_root: Path | None = None) -> dict[str, Any]:
    conn = _connection(project_root)
    try:
        finding = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not finding:
            raise KeyError(f"Finding {finding_id} was not found")
        verdicts = conn.execute(
            "SELECT decision_ts, disposition, reason, analyst, run_id FROM analyst_verdicts WHERE finding_id = ? ORDER BY decision_ts DESC",
            (finding_id,),
        ).fetchall()
        occurrences = conn.execute(
            """
            SELECT run_id, host, occurrence_ts, severity, event_type, event_kind, artifact_path,
                   sha256, context_fingerprint, rule_key, state_for_host_run, score,
                   source_path, source_line_start, source_line_end
            FROM finding_occurrences
            WHERE finding_id = ?
            ORDER BY occurrence_ts DESC, id DESC
            LIMIT 50
            """,
            (finding_id,),
        ).fetchall()
        return {
            "finding": dict(finding),
            "verdicts": [dict(row) for row in verdicts],
            "occurrences": [dict(row) for row in occurrences],
        }
    finally:
        conn.close()



def set_finding_verdict(
    finding_id: int,
    disposition: str,
    reason: str,
    analyst: str,
    run_id: str | None = None,
    project_root: Path | None = None,
) -> None:
    conn = _connection(project_root)
    try:
        record_verdict(conn, finding_id, disposition, reason, analyst, run_id)
        conn.commit()
    finally:
        conn.close()
