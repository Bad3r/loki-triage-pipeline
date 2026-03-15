from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from .utils import higher_priority, higher_severity, json_dumps, utc_now


SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scan_runs (
    id TEXT PRIMARY KEY,
    period TEXT NOT NULL,
    run_kind TEXT NOT NULL,
    run_fingerprint TEXT NOT NULL UNIQUE,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    source_count INTEGER NOT NULL DEFAULT 0,
    logical_record_count INTEGER NOT NULL DEFAULT 0,
    continuation_line_count INTEGER NOT NULL DEFAULT 0,
    truncated_file_count INTEGER NOT NULL DEFAULT 0,
    parse_warning_count INTEGER NOT NULL DEFAULT 0,
    manifest_path TEXT NOT NULL,
    run_path TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS source_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    source_path TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    host_name TEXT,
    scan_started_at TEXT,
    filename_timestamp TEXT,
    is_rescan INTEGER NOT NULL DEFAULT 0,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    line_count INTEGER NOT NULL DEFAULT 0,
    logical_record_count INTEGER NOT NULL DEFAULT 0,
    continuation_line_count INTEGER NOT NULL DEFAULT 0,
    is_truncated_run INTEGER NOT NULL DEFAULT 0,
    has_control_bytes INTEGER NOT NULL DEFAULT 0,
    UNIQUE(run_id, source_path)
);

CREATE TABLE IF NOT EXISTS normalized_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    source_file_id INTEGER NOT NULL REFERENCES source_files(id) ON DELETE CASCADE,
    event_index INTEGER NOT NULL,
    event_ts TEXT,
    host TEXT,
    severity TEXT,
    module TEXT,
    event_type TEXT NOT NULL,
    event_kind TEXT,
    raw_event_text TEXT NOT NULL,
    source_line_start INTEGER NOT NULL,
    source_line_end INTEGER NOT NULL,
    parse_warnings_json TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    UNIQUE(run_id, source_file_id, event_index)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_key TEXT NOT NULL UNIQUE,
    rule_key TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    context_fingerprint TEXT,
    sha256 TEXT,
    md5 TEXT,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    priority TEXT NOT NULL,
    current_disposition TEXT NOT NULL DEFAULT 'unreviewed',
    current_reason TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    first_run_id TEXT NOT NULL REFERENCES scan_runs(id),
    last_run_id TEXT NOT NULL REFERENCES scan_runs(id)
);

CREATE TABLE IF NOT EXISTS finding_occurrences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL REFERENCES normalized_events(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    host TEXT,
    occurrence_ts TEXT,
    severity TEXT NOT NULL,
    event_type TEXT NOT NULL,
    event_kind TEXT,
    artifact_path TEXT,
    sha256 TEXT,
    context_fingerprint TEXT,
    rule_key TEXT NOT NULL,
    state_for_host_run TEXT,
    score INTEGER,
    source_path TEXT NOT NULL,
    source_line_start INTEGER NOT NULL,
    source_line_end INTEGER NOT NULL,
    UNIQUE(finding_id, event_id, rule_key)
);

CREATE TABLE IF NOT EXISTS analyst_verdicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    decision_ts TEXT NOT NULL,
    disposition TEXT NOT NULL,
    reason TEXT NOT NULL,
    analyst TEXT NOT NULL,
    run_id TEXT REFERENCES scan_runs(id)
);

CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_key TEXT NOT NULL UNIQUE,
    entity_type TEXT NOT NULL,
    scope TEXT NOT NULL,
    identity_value TEXT NOT NULL,
    context_fingerprint TEXT,
    sha256 TEXT,
    md5 TEXT,
    artifact_path TEXT,
    title TEXT NOT NULL,
    observed_severity TEXT NOT NULL,
    observed_priority TEXT NOT NULL,
    severity TEXT NOT NULL,
    priority TEXT NOT NULL,
    current_disposition TEXT NOT NULL DEFAULT 'unreviewed',
    current_reason TEXT,
    disposition_source TEXT NOT NULL DEFAULT 'default',
    policy_name TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    first_run_id TEXT NOT NULL REFERENCES scan_runs(id),
    last_run_id TEXT NOT NULL REFERENCES scan_runs(id)
);

CREATE TABLE IF NOT EXISTS case_memberships (
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    UNIQUE(case_id, finding_id)
);

CREATE TABLE IF NOT EXISTS case_occurrences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL REFERENCES normalized_events(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    host TEXT,
    occurrence_ts TEXT,
    severity TEXT NOT NULL,
    event_type TEXT NOT NULL,
    event_kind TEXT,
    artifact_path TEXT,
    sha256 TEXT,
    context_fingerprint TEXT,
    state_for_host_run TEXT,
    score INTEGER,
    source_path TEXT NOT NULL,
    source_line_start INTEGER NOT NULL,
    source_line_end INTEGER NOT NULL,
    UNIQUE(case_id, event_id)
);

CREATE TABLE IF NOT EXISTS case_verdicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    decision_ts TEXT NOT NULL,
    disposition TEXT NOT NULL,
    reason TEXT NOT NULL,
    analyst TEXT NOT NULL,
    run_id TEXT REFERENCES scan_runs(id),
    source TEXT NOT NULL DEFAULT 'analyst'
);

CREATE TABLE IF NOT EXISTS vt_lookups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL,
    lookup_profile TEXT NOT NULL,
    lookup_ts TEXT NOT NULL,
    result_status TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    error_text TEXT,
    UNIQUE(sha256, lookup_profile)
);

CREATE TABLE IF NOT EXISTS report_runs (
    id TEXT PRIMARY KEY,
    period TEXT NOT NULL,
    created_at TEXT NOT NULL,
    run_scope TEXT NOT NULL,
    run_id TEXT,
    html_path TEXT NOT NULL,
    pdf_path TEXT NOT NULL,
    summary_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_source_files_run_id ON source_files(run_id);
CREATE INDEX IF NOT EXISTS idx_normalized_events_run_id ON normalized_events(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_sha256 ON findings(sha256);
CREATE INDEX IF NOT EXISTS idx_occurrences_run_host ON finding_occurrences(run_id, host);
CREATE INDEX IF NOT EXISTS idx_occurrences_finding ON finding_occurrences(finding_id);
CREATE INDEX IF NOT EXISTS idx_verdicts_finding_ts ON analyst_verdicts(finding_id, decision_ts DESC);
CREATE INDEX IF NOT EXISTS idx_cases_sha256 ON cases(sha256);
CREATE INDEX IF NOT EXISTS idx_cases_identity ON cases(scope, identity_value);
CREATE INDEX IF NOT EXISTS idx_case_memberships_case ON case_memberships(case_id);
CREATE INDEX IF NOT EXISTS idx_case_memberships_finding ON case_memberships(finding_id);
CREATE INDEX IF NOT EXISTS idx_case_occurrences_run_host ON case_occurrences(run_id, host);
CREATE INDEX IF NOT EXISTS idx_case_occurrences_case ON case_occurrences(case_id);
CREATE INDEX IF NOT EXISTS idx_case_verdicts_case_ts ON case_verdicts(case_id, decision_ts DESC);
"""


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn



def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)
    conn.commit()



def create_scan_run(conn: sqlite3.Connection, payload: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT INTO scan_runs(
            id, period, run_kind, run_fingerprint, started_at, completed_at,
            source_count, logical_record_count, continuation_line_count,
            truncated_file_count, parse_warning_count, manifest_path, run_path
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload["id"],
            payload["period"],
            payload["run_kind"],
            payload["run_fingerprint"],
            payload["started_at"],
            payload.get("completed_at"),
            payload.get("source_count", 0),
            payload.get("logical_record_count", 0),
            payload.get("continuation_line_count", 0),
            payload.get("truncated_file_count", 0),
            payload.get("parse_warning_count", 0),
            payload["manifest_path"],
            payload["run_path"],
        ),
    )



def get_scan_run_by_fingerprint(conn: sqlite3.Connection, run_fingerprint: str):
    return conn.execute(
        "SELECT * FROM scan_runs WHERE run_fingerprint = ?", (run_fingerprint,)
    ).fetchone()



def update_scan_run(conn: sqlite3.Connection, run_id: str, payload: dict[str, Any]) -> None:
    assignments = ", ".join(f"{key} = ?" for key in payload)
    values = [payload[key] for key in payload]
    values.append(run_id)
    conn.execute(f"UPDATE scan_runs SET {assignments} WHERE id = ?", values)



def insert_source_file(conn: sqlite3.Connection, payload: dict[str, Any]) -> int:
    cursor = conn.execute(
        """
        INSERT INTO source_files(
            run_id, source_path, relative_path, host_name, scan_started_at,
            filename_timestamp, is_rescan, sha256, size_bytes, line_count,
            logical_record_count, continuation_line_count, is_truncated_run,
            has_control_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload["run_id"],
            payload["source_path"],
            payload["relative_path"],
            payload.get("host_name"),
            payload.get("scan_started_at"),
            payload.get("filename_timestamp"),
            int(payload.get("is_rescan", False)),
            payload["sha256"],
            payload["size_bytes"],
            payload["line_count"],
            payload["logical_record_count"],
            payload["continuation_line_count"],
            int(payload.get("is_truncated_run", False)),
            int(payload.get("has_control_bytes", False)),
        ),
    )
    return int(cursor.lastrowid)



def insert_event(conn: sqlite3.Connection, payload: dict[str, Any]) -> int:
    cursor = conn.execute(
        """
        INSERT INTO normalized_events(
            run_id, source_file_id, event_index, event_ts, host, severity,
            module, event_type, event_kind, raw_event_text, source_line_start,
            source_line_end, parse_warnings_json, payload_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload["run_id"],
            payload["source_file_id"],
            payload["event_index"],
            payload.get("event_ts"),
            payload.get("host"),
            payload.get("severity"),
            payload.get("module"),
            payload["event_type"],
            payload.get("event_kind"),
            payload["raw_event_text"],
            payload["source_line_start"],
            payload["source_line_end"],
            json_dumps(payload.get("parse_warnings", [])),
            json_dumps(payload.get("payload", {})),
        ),
    )
    return int(cursor.lastrowid)



def upsert_finding(conn: sqlite3.Connection, payload: dict[str, Any]) -> int:
    row = conn.execute(
        "SELECT * FROM findings WHERE finding_key = ?", (payload["finding_key"],)
    ).fetchone()
    if row:
        new_severity = higher_severity(str(row["severity"]), payload["severity"])
        new_priority = higher_priority(str(row["priority"]), payload["priority"])
        conn.execute(
            """
            UPDATE findings
            SET title = ?, severity = ?, priority = ?, last_seen_at = ?, last_run_id = ?,
                sha256 = COALESCE(sha256, ?), md5 = COALESCE(md5, ?),
                context_fingerprint = COALESCE(context_fingerprint, ?)
            WHERE id = ?
            """,
            (
                payload["title"],
                new_severity,
                new_priority,
                payload["seen_at"],
                payload["run_id"],
                payload.get("sha256"),
                payload.get("md5"),
                payload.get("context_fingerprint"),
                row["id"],
            ),
        )
        return int(row["id"])
    cursor = conn.execute(
        """
        INSERT INTO findings(
            finding_key, rule_key, entity_type, context_fingerprint, sha256, md5,
            title, severity, priority, current_disposition, current_reason,
            first_seen_at, last_seen_at, first_run_id, last_run_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload["finding_key"],
            payload["rule_key"],
            payload["entity_type"],
            payload.get("context_fingerprint"),
            payload.get("sha256"),
            payload.get("md5"),
            payload["title"],
            payload["severity"],
            payload["priority"],
            payload.get("current_disposition", "unreviewed"),
            payload.get("current_reason"),
            payload["seen_at"],
            payload["seen_at"],
            payload["run_id"],
            payload["run_id"],
        ),
    )
    return int(cursor.lastrowid)



def insert_occurrence(conn: sqlite3.Connection, payload: dict[str, Any]) -> int:
    cursor = conn.execute(
        """
        INSERT OR IGNORE INTO finding_occurrences(
            finding_id, event_id, run_id, host, occurrence_ts, severity, event_type,
            event_kind, artifact_path, sha256, context_fingerprint, rule_key,
            state_for_host_run, score, source_path, source_line_start, source_line_end
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload["finding_id"],
            payload["event_id"],
            payload["run_id"],
            payload.get("host"),
            payload.get("occurrence_ts"),
            payload["severity"],
            payload["event_type"],
            payload.get("event_kind"),
            payload.get("artifact_path"),
            payload.get("sha256"),
            payload.get("context_fingerprint"),
            payload["rule_key"],
            payload.get("state_for_host_run"),
            payload.get("score"),
            payload["source_path"],
            payload["source_line_start"],
            payload["source_line_end"],
        ),
    )
    return int(cursor.lastrowid)



def upsert_case(conn: sqlite3.Connection, payload: dict[str, Any]) -> int:
    row = conn.execute("SELECT * FROM cases WHERE case_key = ?", (payload["case_key"],)).fetchone()
    if row:
        new_observed_severity = higher_severity(str(row["observed_severity"]), payload["observed_severity"])
        new_observed_priority = higher_priority(str(row["observed_priority"]), payload["observed_priority"])
        new_effective_severity = higher_severity(str(row["severity"]), payload["observed_severity"])
        new_effective_priority = higher_priority(str(row["priority"]), payload["observed_priority"])
        conn.execute(
            """
            UPDATE cases
            SET artifact_path = COALESCE(artifact_path, ?),
                sha256 = COALESCE(sha256, ?),
                md5 = COALESCE(md5, ?),
                context_fingerprint = COALESCE(context_fingerprint, ?),
                observed_severity = ?,
                observed_priority = ?,
                severity = ?,
                priority = ?,
                last_seen_at = ?,
                last_run_id = ?
            WHERE id = ?
            """,
            (
                payload.get("artifact_path"),
                payload.get("sha256"),
                payload.get("md5"),
                payload.get("context_fingerprint"),
                new_observed_severity,
                new_observed_priority,
                new_effective_severity,
                new_effective_priority,
                payload["seen_at"],
                payload["run_id"],
                row["id"],
            ),
        )
        return int(row["id"])
    cursor = conn.execute(
        """
        INSERT INTO cases(
            case_key, entity_type, scope, identity_value, context_fingerprint,
            sha256, md5, artifact_path, title, observed_severity, observed_priority,
            severity, priority, current_disposition, current_reason, disposition_source,
            policy_name, first_seen_at, last_seen_at, first_run_id, last_run_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload["case_key"],
            payload["entity_type"],
            payload["scope"],
            payload["identity_value"],
            payload.get("context_fingerprint"),
            payload.get("sha256"),
            payload.get("md5"),
            payload.get("artifact_path"),
            payload["title"],
            payload["observed_severity"],
            payload["observed_priority"],
            payload["observed_severity"],
            payload["observed_priority"],
            payload.get("current_disposition", "unreviewed"),
            payload.get("current_reason"),
            payload.get("disposition_source", "default"),
            payload.get("policy_name"),
            payload["seen_at"],
            payload["seen_at"],
            payload["run_id"],
            payload["run_id"],
        ),
    )
    return int(cursor.lastrowid)



def insert_case_membership(conn: sqlite3.Connection, case_id: int, finding_id: int) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO case_memberships(case_id, finding_id) VALUES (?, ?)",
        (case_id, finding_id),
    )



def insert_case_occurrence(conn: sqlite3.Connection, payload: dict[str, Any]) -> int:
    cursor = conn.execute(
        """
        INSERT OR IGNORE INTO case_occurrences(
            case_id, event_id, run_id, host, occurrence_ts, severity, event_type,
            event_kind, artifact_path, sha256, context_fingerprint, state_for_host_run,
            score, source_path, source_line_start, source_line_end
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload["case_id"],
            payload["event_id"],
            payload["run_id"],
            payload.get("host"),
            payload.get("occurrence_ts"),
            payload["severity"],
            payload["event_type"],
            payload.get("event_kind"),
            payload.get("artifact_path"),
            payload.get("sha256"),
            payload.get("context_fingerprint"),
            payload.get("state_for_host_run"),
            payload.get("score"),
            payload["source_path"],
            payload["source_line_start"],
            payload["source_line_end"],
        ),
    )
    return int(cursor.lastrowid)



def record_verdict(
    conn: sqlite3.Connection,
    finding_id: int,
    disposition: str,
    reason: str,
    analyst: str,
    run_id: str | None = None,
) -> None:
    decision_ts = utc_now()
    conn.execute(
        """
        INSERT INTO analyst_verdicts(finding_id, decision_ts, disposition, reason, analyst, run_id)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (finding_id, decision_ts, disposition, reason, analyst, run_id),
    )
    conn.execute(
        "UPDATE findings SET current_disposition = ?, current_reason = ? WHERE id = ?",
        (disposition, reason, finding_id),
    )



def sync_case_disposition_to_findings(conn: sqlite3.Connection, case_id: int) -> None:
    case_row = conn.execute(
        "SELECT current_disposition, current_reason FROM cases WHERE id = ?",
        (case_id,),
    ).fetchone()
    if case_row is None:
        return
    conn.execute(
        """
        UPDATE findings
        SET current_disposition = ?, current_reason = ?
        WHERE id IN (SELECT finding_id FROM case_memberships WHERE case_id = ?)
        """,
        (case_row["current_disposition"], case_row["current_reason"], case_id),
    )



def set_case_state(
    conn: sqlite3.Connection,
    case_id: int,
    disposition: str,
    reason: str | None,
    source: str,
    policy_name: str | None = None,
    severity: str | None = None,
    priority: str | None = None,
) -> None:
    case_row = conn.execute(
        "SELECT observed_severity, observed_priority FROM cases WHERE id = ?",
        (case_id,),
    ).fetchone()
    if case_row is None:
        raise KeyError(f"Case {case_id} was not found")
    effective_severity = severity or str(case_row["observed_severity"])
    effective_priority = priority or str(case_row["observed_priority"])
    conn.execute(
        """
        UPDATE cases
        SET current_disposition = ?, current_reason = ?, disposition_source = ?, policy_name = ?,
            severity = ?, priority = ?
        WHERE id = ?
        """,
        (disposition, reason, source, policy_name, effective_severity, effective_priority, case_id),
    )
    sync_case_disposition_to_findings(conn, case_id)



def record_case_verdict(
    conn: sqlite3.Connection,
    case_id: int,
    disposition: str,
    reason: str,
    analyst: str,
    run_id: str | None = None,
    source: str = "analyst",
) -> None:
    decision_ts = utc_now()
    conn.execute(
        """
        INSERT INTO case_verdicts(case_id, decision_ts, disposition, reason, analyst, run_id, source)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (case_id, decision_ts, disposition, reason, analyst, run_id, source),
    )
    set_case_state(conn, case_id, disposition, reason, source, None)



def case_ids_for_run(conn: sqlite3.Connection, run_id: str) -> list[int]:
    rows = conn.execute(
        "SELECT DISTINCT case_id FROM case_occurrences WHERE run_id = ? ORDER BY case_id",
        (run_id,),
    ).fetchall()
    return [int(row["case_id"]) for row in rows]



def case_ids_for_sha(conn: sqlite3.Connection, sha256: str) -> list[int]:
    rows = conn.execute(
        "SELECT id FROM cases WHERE sha256 = ? ORDER BY id",
        (sha256,),
    ).fetchall()
    return [int(row["id"]) for row in rows]



def upsert_vt_lookup(
    conn: sqlite3.Connection,
    sha256: str,
    lookup_profile: str,
    result_status: str,
    summary: dict[str, Any],
    raw_payload: Any,
    error_text: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO vt_lookups(sha256, lookup_profile, lookup_ts, result_status, summary_json, raw_json, error_text)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(sha256, lookup_profile) DO UPDATE SET
            lookup_ts = excluded.lookup_ts,
            result_status = excluded.result_status,
            summary_json = excluded.summary_json,
            raw_json = excluded.raw_json,
            error_text = excluded.error_text
        """,
        (
            sha256,
            lookup_profile,
            utc_now(),
            result_status,
            json_dumps(summary),
            json_dumps(raw_payload),
            error_text,
        ),
    )



def insert_report_run(conn: sqlite3.Connection, payload: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT INTO report_runs(id, period, created_at, run_scope, run_id, html_path, pdf_path, summary_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload["id"],
            payload["period"],
            payload["created_at"],
            payload["run_scope"],
            payload.get("run_id"),
            payload["html_path"],
            payload["pdf_path"],
            json_dumps(payload.get("summary", {})),
        ),
    )
