from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Iterable

from .classify import build_finding_candidates
from .config import ProjectPaths, ensure_project_layout, get_project_paths, load_runtime_config
from .db import (
    connect,
    create_scan_run,
    ensure_schema,
    get_scan_run_by_fingerprint,
    insert_case_membership,
    insert_case_occurrence,
    insert_event,
    insert_occurrence,
    insert_source_file,
    update_scan_run,
    upsert_case,
    upsert_finding,
)
from .parser import normalize_record, reconstruct_log
from .policy import apply_policy_for_run, build_case_candidate
from .utils import (
    append_jsonl,
    compact_utc_now,
    format_table,
    json_dumps,
    relative_to,
    sha256_file,
    utc_now,
)


VALID_RUN_KINDS = {"baseline", "rescan", "mixed"}



def collect_log_paths(inputs: Iterable[Path]) -> list[Path]:
    discovered: list[Path] = []
    for input_path in inputs:
        path = input_path.resolve()
        if path.is_dir():
            discovered.extend(sorted(file for file in path.rglob("*.log") if file.is_file()))
        elif path.is_file() and path.suffix.lower() == ".log":
            discovered.append(path)
    deduped: list[Path] = []
    seen: set[Path] = set()
    for path in discovered:
        if path in seen:
            continue
        seen.add(path)
        deduped.append(path)
    return deduped



def _run_fingerprint(period: str, run_kind: str, files: list[dict[str, Any]]) -> str:
    payload = json_dumps(
        {
            "period": period,
            "run_kind": run_kind,
            "files": [
                {
                    "path": item["source_path"],
                    "sha256": item["sha256"],
                    "size_bytes": item["size_bytes"],
                }
                for item in files
            ],
        }
    )
    from hashlib import sha256

    return sha256(payload.encode("utf-8")).hexdigest()



def _prepare_file_descriptors(project_paths: ProjectPaths, log_paths: list[Path]) -> list[dict[str, Any]]:
    descriptors: list[dict[str, Any]] = []
    for path in log_paths:
        descriptors.append(
            {
                "source_path": str(path),
                "relative_path": relative_to(path, project_paths.root),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return descriptors



def _run_dir(paths: ProjectPaths, period: str, run_id: str) -> Path:
    run_path = paths.runs_dir / period / run_id
    run_path.mkdir(parents=True, exist_ok=True)
    (run_path / "report").mkdir(parents=True, exist_ok=True)
    (run_path / "exports").mkdir(parents=True, exist_ok=True)
    (run_path / "logs").mkdir(parents=True, exist_ok=True)
    return run_path



def _previous_host_run(conn, host: str, current_run_id: str, current_scan_ts: str | None) -> str | None:
    if current_scan_ts is None:
        return None
    row = conn.execute(
        """
        SELECT sf.run_id, MAX(COALESCE(sf.scan_started_at, sf.filename_timestamp)) AS scan_ts
        FROM source_files sf
        WHERE sf.host_name = ?
          AND sf.run_id != ?
          AND COALESCE(sf.scan_started_at, sf.filename_timestamp) < ?
        GROUP BY sf.run_id
        ORDER BY scan_ts DESC
        LIMIT 1
        """,
        (host, current_run_id, current_scan_ts),
    ).fetchone()
    return str(row["run_id"]) if row else None



def _finding_ids_for_host_run(conn, host: str, run_id: str) -> set[int]:
    rows = conn.execute(
        "SELECT DISTINCT finding_id FROM finding_occurrences WHERE host = ? AND run_id = ?",
        (host, run_id),
    ).fetchall()
    return {int(row["finding_id"]) for row in rows}



def _older_finding_ids_for_host_before(conn, host: str, scan_ts: str, excluding_run_id: str | None = None) -> set[int]:
    query = """
        SELECT DISTINCT fo.finding_id
        FROM finding_occurrences fo
        JOIN source_files sf ON sf.run_id = fo.run_id AND sf.host_name = fo.host
        WHERE fo.host = ?
          AND COALESCE(sf.scan_started_at, sf.filename_timestamp) < ?
    """
    params: list[Any] = [host, scan_ts]
    if excluding_run_id is not None:
        query += " AND fo.run_id != ?"
        params.append(excluding_run_id)
    rows = conn.execute(query, params).fetchall()
    return {int(row["finding_id"]) for row in rows}



def _case_ids_for_host_run(conn, host: str, run_id: str) -> set[int]:
    rows = conn.execute(
        "SELECT DISTINCT case_id FROM case_occurrences WHERE host = ? AND run_id = ?",
        (host, run_id),
    ).fetchall()
    return {int(row["case_id"]) for row in rows}



def _older_case_ids_for_host_before(conn, host: str, scan_ts: str, excluding_run_id: str | None = None) -> set[int]:
    query = """
        SELECT DISTINCT co.case_id
        FROM case_occurrences co
        JOIN source_files sf ON sf.run_id = co.run_id AND sf.host_name = co.host
        WHERE co.host = ?
          AND COALESCE(sf.scan_started_at, sf.filename_timestamp) < ?
    """
    params: list[Any] = [host, scan_ts]
    if excluding_run_id is not None:
        query += " AND co.run_id != ?"
        params.append(excluding_run_id)
    rows = conn.execute(query, params).fetchall()
    return {int(row["case_id"]) for row in rows}



def update_occurrence_states_for_run(conn, run_id: str) -> None:
    host_rows = conn.execute(
        """
        SELECT host_name, MAX(COALESCE(scan_started_at, filename_timestamp)) AS scan_ts
        FROM source_files
        WHERE run_id = ?
        GROUP BY host_name
        """,
        (run_id,),
    ).fetchall()
    for host_row in host_rows:
        host = host_row["host_name"]
        if not host:
            continue
        scan_ts = host_row["scan_ts"]
        previous_run_id = _previous_host_run(conn, host, run_id, scan_ts)
        previous_ids = _finding_ids_for_host_run(conn, host, previous_run_id) if previous_run_id else set()
        older_ids = _older_finding_ids_for_host_before(conn, host, scan_ts, previous_run_id)
        current_rows = conn.execute(
            "SELECT id, finding_id FROM finding_occurrences WHERE run_id = ? AND host = ?",
            (run_id, host),
        ).fetchall()
        for current in current_rows:
            finding_id = int(current["finding_id"])
            if previous_run_id is None:
                state = "new"
            elif finding_id in previous_ids:
                state = "persisting"
            elif finding_id in older_ids:
                state = "reopened"
            else:
                state = "new"
            conn.execute(
                "UPDATE finding_occurrences SET state_for_host_run = ? WHERE id = ?",
                (state, current["id"]),
            )



def update_case_occurrence_states_for_run(conn, run_id: str) -> None:
    host_rows = conn.execute(
        """
        SELECT host_name, MAX(COALESCE(scan_started_at, filename_timestamp)) AS scan_ts
        FROM source_files
        WHERE run_id = ?
        GROUP BY host_name
        """,
        (run_id,),
    ).fetchall()
    for host_row in host_rows:
        host = host_row["host_name"]
        if not host:
            continue
        scan_ts = host_row["scan_ts"]
        previous_run_id = _previous_host_run(conn, host, run_id, scan_ts)
        previous_ids = _case_ids_for_host_run(conn, host, previous_run_id) if previous_run_id else set()
        older_ids = _older_case_ids_for_host_before(conn, host, scan_ts, previous_run_id)
        current_rows = conn.execute(
            "SELECT id, case_id FROM case_occurrences WHERE run_id = ? AND host = ?",
            (run_id, host),
        ).fetchall()
        for current in current_rows:
            case_id = int(current["case_id"])
            if previous_run_id is None:
                state = "new"
            elif case_id in previous_ids:
                state = "persisting"
            elif case_id in older_ids:
                state = "reopened"
            else:
                state = "new"
            conn.execute(
                "UPDATE case_occurrences SET state_for_host_run = ? WHERE id = ?",
                (state, current["id"]),
            )



def queue_rows_for_run(conn, run_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        WITH case_metrics AS (
            SELECT
                case_id,
                COUNT(*) AS occurrences,
                COUNT(DISTINCT host) AS hosts,
                MAX(occurrence_ts) AS last_seen
            FROM case_occurrences
            WHERE run_id = ?
            GROUP BY case_id
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
            c.current_reason,
            c.title,
            c.artifact_path,
            m.occurrences,
            m.hosts,
            m.last_seen,
            r.matched_rules
        FROM case_metrics m
        JOIN cases c ON c.id = m.case_id
        LEFT JOIN case_rules r ON r.case_id = c.id
        ORDER BY
            CASE c.priority
                WHEN 'critical' THEN 5
                WHEN 'high' THEN 4
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 2
                ELSE 1
            END DESC,
            CASE c.severity
                WHEN 'ALERT' THEN 5
                WHEN 'WARNING' THEN 4
                WHEN 'ERROR' THEN 3
                WHEN 'NOTICE' THEN 2
                WHEN 'RESULT' THEN 1
                ELSE 0
            END DESC,
            m.last_seen DESC,
            c.id ASC
        """,
        (run_id,),
    ).fetchall()
    return [dict(row) for row in rows]



def export_case_rows_for_run(conn, run_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        WITH scoped_occurrences AS (
            SELECT * FROM case_occurrences WHERE run_id = ?
        ),
        case_metrics AS (
            SELECT
                case_id,
                COUNT(*) AS occurrence_count,
                COUNT(DISTINCT host) AS host_count,
                MIN(occurrence_ts) AS first_occurrence_ts,
                MAX(occurrence_ts) AS last_occurrence_ts,
                MIN(source_path) AS source_path,
                MIN(source_line_start) AS source_line_start,
                MIN(source_line_end) AS source_line_end
            FROM scoped_occurrences
            GROUP BY case_id
        ),
        case_rules AS (
            SELECT cm.case_id, GROUP_CONCAT(DISTINCT f.rule_key) AS matched_rules
            FROM case_memberships cm
            JOIN findings f ON f.id = cm.finding_id
            GROUP BY cm.case_id
        )
        SELECT
            c.id AS case_id,
            c.title,
            c.severity,
            c.priority,
            c.current_disposition,
            c.current_reason,
            c.artifact_path,
            c.sha256,
            m.occurrence_count,
            m.host_count,
            m.first_occurrence_ts,
            m.last_occurrence_ts,
            r.matched_rules,
            m.source_path,
            m.source_line_start,
            m.source_line_end
        FROM case_metrics m
        JOIN cases c ON c.id = m.case_id
        LEFT JOIN case_rules r ON r.case_id = c.id
        ORDER BY
            CASE c.priority
                WHEN 'critical' THEN 5
                WHEN 'high' THEN 4
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 2
                ELSE 1
            END DESC,
            m.last_occurrence_ts DESC,
            c.id ASC
        """,
        (run_id,),
    ).fetchall()
    return [dict(row) for row in rows]



def export_raw_rows_for_run(conn, run_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT
            fo.id AS occurrence_id,
            fo.run_id,
            fo.host,
            fo.occurrence_ts,
            fo.state_for_host_run,
            fo.event_type,
            fo.event_kind,
            fo.artifact_path,
            fo.sha256,
            fo.context_fingerprint,
            fo.rule_key,
            fo.score,
            fo.source_path,
            fo.source_line_start,
            fo.source_line_end,
            f.id AS finding_id,
            f.title,
            f.severity,
            f.priority,
            f.current_disposition,
            f.current_reason,
            cm.case_id,
            c.current_disposition AS case_disposition,
            c.current_reason AS case_reason
        FROM finding_occurrences fo
        JOIN findings f ON f.id = fo.finding_id
        LEFT JOIN case_memberships cm ON cm.finding_id = f.id
        LEFT JOIN cases c ON c.id = cm.case_id
        WHERE fo.run_id = ?
        ORDER BY fo.host, fo.occurrence_ts, fo.id
        """,
        (run_id,),
    ).fetchall()
    return [dict(row) for row in rows]



def export_rows_for_run(conn, run_id: str) -> list[dict[str, Any]]:
    return export_case_rows_for_run(conn, run_id)



def _run_case_counts(conn, run_id: str) -> dict[str, int]:
    row = conn.execute(
        """
        SELECT
            COUNT(*) AS case_occurrences,
            COUNT(DISTINCT case_id) AS cases
        FROM case_occurrences
        WHERE run_id = ?
        """,
        (run_id,),
    ).fetchone()
    if row is None:
        return {"case_occurrences": 0, "cases": 0}
    return {"case_occurrences": int(row["case_occurrences"]), "cases": int(row["cases"])}



def ingest_logs(
    input_paths: list[Path],
    period: str,
    run_kind: str,
    project_root: Path | None = None,
) -> dict[str, Any]:
    if run_kind not in VALID_RUN_KINDS:
        raise ValueError(f"run_kind must be one of {sorted(VALID_RUN_KINDS)}")
    project_paths = get_project_paths(project_root)
    ensure_project_layout(project_paths)
    runtime_config = load_runtime_config(project_paths)
    lookup_profile = str(runtime_config.vt_config.get("profile", "public_safe"))
    log_paths = collect_log_paths(input_paths or [project_paths.raw_logs_dir])
    if not log_paths:
        raise FileNotFoundError("No Loki log files were found in the provided paths")

    file_descriptors = _prepare_file_descriptors(project_paths, log_paths)
    run_fingerprint = _run_fingerprint(period, run_kind, file_descriptors)

    conn = connect(project_paths.db_path)
    ensure_schema(conn)
    existing = get_scan_run_by_fingerprint(conn, run_fingerprint)
    if existing:
        conn.close()
        return {
            "reused": True,
            "run_id": existing["id"],
            "period": existing["period"],
            "summary": f"Run {existing['id']} already exists for the same source set.",
        }

    run_id = f"{period}-{compact_utc_now()}-{run_kind}"
    run_path = _run_dir(project_paths, period, run_id)
    manifest_path = run_path / "manifest.json"
    normalized_path = run_path / "normalized_events.jsonl"
    findings_path = run_path / "findings.jsonl"
    queue_path = run_path / "triage_queue.jsonl"
    staging_dir = project_paths.runs_dir / ".tmp"
    staging_dir.mkdir(parents=True, exist_ok=True)
    normalized_tmp_path = staging_dir / f"{run_id}.normalized_events.jsonl.tmp"
    findings_tmp_path = staging_dir / f"{run_id}.findings.jsonl.tmp"
    queue_tmp_path = staging_dir / f"{run_id}.triage_queue.jsonl.tmp"
    manifest_tmp_path = staging_dir / f"{run_id}.manifest.json.tmp"

    scan_run = {
        "id": run_id,
        "period": period,
        "run_kind": run_kind,
        "run_fingerprint": run_fingerprint,
        "started_at": utc_now(),
        "completed_at": None,
        "source_count": len(file_descriptors),
        "logical_record_count": 0,
        "continuation_line_count": 0,
        "truncated_file_count": 0,
        "parse_warning_count": 0,
        "manifest_path": str(manifest_path),
        "run_path": str(run_path),
    }

    manifest: dict[str, Any] = {
        "run_id": run_id,
        "period": period,
        "run_kind": run_kind,
        "created_at": scan_run["started_at"],
        "source_count": len(file_descriptors),
        "totals": {
            "logical_records": 0,
            "continuation_lines": 0,
            "truncated_files": 0,
            "parse_warnings": 0,
            "events": 0,
            "finding_occurrences": 0,
            "case_occurrences": 0,
            "cases": 0,
        },
        "sources": [],
    }

    conn.execute("BEGIN")
    try:
        create_scan_run(conn, scan_run)
        with normalized_tmp_path.open("w", encoding="utf-8") as normalized_handle, findings_tmp_path.open(
            "w", encoding="utf-8"
        ) as findings_handle:
            for file_descriptor, log_path in zip(file_descriptors, log_paths, strict=True):
                reconstruction = reconstruct_log(log_path)
                source_payload = {
                    **file_descriptor,
                    "run_id": run_id,
                    "host_name": reconstruction.get("host_from_filename"),
                    "scan_started_at": reconstruction.get("scan_started_at"),
                    "filename_timestamp": reconstruction.get("filename_timestamp"),
                    "is_rescan": reconstruction.get("is_rescan", False),
                    "line_count": reconstruction["line_count"],
                    "logical_record_count": reconstruction["logical_record_count"],
                    "continuation_line_count": reconstruction["continuation_line_count"],
                    "is_truncated_run": reconstruction["is_truncated_run"],
                    "has_control_bytes": reconstruction["has_control_bytes"],
                }
                source_file_id = insert_source_file(conn, source_payload)
                manifest["sources"].append(
                    {
                        **source_payload,
                        "source_file_id": source_file_id,
                        "parse_warnings": reconstruction["parse_warnings"],
                    }
                )
                manifest["totals"]["logical_records"] += reconstruction["logical_record_count"]
                manifest["totals"]["continuation_lines"] += reconstruction["continuation_line_count"]
                manifest["totals"]["parse_warnings"] += len(reconstruction["parse_warnings"])
                if reconstruction["is_truncated_run"]:
                    manifest["totals"]["truncated_files"] += 1
                for event_index, record in enumerate(reconstruction["records"], start=1):
                    event = normalize_record(record)
                    event.update(
                        {
                            "run_id": run_id,
                            "source_file_id": source_file_id,
                            "event_index": event_index,
                            "source_path": str(log_path),
                        }
                    )
                    event_id = insert_event(conn, event)
                    manifest["totals"]["events"] += 1
                    manifest["totals"]["parse_warnings"] += len(event.get("parse_warnings", []))
                    append_jsonl(
                        normalized_handle,
                        {
                            **event,
                            "event_id": event_id,
                            "source_path": str(log_path),
                            "relative_source_path": relative_to(log_path, project_paths.root),
                        },
                    )
                    candidates = build_finding_candidates(event, runtime_config.severity_rules)
                    for candidate in candidates:
                        finding_id = upsert_finding(
                            conn,
                            {
                                **candidate,
                                "seen_at": event["event_ts"],
                                "run_id": run_id,
                            },
                        )
                        insert_occurrence(
                            conn,
                            {
                                "finding_id": finding_id,
                                "event_id": event_id,
                                "run_id": run_id,
                                "host": candidate.get("host") or event.get("host"),
                                "occurrence_ts": candidate.get("occurrence_ts") or event.get("event_ts"),
                                "severity": candidate["severity"],
                                "event_type": candidate["event_type"],
                                "event_kind": candidate.get("event_kind"),
                                "artifact_path": candidate.get("artifact_path"),
                                "sha256": candidate.get("sha256"),
                                "context_fingerprint": candidate.get("context_fingerprint"),
                                "rule_key": candidate["rule_key"],
                                "score": candidate.get("score"),
                                "source_path": str(log_path),
                                "source_line_start": event["source_line_start"],
                                "source_line_end": event["source_line_end"],
                            },
                        )
                        manifest["totals"]["finding_occurrences"] += 1

                        case_payload = build_case_candidate(candidate)
                        case_id = upsert_case(
                            conn,
                            {
                                **case_payload,
                                "seen_at": event["event_ts"],
                                "run_id": run_id,
                            },
                        )
                        insert_case_membership(conn, case_id, finding_id)
                        insert_case_occurrence(
                            conn,
                            {
                                "case_id": case_id,
                                "event_id": event_id,
                                "run_id": run_id,
                                "host": candidate.get("host") or event.get("host"),
                                "occurrence_ts": candidate.get("occurrence_ts") or event.get("event_ts"),
                                "severity": candidate["severity"],
                                "event_type": candidate["event_type"],
                                "event_kind": candidate.get("event_kind"),
                                "artifact_path": candidate.get("artifact_path"),
                                "sha256": candidate.get("sha256"),
                                "context_fingerprint": candidate.get("context_fingerprint"),
                                "score": candidate.get("score"),
                                "source_path": str(log_path),
                                "source_line_start": event["source_line_start"],
                                "source_line_end": event["source_line_end"],
                            },
                        )
                        append_jsonl(
                            findings_handle,
                            {
                                **candidate,
                                "finding_id": finding_id,
                                "case_id": case_id,
                                "event_id": event_id,
                                "source_path": str(log_path),
                                "relative_source_path": relative_to(log_path, project_paths.root),
                                "source_line_start": event["source_line_start"],
                                "source_line_end": event["source_line_end"],
                            },
                        )
        update_occurrence_states_for_run(conn, run_id)
        update_case_occurrence_states_for_run(conn, run_id)
        apply_policy_for_run(conn, run_id, runtime_config.triage_policy, lookup_profile)

        case_counts = _run_case_counts(conn, run_id)
        manifest["totals"]["case_occurrences"] = case_counts["case_occurrences"]
        manifest["totals"]["cases"] = case_counts["cases"]

        queue_rows = queue_rows_for_run(conn, run_id)
        run_path.mkdir(parents=True, exist_ok=True)
        with queue_tmp_path.open("w", encoding="utf-8") as queue_handle:
            for row in queue_rows:
                append_jsonl(queue_handle, row)
        update_scan_run(
            conn,
            run_id,
            {
                "completed_at": utc_now(),
                "logical_record_count": manifest["totals"]["logical_records"],
                "continuation_line_count": manifest["totals"]["continuation_lines"],
                "truncated_file_count": manifest["totals"]["truncated_files"],
                "parse_warning_count": manifest["totals"]["parse_warnings"],
            },
        )
        write_manifest = {
            **manifest,
            "queue_rows": len(queue_rows),
            "run_path": str(run_path),
            "artifacts": {
                "normalized_events": str(normalized_path),
                "findings": str(findings_path),
                "triage_queue": str(queue_path),
            },
        }
        manifest_tmp_path.write_text(json_dumps(write_manifest) + "\n", encoding="utf-8")
        normalized_tmp_path.replace(normalized_path)
        findings_tmp_path.replace(findings_path)
        queue_tmp_path.replace(queue_path)
        manifest_tmp_path.replace(manifest_path)
        conn.commit()
        summary_rows = [
            {
                "metric": "run_id",
                "value": run_id,
            },
            {"metric": "source_files", "value": len(log_paths)},
            {"metric": "events", "value": manifest["totals"]["events"]},
            {"metric": "finding_occurrences", "value": manifest["totals"]["finding_occurrences"]},
            {"metric": "case_occurrences", "value": manifest["totals"]["case_occurrences"]},
            {"metric": "cases", "value": manifest["totals"]["cases"]},
            {"metric": "continuation_lines", "value": manifest["totals"]["continuation_lines"]},
            {"metric": "truncated_files", "value": manifest["totals"]["truncated_files"]},
        ]
        return {
            "reused": False,
            "run_id": run_id,
            "period": period,
            "run_path": str(run_path),
            "manifest_path": str(manifest_path),
            "summary": format_table(summary_rows, [("metric", "Metric"), ("value", "Value")]),
        }
    except Exception:
        conn.rollback()
        shutil.rmtree(run_path, ignore_errors=True)
        for path in (normalized_tmp_path, findings_tmp_path, queue_tmp_path, manifest_tmp_path):
            path.unlink(missing_ok=True)
        raise
    finally:
        conn.close()
