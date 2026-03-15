from __future__ import annotations

from datetime import UTC, datetime
import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from .config import RuntimeConfig, get_project_paths, load_runtime_config
from .db import connect, ensure_schema, upsert_vt_lookup
from .policy import apply_policy_for_sha
from .utils import chunked


NOT_FOUND_PATTERN = re.compile(r'^File "(?P<sha256>[A-Fa-f0-9]{32,64})" not found$', re.MULTILINE)
DEFAULT_VT_ENRICHMENT_SEVERITIES = ("NOTICE", "WARNING", "ERROR", "ALERT")
DEFAULT_VT_ELIGIBLE_DISPOSITIONS = ("unreviewed", "needs_followup", "true_positive")



def _select_profile(runtime_config: RuntimeConfig) -> tuple[str, dict[str, Any]]:
    profile_name = str(runtime_config.vt_config.get("profile", "public_safe"))
    profiles = runtime_config.vt_config.get("profiles", {})
    profile = profiles.get(profile_name)
    if not isinstance(profile, dict):
        raise ValueError(f"VT profile {profile_name!r} is not configured")
    return profile_name, profile



def _eligible_severities(runtime_config: RuntimeConfig) -> tuple[str, ...]:
    configured = runtime_config.vt_config.get("eligible_severities", DEFAULT_VT_ENRICHMENT_SEVERITIES)
    if isinstance(configured, list):
        values = tuple(str(item).upper() for item in configured if str(item).strip())
        if values:
            return values
    return DEFAULT_VT_ENRICHMENT_SEVERITIES



def _eligible_dispositions(runtime_config: RuntimeConfig) -> tuple[str, ...]:
    configured = runtime_config.vt_config.get("eligible_dispositions", DEFAULT_VT_ELIGIBLE_DISPOSITIONS)
    if isinstance(configured, list):
        values = tuple(str(item).strip().lower() for item in configured if str(item).strip())
        if values:
            return values
    return DEFAULT_VT_ELIGIBLE_DISPOSITIONS



def _daily_request_limit(runtime_config: RuntimeConfig) -> int:
    configured = runtime_config.vt_config.get("daily_request_limit", 0)
    try:
        limit = int(configured)
    except (TypeError, ValueError) as exc:
        raise ValueError("VT daily_request_limit must be an integer") from exc
    if limit < 0:
        raise ValueError("VT daily_request_limit must be >= 0")
    return limit



def _utc_today() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")



def _used_budget_today(conn, profile_name: str, utc_day: str) -> int:
    row = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM vt_lookups
        WHERE lookup_profile = ?
          AND substr(lookup_ts, 1, 10) = ?
        """,
        (profile_name, utc_day),
    ).fetchone()
    return int(row["count"] or 0)



def _pending_candidates(
    conn,
    profile_name: str,
    eligible_severities: tuple[str, ...],
    eligible_dispositions: tuple[str, ...],
    run_id: str | None = None,
) -> list[dict[str, Any]]:
    severity_placeholders = ",".join("?" for _ in eligible_severities)
    disposition_placeholders = ",".join("?" for _ in eligible_dispositions)
    params: list[Any] = [profile_name, *eligible_dispositions, *eligible_severities]
    exists_run_clause = ""
    scoped_run_clause = ""
    if run_id:
        exists_run_clause = " AND co.run_id = ?"
        scoped_run_clause = " AND run_id = ?"
        params.append(run_id)
    params.extend(eligible_severities)
    if run_id:
        params.append(run_id)
    rows = conn.execute(
        f"""
        WITH pending_cases AS (
            SELECT c.id AS case_id, c.sha256, c.current_disposition, c.priority
            FROM cases c
            LEFT JOIN vt_lookups v ON v.sha256 = c.sha256 AND v.lookup_profile = ?
            WHERE c.sha256 IS NOT NULL
              AND v.id IS NULL
              AND lower(c.current_disposition) IN ({disposition_placeholders})
              AND EXISTS (
                  SELECT 1
                  FROM case_occurrences co
                  WHERE co.case_id = c.id
                    AND co.severity IN ({severity_placeholders})
                    {exists_run_clause}
              )
        ),
        scoped_occurrences AS (
            SELECT case_id, host, occurrence_ts, COALESCE(score, 0) AS score
            FROM case_occurrences
            WHERE severity IN ({severity_placeholders})
              {scoped_run_clause}
        )
        SELECT
            pc.sha256,
            pc.current_disposition,
            pc.priority,
            MAX(so.score) AS max_score,
            COUNT(DISTINCT so.host) AS host_count,
            COUNT(*) AS occurrence_count,
            MAX(COALESCE(so.occurrence_ts, '')) AS latest_occurrence_ts
        FROM pending_cases pc
        JOIN scoped_occurrences so ON so.case_id = pc.case_id
        GROUP BY pc.case_id, pc.sha256, pc.current_disposition, pc.priority
        ORDER BY
            CASE lower(pc.current_disposition)
                WHEN 'needs_followup' THEN 3
                WHEN 'true_positive' THEN 2
                WHEN 'unreviewed' THEN 1
                ELSE 0
            END DESC,
            CASE lower(pc.priority)
                WHEN 'critical' THEN 5
                WHEN 'high' THEN 4
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 2
                WHEN 'info' THEN 1
                ELSE 0
            END DESC,
            MAX(so.score) DESC,
            COUNT(DISTINCT so.host) DESC,
            COUNT(*) DESC,
            MAX(COALESCE(so.occurrence_ts, '')) DESC,
            pc.sha256 ASC
        """,
        params,
    ).fetchall()
    return [dict(row) for row in rows]



def _extract_vt_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        data = payload.get("data")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            return [data]
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []



def _summarize_vt_record(record: dict[str, Any]) -> dict[str, Any]:
    attributes = record.get("attributes", record)
    stats = attributes.get("last_analysis_stats", {})
    return {
        "meaningful_name": attributes.get("meaningful_name"),
        "type_description": attributes.get("type_description"),
        "reputation": attributes.get("reputation"),
        "size": attributes.get("size"),
        "times_submitted": attributes.get("times_submitted"),
        "first_submission_date": attributes.get("first_submission_date"),
        "last_submission_date": attributes.get("last_submission_date"),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "last_analysis_stats": stats,
        "malicious_count": stats.get("malicious"),
        "suspicious_count": stats.get("suspicious"),
        "popular_threat_classification": attributes.get("popular_threat_classification"),
        "names": attributes.get("names"),
    }



def _vt_command(hashes: list[str], include_fields: list[str]) -> list[str]:
    command = ["vt", "--format", "json", "file", "-t", str(min(len(hashes), 20))]
    for field in include_fields:
        command.extend(["-i", field])
    command.extend(hashes)
    return command


def _record_sha256(record: dict[str, Any]) -> str | None:
    for value in (
        record.get("sha256"),
        record.get("_id"),
        record.get("id"),
        record.get("attributes", {}).get("sha256") if isinstance(record.get("attributes"), dict) else None,
    ):
        if not value:
            continue
        normalized = str(value).strip().lower()
        if normalized:
            return normalized
    return None


def _not_found_hashes(stdout: str, stderr: str) -> set[str]:
    combined = "\n".join(part for part in (stdout, stderr) if part).strip()
    if not combined:
        return set()
    return {match.group("sha256").lower() for match in NOT_FOUND_PATTERN.finditer(combined)}


def _store_vt_lookup(
    conn,
    sha256: str,
    profile_name: str,
    result_status: str,
    summary: dict[str, Any],
    raw_payload: dict[str, Any],
    triage_policy: dict[str, Any],
    errors: list[str],
    error_text: str | None = None,
) -> None:
    upsert_vt_lookup(conn, sha256, profile_name, result_status, summary, raw_payload, error_text)
    apply_policy_for_sha(conn, sha256, triage_policy, profile_name)
    if result_status == "error":
        errors.append(f"{sha256}: {error_text or 'unknown VT error'}")


def _process_vt_group(
    conn,
    group: list[str],
    profile_name: str,
    include_fields: list[str],
    triage_policy: dict[str, Any],
    errors: list[str],
    status_counts: dict[str, int],
) -> int:
    command = _vt_command(group, include_fields)
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    stdout = result.stdout.strip()
    stderr = result.stderr.strip()
    raw_payload = {"stdout": result.stdout, "stderr": result.stderr}

    if result.returncode != 0:
        error_text = stderr or stdout or f"vt exited with {result.returncode}"
        for sha256 in group:
            _store_vt_lookup(conn, sha256, profile_name, "error", {}, raw_payload, triage_policy, errors, error_text)
            status_counts["error"] += 1
        return len(group)

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        payload = None

    if payload is not None:
        records = _extract_vt_records(payload)
        record_map = {
            sha256: record
            for record in records
            if (sha256 := _record_sha256(record))
        }
        for sha256 in group:
            record = record_map.get(sha256.lower())
            if record is None:
                _store_vt_lookup(
                    conn,
                    sha256,
                    profile_name,
                    "not_found",
                    {},
                    raw_payload,
                    triage_policy,
                    errors,
                    "VT returned no record for hash",
                )
                status_counts["not_found"] += 1
                continue
            _store_vt_lookup(
                conn,
                sha256,
                profile_name,
                "ok",
                _summarize_vt_record(record),
                record,
                triage_policy,
                errors,
            )
            status_counts["ok"] += 1
        return len(group)

    not_found_hashes = _not_found_hashes(result.stdout, result.stderr)
    for sha256 in group:
        if sha256.lower() in not_found_hashes:
            _store_vt_lookup(
                conn,
                sha256,
                profile_name,
                "not_found",
                {},
                raw_payload,
                triage_policy,
                errors,
                "VT returned no record for hash",
            )
            status_counts["not_found"] += 1
            continue
        _store_vt_lookup(
            conn,
            sha256,
            profile_name,
            "error",
            {},
            raw_payload,
            triage_policy,
            errors,
            "unexpected-vt-output",
        )
        status_counts["error"] += 1
    return len(group)



def enrich_hashes(run_id: str | None = None, project_root: Path | None = None) -> dict[str, Any]:
    project_paths = get_project_paths(project_root)
    runtime_config = load_runtime_config(project_paths)
    profile_name, profile = _select_profile(runtime_config)
    eligible_severities = _eligible_severities(runtime_config)
    eligible_dispositions = _eligible_dispositions(runtime_config)
    daily_request_limit = _daily_request_limit(runtime_config)
    conn = connect(project_paths.db_path)
    ensure_schema(conn)
    try:
        utc_day = _utc_today()
        used_today = _used_budget_today(conn, profile_name, utc_day)
        remaining_budget = max(daily_request_limit - used_today, 0)
        candidates = _pending_candidates(conn, profile_name, eligible_severities, eligible_dispositions, run_id)
        candidate_count = len(candidates)
        selected_hashes = [str(candidate["sha256"]) for candidate in candidates[:remaining_budget]]
        deferred_count = max(candidate_count - len(selected_hashes), 0)
        base_result = {
            "profile": profile_name,
            "processed": 0,
            "candidate_count": candidate_count,
            "selected_count": len(selected_hashes),
            "deferred_count": deferred_count,
            "daily_request_limit": daily_request_limit,
            "used_today": used_today,
            "remaining_budget": remaining_budget,
            "status_counts": {"ok": 0, "not_found": 0, "error": 0},
            "errors": [],
            "utc_day": utc_day,
        }
        if not candidates:
            base_result["summary"] = (
                f"No pending VT hashes for profile {profile_name} "
                f"(used_today={used_today}/{daily_request_limit}, utc_day={utc_day})"
            )
            return base_result
        if not selected_hashes:
            base_result["summary"] = (
                f"VT daily budget exhausted for profile {profile_name} on {utc_day} UTC "
                f"(used_today={used_today}/{daily_request_limit}, deferred={deferred_count})"
            )
            return base_result
        processed = 0
        errors: list[str] = []
        status_counts = {"ok": 0, "not_found": 0, "error": 0}
        include_fields = list(profile.get("include_fields", ["**"]))
        sleep_seconds = float(profile.get("sleep_seconds", 0))
        batch_size = int(profile.get("batch_size", 1))
        for group in chunked(selected_hashes, batch_size):
            processed += _process_vt_group(
                conn,
                group,
                profile_name,
                include_fields,
                runtime_config.triage_policy,
                errors,
                status_counts,
            )
            conn.commit()
            if sleep_seconds > 0 and processed < len(selected_hashes):
                time.sleep(sleep_seconds)
        return {
            **base_result,
            "processed": processed,
            "status_counts": status_counts,
            "errors": errors,
            "remaining_budget": max(daily_request_limit - used_today - processed, 0),
            "summary": (
                f"Processed {processed} of {candidate_count} eligible hashes with VT profile {profile_name} "
                f"(used_today={used_today + processed}/{daily_request_limit}, deferred={deferred_count}, "
                f"ok={status_counts['ok']}, not_found={status_counts['not_found']}, error={status_counts['error']})"
            ),
        }
    finally:
        conn.close()
