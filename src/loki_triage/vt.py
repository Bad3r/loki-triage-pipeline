from __future__ import annotations

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



def _pending_hashes(conn, profile_name: str, eligible_severities: tuple[str, ...], run_id: str | None = None) -> list[str]:
    severity_placeholders = ",".join("?" for _ in eligible_severities)
    params: list[Any] = [profile_name, "expected_benign", "false_positive", *eligible_severities]
    run_clause = ""
    if run_id:
        run_clause = " AND co.run_id = ?"
        params.append(run_id)
    rows = conn.execute(
        f"""
        SELECT c.sha256
        FROM cases c
        LEFT JOIN vt_lookups v ON v.sha256 = c.sha256 AND v.lookup_profile = ?
        JOIN case_occurrences co ON co.case_id = c.id
        WHERE c.sha256 IS NOT NULL
          AND v.id IS NULL
          AND c.current_disposition NOT IN (?, ?)
          AND co.severity IN ({severity_placeholders})
          {run_clause}
        GROUP BY c.id, c.sha256
        ORDER BY MIN(COALESCE(co.occurrence_ts, c.first_seen_at)) ASC, c.id ASC
        """,
        params,
    ).fetchall()
    return [str(row["sha256"]) for row in rows]



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
    conn = connect(project_paths.db_path)
    ensure_schema(conn)
    try:
        hashes = _pending_hashes(conn, profile_name, eligible_severities, run_id)
        if not hashes:
            return {"profile": profile_name, "processed": 0, "summary": "No pending hashes"}
        processed = 0
        errors: list[str] = []
        status_counts = {"ok": 0, "not_found": 0, "error": 0}
        include_fields = list(profile.get("include_fields", ["**"]))
        sleep_seconds = float(profile.get("sleep_seconds", 0))
        batch_size = int(profile.get("batch_size", 1))
        for group in chunked(hashes, batch_size):
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
            if sleep_seconds > 0 and processed < len(hashes):
                time.sleep(sleep_seconds)
        return {
            "profile": profile_name,
            "processed": processed,
            "status_counts": status_counts,
            "errors": errors,
            "summary": (
                f"Processed {processed} hashes with VT profile {profile_name} "
                f"(ok={status_counts['ok']}, not_found={status_counts['not_found']}, error={status_counts['error']})"
            ),
        }
    finally:
        conn.close()
