from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any

from .config import RuntimeConfig, get_project_paths, load_runtime_config
from .db import connect, ensure_schema, upsert_vt_lookup
from .utils import chunked, utc_now



def _select_profile(runtime_config: RuntimeConfig) -> tuple[str, dict[str, Any]]:
    profile_name = str(runtime_config.vt_config.get("profile", "public_safe"))
    profiles = runtime_config.vt_config.get("profiles", {})
    profile = profiles.get(profile_name)
    if not isinstance(profile, dict):
        raise ValueError(f"VT profile {profile_name!r} is not configured")
    return profile_name, profile



def _pending_hashes(conn, profile_name: str, run_id: str | None = None) -> list[str]:
    params: list[Any] = [profile_name]
    run_clause = ""
    if run_id:
        run_clause = " AND fo.run_id = ?"
        params.append(run_id)
    rows = conn.execute(
        f"""
        SELECT DISTINCT f.sha256
        FROM findings f
        LEFT JOIN vt_lookups v ON v.sha256 = f.sha256 AND v.lookup_profile = ?
        LEFT JOIN finding_occurrences fo ON fo.finding_id = f.id
        WHERE f.sha256 IS NOT NULL
          AND v.id IS NULL
          {run_clause}
        ORDER BY f.sha256 ASC
        """,
        params,
    ).fetchall()
    return [str(row["sha256"]) for row in rows]



def _extract_vt_record(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict):
        data = payload.get("data")
        if isinstance(data, list) and data:
            return data[0]
        if isinstance(data, dict):
            return data
        return payload
    if isinstance(payload, list) and payload:
        return payload[0]
    return {}



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



def _vt_command(sha256: str, include_fields: list[str]) -> list[str]:
    command = ["vt", "--format", "json", "file"]
    for field in include_fields:
        command.extend(["-i", field])
    command.append(sha256)
    return command



def enrich_hashes(run_id: str | None = None, project_root: Path | None = None) -> dict[str, Any]:
    project_paths = get_project_paths(project_root)
    runtime_config = load_runtime_config(project_paths)
    profile_name, profile = _select_profile(runtime_config)
    conn = connect(project_paths.db_path)
    ensure_schema(conn)
    try:
        hashes = _pending_hashes(conn, profile_name, run_id)
        if not hashes:
            return {"profile": profile_name, "processed": 0, "summary": "No pending hashes"}
        processed = 0
        errors: list[str] = []
        include_fields = list(profile.get("include_fields", ["**"]))
        sleep_seconds = float(profile.get("sleep_seconds", 0))
        batch_size = int(profile.get("batch_size", 1))
        for group in chunked(hashes, batch_size):
            for sha256 in group:
                command = _vt_command(sha256, include_fields)
                result = subprocess.run(command, capture_output=True, text=True, check=False)
                if result.returncode != 0:
                    error_text = result.stderr.strip() or result.stdout.strip() or f"vt exited with {result.returncode}"
                    upsert_vt_lookup(conn, sha256, profile_name, "error", {}, {"stdout": result.stdout}, error_text)
                    errors.append(f"{sha256}: {error_text}")
                    processed += 1
                    continue
                try:
                    payload = json.loads(result.stdout)
                except json.JSONDecodeError as exc:
                    upsert_vt_lookup(
                        conn,
                        sha256,
                        profile_name,
                        "error",
                        {},
                        {"stdout": result.stdout},
                        f"invalid-json: {exc}",
                    )
                    errors.append(f"{sha256}: invalid-json")
                    processed += 1
                    continue
                record = _extract_vt_record(payload)
                summary = _summarize_vt_record(record)
                upsert_vt_lookup(conn, sha256, profile_name, "ok", summary, payload)
                processed += 1
            conn.commit()
            if sleep_seconds > 0 and processed < len(hashes):
                time.sleep(sleep_seconds)
        return {
            "profile": profile_name,
            "processed": processed,
            "errors": errors,
            "summary": f"Processed {processed} hashes with VT profile {profile_name}",
        }
    finally:
        conn.close()
