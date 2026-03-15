from __future__ import annotations

import json
import re
from typing import Any

from .db import case_ids_for_run, case_ids_for_sha, set_case_state
from .utils import canonical_key, sha256_bytes


DEFAULT_EXPECTED_BENIGN = "expected_benign"
DEFAULT_VT_FOLLOWUP = "needs_followup"



def build_case_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    entity_type = str(candidate["entity_type"])
    artifact_path = candidate.get("artifact_path")
    sha256 = candidate.get("sha256")
    context_fingerprint = candidate.get("context_fingerprint")

    if entity_type == "file" and sha256:
        scope = "sha256"
        identity_value = sha256.lower()
    elif artifact_path:
        scope = "artifact_path"
        identity_value = canonical_key(str(artifact_path))
    elif context_fingerprint:
        scope = "context"
        identity_value = canonical_key(str(context_fingerprint))
    else:
        scope = "title"
        identity_value = canonical_key(str(candidate.get("title") or entity_type))

    identity = {
        "entity_type": entity_type,
        "identity_value": identity_value,
        "scope": scope,
    }
    ordered = "|".join(f"{key}={identity[key]}" for key in sorted(identity))
    if entity_type == "file" and artifact_path:
        title = str(artifact_path)
    else:
        title = str(candidate.get("title") or identity_value)
    return {
        "case_key": sha256_bytes(ordered.encode("utf-8")),
        "entity_type": entity_type,
        "scope": scope,
        "identity_value": identity_value,
        "context_fingerprint": context_fingerprint,
        "sha256": sha256,
        "md5": candidate.get("md5"),
        "artifact_path": artifact_path,
        "title": title,
        "observed_severity": candidate["severity"],
        "observed_priority": candidate["priority"],
    }



def _case_context(conn, case_id: int, lookup_profile: str) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT
            c.*,
            GROUP_CONCAT(DISTINCT f.rule_key) AS rule_keys,
            GROUP_CONCAT(DISTINCT co.host) AS hosts,
            vt.summary_json AS vt_summary_json,
            vt.result_status AS vt_result_status
        FROM cases c
        LEFT JOIN case_memberships cm ON cm.case_id = c.id
        LEFT JOIN findings f ON f.id = cm.finding_id
        LEFT JOIN case_occurrences co ON co.case_id = c.id
        LEFT JOIN vt_lookups vt ON vt.sha256 = c.sha256 AND vt.lookup_profile = ?
        WHERE c.id = ?
        GROUP BY c.id, vt.summary_json, vt.result_status
        """,
        (lookup_profile, case_id),
    ).fetchone()
    if row is None:
        raise KeyError(f"Case {case_id} was not found")
    payload = dict(row)
    payload["rule_keys"] = {
        item for item in str(payload.get("rule_keys") or "").split(",") if item
    }
    payload["hosts"] = {
        item for item in str(payload.get("hosts") or "").split(",") if item
    }
    occurrence_rows = conn.execute(
        """
        SELECT DISTINCT
            fo.host,
            fo.artifact_path,
            fo.rule_key
        FROM case_memberships cm
        JOIN finding_occurrences fo ON fo.finding_id = cm.finding_id
        WHERE cm.case_id = ?
        """,
        (case_id,),
    ).fetchall()
    payload["occurrences"] = [dict(row) for row in occurrence_rows]
    if payload.get("vt_summary_json"):
        payload["vt_summary"] = json.loads(str(payload["vt_summary_json"]))
    else:
        payload["vt_summary"] = None
    return payload



def _iter_entries(config: Any) -> list[dict[str, Any]]:
    if not isinstance(config, list):
        return []
    entries: list[dict[str, Any]] = []
    for item in config:
        if isinstance(item, str):
            entries.append({"sha256": item})
        elif isinstance(item, dict):
            entries.append(dict(item))
    return entries



def _matches_rules(rule_filters: Any, matched_rules: set[str]) -> bool:
    if not rule_filters:
        return True
    if isinstance(rule_filters, str):
        return canonical_key(rule_filters) in matched_rules
    if isinstance(rule_filters, list):
        normalized = {canonical_key(str(item)) for item in rule_filters}
        return bool(normalized & matched_rules)
    return False



def _matches_hosts(host_regex: str | None, hosts: set[str]) -> bool:
    if not host_regex:
        return True
    if not hosts:
        return False
    pattern = re.compile(host_regex)
    return any(pattern.search(host) for host in hosts)


def _matches_occurrence_rule(rule_filters: Any, rule_key: str | None) -> bool:
    if not rule_filters:
        return True
    normalized_rule = canonical_key(str(rule_key or ""))
    if isinstance(rule_filters, str):
        return normalized_rule == canonical_key(rule_filters)
    if isinstance(rule_filters, list):
        return normalized_rule in {canonical_key(str(item)) for item in rule_filters}
    return False


def _matches_occurrence_host(host_regex: str | None, host: str | None) -> bool:
    if not host_regex:
        return True
    if not host:
        return False
    return re.search(host_regex, host) is not None



def _match_allowlist(case_row: dict[str, Any], triage_policy: dict[str, Any]) -> dict[str, Any] | None:
    allowlists = triage_policy.get("allowlists", {}) if isinstance(triage_policy, dict) else {}
    defaults = triage_policy.get("defaults", {}) if isinstance(triage_policy, dict) else {}
    expected_benign = str(defaults.get("expected_benign_disposition", DEFAULT_EXPECTED_BENIGN))

    for entry in _iter_entries(allowlists.get("sha256")):
        sha256 = str(entry.get("sha256") or "").lower()
        if sha256 and sha256 == str(case_row.get("sha256") or "").lower():
            return {
                "disposition": str(entry.get("disposition", expected_benign)),
                "reason": str(entry.get("reason") or entry.get("name") or "Matched local hash allowlist"),
                "policy_name": str(entry.get("name") or "hash-allowlist"),
                "severity": entry.get("severity"),
                "priority": entry.get("priority"),
            }

    for entry in _iter_entries(allowlists.get("path_rule_patterns")):
        path_regex = entry.get("path_regex")
        if not path_regex:
            continue
        pattern = re.compile(str(path_regex))
        for occurrence in case_row.get("occurrences", []):
            artifact_path = str(occurrence.get("artifact_path") or "")
            if not artifact_path:
                continue
            if not pattern.search(artifact_path):
                continue
            if not _matches_occurrence_rule(entry.get("rule_key"), occurrence.get("rule_key")):
                continue
            if not _matches_occurrence_host(entry.get("host_regex"), occurrence.get("host")):
                continue
            return {
                "disposition": str(entry.get("disposition", expected_benign)),
                "reason": str(entry.get("reason") or entry.get("name") or "Matched local path allowlist"),
                "policy_name": str(entry.get("name") or "path-rule-allowlist"),
                "severity": entry.get("severity"),
                "priority": entry.get("priority"),
            }
    return None



def _match_vt_followup(case_row: dict[str, Any], triage_policy: dict[str, Any]) -> dict[str, Any] | None:
    vt_config = triage_policy.get("vt", {}) if isinstance(triage_policy, dict) else {}
    defaults = triage_policy.get("defaults", {}) if isinstance(triage_policy, dict) else {}
    vt_summary = case_row.get("vt_summary")
    if case_row.get("vt_result_status") != "ok" or not isinstance(vt_summary, dict):
        return None
    malicious_threshold = int(vt_config.get("malicious_threshold", 1))
    suspicious_threshold = int(vt_config.get("suspicious_threshold", 1))
    malicious_count = int(vt_summary.get("malicious_count") or 0)
    suspicious_count = int(vt_summary.get("suspicious_count") or 0)
    if malicious_count >= malicious_threshold or suspicious_count >= suspicious_threshold:
        return {
            "disposition": str(defaults.get("vt_followup_disposition", DEFAULT_VT_FOLLOWUP)),
            "reason": f"VT signal: malicious={malicious_count}, suspicious={suspicious_count}",
            "policy_name": "vt-threshold",
            "severity": None,
            "priority": None,
        }
    return None



def apply_case_policy(
    conn,
    case_id: int,
    triage_policy: dict[str, Any],
    lookup_profile: str,
) -> None:
    case_row = _case_context(conn, case_id, lookup_profile)
    if str(case_row.get("disposition_source") or "") == "analyst":
        return

    allowlist_match = _match_allowlist(case_row, triage_policy)
    if allowlist_match is not None:
        set_case_state(
            conn,
            case_id,
            allowlist_match["disposition"],
            allowlist_match["reason"],
            "policy",
            allowlist_match["policy_name"],
            allowlist_match.get("severity"),
            allowlist_match.get("priority"),
        )
        return

    vt_match = _match_vt_followup(case_row, triage_policy)
    if vt_match is not None:
        set_case_state(
            conn,
            case_id,
            vt_match["disposition"],
            vt_match["reason"],
            "vt",
            vt_match["policy_name"],
            vt_match.get("severity"),
            vt_match.get("priority"),
        )
        return

    set_case_state(
        conn,
        case_id,
        "unreviewed",
        None,
        "default",
        None,
        str(case_row["observed_severity"]),
        str(case_row["observed_priority"]),
    )



def apply_policy_for_run(conn, run_id: str, triage_policy: dict[str, Any], lookup_profile: str) -> None:
    for case_id in case_ids_for_run(conn, run_id):
        apply_case_policy(conn, case_id, triage_policy, lookup_profile)



def apply_policy_for_sha(conn, sha256: str, triage_policy: dict[str, Any], lookup_profile: str) -> None:
    for case_id in case_ids_for_sha(conn, sha256):
        apply_case_policy(conn, case_id, triage_policy, lookup_profile)
