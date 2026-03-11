from __future__ import annotations

from typing import Any

from .utils import canonical_key, normalize_message_for_fingerprint, sha256_bytes



def _priority_for_event(severity: str, event_kind: str | None, severity_rules: dict[str, Any]) -> str:
    overrides = severity_rules.get("process_event_overrides", {})
    if event_kind and event_kind in overrides:
        return str(overrides[event_kind])
    return str(severity_rules.get("priorities", {}).get(severity, "info"))



def _make_finding_key(rule_key: str, sha256: str | None, context_fingerprint: str | None) -> str:
    identity = {
        "rule_key": rule_key,
        "sha256": sha256,
        "context_fingerprint": context_fingerprint,
    }
    if sha256:
        identity["scope"] = "hash"
    else:
        identity["scope"] = "context"
    ordered = "|".join(f"{key}={identity[key] or ''}" for key in sorted(identity))
    return sha256_bytes(ordered.encode("utf-8"))



def _context_fingerprint_for_event(event: dict[str, Any]) -> str:
    payload = event.get("payload", {})
    event_kind = event.get("event_kind") or event["event_type"]
    if event["event_type"] == "init_error":
        raw = f"{payload.get('signature_file') or payload.get('target') or 'unknown'}|{payload.get('error_class') or 'unknown'}"
        return canonical_key(raw)
    if event["event_type"] == "process_event":
        base = payload.get("path") or payload.get("name") or payload.get("raw_summary") or "process"
        port_part = f"|{payload.get('port')}" if payload.get("port") else ""
        return canonical_key(f"{event_kind}|{base}{port_part}")
    payload_message = payload.get("message") or event["raw_event_text"]
    return canonical_key(normalize_message_for_fingerprint(payload_message))



def build_finding_candidates(event: dict[str, Any], severity_rules: dict[str, Any]) -> list[dict[str, Any]]:
    severity = event["severity"]
    queue_enabled = bool(severity_rules.get("default_queue", {}).get(severity, False))
    payload = event.get("payload", {})
    candidates: list[dict[str, Any]] = []
    if event["event_type"] == "file_finding":
        reasons = payload.get("reasons") or []
        fallback_rule = canonical_key(payload.get("file_type") or "file_signal")
        if not reasons:
            reasons = [{"rule_key": fallback_rule, "rule_or_pattern": fallback_rule, "subscore": payload.get("score")}]
        for reason in reasons:
            rule_key = canonical_key(reason.get("rule_key") or reason.get("rule_or_pattern") or fallback_rule)
            context_fingerprint = None if payload.get("sha256") else canonical_key(payload.get("file_path") or event["raw_event_text"])
            title = f"{reason.get('rule_or_pattern') or rule_key} on {payload.get('file_path') or 'unknown file'}"
            candidates.append(
                {
                    "finding_key": _make_finding_key(rule_key, payload.get("sha256"), context_fingerprint),
                    "rule_key": rule_key,
                    "entity_type": "file",
                    "context_fingerprint": context_fingerprint,
                    "sha256": payload.get("sha256"),
                    "md5": payload.get("md5"),
                    "title": title,
                    "severity": severity,
                    "priority": _priority_for_event(severity, event.get("event_kind"), severity_rules),
                    "queue_enabled": queue_enabled,
                    "artifact_path": payload.get("file_path"),
                    "score": payload.get("score") or reason.get("subscore"),
                    "occurrence_ts": event.get("event_ts"),
                    "host": event.get("host"),
                    "event_type": event["event_type"],
                    "event_kind": event.get("event_kind"),
                }
            )
        return candidates

    if event["event_type"] == "process_event":
        if event.get("event_kind") in {"process_scan_status", "process_message"}:
            return []
        rule_key = canonical_key(event.get("event_kind") or "process_event")
        context_fingerprint = _context_fingerprint_for_event(event)
        candidates.append(
            {
                "finding_key": _make_finding_key(rule_key, None, context_fingerprint),
                "rule_key": rule_key,
                "entity_type": "process",
                "context_fingerprint": context_fingerprint,
                "sha256": None,
                "md5": None,
                "title": payload.get("title") or payload.get("raw_summary") or "Process finding",
                "severity": severity,
                "priority": _priority_for_event(severity, event.get("event_kind"), severity_rules),
                "queue_enabled": queue_enabled,
                "artifact_path": payload.get("path"),
                "score": payload.get("patched") or payload.get("replaced"),
                "occurrence_ts": event.get("event_ts"),
                "host": event.get("host"),
                "event_type": event["event_type"],
                "event_kind": event.get("event_kind"),
            }
        )
        return candidates

    if event["event_type"] == "init_error":
        rule_key = canonical_key(payload.get("signature_file") or payload.get("error_class") or "init_error")
        context_fingerprint = _context_fingerprint_for_event(event)
        candidates.append(
            {
                "finding_key": _make_finding_key(rule_key, None, context_fingerprint),
                "rule_key": rule_key,
                "entity_type": "init_error",
                "context_fingerprint": context_fingerprint,
                "sha256": None,
                "md5": None,
                "title": payload.get("title") or "Init error",
                "severity": severity,
                "priority": _priority_for_event(severity, event.get("event_kind"), severity_rules),
                "queue_enabled": queue_enabled,
                "artifact_path": payload.get("target"),
                "score": None,
                "occurrence_ts": event.get("event_ts"),
                "host": event.get("host"),
                "event_type": event["event_type"],
                "event_kind": event.get("event_kind"),
            }
        )
        return candidates

    if event["event_type"] == "generic_event" and severity in {"ALERT", "WARNING", "ERROR"}:
        message = payload.get("message") or event["raw_event_text"]
        context_fingerprint = _context_fingerprint_for_event(event)
        rule_key = canonical_key(message[:80])
        candidates.append(
            {
                "finding_key": _make_finding_key(rule_key, None, context_fingerprint),
                "rule_key": rule_key,
                "entity_type": "generic",
                "context_fingerprint": context_fingerprint,
                "sha256": None,
                "md5": None,
                "title": message[:120],
                "severity": severity,
                "priority": _priority_for_event(severity, event.get("event_kind"), severity_rules),
                "queue_enabled": queue_enabled,
                "artifact_path": None,
                "score": None,
                "occurrence_ts": event.get("event_ts"),
                "host": event.get("host"),
                "event_type": event["event_type"],
                "event_kind": event.get("event_kind"),
            }
        )
    return candidates
