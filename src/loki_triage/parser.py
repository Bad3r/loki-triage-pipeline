from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .utils import canonical_key


PREFIX_RE = re.compile(
    r"^(?P<event_ts>\d{8}T\d{2}:\d{2}:\d{2}Z),(?P<host>[^,]+),(?P<severity>INFO|NOTICE|WARNING|ALERT|ERROR|RESULT),(?P<module>[^,]+),(?P<message>.*)$",
    re.DOTALL,
)
LOG_NAME_RE = re.compile(
    r"^loki_(?P<host>.+)_(?P<date>\d{4}-\d{2}-\d{2})_(?P<time>\d{2}-\d{2}-\d{2})\.log$"
)
REASON_RE = re.compile(r"REASON_(\d+):")
RESULT_SUMMARY_RE = re.compile(r"Results: (?P<alerts>\d+) alerts, (?P<warnings>\d+) warnings, (?P<notices>\d+) notices")

FILE_FIELD_ANCHORS = [
    "FILE:",
    "SCORE:",
    "TYPE:",
    "SIZE:",
    "FIRST_BYTES:",
    "MD5:",
    "SHA1:",
    "SHA256:",
    "CREATED:",
    "MODIFIED:",
    "ACCESSED:",
]
REASON_FIELD_ANCHORS = [
    "MATCH:",
    "PATTERN:",
    "SUBSCORE:",
    "DESC:",
    "DESCRIPTION:",
    "REF:",
    "AUTHOR:",
    "MATCHES:",
]
PROCESS_FIELD_ANCHORS = [
    "PID:",
    "NAME:",
    "OWNER:",
    "CMD:",
    "COMMAND:",
    "PATH:",
    "IP:",
    "PORT:",
    "PATCHED:",
    "REPLACED:",
]
INIT_ERROR_RE = re.compile(r"Error (?:while initializing Yara rule|reading signature file) (?P<target>.+?) ERROR: (?P<error>.+)")



def parse_filename_metadata(path: Path) -> dict[str, Any]:
    match = LOG_NAME_RE.match(path.name)
    metadata: dict[str, Any] = {
        "host_from_filename": None,
        "filename_timestamp": None,
        "is_rescan": "Loki-Rescan" in path.parts,
    }
    if not match:
        return metadata
    metadata["host_from_filename"] = match.group("host")
    metadata["filename_timestamp"] = f"{match.group('date')}T{match.group('time').replace('-', ':')}Z"
    return metadata



def _has_control_bytes(raw_line: bytes) -> bool:
    return any(byte < 32 and byte not in (9, 10, 13) for byte in raw_line)



def _decode_line(raw_line: bytes) -> str:
    return raw_line.decode("utf-8", errors="replace").rstrip("\r")



def reconstruct_log(path: Path) -> dict[str, Any]:
    raw_bytes = path.read_bytes()
    raw_lines = raw_bytes.splitlines()
    file_parse_warnings: list[str] = []
    records: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    continuation_line_count = 0
    line_count = len(raw_lines)
    has_control_bytes = False
    for line_number, raw_line in enumerate(raw_lines, start=1):
        has_control = _has_control_bytes(raw_line)
        has_control_bytes = has_control_bytes or has_control
        text_line = _decode_line(raw_line)
        if PREFIX_RE.match(text_line):
            if current is not None:
                current["raw_event_text"] = "\n".join(current.pop("_raw_lines"))
                records.append(current)
            current = {
                "source_line_start": line_number,
                "source_line_end": line_number,
                "continuation_line_count": 0,
                "has_control_bytes": has_control,
                "parse_warnings": [],
                "_raw_lines": [text_line],
            }
            continue
        continuation_line_count += 1
        if current is None:
            file_parse_warnings.append(f"orphan-continuation-line:{line_number}")
            continue
        current["source_line_end"] = line_number
        current["continuation_line_count"] += 1
        current["has_control_bytes"] = current["has_control_bytes"] or has_control
        current["_raw_lines"].append(text_line)
    if current is not None:
        current["raw_event_text"] = "\n".join(current.pop("_raw_lines"))
        records.append(current)

    scan_started_at = None
    if records:
        header_match = PREFIX_RE.match(records[0]["raw_event_text"])
        if header_match:
            scan_started_at = header_match.group("event_ts")
    is_truncated_run = not any(
        "NOTICE,Results,Finished LOKI Scan" in record["raw_event_text"] for record in records
    )
    metadata = parse_filename_metadata(path)
    return {
        "records": records,
        "line_count": line_count,
        "logical_record_count": len(records),
        "continuation_line_count": continuation_line_count,
        "has_control_bytes": has_control_bytes,
        "is_truncated_run": is_truncated_run,
        "parse_warnings": file_parse_warnings,
        "scan_started_at": scan_started_at,
        **metadata,
    }



def _slice_anchors(text: str, anchors: list[str]) -> dict[str, str]:
    positions: list[tuple[int, str]] = []
    for anchor in anchors:
        index = text.find(anchor)
        if index != -1:
            positions.append((index, anchor))
    positions.sort(key=lambda item: item[0])
    values: dict[str, str] = {}
    for idx, (position, anchor) in enumerate(positions):
        start = position + len(anchor)
        end = positions[idx + 1][0] if idx + 1 < len(positions) else len(text)
        values[anchor.rstrip(":").lower()] = text[start:end].strip()
    return values



def _maybe_int(value: str | None) -> int | None:
    if value is None:
        return None
    digits = re.sub(r"[^0-9]", "", value)
    return int(digits) if digits else None



def parse_reason_block(index: int, raw_block: str) -> dict[str, Any]:
    block = raw_block.strip()
    fields = _slice_anchors(block, REASON_FIELD_ANCHORS)
    rule_or_pattern = fields.get("match") or fields.get("pattern")
    description = fields.get("description") or fields.get("desc")
    block_lines = block.splitlines()
    rule_source = rule_or_pattern or (block_lines[0][:120] if block_lines else f"reason_{index}")
    if block.startswith("Yara Rule"):
        match_type = "yara"
    elif "IOC" in block:
        match_type = "ioc"
    else:
        match_type = "generic"
    return {
        "reason_index": index,
        "match_type": match_type,
        "rule_or_pattern": rule_source,
        "rule_key": canonical_key(rule_source),
        "subscore": _maybe_int(fields.get("subscore")),
        "description": description,
        "ref": fields.get("ref"),
        "author": fields.get("author"),
        "matches_raw": fields.get("matches"),
        "raw": block,
    }



def parse_file_message(message: str) -> dict[str, Any]:
    first_reason = REASON_RE.search(message)
    metadata_text = message[: first_reason.start()] if first_reason else message
    fields = _slice_anchors(metadata_text, FILE_FIELD_ANCHORS)
    reasons: list[dict[str, Any]] = []
    if first_reason:
        matches = list(REASON_RE.finditer(message))
        for idx, match in enumerate(matches):
            start = match.end()
            end = matches[idx + 1].start() if idx + 1 < len(matches) else len(message)
            reasons.append(parse_reason_block(int(match.group(1)), message[start:end]))
    return {
        "file_path": fields.get("file"),
        "score": _maybe_int(fields.get("score")),
        "file_type": fields.get("type"),
        "size": _maybe_int(fields.get("size")),
        "first_bytes": fields.get("first_bytes"),
        "md5": fields.get("md5"),
        "sha1": fields.get("sha1"),
        "sha256": fields.get("sha256"),
        "created": fields.get("created"),
        "modified": fields.get("modified"),
        "accessed": fields.get("accessed"),
        "reasons": reasons,
    }



def parse_process_message(message: str) -> dict[str, Any]:
    fields = _slice_anchors(message, PROCESS_FIELD_ANCHORS)
    event_kind = "process_message"
    title = message[:120]
    if message.startswith("Listening process"):
        event_kind = "listening_process"
        title = f"Listening process {fields.get('name') or 'unknown'} on {fields.get('port') or 'unknown'}"
    elif "PE-Sieve reported patched process" in message:
        event_kind = "patched_process"
        title = f"Patched process {fields.get('name') or 'unknown'}"
    elif "PE-Sieve reported replaced process" in message:
        event_kind = "replaced_process"
        title = f"Replaced process {fields.get('name') or 'unknown'}"
    elif "priority is not" in message:
        event_kind = "priority_anomaly"
        title = f"Priority anomaly for {fields.get('name') or 'unknown'}"
    elif "PE-Sieve reported" in message:
        event_kind = "generic_process_alert"
        title = message.split(" PID:", 1)[0]
    elif message.startswith("Scanning Process") or message.startswith("Skipping Process"):
        event_kind = "process_scan_status"
    return {
        "event_kind": event_kind,
        "title": title,
        "pid": _maybe_int(fields.get("pid")),
        "name": fields.get("name"),
        "owner": fields.get("owner"),
        "cmd": fields.get("cmd") or fields.get("command"),
        "path": fields.get("path"),
        "ip": fields.get("ip"),
        "port": _maybe_int(fields.get("port")),
        "patched": _maybe_int(fields.get("patched")),
        "replaced": _maybe_int(fields.get("replaced")),
        "raw_summary": message[:160],
    }



def parse_init_error(message: str) -> dict[str, Any]:
    match = INIT_ERROR_RE.search(message)
    target = None
    error_text = message
    error_class = "init_error"
    if match:
        target = match.group("target").strip("'")
        error_text = match.group("error")
    if "null character" in error_text.lower():
        error_class = "embedded_null_character"
    elif "invalid argument" in error_text.lower():
        error_class = "invalid_argument"
    return {
        "target": target,
        "signature_file": Path(target).name if target else None,
        "error_text": error_text,
        "error_class": error_class,
        "title": f"Init error loading {Path(target).name if target else 'signature'}",
    }



def parse_results_message(message: str) -> dict[str, Any]:
    match = RESULT_SUMMARY_RE.search(message)
    if not match:
        return {"summary_text": message}
    return {
        "alerts": int(match.group("alerts")),
        "warnings": int(match.group("warnings")),
        "notices": int(match.group("notices")),
        "summary_text": message,
    }



def normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    match = PREFIX_RE.match(record["raw_event_text"])
    if not match:
        raise ValueError(f"Logical record does not match Loki prefix: {record['raw_event_text'][:80]}")
    event = {
        "event_ts": match.group("event_ts"),
        "host": match.group("host"),
        "severity": match.group("severity"),
        "module": match.group("module"),
        "source_line_start": record["source_line_start"],
        "source_line_end": record["source_line_end"],
        "raw_event_text": record["raw_event_text"],
        "parse_warnings": list(record.get("parse_warnings", [])),
        "payload": {"message": match.group("message")},
        "event_type": "generic_event",
        "event_kind": None,
    }
    if record.get("continuation_line_count"):
        event["parse_warnings"].append(f"continuation-lines:{record['continuation_line_count']}")
    if record.get("has_control_bytes"):
        event["parse_warnings"].append("contains-control-bytes")

    message = match.group("message")
    module = event["module"]
    severity = event["severity"]
    if module == "FileScan" and message.startswith("FILE:"):
        event["event_type"] = "file_finding"
        event["event_kind"] = "file_signal"
        event["payload"] = parse_file_message(message)
    elif module == "ProcessScan":
        payload = parse_process_message(message)
        event["event_type"] = "process_event"
        event["event_kind"] = payload.get("event_kind")
        event["payload"] = payload
    elif module == "Init" and severity == "ERROR":
        event["event_type"] = "init_error"
        event["event_kind"] = "signature_load_error"
        event["payload"] = parse_init_error(message)
    elif module == "Results":
        if message.startswith("Results:"):
            event["event_type"] = "results_summary"
            event["event_kind"] = "results_summary"
        else:
            event["event_type"] = "results_advisory"
            event["event_kind"] = "results_advisory"
        event["payload"] = parse_results_message(message)
    return event
