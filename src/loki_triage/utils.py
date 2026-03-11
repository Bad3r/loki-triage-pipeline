from __future__ import annotations

import csv
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Sequence


SEVERITY_ORDER = {
    "ALERT": 5,
    "WARNING": 4,
    "ERROR": 3,
    "NOTICE": 2,
    "RESULT": 1,
    "INFO": 0,
}

PRIORITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def compact_utc_now() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def json_dumps(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json_dumps(payload) + "\n", encoding="utf-8")


def append_jsonl(handle, payload: Any) -> None:
    handle.write(json_dumps(payload))
    handle.write("\n")


def write_csv(path: Path, rows: Sequence[dict[str, Any]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def slugify(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip())
    return value.strip("-").lower() or "value"


def canonical_key(value: str | None) -> str:
    if not value:
        return "unknown"
    normalized = value.strip().lower()
    normalized = re.sub(r"\s+", " ", normalized)
    normalized = re.sub(r"[^a-z0-9._:/\\ -]", "", normalized)
    return normalized[:500]


def normalize_message_for_fingerprint(message: str) -> str:
    normalized = message.lower()
    normalized = re.sub(r"\d{8}t\d{2}:\d{2}:\d{2}z", "<ts>", normalized)
    normalized = re.sub(r"\bpid:\s*\d+", "pid:<pid>", normalized)
    normalized = re.sub(r"\bport:\s*\d+", "port:<port>", normalized)
    normalized = re.sub(r"\b\d+\.\d+\.\d+\.\d+\b", "<ipv4>", normalized)
    normalized = re.sub(r"\b[0-9a-f:]{2,}\b", "<hex>", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized[:500]


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity.upper(), -1)


def higher_severity(left: str, right: str) -> str:
    return left if severity_rank(left) >= severity_rank(right) else right


def priority_rank(priority: str) -> int:
    return PRIORITY_ORDER.get(priority.lower(), 0)


def higher_priority(left: str, right: str) -> str:
    return left if priority_rank(left) >= priority_rank(right) else right


def to_bool(value: Any) -> bool:
    return bool(int(value)) if isinstance(value, (int, str)) and str(value).isdigit() else bool(value)


def relative_to(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def chunked(items: Sequence[Any], size: int) -> Iterable[Sequence[Any]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]


def format_table(rows: Sequence[dict[str, Any]], columns: Sequence[tuple[str, str]]) -> str:
    if not rows:
        return "(no rows)"
    widths: list[int] = []
    for key, header in columns:
        width = len(header)
        for row in rows:
            width = max(width, len(str(row.get(key, ""))))
        widths.append(width)
    header_line = "  ".join(header.ljust(widths[idx]) for idx, (_, header) in enumerate(columns))
    separator = "  ".join("-" * widths[idx] for idx in range(len(columns)))
    lines = [header_line, separator]
    for row in rows:
        lines.append(
            "  ".join(str(row.get(key, "")).ljust(widths[idx]) for idx, (key, _) in enumerate(columns))
        )
    return "\n".join(lines)
