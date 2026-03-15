from __future__ import annotations

from collections.abc import Mapping
from typing import Any


ROUTED_POLICY_PREFIX = "route-"
SUPPRESSED_DISPOSITIONS = ("expected_benign", "false_positive")
VALID_CASE_BUCKETS = ("actionable", "routed", "suppressed", "all")


def normalize_case_bucket(bucket: str | None) -> str:
    value = str(bucket or "actionable").strip().lower()
    if value not in VALID_CASE_BUCKETS:
        choices = ", ".join(VALID_CASE_BUCKETS)
        raise ValueError(f"bucket must be one of: {choices}")
    return value


def is_routed_case(row: Mapping[str, Any]) -> bool:
    disposition_source = str(row.get("disposition_source") or "").lower()
    policy_name = str(row.get("policy_name") or "").lower()
    return disposition_source == "policy" and policy_name.startswith(ROUTED_POLICY_PREFIX)


def case_bucket_for_row(row: Mapping[str, Any]) -> str:
    if is_routed_case(row):
        return "routed"
    if str(row.get("current_disposition") or "").lower() in SUPPRESSED_DISPOSITIONS:
        return "suppressed"
    return "actionable"


def case_matches_bucket(row: Mapping[str, Any], bucket: str | None) -> bool:
    normalized = normalize_case_bucket(bucket)
    if normalized == "all":
        return True
    return case_bucket_for_row(row) == normalized


def case_bucket_sql(alias: str, bucket: str | None) -> tuple[str, list[Any]]:
    normalized = normalize_case_bucket(bucket)
    routed_sql = (
        f"LOWER(COALESCE({alias}.disposition_source, '')) = ? "
        f"AND LOWER(COALESCE({alias}.policy_name, '')) LIKE ?"
    )
    routed_params: list[Any] = ["policy", f"{ROUTED_POLICY_PREFIX}%"]
    if normalized == "all":
        return "1=1", []
    if normalized == "routed":
        return f"({routed_sql})", routed_params
    if normalized == "suppressed":
        return (
            f"{alias}.current_disposition IN (?, ?) AND NOT ({routed_sql})",
            [*SUPPRESSED_DISPOSITIONS, *routed_params],
        )
    return (
        f"{alias}.current_disposition NOT IN (?, ?) AND NOT ({routed_sql})",
        [*SUPPRESSED_DISPOSITIONS, *routed_params],
    )
