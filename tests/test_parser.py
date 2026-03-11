from __future__ import annotations

from pathlib import Path

from loki_triage.parser import parse_file_message, reconstruct_log


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_reconstruct_log_tracks_multiline_and_truncation() -> None:
    baseline = reconstruct_log(FIXTURES_DIR / "loki_ALPHA_2026-01-01_00-00-00.log")
    assert baseline["is_truncated_run"] is False
    assert baseline["continuation_line_count"] == 1
    assert baseline["logical_record_count"] == 5

    file_record = baseline["records"][1]
    assert file_record["source_line_start"] == 2
    assert file_record["source_line_end"] == 3
    assert "evil-string" in file_record["raw_event_text"]

    truncated = reconstruct_log(FIXTURES_DIR / "loki_BETA_2026-01-03_00-00-00.log")
    assert truncated["is_truncated_run"] is True
    assert truncated["logical_record_count"] == 4


def test_parse_file_message_handles_empty_reason_block() -> None:
    message = (
        "FILE: C:\\Temp\\odd.dll SCORE: 90 TYPE: DLL SIZE: 20 FIRST_BYTES: 4d5a "
        "MD5: 33333333333333333333333333333333 "
        "SHA1: 4444444444444444444444444444444444444444 "
        "SHA256: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc "
        "CREATED: Fri Jan  3 00:00:00 2026 MODIFIED: Fri Jan  3 00:00:00 2026 "
        "ACCESSED: Fri Jan  3 00:00:00 2026 REASON_1:"
    )
    payload = parse_file_message(message)
    assert payload["reasons"]
    assert payload["reasons"][0]["rule_key"] == "reason_1"
