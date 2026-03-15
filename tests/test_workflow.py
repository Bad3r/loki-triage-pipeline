from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import subprocess
from pathlib import Path

import pytest
import yaml

from loki_triage.db import connect, ensure_schema, upsert_vt_lookup
from loki_triage.ingest import ingest_logs
from loki_triage.policy import apply_policy_for_sha
from loki_triage.reporting import build_report
from loki_triage.review import queue, set_case_verdict, show_case
from loki_triage.vt import enrich_hashes


MULTI_REASON_LOG = """20260105T00:00:00Z,ALPHA,NOTICE,Init,Starting Loki Scan VERSION: 0.51.0 SYSTEM: ALPHA TIME: 20260105T00:00:00Z
20260105T00:00:01Z,ALPHA,ALERT,FileScan,FILE: C:\\Windows\\System32\\RemComSvc.exe SCORE: 195 TYPE: EXE SIZE: 49664 FIRST_BYTES: 4d5a MD5: 3c34e0479aa237fa6051f856b60b4bd8 SHA1: 5982c49d8ce53e6f3808c6714641334d2085bddb SHA256: f7e69ee120fe298c4e5df34a94d17403e17ac317f66c0b0195dbaf3218b27395 CREATED: Sun Sep 11 15:09:48 2022 MODIFIED: Sun Sep 11 15:09:51 2022 ACCESSED: Sun Jan 25 11:03:05 2026 REASON_1: Yara Rule MATCH: RemCom_RemoteCommandExecution SUBSCORE: 50 DESCRIPTION: Detects strings from RemCom tool REF: https://example.invalid AUTHOR: tester MATCHES: $: '\\\\.\\pipe\\%s%s%d'REASON_2: Yara Rule MATCH: ID_83692 SUBSCORE: 75 DESCRIPTION: Detects Remcom remote access software REF: - AUTHOR: - MATCHES: $s1: 'RemComSvc'
20260105T00:00:02Z,ALPHA,NOTICE,Results,Results: 1 alerts, 0 warnings, 0 notices
20260105T00:00:03Z,ALPHA,NOTICE,Results,Finished LOKI Scan
"""



def _write_single_file_finding_log(
    log_path: Path,
    *,
    host: str,
    artifact_path: str,
    sha256: str,
    rule_key: str,
    severity: str = "ALERT",
    md5: str = "11111111111111111111111111111111",
    sha1: str = "2222222222222222222222222222222222222222",
    score: int = 150,
) -> Path:
    payload = f"""20260105T00:00:00Z,{host},NOTICE,Init,Starting Loki Scan VERSION: 0.51.0 SYSTEM: {host} TIME: 20260105T00:00:00Z
20260105T00:00:01Z,{host},{severity},FileScan,FILE: {artifact_path} SCORE: {score} TYPE: EXE SIZE: 10 FIRST_BYTES: 4d5a MD5: {md5} SHA1: {sha1} SHA256: {sha256} CREATED: Wed Jan  1 00:00:00 2026 MODIFIED: Wed Jan  1 00:00:00 2026 ACCESSED: Wed Jan  1 00:00:00 2026 REASON_1: Yara Rule MATCH: {rule_key} SUBSCORE: 70 DESCRIPTION: test hit REF: https://example.invalid AUTHOR: tester MATCHES:
  $a: 'test'
20260105T00:00:02Z,{host},NOTICE,Results,Results: 1 alerts, 0 warnings, 0 notices
20260105T00:00:03Z,{host},NOTICE,Results,Finished LOKI Scan
"""
    log_path.write_text(payload, encoding="utf-8")
    return log_path



def _write_vt_config(
    project_root: Path,
    *,
    profile: str = "public_safe",
    daily_request_limit: int = 1000,
    eligible_severities: list[str] | None = None,
    eligible_dispositions: list[str] | None = None,
    batch_size: int = 4,
    sleep_seconds: int = 0,
) -> None:
    config_path = project_root / "config" / "vt_config.yaml"
    payload = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    payload["profile"] = profile
    payload["daily_request_limit"] = daily_request_limit
    if eligible_severities is not None:
        payload["eligible_severities"] = eligible_severities
    if eligible_dispositions is not None:
        payload["eligible_dispositions"] = eligible_dispositions
    profiles = payload.setdefault("profiles", {})
    active_profile = dict(profiles.get(profile, {}))
    active_profile["batch_size"] = batch_size
    active_profile["sleep_seconds"] = sleep_seconds
    profiles[profile] = active_profile
    config_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")



def _insert_vt_lookup(
    conn,
    *,
    sha256: str,
    profile: str,
    lookup_ts: str,
    result_status: str = "ok",
) -> None:
    upsert_vt_lookup(
        conn,
        sha256,
        profile,
        result_status,
        {},
        {"seeded": True},
        "seeded lookup" if result_status == "error" else None,
    )
    conn.execute(
        "UPDATE vt_lookups SET lookup_ts = ? WHERE sha256 = ? AND lookup_profile = ?",
        (lookup_ts, sha256, profile),
    )



def test_ingest_reuses_findings_and_marks_persisting(project_root: Path, copy_fixture_log) -> None:
    baseline_log = copy_fixture_log("loki_ALPHA_2026-01-01_00-00-00.log")
    result_one = ingest_logs([baseline_log], period="2026-01", run_kind="baseline", project_root=project_root)
    assert result_one["reused"] is False

    rescan_log = copy_fixture_log("loki_ALPHA_2026-02-01_00-00-00.log", rescan=True)
    result_two = ingest_logs([rescan_log], period="2026-02", run_kind="rescan", project_root=project_root)
    assert result_two["reused"] is False

    conn = connect(project_root / "state" / "triage.db")
    ensure_schema(conn)
    try:
        findings_for_hash = conn.execute(
            "SELECT COUNT(*) AS count FROM findings WHERE sha256 = ?",
            ("a" * 64,),
        ).fetchone()
        assert findings_for_hash["count"] == 1

        cases_for_hash = conn.execute(
            "SELECT COUNT(*) AS count FROM cases WHERE sha256 = ?",
            ("a" * 64,),
        ).fetchone()
        assert cases_for_hash["count"] == 1

        second_run_rows = conn.execute(
            """
            SELECT event_type, event_kind, state_for_host_run
            FROM case_occurrences
            WHERE run_id = ?
            ORDER BY id
            """,
            (result_two["run_id"],),
        ).fetchall()
    finally:
        conn.close()

    states = {(row["event_type"], row["event_kind"], row["state_for_host_run"]) for row in second_run_rows}
    assert ("file_finding", "file_signal", "persisting") in states
    assert ("process_event", "patched_process", "new") in states



def test_multi_reason_file_finding_collapses_to_one_case(project_root: Path) -> None:
    log_path = project_root / "LokiScanResults" / "loki_ALPHA_2026-01-05_00-00-00.log"
    log_path.write_text(MULTI_REASON_LOG, encoding="utf-8")

    ingest_logs([log_path], period="2026-01", run_kind="baseline", project_root=project_root)

    conn = connect(project_root / "state" / "triage.db")
    ensure_schema(conn)
    try:
        finding_count = conn.execute(
            "SELECT COUNT(*) AS count FROM findings WHERE sha256 = ?",
            ("f7e69ee120fe298c4e5df34a94d17403e17ac317f66c0b0195dbaf3218b27395",),
        ).fetchone()
        case_count = conn.execute(
            "SELECT COUNT(*) AS count FROM cases WHERE sha256 = ?",
            ("f7e69ee120fe298c4e5df34a94d17403e17ac317f66c0b0195dbaf3218b27395",),
        ).fetchone()
        membership_count = conn.execute(
            "SELECT COUNT(*) AS count FROM case_memberships cm JOIN cases c ON c.id = cm.case_id WHERE c.sha256 = ?",
            ("f7e69ee120fe298c4e5df34a94d17403e17ac317f66c0b0195dbaf3218b27395",),
        ).fetchone()
    finally:
        conn.close()

    assert finding_count["count"] == 2
    assert case_count["count"] == 1
    assert membership_count["count"] == 2

    queued = queue(project_root=project_root)
    assert queued[0]["matched_rules"] == "remcom_remotecommandexecution,id_83692" or queued[0]["matched_rules"] == "id_83692,remcom_remotecommandexecution"



def test_default_policy_allowlists_remcom_default_paths(project_root: Path) -> None:
    log_path = project_root / "LokiScanResults" / "loki_ALPHA_2026-01-05_00-00-00.log"
    log_path.write_text(MULTI_REASON_LOG, encoding="utf-8")

    ingest_logs([log_path], period="2026-01", run_kind="baseline", project_root=project_root)

    queued = queue(project_root=project_root)
    remcom_row = next(row for row in queued if row["title"] == "C:\\Windows\\System32\\RemComSvc.exe")
    assert remcom_row["current_disposition"] == "expected_benign"

    payload = show_case(remcom_row["case_id"], project_root=project_root)
    assert payload["case"]["current_reason"] == "Approved RemCom service in the default Windows service path"



def test_default_policy_allowlists_xtu_known_filenames_only(project_root: Path) -> None:
    approved_log = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_ALPHA_2026-01-06_00-00-00.log",
        host="ALPHA",
        artifact_path="C:\\Windows\\System32\\DriverStore\\FileRepository\\xtucomponent.inf_amd64_deadbeefdeadbeef\\XtuService.exe",
        sha256="3" * 64,
        rule_key="ID_144731",
    )
    unapproved_log = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_ALPHA_2026-01-07_00-00-00.log",
        host="ALPHA",
        artifact_path="C:\\Windows\\System32\\DriverStore\\FileRepository\\xtucomponent.inf_amd64_deadbeefdeadbeef\\Unexpected.dll",
        sha256="4" * 64,
        rule_key="ID_144731",
    )

    ingest_logs([approved_log, unapproved_log], period="2026-01", run_kind="baseline", project_root=project_root)

    queued = queue(project_root=project_root)
    dispositions = {row["title"]: row["current_disposition"] for row in queued}
    assert dispositions["C:\\Windows\\System32\\DriverStore\\FileRepository\\xtucomponent.inf_amd64_deadbeefdeadbeef\\XtuService.exe"] == "expected_benign"
    assert dispositions["C:\\Windows\\System32\\DriverStore\\FileRepository\\xtucomponent.inf_amd64_deadbeefdeadbeef\\Unexpected.dll"] == "unreviewed"



def test_policy_allowlist_marks_case_expected_benign(project_root: Path, copy_fixture_log) -> None:
    policy_path = project_root / "config" / "triage_policy.yaml"
    policy_path.write_text(
        """
defaults:
  expected_benign_disposition: expected_benign
  vt_followup_disposition: needs_followup
allowlists:
  sha256: []
  path_rule_patterns:
    - name: approved-evil-sample
      rule_key: suspiciousbinary
      path_regex: '(?i)^c:\\\\temp\\\\evil\\.exe$'
      reason: Approved lab sample
vt:
  malicious_threshold: 1
  suspicious_threshold: 1
""".strip()
        + "\n",
        encoding="utf-8",
    )

    baseline_log = copy_fixture_log("loki_ALPHA_2026-01-01_00-00-00.log")
    ingest_logs([baseline_log], period="2026-01", run_kind="baseline", project_root=project_root)

    queued = queue(project_root=project_root)
    assert queued[0]["current_disposition"] == "expected_benign"

    payload = show_case(queued[0]["case_id"], project_root=project_root)
    assert payload["case"]["current_disposition"] == "expected_benign"
    assert payload["case"]["current_reason"] == "Approved lab sample"



def test_enrich_vt_marks_omitted_batch_hashes_as_not_found(project_root: Path, monkeypatch) -> None:
    alpha_log = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_ALPHA_2026-01-08_00-00-00.log",
        host="ALPHA",
        artifact_path="C:\\Temp\\alpha.exe",
        sha256="a" * 64,
        rule_key="SuspiciousBinary",
    )
    beta_log = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_BETA_2026-01-08_00-00-00.log",
        host="BETA",
        artifact_path="C:\\Temp\\beta.exe",
        sha256="b" * 64,
        rule_key="SuspiciousBinary",
    )
    run = ingest_logs([alpha_log, beta_log], period="2026-01", run_kind="baseline", project_root=project_root)

    def fake_run(command, capture_output, text, check):
        assert command[:4] == ["vt", "--format", "json", "file"]
        assert ("a" * 64) in command and ("b" * 64) in command
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=json.dumps([{"_id": "a" * 64, "last_analysis_stats": {"malicious": 1, "suspicious": 0}}]),
            stderr="",
        )

    monkeypatch.setattr("loki_triage.vt.subprocess.run", fake_run)

    result = enrich_hashes(run["run_id"], project_root=project_root)

    conn = connect(project_root / "state" / "triage.db")
    ensure_schema(conn)
    try:
        rows = conn.execute("SELECT sha256, result_status FROM vt_lookups ORDER BY sha256 ASC").fetchall()
    finally:
        conn.close()

    assert result["status_counts"] == {"ok": 1, "not_found": 1, "error": 0}
    assert [dict(row) for row in rows] == [
        {"sha256": "a" * 64, "result_status": "ok"},
        {"sha256": "b" * 64, "result_status": "not_found"},
    ]



def test_enrich_vt_marks_plain_text_no_hits_as_not_found(project_root: Path, monkeypatch) -> None:
    gamma_log = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_GAMMA_2026-01-09_00-00-00.log",
        host="GAMMA",
        artifact_path="C:\\Temp\\gamma.exe",
        sha256="c" * 64,
        rule_key="SuspiciousBinary",
    )
    delta_log = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_DELTA_2026-01-09_00-00-00.log",
        host="DELTA",
        artifact_path="C:\\Temp\\delta.exe",
        sha256="d" * 64,
        rule_key="SuspiciousBinary",
    )
    run = ingest_logs([gamma_log, delta_log], period="2026-01", run_kind="baseline", project_root=project_root)

    def fake_run(command, capture_output, text, check):
        assert ("c" * 64) in command and ("d" * 64) in command
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=f'File "{"c" * 64}" not found\nFile "{"d" * 64}" not found\n',
            stderr="",
        )

    monkeypatch.setattr("loki_triage.vt.subprocess.run", fake_run)

    result = enrich_hashes(run["run_id"], project_root=project_root)

    conn = connect(project_root / "state" / "triage.db")
    ensure_schema(conn)
    try:
        rows = conn.execute("SELECT sha256, result_status FROM vt_lookups ORDER BY sha256 ASC").fetchall()
    finally:
        conn.close()

    assert result["status_counts"] == {"ok": 0, "not_found": 2, "error": 0}
    assert [dict(row) for row in rows] == [
        {"sha256": "c" * 64, "result_status": "not_found"},
        {"sha256": "d" * 64, "result_status": "not_found"},
    ]



def test_enrich_vt_includes_notice_but_skips_info(project_root: Path, monkeypatch) -> None:
    info_log = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_INFOHOST_2026-01-10_00-00-00.log",
        host="INFOHOST",
        artifact_path=r"C:\Temp\info.exe",
        sha256="e" * 64,
        rule_key="SuspiciousBinary",
        severity="INFO",
    )
    notice_log = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_NOTICEHOST_2026-01-10_00-00-00.log",
        host="NOTICEHOST",
        artifact_path=r"C:\Temp\notice.exe",
        sha256="f" * 64,
        rule_key="SuspiciousBinary",
        severity="NOTICE",
    )
    run = ingest_logs([info_log, notice_log], period="2026-01", run_kind="baseline", project_root=project_root)

    def fake_run(command, capture_output, text, check):
        assert ("f" * 64) in command
        assert ("e" * 64) not in command
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=json.dumps([{"_id": "f" * 64, "last_analysis_stats": {"malicious": 1, "suspicious": 0}}]),
            stderr="",
        )

    monkeypatch.setattr("loki_triage.vt.subprocess.run", fake_run)

    result = enrich_hashes(run["run_id"], project_root=project_root)

    conn = connect(project_root / "state" / "triage.db")
    ensure_schema(conn)
    try:
        rows = conn.execute("SELECT sha256, result_status FROM vt_lookups ORDER BY sha256 ASC").fetchall()
    finally:
        conn.close()

    assert result["status_counts"] == {"ok": 1, "not_found": 0, "error": 0}
    assert [dict(row) for row in rows] == [{"sha256": "f" * 64, "result_status": "ok"}]



def test_enrich_vt_stops_when_utc_daily_budget_exhausted(project_root: Path, monkeypatch) -> None:
    _write_vt_config(project_root, daily_request_limit=1, batch_size=1, sleep_seconds=0)
    log_path = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_ALPHA_2026-01-11_00-00-00.log",
        host="ALPHA",
        artifact_path=r"C:\Temp\budget.exe",
        sha256="1" * 64,
        rule_key="SuspiciousBinary",
    )
    run = ingest_logs([log_path], period="2026-01", run_kind="baseline", project_root=project_root)

    conn = connect(project_root / "state" / "triage.db")
    ensure_schema(conn)
    try:
        _insert_vt_lookup(
            conn,
            sha256="f" * 64,
            profile="public_safe",
            lookup_ts=datetime.now(UTC).strftime("%Y-%m-%dT12:00:00Z"),
            result_status="not_found",
        )
        conn.commit()
    finally:
        conn.close()

    def fake_run(command, capture_output, text, check):
        raise AssertionError("VT should not be invoked when the UTC daily budget is exhausted")

    monkeypatch.setattr("loki_triage.vt.subprocess.run", fake_run)

    result = enrich_hashes(run["run_id"], project_root=project_root)

    assert result["processed"] == 0
    assert result["candidate_count"] == 1
    assert result["selected_count"] == 0
    assert result["deferred_count"] == 1
    assert result["used_today"] == 1
    assert result["remaining_budget"] == 0
    assert "budget exhausted" in result["summary"]



def test_enrich_vt_budget_is_scoped_to_active_profile(project_root: Path, monkeypatch) -> None:
    _write_vt_config(project_root, daily_request_limit=1, batch_size=1, sleep_seconds=0)
    log_path = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_ALPHA_2026-01-12_00-00-00.log",
        host="ALPHA",
        artifact_path=r"C:\Temp\profile-scope.exe",
        sha256="2" * 64,
        rule_key="SuspiciousBinary",
    )
    run = ingest_logs([log_path], period="2026-01", run_kind="baseline", project_root=project_root)

    conn = connect(project_root / "state" / "triage.db")
    ensure_schema(conn)
    try:
        _insert_vt_lookup(
            conn,
            sha256="e" * 64,
            profile="private_fast",
            lookup_ts=datetime.now(UTC).strftime("%Y-%m-%dT12:30:00Z"),
        )
        conn.commit()
    finally:
        conn.close()

    def fake_run(command, capture_output, text, check):
        assert ("2" * 64) in command
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=json.dumps([{"_id": "2" * 64, "last_analysis_stats": {"malicious": 1, "suspicious": 0}}]),
            stderr="",
        )

    monkeypatch.setattr("loki_triage.vt.subprocess.run", fake_run)

    result = enrich_hashes(run["run_id"], project_root=project_root)

    assert result["processed"] == 1
    assert result["used_today"] == 0
    assert result["selected_count"] == 1
    assert result["remaining_budget"] == 0



def test_enrich_vt_utc_day_window_ignores_yesterday_rows(project_root: Path, monkeypatch) -> None:
    _write_vt_config(project_root, daily_request_limit=1, batch_size=1, sleep_seconds=0)
    log_path = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_ALPHA_2026-01-13_00-00-00.log",
        host="ALPHA",
        artifact_path=r"C:\Temp\utc-window.exe",
        sha256="3" * 64,
        rule_key="SuspiciousBinary",
    )
    run = ingest_logs([log_path], period="2026-01", run_kind="baseline", project_root=project_root)

    conn = connect(project_root / "state" / "triage.db")
    ensure_schema(conn)
    try:
        _insert_vt_lookup(
            conn,
            sha256="d" * 64,
            profile="public_safe",
            lookup_ts=(datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%dT23:59:59Z"),
        )
        conn.commit()
    finally:
        conn.close()

    def fake_run(command, capture_output, text, check):
        assert ("3" * 64) in command
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=json.dumps([{"_id": "3" * 64, "last_analysis_stats": {"malicious": 1, "suspicious": 0}}]),
            stderr="",
        )

    monkeypatch.setattr("loki_triage.vt.subprocess.run", fake_run)

    result = enrich_hashes(run["run_id"], project_root=project_root)

    assert result["processed"] == 1
    assert result["used_today"] == 0
    assert result["selected_count"] == 1



def test_enrich_vt_skips_reviewed_benign_dispositions_by_default(project_root: Path, monkeypatch) -> None:
    _write_vt_config(project_root, daily_request_limit=5, batch_size=5, sleep_seconds=0)
    approved_log = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_ALPHA_2026-01-14_00-00-00.log",
        host="ALPHA",
        artifact_path=r"C:\Windows\System32\RemComSvc.exe",
        sha256="4" * 64,
        rule_key="RemCom_RemoteCommandExecution",
    )
    reviewed_log = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_BETA_2026-01-14_00-00-00.log",
        host="BETA",
        artifact_path=r"C:\Temp\reviewed.exe",
        sha256="5" * 64,
        rule_key="SuspiciousBinary",
    )
    active_log = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_GAMMA_2026-01-14_00-00-00.log",
        host="GAMMA",
        artifact_path=r"C:\Temp\active.exe",
        sha256="6" * 64,
        rule_key="SuspiciousBinary",
    )
    run = ingest_logs([approved_log, reviewed_log, active_log], period="2026-01", run_kind="baseline", project_root=project_root)

    reviewed_case = next(row for row in queue(project_root=project_root) if row["title"] == r"C:\Temp\reviewed.exe")
    set_case_verdict(
        reviewed_case["case_id"],
        disposition="false_positive",
        reason="Known benign installer",
        analyst="pytest",
        run_id=run["run_id"],
        project_root=project_root,
    )

    def fake_run(command, capture_output, text, check):
        assert ("6" * 64) in command
        assert ("4" * 64) not in command
        assert ("5" * 64) not in command
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=json.dumps([{"_id": "6" * 64, "last_analysis_stats": {"malicious": 1, "suspicious": 0}}]),
            stderr="",
        )

    monkeypatch.setattr("loki_triage.vt.subprocess.run", fake_run)

    result = enrich_hashes(run["run_id"], project_root=project_root)

    assert result["candidate_count"] == 1
    assert result["selected_count"] == 1
    assert result["processed"] == 1



def test_enrich_vt_prioritizes_alert_over_warning_under_quota(project_root: Path, monkeypatch) -> None:
    _write_vt_config(project_root, daily_request_limit=1, batch_size=1, sleep_seconds=0, eligible_dispositions=["unreviewed"])
    warning_log = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_ALPHA_2026-01-15_00-00-00.log",
        host="ALPHA",
        artifact_path=r"C:\Temp\warning.exe",
        sha256="0" * 64,
        rule_key="SuspiciousBinary",
        severity="WARNING",
        score=400,
    )
    alert_log = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_BETA_2026-01-15_00-00-00.log",
        host="BETA",
        artifact_path=r"C:\Temp\alert.exe",
        sha256="f" * 64,
        rule_key="SuspiciousBinary",
        severity="ALERT",
        score=200,
    )
    run = ingest_logs([warning_log, alert_log], period="2026-01", run_kind="baseline", project_root=project_root)

    def fake_run(command, capture_output, text, check):
        assert ("f" * 64) in command
        assert ("0" * 64) not in command
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=json.dumps([{"_id": "f" * 64, "last_analysis_stats": {"malicious": 1, "suspicious": 0}}]),
            stderr="",
        )

    monkeypatch.setattr("loki_triage.vt.subprocess.run", fake_run)

    result = enrich_hashes(run["run_id"], project_root=project_root)

    assert result["selected_count"] == 1
    assert result["processed"] == 1



def test_enrich_vt_prefers_higher_score_within_same_severity_under_quota(project_root: Path, monkeypatch) -> None:
    _write_vt_config(project_root, daily_request_limit=1, batch_size=1, sleep_seconds=0, eligible_dispositions=["unreviewed"])
    lower_score_log = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_ALPHA_2026-01-16_00-00-00.log",
        host="ALPHA",
        artifact_path=r"C:\Temp\lower-score.exe",
        sha256="0" * 64,
        rule_key="SuspiciousBinary",
        severity="ALERT",
        score=100,
    )
    higher_score_log = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_BETA_2026-01-16_00-00-00.log",
        host="BETA",
        artifact_path=r"C:\Temp\higher-score.exe",
        sha256="f" * 64,
        rule_key="SuspiciousBinary",
        severity="ALERT",
        score=900,
    )
    run = ingest_logs([lower_score_log, higher_score_log], period="2026-01", run_kind="baseline", project_root=project_root)

    def fake_run(command, capture_output, text, check):
        assert ("f" * 64) in command
        assert ("0" * 64) not in command
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=json.dumps([{"_id": "f" * 64, "last_analysis_stats": {"malicious": 1, "suspicious": 0}}]),
            stderr="",
        )

    monkeypatch.setattr("loki_triage.vt.subprocess.run", fake_run)

    result = enrich_hashes(run["run_id"], project_root=project_root)

    assert result["selected_count"] == 1
    assert result["processed"] == 1



def test_vt_signal_marks_case_needs_followup(project_root: Path, copy_fixture_log) -> None:
    baseline_log = copy_fixture_log("loki_ALPHA_2026-01-01_00-00-00.log")
    ingest_logs([baseline_log], period="2026-01", run_kind="baseline", project_root=project_root)

    conn = connect(project_root / "state" / "triage.db")
    ensure_schema(conn)
    try:
        upsert_vt_lookup(
            conn,
            "a" * 64,
            "public_safe",
            "ok",
            {"malicious_count": 3, "suspicious_count": 0},
            {"data": []},
        )
        apply_policy_for_sha(conn, "a" * 64, {"defaults": {"vt_followup_disposition": "needs_followup"}, "vt": {"malicious_threshold": 1, "suspicious_threshold": 1}}, "public_safe")
        conn.commit()
        case_row = conn.execute("SELECT current_disposition, current_reason FROM cases WHERE sha256 = ?", (("a" * 64),)).fetchone()
    finally:
        conn.close()

    assert case_row["current_disposition"] == "needs_followup"
    assert "malicious=3" in case_row["current_reason"]



def test_enrich_vt_batches_mixed_hits_and_no_hits(project_root: Path, copy_fixture_log, monkeypatch) -> None:
    baseline_log = copy_fixture_log("loki_ALPHA_2026-01-01_00-00-00.log")
    second_log = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_BETA_2026-01-05_00-00-00.log",
        host="BETA",
        artifact_path=r"C:\Temp\other.exe",
        sha256="b" * 64,
        rule_key="SuspiciousBinary",
        md5="33333333333333333333333333333333",
        sha1="4444444444444444444444444444444444444444",
    )
    result = ingest_logs([baseline_log, second_log], period="2026-01", run_kind="baseline", project_root=project_root)

    def fake_run(command, capture_output, text, check):
        requested = {part for part in command if len(part) == 64}
        assert {"a" * 64, "b" * 64} <= requested
        payload = [
            {
                "_id": "a" * 64,
                "attributes": {
                    "last_analysis_stats": {"malicious": 2, "suspicious": 0},
                    "meaningful_name": "evil.exe",
                },
            }
        ]
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr("loki_triage.vt.subprocess.run", fake_run)
    vt_result = enrich_hashes(result["run_id"], project_root=project_root)
    assert vt_result["status_counts"] == {"ok": 1, "not_found": 1, "error": 0}

    conn = connect(project_root / "state" / "triage.db")
    try:
        rows = {
            row["sha256"]: row["result_status"]
            for row in conn.execute("SELECT sha256, result_status FROM vt_lookups ORDER BY sha256 ASC")
        }
    finally:
        conn.close()

    assert rows == {"a" * 64: "ok", "b" * 64: "not_found"}


def test_enrich_vt_marks_plain_text_no_hits(project_root: Path, copy_fixture_log, monkeypatch) -> None:
    baseline_log = copy_fixture_log("loki_ALPHA_2026-01-01_00-00-00.log")
    second_log = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_BETA_2026-01-05_00-00-00.log",
        host="BETA",
        artifact_path=r"C:\Temp\other.exe",
        sha256="b" * 64,
        rule_key="SuspiciousBinary",
        md5="33333333333333333333333333333333",
        sha1="4444444444444444444444444444444444444444",
    )
    result = ingest_logs([baseline_log, second_log], period="2026-01", run_kind="baseline", project_root=project_root)

    def fake_run(command, capture_output, text, check):
        stdout = '\n'.join(
            [
                f'File "{"a" * 64}" not found',
                f'File "{"b" * 64}" not found',
            ]
        )
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr("loki_triage.vt.subprocess.run", fake_run)
    vt_result = enrich_hashes(result["run_id"], project_root=project_root)
    assert vt_result["status_counts"] == {"ok": 0, "not_found": 2, "error": 0}

    conn = connect(project_root / "state" / "triage.db")
    try:
        statuses = {
            row["sha256"]: row["result_status"]
            for row in conn.execute("SELECT sha256, result_status FROM vt_lookups ORDER BY sha256 ASC")
        }
    finally:
        conn.close()

    assert statuses == {"a" * 64: "not_found", "b" * 64: "not_found"}


def test_active_policy_allowlists_remcom_and_xtu_paths(project_root: Path) -> None:
    remcom_log = project_root / "LokiScanResults" / "loki_ALPHA_2026-01-05_00-00-00.log"
    remcom_log.write_text(MULTI_REASON_LOG, encoding="utf-8")
    bad_remcom_log = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_BETA_2026-01-05_00-00-00.log",
        host="BETA",
        artifact_path=r"C:\Program Files\DesktopCentral_Server\bin\RemCom.exe",
        sha256="c" * 64,
        rule_key="RemCom_RemoteCommandExecution",
        md5="55555555555555555555555555555555",
        sha1="6666666666666666666666666666666666666666",
    )
    xtu_log = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_GAMMA_2026-01-05_00-00-00.log",
        host="GAMMA",
        artifact_path=r"C:\Windows\System32\DriverStore\FileRepository\xtucomponent.inf_amd64_aa0ae5a9f4a275cf\IntelBenchmarkSDK.dll",
        sha256="d" * 64,
        rule_key="ID_144731",
        md5="77777777777777777777777777777777",
        sha1="8888888888888888888888888888888888888888",
    )
    xtu_bad_log = _write_single_file_finding_log(
        project_root / "LokiScanResults" / "loki_DELTA_2026-01-05_00-00-00.log",
        host="DELTA",
        artifact_path=r"C:\Windows\System32\DriverStore\FileRepository\xtucomponent.inf_amd64_aa0ae5a9f4a275cf\Unknown.dll",
        sha256="e" * 64,
        rule_key="Susp_Net_Name_ConfuserEx",
        md5="99999999999999999999999999999999",
        sha1="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )

    ingest_logs([remcom_log, bad_remcom_log, xtu_log, xtu_bad_log], period="2026-01", run_kind="baseline", project_root=project_root)

    conn = connect(project_root / "state" / "triage.db")
    try:
        dispositions = {
            row["artifact_path"]: row["current_disposition"]
            for row in conn.execute(
                "SELECT artifact_path, current_disposition FROM cases WHERE artifact_path IS NOT NULL"
            )
        }
    finally:
        conn.close()

    assert dispositions[r"C:\Windows\System32\RemComSvc.exe"] == "expected_benign"
    assert dispositions[r"C:\Program Files\DesktopCentral_Server\bin\RemCom.exe"] == "unreviewed"
    assert dispositions[
        r"C:\Windows\System32\DriverStore\FileRepository\xtucomponent.inf_amd64_aa0ae5a9f4a275cf\IntelBenchmarkSDK.dll"
    ] == "expected_benign"
    assert dispositions[
        r"C:\Windows\System32\DriverStore\FileRepository\xtucomponent.inf_amd64_aa0ae5a9f4a275cf\Unknown.dll"
    ] == "unreviewed"


def test_review_and_report_workflow(project_root: Path, copy_fixture_log, monkeypatch) -> None:
    baseline_log = copy_fixture_log("loki_ALPHA_2026-01-01_00-00-00.log")
    result = ingest_logs([baseline_log], period="2026-01", run_kind="baseline", project_root=project_root)

    queued = queue(project_root=project_root)
    assert queued
    case_id = queued[0]["case_id"]

    set_case_verdict(
        case_id,
        disposition="false_positive",
        reason="Known lab binary",
        analyst="pytest",
        run_id=result["run_id"],
        project_root=project_root,
    )
    payload = show_case(case_id, project_root=project_root)
    assert payload["case"]["current_disposition"] == "false_positive"
    assert payload["verdicts"][0]["reason"] == "Known lab binary"

    def fake_render_pdf(html_path: Path, pdf_path: Path) -> None:
        pdf_path.write_bytes(b"%PDF-1.4\n% test fixture\n")

    monkeypatch.setattr("loki_triage.reporting._render_pdf", fake_render_pdf)
    with pytest.raises(RuntimeError, match="zero VT coverage"):
        build_report("2026-01", project_root=project_root)

    report = build_report("2026-01", project_root=project_root, allow_missing_vt=True)
    assert Path(report["html_path"]).exists()
    assert Path(report["pdf_path"]).exists()
    assert Path(report["csv_path"]).exists()
    html = Path(report["html_path"]).read_text(encoding="utf-8")
    assert "Artifact Cases" in html
    assert "VT missing coverage on hash-bearing cases" in html


def test_report_surfaces_vt_not_found_state(project_root: Path, copy_fixture_log, monkeypatch) -> None:
    baseline_log = copy_fixture_log("loki_ALPHA_2026-01-01_00-00-00.log")
    ingest_logs([baseline_log], period="2026-01", run_kind="baseline", project_root=project_root)

    conn = connect(project_root / "state" / "triage.db")
    ensure_schema(conn)
    try:
        upsert_vt_lookup(
            conn,
            "a" * 64,
            "public_safe",
            "not_found",
            {},
            {"stdout": f'File "{"a" * 64}" not found', "stderr": ""},
            "VT returned no record for hash",
        )
        conn.commit()
    finally:
        conn.close()

    def fake_render_pdf(html_path: Path, pdf_path: Path) -> None:
        pdf_path.write_bytes(b"%PDF-1.4\n% test fixture\n")

    monkeypatch.setattr("loki_triage.reporting._render_pdf", fake_render_pdf)
    report = build_report("2026-01", project_root=project_root, allow_missing_vt=True)
    html = Path(report["html_path"]).read_text(encoding="utf-8")
    assert "VT no-hit lookups" in html
    assert "not found" in html
    assert "VT no-hit lookups" in html
