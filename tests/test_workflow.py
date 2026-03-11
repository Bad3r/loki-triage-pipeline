from __future__ import annotations

from pathlib import Path

from loki_triage.db import connect, ensure_schema
from loki_triage.ingest import ingest_logs
from loki_triage.reporting import build_report
from loki_triage.review import queue, set_finding_verdict, show_finding


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

        second_run_rows = conn.execute(
            """
            SELECT event_type, event_kind, state_for_host_run
            FROM finding_occurrences
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


def test_review_and_report_workflow(project_root: Path, copy_fixture_log, monkeypatch) -> None:
    baseline_log = copy_fixture_log("loki_ALPHA_2026-01-01_00-00-00.log")
    result = ingest_logs([baseline_log], period="2026-01", run_kind="baseline", project_root=project_root)

    queued = queue(project_root=project_root)
    assert queued
    finding_id = queued[0]["finding_id"]

    set_finding_verdict(
        finding_id,
        disposition="false_positive",
        reason="Known lab binary",
        analyst="pytest",
        run_id=result["run_id"],
        project_root=project_root,
    )
    payload = show_finding(finding_id, project_root=project_root)
    assert payload["finding"]["current_disposition"] == "false_positive"
    assert payload["verdicts"][0]["reason"] == "Known lab binary"

    def fake_render_pdf(html_path: Path, pdf_path: Path) -> None:
        pdf_path.write_bytes(b"%PDF-1.4\n% test fixture\n")

    monkeypatch.setattr("loki_triage.reporting._render_pdf", fake_render_pdf)
    report = build_report("2026-01", project_root=project_root)
    assert Path(report["html_path"]).exists()
    assert Path(report["pdf_path"]).exists()
    assert Path(report["csv_path"]).exists()
    assert "Loki Monthly Threat Triage" in Path(report["html_path"]).read_text(encoding="utf-8")
