from __future__ import annotations

import shutil
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .config import ProjectPaths, get_project_paths, load_runtime_config
from .db import connect, ensure_schema, insert_report_run
from .utils import compact_utc_now, utc_now, write_csv


BROWSER_CANDIDATES = ["chromium", "chromium-browser", "google-chrome", "chrome"]



def _scope_run_ids(conn, period: str, run_id: str | None) -> list[str]:
    if run_id:
        row = conn.execute("SELECT id FROM scan_runs WHERE id = ?", (run_id,)).fetchone()
        return [str(row["id"])] if row else []
    rows = conn.execute("SELECT id FROM scan_runs WHERE period = ? ORDER BY started_at", (period,)).fetchall()
    return [str(row["id"]) for row in rows]



def _query_report_dataset(conn, run_ids: list[str], lookup_profile: str) -> dict[str, Any]:
    if not run_ids:
        return {
            "kpis": {},
            "top_hosts": [],
            "findings": [],
            "appendix": {},
            "recurrent_false_positives": [],
        }
    placeholders = ",".join("?" for _ in run_ids)
    scope_clause = f"WHERE fo.run_id IN ({placeholders})"
    host_rows = conn.execute(
        f"""
        SELECT fo.host, COUNT(*) AS occurrence_count
        FROM finding_occurrences fo
        {scope_clause}
        GROUP BY fo.host
        ORDER BY occurrence_count DESC, fo.host ASC
        LIMIT 15
        """,
        run_ids,
    ).fetchall()
    finding_rows = conn.execute(
        f"""
        SELECT
            f.id AS finding_id,
            f.title,
            f.current_disposition,
            f.priority,
            f.severity,
            f.current_reason,
            fo.host,
            fo.occurrence_ts,
            fo.state_for_host_run,
            fo.event_type,
            fo.event_kind,
            fo.artifact_path,
            fo.sha256,
            fo.rule_key,
            fo.score,
            fo.source_path,
            fo.source_line_start,
            fo.source_line_end,
            vt.summary_json AS vt_summary_json
        FROM finding_occurrences fo
        JOIN findings f ON f.id = fo.finding_id
        LEFT JOIN vt_lookups vt ON vt.sha256 = fo.sha256 AND vt.lookup_profile = ?
        {scope_clause}
        ORDER BY fo.host ASC, fo.occurrence_ts DESC, f.priority DESC
        """,
        [lookup_profile, *run_ids],
    ).fetchall()
    kpis = conn.execute(
        f"""
        SELECT
            COUNT(DISTINCT fo.host) AS host_count,
            COUNT(DISTINCT fo.finding_id) AS finding_count,
            SUM(CASE WHEN fo.state_for_host_run = 'new' THEN 1 ELSE 0 END) AS new_count,
            SUM(CASE WHEN fo.state_for_host_run = 'persisting' THEN 1 ELSE 0 END) AS persisting_count,
            SUM(CASE WHEN fo.state_for_host_run = 'reopened' THEN 1 ELSE 0 END) AS reopened_count,
            SUM(CASE WHEN f.current_disposition = 'true_positive' THEN 1 ELSE 0 END) AS true_positive_count,
            SUM(CASE WHEN f.current_disposition = 'false_positive' THEN 1 ELSE 0 END) AS false_positive_count,
            SUM(CASE WHEN f.current_disposition = 'needs_followup' THEN 1 ELSE 0 END) AS needs_followup_count,
            SUM(CASE WHEN f.current_disposition = 'unreviewed' THEN 1 ELSE 0 END) AS unreviewed_count
        FROM finding_occurrences fo
        JOIN findings f ON f.id = fo.finding_id
        {scope_clause}
        """,
        run_ids,
    ).fetchone()
    recurrent_false_positive_rows = conn.execute(
        f"""
        SELECT fo.rule_key, COUNT(*) AS occurrences
        FROM finding_occurrences fo
        JOIN findings f ON f.id = fo.finding_id
        {scope_clause} AND f.current_disposition = 'false_positive'
        GROUP BY fo.rule_key
        ORDER BY occurrences DESC, fo.rule_key ASC
        LIMIT 10
        """,
        run_ids,
    ).fetchall()
    appendix: dict[str, list[dict[str, Any]]] = defaultdict(list)
    rendered_findings: list[dict[str, Any]] = []
    for row in finding_rows:
        item = dict(row)
        if item.get("vt_summary_json"):
            import json

            item["vt_summary"] = json.loads(item["vt_summary_json"])
        else:
            item["vt_summary"] = None
        item.pop("vt_summary_json", None)
        appendix[item.get("host") or "unknown-host"].append(item)
        rendered_findings.append(item)
    return {
        "kpis": dict(kpis) if kpis else {},
        "top_hosts": [dict(row) for row in host_rows],
        "findings": rendered_findings,
        "appendix": dict(appendix),
        "recurrent_false_positives": [dict(row) for row in recurrent_false_positive_rows],
    }



def _env(paths: ProjectPaths) -> Environment:
    return Environment(
        loader=FileSystemLoader(str(paths.template_dir)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )



def _render_pdf(html_path: Path, pdf_path: Path) -> None:
    browser = next((shutil.which(candidate) for candidate in BROWSER_CANDIDATES if shutil.which(candidate)), None)
    if browser is None:
        raise FileNotFoundError("Unable to locate Chromium or Chrome for PDF generation")
    command = [
        browser,
        "--headless",
        "--disable-gpu",
        "--no-sandbox",
        f"--print-to-pdf={pdf_path}",
        "--allow-file-access-from-files",
        html_path.resolve().as_uri(),
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Chromium PDF rendering failed")



def build_report(period: str, run_id: str | None = None, project_root: Path | None = None) -> dict[str, Any]:
    paths = get_project_paths(project_root)
    runtime_config = load_runtime_config(paths)
    conn = connect(paths.db_path)
    ensure_schema(conn)
    try:
        run_ids = _scope_run_ids(conn, period, run_id)
        if not run_ids:
            raise KeyError(f"No scan runs found for period {period!r}{f' and run {run_id!r}' if run_id else ''}")
        lookup_profile = str(runtime_config.vt_config.get("profile", "public_safe"))
        dataset = _query_report_dataset(conn, run_ids, lookup_profile)
        report_id = f"report-{period}-{compact_utc_now()}"
        report_dir = paths.runs_dir / period / (run_id or "period-summary") / "report"
        report_dir.mkdir(parents=True, exist_ok=True)
        html_path = report_dir / f"{report_id}.html"
        pdf_path = report_dir / f"{report_id}.pdf"
        csv_path = report_dir / f"{report_id}.csv"
        env = _env(paths)
        template = env.get_template("report.html.j2")
        rendered = template.render(
            generated_at=utc_now(),
            period=period,
            report_id=report_id,
            run_ids=run_ids,
            config=runtime_config.report_config,
            dataset=dataset,
        )
        html_path.write_text(rendered, encoding="utf-8")
        _render_pdf(html_path, pdf_path)
        write_csv(
            csv_path,
            dataset["findings"],
            [
                "finding_id",
                "title",
                "current_disposition",
                "priority",
                "severity",
                "host",
                "occurrence_ts",
                "state_for_host_run",
                "event_type",
                "event_kind",
                "artifact_path",
                "sha256",
                "rule_key",
                "score",
                "source_path",
                "source_line_start",
                "source_line_end",
            ],
        )
        insert_report_run(
            conn,
            {
                "id": report_id,
                "period": period,
                "created_at": utc_now(),
                "run_scope": "single-run" if run_id else "period",
                "run_id": run_id,
                "html_path": str(html_path),
                "pdf_path": str(pdf_path),
                "summary": dataset["kpis"],
            },
        )
        conn.commit()
        return {
            "report_id": report_id,
            "html_path": str(html_path),
            "pdf_path": str(pdf_path),
            "csv_path": str(csv_path),
            "run_ids": run_ids,
        }
    finally:
        conn.close()
