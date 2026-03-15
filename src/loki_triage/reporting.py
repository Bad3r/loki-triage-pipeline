from __future__ import annotations

import json
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .buckets import case_bucket_for_row, case_bucket_sql, case_matches_bucket
from .config import ProjectPaths, get_project_paths, load_runtime_config
from .db import connect, ensure_schema, insert_report_run
from .utils import compact_utc_now, utc_now, write_csv


BROWSER_CANDIDATES = ["chromium", "chromium-browser", "google-chrome", "chrome"]
TOP_HOSTS_LIMIT = 15
DEFAULT_TOP_FINDINGS_LIMIT = 20
DEFAULT_APPENDIX_HOST_LIMIT = 25
DEFAULT_APPENDIX_FINDINGS_PER_HOST = 10
PDF_RENDER_TIMEOUT_SECONDS = 900
PRIORITY_ORDER_SQL = """
CASE c.priority
    WHEN 'critical' THEN 5
    WHEN 'high' THEN 4
    WHEN 'medium' THEN 3
    WHEN 'low' THEN 2
    ELSE 1
END
"""
SEVERITY_ORDER_SQL = """
CASE c.severity
    WHEN 'ALERT' THEN 5
    WHEN 'WARNING' THEN 4
    WHEN 'ERROR' THEN 3
    WHEN 'NOTICE' THEN 2
    WHEN 'RESULT' THEN 1
    ELSE 0
END
"""



def _scope_run_ids(conn, period: str, run_id: str | None) -> list[str]:
    if run_id:
        row = conn.execute("SELECT id FROM scan_runs WHERE id = ?", (run_id,)).fetchone()
        return [str(row["id"])] if row else []
    rows = conn.execute("SELECT id FROM scan_runs WHERE period = ? ORDER BY started_at", (period,)).fetchall()
    return [str(row["id"]) for row in rows]



def _scope_placeholders(run_ids: list[str]) -> str:
    return ",".join("?" for _ in run_ids)



def _legacy_scope_has_findings(conn, run_ids: list[str]) -> bool:
    placeholders = _scope_placeholders(run_ids)
    row = conn.execute(
        f"""
        WITH finding_runs AS (
            SELECT DISTINCT run_id FROM finding_occurrences WHERE run_id IN ({placeholders})
        ),
        case_runs AS (
            SELECT DISTINCT run_id FROM case_occurrences WHERE run_id IN ({placeholders})
        )
        SELECT COUNT(*) AS count
        FROM finding_runs fr
        LEFT JOIN case_runs cr ON cr.run_id = fr.run_id
        WHERE cr.run_id IS NULL
        """,
        [*run_ids, *run_ids],
    ).fetchone()
    return int(row["count"] or 0) > 0



def _load_vt_summary(row: dict[str, Any]) -> dict[str, Any] | None:
    if row.get("vt_result_status") != "ok":
        return None
    raw = row.get("vt_summary_json")
    if not raw:
        return None
    return json.loads(str(raw))



def _with_rule_lists(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for row in rows:
        matched_rules = str(row.get("matched_rules") or "")
        row["matched_rules_list"] = [item for item in matched_rules.split(",") if item]
        row["vt_summary"] = _load_vt_summary(row)
        row["case_bucket"] = case_bucket_for_row(row)
        row.pop("vt_summary_json", None)
    return rows



def _vt_coverage(conn, run_ids: list[str], lookup_profile: str) -> dict[str, int]:
    placeholders = _scope_placeholders(run_ids)
    actionable_clause, actionable_params = case_bucket_sql("c", "actionable")
    row = conn.execute(
        f"""
        WITH scoped_cases AS (
            SELECT DISTINCT c.id, c.sha256
            FROM cases c
            JOIN case_occurrences co ON co.case_id = c.id
            WHERE co.run_id IN ({placeholders})
              AND {actionable_clause}
        )
        SELECT
            SUM(CASE WHEN sc.sha256 IS NOT NULL THEN 1 ELSE 0 END) AS hash_case_count,
            SUM(CASE WHEN sc.sha256 IS NOT NULL AND vt.result_status = 'ok' THEN 1 ELSE 0 END) AS vt_covered_case_count,
            SUM(CASE WHEN sc.sha256 IS NOT NULL AND vt.result_status = 'not_found' THEN 1 ELSE 0 END) AS vt_not_found_case_count,
            SUM(CASE WHEN sc.sha256 IS NOT NULL AND vt.result_status = 'error' THEN 1 ELSE 0 END) AS vt_error_case_count
        FROM scoped_cases sc
        LEFT JOIN vt_lookups vt ON vt.sha256 = sc.sha256 AND vt.lookup_profile = ?
        """,
        [*run_ids, *actionable_params, lookup_profile],
    ).fetchone()
    hash_case_count = int(row["hash_case_count"] or 0)
    vt_covered_case_count = int(row["vt_covered_case_count"] or 0)
    vt_not_found_case_count = int(row["vt_not_found_case_count"] or 0)
    vt_error_case_count = int(row["vt_error_case_count"] or 0)
    vt_missing_case_count = max(hash_case_count - vt_covered_case_count - vt_not_found_case_count - vt_error_case_count, 0)
    return {
        "hash_case_count": hash_case_count,
        "vt_covered_case_count": vt_covered_case_count,
        "vt_not_found_case_count": vt_not_found_case_count,
        "vt_error_case_count": vt_error_case_count,
        "vt_missing_case_count": vt_missing_case_count,
    }



def _query_report_dataset(
    conn,
    run_ids: list[str],
    lookup_profile: str,
    report_config: dict[str, Any],
) -> dict[str, Any]:
    if not run_ids:
        return {
            "kpis": {},
            "top_hosts": [],
            "cases": [],
            "priority_cases": [],
            "appendix": {},
            "recurrent_benign_rules": [],
            "routed_cases": [],
            "routed_case_count_total": 0,
            "vt_coverage": {},
        }
    placeholders = _scope_placeholders(run_ids)
    suppressed_clause, suppressed_params = case_bucket_sql("c", "suppressed")

    host_rows = conn.execute(
        f"""
        SELECT host, COUNT(*) AS occurrence_count
        FROM case_occurrences
        WHERE run_id IN ({placeholders})
        GROUP BY host
        ORDER BY occurrence_count DESC, host ASC
        """,
        run_ids,
    ).fetchall()

    case_rows = conn.execute(
        f"""
        WITH scoped_occurrences AS (
            SELECT * FROM case_occurrences WHERE run_id IN ({placeholders})
        ),
        case_metrics AS (
            SELECT
                case_id,
                COUNT(*) AS occurrence_count,
                COUNT(DISTINCT host) AS host_count,
                MIN(occurrence_ts) AS first_occurrence_ts,
                MAX(occurrence_ts) AS last_occurrence_ts
            FROM scoped_occurrences
            GROUP BY case_id
        ),
        latest_case AS (
            SELECT
                sco.case_id,
                sco.host,
                sco.state_for_host_run,
                sco.event_type,
                sco.event_kind,
                sco.artifact_path,
                sco.source_path,
                sco.source_line_start,
                sco.source_line_end
            FROM scoped_occurrences sco
            JOIN (
                SELECT case_id, MAX(occurrence_ts) AS last_occurrence_ts
                FROM scoped_occurrences
                GROUP BY case_id
            ) latest
              ON latest.case_id = sco.case_id
             AND latest.last_occurrence_ts = sco.occurrence_ts
            GROUP BY sco.case_id
        ),
        case_rules AS (
            SELECT
                cm.case_id,
                GROUP_CONCAT(DISTINCT f.rule_key) AS matched_rules,
                COUNT(DISTINCT f.id) AS detection_count
            FROM case_memberships cm
            JOIN findings f ON f.id = cm.finding_id
            GROUP BY cm.case_id
        )
        SELECT
            c.id AS case_id,
            c.title,
            c.current_disposition,
            c.disposition_source,
            c.policy_name,
            c.priority,
            c.severity,
            c.current_reason,
            c.sha256,
            COALESCE(latest_case.artifact_path, c.artifact_path) AS artifact_path,
            case_metrics.occurrence_count,
            case_metrics.host_count,
            case_metrics.first_occurrence_ts,
            case_metrics.last_occurrence_ts,
            latest_case.host AS latest_host,
            latest_case.state_for_host_run,
            latest_case.event_type,
            latest_case.event_kind,
            latest_case.source_path,
            latest_case.source_line_start,
            latest_case.source_line_end,
            case_rules.matched_rules,
            case_rules.detection_count,
            vt.result_status AS vt_result_status,
            vt.summary_json AS vt_summary_json,
            vt.error_text AS vt_error_text,
            vt.lookup_ts AS vt_lookup_ts
        FROM case_metrics
        JOIN cases c ON c.id = case_metrics.case_id
        LEFT JOIN latest_case ON latest_case.case_id = c.id
        LEFT JOIN case_rules ON case_rules.case_id = c.id
        LEFT JOIN vt_lookups vt ON vt.sha256 = c.sha256 AND vt.lookup_profile = ?
        ORDER BY {PRIORITY_ORDER_SQL} DESC, {SEVERITY_ORDER_SQL} DESC, case_metrics.last_occurrence_ts DESC, c.id ASC
        """,
        [*run_ids, lookup_profile],
    ).fetchall()

    appendix_rows = conn.execute(
        f"""
        WITH scoped_occurrences AS (
            SELECT * FROM case_occurrences WHERE run_id IN ({placeholders})
        ),
        host_case_metrics AS (
            SELECT
                host,
                case_id,
                COUNT(*) AS occurrence_count,
                MIN(occurrence_ts) AS first_occurrence_ts,
                MAX(occurrence_ts) AS last_occurrence_ts
            FROM scoped_occurrences
            GROUP BY host, case_id
        ),
        host_case_latest AS (
            SELECT
                sco.host,
                sco.case_id,
                sco.state_for_host_run,
                sco.event_type,
                sco.event_kind,
                sco.artifact_path,
                sco.source_path,
                sco.source_line_start,
                sco.source_line_end
            FROM scoped_occurrences sco
            JOIN (
                SELECT host, case_id, MAX(occurrence_ts) AS last_occurrence_ts
                FROM scoped_occurrences
                GROUP BY host, case_id
            ) latest
              ON latest.host = sco.host
             AND latest.case_id = sco.case_id
             AND latest.last_occurrence_ts = sco.occurrence_ts
            GROUP BY sco.host, sco.case_id
        ),
        case_rules AS (
            SELECT cm.case_id, GROUP_CONCAT(DISTINCT f.rule_key) AS matched_rules
            FROM case_memberships cm
            JOIN findings f ON f.id = cm.finding_id
            GROUP BY cm.case_id
        )
        SELECT
            host_case_metrics.host,
            c.id AS case_id,
            c.title,
            c.current_disposition,
            c.disposition_source,
            c.policy_name,
            c.priority,
            c.severity,
            c.current_reason,
            c.sha256,
            COALESCE(host_case_latest.artifact_path, c.artifact_path) AS artifact_path,
            host_case_metrics.occurrence_count,
            host_case_metrics.first_occurrence_ts,
            host_case_metrics.last_occurrence_ts,
            host_case_latest.state_for_host_run,
            host_case_latest.event_type,
            host_case_latest.event_kind,
            host_case_latest.source_path,
            host_case_latest.source_line_start,
            host_case_latest.source_line_end,
            case_rules.matched_rules,
            vt.result_status AS vt_result_status,
            vt.summary_json AS vt_summary_json,
            vt.error_text AS vt_error_text,
            vt.lookup_ts AS vt_lookup_ts
        FROM host_case_metrics
        JOIN cases c ON c.id = host_case_metrics.case_id
        LEFT JOIN host_case_latest ON host_case_latest.case_id = c.id AND host_case_latest.host = host_case_metrics.host
        LEFT JOIN case_rules ON case_rules.case_id = c.id
        LEFT JOIN vt_lookups vt ON vt.sha256 = c.sha256 AND vt.lookup_profile = ?
        ORDER BY host_case_metrics.host ASC, {PRIORITY_ORDER_SQL} DESC, {SEVERITY_ORDER_SQL} DESC, host_case_metrics.last_occurrence_ts DESC, c.id ASC
        """,
        [*run_ids, lookup_profile],
    ).fetchall()

    kpis_row = conn.execute(
        f"""
        WITH scoped_case_ids AS (
            SELECT DISTINCT case_id FROM case_occurrences WHERE run_id IN ({placeholders})
        )
        SELECT
            (SELECT COUNT(DISTINCT host) FROM case_occurrences WHERE run_id IN ({placeholders})) AS host_count,
            (SELECT COUNT(*) FROM case_occurrences WHERE run_id IN ({placeholders})) AS occurrence_count,
            (SELECT COUNT(*) FROM finding_occurrences WHERE run_id IN ({placeholders})) AS detection_match_count,
            (SELECT COUNT(*) FROM scoped_case_ids) AS artifact_case_count,
            (SELECT COUNT(*) FROM scoped_case_ids sc JOIN cases c ON c.id = sc.case_id WHERE c.current_disposition <> 'unreviewed') AS reviewed_case_count,
            (SELECT COUNT(*) FROM scoped_case_ids sc JOIN cases c ON c.id = sc.case_id WHERE c.current_disposition = 'true_positive') AS true_positive_count,
            (SELECT COUNT(*) FROM scoped_case_ids sc JOIN cases c ON c.id = sc.case_id WHERE c.current_disposition = 'false_positive') AS false_positive_count,
            (SELECT COUNT(*) FROM scoped_case_ids sc JOIN cases c ON c.id = sc.case_id WHERE c.current_disposition = 'expected_benign') AS expected_benign_count,
            (SELECT COUNT(*) FROM scoped_case_ids sc JOIN cases c ON c.id = sc.case_id WHERE c.current_disposition = 'needs_followup') AS needs_followup_count,
            (SELECT COUNT(*) FROM scoped_case_ids sc JOIN cases c ON c.id = sc.case_id WHERE c.current_disposition = 'unreviewed') AS unreviewed_count,
            (SELECT COUNT(*) FROM case_occurrences WHERE run_id IN ({placeholders}) AND state_for_host_run = 'new') AS new_count,
            (SELECT COUNT(*) FROM case_occurrences WHERE run_id IN ({placeholders}) AND state_for_host_run = 'persisting') AS persisting_count,
            (SELECT COUNT(*) FROM case_occurrences WHERE run_id IN ({placeholders}) AND state_for_host_run = 'reopened') AS reopened_count
        """,
        [*run_ids, *run_ids, *run_ids, *run_ids, *run_ids, *run_ids, *run_ids],
    ).fetchone()

    recurrent_benign_rows = conn.execute(
        f"""
        WITH scoped_case_ids AS (
            SELECT DISTINCT case_id FROM case_occurrences WHERE run_id IN ({placeholders})
        ),
        case_metrics AS (
            SELECT case_id, COUNT(*) AS occurrence_count
            FROM case_occurrences
            WHERE run_id IN ({placeholders})
            GROUP BY case_id
        )
        SELECT
            c.current_disposition,
            f.rule_key,
            COUNT(DISTINCT c.id) AS case_count,
            SUM(case_metrics.occurrence_count) AS occurrence_count
        FROM scoped_case_ids sc
        JOIN cases c ON c.id = sc.case_id
        JOIN case_metrics ON case_metrics.case_id = c.id
        JOIN case_memberships cm ON cm.case_id = c.id
        JOIN findings f ON f.id = cm.finding_id
        WHERE {suppressed_clause}
        GROUP BY c.current_disposition, f.rule_key
        ORDER BY occurrence_count DESC, case_count DESC, f.rule_key ASC
        LIMIT 10
        """,
        [*run_ids, *run_ids, *suppressed_params],
    ).fetchall()

    vt_coverage = _vt_coverage(conn, run_ids, lookup_profile)

    top_findings_limit = int(report_config.get("top_findings_limit", DEFAULT_TOP_FINDINGS_LIMIT))
    appendix_host_limit = int(report_config.get("appendix_host_limit", DEFAULT_APPENDIX_HOST_LIMIT))
    appendix_findings_per_host = int(
        report_config.get("appendix_findings_per_host", DEFAULT_APPENDIX_FINDINGS_PER_HOST)
    )

    appendix_allowed_hosts = [
        str(row["host"]) for row in host_rows[:appendix_host_limit] if row["host"] is not None
    ]
    appendix: dict[str, list[dict[str, Any]]] = defaultdict(list)
    rendered_cases = _with_rule_lists([dict(row) for row in case_rows])
    for row in _with_rule_lists([dict(row) for row in appendix_rows]):
        if not case_matches_bucket(row, "actionable"):
            continue
        host = row.get("host") or "unknown-host"
        if appendix_allowed_hosts and host not in appendix_allowed_hosts:
            continue
        if len(appendix[host]) >= appendix_findings_per_host:
            continue
        appendix[host].append(row)

    priority_cases = [row for row in rendered_cases if case_matches_bucket(row, "actionable")]
    routed_cases = [row for row in rendered_cases if case_matches_bucket(row, "routed")]
    kpis = dict(kpis_row) if kpis_row else {}
    kpis["actionable_case_count"] = sum(1 for row in rendered_cases if case_matches_bucket(row, "actionable"))
    kpis["routed_case_count"] = len(routed_cases)
    kpis["suppressed_case_count"] = sum(1 for row in rendered_cases if case_matches_bucket(row, "suppressed"))

    return {
        "kpis": {**kpis, **vt_coverage},
        "top_hosts": [dict(row) for row in host_rows[:TOP_HOSTS_LIMIT]],
        "cases": rendered_cases,
        "priority_cases": priority_cases[:top_findings_limit],
        "appendix": dict(appendix),
        "recurrent_benign_rules": [dict(row) for row in recurrent_benign_rows],
        "routed_cases": routed_cases[:top_findings_limit],
        "routed_case_count_total": len(routed_cases),
        "report_limits": {
            "top_findings_limit": top_findings_limit,
            "appendix_host_limit": appendix_host_limit,
            "appendix_findings_per_host": appendix_findings_per_host,
            "appendix_host_count_rendered": len(appendix),
            "appendix_host_count_total": len(host_rows),
        },
        "vt_coverage": vt_coverage,
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
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=PDF_RENDER_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Chromium PDF rendering timed out after {PDF_RENDER_TIMEOUT_SECONDS} seconds"
        ) from exc
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Chromium PDF rendering failed")



def build_report(
    period: str,
    run_id: str | None = None,
    project_root: Path | None = None,
    allow_missing_vt: bool = False,
) -> dict[str, Any]:
    paths = get_project_paths(project_root)
    runtime_config = load_runtime_config(paths)
    conn = connect(paths.db_path)
    ensure_schema(conn)
    try:
        run_ids = _scope_run_ids(conn, period, run_id)
        if not run_ids:
            raise KeyError(f"No scan runs found for period {period!r}{f' and run {run_id!r}' if run_id else ''}")
        if _legacy_scope_has_findings(conn, run_ids):
            raise RuntimeError(
                "Report scope contains legacy finding rows without case data. Rebuild derived state by re-ingesting raw logs into a fresh state/triage.db."
            )
        lookup_profile = str(runtime_config.vt_config.get("profile", "public_safe"))
        dataset = _query_report_dataset(conn, run_ids, lookup_profile, runtime_config.report_config)
        coverage = dataset["vt_coverage"]
        if coverage.get("hash_case_count", 0) > 0 and coverage.get("vt_covered_case_count", 0) == 0 and not allow_missing_vt:
            raise RuntimeError(
                "Scoped hash-bearing cases have zero VT coverage. Run `loki-triage enrich-vt` first or rebuild with --allow-missing-vt."
            )
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
            dataset["cases"],
            [
                "case_id",
                "title",
                "current_disposition",
                "priority",
                "severity",
                "case_bucket",
                "policy_name",
                "disposition_source",
                "artifact_path",
                "sha256",
                "occurrence_count",
                "host_count",
                "first_occurrence_ts",
                "last_occurrence_ts",
                "matched_rules",
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
