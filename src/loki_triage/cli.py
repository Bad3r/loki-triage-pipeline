from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from .ingest import export_rows_for_run, ingest_logs
from .review import queue_table, set_finding_verdict, show_finding
from .reporting import build_report
from .utils import format_table, write_csv
from .vt import enrich_hashes
from .config import get_project_paths
from .db import connect, ensure_schema


app = typer.Typer(help="Loki log ingestion, triage, enrichment, and reporting")
review_app = typer.Typer(help="Inspect and disposition findings")
export_app = typer.Typer(help="Export run-scoped finding data")
report_app = typer.Typer(help="Build HTML and PDF reports")
app.add_typer(review_app, name="review")
app.add_typer(export_app, name="export")
app.add_typer(report_app, name="report")


def _run_period(conn, run_id: str) -> str:
    row = conn.execute("SELECT period FROM scan_runs WHERE id = ?", (run_id,)).fetchone()
    if not row:
        raise KeyError(f"Run {run_id!r} was not found")
    return str(row["period"])


@app.command()
def ingest(
    paths: Annotated[list[Path], typer.Argument(help="One or more Loki log files or directories")],
    period: Annotated[str, typer.Option("--period", help="Reporting period, for example 2026-01")],
    run_kind: Annotated[str, typer.Option("--run-kind", help="baseline, rescan, or mixed")] = "mixed",
) -> None:
    summary = ingest_logs(paths, period, run_kind)
    typer.echo(summary["summary"])
    if not summary.get("reused"):
        typer.echo(f"\nRun path: {summary['run_path']}")
        typer.echo(f"Manifest: {summary['manifest_path']}")


@app.command("enrich-vt")
def enrich_vt(
    run_id: Annotated[str | None, typer.Option("--run-id", help="Restrict enrichment to one run")] = None,
) -> None:
    result = enrich_hashes(run_id)
    typer.echo(result["summary"])
    if result.get("errors"):
        typer.echo("\nErrors:")
        for error in result["errors"]:
            typer.echo(f"- {error}")


@review_app.command("queue")
def review_queue(
    status: Annotated[list[str], typer.Option("--status", help="Optional disposition filter")] = [],
) -> None:
    typer.echo(queue_table(status or None))


@review_app.command("show")
def review_show(finding_id: Annotated[int, typer.Argument(help="Finding identifier")]) -> None:
    payload = show_finding(finding_id)
    typer.echo(json.dumps(payload, indent=2, ensure_ascii=False))


@review_app.command("set")
def review_set(
    finding_id: Annotated[int, typer.Argument(help="Finding identifier")],
    disposition: Annotated[
        str,
        typer.Option(
            "--disposition",
            help="One of unreviewed, needs_followup, true_positive, false_positive, expected_benign",
        ),
    ],
    reason: Annotated[str, typer.Option("--reason", help="Analyst reasoning")],
    analyst: Annotated[str, typer.Option("--analyst", help="Analyst name or handle")] = "local-analyst",
    run_id: Annotated[str | None, typer.Option("--run-id", help="Optional related run id")] = None,
) -> None:
    set_finding_verdict(finding_id, disposition, reason, analyst, run_id)
    typer.echo(f"Updated finding {finding_id} to {disposition}")


@export_app.command("findings")
def export_findings(
    run_id: Annotated[str, typer.Option("--run-id", help="Run identifier to export")],
    format: Annotated[str, typer.Option("--format", help="csv or jsonl")] = "csv",
) -> None:
    paths = get_project_paths()
    conn = connect(paths.db_path)
    ensure_schema(conn)
    try:
        period = _run_period(conn, run_id)
        rows = export_rows_for_run(conn, run_id)
    finally:
        conn.close()
    output_dir = paths.runs_dir / period / run_id / "exports"
    output_dir.mkdir(parents=True, exist_ok=True)
    if format == "jsonl":
        output_path = output_dir / "findings.jsonl"
        with output_path.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, default=str))
                handle.write("\n")
    else:
        output_path = output_dir / "findings.csv"
        write_csv(output_path, rows, list(rows[0].keys()) if rows else ["finding_id"])
    typer.echo(str(output_path))


@report_app.command("build")
def report_build(
    period: Annotated[str, typer.Option("--period", help="Reporting period, for example 2026-01")],
    run_id: Annotated[str | None, typer.Option("--run-id", help="Optional run identifier")] = None,
) -> None:
    result = build_report(period, run_id)
    typer.echo(format_table([
        {"artifact": "html", "path": result["html_path"]},
        {"artifact": "pdf", "path": result["pdf_path"]},
        {"artifact": "csv", "path": result["csv_path"]},
    ], [("artifact", "Artifact"), ("path", "Path")]))


if __name__ == "__main__":
    app()
