# Loki Triage

`loki-triage` is a CLI-first project for ingesting Loki scan logs, normalizing multiline findings, caching analyst triage state in SQLite, enriching hash-bearing findings with VirusTotal via the `vt` CLI, and generating monthly management reports.

## Highlights
- Keeps raw Loki logs immutable under `LokiScanResults/`
- Writes derived artifacts under `runs/YYYY-MM/<run_id>/`
- Uses `state/triage.db` for persistent finding, verdict, and VT cache state
- Reconstructs multiline Loki records using timestamp-prefix detection
- Tracks both hash-bearing and non-hash findings with reusable finding keys
- Produces HTML and PDF management reports

## Quick start
```bash
uv sync --extra dev
cat > .env <<'EOF'
LOKI_TRIAGE_PROJECT_NAME="Example Organization"
EOF
uv run loki-triage ingest LokiScanResults --period 2026-01 --run-kind mixed
uv run loki-triage review queue
uv run loki-triage report build --period 2026-01
```

## Commands
- `loki-triage ingest <paths...> --period YYYY-MM --run-kind baseline|rescan|mixed`
- `loki-triage enrich-vt --run-id <id>`
- `loki-triage review queue [--status ...]`
- `loki-triage review show <finding-id>`
- `loki-triage review set <finding-id> --disposition ... --reason ...`
- `loki-triage export findings --run-id <id> --format csv|jsonl`
- `loki-triage report build --period YYYY-MM [--run-id ...]`

## Notes
- Set `LOKI_TRIAGE_PROJECT_NAME` in `.env` or the process environment to control the report header. A live environment variable overrides `.env`.
- VT enrichment uses `vt file --format json <hash>` only. The project does not upload files.
- PDF generation uses a locally installed Chromium-compatible browser when available.
