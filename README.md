# Loki Triage

`loki-triage` is a CLI-first project for ingesting Loki scan logs, normalizing multiline findings, caching both raw detections and analyst-facing artifact cases in SQLite, enriching hash-bearing cases with VirusTotal via the `vt` CLI, and generating monthly management reports.

## Highlights
- Keeps raw Loki logs immutable under `LokiScanResults/`
- Writes derived artifacts under `runs/YYYY-MM/<run_id>/`
- Uses `state/triage.db` for persistent raw detection, case, verdict, and VT cache state
- Reconstructs multiline Loki records using timestamp-prefix detection
- Tracks both raw Loki rule matches and aggregated artifact-centric analyst cases
- Produces HTML and PDF management reports

## Quick start
```bash
uv sync --extra dev
cat > .env <<'EOF'
LOKI_TRIAGE_PROJECT_NAME="Example Organization"
EOF
uv run loki-triage ingest LokiScanResults --period 2026-01 --run-kind mixed
uv run loki-triage review queue
uv run loki-triage enrich-vt --run-id <run-id>
uv run loki-triage report build --period 2026-01
```

## Configuration
- Full config reference: `docs/plans/loki-triage-configuration-reference.md`
- Active config files under `config/`:
  - `severity_rules.yaml`: queueing and priority rules
  - `triage_policy.yaml`: deterministic allowlists and VT follow-up thresholds
  - `vt_config.yaml`: active VT profile, UTC daily request budget, eligible severities and dispositions, batch size, sleep interval, and included fields
  - `report_config.yaml`: report title, colors, disclaimer text, and appendix limits
  - `false_positive_rules.yaml`: legacy placeholder config, currently loaded but not enforced by runtime logic
- `.env` and process environment:
  - `LOKI_TRIAGE_PROJECT_NAME` and `LOKI_TRIAGE_ORGANIZATION_NAME` both map to `report_config.organization_name`
  - precedence is process environment > `.env` > YAML value
  - current report template renders `report_title` and `subtitle`; `organization_name` is stored in runtime config for downstream consumers but is not currently printed in the HTML/PDF template
- Triage policy highlights:
  - `allowlists.sha256`: exact hash allowlists
  - `allowlists.path_rule_patterns`: path and rule-based allowlists with optional `host_regex`
  - `defaults.expected_benign_disposition` and `defaults.vt_followup_disposition`: disposition fallbacks
  - `vt.malicious_threshold` and `vt.suspicious_threshold`: when VT should raise `needs_followup`
  - active path allowlists currently cover archived `loki_*.log` output, `RemComSvc.exe` in `System32|SysWOW64`, and known Intel XTU DriverStore binaries in the canonical `xtucomponent.inf_amd64_*` path
  - analyst verdicts take precedence over automatic policy reevaluation

## Commands
- `loki-triage ingest <paths...> --period YYYY-MM --run-kind baseline|rescan|mixed`
- `loki-triage enrich-vt --run-id <id>`
- `loki-triage review queue [--status ...]`
- `loki-triage review show <case-id>`
- `loki-triage review set <case-id> --disposition ... --reason ...`
- `loki-triage export findings --run-id <id> --scope cases|raw --format csv|jsonl`
- `loki-triage report build --period YYYY-MM [--run-id ...] [--allow-missing-vt]`

## Notes
- VT enrichment uses batched threaded `vt file --format json <hash...>` lookups only. The project does not upload files.
- `config/vt_config.yaml -> daily_request_limit` is enforced at runtime as a UTC per-profile VT budget. Current repo default is `1000`.
- VT lookup scope is limited by `vt_config.yaml -> eligible_severities`, currently `NOTICE`, `WARNING`, `ERROR`, and `ALERT`. `INFO` and `RESULT` findings are not sent to VT.
- VT lookup scope is also limited by `vt_config.yaml -> eligible_dispositions`, currently `unreviewed`, `needs_followup`, and `true_positive`. Reviewed benign states such as `expected_benign` and `false_positive` do not consume VT quota by default.
- VT lookup states are:
  - `ok`: VT returned a record and the cached summary is available
  - `not_found`: VT lookup completed but VT had no public record for the hash
  - `error`: VT invocation failed or returned an unparseable unexpected response
  - `missing`: no lookup row exists yet for that hash/profile
- The active VT profile is currently `public_safe`. `private_fast` remains available for faster batch lookups when the configured VT quota supports it.
- `loki-triage enrich-vt` now ranks pending hashes before lookup and returns a quota summary including `used_today`, `remaining_budget`, `candidate_count`, `selected_count`, and `deferred_count`.
- Export behavior:
  - default export scope is `cases`
  - output path is `runs/<period>/<run_id>/exports/`
  - case exports are `cases.csv|jsonl`
  - raw detection exports are `raw_detections.csv|jsonl`
- Report generation fails by default when:
  - scoped hash-bearing cases have zero VT coverage
  - the report scope mixes legacy runs that only have `finding_occurrences` with rebuilt runs that have `case_occurrences`
  - use `--allow-missing-vt` only when you explicitly want a non-enriched report and already understand the coverage gap
- Analyst review is case-centric. Multiple Loki `REASON_n` matches for the same artifact collapse into one case with child rule evidence.
- Local auto-triage policy lives in `config/triage_policy.yaml`. Deterministic allowlists may mark cases `expected_benign`; VT can raise `needs_followup` but does not auto-suppress on its own.
- Active benign path rules are intentionally narrow:
  - `C:\Windows\System32\RemComSvc.exe` and `C:\Windows\SysWOW64\RemComSvc.exe` for the RemCom service signature family
  - known Intel XTU binaries only under `C:\Windows\System32\DriverStore\FileRepository\xtucomponent.inf_amd64_*`
- Existing pre-case `state/triage.db` contents should be treated as legacy derived state. Rebuild from raw logs after upgrading.
- Rebuild runbook for legacy state:
  ```bash
  mv state/triage.db state/triage.pre-case.$(date -u +%Y%m%dT%H%M%SZ).db.bak
  uv run loki-triage ingest LokiScanResults --period 2026-01 --run-kind mixed
  uv run loki-triage enrich-vt --run-id <new-run-id>
  uv run loki-triage report build --period 2026-01
  ```
- Fresh clean rerun for this corpus:
  ```bash
  rm -f state/triage.db
  rm -rf runs/2026-01
  uv run loki-triage ingest LokiScanResults --period 2026-01 --run-kind mixed
  uv run loki-triage enrich-vt --run-id <new-run-id>
  uv run loki-triage report build --period 2026-01
  ```
- PDF generation uses a locally installed Chromium-compatible browser when available.
