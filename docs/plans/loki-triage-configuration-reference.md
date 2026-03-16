# Loki Triage Configuration Reference

This document lists every runtime configuration file loaded by `src/loki_triage/config.py`, the keys that affect behavior, and any defaults or precedence rules.

## `config/severity_rules.yaml`
- `default_queue.<severity>`: whether detections at that Loki severity are queued.
- `priorities.<severity>`: maps Loki severity to internal priority.
- `process_event_overrides.<event_kind>`: overrides priority for specific process event kinds.
- Runtime fallback:
  - missing `default_queue.<severity>` => `false`
  - missing `priorities.<severity>` => `info`
  - `process_event_overrides` wins over severity-to-priority mapping

## `config/triage_policy.yaml`
- `defaults.expected_benign_disposition`: used when an allowlist match omits explicit disposition.
- `defaults.vt_followup_disposition`: used when VT thresholds trigger automatic follow-up.
- `allowlists.sha256[]`:
  - accepts either a bare hash string or an object
  - object fields: `sha256`, optional `name`, `reason`, `disposition`, `severity`, `priority`
- `allowlists.path_rule_patterns[]`:
  - required: `path_regex`
  - optional: `rule_key` as string or list, `host_regex`, `name`, `reason`, `disposition`, `severity`, `priority`
- `vt.malicious_threshold` and `vt.suspicious_threshold`: minimum VT counts that trigger `vt_followup_disposition`.
- `examples.*`: illustrative only; ignored by the evaluator.
- Active default allowlists in the repo:
  - archived `loki_*.log` outputs on disk
  - `RemComSvc.exe` only at `C:\Windows\System32\RemComSvc.exe` or `C:\Windows\SysWOW64\RemComSvc.exe`
  - known Intel XTU binaries only under `C:\Windows\System32\DriverStore\FileRepository\xtucomponent.inf_amd64_*`
- Runtime precedence:
  - analyst verdicts (`disposition_source='analyst'`) are never overwritten automatically
  - then deterministic allowlists
  - then VT threshold follow-up
  - otherwise reset to `unreviewed` with observed severity and priority

## `config/vt_config.yaml`
- `profile`: active VT profile name. Runtime fallback is `public_safe`. Current repo default is `public_safe`; `private_fast` remains available when the VT quota supports it.
- `daily_request_limit`: operator-planning ceiling for the current VT key. Current repo value is `999`. This is documented config today, not an enforced runtime stop.
- `eligible_severities[]`: Loki severities allowed into VT enrichment. Current repo default is `NOTICE`, `WARNING`, `ERROR`, `ALERT`.
- `profiles.<name>.batch_size`: number of hashes submitted before sleeping.
- `profiles.<name>.sleep_seconds`: sleep duration between batches.
- `profiles.<name>.include_fields[]`: repeated `vt file -i <field>` selectors.
- Runtime lookup behavior:
  - only hash-bearing case occurrences whose severity appears in `eligible_severities[]` are eligible for VT enrichment
  - one threaded `vt file` call is issued per configured batch
  - the runtime uses up to 20 VT CLI worker threads per batch
  - returned hashes are stored as `result_status='ok'`
  - hashes omitted from a successful VT response are stored as `result_status='not_found'`
  - nonzero VT exits or unexpected non-JSON output are stored as `result_status='error'`
- Runtime fallback:
  - missing profile => `ValueError`
  - missing `batch_size` => `1`
  - missing `sleep_seconds` => `0`
  - missing `include_fields` => `["**"]`

## Fresh Rerun Procedure
- Use this when you need a clean rebuild of derived state for the January 2026 corpus after policy or VT pipeline changes.
- Commands:
  ```bash
  rm -f state/triage.db
  rm -rf runs/2026-01
  uv run loki-triage ingest LokiScanResults --period 2026-01 --run-kind mixed
  uv run loki-triage enrich-vt --run-id <new-run-id>
  uv run loki-triage report build --period 2026-01
  ```
- The delete step is intentional:
  - `state/triage.db` is derived cache and verdict state
  - `runs/2026-01` contains prior derived artifacts, exports, and reports
  - rebuilding both avoids mixing legacy case state or stale VT coverage into the new report

## `config/report_config.yaml`
- Branding and content:
  - `report_title`
  - `subtitle`
  - `primary_color`
  - `secondary_color`
  - `accent_color`
  - `disclaimer`
  - `redaction_note`
- Layout limits:
  - `top_findings_limit` default fallback `20`
  - `appendix_host_limit` default fallback `25`
  - `appendix_findings_per_host` default fallback `10`
- `logo_path` is present in config but is not currently rendered by the report template.

## `config/false_positive_rules.yaml`
- Loaded into `RuntimeConfig`, but currently unused by ingest, policy, review, reporting, and VT code paths.
- Treat it as a legacy placeholder until the pipeline gains a dedicated false-positive suppression stage.

## Environment And `.env`
- Supported env keys:
  - `LOKI_TRIAGE_PROJECT_NAME`
  - `LOKI_TRIAGE_ORGANIZATION_NAME`
- Both populate `report_config.organization_name`.
- Precedence is:
  - process environment
  - `.env`
  - YAML file value
- Current HTML/PDF output does not render `organization_name`; it is retained in runtime config for downstream consumers.
