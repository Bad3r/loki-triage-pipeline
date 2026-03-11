# Repository Guidelines

## Project Structure & Module Organization
This repository is a Loki scan evidence set, not an application codebase. Raw scan outputs live in `LokiScanResults/`, and follow-up rescans live in `LokiScanResults/Loki-Rescan/`.

Log files follow this naming pattern:
- `loki_<HOSTNAME>_YYYY-MM-DD_HH-MM-SS.log`

Keep raw logs immutable after ingestion. If you need derived outputs (summaries, triage notes, parser output), place them in a separate folder such as `analysis/` or `reports/` to avoid mixing source evidence with processed artifacts.

## Build, Test, and Development Commands
There is no compile/build pipeline in this repository. Use lightweight verification commands:

- `rg --files LokiScanResults | wc -l`  
  Count collected log files.
- `rg -n ",ALERT," LokiScanResults`  
  Locate high-severity findings quickly.
- `rg -n ",ERROR,|,WARNING," LokiScanResults`  
  Identify parsing/runtime scan issues.
- `awk -F, '{print $3}' LokiScanResults/*.log | sort | uniq -c`  
  Summarize severity distribution (`INFO`, `NOTICE`, `ALERT`, etc.).

## Coding Style & Naming Conventions
When adding helper scripts:
- Use `snake_case` file names (example: `parse_alert_counts.py`).
- Prefer 4-space indentation and UTF-8 text files with LF endings.
- Make scripts read-only by default against raw logs; write outputs to a new directory.

For new log imports, preserve the existing filename pattern exactly to keep host/date sorting predictable.

## Testing Guidelines
No formal test framework exists yet. Validate data and tooling changes with command-based checks:
- `awk -F, 'NF < 5 {print FILENAME ":" NR}' LokiScanResults/*.log` to flag malformed rows.
- Run parser/summary scripts against a small sample first, then against full datasets.

If you add a parser module, include fixture-based tests under `tests/` and document how to run them.

## Commit & Pull Request Guidelines
No Git history is present in this snapshot, so use this baseline convention:
- Commit format: `type(scope): short summary` (example: `feat(parser): add alert frequency report`).
- Keep commits focused (ingestion, parsing, and reporting changes separated).

PRs should include:
- What changed and why.
- Data scope (hosts/date range/file count).
- Validation commands run and their key outputs.

## Security & Configuration Tips
These logs may contain sensitive infrastructure details (hostnames, paths, hashes, internal shares). Do not publish raw data externally. Redact sensitive tokens in derived reports, and record redaction rules in the PR description.
