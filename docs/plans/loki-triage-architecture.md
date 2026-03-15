# Loki Triage Architecture

## Goal
Build a CLI-first Python project that ingests raw Loki scan evidence, reconstructs multiline records, persists reusable raw-detection and case-centric triage state, enriches hash-bearing cases with VirusTotal through the `vt` CLI, and produces a monthly management report.

## Core principles
- Raw logs remain immutable in `LokiScanResults/`.
- Derived outputs are written to `runs/YYYY-MM/<run_id>/`.
- Persistent analyst state is stored in `state/triage.db`.
- Loki-native controls should be preferred over local reimplementation when suppression belongs upstream.

## Top-level flow
1. Collect log files from one or more input paths.
2. Reconstruct logical records using the Loki timestamp prefix.
3. Normalize records into typed events with provenance.
4. Derive raw detection candidates from file, process, and init-error events.
5. Upsert raw findings and detection occurrences into SQLite.
6. Collapse raw detections into artifact-centric analyst cases and case occurrences.
7. Reuse analyst verdicts by case identity and mirror case disposition to child detections.
8. Enrich unseen case hashes with batched threaded `vt file --format json <hash...>` lookups and cache `ok`, `not_found`, or `error` results.
9. Generate machine-readable exports and an executive HTML/PDF report with explicit VT coverage state.

## Repository layout
- `config/`: versioned YAML configuration.
- `docs/plans/`: implementation and design docs.
- `src/loki_triage/`: Python package.
- `state/`: SQLite database.
- `runs/`: period and run-scoped derived artifacts.
- `tests/`: fixtures and parser tests.

## CLI contract
- `ingest`: parse and store evidence, write normalized artifacts.
- `enrich-vt`: look up unseen hashes and cache responses.
- `review queue`: inspect current case-centric triage backlog.
- `review queue --bucket`: switch between actionable, routed, suppressed, and all case views.
- `review show`: inspect one analyst case, its child rules, and its occurrences.
- `review set`: append a case verdict and update current status.
- `export findings --bucket`: emit actionable, routed, suppressed, or full case/raw exports.
- `report build`: write HTML and PDF output and guard against zero VT coverage for actionable hash-bearing cases unless explicitly bypassed.

## Loki-native vs local policy
Use Loki-native controls for suppression when possible:
- `excludes.cfg`
- signature-base false-positive handling
- `--csv`
- `--onlyrelevant`
- score thresholds

Use local YAML for:
- severity and queueing priorities
- reporting thresholds and branding
- local downstream allowlists and analyst-triage policy
- VT quota profiles

## Active local policy scope
- Current repo policy keeps automatic benigning deterministic and routes known non-VT URL findings separately.
- Active allowlists cover:
  - archived `loki_*.(log|txt)` artifacts retained on disk
  - Favorites `.url` shortcut hits routed for separate URL review
  - packaged software sample/static families proven to be deterministic noise in the baseline corpus
  - `RemComSvc.exe` only in `C:\Windows\System32\RemComSvc.exe` or `C:\Windows\SysWOW64\RemComSvc.exe`
  - approved Intel XTU binaries only under `C:\Windows\System32\DriverStore\FileRepository\xtucomponent.inf_amd64_*`
- VT enrichment can raise `needs_followup`, but deterministic local policy is the only path to automatic benign classification or routed non-VT review.

## Report guardrails
- Report generation fails when scoped actionable hash-bearing cases have zero VT coverage unless `--allow-missing-vt` is supplied.
- Report generation also fails when the requested scope includes legacy runs with `finding_occurrences` but no corresponding `case_occurrences`.
- Legacy state must be rebuilt from raw logs before case-centric period reports are trustworthy.

## Fresh rebuild workflow
- For a clean corpus rerun after VT or policy changes, delete the derived state and rerun the full pipeline:
  ```bash
  rm -f state/triage.db
  rm -rf runs/2026-01
  uv run loki-triage ingest LokiScanResults --period 2026-01 --run-kind mixed
  uv run loki-triage enrich-vt --run-id <new-run-id>
  uv run loki-triage report build --period 2026-01
  ```
