# Loki Triage Architecture

## Goal
Build a CLI-first Python project that ingests raw Loki scan evidence, reconstructs multiline records, persists reusable triage state, enriches hash-bearing findings with VirusTotal through the `vt` CLI, and produces a monthly management report.

## Core principles
- Raw logs remain immutable in `LokiScanResults/`.
- Derived outputs are written to `runs/YYYY-MM/<run_id>/`.
- Persistent analyst state is stored in `state/triage.db`.
- Loki-native controls should be preferred over local reimplementation when suppression belongs upstream.

## Top-level flow
1. Collect log files from one or more input paths.
2. Reconstruct logical records using the Loki timestamp prefix.
3. Normalize records into typed events with provenance.
4. Derive finding candidates from file, process, and init-error events.
5. Upsert findings and occurrences into SQLite.
6. Reuse analyst verdicts by `sha256 + rule` or `context fingerprint + rule`.
7. Enrich unseen hashes with `vt file --format json`.
8. Generate machine-readable exports and an executive HTML/PDF report.

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
- `review queue`: inspect current triage backlog.
- `review show`: inspect one finding and its occurrences.
- `review set`: append a verdict and update current status.
- `export findings`: emit CSV or JSONL.
- `report build`: write HTML and PDF output.

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
- local downstream suppression notes
- VT quota profiles
