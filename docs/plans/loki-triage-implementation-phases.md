# Loki Triage Implementation Phases

## Phase 1
- Scaffold `uv` project, configs, package layout, and tests.
- Add byte-safe record reconstruction and provenance capture.

## Phase 2
- Implement SQLite schema and ingest pipeline.
- Normalize file, process, init-error, and result events.
- Derive raw detections, aggregate analyst cases, and track host-linked occurrences.

## Phase 3
- Add guided review commands and verdict history.
- Add VT enrichment with conservative throttling, batched hash lookups, cache reuse, distinct no-hit handling, and case-policy reevaluation.

## Phase 4
- Add exports, HTML report generation, and Chromium PDF rendering.
- Validate the pipeline on the provided evidence corpus.

## Current Operational Notes
- VT enrichment now assumes batched threaded `vt file` lookups and records distinct `ok`, `not_found`, and `error` outcomes instead of collapsing no-hit hashes into generic failures.
- The active VT profile is `public_safe`; `private_fast` remains available as a higher-throughput profile when the configured VT quota supports it.
- The default VT severity scope is now `WARNING`, `ERROR`, and `ALERT`; `NOTICE` is opt-in through config.
- Fresh January 2026 reruns should start by deleting `state/triage.db` and `runs/2026-01` before re-ingesting to avoid mixing stale derived state into the rebuilt report.
- Current default routing intentionally separates:
  - actionable analyst-facing cases
  - routed Favorites `.url` shortcut findings for separate URL review
  - suppressed deterministic benign families such as archived `loki_*.(log|txt)` outputs, packaged software samples, `RemComSvc.exe`, and Intel XTU DriverStore components

## Acceptance checks
- Discovers the expected Loki logs.
- Reassembles multiline records.
- Flags truncated runs.
- Reuses analyst cases across months according to the approved identity rules.
- Produces one management-ready HTML/PDF report per period.
