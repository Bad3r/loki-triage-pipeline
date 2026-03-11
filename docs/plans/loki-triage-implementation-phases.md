# Loki Triage Implementation Phases

## Phase 1
- Scaffold `uv` project, configs, package layout, and tests.
- Add byte-safe record reconstruction and provenance capture.

## Phase 2
- Implement SQLite schema and ingest pipeline.
- Normalize file, process, init-error, and result events.
- Derive deduplicated findings and host-linked occurrences.

## Phase 3
- Add guided review commands and verdict history.
- Add VT enrichment with conservative throttling and cache reuse.

## Phase 4
- Add exports, HTML report generation, and Chromium PDF rendering.
- Validate the pipeline on the provided evidence corpus.

## Acceptance checks
- Discovers the expected Loki logs.
- Reassembles multiline records.
- Flags truncated runs.
- Reuses findings across months according to the approved identity rules.
- Produces one management-ready HTML/PDF report per period.
