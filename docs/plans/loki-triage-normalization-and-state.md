# Loki Triage Normalization And State

## Record reconstruction
- A physical line starts a new logical record only when it matches:
  - `^YYYYMMDDTHH:MM:SSZ,<host>,<severity>,<module>,`
- Non-matching lines are continuation payload for the previous record.
- Missing footer marker `NOTICE,Results,Finished LOKI Scan` marks a run as truncated.

## Normalized event types
- `file_finding`
- `process_event`
- `init_error`
- `results_summary`
- `results_advisory`
- `generic_event`

## Provenance
Every normalized event keeps:
- run id
- source log path
- source line start and end
- raw reconstructed event text
- parse warning flags

## Finding identity
- Hash-bearing findings: `sha256 + normalized_rule_key`
- Non-hash findings: `normalized_context_fingerprint + normalized_rule_key`

## Non-hash context fingerprints
- `init_error`: signature file plus error class
- `patched_process`: event kind plus normalized path or process name
- `replaced_process`: event kind plus normalized path or process name
- `listening_process`: event kind plus normalized path or process name plus port
- `priority_anomaly`: event kind plus normalized path or process name
- fallback: canonicalized message with timestamps, PIDs, and IP noise removed

## SQLite entities
- `scan_runs`
- `source_files`
- `normalized_events`
- `findings`
- `finding_occurrences`
- `analyst_verdicts`
- `vt_lookups`
- `report_runs`

## Verdict lifecycle
- Verdicts are append-only.
- `findings.current_disposition` mirrors the latest verdict for queueing speed.
- Run-to-run occurrence states are derived as `new`, `persisting`, `reopened`, and `cleared` based on host timelines.
