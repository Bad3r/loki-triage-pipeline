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

## Raw detection identity
- Hash-bearing findings: `sha256 + normalized_rule_key`
- Non-hash findings: `normalized_context_fingerprint + normalized_rule_key`

## Analyst case identity
- File cases: `sha256` when available, otherwise normalized artifact path
- Non-file cases: normalized context fingerprint, then artifact path fallback
- A case may contain multiple child rule matches through `case_memberships`

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
- `cases`
- `case_memberships`
- `case_occurrences`
- `case_verdicts`
- `vt_lookups`
- `report_runs`

## VT cache semantics
- `vt_lookups.result_status = 'ok'`: VT returned a record and cached summary data.
- `vt_lookups.result_status = 'not_found'`: VT lookup completed but VT had no public record for the hash.
- `vt_lookups.result_status = 'error'`: VT lookup failed or returned an unexpected non-JSON response.
- Missing lookup row means no enrichment has been attempted yet for that hash/profile.
- The active runtime profile is currently `public_safe`; lookup rows remain keyed by profile so the same hash can be cached separately under different quota strategies if needed.

## Verdict lifecycle
- Case verdicts are append-only.
- `cases.current_disposition` mirrors the latest case verdict or automatic policy result.
- `findings.current_disposition` mirrors the parent case for raw-export convenience.
- Automatic policy reevaluation never overwrites cases whose `disposition_source` is `analyst`.
- Run-to-run occurrence states are derived for both raw detections and analyst cases as `new`, `persisting`, `reopened`, and `cleared` based on host timelines.
