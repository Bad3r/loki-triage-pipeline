# VT Quota Prioritization and False-Positive Reduction

Date: 2026-03-15

## Executive Summary

The January corpus is too large for a naive VirusTotal enrichment pass. The current `public_safe` profile is capped at `daily_request_limit: 1000`, while the existing backlog contains `37,628` pending unique hash-bearing cases before disposition filtering. At that rate, a full enrichment pass would require at least `38` UTC days even if every request succeeded.

The first low-risk reduction is now implemented in the runtime: reviewed-benign states no longer consume VT quota by default. The current dataset contains `22,369` `expected_benign` pending cases, leaving `15,259` unresolved cases eligible after the new `eligible_dispositions` filter. That cuts the immediate backlog by about `59.4%`, but still leaves more than `15` days of VT work at the current limit, so further false-positive reduction and prioritization remain necessary.

## Current Backlog Shape

Evidence source: `/home/vx/Documents/loki-q1-darah/state/triage.db`, queried on 2026-03-15 against pending `public_safe` lookups scoped to `NOTICE`, `WARNING`, `ERROR`, and `ALERT`.

- Pending hash-bearing cases before disposition filtering: `37,628`
- Pending by disposition:
  - `expected_benign`: `22,369`
  - `unreviewed`: `15,259`
- Pending after the new default VT disposition filter: `15,259`
- Remaining eligible by severity:
  - `ALERT`: `7,274`
  - `WARNING`: `3,624`
  - `NOTICE`: `4,361`
- Remaining eligible by priority:
  - `critical`: `7,274`
  - `high`: `3,624`
  - `low`: `4,361`
- Eligible host spread:
  - `1 host`: `14,373`
  - `2-5 hosts`: `744`
  - `6-20 hosts`: `89`
  - `21-100 hosts`: `42`
  - `101+ hosts`: `11`

Operational implication: the unresolved set is still dominated by single-host artifacts, so lexicographic lookup order wastes budget. Ranking by disposition, priority, score, host spread, occurrence count, and recency is the correct default.

## Dominant Noisy Clusters

### Already neutralized for VT budget

- `id_133015`: `22,304` pending hashes
  - `22,303` are already `expected_benign`
  - overwhelmingly tied to archived `loki_*.log` outputs under `D:\lokiResult*`
  - effect: these no longer spend VT budget after the `eligible_dispositions` change

This cluster validates the current narrow local policy approach: path-and-rule allowlisting can safely suppress obvious archive artifacts without weakening real malware coverage.

### Highest-volume unresolved clusters

- `webshell_asp_generic_eval_on_input`: `4,658`
- `methodology_suspicious_shortcut_iconnotfromexeordllorico`: `3,329`
- `webshell_generic_os_strings`: `3,144`
- `id_74394`: `1,406`
- `id_150742`: `1,403`
- `powershell_susp_parameter_combo`: `1,232`
- `id_123969`: `995`

### Highest-volume unresolved path and rule combinations

- `3,230`: `C:\Users\*` with `methodology_suspicious_shortcut_iconnotfromexeordllorico`
- `3,144`: `D:\lokiResult*` with `webshell_asp_generic_eval_on_input` plus `webshell_generic_os_strings`
- `1,153`: `D:\lokiResult*` with `webshell_asp_generic_eval_on_input` plus `id_74394`
- `995`: `D:\lokiResult*` with `powershell_susp_parameter_combo` plus `id_123969`
- `322`: `C:\Program Files*` with `id_150738`
- `194`: `C:\ProgramData*` with `susp_wer_suspicious_crash_directory`
- `163`: `C:\ProgramData*` with `susp_wer_critical_heapcorruption`

Interpretation:

- `D:\lokiResult*` remains the dominant path prefix overall at `28,908` pending hashes. Some of that volume is already safely suppressed, but additional unresolved hits against archived scan-output directories remain a major source of waste.
- `C:\Users\*` shortcut and roaming-profile clusters are high-volume and mostly single-host. These are strong candidates for path-scoped, product-scoped, or IOC false-positive refinement, not blanket VT lookups.
- `Program Files` and `ProgramData` clusters suggest vendor/software baselines that should be reviewed for narrow local allowlists after sample validation.

## What Was Implemented

- VT runtime now enforces `daily_request_limit` as a UTC per-profile ceiling.
- VT runtime now excludes reviewed-benign dispositions by default:
  - `expected_benign`
  - `false_positive`
- VT runtime now ranks unresolved hashes before lookup using:
  - disposition
  - priority
  - maximum observed score
  - host spread
  - occurrence count
  - recency
  - SHA-256 as a deterministic tie-breaker

This is the correct minimum change because it removes obvious waste without introducing a new suppression engine or changing raw evidence.

## Source-Backed Reduction Levers

### 1. Use Loki path-scoped excludes for stable benign locations

Maintainer-authored Loki guidance documents user-defined excludes via `config/excludes.cfg`, where each line is a case-insensitive regex applied to the full file path during directory walk. That is the right mechanism for stable product directories, archived scan-output paths, and directories that are known to be unsafe to scan aggressively.

Sources:

- https://github.com/Neo23x0/Loki
- https://raw.githubusercontent.com/Neo23x0/Loki/master/config/excludes.cfg

Recommended use in this corpus:

- Prefer path-scoped exclusions for archived Loki output directories only when paired with exact file-pattern or rule-family evidence.
- Do not exclude entire drives or broad Windows locations to solve a localized false-positive problem.

### 2. Tune filename IOC false positives instead of disabling rule families

Loki’s filename IOC format supports an explicit false-positive regex field. If a noisy hit is driven by filename IOC logic, tightening the false-positive regex is safer than disabling the entire IOC family.

Source:

- https://github.com/Neo23x0/Loki

Best fit in this corpus:

- recurring benign installers and vendor update artifacts
- archived log files whose names or contents resemble malicious strings

### 3. Separate scan-scope noise from rule-quality noise

Loki exposes scan-mode flags that materially change what is scanned, including `--intense`, `--scriptanalysis`, `--excludeprocess`, `--noprocscan`, `--nofilescan`, `--nopesieve`, `--nolisten`, and `--vulnchecks`. These should be treated as scope controls, not as an ad hoc fix for specific false positives.

Source:

- https://github.com/Neo23x0/Loki

Recommendation:

- keep baseline runs conservative
- reserve aggressive modes such as `--intense` or beta-like script analysis for explicit hunt workflows

### 4. Prefer YARA rules with structural guards before content checks

Official YARA-X documentation and Neo23x0’s maintainer-authored guidance align on the same point: broad string matching without file-type, size, or header guards is noisy and expensive. Use format-aware conditions, `filesize` gates, and explicit benign filters where possible.

Sources:

- https://virustotal.github.io/yara-x/docs/writing_rules/rule-conditions/
- https://virustotal.github.io/yara-x/docs/modules/pe/
- https://virustotal.github.io/yara-x/docs/writing_rules/text-patterns/
- https://virustotal.github.io/yara-x/docs/writing_rules/undefined-values/
- https://github.com/Neo23x0/YARA-Style-Guide
- https://github.com/Neo23x0/YARA-Performance-Guidelines

Best-fit recommendations for the dominant unresolved clusters:

- add file-type gates before webshell or PE-oriented content checks
- require `filesize` bounds before expensive string or regex evaluation
- use `fullword` where substring matching is causing noisy hits
- treat `nocase`, `xor`, and base64-driven string logic as higher-risk and review-heavy
- use explicit benign markers such as Neo23x0’s `$fp*` pattern where a family has stable benign overlaps
- avoid permissive `or` branches that can still match when module-derived values are undefined

### 5. Keep signature-base portability issues separate from true false positives

The signature-base maintainer explicitly states the focus is high-quality YARA rules and IOCs with minimal false positives, but also notes that some rules rely on external variables and may behave differently outside Loki or THOR Lite. Those portability/runtime issues should be documented separately from detection-quality issues.

Source:

- https://github.com/Neo23x0/signature-base

## Unsafe Suppressions To Avoid

- Do not suppress by severity alone. Loki severity is not proof that a rule is low-value.
- Do not add broad directory excludes like `\\System32\\` or `D:\\lokiResult\\` without file-pattern or rule-family scoping.
- Do not disable an entire rule family when a path-, vendor-, or product-specific refinement is available.
- Do not use VT as the primary mechanism for filtering obvious archived logs or reviewed-benign vendor software.
- Do not disable entire scan subsystems to solve a local false-positive cluster unless the coverage tradeoff is explicitly accepted.

## Validation Method

1. Recompute the pending universe after each local suppression or rule refinement.
2. Compare:
   - pending eligible hash count
   - retained `ALERT` and `WARNING` case counts
   - host-spread distribution of the retained set
   - top-ranked candidates after the change
3. Sample dropped clusters manually before rollout:
   - at least one representative from each affected rule/path cluster
   - at least one multi-host artifact if present
4. Confirm that true positives are still surfaced near the top of the ranked list after suppression.
5. Keep raw logs immutable and store only derived analysis and reports under `reports/` or `runs/`.

## Action Matrix

| Action | Type | Risk | Expected effect |
| --- | --- | --- | --- |
| Enforce UTC daily VT budget per profile | Implemented | Low | Prevents runaway enrichment and makes daily usage predictable |
| Exclude reviewed-benign dispositions from VT by default | Implemented | Low | Removes `22,369` obviously wasted pending lookups immediately |
| Review archived `D:\\lokiResult*\\loki_*.log` clusters for additional path/rule suppressions | Recommended | Low to Medium | Likely removes a large share of webshell-style noise without needing VT |
| Review `C:\\Users\\*` shortcut and roaming-profile clusters for IOC false-positive regex tuning | Recommended | Medium | Reduces large single-host false-positive families |
| Add vendor-scoped allowlists for stable `Program Files` and `ProgramData` software after sample validation | Recommended | Medium | Reduces repeated benign software hits |
| Tighten noisy YARA families with file-type, size, and benign-marker guards | Recommended | Medium | Improves both precision and scan cost over time |

## Bottom Line

The new VT budgeting logic is necessary but not sufficient. The backlog only becomes operationally tractable when VT is reserved for unresolved, higher-priority cases and obvious archive or reviewed-benign artifacts are filtered locally first. The current data strongly supports continued investment in narrow path/rule suppressions and targeted YARA condition hardening rather than broader exclusions or severity-based skipping.
