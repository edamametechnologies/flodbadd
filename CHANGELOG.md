## 15/08/2025 - https://github.com/edamametechnologies/flodbadd/pull/1
    - Add Group by IP instead of port when factorizing the whitelist.
    - Add port handling in WhitelistEndpoint to improve clarity and support for single values and ranges.
    - Add whitelist comparison functionality by adding a method to calculate differences between old and new whitelists.
    - Add Changelog.md
    - Add support for pull request workflows.

## 16/08/2025
    - Capture: enforce single-worker recomputation in `update_sessions_internal` and wait on in-flight updates to complete before returning, ensuring consistent reads for `get_blacklisted_sessions`/`get_sessions` after rule changes.
    - Capture: tighten end-of-iteration handling to avoid briefly clearing the in-progress flag between queued passes (removes visibility gap under load).
    - IP: harden IPv6 LAN cache initialisation by skipping invalid prefix 0 entries (prevents misclassification of all IPv6 as local on some Windows/container setups).

## 17/08/2025
    Analyzer/Tests overhaul for long-run stability and improved detection quality:
    - Analyzer: align threshold computation with classification API; exclude blacklisted/anomalous from training; avoid refreshing `last_modified` unless criticality changes; change downsampling to flow-signature (keep first snapshot); reduce training/threshold recalc to 6h.
    - Analyzer: feature scaling tuned — `Bytes` linear, `Duration`/`Packets` linear; lower z-threshold for `SegmentInterarrival` (1.5) to improve beacon sensitivity.
    - Tests: added `tests/common.rs` helpers (baseline percentile calibration, score band checks, diagnostics assertions) and expanded diagnostics checks (exfil/scan/dns/beacons).
    - Tests: strengthened scenarios and calibration, added band-based separation in metrics tests; made tests assertive and deterministic; all suites green.
