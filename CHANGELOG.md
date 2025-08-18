## 18/08/2025
    - Port vulns: replaced hot-path reads of `VULNS.data` with lock-free `ArcSwap` pointers for `port_vulns`, `http_ports`, and `https_ports`; writer atomically publishes new maps on update; readers bypass the `RwLock` entirely.
    - Contention: eliminated "Read lock ... took too long to acquire" warnings during updates under high concurrency.
    - Initialization: added `ensure_port_vulns_initialized()` so tests and early helper calls populate the `ArcSwap` pointers deterministically.
    - Caches: preserved existing caches but removed dependency on model reads when they miss; helpers now use the lock-free maps for misses.
    - Dependency: added `arc-swap = "1.6"` to `flodbadd`.

## 18/08/2025 - https://github.com/edamametechnologies/flodbadd/pull/2
    - Add a method to create an empty whitelist

## 17/08/2025
    Analyzer/Tests overhaul for long-run stability and improved detection quality:
    - Analyzer: align threshold computation with classification API; exclude blacklisted/anomalous from training; avoid refreshing `last_modified` unless criticality changes; change downsampling to flow-signature (keep first snapshot); reduce training/threshold recalc to 6h.
    - Analyzer: feature scaling tuned — `Bytes` linear, `Duration`/`Packets` linear; lower z-threshold for `SegmentInterarrival` (1.5) to improve beacon sensitivity.
    - Tests: added `tests/common.rs` helpers (baseline percentile calibration, score band checks, diagnostics assertions) and expanded diagnostics checks (exfil/scan/dns/beacons).
    - Analyzer: increased model dimensionality from 10D → 12D by adding `Segments` and `DstPort` features; updated `FEATURE_DEFS`, sanitization, and scoring to match.
    - Docs: updated `ANALYZER.md` to reflect 12D feature vector, per-flow downsampling, and diagnostic details; clarified timing features.
    - Tests: calibrated `test_basic_anomaly_detection_debug` thresholds from baseline to remain stable without the heuristic; all anomaly tests passing.

## 16/08/2025
    - Capture: enforce single-worker recomputation in `update_sessions_internal` and wait on in-flight updates to complete before returning, ensuring consistent reads for `get_blacklisted_sessions`/`get_sessions` after rule changes.
    - Capture: tighten end-of-iteration handling to avoid briefly clearing the in-progress flag between queued passes (removes visibility gap under load).
    - IP: harden IPv6 LAN cache initialisation by skipping invalid prefix 0 entries (prevents misclassification of all IPv6 as local on some Windows/container setups).

## 15/08/2025 - https://github.com/edamametechnologies/flodbadd/pull/1
    - Add Group by IP instead of port when factorizing the whitelist.
    - Add port handling in WhitelistEndpoint to improve clarity and support for single values and ranges.
    - Add whitelist comparison functionality by adding a method to calculate differences between old and new whitelists.
    - Add Changelog.md
    - Add support for pull request workflows.