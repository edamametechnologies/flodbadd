# Flodbadd Anomaly Detection – Design and Operation

This document explains the anomaly detection subsystem in Flodbadd: the algorithmic choices, the Isolation Forest crate we use, and exactly how we train, score, threshold, and diagnose sessions.

## Library

- Algorithm: Extended Isolation Forest (iForest) for outlier detection in tabular data.
- Crate: `extended-isolation-forest` (see the workspace `extended-isolation-forest/`).
- Why: Isolation Forest is robust, fast, and works well on-device with streaming data.

## Feature Engineering (12D)

Each session is converted into a fixed-length vector `[f64; 12]` in `flodbadd/src/analyzer.rs::compute_features()`:

1) Process Hash (categorical hashed → numeric)
2) Duration (seconds)
3) Total Bytes (numeric)
4) Total Packets (numeric)
5) Segment Interarrival (seconds)
6) Inbound/Outbound Ratio (numeric)
7) Average Packet Size (bytes)
8) Interarrival Regularity (0..1)
9) Packet Rate (packets/second)
10) Missed Bytes (numeric)
11) Segments (count)
12) Destination Port (categorical hashed)

Notes:
- Categorical values are hashed and mapped to bounded numeric ranges.
- Heavy‑tailed numerics are currently kept linear (Duration/Bytes/Packets) to preserve separation for extreme cases; Segment Interarrival and Packet Rate capture timing behaviour.
- All features are sanitized; any NaN/Inf becomes 0.0.

## Training Data Pipeline

- Sliding window buffer: `recent_data` (default capacity: 300 samples).
- Deduplication: before training, duplicate feature vectors are removed.
- Downsampling per flow-signature (5‑tuple): repeated snapshots of the same `(protocol, src_ip, src_port, dst_ip, dst_port)` are downsampled (default: keep 1 out of 5). The first snapshot is always kept.
- Exclusions: sessions already tagged as `blacklist:*` or `anomaly:suspicious|abnormal` are excluded from training to avoid contaminating the baseline.
- Sanitization: all inputs are validated prior to insertion.

## Model Hyperparameters

- Trees: 10 (n<10), 15 (n<50), else 25.
- Sample size: min(128, n) with a lower bound of 1.
- Max tree depth: 6 (cap to keep trees shallow and fast).
- Extension level: `NUM_FEATURES - 1` (full extended iForest in 12D).

Training is performed on a blocking thread (spawn_blocking) and the result is integrated atomically when ready.

## Scoring

- API: `forest.score_with_recursion_cap(features, 12)` for all classification decisions.
- A small cache stores recent session scores keyed by UID, invalidated on session updates.
- A periodic cleanup removes stale cache entries.

## Thresholds and Criticality

- Percentile thresholds computed from `recent_data` scores:
  - Suspicious: 93rd percentile
  - Abnormal: 95th percentile
- Consistency: we compute thresholds using the same API as classification (`score_with_recursion_cap(..., 12)`).
- Safety floors: thresholds are bounded by defaults to avoid unrealistic minima.
- Recalculation cadence: at the end of warm‑up and every 6 hours thereafter.

Criticality levels:
- `anomaly:normal`
- `anomaly:suspicious`
- `anomaly:abnormal`

If the threshold boundary is crossed, we attach a diagnostic (see below). Existing non‑anomaly tags (e.g., `blacklist:*`, custom tags) are preserved.

## Warm‑Up

- Purpose: accumulate baseline samples and fit an initial model/thresholds.
- Behavior:
  - Enforce a minimum warm‑up delay and target duration.
  - Ensure any pending training completes.
  - Compute dynamic thresholds, then disable warm‑up.

During warm‑up, sessions are marked with `anomaly:normal/warming_up` (non‑destructive tagging).

## Diagnostics (Why a session is anomalous)

- We compute simple per‑feature statistics (mean/std‑dev) from `recent_data`.
- For numeric features with variance, we compute a z‑score; values with |z| ≥ 2.5 are marked `UnusuallyHigh` or `UnusuallyLow`.
- `SegmentInterarrival` uses a more sensitive threshold (1.5) to catch timing anomalies such as periodic beacons.
- For numeric features with ≈0 variance, any different value is marked `DeviatesFromNorm`.
- For categorical‑encoded features (hashes), we avoid z‑scores. If the training set shows ≈0 variance and the current value differs, it is marked `Unusual`.
- If no specific features stand out but the overall score is high, we return `OverallScoreHigh`.

Examples:
- `anomaly:abnormal/Duration:UnusuallyHigh/Bytes:UnusuallyHigh`
- `anomaly:suspicious/SegmentInterarrival:UnusuallyHigh/PacketRate:UnusuallyHigh`

## Analysis Loop and Throttling

- We avoid re‑analyzing the exact same unmodified session too frequently via `ANALYSIS_DELAY`.
- Re‑analysis occurs if the session changed or the quiet period elapsed.
- Only when the criticality string changes do we update `last_modified`; this allows caches and retention to expire naturally and prevents unbounded growth of anomalous lists.

## Retention and Caches

- We keep three maps: all sessions, anomalous sessions, blacklisted sessions.
- Cleanup compares `last_modified` with retention timeouts.
- Score cache (per UID) is also pruned periodically.

## Cadence and Adaptation

- Training throttling: minimum 6 hours between regular trainings (forced training can occur at warm‑up end and scheduled recalculations).
- Threshold recalculation: every 6 hours.
- These cadences mitigate data drift over day‑long operations without excessive CPU usage.

## Configuration and Testing Hooks

- `downsample_factor`: per‑flow sampling of training vectors (default 5).
- Warm‑up and retrain intervals are constants to keep code simple and safe; can be tuned if needed.
- Test helpers exist to disable warm‑up and set custom thresholds.

## Rationale Summary

- Isolation Forest is a good fit for on‑device, low‑latency outlier detection.
- Log‑scaling heavy‑tailed features stabilizes the model across long runs.
- Excluding blacklisted/anomalous flows from training keeps the baseline clean.
- Using the same scoring API for both thresholding and classification eliminates inconsistent scaling.
- Per‑flow downsampling reduces duplicate snapshots from long‑lived connections.
