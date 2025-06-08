# Anomaly‐Detection Test Suite

This document explains the synthetic tests found in `tests/anomaly_test.rs`.  Each test feeds hand-crafted traffic patterns into the `SessionAnalyzer` in order to verify that the anomaly-detection logic works, that pre-existing blacklist tags are respected and that the **production** thresholds are not modified by the more aggressive **test** thresholds.

## 1. Synthetic traffic generators

Traffic is synthesised with helper functions that mimic common benign and malicious patterns:

| Function | Pattern | Notable characteristics |
|----------|---------|-------------------------|
| `generate_normal_web_traffic` | Everyday HTTPS browsing | 2–12 s connections on port 443, realistic byte/packet counts, Chrome user agent |
| `generate_beacon_traffic` | Command-and-control beacon | Periodic (1 min – 5 min) 128 B requests, port 8443, completed *SF* handshake |
| `generate_exfiltration_traffic` | Data exfil over SSH | ~8 GB uploaded over 45 min, port 22 |
| `generate_port_scan_traffic` | TCP port scan (Nmap-like) | Rapid SYN probes to 13 common ports |
| `generate_dns_tunnel_traffic` | DNS tunnelling (iodine) | 100 kB queries/responses, 30 s duration, port 53 |
| `generate_cryptomining_traffic` | Stratum mining traffic | 5 GB each way over 5 h, long-lived TCP sessions |

Each generator fills the `SessionInfo` structure closely enough that the random-forest model can learn from the **normal** subset and subsequently flag the outliers.

## 2. Per-test overview

| Test | Purpose | Expected outcome |
|------|---------|------------------|
| `test_c2_beacon_detection` | Detect 10 beacon sessions hidden among 50 normal sessions | At least one beacon flagged as `suspicious` or `abnormal` |
| `test_data_exfiltration_detection` | Spot a single 8 GB SSH upload | Exfil session should not be tagged `anomaly:normal` |
| `test_port_scan_detection` | Identify 13 short SYN probes | ≥ 1 scan tagged anomalous |
| `test_dns_tunnel_detection` | Flag oversize DNS queries | ≥ 1 tunnel tagged anomalous |
| `test_cryptomining_detection` | Catch long-running Stratum traffic | ≥ 1 miner tagged anomalous |
| `test_mixed_anomaly_detection` | Stress-test with **all** patterns mixed & shuffled | Some anomalies found; < 10 false-positive Chrome sessions |
| `test_blacklist_preservation` | Verify pre-existing `blacklist:*` tags survive re-analysis | All three tags remain present |
| `test_basic_anomaly_detection_debug` | Simple sanity check with extreme outliers | Diagnostic prints show scores & thresholds |
| `test_minimal_anomaly` | Edge-case: 100 baseline + 1 extreme outlier | Outlier assigned non-empty criticality |

### Test thresholds
The tests temporarily switch to more sensitive thresholds:

```rust
analyzer.set_test_thresholds(0.60, 0.72); // suspicious, abnormal
```

These **do not** affect production builds.

## 3. Running the tests

The anomaly tests are conditionally compiled behind the `packetcapture` feature and are grouped with the *anomaly* filter:

```bash
# From the flodbadd crate root
cargo test --features packetcapture anomaly -- --nocapture
```

* `--features packetcapture` enables pcap-related dependencies required by the `SessionAnalyzer` implementation.
* `anomaly` filters the test names so that only the heavy synthetic tests run.
* `--nocapture` lets you see the extensive debug output (warm-up status, per-session criticality, scores, etc.).

> **Tip:** Compilation can take a while the first time because the test crate pulls in `tokio`, `rand`, `chrono`, `uuid`, etc. Subsequent runs are much faster.

## 4. Troubleshooting

• **Warm-up timeouts** – If you see `⚠️  analyser did not finish warm-up within …`, the model took longer than the specified 180 s. Increase the timeout or feed more baseline sessions.

• **No anomalies detected** – The synthetic patterns might still be within learned norms. Tighten the test thresholds or exaggerate the generator parameters.

• **Too many false positives** – The mixed test asserts that < 10 normal Chrome sessions are flagged. If this fails, revisit generator realism or threshold selection.

---
Maintainer: *Security & ML Team* – feel free to update this document when adding new anomaly tests or adjusting traffic generators. 