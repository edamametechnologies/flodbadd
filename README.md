# Flodbadd

Flodbadd is the network-visibility and traffic-analysis library that powers the EDAMAME security platform.

It turns raw packets into enriched, security-aware *sessions*, tracks those sessions over time and applies
rule-based (whitelists / blacklists) as well as statistical (Isolation-Forest) analysis – all with a focus on
high throughput and cross-platform support.

> **Heads-up:** The high-level LAN / port-scanning helpers are currently hosted in the `edamame_core` crate.  They
> will be re-exported from Flodbadd in an upcoming release.  In the meantime Flodbadd concentrates on capture,
> session processing and analytics.

---

## Feature Highlights

* Zero-copy packet capture on Linux, macOS and Windows (via `pcap`)  
  Optional eBPF datapath on Linux for even higher throughput (feature: `ebpf`) (work in progress).
* Stateful TCP/UDP session reconstruction with byte / packet counters, RTT estimation, history flags (Zeek-style).
* Real-time DNS correlation, mDNS discovery and L7 process attribution.
* Built-in whitelist / blacklist engine that can ingest EDAMAME-formatted rules.
* On-device anomaly detection powered by an **extended Isolation Forest** model with automatic warm-up & threshold tuning.
* Lookup tables for:
  * MAC OUI → vendor
  * ASN IPv4 / IPv6 ranges
  * Common port & vendor vulnerability references (dynamically updated)
* Fully asynchronous (`tokio`) throughout – optimized for running inside an existing async runtime.

## Anomaly Detection internals (Isolation Forest)

Flodbadd does **per-session behavioural anomaly detection** entirely on-device via a
pure-Rust [extended
Isolation Forest](https://crates.io/crates/extended_isolation_forest) implementation.  Each
`SessionInfo` is converted into a **fixed 10-dimensional feature vector** (no raw IPs/domains are
used – keeping the model privacy-friendly and generalisable):

| # | Feature | Type | Notes |
|---|----------|------|-------|
| 1 | Process name hash | categorical → numeric | Stable 64-bit hash of `process_name` |
| 2 | Session duration | numeric | Seconds between first packet and last activity |
| 3 | Total bytes | numeric | Inbound + outbound |
| 4 | Total packets | numeric | Inbound + outbound |
| 5 | Segment inter-arrival | numeric | Average gap (ms) between TCP segments |
| 6 | Inbound / outbound ratio | numeric | Traffic directionality |
| 7 | Average packet size | numeric | Bytes ÷ packets |
| 8 | Destination service hash | categorical → numeric | Hash of `dst_service` (e.g. "https", "dns") |
| 9 | Self-destination flag | numeric (0/1) | `1.0` when talking to ourselves |
| 10 | Missed bytes | numeric | Retransmissions / packet-loss indicator |

Operational details:

* **Warm-up** – first minute(s) used to collect a baseline and train the forest.
* **Dynamic thresholds** – suspicious ≥ 93rd percentile; abnormal ≥ 95th percentile (defaults can
  be overridden or dynamically re-calculated).
* **Non-destructive tagging** – existing `blacklist:*` tags are preserved when the analyzer writes
  its `anomaly:{normal|suspicious|abnormal}` tag.
* **Sliding window** – keeps the last 300 samples by default; retrains periodically or when
  sufficient fresh data is available.

---

## Installation

Add Flodbadd to your `Cargo.toml`:

```toml
[dependencies]
flodbadd = { git = "https://github.com/edamametechnologies/flodbadd", default-features = false, features = ["packetcapture"] }
```

Key optional features:

* `packetcapture` – enable live packet capture via **pcap** (required for `FlodbaddCapture`).
* `asyncpacketcapture` – same as above but uses an async `pcap` stream (experimental).
* `ebpf` – Linux-only, accelerates capture & process lookup using eBPF + `aya`.
* `examples` – pulls in `clap`, `tracing-subscriber`, `rayon` and registers the example binaries.

---

## Quick Start

### Enumerate local interfaces

```rust
use flodbadd::ip::get_all_interfaces;

fn main() -> anyhow::Result<()> {
    let interfaces = get_all_interfaces()?;
    for iface in &interfaces {
        println!("{} → {}", iface.name, iface.ip);
    }
    Ok(())
}
```

### Capture & list sessions

```rust
use flodbadd::capture::FlodbaddCapture;
use flodbadd::ip::get_all_interfaces;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Pick the interfaces you want to listen on
    let interfaces = get_all_interfaces()?;

    // 2. Start capture
    let capture = FlodbaddCapture::new();
    capture.start(&interfaces).await;

    // 3. Let it run for a while…
    sleep(Duration::from_secs(30)).await;

    // 4. Fetch sessions (set `incremental = false` to get the full table)
    let sessions = capture.get_sessions(false).await;
    println!("captured {} sessions", sessions.len());

    // 5. Done
    capture.stop().await;
    Ok(())
}
```

### Detect anomalies

```rust
use flodbadd::{SessionAnalyzer, AnalysisResult};
use flodbadd::sessions::SessionInfo;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create & start the analyzer
    let analyzer = Arc::new(SessionAnalyzer::new());
    analyzer.start().await;

    // feed it some sessions (from capture or elsewhere)
    let mut sessions: Vec<SessionInfo> = /* … */ Vec::new();
    let AnalysisResult { anomalous_count, .. } = analyzer.analyze_sessions(&mut sessions).await;
    println!("found {anomalous_count} anomalous sessions");

    analyzer.stop().await;
    Ok(())
}
```

---

## Running the bundled examples

Compile & run with all the helper CLIs enabled:

```bash
# Clone the repo
$ git clone https://github.com/edamametechnologies/flodbadd.git
$ cd flodbadd

# LAN scanning (device discovery)
$ cargo run --example lan_scan --features "examples packetcapture"

# Live session capture
$ cargo run --example capture_sessions --features "examples packetcapture" -- --duration 30

# Create / check whitelists
$ cargo run --example whitelist_management --features "examples packetcapture" create

# Real-time anomaly detection
$ cargo run --example session_analyzer --features examples
```

---

## Module Overview

* `capture`        – packet capture & session table maintenance (`FlodbaddCapture`)
* `sessions`       – data-structures for `Session`, `SessionInfo` and helpers (formatting, filters …)
* `analyzer`       – statistical anomaly detection (`SessionAnalyzer`)
* `whitelists`     – rule engine + helpers for whitelist conformance
* `blacklists`     – curated threat feeds and rule-helpers
* `l7` / `l7_ebpf` – OS process → socket correlation (fallback & eBPF back-ends)
* `dns`, `resolver` – passive DNS decoding + active asynchronous resolver
* `ip`, `interface` – cross-platform interface & address enumeration utilities
* `mdns`, `arp`, `broadcast` – helper tasks for local-network discovery
* `asn`, `oui`, `port_vulns`, `vendor_vulns` – static lookup databases

---

## Test & Verification

Flodbadd ships with an extensive, **self-contained test-suite** that exercises both the high-level
anomaly detection logic and the low-level statistics pipeline.

### 1. Synthetic anomaly-detection suite  (`tests/anomaly_test.rs`)

The suite fabricates realistic traffic patterns (normal web browsing, DNS tunnelling, C2 beacons,
port-scans, data-exfiltration, cryptomining …) and feeds them into the `SessionAnalyzer`.
It then checks that the **extended Isolation Forest** model correctly flags the malicious sessions
while keeping false-positives in check.

Key properties:
* Automatic warm-up with dynamic thresholds – the tests wait until the model is ready.
* Per-scenario assertions ("at least one beacon must be flagged", "< 10 normal Chrome sessions
  may be false-positive", …).
* Runs with more sensitive thresholds (`analyzer.set_test_thresholds(0.60, 0.72)`) so that the real
  production thresholds can remain conservative.

### 2. Statistics pipeline sanity test  (`tests/metrics_test.rs`)

This multi-threaded test injects hand-crafted TCP packets straight into the packet-processing
pipeline and ensures that:
* Byte / packet counters add up
* Ratio, average-packet-size and segment-inter-arrival calculations are correct
* Session duration and FIN handling behave as expected

> The metrics test is only compiled when the `packetcapture` feature is enabled **and** the target
> platform is supported (macOS, Linux or Windows).

### 3. Running the tests

```bash
# Run synthetic anomaly tests (shows verbose debug output)
cargo test --features packetcapture anomaly -- --nocapture

# Run the metrics pipeline test (serial, multi-thread)
cargo test --features packetcapture metrics -- --nocapture

# Run **everything**
cargo test --all-features -- --nocapture
```

---

## Blacklist System (quick overview)

Flodbadd contains a flexible IP-based blacklist engine.
Highlights:

* **Custom & global lists** – load trusted feeds plus your own organisation-specific ranges.
* **CIDR aware** – IPv4 & IPv6, individual IPs or whole prefixes.
* **Cryptographically signed JSON** format with `date` / `signature` metadata.
* Runtime helper `is_ip_blacklisted(ip, custom_lists)` returns both a boolean and the matching list
  names, making it trivial to surface *why* traffic was blocked.

Blacklists integrate tightly with the `SessionAnalyzer`: pre-existing `blacklist:*` tags are
preserved during re-analysis and surfaced via `analyzer.get_blacklisted_sessions()`.

### Data structures

```rust
// Main blacklist container
struct Blacklists {
    date: String,
    signature: String,
    blacklists: CustomDashMap<String, BlacklistInfo>,
    parsed_ranges: CustomDashMap<String, Vec<IpNet>>,
}

struct BlacklistInfo {
    name: String,
    description: Option<String>,
    last_updated: Option<String>,
    source_url: Option<String>,
    ip_ranges: Vec<String>,
}
```

### Example JSON

```jsonc
{
  "date": "2025-03-29",
  "signature": "<ed25519-sig>",
  "blacklists": [
    {
      "name": "basic_blocklist",
      "description": "Basic malicious IPs blocklist",
      "last_updated": "2025-03-29",
      "source_url": "https://example.com/blacklist-source",
      "ip_ranges": [
        "192.168.0.0/16",
        "10.0.0.0/8"
      ]
    }
  ]
}
```

### IP-matching algorithm (simplified)

```text
function is_ip_in_blacklist(ip_str, blacklist_name):
    ip     ← parse_ip_address(ip_str)
    ranges ← get_all_ip_ranges(blacklist_name)
    for range in ranges:
        if range.contains(ip):
            return true
    return false
```

The asynchronous helper `is_ip_blacklisted(ip, custom_lists)` combines **custom** and **global**
lists and returns both a boolean and the names of every list that matched.

Blacklists integrate tightly with the `SessionAnalyzer`: pre-existing `blacklist:*` tags are
preserved during re-analysis and surfaced via `analyzer.get_blacklisted_sessions()` (handy for UIs
and alerting systems).

---

## Security & Privileges

* Packet capture requires elevated privileges on most platforms:  
  *Linux* – run as `root` or grant `CAP_NET_RAW`/`CAP_NET_ADMIN`.  
  *macOS* – run as `root` or use the *Packet PEEK* entitlement.  
  *Windows* – install Npcap in "WinPcap compatible" mode.
* Always ensure you have authorization to capture traffic on the network you are analysing.

---

## License

Flodbadd is released under the Apache 2.0 license.