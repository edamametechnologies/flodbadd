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
  Optional eBPF datapath on Linux for even higher throughput (feature: `ebpf`).
* Stateful TCP/UDP session reconstruction with byte / packet counters, RTT estimation, history flags (Zeek-style).
* Real-time DNS correlation, mDNS discovery and L7 process attribution.
* Built-in whitelist / blacklist engine that can ingest Zeek JSON as well as EDAMAME-formatted rules.
* On-device anomaly detection powered by an **extended Isolation Forest** model with automatic warm-up & threshold tuning.
* Huge, compressed lookup tables packaged as const-data for:
  * MAC OUI → vendor (≈2 MB)
  * ASN IPv4 / IPv6 ranges (≈40 MB)  
  * Common port & vendor vulnerability references
* Fully asynchronous (`tokio`) throughout – optimized for running inside an existing async runtime.

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
    let mut capture = FlodbaddCapture::new();
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

## Security & Privileges

* Packet capture requires elevated privileges on most platforms:  
  *Linux* – run as `root` or grant `CAP_NET_RAW`/`CAP_NET_ADMIN`.  
  *macOS* – run as `root` or use the *Packet PEEK* entitlement.  
  *Windows* – install Npcap in "WinPcap compatible" mode.
* Always ensure you have authorization to capture traffic on the network you are analysing.

---

## License

Flodbadd is released under the Apache 2.0 license.