# Flodbadd

Flodbadd is a comprehensive network visibility and traffic analysis library that powers the EDAMAME security platform. It provides real-time packet capture, session tracking, anomaly detection, and security analysis with cross-platform support.

## Core Architecture

Flodbadd transforms raw network packets into enriched, security-aware sessions and applies multiple layers of analysis:

1. **Packet Capture & Processing** - Platform-specific packet capture with async processing
2. **Session Reconstruction** - Stateful TCP/UDP session tracking with comprehensive statistics
3. **Security Analysis** - Multi-layered threat detection including whitelists, blacklists, and ML-based anomaly detection
4. **Intelligence Enrichment** - ASN, DNS, mDNS, and process attribution

---

## Key Features

### Network Capture & Processing
- **Cross-platform packet capture** - Linux, macOS, Windows via pcap
- **Async/sync capture modes** - Configurable based on platform capabilities
- **Session reconstruction** - Stateful TCP/UDP session tracking with Zeek-style history
- **Real-time DNS correlation** - Passive DNS monitoring and active resolution
- **mDNS discovery** - Local network device discovery via multicast DNS
- **Layer 7 attribution** - Process-to-socket correlation (with optional eBPF on Linux)

### Security Analysis
- **Whitelist engine** - Rule-based traffic validation with inheritance and complex matching
- **Blacklist engine** - IP-based threat feeds with CIDR support and cryptographic signatures
- **Anomaly detection** - On-device ML using Extended Isolation Forest with 10-dimensional feature vectors
- **ASN intelligence** - IPv4/IPv6 autonomous system number lookups
- **Vulnerability correlation** - Port and vendor vulnerability databases

### Performance & Scalability
- **Fully asynchronous** - Built on Tokio for high-performance async I/O
- **Concurrent processing** - Parallel analysis pipelines with work distribution
- **Incremental updates** - Efficient session state tracking and delta processing
- **Caching layers** - Multi-level caching for DNS, ASN, and analysis results

---

## Module Overview

### Core Capture & Processing
- **`capture.rs`** - Main capture orchestration with `FlodbaddCapture` struct
- **`packets.rs`** - Packet parsing and session packet processing
- **`sessions.rs`** - Session data structures and management utilities

### Security Analysis
- **`analyzer.rs`** - ML-based anomaly detection using Isolation Forest
- **`whitelists.rs`** - Rule-based whitelist engine with complex matching
- **`blacklists.rs`** - IP-based blacklist engine with CIDR support

### Network Intelligence
- **`dns.rs`** - Passive DNS packet processing
- **`resolver.rs`** - Active DNS resolution with caching
- **`mdns.rs`** - Multicast DNS discovery for local devices
- **`asn.rs`** / **`asn_db.rs`** - Autonomous System Number lookups
- **`l7.rs`** / **`l7_ebpf.rs`** - Layer 7 process attribution

### Network Discovery
- **`arp.rs`** - ARP-based MAC address resolution (cross-platform)
- **`broadcast.rs`** - ICMP broadcast ping for host discovery
- **`neighbors.rs`** - Neighbor table scanning for device discovery

### Utilities & Data
- **`interface.rs`** - Network interface enumeration and management
- **`ip.rs`** - IP address utilities and local network detection
- **`oui.rs`** - MAC OUI to vendor mapping
- **`port_vulns.rs`** - Port-based vulnerability databases
- **`vendor_vulns.rs`** - Vendor-specific vulnerability tracking
- **`device_info.rs`** - Device information aggregation and management

---

## Anomaly Detection System

Flodbadd implements sophisticated on-device anomaly detection using an Extended Isolation Forest model:

### Feature Engineering
Each network session is converted to a 10-dimensional feature vector:

| Feature | Type | Description |
|---------|------|-------------|
| Process Hash | Categorical | Hash of process name for privacy |
| Duration | Numeric | Session duration in seconds |
| Total Bytes | Numeric | Combined inbound/outbound traffic |
| Total Packets | Numeric | Combined packet count |
| Segment Interarrival | Numeric | Average time between segments |
| Inbound/Outbound Ratio | Numeric | Traffic directionality measure |
| Average Packet Size | Numeric | Mean packet size |
| Destination Service | Categorical | Hash of destination service type |
| Self Destination | Binary | Internal traffic indicator |
| Missed Bytes | Numeric | Packet loss/retransmission indicator |

### Operational Model
- **Warm-up period** - Initial training on baseline traffic (configurable, default 2 minutes)
- **Dynamic thresholds** - Percentile-based thresholds (93rd for suspicious, 95th for abnormal)
- **Continuous learning** - Model retraining with sliding window (300 samples default)
- **Permanent anomaly marking** - Once marked as anomalous, sessions never revert to normal status
- **Non-destructive analysis** - Preserves existing security tags while adding anomaly classifications

### Criticality Tagging
Sessions receive comma-separated criticality tags:
- `anomaly:normal` - Normal behavior (only for sessions never marked as anomalous)
- `anomaly:suspicious` - 93rd+ percentile anomaly score
- `anomaly:abnormal` - 95th+ percentile anomaly score
- `blacklist:<list_name>` - Matches IP blacklist
- Multiple tags can coexist (e.g., `anomaly:suspicious,blacklist:malware_c2`)

**Important**: Once a session is marked as `suspicious` or `abnormal`, it maintains that anomalous status permanently, even if subsequent model scoring would classify it as normal. This prevents security-relevant anomalies from being masked by model retraining or threshold changes. Sessions can still transition between `suspicious` and `abnormal` states based on updated scoring.

---

## Whitelist System

### Flexible Matching Rules
Whitelist endpoints support multiple matching criteria:
- **Domain matching** - Exact domain or wildcard patterns
- **IP matching** - Individual IPs or CIDR ranges
- **Port/Protocol** - Specific or wildcard port/protocol combinations
- **ASN matching** - Autonomous System criteria
- **Process matching** - Application-level filtering

### Inheritance & Composition
- **Extends mechanism** - Whitelists can inherit from other whitelists
- **Conflict resolution** - Clear precedence rules for overlapping criteria
- **Custom overrides** - Organization-specific rules can extend standard lists

### JSON Format Example
```json
{
  "date": "2024-01-01",
  "signature": "cryptographic-signature",
  "whitelists": [{
    "name": "corporate_whitelist",
    "extends": ["base_whitelist"],
    "endpoints": [{
      "domain": "*.company.com",
      "port": 443,
      "protocol": "TCP",
      "description": "Corporate HTTPS traffic"
    }]
  }]
}
```

---

## Installation & Usage

### Dependencies
```toml
[dependencies]
flodbadd = { path = ".", features = ["packetcapture"] }
```

### Key Features
- `packetcapture` - Enable live packet capture (requires elevated privileges)
- `asyncpacketcapture` - Async packet capture mode (Linux/macOS/Windows)
- `ebpf` - Linux eBPF acceleration for L7 attribution

### Basic Usage

#### Interface Discovery
```rust
use flodbadd::interface::get_valid_network_interfaces;

let interfaces = get_valid_network_interfaces();
for interface in &interfaces.interfaces {
    println!("Interface: {} - IPv4: {:?}", interface.name, interface.ipv4);
}
```

#### Session Capture
```rust
use flodbadd::capture::FlodbaddCapture;
use flodbadd::interface::get_valid_network_interfaces;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let interfaces = get_valid_network_interfaces();
    let capture = FlodbaddCapture::new();
    
    capture.start(&interfaces).await;
    
    // Let it capture for 30 seconds
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    
    let sessions = capture.get_sessions(false).await;
    println!("Captured {} sessions", sessions.len());
    
    capture.stop().await;
    Ok(())
}
```

#### Anomaly Detection
```rust
use flodbadd::analyzer::SessionAnalyzer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let analyzer = SessionAnalyzer::new();
    analyzer.start().await;
    
    // Analyze sessions (from capture or other source)
    let mut sessions = vec![/* session data */];
    let result = analyzer.analyze_sessions(&mut sessions).await;
    
    println!("Found {} anomalous sessions", result.anomalous_count);
    
    let anomalous = analyzer.get_anomalous_sessions().await;
    for session in anomalous {
        println!("Anomalous: {} -> {} ({})", 
                 session.session.src_ip, 
                 session.session.dst_ip, 
                 session.criticality);
    }
    
    analyzer.stop().await;
    Ok(())
}
```

#### Security Analysis
```rust
// Check blacklist status
let blacklisted = capture.get_blacklisted_sessions(false).await;
println!("Blacklisted sessions: {}", blacklisted.len());

// Check whitelist conformance
let conformant = capture.get_whitelist_conformance().await;
if !conformant {
    let exceptions = capture.get_whitelist_exceptions(false).await;
    println!("Non-conforming sessions: {}", exceptions.len());
}

// Set custom blacklists
let custom_blacklist = r#"{
    "date": "2024-01-01",
    "signature": "test-signature",
    "blacklists": [{
        "name": "custom_threats",
        "ip_ranges": ["192.168.1.100/32", "10.0.0.0/8"]
    }]
}"#;
capture.set_custom_blacklists(custom_blacklist).await?;
```

---

## Platform Support & Requirements

### Supported Platforms
- **Linux** - Full feature support including eBPF acceleration
- **macOS** - Full feature support with native packet capture
- **Windows** - Full feature support via WinPcap/Npcap
- **iOS/Android** - Limited support (no raw packet capture)

### Privileges Required
- **Linux** - `CAP_NET_RAW` capability or root for packet capture
- **macOS** - Root privileges or packet capture entitlements
- **Windows** - Administrator privileges and Npcap installation

### Performance Characteristics
- **Memory usage** - Configurable session limits with automatic cleanup
- **CPU usage** - Multi-threaded processing with configurable worker pools
- **Network overhead** - Minimal - passive monitoring with optional active probing
- **Storage** - In-memory operation with optional persistence layers

---

## Testing & Validation

### Comprehensive Test Suite
- **Unit tests** - Individual module functionality
- **Integration tests** - End-to-end capture and analysis workflows
- **Anomaly detection tests** - ML model validation with synthetic scenarios
- **Cross-platform tests** - Platform-specific functionality verification

### Running Tests
```bash
# All tests with packet capture features
cargo test --features packetcapture

# Specific test categories
cargo test --features packetcapture anomaly_test
cargo test --features packetcapture metrics_test

# Performance tests
cargo test --release --features packetcapture -- --ignored
```

---

## Security Considerations

### Privacy Protection
- **No raw data storage** - Only statistical features retained for ML
- **Hash-based categorization** - Process names and services hashed for privacy
- **Local processing** - All analysis performed on-device
- **Configurable retention** - Automatic session cleanup with configurable timeouts

### Network Security
- **Privilege separation** - Minimal required privileges for operation
- **Input validation** - Comprehensive packet and configuration validation
- **Resource limits** - Built-in protections against resource exhaustion
- **Cryptographic verification** - Signed threat intelligence feeds

---

## Contributing & Development

### Code Structure
- Well-documented modules with clear separation of concerns
- Comprehensive error handling with context preservation  
- Async-first design with efficient resource management
- Platform abstractions for cross-platform compatibility

### Development Setup
```bash
git clone <repository>
cd flodbadd
cargo build --all-features
cargo test --all-features
```

---

## License

Licensed under the Apache License, Version 2.0.