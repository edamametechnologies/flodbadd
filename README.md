# Flodbadd

A high-performance network scanning and session monitoring library for Rust, extracted from the EDAMAME security platform.

## Overview

Flodbadd provides comprehensive network monitoring capabilities including:
- **LAN Scanning**: Discover devices on local networks with port scanning and service detection
- **Session Capture**: Monitor network connections with L7 process information
- **Whitelist Management**: Create and enforce network access policies
- **Blacklist Detection**: Identify and alert on malicious connections
- **Cross-platform Support**: Works on Linux, macOS, and Windows

## Features

- Fast, concurrent network scanning with customizable parallelism
- Deep packet inspection with protocol detection
- Process-level network visibility (who's making connections)
- mDNS/Bonjour service discovery
- MAC address vendor lookup
- Whitelist/blacklist rule engine
- Export to Zeek/Bro format for SIEM integration

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
flodbadd = { git = "https://github.com/edamame/flodbadd.git" }
```

For packet capture features:
```toml
[dependencies]
flodbadd = { git = "https://github.com/edamame/flodbadd.git", features = ["packetcapture"] }
```

## Quick Start

### LAN Scanning

```rust
use flodbadd::ip::get_all_interfaces;
use flodbadd::scanner::{NetworkScanner, ScannerConfig};
use std::time::Duration;

// Get network interfaces
let interfaces = get_all_interfaces()?;

// Configure scanner
let config = ScannerConfig {
    timeout: Duration::from_secs(5),
    concurrent_scans: 100,
    scan_ports: vec![80, 443, 22, 21, 23, 3389],
    enable_mdns: true,
    enable_arp: true,
};

// Start scanning
let mut scanner = NetworkScanner::new(config)?;
scanner.start_scan(&interfaces)?;

// Get results
let devices = scanner.get_discovered_devices()?;
for device in devices {
    println!("Found: {} ({})", device.ip_address, device.hostname);
}
```

### Session Monitoring

```rust
use flodbadd::capture::{PacketCapture, CaptureConfig};
use flodbadd::sessions::format_sessions_zeek;

// Configure capture
let config = CaptureConfig {
    interfaces: get_all_interfaces()?,
    promiscuous: true,
    snaplen: 65535,
    timeout: Duration::from_millis(100),
    buffer_size: 10 * 1024 * 1024,
};

// Start capture
let mut capture = PacketCapture::new(config)?;
capture.start()?;

// Monitor for 60 seconds
thread::sleep(Duration::from_secs(60));
capture.stop()?;

// Get sessions
let sessions = capture.get_sessions()?;
println!("Captured {} sessions", sessions.len());
```

## Examples

Run the examples with:

```bash
# LAN scanning
cargo run --example lan_scan --features examples

# Network capture
cargo run --example capture_sessions --features examples -- --duration 30

# Whitelist management
cargo run --example whitelist_management --features examples create
cargo run --example whitelist_management --features examples check

# Blacklist detection  
cargo run --example blacklist_detection --features examples -- --create
```

See the [examples](examples/) directory for more detailed usage.

## Architecture

Flodbadd is designed as a modular system:

- **Device Info**: Device discovery and fingerprinting
- **Port Info**: Port scanning and service detection  
- **Sessions**: Connection tracking and L7 visibility
- **Vulnerability Info**: Security assessment integration
- **IP Utils**: Network interface and routing utilities
- **Analyzer**: Anomaly detection using Isolation Forest algorithm

The library uses async I/O for high performance and can handle thousands of concurrent operations.

### Session Analyzer

The analyzer module provides real-time anomaly detection for network sessions using machine learning:

```rust
use flodbadd::{SessionAnalyzer, AnalysisResult};

// Create analyzer
let analyzer = Arc::new(SessionAnalyzer::new());
analyzer.start().await;

// Analyze sessions
let result: AnalysisResult = analyzer.analyze_sessions(&mut sessions).await;

println!("Analyzed {} sessions", result.sessions_analyzed);
println!("Found {} anomalous, {} blacklisted", 
         result.anomalous_count, result.blacklisted_count);

// Get anomalous sessions
let anomalous = analyzer.get_anomalous_sessions().await;
for session in anomalous {
    println!("Anomaly: {} -> {} ({})", 
             session.src_ip, session.dst_ip, session.criticality);
}
```

Features:
- Automatic warm-up period for model training
- Dynamic threshold calculation based on network behavior
- Preserves existing classifications (e.g., blacklisted sessions)
- Detailed diagnostics for anomalous sessions

Run the analyzer example:
```bash
cargo run --example session_analyzer --features examples
```

## Security Considerations

- Requires appropriate permissions for packet capture (root/admin)
- Use responsibly and only on networks you own or have permission to scan
- Consider rate limiting in production environments
- Whitelist/blacklist rules should be regularly updated