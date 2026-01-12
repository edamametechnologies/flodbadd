# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Flodbadd is a network visibility and traffic analysis library powering the EDAMAME security platform. It provides real-time packet capture, session tracking, ML-based anomaly detection, and network discovery across Linux, macOS, and Windows.

Part of the EDAMAME ecosystem - see `../edamame_core/CLAUDE.md` for full ecosystem documentation.

## Documentation Index

- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Module structure, data flow, session tracking
- **[README.md](README.md)** - Overview, installation, usage examples
- **[ANALYZER.md](ANALYZER.md)** - ML anomaly detection (iForest, features, thresholds)
- **[EBPF.md](EBPF.md)** - Linux eBPF process attribution architecture
- **[WHITELISTS.md](WHITELISTS.md)** - Whitelist system design and rules
- **[PROFILES.md](PROFILES.md)** - Device profiling and identification
- **[CDN.md](CDN.md)** - Threat intelligence CDN
- **[CHANGELOG.md](CHANGELOG.md)** - Version history
- **[ebpf/l7_ebpf_program/README.md](ebpf/l7_ebpf_program/README.md)** - eBPF program build

## Build Commands

```bash
# Basic build
cargo build

# With packet capture (requires elevated privileges)
cargo build --features packetcapture

# With async packet capture
cargo build --features packetcapture,asyncpacketcapture

# Linux with eBPF (x86_64/aarch64 only)
cargo build --features packetcapture,asyncpacketcapture,ebpf

# Build examples
cargo build --release --features packetcapture,asyncpacketcapture --examples
```

## Testing

```bash
# macOS (requires sudo)
sudo -E cargo test --features packetcapture,asyncpacketcapture -- --nocapture --test-threads=1

# Linux with eBPF
make ebpf_setup  # Install eBPF dependencies first
sudo -E cargo test --features packetcapture,asyncpacketcapture,ebpf -- --nocapture --test-threads=1

# Specific test suites
cargo test --features packetcapture anomaly_test
cargo test --features packetcapture metrics_test

# Cross-platform testing via Lima VMs (from macOS)
make lima_create && make lima_test
make alpine_create && make alpine_test
```

## Architecture

### Core Capture & Processing
- `capture.rs` - Main orchestration (FlodbaddCapture struct)
- `packets.rs` - Packet parsing and session processing
- `sessions.rs` - Session data structures and management
- `interface.rs` - Network interface enumeration

### Security Analysis
- `analyzer.rs` - Extended Isolation Forest ML anomaly detection (12D feature vectors)
- `whitelists.rs` - Rule-based whitelist engine (domain, IP, port, ASN, process)
- `blacklists.rs` - IP-based blacklist engine with CIDR support

### Network Intelligence
- `dns.rs` - Passive DNS packet processing
- `resolver.rs` - Active DNS resolution with caching
- `mdns.rs` - Multicast DNS discovery
- `asn.rs`, `asn_db.rs` - ASN lookups
- `l7.rs`, `l7_ebpf.rs` - Layer 7 process attribution

### Network Discovery
- `arp.rs` - MAC address resolution
- `broadcast.rs` - ICMP broadcast ping
- `neighbors.rs` - Neighbor table scanning

### Device Intelligence
- `device_info.rs` - Device information aggregation
- `oui.rs` - MAC OUI vendor lookup
- `profiles.rs` - Device type identification
- `port_vulns.rs`, `vendor_vulns.rs` - Vulnerability databases

## Key Features

| Feature | Description |
|---------|-------------|
| `packetcapture` | Live packet capture (requires root/CAP_NET_RAW) |
| `asyncpacketcapture` | Async packet capture mode |
| `ebpf` | Linux eBPF acceleration via Aya (x86_64/aarch64 only) |

## Platform Requirements

- **Linux**: CAP_NET_RAW or root; eBPF requires clang, llvm, libbpf-dev, linux-headers
- **macOS**: Root or packet capture entitlements
- **Windows**: Administrator + Npcap (auto-downloaded during build)

## Examples

Located in `/examples/`:
- `lan_scan.rs` - Local network scanning
- `capture_sessions.rs` - Session capture demo
- `session_analyzer.rs` - Anomaly detection demo
- `check_ebpf.rs` - eBPF availability check

## Local Development

Use `../edamame_app/flip.sh local` to switch to local path dependencies across all repos.
