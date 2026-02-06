# Flodbadd Architecture

Network visibility and traffic analysis library powering the EDAMAME security platform.

## Overview

Flodbadd transforms raw network packets into enriched, security-aware sessions and applies multiple layers of analysis:

1. **Packet Capture** - Platform-specific capture (pcap/Npcap/eBPF)
2. **Session Reconstruction** - Stateful TCP/UDP tracking with Zeek-style history
3. **Security Analysis** - Whitelists, blacklists, ML anomaly detection
4. **Intelligence Enrichment** - ASN, DNS, mDNS, process attribution

## Module Structure

```
src/
├── capture.rs          # Main orchestration (FlodbaddCapture)
├── packets.rs          # Packet parsing and session processing
├── sessions.rs         # Session data structures
├── interface.rs        # Network interface enumeration
│
├── analyzer.rs         # Extended Isolation Forest ML (12D features)
├── whitelists.rs       # Rule-based whitelist engine
├── blacklists.rs       # IP-based blacklist with CIDR
│
├── dns.rs              # Passive DNS processing
├── resolver.rs         # Active DNS with caching
├── mdns.rs             # Multicast DNS discovery
├── asn.rs              # ASN lookups
├── l7.rs               # L7 process attribution (netstat)
├── l7_ebpf.rs          # L7 via eBPF (Linux)
├── dns_ebpf.rs         # DNS via eBPF (Linux)
│
├── arp.rs              # MAC address resolution
├── broadcast.rs        # ICMP broadcast ping
├── neighbors.rs        # Neighbor table scanning
│
├── device_info.rs      # Device information aggregation
├── oui.rs              # MAC OUI vendor lookup
├── profiles.rs         # Device type identification
├── port_vulns.rs       # Port vulnerability database
└── vendor_vulns.rs     # Vendor vulnerability tracking
```

## Data Flow

```
Raw Packet → Parse → Normalize Direction → Update Session Stats
                                               │
              ┌────────────────────────────────┼────────────────────────────────┐
              ↓                                ↓                                ↓
         ASN Lookup                    DNS Lookup (passive/active)       L7 Resolution
              │                                │                                │
              └────────────────────────────────┼────────────────────────────────┘
                                               ↓
                                    Anomaly Scoring (iForest)
                                               │
                                               ↓
                                    Whitelist/Blacklist Matching
                                               │
                                               ↓
                                    Session with Criticality Tag
```

## Session Tracking

```rust
struct SessionInfo {
    session: Session,  // 5-tuple: protocol, src_ip, src_port, dst_ip, dst_port
    stats: SessionStats {
        start_time, end_time, last_activity,
        inbound_bytes, outbound_bytes,
        orig_pkts, resp_pkts,
        segment_count, segment_interarrival,
        history: String,  // Zeek-style: "ShADaFf" (capped at 1000 chars)
        conn_state: String,  // "SF", "S0", "REJ"
    },
    l7: Option<SessionL7> { pid, process_name, process_path, cmd, memory },
    src_asn, dst_asn,
    src_domain, dst_domain,
    is_whitelisted: WhitelistState,
    criticality: String,  // "anomaly:abnormal,blacklist:malware_c2"
}
```

## Session Fetching API

Sessions can be retrieved with either full or incremental fetching:

```rust
// Full fetch - returns all sessions (useful on startup/restart)
let all_sessions = capture.get_sessions(false).await;

// Incremental fetch - returns only sessions modified since last fetch
let new_sessions = capture.get_sessions(true).await;
```

**API methods supporting incremental mode:**

| Method | Description |
|--------|-------------|
| `get_sessions(incremental)` | All historical sessions |
| `get_current_sessions(incremental)` | Active sessions (within `CONNECTION_CURRENT_TIMEOUT`) |
| `get_blacklisted_sessions(incremental)` | Sessions matching blacklist rules |
| `get_whitelist_exceptions(incremental)` | Sessions not matching whitelist |

**Incremental fetch behavior:**
- Each method tracks its own `last_fetch_timestamp`
- When `incremental=true`: returns sessions where `last_modified > last_fetch_timestamp`
- Timestamp is updated after **every** fetch (both full and incremental)
- Sessions are only returned once unless they are modified again
- Use `incremental=false` on startup to establish baseline, then `true` for polling

**Typical usage pattern:**
```rust
// Initial full fetch to get current state
let sessions = capture.get_sessions(false).await;
analyzer.analyze_sessions(&mut sessions).await;

// Subsequent polls - only get new/modified sessions
loop {
    tokio::time::sleep(Duration::from_secs(5)).await;
    let new_sessions = capture.get_sessions(true).await;
    if !new_sessions.is_empty() {
        analyzer.analyze_sessions(&mut new_sessions).await;
    }
}
```

## Memory Management and Retention

### Session Retention

Sessions are managed with time-based retention policies defined in `sessions.rs`:

| Timeout | Duration | Purpose |
|---------|----------|---------|
| `CONNECTION_ACTIVITY_TIMEOUT` | 60s | Session considered "active" if activity within this window |
| `CONNECTION_CURRENT_TIMEOUT` | 180s | Session included in "current sessions" list |
| `CONNECTION_RETENTION_TIMEOUT` | 8 hours | Session pruned after no activity for this duration |

**Key behavior:**
- Active sessions (receiving packets) are never pruned - this is correct behavior
- Inactive sessions are pruned after 8 hours of no activity
- The `update_sessions_status()` function in `capture.rs` handles pruning

### Bounded Data Structures

To prevent unbounded memory growth on high-activity devices:

| Structure | Location | Limit | Notes |
|-----------|----------|-------|-------|
| `history` string | `SessionStats` | 1000 chars | TCP flag sequence, capped to prevent growth on long-lived connections |
| `dns_resolutions` | `dns.rs` | 50,000 entries | LRU eviction (oldest 10%) when exceeded |
| `dns_resolutions_with_process` | `dns.rs` | 50,000 entries | LRU eviction (oldest 10%) when exceeded |
| `reverse_dns` | `resolver.rs` | 50,000 entries | LRU eviction (oldest 10%) when exceeded |
| `resolver_queue` | `resolver.rs` | 10,000 entries | New entries dropped when full |
| `per_flow_downsample` | `analyzer.rs` | 200,000 entries | Cleared when exceeded |
| `recent_data` buffer | `analyzer.rs` | 800 samples | Training data sliding window |
| `port_process_cache` | `l7.rs` | 10,000 entries | L7 resolution cache |

### Analyzer Caches

The anomaly detection system maintains several caches with TTL-based eviction:

| Cache | TTL | Purpose |
|-------|-----|---------|
| Score cache | 1 hour | Recent anomaly scores by session UID |
| Anomalous sessions | 24 hours | Sessions flagged as suspicious/abnormal |
| Blacklisted sessions | 24 hours | Sessions matching blacklist rules |

See [GAPS.md](GAPS.md) for known limitations and planned improvements.

## Anomaly Detection

12-dimensional Extended Isolation Forest:

| Feature | Description |
|---------|-------------|
| Process Hash | Categorical hash of process name |
| Duration | Session duration (seconds) |
| Total Bytes | Combined traffic volume |
| Total Packets | Combined packet count |
| Segment Interarrival | Average time between segments |
| In/Out Ratio | Traffic directionality |
| Avg Packet Size | Mean packet size |
| Interarrival Regularity | 0..1 proximity to uniform |
| Packet Rate | Packets per second |
| Missed Bytes | Packet loss indicator |
| Segments | Segment count |
| Dest Port | Categorical hash |

**Thresholds** (dynamic percentile-based):
- Suspicious: 99.5th percentile
- Abnormal: 99.75th percentile

See [ANALYZER.md](ANALYZER.md) for complete details.

## eBPF Support (Linux)

Kernel-level process attribution via Aya framework:

```
User Space                    Kernel Space (eBPF)
+-----------------+          +------------------------+
| Query session   |--peek--->| kprobe: tcp_v4_connect |
|                 |          | kprobe: tcp_set_state  |
| Get ProcessInfo |<--map----| l7_connections map     |
+-----------------+          +------------------------+
```

**Requirements**: Linux kernel 5.3+, CAP_SYS_ADMIN or root
**Fallback**: netstat2 crate when eBPF unavailable

See [EBPF.md](EBPF.md) for complete documentation.

## Feature Flags

| Feature | Description |
|---------|-------------|
| `packetcapture` | Live packet capture (requires root/CAP_NET_RAW) |
| `asyncpacketcapture` | Async capture mode |
| `ebpf` | Linux eBPF acceleration (x86_64/aarch64) |

## Platform Support

| Platform | Capture | eBPF | Privileges |
|----------|---------|------|------------|
| Linux | ✅ | ✅ | CAP_NET_RAW or root |
| macOS | ✅ | ❌ | Root or BPF entitlements |
| Windows | ✅ (Npcap) | ❌ | Administrator |
| iOS/Android | Limited | ❌ | App entitlements |

## Related Documentation

- [README.md](README.md) - Overview and usage examples
- [ANALYZER.md](ANALYZER.md) - ML anomaly detection deep dive
- [EBPF.md](EBPF.md) - eBPF architecture and troubleshooting
- [WHITELISTS.md](WHITELISTS.md) - Whitelist system design
- [PROFILES.md](PROFILES.md) - Device profiling system
- [CDN.md](CDN.md) - Threat intelligence CDN
- [GAPS.md](GAPS.md) - Known limitations and planned improvements
- [CHANGELOG.md](CHANGELOG.md) - Version history

## Dependencies

- `edamame_backend` - Backend data structures
- `extended-isolation-forest` - ML anomaly detection
- `pcap` / `Npcap` - Packet capture
- `aya` - eBPF framework (Linux)
- `tokio` - Async runtime
- `dashmap` - Concurrent hash maps
