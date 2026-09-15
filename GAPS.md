# Flodbadd Known Gaps and Planned Improvements

This document tracks known limitations, potential memory issues, and planned improvements for the flodbadd crate.

---

## L7 Process Attribution

### Strategy Overview

L7 resolution maps network sessions (5-tuples) to the local process responsible. The resolver uses a priority-ordered cascade of strategies per platform:

| Priority | Strategy | Platform | Mechanism |
|----------|----------|----------|-----------|
| 1 | eBPF kprobe | Linux | Kernel-level `tcp_set_state`, `tcp_v4_connect`, `tcp_v6_connect` kprobes via Aya; maps session 4-tuples to PID/UID/process in a BPF hashmap |
| 2 | macOS libproc | macOS | `PROC_PIDFDSOCKETINFO` via `proc_pidfdinfo()`; iterates all process FDs for direct socket-to-PID binding |
| 3 | Exact match (netstat) | All | `netstat2::get_sockets_info()` + `sysinfo::System::processes()`; matches full 4-tuple for TCP or local IP/port for UDP |
| 4 | Host service cache | All | Caches known local services by (port, protocol); fallback for inbound connections |
| 5 | Port-process cache | All | Keyed by (local_port, protocol) with PID-reuse protection via process start time and grace period for terminated processes |

### Resolution Sources Tracked

Each resolution is tagged with its source: `Ebpf`, `MacosLibproc`, `ExactMatch`, `CacheHitRunning`, `CacheHitTerminated`, `HostCacheHitRunning`, `HostCacheHitTerminated`, `FailedMaxRetries`, `Unknown`.

### Platform-Specific Gaps

#### Linux eBPF (`l7_ebpf.rs`)

| Gap | Severity | Details |
|-----|----------|---------|
| TCP-only kprobe coverage | Medium | eBPF hooks `tcp_set_state`, `tcp_v4_connect`, `tcp_v6_connect` -- no UDP process attribution at the kernel level. UDP falls through to netstat exact match or port cache. |
| BPF map size fixed at 65,536 | Low | `MAX_ENTRIES = 65536` in eBPF C program. Long-running systems with high session churn may silently drop new entries when the map is full. No user-space eviction of stale map entries. |
| Kernel 5.3+ requirement | Low | Minimum kernel version for BTF/tracepoint support. Pre-5.3 kernels silently fall back to netstat. |
| `unprivileged_bpf_disabled` pre-flight only | Low | Checked once at init. If sysctl changes at runtime, eBPF stays in its initial state (either loaded or not). |
| Container/LinuxKit limitations | Medium | Docker Desktop (LinuxKit kernel) lacks kprobe support. eBPF silently disabled. Not clearly surfaced to the user beyond log messages. |
| No eBPF map garbage collection | Medium | The `l7_connections` BPF hashmap is written by kernel kprobes but never pruned from user space. Stale entries for closed connections accumulate until the map is full. |
| Process path limited to 256 bytes | Low | `process_path` field in eBPF `ProcessInfo` struct is 256 bytes. Deeply nested paths are truncated. |
| eBPF object embedded at compile time | Low | If clang/llvm not available at build time, eBPF object is empty and all lookups return `None`. Build-time dependency not always obvious. |

#### macOS libproc (`l7_macos.rs`)

| Gap | Severity | Details |
|-----|----------|---------|
| Full process scan each cycle | Medium | `scan_all_process_sockets()` calls `proc_listallpids()` then `proc_pidinfo(PROC_PIDLISTFDS)` + `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` for every process. On systems with many processes, this is expensive (100+ ms). |
| Race with process exit | Low | A process may exit between `proc_listallpids()` and `proc_pidfdinfo()`. Handled gracefully (returns empty), but the connection may be missed. |
| UDP fuzzy matching only | Low | For UDP, falls back to port-based matching against `all_entries` since UDP sockets are often unconnected. May attribute to the wrong process if multiple processes bind the same port. |
| No kernel-level connection tracing | Medium | Endpoint Security delivers process events but never socket events, so macOS has no kernel-side 4-tuple to PID join. ES narrows libproc to kernel-known PIDs, which lifts the 50 ms bucket from 33% to 100%, but the floor stays at 50 ms because libproc probing is still the bottleneck. Apple's Network Extension framework could provide per-flow PID mapping and would need further entitlements. |
| Requires root or elevated entitlements | Low | `proc_pidfdinfo` for other processes requires root or appropriate entitlements. Without them, only the current process's sockets are visible. |

#### Windows

| Gap | Severity | Details |
|-----|----------|---------|
| No kernel-time socket-to-PID join | Low | Windows relies on `netstat2::get_sockets_info()` for the join. ETW is enabled and supplies a connection table, but its events arrive after `GetExtendedTcpTable` already sees the connection, so ETW never wins the race. Measured resolution is 100% at every hold duration including 0 ms, so this costs nothing in practice; it is listed because the mechanism differs from Linux. |
| Sensitive file scan is expensive | Medium | `start_sensitive_scan_task` interval is 120s on Windows because `NtQuerySystemInformation` enumerates ALL handles system-wide. |
| Username resolution via NetUserGetInfo | Low | Uses `NetApiBufferFree`/`NetUserGetInfo` Win32 API for UID-to-username mapping. May fail for domain accounts without network connectivity to the domain controller. |
| No QUIC/UDP acceleration | Low | Same as Linux without eBPF -- UDP attribution relies on netstat exact match and port cache. |

#### iOS / Android

| Gap | Severity | Details |
|-----|----------|---------|
| No L7 resolution | High | Mobile platforms have no process enumeration capability available to apps. L7 data is always `None`. Sessions are captured but never attributed to a process. |

### Cross-Platform L7 Gaps

| Gap | Severity | Details |
|-----|----------|---------|
| Short-lived connection race | Medium | All poll-based strategies (netstat, libproc) can miss connections that open and close between scan cycles. eBPF mitigates this on Linux for TCP only. |
| PID reuse window | Low | Port-process cache checks `process_start_time` for PID reuse protection, but there is a small race window between process exit and the next sysinfo refresh where a recycled PID could be misattributed. Grace period mitigates this. |
| `l7_map` unbounded for active sessions | Low | `l7_map` is a `CustomDashMap<Session, L7Resolution>` cleaned up by TTL, but while a session is active its entry is never evicted. Very long-running systems with 100k+ unique sessions could grow large. Mitigated by session pruning in `capture.rs`. |
| No command-line argument capture | Low | `SessionL7.cmd` and `SessionL7.memory` fields exist but are populated only via `sysinfo::Process`; eBPF returns empty strings for these. |
| UDP attribution accuracy | Medium | Without kernel-level hooks, UDP process attribution is best-effort across all platforms. Multiple processes using the same UDP port (e.g., DNS stub resolvers) may be misattributed. |
| QUIC sessions | Medium | QUIC traffic appears as UDP. Process attribution works through standard UDP resolution paths but has no QUIC-specific awareness (no connection ID tracking, no 0-RTT visibility). |

---

## DNS Resolution

### Strategy Overview

DNS resolution uses two complementary approaches that feed into a unified domain cache:

| Strategy | Module | Mechanism |
|----------|--------|-----------|
| Passive DNS (packet capture) | `dns.rs` | Intercepts DNS query/response packets from the wire; matches transaction IDs; stores IP-to-domain mappings |
| Active reverse DNS | `resolver.rs` | Background task performs PTR lookups via hickory-resolver against Google, Cloudflare, and Quad9 DNS with retry and failover |
| eBPF DNS process attribution | `dns_ebpf.rs` | Linux-only; hooks `udp_sendmsg`, `udpv6_sendmsg`, `__sys_sendto`, `ip4_datagram_connect`, `ip6_datagram_connect` to attribute DNS queries to processes |

Forward DNS (from packet capture) takes priority over reverse DNS when both are available.

### DNS-Specific Gaps

| Gap | Severity | Details |
|-----|----------|---------|
| Encrypted DNS invisible | High | DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) traffic is encrypted. Passive DNS capture sees nothing; these sessions appear as regular HTTPS/TLS connections to well-known DNS providers (1.1.1.1, 8.8.8.8). No domain attribution for sessions using DoH/DoT. |
| DNS-over-QUIC invisible | High | Same as DoH/DoT but using QUIC. Appears as UDP traffic to DNS providers with no domain extraction. |
| No eBPF process attribution for DNS-over-TCP | Medium | `dns_ebpf.rs` hooks `udp_sendmsg`/`udpv6_sendmsg`/`__sys_sendto` -- UDP only. DNS queries sent over TCP (e.g., large responses, zone transfers) bypass these hooks and have no kernel-level process attribution. Passive packet capture still sees the DNS content but cannot attribute it to a process. |
| No CNAME chain following | Low | Passive DNS captures A/AAAA records from responses but does not follow CNAME chains. If a domain resolves via CNAME, the final IP maps to the original query domain, not intermediate CNAMEs. This is usually the desired behavior but can miss alias relationships. |
| Resolver drains entire queue at once | Low | `resolver.rs` collects all queued IPs with `drain(..)` before resolving. If the queue is at its 10,000 limit, this creates a burst of 10,000 concurrent reverse DNS lookups. Could spike memory and DNS provider rate limits. |
| No negative caching TTL for reverse DNS | Low | Failed reverse DNS lookups are stored as `"Unknown"` indefinitely. IPs that later become resolvable (e.g., after DNS propagation) will not be retried. |
| Forward DNS cache does not honor DNS TTL | Low | Passive DNS entries persist until LRU eviction (50,000 entries). A domain that changes IPs (e.g., CDN rotation) will retain stale mappings until evicted. |
| DNS eBPF map not pruned | Low | `dns_sockets` BPF hashmap is written by kernel kprobes but never garbage-collected from user space. Long-running systems accumulate stale source-port entries. |
| mDNS not integrated with resolver cache | Low | `mdns.rs` handles multicast DNS discovery separately. mDNS-resolved names are not injected into the reverse DNS cache used by sessions. |
| Resolver retry delay is fixed | Low | `RESOLUTION_RETRY_DELAY_MS = 500ms` between attempts per resolver, `MAX_RESOLUTION_ATTEMPTS = 3` per resolver. Not adaptive to network conditions. |

---

## Memory Management

### Completed Fixes

| Issue | Status | Details |
|-------|--------|---------|
| TCP history string unbounded | **Fixed** | Added `MAX_HISTORY_LENGTH = 1000` in `packets.rs`. Previously, long-lived high-traffic connections could accumulate millions of characters in the history string. |
| DNS resolution caches unbounded | **Fixed** | Added `DNS_CACHE_MAX_ENTRIES = 50,000` with LRU eviction in `dns.rs`. Both `dns_resolutions` and `dns_resolutions_with_process` now track insertion timestamps and evict oldest 10% when over capacity. |
| Reverse DNS cache unbounded | **Fixed** | Added `REVERSE_DNS_CACHE_MAX_ENTRIES = 50,000` with LRU eviction in `resolver.rs`. Cache tracks insertion timestamps and evicts oldest 10% when over capacity during resolver task cycle. |
| Resolver queue unbounded | **Fixed** | Added `RESOLVER_QUEUE_MAX_SIZE = 10,000` in `resolver.rs`. New IPs are dropped (with debug log) when queue is full. |

### Cache Size Limits

| Cache | Location | Max Entries | Eviction Strategy |
|-------|----------|-------------|-------------------|
| `dns_resolutions` | `dns.rs` | 50,000 | LRU (oldest 10% evicted) |
| `dns_resolutions_with_process` | `dns.rs` | 50,000 | LRU (oldest 10% evicted) |
| `reverse_dns` | `resolver.rs` | 50,000 | LRU (oldest 10% evicted) |
| `resolver_queue` | `resolver.rs` | 10,000 | Drop new entries |
| `pending_dns_queries` | `dns.rs` | 65,535 | 30s TTL cleanup |
| `port_process_cache` | `l7.rs` | 10,000 | TTL-based (5 min for both ephemeral and server ports) |
| `l7_map` | `l7.rs` | Unbounded | TTL-based cleanup task |
| `per_flow_downsample` | `analyzer.rs` | 200,000 | Cleared when exceeded |
| `recent_data` | `analyzer.rs` | 800 samples | Sliding window |

### Remaining Memory Items

#### 1. Pending DNS Queries Map (Low Priority - Already Mitigated)

**Location:** `dns.rs`

**Issue:** `pending_dns_queries: CustomDashMap<u16, PendingQuery>` could theoretically grow.

**Current mitigation:** 
- Keyed by transaction ID (u16), so max 65,535 entries
- Cleanup task removes entries older than 30 seconds
- Entries removed when matching response arrives

**Status:** Adequately bounded. No action needed.

#### 2. eBPF BPF Maps (Medium Priority)

**Location:** `l7_ebpf.rs`, `dns_ebpf.rs`

**Issue:** Both `l7_connections` and `dns_sockets` BPF hashmaps have `MAX_ENTRIES = 65536` but are never pruned from user space. Kernel kprobes insert entries; nothing removes stale entries for closed connections.

**Current mitigation:** Fixed map size (65,536) prevents unbounded growth, but stale entries consume slots and eventually prevent new entries from being tracked.

**Potential fix:** Periodic user-space sweep that checks map entries against active sessions and deletes stale ones.

---

## Kernel Sensors

The three privileged sensors (Linux eBPF plus fanotify, macOS Endpoint
Security, Windows ETW) are documented in `EBPF.md`, `ENDPOINTSECURITY.md` and
`ETW.md`. This section tracks only their gaps.

### Closed

Each row names the commit and, where one exists, the run or host that
confirmed it.

| Gap | Platforms | Closed by | Confirmed on |
|---|---|---|---|
| File attribution recorded the last reader, not the writer | macOS, Windows | `7b23842` | Security gate, 2026-09-08 |
| Writer lost to the `lsof` race when the writer closed first | Linux | `18b7b56` (fanotify) | ubuntu-arm64 gate, 2026-09-07 |
| Atomic replace left the final path unattributed | macOS | `ea48a38` (rename destination) | |
| No task-access telemetry at all | Windows | `e566ffd` | Azure Windows runner |
| Any `PROCESS_VM_READ` open graded as attach | Windows | `157cd5e` | Azure runner: 0x0410 no event, 0x0438 mode 2 |
| Processes started after the sensor had no image path | Windows | `59be337` | Azure runner: `exec_with_path` 0 of 5 to 8 of 8 |
| Short-name and device-path spellings split one file's identity | Windows | `8e5b85c`, `7a644b0` | Gate run 34520133863 |
| `EVENT_TRACE_FLAG_FILE_IO` flooded 6-7 MB/s of discarded events | Windows | `ee6f5f4` | Dogfood host shiawase |
| BPF map create failed under `RLIMIT_MEMLOCK` | Linux | `ab753b8` | 23,000 Sentry events on 1.4.1 to 1.8.3 |
| Fork and exit tracepoints never attached on kernel 6.17 | Linux | `c5e2a44` | 6.17 dogfood host |
| Sensor's own procfs reads re-triggered its ptrace probe | Linux | `6caca3c` | Lima VM 6.8, measured 26,000 ev/s before the filter |
| CI watch-root fallback watched the filesystem root | all | `657ee49` | Azure runners, 17-24 GB RSS in 6-8 h |
| Attribution tables recorded every file event on the machine | macOS, Windows | `0f42307` | |

### Open

| Gap | Severity | Details |
|---|---|---|
| No per-sensor unmeasured marker | Medium | Where a sensor is absent it attaches nothing, so the evidence fields it would have set stay false. A consumer reading those fields cannot distinguish an absent sensor from a measured negative. This affects severity grading between a sandboxed host and a fully instrumented one. |
| No overhead measurement for the eBPF programs | Medium | There is a measured cost for the Windows FileIo flood and for the L7 re-arm cadence, but no CPU or latency number for the eBPF programs themselves. `EBPF.md` carries only a qualitative claim. |
| ETW availability decided after a fixed 500 ms sleep | Low | `FlodbaddL7Etw::init` sleeps 500 ms and then reads the flag, so a slow-starting trace session is reported unavailable for the life of the process. |
| fanotify mark cap below the kernel default | Low | Marks are capped at 4096 against a kernel default `max_user_marks` of 8192 per user. A watch set exceeding the cap silently stops marking further subdirectories. |
| Net-intent LRU may coalesce distinct events | Low | The cgroup egress-intent hook drops repeats of `(tgid, family, proto, port, addr)` inside a 1 s window, so a burst of genuinely distinct connections to the same destination inside that window is reported once. |
| Linux kernel-time file attribution is coupled to the `ebpf` feature | Low | `fim_fanotify` is gated on `fim` AND `ebpf`, the latter only because it supplies the `nix` dependency with its `fanotify` feature. A Linux build with `fim` but without `ebpf`, which is what 32-bit Linux gets, silently loses kernel-time writer attribution and falls back to the `lsof` race the fanotify work was written to close. |
| ES file attribution untestable in-process | Low | Endpoint Security suppresses events from its client's own process tree including children, so a single test binary is its own client and never sees its own writes. `tests/fim_attribution_benchmark_test.rs` can only validate init, the tier cascade and the `lsof` fallback. |
| ETW TCP/IP decode may never key an IPv4 session | Medium | `handle_tcp_event` selects the IPv4 or IPv6 payload by event version alone, never by opcode. Modern kernels emit version 2 for IPv4 Connect/Accept/Reconnect and use separate opcodes for the IPv6 variants, so IPv4 tuples may decode through the V6 arm and never key a session. This would explain the benchmark result that ETW never wins the Windows L7 race mechanically rather than as a latency race. Unverified; no Windows host was available when it was found. |
| Two ETW consumers on one host contend for the kernel session | Low | `init` unconditionally stops any pre-existing NT Kernel Logger session, and both the helper and the posture daemon now build the `etw` feature. On a host running both, the second to start takes the kernel session from the first. |
| No garbage collection of the eBPF connection map | Medium | `l7_connections` is written by the kernel programs and only ever read from user space. `__sk_free` deletes the socket row but not the connection row, and the in-code comment claiming a userspace TTL describes a sweep that does not exist. Rows persist until the 65,536 cap is reached. Already listed under the Linux eBPF table above; repeated here because the comment is misleading. |
| Linux task-access probe is ATTACH-only | Low | The `ptrace_may_access` kprobe filters to `PTRACE_MODE_ATTACH`. Read-mode access is deliberately not reported because it is far too noisy, and is covered instead by the procfs open-file route. macOS reports both modes, so the platforms are not symmetric here. |

---

## Performance Optimizations

### Potential Improvements (Low Priority)

#### 1. Whitelist Lookup Performance

**Location:** `whitelists.rs`

**Issue:** Whitelist matching iterates through all endpoints linearly.

**Current behavior:** O(n) where n = number of whitelist endpoints.

**Impact:** Low for typical whitelists (< 1000 rules). Could be noticeable for very large whitelists.

**Potential fix:** Build a hash index for common lookups (by port, by domain suffix).

---

#### 2. DNS Resolution Batch Processing

**Location:** `resolver.rs`

**Issue:** The resolver drains the entire queue at once:
```rust
let to_resolve: Vec<IpAddr> = resolver_queue.write().await.drain(..).collect();
```

**Impact:** Low. Could cause memory spike if queue is very large.

**Potential fix:** Process in batches of 100-500 IPs.

---

#### 3. macOS libproc Full Process Scan Cost

**Location:** `l7_macos.rs`

**Issue:** `scan_all_process_sockets(None)` enumerates every PID on the system and queries every socket FD for each. On systems with many processes (500+), this involves thousands of `proc_pidfdinfo` syscalls per L7 resolution cycle.

**Current mitigation:** Run via `tokio::task::spawn_blocking` to avoid blocking the async runtime.

**Potential fix:** Cache the PID list and only rescan processes whose socket FD count changed, or use a differential scan based on `proc_listallpids` delta.

---

#### 4. Windows Sensitive File Scan Interval

**Location:** `l7.rs`

**Issue:** `start_sensitive_scan_task` runs at 120s intervals on Windows because `NtQuerySystemInformation` enumerates ALL system handles. This is significantly slower than Linux (30s) and macOS (60s).

**Potential fix:** Use `NtQueryInformationProcess` per-process instead of the global handle enumeration, or implement incremental scanning.

---

## Testing Gaps

### Areas Needing More Test Coverage

1. **Long-running capture tests** - Verify memory doesn't grow unbounded over 24+ hours
2. **High packet rate tests** - Stress test with 100k+ packets/second
3. **Cache eviction tests** - Verify LRU/TTL eviction works correctly under load
4. **eBPF map saturation** - Test behavior when `l7_connections` BPF map reaches 65,536 entries
5. **DNS-over-HTTPS detection** - Verify sessions to known DoH providers are at least flagged as DNS-related even without domain extraction
6. **Cross-platform L7 accuracy** - Covered by `tests/l7_benchmark_test.rs` and `.github/workflows/l7_benchmark.yml`, which run six variants across the three platforms with and without the kernel feature. Results are in `L7.md`.
7. **Short-lived connection coverage** - Measure what percentage of sub-100ms connections are successfully attributed to processes on each platform

---

## Version History

| Date | Change |
|------|--------|
| 2026-09-15 | Added the Kernel Sensors section with the closed and open registers; corrected the Windows and macOS L7 rows, which described a state that predates the ETW and Endpoint Security work |
| 2026-03-18 | Rewrote GAPS.md with comprehensive L7 and DNS strategy analysis; added platform-specific gap tables for eBPF, macOS libproc, Windows, mobile; added DNS resolution gaps (DoH/DoT, eBPF map pruning, TTL handling); added cross-platform L7 gaps |
| 2026-01-22 | Added `MAX_HISTORY_LENGTH` fix for TCP history string |
| 2026-01-22 | Created GAPS.md to track remaining items |
