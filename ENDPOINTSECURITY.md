# Endpoint Security Layer 7 Process Attribution

## Overview

Flodbadd includes an optional macOS Endpoint Security (ES) subsystem that maintains a live process table fed by kernel-delivered lifecycle events. This provides high-fidelity process metadata (executable path, parent chain, code signing status, arguments) without the race conditions inherent in polling `sysinfo` after the fact.

ES complements the existing `libproc`-based socket-to-PID mapping (`l7_macos.rs`). The division of labor:

- **libproc** (`l7_macos.rs`): Maps network 4-tuples to PIDs via `PROC_PIDFDSOCKETINFO`.
- **Endpoint Security** (`l7_es.rs`): Maintains a live process table with rich metadata, used to enrich the PID obtained from libproc.

This is the macOS counterpart of the eBPF module on Linux (`l7_ebpf.rs`).

## What is Endpoint Security?

Apple's Endpoint Security framework (macOS 10.15+) delivers real-time system events from the kernel to user-space security clients. For process attribution it provides:

- **FORK/EXEC/EXIT events**: Full process lifecycle tracking
- **Rich process metadata**: Executable path, arguments, CWD, audit token (PID, UID)
- **Code signing info**: Signing flags, platform binary status
- **Parent chain**: Parent process identity captured at event time (no reconstruction from snapshots)

## Architecture

```
                            +---------------------------------------------+
                            |           User Space                         |
                            |  +-----------+    +------------------------+ |
                            |  | flodbadd  |--->|  l7_es.rs              | |
                            |  | l7.rs     |    |  - ES client singleton | |
                            |  | resolver  |<---|  - DashMap process     | |
                            |  +-----------+    |    table               | |
                            |       |           |  - DashMap file        | |
                            |       |           |    attribution table   | |
                            |  +-----------+    +------------------------+ |
                            |  | fim.rs    |--->  (file attribution)      |
                            |  | FIM       |             ^                  |
                            |  | watcher   |             |                  |
                            |  +-----------+    ES event callbacks         |
                            |       |           (FORK / EXEC / EXIT +      |
                            |       v            CREATE / CLOSE /           |
                            |  +-----------+     RENAME / UNLINK)          |
                            |  |l7_macos.rs|             |                  |
                            |  | libproc   |    +------------------------+ |
                            |  | socket    |    |  EndpointSecurity.fwk  | |
                            |  | scan      |    +------------------------+ |
                            |  +-----------+                               |
                            +---------------------------------------------+
                                                         |
                                                         | mach messages
                                                         v
                            +---------------------------------------------+
                            |              macOS Kernel                    |
                            |    Process lifecycle + file event delivery   |
                            +---------------------------------------------+
```

### Hybrid Resolution Strategy

1. **libproc socket scan** maps the network 4-tuple to a PID (same as today).
2. **ES process table** enriches the PID with metadata captured at EXEC time:
   - Full executable path (not reconstructed from `/proc`)
   - Arguments, CWD, UID, username
   - Parent and grandparent chain (captured at fork/exec, not polled)
   - Code signing flags, platform binary status
3. If ES is unavailable, the system falls back to `sysinfo` polling (current behavior).

This eliminates:
- `System::refresh_specifics()` polling overhead for every batch
- Race conditions between process exit and metadata collection
- Reconstructed parent chains from stale snapshots

### L7 Resolution Priority

```
1. eBPF          (Linux only)   -- kernel 4-tuple to PID mapping
2. ES + libproc  (macOS only)   -- libproc socket scan + ES metadata enrichment
3. libproc only  (macOS)        -- fallback when ES unavailable
4. netstat       (all platforms) -- universal fallback
```

## Enabling Endpoint Security

### Cargo Feature

```toml
[dependencies]
flodbadd = { version = "*", features = ["packetcapture", "endpointsecurity"] }
```

### Runtime Requirements

| Requirement | Details |
|---|---|
| **macOS version** | 13.0+ (Ventura) for process events |
| **Privileges** | Root (or LaunchDaemon running as root) |
| **Entitlement** | `com.apple.developer.endpoint-security.client` |
| **Distribution** | Developer ID only (not Mac App Store) |
| **Notarization** | Required for distribution |

### Entitlement Request

The `com.apple.developer.endpoint-security.client` entitlement must be requested from Apple:

1. Go to [developer.apple.com/contact/request/system-extension](https://developer.apple.com/contact/request/system-extension/)
2. Select "Endpoint Security" as the extension type
3. Describe the use case (network session process attribution for security monitoring)
4. Apple typically responds within 1-2 weeks

**Development without entitlement**: Disable System Integrity Protection (SIP) on the development machine:
```bash
# Boot into Recovery Mode, then:
csrutil disable
# Reboot to normal mode
```

With SIP disabled, ES clients can be created without the entitlement. Re-enable SIP before shipping.

## Where the ES Client Runs

### edamame_helper (Production)

The ES client runs inside the `edamame_helper` LaunchDaemon:

- Already runs as root (privileged LaunchDaemon)
- Already handles packet capture via flodbadd
- No IPC overhead -- process table is in-process
- No new daemon or System Extension needed

The helper's `macos/edamame_helper.entitlements` includes the ES entitlement. The signing script (`macos/make-pkg.sh`) embeds it during code signing.

### edamame_posture (Standalone)

`edamame_posture` runs as root on macOS (`ensure_admin()`), so it can also use ES directly when built with the `endpointsecurity` feature. No helper needed.

### edamame_app (Flutter)

The Flutter app is sandboxed and cannot use ES directly. It reads session data (including ES-enriched L7 metadata) from the helper via gRPC.

## ES Events Used

### Process Lifecycle Events

| Event | Purpose |
|---|---|
| `ES_EVENT_TYPE_NOTIFY_FORK` | Track new PIDs, build parent chain |
| `ES_EVENT_TYPE_NOTIFY_EXEC` | Capture executable path, arguments, CWD, code signing |
| `ES_EVENT_TYPE_NOTIFY_EXIT` | Garbage-collect stale PIDs from process table |

### File Attribution Events

| Event | Purpose |
|---|---|
| `ES_EVENT_TYPE_NOTIFY_CREATE` | Record which process created a file |
| `ES_EVENT_TYPE_NOTIFY_CLOSE` | Record which process modified and closed a file (only when `modified == true`) |
| `ES_EVENT_TYPE_NOTIFY_RENAME` | Record which process renamed a file |
| `ES_EVENT_TYPE_NOTIFY_UNLINK` | Record which process deleted a file |

File events populate a bounded `file_attribution_table` (DashMap, max 50K entries, 30s TTL) that the FIM subsystem queries for process attribution. This eliminates the racy `lsof` probe for short-lived file operations.

Only NOTIFY (not AUTH) events are used -- the ES client never blocks process execution or file I/O.

## Graceful Fallback

When ES is unavailable (no entitlement, older macOS, SIP issues), the module returns `is_available() == false` and all enrichment calls are no-ops. The existing `l7_macos.rs` + `sysinfo` path continues to work as before.

```rust
// Pseudo-code of the resolution flow
fn resolve_session(connection: &Session) -> Option<SessionL7> {
    // Step 1: libproc socket scan for PID
    let pid = l7_macos::find_pid_for_session(connection)?;

    // Step 2: Build base L7 from sysinfo
    let mut l7 = build_l7_from_sysinfo(pid)?;

    // Step 3: Enrich from ES table (no-op if unavailable)
    l7_es::enrich_session_l7(pid, &mut l7);

    Some(l7)
}
```

## Platform Support

| Platform | ES Support | Notes |
|---|---|---|
| **macOS 13+** | Full | FORK/EXEC/EXIT events |
| **macOS 10.15-12** | Partial | ES available but some events require newer versions |
| **macOS < 10.15** | None | ES framework not available |
| **Linux** | None | Use eBPF instead |
| **Windows** | None | Falls back to netstat |

## Performance

| Method | Metadata Latency | Accuracy | Notes |
|---|---|---|---|
| **ES + libproc** | < 1ms lookup | Very High | Metadata captured at exec time |
| **libproc + sysinfo** | 10-50ms refresh | High | Polling-based, race-prone |
| **netstat** | 10-50ms | Moderate | Platform-generic fallback |

ES provides better performance because:
- Process metadata is captured at EXEC time (event-driven, not polled)
- DashMap lookups are O(1) and lock-free
- No `System::refresh_specifics()` call needed per batch

## Troubleshooting

### ES Client Creation Fails

```
ES client creation failed: ERR_NOT_ENTITLED
```

**Causes:**
- Missing `com.apple.developer.endpoint-security.client` entitlement
- Running as non-root user
- SIP is enabled and entitlement not approved by Apple

**Solutions:**
1. Ensure running as root (helper LaunchDaemon or `sudo`)
2. For development: disable SIP (`csrutil disable` from Recovery)
3. For production: ensure Apple-approved entitlement is in the provisioning profile

### Process Table Empty

If ES is available but the process table shows zero entries:

1. Check logs for subscription errors
2. Verify the helper is running as root
3. Restart the helper daemon

### ES Events Not Delivered

```
ES subscribe failed: event type not available
```

This can happen on older macOS versions that don't support all event types. The module requires macOS 13+ for full functionality.

## Code Structure

```
flodbadd/
  src/
    l7.rs          # L7 resolution interface (dispatch + enrichment)
    l7_es.rs       # ES client, process + file attribution tables (macOS only)
    l7_ebpf.rs     # eBPF-based resolution (Linux only)
    l7_macos.rs    # libproc socket-to-PID mapping (macOS)
    capture.rs     # Integrates L7 with packet capture
    fim.rs         # FIM watcher, 3-tier attribution, lsof cache
    fim_events.rs  # FIM event store (bounded at 10K events, 8h retention)
  tests/
    l7_benchmark_test.rs             # L7 network attribution benchmark
    fim_attribution_benchmark_test.rs # FIM file attribution benchmark (ES vs lsof)

edamame_helper/
  macos/
    edamame_helper.entitlements  # ES entitlement plist
    make-pkg.sh                  # Signing script (uses entitlements)
```

## Rust Crate

The `endpoint-sec` crate (v0.5) provides safe Rust bindings to `EndpointSecurity.framework`:

- `Client::new()` -- create an ES client with an event handler closure
- `Client::subscribe()` -- subscribe to event types
- `Message` / `Event` / `Process` -- event data accessors
- `AuditToken` -- PID, UID extraction

## Security Considerations

### Privilege Model

ES clients require root or equivalent privileges. The helper LaunchDaemon satisfies this. The ES client receives all system-wide process events, which is necessary for comprehensive session attribution but means the helper has broad visibility into process lifecycle.

### Event Volume

FORK/EXEC/EXIT events are high-frequency on busy systems. The DashMap process table handles this efficiently, and GC via EXIT events prevents unbounded growth.

File events (CREATE/CLOSE/RENAME/UNLINK) can be higher frequency than process events. The file attribution table is bounded at 50,000 entries with a 30-second TTL and lazy pruning (every 1,000th insert) to keep memory usage predictable.

### No AUTH Events

This module only uses NOTIFY events (observation-only). It never blocks or delays process execution or file I/O. This is a deliberate choice to avoid any performance impact on the system.

## FIM Attribution Pipeline

When the FIM subsystem (`fim.rs`) needs to attribute a file event to a process, it uses a three-tier lookup:

```
1. ES file attribution table   -- l7_es::get_file_attribution(path)
2. lsof result cache            -- FIM_ATTRIBUTION_CACHE (5K entries, 10s TTL)
3. Live lsof + sysinfo          -- lookup_pid_for_path() + lookup_process_details()
```

Tier 1 is populated by kernel-delivered ES file events and provides near-100% attribution for short-lived files. Tier 2 caches successful lsof results so burst writes to the same path avoid repeated lsof invocations. Tier 3 is the existing racy fallback.

ES initialization is idempotent (OnceCell-based) and is called by both `FlodbaddCapture::start()` (packet capture) and `FimWatcher::start()` (FIM), so the ES client is active whenever either subsystem is running.

### Memory Bounds

| Collection | Max Size | TTL | Pruning |
|---|---|---|---|
| `process_table` (DashMap) | Bounded by OS process count | N/A | EXIT events remove entries |
| `file_attribution_table` (DashMap) | 50,000 entries | 30s | Lazy (every 1,000th insert) + hard cap |
| `FIM_ATTRIBUTION_CACHE` (DashMap) | 5,000 entries | 10s | Lazy (every 500th insert) + hard cap |

## Related Documentation

- [Apple Endpoint Security](https://developer.apple.com/documentation/endpointsecurity)
- [endpoint-sec crate](https://docs.rs/endpoint-sec/)
- [eBPF L7 resolution](EBPF.md) -- Linux counterpart
