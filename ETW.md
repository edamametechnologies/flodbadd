# ETW Layer 7 Process Attribution (Experimental -- Not Enabled)

## Status

**The `etw` feature flag is not enabled by default.** Benchmarks show that
`netstat2` (`GetExtendedTcpTable` from `iphlpapi.dll`) provides equivalent
or better L7 resolution performance on Windows without any of ETW's
operational complexity.

### Why ETW is not useful for L7 socket attribution

`GetExtendedTcpTable` is a synchronous Win32 syscall that queries the
kernel's TCP connection table as a point-in-time snapshot. It returns all
active connections with their owning PIDs in a single call. This is fast
enough to resolve even instant-close (0 ms hold) TCP sessions -- matching
eBPF's coverage on Linux.

ETW, by contrast, delivers kernel trace events asynchronously via a callback
thread with buffering latency. The TCP/IP Connect event arrives in the
DashMap *after* the connection is already visible to `GetExtendedTcpTable`.
In practice, `netstat2` always wins the resolution race.

| Metric | netstat2 (GetExtendedTcpTable) | ETW (kernel trace) |
|---|---|---|
| Resolution rate (0 ms hold) | **100%** | 100% (but resolves as ExactMatch, not Etw) |
| Min detectable session | **0 ms** | 0 ms (no improvement) |
| API model | Synchronous syscall | Asynchronous event callback |
| Privilege required | None | Administrator |
| Session exclusivity | None | Exclusive NT Kernel Logger |
| Operational conflicts | None | Conflicts with PerfMon, Xperf, etc. |
| Additional dependency | `iphlpapi.dll` (always present) | `windows` crate ETW APIs |

### Where ETW could add value beyond L7

ETW is a powerful general-purpose kernel tracing facility. If EDAMAME needs
Windows-specific telemetry beyond socket attribution in the future, ETW
could be repurposed for:

- **DLL/image load tracking** (`IMAGE_LOAD` events) -- detect injected DLLs
- **File I/O monitoring** (`FileIo` provider) -- track sensitive file access
- **Registry access tracing** -- detect persistence mechanisms
- **Thread injection detection** -- cross-process thread creation
- **Process metadata for exited processes** -- command line, environment
  captured at process start, surviving process exit

These use cases would require new event handlers beyond the current
TCP/IP and Process providers.

## Overview

Flodbadd includes an optional Windows ETW (Event Tracing for Windows) subsystem that maintains a live process table and connection-to-PID mapping fed by kernel trace events. The `etw` feature flag is available for experimentation but is not enabled in production builds.

ETW was originally intended as the Windows counterpart of the eBPF module on Linux (`l7_ebpf.rs`) and Endpoint Security on macOS (`l7_es.rs`), but benchmarks demonstrated that Windows does not need kernel-level event tracing for L7 attribution because `GetExtendedTcpTable` is already fast enough.

## What is ETW?

Windows Event Tracing for Windows (ETW) is a kernel-level tracing facility that delivers real-time system events to user-space consumers. For process attribution it provides:

- TCP/IP connection events with PIDs (connect, accept, reconnect)
- Process lifecycle events (start, end) with full image path and parent PID
- Near-zero overhead kernel-level event delivery
- No driver installation needed -- built into all Windows versions since Vista

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           User Space                                      │
│  ┌─────────────────┐    ┌───────────────────────────────────────────────┐  │
│  │  flodbadd       │    │  l7_etw.rs                                    │  │
│  │  l7.rs          │───>│  - ETW session singleton                      │  │
│  │  resolver       │<───│  - DashMap process table                    │  │
│  │                 │    │  - DashMap connection table                 │  │
│  └─────────────────┘    └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ StartTraceW / OpenTraceW / ProcessTrace
                                    │ EVENT_RECORD callbacks
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         Kernel Space                                      │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  NT Kernel Logger trace session                                    │  │
│  │  - Microsoft-Windows-Kernel-Network (TCP/IP Provider)            │  │
│  │  - Microsoft-Windows-Kernel-Process (Process Provider)             │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### Hybrid Resolution Strategy

1. ETW connection table maps TCP 4-tuples directly to PIDs (replaces netstat polling)
2. ETW process table enriches PIDs with metadata captured at process start
3. If ETW is unavailable, falls back to netstat2 + sysinfo (current behavior)

### L7 Resolution Priority

1. eBPF (Linux only)
2. ES + libproc (macOS only)
3. ETW (Windows only) -- kernel TCP/IP + Process providers
4. netstat (all platforms) -- universal fallback

## Enabling ETW (Experimental)

ETW is **not enabled** in `edamame_helper` or `edamame_posture` by default.
To experiment with it:

```toml
[dependencies]
flodbadd = { version = "*", features = ["packetcapture", "etw"] }
```

### Runtime Requirements

| Requirement | Details |
|---|---|
| **Windows version** | Windows 10 21H2+ (or Server 2019+) |
| **Privileges** | Administrator (for kernel trace sessions) |
| **Installation** | None -- ETW is built into Windows |

No entitlement request needed (unlike macOS ES).

## Where the ETW Client Runs

ETW is not enabled in production. If re-enabled for experimentation:

### edamame_helper

- Runs as Windows Service with LocalSystem privileges
- Would create ETW session in-process alongside packet capture

### edamame_posture

- Must run as Administrator
- Would get direct ETW access when built with `etw` feature

## ETW Providers Used

| Provider | GUID | Purpose |
|---|---|---|
| Microsoft-Windows-Kernel-Network (TCP/IP) | 9a280ac0-c8e0-11d1-84e2-00c04fb998a2 | TCP connect/accept/reconnect events with PIDs |
| Microsoft-Windows-Kernel-Process | 3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c | Process start/end with image path, parent PID |

### Event Types

| Event | Opcode | Purpose |
|---|---|---|
| TcpIp/Connect | 12 | Outbound TCP connection with PID |
| TcpIp/Accept | 15 | Inbound TCP accept with PID |
| TcpIp/Reconnect | 16 | TCP reconnection with PID |
| Process/Start | 1 | New process with image path, parent PID |
| Process/End | 2 | Process exit -- garbage-collect from tables |

## Graceful Fallback

When ETW is unavailable (not admin, session conflict), the module returns `is_available() == false` and all lookups return None. The existing netstat2 + sysinfo path continues to work.

## Platform Support

| Platform | ETW Support | Notes |
|---|---|---|
| **Windows 10 21H2+** | Full | TCP/IP + Process providers |
| **Windows Server 2019+** | Full | Same as desktop |
| **Windows 8.1 / Server 2016** | Partial | May work but not tested |
| **macOS** | None | Use ES instead |
| **Linux** | None | Use eBPF instead |

## Performance (Benchmark Results)

CI benchmarks (`tests/l7_benchmark_test.rs`) show no measurable resolution
improvement from ETW over `netstat2` on Windows:

| Method | Resolution rate (0 ms hold) | Min detectable session | Primary source |
|---|---|---|---|
| **netstat2 (GetExtendedTcpTable)** | **100%** | **0 ms** | ExactMatch |
| **ETW + netstat2** | **100%** | **0 ms** | ExactMatch (ETW never wins the race) |

On Windows, `GetExtendedTcpTable` is a synchronous kernel syscall, not a
polling loop. It returns the full connection table with PIDs in one call,
which is why it resolves even instant-close sessions.

## Kernel Trace Session Limitations

- Only one system-wide "NT Kernel Logger" session is allowed at a time
- The ETW module attempts to stop any pre-existing session before starting
- If another process (e.g. PerfMon, Xperf, Process Monitor) holds the session, ETW init fails gracefully

## Troubleshooting

### ETW Session Start Fails

"ETW StartTrace failed" -- usually means not running as Administrator.

### Connection Table Empty

If ETW is available but connections are not being tracked:

1. Check that the process is running as Administrator
2. Check if another tool is holding the kernel trace session
3. Restart the application

### No IPv6 Connections

IPv6 TCP events use version >= 2 of the TCP/IP event format. Older Windows versions may only deliver IPv4 events.

## Code Structure

```
flodbadd/
  src/
    l7.rs          # L7 resolution dispatch (eBPF -> ES -> ETW -> netstat)
    l7_etw.rs      # ETW session, process table, connection table (Windows only)
    l7_ebpf.rs     # eBPF-based resolution (Linux only)
    l7_es.rs       # ES client, process table (macOS only)
    l7_macos.rs    # libproc socket-to-PID mapping (macOS)
    capture.rs     # Integrates L7 with packet capture
```

## Windows Crate

Uses the `windows` crate (v0.62) raw Win32 ETW APIs directly:

- `StartTraceW` / `ControlTraceW` / `CloseTrace` -- trace session lifecycle
- `EnableTraceEx2` -- enable kernel providers
- `OpenTraceW` / `ProcessTrace` -- event consumption
- `EVENT_RECORD` callback -- event dispatch

No external ETW helper crate needed -- avoids version conflicts.

## Security Considerations

### Privilege Model

ETW kernel trace sessions require Administrator privileges. The helper Windows Service satisfies this.

### Event Volume

TCP/IP and Process events are moderate-frequency. DashMap provides efficient concurrent access. Process exit events garbage-collect stale entries.

### Session Exclusivity

The "NT Kernel Logger" session is system-wide. Starting it will stop any existing session held by other tools.

## Related Documentation

- [ETW Documentation](https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal)
- [Kernel Logger](https://learn.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants)
- [eBPF L7 resolution](EBPF.md) -- Linux counterpart
- [Endpoint Security L7](ENDPOINTSECURITY.md) -- macOS counterpart
