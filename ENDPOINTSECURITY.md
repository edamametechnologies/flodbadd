# Endpoint Security (macOS)

## Overview

Flodbadd includes an optional macOS Endpoint Security (ES) subsystem (`src/l7_es.rs`)
that consumes kernel-delivered process and file notifications. It is not a single
feature: one ES client feeds three independent consumers.

| Consumer | What ES provides | Where it is read |
|---|---|---|
| L7 network attribution | A live process table keyed by pid (image path, argv, cwd, uid, parent and grandparent chain, code signing) | `l7_es::get_l7_for_session`, `l7_es::enrich_session_l7` |
| File Integrity Monitoring | The FIM **event source** on macOS (`src/fim_es.rs`), plus a bounded file attribution table read as Tier 1 of the FIM backfill | `fim::spawn_fim_es_consumer`, `fim::kernel_table_attribution` |
| Process-event monitoring stream | `Exec` / `Fork` / `Exit` / `TaskAccess` events into the bounded ring in `src/process_events.rs` | `process_events::recent`, consumers in `edamame_core` |

ES never maps sockets to pids. That is still libproc's job (`l7_macos.rs`); ES supplies
the pid set to probe and the metadata to attach. This module is the macOS counterpart of
the eBPF module on Linux (`l7_ebpf.rs`) and the ETW module on Windows (`l7_etw.rs`).

## What Endpoint Security delivers

Apple's Endpoint Security framework delivers real-time events from the kernel to
user-space security clients. Flodbadd uses it for:

- Process lifecycle: FORK, EXEC, EXIT, with the executable path, argv, cwd and audit token.
- Kernel-vouched publisher identity: signing id, team id and the platform-binary flag come
  out of the exec message itself, so they cannot be forged by the process being observed.
- Task-port access: GET_TASK and GET_TASK_READ, the macOS primitives for reading another
  process's memory.
- File events: CREATE, WRITE, CLOSE, RENAME, UNLINK, with the responsible process attached
  at event time.

## Architecture

```
                  +--------------------------------------------------+
                  |                    User space                     |
                  |                                                  |
                  |  l7.rs  <----- process table -----+               |
                  |  (eager + batch L7)               |               |
                  |                                   |               |
                  |  fim.rs <--- FimSourceEvent ------+  l7_es.rs     |
                  |  (fim-es consumer thread)         |  - es-client  |
                  |          ^                        |    thread     |
                  |          |  file attribution      |  - process    |
                  |          +--- table (Tier 1) -----+    table      |
                  |                                   |  - file attr  |
                  |  process_events.rs <-- ring ------+    table      |
                  |  (Exec/Fork/Exit/TaskAccess)      |               |
                  |                                   |               |
                  |                        +----------+------------+  |
                  |                        | EndpointSecurity.fwk  |  |
                  |                        +----------+------------+  |
                  +-------------------------------------|------------+
                                                        | mach messages
                                                        v
                  +--------------------------------------------------+
                  |                   macOS kernel                    |
                  +--------------------------------------------------+
```

The ES client is created on a dedicated thread named `es-client`, which then parks. The
handler closure does not run on that thread: it runs on Apple's serial ES dispatch queue.
Everything the handler touches is an `Arc<DashMap>` or an atomic, and the handler must
never block, because the queue is serial and a stall there stalls the whole stream.

## Events subscribed

All subscriptions are NOTIFY. The client never subscribes to an AUTH event, so it cannot
block or delay process execution or file I/O.

| Event | Used for |
|---|---|
| `NOTIFY_FORK` | Insert the child into the process table with the parent and grandparent chain; push a `Fork` process event |
| `NOTIFY_EXEC` | Overwrite the row with the exec target's identity (path, argv, cwd, signing id, team id, platform binary); push an `Exec` process event with the argv digest |
| `NOTIFY_EXIT` | Remove the pid from the process table; push an `Exit` process event |
| `NOTIFY_GET_TASK` | Push a `TaskAccess` event with `task_access_mode = 2` (control port) |
| `NOTIFY_GET_TASK_READ` | Push a `TaskAccess` event with `task_access_mode = 1` (read-only port) |
| `NOTIFY_CREATE` | Record file attribution for the destination; emit a FIM `Create` |
| `NOTIFY_WRITE` | Record file attribution at the first write; emit a FIM `Modify` |
| `NOTIFY_CLOSE` | Only when `ev.modified()` is true: record attribution; emit a FIM `Modify` |
| `NOTIFY_RENAME` | Record attribution for **both** the source and the destination; emit a FIM `Delete` for the source and a FIM `Rename` for the destination |
| `NOTIFY_UNLINK` | Record attribution for the target; emit a FIM `Delete` |

`NOTIFY_GET_TASK_READ` requires the `endpoint-sec` crate's `macos_11_3_0` feature, which
`Cargo.toml` enables unconditionally on the optional dependency.

`NOTIFY_WRITE` is the highest-volume event ES emits: every write syscall by every process
on the machine. Both hot arms (WRITE and modified CLOSE) answer
`fim_attribution::is_attributable` on the borrowed path before allocating anything.

## L7 network attribution

Two entry points, both no-ops when ES is unavailable:

- `get_l7_for_session(session)` is the eager path. It iterates the pids ES told us about
  and probes each one's sockets through `l7_macos::scan_process_sockets`, short-circuiting
  on the first 4-tuple match (forward or reversed). It is cheaper than a full system socket
  scan because it only visits kernel-known pids. It also sets `spawned_from_tmp` from the
  process, parent and grandparent image paths.
- `enrich_session_l7(pid, &mut l7)` fills in only the fields the base resolution left empty
  or left as a placeholder (`/proc/`-prefixed paths, `pid-` names, `uid-` usernames). It
  never overwrites a populated field.

In `l7.rs` the eager order is eBPF, then ETW, then ES, then plain libproc. On the batch
path the resolution source is reported as `EndpointSecurity` when `l7_es::is_available()`
is true and `MacosLibproc` otherwise.

## FIM

### ES as the event source

Until 2026-09-08 the macOS FIM ran on FSEvents (`notify`) and asked ES *who* wrote a path
only after the fact. Since `ed2916d`, ES is the event source.

`FimWatcher::start` waits up to 3 seconds (polling every 100 ms) for `l7_es::is_available()`,
because the ES client subscribes on its own thread and the decision cannot be made before it
has had a chance. If ES is up, the watcher does not register the paths with the FSEvents
watcher at all; it installs an ES sink instead:

1. `fim_attribution::set_roots(paths, recursive)` publishes the roots. This happens **before**
   the event-source decision, so the FSEvents fallback is covered too: the fallback still
   reads the ES attribution table for the writer pid, and gating on the ES sink's own roots
   would have left it empty.
2. `fim_es::install(paths, recursive)` creates a bounded `sync_channel` of capacity 4096 and
   returns the receiver. Both the raw and the canonical spelling of each root are kept, since
   ES reports `/private/var/...` where callers pass `/var/...`.
3. The ES handler filters by root **inside the callback** before anything crosses the channel,
   so build trees and browser caches never leave the dispatch queue. A full channel increments
   `dropped_full` rather than blocking the queue.
4. `spawn_fim_es_consumer` runs a thread named `fim-es` that drains the receiver with a 500 ms
   `recv_timeout`, passes each event through a 500 ms `Coalescer`, translates it into the
   `notify` event shape the existing FIM translation already understands, and inserts the
   result with the writer's pid, name and image path attached.

The `Coalescer` exists because ES emits a WRITE per open plus a modified CLOSE on top, and a
writer that appends in bursts produces several of each. FSEvents coalesced this for free. Only
`Modify` is coalesced; `Create`, `Rename` and `Delete` always pass and reset the window for
that path.

If a previous watcher already installed the sink (a restart within the same process), the new
watcher logs the collision and falls back to FSEvents for its own lifetime rather than losing
the roots. `FimWatcher::stop` calls `fim_attribution::clear_roots`, since nothing reads the
attribution table while no watcher is running.

The ES source requires both the `endpointsecurity` and the `fim` feature: the
`fim_source_push` call sites in the ES handler are gated on `fim`.

### The file attribution table

Independently of the event source, the handler maintains a `DashMap<String, FimEsAttribution>`
mapping recently touched paths to `(pid, process_name, process_path)`. `fim::kernel_table_attribution`
reads it as Tier 1 of the FIM attribution cascade:

```
1. kernel table      -- l7_es::get_file_attribution(path) on macOS
                        (fim_fanotify on Linux, l7_etw on Windows)
2. lsof result cache -- FIM_ATTRIBUTION_CACHE, 5,000 entries, 10s TTL
3. live lsof+sysinfo -- lookup_pid_for_path() + lookup_process_details(),
                        budgeted to FIM_BACKFILL_TIER3_PROBE_LIMIT probes
```

Lookups try the raw path first, then the canonicalized form, because ES records canonical
paths while callers often pass the symlinked spelling.

Temp-staging events get a kernel-table-only backfill
(`backfill_temp_events_from_kernel_tables`): map lookups, never `lsof`, so `/tmp` churn
cannot starve the budgeted Tier 3 probes reserved for credential-store candidates.

Recording is confined to the FIM watch roots. With no roots published, nothing is
attributable. That is an absent capability, not a permissive verdict: the effect is that
less is recorded, never that an unwatched path is treated as watched.

### The `fim_attribution` module

`src/fim_attribution.rs` carries the roots and the `normalize` / `path_under_root` /
`is_attributable` predicates. It is shared by the ES sink filter and the attribution
confinement so the two cannot drift apart, and it is **deliberately not behind the `fim`
feature**: the sensors that consult it are gated on `endpointsecurity` and `etw`, which are
independent features, and a predicate that vanishes under a `#[cfg]` stops confining
anything without a compile error (the no-permissive-fallback rule).

Linux needs none of this. fanotify is mark-based, so the kernel already filters to the
marked roots.

## Process-event monitoring stream

The ES handler pushes into the cross-platform ring in `src/process_events.rs`:

| Kind | Source event | Notes |
|---|---|---|
| `Exec` | `NOTIFY_EXEC` | Carries `signing_id`, `team_id`, `is_platform_binary` from the kernel message, plus `argv_sha256` and `argv_len` |
| `Fork` | `NOTIFY_FORK` | No argv (the child has not exec'd) |
| `Exit` | `NOTIFY_EXIT` | Identity from the removed process-table row, or from the message when the row is missing |
| `TaskAccess` | `NOTIFY_GET_TASK` / `NOTIFY_GET_TASK_READ` | `target_pid` and `target_process_path` name the victim; `task_access_mode` is 2 for the control port and 1 for the read-only port |

Invariant I5: raw argv never enters the ring. Only a SHA-256 digest over the NUL-joined argv
and the argument count are stored. The `EsProcessInfo.args` vector in the process table is a
separate in-memory structure used for L7 enrichment and is not part of this stream.

`task_access_mode` uses the PTRACE_MODE vocabulary shared with the Linux kprobe backend, so
every platform speaks the same language: 1 is READ (macOS `GET_TASK_READ`, Linux
`PTRACE_MODE_READ`), 2 is ATTACH (macOS control port, Linux `/proc/<pid>/mem`,
`process_vm_readv`, ptrace attach). The distinction matters because read-only task ports are
what `ps`, `sysmond` and process monitors hold all day.

The ring is bounded at `PROCESS_EVENT_RING_MAX` = 8192 entries and is taken through
undeadlock's `CustomMutex` with a non-blocking `try_with`, so a sensor thread never blocks on
it. The stream is notify-only and fail-open: a backend that cannot start simply never pushes.

## Fixes landed in 2026

| Commit | Date | What it fixed |
|---|---|---|
| `c5e2a44` | 2026-09-05 | Landed the process-event stream. During bring-up: the fork and exec handlers held a DashMap read guard across the child insert, which self-deadlocks the serial ES dispatch queue on a shard collision and froze the whole stream after the first colliding exec. The guard is now dropped before the insert. |
| `18d1134` | 2026-09-07 | `task_access_mode` on the wire. ES passes 2 for `GET_TASK` and 1 for `GET_TASK_READ`, in the PTRACE_MODE vocabulary shared with the Linux kprobe, so the detector can tell a read-only monitor apart from an attach. |
| `7b23842` | 2026-09-08 | The kernel-time writer must be the writer, not the last reader. Recording every CLOSE made the FIM hash worker's own read of a freshly dropped `~/.env*` replace the Python writer with `edamame_posture` on the security gate. Fix: subscribe `NOTIFY_WRITE` and record at the first write, and record CLOSE only when the kernel says the file was modified. Same commit started attributing the macOS per-user temp root (`/var/folders`), whose events carried a null writer by construction. |
| `ea48a38` | 2026-09-08 | The notify event for a fresh drop can be handled before the kernel table has the writer (FSEvents fires on the write while the ES WRITE message is still in flight), and a single-write drop never gets a second event to retry on. Added `backfill_temp_events_from_kernel_tables`, kernel tables only and never `lsof`. Same commit records the ES rename **destination** as well as the source, since the destination is the path FIM reports for an atomic replace (`write tmp; rename tmp -> file`). |
| `ed2916d` | 2026-09-08 | ES becomes the FIM event source: bounded channel, in-callback root filter, coalescing consumer, 3-second wait for ES availability at watcher start, FSEvents retained as the fallback. |
| `7d4ada3` | 2026-09-09 | `FimEvent.process_pid` so `edamame_core` joins a FIM event to `writer_kernel_exec` by pid rather than by image path. Same commit split `platform_path_marked` out of `is_platform_binary`, so a PATH-shaped mark can never be mistaken for a kernel-vouched platform fact. |
| `0f42307` | 2026-09-10 | Confined kernel-time attribution recording to the FIM watch roots via the new always-compiled `fim_attribution` module. Both the ES client and the Windows ETW FileIo session had been recording an entry for every file event on the machine into a table whose only reader is `fim::kernel_table_attribution`, which is only ever asked about paths under a watch root. |

## Enabling Endpoint Security

### Cargo feature

```toml
[dependencies]
flodbadd = { version = "*", features = ["packetcapture", "endpointsecurity", "fim"] }
```

`endpointsecurity` pulls in `endpoint-sec` 0.5 with the `macos_11_3_0` feature. `fim` is
required for the FIM event source; `endpointsecurity` alone still gives the process table,
the attribution table and the process-event stream.

### Runtime requirements

| Requirement | Details |
|---|---|
| macOS version | 13.0+. `FlodbaddL7Es::init` reads `sw_vers -productVersion` and disables itself below 13. |
| Privileges | Root (LaunchDaemon, or `sudo` for tests). |
| Entitlement | `com.apple.developer.endpoint-security.client` |
| Provisioning profile | Required at runtime. AMFI authorizes the restricted entitlement only against an embedded profile. |
| Distribution | Developer ID, notarized. Not Mac App Store. |

### Entitlement request

The `com.apple.developer.endpoint-security.client` entitlement must be requested from Apple:

1. Go to [developer.apple.com/contact/request/system-extension](https://developer.apple.com/contact/request/system-extension/)
2. Select "Endpoint Security" as the extension type
3. Describe the use case (network session process attribution for security monitoring)
4. Apple typically responds within 1-2 weeks

Development without the entitlement: disable System Integrity Protection on the development
machine (`csrutil disable` from Recovery, reboot). With SIP disabled, ES clients can be
created without the entitlement. Re-enable SIP before shipping.

### The provisioning profile is not optional

A restricted entitlement is authorized at runtime by an embedded provisioning profile inside
an app-like bundle, not by a loose system-wide profile. `edamame_helper/macos/make-pkg.sh`
takes `--provisioning-profile` and copies it to `Contents/embedded.provisionprofile` inside
the bundle before signing with the hardened runtime and the entitlements plist. A loose Mach-O
dropped into Application Support is still subject to AMFI policy and may be killed on exec.
`edamame_posture` packages the same way.

For local development, `make install_provisioning` in `edamame_helper` or `edamame_posture`
installs the profile.

## Where the ES client runs

### edamame_helper (production)

The ES client runs inside the `edamame_helper` LaunchDaemon:

- Already runs as root.
- Already handles packet capture via flodbadd, so the process table is in-process and there is
  no IPC hop.
- No System Extension needed.

`macos/edamame_helper.entitlements` carries the entitlement; `macos/make-pkg.sh` applies it
during code signing and embeds the provisioning profile.

### edamame_posture (standalone)

`edamame_posture` runs as root on macOS, so it uses ES directly when built with the
`endpointsecurity` feature. No helper needed. Its `.pkg` embeds the provisioning profile the
same way.

### edamame_app (Flutter)

The Flutter app is sandboxed and cannot use ES. It reads session data, FIM events and
ES-derived L7 metadata from the helper over gRPC.

## ES self-muting

macOS Endpoint Security suppresses events from the ES client's own process tree, the client's
child processes included. Only events from independent process trees are delivered.

```
edamame_helper (ES client)     <-- owns ES, generates no observable user file events
    |
    +-- flodbadd capture       <-- packet capture, session tracking
    +-- l7_es process table    <-- populated by events from OTHER processes
    +-- l7_es file attribution <-- populated by file events from OTHER processes
    +-- fim-es consumer        <-- FIM events from OTHER processes

User processes (editors, AI agents, scripts)  <-- independent process tree
    |
    +-- File operations visible to ES
```

This is load-bearing, not incidental. The ES client must be an independent daemon, not a
library loaded into the process being monitored.

### Testing implications

ES file attribution cannot be exercised from within a single test binary, because the test
process *is* the ES client and its own file operations are muted.
`tests/fim_attribution_benchmark_test.rs` therefore verifies what it can:

1. ES initializes and receives events from other processes on the system.
2. The three-tier lookup path works end to end.
3. lsof-based attribution works as the fallback.

Full ES file attribution is validated in the production deployment, where the helper daemon is
independent of user file operations.

## Graceful fallback

When ES is unavailable (no entitlement, not root, macOS below 13, SIP policy), `is_available()`
returns false, the tables stay empty and every lookup returns `None`.
`get_l7_for_session` short-circuits on the availability flag before touching the process table.

On non-macOS targets, and on macOS without the `endpointsecurity` feature, `l7_es` compiles a
stub module with the same public surface: `is_available()` is false, the getters return `None`
or empty collections, and `enrich_session_l7` does nothing. No caller needs a `#[cfg]`.

| Subsystem | ES available | ES unavailable |
|---|---|---|
| L7 | ES eager path, then libproc, then netstat | libproc + sysinfo, then netstat |
| FIM events | ES source: kernel-time events, writer attached in the callback | FSEvents (`notify`) watcher |
| FIM attribution | Tier 1 kernel table hits | Tier 2 lsof cache, Tier 3 live lsof + sysinfo |

## Platform support

| Platform | ES support | Notes |
|---|---|---|
| macOS 13+ | Full | Process, task-port and file events |
| macOS 10.15-12 | None as built | `init` disables itself below 13 |
| macOS < 10.15 | None | Framework not available |
| Linux | None | eBPF for L7, fanotify for FIM attribution |
| Windows | None | ETW for FIM attribution, netstat2 for L7 |

## Performance

### L7 resolution

From the L7 benchmark (`tests/l7_benchmark_test.rs`, results tabulated in `L7.md`):

| Metric | macOS + ES | macOS libproc only |
|---|---|---|
| Resolution at 50 ms hold | 100% | 33% |
| Overall resolution | 71% | 62% |
| Minimum detectable session | 50 ms | 50 ms |

ES does not lower the 50 ms floor on macOS, because the socket lookup is still libproc's.
What it buys is reliability at the boundary: the eager path iterates only kernel-known pids
and short-circuits on the first match, so it is far more likely to win the race against a
process that is about to exit. Metadata lookup on the eager path is under 1 ms, from the
pre-populated DashMap, versus a `System::refresh_specifics()` poll per batch.

### FIM path

From `0f42307`, measured on a release build: the FIM path already reports `total: 0ms` per
batch and the helper idles at 6-12%. That commit is explicit that it is **not** a fix for
helper CPU. The periodic burst is the 12-14 MB session payload, which predates those changes.
Confining the attribution tables removes work that was never read, nothing more.

### Memory bounds

| Collection | Bound | TTL | Pruning |
|---|---|---|---|
| `process_table` (DashMap) | OS process count | none | EXIT events remove entries |
| `file_attribution_table` (DashMap) | 50,000 entries | 30s | Lazy, every 1,000th insert, plus a hard cap that evicts oldest first |
| `FIM_ATTRIBUTION_CACHE` (DashMap) | 5,000 entries | 10s | Lazy, every 500th insert, plus hard cap |
| `fim_es` channel (`sync_channel`) | 4,096 events | n/a | Full channel increments `dropped_full`; the handler never blocks |
| `Coalescer.last_modify` | 8,192 paths | 500ms window | Retained on overflow |
| `process_events::RING` | 8,192 events | n/a | Oldest evicted, counted |

`prune_file_attribution_table` uses `Instant::now().checked_sub(TTL)` rather than plain
subtraction: the monotonic-from-boot clock underflows and panics within TTL seconds of boot,
and nothing can be older than the window at that point anyway.

## Counters and diagnostics

`l7_es::file_event_stats()` returns a nine-element tuple:

```
(create, create_dest_some, create_dest_none, write, close, close_modified, rename, unlink, other)
```

`create_dest_none` counts CREATE messages ES delivered without a resolvable destination, which
are dropped. `close` versus `close_modified` shows how much of the close volume the modified-only
rule suppresses. `other` counts messages for event types the handler does not match, which should
stay at zero for the subscribed set.

`l7_es::dump_file_attribution_paths(max)` returns up to `max` `(path, pid, process_path)` triples
from the attribution table, for eyeballing what is actually being recorded.

`tests/fim_attribution_benchmark_test.rs` consumes both: it prints all nine counters, sums
`create + write + close + rename + unlink` as the system event total, and dumps a 15-entry table
sample tagged `MATCH` or `sys` so a run can show whether the benchmark's own files made it in.

Other accessors: `l7_es::process_count()`, `l7_es::file_attribution_count()`,
`l7_es::es_support()` (a human-readable init status string), `fim_es::stats()` returning
`(delivered, dropped_because_full)`, `fim_es::root_count()`, and
`fim_attribution::root_count()`.

## Troubleshooting

### ES client creation fails

```
ES client creation failed: ERR_NOT_ENTITLED
```

Causes: missing `com.apple.developer.endpoint-security.client` entitlement, not running as
root, or SIP enabled with no Apple-approved entitlement and no embedded provisioning profile.

Fixes:

1. Run as root (helper LaunchDaemon, or `sudo`).
2. For development, disable SIP (`csrutil disable` from Recovery) or install the provisioning
   profile locally (`make install_provisioning` in `edamame_helper` or `edamame_posture`).
3. For production, install via the notarized `.pkg`, which wraps the binary in an app-like
   bundle with `Contents/embedded.provisionprofile`.

### Process table empty

If ES reports available but `process_count()` stays at zero:

1. Check the logs for subscription errors.
2. Verify the process is running as root.
3. Restart the daemon.

Remember that self-muting means a test binary will never see its own tree.

### FIM events stop, or the writer is null

- `fim_es::stats()` shows `dropped_because_full` climbing: the consumer thread is not keeping
  up with the ES callback, and events under the roots are being dropped at the channel.
- `fim_attribution::root_count()` is zero while FIM is supposed to be running: the roots were
  never published or were cleared, so nothing is attributable and every event loses its writer.
- The log line "ES sink already installed; falling back to FSEvents for this watcher" means a
  second `FimWatcher` started in the same process; only the first owns the ES sink.

### ES events not delivered

```
ES subscribe failed: event type not available
```

An event type in the subscribe array is unavailable on this OS version. The module requires
macOS 13+ and the `endpoint-sec` `macos_11_3_0` feature for `NOTIFY_GET_TASK_READ`.

## Build and test

```bash
# Full macOS suite, codesigning the test binaries with the ES entitlement first
make macos_test

# L7 benchmark with and without ES
make macos_benchmark
make macos_benchmark_no_es

# FIM attribution benchmark with and without ES
make macos_fim_benchmark
make macos_fim_benchmark_no_es
```

`macos_codesign_es` builds the test binaries with
`--features packetcapture,asyncpacketcapture,endpointsecurity,fim --no-run`, writes a
throwaway entitlements plist, and codesigns every test binary under `target/debug/deps`. With
no Developer ID certificate in the keychain it signs ad hoc, which only works in CI or with
SIP disabled.

## Code structure

```
flodbadd/
  src/
    l7.rs             # L7 dispatch: eager (eBPF, ETW, ES, libproc) and batch paths
    l7_es.rs          # ES client, process table, file attribution table (macOS only)
    l7_ebpf.rs        # eBPF resolution (Linux)
    l7_etw.rs         # ETW resolution + FileIo attribution (Windows)
    l7_macos.rs       # libproc socket-to-PID mapping (macOS)
    fim.rs            # FIM watcher, event-source selection, tiered attribution, backfill
    fim_es.rs         # ES sink: bounded channel, root filter, Coalescer (macOS)
    fim_attribution.rs# Always-compiled watch-root predicate shared by ES and ETW
    fim_events.rs     # FIM event store (10,000 events, 8h retention)
    fim_fanotify.rs   # fanotify attribution (Linux)
    process_events.rs # Cross-platform process-event ring + counters
    capture.rs        # Calls l7_es::init_and_log_status() on capture start
  tests/
    l7_benchmark_test.rs              # L7 network attribution benchmark
    fim_attribution_benchmark_test.rs # FIM attribution benchmark (ES vs lsof)

edamame_helper/
  macos/
    edamame_helper.entitlements  # ES entitlement plist
    make-pkg.sh                  # Bundle + embedded.provisionprofile + signing
```

ES initialization is idempotent (a `OnceCell` behind `l7_es::global()`) and is triggered from
both `capture.rs` and `fim.rs`, so the client is up whenever either subsystem starts.

## Rust crate

`endpoint-sec` 0.5 provides the safe bindings to `EndpointSecurity.framework`:

- `Client::new()` creates a client with an event handler closure.
- `Client::subscribe()` takes the `es_event_type_t` array.
- `Message` / `Event` / `Process` give the event accessors.
- `AuditToken` yields pid and euid.
- `version::set_runtime_version()` gates the version-dependent accessors; `init` sets it from
  `sw_vers` output, defaulting to 13.0 when parsing fails.

`FlodbaddL7Es` carries `unsafe impl Send + Sync`. The justification is in the source: the
struct only holds `Arc<DashMap>` and atomics, while the `!Send` `Client` lives exclusively on
the `es-client` thread and is never reachable through the struct.

## Security considerations

### Privilege model

An ES client requires root. The helper LaunchDaemon satisfies this. The client receives
system-wide process, task-port and file events, which is what makes comprehensive attribution
possible, and also means the helper has broad visibility into system activity. Nothing it sees
leaves the attribution tables and the bounded ring.

### No AUTH events

Observation only. The client never blocks or delays a syscall.

### Event volume

FORK/EXEC/EXIT are high-frequency on busy systems, and NOTIFY_WRITE is higher still. The
mitigations are: a root predicate answered on the borrowed path before any allocation, a
bounded and TTL'd attribution table with lazy pruning, an in-callback root filter on the FIM
sink, a bounded channel that drops rather than blocks, and a coalescer on the consumer side.

### argv never stored raw in the stream

Invariant I5. argv routinely carries secrets, so the process-event ring holds only a SHA-256
digest and the argument count.

## Related documentation

- [Apple Endpoint Security](https://developer.apple.com/documentation/endpointsecurity)
- [endpoint-sec crate](https://docs.rs/endpoint-sec/)
- [L7.md](L7.md) -- L7 resolution paths and benchmark results
- [EBPF.md](EBPF.md) -- Linux counterpart
- [ETW.md](ETW.md) -- Windows counterpart
