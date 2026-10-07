# ETW Process, File and Task-Access Attribution

## Status

The `etw` feature is enabled in production. Both Windows daemons that link
flodbadd build it in:

| Consumer | Cargo entry | Features |
|---|---|---|
| `edamame_helper` | `flodbadd` dependency | `packetcapture`, `asyncpacketcapture`, `endpointsecurity`, `fim`, `etw` |
| `edamame_posture` | `flodbadd` under `[target.'cfg(target_os = "windows")'.dependencies]` | `packetcapture`, `asyncpacketcapture`, `etw` (enabled 2026-09-07, `edamame_posture` 54f53bc) |

The EDAMAME app itself does not link the ETW backend; on Windows the helper
service is the process that normally holds the kernel session.

ETW is not enabled because it wins the L7 resolution race. It does not.
It is enabled because it is the only source on Windows for three things
nothing else provides: kernel-time file-writer attribution for FIM,
cross-process task-access observation, and process lineage with image paths
for processes that have already exited. Those three products are described
below.

## The two sessions

`FlodbaddL7Etw::init` (`src/l7_etw.rs`) spawns two threads, each owning an
independent trace session. Neither depends on the other, and either can fail
without taking the other down.

| | Session A | Session B |
|---|---|---|
| Thread name | `etw-client` | `etw-audit-api-calls` |
| Session name | `NT Kernel Logger` | `EDAMAME-KernelAuditApiCalls` |
| Scope | System-wide, exclusive (one per machine) | Private real-time session |
| Providers | Kernel providers selected by `EnableFlags` | `Microsoft-Windows-Kernel-Audit-API-Calls` (manifest provider, GUID `e02a841c-75a3-4fa7-afc8-ae09cf9b7f23`) |
| Feeds | Connection table, process table, file attribution and namespace tables, `Exec` / `Exit` ring events | `TaskAccess` ring events |
| Sets `is_available()` | Yes | No |

Both call `ControlTraceW(..., EVENT_TRACE_CONTROL_STOP)` on their session name
before `StartTraceW`, so a session left behind by a previous daemon instance is
torn down rather than blocking the start. `l7_etw::shutdown()` stops the two
sessions this process started (see "2026-09-29 -- the sessions stop with their
process" below).

A manifest provider cannot ride the NT Kernel Logger, which is why
`Microsoft-Windows-Kernel-Audit-API-Calls` needs a session of its own.

### Session A: kernel flags

`props.EnableFlags` is exactly four flags:

| Flag | Delivers | Consumed as |
|---|---|---|
| `EVENT_TRACE_FLAG_NETWORK_TCPIP` | TcpIp Connect (12), Accept (15), Reconnect (16) | 4-tuple -> PID connection table |
| `EVENT_TRACE_FLAG_PROCESS` | Process Start (1), End (2) | Live process table, plus `Exec` / `Exit` ring events |
| `EVENT_TRACE_FLAG_FILE_IO_INIT` | FileIo initiation events (TypeGroup2) in the caller's context: Create (64), Cleanup (65), Close (66), Write (68), Delete (70), Rename (71), DeletePath (79), RenamePath (80) | File attribution table (writes), namespace table (deletes, renames) |
| `EVENT_TRACE_FLAG_IMAGE_LOAD` | Image Load (10); the DCStart rundown and Unload are ignored | The program image (`.exe`) of each new process, by pid: the full path of a process its Start event names by a bare image name (see 2026-10-07 below) |

On a kernel-logger session the `EnableFlags` bitmask is what selects the
providers. The module additionally calls `EnableTraceEx2` for the TCP/IP and
Process provider GUIDs and ignores both results.

Before the process table can attribute anything it is primed from a one-time
whole-system `sysinfo` enumeration on the trace thread, before `ProcessTrace`
blocks. Without that, any process that predates the session (an already-open
browser surviving a helper restart) resolves as `pid-XXXX`, which defeats the
detector's identity-token self-access suppression.

### Session B: PsOpenProcess

Event id 5 of the audit provider is `PsOpenProcess`. Its payload is
`TargetProcessId: u32, DesiredAccess: u32, ReturnCode: u32`; the requester is
the event header's `ProcessId`, not a payload field. The callback drops the
event unless the payload is at least 12 bytes, and filters out zero pids, self
opens (`requester == target`), and anything where either side is the sensor's
own pid.

The return code is deliberately not consulted. Like the Linux
`ptrace_may_access` kprobe, this stream records the attempt: a denied open of a
sensitive target is evidence in its own right.

## EVENT_TRACE_FLAG_FILE_IO is deliberately not enabled

The session used to enable `EVENT_TRACE_FLAG_FILE_IO` (TypeGroup1: read/write
completion and OpEnd) alongside `FILE_IO_INIT`. The callback has never consumed
a TypeGroup1 opcode -- then it read only FileIo/Create, today it reads
Create / Write / Cleanup / Close, all of which are TypeGroup2 initiation events
-- so every TypeGroup1 event was copied from kernel to user space and discarded
at the first opcode check.

Measured on the dogfood Windows host shiawase (commit ee6f5f4, 2026-05-25):

| Metric | Value |
|---|---|
| Kernel-to-user event traffic | ~6-7 MB/s |
| Buffers consumed | 154,475 64 KB buffers over 24 minutes of helper uptime |
| `handle_fileio_event` share of helper kernel time | ~80% |
| Helper CPU | ~120% of one core |

The flag was dropped. Correctness is unchanged: `FILEIO_CREATE` is a TypeGroup2
opcode and continues to arrive through `EVENT_TRACE_FLAG_FILE_IO_INIT`.

## What ETW produces

### 1. L7 enrichment, not L7 resolution

`GetExtendedTcpTable` (via `netstat2`) is a synchronous syscall that returns the
whole connection table with owning PIDs in one call, so it resolves even
instant-close (0 ms hold) sessions. ETW events arrive asynchronously through a
buffered callback thread.

The CI benchmark (`tests/l7_benchmark_test.rs`, driven by
`.github/workflows/l7_benchmark.yml` with and without the feature) measured no
resolution-rate or minimum-hold improvement from ETW on Windows, with every
session attributed as `ExactMatch`:

| Method | Resolution rate (0 ms hold) | Min detectable session | Source recorded |
|---|---|---|---|
| netstat2 only | 100% | 0 ms | `ExactMatch` |
| ETW + netstat2 | 100% | 0 ms | `ExactMatch` |

What the code actually does: `FlodbaddL7::try_kernel_resolve` and the batch
resolver both consult `l7_etw::get_l7_for_session` before the netstat exact
match, so ETW can resolve a session and is recorded as `L7ResolutionSource::Etw`
when its connection table holds the tuple. `l7_etw::enrich_session_l7` -- image
path, process name, username, parent and grandparent lineage -- runs only on
sessions ETW itself resolved. A session resolved by netstat2 is not
back-enriched from the ETW process table.

### 2. FIM writer attribution

`FileIo` events run in the calling process's context, so the event header pid is
the actor. `record_file_attribution` writes `(pid, process_name, process_path,
recorded_at)` into the file attribution table keyed by the canonical path.
Deletes and renames go to a second table of the same shape, the namespace
table (`get_file_namespace_attribution`), so a delete never takes the file's
writer and a write looked up after its file is gone never takes the remover
(see "2026-10-06 -- deletes and renames carry their actor" below). The payloads
are decoded by `src/etw_fileio_payload.rs`, which is pure and unit-tested on
every host.

The image recorded with a pid comes from the process table, unless the process
holding the pid there started after the FileIo event (`started_at`, the
Process/Start timestamp or the kernel creation time): then the pid was still its
predecessor's, and only `pid-N` is recorded (FP-WIN-29 class).

| Property | Value |
|---|---|
| Max entries | 50,000 |
| TTL | 30 s (enforced on prune and again on read) |
| Prune cadence | every 1,000 inserts |
| Reader | `fim::kernel_table_attribution_for`, Tier 1 of the Windows attribution ladder (writes: file attribution table; deletes and renames: namespace table) |

The Windows tiers in `fim.rs`:

| Tier | Source | Cost | Requires |
|---|---|---|---|
| 1 | ETW file attribution table | Map lookup | `etw` feature + a running session |
| 2 | In-memory attribution cache (positive or negative, path-keyed, no pid) | Map lookup | A previous successful attribution |
| 3 | Restart Manager + `sysinfo` on the artifact path | ~1-5 ms per file | Nothing |
| 3b | Restart Manager on up to two parent directories, sensitive events only | One extra RM session | Nothing |

Only Tier 1 and the Linux/macOS kernel tables carry a writer pid, which is what
`FimEvent.process_pid` exposes so the core detector can join a FIM event to the
writer's exec event by pid rather than by image path (7d4ada3).

Recording is confined to the FIM watch roots. `fim_attribution::is_attributable`
is consulted before anything is allocated, and it answers `false` when no roots
are installed, which is the "FIM is not running, nothing will ever read this
table" case.

### 3. The process-events ring

Windows pushes three of the five `ProcessEventKind` variants into the bounded
ring in `src/process_events.rs` (8192 entries, try-lock push, counters for
evicted and lock-dropped events):

| Kind | Source | Payload specifics |
|---|---|---|
| `Exec` | Session A, Process/Start | `process_path`, `parent_process_path` from the table, `argv_sha256` over the command line (raw argv never enters the ring) |
| `Exit` | Session A, Process/End | Identity copied out of the process table entry being removed |
| `TaskAccess` | Session B, PsOpenProcess | `target_pid`, `target_process_path`, `task_access_mode`, `task_access_mask` (the raw `DesiredAccess`), `platform_path_marked` |

`Fork` and `NetConnect` have no Windows producer. `signing_id`, `team_id`,
`uid`, `argv_len` and `is_platform_binary` stay `None` on every Windows event:
unmeasured, never fabricated.

## Changes in 2026

### e566ffd (2026-09-07) -- PsOpenProcess becomes the Windows task-access stream

Before this commit Windows had no task-access telemetry at all: BS-9 was a
macOS/Linux-only signal. The commit adds Session B, decodes event id 5, and
pushes `TaskAccess` ring events whose requester comes from the event header's
`ProcessId` and whose target comes from the payload. Self-pid and self-opens are
filtered. Fail-open: if `StartTraceW`, `EnableTraceEx2` or `OpenTraceW` fails,
the thread logs at debug and returns, disabling only this stream. Session A and
everything downstream of it are untouched.

### 0a9576f (2026-09-07) -- bounded raw-event diagnostics

The `PsOpenProcess` layout was decoded from documentation, not from an SDK
header, and the first security-gate run with the session live (run
34159044624) opened the session cleanly but produced no task-access edge for 80
`OpenProcess(PROCESS_VM_READ)` calls. The callback now logs the first 12 audit
events at info level with event id, version, opcode, level, keyword, header pid,
payload length and a 32-byte hex preview, so a daemon log answers "what does
this kernel actually deliver" without a debugger. The counter is a process-wide
`AtomicU64`, so the cost is bounded to those 12 lines.

### 157cd5e (2026-09-08) -- grade by access mask

Before: any mask carrying `PROCESS_VM_READ` was forwarded as ATTACH-grade, so
Google Updater's routine opens of svchost and of the updater it launched graded
like a memory scraper on the 2026-09-08 idle Windows baseline.

Now the mask maps onto the same PTRACE_MODE vocabulary ES and the Linux kprobe
use:

| Desired access | Mode | Forwarded |
|---|---|---|
| `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION` or `PROCESS_CREATE_THREAD`, or the full `0x001F_FFFF` all-access mask | 2 (ATTACH) | Always |
| `PROCESS_VM_READ` alone | 1 (READ) | Only from a requester whose image is not OS-shipped by path |
| Query-only | -- | Never |

Verified on the Azure windows-x64 runner: a PowerShell `0x0410` open leaves no
event, and a `0x0438` open on the same target is recorded with mode 2.

The in-code doc comment on `audit_record_callback` still says only ATTACH-grade
masks are forwarded; the code has forwarded non-OS-shipped READ-grade opens
since this commit.

### 59be337 (2026-09-08) -- layout-aware Kernel-Process start decoding

Before: the decoder scanned for a printable ANSI run immediately after
`ExitStatus`, which lands inside `DirectoryTableBase`, so every process started
after the sensor had an empty image path and name. Only the snapshot-primed
table carried paths. Measured on the Azure Windows runner with the
`process_events_monitor` example: `exec_with_path` = 0 of 5. A BS-9 edge whose
requester has no path is dropped by the detector, so the CI trigger's own
Python process produced no edge.

`src/etw_process_payload.rs` is a new pure module, host-testable on macOS and
Linux, that decodes MOF `Process_V3` / `Process_V4`: pointer size from
`EVENT_HEADER_FLAG_32_BIT_HEADER`, the `Flags` field only from V4, the variable
`object(SID)` field (pointer-sized `PSID`, or `TOKEN_USER` header plus a SID
whose length follows from `SubAuthorityCount`), then `ImageFileName` (ANSI) and
`CommandLine` (UTF-16LE).

`ImageFileName` is usually a bare `image.exe`, so the full path comes from the
command line's first token when that token's basename matches the image name
(`image_path_from_command_line`), or from `QueryFullProcessImageNameW` while the
process is still alive. The old printable-run heuristics remain as a fallback
for layouts not yet seen. After the fix the runner reports `exec_with_path` =
8 of 8 and task-access targets resolve.

### 8e5b85c and 7a644b0 (2026-09-08) -- one file, one identity

Two halves of the same problem: the same file reaching the attribution table
under two spellings.

`normalize_win_path` (`src/win_path_normalize.rs`) is the ETW half. It strips
`\\?\` and `\??\`, rewrites `\Device\HarddiskVolume<N>\` to a drive letter via a
cached `QueryDosDeviceW` table (refreshed on an unknown volume, left verbatim
when no drive maps), folds 8.3 short-name components to their long form, then
lowercases and collapses separators. Only paths containing `~` pay the
filesystem call. ETW records the spelling the writer opened, and `%TEMP%` on the
CI runners is `C:\Users\RUNNER~1\...`, so before the fold the long-form lookup
missed and a staged file lost its writer on the 2026-09-08 security gate.
Verified on the Azure runner: a PowerShell write through the short-name
directory is found by the long-form lookup, before and after a second reader.

The complementary half is in `fim.rs`: `notify` reports the spelling the writer
used, and downstream identity (finding keys, dedup, the attribution table) is by
path string, so the same staged file produced two `temp_modify` findings on the
same gate, one of them with a null writer. Windows event paths are now
canonicalized while the file exists (verbatim prefix stripped, UNC form
restored); a deleted path keeps its raw spelling.

### 306bb61 and 7d4ada3 (2026-09-08 / 2026-09-09) -- the OS-shipped mark is a pre-filter

`is_os_shipped_windows_image` matches three roots: `<drive>:\windows\`, `C:\Program
Files\Windows Defender\`, and `C:\ProgramData\Microsoft\Windows Defender\`. csrss,
lsass, svchost and Defender's MsMpEng open effectively every process with
`VM_READ`, and Windows delivers no in-message signing fact the way ES does, so
this path check exists to keep that constant background out of the ring.

Its only use is that pre-filter: a READ-grade open by an OS-shipped requester is
dropped, an ATTACH-grade open is forwarded whatever the requester's path. The
mark rides the wire on its own field, `ProcessEvent.platform_path_marked`, and
`is_platform_binary` stays `None`, because a path is not a kernel fact. The
grader in core does not trust the mark: it attaches the requester's measured
publisher verdict (in-process `WinVerifyTrust` plus catalog, via
`edamame_foundation::publisher_attestation`) and drops an edge only for a
Microsoft-signed binary at a canonical OS path.

### 7b23842 (2026-09-08) -- the writer is not the last reader

Before: every `FileIo/Create`, read-only opens included, overwrote the
attribution entry, so the last reader of a file became its recorded writer. On
the security gate the FIM hash worker's own read of a freshly dropped `~/.env*`
replaced the real writer with `edamame_posture`.

Now:

| Event | Action |
|---|---|
| `FileIo/Create` with a creating or truncating disposition (`FILE_SUPERSEDE`, `FILE_CREATE`, `FILE_OVERWRITE`, `FILE_OVERWRITE_IF`, read from the top byte of `CreateOptions`) | Record the attribution immediately |
| `FileIo/Create` with any other disposition | Remember the path against the kernel `FileObject` pointer; record nothing |
| `FileIo/Write` on a remembered `FileObject` | Record the attribution now |
| `FileIo/Cleanup` or `FileIo/Close` | Evict the remembered `FileObject` |

The remembered-object map is thread-local to the trace thread (only that thread
touches it), bounded at 16,384 entries with a 120 s TTL applied when the bound
is reached.

`examples/etw_file_writers.rs` checks this on a real host: it starts the
session, has one PowerShell child create and write a temp file through the 8.3
short spelling of its directory, then a second PowerShell child only read it via
the long form, and asserts that both lookups name the same pid and
`powershell.exe`.

```
cargo build --example etw_file_writers --features etw,examples
target\debug\examples\etw_file_writers.exe
```

### 2026-10-06 -- deletes and renames carry their actor

Before: `handle_fileio_event` read Create, Write, Cleanup and Close and dropped
every other opcode, and `fim` never looked a non-sensitive delete up (the only
table it had named writers). Every Windows delete reached the detectors with a
null process. FP lab run 37390270562 (windows-x64): a Claude Code session ran
`git worktree add` into a `mktemp -d` directory and `git worktree remove` 180 ms
later; the creates carried `git.exe`, the deletes of `tests\__init__.py`,
`tests\test_app.py` and `.github\workflows\ci.yml` carried nothing, and the
divergence engine's evaluator-integrity policy read an unknown actor deleting
test and CI files during the session as CRITICAL. macOS (Endpoint Security
UNLINK / RENAME carry their actor) passed the same case.

What the kernel sends, measured on the Azure runner (Windows Server 2022): a
delete (`DeleteFileW`, `RemoveDirectoryW`, git's `unlink` / `rmdir`,
PowerShell `Remove-Item`) is one `FileIo/Delete` (70, `FileIo_Info`, the
`FileObject` of the open that asked for it, `InfoClass` 64
`FileDispositionInformationEx`) plus one `FileIo/DeletePath` (79,
`FileIo_PathOperation`, the same request with the NT path). A rename is
`FileIo/Rename` (71, the object, i.e. the old name, `InfoClass` 10) plus
`FileIo/RenamePath` (80) whose `FileName` is the new name. An open with
`FILE_DELETE_ON_CLOSE` deletes with neither: the file goes when the opener's
last handle closes.

Now:

| Event | Action |
|---|---|
| `FileIo/Delete`, `FileIo/Rename` | Record the remembered `FileObject`'s path in the namespace table |
| `FileIo/DeletePath` | Record its path in the namespace table |
| `FileIo/RenamePath` | Record the old name (the object) and the new name; the object now names the new path |
| `FileIo/Create` with `FILE_DELETE_ON_CLOSE` | Record the path in the namespace table (and as a write when the disposition writes) |

`fim` asks the namespace table, and only it, for a delete or a rename while the
session runs: at event time, again through the deferred worker (2 s and 8 s,
sensitive events included), and in the drain-time backfills, which group a
path's writes and its deletes or renames apart. Never the writer table, the
attribution cache or the open-handle probes: those name whoever wrote or holds
the file. Without the session the previous behaviour stands (non-sensitive
deletes are not looked up).

`examples/etw_file_deletes.rs` checks it end to end with a `FimWatcher`: a
`git worktree add` / `git worktree remove --force` of a scratch repository in
`%TEMP%`, then PowerShell creating a tree, `Rename-Item`, `File.Replace`, a
`DeleteOnClose` file and `Remove-Item -Recurse`. It asserts every delete and
rename is attributed, to the pid of the process that ran the command (the
remover, not git's checkout child that wrote the files), and that no write is
given to the remover. Same scenario on the runner:

| | Delete | Rename | Create | Modify |
|---|---|---|---|---|
| Before | 0/17 attributed | 5/6 (from the writer table, the new name unattributed) | 17/17 | 40/40 |
| After | 17/17, all to the remover's pid | 6/6 | 17/17 | 37/37 |

```
cargo build --example etw_file_deletes --features etw,fim,examples
target\debug\examples\etw_file_deletes.exe
```

### 0f42307 (2026-09-10) -- attribution confined to the FIM watch roots

The FileIo session sees every file event on the machine, and every one of them
used to become an attribution entry. The only reader of that table is
`fim::kernel_table_attribution`, which is only ever asked about paths under a
FIM watch root, so on a build machine the table filled with thousands of entries
a minute that expired unread after their 30 s TTL, each costing two string
allocations and a map insert.

`src/fim_attribution.rs` is the always-compiled module that holds the roots and
answers "will anyone ever ask about this path". It is deliberately not behind
the `fim` feature: the sensors that consult it are gated on `endpointsecurity`
and `etw`, which are independent features, and a predicate that vanishes under a
`#[cfg]` stops confining anything. The FIM watcher publishes the roots on start
(`set_roots`) and clears them on stop.

On Windows the predicate must canonicalize through `win_path_normalize` before
matching, because the watcher registers the Win32 form while ETW reports the NT
object path and the runners' `%TEMP%` is a short name. Skipping that step
regressed `package_install_lifecycle` on windows-x64 in gate run 34520133863.

The commit message records that this is not a helper-CPU fix: on a release build
the FIM path already reported 0 ms per batch with the helper idling at 6-12%.
It removes work that was never read.

### 2026-09-29 -- every PROCESS_ALL_ACCESS spelling grades READ; the raw mask rides the event

On 2026-09-18 the blanket ask stopped grading ATTACH, but only for the exact
Vista value `0x001F_FFFF`. .NET asks for the legacy `0x001F_0FFF`
(`STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF`), so Chocolatey's
`Process.Handle` opens kept grading ATTACH and the detector's read relief could
never apply (FP-WIN-23: `choco.exe` 4 HIGH + 2 CRITICAL `access:attach` on the
released-2.0.2 cli and helper gates, runs 36508482670 / 36508252126). Masks
spelled only in generic or special rights graded query-only and were never
forwarded. The grading (`task_access_mode_for_desired_access`) is now a pure,
always-compiled function, unit-tested on every host, and `ProcessEvent` carries
the raw mask as `task_access_mask`.

Measured on the Azure windows-x64 runner with `process_events_monitor` and a
.NET Framework probe opening a live `ping.exe` (the kernel reports the mask as
the caller passed it, before generic mapping):

| Open | Mask reported | Mode now |
|---|---|---|
| .NET Framework `Process.Handle` | `0x1f0fff` | 1 (READ; was 2) |
| pwsh 7 (.NET) `(Get-Process).Handle` | `0x1f0fff` | 1 (READ; was 2) |
| `Process.MainModule` | `0x410` | 1 |
| `OpenProcess(0x1FFFFF)` | `0x1fffff` | 1 |
| `OpenProcess(VM_WRITE \| VM_OPERATION)` | `0x28` | 2 |
| `MAXIMUM_ALLOWED` / `GENERIC_ALL` / `GENERIC_READ` | `0x2000000` / `0x10000000` / `0x80000000` | 1 (were never forwarded) |
| `GENERIC_WRITE` | `0x40000000` | 2 (was never forwarded) |
| `PROCESS_QUERY_LIMITED_INFORMATION` | -- | not forwarded |

### 2026-09-29 -- the sessions stop with their process

ETW sessions are kernel objects: they outlive the process that started them.
The sessions lived in a static `OnceCell` with no stop path, so after the host
exited the NT Kernel Logger kept producing process, TCP/IP and FileIo events
for no consumer, and stayed taken, until the next EDAMAME start or a reboot.
The Azure runner showed it on 2026-09-29: both `NT Kernel Logger` (keywords
`process,net,fileio`) and `EDAMAME-KernelAuditApiCalls` were running with no
EDAMAME process on the host.

`l7_etw::shutdown()` (a no-op off Windows / without `etw`) stops both
sessions, idempotently and for good in that process; `is_available()` reads
false afterwards. It stops by the handle this process's `StartTraceW` returned,
and only while that session is still ours: a session another EDAMAME process
has since started under the same name is left alone. A session that was
starting while `shutdown` ran stops itself. Kernel session end also clears
`is_available()`, whoever ended it.

`init` registers `shutdown` with the CRT exit hook (`atexit`). That covers a
host whose `main` returns (the helper service returns once the SCM stops it)
and a DLL being unloaded. `std::process::exit` calls `ExitProcess` directly and
skips the hook: such a host calls `shutdown()` on its way out.

Measured on the runner with `process_events_monitor`: returning from `main`
left no EDAMAME session behind (`logman query -ets`); `--hard-exit`
(`std::process::exit`) left both running; `--shutdown --hard-exit` left none.

### 2026-10-07 -- a bare image name takes its program image path

`Process/Start` names an image by its bare `ImageFileName`. The full path came
from the command line's first token or from a live kernel query, so a process
started by bare name (`wmic ...`) and gone before its Start event was handled
kept `WMIC.exe`. That is not path-marked as OS-shipped, so its READ opens
reached the detector: the `edamame_cli` Windows gate graded `WMIC.exe` reading
`Runner.Worker.exe` CRITICAL on every run since 2026-09-30 (FP-CI-20 in
`edamame_core/FALSEPOSITIVES.md`).

Session A now takes `EVENT_TRACE_FLAG_IMAGE_LOAD`. The first program image
(`.exe`) mapped into a process is its own, logged as the process is created,
with the full NT path:

- `handle_image_load` keeps it per pid (`PROGRAM_IMAGES`, at most 8192
  entries, pruned past 120 s).
- A process-table entry of the same process that has only a bare name takes
  it, and so does Process/Start when its own name is bare.
- The audit thread resolves a bare-name requester the same way. While the
  record is not in yet (the two sessions deliver out of order), the open
  waits up to 2 s for it, then goes as it is.
- "The same process" means the same pid and a creation within 1 s; an unknown
  time never matches, and a bare name of another image is never replaced
  (`etw_process_payload::{same_process_creation, kernel_image_path_upgrades}`).
- The audit path's parent is now verified like the Exec path's: only a
  process created before the requester names it.

The Kernel-Process manifest provider's ProcessStart would carry `ImageName`
and `CreateTime` directly, but Windows 11 build 26200 delivers none to a user
session (logman with every keyword: event ids 3-8, 10 and 21 only).

Measured on the Azure runner against HEAD:

- A ~2 ms native opener launched 25 times by bare name: HEAD forwarded 3 opens
  as bare `tinyopen.exe`; the fix forwarded 2 with the full path and none bare.
- `tasklist /M` launched by bare name: HEAD forwarded 2 of 30 opens as bare,
  unmarked `tasklist.exe`; the fix forwarded none bare (the resolved ones are
  OS-shipped and dropped as background).
- The kernel session lost no buffers. It wrote 104 buffers in its first 8 s
  against 52, the extra mostly the image rundown at session start.

## Privilege, deployment and failure modes

Both sessions need Administrator or LocalSystem. `edamame_helper` runs as a
Windows Service under LocalSystem and is the production home of the kernel
session; `edamame_posture` also builds the feature and needs an elevated token
for it to start.

The NT Kernel Logger is system-wide and exclusive. It conflicts with PerfMon,
Xperf and Process Monitor, and with any other flodbadd-linked EDAMAME daemon on
the same host: `init` unconditionally stops any pre-existing session of that
name before starting its own, so the second daemon to start takes the session
away from the first. The private audit session is named
`EDAMAME-KernelAuditApiCalls` and behaves the same way against a stale session
of that name.

Every failure is soft. Nothing panics, nothing retries in a loop, and the rest
of the L7 and FIM paths continue on their own fallbacks.

| Failure | Effect | Status reported |
|---|---|---|
| Session A `StartTraceW` fails | `warn!("ETW StartTrace failed: ... (need Administrator privileges)")`, thread returns, `available` stays false | `Disabled: ETW kernel trace session failed to start (need Administrator)` |
| Session A `OpenTraceW` fails | `error!("ETW OpenTrace failed")`, session stopped, thread returns | Same as above |
| Session A healthy | `available` set true after `OpenTraceW` | `Enabled: Windows ETW kernel trace with TCP/IP, Process, and FileIo providers` |
| Session B `StartTraceW` / `EnableTraceEx2` / `OpenTraceW` fails | Debug log, session stopped, thread returns; task-access stream absent, everything else unaffected | Not reflected in `init_status` |
| Built on Windows without the feature | No-op stubs | `Not enabled: compiled without 'etw' feature flag` |
| Built on a non-Windows target | No-op stubs | `Not supported: ETW requires Windows` |

Availability is decided by a fixed 500 ms sleep in `init`: the constructor sleeps,
reads the `available` flag once, and freezes `init_status` from it. A session
that is slow to reach `OpenTraceW` is therefore reported as unavailable even
though it comes up shortly afterwards. `is_available()` itself keeps reading the
live atomic, so later callers see the truth; only the frozen status string and
the one-time startup log line are wrong in that window. `init_status` also says
nothing about Session B.

The status string reported by `fim::attribution_cache_stats` on Windows is
`l7_etw::is_available()`, which is Session A only.

On non-Windows targets, and on Windows without the feature, `l7_etw` compiles a
stub module: every lookup returns `None`, `is_available()` returns false, and the
counters return 0, so no call site needs its own `#[cfg]`.

The sensor cannot pollute its own stream. `query_image_path`, the audit
callback's fallback for a requester or target the process table does not know,
opens the process with `PROCESS_QUERY_LIMITED_INFORMATION` only -- never an
ATTACH-grade or VM_READ right -- and the callback drops any event where the
sensor's own pid is either side. FileIo events from the sensor's own pid are
dropped too, as are Process/Start events for its own pid.

## What is not enabled

These are ETW capabilities the module does not use. They are listed so nobody
has to re-derive that from `EnableFlags`, not as a roadmap.

| Capability | Flag / provider | State |
|---|---|---|
| DLL load tracking | `EVENT_TRACE_FLAG_IMAGE_LOAD` | The flag is on (program images, 2026-10-07); library loads are dropped as they arrive. Injected-DLL detection would need them. |
| Registry access tracing | `EVENT_TRACE_FLAG_REGISTRY` | Not enabled. |
| Thread lifecycle and cross-process thread creation | `EVENT_TRACE_FLAG_THREAD` | Not enabled. `PROCESS_CREATE_THREAD` in a `PsOpenProcess` mask is the only thread-injection-adjacent signal collected, and it is graded as ATTACH intent, not as an observed injection. |
| File read/write completion | `EVENT_TRACE_FLAG_FILE_IO` | Removed on purpose, see the section above. |
| Disk I/O, page faults, context switches | Various kernel flags | Not enabled. |

## Known limitations

- **The TCP/IP decode branches on event version alone.** `handle_tcp_event`
  treats version <= 1 as the IPv4 payload and version >= 2 as the IPv6 payload,
  without consulting the opcode. Modern kernels emit version 2 for IPv4 TcpIp
  events and use distinct opcodes for the IPv6 variants, so IPv4 tuples can be
  decoded through the IPv6 arm and never match a session key. This is consistent
  with the benchmark result that ETW never supplies the resolution on Windows,
  but it has not been re-measured since the 2026-04 benchmark, so treat the
  connection table as unproven rather than as known-broken.
- **The connection table has no TTL.** Entries are removed when the owning
  process's Process/End event arrives. A missed End event leaks a row until the
  daemon restarts.
- **A short-lived requester can lose its identity.** The PsOpenProcess event
  arrives on Session B, the requester's Process/Start and Process/End on
  Session A, and each session flushes on its own timer. A requester that exits
  within about a second can leave the process table (its End handled first)
  before its open is handled, and the kernel query fails as well: the edge
  carries an empty image, and the detector drops edges with no requester
  (measured 2026-09-29 on the Azure runner: every open by a .NET probe that
  exits at once, and a pwsh one-liner; 22 of 25 opens by a ~2 ms native
  probe on 2026-10-07). A requester whose Start was handled after it exited
  used to keep a bare image name; it now takes its program image path (see
  2026-10-07 above).
- **The remembered `FileObject` map is thread-local.** That is correct today
  because one trace thread delivers all FileIo events, and it is not safe to
  assume if a second consumer thread is ever added.
- **The sessions stop at exit only on a normal exit or an explicit
  `shutdown()`.** A host that ends with `std::process::exit` without calling
  `shutdown()`, or that is killed, leaves both sessions running until the next
  EDAMAME start stops them (see 2026-09-29 above). `shutdown` is final: nothing
  restarts ETW in that process.

## Troubleshooting

### "ETW StartTrace failed"

The process is not elevated, or another tool holds the NT Kernel Logger. Check
for PerfMon, Xperf, Process Monitor, and for a second EDAMAME daemon with the
feature built in. `logman query -ets` lists live sessions.

### File attribution returns nothing

1. Confirm Session A is up: `etw_support()` should report the `Enabled:` string.
2. Confirm the FIM watcher has published roots. With no roots installed
   `fim_attribution::is_attributable` is false for every path and nothing is
   recorded at all -- the table will be empty and `file_event_stats()` flat.
3. Confirm the path is under a watch root, after normalization. A path that
   normalizes outside the roots is dropped before any work is done.
4. Remember the 30 s TTL: a lookup for a file written a minute ago returns
   `None` by design.
5. Reproduce in isolation with `examples/etw_file_writers.rs`, which prints both
   the write path and the lookup path.

### No task-access edges

1. Session B failures only log at debug level. Raise the log level and look for
   `ETW audit-api-calls session open` on success, or
   `ETW audit-api-calls session not started` / `provider not enabled` /
   `OpenTrace failed` on failure.
2. The first 12 audit events are logged at info with their id, opcode and a
   32-byte payload preview. If those lines appear but no edge does, the payload
   shape on that kernel is the thing to check.
3. Query-only opens are never forwarded, and READ-grade opens from requesters
   under `%SystemRoot%` or the Defender roots are dropped as background. Drive
   the check with an explicit `0x0438` open, not a `0x0410` one.
4. `examples/process_events_monitor.rs` prints ring counters and up to 32
   task-access edges with their mode and raw mask (`--show-requester a,b`
   keeps only requesters whose name or path contains one of the texts):
   `cargo run --example process_events_monitor --features etw,examples -- --seconds 20`

### Connection table empty

Expected. See the known limitation above; `netstat2` resolves those sessions and
records them as `ExactMatch`.

## Code structure

```
flodbadd/
  src/
    l7_etw.rs                 # Both sessions, the three tables, both callbacks (Windows)
    etw_process_payload.rs    # Pure MOF Process_V3/V4 decoder, host-testable
    win_path_normalize.rs     # Canonical Windows path form shared by ETW and FIM
    fim_attribution.rs        # Watch-root confinement, shared with the macOS ES sensor
    fim.rs                    # FIM watcher, tiered attribution, Windows path folding
    process_events.rs         # Bounded cross-platform process-event ring
    l7.rs                     # L7 resolution dispatch (eBPF -> ETW -> ES -> netstat)
  examples/
    etw_file_writers.rs       # Writer-vs-reader attribution check on a real host
    process_events_monitor.rs # Ring counters, event rates, task-access edges
```

The module uses the `windows` crate's raw Win32 ETW APIs directly (`StartTraceW`,
`ControlTraceW`, `EnableTraceEx2`, `OpenTraceW`, `ProcessTrace`, `CloseTrace`,
`EVENT_RECORD` callbacks). No external ETW helper crate.

## Related documentation

- [L7.md](L7.md) -- L7 resolution across all platforms, including where ETW sits
- [EBPF.md](EBPF.md) -- Linux counterpart
- [ENDPOINTSECURITY.md](ENDPOINTSECURITY.md) -- macOS counterpart, and the file
  attribution table this one mirrors
- [ETW event tracing portal](https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal)
- [NT Kernel Logger constants](https://learn.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants)
