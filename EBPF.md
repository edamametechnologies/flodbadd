# eBPF Kernel Sensors (Linux)

## Scope

The `ebpf` feature builds and embeds two BPF ELF objects and loads them with
aya at first use. What started as L7 process attribution for TCP sessions is
now four distinct sensors sharing one object:

| Sensor | Mechanism | Consumer |
|---|---|---|
| L7 session attribution | 4 kprobes + 2 hash maps | `l7.rs` session resolution |
| Process lifecycle stream | 3 `sched` tracepoints + ringbuf | `process_events.rs` ring |
| Cross-process task access (BS-9) | `ptrace_may_access` kprobe, BPF-LSM fallback | `process_events.rs` ring |
| Kernel-time egress intent | 4 cgroup `sock_addr` programs | `process_events.rs` ring |

A fifth Linux kernel sensor ships with the same feature but is not BPF:
`fim_fanotify.rs` uses fanotify for FIM writer attribution. It is documented
here because it rides the `ebpf` feature set and joins the BPF exec stream.

Everything except the L7 attribution path is fail-open and non-critical: a
program that cannot load or attach logs at `debug!` and the stream is simply
absent. Only a failure of the `tcp_set_state` kprobe disables the L7 helper.

## L7 object hook inventory

`ebpf/l7_ebpf_program/src/l7_ebpf.c`, loaded by `src/l7_ebpf.rs`.

| Program | Attach point | Type | Role |
|---|---|---|---|
| `track_connect_v4` | `tcp_v4_connect` | kprobe | Stash process info keyed by `struct sock *` |
| `track_connect_v6` | `tcp_v6_connect` | kprobe | Same, IPv6 |
| `minimal_probe` | `tcp_set_state` | kprobe | On `TCP_ESTABLISHED`, join the 4-tuple to the stashed process info |
| `socket_cleanup` | `__sk_free` | kprobe | Delete the `socket_to_process` row |
| `trace_sched_fork` | `sched/sched_process_fork` | tracepoint | Fork event + child to parent row |
| `trace_sched_exec` | `sched/sched_process_exec` | tracepoint | Exec event with the binary path |
| `trace_sched_exit` | `sched/sched_process_exit` | tracepoint | Exit event, group leaders only |
| `trace_ptrace_may_access` | `ptrace_may_access` | kprobe | Task-access attempt (ring kind 4) |
| `lsm_ptrace_access_check` | `ptrace_access_check` | BPF-LSM | Fallback for the above, always returns 0 (allow) |
| `cg_connect4` / `cg_connect6` | cgroup v2 root | `cgroup/connect{4,6}` | Egress intent at `connect(2)` |
| `cg_sendmsg4` / `cg_sendmsg6` | cgroup v2 root | `cgroup/sendmsg{4,6}` | Egress intent at unconnected UDP send |

Six kprobes, three tracepoints, one BPF-LSM program, four cgroup programs.

The `tcp_v4_connect` / `tcp_v6_connect` pair exists for one reason: they run
in the caller's user context, so `bpf_get_current_pid_tgid()` names the
process that called `connect()`. `tcp_set_state` can fire from softirq
context, where the same helper returns the kernel thread (`swapper/0`). The
connect probes write `socket_to_process` keyed by the socket pointer;
`tcp_set_state` reads that row back and only falls through to the current
task when there is none.

`socket_cleanup` deletes the `socket_to_process` row when the socket is
freed. It deliberately leaves `l7_connections` alone so userspace can still
resolve a session whose socket is already gone.

Note on `l7_connections` lifetime: the C source says those rows are "cleaned
up by TTL in userspace", but no such sweep exists today. `src/l7_ebpf.rs`
only ever calls `get()` on the map. Rows are overwritten on key collision
and otherwise persist for the life of the process, bounded by the 65536
entry cap.

## L7 object maps

| Map | Type | Max entries | Key / value |
|---|---|---|---|
| `l7_connections` | HASH | 65536 | `session_key` (5-tuple + family) -> `process_info` |
| `socket_to_process` | HASH | 65536 | `struct sock *` (u64) -> `process_info` |
| `proc_events` | RINGBUF | 262144 bytes (256 KiB) | `proc_event` records |
| `proc_parent` | HASH | 65536 | child pid -> parent pid |
| `proc_tp_cfg` | ARRAY | 1 | Live tracepoint field offsets from the loader |
| `task_access_cfg` | ARRAY | 1 | Sensor tgid + PTRACE_MODE mask |
| `net_intent_seen` | LRU_HASH | 8192 | `(tgid, family, proto, port, addr)` -> last-seen ns |

`proc_event` is a fixed 272-byte record: `kind`, `pid`, `ppid`, `uid`, and a
256-byte text slot whose meaning depends on `kind` (exec path, comm, or the
packed network destination). Kinds are 1 exec, 2 fork, 3 exit, 4 task
access, 5 net connect.

## DNS object

`ebpf/l7_ebpf_program/src/dns_ebpf.c`, loaded by `src/dns_ebpf.rs`. Five
kprobes, two maps.

| Program | Attach point | Role |
|---|---|---|
| `trace_udp_send` | `udp_sendmsg` | Source port for the pending query; connected-socket path |
| `trace_udpv6_send` | `udpv6_sendmsg` | Same, IPv6 |
| `trace_sendto` | `__sys_sendto` | Unconnected UDP, destination read from the `sendto` sockaddr |
| `trace_udp4_connect` | `ip4_datagram_connect` | UDP socket made "connected" to a resolver |
| `trace_udp6_connect` | `ip6_datagram_connect` | Same, IPv6 |

| Map | Type | Max entries | Key / value |
|---|---|---|---|
| `dns_sockets` | HASH | 65536 | source port (u16) -> `dns_socket_info` |
| `dns_events` | RINGBUF | 256 KiB | Reserved for debugging, no consumer today |

The `__sys_sendto` probe is there because the common DNS client does not
`connect()` its UDP socket: glibc's resolver sends with `sendto()` and the
destination lives in the syscall's sockaddr argument, not on the socket. At
`__sys_sendto` time only the fd is known, not the source port, so the probe
stores the record keyed by pid; the `udp_sendmsg` / `udpv6_sendmsg` probe
that follows reads the source port off the socket, rewrites the entry under
the source-port key and deletes the pid-keyed one.

Userspace correlates a captured DNS packet back to a process by looking up
the packet's source port in `dns_sockets`.

## CO-RE policy

The overview claim that eBPF gives "compile once, run everywhere" is only
half true here, on purpose.

**Sockets do not use CO-RE.** `vmlinux.h` in this repo is a hand-trimmed
154-line header; `struct sock` in it is an opaque forward declaration. Both
objects read `sock_common` at hard-coded byte offsets verified with `pahole`
on 6.8.0-88-generic (`skc_daddr` 0, `skc_rcv_saddr` 4, `skc_dport` 12,
`skc_num` 14, `skc_family` 16, `skc_v6_daddr` 56, `skc_v6_rcv_saddr` 72).
These offsets are stable across the kernels in scope, and the alternative
would be either vendoring a full generated `vmlinux.h` (megabytes, and a new
one per architecture) or depending on kernel BTF at load time for the L7
path, which would lose attribution on every kernel built without BTF. The
tradeoff is deliberate: the L7 path works without BTF, at the cost of an
assumption that must be rechecked if `sock_common` ever changes layout.

**`task_struct` does use CO-RE.** The task-access programs need `tgid` and
`comm`, and the trimmed `vmlinux.h` has no `task_struct` at all (again, only
a forward declaration). Rather than guess those offsets, the object declares
a CO-RE flavour:

```c
struct task_struct___local {
    int tgid;
    char comm[16];
} __attribute__((preserve_access_index));
```

The `___local` suffix is stripped when relocating against the running
kernel's BTF, so `bpf_core_read()` resolves both fields per kernel. The same
technique is used for `bpf_sock_addr___local` in the cgroup programs.

## Process-event stream

The three `sched` tracepoints, the task-access hook and the four cgroup
programs all write to `proc_events`. A dedicated `proc-events-ebpf` thread
drains the ringbuf and pushes into the cross-platform ring in
`src/process_events.rs` (macOS fills the same ring from Endpoint Security,
Windows from the NT Kernel Logger).

Exec argv never crosses the kernel boundary. The consumer reads
`/proc/<pid>/cmdline` at delivery time and stores only a SHA-256 digest plus
the argument count (invariant I5). A process that is already gone yields
`None`, which reads as unmeasured rather than empty.

### Tracepoint records are not layout-stable

`sched_process_exec` has a fixed layout (`__data_loc filename` at 8, `pid` at
12, `old_pid` at 16) and is read as a struct. `sched_process_fork` and
`sched_process_exit` are not. Kernel 6.17 moved the fork comm fields to
`__data_loc`, shrinking the record from 48 bytes to 24. A program that
touches the context past the real record size is rejected at ATTACH time
(`perf_event_set_bpf_prog` refuses `max_ctx_offset > record size`), so on the
6.17 dogfood host fork and exit never fired at all and the failure surfaced
only as a `bpf_link_create failed` debug line.

The fix (c5e2a44) is to stop hard-coding those offsets. The loader parses
`/sys/kernel/tracing/events/sched/<tp>/format` (falling back to
`/sys/kernel/debug/tracing`), extracts each field's offset and whether it is
`__data_loc`, and writes them into `proc_tp_cfg` before the programs attach.
The two programs then use `bpf_probe_read_kernel` exclusively with zero
direct context access, so there is no `max_ctx_offset` for the kernel to trip
on, and they return early while `cfg->valid` is 0. Unreadable tracefs means
no fork/exit stream, not a failed load.

### Task access (BS-9)

`ptrace_may_access(task, mode)` is the choke point for every cross-process
memory primitive: `ptrace` attach, `process_vm_readv` / `writev`, and every
open of `/proc/<pid>/mem`, `maps`, `environ`, `auxv`, `stack`. A kprobe on it
fires on the attempt, before the kernel decides, which is the half an
observer wants: the attempt that Yama refuses is exactly the interesting one.

Only the requester tgid, the target tgid, the mode bits and the target comm
leave the kernel. The consumer resolves both images from `/proc`.

Two in-kernel filters carry the design (6caca3c):

- **Self-tgid.** The loader writes its own pid into `task_access_cfg`. Without
  it the consumer's own `/proc/<pid>/exe` readlinks, done while resolving the
  previous event, go through `ptrace_may_access` and re-trigger the probe.
  That feedback loop was measured at 26,000 events per second.
- **ATTACH-only.** The mode mask defaults to `PTRACE_MODE_ATTACH` (0x02).
  READ mode (0x01) covers `ps`, `lsof` and every IDE reading `exe`, `maps`,
  `environ` or `cmdline`; it is ambient noise on any desktop and is already
  covered by the procfs open-file route.

The program also drops `target_tgid == 0` and `target == requester`, since
reading one's own `/proc/self/*` is not cross-process access.

The wire field is `task_access_mode` (18d1134), not an overload of
`argv_len`. The vocabulary is shared by all three platform backends: 1 READ
(macOS `GET_TASK_READ`, Linux `PTRACE_MODE_READ`), 2 ATTACH (macOS `GET_TASK`
control port, Linux `PTRACE_MODE_ATTACH`).

### BPF-LSM is a fallback, never a second source

`lsm/ptrace_access_check` observes the same check at the security layer. It
is a stable attach point with no symbol dependence, and it is where a future
enforce mode would return `-EPERM`. In observe mode it always returns 0.

The loader attaches it **only** when the kprobe could not load or attach, and
never alongside it (70848fb). The reason is ordering: LSM hooks run in
`lsm=` boot-line order and stop at the first refusal, and `bpf` is last. An
access that Yama or AppArmor denies therefore never reaches the BPF hook,
while the kprobe still sees the attempt. Verified on the Lima VM booted with
`lsm=...,bpf`: the sibling `/proc/<pid>/mem` read Yama refuses is reported by
the kprobe only. Loading an LSM program requires kernel BTF
(`aya::Btf::from_sys_fs()`); without it there is no task-access stream.

### Kernel-time egress intent

`cgroup/connect{4,6}` fires at `connect(2)` for TCP and connected UDP;
`cgroup/sendmsg{4,6}` fires at every unconnected UDP send, DNS queries
included. That is the "who asked for which destination" half of BS-5, and the
attach point a future cgroup deny would return 0 from. All four return 1
(allow).

They attach to `/sys/fs/cgroup` as plain BPF links in `CgroupAttachMode::Single`.
Links coexist with other links and with systemd's own cgroup programs; aya's
link API rejects the allow-multi flag, so Single is the mode that works. (The
C source comment still says allow-multi; the loader is authoritative.)

Volume is bounded in the kernel by `net_intent_seen`, an LRU keyed on
`(tgid, family, proto, port, addr)` that drops repeats inside a 1 second
window. A chatty UDP flow therefore costs one event per second. The sensor's
own traffic is excluded via the same `task_access_cfg.self_tgid`.

The verifier will not let a v4 program touch `user_ip6` or vice versa, so
`is_v6` is a compile-time constant argument to the shared helper and the
branch folds away rather than being evaluated at run time.

The destination is packed into the event's 256-byte text slot: family at 0,
protocol at 1, port (network order) at 2, 16-byte address at 4, comm at 20.

## FIM writer attribution via fanotify

`src/fim_fanotify.rs`, added in 18b7b56.

Before it, Linux FIM used `notify` (inotify), which reports *what* changed
but never *who*. The writer was resolved after the fact by running `lsof`
against the path, which loses the race whenever the writer closes the file
before the poll. That is the shape of every credential-drop trigger, and the
security gate showed the consequence directly: `file_events` findings with a
null writer, graded LOW, on ubuntu-arm64 on 2026-09-07.

fanotify delivers `FAN_MODIFY` / `FAN_CLOSE_WRITE` with the writer's pid and
an open fd on the file, at kernel time.

| Property | Value |
|---|---|
| Init flags | `FAN_CLASS_NOTIF \| FAN_CLOEXEC`, notification class only, no permission events |
| Mark mask | `FAN_MODIFY \| FAN_CLOSE_WRITE \| FAN_EVENT_ON_CHILD` |
| Marking | Each FIM root and its subdirectories, breadth-first, no symlink following |
| Mark cap | 4096, against a kernel default `max_user_marks` of 8192 per user |
| Table | Path to writer, 60 s TTL, pruned when it reaches 50,000 entries |
| Privilege | `CAP_SYS_ADMIN` |

Marks are per directory, so a directory created after startup would be
invisible. The notify watcher closes that gap: on a `Create(Folder)` event it
calls `fim_fanotify::remark_directory()` for the new path.

The reader thread resolves the event path by reading
`/proc/self/fd/<event fd>` and skips events whose pid is its own. Writer
image resolution is three steps, in order:

1. `/proc/<pid>/exe` -- the normal case, writer still alive.
2. `/proc/<pid>/comm` -- alive but exe unreadable.
3. The eBPF exec ring -- the writer has already exited.

Step 3 is the cross-sensor join that actually closes the race. A
`sh -c 'echo secret > file'` writer is gone before the reader thread wakes,
so procfs has nothing; the `sched_process_exec` event for that pid still
carries the image path.

`fim::kernel_table_attribution()` reads this table as Tier 1, the same slot
Endpoint Security occupies on macOS and ETW FileIo on Windows. Tier 2 is the
in-memory `lsof` cache, Tier 3 the live `lsof` probe.

Unlike the macOS and Windows tables, the fanotify table needs no watch-root
confinement. ES and ETW sessions see every file event on the machine, so both
guard their insert with `fim_attribution::is_attributable()` to avoid filling
the table with rows that expire unread. fanotify is mark-based: the kernel
only delivers events for directories that were explicitly marked, which are
by construction the FIM roots.

## FIM watch roots (657ee49)

Not an eBPF change, but the same subsystem and the most expensive failure in
this file's history.

In CI mode the FIM watch list fell back to `std::env::current_dir()` when
`GITHUB_WORKSPACE` was unset. The systemd-started runner-protection daemon has
cwd `/`, so it watched the whole filesystem recursively. The inotify walk went
through `/proc` and `/sys` and never finished: 28,551 watches after five
hours and still adding, with bookkeeping growing roughly 40 MB per minute,
reaching 17-24 GB RSS in 6-8 hours on the Azure runners until the kernel
OOM-killed the GitHub runner service during the 1.8.4 release on 2026-09-03.

Two independent guards now exist:

- `ci_workspace_root()` prefers `GITHUB_WORKSPACE`, `CI_PROJECT_DIR` and
  `BUILD_SOURCESDIRECTORY` in that order, accepting each only if
  `is_acceptable_workspace_root()` passes, then the cwd under the same test,
  and otherwise watches no workspace at all.
- `is_acceptable_workspace_root()` requires an existing directory that is not
  a filesystem root, not one of the top-level system trees, and at least two
  normal path components deep.
- `FimWatcher::start()` independently refuses a recursive watch on a root or
  top-level system tree whatever the caller passed, and logs the refusal.

The forbidden-root list is platform-neutral by design: it carries the Unix
trees (`/bin`, `/proc`, `/sys`, `/usr`, `/var`, the macOS `/Applications`,
`/Library`, `/System`, `/Users`, `/Volumes`, `/private`) and the Windows drive
roots (`C:\`, `C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`,
`C:\Users`). `/tmp` and `/var/tmp` are not in the list and stay watchable.

## RLIMIT_MEMLOCK before load (ab753b8)

`setrlimit(RLIMIT_MEMLOCK, RLIM_INFINITY)` runs immediately before
`Ebpf::load()`. On kernels below 5.11, and in locked-down containers, BPF map
memory is charged against `RLIMIT_MEMLOCK`, whose default makes
`BPF_MAP_CREATE` fail with `EPERM`. The visible symptom was
`failed to create map 'socket_to_process' with code -1`, a Sentry issue with
23,000 events across production hosts on 1.4.1 through 1.8.3.

Failing to raise the limit is not itself fatal; the load below reports the
real outcome.

The same commit demoted the load failure from `error!` to `warn!`. An eBPF
load or kprobe failure is an environment limitation: capture degrades to the
non-eBPF L7 path and the `Disabled: ...` status is surfaced to the operator.
At `error!` it was producing one Sentry event per process start on every
affected host.

## Build

### Feature

```toml
[dependencies]
flodbadd = { version = "*", features = ["packetcapture", "ebpf"] }
```

`ebpf = [ "aya", "bytemuck", "nix", "l7_ebpf_program" ]`. `aya` 0.13,
`bytemuck` (map key/value `Pod` impls) and `nix` (with `user`, `resource` and
`fanotify`) are declared under
`cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))`.
aya does not support 32-bit, so those are the two supported architectures.

### Toolchain

```bash
# Ubuntu/Debian
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r)

# Alpine Linux
sudo apk add clang llvm libbpf-dev linux-headers

# Fedora/RHEL
sudo dnf install clang llvm libbpf-devel kernel-devel
```

### Compilation

`build.rs` compiles both objects on Linux when the feature is on, removing any
stale object first so clang always runs and diagnostics stay fresh:

```
clang -target bpf -D__BPF_TRACING__ -D__TARGET_ARCH_<arch> -Wall -O2 -g -c \
      -I<arch include> -I ebpf/l7_ebpf_program/src -o <out>.o <src>.c
```

Architecture mapping is `aarch64` to `arm64` and `x86_64` to `x86`, with the
include path `/usr/include/aarch64-linux-gnu` or
`/usr/include/x86_64-linux-gnu` respectively, falling back to `/usr/include`
when the arch-specific directory does not exist.

On success the build sets `L7_EBPF_OBJECT` / `DNS_EBPF_OBJECT` plus the cfg
flags `L7_EBPF_EMBEDDED` / `DNS_EBPF_EMBEDDED`, and the objects are embedded
with `include_bytes!`.

Two things about this step are deliberate:

- **The object is never stripped.** `llvm-strip -g` removes the `.BTF` and
  `.BTF.ext` sections, which aya needs. The debug info is the BTF.
- **Missing clang is not a build failure.** It emits a cargo warning, no
  object is produced, the cfg flag stays unset, `EBPF_OBJECT` is an empty
  slice, and the runtime status reads
  `Disabled: eBPF object not embedded (clang/llvm not available at build time)`.

At load time the embedded bytes are copied into a `Vec<u8>` first.
`include_bytes!` does not guarantee the 8-byte alignment aya's ELF parser
requires; without the copy, loading broke on aarch64.

`ebpf/l7_ebpf_program/build.rs` is a second, narrower build script for the
subcrate that compiles `l7_ebpf.c` only. The top-level `build.rs` is the one
that produces the objects the crate actually embeds.

## Runtime requirements

| Requirement | Details |
|---|---|
| Architecture | `x86_64`, `aarch64` |
| Kernel (L7 kprobes) | 5.3 minimum, enforced by the loader preflight |
| Kernel (`proc_events` ringbuf) | 5.8 (`BPF_MAP_TYPE_RINGBUF`) |
| Kernel (cgroup links) | 5.7 |
| BPF-LSM | `CONFIG_BPF_LSM`, `bpf` present in the `lsm=` boot line, and kernel BTF at `/sys/kernel/btf/vmlinux` |
| fanotify | `CAP_SYS_ADMIN` |
| Privileges | root, or `CAP_BPF` + `CAP_SYS_ADMIN` |
| Kernel config | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y` |

### Loader preflight

Before touching the object, `Inner::new_with_status()` checks, in order:

1. `/proc/sys/kernel/unprivileged_bpf_disabled` -- a value of 1 or 2 while
   the effective uid is non-zero returns `Disabled: unprivileged_bpf_disabled=N
   and not running as root`.
2. Kernel version from `uname()` -- below 5.3 returns
   `Disabled: kernel M.m < 5.3`.
3. LinuxKit detection (`linuxkit` in the release string) and container
   detection (`/.dockerenv`, or `/docker/`, `/lxc/`, `/containerd/` in
   `/proc/1/cgroup`). Neither aborts the load; both sharpen the message the
   operator sees.

`perf_event_paranoid` and the debugfs mount are checked and logged at debug
level only.

### Checking availability by hand

```bash
uname -r

cat /proc/sys/kernel/unprivileged_bpf_disabled
# 0 = unprivileged BPF allowed
# 1 = unprivileged BPF disabled (need root)
# 2 = permanently disabled until reboot

ls -la /sys/kernel/btf/vmlinux        # needed for the BPF-LSM fallback
cat /sys/kernel/security/lsm          # is 'bpf' in the list, and last?
mount | grep -E 'cgroup2|tracefs|debugfs'
```

## Platform support

| Platform | eBPF | Notes |
|---|---|---|
| Linux (native) | Yes | All sensors |
| Linux (VM) | Yes | Lima and similar; the validation environment |
| Linux (container) | Limited | Needs privileged mode or explicit capabilities |
| Docker Desktop | No | LinuxKit kernel lacks kprobe support |
| macOS | No | Endpoint Security instead, see ENDPOINTSECURITY.md |
| Windows | No | netstat2, with ETW for FIM, see ETW.md |

```yaml
# Docker Compose
services:
  app:
    cap_add:
      - SYS_ADMIN
      - SYS_PTRACE
      - BPF
      - NET_ADMIN
    security_opt:
      - seccomp:unconfined
```

## Failure behaviour

Failure is layered, and the layers are not equivalent.

**Hard failure (L7 helper disabled).** Any of: preflight rejection, empty
embedded object, `Ebpf::load()` error, `minimal_probe` failing to cast, load
or attach to `tcp_set_state`, or `l7_connections` missing from the object.
`Inner` is `None`, `is_available()` is false, and session resolution falls
back to the polling path: `netstat2` (`/proc/net/tcp` and friends on Linux).
This costs short-lived sessions, as the benchmark below shows, but nothing
breaks.

**Fail-open (stream absent).** Everything added in 2026. The connect probes,
the three tracepoints, `proc_tp_cfg` installation, the task-access kprobe and
its LSM fallback, the four cgroup programs, the ringbuf consumer thread, and
fanotify: each logs at `debug!` (fanotify at `info!`) and leaves its stream
absent. Consumers see that through the `process_events` counters, or through
fanotify simply having no table and FIM reverting to `lsof`.

### Status string

`ebpf_support()` returns the composed status. On success:

```
Enabled: kernel <release> with tcp_set_state kprobe attached[ (container)][; task access via kprobe|; task access via BPF LSM][; cgroup net-intent observe]
```

On failure it is one of the `Disabled: ...` strings above.

`is_fully_functional()` greps that status for the literal `"kprobe attached"`.
That is what the integration tests gate on (`tests/ebpf_l7_integration_test.rs`,
`tests/l7_short_lived_process_test.rs`), so a containerised CI run where the
kprobe cannot attach skips those tests rather than failing them. The DNS
loader follows the same convention with its own status string
(`Enabled: kernel <release> with udp_sendmsg[ + sendto][ + IPv6] kprobe attached`).

## Measured numbers

Each figure below comes from a named source. Nothing here is estimated.

| Figure | What it measures | Source |
|---|---|---|
| 26,000 events/s | Feedback loop from the consumer's own `/proc/<pid>/exe` readlinks re-entering `ptrace_may_access`, without the self-tgid filter | 6caca3c bring-up |
| 23,000 Sentry events | `failed to create map 'socket_to_process' with code -1` across production hosts, 1.4.1 through 1.8.3 | Sentry, ab753b8 |
| 28,551 watches, 17-24 GB RSS in 6-8 h | Recursive inotify walk from cwd `/` on the Azure runners | 657ee49, 1.8.4 release 2026-09-03 |
| 10 reads -> 10 events, 0 evictions | Task-access probe fidelity, 10 sibling `/proc/<pid>/mem` reads | Lima VM, kernel 6.8, 6caca3c |
| 4 programs attached, NTP/DNS/HTTPS observed with pid and image | cgroup net-intent bring-up | Lima VM, 70848fb |
| 1 event/s per flow | Net-intent LRU ceiling per `(tgid, family, proto, port, addr)` | `NET_INTENT_WINDOW_NS`, by construction |
| 100% resolution at every hold duration including 0 ms | L7 attribution with eBPF | `tests/l7_benchmark_test.rs`, L7.md |
| 71% overall, 50 ms minimum session | L7 attribution without eBPF on Linux | Same benchmark |

There is no CPU or overhead measurement for the eBPF programs themselves. The
benchmark measures resolution rate and end-to-end latency, not the cost of the
kernel-side programs. Claims like "near-zero overhead" are architectural
reasoning, not data, and should not be quoted as a measurement.

For the full per-platform benchmark tables, see L7.md.

## Troubleshooting

### eBPF not loading

```
[l7_ebpf] Failed to load eBPF object: no BTF parsed for object
```

BTF was stripped from the object. Check that nothing runs `llvm-strip -g` on
the `.o`; `build.rs` deliberately does not.

```
Failed to load eBPF program: map error: failed to create map `socket_to_process` with code -1
```

`RLIMIT_MEMLOCK`. This is what ab753b8 fixed; if it reappears, check whether
the process is prevented from raising its own limit (the loader logs
`could not raise RLIMIT_MEMLOCK` at warn when `setrlimit` itself fails).

### Kprobe attachment failed

```
Disabled: kprobe attachment failed - ... (kernel 6.8.0-88-generic)
```

Causes: running in a container without privileges, kernel built without the
target function, or SELinux/AppArmor blocking BPF. In order:

1. Run as root, or grant `CAP_BPF` + `CAP_SYS_ADMIN`.
2. `sudo sysctl -w kernel.perf_event_paranoid=-1`.
3. Mount debugfs: `sudo mount -t debugfs none /sys/kernel/debug`.
4. For containers, `--privileged` or the capability set above.
5. SELinux: `ausearch -m avc -ts recent`.

`make ebpf_setup` performs steps 2 and 3 plus the bpffs mount.

### Process info shows "swapper/0"

The connection was seen in kernel context rather than user context. The
`tcp_v4_connect` / `tcp_v6_connect` probes exist precisely to avoid this for
client connections; if it still happens, check whether those two probes
attached (they are non-critical and their failure only logs at debug).
Server-side connections arriving through the accept path have no user-context
`connect()` to hook, so they remain exposed to it.

### No fork or exit events, exec works

The `proc_tp_cfg` install failed, or tracefs is unreadable. Look for
`proc_tp_cfg: tracefs format unreadable` or `proc_tp_cfg set failed` at debug
level. Confirm `/sys/kernel/tracing/events/sched/sched_process_fork/format`
is readable as the running user.

### No task-access events

Check the status string suffix. Neither `; task access via kprobe` nor
`; task access via BPF LSM` means both the kprobe and the LSM fallback failed.
The LSM path additionally needs `/sys/kernel/btf/vmlinux` and `bpf` in the
`lsm=` boot line. Remember that only ATTACH-mode accesses are reported by
design; `ps` and `lsof` will never show up here.

### No net-intent events

No cgroup v2 mounted at `/sys/fs/cgroup`, kernel below 5.7, or the attach was
refused. All four programs are optional and log at debug.

### FIM writers are null

`FIM fanotify writer attribution unavailable: ...` at info level means no
`CAP_SYS_ADMIN` or no fanotify; attribution falls back to `lsof` with the
race it always had. `directory mark cap (4096) reached` means deeper
directories under the watch roots are `lsof`-attributed only.

### Map lookups return None

1. Timing: the session key must match exactly. eBPF captures at
   `TCP_ESTABLISHED`.
2. IP byte order: `skc_rcv_saddr` / `skc_daddr` are network order, `skc_num`
   is host order and `skc_dport` is network order (the program converts it).
3. Protocol: `l7_connections` is populated for TCP only. UDP attribution for
   DNS goes through the separate DNS object.

## Testing

```bash
# Full Linux suite with eBPF (sets up debugfs, bpffs, sysctls first)
make linux_test

# Same without the feature, for comparison
make linux_test_no_ebpf

# L7 resolution benchmark
make linux_benchmark
make linux_benchmark_no_ebpf

# eBPF integration tests only
cargo test --features packetcapture,ebpf --test ebpf_l7_integration_test -- --nocapture
cargo test --features packetcapture,ebpf --test dns_ebpf_integration_test -- --nocapture
cargo test --features packetcapture,ebpf --test ipv6_ebpf_test -- --nocapture

# fanotify end-to-end, needs root, ignored by default
sudo -E cargo test --features fim,ebpf -- --ignored fanotify
```

### Diagnostics

```bash
cargo build --release --features packetcapture,ebpf --examples
./target/release/examples/check_ebpf          # L7 object status
./target/release/examples/check_dns_ebpf      # DNS object status
./target/release/examples/process_events_monitor   # live ring, per-second counters
BINARY_PATH=./target/release/examples/check_ebpf ./tests/ebpf_test.sh
```

### Lima VM (from macOS)

eBPF needs a Linux kernel, so development on macOS runs against a Lima VM.

```bash
make lima_create        # once; uses Lima.linux-test.yml
make lima_start
make lima_test          # build + diagnostics + full suite in the VM
make lima_test_ebpf     # eBPF tests only
make lima_test_dns_ebpf # DNS eBPF tests only
make lima_shell
make lima_status
```

`LIMA_VM_NAME` defaults to `ebpf-test`; the workspace VM used for the 2026
bring-up validations is `core-ebpf-test`, passed as
`make lima_test LIMA_VM_NAME=core-ebpf-test`. Alternative guest images:
`Lima.ubuntu2004-test.yml`, `Lima.ubuntu2204-test.yml`,
`Lima.alpine-test.yml`, `Lima.alpine315-test.yml`.

## Code structure

```
flodbadd/
├── ebpf/
│   └── l7_ebpf_program/
│       ├── src/
│       │   ├── l7_ebpf.c       # L7 + process events + task access + net intent
│       │   ├── dns_ebpf.c      # DNS source-port to process map
│       │   ├── vmlinux.h       # Trimmed kernel header (opaque sock, opaque task_struct)
│       │   └── lib.rs
│       ├── build.rs            # Subcrate build (l7_ebpf.c only)
│       └── Cargo.toml
├── src/
│   ├── l7.rs                   # L7 resolution interface and fallback ordering
│   ├── l7_ebpf.rs              # aya loader, attach sequence, ringbuf consumer
│   ├── dns_ebpf.rs             # aya loader for the DNS object
│   ├── process_events.rs       # Cross-platform process-event ring (I5 argv digest)
│   ├── fim_fanotify.rs         # Linux FIM writer attribution
│   ├── fim.rs                  # Watch roots, tiered attribution
│   └── capture.rs
├── examples/
│   ├── check_ebpf.rs
│   ├── check_dns_ebpf.rs
│   └── process_events_monitor.rs
└── build.rs                    # Compiles and embeds both objects
```

## Security considerations

### Privileges

- Root or `CAP_SYS_ADMIN` to load programs.
- `CAP_BPF` (5.8+) for the BPF syscall subset.
- `CAP_PERFMON` may be required for perf_event-based kprobes.
- `CAP_SYS_ADMIN` for fanotify.

### Observe only

Every program in both objects is notify-only. The BPF-LSM hook returns 0
(allow) unconditionally and the four cgroup programs return 1 (allow). None of
them can deny anything today. The attach points were chosen so that a future
enforce mode has somewhere to live (`ptrace_access_check` returning `-EPERM`,
`cgroup/connect*` returning 0), but that is not what ships.

### Data leaving the kernel

The task-access hook exports only the requester tgid, the target tgid, the
PTRACE_MODE bits and the target's 16-byte comm. Image paths are resolved in
userspace from `/proc`. Raw argv never enters the process-event ring, only a
SHA-256 digest and the argument count.

### Kernel lockdown

On systems with Kernel Lockdown (Secure Boot), BPF may be restricted:

```bash
cat /sys/kernel/security/lockdown
# none / integrity / confidentiality
```

### Auditing

```bash
ausearch -m BPF
```

## Related documentation

- L7.md -- cross-platform L7 attribution, the benchmark tables quoted above
- ENDPOINTSECURITY.md -- the macOS counterpart (ES process and file events)
- ETW.md -- the Windows counterpart (kernel trace, FIM FileIo attribution)
- [Linux eBPF documentation](https://ebpf.io/what-is-ebpf/)
- [Aya, the Rust eBPF library](https://aya-rs.dev/)
- [BPF CO-RE reference](https://nakryiko.com/posts/bpf-core-reference-guide/)
