// This module provides an optional eBPF-based helper for Layer-7 process
// resolution on Linux. When running on Linux and the Aya crate can load an
// appropriate eBPF object, this can provide near-real-time and highly
// accurate mapping of network 4-tuples to local processes.
//
// On non-Linux platforms (or if eBPF is not available / fails to initialise)
// all public functions gracefully fall back to no-op stubs so that the rest
// of the codebase does not need to care whether eBPF is available.
//
// NOTE: The eBPF program is embedded directly in the binary at compile time
// using include_bytes!(). This avoids runtime file lookup issues and makes
// the binary fully self-contained.

use crate::sessions::{Session, SessionL7};
use tracing::info;

#[cfg(all(target_os = "linux", feature = "ebpf"))]
mod linux {
    use super::*;
    use aya::Pod as AyaPod;
    use aya::{
        maps::{HashMap as AyaHashMap, MapData},
        Ebpf,
    };
    use bytemuck::{Pod, Zeroable};
    use once_cell::sync::OnceCell;
    use std::process::Command;
    use std::sync::Arc;
    use tracing::{debug, error, info, warn};

    // Embed the eBPF object file directly into the binary at compile time.
    // The L7_EBPF_OBJECT environment variable is set by build.rs during compilation.
    // If not set (e.g., clang not available), we provide an empty slice and handle gracefully.
    #[cfg(L7_EBPF_EMBEDDED)]
    static EBPF_OBJECT: &[u8] = include_bytes!(env!("L7_EBPF_OBJECT"));

    #[cfg(not(L7_EBPF_EMBEDDED))]
    static EBPF_OBJECT: &[u8] = &[];

    // Compile-time marker for debugging - this gets embedded in the binary
    #[allow(dead_code)]
    #[cfg(L7_EBPF_EMBEDDED)]
    const EBPF_BUILD_STATUS: &str = "EMBEDDED";

    #[allow(dead_code)]
    #[cfg(not(L7_EBPF_EMBEDDED))]
    const EBPF_BUILD_STATUS: &str = "NOT_EMBEDDED";

    // Match the eBPF program structures
    #[repr(C)]
    #[derive(Clone, Copy, Zeroable, Pod)]
    struct SessionKey {
        src_ip: [u32; 4], // IPv4/IPv6 address (IPv4 uses first element)
        dst_ip: [u32; 4], // IPv4/IPv6 address (IPv4 uses first element)
        src_port: u16,
        dst_port: u16,
        protocol: u8, // TCP=6, UDP=17
        family: u8,   // AF_INET=2, AF_INET6=10
        padding: u16, // Ensure alignment
    }

    unsafe impl AyaPod for SessionKey {}

    #[repr(C)]
    #[derive(Clone, Copy, Zeroable, Pod)]
    struct ProcessInfo {
        pid: u32,
        uid: u32,
        start_time: u64,
        process_name: [u8; 16],
        process_path: [u8; 256],
        username: [u8; 32],
    }

    unsafe impl AyaPod for ProcessInfo {}

    // Convert Session into SessionKey
    // Note: eBPF reads IPs from sock_common using bpf_probe_read_kernel which gives
    // the raw bytes as a u32 in host byte order. We match that format.
    fn session_to_key(s: &Session) -> SessionKey {
        let mut key = SessionKey {
            src_ip: [0; 4],
            dst_ip: [0; 4],
            src_port: s.src_port,
            dst_port: s.dst_port,
            protocol: match s.protocol {
                crate::sessions::Protocol::TCP => 6,
                crate::sessions::Protocol::UDP => 17,
            },
            family: match s.src_ip {
                std::net::IpAddr::V4(_) => 2,  // AF_INET
                std::net::IpAddr::V6(_) => 10, // AF_INET6
            },
            padding: 0,
        };

        // Set IP addresses - use native byte order to match eBPF's bpf_probe_read_kernel
        match s.src_ip {
            std::net::IpAddr::V4(ipv4) => {
                // Read IP bytes as little-endian u32 (how eBPF reads from kernel)
                let octets = ipv4.octets();
                key.src_ip[0] = u32::from_le_bytes(octets);
            }
            std::net::IpAddr::V6(ipv6) => {
                let octets = ipv6.octets();
                key.src_ip[0] = u32::from_le_bytes([octets[0], octets[1], octets[2], octets[3]]);
                key.src_ip[1] = u32::from_le_bytes([octets[4], octets[5], octets[6], octets[7]]);
                key.src_ip[2] = u32::from_le_bytes([octets[8], octets[9], octets[10], octets[11]]);
                key.src_ip[3] =
                    u32::from_le_bytes([octets[12], octets[13], octets[14], octets[15]]);
            }
        }

        match s.dst_ip {
            std::net::IpAddr::V4(ipv4) => {
                // Read IP bytes as little-endian u32 (how eBPF reads from kernel)
                let octets = ipv4.octets();
                key.dst_ip[0] = u32::from_le_bytes(octets);
            }
            std::net::IpAddr::V6(ipv6) => {
                let octets = ipv6.octets();
                key.dst_ip[0] = u32::from_le_bytes([octets[0], octets[1], octets[2], octets[3]]);
                key.dst_ip[1] = u32::from_le_bytes([octets[4], octets[5], octets[6], octets[7]]);
                key.dst_ip[2] = u32::from_le_bytes([octets[8], octets[9], octets[10], octets[11]]);
                key.dst_ip[3] =
                    u32::from_le_bytes([octets[12], octets[13], octets[14], octets[15]]);
            }
        }

        key
    }

    /// Live layout of the `sched_process_fork` / `sched_process_exit`
    /// records, parsed from tracefs at load time. The kernel is not
    /// layout-stable here (6.17 turned the fork comm fields into
    /// `__data_loc`, shrinking the record from 48 to 24 bytes), and a
    /// program that loads a field past the real record size is rejected at
    /// ATTACH time (`perf_event_set_bpf_prog`: max_ctx_offset > record size
    /// -> EACCES), so the offsets are handed to the programs through the
    /// `proc_tp_cfg` map instead of being compiled in. Mirrors
    /// `struct proc_tp_cfg` in `l7_ebpf.c`.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default)]
    struct ProcTpCfg {
        valid: u32,
        fork_parent_pid_off: u32,
        fork_child_pid_off: u32,
        fork_child_comm_off: u32,
        fork_child_comm_data_loc: u32,
        exit_pid_off: u32,
        exit_comm_off: u32,
        exit_comm_data_loc: u32,
    }
    unsafe impl AyaPod for ProcTpCfg {}

    fn read_tracepoint_format(name: &str) -> Option<String> {
        ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
            .iter()
            .find_map(|root| {
                std::fs::read_to_string(format!("{root}/events/sched/{name}/format")).ok()
            })
    }

    /// `(offset, is_data_loc)` of one field in a tracefs `format` file.
    /// Lines look like `field:__data_loc char[] child_comm;\toffset:16;...`
    /// or `field:char comm[16];\toffset:8;...`.
    fn tracepoint_field(format: &str, name: &str) -> Option<(u32, bool)> {
        for line in format.lines() {
            let Some(rest) = line.trim().strip_prefix("field:") else {
                continue;
            };
            let mut parts = rest.split(';');
            let decl = parts.next()?.trim();
            let last = decl.split_whitespace().last()?;
            let field_name = last.split('[').next().unwrap_or(last);
            if field_name != name {
                continue;
            }
            let offset = parts
                .find_map(|p| p.trim().strip_prefix("offset:"))
                .and_then(|v| v.trim().parse::<u32>().ok())?;
            return Some((offset, decl.starts_with("__data_loc")));
        }
        None
    }

    fn proc_tp_cfg_from_tracefs() -> Option<ProcTpCfg> {
        let fork = read_tracepoint_format("sched_process_fork")?;
        let exit = read_tracepoint_format("sched_process_exit")?;
        let (fork_parent_pid_off, _) = tracepoint_field(&fork, "parent_pid")?;
        let (fork_child_pid_off, _) = tracepoint_field(&fork, "child_pid")?;
        let (fork_child_comm_off, fork_child_comm_data_loc) =
            tracepoint_field(&fork, "child_comm")?;
        let (exit_pid_off, _) = tracepoint_field(&exit, "pid")?;
        let (exit_comm_off, exit_comm_data_loc) = tracepoint_field(&exit, "comm")?;
        Some(ProcTpCfg {
            valid: 1,
            fork_parent_pid_off,
            fork_child_pid_off,
            fork_child_comm_off,
            fork_child_comm_data_loc: u32::from(fork_child_comm_data_loc),
            exit_pid_off,
            exit_comm_off,
            exit_comm_data_loc: u32::from(exit_comm_data_loc),
        })
    }

    /// Parent pid from `/proc/<pid>/stat` (field after the `)`-terminated
    /// comm, then state, then ppid) for processes whose fork predates the
    /// tracepoint attach; short-lived processes may already be gone.
    fn proc_ppid(pid: u32) -> Option<u32> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let rest = stat.rsplit_once(')')?.1;
        rest.split_whitespace().nth(1)?.parse().ok()
    }

    fn proc_exe(pid: u32) -> Option<String> {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().to_string())
    }

    /// FLODBADD2 §1b.2: consumer thread for the `proc_events` ringbuf.
    /// Monitoring role only (fail-open: absence of the map or a spawn
    /// failure degrades to "no stream"). Exec argv is read from /proc at
    /// delivery time and immediately digested (I5) -- raw argv is never
    /// stored.
    fn spawn_proc_event_thread(mut ring: aya::maps::RingBuf<aya::maps::MapData>) {
        if let Err(e) = std::thread::Builder::new()
            .name("proc-events-ebpf".into())
            .spawn(move || loop {
                let mut drained = false;
                while let Some(item) = ring.next() {
                    drained = true;
                    handle_proc_event_bytes(&item);
                }
                if !drained {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
            })
        {
            warn!("proc-events consumer thread spawn failed: {}", e);
        }
    }

    fn handle_proc_event_bytes(bytes: &[u8]) {
        use crate::process_events as pe;
        if bytes.len() < 16 {
            return;
        }
        let word = |i: usize| u32::from_ne_bytes(bytes[i..i + 4].try_into().unwrap());
        let raw_kind = word(0);
        let pid = word(4);
        let ppid = word(8);
        let uid = word(12);
        let text_bytes = &bytes[16..bytes.len().min(16 + 256)];
        let end = text_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(text_bytes.len());
        let text = String::from_utf8_lossy(&text_bytes[..end]).to_string();

        let basename = |path: &str| {
            std::path::Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.to_string())
        };

        let event = match raw_kind {
            1 => {
                // Exec: `text` is the binary path from the tracepoint;
                // argv comes from /proc at delivery time (short-lived
                // processes may already be gone -> unmeasured None).
                let argv: Option<Vec<String>> = std::fs::read(format!("/proc/{pid}/cmdline"))
                    .ok()
                    .map(|raw| {
                        raw.split(|b| *b == 0)
                            .filter(|part| !part.is_empty())
                            .map(|part| String::from_utf8_lossy(part).to_string())
                            .collect()
                    })
                    .filter(|argv: &Vec<String>| !argv.is_empty());
                // Kernel-vouched ppid when the fork was seen after attach;
                // otherwise /proc (near-kernel-time, may already be gone).
                let ppid = (ppid > 0).then_some(ppid).or_else(|| proc_ppid(pid));
                pe::ProcessEvent {
                    timestamp_ms: pe::now_ms(),
                    kind: pe::ProcessEventKind::Exec,
                    pid,
                    ppid,
                    uid: Some(uid),
                    process_name: basename(&text),
                    process_path: text,
                    parent_process_path: ppid.and_then(proc_exe),
                    argv_sha256: argv.as_deref().and_then(pe::argv_digest),
                    argv_len: argv.as_ref().map(|a| a.len() as u32),
                    signing_id: None,
                    team_id: None,
                    is_platform_binary: None,
                    target_pid: None,
                    target_process_path: None,
                }
            }
            2 | 3 => pe::ProcessEvent {
                timestamp_ms: pe::now_ms(),
                kind: if raw_kind == 2 {
                    pe::ProcessEventKind::Fork
                } else {
                    pe::ProcessEventKind::Exit
                },
                pid,
                ppid: (ppid > 0).then_some(ppid),
                uid: Some(uid),
                // Fork/exit carry the 16-byte comm, not a path.
                process_name: text,
                process_path: String::new(),
                parent_process_path: None,
                argv_sha256: None,
                argv_len: None,
                signing_id: None,
                team_id: None,
                is_platform_binary: None,
                target_pid: None,
                target_process_path: None,
            },
            _ => return,
        };
        pe::push(event);
    }

    // Internal singleton that owns the BPF instance and user-space map copy
    pub struct Inner {
        _bpf: Ebpf,
        map: AyaHashMap<MapData, SessionKey, ProcessInfo>,
    }

    impl Inner {
        /// Initialize eBPF and return (Option<Inner>, status_message)
        fn new_with_status() -> (Option<Self>, String) {
            // Get kernel version first for status messages
            let kernel_version = nix::sys::utsname::uname()
                .map(|u| u.release().to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string());

            // -------------------------------------------------------------
            //  Quick pre-flight checks to give a clearer error message when
            //  the kernel/capabilities do not allow loading eBPF programs.
            // -------------------------------------------------------------

            // 1. Check unprivileged_bpf_disabled.
            //    - 0 = unprivileged allowed
            //    - 1 = unprivileged disabled (need root or CAP_BPF)
            //    - 2 = permanently disabled until reboot (even root may have issues)
            if let Ok(disabled) =
                std::fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled")
            {
                let value = disabled.trim();
                if value == "1" || value == "2" {
                    if nix::unistd::geteuid().as_raw() != 0 {
                        let msg = format!(
                            "Disabled: unprivileged_bpf_disabled={} and not running as root (kernel {})",
                            value, kernel_version
                        );
                        warn!("eBPF disabled: kernel has unprivileged_bpf_disabled={} (need root or CAP_BPF)", value);
                        return (None, msg);
                    }
                }
            }
            debug!("eBPF: unprivileged_bpf_disabled check passed");

            // 2. Basic kernel version heuristic – we need at least 5.3 for
            //    tracepoints with BTF; bail early on older kernels.
            let uts = match nix::sys::utsname::uname() {
                Ok(u) => u,
                Err(e) => {
                    let msg = format!("Disabled: uname() syscall failed: {}", e);
                    warn!("eBPF disabled: {}", msg);
                    return (None, msg);
                }
            };
            let release_str = uts.release().to_string_lossy();
            let mut parts = release_str.split('.');
            if let (Some(maj), Some(min)) = (parts.next(), parts.next()) {
                if let (Ok(maj), Ok(min)) = (maj.parse::<u32>(), min.parse::<u32>()) {
                    if maj < 5 || (maj == 5 && min < 3) {
                        let msg = format!(
                            "Disabled: kernel {}.{} < 5.3 (BTF/tracepoint support required)",
                            maj, min
                        );
                        warn!("eBPF disabled: {}", msg);
                        return (None, msg);
                    }
                }
            }
            debug!("eBPF: kernel version check passed");

            // Check for LinuxKit kernel (Docker Desktop, etc.)
            let is_linuxkit = release_str.contains("linuxkit");
            if is_linuxkit {
                warn!("eBPF: Running on LinuxKit kernel ({}). eBPF functionality may be limited in Docker Desktop", release_str);
            }

            // Check if perf_event_paranoid is set correctly
            if let Ok(paranoid) = std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid") {
                if let Ok(value) = paranoid.trim().parse::<i32>() {
                    if value > -1 {
                        debug!(
                            "eBPF: perf_event_paranoid = {} (should be -1 or lower for unprivileged access)",
                            value
                        );
                    }
                }
            }

            // Check debug fs mount
            let debug_mounted = Command::new("mount")
                .output()
                .map(|out| String::from_utf8_lossy(&out.stdout).contains("debugfs"))
                .unwrap_or(false);

            if !debug_mounted {
                debug!("eBPF: debugfs not mounted - this may cause issues with kprobes");
            }

            // Decide which object file to load.  Priority:
            //   1. Runtime env-var `L7_EBPF_OBJECT` (allows overrides).
            //   2. Compile-time value injected by build.rs via `cargo:rustc-env`.
            //   3. Fallback to an object named `l7_ebpf.o` next to the executable.
            // This makes the helper work both when the caller sets the env-var
            // at runtime **and** when we rely on the path discovered at build
            // time (which is not automatically exported into the runtime
            // environment).

            // Check if eBPF object was embedded at compile time
            if EBPF_OBJECT.is_empty() {
                let msg = format!(
                    "Disabled: eBPF object not embedded (clang/llvm not available at build time) (kernel {})",
                    kernel_version
                );
                warn!("eBPF object not embedded - was clang available during build?");
                return (None, msg);
            }

            // Load from embedded bytes (compiled into binary at build time)
            // Note: We copy to a Vec to ensure proper 8-byte alignment, as include_bytes!
            // doesn't guarantee alignment and aya's ELF parser requires aligned data.
            info!(
                "eBPF: Loading embedded object ({} bytes)",
                EBPF_OBJECT.len()
            );
            let aligned_object: Vec<u8> = EBPF_OBJECT.to_vec();

            // On kernels < 5.11 (and in many containers) BPF map memory is
            // charged against RLIMIT_MEMLOCK, and the default limit makes
            // `bpf(BPF_MAP_CREATE)` fail with EPERM -- the single most
            // common shape of the "failed to create map `socket_to_process`
            // with code -1" load failure Sentry has recorded across
            // 1.4.1..1.8.3 production hosts. Lift the limit for this process
            // before loading, the way aya's own examples do; failing to lift
            // it is not fatal (the load below reports the real outcome).
            {
                use nix::sys::resource::{setrlimit, Resource, RLIM_INFINITY};
                if let Err(e) = setrlimit(Resource::RLIMIT_MEMLOCK, RLIM_INFINITY, RLIM_INFINITY) {
                    warn!(
                        "eBPF: could not raise RLIMIT_MEMLOCK ({}); map creation may fail on kernels < 5.11",
                        e
                    );
                }
            }

            let mut bpf = match Ebpf::load(&aligned_object) {
                Ok(bpf) => bpf,
                Err(e) => {
                    let msg = format!(
                        "Disabled: failed to load eBPF program: {} (kernel {})",
                        e, kernel_version
                    );
                    // Environment limitation (unprivileged process, locked-down
                    // container, old kernel), not a developer-actionable bug:
                    // capture degrades to the non-eBPF L7 path and the status
                    // string above is surfaced to the operator. error! here
                    // produced a Sentry issue with 23k events, once per process
                    // start on every affected host. Keep it at warn!.
                    warn!("Failed to load eBPF program: {}", e);
                    return (None, msg);
                }
            };

            // Attach kprobe to tcp_set_state (matching our simplified eBPF program function name)
            if let Some(prog_any) = bpf.program_mut("minimal_probe") {
                use aya::programs::KProbe;
                let kp: &mut KProbe = match prog_any.try_into() {
                    Ok(kp) => kp,
                    Err(e) => {
                        let msg = format!(
                            "Disabled: failed to cast eBPF program to KProbe: {} (kernel {})",
                            e, kernel_version
                        );
                        warn!("Failed to cast program into KProbe: {}", e);
                        return (None, msg);
                    }
                };
                if let Err(e) = kp.load() {
                    let msg = format!(
                        "Disabled: kernel rejected eBPF program load: {} (kernel {})",
                        e, kernel_version
                    );
                    warn!("Failed to load kprobe program: {}", e);
                    return (None, msg);
                }
                if let Err(e) = kp.attach("tcp_set_state", 0) {
                    // Check if we're in Docker for better error message
                    let in_docker = std::path::Path::new("/.dockerenv").exists()
                        || std::fs::read_to_string("/proc/1/cgroup")
                            .map(|s| s.contains("/docker/"))
                            .unwrap_or(false);

                    let context = if is_linuxkit {
                        "LinuxKit/Docker Desktop doesn't support kprobes"
                    } else if in_docker {
                        "container may lack SYS_ADMIN/BPF capabilities"
                    } else if e.to_string().contains("perf_event_open") {
                        "perf_event_open failed - need root or CAP_BPF"
                    } else {
                        "kprobe attachment failed"
                    };

                    let msg = format!("Disabled: {} - {} (kernel {})", context, e, kernel_version);
                    warn!(
                        "eBPF disabled: failed to attach kprobe to tcp_set_state: {}",
                        e
                    );

                    // Extra diagnostics for perf_event_open failure (to debug log)
                    if e.to_string().contains("perf_event_open") {
                        debug!("eBPF perf_event_open failure - common fixes: 1) sudo sysctl -w kernel.perf_event_paranoid=-1, 2) mount debugfs, 3) use --privileged in Docker");
                        if in_docker {
                            debug!("eBPF: Docker environment detected - Docker Desktop on macOS has limited eBPF support");
                        }
                    }

                    return (None, msg);
                }
            } else {
                let msg = format!(
                    "Disabled: eBPF object missing 'minimal_probe' kprobe program (kernel {})",
                    kernel_version
                );
                warn!("eBPF object missing expected kprobe; running without eBPF");
                return (None, msg);
            }

            // Attach kprobe for tcp_v4_connect (captures process info in user context for IPv4)
            if let Some(prog_any) = bpf.program_mut("track_connect_v4") {
                use aya::programs::KProbe;
                if let Ok(kp) = TryInto::<&mut KProbe>::try_into(prog_any) {
                    if kp.load().is_ok() {
                        if let Err(e) = kp.attach("tcp_v4_connect", 0) {
                            debug!("Could not attach to tcp_v4_connect: {} (non-critical)", e);
                        } else {
                            debug!(
                                "Attached track_connect_v4 to tcp_v4_connect for IPv4 process info"
                            );
                        }
                    }
                }
            }

            // Attach kprobe for tcp_v6_connect (captures process info in user context for IPv6)
            if let Some(prog_any) = bpf.program_mut("track_connect_v6") {
                use aya::programs::KProbe;
                if let Ok(kp) = TryInto::<&mut KProbe>::try_into(prog_any) {
                    if kp.load().is_ok() {
                        if let Err(e) = kp.attach("tcp_v6_connect", 0) {
                            debug!("Could not attach to tcp_v6_connect: {} (non-critical)", e);
                        } else {
                            debug!(
                                "Attached track_connect_v6 to tcp_v6_connect for IPv6 process info"
                            );
                        }
                    }
                }
            }

            // FLODBADD2 §1b.2: hand the live fork/exit record layout to the
            // programs before they attach. Fail-open: unreadable tracefs
            // leaves `valid = 0` and the two programs stay silent.
            match proc_tp_cfg_from_tracefs() {
                Some(cfg) => match bpf.map_mut("proc_tp_cfg") {
                    Some(map) => match aya::maps::Array::<_, ProcTpCfg>::try_from(map) {
                        Ok(mut array) => match array.set(0, cfg, 0) {
                            Ok(()) => debug!("proc_tp_cfg installed: {:?}", cfg),
                            Err(e) => debug!("proc_tp_cfg set failed: {} (non-critical)", e),
                        },
                        Err(e) => debug!("proc_tp_cfg map open failed: {} (non-critical)", e),
                    },
                    None => debug!("proc_tp_cfg map missing from object (non-critical)"),
                },
                None => debug!(
                    "proc_tp_cfg: tracefs format unreadable; fork/exit stream disabled (non-critical)"
                ),
            }

            // Process-event tracepoints (monitoring role; fail-open -- a
            // failed attach only means no stream).
            for (prog_name, category, tp_name) in [
                ("trace_sched_fork", "sched", "sched_process_fork"),
                ("trace_sched_exec", "sched", "sched_process_exec"),
                ("trace_sched_exit", "sched", "sched_process_exit"),
            ] {
                if let Some(prog_any) = bpf.program_mut(prog_name) {
                    use aya::programs::TracePoint;
                    if let Ok(tp) = TryInto::<&mut TracePoint>::try_into(prog_any) {
                        if tp.load().is_ok() {
                            if let Err(e) = tp.attach(category, tp_name) {
                                debug!("Could not attach {}: {} (non-critical)", prog_name, e);
                            } else {
                                debug!("Attached {} to {}/{}", prog_name, category, tp_name);
                            }
                        }
                    }
                }
            }

            // Ring-buffer consumer for the process-event stream.
            if let Some(map) = bpf.take_map("proc_events") {
                match aya::maps::RingBuf::try_from(map) {
                    Ok(ring) => spawn_proc_event_thread(ring),
                    Err(e) => {
                        debug!("proc_events ringbuf unavailable: {} (non-critical)", e)
                    }
                }
            }

            // Obtain the `l7_connections` hash map from the object
            let map: AyaHashMap<_, SessionKey, ProcessInfo> = match bpf.take_map("l7_connections") {
                Some(m) => match AyaHashMap::try_from(m) {
                    Ok(h) => h,
                    Err(e) => {
                        let msg = format!(
                            "Disabled: failed to open eBPF map: {} (kernel {})",
                            e, kernel_version
                        );
                        error!("Failed to open HashMap from map: {}", e);
                        return (None, msg);
                    }
                },
                None => {
                    let msg = format!(
                        "Disabled: eBPF map 'l7_connections' not found in object (kernel {})",
                        kernel_version
                    );
                    error!("Failed to obtain eBPF hash map 'l7_connections'");
                    return (None, msg);
                }
            };

            // Check if we're in a container for the success message
            let in_container = std::path::Path::new("/.dockerenv").exists()
                || std::fs::read_to_string("/proc/1/cgroup")
                    .map(|s| {
                        s.contains("/docker/") || s.contains("/lxc/") || s.contains("/containerd/")
                    })
                    .unwrap_or(false);

            let env_info = if in_container { " (container)" } else { "" };

            let msg = format!(
                "Enabled: kernel {} with tcp_set_state kprobe attached{}",
                kernel_version, env_info
            );

            info!("eBPF L7 helper initialised successfully: {}", msg);

            (Some(Inner { _bpf: bpf, map }), msg)
        }

        fn lookup_session(&self, session: &Session) -> Option<SessionL7> {
            let key = session_to_key(session);
            match self.map.get(&key, 0) {
                Ok(info) => {
                    // Convert C strings to Rust strings safely
                    let process_name = String::from_utf8_lossy(
                        &info.process_name
                            [..info.process_name.iter().position(|&c| c == 0).unwrap_or(16)],
                    )
                    .to_string();

                    let process_path = String::from_utf8_lossy(
                        &info.process_path[..info
                            .process_path
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(256)],
                    )
                    .to_string();

                    let username = String::from_utf8_lossy(
                        &info.username[..info.username.iter().position(|&c| c == 0).unwrap_or(32)],
                    )
                    .to_string();

                    Some(SessionL7 {
                        pid: info.pid,
                        process_name: if process_name.is_empty() {
                            format!("pid-{}", info.pid)
                        } else {
                            process_name
                        },
                        process_path: if process_path.is_empty() {
                            format!("/proc/{}", info.pid)
                        } else {
                            process_path
                        },
                        username: if username.is_empty() || username == "unknown" {
                            format!("uid-{}", info.uid)
                        } else {
                            username
                        },
                        ..SessionL7::default()
                    })
                }
                Err(e) => {
                    debug!("eBPF map lookup error: {}", e);
                    None
                }
            }
        }
    }

    // Singleton wrapper so that the rest of the code only ever initialises once.
    pub struct FlodbaddL7Ebpf {
        inner: Option<Arc<Inner>>, // None when eBPF not available
        init_status: String,       // Detailed initialization status message
    }

    impl FlodbaddL7Ebpf {
        fn init() -> Self {
            let (inner, status) = Inner::new_with_status();
            Self {
                inner: inner.map(Arc::new),
                init_status: status,
            }
        }

        pub fn get_l7(&self, session: &Session) -> Option<SessionL7> {
            self.inner.as_ref()?.lookup_session(session)
        }

        pub fn is_available(&self) -> bool {
            self.inner.is_some()
        }

        pub fn init_status(&self) -> &str {
            &self.init_status
        }
    }

    // Global accessor – lazily initialises on first use
    pub fn global() -> &'static FlodbaddL7Ebpf {
        static INSTANCE: OnceCell<FlodbaddL7Ebpf> = OnceCell::new();
        INSTANCE.get_or_init(|| FlodbaddL7Ebpf::init())
    }

    /// Get the detailed initialization status message
    pub fn get_init_status() -> &'static str {
        global().init_status()
    }
}

#[cfg(not(all(target_os = "linux", feature = "ebpf")))]
mod linux {
    #![allow(dead_code)] // These stubs exist for API completeness on non-Linux platforms
    use super::*;

    pub struct FlodbaddL7Ebpf;
    impl FlodbaddL7Ebpf {
        pub fn get_l7(&self, _session: &Session) -> Option<SessionL7> {
            None
        }

        pub fn is_available(&self) -> bool {
            false
        }

        pub fn init_status(&self) -> &str {
            "Not available: eBPF requires Linux with 'ebpf' feature"
        }
    }

    pub fn global() -> &'static FlodbaddL7Ebpf {
        static INSTANCE: FlodbaddL7Ebpf = FlodbaddL7Ebpf {};
        &INSTANCE
    }

    /// Stub for non-Linux platforms
    pub fn get_init_status() -> &'static str {
        global().init_status()
    }
}

/// Public helper that the rest of the codebase can call to attempt an eBPF-based
/// resolution. It is **always** present on all platforms and simply returns
/// `None` if the functionality is not available.
pub fn get_l7_for_session(session: &Session) -> Option<SessionL7> {
    linux::global().get_l7(session)
}

/// Returns `true` if the eBPF helper was successfully initialised and is ready
/// for look-ups.  On non-Linux platforms or when the helper failed to load it
/// always returns `false`.
pub fn is_available() -> bool {
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    {
        linux::global().is_available()
    }

    #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
    {
        false
    }
}

/// Returns true if eBPF is not just available but actually has kprobes attached
/// and is fully functional. This is useful for tests that need to know if eBPF
/// will actually capture traffic, not just if the object was embedded.
pub fn is_fully_functional() -> bool {
    if !is_available() {
        return false;
    }
    // Check if the status indicates kprobes are attached
    let status = ebpf_support();
    status.contains("kprobe attached")
}

/// Initialize and log the eBPF status. Call this at capture start to get
/// early feedback about eBPF availability.
pub fn init_and_log_status() {
    let available = is_available();
    if available {
        info!(
            "eBPF L7 resolution helper is ENABLED - network sessions will be resolved via kernel"
        );
    } else {
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            tracing::warn!(
                "eBPF L7 resolution helper is DISABLED - falling back to /proc-based resolution"
            );
        }
        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        {
            info!(
                "eBPF L7 resolution not available on this platform (non-Linux or feature disabled)"
            );
        }
    }
}

/// Returns a detailed string describing eBPF support status.
/// This includes the actual result of attempting to load and use the eBPF module.
pub fn ebpf_support() -> String {
    #[cfg(not(target_os = "linux"))]
    {
        return "Not supported: eBPF requires Linux".to_string();
    }

    #[cfg(all(target_os = "linux", not(feature = "ebpf")))]
    {
        return "Not enabled: compiled without 'ebpf' feature flag".to_string();
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    {
        // Trigger initialization if not already done and get the status
        // This will actually attempt to load the eBPF program
        linux::get_init_status().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::{Protocol, Session};
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_ebpf_lookup_returns_none_without_kernel_support() {
        let session = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::from_str("127.0.0.1").unwrap(),
            src_port: 12345,
            dst_ip: IpAddr::from_str("127.0.0.1").unwrap(),
            dst_port: 80,
        };
        // On most CI hosts eBPF program will not be loaded – expect None.
        assert!(get_l7_for_session(&session).is_none());
    }
}
