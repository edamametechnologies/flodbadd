// This module provides an optional eBPF-based helper for Layer-7 process
// resolution on Linux. When running on Linux and the Aya crate can load an
// appropriate eBPF object, this can provide near-real-time and highly
// accurate mapping of network 4-tuples to local processes.
//
// On non-Linux platforms (or if eBPF is not available / fails to initialise)
// all public functions gracefully fall back to no-op stubs so that the rest
// of the codebase does not need to care whether eBPF is available.
//
// NOTE: The actual eBPF program is **not** included here – the `aya` run-time
// will attempt to load `l7_ebpf.o` from the same directory as the executable
// (or the path specified in the `L7_EBPF_OBJECT` env-var). If that fails we
// simply operate in stub mode.

use crate::sessions::{Session, SessionL7};

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
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Arc;
    use tracing::{debug, error, info, warn};

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

        // Set IP addresses
        match s.src_ip {
            std::net::IpAddr::V4(ipv4) => {
                key.src_ip[0] = u32::from(ipv4);
            }
            std::net::IpAddr::V6(ipv6) => {
                let octets = ipv6.octets();
                key.src_ip[0] = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
                key.src_ip[1] = u32::from_be_bytes([octets[4], octets[5], octets[6], octets[7]]);
                key.src_ip[2] = u32::from_be_bytes([octets[8], octets[9], octets[10], octets[11]]);
                key.src_ip[3] =
                    u32::from_be_bytes([octets[12], octets[13], octets[14], octets[15]]);
            }
        }

        match s.dst_ip {
            std::net::IpAddr::V4(ipv4) => {
                key.dst_ip[0] = u32::from(ipv4);
            }
            std::net::IpAddr::V6(ipv6) => {
                let octets = ipv6.octets();
                key.dst_ip[0] = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
                key.dst_ip[1] = u32::from_be_bytes([octets[4], octets[5], octets[6], octets[7]]);
                key.dst_ip[2] = u32::from_be_bytes([octets[8], octets[9], octets[10], octets[11]]);
                key.dst_ip[3] =
                    u32::from_be_bytes([octets[12], octets[13], octets[14], octets[15]]);
            }
        }

        key
    }

    // Internal singleton that owns the BPF instance and user-space map copy
    pub struct Inner {
        _bpf: Ebpf,
        map: AyaHashMap<MapData, SessionKey, ProcessInfo>,
    }

    impl Inner {
        fn new() -> Option<Self> {
            // -------------------------------------------------------------
            //  Quick pre-flight checks to give a clearer error message when
            //  the kernel/capabilities do not allow loading eBPF programs.
            // -------------------------------------------------------------

            // 1. Check unprivileged_bpf_disabled.  When it is "1" and the
            //    process is not running as root the kernel will reject any
            //    program load attempt with EPERM.
            if let Ok(disabled) =
                std::fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled")
            {
                if disabled.trim() == "1" {
                    if nix::unistd::geteuid().as_raw() != 0 {
                        println!("[l7_ebpf] Disabled – kernel has unprivileged_bpf_disabled=1 (need root/CAP_BPF)");
                        return None;
                    }
                }
            }
            println!("unprivileged_bpf_disabled check passed");

            // 2. Basic kernel version heuristic – we need at least 5.3 for
            //    tracepoints with BTF; bail early on older kernels.
            let uts = match nix::sys::utsname::uname() {
                Ok(u) => u,
                Err(e) => {
                    println!("[l7_ebpf] Disabled – uname() syscall failed: {}", e);
                    return None;
                }
            };
            let release_str = uts.release().to_string_lossy();
            let mut parts = release_str.split('.');
            if let (Some(maj), Some(min)) = (parts.next(), parts.next()) {
                if let (Ok(maj), Ok(min)) = (maj.parse::<u32>(), min.parse::<u32>()) {
                    if maj < 5 || (maj == 5 && min < 3) {
                        println!(
                            "[l7_ebpf] Disabled – kernel {}.{} < 5.3 (tracepoint+BTF required)",
                            maj, min
                        );
                        return None;
                    }
                }
            }
            println!("kernel version check passed");

            // Check for LinuxKit kernel (Docker Desktop, etc.)
            if release_str.contains("linuxkit") {
                println!("[l7_ebpf] WARNING: Running on LinuxKit kernel ({}). eBPF functionality may be limited in Docker Desktop", release_str);
            }

            // Check if perf_event_paranoid is set correctly
            if let Ok(paranoid) = std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid") {
                if let Ok(value) = paranoid.trim().parse::<i32>() {
                    if value > -1 {
                        println!(
                            "[l7_ebpf] WARNING: perf_event_paranoid = {} (should be -1 or lower)",
                            value
                        );
                        println!("[l7_ebpf] Try: sudo sysctl -w kernel.perf_event_paranoid=-1");
                    }
                }
            }

            // Check debug fs mount
            let debug_mounted = Command::new("mount")
                .output()
                .map(|out| String::from_utf8_lossy(&out.stdout).contains("debugfs"))
                .unwrap_or(false);

            if !debug_mounted {
                println!(
                    "[l7_ebpf] WARNING: debugfs not mounted. This may cause issues with kprobes."
                );
                println!("[l7_ebpf] Try: sudo mount -t debugfs none /sys/kernel/debug");
            }

            // Decide which object file to load.  Priority:
            //   1. Runtime env-var `L7_EBPF_OBJECT` (allows overrides).
            //   2. Compile-time value injected by build.rs via `cargo:rustc-env`.
            //   3. Fallback to an object named `l7_ebpf.o` next to the executable.
            // This makes the helper work both when the caller sets the env-var
            // at runtime **and** when we rely on the path discovered at build
            // time (which is not automatically exported into the runtime
            // environment).

            let obj_path = std::env::var("L7_EBPF_OBJECT")
                .ok()
                .or_else(|| option_env!("L7_EBPF_OBJECT").map(|s| s.to_string()))
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    // Default: executable directory + "l7_ebpf.o"
                    std::env::current_exe()
                        .map(|mut p| {
                            p.pop();
                            p.push("l7_ebpf.o");
                            p
                        })
                        .unwrap_or_else(|_| PathBuf::from("l7_ebpf.o"))
                });
            println!("obj_path: {}", obj_path.display());

            // Even if the application hasn't initialised a logger we still want
            // a clear indication during CI / test runs as to whether the eBPF
            // helper was activated.  Therefore emit an unconditional
            // `println!`.  (It will show up once per process, at most.)
            println!(
                "[l7_ebpf] Attempting to load object: {}",
                obj_path.display()
            );

            let data = match std::fs::read(&obj_path) {
                Ok(d) => d,
                Err(e) => {
                    warn!(
                        "Unable to read eBPF object {}: {} – running without eBPF",
                        obj_path.display(),
                        e
                    );
                    println!("[l7_ebpf] Disabled – couldn't read object: {}", e);
                    return None;
                }
            };

            let mut bpf = match Ebpf::load(&data) {
                Ok(bpf) => bpf,
                Err(e) => {
                    error!("Failed to load eBPF program: {}", e);
                    println!(
                        "[l7_ebpf] Disabled – failed to parse/load object: {} (debug: {:?})",
                        e, e
                    );

                    // Extra diagnostics inside the container
                    if let Ok(out) = Command::new("file").arg(&obj_path).output() {
                        println!("[l7_ebpf] file: {}", String::from_utf8_lossy(&out.stdout));
                    }
                    if let Ok(out) = Command::new("readelf")
                        .args(["-h", obj_path.to_str().unwrap()])
                        .output()
                    {
                        println!(
                            "[l7_ebpf] readelf -h:\n{}",
                            String::from_utf8_lossy(&out.stdout)
                        );
                    }
                    return None;
                }
            };

            // Attach kprobe to inet_sock_set_state (matching our simplified eBPF program function name)
            if let Some(prog_any) = bpf.program_mut("minimal_probe") {
                use aya::programs::KProbe;
                let kp: &mut KProbe = match prog_any.try_into() {
                    Ok(kp) => kp,
                    Err(e) => {
                        error!("Failed to cast program into KProbe: {}", e);
                        return None;
                    }
                };
                if let Err(e) = kp.load() {
                    error!("Failed to load kprobe program: {}", e);
                    println!("[l7_ebpf] Disabled – kernel rejected program load: {}", e);
                    return None;
                }
                if let Err(e) = kp.attach("inet_sock_set_state", 0) {
                    error!("Failed to attach kprobe: {}", e);
                    println!("[l7_ebpf] Disabled – failed to attach kprobe: {}", e);

                    // Extra diagnostics for perf_event_open failure
                    if e.to_string().contains("perf_event_open") {
                        println!("[l7_ebpf] perf_event_open failure - common fixes:");
                        println!("[l7_ebpf]   1. Set kernel.perf_event_paranoid=-1");
                        println!("[l7_ebpf]      sudo sysctl -w kernel.perf_event_paranoid=-1");
                        println!("[l7_ebpf]   2. Ensure debugfs is mounted:");
                        println!("[l7_ebpf]      sudo mount -t debugfs none /sys/kernel/debug");
                        println!("[l7_ebpf]   3. When in Docker, use --privileged and:");
                        println!("[l7_ebpf]      -v /sys/kernel/debug:/sys/kernel/debug");

                        // Check if we're in Docker
                        let in_docker = std::path::Path::new("/.dockerenv").exists()
                            || std::fs::read_to_string("/proc/1/cgroup")
                                .map(|s| s.contains("/docker/"))
                                .unwrap_or(false);

                        if in_docker {
                            println!("[l7_ebpf] **DETECTED DOCKER ENVIRONMENT**");
                            println!("[l7_ebpf] Docker Desktop on macOS has limited eBPF support.");
                            println!(
                                "[l7_ebpf] Consider testing on a native Linux system instead."
                            );
                        }
                    }

                    return None;
                }
            } else {
                warn!("eBPF object missing expected kprobe; running without eBPF");
                println!("[l7_ebpf] Disabled – object missing kprobe program");
                return None;
            }

            // Obtain the `l7_connections` hash map from the object
            let map: AyaHashMap<_, SessionKey, ProcessInfo> = match bpf.take_map("l7_connections") {
                Some(m) => match AyaHashMap::try_from(m) {
                    Ok(h) => h,
                    Err(e) => {
                        error!("Failed to open HashMap from map: {}", e);
                        println!("[l7_ebpf] Disabled – failed to open user map: {}", e);
                        return None;
                    }
                },
                None => {
                    error!("Failed to obtain eBPF hash map 'l7_connections'");
                    println!("[l7_ebpf] Disabled – map 'l7_connections' not found in object");
                    return None;
                }
            };

            info!("eBPF L7 helper initialised successfully");
            println!("[l7_ebpf] Initialised successfully (kernel eBPF enabled)");

            Some(Inner { _bpf: bpf, map })
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
    }

    impl FlodbaddL7Ebpf {
        fn init() -> Self {
            let inner = Inner::new().map(Arc::new);
            Self { inner }
        }

        pub fn get_l7(&self, session: &Session) -> Option<SessionL7> {
            self.inner.as_ref()?.lookup_session(session)
        }

        pub fn is_available(&self) -> bool {
            self.inner.is_some()
        }
    }

    // Global accessor – lazily initialises on first use
    pub fn global() -> &'static FlodbaddL7Ebpf {
        static INSTANCE: OnceCell<FlodbaddL7Ebpf> = OnceCell::new();
        INSTANCE.get_or_init(|| FlodbaddL7Ebpf::init())
    }
}

#[cfg(not(all(target_os = "linux", feature = "ebpf")))]
mod linux {
    use super::*;

    pub struct FlodbaddL7Ebpf;
    impl FlodbaddL7Ebpf {
        pub fn get_l7(&self, _session: &Session) -> Option<SessionL7> {
            None
        }
    }

    pub fn global() -> &'static FlodbaddL7Ebpf {
        static INSTANCE: FlodbaddL7Ebpf = FlodbaddL7Ebpf {};
        &INSTANCE
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
