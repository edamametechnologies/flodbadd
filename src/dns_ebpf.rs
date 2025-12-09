// DNS eBPF Module for Process-Aware DNS Resolution
//
// This module provides eBPF-based DNS query tracking that associates
// DNS queries with the processes that made them. It hooks into UDP
// sendmsg operations to capture DNS traffic.
//
// The eBPF program tracks UDP sockets sending to port 53 (DNS) and
// stores the process info keyed by source port. When the packet capture
// sees a DNS query, it can look up the source port to find which process
// made the query.
//
// When eBPF is not available (non-Linux, feature disabled, or runtime
// failure), it falls back gracefully to no-op stubs.

use tracing::info;

/// DNS socket info from eBPF
#[derive(Debug, Clone)]
pub struct DnsSocketInfo {
    pub pid: u32,
    pub uid: u32,
    pub process_name: String,
    pub src_port: u16,
    pub timestamp: u64,
    /// Address family: 2 = IPv4, 10 = IPv6
    pub family: u8,
    /// Source IP address (for IPv4, only first element is used)
    pub src_ip: [u32; 4],
    /// Destination IP address (DNS server)
    pub dst_ip: [u32; 4],
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
mod linux {
    use super::*;
    use aya::maps::HashMap as AyaHashMap;
    use aya::Pod as AyaPod;
    use aya::Ebpf;
    use bytemuck::{Pod, Zeroable};
    use once_cell::sync::OnceCell;
    use std::sync::{Arc, RwLock};
    use tracing::{error, info, warn};

    // Embed the DNS eBPF object file at compile time
    #[cfg(DNS_EBPF_EMBEDDED)]
    static DNS_EBPF_OBJECT: &[u8] = include_bytes!(env!("DNS_EBPF_OBJECT"));

    #[cfg(not(DNS_EBPF_EMBEDDED))]
    static DNS_EBPF_OBJECT: &[u8] = &[];

    // Match the eBPF structure for dns_socket_info
    #[repr(C)]
    #[derive(Clone, Copy, Zeroable, Pod)]
    struct EbpfDnsSocketInfo {
        pid: u32,
        uid: u32,
        timestamp: u64,
        src_port: u16,
        dst_port: u16,
        family: u8,
        padding: [u8; 3],
        src_ip: [u32; 4],  // Source IP (IPv4 in first element, or full IPv6)
        dst_ip: [u32; 4],  // Destination IP (DNS server)
        process_name: [u8; 16],
    }

    unsafe impl AyaPod for EbpfDnsSocketInfo {}

    struct Inner {
        bpf: RwLock<Ebpf>,
    }

    impl Inner {
        fn new_with_status() -> (Option<Self>, String) {
            // Get kernel version first for status messages
            let kernel_version = nix::sys::utsname::uname()
                .map(|u| u.release().to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string());

            // Check if running as root or has CAP_BPF
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
                        warn!("DNS eBPF disabled: {}", msg);
                        return (None, msg);
                    }
                }
            }

            // Check if DNS eBPF object was embedded
            if DNS_EBPF_OBJECT.is_empty() {
                let msg = format!(
                    "Disabled: DNS eBPF object not embedded (clang/llvm not available at build time) (kernel {})",
                    kernel_version
                );
                warn!("DNS eBPF object not embedded");
                return (None, msg);
            }

            info!(
                "DNS eBPF: Loading embedded object ({} bytes)",
                DNS_EBPF_OBJECT.len()
            );

            // Copy to Vec for alignment (same fix as l7_ebpf)
            let aligned_object: Vec<u8> = DNS_EBPF_OBJECT.to_vec();

            let mut bpf = match Ebpf::load(&aligned_object) {
                Ok(bpf) => bpf,
                Err(e) => {
                    let msg = format!(
                        "Disabled: failed to load DNS eBPF program: {} (kernel {})",
                        e, kernel_version
                    );
                    error!("Failed to load DNS eBPF program: {}", e);
                    return (None, msg);
                }
            };

            // Attach udp_sendmsg kprobe
            use aya::programs::KProbe;

            let prog_name = "trace_udp_send";
            let prog: &mut KProbe = match bpf.program_mut(prog_name) {
                Some(p) => match p.try_into() {
                    Ok(kp) => kp,
                    Err(e) => {
                        let msg = format!("Disabled: {} is not a kprobe: {}", prog_name, e);
                        error!("{}", msg);
                        return (None, msg);
                    }
                },
                None => {
                    let msg = format!("Disabled: program {} not found", prog_name);
                    error!("{}", msg);
                    return (None, msg);
                }
            };

            if let Err(e) = prog.load() {
                let msg = format!("Disabled: failed to load {}: {}", prog_name, e);
                error!("{}", msg);
                return (None, msg);
            }

            if let Err(e) = prog.attach("udp_sendmsg", 0) {
                let msg = format!("Disabled: failed to attach {}: {}", prog_name, e);
                error!("{}", msg);
                return (None, msg);
            }

            info!("DNS eBPF: udp_sendmsg kprobe attached successfully");

            // Attach udpv6_sendmsg kprobe for IPv6 DNS (non-critical if fails)
            let mut ipv6_attached = false;
            if let Some(prog_any) = bpf.program_mut("trace_udpv6_send") {
                if let Ok(kp) = TryInto::<&mut KProbe>::try_into(prog_any) {
                    if kp.load().is_ok() {
                        if kp.attach("udpv6_sendmsg", 0).is_ok() {
                            info!("DNS eBPF: udpv6_sendmsg kprobe attached for IPv6");
                            ipv6_attached = true;
                        }
                    }
                }
            }

            let ipv6_note = if ipv6_attached { " + IPv6" } else { "" };
            let msg = format!(
                "Enabled: kernel {} with udp_sendmsg{} kprobe attached",
                kernel_version, ipv6_note
            );
            info!("DNS eBPF L7 helper initialised successfully: {}", msg);

            (Some(Self { bpf: RwLock::new(bpf) }), msg)
        }

        fn lookup_by_src_port(&self, src_port: u16) -> Option<DnsSocketInfo> {
            let bpf = self.bpf.read().ok()?;
            
            let map = bpf.map("dns_sockets")?;
            let map: AyaHashMap<_, u16, EbpfDnsSocketInfo> =
                AyaHashMap::try_from(map).ok()?;

            let info = map.get(&src_port, 0).ok()?;
            
            let name = std::str::from_utf8(&info.process_name)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_string();

            Some(DnsSocketInfo {
                pid: info.pid,
                uid: info.uid,
                process_name: name,
                src_port: info.src_port,
                timestamp: info.timestamp,
                family: info.family,
                src_ip: info.src_ip,
                dst_ip: info.dst_ip,
            })
        }
    }

    pub struct DnsEbpf {
        inner: Option<Arc<Inner>>,
        init_status: String,
    }

    impl DnsEbpf {
        fn init() -> Self {
            let (inner, status) = Inner::new_with_status();
            Self {
                inner: inner.map(Arc::new),
                init_status: status,
            }
        }

        pub fn is_available(&self) -> bool {
            self.inner.is_some()
        }

        pub fn init_status(&self) -> &str {
            &self.init_status
        }

        /// Get process info for a DNS query by source port
        pub fn get_process_by_src_port(&self, src_port: u16) -> Option<DnsSocketInfo> {
            let inner = self.inner.as_ref()?;
            inner.lookup_by_src_port(src_port)
        }
    }

    // Global accessor – lazily initialises on first use
    pub fn global() -> &'static DnsEbpf {
        static INSTANCE: OnceCell<DnsEbpf> = OnceCell::new();
        INSTANCE.get_or_init(|| DnsEbpf::init())
    }

    pub fn get_init_status() -> &'static str {
        global().init_status()
    }
}

#[cfg(not(all(target_os = "linux", feature = "ebpf")))]
mod linux {
    use super::*;

    #[allow(dead_code)]
    pub struct DnsEbpf;

    impl DnsEbpf {
        #[allow(dead_code)]
        pub fn is_available(&self) -> bool {
            false
        }

        #[allow(dead_code)]
        pub fn init_status(&self) -> &str {
            "Not available: compiled without eBPF support"
        }

        #[allow(dead_code)]
        pub fn get_process_by_src_port(&self, _src_port: u16) -> Option<DnsSocketInfo> {
            None
        }
    }

    #[allow(dead_code)]
    pub fn global() -> &'static DnsEbpf {
        static INSTANCE: DnsEbpf = DnsEbpf;
        &INSTANCE
    }

    #[allow(dead_code)]
    pub fn get_init_status() -> &'static str {
        "Not available: compiled without eBPF support"
    }
}

// Public API

/// Check if DNS eBPF is available
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

/// Get detailed DNS eBPF support status
pub fn dns_ebpf_support() -> String {
    #[cfg(not(target_os = "linux"))]
    {
        return "Not supported: DNS eBPF requires Linux".to_string();
    }

    #[cfg(all(target_os = "linux", not(feature = "ebpf")))]
    {
        return "Not enabled: compiled without 'ebpf' feature flag".to_string();
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    {
        linux::get_init_status().to_string()
    }
}

/// Get process info for a DNS query by source port
/// This is called when the packet capture sees a DNS query and wants to
/// know which process made it.
pub fn get_process_by_src_port(src_port: u16) -> Option<DnsSocketInfo> {
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    {
        linux::global().get_process_by_src_port(src_port)
    }

    #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
    {
        let _ = src_port;
        None
    }
}

/// Initialize and log DNS eBPF status
pub fn init_and_log_status() {
    let available = is_available();
    if available {
        info!(
            "DNS eBPF L7 resolution helper is ENABLED - DNS queries will be attributed to processes"
        );
    } else {
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            tracing::warn!(
                "DNS eBPF L7 resolution helper is DISABLED - falling back to packet-only resolution"
            );
        }
        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        {
            info!(
                "DNS eBPF L7 resolution not available on this platform (non-Linux or feature disabled)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_ebpf_availability_check() {
        // This just tests that the availability check doesn't panic
        let available = is_available();
        println!("DNS eBPF available: {}", available);
        let status = dns_ebpf_support();
        println!("DNS eBPF status: {}", status);
    }

    #[test]
    fn test_dns_ebpf_lookup_returns_none_without_kernel_support() {
        // Without actual kernel eBPF support, lookups should return None
        let result = get_process_by_src_port(12345);
        if !is_available() {
            assert!(result.is_none());
        }
    }
}
