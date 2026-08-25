pub mod analyzer;
pub mod arp;
pub mod asn;
pub mod asn_db;
pub mod asn_v4_db;
pub mod asn_v6_db;
pub mod blacklists;
pub mod blacklists_db;
pub mod broadcast;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub mod capture;
pub mod cloud_model_fallback;
pub mod device_info;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub mod dns;
pub mod dns_ebpf;
pub mod error;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "fim"
))]
pub mod fim;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "fim"
))]
pub mod fim_events;
pub mod interface;
pub mod ip;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub mod l7;
pub mod l7_ebpf;
pub mod l7_es;
pub mod l7_etw;
#[cfg(target_os = "macos")]
pub mod l7_macos;
pub mod l7_trait;
pub mod mdns;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
pub mod neighbors;
#[cfg(target_os = "windows")]
pub mod windows_npcap;
#[cfg(target_os = "windows")]
pub use windows_npcap as npcap_utils; // backward-compatible re-export
pub mod dns_patterns;
pub mod open_files;
pub mod oui;
pub mod oui_db;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub mod packets;
pub mod packetstats;
pub mod port_info;
pub mod port_vulns;
pub mod port_vulns_db;
pub mod profiles;
pub mod profiles_db;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub mod resolver;
pub mod sensitive_paths;
pub mod sensitive_paths_db;
pub mod sessions;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub mod sni;
pub mod task;
pub mod vendor_vulns;
pub mod vendor_vulns_db;
pub mod vulnerability_info;
pub mod whitelists;
pub mod whitelists_db;
pub mod win_path_normalize;

// Automatic initialization for Windows tests - adds Npcap DLL directory to PATH
#[cfg(all(test, target_os = "windows"))]
mod test_init {
    use crate::npcap_utils;

    #[ctor::ctor]
    fn init_npcap_path() {
        // Use shared utility to configure Npcap runtime
        match npcap_utils::configure_npcap_runtime() {
            Ok(_) => {
                let npcap_dir = npcap_utils::get_npcap_dir();
                println!(
                    "[Test Init] ✓ Npcap DLL path configured: {}",
                    npcap_dir.display()
                );
            }
            Err(e) => {
                println!(
                    "[Test Init] [WARN] Warning: Failed to configure Npcap: {}",
                    e
                );
                println!("[Test Init] Tests may fail with STATUS_DLL_NOT_FOUND");
            }
        }
    }
}
