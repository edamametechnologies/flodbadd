//! Example: LAN Neighbor Scan
//!
//! This minimal example lists the network interfaces available on the host
//! and performs a simple neighbor discovery (ARP/NDP) on the default
//! interface using the current `flodbadd` public API.
use flodbadd::interface::{get_all_interfaces, get_default_interface};
#[cfg(all(any(target_os = "macos", target_os = "linux", target_os = "windows"),))]
use flodbadd::neighbors::scan_neighbors;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialise basic logging so that the library can emit tracing output.
    tracing_subscriber::fmt::init();

    // Enumerate all (validated) interfaces.
    let interfaces = get_all_interfaces();
    println!("Found {} interface(s):", interfaces.len());
    for iface in &interfaces.interfaces {
        if let Some(v4) = &iface.ipv4 {
            println!("  - {} (IPv4: {})", iface.name, v4.ip);
        } else {
            println!("  - {} (no IPv4)", iface.name);
        }
    }

    // Pick the OS-determined default interface – bail out if none.
    let Some(default_iface) = get_default_interface() else {
        eprintln!("No suitable default interface detected.");
        return Ok(());
    };
    println!("\nScanning neighbours on '{}':", default_iface.name);

    // Run the neighbour scan (ARP/NDP); this call is async and cross-platform.
    #[cfg(all(any(target_os = "macos", target_os = "linux", target_os = "windows"),))]
    let neighbours = scan_neighbors(Some(&default_iface.name)).await?;
    #[cfg(all(any(target_os = "macos", target_os = "linux", target_os = "windows"),))]
    println!("Discovered {} neighbour group(s):", neighbours.len());

    #[cfg(all(any(target_os = "macos", target_os = "linux", target_os = "windows"),))]
    for (mac, v4_addrs, v6_addrs) in neighbours {
        println!("\nMAC: {mac}");
        if !v4_addrs.is_empty() {
            println!("  IPv4: {:?}", v4_addrs);
        }
        if !v6_addrs.is_empty() {
            println!("  IPv6: {:?}", v6_addrs);
        }
    }

    Ok(())
}
