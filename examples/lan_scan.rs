//! Example: LAN Scanner
//! 
//! This example demonstrates how to perform a LAN scan to discover devices on the local network.
//! It will scan all available network interfaces and display discovered devices.

use flodbadd::ip::get_all_interfaces;
use flodbadd::scanner::{NetworkScanner, ScannerConfig};
use flodbadd::device_info::DeviceInfo;
use std::time::Duration;
use std::thread::sleep;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Flodbadd LAN Scanner Example ===\n");

    // Initialize tracing for debug output
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    // Get all network interfaces
    let interfaces = get_all_interfaces()?;
    println!("Found {} network interfaces:", interfaces.len());
    for interface in &interfaces {
        println!("  - {} ({})", interface.name, interface.ip);
    }
    println!();

    // Create scanner configuration
    let config = ScannerConfig {
        timeout: Duration::from_secs(5),
        concurrent_scans: 100,
        scan_ports: vec![80, 443, 22, 21, 23, 25, 110, 139, 445, 3389, 8080],
        enable_mdns: true,
        enable_arp: true,
    };

    // Create network scanner
    let mut scanner = NetworkScanner::new(config)?;

    // Start scanning
    println!("Starting LAN scan...");
    scanner.start_scan(&interfaces)?;

    // Wait for scan to complete (or timeout after 30 seconds)
    let mut devices: Vec<DeviceInfo> = Vec::new();
    let scan_duration = Duration::from_secs(30);
    let start_time = std::time::Instant::now();

    while start_time.elapsed() < scan_duration {
        // Get current scan results
        devices = scanner.get_discovered_devices()?;
        
        // Display progress
        print!("\rScanning... Found {} devices", devices.len());
        use std::io::{self, Write};
        io::stdout().flush()?;

        // Check if scan is complete
        if scanner.is_scan_complete()? {
            break;
        }

        sleep(Duration::from_millis(500));
    }

    // Stop scanning
    scanner.stop_scan()?;
    println!("\n\nScan complete!\n");

    // Display results
    if devices.is_empty() {
        println!("No devices found on the network.");
    } else {
        println!("Discovered {} devices:\n", devices.len());
        
        for (idx, device) in devices.iter().enumerate() {
            println!("Device #{}:", idx + 1);
            println!("  IP Address: {}", device.get_ip_address());
            
            if let Some(mac) = device.get_mac_address() {
                println!("  MAC Address: {}", mac);
            }
            
            if !device.hostname.is_empty() {
                println!("  Hostname: {}", device.hostname);
            }
            
            if !device.device_vendor.is_empty() {
                println!("  Vendor: {}", device.device_vendor);
            }
            
            if !device.os_name.is_empty() {
                println!("  OS: {} {}", device.os_name, device.os_version);
            }
            
            if !device.open_ports.is_empty() {
                println!("  Open Ports:");
                for port in &device.open_ports {
                    println!("    - {} ({})", port.port, port.service);
                }
            }
            
            if !device.mdns_services.is_empty() {
                println!("  mDNS Services:");
                for service in &device.mdns_services {
                    println!("    - {}", service);
                }
            }
            
            println!("  Device Type: {}", device.device_type);
            println!("  Criticality: {}", device.criticality);
            println!();
        }
    }

    Ok(())
} 