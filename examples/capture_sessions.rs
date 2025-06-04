//! Example: Network Session Capture
//!
//! This example demonstrates how to capture network sessions and analyze network traffic.
//! It captures packets for a specified duration and displays session information.

use clap::{arg, Command};
use flodbadd::capture::{CaptureConfig, PacketCapture};
use flodbadd::ip::get_all_interfaces;
use flodbadd::sessions::{format_sessions_log, format_sessions_zeek, SessionFilter, SessionInfo};
use std::thread::sleep;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("capture_sessions")
        .about("Capture and analyze network sessions")
        .arg(arg!(-d --duration <SECONDS> "Capture duration in seconds").default_value("60"))
        .arg(arg!(-z --zeek "Output in Zeek format"))
        .arg(arg!(-l --local "Include local traffic"))
        .arg(arg!(-i --interface <INTERFACE> "Network interface to capture on"))
        .get_matches();

    let duration = matches
        .get_one::<String>("duration")
        .unwrap()
        .parse::<u64>()
        .unwrap_or(60);
    let zeek_format = matches.get_flag("zeek");
    let include_local = matches.get_flag("local");
    let interface_name = matches.get_one::<String>("interface");

    println!("=== Flodbadd Session Capture Example ===\n");

    // Initialize tracing for debug output
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    // Get network interfaces
    let mut interfaces = get_all_interfaces()?;

    // Filter interface if specified
    if let Some(name) = interface_name {
        interfaces.retain(|i| i.name == *name);
        if interfaces.is_empty() {
            eprintln!("Interface '{}' not found", name);
            return Err("Interface not found".into());
        }
    }

    println!("Capturing on {} interface(s):", interfaces.len());
    for interface in &interfaces {
        println!("  - {} ({})", interface.name, interface.ip);
    }
    println!();

    // Create capture configuration
    let config = CaptureConfig {
        interfaces: interfaces.clone(),
        promiscuous: true,
        snaplen: 65535,
        timeout: Duration::from_millis(100),
        buffer_size: 10 * 1024 * 1024, // 10MB
    };

    // Create packet capture instance
    let mut capture = PacketCapture::new(config)?;

    // Start capturing
    println!("Starting packet capture for {} seconds...", duration);
    capture.start()?;

    // Capture for specified duration
    let start_time = std::time::Instant::now();
    let capture_duration = Duration::from_secs(duration);

    while start_time.elapsed() < capture_duration {
        let remaining = capture_duration - start_time.elapsed();
        print!("\rCapturing... {} seconds remaining", remaining.as_secs());
        use std::io::{self, Write};
        io::stdout().flush()?;

        sleep(Duration::from_secs(1));
    }

    // Stop capturing
    println!("\n\nStopping capture...");
    capture.stop()?;

    // Get captured sessions
    let sessions = capture.get_sessions()?;

    // Filter sessions based on user preference
    let filtered_sessions = if include_local {
        sessions
    } else {
        flodbadd::sessions::filter_global_sessions(&sessions)
    };

    println!(
        "Captured {} sessions ({} after filtering)\n",
        sessions.len(),
        filtered_sessions.len()
    );

    // Display results
    if filtered_sessions.is_empty() {
        println!("No sessions captured.");
    } else {
        if zeek_format {
            // Output in Zeek format
            println!("Sessions in Zeek format:\n");
            let zeek_output = format_sessions_zeek(&filtered_sessions);
            for line in zeek_output {
                println!("{}", line);
            }
        } else {
            // Output in human-readable format
            println!("Captured Sessions:\n");
            for (idx, session) in filtered_sessions.iter().enumerate() {
                println!("Session #{}:", idx + 1);
                println!(
                    "  Protocol: {}",
                    match session.session.protocol {
                        flodbadd::sessions::Protocol::TCP => "TCP",
                        flodbadd::sessions::Protocol::UDP => "UDP",
                    }
                );
                println!(
                    "  Source: {}:{}",
                    session.session.src_ip, session.session.src_port
                );
                println!(
                    "  Destination: {}:{}",
                    session.session.dst_ip, session.session.dst_port
                );

                if let Some(domain) = &session.dst_domain {
                    println!("  Domain: {}", domain);
                }

                if let Some(service) = &session.dst_service {
                    println!("  Service: {}", service);
                }

                if let Some(l7) = &session.l7 {
                    println!("  Process: {} (PID: {})", l7.process_name, l7.pid);
                    println!("  User: {}", l7.username);
                }

                println!(
                    "  Duration: {:?}",
                    session.stats.last_activity - session.stats.start_time
                );
                println!("  Bytes In: {}", session.stats.inbound_bytes);
                println!("  Bytes Out: {}", session.stats.outbound_bytes);
                println!("  Criticality: {}", session.criticality);

                match session.is_whitelisted {
                    flodbadd::sessions::WhitelistState::Conforming => {
                        println!("  Status: ✓ Whitelisted");
                    }
                    flodbadd::sessions::WhitelistState::NonConforming => {
                        println!("  Status: ⚠ Non-conforming");
                        if let Some(reason) = &session.whitelist_reason {
                            println!("  Reason: {}", reason);
                        }
                    }
                    flodbadd::sessions::WhitelistState::Unknown => {
                        println!("  Status: ? Unknown");
                    }
                }

                println!();
            }
        }
    }

    // Display statistics
    println!("\nCapture Statistics:");
    let stats = capture.get_statistics()?;
    println!("  Packets Received: {}", stats.packets_received);
    println!("  Packets Dropped: {}", stats.packets_dropped);
    println!("  Interface Dropped: {}", stats.interface_dropped);

    Ok(())
}
