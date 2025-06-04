//! Example: Whitelist Management
//!
//! This example demonstrates how to create, manage, and check network whitelists.
//! It shows how to generate whitelists from current sessions and validate traffic against them.

use clap::{arg, Command, Subcommand};
use flodbadd::capture::{CaptureConfig, PacketCapture};
use flodbadd::ip::get_all_interfaces;
use flodbadd::sessions::{SessionInfo, WhitelistState};
use flodbadd::whitelists::{WhitelistEntry, WhitelistManager, WhitelistType};
use serde_json;
use std::net::IpAddr;
use std::time::Duration;

#[derive(Subcommand)]
enum Commands {
    /// Create whitelist from current network sessions
    Create {
        /// Duration to capture sessions (seconds)
        #[arg(short, long, default_value = "60")]
        duration: u64,
        /// Output file for whitelist
        #[arg(short, long, default_value = "whitelist.json")]
        output: String,
    },
    /// Check sessions against existing whitelist
    Check {
        /// Whitelist file to use
        #[arg(short, long, default_value = "whitelist.json")]
        whitelist: String,
        /// Duration to monitor (seconds)
        #[arg(short, long, default_value = "30")]
        duration: u64,
    },
    /// Display whitelist contents
    Show {
        /// Whitelist file to display
        #[arg(short, long, default_value = "whitelist.json")]
        whitelist: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Command::new("whitelist_management")
        .about("Manage network whitelists")
        .subcommand_required(true)
        .subcommand(
            Command::new("create")
                .about("Create whitelist from current sessions")
                .arg(arg!(-d --duration <SECONDS> "Capture duration").default_value("60"))
                .arg(arg!(-o --output <FILE> "Output file").default_value("whitelist.json")),
        )
        .subcommand(
            Command::new("check")
                .about("Check sessions against whitelist")
                .arg(arg!(-w --whitelist <FILE> "Whitelist file").default_value("whitelist.json"))
                .arg(arg!(-d --duration <SECONDS> "Monitor duration").default_value("30")),
        )
        .subcommand(
            Command::new("show")
                .about("Display whitelist contents")
                .arg(arg!(-w --whitelist <FILE> "Whitelist file").default_value("whitelist.json")),
        );

    let matches = cli.get_matches();

    println!("=== Flodbadd Whitelist Management Example ===\n");

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    match matches.subcommand() {
        Some(("create", sub_matches)) => {
            let duration = sub_matches
                .get_one::<String>("duration")
                .unwrap()
                .parse::<u64>()?;
            let output = sub_matches.get_one::<String>("output").unwrap();
            create_whitelist(duration, output)?;
        }
        Some(("check", sub_matches)) => {
            let whitelist_file = sub_matches.get_one::<String>("whitelist").unwrap();
            let duration = sub_matches
                .get_one::<String>("duration")
                .unwrap()
                .parse::<u64>()?;
            check_whitelist(whitelist_file, duration)?;
        }
        Some(("show", sub_matches)) => {
            let whitelist_file = sub_matches.get_one::<String>("whitelist").unwrap();
            show_whitelist(whitelist_file)?;
        }
        _ => unreachable!(),
    }

    Ok(())
}

fn create_whitelist(duration: u64, output_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Creating whitelist from current network sessions...\n");

    // Get network interfaces
    let interfaces = get_all_interfaces()?;

    // Create capture configuration
    let config = CaptureConfig {
        interfaces: interfaces.clone(),
        promiscuous: true,
        snaplen: 65535,
        timeout: Duration::from_millis(100),
        buffer_size: 10 * 1024 * 1024,
    };

    // Capture sessions
    let mut capture = PacketCapture::new(config)?;
    println!("Capturing network sessions for {} seconds...", duration);

    capture.start()?;
    std::thread::sleep(Duration::from_secs(duration));
    capture.stop()?;

    let sessions = capture.get_sessions()?;
    println!("Captured {} sessions\n", sessions.len());

    // Create whitelist manager
    let mut whitelist_manager = WhitelistManager::new();

    // Generate whitelist entries from sessions
    let mut entries_count = 0;
    for session in &sessions {
        // Skip local-only traffic
        if flodbadd::ip::is_lan_ip(&session.session.src_ip)
            && flodbadd::ip::is_lan_ip(&session.session.dst_ip)
        {
            continue;
        }

        // Create entry based on destination
        let entry = WhitelistEntry {
            name: session
                .dst_domain
                .clone()
                .unwrap_or_else(|| format!("Service on port {}", session.session.dst_port)),
            description: format!(
                "Auto-generated from {} traffic to {}",
                match session.session.protocol {
                    flodbadd::sessions::Protocol::TCP => "TCP",
                    flodbadd::sessions::Protocol::UDP => "UDP",
                },
                session
                    .dst_service
                    .as_ref()
                    .unwrap_or(&"unknown service".to_string())
            ),
            whitelist_type: WhitelistType::Domain,
            value: session
                .dst_domain
                .clone()
                .unwrap_or_else(|| session.session.dst_ip.to_string()),
            ports: vec![session.session.dst_port],
            protocols: vec![match session.session.protocol {
                flodbadd::sessions::Protocol::TCP => "TCP".to_string(),
                flodbadd::sessions::Protocol::UDP => "UDP".to_string(),
            }],
            process_names: session
                .l7
                .as_ref()
                .map(|l7| vec![l7.process_name.clone()])
                .unwrap_or_default(),
            enabled: true,
        };

        whitelist_manager.add_entry(entry)?;
        entries_count += 1;
    }

    // Save whitelist
    whitelist_manager.save_to_file(output_file)?;

    println!("Created whitelist with {} entries", entries_count);
    println!("Saved to: {}", output_file);

    // Show summary
    println!("\nWhitelist Summary:");
    let entries = whitelist_manager.get_entries();
    for (idx, entry) in entries.iter().take(10).enumerate() {
        println!("  {}. {} - {}", idx + 1, entry.name, entry.value);
    }
    if entries.len() > 10 {
        println!("  ... and {} more entries", entries.len() - 10);
    }

    Ok(())
}

fn check_whitelist(whitelist_file: &str, duration: u64) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "Checking network sessions against whitelist: {}\n",
        whitelist_file
    );

    // Load whitelist
    let mut whitelist_manager = WhitelistManager::new();
    whitelist_manager.load_from_file(whitelist_file)?;

    let entry_count = whitelist_manager.get_entries().len();
    println!("Loaded whitelist with {} entries\n", entry_count);

    // Get network interfaces
    let interfaces = get_all_interfaces()?;

    // Create capture configuration
    let config = CaptureConfig {
        interfaces,
        promiscuous: true,
        snaplen: 65535,
        timeout: Duration::from_millis(100),
        buffer_size: 10 * 1024 * 1024,
    };

    // Monitor sessions
    let mut capture = PacketCapture::new(config)?;
    println!("Monitoring network sessions for {} seconds...\n", duration);

    capture.start()?;

    let start_time = std::time::Instant::now();
    let monitor_duration = Duration::from_secs(duration);

    let mut conforming_count = 0;
    let mut non_conforming_count = 0;
    let mut exceptions = Vec::new();

    while start_time.elapsed() < monitor_duration {
        std::thread::sleep(Duration::from_secs(5));

        let sessions = capture.get_sessions()?;

        for session in &sessions {
            // Skip local traffic
            if flodbadd::ip::is_lan_ip(&session.session.src_ip)
                && flodbadd::ip::is_lan_ip(&session.session.dst_ip)
            {
                continue;
            }

            // Check against whitelist
            let is_whitelisted = whitelist_manager.check_session(session)?;

            match is_whitelisted {
                WhitelistState::Conforming => {
                    conforming_count += 1;
                }
                WhitelistState::NonConforming => {
                    non_conforming_count += 1;
                    exceptions.push(session.clone());
                }
                WhitelistState::Unknown => {}
            }
        }

        print!(
            "\rChecking... Conforming: {} | Non-conforming: {}",
            conforming_count, non_conforming_count
        );
        use std::io::{self, Write};
        io::stdout().flush()?;
    }

    capture.stop()?;
    println!("\n\nMonitoring complete!\n");

    // Display results
    println!("Results:");
    println!("  Conforming sessions: {}", conforming_count);
    println!("  Non-conforming sessions: {}", non_conforming_count);

    if !exceptions.is_empty() {
        println!("\nNon-conforming sessions detected:");
        for (idx, session) in exceptions.iter().take(10).enumerate() {
            println!("\n  Exception #{}:", idx + 1);
            println!(
                "    Destination: {}:{}",
                session.session.dst_ip, session.session.dst_port
            );
            if let Some(domain) = &session.dst_domain {
                println!("    Domain: {}", domain);
            }
            if let Some(l7) = &session.l7 {
                println!("    Process: {}", l7.process_name);
            }
            if let Some(reason) = &session.whitelist_reason {
                println!("    Reason: {}", reason);
            }
        }

        if exceptions.len() > 10 {
            println!("\n  ... and {} more exceptions", exceptions.len() - 10);
        }
    }

    Ok(())
}

fn show_whitelist(whitelist_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Displaying whitelist: {}\n", whitelist_file);

    // Load whitelist
    let mut whitelist_manager = WhitelistManager::new();
    whitelist_manager.load_from_file(whitelist_file)?;

    let entries = whitelist_manager.get_entries();
    println!("Whitelist contains {} entries:\n", entries.len());

    for (idx, entry) in entries.iter().enumerate() {
        println!("Entry #{}:", idx + 1);
        println!("  Name: {}", entry.name);
        println!("  Description: {}", entry.description);
        println!("  Type: {:?}", entry.whitelist_type);
        println!("  Value: {}", entry.value);
        if !entry.ports.is_empty() {
            println!("  Ports: {:?}", entry.ports);
        }
        if !entry.protocols.is_empty() {
            println!("  Protocols: {:?}", entry.protocols);
        }
        if !entry.process_names.is_empty() {
            println!("  Processes: {:?}", entry.process_names);
        }
        println!("  Enabled: {}", entry.enabled);
        println!();
    }

    Ok(())
}
