//! Example demonstrating how to use the SessionAnalyzer for anomaly detection
//!
//! This example shows how to:
//! - Create a SessionAnalyzer instance
//! - Analyze network sessions for anomalies
//! - Handle the warm-up period
//! - Retrieve anomalous sessions

use flodbadd::capture::start_packet_capture;
use flodbadd::sessions::SessionInfo;
use flodbadd::{AnalysisResult, SessionAnalyzer, SessionCriticality};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Create the session analyzer
    let analyzer = Arc::new(SessionAnalyzer::new());

    // Start the analyzer
    analyzer.start().await;
    info!("Session analyzer started");

    // Simulate getting sessions (in a real app, these would come from packet capture)
    let mut sessions = generate_sample_sessions();

    // Analyze sessions multiple times to demonstrate warm-up period
    for i in 0..5 {
        info!("Analysis round {}", i + 1);

        // Analyze the sessions
        let result: AnalysisResult = analyzer.analyze_sessions(&mut sessions).await;

        info!(
            "Analyzed {} sessions: {} anomalous, {} blacklisted (new anomalous: {}, new blacklisted: {})",
            result.sessions_analyzed,
            result.anomalous_count,
            result.blacklisted_count,
            result.new_anomalous_found,
            result.new_blacklisted_found
        );

        // Print some details about anomalous sessions
        for session in &sessions {
            if session.criticality.contains("anomaly:suspicious")
                || session.criticality.contains("anomaly:abnormal")
            {
                info!(
                    "Anomalous session: {} -> {} (criticality: {})",
                    session.src_ip, session.dst_ip, session.criticality
                );
            }
        }

        // Wait a bit before next analysis
        sleep(Duration::from_secs(30)).await;

        // Generate some new sessions for next round
        sessions.extend(generate_sample_sessions());
    }

    // Get all tracked anomalous sessions
    let anomalous = analyzer.get_anomalous_sessions().await;
    info!("Total anomalous sessions tracked: {}", anomalous.len());

    // Clean up
    analyzer.stop().await;
    info!("Session analyzer stopped");

    Ok(())
}

/// Generate some sample sessions for testing
fn generate_sample_sessions() -> Vec<SessionInfo> {
    use chrono::Utc;
    use std::net::IpAddr;
    use std::str::FromStr;

    let mut sessions = Vec::new();

    // Normal sessions
    for i in 0..10 {
        let mut session = SessionInfo::default();
        session.uid = format!("normal_{}", i);
        session.src_ip = IpAddr::from_str("192.168.1.100").unwrap();
        session.dst_ip = IpAddr::from_str(&format!("192.168.1.{}", 200 + i)).unwrap();
        session.dst_port = 80;
        session.stats.inbound_bytes = 1024 * (i as u64 + 1);
        session.stats.outbound_bytes = 512 * (i as u64 + 1);
        session.stats.orig_pkts = 10 + i as u64;
        session.stats.resp_pkts = 8 + i as u64;
        session.stats.start_time = Utc::now();
        session.stats.last_activity = Utc::now();
        sessions.push(session);
    }

    // Some potentially anomalous sessions
    for i in 0..3 {
        let mut session = SessionInfo::default();
        session.uid = format!("suspicious_{}", i);
        session.src_ip = IpAddr::from_str("10.0.0.100").unwrap();
        session.dst_ip = IpAddr::from_str(&format!("185.220.101.{}", i + 1)).unwrap(); // Tor exit node range
        session.dst_port = 443;
        session.stats.inbound_bytes = 1024 * 1024 * 50; // Large data transfer
        session.stats.outbound_bytes = 1024 * 100;
        session.stats.orig_pkts = 5000;
        session.stats.resp_pkts = 4800;
        session.stats.missed_bytes = 1024 * 10; // Some missed data
        session.stats.start_time = Utc::now();
        session.stats.last_activity = Utc::now();
        sessions.push(session);
    }

    // A blacklisted session (would normally be detected by blacklist DB)
    let mut blacklisted = SessionInfo::default();
    blacklisted.uid = "blacklisted_1".to_string();
    blacklisted.src_ip = IpAddr::from_str("192.168.1.150").unwrap();
    blacklisted.dst_ip = IpAddr::from_str("198.51.100.1").unwrap(); // Known C2 server (example)
    blacklisted.dst_port = 4444;
    blacklisted.criticality = "blacklist:known_c2_server".to_string(); // Pre-marked as blacklisted
    blacklisted.stats.start_time = Utc::now();
    blacklisted.stats.last_activity = Utc::now();
    sessions.push(blacklisted);

    sessions
}
