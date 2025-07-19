//! Example: Using the `SessionAnalyzer` for anomaly detection with the
//! current `flodbadd` API.
//!
//! The sample simply feeds a small set of synthetic sessions to the
//! analyzer and prints the resulting statistics.
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
use chrono::Utc;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
use flodbadd::analyzer::{AnalysisResult, SessionAnalyzer};
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
use flodbadd::sessions::{Protocol, SessionInfo};
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
use std::net::IpAddr;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
use std::str::FromStr;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
use std::sync::Arc;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
use tokio::time::{sleep, Duration};
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(all(
        any(target_os = "macos", target_os = "linux", target_os = "windows"),
        feature = "packetcapture"
    ))]
    {
        tracing_subscriber::fmt::init();

        // Create & start the analyzer.
        let analyzer = Arc::new(SessionAnalyzer::new());
        analyzer.start().await;

        // Generate a handful of synthetic sessions and analyse them.
        let mut sessions = generate_sample_sessions();
        let AnalysisResult {
            sessions_analyzed,
            anomalous_count,
            blacklisted_count,
            new_anomalous_found,
            new_blacklisted_found,
            ..
        } = analyzer.analyze_sessions(&mut sessions).await;

        info!(
            "Analyzed {sessions_analyzed} sessions → anomalous: {anomalous_count} (new: {new_anomalous_found}), blacklisted: {blacklisted_count} (new: {new_blacklisted_found})"
        );

        // Give the background model a moment (purely illustrative).
        sleep(Duration::from_secs(1)).await;

        analyzer.stop().await;
    }
    Ok(())
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
fn generate_sample_sessions() -> Vec<SessionInfo> {
    let now = Utc::now();

    let mut normal = SessionInfo::default();
    normal.session.protocol = Protocol::TCP;
    normal.session.src_ip = IpAddr::from_str("192.168.1.10").unwrap();
    normal.session.src_port = 50000;
    normal.session.dst_ip = IpAddr::from_str("93.184.216.34").unwrap(); // example.com
    normal.session.dst_port = 80;
    normal.stats.start_time = now;
    normal.stats.last_activity = now;

    let mut large_transfer = SessionInfo::default();
    large_transfer.session.protocol = Protocol::TCP;
    large_transfer.session.src_ip = IpAddr::from_str("10.0.0.5").unwrap();
    large_transfer.session.src_port = 40000;
    large_transfer.session.dst_ip = IpAddr::from_str("185.220.101.1").unwrap(); // TOR exit (example)
    large_transfer.session.dst_port = 443;
    large_transfer.stats.inbound_bytes = 50 * 1024 * 1024; // 50 MiB
    large_transfer.stats.outbound_bytes = 100 * 1024;
    large_transfer.stats.start_time = now;
    large_transfer.stats.last_activity = now;

    vec![normal, large_transfer]
}
