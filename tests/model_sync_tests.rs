//! This test exercises low-level session statistics. Requires the `packetcapture` feature because it
//! depends on the `packets` module.
#![cfg(all(
    feature = "packetcapture",
    any(target_os = "macos", target_os = "linux", target_os = "windows")
))]

use chrono::Utc;
use flodbadd::capture::{FlodbaddCapture, MODEL_SYNCED};
use flodbadd::sessions::*;
use std::net::{IpAddr, Ipv4Addr};
use tokio::time::{timeout, Duration};

// Helper to build a minimal SessionInfo for tests
fn build_session(ip: IpAddr) -> SessionInfo {
    let now = Utc::now();
    SessionInfo {
        session: Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 50000,
            dst_ip: ip,
            dst_port: 443,
        },
        status: SessionStatus::default(),
        stats: SessionStats::new(now),
        is_local_src: true,
        is_local_dst: false,
        is_self_src: false,
        is_self_dst: false,
        src_domain: None,
        dst_domain: None,
        dst_service: None,
        l7: None,
        src_asn: None,
        dst_asn: None,
        is_whitelisted: WhitelistState::Unknown,
        criticality: String::new(),
        dismissed: false,
        whitelist_reason: None,
        uid: uuid::Uuid::new_v4().to_string(),
        last_modified: now,
    }
}

#[tokio::test]
#[cfg_attr(
    not(all(
        feature = "packetcapture",
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    )),
    ignore
)]
async fn test_blacklist_revision_notifier() {
    let capture = FlodbaddCapture::new();

    // Add a session destined for IP we will blacklist
    let ip: IpAddr = "5.78.100.21".parse().unwrap();
    let session = build_session(ip);
    capture
        .sessions
        .insert(session.session.clone(), session.clone());

    // Prepare custom blacklist JSON
    let blacklist_json = format!(
        r#"{{
            "date": "2025-01-01T00:00:00Z",
            "signature": "test-sig",
            "blacklists": [{{
                "name": "sync_test_blacklist",
                "ip_ranges": ["{ip}"]
            }}]
        }}"#
    );

    // Set blacklist and wait for model recomputation via notifier
    capture
        .set_custom_blacklists(&blacklist_json)
        .await
        .expect("set_custom_blacklists failed");

    // Wait (with timeout) for notifier
    timeout(Duration::from_secs(5), MODEL_SYNCED.notified())
        .await
        .expect("MODEL_SYNCED timeout");

    // Re-check sessions
    capture.update_sessions().await; // Ensure latest state
    let bl_sessions = capture.get_blacklisted_sessions(false).await;
    assert!(
        !bl_sessions.is_empty(),
        "Session should be blacklisted after notifier"
    );
}
