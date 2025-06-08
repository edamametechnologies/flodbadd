//! This test exercises low-level session statistics. Requires the `packetcapture` feature because it
//! depends on the `packets` module.
#![cfg(all(
    feature = "packetcapture",
    any(target_os = "macos", target_os = "linux", target_os = "windows")
))]

use flodbadd::packets::{process_parsed_packet, SessionPacketData};
use flodbadd::sessions::{Protocol, Session, SessionFilter};
use pnet_packet::tcp::TcpFlags;
use serial_test::serial;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::time::sleep;
use undeadlock::{CustomDashMap, CustomRwLock};

/// Helper that quickly creates a PacketData instance
fn pkt(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    len: usize,
    flags: u8,
) -> SessionPacketData {
    SessionPacketData {
        session: Session {
            protocol: Protocol::TCP,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        },
        packet_length: len,
        ip_packet_length: len + 20, // assume fixed IP hdr for simplicity
        flags: Some(flags),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_statistics_pipeline() {
    // ---------------- Setup basic plumbing ----------------

    println!("test_statistics_pipeline");
    let sessions: Arc<CustomDashMap<Session, flodbadd::sessions::SessionInfo>> =
        Arc::new(CustomDashMap::new("Sessions"));
    let current_sessions: Arc<CustomRwLock<Vec<Session>>> = Arc::new(CustomRwLock::new(Vec::new()));
    let filter: Arc<CustomRwLock<SessionFilter>> = Arc::new(CustomRwLock::new(SessionFilter::All));

    // Treat 192.168.1.1 as one of our own IPs so packets in src→dst direction are originator
    let own_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let mut own_ips = HashSet::new();
    own_ips.insert(own_ip);

    // Common addresses / ports for the test session
    let src_ip = own_ip;
    let src_port = 40000;
    let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let dst_port = 9000;

    println!("Starting packet injection and processing");

    // ---------------- Feed packets ----------------
    // 1) SYN – starts session
    let p1 = pkt(src_ip, src_port, dst_ip, dst_port, 100, TcpFlags::SYN);
    process_parsed_packet(p1, &sessions, &current_sessions, &own_ips, &filter, None).await;

    println!("Processed p1");

    // 2) ACK with payload (150 bytes)
    let p2 = pkt(src_ip, src_port, dst_ip, dst_port, 150, TcpFlags::ACK);
    process_parsed_packet(p2, &sessions, &current_sessions, &own_ips, &filter, None).await;

    println!("Processed p2");

    // 3) ACK+PSH (ends first segment)
    let p3 = pkt(
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        100,
        TcpFlags::ACK | TcpFlags::PSH,
    );
    process_parsed_packet(p3, &sessions, &current_sessions, &own_ips, &filter, None).await;

    println!("Processed p3");

    // Wait 150 ms before second segment – influences segment_interarrival
    sleep(StdDuration::from_millis(150)).await;

    // 4) ACK (start second segment)
    let p4 = pkt(src_ip, src_port, dst_ip, dst_port, 200, TcpFlags::ACK);
    process_parsed_packet(p4, &sessions, &current_sessions, &own_ips, &filter, None).await;

    println!("Processed p4");

    // 5) ACK+PSH (end second segment)
    let p5 = pkt(
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        50,
        TcpFlags::ACK | TcpFlags::PSH,
    );
    process_parsed_packet(p5, &sessions, &current_sessions, &own_ips, &filter, None).await;

    println!("Processed p5");

    // 6) Inbound responder packet (300 bytes)
    let p6 = pkt(dst_ip, dst_port, src_ip, src_port, 300, TcpFlags::ACK);
    process_parsed_packet(p6, &sessions, &current_sessions, &own_ips, &filter, None).await;

    println!("Processed p6");

    // 7) FIN from originator (closes session)
    let p7 = pkt(src_ip, src_port, dst_ip, dst_port, 40, TcpFlags::FIN);
    process_parsed_packet(p7, &sessions, &current_sessions, &own_ips, &filter, None).await;

    println!("Processed p7");

    // ---------------- Assertions ----------------
    // Build the canonical key (direction should be unchanged as ports are high/unrecognised)
    let key = Session {
        protocol: Protocol::TCP,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
    };

    let entry = sessions
        .get(&key)
        .expect("Session should exist after feeding packets");
    let stats = &entry.value().stats;

    println!("Sessions: {:?}", sessions);
    println!("Current sessions: {:?}", current_sessions);
    println!("Filter: {:?}", filter);
    println!("Stats: {:?}", stats);

    // Bytes & packets
    assert_eq!(stats.outbound_bytes, 640, "Outbound bytes mismatch");
    assert_eq!(stats.inbound_bytes, 300, "Inbound bytes mismatch");
    assert_eq!(stats.orig_pkts, 6, "Originator packet count mismatch"); // 5 + FIN
    assert_eq!(stats.resp_pkts, 1, "Responder packet count mismatch");

    // Ratio (within small epsilon)
    let expected_ratio = 300.0 / 640.0;
    assert!((stats.inbound_outbound_ratio - expected_ratio).abs() < 1e-6);

    // Average packet size
    let expected_avg = (640.0 + 300.0) / 7.0;
    assert!((stats.average_packet_size - expected_avg).abs() < 1e-6);

    // Segment metrics
    assert!(
        stats.segment_count >= 2 && stats.segment_count <= 3,
        "Segment count expected 2 (two PSH ends) but got {}",
        stats.segment_count
    );
    assert!(
        stats.segment_interarrival > 0.05 && stats.segment_interarrival < 1.0,
        "Segment inter-arrival should reflect delay, got {}",
        stats.segment_interarrival
    );

    // Duration – should at least reflect the sleeps (~0.15 s) + processing time
    if let Some(end) = stats.end_time {
        let duration = (end - stats.start_time).num_milliseconds() as f64 / 1000.0;
        assert!(
            duration >= 0.15,
            "Duration should be >=0.15 s, got {}",
            duration
        );
    } else {
        panic!("end_time not set after FIN packet");
    }
}
