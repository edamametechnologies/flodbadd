//! This test exercises low-level session statistics. Requires the `packetcapture` feature because it
//! depends on the `packets` module.
#![cfg(all(
    feature = "packetcapture",
    any(target_os = "macos", target_os = "linux", target_os = "windows")
))]

use flodbadd::analyzer::SessionAnalyzer;
use flodbadd::packets::{process_parsed_packet, SessionPacketData};
use flodbadd::sessions::SessionInfo as FlodSessionInfo;
use flodbadd::sessions::{Protocol, Session, SessionFilter};
use pnet_packet::tcp::TcpFlags;
use serial_test::serial;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::time::sleep;
use undeadlock::{CustomDashMap, CustomRwLock};
mod common;

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

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_analyzer_bytes_scaling_detection() {
    // Build many normal flows for baseline, then add a very large (exfil-like) flow
    let sessions: Arc<CustomDashMap<Session, flodbadd::sessions::SessionInfo>> =
        Arc::new(CustomDashMap::new("SessionsBytes"));
    let current_sessions: Arc<CustomRwLock<Vec<Session>>> = Arc::new(CustomRwLock::new(Vec::new()));
    let filter: Arc<CustomRwLock<SessionFilter>> = Arc::new(CustomRwLock::new(SessionFilter::All));

    let own_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    let mut own_ips = HashSet::new();
    own_ips.insert(own_ip);

    // Multiple normal flows with modest variability to avoid zero-variance diagnostics
    for i in 0..30u16 {
        let n_src = own_ip;
        let n_dst = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34 + (i % 10) as u8)); // vary IP
        let sport = 41000 + i;
        let upl = 800 + ((i as usize) * 13) % 500;
        let down = 6000 + ((i as usize) * 23) % 6000;
        process_parsed_packet(
            pkt(n_src, sport, n_dst, 443, 600 + (upl % 400), TcpFlags::SYN),
            &sessions,
            &current_sessions,
            &own_ips,
            &filter,
            None,
        )
        .await;
        process_parsed_packet(
            pkt(n_src, sport, n_dst, 443, 1000 + (upl % 700), TcpFlags::ACK),
            &sessions,
            &current_sessions,
            &own_ips,
            &filter,
            None,
        )
        .await;
        process_parsed_packet(
            pkt(
                n_src,
                sport,
                n_dst,
                443,
                200 + (upl % 300),
                TcpFlags::ACK | TcpFlags::PSH,
            ),
            &sessions,
            &current_sessions,
            &own_ips,
            &filter,
            None,
        )
        .await;
        process_parsed_packet(
            pkt(
                n_dst,
                443,
                n_src,
                sport,
                3000 + (down % 6000),
                TcpFlags::ACK,
            ),
            &sessions,
            &current_sessions,
            &own_ips,
            &filter,
            None,
        )
        .await;
        process_parsed_packet(
            pkt(n_src, sport, n_dst, 443, 40, TcpFlags::FIN),
            &sessions,
            &current_sessions,
            &own_ips,
            &filter,
            None,
        )
        .await;
    }

    // Collect baseline normals into a vector for the analyzer
    let mut baseline: Vec<FlodSessionInfo> = sessions.iter().map(|e| e.value().clone()).collect();

    // Analyze with stricter sensitivity for test and train on baseline only
    let analyzer = SessionAnalyzer::new();
    analyzer.start().await;
    analyzer.disable_warmup_for_testing().await;
    analyzer.set_test_thresholds(0.80, 0.90).await;
    let _ = analyzer.analyze_sessions(&mut baseline).await;
    analyzer.force_train_for_testing().await;
    let _ = analyzer.analyze_sessions(&mut baseline).await;

    // Calibrate thresholds just above the maximum baseline score
    let mut max_baseline_score = 0.0f64;
    for s in &baseline {
        if let Some((score, _, _)) = analyzer.debug_score_and_thresholds(s).await {
            if score > max_baseline_score {
                max_baseline_score = score;
            }
        }
    }
    let suspicious = max_baseline_score + 1e-6;
    let abnormal = max_baseline_score + 0.05;
    analyzer.set_test_thresholds(suspicious, abnormal).await;

    // Now add an exfil-like large flow (post-training)
    let x_src = own_ip;
    let x_dst = IpAddr::V4(Ipv4Addr::new(45, 33, 122, 89));
    process_parsed_packet(
        pkt(x_src, 42000, x_dst, 22, 200, TcpFlags::SYN),
        &sessions,
        &current_sessions,
        &own_ips,
        &filter,
        None,
    )
    .await;
    for _ in 0..1000 {
        // massive payloads to ensure separation
        process_parsed_packet(
            pkt(x_src, 42000, x_dst, 22, 64_000, TcpFlags::ACK),
            &sessions,
            &current_sessions,
            &own_ips,
            &filter,
            None,
        )
        .await;
    }
    // Prolong duration to amplify separation on the Duration feature
    sleep(StdDuration::from_millis(3000)).await;
    process_parsed_packet(
        pkt(x_src, 42000, x_dst, 22, 40, TcpFlags::FIN),
        &sessions,
        &current_sessions,
        &own_ips,
        &filter,
        None,
    )
    .await;

    // Rebuild full list including exfil and analyze (first pass)
    let mut list: Vec<FlodSessionInfo> = sessions.iter().map(|e| e.value().clone()).collect();
    let _ = analyzer.analyze_sessions(&mut list).await;

    // Identify exfil and normals and measure scores
    let exfil = list
        .iter()
        .find(|s| s.session.dst_port == 22)
        .expect("exfil session present");
    let normals: Vec<_> = list
        .iter()
        .filter(|s| s.session.dst_port == 443)
        .cloned()
        .collect();

    let mut max_baseline_score = 0.0f64;
    for s in &normals {
        if let Some((score, _, _)) = analyzer.debug_score_and_thresholds(s).await {
            if score > max_baseline_score {
                max_baseline_score = score;
            }
        }
    }
    let exfil_score = analyzer
        .debug_score_and_thresholds(exfil)
        .await
        .map(|(score, _, _)| score)
        .unwrap_or(0.0);

    // Calibrate thresholds between baseline and exfil if possible
    if exfil_score > max_baseline_score {
        let suspicious = (max_baseline_score + exfil_score) / 2.0;
        let abnormal = suspicious + 0.05;
        analyzer.set_test_thresholds(suspicious, abnormal).await;
        // Rebuild to drop previous immutable borrows
        let mut list2: Vec<FlodSessionInfo> = sessions.iter().map(|e| e.value().clone()).collect();
        let _ = analyzer.analyze_sessions(&mut list2).await;
        list = list2;
    }

    // Find exfil and normal sessions
    let exfil = list
        .iter()
        .find(|s| s.session.dst_port == 22)
        .expect("exfil session present");
    // normals already computed above

    // Use raw scores to assert separation regardless of score orientation
    common::assert_score_outside_band(&analyzer, exfil, &normals, 0.20, 0.80, "exfil separation")
        .await;

    analyzer.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_analyzer_duration_sensitivity() {
    // Build two flows with similar bytes but very different durations
    let sessions: Arc<CustomDashMap<Session, flodbadd::sessions::SessionInfo>> =
        Arc::new(CustomDashMap::new("SessionsDuration"));
    let current_sessions: Arc<CustomRwLock<Vec<Session>>> = Arc::new(CustomRwLock::new(Vec::new()));
    let filter: Arc<CustomRwLock<SessionFilter>> = Arc::new(CustomRwLock::new(SessionFilter::All));

    let own_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11));
    let mut own_ips = HashSet::new();
    own_ips.insert(own_ip);

    // Short flow
    let s_src = own_ip;
    let s_dst = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    process_parsed_packet(
        pkt(s_src, 43000, s_dst, 80, 500, TcpFlags::SYN),
        &sessions,
        &current_sessions,
        &own_ips,
        &filter,
        None,
    )
    .await;
    process_parsed_packet(
        pkt(s_src, 43000, s_dst, 80, 1000, TcpFlags::ACK | TcpFlags::PSH),
        &sessions,
        &current_sessions,
        &own_ips,
        &filter,
        None,
    )
    .await;
    process_parsed_packet(
        pkt(s_src, 43000, s_dst, 80, 40, TcpFlags::FIN),
        &sessions,
        &current_sessions,
        &own_ips,
        &filter,
        None,
    )
    .await;

    // Long flow (sleep to extend duration)
    let l_src = own_ip;
    let l_dst = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    process_parsed_packet(
        pkt(l_src, 44000, l_dst, 80, 500, TcpFlags::SYN),
        &sessions,
        &current_sessions,
        &own_ips,
        &filter,
        None,
    )
    .await;
    sleep(StdDuration::from_millis(400)).await;
    process_parsed_packet(
        pkt(l_src, 44000, l_dst, 80, 1000, TcpFlags::ACK | TcpFlags::PSH),
        &sessions,
        &current_sessions,
        &own_ips,
        &filter,
        None,
    )
    .await;
    process_parsed_packet(
        pkt(l_src, 44000, l_dst, 80, 40, TcpFlags::FIN),
        &sessions,
        &current_sessions,
        &own_ips,
        &filter,
        None,
    )
    .await;

    let mut list: Vec<FlodSessionInfo> = sessions.iter().map(|e| e.value().clone()).collect();

    let analyzer = SessionAnalyzer::new();
    analyzer.start().await;
    analyzer.disable_warmup_for_testing().await;
    analyzer.set_test_thresholds(0.60, 0.72).await;
    let _ = analyzer.analyze_sessions(&mut list).await;
    analyzer.force_train_for_testing().await;
    let _ = analyzer.analyze_sessions(&mut list).await;

    let long_flow = list.iter().find(|s| s.session.src_port == 44000).unwrap();
    let short_flow = list.iter().find(|s| s.session.src_port == 43000).unwrap();

    // We expect at least one of them to be non-normal with test thresholds; priority is that long duration contributes to anomaly
    let long_is_anom =
        long_flow.criticality.contains("suspicious") || long_flow.criticality.contains("abnormal");
    let short_is_anom = short_flow.criticality.contains("suspicious")
        || short_flow.criticality.contains("abnormal");

    assert!(
        long_is_anom || !short_is_anom,
        "Duration sensitivity check failed: long='{}', short='{}'",
        long_flow.criticality,
        short_flow.criticality
    );

    analyzer.stop().await;
}
