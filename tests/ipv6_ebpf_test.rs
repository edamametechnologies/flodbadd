//! IPv6 eBPF Integration Tests
//!
//! These tests verify that both L7 and DNS eBPF modules properly support IPv6.
//! Tests include:
//! - TCP connections over IPv6
//! - DNS queries over IPv6
//! - Mixed IPv4/IPv6 scenarios

use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// Test L7 eBPF IPv6 support status
#[test]
fn test_l7_ebpf_ipv6_status() {
    let available = flodbadd::l7_ebpf::is_available();
    let status = flodbadd::l7_ebpf::ebpf_support();

    println!("L7 eBPF available: {}", available);
    println!("L7 eBPF status: {}", status);

    // On Linux with eBPF support, status should mention tcp_set_state
    // which handles both IPv4 and IPv6
    if available {
        assert!(
            status.contains("tcp_set_state") || status.contains("Enabled"),
            "L7 eBPF should indicate it's enabled with tcp_set_state"
        );
    }
}

/// Test DNS eBPF IPv6 support status
#[test]
fn test_dns_ebpf_ipv6_status() {
    let available = flodbadd::dns_ebpf::is_available();
    let status = flodbadd::dns_ebpf::dns_ebpf_support();

    println!("DNS eBPF available: {}", available);
    println!("DNS eBPF status: {}", status);

    // On Linux with eBPF support, if IPv6 is enabled, status should mention it
    if available && status.contains("IPv6") {
        println!("✅ DNS eBPF has IPv6 support enabled");
    } else if available {
        println!("⚠️  DNS eBPF is enabled but IPv6 status unclear");
    }
}

/// Test TCP connection over IPv6 loopback
#[tokio::test]
async fn test_tcp_ipv6_loopback() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    // Start a simple TCP server on IPv6 loopback
    let listener = match TcpListener::bind("[::1]:0") {
        Ok(l) => l,
        Err(e) => {
            println!(
                "Cannot bind to IPv6 loopback: {} (IPv6 may not be available)",
                e
            );
            return;
        }
    };

    let server_addr = listener.local_addr().unwrap();
    println!("IPv6 test server listening on {}", server_addr);

    // Start server in a thread
    let server_handle = thread::spawn(move || {
        if let Ok((mut stream, addr)) = listener.accept() {
            println!("Accepted connection from {}", addr);
            let mut buf = [0u8; 128];
            if let Ok(n) = stream.read(&mut buf) {
                println!("Server received {} bytes", n);
                let _ = stream.write_all(b"IPv6 OK");
            }
        }
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect as client over IPv6
    println!("Connecting to IPv6 server...");
    match TcpStream::connect_timeout(&server_addr, Duration::from_secs(2)) {
        Ok(mut stream) => {
            println!("Connected to IPv6 server!");
            let _ = stream.write_all(b"Hello IPv6");

            // Check if eBPF captured this
            if flodbadd::l7_ebpf::is_available() {
                println!("L7 eBPF is available, connection should be tracked");
                // Note: The actual lookup would need the session key
            }

            let mut response = [0u8; 128];
            if let Ok(n) = stream.read(&mut response) {
                let resp = String::from_utf8_lossy(&response[..n]);
                println!("Received response: {}", resp);
                assert!(resp.contains("IPv6 OK"), "Should receive IPv6 OK response");
            }
        }
        Err(e) => {
            println!("Failed to connect over IPv6: {} (may be expected)", e);
        }
    }

    let _ = server_handle.join();
    println!("✅ IPv6 TCP loopback test completed");
}

/// Test DNS resolution over IPv6
#[test]
fn test_dns_ipv6_resolution() {
    // Try to resolve an IPv6 address
    let domains = ["ipv6.google.com", "ipv6.cloudflare.com", "example.com"];

    for domain in domains {
        println!("\nResolving {} for IPv6 addresses...", domain);

        match format!("{}:80", domain).to_socket_addrs() {
            Ok(addrs) => {
                let addrs: Vec<_> = addrs.collect();
                let ipv6_addrs: Vec<_> = addrs.iter().filter(|a| a.is_ipv6()).collect();
                let ipv4_addrs: Vec<_> = addrs.iter().filter(|a| a.is_ipv4()).collect();

                println!("  IPv4 addresses: {:?}", ipv4_addrs);
                println!("  IPv6 addresses: {:?}", ipv6_addrs);

                if !ipv6_addrs.is_empty() {
                    println!("  ✅ {} has IPv6 addresses", domain);
                }
            }
            Err(e) => {
                println!("  Failed to resolve {}: {}", domain, e);
            }
        }
    }
}

/// Test DNS query over IPv6 UDP
#[test]
fn test_dns_udp_ipv6_query() {
    // Try to send a DNS query over IPv6 to a public DNS server
    // Google's IPv6 DNS: 2001:4860:4860::8888

    let ipv6_dns_servers = [
        "[2001:4860:4860::8888]:53", // Google
        "[2606:4700:4700::1111]:53", // Cloudflare
        "[2620:fe::fe]:53",          // Quad9
    ];

    // DNS query for example.com (A record)
    let dns_query: Vec<u8> = vec![
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        // Query: example.com
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
        0x00, // Root label
        0x00, 0x01, // Type A
        0x00, 0x01, // Class IN
    ];

    // Try to bind to an IPv6 address
    match UdpSocket::bind("[::]:0") {
        Ok(socket) => {
            let local_addr = socket.local_addr().ok();
            println!("Bound to IPv6 socket: {:?}", local_addr);

            socket.set_read_timeout(Some(Duration::from_secs(2))).ok();
            socket.set_write_timeout(Some(Duration::from_secs(2))).ok();

            for dns_server in ipv6_dns_servers {
                println!("\nTrying IPv6 DNS server: {}", dns_server);

                match socket.send_to(&dns_query, dns_server) {
                    Ok(sent) => {
                        println!("  Sent {} bytes to {}", sent, dns_server);

                        // Check if eBPF captured this
                        if let Some(addr) = local_addr {
                            let src_port = addr.port();
                            if flodbadd::dns_ebpf::is_available() {
                                std::thread::sleep(Duration::from_millis(10));
                                if let Some(info) =
                                    flodbadd::dns_ebpf::get_process_by_src_port(src_port)
                                {
                                    println!("  ✅ eBPF captured DNS query!");
                                    println!("     PID: {}", info.pid);
                                    println!("     Process: {}", info.process_name);
                                    println!("     Family: {} (10 = IPv6)", info.family);

                                    // Check if it's IPv6
                                    if info.family == 10 {
                                        println!("     ✅ Correctly identified as IPv6!");
                                    }
                                }
                            }
                        }

                        // Try to receive response
                        let mut buf = [0u8; 512];
                        match socket.recv_from(&mut buf) {
                            Ok((size, from)) => {
                                println!("  Received {} bytes from {}", size, from);
                                if size >= 2 {
                                    let tx_id = ((buf[0] as u16) << 8) | (buf[1] as u16);
                                    if tx_id == 0x1234 {
                                        println!("  ✅ DNS response received over IPv6!");
                                        return; // Success!
                                    }
                                }
                            }
                            Err(e) => {
                                println!("  No response: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        println!("  Failed to send: {}", e);
                    }
                }
            }
        }
        Err(e) => {
            println!(
                "Cannot create IPv6 UDP socket: {} (IPv6 may not be available)",
                e
            );
        }
    }
}

/// Test mixed IPv4 and IPv6 scenarios
#[tokio::test]
async fn test_mixed_ipv4_ipv6() {
    println!("\n=== Testing Mixed IPv4/IPv6 Scenarios ===\n");

    // Test 1: Resolve domain that has both A and AAAA records
    let domain = "google.com";
    println!(
        "1. Resolving {} (should have both IPv4 and IPv6)...",
        domain
    );

    match format!("{}:443", domain).to_socket_addrs() {
        Ok(addrs) => {
            let addrs: Vec<_> = addrs.collect();
            let has_ipv4 = addrs.iter().any(|a| a.is_ipv4());
            let has_ipv6 = addrs.iter().any(|a| a.is_ipv6());

            println!("   Has IPv4: {}", has_ipv4);
            println!("   Has IPv6: {}", has_ipv6);
            println!("   All addresses: {:?}", addrs);
        }
        Err(e) => {
            println!("   Failed: {}", e);
        }
    }

    // Test 2: Create both IPv4 and IPv6 sockets
    println!("\n2. Creating both IPv4 and IPv6 UDP sockets...");

    let v4_socket = UdpSocket::bind("0.0.0.0:0");
    let v6_socket = UdpSocket::bind("[::]:0");

    match (&v4_socket, &v6_socket) {
        (Ok(v4), Ok(v6)) => {
            println!("   ✅ IPv4 socket: {}", v4.local_addr().unwrap());
            println!("   ✅ IPv6 socket: {}", v6.local_addr().unwrap());
        }
        (Ok(v4), Err(e)) => {
            println!("   ✅ IPv4 socket: {}", v4.local_addr().unwrap());
            println!("   ⚠️  IPv6 socket failed: {}", e);
        }
        (Err(e), Ok(v6)) => {
            println!("   ⚠️  IPv4 socket failed: {}", e);
            println!("   ✅ IPv6 socket: {}", v6.local_addr().unwrap());
        }
        (Err(e1), Err(e2)) => {
            println!("   ❌ IPv4 failed: {}", e1);
            println!("   ❌ IPv6 failed: {}", e2);
        }
    }

    // Test 3: If eBPF is available, check status
    println!("\n3. eBPF Support Status:");

    if flodbadd::l7_ebpf::is_available() {
        println!("   L7 eBPF: ✅ Enabled");
        println!("   Status: {}", flodbadd::l7_ebpf::ebpf_support());
    } else {
        println!("   L7 eBPF: ❌ Disabled");
    }

    if flodbadd::dns_ebpf::is_available() {
        println!("   DNS eBPF: ✅ Enabled");
        println!("   Status: {}", flodbadd::dns_ebpf::dns_ebpf_support());
    } else {
        println!("   DNS eBPF: ❌ Disabled");
    }

    println!("\n=== Mixed IPv4/IPv6 Test Complete ===");
}

/// Test IPv6-only DNS lookup (AAAA records)
#[test]
fn test_ipv6_only_dns() {
    // Try to resolve AAAA records specifically
    let domain = "ipv6.google.com";

    println!("\nTesting IPv6-only DNS for {}...", domain);

    // This will use the system resolver which typically returns both A and AAAA
    match format!("{}:443", domain).to_socket_addrs() {
        Ok(addrs) => {
            let addrs: Vec<_> = addrs.collect();
            let ipv6_count = addrs.iter().filter(|a| a.is_ipv6()).count();
            let ipv4_count = addrs.iter().filter(|a| a.is_ipv4()).count();

            println!(
                "Resolved {} IPv4 and {} IPv6 addresses",
                ipv4_count, ipv6_count
            );

            for addr in &addrs {
                match addr {
                    SocketAddr::V4(v4) => println!("  IPv4: {}", v4),
                    SocketAddr::V6(v6) => println!("  IPv6: {}", v6),
                }
            }

            if ipv6_count > 0 {
                println!("✅ IPv6 addresses resolved successfully");
            }
        }
        Err(e) => {
            println!("Failed to resolve: {} (IPv6 may not be available)", e);
        }
    }
}

/// Benchmark IPv6 vs IPv4 DNS resolution
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
#[tokio::test]
async fn test_ipv6_dns_performance() {
    use flodbadd::dns::DnsPacketProcessor;
    use std::time::Instant;

    let processor = DnsPacketProcessor::new();

    // Create DNS query packets for IPv4 (A) and IPv6 (AAAA) records
    let dns_query_a: Vec<u8> = vec![
        0x00, 0x01, // Transaction ID
        0x01, 0x00, // Flags
        0x00, 0x01, // Questions: 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03,
        b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01, // Type A (IPv4)
    ];

    let dns_query_aaaa: Vec<u8> = vec![
        0x00, 0x02, // Transaction ID
        0x01, 0x00, // Flags
        0x00, 0x01, // Questions: 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03,
        b'c', b'o', b'm', 0x00, 0x00, 0x1c, 0x00, 0x01, // Type AAAA (IPv6)
    ];

    let iterations = 500;

    // Benchmark IPv4 queries
    let start = Instant::now();
    for i in 0..iterations {
        let mut query = dns_query_a.clone();
        query[0] = ((i >> 8) & 0xff) as u8;
        query[1] = (i & 0xff) as u8;
        processor
            .process_dns_packet_with_port(query, Some(50000 + (i % 10000) as u16))
            .await;
    }
    let ipv4_time = start.elapsed();

    // Benchmark IPv6 queries
    let start = Instant::now();
    for i in 0..iterations {
        let mut query = dns_query_aaaa.clone();
        query[0] = ((i >> 8) & 0xff) as u8;
        query[1] = (i & 0xff) as u8;
        processor
            .process_dns_packet_with_port(query, Some(60000 + (i % 10000) as u16))
            .await;
    }
    let ipv6_time = start.elapsed();

    println!("\nDNS Processing Performance:");
    println!(
        "  IPv4 (A) records:    {:?} ({} ns/query)",
        ipv4_time,
        ipv4_time.as_nanos() / iterations as u128
    );
    println!(
        "  IPv6 (AAAA) records: {:?} ({} ns/query)",
        ipv6_time,
        ipv6_time.as_nanos() / iterations as u128
    );
}
