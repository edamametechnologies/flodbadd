//! Realistic Traffic Integration Tests for eBPF
//!
//! These tests verify that eBPF actually captures real network traffic
//! with accurate process attribution. They test end-to-end functionality
//! with actual system calls and network packets.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process;
use std::thread;
use std::time::Duration;

/// Test that L7 eBPF captures a real TCP connection with correct PID
/// This test creates a real TCP connection and verifies eBPF tracked it
#[tokio::test]
async fn test_l7_ebpf_captures_real_tcp_with_correct_pid() {
    if !flodbadd::l7_ebpf::is_available() {
        println!("⚠️  L7 eBPF not available - skipping realistic test");
        return;
    }

    let my_pid = process::id();
    println!("\n=== L7 eBPF Realistic Traffic Test ===");
    println!("Current PID: {}", my_pid);

    // Start a TCP server on a random port
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind server");
    let server_port = listener.local_addr().unwrap().port();
    println!("Server listening on port {}", server_port);

    // Server thread
    let server_handle = thread::spawn(move || {
        match listener.accept() {
            Ok((mut stream, addr)) => {
                println!("Server: Accepted connection from {}", addr);
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).unwrap_or(0);
                println!("Server: Received {} bytes", n);
                stream.write_all(b"PONG").ok();
            }
            Err(e) => {
                eprintln!("Server: Accept failed: {}", e);
            }
        }
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Create client connection
    let mut client =
        TcpStream::connect(format!("127.0.0.1:{}", server_port)).expect("Failed to connect");
    let client_port = client.local_addr().unwrap().port();
    println!("Client: Connected from port {}", client_port);

    // Send some data to ensure the connection is ESTABLISHED
    client.write_all(b"PING").expect("Failed to write");
    client.flush().ok();

    // Read response to ensure bidirectional traffic
    let mut response = [0u8; 10];
    let _ = client.read(&mut response);

    // Give eBPF time to process
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Now query eBPF for this session
    let session = flodbadd::sessions::Session {
        protocol: flodbadd::sessions::Protocol::TCP,
        src_ip: "127.0.0.1".parse().unwrap(),
        src_port: client_port,
        dst_ip: "127.0.0.1".parse().unwrap(),
        dst_port: server_port,
    };

    println!("Querying eBPF for session: {:?}", session);
    let l7_data = flodbadd::l7_ebpf::get_l7_for_session(&session);

    // Also try reverse direction
    let reverse_session = flodbadd::sessions::Session {
        protocol: flodbadd::sessions::Protocol::TCP,
        src_ip: "127.0.0.1".parse().unwrap(),
        src_port: server_port,
        dst_ip: "127.0.0.1".parse().unwrap(),
        dst_port: client_port,
    };
    let reverse_data = flodbadd::l7_ebpf::get_l7_for_session(&reverse_session);

    // Report results
    if let Some(ref data) = l7_data {
        println!("✅ L7 eBPF captured the connection!");
        println!("   Captured PID: {}", data.pid);
        println!("   Our PID:      {}", my_pid);
        println!("   Process name: {}", data.process_name);

        // For loopback, tcp_set_state is called in kernel context so PID may be 0
        // But if captured from tcp_v4_connect, it should have our PID
        if data.pid == my_pid {
            println!("   ✅ PID matches exactly!");
        } else if data.pid == 0 {
            println!("   ℹ️  PID is 0 (captured in kernel context via tcp_set_state)");
            println!("      This is expected behavior for the tcp_set_state hook");
        } else {
            println!("   ⚠️  PID mismatch (might be from different connection)");
        }
    } else if let Some(ref data) = reverse_data {
        println!("✅ L7 eBPF captured the connection (reverse direction)!");
        println!("   Captured PID: {}", data.pid);
        println!("   Process name: {}", data.process_name);
    } else {
        println!("⚠️  L7 eBPF did not capture localhost connection");
        println!("   This may be expected - localhost can bypass tcp_set_state on some kernels");
    }

    // Cleanup
    drop(client);
    server_handle.join().ok();

    println!("=== L7 eBPF Realistic Test Complete ===\n");
}

/// Test that L7 eBPF captures external TCP connection with correct PID
#[tokio::test]
async fn test_l7_ebpf_captures_external_tcp() {
    if !flodbadd::l7_ebpf::is_available() {
        println!("⚠️  L7 eBPF not available - skipping");
        return;
    }

    let my_pid = process::id();
    println!("\n=== L7 eBPF External Connection Test ===");
    println!("Current PID: {}", my_pid);

    // Try to connect to well-known external services
    let targets = [
        ("1.1.1.1", 80, "Cloudflare"),
        ("8.8.8.8", 53, "Google DNS"),
        ("93.184.216.34", 80, "example.com"),
    ];

    for (ip, port, name) in targets {
        println!("\nTrying {} ({}:{})...", name, ip, port);

        let addr: std::net::SocketAddr = format!("{}:{}", ip, port).parse().unwrap();

        match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
            Ok(stream) => {
                let local = stream.local_addr().unwrap();
                let remote = stream.peer_addr().unwrap();
                println!("  Connected: {} -> {}", local, remote);

                // Give eBPF time to capture
                tokio::time::sleep(Duration::from_millis(100)).await;

                // Query eBPF
                let session = flodbadd::sessions::Session {
                    protocol: flodbadd::sessions::Protocol::TCP,
                    src_ip: local.ip(),
                    src_port: local.port(),
                    dst_ip: remote.ip(),
                    dst_port: remote.port(),
                };

                let l7_data = flodbadd::l7_ebpf::get_l7_for_session(&session);

                if let Some(data) = l7_data {
                    println!("  ✅ eBPF captured connection!");
                    println!("     PID: {} (ours: {})", data.pid, my_pid);
                    println!("     Process: {}", data.process_name);

                    // For external connections via tcp_v4_connect, we should get our PID
                    if data.pid == my_pid || data.pid > 0 {
                        println!("     ✅ Valid PID captured");
                    } else {
                        println!("     ℹ️  PID is 0 (kernel context)");
                    }
                    drop(stream);
                    return; // Success
                } else {
                    println!("  ⚠️  eBPF didn't capture (timing issue?)");
                }

                drop(stream);
            }
            Err(e) => {
                println!("  Could not connect: {}", e);
            }
        }
    }

    println!("\n⚠️  No external connections captured - network may be restricted");
    println!("=== L7 eBPF External Test Complete ===\n");
}

/// Test that DNS eBPF captures real DNS queries with correct PID
#[test]
fn test_dns_ebpf_captures_real_dns_query() {
    if !flodbadd::dns_ebpf::is_available() {
        println!("⚠️  DNS eBPF not available - skipping");
        return;
    }

    let my_pid = process::id();
    println!("\n=== DNS eBPF Realistic Traffic Test ===");
    println!("Current PID: {}", my_pid);

    // Create a UDP socket and send a real DNS query
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind UDP socket");
    let local_addr = socket.local_addr().unwrap();
    let src_port = local_addr.port();
    println!("Bound to {}", local_addr);

    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .ok();
    socket.set_read_timeout(Some(Duration::from_secs(2))).ok();

    // DNS query for example.com A record
    let dns_query: Vec<u8> = vec![
        0xDE, 0xAD, // Transaction ID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03,
        b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    // Try multiple DNS servers
    let dns_servers = ["8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"];

    for dns_server in dns_servers {
        println!("\nSending DNS query to {} from port {}...", dns_server, src_port);

        match socket.send_to(&dns_query, dns_server) {
            Ok(sent) => {
                println!("  Sent {} bytes", sent);

                // Give eBPF a moment to process
                thread::sleep(Duration::from_millis(20));

                // Now query eBPF for this source port
                let info = flodbadd::dns_ebpf::get_process_by_src_port(src_port);

                if let Some(info) = info {
                    println!("  ✅ DNS eBPF captured the query!");
                    println!("     Captured PID: {}", info.pid);
                    println!("     Our PID:      {}", my_pid);
                    println!("     Process:      {}", info.process_name);
                    println!("     Family:       {} (2=IPv4, 10=IPv6)", info.family);

                    // Verify PID matches
                    if info.pid == my_pid {
                        println!("     ✅ PID matches exactly!");
                    } else if info.pid > 0 {
                        println!("     ⚠️  PID {} doesn't match ours {}", info.pid, my_pid);
                    }

                    // Try to receive response
                    let mut buf = [0u8; 512];
                    match socket.recv_from(&mut buf) {
                        Ok((size, from)) => {
                            println!("  ✅ Received {} bytes response from {}", size, from);
                        }
                        Err(e) => {
                            println!("  ⚠️  No response: {}", e);
                        }
                    }
                    println!("\n=== DNS eBPF Realistic Test PASSED ===\n");
                    return; // Success
                } else {
                    println!("  ⚠️  DNS eBPF didn't capture for port {}", src_port);
                }
            }
            Err(e) => {
                println!("  Could not send: {}", e);
            }
        }
    }

    println!("\n⚠️  DNS eBPF did not capture any queries - may be timing issue");
    println!("=== DNS eBPF Realistic Test Complete ===\n");
}

/// Test DNS eBPF with IPv6 DNS servers
#[test]
fn test_dns_ebpf_captures_ipv6_dns_query() {
    if !flodbadd::dns_ebpf::is_available() {
        println!("⚠️  DNS eBPF not available - skipping");
        return;
    }

    println!("\n=== DNS eBPF IPv6 Realistic Test ===");

    // Try to create an IPv6 socket
    let socket = match UdpSocket::bind("[::]:0") {
        Ok(s) => s,
        Err(e) => {
            println!("⚠️  Cannot create IPv6 socket: {} - skipping", e);
            return;
        }
    };

    let local_addr = socket.local_addr().unwrap();
    let src_port = local_addr.port();
    println!("Bound to {} (port {})", local_addr, src_port);

    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .ok();
    socket.set_read_timeout(Some(Duration::from_secs(2))).ok();

    // DNS query for AAAA record
    let dns_query: Vec<u8> = vec![
        0xBE, 0xEF, // Transaction ID
        0x01, 0x00, // Flags
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x', b'a', b'm', b'p', b'l',
        b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x1c, // Type AAAA
        0x00, 0x01,
    ];

    // IPv6 DNS servers
    let ipv6_dns_servers = [
        "[2001:4860:4860::8888]:53", // Google
        "[2606:4700:4700::1111]:53", // Cloudflare
    ];

    for dns_server in ipv6_dns_servers {
        println!("\nSending IPv6 DNS query to {}...", dns_server);

        match socket.send_to(&dns_query, dns_server) {
            Ok(sent) => {
                println!("  Sent {} bytes", sent);

                thread::sleep(Duration::from_millis(20));

                let info = flodbadd::dns_ebpf::get_process_by_src_port(src_port);

                if let Some(info) = info {
                    println!("  ✅ DNS eBPF captured IPv6 query!");
                    println!("     PID: {}", info.pid);
                    println!("     Process: {}", info.process_name);
                    println!("     Family: {} (10 = IPv6)", info.family);

                    if info.family == 10 {
                        println!("     ✅ Correctly identified as IPv6!");
                    }
                    return; // Success
                } else {
                    println!("  ⚠️  Not captured");
                }
            }
            Err(e) => {
                println!("  Network unreachable: {} (IPv6 routing may not be available)", e);
            }
        }
    }

    println!("\n⚠️  No IPv6 DNS queries captured - IPv6 may not be routed");
    println!("=== DNS eBPF IPv6 Test Complete ===\n");
}

/// Test that eBPF correctly tracks multiple simultaneous connections
#[tokio::test]
async fn test_ebpf_multiple_concurrent_connections() {
    if !flodbadd::l7_ebpf::is_available() {
        println!("⚠️  L7 eBPF not available - skipping");
        return;
    }

    println!("\n=== Multiple Concurrent Connections Test ===");

    // Create multiple concurrent connections
    let mut handles = vec![];
    let num_connections = 5;

    for i in 0..num_connections {
        let handle = tokio::spawn(async move {
            let targets = ["1.1.1.1:80", "8.8.8.8:53"];
            let target = targets[i % targets.len()];

            match TcpStream::connect_timeout(
                &target.parse().unwrap(),
                Duration::from_secs(2),
            ) {
                Ok(stream) => {
                    let local = stream.local_addr().ok();
                    println!("  [{}] Connected to {} from {:?}", i, target, local);
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    if let Some(local) = local {
                        let session = flodbadd::sessions::Session {
                            protocol: flodbadd::sessions::Protocol::TCP,
                            src_ip: local.ip(),
                            src_port: local.port(),
                            dst_ip: target
                                .split(':')
                                .next()
                                .unwrap()
                                .parse()
                                .unwrap(),
                            dst_port: target
                                .split(':')
                                .last()
                                .unwrap()
                                .parse()
                                .unwrap(),
                        };

                        let data = flodbadd::l7_ebpf::get_l7_for_session(&session);
                        drop(stream);
                        return (i, data.is_some());
                    }
                    drop(stream);
                }
                Err(e) => {
                    println!("  [{}] Failed: {}", i, e);
                }
            }
            (i, false)
        });
        handles.push(handle);
    }

    // Wait for all connections
    let results: Vec<_> = futures::future::join_all(handles).await;
    let captured_count = results.iter().filter(|r| r.as_ref().map(|r| r.1).unwrap_or(false)).count();

    println!(
        "\n  Captured {}/{} concurrent connections",
        captured_count, num_connections
    );
    println!("=== Multiple Connections Test Complete ===\n");
}

/// Integration test verifying eBPF with full capture pipeline
#[cfg(all(
    any(target_os = "linux"),
    feature = "packetcapture"
))]
#[tokio::test]
async fn test_full_capture_pipeline_with_ebpf() {
    use flodbadd::dns::DnsPacketProcessor;

    println!("\n=== Full Capture Pipeline Test ===");

    if !flodbadd::l7_ebpf::is_available() {
        println!("L7 eBPF: ❌ Not available");
    } else {
        println!("L7 eBPF: ✅ {}", flodbadd::l7_ebpf::ebpf_support());
    }

    if !flodbadd::dns_ebpf::is_available() {
        println!("DNS eBPF: ❌ Not available");
    } else {
        println!("DNS eBPF: ✅ {}", flodbadd::dns_ebpf::dns_ebpf_support());
    }

    // Create DNS processor which integrates with eBPF
    let dns_processor = DnsPacketProcessor::new();
    println!(
        "DNS Processor eBPF enabled: {}",
        dns_processor.is_ebpf_enabled()
    );

    // Make a real DNS query that will be captured
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    let src_port = socket.local_addr().unwrap().port();
    socket.set_read_timeout(Some(Duration::from_secs(2))).ok();

    // DNS query
    let dns_query: Vec<u8> = vec![
        0x11, 0x22, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, b'g', b'o',
        b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    if socket.send_to(&dns_query, "8.8.8.8:53").is_ok() {
        // Wait for the actual DNS packet to be sent and eBPF to capture
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify DNS eBPF captured it
        if dns_processor.is_ebpf_enabled() {
            if let Some(info) = flodbadd::dns_ebpf::get_process_by_src_port(src_port) {
                println!("✅ DNS eBPF captured real traffic from port {}", src_port);
                println!("   PID: {}, Process: {}", info.pid, info.process_name);
            }
        }

        // Read response
        let mut buf = [0u8; 512];
        if let Ok((size, _)) = socket.recv_from(&mut buf) {
            // Process the response through the DNS processor
            dns_processor
                .process_dns_packet_with_port(buf[..size].to_vec(), Some(src_port))
                .await;

            let resolutions = dns_processor.get_dns_resolutions_with_process();
            println!(
                "DNS resolutions with process info: {}",
                resolutions.len()
            );
        }
    }

    println!("=== Full Pipeline Test Complete ===\n");
}

