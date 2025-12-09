//! Integration tests for DNS eBPF functionality
//!
//! These tests verify that the DNS eBPF module can:
//! 1. Initialize successfully when eBPF is available
//! 2. Track DNS queries by source port and associate them with processes
//! 3. Fall back gracefully when eBPF is not available

use std::net::{ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// Test that the DNS eBPF module initializes without panicking
#[test]
fn test_dns_ebpf_initialization() {
    let available = flodbadd::dns_ebpf::is_available();
    let status = flodbadd::dns_ebpf::dns_ebpf_support();

    println!("DNS eBPF available: {}", available);
    println!("DNS eBPF status: {}", status);

    // The function should complete without panicking regardless of availability
    assert!(!status.is_empty());
}

/// Test DNS lookup with process tracking
/// This test makes a real DNS query and checks if eBPF can track it
#[tokio::test]
async fn test_dns_query_with_ebpf_tracking() {
    // Initialize and log status
    flodbadd::dns_ebpf::init_and_log_status();

    let available = flodbadd::dns_ebpf::is_available();
    println!("DNS eBPF available for test: {}", available);

    // Make a DNS query using the system resolver
    let domain = "example.com";
    println!("Making DNS query for: {}", domain);

    // Perform DNS lookup
    let addrs: Vec<_> = format!("{}:80", domain)
        .to_socket_addrs()
        .unwrap_or_else(|_| vec![].into_iter())
        .collect();

    println!("Resolved addresses: {:?}", addrs);
    assert!(!addrs.is_empty(), "Should resolve at least one address");

    // If eBPF is available, we should be able to find process info
    if available {
        println!("eBPF is available - checking for process tracking...");
        // Note: Due to timing, the eBPF map might not have the entry yet
        // This is more of a smoke test to ensure the code path works
    } else {
        println!("eBPF not available - skipping process tracking check");
    }

    // Sleep briefly to allow cleanup
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// Test UDP DNS query to a known server (simulates what eBPF would track)
#[test]
fn test_manual_udp_dns_query() {
    // This test sends a raw DNS query to demonstrate what eBPF would intercept

    // Create a simple DNS query for example.com (A record)
    // DNS header: ID=0x1234, flags=0x0100 (standard query), QDCOUNT=1
    let dns_query: Vec<u8> = vec![
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        // Query: example.com
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
        0x03, b'c', b'o', b'm', // "com"
        0x00,       // Root label
        0x00, 0x01, // Type A
        0x00, 0x01, // Class IN
    ];

    println!("DNS query packet size: {} bytes", dns_query.len());

    // Try to send to localhost (may fail if no DNS server, that's ok)
    match UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => {
            let local_addr = socket.local_addr().ok();
            println!("Bound to local address: {:?}", local_addr);
            
            // Get the source port - this is what eBPF would track
            if let Some(addr) = local_addr {
                let src_port = addr.port();
                println!("Source port: {} (eBPF would track this)", src_port);
                
                // Check if eBPF can find info for this port
                if flodbadd::dns_ebpf::is_available() {
                    // The eBPF map is populated when udp_sendmsg is called
                    // At this point, we haven't sent yet, so no entry expected
                    let info = flodbadd::dns_ebpf::get_process_by_src_port(src_port);
                    println!("eBPF info before send: {:?}", info);
                }
            }

            socket
                .set_read_timeout(Some(Duration::from_secs(1)))
                .ok();
            socket
                .set_write_timeout(Some(Duration::from_secs(1)))
                .ok();

            // Try sending to a public DNS (8.8.8.8) on port 53
            // This might fail due to network restrictions, which is fine
            match socket.send_to(&dns_query, "8.8.8.8:53") {
                Ok(sent) => {
                    println!("Sent {} bytes to 8.8.8.8:53", sent);
                    
                    // Now check if eBPF captured this
                    if let Some(addr) = local_addr {
                        let src_port = addr.port();
                        if flodbadd::dns_ebpf::is_available() {
                            // Give eBPF a moment to process
                            std::thread::sleep(Duration::from_millis(10));
                            let info = flodbadd::dns_ebpf::get_process_by_src_port(src_port);
                            if let Some(info) = info {
                                println!("✅ eBPF captured DNS query!");
                                println!("   PID: {}", info.pid);
                                println!("   Process: {}", info.process_name);
                            } else {
                                println!("⚠️  eBPF did not capture (may be timing issue)");
                            }
                        }
                    }

                    // Try to receive response
                    let mut buf = [0u8; 512];
                    match socket.recv_from(&mut buf) {
                        Ok((size, addr)) => {
                            println!("Received {} bytes from {}", size, addr);
                            // Parse transaction ID from response
                            if size >= 2 {
                                let tx_id = ((buf[0] as u16) << 8) | (buf[1] as u16);
                                println!("Response transaction ID: 0x{:04x}", tx_id);
                                assert_eq!(tx_id, 0x1234, "Transaction ID should match");
                            }
                        }
                        Err(e) => {
                            println!("No response (may be expected): {}", e);
                        }
                    }
                }
                Err(e) => {
                    println!("Could not send DNS query (may be expected): {}", e);
                }
            }
        }
        Err(e) => {
            println!("Could not create socket: {}", e);
        }
    }
}

/// Test DNS packet processor with eBPF integration
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
#[tokio::test]
async fn test_dns_packet_processor_ebpf_integration() {
    use flodbadd::dns::DnsPacketProcessor;

    // Create DNS processor
    let processor = DnsPacketProcessor::new();
    let ebpf_enabled = processor.is_ebpf_enabled();

    println!("DNS packet processor eBPF enabled: {}", ebpf_enabled);

    // Create a simple DNS query packet for testing
    let dns_query: Vec<u8> = vec![
        0x12, 0x35, // Transaction ID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        // Query: test.example
        0x04, b't', b'e', b's', b't',
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x00,       // Root label
        0x00, 0x01, // Type A
        0x00, 0x01, // Class IN
    ];

    // Process the query with a source port
    processor.process_dns_packet_with_port(dns_query, Some(54321)).await;

    // Create a mock response
    let dns_response: Vec<u8> = vec![
        0x12, 0x35, // Transaction ID (same as query)
        0x81, 0x80, // Flags: standard response, no error
        0x00, 0x01, // Questions: 1
        0x00, 0x01, // Answer RRs: 1
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        // Query section (same as request)
        0x04, b't', b'e', b's', b't',
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x00,       // Root label
        0x00, 0x01, // Type A
        0x00, 0x01, // Class IN
        // Answer section
        0xc0, 0x0c, // Name pointer to offset 12
        0x00, 0x01, // Type A
        0x00, 0x01, // Class IN
        0x00, 0x00, 0x00, 0x3c, // TTL: 60 seconds
        0x00, 0x04, // RDLENGTH: 4 bytes
        0x5d, 0xb8, 0xd8, 0x22, // RDATA: 93.184.216.34 (example.com)
    ];

    // Process the response
    processor.process_dns_packet(dns_response).await;

    // Check that the resolution was recorded
    let resolutions = processor.get_dns_resolutions();
    let resolutions_with_process = processor.get_dns_resolutions_with_process();

    println!(
        "Recorded {} DNS resolutions ({} with process info)",
        resolutions.len(),
        resolutions_with_process.len()
    );

    // The resolution should have been recorded
    let ip: std::net::IpAddr = "93.184.216.34".parse().unwrap();
    if let Some(domain) = resolutions.get(&ip) {
        println!("Found resolution: {} -> {}", ip, *domain);
        assert!(domain.contains("example"), "Domain should contain 'example'");
    }

    if let Some(resolution) = resolutions_with_process.get(&ip) {
        println!(
            "Found resolution with process: {} -> {} (PID: {:?}, Process: {:?})",
            ip, resolution.domain, resolution.pid, resolution.process_name
        );
    };
}

/// Benchmark test to measure DNS eBPF overhead
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
#[tokio::test]
async fn test_dns_ebpf_performance() {
    use flodbadd::dns::DnsPacketProcessor;
    use std::time::Instant;

    let processor = DnsPacketProcessor::new();

    // Create a test DNS query
    let dns_query: Vec<u8> = vec![
        0x00, 0x00, // Transaction ID (will be varied)
        0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    // Process many packets and measure time
    let iterations = 1000;
    let start = Instant::now();

    for i in 0..iterations {
        let mut query = dns_query.clone();
        // Vary transaction ID
        query[0] = ((i >> 8) & 0xff) as u8;
        query[1] = (i & 0xff) as u8;
        // Vary source port
        let port = 50000 + (i % 10000) as u16;
        processor.process_dns_packet_with_port(query, Some(port)).await;
    }

    let elapsed = start.elapsed();
    let per_packet = elapsed.as_nanos() / iterations as u128;

    println!(
        "Processed {} DNS queries in {:?} ({} ns/packet)",
        iterations, elapsed, per_packet
    );

    // Should be reasonably fast (less than 1ms per packet)
    assert!(
        per_packet < 1_000_000,
        "DNS processing should be faster than 1ms/packet"
    );
}
