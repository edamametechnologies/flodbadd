//! Example to check DNS eBPF status and test DNS process attribution
//!
//! Run with: cargo run --release --features packetcapture,asyncpacketcapture,ebpf --example check_dns_ebpf

use std::net::{ToSocketAddrs, UdpSocket};
use std::time::Duration;

fn main() {
    println!("=== DNS eBPF Status Check ===\n");

    // Check DNS eBPF availability
    let available = flodbadd::dns_ebpf::is_available();
    let status = flodbadd::dns_ebpf::dns_ebpf_support();

    println!("DNS eBPF available: {}", available);
    println!("DNS eBPF status: {}", status);
    println!();

    // Also show L7 eBPF status for comparison
    let l7_available = flodbadd::l7_ebpf::is_available();
    let l7_status = flodbadd::l7_ebpf::ebpf_support();

    println!("L7 eBPF available: {}", l7_available);
    println!("L7 eBPF status: {}", l7_status);
    println!();

    // Test DNS lookup with eBPF tracking
    println!("=== Testing DNS Process Attribution ===\n");

    if available {
        // Send a DNS query and check if eBPF tracks it
        println!("Sending DNS query to test eBPF tracking...");
        
        // Create a UDP socket for DNS query
        match UdpSocket::bind("0.0.0.0:0") {
            Ok(socket) => {
                let local_addr = socket.local_addr().ok();
                if let Some(addr) = local_addr {
                    let src_port = addr.port();
                    println!("Source port: {}", src_port);
                    
                    // DNS query for example.com
                    let dns_query: Vec<u8> = vec![
                        0xAB, 0xCD, // Transaction ID
                        0x01, 0x00, // Flags
                        0x00, 0x01, // Questions: 1
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
                        0x03, b'c', b'o', b'm',
                        0x00, 0x00, 0x01, 0x00, 0x01,
                    ];
                    
                    socket.set_write_timeout(Some(Duration::from_secs(2))).ok();
                    socket.set_read_timeout(Some(Duration::from_secs(2))).ok();
                    
                    // Send to 8.8.8.8 (Google DNS)
                    match socket.send_to(&dns_query, "8.8.8.8:53") {
                        Ok(_) => {
                            println!("Sent DNS query to 8.8.8.8:53");
                            
                            // Give eBPF time to process
                            std::thread::sleep(Duration::from_millis(50));
                            
                        // Check if eBPF captured it
                        // Check map size for debugging
                        let map_size = flodbadd::dns_ebpf::map_size();
                        println!("DNS eBPF map size: {} entries", map_size);
                        
                        if let Some(info) = flodbadd::dns_ebpf::get_process_by_src_port(src_port) {
                            println!("\n✅ eBPF captured the DNS query!");
                            println!("   PID: {}", info.pid);
                            println!("   Process: {}", info.process_name);
                            println!("   Source Port: {}", info.src_port);
                            println!("   Family: {} (2=IPv4, 10=IPv6)", info.family);
                        } else {
                            println!("\n⚠️  eBPF did not capture the query for port {}", src_port);
                            println!("   Map has {} entries", map_size);
                        }
                            
                            // Try to get response
                            let mut buf = [0u8; 512];
                            match socket.recv_from(&mut buf) {
                                Ok((size, _)) => {
                                    println!("\nReceived {} byte DNS response", size);
                                }
                                Err(e) => {
                                    println!("\nNo DNS response: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            println!("Failed to send DNS query: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                println!("Failed to create socket: {}", e);
            }
        }
    } else {
        println!("Skipping DNS eBPF test (not available)");
    }

    // Standard DNS resolution test
    println!("\n=== Standard DNS Resolution Test ===\n");

    let domains = ["example.com", "google.com", "cloudflare.com"];

    for domain in domains {
        println!("Resolving: {}", domain);
        match format!("{}:80", domain).to_socket_addrs() {
            Ok(addrs) => {
                let addrs: Vec<_> = addrs.collect();
                println!("  Resolved to: {:?}", addrs);
            }
            Err(e) => {
                println!("  Failed to resolve: {}", e);
            }
        }
    }

    // Summary
    println!("\n=== Summary ===\n");
    if available {
        println!("✅ DNS eBPF is ENABLED");
        println!("   DNS queries will be attributed to processes via source port tracking");
    } else {
        println!("⚠️  DNS eBPF is DISABLED");
        println!("   Falling back to packet-only DNS resolution");
        println!("   Reason: {}", status);
    }

    std::process::exit(if available { 0 } else { 1 });
}
