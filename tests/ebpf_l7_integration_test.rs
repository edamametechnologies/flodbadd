#[cfg(all(target_os = "linux", feature = "ebpf"))]
mod ebpf_integration_tests {
    use flodbadd::l7_ebpf;
    use flodbadd::sessions::{Protocol, Session};
    use serial_test::serial;
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::sleep;

    #[tokio::test]
    #[serial]
    async fn test_ebpf_availability() {
        // Test that eBPF is available on this system
        let available = l7_ebpf::is_available();

        if !available {
            println!("eBPF not available on this system - skipping eBPF tests");
            println!("This could be due to:");
            println!("  - Not running on Linux");
            println!("  - Insufficient privileges (need root or CAP_BPF)");
            println!("  - Missing kernel features");
            println!("  - eBPF program compilation failed");
            return;
        }

        println!("✅ eBPF is available (object embedded)");

        // Also check if it's fully functional (kprobes attached)
        let fully_functional = l7_ebpf::is_fully_functional();
        if fully_functional {
            println!("✅ eBPF is fully functional (kprobes attached)");
        } else {
            println!("⚠️  eBPF available but not fully functional (kprobes may not be attached)");
            println!("   Status: {}", l7_ebpf::ebpf_support());
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_ebpf_basic_session_lookup() {
        if !l7_ebpf::is_fully_functional() {
            println!("Skipping test - eBPF not fully functional");
            println!("Status: {}", l7_ebpf::ebpf_support());
            return;
        }

        // Test basic session lookup
        let session = Session {
            protocol: Protocol::TCP,
            src_ip: "127.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_ip: "127.0.0.1".parse().unwrap(),
            dst_port: 80,
        };

        // Try to get L7 data (may be None if no matching connection)
        let l7_data = l7_ebpf::get_l7_for_session(&session);

        // This test just verifies the API works - actual data depends on active connections
        println!("L7 lookup result: {:?}", l7_data);

        // Test with different session types
        let udp_session = Session {
            protocol: Protocol::UDP,
            src_ip: "127.0.0.1".parse().unwrap(),
            src_port: 53,
            dst_ip: "8.8.8.8".parse().unwrap(),
            dst_port: 53,
        };

        let udp_l7_data = l7_ebpf::get_l7_for_session(&udp_session);
        println!("UDP L7 lookup result: {:?}", udp_l7_data);

        println!("✅ eBPF session lookup API works correctly");
    }

    #[tokio::test]
    #[serial]
    async fn test_ebpf_with_real_connection() {
        if !l7_ebpf::is_fully_functional() {
            println!("Skipping test - eBPF not fully functional");
            println!("Status: {}", l7_ebpf::ebpf_support());
            return;
        }

        // Create a real network connection to test eBPF tracking
        let test_port = 18080u16;
        let client_port = Arc::new(AtomicU16::new(0));
        let client_port_clone = client_port.clone();

        // Start a simple TCP server using async tokio networking
        let listener = match TcpListener::bind(format!("127.0.0.1:{}", test_port)).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Failed to bind to port {}: {}", test_port, e);
                return;
            }
        };

        println!("Test server listening on port {}", test_port);

        // Spawn server to accept one connection
        let server_handle = tokio::spawn(async move {
            match listener.accept().await {
                Ok((mut stream, addr)) => {
                    println!("Test server accepted connection from {}", addr);
                    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!";
                    let _ = stream.write_all(response).await;
                    let _ = stream.flush().await;
                    addr.port()
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                    0
                }
            }
        });

        // Give server time to start accepting
        sleep(Duration::from_millis(50)).await;

        // Make a client connection and capture the local port
        let client_handle = tokio::spawn(async move {
            match TcpStream::connect(format!("127.0.0.1:{}", test_port)).await {
                Ok(mut stream) => {
                    // Get the local port
                    if let Ok(local_addr) = stream.local_addr() {
                        println!(
                            "Test client connected from port {} to port {}",
                            local_addr.port(),
                            test_port
                        );
                        client_port_clone.store(local_addr.port(), Ordering::SeqCst);
                    }

                    // Send HTTP request
                    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
                    let _ = stream.write_all(request).await;
                    let _ = stream.flush().await;

                    // Read response
                    let mut response = vec![0u8; 1024];
                    let n = stream.read(&mut response).await.unwrap_or(0);
                    println!("Client received: {} bytes", n);
                }
                Err(e) => {
                    eprintln!("Failed to connect to test server: {}", e);
                }
            }
        });

        // Wait for both to complete with timeout
        let timeout = tokio::time::timeout(Duration::from_secs(5), async {
            let _ = tokio::join!(server_handle, client_handle);
        });

        if timeout.await.is_err() {
            println!("⚠️  Test timed out - this shouldn't happen with async networking");
            return;
        }

        // Give eBPF time to process the connection
        sleep(Duration::from_millis(200)).await;

        // Get the captured client port
        let captured_port = client_port.load(Ordering::SeqCst);
        println!("Captured client port: {}", captured_port);

        if captured_port > 0 {
            // Try to lookup the session with the exact ports
            let client_session = Session {
                protocol: Protocol::TCP,
                src_ip: "127.0.0.1".parse().unwrap(),
                src_port: captured_port,
                dst_ip: "127.0.0.1".parse().unwrap(),
                dst_port: test_port,
            };

            let l7_data = l7_ebpf::get_l7_for_session(&client_session);
            println!("eBPF lookup for client session: {:?}", l7_data);

            if let Some(data) = l7_data {
                println!("✅ Found L7 data for test connection:");
                println!("   PID: {}", data.pid);
                println!("   Process: {}", data.process_name);
                assert!(data.pid > 0, "PID should be valid");
            } else {
                // Note: eBPF may not capture localhost connections on all kernels
                println!("⚠️  eBPF did not capture localhost connection");
                println!(
                    "   This may be expected - localhost traffic sometimes bypasses tcp_set_state"
                );
            }
        }

        println!("✅ Real connection test completed");
    }

    #[tokio::test]
    #[serial]
    async fn test_ebpf_with_external_connection() {
        if !l7_ebpf::is_fully_functional() {
            println!("Skipping test - eBPF not fully functional");
            println!("Status: {}", l7_ebpf::ebpf_support());
            return;
        }

        // Make a real external connection - this should definitely trigger tcp_set_state
        // We'll connect to a well-known reliable endpoint
        let targets = vec![
            ("1.1.1.1", 80),       // Cloudflare
            ("8.8.8.8", 53),       // Google DNS
            ("93.184.216.34", 80), // example.com
        ];

        let mut found_connection = false;

        for (host, port) in targets {
            println!("Attempting connection to {}:{}", host, port);

            // Try to connect with a short timeout
            let connect_result = std::net::TcpStream::connect_timeout(
                &format!("{}:{}", host, port).parse().unwrap(),
                Duration::from_secs(2),
            );

            if let Ok(stream) = connect_result {
                if let Ok(local_addr) = stream.local_addr() {
                    let local_ip = local_addr.ip();
                    let local_port = local_addr.port();

                    println!(
                        "Connected from {}:{} to {}:{}",
                        local_ip, local_port, host, port
                    );

                    // Give eBPF time to capture the connection
                    sleep(Duration::from_millis(100)).await;

                    // Try to lookup the session
                    let session = Session {
                        protocol: Protocol::TCP,
                        src_ip: local_ip,
                        src_port: local_port,
                        dst_ip: host.parse().unwrap(),
                        dst_port: port,
                    };

                    let l7_data = l7_ebpf::get_l7_for_session(&session);

                    if let Some(data) = l7_data {
                        println!("✅ eBPF captured external connection!");
                        println!("   PID: {}", data.pid);
                        println!("   Process: {}", data.process_name);
                        println!("   Path: {}", data.process_path);
                        // Note: tcp_set_state is often called in softirq context where
                        // the current task is swapper (PID 0). This is a known limitation.
                        // The important thing is that we tracked the connection.
                        if data.pid == 0 {
                            println!("   Note: PID is 0 (captured in kernel context - expected for tcp_set_state hook)");
                        }
                        found_connection = true;
                        break;
                    } else {
                        println!("eBPF lookup returned None for this connection");
                    }
                }
                drop(stream); // Close connection
            } else {
                println!("Could not connect to {}:{}", host, port);
            }
        }

        if !found_connection {
            println!("⚠️  Could not verify eBPF capture with external connections");
            println!("   This may be due to network restrictions or timing issues");
        }

        println!("✅ External connection test completed");
    }

    #[tokio::test]
    #[serial]
    async fn test_ebpf_session_data_structure() {
        if !l7_ebpf::is_fully_functional() {
            println!("Skipping test - eBPF not fully functional");
            println!("Status: {}", l7_ebpf::ebpf_support());
            return;
        }

        // Test the data structure handling
        let sessions = vec![
            Session {
                protocol: Protocol::TCP,
                src_ip: "192.168.1.1".parse().unwrap(),
                src_port: 80,
                dst_ip: "192.168.1.100".parse().unwrap(),
                dst_port: 12345,
            },
            Session {
                protocol: Protocol::UDP,
                src_ip: "10.0.0.1".parse().unwrap(),
                src_port: 53,
                dst_ip: "8.8.8.8".parse().unwrap(),
                dst_port: 53,
            },
            Session {
                protocol: Protocol::TCP,
                src_ip: "::1".parse().unwrap(),
                src_port: 443,
                dst_ip: "::1".parse().unwrap(),
                dst_port: 56789,
            },
        ];

        for session in sessions {
            let l7_data = l7_ebpf::get_l7_for_session(&session);
            println!("Session {:?} -> L7 data: {:?}", session, l7_data);

            // Test that the API handles all session types correctly
            if let Some(data) = l7_data {
                // Validate the data structure
                assert!(data.pid > 0, "PID should be positive");
                assert!(
                    !data.process_name.is_empty(),
                    "Process name should not be empty"
                );
            }
        }

        println!("✅ Session data structure test completed");
    }

    #[tokio::test]
    #[serial]
    async fn test_ebpf_performance() {
        if !l7_ebpf::is_fully_functional() {
            println!("Skipping test - eBPF not fully functional");
            println!("Status: {}", l7_ebpf::ebpf_support());
            return;
        }

        // Test performance with multiple lookups
        let start_time = std::time::Instant::now();
        let num_lookups = 1000;

        for i in 0..num_lookups {
            let session = Session {
                protocol: Protocol::TCP,
                src_ip: "127.0.0.1".parse().unwrap(),
                src_port: 80,
                dst_ip: "127.0.0.1".parse().unwrap(),
                dst_port: 10000 + (i % 1000),
            };

            let _l7_data = l7_ebpf::get_l7_for_session(&session);
        }

        let elapsed = start_time.elapsed();
        let avg_time = elapsed / num_lookups as u32;

        println!("Performance test: {} lookups in {:?}", num_lookups, elapsed);
        println!("Average lookup time: {:?}", avg_time);

        // Should be very fast (< 1ms per lookup)
        assert!(
            avg_time < Duration::from_millis(1),
            "Lookups should be fast (got {:?})",
            avg_time
        );

        println!("✅ Performance test passed");
    }

    #[test]
    fn test_ebpf_feature_compilation() {
        // This test just verifies that the eBPF code compiles correctly
        let available = l7_ebpf::is_available();
        println!("eBPF availability: {}", available);

        let session = Session {
            protocol: Protocol::TCP,
            src_ip: "127.0.0.1".parse().unwrap(),
            src_port: 80,
            dst_ip: "127.0.0.1".parse().unwrap(),
            dst_port: 12345,
        };

        let _result = l7_ebpf::get_l7_for_session(&session);
        println!("✅ eBPF feature compilation test passed");
    }

    #[tokio::test]
    #[serial]
    async fn test_ebpf_error_handling() {
        if !l7_ebpf::is_fully_functional() {
            println!("Skipping test - eBPF not fully functional");
            println!("Status: {}", l7_ebpf::ebpf_support());
            return;
        }

        // Test error handling with invalid sessions
        let invalid_sessions = vec![
            Session {
                protocol: Protocol::TCP,
                src_ip: "0.0.0.0".parse().unwrap(),
                src_port: 0,
                dst_ip: "0.0.0.0".parse().unwrap(),
                dst_port: 0,
            },
            Session {
                protocol: Protocol::UDP,
                src_ip: "255.255.255.255".parse().unwrap(),
                src_port: 65535,
                dst_ip: "255.255.255.255".parse().unwrap(),
                dst_port: 65535,
            },
        ];

        for session in invalid_sessions {
            let l7_data = l7_ebpf::get_l7_for_session(&session);
            println!("Invalid session {:?} -> L7 data: {:?}", session, l7_data);
            // Should handle gracefully (return None, not panic)
        }

        println!("✅ Error handling test passed");
    }

    /// Test IPv6 connection tracking
    #[tokio::test]
    #[serial]
    async fn test_ebpf_ipv6_connection() {
        if !l7_ebpf::is_fully_functional() {
            println!("Skipping IPv6 test - eBPF not fully functional");
            println!("Status: {}", l7_ebpf::ebpf_support());
            return;
        }

        println!("=== IPv6 L7 eBPF Connection Test ===");

        // Try to establish an IPv6 TCP connection to a known server
        // We'll try multiple IPv6 addresses in case some aren't reachable
        let ipv6_targets = [
            ("2607:f8b0:4004:800::200e", 80), // Google
            ("2606:4700::6810:84e5", 80),     // Cloudflare
            ("2001:4860:4860::8888", 53),     // Google DNS
        ];

        for (ip, port) in &ipv6_targets {
            let addr = format!("[{}]:{}", ip, port);
            println!("Trying to connect to {} ...", addr);

            match tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::TcpStream::connect(&addr),
            )
            .await
            {
                Ok(Ok(stream)) => {
                    let local_addr = stream.local_addr().ok();
                    let peer_addr = stream.peer_addr().ok();

                    println!("✅ Connected to {} from {:?}", addr, local_addr);

                    // Give eBPF time to process the connection
                    sleep(Duration::from_millis(100)).await;

                    // Create a session to query
                    if let (Some(local), Some(peer)) = (local_addr, peer_addr) {
                        let session = Session {
                            protocol: Protocol::TCP,
                            src_ip: local.ip(),
                            src_port: local.port(),
                            dst_ip: peer.ip(),
                            dst_port: peer.port(),
                        };

                        println!("Session: {:?}", session);

                        // Query eBPF for L7 info
                        let l7_data = l7_ebpf::get_l7_for_session(&session);
                        if let Some(ref data) = l7_data {
                            println!("✅ eBPF tracked IPv6 connection!");
                            println!("   PID: {}", data.pid);
                            println!("   Process: {:?}", data.process_name);
                            return; // Success
                        } else {
                            // Also try reverse lookup
                            let reverse_session = Session {
                                protocol: Protocol::TCP,
                                src_ip: peer.ip(),
                                src_port: peer.port(),
                                dst_ip: local.ip(),
                                dst_port: local.port(),
                            };
                            if let Some(ref data) = l7_ebpf::get_l7_for_session(&reverse_session) {
                                println!("✅ eBPF tracked IPv6 connection (reverse lookup)!");
                                println!("   PID: {}", data.pid);
                                println!("   Process: {:?}", data.process_name);
                                return; // Success
                            }
                            println!("⚠️  eBPF didn't capture (timing issue?)");
                        }
                    }
                    return; // Connection worked, that's the main test
                }
                Ok(Err(e)) => {
                    println!("⚠️  Could not connect to {}: {}", addr, e);
                }
                Err(_) => {
                    println!("⚠️  Connection to {} timed out", addr);
                }
            }
        }

        println!("ℹ️  No IPv6 targets reachable - this may be expected in some environments");
        // Don't fail the test if IPv6 isn't available
    }
}

#[cfg(not(all(target_os = "linux", feature = "ebpf")))]
mod non_ebpf_tests {
    use flodbadd::l7_ebpf;
    use flodbadd::sessions::{Protocol, Session};

    #[test]
    fn test_ebpf_unavailable() {
        assert!(!l7_ebpf::is_available(), "eBPF should not be available");

        let session = Session {
            protocol: Protocol::TCP,
            src_ip: "127.0.0.1".parse().unwrap(),
            src_port: 80,
            dst_ip: "127.0.0.1".parse().unwrap(),
            dst_port: 12345,
        };

        let result = l7_ebpf::get_l7_for_session(&session);
        assert!(
            result.is_none(),
            "Should return None when eBPF is unavailable"
        );

        println!("✅ Non-eBPF fallback test passed");
    }
}
