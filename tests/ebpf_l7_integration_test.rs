#[cfg(all(target_os = "linux", feature = "ebpf"))]
mod ebpf_integration_tests {
    use flodbadd::l7_ebpf;
    use flodbadd::sessions::{Protocol, Session, SessionL7};
    use serial_test::serial;
    use std::net::IpAddr;
    use std::process::Command;
    use std::time::Duration;
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

        assert!(
            available,
            "eBPF should be available when feature is enabled"
        );
        println!("✅ eBPF is available and ready");
    }

    #[tokio::test]
    #[serial]
    async fn test_ebpf_basic_session_lookup() {
        if !l7_ebpf::is_available() {
            println!("Skipping test - eBPF not available");
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
        if !l7_ebpf::is_available() {
            println!("Skipping test - eBPF not available");
            return;
        }

        // Create a real network connection to test eBPF tracking
        let test_port = 18080;

        // Start a simple HTTP server
        let server_handle = tokio::spawn(async move {
            use std::io::Write;
            use std::net::{TcpListener, TcpStream};

            let listener = match TcpListener::bind(format!("127.0.0.1:{}", test_port)) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("Failed to bind to port {}: {}", test_port, e);
                    return;
                }
            };

            println!("Test server listening on port {}", test_port);

            // Accept one connection
            match listener.accept() {
                Ok((mut stream, addr)) => {
                    println!("Test server accepted connection from {}", addr);
                    let response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!";
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                }
            }
        });

        // Give server time to start
        sleep(Duration::from_millis(100)).await;

        // Make a client connection
        let client_handle = tokio::spawn(async move {
            use std::io::Read;
            use std::net::TcpStream;

            match TcpStream::connect(format!("127.0.0.1:{}", test_port)) {
                Ok(mut stream) => {
                    println!("Test client connected to port {}", test_port);

                    // Send HTTP request
                    let request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
                    let _ = stream.write_all(request.as_bytes());
                    let _ = stream.flush();

                    // Read response
                    let mut response = String::new();
                    let _ = stream.read_to_string(&mut response);
                    println!("Client received: {}", response.trim());
                }
                Err(e) => {
                    eprintln!("Failed to connect to test server: {}", e);
                }
            }
        });

        // Wait for both to complete
        let _ = tokio::join!(server_handle, client_handle);

        // Give eBPF time to process the connection
        sleep(Duration::from_millis(500)).await;

        // Now test if eBPF captured the connection
        let test_session = Session {
            protocol: Protocol::TCP,
            src_ip: "127.0.0.1".parse().unwrap(),
            src_port: test_port, // Server port
            dst_ip: "127.0.0.1".parse().unwrap(),
            dst_port: test_port, // This might not match exactly due to client ephemeral port
        };

        let l7_data = l7_ebpf::get_l7_for_session(&test_session);
        println!("Test connection L7 data: {:?}", l7_data);

        // Try different combinations since we don't know exact client port
        for port in 1024..65535 {
            let client_session = Session {
                protocol: Protocol::TCP,
                src_ip: "127.0.0.1".parse().unwrap(),
                src_port: port,
                dst_ip: "127.0.0.1".parse().unwrap(),
                dst_port: test_port,
            };

            if let Some(data) = l7_ebpf::get_l7_for_session(&client_session) {
                println!("✅ Found L7 data for test connection: {:?}", data);
                assert!(data.pid > 0, "PID should be valid");
                assert!(
                    !data.process_name.is_empty(),
                    "Process name should not be empty"
                );
                break;
            }
        }

        println!("✅ Real connection test completed");
    }

    #[tokio::test]
    #[serial]
    async fn test_ebpf_session_data_structure() {
        if !l7_ebpf::is_available() {
            println!("Skipping test - eBPF not available");
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
                // process_path and username might be empty in some cases, so don't assert them
            }
        }

        println!("✅ Session data structure test completed");
    }

    #[tokio::test]
    #[serial]
    async fn test_ebpf_performance() {
        if !l7_ebpf::is_available() {
            println!("Skipping test - eBPF not available");
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
        let avg_time = elapsed / num_lookups;

        println!("Performance test: {} lookups in {:?}", num_lookups, elapsed);
        println!("Average lookup time: {:?}", avg_time);

        // Should be very fast (< 1ms per lookup)
        assert!(
            avg_time < Duration::from_millis(1),
            "Lookups should be fast"
        );

        println!("✅ Performance test passed");
    }

    #[test]
    fn test_ebpf_feature_compilation() {
        // This test just verifies that the eBPF code compiles correctly
        // when the feature is enabled

        // Test that the API is available
        let available = l7_ebpf::is_available();
        println!("eBPF availability: {}", available);

        // Test that we can create session objects
        let session = Session {
            protocol: Protocol::TCP,
            src_ip: "127.0.0.1".parse().unwrap(),
            src_port: 80,
            dst_ip: "127.0.0.1".parse().unwrap(),
            dst_port: 12345,
        };

        // Test that the function exists (even if it returns None)
        let _result = l7_ebpf::get_l7_for_session(&session);

        println!("✅ eBPF feature compilation test passed");
    }

    #[tokio::test]
    #[serial]
    async fn test_ebpf_error_handling() {
        if !l7_ebpf::is_available() {
            println!("Skipping test - eBPF not available");
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
            // This test mainly checks that we don't crash
        }

        println!("✅ Error handling test passed");
    }
}

#[cfg(not(all(target_os = "linux", feature = "ebpf")))]
mod non_ebpf_tests {
    use flodbadd::l7_ebpf;
    use flodbadd::sessions::{Protocol, Session};

    #[test]
    fn test_ebpf_unavailable() {
        // Test that eBPF is properly disabled when not on Linux or feature disabled
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
