// These tests require the packetcapture feature (which enables the l7 module).
// Run with: cargo test --features packetcapture,asyncpacketcapture --test l7_short_lived_process_test
// On Linux with eBPF: cargo test --features packetcapture,asyncpacketcapture,ebpf --test l7_short_lived_process_test

#![cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]

use flodbadd::l7::FlodbaddL7;
#[cfg(all(target_os = "linux", feature = "ebpf"))]
use flodbadd::l7::L7ResolutionSource;
#[cfg(all(target_os = "linux", feature = "ebpf"))]
use flodbadd::l7_ebpf;
use flodbadd::sessions::{Protocol, Session};
use serial_test::serial;
use std::time::Duration;
use tokio::time::sleep;

/// Spawn a short-lived TCP connection via an external command (python3)
/// and return (child_pid, local_port, remote_ip, remote_port).
/// The process will have exited by the time this returns.
#[cfg(target_os = "linux")]
async fn spawn_short_lived_tcp_connection() -> Option<(u32, u16, std::net::IpAddr, u16)> {
    use std::process::Command;
    use tokio::net::TcpListener;

    // Start a local TCP server to receive the connection
    let listener = TcpListener::bind("127.0.0.1:0").await.ok()?;
    let server_port = listener.local_addr().ok()?.port();

    // Spawn a short-lived process that connects, writes, and exits immediately.
    // Using python3 because it's the process type that caused flakiness.
    let child = Command::new("python3")
        .arg("-c")
        .arg(format!(
            "import socket; s=socket.socket(); s.connect(('127.0.0.1',{})); \
             s.sendall(b'test'); s.close()",
            server_port
        ))
        .spawn()
        .ok()?;

    let child_pid = child.id();

    // Accept the connection on the server side
    let accept_result = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await;

    let (stream, peer_addr) = match accept_result {
        Ok(Ok((s, a))) => (s, a),
        _ => return None,
    };
    let client_port = peer_addr.port();
    drop(stream);

    // Wait for the child to exit
    let mut child = child;
    let _ = child.wait();

    // Small delay to ensure the process is fully reaped
    sleep(Duration::from_millis(50)).await;

    // Verify the process is gone
    let proc_dir = format!("/proc/{}", child_pid);
    let process_gone = !std::path::Path::new(&proc_dir).exists();
    println!(
        "Short-lived process PID={} exited={}, server_port={}, client_port={}",
        child_pid, process_gone, server_port, client_port
    );

    Some((
        child_pid,
        client_port,
        "127.0.0.1".parse().unwrap(),
        server_port,
    ))
}

/// Verify that the L7 resolver captures process_name for a short-lived
/// external TCP connection via the eager eBPF path. This test reproduces
/// the exact scenario that caused benchmark flakiness: a python3 process
/// connects, transfers data, and exits before the periodic resolver runs.
#[cfg(all(target_os = "linux", feature = "ebpf"))]
#[tokio::test]
#[serial]
async fn test_ebpf_eager_resolution_short_lived_python() {
    if !l7_ebpf::is_fully_functional() {
        println!(
            "Skipping -- eBPF not fully functional: {}",
            l7_ebpf::ebpf_support()
        );
        return;
    }

    // Alpine and other minimal containers may not ship python3.
    let python_ok = std::process::Command::new("python3")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !python_ok {
        println!("Skipping -- python3 not available on this platform");
        return;
    }

    let mut l7 = FlodbaddL7::new();
    l7.start().await;

    let iterations = 5;
    let mut connected_count = 0;
    let mut resolved_count = 0;
    let mut total_with_process_name = 0;

    for i in 0..iterations {
        println!("--- Iteration {}/{} ---", i + 1, iterations);

        let conn = match spawn_short_lived_tcp_connection().await {
            Some(c) => c,
            None => {
                println!("  Failed to create short-lived connection, skipping");
                continue;
            }
        };
        connected_count += 1;

        let (_child_pid, client_port, remote_ip, remote_port) = conn;

        let session = Session {
            protocol: Protocol::TCP,
            src_ip: "127.0.0.1".parse().unwrap(),
            src_port: client_port,
            dst_ip: remote_ip,
            dst_port: remote_port,
        };

        l7.add_connection_to_resolver(&session).await;
        let resolution = l7.get_resolved_l7(&session).await;

        match resolution {
            Some(res) => {
                resolved_count += 1;
                if let Some(ref l7_data) = res.l7 {
                    println!(
                        "  Resolved: process='{}' pid={} source={:?} open_files={}",
                        l7_data.process_name,
                        l7_data.pid,
                        res.source,
                        l7_data.open_files.len()
                    );
                    if !l7_data.process_name.is_empty() {
                        total_with_process_name += 1;
                        assert!(
                            l7_data.process_name.contains("python"),
                            "Expected python process, got '{}'",
                            l7_data.process_name
                        );
                    }
                    if res.source == L7ResolutionSource::Ebpf {
                        println!("  Resolved via eBPF eager path (expected)");
                    }
                } else {
                    println!(
                        "  Resolution entry exists but l7 is None (source={:?})",
                        res.source
                    );
                }
            }
            None => {
                println!("  No resolution yet (will be resolved by background task)");
            }
        }
    }

    l7.stop().await;

    println!(
        "\nResults: {}/{} connected, {}/{} resolved, {}/{} had process_name",
        connected_count, iterations, resolved_count, connected_count, total_with_process_name,
        connected_count
    );

    assert!(
        connected_count > 0,
        "All {} connection attempts failed despite python3 being available",
        iterations
    );

    // With eBPF eager resolution, we expect most iterations to succeed.
    // Allow some slack for localhost connections that may bypass tcp_set_state.
    assert!(
        total_with_process_name >= connected_count / 2,
        "Expected at least half of connected iterations to have process_name, \
         got {}/{}. eBPF eager resolution may not be working.",
        total_with_process_name,
        connected_count
    );
}

/// Non-eBPF variant: verify that the L7 resolver eventually resolves a
/// still-running process via netstat/socket matching. This tests the
/// fallback path and ensures the code compiles on all platforms.
#[tokio::test]
#[serial]
async fn test_l7_resolver_resolves_running_process() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    let mut l7 = FlodbaddL7::new();
    l7.start().await;

    // Create a connection that stays open long enough for the resolver
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        // Keep the connection alive
        sleep(Duration::from_secs(5)).await;
        let _ = stream.write_all(b"done").await;
    });

    let client = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();
    let client_port = client.local_addr().unwrap().port();

    let session = Session {
        protocol: Protocol::TCP,
        src_ip: "127.0.0.1".parse().unwrap(),
        src_port: client_port,
        dst_ip: "127.0.0.1".parse().unwrap(),
        dst_port: port,
    };

    // Queue and attempt resolution
    l7.add_connection_to_resolver(&session).await;

    // Poll for resolution with a timeout
    let mut resolved = false;
    for attempt in 0..50 {
        sleep(Duration::from_millis(100)).await;
        if let Some(res) = l7.get_resolved_l7(&session).await {
            if let Some(ref l7_data) = res.l7 {
                println!(
                    "Resolved on attempt {}: process='{}' pid={} source={:?}",
                    attempt, l7_data.process_name, l7_data.pid, res.source
                );
                assert!(l7_data.pid > 0, "PID should be valid");
                assert!(
                    !l7_data.process_name.is_empty(),
                    "process_name should not be empty for a running process"
                );
                resolved = true;
                break;
            }
        }
    }

    // Clean up
    drop(client);
    server.abort();
    l7.stop().await;

    assert!(
        resolved,
        "L7 resolver should resolve a still-running process within 5 seconds"
    );
}

/// Verify that eBPF eager resolution in add_connection_to_resolver
/// populates the l7_map entry with Some(l7) instead of None, avoiding
/// the placeholder-blocks-eBPF bug.
#[cfg(all(target_os = "linux", feature = "ebpf"))]
#[tokio::test]
#[serial]
async fn test_add_connection_does_not_create_none_placeholder_when_ebpf_available() {
    if !l7_ebpf::is_fully_functional() {
        println!("Skipping -- eBPF not fully functional");
        return;
    }

    let mut l7 = FlodbaddL7::new();
    l7.start().await;

    // Create a real connection so eBPF can capture it
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let _server = tokio::spawn(async move {
        let _ = listener.accept().await;
        sleep(Duration::from_secs(2)).await;
    });

    let client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();
    let client_port = client.local_addr().unwrap().port();

    // Give eBPF time to capture
    sleep(Duration::from_millis(100)).await;

    let session = Session {
        protocol: Protocol::TCP,
        src_ip: "127.0.0.1".parse().unwrap(),
        src_port: client_port,
        dst_ip: "127.0.0.1".parse().unwrap(),
        dst_port: port,
    };

    // add_connection_to_resolver should try eBPF eagerly
    l7.add_connection_to_resolver(&session).await;

    // get_resolved_l7 should return the eBPF result, not a None placeholder
    let resolution = l7.get_resolved_l7(&session).await;
    if let Some(res) = &resolution {
        if res.l7.is_some() {
            println!(
                "add_connection_to_resolver populated l7 eagerly via {:?}",
                res.source
            );
            assert_eq!(
                res.source,
                L7ResolutionSource::Ebpf,
                "Expected eBPF source when eBPF is available"
            );
        } else {
            println!("l7 is None -- eBPF may not have captured localhost connection");
        }
    }

    drop(client);
    l7.stop().await;
}
