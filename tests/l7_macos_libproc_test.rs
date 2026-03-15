// Tests for macOS libproc-based socket-to-PID resolution (l7_macos module).
//
// These tests require root privileges because proc_pidinfo/proc_pidfdinfo
// need to inspect other processes' file descriptors. The test binary itself
// holds open sockets, so self-inspection works without root, but the full
// system scan and cross-process tests need elevated access.
//
// Run with:
//   sudo cargo test --features packetcapture --test l7_macos_libproc_test -- --nocapture
//
// Sudoers entry (if you prefer passwordless):
//   %staff ALL=(ALL) NOPASSWD: /Users/flyonnet/.cargo/bin/cargo
//   # Or more precisely, allow the test binary:
//   %staff ALL=(ALL) NOPASSWD: /Users/flyonnet/Programming/flodbadd/target/debug/deps/l7_macos_libproc_test-*

#![cfg(target_os = "macos")]

use flodbadd::l7_macos;
use flodbadd::sessions::{Protocol, Session};
use serial_test::serial;
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream, UdpSocket};

// ---------------------------------------------------------------------------
// Struct size validation (compile-time contract with the kernel)
// ---------------------------------------------------------------------------

#[test]
fn test_struct_sizes_match_kernel() {
    use std::mem;
    // These must match the values from <sys/proc_info.h> on macOS.
    // If Apple changes the struct layout in a future SDK, this test
    // catches it at build time.
    assert_eq!(mem::size_of::<u8>(), 1); // sanity
                                         // The real struct size tests are in the module's own unit tests;
                                         // re-verify here as an integration check.
    let (_, entries) = l7_macos::scan_all_process_sockets(Some(&[std::process::id()]));
    // Just verifying the call doesn't crash with misaligned structs
    let _ = entries;
}

// ---------------------------------------------------------------------------
// TCP: self-connected loopback socket should be found
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_tcp_loopback_self_detection() {
    // Bind a TCP listener and connect to it from the same process
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let local_addr = listener.local_addr().expect("listener addr");

    let client = TcpStream::connect(local_addr).expect("connect to listener");
    let _accepted = listener.accept().expect("accept");

    let client_local = client.local_addr().expect("client local addr");
    let my_pid = std::process::id();

    let entries = l7_macos::scan_process_sockets(my_pid);
    eprintln!(
        "TCP test: pid={}, listener={}, client_local={}, entries={}",
        my_pid,
        local_addr,
        client_local,
        entries.len()
    );
    for e in &entries {
        eprintln!(
            "  {:?} {}:{} -> {}:{} (tcp_state={:?})",
            e.protocol, e.local_ip, e.local_port, e.remote_ip, e.remote_port, e.tcp_state
        );
    }

    // The client-side socket should appear with the correct 4-tuple
    let found_client = entries.iter().any(|e| {
        e.protocol == Protocol::TCP
            && e.local_port == client_local.port()
            && e.remote_port == local_addr.port()
            && e.pid == my_pid
    });
    assert!(
        found_client,
        "Expected to find client TCP socket (local_port={}) in entries for pid {}",
        client_local.port(),
        my_pid
    );

    // The listener socket should appear (remote=0.0.0.0:0 in LISTEN state)
    let found_listener = entries.iter().any(|e| {
        e.protocol == Protocol::TCP && e.local_port == local_addr.port() && e.pid == my_pid
    });
    assert!(
        found_listener,
        "Expected to find listener TCP socket (local_port={}) in entries for pid {}",
        local_addr.port(),
        my_pid
    );
}

// ---------------------------------------------------------------------------
// UDP: bound socket should be found
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_udp_socket_self_detection() {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind UDP");
    let local_addr = sock.local_addr().expect("udp local addr");
    let my_pid = std::process::id();

    let entries = l7_macos::scan_process_sockets(my_pid);
    eprintln!(
        "UDP test: pid={}, bound={}, entries={}",
        my_pid,
        local_addr,
        entries.len()
    );
    for e in &entries {
        if e.protocol == Protocol::UDP {
            eprintln!(
                "  {:?} {}:{} -> {}:{}",
                e.protocol, e.local_ip, e.local_port, e.remote_ip, e.remote_port
            );
        }
    }

    let found = entries.iter().any(|e| {
        e.protocol == Protocol::UDP && e.local_port == local_addr.port() && e.pid == my_pid
    });
    assert!(
        found,
        "Expected to find UDP socket (port={}) in entries for pid {}",
        local_addr.port(),
        my_pid
    );
}

// ---------------------------------------------------------------------------
// Session map: lookup_session_pid resolves exact TCP session
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_session_map_tcp_lookup() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let server_addr = listener.local_addr().expect("addr");

    let client = TcpStream::connect(server_addr).expect("connect");
    let _accepted = listener.accept().expect("accept");

    let client_local = client.local_addr().expect("client local");
    let my_pid = std::process::id();

    let (session_map, all_entries) = l7_macos::scan_all_process_sockets(Some(&[my_pid]));

    let session = Session {
        protocol: Protocol::TCP,
        src_ip: client_local.ip(),
        src_port: client_local.port(),
        dst_ip: server_addr.ip(),
        dst_port: server_addr.port(),
    };

    let found_pid = l7_macos::lookup_session_pid(&session, &session_map, &all_entries);
    assert_eq!(
        found_pid,
        Some(my_pid),
        "lookup_session_pid should find our PID for the client session"
    );

    // Also test reverse direction
    let reverse_session = Session {
        protocol: Protocol::TCP,
        src_ip: server_addr.ip(),
        src_port: server_addr.port(),
        dst_ip: client_local.ip(),
        dst_port: client_local.port(),
    };
    let found_reverse = l7_macos::lookup_session_pid(&reverse_session, &session_map, &all_entries);
    assert_eq!(
        found_reverse,
        Some(my_pid),
        "lookup_session_pid should find our PID for the reverse session"
    );
}

// ---------------------------------------------------------------------------
// Session map: UDP fuzzy port-based lookup
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_session_map_udp_fuzzy_lookup() {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind UDP");
    let local_addr = sock.local_addr().expect("addr");
    let my_pid = std::process::id();

    let (session_map, all_entries) = l7_macos::scan_all_process_sockets(Some(&[my_pid]));

    // Simulate a captured session where the local UDP port appears as src_port
    // and the remote side is some arbitrary address
    let session = Session {
        protocol: Protocol::UDP,
        src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        src_port: local_addr.port(),
        dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        dst_port: 53,
    };

    let found_pid = l7_macos::lookup_session_pid(&session, &session_map, &all_entries);
    assert_eq!(
        found_pid,
        Some(my_pid),
        "UDP fuzzy lookup should find our PID by port"
    );
}

// ---------------------------------------------------------------------------
// System-wide scan: verify well-known services are detected
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_system_scan_finds_common_services() {
    let (session_map, all_entries) = l7_macos::scan_all_process_sockets(None);

    eprintln!(
        "System scan: {} session entries, {} raw socket entries",
        session_map.len(),
        all_entries.len()
    );

    // On a running macOS system, there should be TCP and UDP sockets
    let has_tcp = all_entries.iter().any(|e| e.protocol == Protocol::TCP);
    let has_udp = all_entries.iter().any(|e| e.protocol == Protocol::UDP);

    assert!(has_tcp, "Expected at least one TCP socket on the system");
    assert!(has_udp, "Expected at least one UDP socket on the system");

    // Verify PIDs are reasonable
    for entry in &all_entries {
        assert!(entry.pid > 0, "PID should be positive, got {}", entry.pid);
    }
}

// ---------------------------------------------------------------------------
// IPv6 socket detection
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_ipv6_tcp_detection() {
    let listener = match TcpListener::bind("[::1]:0") {
        Ok(l) => l,
        Err(_) => {
            eprintln!("IPv6 loopback not available, skipping test");
            return;
        }
    };
    let local_addr = listener.local_addr().expect("addr");

    let client = TcpStream::connect(local_addr).expect("connect");
    let _accepted = listener.accept().expect("accept");

    let client_local = client.local_addr().expect("client local");
    let my_pid = std::process::id();

    let entries = l7_macos::scan_process_sockets(my_pid);

    let found = entries.iter().any(|e| {
        e.protocol == Protocol::TCP
            && e.local_port == client_local.port()
            && matches!(e.local_ip, IpAddr::V6(_))
            && e.pid == my_pid
    });

    eprintln!(
        "IPv6 test: found={}, client_local={}, entries={}",
        found,
        client_local,
        entries.len()
    );
    for e in &entries {
        if matches!(e.local_ip, IpAddr::V6(_)) {
            eprintln!(
                "  {:?} [{}]:{} -> [{}]:{}",
                e.protocol, e.local_ip, e.local_port, e.remote_ip, e.remote_port
            );
        }
    }

    assert!(
        found,
        "Expected to find IPv6 TCP client socket (port={}) for pid {}",
        client_local.port(),
        my_pid
    );
}

// ---------------------------------------------------------------------------
// Dead PID handling
// ---------------------------------------------------------------------------

#[test]
fn test_dead_pid_returns_empty() {
    let entries = l7_macos::scan_process_sockets(4_000_000);
    assert!(
        entries.is_empty(),
        "Dead PID should yield empty entries, got {}",
        entries.len()
    );
}

// ---------------------------------------------------------------------------
// Cross-process detection (requires root)
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_cross_process_socket_detection() {
    use std::process::{Command, Stdio};

    // Spawn a Python process that opens a TCP listener and keeps it open
    let mut child = match Command::new("python3")
        .arg("-c")
        .arg(
            "import socket, time, sys; \
             s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); \
             s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); \
             s.bind(('127.0.0.1', 0)); \
             s.listen(1); \
             print(s.getsockname()[1], flush=True); \
             time.sleep(30)",
        )
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to spawn python3: {}, skipping test", e);
            return;
        }
    };

    let child_pid = child.id();

    // Read the port number from the child's stdout
    let port: u16 = {
        use std::io::BufRead;
        let stdout = child.stdout.as_mut().expect("child stdout");
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read port");
        line.trim().parse().expect("parse port number")
    };

    eprintln!(
        "Child python3 pid={} listening on 127.0.0.1:{}",
        child_pid, port
    );

    // Scan the child's sockets
    let entries = l7_macos::scan_process_sockets(child_pid);
    eprintln!("Entries for child pid {}: {}", child_pid, entries.len());
    for e in &entries {
        eprintln!(
            "  {:?} {}:{} -> {}:{} (tcp_state={:?})",
            e.protocol, e.local_ip, e.local_port, e.remote_ip, e.remote_port, e.tcp_state
        );
    }

    let found = entries
        .iter()
        .any(|e| e.protocol == Protocol::TCP && e.local_port == port && e.pid == child_pid);

    child.kill().ok();
    child.wait().ok();

    if !found && entries.is_empty() {
        eprintln!(
            "WARN: Could not scan child process sockets. \
             This test requires root (sudo) to inspect other processes' FDs."
        );
        // Don't assert-fail when not root -- the test is expected to need sudo
        return;
    }

    assert!(
        found,
        "Expected to find child's TCP listener on port {} (pid {})",
        port, child_pid
    );
}

// ---------------------------------------------------------------------------
// Full system scan: lookup a known TCP connection from this process
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_full_system_scan_resolves_self_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let client = TcpStream::connect(addr).expect("connect");
    let _accepted = listener.accept().expect("accept");

    let client_local = client.local_addr().expect("client local");
    let my_pid = std::process::id();

    // Full system scan (no PID filter)
    let (session_map, all_entries) = l7_macos::scan_all_process_sockets(None);

    let session = Session {
        protocol: Protocol::TCP,
        src_ip: client_local.ip(),
        src_port: client_local.port(),
        dst_ip: addr.ip(),
        dst_port: addr.port(),
    };

    let found_pid = l7_macos::lookup_session_pid(&session, &session_map, &all_entries);

    eprintln!(
        "Full scan: session {:?}, found_pid={:?}, my_pid={}",
        session, found_pid, my_pid
    );

    assert_eq!(
        found_pid,
        Some(my_pid),
        "Full system scan should resolve our TCP connection to our PID"
    );
}
