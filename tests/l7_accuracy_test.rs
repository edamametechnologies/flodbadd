// L7 attribution accuracy test suite.
//
// Measures the L7 resolver's ability to correctly attribute real outbound
// network sessions to the originating process. Each scenario spawns a known
// process (curl, python3) that makes a real outbound connection, then checks
// whether the resolver returns the correct process name.
//
// Run with: cargo test --features packetcapture,asyncpacketcapture --test l7_accuracy_test -- --nocapture
// On Linux with eBPF: cargo test --features packetcapture,asyncpacketcapture,ebpf --test l7_accuracy_test -- --nocapture

#![cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]

use flodbadd::l7::FlodbaddL7;
use flodbadd::sessions::{Protocol, Session};
use serial_test::serial;
use std::net::IpAddr;
use std::process::Command;
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[derive(Debug, Clone)]
struct TestScenario {
    label: &'static str,
    process: &'static str,
    args: Vec<String>,
    dst_ip: IpAddr,
    dst_port: u16,
    #[allow(dead_code)]
    hold_secs: f64,
}

#[derive(Debug, Default)]
struct ScenarioResult {
    resolved: u32,
    correct_name: u32,
    total: u32,
    total_latency_ms: u64,
}

fn is_available(cmd: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        Command::new("where")
            .arg(cmd)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Command::new("which")
            .arg(cmd)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

fn matches_process(resolved_name: &str, expected: &str) -> bool {
    let r = resolved_name.to_lowercase();
    let e = expected.to_lowercase();
    r.contains(&e) || e.contains(&r)
}

fn null_device() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "NUL"
    }
    #[cfg(not(target_os = "windows"))]
    {
        "/dev/null"
    }
}

fn build_scenarios() -> Vec<TestScenario> {
    let mut scenarios = Vec::new();
    let target_ip: IpAddr = "1.1.1.1".parse().unwrap();

    if is_available("curl") {
        scenarios.push(TestScenario {
            label: "curl/short-http",
            process: "curl",
            args: vec![
                "-s".into(),
                "-o".into(),
                null_device().into(),
                "--max-time".into(),
                "5".into(),
                "http://1.1.1.1/".into(),
            ],
            dst_ip: target_ip,
            dst_port: 80,
            hold_secs: 0.0,
        });
        scenarios.push(TestScenario {
            label: "curl/short-https",
            process: "curl",
            args: vec![
                "-s".into(),
                "-o".into(),
                null_device().into(),
                "--max-time".into(),
                "5".into(),
                "https://1.1.1.1/".into(),
            ],
            dst_ip: target_ip,
            dst_port: 443,
            hold_secs: 0.0,
        });
        scenarios.push(TestScenario {
            label: "curl/medium-slow",
            process: "curl",
            args: vec![
                "-s".into(),
                "-o".into(),
                null_device().into(),
                "--limit-rate".into(),
                "100".into(),
                "--max-time".into(),
                "5".into(),
                "http://1.1.1.1/".into(),
            ],
            dst_ip: target_ip,
            dst_port: 80,
            hold_secs: 3.0,
        });
    }

    if is_available("python3") {
        scenarios.push(TestScenario {
            label: "python3/short-http",
            process: "python3",
            args: vec![
                "-c".into(),
                "import socket; s=socket.socket(); s.settimeout(5); s.connect(('1.1.1.1',80)); s.sendall(b'GET / HTTP/1.0\\r\\nHost: 1.1.1.1\\r\\n\\r\\n'); s.recv(4096); s.close()".into(),
            ],
            dst_ip: target_ip,
            dst_port: 80,
            hold_secs: 0.0,
        });
        scenarios.push(TestScenario {
            label: "python3/medium-hold",
            process: "python3",
            args: vec![
                "-c".into(),
                "import socket,time; s=socket.socket(); s.settimeout(10); s.connect(('1.1.1.1',80)); s.sendall(b'GET / HTTP/1.0\\r\\nHost: 1.1.1.1\\r\\n\\r\\n'); time.sleep(3); s.recv(4096); s.close()".into(),
            ],
            dst_ip: target_ip,
            dst_port: 80,
            hold_secs: 3.0,
        });
        scenarios.push(TestScenario {
            label: "python3/long-hold",
            process: "python3",
            args: vec![
                "-c".into(),
                "import socket,time; s=socket.socket(); s.settimeout(10); s.connect(('1.1.1.1',80)); s.sendall(b'GET / HTTP/1.0\\r\\nHost: 1.1.1.1\\r\\n\\r\\n'); time.sleep(6); s.recv(4096); s.close()".into(),
            ],
            dst_ip: target_ip,
            dst_port: 80,
            hold_secs: 6.0,
        });
    }

    scenarios
}

/// Discover the ephemeral source port the child opened.
/// Uses `lsof` on macOS/Linux and `netstat -ano` on Windows.
async fn find_client_port(pid: u32, dst_ip: &IpAddr, dst_port: u16) -> Option<u16> {
    let deadline = Instant::now() + Duration::from_secs(5);

    while Instant::now() < deadline {
        if let Some(port) = try_find_client_port_once(pid, dst_ip, dst_port) {
            return Some(port);
        }
        sleep(Duration::from_millis(50)).await;
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn try_find_client_port_once(pid: u32, dst_ip: &IpAddr, dst_port: u16) -> Option<u16> {
    let dst_str = format!("{}:{}", dst_ip, dst_port);
    let output = Command::new("lsof")
        .args(["-anP", "-iTCP", &format!("-p{}", pid)])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if line.contains(&dst_str) && line.contains("->") {
            // Format: ... TCP 192.168.1.2:54321->1.1.1.1:80 (ESTABLISHED)
            if let Some(arrow_pos) = line.find("->") {
                let before = &line[..arrow_pos];
                if let Some(colon_pos) = before.rfind(':') {
                    if let Ok(port) = before[colon_pos + 1..].trim().parse::<u16>() {
                        return Some(port);
                    }
                }
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn try_find_client_port_once(pid: u32, dst_ip: &IpAddr, dst_port: u16) -> Option<u16> {
    // `netstat -ano` output: TCP  10.0.0.1:54321  1.1.1.1:80  ESTABLISHED  1234
    let dst_str = format!("{}:{}", dst_ip, dst_port);
    let pid_str = pid.to_string();
    let output = Command::new("netstat")
        .args(["-ano", "-p", "TCP"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.contains(&dst_str) {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        // TCP  local_addr  remote_addr  state  pid
        if parts.len() >= 5 && parts[4] == pid_str {
            let local_addr = parts[1];
            if let Some(colon_pos) = local_addr.rfind(':') {
                if let Ok(port) = local_addr[colon_pos + 1..].parse::<u16>() {
                    return Some(port);
                }
            }
        }
    }
    None
}

async fn run_scenario_iteration(l7: &FlodbaddL7, scenario: &TestScenario) -> (bool, bool, u64) {
    let mut child = match Command::new(scenario.process)
        .args(&scenario.args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            println!("    SKIP: failed to spawn {}: {}", scenario.process, e);
            return (false, false, 0);
        }
    };

    let pid = child.id();
    let client_port = match find_client_port(pid, &scenario.dst_ip, scenario.dst_port).await {
        Some(p) => p,
        None => {
            // Process may have finished too fast for lsof to catch
            let _ = child.kill();
            let _ = child.wait();
            return (false, false, 0);
        }
    };

    let local_ip = get_default_local_ip();
    let session = Session {
        protocol: Protocol::TCP,
        src_ip: local_ip,
        src_port: client_port,
        dst_ip: scenario.dst_ip,
        dst_port: scenario.dst_port,
    };

    l7.add_connection_to_resolver(&session).await;
    let poll_start = Instant::now();

    let max_poll = Duration::from_secs(10);
    let mut resolved = false;
    let mut correct = false;
    let mut latency_ms = 0u64;

    while poll_start.elapsed() < max_poll {
        if let Some(resolution) = l7.get_resolved_l7(&session).await {
            if let Some(ref l7_data) = resolution.l7 {
                resolved = true;
                latency_ms = poll_start.elapsed().as_millis() as u64;
                if matches_process(&l7_data.process_name, scenario.process) {
                    correct = true;
                } else {
                    println!(
                        "    MISMATCH: expected='{}' got='{}' path='{}' pid={} source={:?}",
                        scenario.process,
                        l7_data.process_name,
                        l7_data.process_path,
                        l7_data.pid,
                        resolution.source
                    );
                }
                break;
            }
        }
        sleep(Duration::from_millis(50)).await;
    }

    if !resolved {
        latency_ms = poll_start.elapsed().as_millis() as u64;
        println!(
            "    UNRESOLVED after {}ms (port={})",
            latency_ms, client_port
        );
    }

    let _ = child.kill();
    let _ = child.wait();
    sleep(Duration::from_millis(200)).await;

    (resolved, correct, latency_ms)
}

fn get_default_local_ip() -> IpAddr {
    // Connect a UDP socket to determine the local IP that routes to the internet
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let _ = socket.connect("1.1.1.1:80");
    socket.local_addr().unwrap().ip()
}

#[tokio::test]
#[serial]
async fn l7_accuracy_matrix() {
    let iterations = 5;
    let scenarios = build_scenarios();
    if scenarios.is_empty() {
        println!("No test tools available (curl, python3). Skipping.");
        return;
    }

    let mut l7 = FlodbaddL7::new();
    l7.start().await;
    sleep(Duration::from_millis(500)).await;

    println!(
        "\nL7 Accuracy Test - {} scenarios x {} iterations",
        scenarios.len(),
        iterations
    );
    println!("Local IP: {}", get_default_local_ip());
    println!();

    let mut results: Vec<(&str, ScenarioResult)> = Vec::new();

    for scenario in &scenarios {
        let mut result = ScenarioResult::default();
        for i in 0..iterations {
            let (resolved, correct, latency_ms) = run_scenario_iteration(&l7, scenario).await;
            result.total += 1;
            if resolved {
                result.resolved += 1;
                result.total_latency_ms += latency_ms;
            }
            if correct {
                result.correct_name += 1;
            }
            println!(
                "  [{}/{}] {}: resolved={} correct={} latency={}ms",
                i + 1,
                iterations,
                scenario.label,
                resolved,
                correct,
                latency_ms
            );
            sleep(Duration::from_millis(300)).await;
        }
        results.push((scenario.label, result));
    }

    l7.stop().await;

    println!("\n{:-<78}", "");
    println!(
        "{:<25} {:>6} {:>6} {:>6} {:>8} {:>10}",
        "Scenario", "Total", "Resol", "Corr", "Res%", "Avg ms"
    );
    println!("{:-<78}", "");

    let mut total_resolved = 0u32;
    let mut total_correct = 0u32;
    let mut grand_total = 0u32;

    for (label, r) in &results {
        let res_pct = if r.total > 0 {
            (r.resolved as f64 / r.total as f64) * 100.0
        } else {
            0.0
        };
        let avg_ms = if r.resolved > 0 {
            r.total_latency_ms / r.resolved as u64
        } else {
            0
        };
        println!(
            "{:<25} {:>6} {:>6} {:>6} {:>7.1}% {:>8}ms",
            label, r.total, r.resolved, r.correct_name, res_pct, avg_ms
        );
        total_resolved += r.resolved;
        total_correct += r.correct_name;
        grand_total += r.total;
    }

    println!("{:-<78}", "");
    let overall_res = if grand_total > 0 {
        (total_resolved as f64 / grand_total as f64) * 100.0
    } else {
        0.0
    };
    let overall_corr = if grand_total > 0 {
        (total_correct as f64 / grand_total as f64) * 100.0
    } else {
        0.0
    };
    println!(
        "{:<25} {:>6} {:>6} {:>6} {:>7.1}%",
        "TOTAL", grand_total, total_resolved, total_correct, overall_res
    );
    println!("Overall resolution: {:.1}%", overall_res);
    println!("Overall correct name: {:.1}%", overall_corr);

    // Separate medium/long-lived results
    let medium_long: Vec<_> = results
        .iter()
        .filter(|(label, _)| label.contains("medium") || label.contains("long"))
        .collect();
    if !medium_long.is_empty() {
        let ml_resolved: u32 = medium_long.iter().map(|(_, r)| r.resolved).sum();
        let ml_total: u32 = medium_long.iter().map(|(_, r)| r.total).sum();
        let ml_correct: u32 = medium_long.iter().map(|(_, r)| r.correct_name).sum();
        if ml_total > 0 {
            let ml_res_pct = (ml_resolved as f64 / ml_total as f64) * 100.0;
            let ml_corr_pct = (ml_correct as f64 / ml_total as f64) * 100.0;
            println!("Medium+Long resolution: {:.1}%", ml_res_pct);
            println!("Medium+Long correct: {:.1}%", ml_corr_pct);

            // macOS has libproc for direct socket-to-PID lookup, so we can
            // hold a meaningful accuracy bar. On Windows/Linux CI (no eBPF,
            // no libproc), the netstat-based resolver has much lower accuracy
            // for ephemeral connections, so we only assert on macOS.
            #[cfg(target_os = "macos")]
            assert!(
                ml_res_pct >= 40.0,
                "Medium/long-lived resolution ({:.1}%) below 40% baseline",
                ml_res_pct
            );
        }
    }
}
