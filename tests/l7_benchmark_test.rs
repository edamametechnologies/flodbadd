// Cross-platform L7 attribution benchmark.
//   cargo test --features packetcapture --test l7_benchmark_test -- --nocapture
#![cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]

use flodbadd::l7::{FlodbaddL7, L7ResolutionSource};
use flodbadd::l7_ebpf;
use flodbadd::l7_es;
use flodbadd::l7_etw;
use flodbadd::sessions::{Protocol, Session};
use serde::Serialize;
use serial_test::serial;
use std::net::IpAddr;
use std::process::Command;
use std::time::{Duration, Instant};
use tokio::time::sleep;

const DST: &str = "1.1.1.1";
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
const PORT_DISCOVER_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Serialize)]
struct BenchmarkResult {
    platform: String,
    kernel_l7: String,
    kernel_l7_available: bool,
    scenarios: Vec<ScenarioResult>,
}

#[derive(Debug, Serialize)]
struct ScenarioResult {
    name: String,
    resolved: u32,
    total: u32,
    avg_latency_ms: u64,
    source: String,
    correct_name: u32,
}

fn null_device() -> &'static str {
    #[cfg(windows)]
    { "NUL" }
    #[cfg(not(windows))]
    { "/dev/null" }
}

fn is_available(cmd: &str) -> bool {
    #[cfg(windows)]
    { Command::new("where").arg(cmd).output().map(|o| o.status.success()).unwrap_or(false) }
    #[cfg(not(windows))]
    { Command::new("which").arg(cmd).output().map(|o| o.status.success()).unwrap_or(false) }
}

fn platform_string() -> &'static str {
    #[cfg(target_os = "linux")]
    { "linux" }
    #[cfg(target_os = "macos")]
    { "macos" }
    #[cfg(target_os = "windows")]
    { "windows" }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    { "unknown" }
}

fn kernel_l7_info() -> (&'static str, bool) {
    if l7_ebpf::is_available() {
        ("ebpf", true)
    } else if l7_es::is_available() {
        ("endpointsecurity", true)
    } else if l7_etw::is_available() {
        ("etw", true)
    } else {
        ("none", false)
    }
}

fn format_source(s: &L7ResolutionSource) -> String {
    format!("{:?}", s)
}

fn get_default_local_ip() -> IpAddr {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let _ = socket.connect("1.1.1.1:80");
    socket.local_addr().unwrap().ip()
}

#[cfg(target_os = "linux")]
fn try_find_client_port_proc(pid: u32, dst_ip: &IpAddr, dst_port: u16) -> Option<u16> {
    use std::io::Read as IoRead;
    let dst_port_hex = format!("{:04X}", dst_port);
    let dst_ip_hex = match dst_ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{:02X}{:02X}{:02X}{:02X}", o[3], o[2], o[1], o[0])
        }
        _ => return None,
    };
    let fd_path = format!("/proc/{}/fd", pid);
    let mut inodes = std::collections::HashSet::new();
    if let Ok(entries) = std::fs::read_dir(&fd_path) {
        for entry in entries.flatten() {
            if let Ok(link) = std::fs::read_link(entry.path()) {
                let s = link.to_string_lossy();
                if s.starts_with("socket:[") {
                    if let Some(ino) = s.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                        if let Ok(i) = ino.parse::<u64>() {
                            inodes.insert(i);
                        }
                    }
                }
            }
        }
    }
    let mut tcp_content = String::new();
    if std::fs::File::open("/proc/net/tcp")
        .and_then(|mut f| f.read_to_string(&mut tcp_content))
        .is_err()
    {
        return None;
    }
    for line in tcp_content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let remote = cols[2];
        if !remote.ends_with(&format!(":{}", dst_port_hex)) || !remote.starts_with(&dst_ip_hex) {
            continue;
        }
        if let Ok(inode) = cols[9].parse::<u64>() {
            if inodes.contains(&inode) {
                let local = cols[1];
                if let Some(colon_pos) = local.rfind(':') {
                    if let Ok(port) = u16::from_str_radix(&local[colon_pos + 1..], 16) {
                        return Some(port);
                    }
                }
            }
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn try_find_client_port(pid: u32, dst_ip: &IpAddr, dst_port: u16) -> Option<u16> {
    #[cfg(target_os = "linux")]
    if let Some(port) = try_find_client_port_proc(pid, dst_ip, dst_port) {
        return Some(port);
    }
    let dst_str = format!("{}:{}", dst_ip, dst_port);
    let output = Command::new("lsof")
        .args(["-anP", "-iTCP", &format!("-p{}", pid)])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if line.contains(&dst_str) && line.contains("->") {
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
fn try_find_client_port(pid: u32, dst_ip: &IpAddr, dst_port: u16) -> Option<u16> {
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

async fn find_client_port(pid: u32, dst_ip: &IpAddr, dst_port: u16) -> Option<u16> {
    let start = Instant::now();
    while start.elapsed() < PORT_DISCOVER_TIMEOUT {
        if let Some(port) = try_find_client_port(pid, dst_ip, dst_port) {
            return Some(port);
        }
        sleep(Duration::from_millis(50)).await;
    }
    None
}

struct Scenario {
    name: &'static str,
    process: &'static str,
    args: Vec<String>,
    dst_port: u16,
    iterations: u32,
}

fn build_scenarios(null_out: &str) -> Vec<Scenario> {
    let mut s = Vec::new();
    if !is_available("curl") {
        return s;
    }

    s.push(Scenario {
        name: "short_lived_curl",
        process: "curl",
        args: vec![
            "-s".into(), "-o".into(), null_out.into(),
            "--limit-rate".into(), "1K".into(),
            "--max-time".into(), "3".into(),
            "http://1.1.1.1/".into(),
        ],
        dst_port: 80,
        iterations: 3,
    });

    s.push(Scenario {
        name: "medium_lived_curl",
        process: "curl",
        args: vec![
            "-s".into(), "-o".into(), null_out.into(),
            "--limit-rate".into(), "100".into(),
            "--max-time".into(), "5".into(),
            "http://1.1.1.1/".into(),
        ],
        dst_port: 80,
        iterations: 3,
    });

    s.push(Scenario {
        name: "long_lived_curl",
        process: "curl",
        args: vec![
            "-s".into(), "-o".into(), null_out.into(),
            "--limit-rate".into(), "50".into(),
            "--max-time".into(), "8".into(),
            "http://1.1.1.1/".into(),
        ],
        dst_port: 80,
        iterations: 2,
    });

    s.push(Scenario {
        name: "short_lived_curl_https",
        process: "curl",
        args: vec![
            "-s".into(), "-o".into(), null_out.into(),
            "--limit-rate".into(), "1K".into(),
            "--max-time".into(), "3".into(),
            "https://1.1.1.1/".into(),
        ],
        dst_port: 443,
        iterations: 3,
    });

    s
}

async fn run_single_iteration(
    l7: &FlodbaddL7,
    process: &str,
    args: &[String],
    dst_ip: IpAddr,
    dst_port: u16,
    local_ip: IpAddr,
) -> (bool, bool, u64, String) {
    let mut child = match Command::new(process)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return (false, false, 0, "spawn_failed".into()),
    };

    let pid = child.id();

    let client_port = match find_client_port(pid, &dst_ip, dst_port).await {
        Some(p) => p,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return (false, false, 0, "no_port_discovered".into());
        }
    };

    let session = Session {
        protocol: Protocol::TCP,
        src_ip: local_ip,
        src_port: client_port,
        dst_ip,
        dst_port,
    };

    l7.add_connection_to_resolver(&session).await;
    let poll_start = Instant::now();

    let mut resolved = false;
    let mut correct = false;
    let mut latency_ms = 0u64;
    let mut source = String::from("timeout");

    while poll_start.elapsed() < RESOLVE_TIMEOUT {
        if let Some(res) = l7.get_resolved_l7(&session).await {
            if let Some(ref data) = res.l7 {
                resolved = true;
                latency_ms = poll_start.elapsed().as_millis() as u64;
                source = format_source(&res.source);
                let name = data.process_name.to_lowercase();
                correct = name.contains("curl");
                break;
            }
        }
        sleep(Duration::from_millis(50)).await;
    }

    if !resolved {
        latency_ms = poll_start.elapsed().as_millis() as u64;
    }

    let _ = child.kill();
    let _ = child.wait();
    sleep(Duration::from_millis(200)).await;

    (resolved, correct, latency_ms, source)
}

async fn run_burst_scenario(
    l7: &FlodbaddL7,
    local_ip: IpAddr,
    null_out: &str,
) -> ScenarioResult {
    const N: u32 = 5;
    if !is_available("curl") {
        return ScenarioResult {
            name: "burst_curl".into(), resolved: 0, total: N,
            avg_latency_ms: 0, source: "skipped".into(), correct_name: 0,
        };
    }

    let dst_ip: IpAddr = DST.parse().unwrap();
    let mut resolved = 0u32;
    let mut correct_name = 0u32;
    let mut latency_sum = 0u64;
    let mut last_source = String::from("none");

    for _ in 0..N {
        let args: Vec<String> = vec![
            "-s".into(), "-o".into(), null_out.into(),
            "--limit-rate".into(), "1K".into(),
            "--max-time".into(), "3".into(),
            "http://1.1.1.1/".into(),
        ];
        let (res, corr, lat, src) = run_single_iteration(
            l7, "curl", &args, dst_ip, 80, local_ip,
        ).await;
        last_source = src;
        if res {
            resolved += 1;
            latency_sum += lat;
            if corr { correct_name += 1; }
        }
        sleep(Duration::from_millis(100)).await;
    }

    let avg_latency_ms = if resolved > 0 { latency_sum / u64::from(resolved) } else { 0 };

    ScenarioResult {
        name: "burst_curl".into(),
        resolved,
        total: N,
        avg_latency_ms,
        source: last_source,
        correct_name,
    }
}

#[tokio::test]
#[serial]
async fn l7_benchmark() {
    let null_out = null_device();
    let (kernel_l7, kernel_l7_available) = kernel_l7_info();
    let local_ip = get_default_local_ip();
    let dst_ip: IpAddr = DST.parse().unwrap();

    println!("\nL7 Attribution Benchmark");
    println!("  Platform:  {}", platform_string());
    println!("  Kernel L7: {} (available={})", kernel_l7, kernel_l7_available);
    println!("  Local IP:  {}", local_ip);
    println!();

    let mut l7 = FlodbaddL7::new();
    l7.start().await;
    sleep(Duration::from_millis(500)).await;

    let scenarios = build_scenarios(null_out);
    let mut results: Vec<ScenarioResult> = Vec::new();

    for sc in &scenarios {
        let mut total_resolved = 0u32;
        let mut total_correct = 0u32;
        let mut total_latency = 0u64;
        let mut last_source = String::from("none");

        for i in 0..sc.iterations {
            let (res, corr, lat, src) = run_single_iteration(
                &l7, sc.process, &sc.args, dst_ip, sc.dst_port, local_ip,
            ).await;
            last_source = src.clone();
            if res {
                total_resolved += 1;
                total_latency += lat;
                if corr { total_correct += 1; }
            }
            println!(
                "  [{}/{}] {}: resolved={} correct={} latency={}ms source={}",
                i + 1, sc.iterations, sc.name, res, corr, lat, src,
            );
            sleep(Duration::from_millis(300)).await;
        }

        let avg_latency_ms = if total_resolved > 0 {
            total_latency / u64::from(total_resolved)
        } else {
            0
        };

        results.push(ScenarioResult {
            name: sc.name.to_string(),
            resolved: total_resolved,
            total: sc.iterations,
            avg_latency_ms,
            source: last_source,
            correct_name: total_correct,
        });
    }

    results.push(run_burst_scenario(&l7, local_ip, null_out).await);

    l7.stop().await;

    let result = BenchmarkResult {
        platform: platform_string().to_string(),
        kernel_l7: kernel_l7.to_string(),
        kernel_l7_available,
        scenarios: results,
    };

    let json = serde_json::to_string_pretty(&result).expect("serialize benchmark");
    println!("BENCHMARK_JSON_START");
    println!("{}", json);
    println!("BENCHMARK_JSON_END");
}
