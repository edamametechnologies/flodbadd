// L7 Attribution Benchmark -- resolution rate and minimum detectable session duration.
//
// Two measurements:
//   1. Resolution rate (%): for a realistic mix of session lifetimes, what fraction
//      gets L7-resolved with vs. without kernel support?
//   2. Minimum detectable duration: binary search for the shortest TCP connection
//      that the resolver can still attribute.
//
// All sessions are created from the test process itself (TcpStream::connect), so
// local port is always known -- no lsof/proc dependency.
//
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
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};
use tokio::time::sleep;

const DST_IP: &str = "1.1.1.1";
const DST_PORT: u16 = 80;
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(12);

fn platform_string() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "linux"
    }
    #[cfg(target_os = "macos")]
    {
        "macos"
    }
    #[cfg(target_os = "windows")]
    {
        "windows"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "unknown"
    }
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
    let _ = socket.connect(format!("{}:{}", DST_IP, DST_PORT));
    socket.local_addr().unwrap().ip()
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct BenchmarkResult {
    platform: String,
    kernel_l7: String,
    kernel_l7_available: bool,
    resolution_rate: ResolutionRateResult,
    min_duration: MinDurationResult,
}

#[derive(Debug, Serialize)]
struct ResolutionRateResult {
    buckets: Vec<DurationBucket>,
    overall_resolved: u32,
    overall_total: u32,
    overall_rate_pct: f64,
}

#[derive(Debug, Serialize)]
struct DurationBucket {
    label: String,
    hold_ms: u64,
    resolved: u32,
    total: u32,
    rate_pct: f64,
    avg_latency_ms: u64,
    sources: Vec<String>,
}

#[derive(Debug, Serialize)]
struct MinDurationResult {
    min_resolved_ms: u64,
    max_unresolved_ms: u64,
    probes: Vec<DurationProbe>,
}

#[derive(Debug, Serialize)]
struct DurationProbe {
    hold_ms: u64,
    resolved: bool,
    latency_ms: u64,
    source: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct ConnectionAttempt {
    resolved: bool,
    #[allow(dead_code)]
    correct: bool,
    latency_ms: u64,
    source: String,
}

async fn attempt_connection(
    l7: &FlodbaddL7,
    local_ip: IpAddr,
    dst_ip: IpAddr,
    hold_duration: Duration,
) -> ConnectionAttempt {
    let stream = match TcpStream::connect_timeout(
        &SocketAddr::new(dst_ip, DST_PORT),
        Duration::from_secs(5),
    ) {
        Ok(s) => s,
        Err(_) => {
            return ConnectionAttempt {
                resolved: false,
                correct: false,
                latency_ms: 0,
                source: "connect_failed".into(),
            };
        }
    };

    let local_port = match stream.local_addr() {
        Ok(a) => a.port(),
        Err(_) => {
            return ConnectionAttempt {
                resolved: false,
                correct: false,
                latency_ms: 0,
                source: "no_local_addr".into(),
            };
        }
    };

    let session = Session {
        protocol: Protocol::TCP,
        src_ip: local_ip,
        src_port: local_port,
        dst_ip,
        dst_port: DST_PORT,
    };

    l7.add_connection_to_resolver(&session).await;

    sleep(hold_duration).await;
    drop(stream);

    let poll_start = Instant::now();
    while poll_start.elapsed() < RESOLVE_TIMEOUT {
        if let Some(res) = l7.get_resolved_l7(&session).await {
            if let Some(ref data) = res.l7 {
                let name = data.process_name.to_lowercase();
                let correct = name.contains("l7_benchmark")
                    || name.contains("benchmark")
                    || name.contains("cargo");
                return ConnectionAttempt {
                    resolved: true,
                    correct,
                    latency_ms: poll_start.elapsed().as_millis() as u64,
                    source: format_source(&res.source),
                };
            }
        }
        sleep(Duration::from_millis(30)).await;
    }
    ConnectionAttempt {
        resolved: false,
        correct: false,
        latency_ms: poll_start.elapsed().as_millis() as u64,
        source: "timeout".into(),
    }
}

// ---------------------------------------------------------------------------
// Part 1 -- Resolution rate across realistic session durations
// ---------------------------------------------------------------------------

async fn run_resolution_rate(
    l7: &FlodbaddL7,
    local_ip: IpAddr,
    dst_ip: IpAddr,
) -> ResolutionRateResult {
    // Durations representing a realistic traffic mix:
    //   0ms   = connect-and-immediately-close (health probe, port scan)
    //   10ms  = very short REST API call
    //   50ms  = typical HTTPS handshake + small payload
    //   200ms = moderate API call
    //   500ms = file download chunk, websocket setup
    //   1s    = page load, streaming start
    //   3s    = long API call or download
    let hold_times: &[(&str, u64)] = &[
        ("0ms_instant", 0),
        ("10ms_api_call", 10),
        ("50ms_https", 50),
        ("200ms_moderate", 200),
        ("500ms_download", 500),
        ("1000ms_page_load", 1000),
        ("3000ms_long", 3000),
    ];
    const ITERATIONS_PER_BUCKET: u32 = 3;

    let mut buckets = Vec::new();
    let mut overall_resolved = 0u32;
    let mut overall_total = 0u32;

    for &(label, hold_ms) in hold_times {
        let mut resolved = 0u32;
        let mut latency_sum = 0u64;
        let mut sources = Vec::new();

        for i in 0..ITERATIONS_PER_BUCKET {
            let r = attempt_connection(l7, local_ip, dst_ip, Duration::from_millis(hold_ms)).await;
            println!(
                "  [{}/{}] {}: resolved={} latency={}ms source={}",
                i + 1,
                ITERATIONS_PER_BUCKET,
                label,
                r.resolved,
                r.latency_ms,
                r.source,
            );
            if r.resolved {
                resolved += 1;
                latency_sum += r.latency_ms;
            }
            if !sources.contains(&r.source) {
                sources.push(r.source);
            }
            sleep(Duration::from_millis(200)).await;
        }

        let avg_latency_ms = if resolved > 0 {
            latency_sum / u64::from(resolved)
        } else {
            0
        };
        overall_resolved += resolved;
        overall_total += ITERATIONS_PER_BUCKET;

        buckets.push(DurationBucket {
            label: label.to_string(),
            hold_ms,
            resolved,
            total: ITERATIONS_PER_BUCKET,
            rate_pct: (f64::from(resolved) / f64::from(ITERATIONS_PER_BUCKET)) * 100.0,
            avg_latency_ms,
            sources,
        });
    }

    let overall_rate_pct = (f64::from(overall_resolved) / f64::from(overall_total)) * 100.0;

    ResolutionRateResult {
        buckets,
        overall_resolved,
        overall_total,
        overall_rate_pct,
    }
}

// ---------------------------------------------------------------------------
// Part 2 -- Binary search for minimum detectable session duration
// ---------------------------------------------------------------------------

async fn run_min_duration_search(
    l7: &FlodbaddL7,
    local_ip: IpAddr,
    dst_ip: IpAddr,
) -> MinDurationResult {
    // Search range: 0ms to 500ms.  Anything above 500ms is expected to resolve.
    let probe_durations_ms: &[u64] = &[0, 5, 10, 20, 50, 100, 150, 200, 300, 500];
    const ATTEMPTS_PER_PROBE: u32 = 3;
    const MAJORITY: u32 = 2; // 2/3 must resolve to count as "resolvable"

    let mut probes = Vec::new();
    let mut min_resolved_ms: u64 = u64::MAX;
    let mut max_unresolved_ms: u64 = 0;

    for &hold_ms in probe_durations_ms {
        let mut successes = 0u32;
        let mut total_latency = 0u64;
        let mut last_source = String::from("none");

        for _ in 0..ATTEMPTS_PER_PROBE {
            let r = attempt_connection(l7, local_ip, dst_ip, Duration::from_millis(hold_ms)).await;
            if r.resolved {
                successes += 1;
                total_latency += r.latency_ms;
                last_source = r.source;
            } else {
                last_source = r.source;
            }
            sleep(Duration::from_millis(200)).await;
        }

        let resolved = successes >= MAJORITY;
        let avg_lat = if successes > 0 {
            total_latency / u64::from(successes)
        } else {
            0
        };

        println!(
            "  probe {}ms: {}/{} resolved={} latency={}ms source={}",
            hold_ms, successes, ATTEMPTS_PER_PROBE, resolved, avg_lat, last_source,
        );

        if resolved && hold_ms < min_resolved_ms {
            min_resolved_ms = hold_ms;
        }
        if !resolved && hold_ms > max_unresolved_ms {
            max_unresolved_ms = hold_ms;
        }

        probes.push(DurationProbe {
            hold_ms,
            resolved,
            latency_ms: avg_lat,
            source: last_source,
        });
    }

    if min_resolved_ms == u64::MAX {
        min_resolved_ms = 0;
    }

    MinDurationResult {
        min_resolved_ms,
        max_unresolved_ms,
        probes,
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn l7_benchmark() {
    let (kernel_l7, kernel_l7_available) = kernel_l7_info();
    let local_ip = get_default_local_ip();
    let dst_ip: IpAddr = DST_IP.parse().unwrap();

    println!("\n=== L7 Attribution Benchmark ===");
    println!("  Platform:  {}", platform_string());
    println!(
        "  Kernel L7: {} (available={})",
        kernel_l7, kernel_l7_available
    );
    println!("  Local IP:  {}", local_ip);
    println!();

    let mut l7 = FlodbaddL7::new();
    l7.start().await;
    sleep(Duration::from_millis(500)).await;

    println!("--- Part 1: Resolution Rate by Session Duration ---");
    let resolution_rate = run_resolution_rate(&l7, local_ip, dst_ip).await;

    println!();
    println!("--- Part 2: Minimum Detectable Session Duration ---");
    let min_duration = run_min_duration_search(&l7, local_ip, dst_ip).await;

    l7.stop().await;

    let result = BenchmarkResult {
        platform: platform_string().to_string(),
        kernel_l7: kernel_l7.to_string(),
        kernel_l7_available,
        resolution_rate,
        min_duration,
    };

    let json = serde_json::to_string_pretty(&result).expect("serialize benchmark");
    println!("\nBENCHMARK_JSON_START");
    println!("{}", json);
    println!("BENCHMARK_JSON_END");
}
