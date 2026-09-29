//! Live harness for the FLODBADD2 §1b.2 process-event monitoring stream.
//!
//! Runs the platform sensor (ES on macOS -- requires an entitled, signed
//! host binary; ETW on Windows -- requires Administrator; eBPF on Linux --
//! requires root + kernel support), then reports ring counters every
//! second and a final event-rate + overhead summary. With `--storm N` it
//! also spawns N short-lived children mid-run so exec/fork/exit rates and
//! per-event cost can be measured against a known workload.
//!
//! Monitoring role only: this binary never blocks anything (§1b.1 R1-R2).
//!
//! Build with the `examples` feature as well so sensor start / attach
//! diagnostics (which are `tracing` events) reach the terminal; `PE_LOG=debug`
//! widens them.
//!
//!   cargo run --example process_events_monitor --features endpointsecurity,examples -- --seconds 20 --storm 200
//!   cargo run --example process_events_monitor --features ebpf,examples -- --seconds 20 --storm 200   (Linux, root)
//!   cargo run --example process_events_monitor --features etw,examples -- --seconds 20 --storm 200    (Windows, admin)
//!
//! Exit paths (the kernel trace sessions must not outlive the process): by
//! default `main` returns, which runs the ETW exit hook; `--shutdown` calls
//! `l7_etw::shutdown()` explicitly first; `--hard-exit` ends with
//! `std::process::exit`, which bypasses the exit hook (as a host that exits
//! that way must call `shutdown()` itself). Check with `logman query -ets`.
//! `--show-requester <a,b>` lists only the task accesses whose requester
//! name or path contains one of the texts, with the raw access mask.

use std::time::{Duration, Instant};

fn spawn_storm(count: u32) {
    #[cfg(target_os = "windows")]
    let (program, args): (&str, &[&str]) = ("cmd", &["/C", "exit"]);
    #[cfg(not(target_os = "windows"))]
    let (program, args): (&str, &[&str]) = ("/usr/bin/true", &[]);

    let started = Instant::now();
    let mut spawned = 0u32;
    for _ in 0..count {
        match std::process::Command::new(program).args(args).spawn() {
            Ok(mut child) => {
                let _ = child.wait();
                spawned += 1;
            }
            Err(e) => {
                eprintln!("storm spawn failed: {e}");
                break;
            }
        }
    }
    println!(
        "storm: spawned {} children in {:?} ({:.0} proc/s)",
        spawned,
        started.elapsed(),
        spawned as f64 / started.elapsed().as_secs_f64().max(0.001)
    );
}

fn sensor_status() -> String {
    #[cfg(all(target_os = "macos", feature = "endpointsecurity"))]
    {
        flodbadd::l7_es::init_and_log_status();
        return format!("ES available: {}", flodbadd::l7_es::is_available());
    }
    #[cfg(all(target_os = "windows", feature = "etw"))]
    {
        flodbadd::l7_etw::init_and_log_status();
        return format!("ETW: {}", flodbadd::l7_etw::etw_support());
    }
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    {
        flodbadd::l7_ebpf::init_and_log_status();
        return format!("eBPF: {}", flodbadd::l7_ebpf::ebpf_support());
    }
    #[allow(unreachable_code)]
    {
        "no platform sensor compiled in (enable endpointsecurity / etw / ebpf)".to_string()
    }
}

fn main() {
    // Sensor start / attach failures are reported through `tracing`; without
    // a subscriber an ES "not permitted", an ETW session clash or an eBPF
    // attach failure is silent and the run just shows zero events.
    #[cfg(feature = "examples")]
    {
        let level = std::env::var("PE_LOG")
            .ok()
            .and_then(|v| v.parse::<tracing::Level>().ok())
            .unwrap_or(tracing::Level::INFO);
        tracing_subscriber::fmt()
            .with_max_level(level)
            .with_target(true)
            .init();
    }

    let mut seconds: u64 = 15;
    let mut storm: u32 = 0;
    let mut explicit_shutdown = false;
    let mut hard_exit = false;
    let mut show_requester: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--seconds" => seconds = args.next().and_then(|v| v.parse().ok()).unwrap_or(seconds),
            "--storm" => storm = args.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            "--shutdown" => explicit_shutdown = true,
            "--hard-exit" => hard_exit = true,
            "--show-requester" => show_requester = args.next(),
            other => eprintln!("ignoring unknown arg: {other}"),
        }
    }

    // Initialize the platform sensor (the same global the capture/FIM
    // paths use), then watch the ring fill.
    println!("sensor: {}", sensor_status());

    let t0 = Instant::now();
    let c0 = flodbadd::process_events::counters();
    let mut storm_fired = false;
    for tick in 0..seconds {
        std::thread::sleep(Duration::from_secs(1));
        if storm > 0 && !storm_fired && tick >= seconds / 3 {
            storm_fired = true;
            spawn_storm(storm);
        }
        let c = flodbadd::process_events::counters();
        println!(
            "t={:>3}s exec={} fork={} exit={} task_access={} net_connect={} evicted={}",
            tick + 1,
            c.exec - c0.exec,
            c.fork - c0.fork,
            c.exit - c0.exit,
            c.task_access - c0.task_access,
            c.net_connect - c0.net_connect,
            c.evicted - c0.evicted,
        );
    }

    let c1 = flodbadd::process_events::counters();
    let elapsed = t0.elapsed().as_secs_f64();
    let total = (c1.exec - c0.exec)
        + (c1.fork - c0.fork)
        + (c1.exit - c0.exit)
        + (c1.task_access - c0.task_access);
    println!(
        "summary: {} events in {:.1}s ({:.1} ev/s), evicted {}",
        total,
        elapsed,
        total as f64 / elapsed.max(0.001),
        c1.evicted - c0.evicted
    );

    // Field coverage over everything still in the ring: which of the
    // per-platform claims (argv digest, image path, kernel-vouched signing
    // identity, task-port access) actually carried data on this host.
    use flodbadd::process_events::ProcessEventKind;
    let all = flodbadd::process_events::recent(usize::MAX);
    let execs: Vec<_> = all
        .iter()
        .filter(|e| e.kind == ProcessEventKind::Exec)
        .collect();
    println!(
        "coverage: ring={} exec={} exec_with_argv_digest={} exec_with_path={} exec_with_signing_id={} exec_with_ppid={} task_access={}",
        all.len(),
        execs.len(),
        execs.iter().filter(|e| e.argv_sha256.is_some()).count(),
        execs.iter().filter(|e| !e.process_path.is_empty()).count(),
        execs.iter().filter(|e| e.signing_id.is_some()).count(),
        execs.iter().filter(|e| e.ppid.is_some()).count(),
        all.iter()
            .filter(|e| e.kind == ProcessEventKind::TaskAccess)
            .count()
    );
    // `--show-requester <a,b,...>`: only task accesses whose requester name or
    // path contains one of the texts (case-insensitive), so a driven open is
    // not lost behind the first 32 of a busy host.
    let requester_filter: Option<Vec<String>> = show_requester
        .as_deref()
        .map(|s| s.split(',').map(|n| n.trim().to_lowercase()).collect());
    for event in all
        .iter()
        .filter(|e| e.kind == ProcessEventKind::TaskAccess)
        .filter(|e| {
            requester_filter.as_ref().is_none_or(|needles| {
                let name = e.process_name.to_lowercase();
                let path = e.process_path.to_lowercase();
                needles
                    .iter()
                    .any(|n| name.contains(n.as_str()) || path.contains(n.as_str()))
            })
        })
        .take(32)
    {
        println!(
            "  task_access by pid={} {} ({}) -> target pid={:?} {:?} mode={:?} mask={:#x?} marked={}",
            event.pid,
            event.process_name,
            event.process_path,
            event.target_pid,
            event.target_process_path,
            event.task_access_mode,
            event.task_access_mask,
            event.platform_path_marked
        );
    }

    let recent = flodbadd::process_events::recent(6);
    println!("last {} events:", recent.len());
    for event in recent {
        println!(
            "  {:>13} {:?} pid={} ppid={:?} name={} path={} argv_len={:?} digest={} signing={:?} platform={:?} net_dst={:?}",
            event.timestamp_ms,
            event.kind,
            event.pid,
            event.ppid,
            event.process_name,
            event.process_path,
            event.argv_len,
            event
                .argv_sha256
                .as_deref()
                .map(|d| &d[..12])
                .unwrap_or("-"),
            event.signing_id,
            event.is_platform_binary,
            event.net_dst
        );
    }

    if explicit_shutdown {
        flodbadd::l7_etw::shutdown();
        println!(
            "explicit shutdown: etw available={}",
            flodbadd::l7_etw::is_available()
        );
    }
    if hard_exit {
        println!("hard exit (std::process::exit)");
        std::process::exit(0);
    }
}
