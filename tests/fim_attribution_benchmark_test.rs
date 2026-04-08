// FIM Process Attribution Benchmark -- ES vs lsof+cache attribution rates.
//
// On macOS, the ES framework suppresses all events (process + file) from
// the ES client's own process tree.  To test ES-based file attribution we
// must create files from a process that is NOT a descendant of the test
// binary.  We use `launchctl submit` to launch a launchd-managed job
// whose parent is launchd (PID 1), making its events visible to our ES
// client.
//
//   With ES:     sudo -E cargo test --features endpointsecurity,fim --test fim_attribution_benchmark_test -- --nocapture
//   Without ES:  sudo -E cargo test --features fim --test fim_attribution_benchmark_test -- --nocapture
#![cfg(all(target_os = "macos", feature = "fim"))]

use flodbadd::fim::{
    attribution_cache_stats, backfill_missing_process_attribution, clear_attribution_cache,
    FimConfig, FimWatcher, FIM_PROCESS_ATTRIBUTION_BACKFILL_LIMIT,
};
use flodbadd::fim_events::FimEventType;
use flodbadd::l7_es;
use serde::Serialize;
use std::process::Command;
use std::time::{Duration, Instant};

const FILE_COUNT: usize = 50;
const SETTLE_SECS: u64 = 5;

#[derive(Debug, Serialize)]
struct FimBenchmarkResult {
    platform: String,
    es_available: bool,
    es_file_table_size: usize,
    lsof_cache_size: usize,
    total_file_events: usize,
    attributed_events: usize,
    attribution_rate_pct: f64,
    backfill_updated: usize,
    elapsed_ms: u64,
}

fn poll_for_events(
    store: &flodbadd::fim_events::FimEventStore,
    min_count: usize,
    timeout: Duration,
) -> Vec<flodbadd::fim_events::FimEvent> {
    let deadline = Instant::now() + timeout;
    loop {
        let events = store.get_all_events();
        if events.len() >= min_count || Instant::now() >= deadline {
            return events;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

const LAUNCHD_LABEL: &str = "com.edamame.fimbench";

/// Write files from a launchd-managed job (parent = launchd PID 1).
/// ES suppresses the client's own process tree, so we must create files
/// from a completely independent process for ES to see them.
fn write_files_via_launchd(dir: &std::path::Path) -> Duration {
    let done_flag = dir.join(".done");
    let script = format!(
        "#!/bin/bash\nfor i in $(seq -w 0000 {:04}); do\n  /bin/dd if=/dev/zero of={}/bench_${{i}}.dat bs=1024 count=1 2>/dev/null\ndone\ntouch {}\n",
        FILE_COUNT - 1,
        dir.display(),
        done_flag.display()
    );
    let script_path = dir.join("writer.sh");
    std::fs::write(&script_path, script).expect("write script");

    Command::new("chmod")
        .args(["+x", &script_path.to_string_lossy().to_string()])
        .status()
        .expect("chmod");

    // Remove any stale job with this label
    let _ = Command::new("launchctl")
        .args(["remove", LAUNCHD_LABEL])
        .output();

    let start = Instant::now();

    let submit = Command::new("launchctl")
        .args([
            "submit",
            "-l",
            LAUNCHD_LABEL,
            "--",
            "/bin/bash",
            &script_path.to_string_lossy().to_string(),
        ])
        .output()
        .expect("launchctl submit");

    if !submit.status.success() {
        let stderr = String::from_utf8_lossy(&submit.stderr);
        println!("  [warn] launchctl submit failed: {}", stderr.trim());
        println!("  Falling back to direct child process");
        return write_files_via_child(dir);
    }

    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if done_flag.exists() {
            break;
        }
        if Instant::now() > deadline {
            println!("  [warn] launchd job timed out, checking files...");
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let _ = Command::new("launchctl")
        .args(["remove", LAUNCHD_LABEL])
        .output();

    start.elapsed()
}

/// Fallback: spawn child process for file writing (ES won't see these).
fn write_files_via_child(dir: &std::path::Path) -> Duration {
    let start = Instant::now();
    for i in 0..FILE_COUNT {
        let path = dir.join(format!("bench_{:04}.dat", i));
        let status = Command::new("dd")
            .args([
                &format!("if=/dev/zero"),
                &format!("of={}", path.display()),
                "bs=1024",
                "count=1",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .expect("spawn dd child");
        assert!(status.success(), "dd failed for file {i}");
    }
    start.elapsed()
}

#[test]
fn fim_attribution_benchmark() {
    l7_es::init_and_log_status();

    clear_attribution_cache();

    let tmp = tempfile::Builder::new()
        .prefix("fim_bench_")
        .tempdir_in("/tmp")
        .expect("create temp dir in /tmp");

    // Make the temp dir world-writable so the launchd job can write to it
    Command::new("chmod")
        .args(["777", &tmp.path().to_string_lossy().to_string()])
        .status()
        .expect("chmod temp dir");

    let config = FimConfig {
        recursive: true,
        ..Default::default()
    };
    let watcher =
        FimWatcher::start(vec![tmp.path().to_path_buf()], config).expect("start FIM watcher");

    std::thread::sleep(Duration::from_millis(500));

    println!("\n=== FIM Attribution Benchmark ===");
    println!("  Test process PID: {}", std::process::id());
    println!("  ES available: {}", l7_es::is_available());
    println!("  ES support:   {}", l7_es::es_support());
    println!("  ES process table size: {}", l7_es::process_count());
    println!(
        "  Writing {} files to {} (via launchd job)",
        FILE_COUNT,
        tmp.path().display()
    );

    let write_elapsed = write_files_via_launchd(tmp.path());

    let actual_files = (0..FILE_COUNT)
        .filter(|i| tmp.path().join(format!("bench_{:04}.dat", i)).exists())
        .count();
    println!(
        "  Wrote {}/{} files in {}ms",
        actual_files,
        FILE_COUNT,
        write_elapsed.as_millis()
    );

    println!(
        "  ES file table size (immediate): {}",
        l7_es::file_attribution_count()
    );

    println!("  Waiting {}s for events to settle...", SETTLE_SECS);
    std::thread::sleep(Duration::from_secs(SETTLE_SECS));

    println!(
        "  ES file table size (after settle): {}",
        l7_es::file_attribution_count()
    );

    let events = poll_for_events(watcher.store(), FILE_COUNT, Duration::from_secs(5));

    let create_events: Vec<_> = events
        .iter()
        .filter(|e| {
            e.event_type == FimEventType::Create
                && e.path.contains("bench_")
                && e.path.ends_with(".dat")
        })
        .collect();

    println!(
        "  Total FIM events from notify: {} (of which {} are bench_ Create events)",
        events.len(),
        create_events.len()
    );
    for (i, ev) in create_events.iter().take(5).enumerate() {
        let es_hit = l7_es::get_file_attribution(&ev.path);
        println!(
            "  [diag {}] path={} proc={:?} es_hit={:?}",
            i, ev.path, ev.process_name, es_hit
        );
    }

    let pre_attributed = create_events
        .iter()
        .filter(|e| e.process_name.is_some())
        .count();

    println!(
        "  Pre-backfill: {}/{} create events attributed",
        pre_attributed,
        create_events.len()
    );

    let backfill_start = Instant::now();
    let backfill_updated = backfill_missing_process_attribution(
        watcher.store(),
        FIM_PROCESS_ATTRIBUTION_BACKFILL_LIMIT,
    );
    let backfill_elapsed = backfill_start.elapsed();

    let events_after = watcher.store().get_all_events();
    let create_events_after: Vec<_> = events_after
        .iter()
        .filter(|e| {
            e.event_type == FimEventType::Create
                && e.path.contains("bench_")
                && e.path.ends_with(".dat")
        })
        .collect();

    let post_attributed = create_events_after
        .iter()
        .filter(|e| e.process_name.is_some())
        .count();

    let total_create = create_events_after.len();
    let attribution_rate = if total_create > 0 {
        (post_attributed as f64 / total_create as f64) * 100.0
    } else {
        0.0
    };

    let (lsof_cache_size, es_available) = attribution_cache_stats();
    let es_file_table_size = l7_es::file_attribution_count();

    println!(
        "  Post-backfill: {}/{} create events attributed (backfill updated {})",
        post_attributed, total_create, backfill_updated
    );
    println!("  Attribution rate: {:.1}%", attribution_rate);
    println!("  ES file table size: {}", es_file_table_size);
    println!("  lsof cache size: {}", lsof_cache_size);
    println!("  Backfill took {}ms", backfill_elapsed.as_millis());

    let (cr, cds, cdn, clr, clm, rn, ul, oth) = l7_es::file_event_stats();
    println!("  ES event counters: create={cr}(dest_some={cds},dest_none={cdn}) close={clr}(modified={clm}) rename={rn} unlink={ul} other={oth}");

    let table_dump = l7_es::dump_file_attribution_paths(30);
    println!("  ES file table dump ({} entries shown):", table_dump.len());
    for (path, pid, exe) in &table_dump {
        let is_bench = path.contains("bench_");
        println!(
            "    {} pid={} exe={} path={}",
            if is_bench { "[MATCH]" } else { "[other]" },
            pid,
            exe,
            path
        );
    }

    watcher.stop();

    let result = FimBenchmarkResult {
        platform: "macos".to_string(),
        es_available,
        es_file_table_size,
        lsof_cache_size,
        total_file_events: total_create,
        attributed_events: post_attributed,
        attribution_rate_pct: (attribution_rate * 10.0).round() / 10.0,
        backfill_updated,
        elapsed_ms: (write_elapsed + Duration::from_secs(SETTLE_SECS) + backfill_elapsed)
            .as_millis() as u64,
    };

    let json = serde_json::to_string_pretty(&result).expect("serialize benchmark");
    println!("\nBENCHMARK_JSON_START");
    println!("{}", json);
    println!("BENCHMARK_JSON_END");
}
