// FIM Process Attribution Benchmark -- ES vs lsof+cache attribution rates.
//
// Spawns a child process to write files so the ES framework delivers events
// to the parent (ES client host).  ES silently suppresses file events from
// the process that owns the ES client, so in-process writes are invisible.
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

/// Spawn individual child processes that each write one file.
/// This ensures each file write is a separate process event for ES.
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
        assert!(status.success(), "dd exited with {status} for file {i}");
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

    let config = FimConfig {
        recursive: true,
        ..Default::default()
    };
    let watcher =
        FimWatcher::start(vec![tmp.path().to_path_buf()], config).expect("start FIM watcher");

    std::thread::sleep(Duration::from_millis(500));

    println!("\n=== FIM Attribution Benchmark ===");
    println!("  ES available: {}", l7_es::is_available());
    println!("  ES support:   {}", l7_es::es_support());
    println!(
        "  Writing {} files to {} (via child process)",
        FILE_COUNT,
        tmp.path().display()
    );

    let write_elapsed = write_files_via_child(tmp.path());
    println!(
        "  Wrote {} files in {}ms",
        FILE_COUNT,
        write_elapsed.as_millis()
    );

    let es_immediate = l7_es::file_attribution_count();
    println!("  ES file table size (immediate): {}", es_immediate);

    println!("  Waiting {}s for events to settle...", SETTLE_SECS);
    std::thread::sleep(Duration::from_secs(SETTLE_SECS));

    let es_after_settle = l7_es::file_attribution_count();
    println!("  ES file table size (after settle): {}", es_after_settle);

    let events = poll_for_events(watcher.store(), FILE_COUNT, Duration::from_secs(5));

    let create_events: Vec<_> = events
        .iter()
        .filter(|e| {
            e.event_type == FimEventType::Create
                && e.path.contains("bench_")
                && e.path.ends_with(".dat")
        })
        .collect();

    for (i, ev) in create_events.iter().take(3).enumerate() {
        let es_hit = l7_es::get_file_attribution(&ev.path);
        println!("  [diag {}] path={} es_hit={:?}", i, ev.path, es_hit);
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
