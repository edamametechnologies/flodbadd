// FIM Process Attribution Benchmark -- ES vs lsof+cache attribution rates.
//
// Creates short-lived files and measures how many FIM events get process
// attribution with vs without Endpoint Security. When ES is available the
// file_attribution_table provides near-100% hit rate because the kernel
// delivers (pid, path) at event time. Without ES the lsof+cache fallback
// is inherently racy for short-lived file descriptors.
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
use std::fs;
use std::time::{Duration, Instant};

const FILE_COUNT: usize = 50;
const SETTLE_SECS: u64 = 3;

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
    println!("  Writing {} files to {}", FILE_COUNT, tmp.path().display());

    let write_start = Instant::now();
    for i in 0..FILE_COUNT {
        let path = tmp.path().join(format!("bench_{:04}.dat", i));
        fs::write(&path, vec![0x42u8; 1024]).expect("write benchmark file");
    }
    let write_elapsed = write_start.elapsed();
    println!(
        "  Wrote {} files in {}ms",
        FILE_COUNT,
        write_elapsed.as_millis()
    );

    // Check ES table right after writes (before settle)
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

    // Diagnostic: show path forms and manual ES lookup for first few events
    for (i, ev) in create_events.iter().take(3).enumerate() {
        let canonical = std::fs::canonicalize(&ev.path)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "N/A".to_string());
        let es_raw = l7_es::get_file_attribution(&ev.path);
        let es_canonical = l7_es::get_file_attribution(&canonical);
        println!(
            "  [diag {}] path={} canonical={} es_raw={:?} es_canonical={:?}",
            i, ev.path, canonical, es_raw, es_canonical
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

    let (cr, cds, cdn, clr, clm, rn, ul) = l7_es::file_event_stats();
    println!("  ES event counters: create_recv={cr} dest_some={cds} dest_none={cdn} close_recv={clr} close_modified={clm} rename={rn} unlink={ul}");

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
