// FIM Process Attribution Benchmark
//
// Measures three attribution tiers:
//   1. ES-backed cache (best -- kernel-delivered, zero-race)
//   2. lsof result cache (good -- bounded in-memory cache of lsof results)
//   3. Direct lsof probe (baseline -- racy but always available)
//
// Tier 1 (ES) cannot be exercised from within the test because macOS ES
// suppresses all events from the client's own process tree.  In production
// the helper daemon owns the ES client while user processes generate file
// events -- a completely independent process tree.  This test verifies:
//   - ES initializes and receives system events when entitled
//   - The 3-tier lookup code path works end-to-end
//   - lsof-based attribution works for long-lived processes
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
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const FILE_COUNT: usize = 50;
const SETTLE_SECS: u64 = 3;

#[derive(Debug, Serialize)]
struct FimBenchmarkResult {
    platform: String,
    es_available: bool,
    es_process_count: usize,
    es_file_table_size: usize,
    es_system_events: u64,
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

/// Spawn a long-lived process that writes files and keeps them open.
/// Returns the child handle so lsof can find the open file descriptors.
fn spawn_writer(dir: &std::path::Path) -> Child {
    let script = format!(
        concat!(
            "for i in $(seq 0 {}); do\n",
            "  f=$(printf '{}/bench_%04d.dat' \"$i\")\n",
            "  dd if=/dev/zero of=\"$f\" bs=1024 count=1 2>/dev/null\n",
            "done\n",
            "exec 3< {}/bench_0000.dat\n",
            "exec 4< {}/bench_0001.dat\n",
            "sleep 30\n"
        ),
        FILE_COUNT - 1,
        dir.display(),
        dir.display(),
        dir.display()
    );
    Command::new("/bin/bash")
        .args(["-c", &script])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn writer process")
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
    println!("  Test process PID: {}", std::process::id());
    println!("  ES available: {}", l7_es::is_available());
    println!("  ES support:   {}", l7_es::es_support());

    let start = Instant::now();
    let mut writer = spawn_writer(tmp.path());
    let writer_pid = writer.id();
    println!("  Writer PID: {}", writer_pid);

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let count = (0..FILE_COUNT)
            .filter(|i| tmp.path().join(format!("bench_{:04}.dat", i)).exists())
            .count();
        if count >= FILE_COUNT || Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let write_elapsed = start.elapsed();
    let actual_files = (0..FILE_COUNT)
        .filter(|i| tmp.path().join(format!("bench_{:04}.dat", i)).exists())
        .count();

    println!(
        "  Wrote {}/{} files in {}ms",
        actual_files,
        FILE_COUNT,
        write_elapsed.as_millis()
    );
    println!("  ES process table: {} entries", l7_es::process_count());
    println!(
        "  ES file table (immediate): {} entries",
        l7_es::file_attribution_count()
    );

    println!("  Waiting {}s for events to settle...", SETTLE_SECS);
    std::thread::sleep(Duration::from_secs(SETTLE_SECS));

    println!(
        "  ES file table (after settle): {} entries",
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
        "  FIM events: {} total, {} bench_ Create",
        events.len(),
        create_events.len()
    );

    for (i, ev) in create_events.iter().take(3).enumerate() {
        let es_hit = l7_es::get_file_attribution(&ev.path);
        println!(
            "  [diag {}] path={} proc={:?} es={:?}",
            i, ev.path, ev.process_name, es_hit
        );
    }

    let pre_attributed = create_events
        .iter()
        .filter(|e| e.process_name.is_some())
        .count();
    println!(
        "  Pre-backfill: {}/{} attributed",
        pre_attributed,
        create_events.len()
    );

    let backfill_start = Instant::now();
    let backfill_updated = backfill_missing_process_attribution(
        watcher.store(),
        FIM_PROCESS_ATTRIBUTION_BACKFILL_LIMIT,
    );
    let backfill_elapsed = backfill_start.elapsed();

    // Kill writer now that backfill probed it via lsof
    let _ = writer.kill();
    let _ = writer.wait();

    let events_after = watcher.store().get_all_events();
    let create_after: Vec<_> = events_after
        .iter()
        .filter(|e| {
            e.event_type == FimEventType::Create
                && e.path.contains("bench_")
                && e.path.ends_with(".dat")
        })
        .collect();

    let post_attributed = create_after
        .iter()
        .filter(|e| e.process_name.is_some())
        .count();
    let total_create = create_after.len();
    let attribution_rate = if total_create > 0 {
        (post_attributed as f64 / total_create as f64) * 100.0
    } else {
        0.0
    };

    let (lsof_cache_size, es_available) = attribution_cache_stats();
    let es_file_table_size = l7_es::file_attribution_count();
    let es_process_count = l7_es::process_count();
    let (cr, cds, cdn, clr, clm, rn, ul, oth) = l7_es::file_event_stats();
    let es_system_events = cr + clr + rn + ul;

    println!(
        "  Post-backfill: {}/{} attributed (backfill updated {})",
        post_attributed, total_create, backfill_updated
    );
    println!("  Attribution rate: {:.1}%", attribution_rate);
    println!("  ES file table: {} entries", es_file_table_size);
    println!("  ES process table: {} entries", es_process_count);
    println!("  lsof cache: {} entries", lsof_cache_size);
    println!("  Backfill took {}ms", backfill_elapsed.as_millis());
    println!(
        "  ES counters: create={}(dest_some={},dest_none={}) close={}(modified={}) rename={} unlink={} other={}",
        cr, cds, cdn, clr, clm, rn, ul, oth
    );

    let table_dump = l7_es::dump_file_attribution_paths(15);
    if !table_dump.is_empty() {
        println!("  ES file table sample ({} shown):", table_dump.len());
        for (path, pid, exe) in &table_dump {
            let tag = if path.contains("bench_") {
                "MATCH"
            } else {
                "sys"
            };
            println!("    [{}] pid={} exe={} path={}", tag, pid, exe, path);
        }
    }

    watcher.stop();

    let result = FimBenchmarkResult {
        platform: "macos".to_string(),
        es_available,
        es_process_count,
        es_file_table_size,
        es_system_events,
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

    // Assertions: the pipeline must work regardless of ES availability
    assert!(
        actual_files >= FILE_COUNT / 2,
        "Expected at least {} files created, got {}",
        FILE_COUNT / 2,
        actual_files
    );
    assert!(
        total_create > 0,
        "Expected FIM to capture at least some Create events"
    );
}
