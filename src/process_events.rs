// Cross-platform process-lifecycle monitoring stream (FLODBADD2 §1b.2,
// MONITORING ROLE ONLY per the §1b.1 R1-R4 invariants).
//
// Kernel-event backends push here from their existing sensor threads:
//   - macOS: Endpoint Security FORK/EXEC/EXIT + GET_TASK (l7_es.rs)
//   - Windows: NT Kernel Logger Process/Start|End (l7_etw.rs)
//   - Linux: sched_process_exec/fork/exit tracepoints (l7_ebpf.rs)
//
// The stream is notify-only and fail-open: a backend that cannot start
// simply never pushes, and consumers observe that through the counters.
// Nothing in this module blocks, authorizes, or calls out (no I/O, no
// RPC, no LLM) -- it is a bounded in-memory ring plus atomic counters.
//
// Invariant I5 (VISIBILITYIMPROVEMENTS.md): argv routinely carries
// secrets, so raw argv NEVER enters the ring -- only a SHA-256 digest
// and the argument count. The per-process tables that some backends
// keep for attribution (e.g. `EsProcessInfo.args`) are separate,
// in-memory-only structures and are not part of this stream.

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use undeadlock::{CustomMutex, CustomMutexExt};

/// Bounded ring size. At a pathological 2,000 events/s (process storm)
/// this holds ~4 s of history; the point of the ring is "what just
/// happened around this finding", not long-term storage -- consumers
/// that need history drain it on their own cadence.
pub const PROCESS_EVENT_RING_MAX: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessEventKind {
    Exec,
    Fork,
    Exit,
    /// BS-9 observe: another process requested this target's task port
    /// (macOS `GET_TASK`) or equivalent memory-access primitive. The
    /// requestor is the event's `pid`; the victim is `target_pid`.
    TaskAccess,
}

/// One kernel-delivered process event. Fields that a platform cannot
/// vouch for are `None` (unmeasured) -- never fabricated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessEvent {
    /// Unix epoch milliseconds at kernel delivery (wall clock, same
    /// clock family as sessions and FIM events for temporal joins).
    pub timestamp_ms: u64,
    pub kind: ProcessEventKind,
    pub pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    pub process_name: String,
    pub process_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_process_path: Option<String>,
    /// I5: SHA-256 over the NUL-joined argv; `None` when the platform
    /// did not deliver argv for this event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argv_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argv_len: Option<u32>,
    /// Kernel-vouched signing identity (macOS ES delivers these in the
    /// exec message itself; `None` on other platforms = unmeasured,
    /// per the no-permissive-fallback rule).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_platform_binary: Option<bool>,
    /// `TaskAccess` only: the victim process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_process_path: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessEventCountersSnapshot {
    pub exec: u64,
    pub fork: u64,
    pub exit: u64,
    pub task_access: u64,
    /// Events evicted because the ring was full when they were pushed
    /// (the PUSH always succeeds; the oldest entry is dropped).
    pub evicted: u64,
    /// Events dropped because the ring lock was contended at push time.
    /// The push path is try-lock only -- a sensor thread (ES dispatch
    /// queue, eBPF consumer, ETW callback) must never block here -- so on
    /// the rare contention with a reader the event is dropped and counted.
    /// Expected to stay 0: pushes are effectively single-threaded per host.
    pub dropped_locked: u64,
}

struct Counters {
    exec: AtomicU64,
    fork: AtomicU64,
    exit: AtomicU64,
    task_access: AtomicU64,
    evicted: AtomicU64,
    dropped_locked: AtomicU64,
}

// undeadlock `CustomMutex` (not a raw `std::sync::Mutex`) so debug builds
// get the hold-time / contention diagnostics; accessed only through the
// non-blocking `try_with` (CustomMutexExt) because pushes come from
// synchronous kernel-callback threads that must never block or `.await`.
// `CustomMutex::new` is not const, so the ring is a `Lazy` static.
static RING: Lazy<CustomMutex<VecDeque<ProcessEvent>>> =
    Lazy::new(|| CustomMutex::new(VecDeque::new()));
static COUNTERS: Counters = Counters {
    exec: AtomicU64::new(0),
    fork: AtomicU64::new(0),
    exit: AtomicU64::new(0),
    task_access: AtomicU64::new(0),
    evicted: AtomicU64::new(0),
    dropped_locked: AtomicU64::new(0),
};

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// I5 digest: SHA-256 over the NUL-joined argv, lowercase hex. `None`
/// for an empty argv so "no argv delivered" and "argv was empty" both
/// read as unmeasured rather than as a stable-but-meaningless hash.
pub fn argv_digest(args: &[String]) -> Option<String> {
    if args.is_empty() {
        return None;
    }
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            hasher.update([0u8]);
        }
        hasher.update(arg.as_bytes());
    }
    Some(hex::encode(hasher.finalize()))
}

/// Push one event (called from kernel-event threads; must stay cheap and
/// never block). The ring is taken with a non-blocking try-lock: a sensor
/// thread must never stall, so on the (vanishingly rare) contention with a
/// reader the event is dropped and counted rather than blocking.
pub fn push(event: ProcessEvent) {
    let total_before = match event.kind {
        ProcessEventKind::Exec => COUNTERS.exec.fetch_add(1, Ordering::Relaxed),
        ProcessEventKind::Fork => COUNTERS.fork.fetch_add(1, Ordering::Relaxed),
        ProcessEventKind::Exit => COUNTERS.exit.fetch_add(1, Ordering::Relaxed),
        ProcessEventKind::TaskAccess => COUNTERS.task_access.fetch_add(1, Ordering::Relaxed),
    };
    // Throttled visibility so a hosting daemon's logs show the stream is
    // alive without per-event noise (validation on entitled hosts reads
    // exactly these lines).
    if total_before % 5000 == 0 {
        let snapshot = counters();
        tracing::info!(
            "process_events: exec={} fork={} exit={} task_access={} evicted={} dropped_locked={}",
            snapshot.exec,
            snapshot.fork,
            snapshot.exit,
            snapshot.task_access,
            snapshot.evicted,
            snapshot.dropped_locked
        );
    }
    let stored = RING.try_with(|ring| {
        if ring.len() >= PROCESS_EVENT_RING_MAX {
            ring.pop_front();
            COUNTERS.evicted.fetch_add(1, Ordering::Relaxed);
        }
        ring.push_back(event);
    });
    if stored.is_none() {
        COUNTERS.dropped_locked.fetch_add(1, Ordering::Relaxed);
    }
}

/// Newest-last copy of up to `limit` most recent events. Non-blocking:
/// returns empty if the ring lock is momentarily contended.
pub fn recent(limit: usize) -> Vec<ProcessEvent> {
    RING.try_with(|ring| {
        let skip = ring.len().saturating_sub(limit);
        ring.iter().skip(skip).cloned().collect()
    })
    .unwrap_or_default()
}

pub fn counters() -> ProcessEventCountersSnapshot {
    ProcessEventCountersSnapshot {
        exec: COUNTERS.exec.load(Ordering::Relaxed),
        fork: COUNTERS.fork.load(Ordering::Relaxed),
        exit: COUNTERS.exit.load(Ordering::Relaxed),
        task_access: COUNTERS.task_access.load(Ordering::Relaxed),
        evicted: COUNTERS.evicted.load(Ordering::Relaxed),
        dropped_locked: COUNTERS.dropped_locked.load(Ordering::Relaxed),
    }
}

/// Test-only: drain the ring (counters keep their totals; they are
/// monotonic by design).
pub fn clear_ring_for_tests() {
    RING.try_with(|ring| ring.clear());
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn ev(kind: ProcessEventKind, pid: u32) -> ProcessEvent {
        ProcessEvent {
            timestamp_ms: now_ms(),
            kind,
            pid,
            ppid: Some(1),
            uid: Some(501),
            process_name: "t".into(),
            process_path: format!("/bin/t{pid}"),
            parent_process_path: None,
            argv_sha256: None,
            argv_len: None,
            signing_id: None,
            team_id: None,
            is_platform_binary: None,
            target_pid: None,
            target_process_path: None,
        }
    }

    #[test]
    fn argv_digest_is_stable_and_separator_safe() {
        let a = argv_digest(&["a".into(), "b".into()]).unwrap();
        let b = argv_digest(&["a".into(), "b".into()]).unwrap();
        assert_eq!(a, b);
        // NUL joining must distinguish ["ab"] from ["a","b"].
        assert_ne!(argv_digest(&["ab".into()]).unwrap(), a);
        // Empty argv is unmeasured, not a constant hash.
        assert_eq!(argv_digest(&[]), None);
        assert_eq!(a.len(), 64);
    }

    #[test]
    #[serial]
    fn ring_is_bounded_ordered_and_counts_evictions() {
        clear_ring_for_tests();
        let evicted_before = counters().evicted;
        for pid in 0..(PROCESS_EVENT_RING_MAX as u32 + 10) {
            push(ev(ProcessEventKind::Exec, pid));
        }
        let all = recent(usize::MAX);
        assert_eq!(all.len(), PROCESS_EVENT_RING_MAX);
        // Oldest were evicted; newest-last ordering.
        assert_eq!(all.first().unwrap().pid, 10);
        assert_eq!(all.last().unwrap().pid, PROCESS_EVENT_RING_MAX as u32 + 9);
        assert_eq!(counters().evicted - evicted_before, 10);
        // Bounded fetch takes the newest tail.
        let tail = recent(3);
        assert_eq!(tail.len(), 3);
        assert_eq!(tail.last().unwrap().pid, PROCESS_EVENT_RING_MAX as u32 + 9);
        clear_ring_for_tests();
    }

    #[test]
    #[serial]
    fn serde_roundtrip_skips_unmeasured_fields() {
        let mut event = ev(ProcessEventKind::TaskAccess, 42);
        event.target_pid = Some(7);
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            !json.contains("signing_id"),
            "unmeasured fields elided: {json}"
        );
        assert!(json.contains("\"target_pid\":7"));
        let back: ProcessEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, event);
    }
}
