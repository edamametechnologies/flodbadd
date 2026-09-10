//! Endpoint Security as the FIM event source on macOS (FLODBADD2 §1b.2,
//! "ES as the FIM event source").
//!
//! Until 2026-09-08 the macOS FIM ran on FSEvents (`notify`) and only asked
//! Endpoint Security *who* wrote a path after the fact. ES already delivers
//! every CREATE / WRITE / modified CLOSE / RENAME / UNLINK on the volume with
//! the writer's pid and image, so the watcher now consumes those directly:
//! kernel-time events, attribution attached at event time, no lookup race,
//! no `lsof`. FSEvents stays as the fallback when the ES client is
//! unavailable (no entitlement, not root).
//!
//! The ES stream is volume-wide; the sink filters by the FIM roots *inside
//! the ES handler* before anything crosses to the watcher thread, so build
//! trees and browser caches never leave the callback. Recursion follows
//! the watcher config: recursive roots accept every descendant, otherwise
//! only direct children.

use once_cell::sync::OnceCell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::time::{Duration, Instant};

/// Bounded hand-off from the ES dispatch queue to the FIM consumer thread.
const CHANNEL_CAPACITY: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FimSourceKind {
    Create,
    Modify,
    Rename,
    Delete,
}

/// One kernel-delivered file event under a FIM root, with the writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FimSourceEvent {
    pub kind: FimSourceKind,
    pub path: String,
    pub pid: u32,
    pub process_name: String,
    pub process_path: String,
}

struct Sink {
    roots: Vec<String>,
    recursive: bool,
    tx: SyncSender<FimSourceEvent>,
    delivered: AtomicU64,
    dropped_full: AtomicU64,
}

static SINK: OnceCell<Sink> = OnceCell::new();

// Root matching lives in `fim_attribution` so the sink filter here and the
// attribution confinement in the sensors cannot drift apart.
pub use crate::fim_attribution::{normalize, path_under_root};

/// Install the sink for the given roots (raw and canonical spellings are
/// both kept: ES reports `/private/var/...` while callers often pass
/// `/var/...`). Returns the receiver the watcher consumes. `None` when a
/// sink is already installed.
pub fn install(roots: &[PathBuf], recursive: bool) -> Option<Receiver<FimSourceEvent>> {
    if SINK.get().is_some() {
        return None;
    }
    let mut set = std::collections::BTreeSet::new();
    for root in roots {
        let raw = normalize(&root.to_string_lossy());
        if !raw.is_empty() {
            set.insert(raw);
        }
        if let Ok(canonical) = std::fs::canonicalize(root) {
            let canonical = normalize(&canonical.to_string_lossy());
            if !canonical.is_empty() {
                set.insert(canonical);
            }
        }
    }
    let (tx, rx) = std::sync::mpsc::sync_channel(CHANNEL_CAPACITY);
    let sink = Sink {
        roots: set.into_iter().collect(),
        recursive,
        tx,
        delivered: AtomicU64::new(0),
        dropped_full: AtomicU64::new(0),
    };
    SINK.set(sink).ok()?;
    Some(rx)
}

pub fn is_active() -> bool {
    SINK.get().is_some()
}

/// `(delivered, dropped_because_full)` since install.
pub fn stats() -> (u64, u64) {
    SINK.get()
        .map(|s| {
            (
                s.delivered.load(Ordering::Relaxed),
                s.dropped_full.load(Ordering::Relaxed),
            )
        })
        .unwrap_or((0, 0))
}

/// Called from the ES handler for every file event it records. Cheap when
/// no sink is installed or the path is outside every root.
pub fn push(kind: FimSourceKind, path: &str, pid: u32, process_name: &str, process_path: &str) {
    let Some(sink) = SINK.get() else {
        return;
    };
    let normalized = normalize(path);
    if !sink
        .roots
        .iter()
        .any(|root| path_under_root(&normalized, root, sink.recursive))
    {
        return;
    }
    let event = FimSourceEvent {
        kind,
        path: path.to_string(),
        pid,
        process_name: process_name.to_string(),
        process_path: process_path.to_string(),
    };
    match sink.tx.try_send(event) {
        Ok(()) => {
            sink.delivered.fetch_add(1, Ordering::Relaxed);
        }
        Err(TrySendError::Full(_)) => {
            sink.dropped_full.fetch_add(1, Ordering::Relaxed);
        }
        Err(TrySendError::Disconnected(_)) => {}
    }
}

/// ES emits WRITE once per open and a modified CLOSE on top; a writer that
/// appends in bursts produces several of each. FSEvents coalesced these for
/// free; the consumer does it here: a Modify within `window` of the previous
/// Modify for the same path is dropped.
pub struct Coalescer {
    window: Duration,
    last_modify: std::collections::HashMap<String, Instant>,
}

impl Coalescer {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            last_modify: std::collections::HashMap::new(),
        }
    }

    /// `true` when the event should be forwarded.
    pub fn admit(&mut self, event: &FimSourceEvent, now: Instant) -> bool {
        if event.kind != FimSourceKind::Modify {
            self.last_modify.remove(&event.path);
            return true;
        }
        if self.last_modify.len() > 8192 {
            let window = self.window;
            self.last_modify
                .retain(|_, seen| now.duration_since(*seen) < window);
        }
        match self.last_modify.get(&event.path) {
            Some(seen) if now.duration_since(*seen) < self.window => false,
            _ => {
                self.last_modify.insert(event.path.clone(), now);
                true
            }
        }
    }
}

/// Convenience for the watcher: the roots as `Path`s for logging.
pub fn root_count() -> usize {
    SINK.get().map(|s| s.roots.len()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_matching_follows_recursion_mode() {
        assert!(path_under_root(
            "/users/me/.ssh/id_rsa",
            "/users/me/.ssh",
            false
        ));
        assert!(path_under_root(
            "/users/me/.ssh/id_rsa",
            "/users/me/.ssh",
            true
        ));
        assert!(!path_under_root(
            "/users/me/.ssh/sub/key",
            "/users/me/.ssh",
            false
        ));
        assert!(path_under_root(
            "/users/me/.ssh/sub/key",
            "/users/me/.ssh",
            true
        ));
        // Sibling sharing the prefix, and the root itself, never match.
        assert!(!path_under_root(
            "/users/me/.sshd/x",
            "/users/me/.ssh",
            true
        ));
        assert!(!path_under_root("/users/me/.ssh", "/users/me/.ssh", true));
        assert!(!path_under_root("/tmp/x", "", true));
    }

    #[test]
    fn coalescer_drops_modify_bursts_but_never_creates_or_deletes() {
        let mut c = Coalescer::new(Duration::from_millis(500));
        let ev = |kind| FimSourceEvent {
            kind,
            path: "/tmp/a".into(),
            pid: 1,
            process_name: "x".into(),
            process_path: "/x".into(),
        };
        let t0 = Instant::now();
        assert!(c.admit(&ev(FimSourceKind::Create), t0));
        assert!(c.admit(&ev(FimSourceKind::Modify), t0));
        assert!(!c.admit(&ev(FimSourceKind::Modify), t0 + Duration::from_millis(100)));
        assert!(c.admit(&ev(FimSourceKind::Modify), t0 + Duration::from_millis(700)));
        assert!(c.admit(&ev(FimSourceKind::Delete), t0 + Duration::from_millis(710)));
        // A delete resets the window: the next modify is a new file.
        assert!(c.admit(&ev(FimSourceKind::Modify), t0 + Duration::from_millis(720)));
    }
}
