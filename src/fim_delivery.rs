//! Delivery probe for the file monitor: proves that file events reach the
//! watcher, rather than trusting that a watcher that was started still
//! delivers.
//!
//! `FimWatcher::is_running` is a flag set at start and cleared by `stop`. An
//! event source that dies underneath it (a backend thread gone, a stream the
//! OS dropped, a consumer that exited) leaves the flag up while nothing
//! arrives. The probe creates a file every [`PROBE_INTERVAL_SECS`] in a
//! directory of the process's own that the watcher also watches, and
//! records when the event for it comes back through the same path every
//! other event takes (`translate_notify_event_with_attribution`, whichever
//! source feeds it). A probe not seen within [`PROBE_ALLOWANCE_SECS`] means
//! events are not arriving.
//!
//! The probe directory is not a temp, sensitive or operator root, so another
//! file monitor on the same host drops its events by its ordinary rules;
//! this watcher recognises only the exact paths it created and keeps them
//! out of the event store.

use chrono::{DateTime, TimeZone, Utc};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use tracing::{debug, info, warn};

/// How often a probe is written.
pub const PROBE_INTERVAL_SECS: i64 = 30;

/// How long a probe may stay unseen before events read as not arriving: a
/// lost probe followed by a seen one is a hiccup, two in a row are not.
pub const PROBE_ALLOWANCE_SECS: i64 = 45;

/// The first probe waits for the event source to come up (an FSEvents
/// stream starts at `commit`, the Endpoint Security consumer a moment later).
const FIRST_PROBE_DELAY_SECS: u64 = 2;

/// Every probe file name starts with this; the event path checks it before
/// any lookup.
const PROBE_FILE_PREFIX: &str = "edamame-fim-probe-";

/// The delivery probe's record, as the status orders report it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FimDeliveryStatus {
    /// The directory the probe writes into; `None` when the watcher runs
    /// without a probe (no probe directory configured, or it could not be
    /// created or watched), so delivery is not measured.
    pub probe_dir: Option<String>,
    pub interval_secs: i64,
    pub probes_written: u64,
    pub probes_seen: u64,
    pub last_written_at: Option<DateTime<Utc>>,
    pub last_seen_at: Option<DateTime<Utc>>,
    /// The oldest probe written and not seen since.
    pub unseen_since: Option<DateTime<Utc>>,
    /// Why the last probe could not be written; cleared by a write that works.
    pub last_write_error: Option<String>,
}

impl FimDeliveryStatus {
    /// A watcher without a probe: `reason` says why.
    pub fn not_probed(reason: impl Into<String>) -> Self {
        Self {
            probe_dir: None,
            interval_secs: PROBE_INTERVAL_SECS,
            probes_written: 0,
            probes_seen: 0,
            last_written_at: None,
            last_seen_at: None,
            unseen_since: None,
            last_write_error: Some(reason.into()),
        }
    }

    /// What the record says about delivery at `now`.
    pub fn verdict(&self, now: DateTime<Utc>) -> FimDeliveryVerdict {
        if self.probe_dir.is_none() {
            return FimDeliveryVerdict::NotProbed(
                self.last_write_error
                    .clone()
                    .unwrap_or_else(|| "no delivery probe".to_string()),
            );
        }
        if let Some(since) = self.unseen_since {
            if now.signed_duration_since(since).num_seconds() >= PROBE_ALLOWANCE_SECS {
                return FimDeliveryVerdict::NotDelivering {
                    unseen_since: since,
                };
            }
        }
        if let Some(error) = &self.last_write_error {
            return FimDeliveryVerdict::NotProbed(format!(
                "the probe could not be written: {error}"
            ));
        }
        // A probe that stopped writing proves nothing about now.
        let stale_after = 3 * self.interval_secs.max(1);
        match self.last_written_at {
            Some(at) if now.signed_duration_since(at).num_seconds() > stale_after => {
                return FimDeliveryVerdict::NotProbed("the probe stopped writing".to_string());
            }
            _ => {}
        }
        match self.last_seen_at {
            Some(at) if self.probes_seen > 0 => FimDeliveryVerdict::Delivering { last_seen_at: at },
            _ => FimDeliveryVerdict::Pending,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FimDeliveryVerdict {
    /// Delivery is not measured; the string says why.
    NotProbed(String),
    /// No probe has come back yet, and none is overdue (just started).
    Pending,
    /// The last probe came back.
    Delivering { last_seen_at: DateTime<Utc> },
    /// A probe written at `unseen_since` has not come back within
    /// [`PROBE_ALLOWANCE_SECS`]: events are not arriving.
    NotDelivering { unseen_since: DateTime<Utc> },
}

/// One watcher's probe. Owned by the watcher; the writer thread and the
/// outstanding-path registry hold it weakly, so dropping the watcher ends
/// both.
pub(crate) struct DeliveryProbe {
    dir: PathBuf,
    interval_secs: i64,
    probes_written: AtomicU64,
    probes_seen: AtomicU64,
    /// Milliseconds since the epoch; 0 = never.
    last_written_ms: AtomicI64,
    last_seen_ms: AtomicI64,
    unseen_since_ms: AtomicI64,
    last_write_error: arc_swap::ArcSwapOption<String>,
}

/// A probe file not yet retired: its path spellings map here.
struct Outstanding {
    probe: Weak<DeliveryProbe>,
    written_ms: i64,
    seen: Arc<AtomicBool>,
}

/// Outstanding probe paths of every watcher in this process, keyed by
/// [`path_key`]. Exact paths only: a file named like a probe that this
/// process did not create is an ordinary file.
static OUTSTANDING: Lazy<DashMap<String, Outstanding>> = Lazy::new(DashMap::new);

/// The spelling an event path is compared in: `\` folded to `/`, lower
/// case (the probe names are unique; the comparison need not tell case).
fn path_key(path: &str) -> String {
    path.replace('\\', "/").to_lowercase()
}

fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

fn ms_to_time(ms: i64) -> Option<DateTime<Utc>> {
    if ms == 0 {
        None
    } else {
        Utc.timestamp_millis_opt(ms).single()
    }
}

/// Called for every path the event sources hand over: `true` when it is
/// one of this process's outstanding probe files, which is then counted as
/// seen and must not reach the store.
pub(crate) fn observe(path: &Path) -> bool {
    let raw = path.to_string_lossy();
    if !raw.contains(PROBE_FILE_PREFIX) {
        return false;
    }
    let key = path_key(&raw);
    // Out of the map before upgrading: the last strong reference dropping
    // here would run `Drop`, which writes the map.
    let (probe, seen) = match OUTSTANDING.get(&key) {
        Some(entry) => (entry.probe.clone(), entry.seen.clone()),
        None => return false,
    };
    if !seen.swap(true, Ordering::AcqRel) {
        if let Some(probe) = probe.upgrade() {
            probe.note_seen();
        }
    }
    true
}

impl DeliveryProbe {
    /// Create (when missing) and prepare `dir`. `None` when it cannot be
    /// used; the watcher then reports delivery as not probed.
    pub(crate) fn prepare(dir: &Path) -> std::result::Result<Arc<Self>, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        remove_leftovers(dir);
        Ok(Arc::new(Self {
            dir: dir.to_path_buf(),
            interval_secs: PROBE_INTERVAL_SECS,
            probes_written: AtomicU64::new(0),
            probes_seen: AtomicU64::new(0),
            last_written_ms: AtomicI64::new(0),
            last_seen_ms: AtomicI64::new(0),
            unseen_since_ms: AtomicI64::new(0),
            last_write_error: arc_swap::ArcSwapOption::empty(),
        }))
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    /// Start writing probes until `running` clears or the watcher drops the
    /// probe.
    pub(crate) fn spawn_writer(self: &Arc<Self>, running: Arc<AtomicBool>) {
        let weak = Arc::downgrade(self);
        let interval = std::time::Duration::from_secs(self.interval_secs.max(1) as u64);
        let spawned = std::thread::Builder::new()
            .name("fim-probe".into())
            .spawn(move || {
                let mut next = std::time::Instant::now()
                    + std::time::Duration::from_secs(FIRST_PROBE_DELAY_SECS);
                loop {
                    if !running.load(Ordering::SeqCst) {
                        break;
                    }
                    if std::time::Instant::now() >= next {
                        let Some(probe) = weak.upgrade() else {
                            break;
                        };
                        probe.write_one();
                        next = std::time::Instant::now() + interval;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                retire_outstanding(&weak, i64::MAX);
            });
        if let Err(e) = spawned {
            warn!("FIM: could not start the delivery probe: {}", e);
            self.last_write_error
                .store(Some(Arc::new(format!("probe thread: {e}"))));
        }
    }

    /// Write one probe: create a new file (never an existing path) and
    /// remove it; the create is what the event sources report.
    fn write_one(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        // Probes older than two intervals are retired: a late duplicate of
        // their event is ordinary noise by then (dropped by the early filter,
        // the probe directory being no root an event is kept for).
        retire_outstanding(&weak, now_ms() - 2 * self.interval_secs * 1000);
        remove_leftovers(&self.dir);

        let name = format!("{}{}", PROBE_FILE_PREFIX, uuid::Uuid::new_v4().simple());
        let path = self.dir.join(&name);
        let written_ms = now_ms();
        let seen = Arc::new(AtomicBool::new(false));
        let mut keys = vec![path_key(&path.to_string_lossy())];
        if let Ok(canonical_dir) = std::fs::canonicalize(&self.dir) {
            let key = path_key(&canonical_dir.join(&name).to_string_lossy());
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        for key in &keys {
            OUTSTANDING.insert(
                key.clone(),
                Outstanding {
                    probe: weak.clone(),
                    written_ms,
                    seen: seen.clone(),
                },
            );
        }
        // Recorded before the create: the event can come back before the
        // create call returns.
        let _ = self.unseen_since_ms.compare_exchange(
            0,
            written_ms,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => {
                drop(file);
                self.probes_written.fetch_add(1, Ordering::Relaxed);
                self.last_written_ms.store(written_ms, Ordering::Release);
                self.last_write_error.store(None);
                if let Err(e) = std::fs::remove_file(&path) {
                    debug!("FIM: delivery probe {} not removed: {}", path.display(), e);
                }
            }
            Err(e) => {
                for key in &keys {
                    OUTSTANDING.remove(key);
                }
                // Not a probe in flight: undo the mark set for it, unless an
                // earlier unseen probe set it.
                let _ = self.unseen_since_ms.compare_exchange(
                    written_ms,
                    0,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                debug!("FIM: delivery probe {} not written: {}", path.display(), e);
                self.last_write_error
                    .store(Some(Arc::new(format!("{}: {}", path.display(), e))));
            }
        }
    }

    fn note_seen(&self) {
        let seen = self.probes_seen.fetch_add(1, Ordering::Relaxed) + 1;
        self.last_seen_ms.store(now_ms(), Ordering::Release);
        let unseen_since = self.unseen_since_ms.swap(0, Ordering::AcqRel);
        if unseen_since != 0 && now_ms() - unseen_since >= PROBE_ALLOWANCE_SECS * 1000 && seen > 1 {
            info!(
                "FIM: file events are arriving again (a probe went unseen for {} s)",
                (now_ms() - unseen_since) / 1000
            );
        }
    }

    pub(crate) fn status(&self) -> FimDeliveryStatus {
        FimDeliveryStatus {
            probe_dir: Some(self.dir.to_string_lossy().to_string()),
            interval_secs: self.interval_secs,
            probes_written: self.probes_written.load(Ordering::Relaxed),
            probes_seen: self.probes_seen.load(Ordering::Relaxed),
            last_written_at: ms_to_time(self.last_written_ms.load(Ordering::Acquire)),
            last_seen_at: ms_to_time(self.last_seen_ms.load(Ordering::Acquire)),
            unseen_since: ms_to_time(self.unseen_since_ms.load(Ordering::Acquire)),
            last_write_error: self.last_write_error.load_full().map(|e| (*e).clone()),
        }
    }
}

impl Drop for DeliveryProbe {
    fn drop(&mut self) {
        // The owner is gone: its entries cannot upgrade any more.
        OUTSTANDING.retain(|_, entry| entry.probe.strong_count() > 0);
    }
}

/// Probe files a removal missed (a scanner holding the new file on Windows,
/// a process that ended between a create and its removal): nothing reads
/// them, and the directory must not grow.
fn remove_leftovers(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(PROBE_FILE_PREFIX)
            {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// Drop `probe`'s outstanding entries written before `before_ms` (and
/// every entry whose probe is gone).
fn retire_outstanding(probe: &Weak<DeliveryProbe>, before_ms: i64) {
    OUTSTANDING.retain(|_, entry| {
        entry.probe.strong_count() > 0
            && !(Weak::ptr_eq(&entry.probe, probe) && entry.written_ms < before_ms)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn status_at(
        written: Option<DateTime<Utc>>,
        seen: Option<DateTime<Utc>>,
        unseen_since: Option<DateTime<Utc>>,
        probes_seen: u64,
    ) -> FimDeliveryStatus {
        FimDeliveryStatus {
            probe_dir: Some("/probe".to_string()),
            interval_secs: PROBE_INTERVAL_SECS,
            probes_written: if written.is_some() { 1 } else { 0 },
            probes_seen,
            last_written_at: written,
            last_seen_at: seen,
            unseen_since,
            last_write_error: None,
        }
    }

    #[test]
    fn a_probe_that_does_not_come_back_reads_not_delivering_after_the_allowance() {
        let now = Utc::now();
        // Just started: nothing written or seen yet.
        assert_eq!(
            status_at(None, None, None, 0).verdict(now),
            FimDeliveryVerdict::Pending
        );
        // Written, not back yet, within the allowance.
        let written = now - Duration::seconds(10);
        assert_eq!(
            status_at(Some(written), None, Some(written), 0).verdict(now),
            FimDeliveryVerdict::Pending
        );
        // One lost probe, the next one came back: delivering.
        let seen = now - Duration::seconds(2);
        assert_eq!(
            status_at(Some(written), Some(seen), None, 1).verdict(now),
            FimDeliveryVerdict::Delivering { last_seen_at: seen }
        );
        // Unseen past the allowance, even with earlier probes seen.
        let stuck = now - Duration::seconds(PROBE_ALLOWANCE_SECS);
        assert_eq!(
            status_at(
                Some(now - Duration::seconds(5)),
                Some(stuck - Duration::seconds(30)),
                Some(stuck),
                7
            )
            .verdict(now),
            FimDeliveryVerdict::NotDelivering {
                unseen_since: stuck
            }
        );
    }

    #[test]
    fn delivery_is_not_probed_without_a_probe_or_a_probe_that_writes() {
        let now = Utc::now();
        assert_eq!(
            FimDeliveryStatus::not_probed("no probe directory").verdict(now),
            FimDeliveryVerdict::NotProbed("no probe directory".to_string())
        );
        let mut failed = status_at(None, None, None, 0);
        failed.last_write_error = Some("permission denied".to_string());
        assert!(matches!(
            failed.verdict(now),
            FimDeliveryVerdict::NotProbed(_)
        ));
        // A probe that stopped writing long ago proves nothing about now.
        let old = now - Duration::seconds(10 * PROBE_INTERVAL_SECS);
        assert!(matches!(
            status_at(Some(old), Some(old), None, 3).verdict(now),
            FimDeliveryVerdict::NotProbed(_)
        ));
    }

    #[test]
    fn only_the_exact_outstanding_probe_paths_are_recognised() {
        let dir = tempfile::tempdir().expect("temp dir");
        let probe = DeliveryProbe::prepare(dir.path()).expect("prepare");
        probe.write_one();
        assert_eq!(probe.status().probes_written, 1);
        let outstanding: Vec<String> = OUTSTANDING
            .iter()
            .filter(|e| Weak::ptr_eq(&e.probe, &Arc::downgrade(&probe)))
            .map(|e| e.key().clone())
            .collect();
        assert!(!outstanding.is_empty());
        // A file named like a probe that this process did not create is an
        // ordinary file.
        let impostor = dir.path().join(format!("{}deadbeef", PROBE_FILE_PREFIX));
        assert!(!observe(&impostor));
        assert!(!observe(&dir.path().join("ordinary.txt")));
        // The probe's own path is recognised, counted once.
        let own = PathBuf::from(&outstanding[0]);
        assert!(observe(&own));
        assert!(observe(&own));
        let status = probe.status();
        assert_eq!(status.probes_seen, 1);
        assert!(status.unseen_since.is_none());
        assert!(matches!(
            status.verdict(Utc::now()),
            FimDeliveryVerdict::Delivering { .. }
        ));
        // The probe file itself was removed after the create.
        let left: Vec<_> = std::fs::read_dir(dir.path()).unwrap().flatten().collect();
        assert!(left.is_empty(), "probe files left behind: {left:?}");
        drop(probe);
        assert!(!observe(&own), "a dropped probe's paths are retired");
    }
}
