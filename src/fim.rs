use crate::fim_events::{
    is_temp_directory_path, FimEvent, FimEventStore, FimEventType, FIM_HASH_SIZE_THRESHOLD,
};
use crate::open_files::is_sensitive_path;
use crate::sensitive_paths::{classify_sensitive_path_labels_sync, is_fim_excluded_path};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use tokio::sync::RwLock as TokioRwLock;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use dashmap::DashMap;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use once_cell::sync::Lazy;
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use std::time::Instant;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System};
use tracing::{debug, error, info, warn};

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
const FIM_ATTRIBUTION_CACHE_TTL_SECS: u64 = 10;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
const FIM_ATTRIBUTION_CACHE_MAX_ENTRIES: usize = 5_000;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
const FIM_ATTRIBUTION_CACHE_PRUNE_INTERVAL: u64 = 500;
#[cfg(target_os = "windows")]
const FIM_HASH_WORK_QUEUE_CAPACITY: usize = 2_048;
#[cfg(target_os = "windows")]
const FIM_HASH_QUIET_DELAY_MS: u64 = 250;

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
struct CachedAttribution {
    process_name: Option<String>,
    process_path: Option<String>,
    recorded_at: Instant,
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
static FIM_ATTRIBUTION_CACHE: Lazy<DashMap<String, CachedAttribution>> = Lazy::new(DashMap::new);

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
static FIM_CACHE_INSERT_COUNTER: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn prune_attribution_cache() {
    let cutoff = Instant::now() - std::time::Duration::from_secs(FIM_ATTRIBUTION_CACHE_TTL_SECS);
    FIM_ATTRIBUTION_CACHE.retain(|_, v| v.recorded_at > cutoff);

    if FIM_ATTRIBUTION_CACHE.len() > FIM_ATTRIBUTION_CACHE_MAX_ENTRIES {
        let mut entries: Vec<_> = FIM_ATTRIBUTION_CACHE
            .iter()
            .map(|e| (e.key().clone(), e.value().recorded_at))
            .collect();
        entries.sort_by_key(|(_, ts)| *ts);
        let to_remove = entries.len() - FIM_ATTRIBUTION_CACHE_MAX_ENTRIES;
        for (key, _) in entries.into_iter().take(to_remove) {
            FIM_ATTRIBUTION_CACHE.remove(&key);
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn cache_attribution(path: &str, process_name: &Option<String>, process_path: &Option<String>) {
    FIM_ATTRIBUTION_CACHE.insert(
        path.to_string(),
        CachedAttribution {
            process_name: process_name.clone(),
            process_path: process_path.clone(),
            recorded_at: Instant::now(),
        },
    );

    let count = FIM_CACHE_INSERT_COUNTER.fetch_add(1, Ordering::Relaxed);
    if count % FIM_ATTRIBUTION_CACHE_PRUNE_INTERVAL == 0 && count > 0 {
        prune_attribution_cache();
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn lookup_cache(path: &str) -> Option<(Option<String>, Option<String>)> {
    let entry = FIM_ATTRIBUTION_CACHE.get(path)?;
    if entry.recorded_at.elapsed().as_secs() > FIM_ATTRIBUTION_CACHE_TTL_SECS {
        return None;
    }
    Some((entry.process_name.clone(), entry.process_path.clone()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FimMode {
    CI,
    Desktop,
}

#[derive(Debug, Clone)]
pub struct FimConfig {
    pub hash_size_threshold: u64,
    pub recursive: bool,
}

impl Default for FimConfig {
    fn default() -> Self {
        Self {
            hash_size_threshold: FIM_HASH_SIZE_THRESHOLD,
            recursive: true,
        }
    }
}

pub struct FimWatcher {
    _watcher: RecommendedWatcher,
    store: Arc<FimEventStore>,
    watch_paths: Vec<PathBuf>,
    running: Arc<AtomicBool>,
    /// Wall-clock time of the last `get_events(incremental=true)` call.
    /// Mirrors `FlodbaddCapture::last_get_sessions_fetch_timestamp`. The next
    /// incremental call returns only events whose `last_modified` is strictly
    /// newer than this timestamp, so backfilled attribution / content-hash
    /// updates on existing events are picked up alongside fresh inserts.
    last_get_file_events_fetch_timestamp: Arc<TokioRwLock<DateTime<Utc>>>,
    #[cfg(target_os = "windows")]
    _hash_worker: Option<std::thread::JoinHandle<()>>,
}

pub const FIM_PROCESS_ATTRIBUTION_BACKFILL_LIMIT: usize = 128;

impl FimWatcher {
    pub fn start(paths: Vec<PathBuf>, config: FimConfig) -> Result<Self> {
        crate::l7_es::init_and_log_status();

        let store = Arc::new(FimEventStore::new());
        let running = Arc::new(AtomicBool::new(true));

        #[cfg(target_os = "windows")]
        let (hash_tx, hash_rx) = std::sync::mpsc::sync_channel(FIM_HASH_WORK_QUEUE_CAPACITY);
        #[cfg(target_os = "windows")]
        let hash_worker = Some(
            spawn_fim_hash_worker(store.clone(), running.clone(), hash_rx)
                .context("Failed to spawn FIM hash worker")?,
        );

        #[cfg(target_os = "linux")]
        check_inotify_limits(paths.len());

        // The watcher closure needs a forward-slash-normalized snapshot of
        // the explicit watch roots so the early-drop gate
        // (`should_keep_fim_event`) can accept any event under an operator-
        // requested path even when that path is non-sensitive AND non-temp
        // (e.g. a custom audit directory). Built once at start time so the
        // closure does not need to re-walk `paths` on every event.
        //
        // We store BOTH the original path and the `canonicalize()` result
        // for each input. macOS FSEvents reports events under the realpath
        // (`/private/var/folders/...`) while `tempfile` and most callers
        // pass the symlink-relative form (`/var/folders/...`); on Linux
        // /tmp may also be a symlink in some distros. Storing both shapes
        // makes the prefix match work under either reporting convention.
        let mut explicit_set: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        for p in &paths {
            let raw = p.to_string_lossy().replace('\\', "/");
            if !raw.is_empty() {
                explicit_set.insert(raw);
            }
            if let Ok(canon) = std::fs::canonicalize(p) {
                let canon_str = canon.to_string_lossy().replace('\\', "/");
                if !canon_str.is_empty() {
                    explicit_set.insert(canon_str);
                }
            }
        }
        let explicit_watch_roots: Arc<Vec<String>> = Arc::new(explicit_set.into_iter().collect());

        let store_clone = store.clone();
        let hash_threshold = config.hash_size_threshold;
        let explicit_clone = explicit_watch_roots.clone();
        #[cfg(target_os = "windows")]
        let hash_tx_clone = hash_tx.clone();
        let mut watcher = RecommendedWatcher::new(
            move |result: std::result::Result<Event, notify::Error>| match result {
                Ok(event) => {
                    if let Some(fim_events) =
                        translate_notify_event(&event, hash_threshold, explicit_clone.as_ref())
                    {
                        for fim_event in fim_events {
                            // FP-CI-2: only queue deferred content hashing for
                            // sensitive paths. Non-sensitive events (temp-staging
                            // and explicit-watch-root churn) bypass the hash
                            // worker entirely, preventing the Win32 sharing
                            // asymmetry where our FIM read-handle conflicts with
                            // build-tool exclusive opens on transient artifacts
                            // (Dart pub temp, MSBuild tlog, .vcxproj, target/,
                            // MSIX intermediate files, ...).
                            #[cfg(target_os = "windows")]
                            let hash_work = if fim_event.is_sensitive {
                                fim_hash_work_item_for_event(&fim_event, hash_threshold)
                            } else {
                                None
                            };
                            store_clone.insert(fim_event);
                            #[cfg(target_os = "windows")]
                            if let Some(hash_work) = hash_work {
                                queue_fim_hash_work(&hash_tx_clone, hash_work);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("FIM watcher error: {:?}", e);
                }
            },
            Config::default(),
        )
        .context("Failed to create FIM watcher")?;

        let mode = if config.recursive {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };

        let mut actual_paths = Vec::new();
        for path in &paths {
            if path.exists() {
                if let Err(e) = watcher.watch(path, mode) {
                    warn!("FIM: failed to watch {}: {}", path.display(), e);
                } else {
                    info!("FIM: watching {}", path.display());
                    actual_paths.push(path.clone());
                }
            } else {
                debug!("FIM: skipping non-existent path {}", path.display());
            }
        }

        if actual_paths.is_empty() {
            warn!("FIM: no valid watch paths, watcher started but inactive");
        }

        Ok(Self {
            _watcher: watcher,
            store,
            watch_paths: actual_paths,
            running,
            last_get_file_events_fetch_timestamp: Arc::new(TokioRwLock::new(Utc::now())),
            #[cfg(target_os = "windows")]
            _hash_worker: hash_worker,
        })
    }

    pub fn stop(self) {
        self.running.store(false, Ordering::SeqCst);
        info!("FIM: watcher stopped");
    }

    pub fn store(&self) -> &FimEventStore {
        &self.store
    }

    /// Return a clonable handle to the event store so callers can drop any
    /// outer guard (e.g. a `FIM_WATCHER` `RwLock` read guard) before doing
    /// slow work like live process attribution probing or JSON serialization.
    /// `FimEventStore` is internally lock-free (DashMap), so concurrent
    /// readers are safe and writers (e.g. `start_file_monitor`) won't be
    /// starved.
    pub fn store_arc(&self) -> Arc<FimEventStore> {
        self.store.clone()
    }

    pub fn watch_paths(&self) -> &[PathBuf] {
        &self.watch_paths
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Clone the cursor handle (`Arc<RwLock<DateTime<Utc>>>`) so callers can
    /// drive the incremental fetch loop without holding any outer
    /// `FIM_WATCHER` read guard while waiting on the cursor lock. The cursor
    /// is shared with `get_events` and is advanced unconditionally on each
    /// call to it.
    pub fn fetch_cursor(&self) -> Arc<TokioRwLock<DateTime<Utc>>> {
        self.last_get_file_events_fetch_timestamp.clone()
    }

    /// Return FIM events, optionally incrementally based on `last_modified`.
    /// Mirrors `FlodbaddCapture::get_sessions(incremental: bool)`:
    /// - read the cursor lock, capture `now = Utc::now()`
    /// - call `store.get_events_modified_since(last_ts)` when `incremental`,
    ///   else `store.get_all_events()`
    /// - write `now` back into the cursor lock unconditionally so the next
    ///   caller resumes from there
    ///
    /// Incremental callers must tolerate occasional duplicates around the
    /// instant the cursor is advanced; the merge layer (helper-side or core-
    /// side cache) keys by `uid` so re-emitting an event is idempotent.
    pub async fn get_events(&self, incremental: bool) -> Vec<FimEvent> {
        let now = Utc::now();
        let last_fetch_ts = {
            let reader = self.last_get_file_events_fetch_timestamp.read().await;
            *reader
        };

        let events = if incremental {
            self.store.get_events_modified_since(last_fetch_ts)
        } else {
            self.store.get_all_events()
        };

        let mut writer = self.last_get_file_events_fetch_timestamp.write().await;
        *writer = now;

        events
    }
}

/// Decide whether a raw notify event for `path_str` is worth promoting to a
/// `FimEvent`. The detector pipeline only consumes sensitive findings and
/// suspicious temp staging, so churn from build trees, browser caches, and
/// other dev-machine noise is dropped here BEFORE we hash the file or run
/// process attribution -- both of which dominate FIM CPU on busy hosts
/// (FP-FIM-CPU-1).
///
/// Accept rules (any one is enough):
/// 1. The path matches a sensitive credential pattern shipped via the
///    CloudModel (`is_sensitive_path`), OR
/// 2. The path is in a temp-staging directory recognized by
///    `is_temp_directory_path` (canonical malware drop sites), OR
/// 3. The path is under one of the operator-requested explicit watch
///    roots (`explicit_watch_roots`). Operators that hand a custom
///    audit dir to `FimWatcher::start` deliberately want everything
///    under it tracked.
///
/// Reject rule (overrides ALL accept rules):
/// - The path matches one of the build-output / browser-cache patterns
///   shipped via `sensitive-paths-db.json::fim_excluded_path_patterns`
///   (`is_fim_excluded_path`). These are structurally noisy --
///   `target/release/`, `node_modules/`, browser `Code Cache`, ... --
///   and have no security-relevant signal even if they happen to live
///   under a sensitive watch root.
fn should_keep_fim_event(path_str: &str, explicit_watch_roots: &[String]) -> (bool, bool) {
    if is_fim_excluded_path(path_str) {
        return (false, false);
    }

    let sensitive = is_sensitive_path(path_str);
    if sensitive {
        return (true, true);
    }

    let normalized = path_str.replace('\\', "/");
    if is_temp_directory_path(&normalized) {
        return (true, false);
    }

    let lower_normalized = normalized.to_lowercase();
    let under_explicit = explicit_watch_roots.iter().any(|root| {
        if root.is_empty() {
            return false;
        }
        let root_lower = root.to_lowercase();
        lower_normalized == root_lower || lower_normalized.starts_with(&format!("{}/", root_lower))
    });

    if under_explicit {
        return (true, false);
    }

    (false, false)
}

fn translate_notify_event(
    event: &Event,
    hash_threshold: u64,
    explicit_watch_roots: &[String],
) -> Option<Vec<FimEvent>> {
    #[cfg(target_os = "windows")]
    let _ = hash_threshold;

    let event_type = match &event.kind {
        EventKind::Create(_) => FimEventType::Create,
        EventKind::Modify(modify_kind) => match modify_kind {
            notify::event::ModifyKind::Name(_) => FimEventType::Rename,
            _ => FimEventType::Modify,
        },
        EventKind::Remove(_) => FimEventType::Delete,
        _ => return None,
    };

    let mut fim_events = Vec::new();
    for path in &event.paths {
        let path_str = path.to_string_lossy().to_string();

        // Early-drop: skip hashing, attribution, and store insertion for
        // events that fall outside the sensitive / temp / explicit-watch
        // accept set, OR that match the build-output exclusion list.
        let (keep, sensitive) = should_keep_fim_event(&path_str, explicit_watch_roots);
        if !keep {
            continue;
        }

        // FP-CI-2: gate content hashing on `sensitive`. Non-sensitive
        // events (temp-staging files, files under operator-specified
        // explicit watch roots) get `hash = None` because the downstream
        // detector only consumes the hash for change-tracking of
        // *sensitive* findings -- it never alerts on non-sensitive hash
        // values. Hashing them anyway opens a file handle that races
        // with build-tool exclusive opens (Win32 sharing asymmetry),
        // causing FP-CI-2 MSB8066 "process cannot access the file"
        // failures on Windows runners, and is wasted I/O everywhere else.
        let (size, hash) = if event_type != FimEventType::Delete && path.is_file() {
            #[cfg(target_os = "windows")]
            {
                (get_file_size_metadata(path), None)
            }
            #[cfg(not(target_os = "windows"))]
            {
                if sensitive {
                    get_file_metadata(path, hash_threshold)
                } else {
                    (get_file_size_metadata(path), None)
                }
            }
        } else {
            (None, None)
        };

        let labels = classify_sensitive_path_labels_sync(&[path_str.clone()]);
        // Attribution is expensive and platform-dependent, so only attempt it for
        // sensitive or temp-ish paths that are likely to matter for vuln correlation.
        let (process_name, process_path) =
            best_effort_process_attribution(path, sensitive, event_type);

        let ts = Utc::now();
        let uid = FimEvent::compute_uid(&path_str, &event_type, &ts);

        fim_events.push(FimEvent {
            path: path_str,
            event_type,
            timestamp: ts,
            size,
            hash,
            process_name,
            process_path,
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: sensitive,
            labels,
            uid,
            last_modified: ts,
        });
    }

    if fim_events.is_empty() {
        None
    } else {
        Some(fim_events)
    }
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
struct FimHashWorkItem {
    uid: String,
    path: PathBuf,
    size: u64,
    hash_threshold: u64,
    ready_at: std::time::Instant,
}

#[cfg(target_os = "windows")]
fn fim_hash_work_item_for_event(event: &FimEvent, hash_threshold: u64) -> Option<FimHashWorkItem> {
    if event.event_type == FimEventType::Delete {
        return None;
    }

    let size = event.size?;
    if size > hash_threshold {
        return None;
    }

    Some(FimHashWorkItem {
        uid: event.uid.clone(),
        path: PathBuf::from(&event.path),
        size,
        hash_threshold,
        ready_at: std::time::Instant::now()
            + std::time::Duration::from_millis(FIM_HASH_QUIET_DELAY_MS),
    })
}

#[cfg(target_os = "windows")]
fn queue_fim_hash_work(
    hash_tx: &std::sync::mpsc::SyncSender<FimHashWorkItem>,
    hash_work: FimHashWorkItem,
) {
    match hash_tx.try_send(hash_work) {
        Ok(()) => {}
        Err(std::sync::mpsc::TrySendError::Full(_)) => {
            debug!("FIM: dropping content-hash work item because queue is full");
        }
        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
            debug!("FIM: dropping content-hash work item because worker stopped");
        }
    }
}

#[cfg(target_os = "windows")]
fn spawn_fim_hash_worker(
    store: Arc<FimEventStore>,
    running: Arc<AtomicBool>,
    hash_rx: std::sync::mpsc::Receiver<FimHashWorkItem>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("fim-hash-worker".into())
        .spawn(move || {
            let mut pending = std::collections::VecDeque::new();
            while running.load(Ordering::SeqCst) {
                while let Ok(hash_work) = hash_rx.try_recv() {
                    pending.push_back(hash_work);
                }

                if let Some(hash_work) = pending.pop_front() {
                    let now = std::time::Instant::now();
                    if hash_work.ready_at > now {
                        let wait = hash_work
                            .ready_at
                            .duration_since(now)
                            .min(std::time::Duration::from_millis(100));
                        pending.push_front(hash_work);
                        match hash_rx.recv_timeout(wait) {
                            Ok(new_work) => pending.push_back(new_work),
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    } else {
                        process_fim_hash_work_item(&store, hash_work);
                    }
                } else {
                    match hash_rx.recv_timeout(std::time::Duration::from_millis(100)) {
                        Ok(hash_work) => pending.push_back(hash_work),
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            }
        })
}

#[cfg(target_os = "windows")]
fn process_fim_hash_work_item(store: &FimEventStore, hash_work: FimHashWorkItem) -> bool {
    let Some(hash) = compute_hash_for_work_item(&hash_work) else {
        return false;
    };

    store.update_content_hash(&hash_work.uid, Some(hash));
    true
}

#[cfg(target_os = "windows")]
fn compute_hash_for_work_item(hash_work: &FimHashWorkItem) -> Option<String> {
    if hash_work.size > hash_work.hash_threshold {
        return None;
    }

    let current_size = get_file_size_metadata(&hash_work.path)?;
    if current_size != hash_work.size || current_size > hash_work.hash_threshold {
        return None;
    }

    match read_file_for_fim_hash(&hash_work.path) {
        Ok(data) => Some(blake3::hash(&data).to_hex().to_string()),
        Err(e) => {
            if matches!(e.raw_os_error(), Some(32 | 33)) {
                debug!(
                    "FIM: skipped deferred content hash for {} due to sharing/lock violation",
                    hash_work.path.display()
                );
            } else {
                debug!(
                    "FIM: skipped deferred content hash for {}: {}",
                    hash_work.path.display(),
                    e
                );
            }
            None
        }
    }
}

fn get_file_size_metadata(path: &Path) -> Option<u64> {
    std::fs::metadata(path).ok().map(|meta| meta.len())
}

#[cfg(not(target_os = "windows"))]
fn get_file_metadata(path: &Path, hash_threshold: u64) -> (Option<u64>, Option<String>) {
    match get_file_size_metadata(path) {
        Some(size) => {
            let hash = if size <= hash_threshold {
                match read_file_for_fim_hash(path) {
                    Ok(data) => Some(blake3::hash(&data).to_hex().to_string()),
                    Err(_) => None,
                }
            } else {
                None
            };
            (Some(size), hash)
        }
        None => (None, None),
    }
}

#[cfg(target_os = "windows")]
fn read_file_for_fim_hash(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;

    let mut file = open_file_for_fim_hash(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}

#[cfg(target_os = "windows")]
fn open_file_for_fim_hash(path: &Path) -> std::io::Result<std::fs::File> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_SHARE_READ: u32 = 0x00000001;
    const FILE_SHARE_WRITE: u32 = 0x00000002;
    const FILE_SHARE_DELETE: u32 = 0x00000004;

    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path)
}

#[cfg(not(target_os = "windows"))]
fn read_file_for_fim_hash(path: &Path) -> std::io::Result<Vec<u8>> {
    std::fs::read(path)
}

fn should_attempt_process_attribution(
    path: &Path,
    is_sensitive: bool,
    event_type: FimEventType,
) -> bool {
    if is_sensitive {
        return true;
    }

    if event_type == FimEventType::Delete {
        return false;
    }

    let path_str = path.to_string_lossy();
    path_str.contains("/tmp/")
        || path_str.contains("/var/tmp/")
        || path_str.contains("/private/tmp/")
        || path_str.contains("\\Temp\\")
        || path_str.contains("\\AppData\\Local\\Temp\\")
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn best_effort_process_attribution(
    path: &Path,
    is_sensitive: bool,
    event_type: FimEventType,
) -> (Option<String>, Option<String>) {
    if !should_attempt_process_attribution(path, is_sensitive, event_type) {
        return (None, None);
    }

    let path_str = path.to_string_lossy();

    // Tier 1: ES file attribution table (macOS only, zero-cost on other platforms)
    if let Some((_pid, name, proc_path)) = crate::l7_es::get_file_attribution(&path_str) {
        return (Some(name), Some(proc_path));
    }

    // Tier 2: in-memory lsof result cache
    if let Some((name, proc_path)) = lookup_cache(&path_str) {
        if name.is_some() || proc_path.is_some() {
            return (name, proc_path);
        }
    }

    // Tier 3: live lsof + sysinfo
    let (pid, fallback_name) = match lookup_pid_for_path(path) {
        Some(details) => details,
        None => return (None, None),
    };

    let result = lookup_process_details(pid, fallback_name);
    if result.0.is_some() || result.1.is_some() {
        cache_attribution(&path_str, &result.0, &result.1);
    }
    result
}

#[cfg(target_os = "windows")]
fn best_effort_process_attribution(
    path: &Path,
    is_sensitive: bool,
    event_type: FimEventType,
) -> (Option<String>, Option<String>) {
    if !should_attempt_process_attribution(path, is_sensitive, event_type) {
        return (None, None);
    }

    let path_str = path.to_string_lossy();

    // Tier 1: ETW file attribution table (when etw feature is enabled and running).
    // The lookup canonicalizes the path so it matches whichever shape ETW
    // recorded (NT object manager `\Device\HarddiskVolumeN\...` or
    // long-path-prefixed Win32).
    if let Some((_pid, name, proc_path)) = crate::l7_etw::get_file_attribution(&path_str) {
        return (Some(name), Some(proc_path));
    }

    // Tier 2: in-memory cache
    if let Some((name, proc_path)) = lookup_cache(&path_str) {
        if name.is_some() || proc_path.is_some() {
            return (name, proc_path);
        }
    }

    // Tier 3: Restart Manager + sysinfo, on the artifact path itself.
    // Only fires when a process is currently holding an open handle to the
    // file. This works for persistently-open files (e.g. Edge `Cookies`)
    // but misses atomic-rename writers (e.g. Chrome's `LevelDB`/`User Data`
    // pattern, where Chrome writes to `<file>.tmp`, then renames over the
    // real file and immediately closes the handle).
    if let Some((pid, fallback_name)) = lookup_pid_for_path(path) {
        let result = lookup_process_details(pid, fallback_name);
        if result.0.is_some() || result.1.is_some() {
            cache_attribution(&path_str, &result.0, &result.1);
            return result;
        }
    }

    // Tier 3b: parent-directory Restart Manager probe for sensitive events.
    //
    // For sensitive FIM events the cost of an extra RM session is worth
    // it. Atomic-rename writers (Chrome / Edge / Vivaldi browser
    // profiles, Outlook `.ost`, sqlite WAL, etc.) typically keep the
    // *parent directory* open even after the artifact handle is gone --
    // they need it to enumerate siblings and stage tmp files for the
    // next write cycle. Walking up at most two parents catches both
    // common shapes:
    //
    //   `...\User Data\Default\Network\Cookies`
    //                                  ^ artifact (handle gone)
    //                          ^ parent (Network/, often held)
    //                  ^ grandparent (Default/, profile root, always held)
    //
    // We treat any process holding an ancestor handle as the most
    // plausible writer of the artifact. This is deliberately
    // best-effort: we accept some false positives (e.g. attributing a
    // FIM event to a process that just happened to be browsing the
    // directory) in exchange for closing the systemic 0% attribution
    // gap that produces the persistent self-access-suppression
    // failures captured in FP-WIN-16.
    if is_sensitive {
        let mut current = path.parent();
        let mut hops = 0u32;
        while let Some(parent) = current {
            // Skip the drive root (`C:\`) -- RM on a volume root would
            // attribute every process holding the drive as the writer.
            if parent.parent().is_none() {
                break;
            }
            if let Some((pid, fallback_name)) = lookup_pid_for_path(parent) {
                let result = lookup_process_details(pid, fallback_name);
                if result.0.is_some() || result.1.is_some() {
                    cache_attribution(&path_str, &result.0, &result.1);
                    return result;
                }
            }
            hops += 1;
            if hops >= 2 {
                break;
            }
            current = parent.parent();
        }
    }

    (None, None)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn best_effort_process_attribution(
    _path: &Path,
    _is_sensitive: bool,
    _event_type: FimEventType,
) -> (Option<String>, Option<String>) {
    (None, None)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn lookup_pid_for_path(path: &Path) -> Option<(u32, Option<String>)> {
    let output = Command::new("lsof")
        .arg("-n")
        .arg("-w")
        .arg("-Fpc")
        .arg("--")
        .arg(path)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    parse_lsof_pid_and_command(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn parse_lsof_pid_and_command(output: &str) -> Option<(u32, Option<String>)> {
    let mut pid = None;
    let mut command = None;

    for line in output.lines() {
        if pid.is_none() {
            if let Some(rest) = line.strip_prefix('p') {
                pid = rest.parse::<u32>().ok();
            }
            continue;
        }

        if command.is_none() {
            if let Some(rest) = line.strip_prefix('c') {
                if !rest.is_empty() {
                    command = Some(rest.to_string());
                }
                break;
            }
        }
    }

    pid.map(|pid| (pid, command))
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn lookup_process_details(
    pid: u32,
    fallback_name: Option<String>,
) -> (Option<String>, Option<String>) {
    let mut system = System::new_with_specifics(
        RefreshKind::nothing().with_processes(ProcessRefreshKind::everything().without_cpu()),
    );
    system.refresh_specifics(
        RefreshKind::nothing().with_processes(ProcessRefreshKind::everything().without_cpu()),
    );

    let process = system.process(Pid::from_u32(pid));
    let process_path = process
        .and_then(|process| process.exe())
        .map(|path| path.to_string_lossy().to_string());
    let process_name = process
        .map(|process| process.name().to_string_lossy().to_string())
        .or(fallback_name)
        .or_else(|| {
            process_path.as_ref().and_then(|path| {
                Path::new(path)
                    .file_name()
                    .map(|name| name.to_string_lossy().to_string())
            })
        });

    (process_name, process_path)
}

#[cfg(target_os = "windows")]
fn lookup_pid_for_path(path: &Path) -> Option<(u32, Option<String>)> {
    use windows::core::PWSTR;
    use windows::Win32::System::RestartManager::{
        RmEndSession, RmGetList, RmRegisterResources, RmStartSession,
    };

    let path_wide: Vec<u16> = path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut session: u32 = 0;
        let mut session_key = [0u16; 256]; // CCH_RM_SESSION_KEY + 1
        if RmStartSession(&mut session, None, PWSTR(session_key.as_mut_ptr())).is_err() {
            return None;
        }

        let file_ptr = windows::core::PCWSTR(path_wide.as_ptr());
        let files = [file_ptr];
        if RmRegisterResources(session, Some(&files), None, None).is_err() {
            let _ = RmEndSession(session);
            return None;
        }

        let mut needed: u32 = 0;
        let mut count: u32 = 0;
        let mut reason: u32 = 0;
        // First call to get the required buffer size
        let _ = RmGetList(session, &mut needed, &mut count, None, &mut reason);
        if needed == 0 {
            let _ = RmEndSession(session);
            return None;
        }

        let mut buf = vec![
            std::mem::zeroed::<windows::Win32::System::RestartManager::RM_PROCESS_INFO>(
            );
            needed as usize
        ];
        count = needed;
        let result = RmGetList(
            session,
            &mut needed,
            &mut count,
            Some(buf.as_mut_ptr()),
            &mut reason,
        );
        let _ = RmEndSession(session);

        if result.is_err() || count == 0 {
            return None;
        }

        let info = &buf[0];
        let pid = info.Process.dwProcessId;
        let name_slice = &info.strAppName;
        let name_len = name_slice
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(name_slice.len());
        let app_name = if name_len > 0 {
            Some(String::from_utf16_lossy(&name_slice[..name_len]))
        } else {
            None
        };
        Some((pid, app_name))
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn backfill_missing_process_attribution(store: &FimEventStore, max_events: usize) -> usize {
    let candidates = store.get_recent_events_missing_process_attribution(max_events);
    let mut updated = 0;

    for event in candidates {
        if event.event_type == FimEventType::Delete {
            continue;
        }

        // Tier 1: ES file attribution table
        if let Some((_pid, name, proc_path)) = crate::l7_es::get_file_attribution(&event.path) {
            store.update_process_attribution(&event.uid, Some(name), Some(proc_path));
            updated += 1;
            continue;
        }

        // Tier 2: in-memory lsof result cache
        if let Some((name, proc_path)) = lookup_cache(&event.path) {
            if name.is_some() || proc_path.is_some() {
                store.update_process_attribution(&event.uid, name, proc_path);
                updated += 1;
                continue;
            }
        }

        // Tier 3: live lsof + sysinfo
        let path = Path::new(&event.path);
        let (pid, fallback_name) = match lookup_pid_for_path(path) {
            Some(details) => details,
            None => continue,
        };

        let (process_name, process_path) = lookup_process_details(pid, fallback_name);
        if process_name.is_none() && process_path.is_none() {
            continue;
        }

        cache_attribution(&event.path, &process_name, &process_path);
        store.update_process_attribution(&event.uid, process_name, process_path);
        updated += 1;
    }

    updated
}

#[cfg(target_os = "windows")]
pub fn backfill_missing_process_attribution(store: &FimEventStore, max_events: usize) -> usize {
    let candidates = store.get_recent_events_missing_process_attribution(max_events);
    let mut updated = 0;

    for event in candidates {
        if event.event_type == FimEventType::Delete {
            continue;
        }

        // Tier 1: ETW file attribution table (canonicalizes path internally).
        if let Some((_pid, name, proc_path)) = crate::l7_etw::get_file_attribution(&event.path) {
            store.update_process_attribution(&event.uid, Some(name), Some(proc_path));
            updated += 1;
            continue;
        }

        // Tier 2: in-memory cache
        if let Some((name, proc_path)) = lookup_cache(&event.path) {
            if name.is_some() || proc_path.is_some() {
                store.update_process_attribution(&event.uid, name, proc_path);
                updated += 1;
                continue;
            }
        }

        // Tier 3: Restart Manager on the artifact path itself.
        let path = Path::new(&event.path);
        if let Some((pid, fallback_name)) = lookup_pid_for_path(path) {
            let (process_name, process_path) = lookup_process_details(pid, fallback_name);
            if process_name.is_some() || process_path.is_some() {
                cache_attribution(&event.path, &process_name, &process_path);
                store.update_process_attribution(&event.uid, process_name, process_path);
                updated += 1;
                continue;
            }
        }

        // Tier 3b: parent-directory Restart Manager probe for sensitive
        // events (atomic-rename writers like Chrome `User Data`). See
        // `best_effort_process_attribution` for the rationale.
        if event.is_sensitive {
            let mut current = path.parent();
            let mut hops = 0u32;
            let mut found = false;
            while let Some(parent) = current {
                if parent.parent().is_none() {
                    break;
                }
                if let Some((pid, fallback_name)) = lookup_pid_for_path(parent) {
                    let (process_name, process_path) = lookup_process_details(pid, fallback_name);
                    if process_name.is_some() || process_path.is_some() {
                        cache_attribution(&event.path, &process_name, &process_path);
                        store.update_process_attribution(&event.uid, process_name, process_path);
                        updated += 1;
                        found = true;
                        break;
                    }
                }
                hops += 1;
                if hops >= 2 {
                    break;
                }
                current = parent.parent();
            }
            if found {
                continue;
            }
        }
    }

    updated
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn backfill_missing_process_attribution(_store: &FimEventStore, _max_events: usize) -> usize {
    0
}

/// Returns `(cache_size, kernel_attribution_available)` for diagnostic purposes.
/// On macOS the kernel source is ES; on Windows it is ETW.
pub fn attribution_cache_stats() -> (usize, bool) {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        (FIM_ATTRIBUTION_CACHE.len(), crate::l7_es::is_available())
    }
    #[cfg(target_os = "windows")]
    {
        (FIM_ATTRIBUTION_CACHE.len(), crate::l7_etw::is_available())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        (0, false)
    }
}

pub fn clear_attribution_cache() {
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    {
        FIM_ATTRIBUTION_CACHE.clear();
        FIM_CACHE_INSERT_COUNTER.store(0, Ordering::Relaxed);
    }
}

#[cfg(target_os = "linux")]
fn check_inotify_limits(watch_count: usize) {
    if let Ok(content) = std::fs::read_to_string("/proc/sys/fs/inotify/max_user_watches") {
        if let Ok(max_watches) = content.trim().parse::<usize>() {
            if max_watches < watch_count * 100 {
                warn!(
                    "FIM: inotify max_user_watches ({}) may be insufficient for {} watch paths. \
                     Consider increasing: sudo sysctl fs.inotify.max_user_watches=524288",
                    max_watches, watch_count
                );
            }
        }
    }
}

pub fn default_watch_paths(mode: FimMode) -> Vec<PathBuf> {
    match mode {
        FimMode::CI => ci_watch_paths(),
        FimMode::Desktop => desktop_watch_paths(),
    }
}

/// Platform-specific temp directory roots to watch for staged-payload detection.
///
/// These correspond to `fim_temp_executable_patterns` in `vuln_detector_params`
/// (the detector's `is_temp_directory_path` recognizes events from these roots
/// as temp-staging candidates). This is the shared source of truth used by both
/// standalone and helper-daemon FIM startup paths.
pub fn default_temp_watch_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // /tmp and /var/tmp are the canonical staging directories attackers use for
        // dropped payloads, temp scripts, and intermediate artifacts. On macOS /tmp
        // is a symlink to /private/tmp; the notify framework resolves it transparently.
        for p in ["/tmp", "/var/tmp"] {
            let path = PathBuf::from(p);
            if path.exists() {
                paths.push(path);
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        // Windows per-user and system temp directories.
        for key in ["TEMP", "TMP"] {
            if let Ok(val) = std::env::var(key) {
                let path = PathBuf::from(val);
                if path.exists() && !paths.contains(&path) {
                    paths.push(path);
                }
            }
        }
    }

    paths
}

/// Sensitive per-home watch directories (credentials, agent configs, platform
/// key stores). Shared by standalone and helper-daemon startup paths so both
/// paths monitor exactly the same default set.
///
/// The directory list comes from `sensitive-paths-db.json::watch_roots`
/// (CloudModel-tunable, embedded fallback in
/// `flodbadd::sensitive_paths_db`) -- there is intentionally NO hardcoded
/// path list in this function. See
/// `crate::sensitive_paths::default_sensitive_watch_paths_for_home`.
pub fn default_sensitive_watch_paths_for_home(home: &Path) -> Vec<PathBuf> {
    crate::sensitive_paths::default_sensitive_watch_paths_for_home(home)
}

fn ci_watch_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Ok(workspace) = std::env::var("GITHUB_WORKSPACE") {
        paths.push(PathBuf::from(workspace));
    } else if let Ok(cwd) = std::env::current_dir() {
        paths.push(cwd);
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(tmpdir) = std::env::var("TMPDIR") {
            let p = PathBuf::from(tmpdir);
            if p.exists() && !paths.contains(&p) {
                paths.push(p);
            }
        }
    }

    for p in default_temp_watch_paths() {
        if !paths.contains(&p) {
            paths.push(p);
        }
    }

    if let Some(home) = home_dir() {
        let home = PathBuf::from(home);
        for dir in &[".npm", ".cargo", ".local"] {
            let p = home.join(dir);
            if p.exists() {
                paths.push(p);
            }
        }
    }

    paths
}

fn desktop_watch_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(home) = home_dir() {
        paths.extend(default_sensitive_watch_paths_for_home(&PathBuf::from(home)));
    }

    for p in default_temp_watch_paths() {
        if !paths.contains(&p) {
            paths.push(p);
        }
    }

    paths
}

fn home_dir() -> Option<String> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        std::env::var("HOME").ok()
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("USERPROFILE").ok()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_default_ci_paths_not_empty() {
        let paths = default_watch_paths(FimMode::CI);
        assert!(!paths.is_empty(), "CI watch paths should not be empty");
    }

    #[test]
    fn test_default_desktop_paths() {
        let paths = default_watch_paths(FimMode::Desktop);
        // Desktop paths depend on home dir; just verify no panic
        let _ = paths;
    }

    fn poll_for_events(store: &FimEventStore, min_count: usize, timeout_ms: u64) -> Vec<FimEvent> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        loop {
            let events = store.get_all_events();
            if events.len() >= min_count || std::time::Instant::now() >= deadline {
                return events;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    fn poll_for_sensitive_events(store: &FimEventStore, timeout_ms: u64) -> Vec<FimEvent> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        loop {
            let sensitive = store.get_sensitive_events();
            if !sensitive.is_empty() || std::time::Instant::now() >= deadline {
                return sensitive;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    #[test]
    fn test_fim_watcher_lifecycle() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let config = FimConfig {
            recursive: true,
            ..Default::default()
        };

        let watcher =
            FimWatcher::start(vec![temp.path().to_path_buf()], config).expect("start watcher");
        assert!(watcher.is_running());
        assert_eq!(watcher.watch_paths().len(), 1);

        let test_file = temp.path().join("test.txt");
        fs::write(&test_file, "hello fim").expect("write test file");

        let events = poll_for_events(watcher.store(), 1, 5000);
        assert!(
            !events.is_empty(),
            "FIM watcher should detect file creation within 5s"
        );

        let matching = events.iter().any(|e| e.path.contains("test.txt"));
        assert!(
            matching,
            "Should have an event for test.txt, got: {:?}",
            events.iter().map(|e| &e.path).collect::<Vec<_>>()
        );

        watcher.stop();
    }

    #[test]
    fn test_fim_watcher_nonexistent_path() {
        let config = FimConfig::default();
        let watcher = FimWatcher::start(
            vec![PathBuf::from("/nonexistent/path/that/does/not/exist")],
            config,
        )
        .expect("start watcher with nonexistent path");
        assert!(watcher.watch_paths().is_empty());
        watcher.stop();
    }

    #[test]
    fn test_fim_sensitive_event_detection() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let ssh_dir = temp.path().join(".ssh");
        fs::create_dir_all(&ssh_dir).expect("create .ssh dir");

        let config = FimConfig {
            recursive: true,
            ..Default::default()
        };
        let watcher =
            FimWatcher::start(vec![temp.path().to_path_buf()], config).expect("start watcher");

        let key_file = ssh_dir.join("id_rsa");
        fs::write(&key_file, "fake-key-content").expect("write key file");

        let events = poll_for_events(watcher.store(), 1, 5000);
        assert!(
            !events.is_empty(),
            "FIM watcher should detect .ssh/id_rsa creation within 5s"
        );

        let sensitive = poll_for_sensitive_events(watcher.store(), 5000);
        assert!(
            !sensitive.is_empty(),
            "Creating .ssh/id_rsa should produce a sensitive event. All events: {:?}",
            events
                .iter()
                .map(|e| (&e.path, e.is_sensitive))
                .collect::<Vec<_>>()
        );

        watcher.stop();
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_fim_hash_computation() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let test_file = temp.path().join("hashme.txt");
        let content = b"test content for hashing";
        fs::write(&test_file, content).expect("write");

        let (size, hash) = get_file_metadata(&test_file, FIM_HASH_SIZE_THRESHOLD);
        assert_eq!(size, Some(content.len() as u64));
        assert!(hash.is_some());

        let expected = blake3::hash(content).to_hex().to_string();
        assert_eq!(hash.unwrap(), expected);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_fim_hash_handle_allows_rename_while_open() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let test_file = temp.path().join("hashme.txt");
        let renamed_file = temp.path().join("hashme-renamed.txt");
        fs::write(&test_file, b"test content for hashing").expect("write");

        let handle = open_file_for_fim_hash(&test_file).expect("open file for FIM hash");
        fs::rename(&test_file, &renamed_file)
            .expect("FIM hash handle should not block Windows rename/delete sharing");
        drop(handle);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_fim_hash_skips_large_files() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let test_file = temp.path().join("large.bin");
        fs::write(&test_file, vec![0u8; 100]).expect("write");

        // Use a very small threshold
        let (size, hash) = get_file_metadata(&test_file, 10);
        assert_eq!(size, Some(100));
        assert!(hash.is_none(), "Should skip hashing files above threshold");
    }

    #[test]
    fn test_fim_watcher_create_modify_delete() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let config = FimConfig {
            recursive: true,
            ..Default::default()
        };
        let watcher =
            FimWatcher::start(vec![temp.path().to_path_buf()], config).expect("start watcher");

        let test_file = temp.path().join("lifecycle.txt");

        fs::write(&test_file, "initial").expect("create file");
        let events = poll_for_events(watcher.store(), 1, 5000);
        assert!(!events.is_empty(), "Should detect file creation");

        let before_modify = watcher.store().event_count();
        fs::write(&test_file, "modified content").expect("modify file");
        let events = poll_for_events(watcher.store(), before_modify + 1, 5000);
        assert!(
            events.len() > before_modify,
            "Should detect file modification (had {}, now {})",
            before_modify,
            events.len()
        );

        let before_delete = watcher.store().event_count();
        fs::remove_file(&test_file).expect("delete file");
        let events = poll_for_events(watcher.store(), before_delete + 1, 5000);
        assert!(
            events.len() > before_delete,
            "Should detect file deletion (had {}, now {})",
            before_delete,
            events.len()
        );

        watcher.stop();
    }

    #[test]
    fn test_translate_notify_event_create_with_explicit_watch() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let test_file = temp.path().join("new.txt");
        fs::write(&test_file, "new content").expect("write");

        let explicit_roots = vec![temp.path().to_string_lossy().replace('\\', "/")];

        let event = Event {
            kind: EventKind::Create(notify::event::CreateKind::File),
            paths: vec![test_file.clone()],
            attrs: Default::default(),
        };
        let results = translate_notify_event(&event, FIM_HASH_SIZE_THRESHOLD, &explicit_roots);
        assert!(
            results.is_some(),
            "Event under explicit watch root must be kept"
        );
        let events = results.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, FimEventType::Create);
        // FP-CI-2: a non-sensitive file kept only because it lives under
        // an explicit watch root (operator-supplied audit dir) MUST NOT
        // be hashed. The downstream detector only consumes hashes for
        // sensitive findings; hashing non-sensitive churn races with
        // build-tool exclusive opens on Windows and is wasted I/O on
        // other platforms. We still record the event (size + path +
        // attribution) so the operator can audit it via the FIM event
        // stream -- we just leave `hash == None`.
        assert!(
            !events[0].is_sensitive,
            "tempdir-created random filename is not a sensitive path",
        );
        assert!(
            events[0].hash.is_none(),
            "Non-sensitive explicit-watch-root events must skip content hashing (FP-CI-2)",
        );
        assert!(
            events[0].size.is_some(),
            "Size must still be populated for non-sensitive events (used for dedup)",
        );
    }

    #[test]
    fn test_translate_notify_event_non_sensitive_temp_skips_hash() {
        // FP-CI-2 regression guard. Reproduces the canonical Windows build
        // shape: a build tool (Dart pub, MSBuild, cargo, ...) writes a
        // transient file under the OS temp dir, the notify watcher emits a
        // Create event for it, the path is matched only by
        // `is_temp_directory_path` (NOT by `is_sensitive_path`), and the
        // detector pipeline does not need a content hash for it. The
        // assertions below pin three properties that, if violated, would
        // re-introduce the file-locking race on Windows runners:
        //
        //   1. `is_sensitive == false`        -- so the watcher's hash-work
        //                                        queue gate (Windows side)
        //                                        does NOT submit work for it.
        //   2. `hash == None`                 -- so the synchronous
        //                                        non-Windows hash gate
        //                                        (Linux/macOS) does NOT
        //                                        open and read it.
        //   3. `size.is_some()`               -- size is still recorded so
        //                                        the dedup key works.
        //
        // We construct the path ourselves under a real OS temp directory
        // recognized by `is_temp_directory_path` (`/tmp/` on Unix,
        // `%TEMP%\AppData\Local\Temp\` on Windows) -- `tempfile::tempdir()`
        // resolves to `/var/folders/...` on macOS which is NOT matched.
        #[cfg(not(target_os = "windows"))]
        let test_file = {
            let name = format!(
                "edamame_fim_fp_ci_2_{}_{}.tmp",
                std::process::id(),
                Utc::now().timestamp_nanos_opt().unwrap_or_default(),
            );
            PathBuf::from("/tmp").join(name)
        };
        #[cfg(target_os = "windows")]
        let test_file = {
            // tempfile::env::temp_dir() returns %TEMP% which is under
            // AppData\Local\Temp on standard Windows installs.
            let name = format!(
                "edamame_fim_fp_ci_2_{}_{}.tmp",
                std::process::id(),
                Utc::now().timestamp_nanos_opt().unwrap_or_default(),
            );
            std::env::temp_dir().join(name)
        };

        fs::write(&test_file, b"non-sensitive churn").expect("write");
        struct Cleanup<'a>(&'a Path);
        impl<'a> Drop for Cleanup<'a> {
            fn drop(&mut self) {
                let _ = fs::remove_file(self.0);
            }
        }
        let _cleanup = Cleanup(&test_file);

        // No explicit watch roots -- this event survives only because the
        // path falls under an OS temp dir recognized by
        // `is_temp_directory_path`.
        let explicit_roots: Vec<String> = Vec::new();

        let event = Event {
            kind: EventKind::Create(notify::event::CreateKind::File),
            paths: vec![test_file.clone()],
            attrs: Default::default(),
        };

        let results = translate_notify_event(&event, FIM_HASH_SIZE_THRESHOLD, &explicit_roots);
        let events = results.expect("temp-staging event must be kept");
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert!(
            !event.is_sensitive,
            "transient build artifact is NOT a sensitive path; the temp-staging accept rule must mark it non-sensitive",
        );
        assert!(
            event.hash.is_none(),
            "Non-sensitive temp-staging events must skip content hashing (FP-CI-2)",
        );
        assert!(
            event.size.is_some(),
            "Size must still be populated for non-sensitive events",
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_deferred_hash_worker_updates_stable_file() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let test_file = temp.path().join("stable.txt");
        let content = b"stable content for deferred hashing";
        fs::write(&test_file, content).expect("write");

        let store = Arc::new(FimEventStore::new());
        let ts = Utc::now();
        let uid = FimEvent::compute_uid(&test_file.to_string_lossy(), &FimEventType::Create, &ts);
        store.insert(FimEvent {
            path: test_file.to_string_lossy().to_string(),
            event_type: FimEventType::Create,
            timestamp: ts,
            size: Some(content.len() as u64),
            hash: None,
            process_name: None,
            process_path: None,
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: false,
            labels: vec![],
            uid: uid.clone(),
            last_modified: ts,
        });

        let running = Arc::new(AtomicBool::new(true));
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let worker =
            spawn_fim_hash_worker(store.clone(), running.clone(), rx).expect("spawn worker");

        tx.send(FimHashWorkItem {
            uid: uid.clone(),
            path: test_file.clone(),
            size: content.len() as u64,
            hash_threshold: FIM_HASH_SIZE_THRESHOLD,
            ready_at: std::time::Instant::now(),
        })
        .expect("send hash work");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let expected = blake3::hash(content).to_hex().to_string();
        loop {
            let events = store.get_all_events();
            if events
                .iter()
                .any(|event| event.uid == uid && event.hash.as_deref() == Some(expected.as_str()))
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "deferred hash worker did not update the event"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        running.store(false, Ordering::SeqCst);
        drop(tx);
        worker.join().expect("join worker");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_deferred_hash_sharing_violation_leaves_hash_empty() {
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;

        let temp = tempfile::tempdir().expect("create temp dir");
        let test_file = temp.path().join("locked.txt");
        let content = b"locked content";
        fs::write(&test_file, content).expect("write");

        let store = FimEventStore::new();
        let ts = Utc::now();
        let uid = FimEvent::compute_uid(&test_file.to_string_lossy(), &FimEventType::Create, &ts);
        store.insert(FimEvent {
            path: test_file.to_string_lossy().to_string(),
            event_type: FimEventType::Create,
            timestamp: ts,
            size: Some(content.len() as u64),
            hash: None,
            process_name: None,
            process_path: None,
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: false,
            labels: vec![],
            uid: uid.clone(),
            last_modified: ts,
        });

        let _exclusive_handle = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&test_file)
            .expect("open exclusive handle");

        let updated = process_fim_hash_work_item(
            &store,
            FimHashWorkItem {
                uid: uid.clone(),
                path: test_file.clone(),
                size: content.len() as u64,
                hash_threshold: FIM_HASH_SIZE_THRESHOLD,
                ready_at: std::time::Instant::now(),
            },
        );

        assert!(!updated, "sharing violation must be a non-fatal skip");
        let events = store.get_all_events();
        assert_eq!(events.len(), 1);
        assert!(events[0].hash.is_none());
    }

    #[test]
    fn test_translate_notify_event_delete_sensitive() {
        let event = Event {
            kind: EventKind::Remove(notify::event::RemoveKind::File),
            paths: vec![PathBuf::from("/Users/me/.ssh/id_rsa")],
            attrs: Default::default(),
        };
        let results = translate_notify_event(&event, FIM_HASH_SIZE_THRESHOLD, &[]);
        assert!(
            results.is_some(),
            "Sensitive delete must be kept even with no explicit roots"
        );
        let events = results.unwrap();
        assert_eq!(events[0].event_type, FimEventType::Delete);
        assert!(events[0].hash.is_none());
        assert!(events[0].size.is_none());
    }

    #[test]
    fn test_translate_notify_event_ignores_access() {
        let event = Event {
            kind: EventKind::Access(notify::event::AccessKind::Read),
            paths: vec![PathBuf::from("/some/file.txt")],
            attrs: Default::default(),
        };
        let results = translate_notify_event(&event, FIM_HASH_SIZE_THRESHOLD, &[]);
        assert!(results.is_none());
    }

    #[test]
    fn test_translate_notify_event_drops_non_sensitive_non_temp_non_explicit() {
        let event = Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Content,
            )),
            paths: vec![PathBuf::from("/Users/me/Documents/random.txt")],
            attrs: Default::default(),
        };
        // No explicit watch roots, path is not sensitive, not temp, not build
        // exclusion -- gate must drop it BEFORE hashing. This is the FP-FIM-CPU-1
        // hot path: dev machines generate enormous churn here from editor
        // saves, language-server caches, etc., none of which is detector-relevant.
        let results = translate_notify_event(&event, FIM_HASH_SIZE_THRESHOLD, &[]);
        assert!(
            results.is_none(),
            "Random non-sensitive non-temp non-explicit event must be dropped early"
        );
    }

    #[test]
    fn test_translate_notify_event_drops_build_artifacts_under_explicit_watch() {
        // Even when an operator explicitly watches the project root, build
        // artifacts under it (cargo target/, node_modules/, ...) must still
        // be dropped -- the exclusion list is the structural noise filter
        // and overrides the explicit-watch accept.
        let temp = tempfile::tempdir().expect("create temp dir");
        let target_dir = temp.path().join("target/release/deps");
        fs::create_dir_all(&target_dir).expect("mkdir target/release/deps");
        let bin_file = target_dir.join("libfoo.rlib");
        fs::write(&bin_file, b"\0\0\0\0").expect("write");

        let explicit_roots = vec![temp.path().to_string_lossy().replace('\\', "/")];

        let event = Event {
            kind: EventKind::Create(notify::event::CreateKind::File),
            paths: vec![bin_file.clone()],
            attrs: Default::default(),
        };
        let results = translate_notify_event(&event, FIM_HASH_SIZE_THRESHOLD, &explicit_roots);
        assert!(
            results.is_none(),
            "Build artifact under explicit watch root must be dropped by exclusion list. \
             explicit_roots={:?}, bin_file={:?}",
            explicit_roots,
            bin_file
        );
    }

    #[test]
    fn test_translate_notify_event_keeps_temp_with_no_explicit_roots() {
        let event = Event {
            kind: EventKind::Create(notify::event::CreateKind::File),
            paths: vec![PathBuf::from("/tmp/dropper.sh")],
            attrs: Default::default(),
        };
        let results = translate_notify_event(&event, FIM_HASH_SIZE_THRESHOLD, &[]);
        assert!(
            results.is_some(),
            "Temp staging path must be kept even with no explicit watch root"
        );
    }

    #[test]
    fn test_should_keep_fim_event_classifications() {
        // Sensitive + non-excluded -> keep (sensitive=true)
        let (keep, sensitive) = should_keep_fim_event("/Users/me/.ssh/id_rsa", &[]);
        assert!(keep);
        assert!(sensitive);

        // Temp + non-excluded -> keep (sensitive=false)
        let (keep, sensitive) = should_keep_fim_event("/tmp/dropper.sh", &[]);
        assert!(keep);
        assert!(!sensitive);

        // Non-sensitive + non-temp + no explicit + no exclusion match -> drop
        let (keep, _) = should_keep_fim_event("/Users/me/Documents/notes.txt", &[]);
        assert!(!keep);

        // Non-sensitive + under explicit watch -> keep (sensitive=false)
        let explicit = vec!["/Users/me/audit".to_string()];
        let (keep, sensitive) = should_keep_fim_event("/Users/me/audit/log.txt", &explicit);
        assert!(keep);
        assert!(!sensitive);

        // Build artifact (excluded) under explicit watch -> drop (exclusion wins)
        let explicit = vec!["/Users/me/repo".to_string()];
        let (keep, _) =
            should_keep_fim_event("/Users/me/repo/target/release/deps/libfoo.rlib", &explicit);
        assert!(!keep);

        // Build artifact (excluded) that happens to look "sensitive" by suffix:
        // exclusion still wins because excluded paths are structurally noisy
        // regardless of name. node_modules/.bin/foo is the canonical example.
        let (keep, _) =
            should_keep_fim_event("/Users/me/repo/node_modules/.bin/credentials.json", &[]);
        assert!(!keep);
    }

    #[test]
    fn test_should_keep_fim_event_explicit_watch_does_not_substring_match() {
        // Explicit roots must be matched as path prefixes, not substrings,
        // so a watch on /Users/me/sshlogs does NOT accept events under
        // /Users/me/.ssh/.
        let explicit = vec!["/Users/me/sshlogs".to_string()];
        let (keep, _) = should_keep_fim_event("/Users/me/sshlogs/foo.log", &explicit);
        assert!(keep);

        let (keep, _) = should_keep_fim_event("/Users/me/sshlogsplus/foo", &explicit);
        assert!(!keep, "Sibling path with shared prefix must not match");
    }

    #[test]
    fn test_should_attempt_process_attribution_for_sensitive_or_temp_paths() {
        assert!(should_attempt_process_attribution(
            Path::new("/Users/test/.ssh/id_rsa"),
            true,
            FimEventType::Create
        ));
        assert!(should_attempt_process_attribution(
            Path::new("/tmp/suspicious-script.sh"),
            false,
            FimEventType::Modify
        ));
        assert!(!should_attempt_process_attribution(
            Path::new("/tmp/deleted-secret.txt"),
            false,
            FimEventType::Delete
        ));
        assert!(!should_attempt_process_attribution(
            Path::new("/Users/test/Documents/notes.txt"),
            false,
            FimEventType::Modify
        ));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn test_parse_lsof_pid_and_command_extracts_first_process() {
        let parsed = parse_lsof_pid_and_command("p4242\nccursor\nf4\n");
        assert_eq!(parsed, Some((4242, Some("cursor".to_string()))));
    }
}
