use crate::fim_events::{FimEvent, FimEventStore, FimEventType, FIM_HASH_SIZE_THRESHOLD};
use crate::open_files::is_sensitive_path;
use crate::sensitive_paths::classify_sensitive_path_labels_sync;
use anyhow::{Context, Result};
use chrono::Utc;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System};
use tracing::{debug, error, info, warn};

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
}

pub const FIM_PROCESS_ATTRIBUTION_BACKFILL_LIMIT: usize = 128;

impl FimWatcher {
    pub fn start(paths: Vec<PathBuf>, config: FimConfig) -> Result<Self> {
        let store = Arc::new(FimEventStore::new());
        let running = Arc::new(AtomicBool::new(true));

        #[cfg(target_os = "linux")]
        check_inotify_limits(paths.len());

        let store_clone = store.clone();
        let hash_threshold = config.hash_size_threshold;
        let mut watcher = RecommendedWatcher::new(
            move |result: std::result::Result<Event, notify::Error>| match result {
                Ok(event) => {
                    if let Some(fim_events) = translate_notify_event(&event, hash_threshold) {
                        for fim_event in fim_events {
                            store_clone.insert(fim_event);
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
        })
    }

    pub fn stop(self) {
        self.running.store(false, Ordering::SeqCst);
        info!("FIM: watcher stopped");
    }

    pub fn store(&self) -> &FimEventStore {
        &self.store
    }

    pub fn watch_paths(&self) -> &[PathBuf] {
        &self.watch_paths
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

fn translate_notify_event(event: &Event, hash_threshold: u64) -> Option<Vec<FimEvent>> {
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

        let (size, hash) = if event_type != FimEventType::Delete && path.is_file() {
            get_file_metadata(path, hash_threshold)
        } else {
            (None, None)
        };

        let sensitive = is_sensitive_path(&path_str);
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
            is_sensitive: sensitive,
            labels,
            uid,
        });
    }

    if fim_events.is_empty() {
        None
    } else {
        Some(fim_events)
    }
}

fn get_file_metadata(path: &Path, hash_threshold: u64) -> (Option<u64>, Option<String>) {
    match std::fs::metadata(path) {
        Ok(meta) => {
            let size = meta.len();
            let hash = if size <= hash_threshold {
                match std::fs::read(path) {
                    Ok(data) => Some(blake3::hash(&data).to_hex().to_string()),
                    Err(_) => None,
                }
            } else {
                None
            };
            (Some(size), hash)
        }
        Err(_) => (None, None),
    }
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

    let (pid, fallback_name) = match lookup_pid_for_path(path) {
        Some(details) => details,
        None => return (None, None),
    };

    lookup_process_details(pid, fallback_name)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
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

#[cfg(any(target_os = "macos", target_os = "linux"))]
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

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn backfill_missing_process_attribution(store: &FimEventStore, max_events: usize) -> usize {
    let candidates = store.get_recent_events_missing_process_attribution(max_events);
    let mut updated = 0;

    for event in candidates {
        if event.event_type == FimEventType::Delete {
            continue;
        }

        let path = Path::new(&event.path);
        let (pid, fallback_name) = match lookup_pid_for_path(path) {
            Some(details) => details,
            None => continue,
        };

        let (process_name, process_path) = lookup_process_details(pid, fallback_name);
        if process_name.is_none() && process_path.is_none() {
            continue;
        }

        store.update_process_attribution(&event.uid, process_name, process_path);
        updated += 1;
    }

    updated
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn backfill_missing_process_attribution(_store: &FimEventStore, _max_events: usize) -> usize {
    0
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

fn ci_watch_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Ok(workspace) = std::env::var("GITHUB_WORKSPACE") {
        paths.push(PathBuf::from(workspace));
    } else if let Ok(cwd) = std::env::current_dir() {
        paths.push(cwd);
    }

    #[cfg(target_os = "linux")]
    {
        paths.push(PathBuf::from("/tmp"));
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(tmpdir) = std::env::var("TMPDIR") {
            paths.push(PathBuf::from(tmpdir));
        } else {
            paths.push(PathBuf::from("/tmp"));
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(temp) = std::env::var("TEMP") {
            paths.push(PathBuf::from(temp));
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
        let home = PathBuf::from(home);

        let common_dirs = [
            ".ssh", ".gnupg", ".aws", ".kube", ".docker", ".cursor", ".claude",
        ];
        for dir in &common_dirs {
            let p = home.join(dir);
            if p.exists() {
                paths.push(p);
            }
        }

        #[cfg(target_os = "macos")]
        {
            let mac_dirs = ["Library/Keychains"];
            for dir in &mac_dirs {
                let p = home.join(dir);
                if p.exists() {
                    paths.push(p);
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            let linux_dirs = [".config", ".local/share"];
            for dir in &linux_dirs {
                let p = home.join(dir);
                if p.exists() {
                    paths.push(p);
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            if let Ok(appdata) = std::env::var("APPDATA") {
                paths.push(PathBuf::from(appdata));
            }
            if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
                paths.push(PathBuf::from(localappdata));
            }
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

        let sensitive = watcher.store().get_sensitive_events();
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
    fn test_translate_notify_event_create() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let test_file = temp.path().join("new.txt");
        fs::write(&test_file, "new content").expect("write");

        let event = Event {
            kind: EventKind::Create(notify::event::CreateKind::File),
            paths: vec![test_file.clone()],
            attrs: Default::default(),
        };
        let results = translate_notify_event(&event, FIM_HASH_SIZE_THRESHOLD);
        assert!(results.is_some());
        let events = results.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, FimEventType::Create);
        assert!(events[0].hash.is_some());
    }

    #[test]
    fn test_translate_notify_event_delete() {
        let event = Event {
            kind: EventKind::Remove(notify::event::RemoveKind::File),
            paths: vec![PathBuf::from("/some/deleted/file.txt")],
            attrs: Default::default(),
        };
        let results = translate_notify_event(&event, FIM_HASH_SIZE_THRESHOLD);
        assert!(results.is_some());
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
        let results = translate_notify_event(&event, FIM_HASH_SIZE_THRESHOLD);
        assert!(results.is_none());
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
