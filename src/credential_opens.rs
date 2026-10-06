// BS-10: remember which process opened a cold credential file, after the
// descriptor is closed (edamame_core/INPROCESS-KEY-THEFT.md, change 1).
//
// The open-file poll only sees a credential file while it is held open. An
// in-process stealer (the @solana/web3.js 1.95.6 shape) reads the key and
// closes it in microseconds, so the poll never sees the read. The kernel
// does: the backends call `record_open` from their open notifications and
// this module keeps one slot per (process, path) with the time of the last
// open, refreshed in place, bounded, and expired after
// `credential_open_ttl_ms()`. Nothing is written to disk.
//
// Cold set only. The full sensitive catalog includes browser cookie stores
// and `.env`, which are opened continuously; those stay on the open-file
// poll. Here: wallet keys, SSH, cloud credentials, GPG -- files a healthy
// host opens a handful of times an hour. The kernel delivers only those
// paths (macOS ES inverted target-prefix muting, Linux fanotify marks on
// those directories); Windows ETW already delivers every FileIo/Create, so
// that backend filters with `is_cold_credential_path` before recording.
//
// Monitoring role only: notify class, never blocks the opener, fail-open
// (a backend that cannot start never records and readers see nothing).

use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use undeadlock::{CustomMutex, CustomMutexExt};

// The cold set itself is published data
// (`sensitive-paths-db.json::credential_opens`, read through
// `crate::sensitive_paths::credential_opens_params`): the catalog labels
// whose files are opened rarely enough to take an open notification each;
// the sub-paths inside them that are hot (MetaMask / Phantom extension
// stores the browser touches all day, a full node's chain database), which
// stay on the open-file poll; how long a closed open stays attached to its
// process; where the labels' prefixes live under a home.

/// How long a closed credential open stays attached to its process
/// (`credential_opens.open_ttl_secs`).
pub fn credential_open_ttl_ms() -> u64 {
    crate::sensitive_paths::credential_opens_params()
        .open_ttl_secs
        .saturating_mul(1000)
}
/// Distinct credential paths remembered per process (oldest dropped).
pub const MAX_PATHS_PER_PID: usize = 32;
/// Processes with remembered opens (least recently active dropped).
pub const MAX_PIDS: usize = 4_096;
/// Kernel watch prefixes per host, across all homes.
const MAX_WATCH_PREFIXES: usize = 1_024;
const MAX_HOMES: usize = 64;

#[derive(Debug, Clone, Default)]
struct PidOpens {
    uid: Option<u32>,
    process_path: String,
    last_open_ms_by_path: HashMap<String, u64>,
}

impl PidOpens {
    fn newest_ms(&self) -> u64 {
        self.last_open_ms_by_path
            .values()
            .copied()
            .max()
            .unwrap_or(0)
    }
}

#[derive(Debug, Default)]
struct OpenTable {
    by_pid: HashMap<u32, PidOpens>,
}

impl OpenTable {
    fn record(
        &mut self,
        pid: u32,
        uid: Option<u32>,
        process_path: &str,
        file_path: &str,
        now_ms: u64,
    ) {
        let entry = self.by_pid.entry(pid).or_default();
        if !same_image(&entry.process_path, process_path) {
            // Pid reused by another image (or the process exec'd): what the
            // old image read is not evidence about this one.
            *entry = PidOpens::default();
        }
        if entry.process_path.is_empty() {
            entry.process_path = process_path.to_string();
        }
        if uid.is_some() {
            entry.uid = uid;
        }
        let slot = entry
            .last_open_ms_by_path
            .entry(file_path.to_string())
            .or_insert(now_ms);
        *slot = (*slot).max(now_ms);
        if entry.last_open_ms_by_path.len() > MAX_PATHS_PER_PID {
            if let Some(oldest) = entry
                .last_open_ms_by_path
                .iter()
                .min_by_key(|(_, ts)| **ts)
                .map(|(path, _)| path.clone())
            {
                entry.last_open_ms_by_path.remove(&oldest);
            }
        }
        if self.by_pid.len() > MAX_PIDS {
            self.prune(now_ms);
        }
        if self.by_pid.len() > MAX_PIDS {
            if let Some(oldest) = self
                .by_pid
                .iter()
                .min_by_key(|(_, opens)| opens.newest_ms())
                .map(|(pid, _)| *pid)
            {
                self.by_pid.remove(&oldest);
            }
        }
    }

    fn prune(&mut self, now_ms: u64) {
        let ttl_ms = credential_open_ttl_ms();
        self.by_pid.retain(|_, opens| {
            opens
                .last_open_ms_by_path
                .retain(|_, ts| now_ms.saturating_sub(*ts) <= ttl_ms);
            !opens.last_open_ms_by_path.is_empty()
        });
    }

    fn recent(&self, pid: u32, process_path: Option<&str>, now_ms: u64) -> Vec<String> {
        let Some(opens) = self.by_pid.get(&pid) else {
            return Vec::new();
        };
        if let Some(wanted) = process_path.filter(|p| !p.trim().is_empty()) {
            if !same_image(&opens.process_path, wanted) {
                return Vec::new();
            }
        }
        let ttl_ms = credential_open_ttl_ms();
        let mut fresh: Vec<(&String, u64)> = opens
            .last_open_ms_by_path
            .iter()
            .filter(|(_, ts)| now_ms.saturating_sub(**ts) <= ttl_ms)
            .map(|(path, ts)| (path, *ts))
            .collect();
        fresh.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        fresh.into_iter().map(|(path, _)| path.clone()).collect()
    }
}

/// Unknown on either side is not a mismatch: a backend that could not
/// resolve the image must not erase what it recorded.
fn same_image(a: &str, b: &str) -> bool {
    let a = normalize(a);
    let b = normalize(b);
    a.is_empty() || b.is_empty() || a == b
}

fn normalize(path: &str) -> String {
    path.trim().to_ascii_lowercase().replace('\\', "/")
}

// Same locking shape as `process_events::RING`: the backends call in from
// kernel-callback threads that must never block, so a contended record is
// dropped and counted.
static TABLE: Lazy<CustomMutex<OpenTable>> = Lazy::new(|| CustomMutex::new(OpenTable::default()));
static RECORDED: AtomicU64 = AtomicU64::new(0);
static DROPPED_LOCKED: AtomicU64 = AtomicU64::new(0);

/// The observer's own image. The secret-content scan opens these same
/// files, and a posture subcommand is another process running this binary.
static OWN_IMAGE: Lazy<String> = Lazy::new(|| {
    std::env::current_exe()
        .map(|p| normalize(&p.to_string_lossy()))
        .unwrap_or_default()
});

fn now_ms() -> u64 {
    crate::process_events::now_ms()
}

/// True when `path` is in the cold credential set this module records.
pub fn is_cold_credential_path(path: &str) -> bool {
    let params = crate::sensitive_paths::credential_opens_params();
    let normalized = normalize(path);
    if normalized.is_empty() || is_hot(&params.hot_subpaths, &normalized) {
        return false;
    }
    crate::sensitive_paths::classify_sensitive_path_labels_sync(&[normalized])
        .iter()
        .any(|label| params.cold_labels.iter().any(|cold| cold == label))
}

/// A (lowercase) path inside one of the hot sub-paths.
fn is_hot(hot_subpaths: &[String], lowercase_path: &str) -> bool {
    hot_subpaths
        .iter()
        .any(|hot| !hot.is_empty() && lowercase_path.contains(hot.as_str()))
}

/// Record one open (called from the kernel-event backends; cheap, never
/// blocks). Paths outside the cold set and the observer's own opens are
/// ignored, so a backend that cannot filter in the kernel stays correct.
pub fn record_open(pid: u32, uid: Option<u32>, process_path: &str, file_path: &str) {
    if pid == 0 || pid == std::process::id() {
        return;
    }
    if !OWN_IMAGE.is_empty() && normalize(process_path) == *OWN_IMAGE {
        return;
    }
    if !is_cold_credential_path(file_path) {
        return;
    }
    let now = now_ms();
    if TABLE
        .try_with(|table| table.record(pid, uid, process_path, file_path, now))
        .is_some()
    {
        RECORDED.fetch_add(1, Ordering::Relaxed);
    } else {
        DROPPED_LOCKED.fetch_add(1, Ordering::Relaxed);
    }
}

/// Cold credential files `pid` opened within `credential_open_ttl_ms()`,
/// newest first. `process_path`, when known, must match the image that did
/// the opens, so a reused pid never inherits them. Empty when the table is
/// momentarily contended (fail-open, same as the process-event ring).
pub fn recent_for_pid(pid: u32, process_path: Option<&str>) -> Vec<String> {
    let now = now_ms();
    TABLE
        .try_with(|table| {
            table.prune(now);
            table.recent(pid, process_path, now)
        })
        .unwrap_or_default()
}

/// `(recorded, dropped_locked)` since start.
pub fn counters() -> (u64, u64) {
    (
        RECORDED.load(Ordering::Relaxed),
        DROPPED_LOCKED.load(Ordering::Relaxed),
    )
}

/// Test-only: forget every recorded open.
pub fn clear_for_tests() {
    TABLE.try_with(|table| table.by_pid.clear());
}

/// Test-only: record without the own-process filter, so a unit test can
/// stand in for another process.
pub fn record_open_for_tests(pid: u32, process_path: &str, file_path: &str) {
    if is_cold_credential_path(file_path) {
        let now = now_ms();
        TABLE.try_with(|table| table.record(pid, None, process_path, file_path, now));
    }
}

// ---------------------------------------------------------------------------
// Kernel watch prefixes
// ---------------------------------------------------------------------------

/// Interactive user homes on this host, plus `$HOME`. The sensor runs as
/// root, so its own home is not the user's.
pub fn user_homes() -> Vec<PathBuf> {
    let mut homes: Vec<PathBuf> = Vec::new();
    let mut push = |path: PathBuf| {
        if homes.len() < MAX_HOMES && path.is_dir() && !homes.contains(&path) {
            homes.push(path);
        }
    };
    let roots: &[&str] = if cfg!(target_os = "macos") {
        &["/Users"]
    } else if cfg!(target_os = "linux") {
        &["/home"]
    } else {
        &[]
    };
    for root in roots {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') || name == "Shared" {
                continue;
            }
            push(entry.path());
        }
    }
    if cfg!(target_os = "linux") {
        push(PathBuf::from("/root"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        push(PathBuf::from(home));
    }
    homes
}

/// Home-relative locations of the cold set: the cold label patterns that
/// name a dot directory or an Application Support folder (`/id_rsa`-style
/// basename patterns are covered by the `~/.ssh/` prefix), with the
/// case-preserving catalog patterns that classify as cold.
pub fn home_relative_cold_patterns() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |rel: String| {
        if !out.iter().any(|p| p.eq_ignore_ascii_case(&rel)) {
            out.push(rel);
        }
    };
    for pattern in crate::open_files::sensitive_patterns() {
        if is_home_relative(&pattern) && is_cold_credential_path(&pattern) {
            push(pattern);
        }
    }
    let params = crate::sensitive_paths::credential_opens_params();
    let home_roots = crate::sensitive_paths::credential_opens_label_home_roots();
    let cold_labels: Vec<&str> = params.cold_labels.iter().map(String::as_str).collect();
    for pattern in crate::sensitive_paths::label_patterns_sync(&cold_labels) {
        if is_hot(&params.hot_subpaths, &pattern) {
            continue;
        }
        if let Some((root, rest)) = home_roots.iter().find_map(|root| {
            pattern
                .strip_prefix(root.label_prefix.as_str())
                .map(|rest| (root, rest))
        }) {
            push(format!("{}{rest}", root.home_prefix));
        } else if pattern.starts_with("/.") {
            push(pattern);
        }
    }
    out
}

/// A dot directory under the home, or a path under one of the platform's
/// published home roots (the first component of each `home_prefix`:
/// `/Library/` on macOS).
fn is_home_relative(pattern: &str) -> bool {
    pattern.starts_with("/.")
        || crate::sensitive_paths::credential_opens_label_home_roots()
            .iter()
            .filter_map(|root| home_root_component(&root.home_prefix))
            .any(|component| pattern.starts_with(component))
}

/// `/Library/` of `/Library/Application Support/`.
fn home_root_component(home_prefix: &str) -> Option<&str> {
    let rest = home_prefix.strip_prefix('/')?;
    let end = rest.find('/')?;
    Some(&home_prefix[..end + 2])
}

/// Absolute kernel watch prefixes: every cold pattern under every home,
/// with each path component matched case-insensitively against what is on
/// disk (catalog labels are lowercase; `~/Library/Application Support/Bitcoin`
/// is not), so a prefix compares equal to the path the kernel reports.
pub fn kernel_watch_prefixes(homes: &[PathBuf]) -> Vec<String> {
    let patterns = home_relative_cold_patterns();
    let mut out: Vec<String> = Vec::new();
    for home in homes {
        for rel in &patterns {
            if out.len() >= MAX_WATCH_PREFIXES {
                return out;
            }
            let trailing_slash = rel.ends_with('/');
            let resolved = resolve_case(home, rel.trim_matches('/'));
            let mut prefix = resolved.to_string_lossy().to_string();
            if trailing_slash && !prefix.ends_with('/') {
                prefix.push('/');
            }
            if !out.contains(&prefix) {
                out.push(prefix);
            }
        }
    }
    out
}

/// `base` joined with `rel`, each component replaced by the on-disk entry
/// that matches it case-insensitively when one exists.
fn resolve_case(base: &Path, rel: &str) -> PathBuf {
    let mut cur = base.to_path_buf();
    for component in rel.split('/').filter(|c| !c.is_empty()) {
        let on_disk = std::fs::read_dir(&cur).ok().and_then(|entries| {
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .find(|name| name.eq_ignore_ascii_case(component))
        });
        cur.push(on_disk.as_deref().unwrap_or(component));
    }
    cur
}

// ---------------------------------------------------------------------------
// Linux backend: fanotify FAN_OPEN on the cold directories only
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "linux", feature = "ebpf"))]
mod linux {
    use super::*;
    use nix::sys::fanotify::{EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags};
    use once_cell::sync::OnceCell;
    use std::collections::HashSet;
    use std::os::fd::AsRawFd;
    use std::sync::Arc;
    use std::time::Duration;
    use tracing::{debug, info, warn};

    /// Directory marks for the cold set (well under the kernel's default
    /// `max_user_marks`, which `fim_fanotify` also draws from).
    const MAX_MARKS: usize = 512;
    /// Wallet / cloud CLI directories are often created after the daemon
    /// starts; re-mark on this cadence.
    const REMARK_INTERVAL: Duration = Duration::from_secs(300);

    struct Watcher {
        fan: Fanotify,
        marked: CustomMutex<HashSet<PathBuf>>,
    }

    static WATCHER: OnceCell<Arc<Watcher>> = OnceCell::new();

    pub fn start() {
        if WATCHER.get().is_some() {
            return;
        }
        let fan = match Fanotify::init(
            InitFlags::FAN_CLASS_NOTIF | InitFlags::FAN_CLOEXEC,
            EventFFlags::O_RDONLY | EventFFlags::O_CLOEXEC | EventFFlags::O_LARGEFILE,
        ) {
            Ok(fan) => fan,
            Err(e) => {
                info!("credential-open fanotify unavailable: {} (closed credential reads not remembered)", e);
                return;
            }
        };
        let watcher = Arc::new(Watcher {
            fan,
            marked: CustomMutex::new(HashSet::new()),
        });
        if WATCHER.set(Arc::clone(&watcher)).is_err() {
            return;
        }
        let marked = remark(&watcher);
        let reader = Arc::clone(&watcher);
        if let Err(e) = std::thread::Builder::new()
            .name("credential-open-fanotify".into())
            .spawn(move || reader_loop(reader))
        {
            warn!("credential-open fanotify reader spawn failed: {}", e);
            return;
        }
        let remarker = Arc::clone(&watcher);
        let _ = std::thread::Builder::new()
            .name("credential-open-remark".into())
            .spawn(move || loop {
                std::thread::sleep(REMARK_INTERVAL);
                remark(&remarker);
            });
        info!(
            "credential-open fanotify active: {} directories marked",
            marked
        );
    }

    /// Directories to mark for one prefix: the prefix itself when it is a
    /// directory (and its subdirectories, bounded), else its parent.
    fn directories_for(prefix: &str) -> Vec<PathBuf> {
        let path = PathBuf::from(prefix.trim_end_matches('/'));
        let root = if path.is_dir() {
            path
        } else {
            match path.parent() {
                Some(parent) if parent.is_dir() => parent.to_path_buf(),
                _ => return Vec::new(),
            }
        };
        let mut out = Vec::new();
        let mut queue = std::collections::VecDeque::from([root]);
        while let Some(dir) = queue.pop_front() {
            if out.len() >= 64 {
                break;
            }
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    if entry
                        .file_type()
                        .is_ok_and(|ft| ft.is_dir() && !ft.is_symlink())
                    {
                        queue.push_back(entry.path());
                    }
                }
            }
            out.push(dir);
        }
        out
    }

    fn remark(watcher: &Watcher) -> usize {
        let prefixes = kernel_watch_prefixes(&user_homes());
        let mut added = 0usize;
        for prefix in prefixes {
            for dir in directories_for(&prefix) {
                let fresh = watcher
                    .marked
                    .try_with(|marked| marked.len() < MAX_MARKS && !marked.contains(&dir))
                    .unwrap_or(false);
                if !fresh {
                    continue;
                }
                let Ok(handle) = std::fs::File::open(&dir) else {
                    continue;
                };
                match watcher.fan.mark::<_, Path>(
                    MarkFlags::FAN_MARK_ADD,
                    MaskFlags::FAN_OPEN | MaskFlags::FAN_EVENT_ON_CHILD,
                    &handle,
                    None,
                ) {
                    Ok(()) => {
                        watcher.marked.try_with(|marked| marked.insert(dir.clone()));
                        added += 1;
                    }
                    Err(e) => debug!(
                        "credential-open fanotify: mark {} failed: {}",
                        dir.display(),
                        e
                    ),
                }
            }
        }
        added
    }

    fn proc_uid(pid: u32) -> Option<u32> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|uid| uid.parse().ok())
    }

    fn reader_loop(watcher: Arc<Watcher>) {
        loop {
            let events = match watcher.fan.read_events() {
                Ok(events) => events,
                Err(nix::errno::Errno::EINTR) | Err(nix::errno::Errno::EAGAIN) => continue,
                Err(e) => {
                    warn!("credential-open fanotify reader stopped: {}", e);
                    return;
                }
            };
            for event in events {
                let Some(fd) = event.fd() else {
                    continue;
                };
                let pid = event.pid();
                if pid <= 0 || pid as u32 == std::process::id() {
                    continue;
                }
                let pid = pid as u32;
                let Ok(path) = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
                else {
                    continue;
                };
                let process_path = std::fs::read_link(format!("/proc/{pid}/exe"))
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                record_open(pid, proc_uid(pid), &process_path, &path.to_string_lossy());
            }
        }
    }
}

/// Start the backend that is not hosted by an existing sensor thread
/// (Linux fanotify). macOS records from a dedicated Endpoint Security
/// client in `l7_es`, Windows from the ETW FileIo session in `l7_etw`.
pub fn start() {
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    linux::start();
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE: &str = "/opt/homebrew/bin/node";
    const KEY: &str = "/Users/u/.config/solana/id.json";

    #[test]
    fn the_cold_set_is_wallets_ssh_cloud_and_gpg_only() {
        for cold in [
            KEY,
            "/Users/u/.ssh/id_ed25519",
            "/home/u/.aws/credentials",
            "/home/u/.config/gcloud/application_default_credentials.json",
            "/Users/u/.azure/msal_token_cache.json",
            "/Users/u/.gnupg/private-keys-v1.d/abc.key",
            "/Users/u/Library/Application Support/Exodus/exodus.wallet/seed.seco",
            r"C:\Users\u\.ssh\id_rsa",
        ] {
            assert!(is_cold_credential_path(cold), "{cold} should be cold");
        }
        for hot in [
            "/Users/u/Library/Application Support/Google/Chrome/Default/Cookies",
            "/Users/u/project/.env",
            "/Users/u/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log",
            "/Users/u/Library/Application Support/Bitcoin/blocks/blk00001.dat",
            "/Users/u/.npmrc",
            "/usr/lib/libssl.dylib",
        ] {
            assert!(!is_cold_credential_path(hot), "{hot} should not be cold");
        }
    }

    /// The cold set is the published `credential_opens`, read through the
    /// accessors production uses: every published hot sub-path takes a
    /// cold-labelled path off the set, the TTL is the published one, and
    /// each label home root maps its label prefix under the home.
    #[test]
    fn the_cold_set_is_the_published_params() {
        let params = crate::sensitive_paths::credential_opens_params();
        assert!(!params.cold_labels.is_empty(), "{params:?}");
        assert_eq!(credential_open_ttl_ms(), params.open_ttl_secs * 1000);
        assert!(params.open_ttl_secs > 0);
        let cold_labels: Vec<&str> = params.cold_labels.iter().map(String::as_str).collect();
        let cold_patterns = crate::sensitive_paths::label_patterns_sync(&cold_labels);
        assert!(!cold_patterns.is_empty());
        for hot in &params.hot_subpaths {
            // A cold-labelled path that runs through the hot sub-path.
            let path = format!("/Users/u/.ssh{hot}x");
            assert!(!is_cold_credential_path(&path), "{path}");
        }
        for root in crate::sensitive_paths::credential_opens_label_home_roots() {
            assert!(
                root.home_prefix
                    .to_ascii_lowercase()
                    .ends_with(&root.label_prefix),
                "{root:?}"
            );
            let component = home_root_component(&root.home_prefix).expect("a root directory");
            assert!(is_home_relative(&format!("{component}x")), "{root:?}");
            if cold_patterns.iter().any(|p| {
                p.starts_with(root.label_prefix.as_str()) && !is_hot(&params.hot_subpaths, p)
            }) {
                assert!(
                    home_relative_cold_patterns()
                        .iter()
                        .any(|p| p.starts_with(root.home_prefix.as_str())),
                    "{root:?}"
                );
            }
        }
    }

    #[test]
    fn home_root_component_is_the_first_directory() {
        assert_eq!(
            home_root_component("/Library/Application Support/"),
            Some("/Library/")
        );
        assert_eq!(home_root_component("/Library/"), Some("/Library/"));
        assert_eq!(home_root_component("Library/"), None);
        assert_eq!(home_root_component("/x"), None);
    }

    #[test]
    fn one_slot_per_path_refreshed_in_place_and_expired_after_the_ttl() {
        let mut table = OpenTable::default();
        for i in 0..1_000 {
            table.record(700, None, NODE, KEY, 1_000 + i);
        }
        assert_eq!(table.by_pid[&700].last_open_ms_by_path.len(), 1);
        assert_eq!(table.recent(700, Some(NODE), 2_000), vec![KEY]);

        let expiry = 1_999 + credential_open_ttl_ms();
        assert_eq!(table.recent(700, Some(NODE), expiry), vec![KEY]);
        assert!(table.recent(700, Some(NODE), expiry + 1).is_empty());
        table.prune(expiry + 1);
        assert!(table.by_pid.is_empty());
    }

    #[test]
    fn a_reused_pid_on_another_image_does_not_inherit_opens() {
        let mut table = OpenTable::default();
        table.record(700, None, NODE, KEY, 1);
        assert!(table.recent(700, Some("/usr/bin/curl"), 2).is_empty());
        assert_eq!(table.recent(700, None, 2), vec![KEY]);

        table.record(700, None, "/usr/bin/curl", "/Users/u/.aws/credentials", 3);
        assert_eq!(
            table.recent(700, Some("/usr/bin/curl"), 4),
            vec!["/Users/u/.aws/credentials"]
        );
    }

    #[test]
    fn paths_per_pid_and_pids_are_capped() {
        let mut table = OpenTable::default();
        for i in 0..(MAX_PATHS_PER_PID as u64 + 5) {
            table.record(700, None, NODE, &format!("/Users/u/.ssh/key{i}"), i + 1);
        }
        let kept = table.recent(700, None, 100);
        assert_eq!(kept.len(), MAX_PATHS_PER_PID);
        assert!(!kept.contains(&"/Users/u/.ssh/key0".to_string()));

        let mut table = OpenTable::default();
        for pid in 0..(MAX_PIDS as u32 + 10) {
            table.record(pid + 1, None, NODE, KEY, u64::from(pid) + 1);
        }
        assert_eq!(table.by_pid.len(), MAX_PIDS);
        assert!(
            !table.by_pid.contains_key(&1),
            "least recently active dropped"
        );
    }

    #[test]
    fn the_observer_never_records_its_own_opens() {
        clear_for_tests();
        record_open(std::process::id(), None, NODE, KEY);
        let own = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .to_string();
        record_open(4_242_001, None, &own, KEY);
        assert!(recent_for_pid(std::process::id(), None).is_empty());
        assert!(recent_for_pid(4_242_001, None).is_empty());
    }

    // Kernel watch prefixes feed Endpoint Security and fanotify only; Windows
    // records cold opens through ETW and never builds them.
    #[cfg(unix)]
    #[test]
    fn watch_prefixes_cover_the_cold_directories_under_each_home() {
        let homes = vec![PathBuf::from("/nonexistent-home-a")];
        let prefixes = kernel_watch_prefixes(&homes);
        for expected in [
            "/nonexistent-home-a/.ssh/",
            "/nonexistent-home-a/.aws/",
            "/nonexistent-home-a/.gnupg/",
            "/nonexistent-home-a/.config/solana/",
            "/nonexistent-home-a/.config/gcloud/",
        ] {
            assert!(
                prefixes.iter().any(|p| p == expected),
                "missing {expected} in {prefixes:?}"
            );
        }
        for prefix in &prefixes {
            let lower = prefix.to_ascii_lowercase();
            assert!(
                !lower.contains("cookies") && !lower.contains("/.env"),
                "{prefix}"
            );
            assert!(!lower.contains("local extension settings"), "{prefix}");
        }
    }

    #[test]
    fn watch_prefixes_take_the_case_that_is_on_disk() {
        let base = std::env::temp_dir().join(format!("flodbadd-credopen-{}", std::process::id()));
        let dir = base.join("Library/Application Support/Exodus");
        std::fs::create_dir_all(&dir).unwrap();
        let resolved = resolve_case(&base, "library/application support/exodus");
        let _ = std::fs::remove_dir_all(&base);
        assert_eq!(resolved, dir);
    }
}
