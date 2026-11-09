use crate::sensitive_paths::SENSITIVE_PATHS;
use crate::sessions::SessionL7;
use arc_swap::ArcSwap;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use undeadlock::CustomDashMap;

pub const MAX_OPEN_FILES: usize = 100;

/// Compiled-in fallback patterns used before the cloud model snapshot is populated.
const FALLBACK_COMMON: &[&str] = &[
    "/.ssh/",
    "/.gnupg/",
    "/.aws/credentials",
    "/.aws/config",
    "/.kube/config",
    "/.docker/config.json",
    "/.npmrc",
    "/.env",
    "/.netrc",
    "/.pgpass",
    "/.pypirc",
    "/credentials.json",
    "/id_rsa",
    "/id_ed25519",
    "/id_ecdsa",
    "/id_dsa",
    "/Login Data",
    "/Cookies$",
    "/Cookies-journal$",
    "/Network/Cookies",
    "/cookies.sqlite",
    "/Cookies.binarycookies",
    "/Web Data",
    "/.git-credentials",
    "/.vault-token",
    "/.config/gcloud/application_default_credentials.json",
    "/.azure/",
    "/.my.cnf",
    "/.bitcoin/",
    "/.ethereum/keystore/",
    "/.config/solana/id.json",
    "/.bitmonero/",
    "/.litecoin/",
    "/.dogecoin/",
    "/CLAUDE.md",
    "/AGENTS.md",
    "/.cursorrules",
    "/mcp.json",
    "/.cursor/rules/",
];

#[cfg(target_os = "macos")]
const FALLBACK_PLATFORM: &[&str] = &[
    "/Library/Keychains/",
    "/MobileSyncBackup/",
    "/Library/Application Support/Bitcoin/",
    "/Library/Application Support/Ethereum/keystore/",
    "/Library/Application Support/Litecoin/",
    "/Library/Application Support/Dogecoin/",
    "/Library/Application Support/Monero/",
];

#[cfg(target_os = "linux")]
const FALLBACK_PLATFORM: &[&str] = &["/etc/shadow", "/etc/gshadow", "/etc/security/opasswd"];

#[cfg(target_os = "windows")]
const FALLBACK_PLATFORM: &[&str] = &[
    "/AppData/Roaming/Microsoft/Credentials/",
    "/AppData/Roaming/Microsoft/Protect/",
    "/Windows/System32/config/SAM",
    "/Windows/System32/config/SECURITY",
    "/Windows/NTDS/ntds.dit",
    "/AppData/Local/Google/Chrome/User Data/",
    "/AppData/Roaming/Mozilla/Firefox/Profiles/",
    "/AppData/Local/Bitcoin/",
    "/AppData/Local/Ethereum/keystore/",
    "/AppData/Roaming/Litecoin/",
    "/AppData/Roaming/Dogecoin/",
    "/AppData/Local/bitmonero/",
];

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
const FALLBACK_PLATFORM: &[&str] = &[];

fn build_fallback_patterns() -> Vec<String> {
    let mut patterns: Vec<String> = FALLBACK_COMMON.iter().map(|s| s.to_string()).collect();
    patterns.extend(FALLBACK_PLATFORM.iter().map(|s| s.to_string()));
    patterns
}

lazy_static::lazy_static! {
    static ref PATTERNS_SNAPSHOT: ArcSwap<Vec<String>> =
        ArcSwap::from_pointee(build_fallback_patterns());
}

/// Refresh the sync-accessible pattern snapshot from the cloud model.
/// Called after every `sensitive_paths::update()` attempt, regardless of status --
/// see the comment there for why `Updated`-only refreshing was wrong.
pub async fn refresh_patterns_snapshot() {
    let db = SENSITIVE_PATHS.data.read().await;
    let patterns: Vec<String> = db
        .get_patterns_for_platform()
        .into_iter()
        .map(str::to_string)
        .collect();
    PATTERNS_SNAPSHOT.store(Arc::new(patterns));
}

/// Returns true if `path` matches a known credential / secret pattern.
/// Uses a lock-free snapshot refreshed from the cloud model.
pub fn is_sensitive_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let patterns = PATTERNS_SNAPSHOT.load();
    patterns
        .iter()
        .any(|pat| crate::sensitive_paths::catalog_pattern_matches(&normalized, pat))
}

/// Returns the combined list of sensitive patterns (common + platform).
pub fn sensitive_patterns() -> Vec<String> {
    PATTERNS_SNAPSHOT.load().as_ref().clone()
}

lazy_static::lazy_static! {
    /// The file names that mark a store as the process's own (the detector
    /// params' `ownership_lock_file_names`: LevelDB `LOCK`, Firefox
    /// `parent.lock`, ...), lowercase. Empty until the params are handed over
    /// ([`set_ownership_lock_file_names`]): the capture then records no lock.
    static ref OWNERSHIP_LOCK_NAMES: ArcSwap<Vec<String>> = ArcSwap::from_pointee(Vec::new());
}

/// Install the lock-file names the capture records for the detector's
/// OWNS-by-lock relation. Foundation hands them over from the detector params
/// in whichever process runs the capture (the helper on the app path, the
/// daemon standalone), at capture start and after each params update.
pub fn set_ownership_lock_file_names(names: &[String]) {
    let names: Vec<String> = names
        .iter()
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect();
    OWNERSHIP_LOCK_NAMES.store(Arc::new(names));
}

/// `path`'s file name is one of the ownership lock-file names. Compared in
/// place (the names are stored lowercase): this runs on every open-file
/// path a resolution keeps.
pub fn is_ownership_lock_path(path: &str) -> bool {
    let name = path.rsplit(['/', '\\']).next().unwrap_or("").trim();
    !name.is_empty()
        && OWNERSHIP_LOCK_NAMES
            .load()
            .iter()
            .any(|lock| lock.eq_ignore_ascii_case(name))
}

/// A path a session's record keeps by name and carries across
/// re-resolutions: sensitive material, or a lock file marking the store its
/// process owns.
fn is_retained_open_file_path(path: &str) -> bool {
    is_sensitive_path(path) || is_ownership_lock_path(path)
}

fn should_keep_open_file_path(path: &str) -> bool {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return false;
    }

    let normalized = trimmed.replace('\\', "/");
    normalized != "/"
}

fn directory_glob_entry(dir: &str) -> String {
    let trimmed = dir.trim_end_matches('/');
    if trimmed.is_empty() {
        "/*".to_string()
    } else {
        format!("{}/*", trimmed)
    }
}

/// Aggregate file paths when the list exceeds MAX_OPEN_FILES.
/// Sensitive paths (credentials, keys, etc.) and ownership lock files are
/// always preserved individually; only the other paths are subject to
/// directory-level aggregation.
pub fn aggregate_open_files(mut paths: Vec<String>) -> Vec<String> {
    paths.retain(|path| should_keep_open_file_path(path));
    paths.sort();
    paths.dedup();

    if paths.len() <= MAX_OPEN_FILES {
        return paths;
    }

    // Partition: retained paths survive aggregation unconditionally
    let (sensitive, regular): (Vec<_>, Vec<_>) = paths
        .into_iter()
        .partition(|p| is_retained_open_file_path(p));

    let budget = MAX_OPEN_FILES.saturating_sub(sensitive.len());
    let mut result = sensitive;
    result.extend(aggregate_regular(regular, budget));
    result.sort();
    result.dedup();
    result.truncate(MAX_OPEN_FILES);
    result
}

/// Directory-level aggregation for non-sensitive paths, capped to `budget`.
fn aggregate_regular(paths: Vec<String>, budget: usize) -> Vec<String> {
    if paths.len() <= budget {
        return paths;
    }

    let mut dir_counts: HashMap<String, Vec<String>> = HashMap::new();
    for p in &paths {
        let parent = Path::new(p)
            .parent()
            .map(|d| d.to_string_lossy().to_string())
            .unwrap_or_else(|| "/".to_string());
        dir_counts.entry(parent).or_default().push(p.clone());
    }

    let mut ranked: Vec<(String, Vec<String>)> = dir_counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

    let mut result: Vec<String> = Vec::new();
    let mut remaining = budget;

    for (dir, files) in &ranked {
        if remaining == 0 {
            break;
        }
        if files.len() > 1 && result.len() + files.len() > budget {
            let entry = directory_glob_entry(dir);
            if !result.contains(&entry) {
                result.push(entry);
                remaining = remaining.saturating_sub(1);
            }
        } else {
            for f in files {
                if remaining == 0 {
                    let entry = directory_glob_entry(dir);
                    if !result.contains(&entry) {
                        result.push(entry);
                    }
                    break;
                }
                result.push(f.clone());
                remaining = remaining.saturating_sub(1);
            }
        }
    }

    result
}

/// Merge sensitive paths from a previous snapshot into the current one.
/// Sensitive files and ownership lock files that were observed in
/// `previous` but are absent from `current` are carried forward (sticky), so
/// a file that was open during one L7 refresh cycle remains visible even if
/// the process closed it before the next cycle. Other paths are NOT carried
/// forward, and they are the ones the cap drops first.
pub fn merge_sensitive_open_files(mut current: Vec<String>, previous: &[String]) -> Vec<String> {
    for p in previous {
        if is_retained_open_file_path(p) && !current.contains(p) {
            current.push(p.clone());
        }
    }
    current.sort();
    current.dedup();
    if current.len() > MAX_OPEN_FILES {
        let (retained, other): (Vec<_>, Vec<_>) = current
            .into_iter()
            .partition(|p| is_retained_open_file_path(p));
        current = retained;
        let room = MAX_OPEN_FILES.saturating_sub(current.len());
        current.extend(other.into_iter().take(room));
        current.sort();
        current.truncate(MAX_OPEN_FILES);
    }
    current
}

/// The lock files a session's process and its parent of the same image hold,
/// appended to `l7.open_files` (FP-MAC-29): what the detector's OWNS-by-lock
/// relation reads. Chromium's network service, the session's process, holds
/// the profile's `Cookies`; the browser process of the same image holds the
/// profile's LevelDB `LOCK` files. The capture calls it each time it attaches
/// a resolution to its session: the first time it sees the process there it
/// reads them, afterwards it carries forward what `previous` (the session's
/// record) holds for the same process, so a browser that exited before the
/// detector's tick keeps the fact. The resolver reads the parent's locks
/// already, while the process runs ([`add_same_image_parent_lock_files`]):
/// the update pass that attaches a resolution can come after a short-lived
/// browser exited, and a read at that point finds no parent. A record that
/// holds no lock file yet asks the same-image parent again at each attach
/// ([`READS_PARENT_LOCKS`]). Only lock files are added: a parent's
/// other open files would attribute material to a child that never opened
/// it.
pub fn retain_ownership_lock_files(l7: &mut SessionL7, previous: Option<&SessionL7>) {
    if OWNERSHIP_LOCK_NAMES.load().is_empty() {
        return;
    }
    let material = lock_material(l7);
    retain_ownership_lock_files_with(l7, previous, READS_PARENT_LOCKS, &mut |pid| {
        locks_held_by(pid, &material)
    });
}

/// Whether a parent's lock files are read beyond a session's first attach
/// (when the resolver resolves a connection, and again while the record
/// holds none). Everywhere since 2.3.2: on Windows the handle enumeration
/// leaves out the handles a process holds for writing (`win_handles`), a
/// lock file among them, so the holders are asked by path instead
/// ([`lock_file_holders`]).
const READS_PARENT_LOCKS: bool = true;

/// Appends to `l7.open_files` the lock files its parent of the same image
/// holds now (the browser process of a Chromium network service). The
/// resolver calls it on every resolution, while the process runs: the
/// capture attaches a resolution to its session on its update pass, which a
/// short-lived browser can outlive (2026-11-08: a headless browser that ran
/// 45 s between two passes left all its sessions without the locks, read at
/// attach time after it exited).
pub fn add_same_image_parent_lock_files(l7: &mut SessionL7) {
    if !READS_PARENT_LOCKS || OWNERSHIP_LOCK_NAMES.load().is_empty() {
        return;
    }
    let Some(parent_pid) = same_image_parent(l7) else {
        return;
    };
    for lock in locks_held_by(parent_pid, &lock_material(l7)) {
        if !l7.open_files.contains(&lock) {
            l7.open_files.push(lock);
        }
    }
}

/// The paths whose store's lock files [`locks_held_by`] looks for on
/// Windows: the record's open files. Elsewhere the holder is enumerated
/// directly and nothing is copied.
fn lock_material(l7: &SessionL7) -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        l7.open_files.clone()
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = l7;
        Vec::new()
    }
}

/// The lock files `pid` holds now, read from its open files where the
/// enumeration sees them. On Windows a handle held for writing is left out
/// of the enumeration (`win_handles`), so the lock files that may mark the
/// stores `material` lies in are listed on disk ([`lock_file_candidates`])
/// and their holders asked for by path ([`lock_file_holders`]).
fn locks_held_by(pid: u32, material: &[String]) -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        cached_locks_held_with(
            &LOCKS_HELD_CACHE,
            pid,
            lock_material_key(material),
            Instant::now(),
            LOCKS_HELD_CACHE_TTL,
            || {
                let mut locks: Vec<String> = lock_file_holders(&lock_file_candidates(material))
                    .into_iter()
                    .filter(|(_, pids)| pids.contains(&pid))
                    .map(|(path, _)| path)
                    .collect();
                locks.sort();
                locks
            },
        )
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = material;
        get_open_file_paths(pid)
            .into_iter()
            .filter(|path| is_ownership_lock_path(path))
            .collect()
    }
}

/// Directory roots listed per call of [`lock_file_candidates`], and the
/// directories read below each root (two levels, breadth first).
const LOCK_CANDIDATE_ROOTS: usize = 32;
const LOCK_CANDIDATE_DIRS_PER_ROOT: usize = 64;
const LOCK_CANDIDATE_DEPTH: usize = 2;
/// Lock files reported per call.
const LOCK_CANDIDATES: usize = 128;

/// The lock files on disk that may mark the stores `material` (paths a
/// process holds open) lies in: files named like an ownership lock
/// (compared without case) in each path's directory, its parent, and the
/// subdirectories of both, two levels down and bounded. A profile's locks
/// sit beside its databases (`parent.lock`), a level above them
/// (`lockfile`) or in a store's own subdirectory (`Local Storage/leveldb/LOCK`
/// beside `Cookies`). The paths are what [`lock_file_holders`] is asked
/// about; the listing runs where the files are readable (the helper, a
/// standalone daemon), like the enumeration itself.
pub fn lock_file_candidates(material: &[String]) -> Vec<String> {
    let names = OWNERSHIP_LOCK_NAMES.load();
    if names.is_empty() || material.is_empty() {
        return Vec::new();
    }
    let mut roots: Vec<std::path::PathBuf> = Vec::new();
    for path in material {
        let path = Path::new(path.trim());
        for root in [path.parent(), path.parent().and_then(Path::parent)]
            .into_iter()
            .flatten()
        {
            if roots.len() >= LOCK_CANDIDATE_ROOTS {
                break;
            }
            if !root.as_os_str().is_empty() && !roots.iter().any(|known| known == root) {
                roots.push(root.to_path_buf());
            }
        }
    }
    let mut out: Vec<String> = Vec::new();
    let mut listed: std::collections::HashSet<std::path::PathBuf> =
        std::collections::HashSet::new();
    for root in roots {
        let mut queue = std::collections::VecDeque::from([(root, 0usize)]);
        let mut read = 0usize;
        while let Some((dir, depth)) = queue.pop_front() {
            if read >= LOCK_CANDIDATE_DIRS_PER_ROOT || out.len() >= LOCK_CANDIDATES {
                break;
            }
            if !listed.insert(dir.clone()) {
                continue;
            }
            read += 1;
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                if file_type.is_dir() && !file_type.is_symlink() {
                    if depth < LOCK_CANDIDATE_DEPTH {
                        queue.push_back((entry.path(), depth + 1));
                    }
                } else if file_type.is_file() {
                    let name = entry.file_name();
                    let is_lock = name.to_str().is_some_and(|name| {
                        names.iter().any(|lock| lock.eq_ignore_ascii_case(name))
                    });
                    if is_lock {
                        let candidate = entry.path().to_string_lossy().to_string();
                        if !out.contains(&candidate) {
                            out.push(candidate);
                            if out.len() >= LOCK_CANDIDATES {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// The processes holding each of `paths` open, by path. On Windows the
/// Restart Manager answers for the files the handle enumeration leaves out
/// (those held for writing, a lock file among them), without duplicating any
/// handle; elsewhere the enumeration sees them and this reads empty.
pub fn lock_file_holders(paths: &[String]) -> HashMap<String, Vec<u32>> {
    #[cfg(target_os = "windows")]
    {
        restart_manager::holders(paths)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = paths;
        HashMap::new()
    }
}

#[cfg(target_os = "windows")]
mod restart_manager {
    //! Which processes hold a file open, asked of the Restart Manager: it
    //! answers by path, for handles of every access mode, and duplicates
    //! nothing into this process (see `win_handles::resolvable` for why a
    //! writer's handle must never be duplicated).

    use std::collections::HashMap;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
    use windows::Win32::System::RestartManager::{
        RmEndSession, RmGetList, RmRegisterResources, RmStartSession, CCH_RM_SESSION_KEY,
        RM_PROCESS_INFO,
    };

    /// Paths asked about per call; a session costs a scan of the running
    /// processes, so one shared session first, then one per path only when
    /// something holds one of them.
    const MAX_QUERIED_PATHS: usize = 64;

    pub(super) fn holders(paths: &[String]) -> HashMap<String, Vec<u32>> {
        let mut out = HashMap::new();
        let paths: Vec<&String> = paths.iter().take(MAX_QUERIED_PATHS).collect();
        if paths.is_empty() {
            return out;
        }
        let any = holders_of(&paths);
        if any.is_empty() {
            return out;
        }
        if paths.len() == 1 {
            out.insert(paths[0].clone(), any);
            return out;
        }
        for path in paths {
            let pids = holders_of(&[path]);
            if !pids.is_empty() {
                out.insert(path.clone(), pids);
            }
        }
        out
    }

    /// The pids holding any of `paths`, sorted, each once.
    fn holders_of(paths: &[&String]) -> Vec<u32> {
        let wide: Vec<Vec<u16>> = paths
            .iter()
            .map(|path| path.encode_utf16().chain(std::iter::once(0)).collect())
            .collect();
        let names: Vec<PCWSTR> = wide.iter().map(|w| PCWSTR(w.as_ptr())).collect();
        let mut session: u32 = 0;
        let mut key = [0u16; CCH_RM_SESSION_KEY as usize + 1];
        let mut pids: Vec<u32> = Vec::new();
        // SAFETY: plain Win32 calls over buffers that outlive them; the
        // session is ended on every path once started.
        unsafe {
            if RmStartSession(&mut session, None, PWSTR(key.as_mut_ptr())) != ERROR_SUCCESS {
                return pids;
            }
            if RmRegisterResources(session, Some(&names), None, None) == ERROR_SUCCESS {
                let mut needed: u32 = 0;
                let mut count: u32 = 0;
                let mut reasons: u32 = 0;
                let mut infos: Vec<RM_PROCESS_INFO> = Vec::new();
                // The first call sizes the list (ERROR_MORE_DATA), the
                // second fills it; one more round covers a process that
                // opened the file in between.
                for _ in 0..3 {
                    let status = RmGetList(
                        session,
                        &mut needed,
                        &mut count,
                        if infos.is_empty() {
                            None
                        } else {
                            Some(infos.as_mut_ptr())
                        },
                        &mut reasons,
                    );
                    if status == ERROR_SUCCESS {
                        let filled = (count as usize).min(infos.len());
                        pids = infos[..filled]
                            .iter()
                            .map(|info| info.Process.dwProcessId)
                            .collect();
                        break;
                    }
                    if status != ERROR_MORE_DATA {
                        break;
                    }
                    infos = vec![RM_PROCESS_INFO::default(); needed as usize];
                    count = needed;
                }
            }
            let _ = RmEndSession(session);
        }
        pids.sort_unstable();
        pids.dedup();
        pids
    }
}

/// The pure half of [`retain_ownership_lock_files`]: `locks_of` reports the
/// lock files a pid holds now. The same process is the same pid with the
/// same start time (a recycled pid is a new process, its predecessor's locks
/// are not its own). A pid of zero, or a parent of another image, is not
/// asked. With `asks_parent_again`, a record of the same process that holds
/// no lock file asks the same-image parent its current lineage names.
fn retain_ownership_lock_files_with(
    l7: &mut SessionL7,
    previous: Option<&SessionL7>,
    asks_parent_again: bool,
    locks_of: &mut dyn FnMut(u32) -> Vec<String>,
) {
    fn append(l7: &mut SessionL7, path: String) {
        if !l7.open_files.contains(&path) {
            l7.open_files.push(path);
        }
    }
    if let Some(previous) =
        previous.filter(|prev| prev.pid == l7.pid && prev.start_time == l7.start_time)
    {
        for path in previous
            .open_files
            .iter()
            .filter(|path| is_ownership_lock_path(path))
        {
            append(l7, path.clone());
        }
        let holds_a_lock = l7
            .open_files
            .iter()
            .any(|path| is_ownership_lock_path(path));
        if asks_parent_again && !holds_a_lock {
            if let Some(parent_pid) = same_image_parent(l7) {
                for lock in locks_of(parent_pid) {
                    append(l7, lock);
                }
            }
        }
        return;
    }
    let mut pids: Vec<u32> = Vec::new();
    if l7.pid > 0 {
        pids.push(l7.pid);
    }
    pids.extend(same_image_parent(l7));
    for pid in pids {
        for lock in locks_of(pid) {
            append(l7, lock);
        }
    }
}

/// The parent `l7` names when it runs the process's own image.
fn same_image_parent(l7: &SessionL7) -> Option<u32> {
    let same_image =
        !l7.process_path.trim().is_empty() && l7.process_path == l7.parent_process_path;
    match (l7.parent_pid, same_image) {
        (Some(parent_pid), true) if parent_pid > 0 && parent_pid != l7.pid => Some(parent_pid),
        _ => None,
    }
}

/// How long the lock files a process holds, once read, are reused for the
/// other sessions of the same process. On Windows the read is a Restart
/// Manager query (`restart_manager::holders`, a scan of the running
/// processes per session it starts) over the lock files listed around the
/// process's open files (`lock_file_candidates`, directory listings), and
/// the capture asked for it on every session it attached a resolution to:
/// a scanner's own sessions, ~16,000 a minute from one pid on the perf
/// gate's Windows `all` scenario, cost 40 % of a core on average against
/// 7 % before the lock reads (posture tests.yml 42679176729, windows-x64,
/// 2026-11-09). The locks a process holds change with the stores it opens,
/// not with its connections: one read per process per minute, re-read when
/// the material it is asked about changes.
#[cfg(target_os = "windows")]
const LOCKS_HELD_CACHE_TTL: Duration = Duration::from_secs(60);

#[cfg(any(target_os = "windows", test))]
struct CachedLocksHeld {
    locks: Arc<Vec<String>>,
    refreshed_at: Instant,
    /// [`lock_material_key`] of the material the read was asked about: a
    /// process that opened another store since is asked again.
    material: u64,
}

/// Per-pid memo of [`locks_held_by`]'s answers (Windows). A pid recycled
/// within the TTL can briefly be served its predecessor's locks, the same
/// window [`OPEN_FILES_CACHE`] accepts; a process exit invalidates both
/// ([`invalidate_open_files_cache`]).
#[cfg(target_os = "windows")]
static LOCKS_HELD_CACHE: Lazy<CustomDashMap<u32, CachedLocksHeld>> =
    Lazy::new(|| CustomDashMap::new("locks_held_cache"));

/// Order-independent key of the material a lock read is asked about.
#[cfg(any(target_os = "windows", test))]
fn lock_material_key(material: &[String]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut sorted: Vec<&str> = material.iter().map(|path| path.trim()).collect();
    sorted.sort_unstable();
    sorted.dedup();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    sorted.hash(&mut hasher);
    hasher.finish()
}

/// Cache-or-compute behind [`locks_held_by`], with an injectable clock and
/// reader so the policy is unit-testable without the OS. Bounded like the
/// open-files cache: full, it drops the expired entries, then the oldest
/// half.
#[cfg(any(target_os = "windows", test))]
fn cached_locks_held_with(
    cache: &CustomDashMap<u32, CachedLocksHeld>,
    pid: u32,
    material: u64,
    now: Instant,
    ttl: Duration,
    read: impl FnOnce() -> Vec<String>,
) -> Vec<String> {
    if let Some(hit) = cache.get(&pid) {
        if now.saturating_duration_since(hit.refreshed_at) < ttl && hit.material == material {
            return hit.locks.as_ref().clone();
        }
    }
    let locks = read();
    if cache.len() >= OPEN_FILES_CACHE_MAX_ENTRIES {
        cache.retain(|_, v| now.saturating_duration_since(v.refreshed_at) < ttl);
        if cache.len() >= OPEN_FILES_CACHE_MAX_ENTRIES {
            let mut ages: Vec<(u32, Instant)> = cache
                .iter()
                .map(|e| (*e.key(), e.value().refreshed_at))
                .collect();
            ages.sort_by_key(|(_, at)| *at);
            for (old_pid, _) in ages.into_iter().take(OPEN_FILES_CACHE_MAX_ENTRIES / 2) {
                cache.remove(&old_pid);
            }
        }
    }
    cache.insert(
        pid,
        CachedLocksHeld {
            locks: Arc::new(locks.clone()),
            refreshed_at: now,
            material,
        },
    );
    locks
}

/// Lightweight scan: only returns open file paths that match sensitive
/// patterns.  Same procfs / libproc I/O as `get_open_file_paths` but skips
/// aggregation, making it cheap enough to run every 30 s.
pub fn get_sensitive_open_file_paths(pid: u32) -> Vec<String> {
    get_open_file_paths(pid)
        .into_iter()
        .filter(|p| is_sensitive_path(p))
        .collect()
}

/// The paths the L7 sensitive scan adds to a populated session: sensitive
/// material and ownership lock files (a store the process opened after its
/// session was first resolved). Same I/O as [`get_sensitive_open_file_paths`].
pub fn get_retained_open_file_paths(pid: u32) -> Vec<String> {
    get_open_file_paths(pid)
        .into_iter()
        .filter(|p| is_retained_open_file_path(p))
        .collect()
}

/// How long a per-pid open-file enumeration is reused before the OS is
/// asked again.
///
/// Every caller of [`get_open_file_paths`] tolerates staleness of this
/// order already: the resolver populates `open_files` once per resolution
/// and the sensitive scan re-reads them every 30 s (120 s on Windows), the
/// attack pattern detector reads them once per 60 s tick. What they do NOT
/// tolerate is the cost of the raw enumeration -- a `/proc/<pid>/fd`
/// readlink walk on Linux, a libproc fd walk on macOS and, on Windows, a
/// share of a system-wide handle-table snapshot -- repeated for the same
/// pid by every socket that pid owns in the same resolver round. Live
/// profiles on the Linux and Windows dogfood hosts (2026-09-19) put that
/// repetition at the top of the daemon's CPU.
pub const OPEN_FILES_CACHE_TTL: Duration = Duration::from_secs(15);

/// Upper bound on cached pids; beyond it expired entries are dropped and,
/// if still over, the oldest are evicted so pid churn cannot grow the map.
const OPEN_FILES_CACHE_MAX_ENTRIES: usize = 4096;

struct CachedOpenFiles {
    paths: Arc<Vec<String>>,
    refreshed_at: Instant,
    /// `live_fd_fingerprint(pid)` at enumeration time. A lookup re-probes it
    /// and treats a change as a miss, so a handle the process opened after
    /// the cached enumeration is visible on the very next lookup (the attack
    /// pattern detector's live open-file scan depends on that), while a
    /// process whose fd table did not move keeps the cached answer.
    fingerprint: Option<u64>,
}

/// Cheap fingerprint of the process's descriptor table: one or two
/// syscalls and no per-descriptor path lookups (the expensive part of the
/// enumeration). `None` when the process cannot be inspected.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn fnv1a64(bytes: impl IntoIterator<Item = u8>) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Linux: hash of the `/proc/<pid>/fd` entry names (one getdents walk; a
/// new descriptor takes the lowest free number and changes the set).
#[cfg(target_os = "linux")]
fn live_fd_fingerprint(pid: u32) -> Option<u64> {
    let entries = std::fs::read_dir(format!("/proc/{}/fd", pid)).ok()?;
    let mut names: Vec<Vec<u8>> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned().into_bytes())
        .collect();
    names.sort();
    Some(fnv1a64(
        names
            .into_iter()
            .flat_map(|n| n.into_iter().chain(std::iter::once(0))),
    ))
}

/// macOS: hash of the raw `PROC_PIDLISTFDS` list (fd number + type per
/// entry). The size-only probe is NOT usable here: with a null buffer
/// libproc reports the fd table's capacity, which grows in chunks and does
/// not move when one more file is opened.
#[cfg(target_os = "macos")]
fn live_fd_fingerprint(pid: u32) -> Option<u64> {
    const PROC_PIDLISTFDS: i32 = 1;
    extern "C" {
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut std::ffi::c_void,
            buffersize: i32,
        ) -> i32;
    }
    let size = unsafe { proc_pidinfo(pid as i32, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if size <= 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let got = unsafe {
        proc_pidinfo(
            pid as i32,
            PROC_PIDLISTFDS,
            0,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            size,
        )
    };
    if got <= 0 {
        return None;
    }
    buf.truncate(got as usize);
    Some(fnv1a64(buf))
}

#[cfg(target_os = "windows")]
fn live_fd_fingerprint(pid: u32) -> Option<u64> {
    win_handles::handle_count(pid)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn live_fd_fingerprint(_pid: u32) -> Option<u64> {
    None
}

/// Per-pid result cache. A `CustomDashMap` (undeadlock) so debug builds
/// get the usual hold-time diagnostics; it is only ever used from sync
/// blocking-pool code.
static OPEN_FILES_CACHE: Lazy<CustomDashMap<u32, CachedOpenFiles>> =
    Lazy::new(|| CustomDashMap::new("open_files_cache"));

/// Cache-or-compute with an injectable clock and enumerator so the policy
/// is unit-testable without touching the OS.
fn cached_open_files_with(
    cache: &CustomDashMap<u32, CachedOpenFiles>,
    pid: u32,
    now: Instant,
    ttl: Duration,
    fingerprint: Option<u64>,
    enumerate: impl FnOnce(Option<u64>) -> Vec<String>,
) -> Vec<String> {
    if let Some(hit) = cache.get(&pid) {
        let fresh_enough = now.saturating_duration_since(hit.refreshed_at) < ttl;
        if fresh_enough && hit.fingerprint == fingerprint {
            return hit.paths.as_ref().clone();
        }
    }

    let paths = enumerate(fingerprint);

    if cache.len() >= OPEN_FILES_CACHE_MAX_ENTRIES {
        cache.retain(|_, v| now.saturating_duration_since(v.refreshed_at) < ttl);
        if cache.len() >= OPEN_FILES_CACHE_MAX_ENTRIES {
            // Still full of live entries: drop the oldest half rather than
            // let the map grow without bound.
            let mut ages: Vec<(u32, Instant)> = cache
                .iter()
                .map(|e| (*e.key(), e.value().refreshed_at))
                .collect();
            ages.sort_by_key(|(_, at)| *at);
            for (old_pid, _) in ages.into_iter().take(OPEN_FILES_CACHE_MAX_ENTRIES / 2) {
                cache.remove(&old_pid);
            }
        }
    }

    cache.insert(
        pid,
        CachedOpenFiles {
            paths: Arc::new(paths.clone()),
            refreshed_at: now,
            fingerprint,
        },
    );
    paths
}

/// Open disk-backed file paths of `pid`, served from a per-pid cache for
/// [`OPEN_FILES_CACHE_TTL`] and enumerated from the OS on a miss.
///
/// A pid recycled within the TTL can briefly be served the previous
/// owner's list; the L7 layer keys its own process cache by
/// `(pid, start_time)` and the sensitive scan already tolerated 30 s of
/// staleness, so that window is acceptable.
pub fn get_open_file_paths(pid: u32) -> Vec<String> {
    cached_open_files_with(
        &OPEN_FILES_CACHE,
        pid,
        Instant::now(),
        OPEN_FILES_CACHE_TTL,
        live_fd_fingerprint(pid),
        |fingerprint| enumerate_open_file_paths(pid, fingerprint),
    )
}

/// Drop the cached entry for `pid` (a process exit, for instance) so the
/// next lookup asks the OS. On Windows this also drops the shared handle
/// snapshot: an explicit invalidation means "now", not "within the
/// snapshot window".
pub fn invalidate_open_files_cache(pid: u32) {
    OPEN_FILES_CACHE.remove(&pid);
    #[cfg(target_os = "windows")]
    {
        LOCKS_HELD_CACHE.remove(&pid);
        win_handles::invalidate_snapshot();
    }
}

/// Number of pids currently cached (diagnostics).
pub fn open_files_cache_len() -> usize {
    OPEN_FILES_CACHE.len()
}

/// Start a "fresh" scan pass (the attack pattern detector's live open-file
/// scan). On Windows this takes one system-wide handle snapshot now so the
/// following [`get_open_file_paths_fresh`] calls of the pass share it; on
/// the other platforms enumeration reads the live table and this is a
/// no-op.
pub fn begin_fresh_open_files_scan() {
    #[cfg(target_os = "windows")]
    {
        let _ = win_handles::current_snapshot_max_age(Duration::ZERO);
    }
}

/// Open disk-backed file paths of `pid`, read from the OS now, bypassing
/// and refreshing the per-pid cache.
///
/// For callers that need the current state rather than a cheap answer:
/// the detector's live scan hydrates `open_files` for recent sessions once
/// per tick and must see a secret opened moments ago. The cached lookup is
/// keyed by a descriptor-table fingerprint, but fd numbers are recycled
/// (close one file, open another at the same number) so a fingerprint hit
/// can still be stale; the L7 resolver tolerates that, the detector does
/// not. On Windows a snapshot younger than
/// [`win_handles::FRESH_SCAN_SNAPSHOT_MAX_AGE`] is accepted so a pass that
/// called [`begin_fresh_open_files_scan`] costs one snapshot in total.
pub fn get_open_file_paths_fresh(pid: u32) -> Vec<String> {
    let fingerprint = live_fd_fingerprint(pid);
    #[cfg(target_os = "windows")]
    let paths = enumerate_open_file_paths_with_max_age(
        pid,
        fingerprint,
        win_handles::FRESH_SCAN_SNAPSHOT_MAX_AGE,
    );
    #[cfg(not(target_os = "windows"))]
    let paths = enumerate_open_file_paths(pid, fingerprint);
    OPEN_FILES_CACHE.insert(
        pid,
        CachedOpenFiles {
            paths: Arc::new(paths.clone()),
            refreshed_at: Instant::now(),
            fingerprint,
        },
    );
    paths
}

/// Sensitive subset of [`get_open_file_paths_fresh`].
pub fn get_sensitive_open_file_paths_fresh(pid: u32) -> Vec<String> {
    get_open_file_paths_fresh(pid)
        .into_iter()
        .filter(|p| is_sensitive_path(p))
        .collect()
}

#[cfg(target_os = "linux")]
fn enumerate_open_file_paths(pid: u32, _fingerprint: Option<u64>) -> Vec<String> {
    let fd_dir = format!("/proc/{}/fd", pid);
    let entries = match std::fs::read_dir(&fd_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut paths = Vec::new();
    for entry in entries.flatten() {
        if let Ok(target) = std::fs::read_link(entry.path()) {
            let s = target.to_string_lossy().to_string();
            if s.starts_with('/')
                && !s.starts_with("/dev/")
                && !s.starts_with("/proc/")
                && should_keep_open_file_path(&s)
            {
                paths.push(s);
            }
        }
    }
    paths
}

#[cfg(target_os = "macos")]
fn enumerate_open_file_paths(pid: u32, _fingerprint: Option<u64>) -> Vec<String> {
    use std::mem;

    #[allow(non_camel_case_types)]
    #[repr(C)]
    struct proc_fdinfo {
        proc_fd: i32,
        proc_fdtype: u32,
    }

    #[allow(non_camel_case_types)]
    #[repr(C)]
    struct vnode_fdinfowithpath {
        pfi: proc_fileinfo,
        pvip: vnode_info_path,
    }

    #[allow(non_camel_case_types)]
    #[repr(C)]
    struct proc_fileinfo {
        fi_openflags: u32,
        fi_status: u32,
        fi_offset: i64,
        fi_type: i32,
        fi_guardflags: u32,
    }

    #[allow(non_camel_case_types)]
    #[repr(C)]
    struct vnode_info_path {
        vip_vi: vnode_info,
        vip_path: [u8; 1024],
    }

    #[allow(non_camel_case_types)]
    #[repr(C)]
    struct vnode_info {
        vi_stat: vinfo_stat,
        vi_type: i32,
        vi_pad: i32,
        vi_fsid: fsid_t,
    }

    #[allow(non_camel_case_types)]
    #[repr(C)]
    struct vinfo_stat {
        vst_dev: u32,
        vst_mode: u16,
        vst_nlink: u16,
        vst_ino: u64,
        vst_uid: u32,
        vst_gid: u32,
        vst_atime: i64,
        vst_atimensec: i64,
        vst_mtime: i64,
        vst_mtimensec: i64,
        vst_ctime: i64,
        vst_ctimensec: i64,
        vst_birthtime: i64,
        vst_birthtimensec: i64,
        vst_size: i64,
        vst_blocks: i64,
        vst_blksize: i32,
        vst_flags: u32,
        vst_gen: u32,
        vst_rdev: u32,
        vst_qspare: [i64; 2],
    }

    #[allow(non_camel_case_types)]
    #[repr(C)]
    struct fsid_t {
        val: [i32; 2],
    }

    const PROC_PIDLISTFDS: i32 = 1;
    const PROC_PIDFDVNODEPATHINFO: i32 = 2;
    const PROX_FDTYPE_VNODE: u32 = 1;

    extern "C" {
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut std::ffi::c_void,
            buffersize: i32,
        ) -> i32;
        fn proc_pidfdinfo(
            pid: i32,
            fd: i32,
            flavor: i32,
            buffer: *mut std::ffi::c_void,
            buffersize: i32,
        ) -> i32;
    }

    let fd_size = mem::size_of::<proc_fdinfo>() as i32;
    let buf_size = unsafe { proc_pidinfo(pid as i32, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if buf_size <= 0 {
        return Vec::new();
    }

    let num_fds = buf_size / fd_size;
    let mut fd_buf: Vec<proc_fdinfo> = Vec::with_capacity(num_fds as usize);
    let ret = unsafe {
        proc_pidinfo(
            pid as i32,
            PROC_PIDLISTFDS,
            0,
            fd_buf.as_mut_ptr() as *mut std::ffi::c_void,
            buf_size,
        )
    };
    if ret <= 0 {
        return Vec::new();
    }
    unsafe { fd_buf.set_len((ret / fd_size) as usize) };

    let mut paths = Vec::new();
    let vpath_size = mem::size_of::<vnode_fdinfowithpath>() as i32;

    for fd_info in &fd_buf {
        if fd_info.proc_fdtype != PROX_FDTYPE_VNODE {
            continue;
        }
        let mut vpath: vnode_fdinfowithpath = unsafe { mem::zeroed() };
        let ret = unsafe {
            proc_pidfdinfo(
                pid as i32,
                fd_info.proc_fd,
                PROC_PIDFDVNODEPATHINFO,
                &mut vpath as *mut _ as *mut std::ffi::c_void,
                vpath_size,
            )
        };
        if ret <= 0 {
            continue;
        }
        let path_bytes = &vpath.pvip.vip_path;
        let nul_pos = path_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(path_bytes.len());
        let s = String::from_utf8_lossy(&path_bytes[..nul_pos]).to_string();
        if s.starts_with('/') && !s.starts_with("/dev/") && should_keep_open_file_path(&s) {
            paths.push(s);
        }
    }
    paths
}

#[cfg(target_os = "windows")]
mod win_handles {
    //! System-wide handle-table snapshot shared by every per-pid open-files
    //! lookup.
    //!
    //! `NtQuerySystemInformation(SystemHandleInformation)` copies the handle
    //! table of EVERY process (tens of thousands of entries, a multi-MB
    //! buffer the kernel zeroes and fills under the handle-table locks).
    //! Before this module each `get_open_file_paths(pid)` call performed that
    //! snapshot on its own, so a resolver round with N resolved sockets or a
    //! sensitive-scan cycle with 50 pids cost N / 50 full snapshots. A
    //! symbolized xperf profile of the released 1.9.0 posture daemon on the
    //! Windows dogfood host (2026-09-19) attributed ~75% of the daemon's CPU
    //! to `ObpCaptureHandleInformation` / `ExpSnapShotHandleTables` /
    //! `ExLockHandleTableEntry` / `KeZeroPages` -- i.e. to this one call.
    //!
    //! The snapshot is now taken at most once per `SNAPSHOT_TTL`, bucketed by
    //! owning pid, and every caller within the window reads its pid's bucket
    //! from the shared copy. Per-handle work (DuplicateHandle, GetFileType,
    //! GetFinalPathNameByHandleW) is unchanged and still done per pid.
    //!
    //! Handles their owner holds with write, append, delete or ACL-change
    //! rights are left out of the buckets, so they are never duplicated (see
    //! [`resolvable`]).

    use arc_swap::ArcSwapOption;
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::ptr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    pub(super) type HANDLE = *mut c_void;
    type NTSTATUS = i32;

    const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = 0xC0000004_u32 as i32;
    const STATUS_SUCCESS: NTSTATUS = 0;
    const SYSTEM_HANDLE_INFORMATION_CLASS: u32 = 16;
    pub(super) const PROCESS_DUP_HANDLE: u32 = 0x0040;
    pub(super) const DUPLICATE_SAME_ACCESS: u32 = 0x0002;
    pub(super) const FILE_TYPE_DISK: u32 = 0x0001;

    /// How long one system-wide handle snapshot is reused. Long enough to
    /// cover a whole resolver round / sensitive-scan cycle (they iterate
    /// their pids back to back), short enough that a handle opened by a
    /// process is visible within a few seconds.
    pub(super) const SNAPSHOT_TTL: Duration = Duration::from_secs(2);
    /// Snapshot age accepted by the fresh-scan entry points: long enough to
    /// span one detector pass after `begin_fresh_open_files_scan`.
    pub(super) const FRESH_SCAN_SNAPSHOT_MAX_AGE: Duration = Duration::from_secs(5);
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const INITIAL_BUF_SIZE: u32 = 1 << 20;
    const MAX_BUF_SIZE: u32 = 512 << 20;

    // Stable NT ABI -- layout verified against ntifs.h SYSTEM_HANDLE_TABLE_ENTRY_INFO.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) struct HandleEntry {
        pub unique_process_id: u16,
        pub creator_back_trace_index: u16,
        pub object_type_index: u8,
        pub handle_attributes: u8,
        pub handle_value: u16,
        pub object: usize,
        pub granted_access: u32,
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtQuerySystemInformation(
            class: u32,
            info: *mut c_void,
            len: u32,
            ret_len: *mut u32,
        ) -> NTSTATUS;
    }

    extern "system" {
        pub(super) fn OpenProcess(access: u32, inherit: i32, pid: u32) -> HANDLE;
        pub(super) fn DuplicateHandle(
            src_proc: HANDLE,
            src: HANDLE,
            dst_proc: HANDLE,
            dst: *mut HANDLE,
            access: u32,
            inherit: i32,
            options: u32,
        ) -> i32;
        pub(super) fn GetCurrentProcess() -> HANDLE;
        pub(super) fn CloseHandle(h: HANDLE) -> i32;
        pub(super) fn GetFileType(h: HANDLE) -> u32;
        pub(super) fn GetFinalPathNameByHandleW(
            h: HANDLE,
            buf: *mut u16,
            buf_len: u32,
            flags: u32,
        ) -> u32;
        fn GetProcessHandleCount(h: HANDLE, count: *mut u32) -> i32;
    }

    /// Live handle count of `pid` (one OpenProcess + GetProcessHandleCount).
    pub(super) fn handle_count(pid: u32) -> Option<u64> {
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h.is_null() {
            return None;
        }
        let mut count: u32 = 0;
        let ok = unsafe { GetProcessHandleCount(h, &mut count) };
        unsafe { CloseHandle(h) };
        if ok == 0 {
            None
        } else {
            Some(count as u64)
        }
    }

    /// One system-wide snapshot, bucketed by owning pid.
    pub(super) struct HandleSnapshot {
        pub taken_at: Instant,
        pub by_pid: HashMap<u32, Vec<u16>>,
    }

    static SNAPSHOT: ArcSwapOption<HandleSnapshot> = ArcSwapOption::const_empty();
    /// Size that satisfied the last query; the next query starts from it
    /// instead of re-growing from 1 MiB through several
    /// STATUS_INFO_LENGTH_MISMATCH round trips.
    static LAST_BUF_SIZE: AtomicU32 = AtomicU32::new(INITIAL_BUF_SIZE);

    /// Access rights of a handle whose file or directory is being written,
    /// replaced or secured: FILE_WRITE_DATA, FILE_APPEND_DATA, DELETE,
    /// WRITE_DAC, WRITE_OWNER.
    const WRITER_ACCESS: u32 = 0x0000_0002 | 0x0000_0004 | 0x0001_0000 | 0x0004_0000 | 0x0008_0000;

    /// Whether this handle's path may be resolved without getting in its
    /// owner's way. Resolving duplicates the handle into this process, and
    /// the duplicate keeps the file object open until it is closed: a writer
    /// that patches or replaces the file it has just written is refused with
    /// "Access is denied" meanwhile. uv failed exactly so while EDAMAME ran
    /// on windows-latest ("Failed to update Windows PE resources:
    /// ...\uv-trampoline-NNNN.exe", fleet E2E and probe run 36273248402:
    /// Hermes' uv installs failed 3/3 with EDAMAME, succeeded 3/3 without).
    /// Read handles, what the sensitive-file detections need, are still
    /// resolved; writes to sensitive paths are the file monitor's to see.
    pub(super) fn resolvable(entry: &HandleEntry) -> bool {
        entry.granted_access & WRITER_ACCESS == 0
    }

    /// Bucket raw handle-table entries by owning pid, leaving out the handles
    /// that are not [`resolvable`] (pure; unit-tested).
    pub(super) fn bucket_by_pid(entries: &[HandleEntry]) -> HashMap<u32, Vec<u16>> {
        let mut by_pid: HashMap<u32, Vec<u16>> = HashMap::new();
        for entry in entries.iter().filter(|entry| resolvable(entry)) {
            by_pid
                .entry(entry.unique_process_id as u32)
                .or_default()
                .push(entry.handle_value);
        }
        by_pid
    }

    fn query_handle_table() -> Option<HandleSnapshot> {
        let mut buf_size: u32 = LAST_BUF_SIZE.load(Ordering::Relaxed).max(INITIAL_BUF_SIZE);
        let mut buffer: Vec<u8>;
        let mut ret_len: u32 = 0;

        loop {
            buffer = vec![0u8; buf_size as usize];
            let status = unsafe {
                NtQuerySystemInformation(
                    SYSTEM_HANDLE_INFORMATION_CLASS,
                    buffer.as_mut_ptr() as *mut c_void,
                    buf_size,
                    &mut ret_len,
                )
            };
            if status == STATUS_INFO_LENGTH_MISMATCH {
                buf_size = ret_len.max(buf_size).saturating_mul(2);
                if buf_size > MAX_BUF_SIZE {
                    return None;
                }
                continue;
            }
            if status != STATUS_SUCCESS {
                return None;
            }
            break;
        }
        LAST_BUF_SIZE.store(buf_size, Ordering::Relaxed);

        let num_handles = unsafe { *(buffer.as_ptr() as *const u32) };
        let entry_align = std::mem::align_of::<HandleEntry>();
        let entries_offset = (std::mem::size_of::<u32>() + entry_align - 1) & !(entry_align - 1);
        let needed = entries_offset + num_handles as usize * std::mem::size_of::<HandleEntry>();
        if needed > buffer.len() {
            return None;
        }

        let entries = unsafe {
            std::slice::from_raw_parts(
                buffer.as_ptr().add(entries_offset) as *const HandleEntry,
                num_handles as usize,
            )
        };

        Some(HandleSnapshot {
            taken_at: Instant::now(),
            by_pid: bucket_by_pid(entries),
        })
    }

    /// Forget the current snapshot so the next lookup queries the kernel.
    pub(super) fn invalidate_snapshot() {
        SNAPSHOT.store(None);
    }

    /// Two callers racing past an expired snapshot may both query; the
    /// second store simply wins. A failed query keeps serving the stale
    /// snapshot (if any) rather than returning nothing.
    /// The current snapshot, refreshed when older than `max_age`
    /// (callers pass `SNAPSHOT_TTL`, or `Duration::ZERO` to force a query).
    pub(super) fn current_snapshot_max_age(max_age: Duration) -> Option<Arc<HandleSnapshot>> {
        if let Some(snap) = SNAPSHOT.load_full() {
            if snap.taken_at.elapsed() < max_age {
                return Some(snap);
            }
        }
        match query_handle_table() {
            Some(fresh) => {
                let fresh = Arc::new(fresh);
                SNAPSHOT.store(Some(fresh.clone()));
                Some(fresh)
            }
            None => SNAPSHOT.load_full(),
        }
    }

    /// Resolve the disk-backed file paths behind `handles` owned by `pid`.
    pub(super) fn resolve_paths(pid: u32, handles: &[u16]) -> Vec<String> {
        let proc_handle = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, pid) };
        if proc_handle.is_null() {
            return Vec::new();
        }
        let current = unsafe { GetCurrentProcess() };
        let mut paths = Vec::new();

        for &handle_value in handles {
            let mut dup: HANDLE = ptr::null_mut();
            let ok = unsafe {
                DuplicateHandle(
                    proc_handle,
                    handle_value as usize as HANDLE,
                    current,
                    &mut dup,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            };
            if ok == 0 || dup.is_null() {
                continue;
            }

            // Only query disk-backed files; pipes/devices/mailslots can deadlock
            // GetFinalPathNameByHandleW on synchronous I/O handles.
            if unsafe { GetFileType(dup) } != FILE_TYPE_DISK {
                unsafe { CloseHandle(dup) };
                continue;
            }

            let mut name_buf = [0u16; 1024];
            let len = unsafe { GetFinalPathNameByHandleW(dup, name_buf.as_mut_ptr(), 1024, 0) };
            unsafe { CloseHandle(dup) };

            if len == 0 || len as usize >= name_buf.len() {
                continue;
            }

            let raw = String::from_utf16_lossy(&name_buf[..len as usize]);
            let s = raw.strip_prefix("\\\\?\\").unwrap_or(&raw);
            if !s.starts_with('\\') {
                paths.push(s.to_string());
            }
        }

        unsafe { CloseHandle(proc_handle) };
        paths
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn entry(pid: u16, handle: u16) -> HandleEntry {
            HandleEntry {
                unique_process_id: pid,
                creator_back_trace_index: 0,
                object_type_index: 0,
                handle_attributes: 0,
                handle_value: handle,
                object: 0,
                granted_access: 0,
            }
        }

        #[test]
        fn bucket_by_pid_groups_handles_per_owner() {
            let entries = [
                entry(4, 0x10),
                entry(1652, 0x20),
                entry(4, 0x30),
                entry(7, 0x40),
            ];
            let by_pid = bucket_by_pid(&entries);
            assert_eq!(by_pid.len(), 3);
            assert_eq!(by_pid[&4], vec![0x10, 0x30]);
            assert_eq!(by_pid[&1652], vec![0x20]);
            assert_eq!(by_pid[&7], vec![0x40]);
        }

        #[test]
        fn bucket_by_pid_empty_table() {
            assert!(bucket_by_pid(&[]).is_empty());
        }

        #[test]
        fn handles_held_for_writing_or_replacing_are_never_resolved() {
            let with_access = |handle: u16, granted_access: u32| HandleEntry {
                granted_access,
                ..entry(42, handle)
            };
            const FILE_READ_DATA: u32 = 0x0001;
            const SYNCHRONIZE: u32 = 0x0010_0000;
            const READ_CONTROL: u32 = 0x0002_0000;
            let entries = [
                with_access(0x10, FILE_READ_DATA | SYNCHRONIZE | READ_CONTROL),
                with_access(0x14, 0x0012_019f), // FILE_GENERIC_READ | FILE_GENERIC_WRITE
                with_access(0x18, 0x0000_0004 | SYNCHRONIZE), // append
                with_access(0x1c, 0x0001_0000 | FILE_READ_DATA), // delete (rename / replace)
                with_access(0x20, 0x0004_0000 | READ_CONTROL), // WRITE_DAC (securing a new directory)
                with_access(0x24, 0x0008_0000),                // WRITE_OWNER
                with_access(0x28, 0),
            ];
            let by_pid = bucket_by_pid(&entries);
            assert_eq!(by_pid[&42], vec![0x10, 0x28]);
        }

        #[test]
        fn snapshot_is_shared_within_ttl() {
            // Two consecutive lookups must observe the same snapshot instance
            // (the whole point: one NtQuerySystemInformation per TTL window).
            let a = current_snapshot_max_age(SNAPSHOT_TTL).expect("handle snapshot");
            let b = current_snapshot_max_age(SNAPSHOT_TTL).expect("handle snapshot");
            assert!(Arc::ptr_eq(&a, &b));
            // Our own process is in the table.
            assert!(a.by_pid.contains_key(&std::process::id()));
        }
    }
}

#[cfg(target_os = "windows")]
fn enumerate_open_file_paths(pid: u32, live_handle_count: Option<u64>) -> Vec<String> {
    enumerate_open_file_paths_with_max_age(pid, live_handle_count, win_handles::SNAPSHOT_TTL)
}

#[cfg(target_os = "windows")]
fn enumerate_open_file_paths_with_max_age(
    pid: u32,
    live_handle_count: Option<u64>,
    max_age: Duration,
) -> Vec<String> {
    // The shared snapshot may predate a handle this process just opened.
    // The live handle count says exactly whether it does: if the pid's
    // bucket in the snapshot has a different size, re-snapshot. A fresh
    // snapshot then compares equal for every other pid, so a burst of
    // callers costs one query rather than one per caller, and a process
    // whose table did not move never forces one.
    let mut snapshot = match win_handles::current_snapshot_max_age(max_age) {
        Some(s) => s,
        None => return Vec::new(),
    };
    if let Some(live) = live_handle_count {
        let in_snapshot = snapshot
            .by_pid
            .get(&pid)
            .map(|h| h.len() as u64)
            .unwrap_or(0);
        if in_snapshot != live {
            if let Some(fresh) = win_handles::current_snapshot_max_age(Duration::ZERO) {
                snapshot = fresh;
            }
        }
    }
    match snapshot.by_pid.get(&pid) {
        Some(handles) => win_handles::resolve_paths(pid, handles),
        None => Vec::new(),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn enumerate_open_file_paths(_pid: u32, _fingerprint: Option<u64>) -> Vec<String> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- aggregate_open_files tests ---

    // --- open_files cache tests ---

    use std::cell::Cell;

    fn fresh_cache() -> CustomDashMap<u32, CachedOpenFiles> {
        CustomDashMap::new("open_files_cache_test")
    }

    // --- locks-held memo (the Restart Manager read behind locks_held_by) ---

    /// One read per process within the TTL, whatever the number of sessions
    /// asking; another process, other material or an expired entry read
    /// again.
    #[test]
    fn locks_held_memo_reads_once_per_process_within_the_ttl() {
        let cache: CustomDashMap<u32, CachedLocksHeld> = CustomDashMap::new("locks_held_test");
        let ttl = Duration::from_secs(60);
        let now = Instant::now();
        let reads = Cell::new(0usize);
        let key = lock_material_key(&["C:\\p\\Cookies".to_string()]);
        let counter = &reads;
        let read = |answer: Vec<String>| {
            move || {
                counter.set(counter.get() + 1);
                answer
            }
        };

        let first = cached_locks_held_with(
            &cache,
            7,
            key,
            now,
            ttl,
            read(vec!["C:\\p\\LOCK".to_string()]),
        );
        assert_eq!(first, vec!["C:\\p\\LOCK".to_string()]);
        assert_eq!(reads.get(), 1);

        // Every further session of pid 7 in the minute: the memo, not a read.
        for i in 1..1000u64 {
            let again = cached_locks_held_with(
                &cache,
                7,
                key,
                now + Duration::from_millis(i * 59),
                ttl,
                read(Vec::new()),
            );
            assert_eq!(again, first);
        }
        assert_eq!(reads.get(), 1);

        // Another process reads for itself.
        let other = cached_locks_held_with(&cache, 8, key, now, ttl, read(Vec::new()));
        assert!(other.is_empty());
        assert_eq!(reads.get(), 2);

        // The same process asked about other material (a store opened since).
        let key2 = lock_material_key(&["C:\\q\\Login Data".to_string()]);
        let _ = cached_locks_held_with(&cache, 7, key2, now, ttl, read(Vec::new()));
        assert_eq!(reads.get(), 3);

        // Expired: read again.
        let _ = cached_locks_held_with(&cache, 7, key2, now + ttl, ttl, read(Vec::new()));
        assert_eq!(reads.get(), 4);
    }

    #[test]
    fn lock_material_key_ignores_order_duplicates_and_surrounding_blanks() {
        let a = lock_material_key(&["C:\\p\\Cookies".to_string(), "C:\\p\\Web Data".to_string()]);
        let b = lock_material_key(&[
            " C:\\p\\Web Data ".to_string(),
            "C:\\p\\Cookies".to_string(),
            "C:\\p\\Cookies".to_string(),
        ]);
        assert_eq!(a, b);
        assert_ne!(a, lock_material_key(&["C:\\p\\Cookies".to_string()]));
        assert_ne!(a, lock_material_key(&[]));
    }

    #[test]
    fn locks_held_memo_stays_bounded_under_pid_churn() {
        let cache: CustomDashMap<u32, CachedLocksHeld> = CustomDashMap::new("locks_held_bound");
        let now = Instant::now();
        for pid in 0..(OPEN_FILES_CACHE_MAX_ENTRIES as u32 * 2) {
            let _ = cached_locks_held_with(&cache, pid, 0, now, Duration::from_secs(60), Vec::new);
            assert!(cache.len() <= OPEN_FILES_CACHE_MAX_ENTRIES);
        }
    }

    #[test]
    fn cache_serves_second_lookup_within_ttl_without_enumerating() {
        let cache = fresh_cache();
        let calls = Cell::new(0);
        let t0 = Instant::now();
        let ttl = Duration::from_secs(15);
        let enumerate = |_: Option<u64>| {
            calls.set(calls.get() + 1);
            vec!["/etc/hosts".to_string()]
        };
        let a = cached_open_files_with(&cache, 42, t0, ttl, None, enumerate);
        let b = cached_open_files_with(
            &cache,
            42,
            t0 + Duration::from_secs(14),
            ttl,
            None,
            enumerate,
        );
        assert_eq!(a, b);
        assert_eq!(
            calls.get(),
            1,
            "second lookup inside the TTL must hit the cache"
        );
    }

    #[test]
    fn cache_re_enumerates_after_ttl() {
        let cache = fresh_cache();
        let calls = Cell::new(0);
        let t0 = Instant::now();
        let ttl = Duration::from_secs(15);
        let enumerate = |_: Option<u64>| {
            calls.set(calls.get() + 1);
            vec![format!("/tmp/gen{}", calls.get())]
        };
        let a = cached_open_files_with(&cache, 7, t0, ttl, None, enumerate);
        let b = cached_open_files_with(&cache, 7, t0 + ttl, ttl, None, enumerate);
        assert_eq!(calls.get(), 2);
        assert_ne!(a, b, "an expired entry must be refreshed from the OS");
    }

    #[test]
    fn cache_caches_negative_results_too() {
        // A process with no disk files open still costs a full enumeration;
        // the empty answer must be cached like any other.
        let cache = fresh_cache();
        let calls = Cell::new(0);
        let t0 = Instant::now();
        let enumerate = |_: Option<u64>| {
            calls.set(calls.get() + 1);
            Vec::new()
        };
        let _ = cached_open_files_with(&cache, 9, t0, Duration::from_secs(15), None, enumerate);
        let _ = cached_open_files_with(
            &cache,
            9,
            t0 + Duration::from_secs(1),
            Duration::from_secs(15),
            None,
            enumerate,
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn cache_misses_when_fd_fingerprint_changes() {
        // The detector's live open-file scan must see a handle opened after
        // the cached enumeration: a changed fd count is a miss even inside
        // the TTL, and the enumerator receives the live fingerprint.
        let cache = fresh_cache();
        let t0 = Instant::now();
        let ttl = Duration::from_secs(15);
        let moved_flags = std::cell::RefCell::new(Vec::new());
        let enumerate = |fp: Option<u64>| {
            moved_flags.borrow_mut().push(fp);
            vec![format!("/f{}", moved_flags.borrow().len())]
        };
        let a = cached_open_files_with(&cache, 5, t0, ttl, Some(10), enumerate);
        let b = cached_open_files_with(
            &cache,
            5,
            t0 + Duration::from_secs(1),
            ttl,
            Some(11),
            enumerate,
        );
        assert_ne!(a, b, "a new descriptor must force a fresh enumeration");
        assert_eq!(*moved_flags.borrow(), vec![Some(10), Some(11)]);
        // Same fingerprint again: served from the cache.
        let c = cached_open_files_with(
            &cache,
            5,
            t0 + Duration::from_secs(2),
            ttl,
            Some(11),
            enumerate,
        );
        assert_eq!(b, c);
        assert_eq!(moved_flags.borrow().len(), 2);
    }

    #[test]
    fn cache_ttl_expiry_re_enumerates_with_the_same_fingerprint() {
        let cache = fresh_cache();
        let t0 = Instant::now();
        let ttl = Duration::from_secs(15);
        let moved_flags = std::cell::RefCell::new(Vec::new());
        let enumerate = |fp: Option<u64>| {
            moved_flags.borrow_mut().push(fp);
            Vec::new()
        };
        let _ = cached_open_files_with(&cache, 6, t0, ttl, Some(3), enumerate);
        let _ = cached_open_files_with(&cache, 6, t0 + ttl, ttl, Some(3), enumerate);
        assert_eq!(*moved_flags.borrow(), vec![Some(3), Some(3)]);
    }

    #[test]
    fn fresh_lookup_sees_a_handle_opened_after_the_cached_enumeration() {
        // End-to-end on the real OS: populate the cache for self, open a new
        // file, then ask for a fresh read. Unlike the cached lookup this is
        // deterministic even with other tests opening and closing files in
        // the same process (fd numbers are recycled, so a fingerprint can
        // collide); the detector's live scan relies on it.
        let me = std::process::id();
        invalidate_open_files_cache(me);
        let before = get_open_file_paths(me);
        let dir = std::env::temp_dir().join(format!("edamame_openfiles_fresh_{}", me));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("late_sentinel.txt");
        std::fs::File::create(&path).expect("create late sentinel");
        // Held for reading: handles held for writing are never resolved on
        // Windows (their producer may be about to replace the file).
        let handle = std::fs::File::open(&path).expect("open late sentinel");
        begin_fresh_open_files_scan();
        let after = get_open_file_paths_fresh(me);
        let canon = path
            .canonicalize()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let plain = path.to_string_lossy().to_string();
        drop(handle);
        let _ = std::fs::remove_dir_all(&dir);
        if before.is_empty() && after.is_empty() {
            // No /proc permissions (some CI containers): nothing to assert.
            return;
        }
        assert!(
            after.iter().any(|p| {
                p == &plain || p == &canon || p == canon.trim_start_matches("\\\\?\\")
            }),
            "late sentinel {} not seen by the fresh lookup: {:?}",
            plain,
            after
        );
        // The fresh read refreshed the cache: a cached lookup now agrees.
        assert!(OPEN_FILES_CACHE.get(&me).is_some());
        invalidate_open_files_cache(me);
    }

    #[test]
    fn cache_is_per_pid() {
        let cache = fresh_cache();
        let t0 = Instant::now();
        let ttl = Duration::from_secs(15);
        let a = cached_open_files_with(&cache, 1, t0, ttl, None, |_| vec!["/a".to_string()]);
        let b = cached_open_files_with(&cache, 2, t0, ttl, None, |_| vec!["/b".to_string()]);
        assert_eq!(a, vec!["/a".to_string()]);
        assert_eq!(b, vec!["/b".to_string()]);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn cache_is_bounded_under_pid_churn() {
        let cache = fresh_cache();
        let t0 = Instant::now();
        let ttl = Duration::from_secs(15);
        for pid in 0..(OPEN_FILES_CACHE_MAX_ENTRIES as u32 * 2) {
            let _ = cached_open_files_with(&cache, pid, t0, ttl, None, |_| Vec::new());
        }
        assert!(
            cache.len() <= OPEN_FILES_CACHE_MAX_ENTRIES,
            "cache grew to {} entries",
            cache.len()
        );
    }

    #[test]
    fn cache_evicts_expired_entries_before_live_ones() {
        let cache = fresh_cache();
        let ttl = Duration::from_secs(15);
        let t0 = Instant::now();
        // Fill to the cap with entries that will be expired by t1.
        for pid in 0..(OPEN_FILES_CACHE_MAX_ENTRIES as u32) {
            let _ = cached_open_files_with(&cache, pid, t0, ttl, None, |_| Vec::new());
        }
        let t1 = t0 + ttl + Duration::from_secs(1);
        let _ =
            cached_open_files_with(
                &cache,
                999_999,
                t1,
                ttl,
                None,
                |_| vec!["/live".to_string()],
            );
        assert_eq!(cache.len(), 1, "expired entries must be dropped first");
        assert!(cache.get(&999_999).is_some());
    }

    /// Manual timing probe, run with `--ignored --nocapture`: enumerates the
    /// open files of up to 50 live pids twice in a row. Before the per-pid
    /// cache (and, on Windows, the shared handle snapshot) the second pass
    /// cost the same as the first; now it is served from memory.
    #[test]
    #[ignore]
    #[cfg(any(feature = "packetcapture", feature = "etw", feature = "fim"))]
    fn timing_probe_open_files_50_pids_twice() {
        let mut sys = sysinfo::System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        let pids: Vec<u32> = sys
            .processes()
            .keys()
            .map(|p| p.as_u32())
            .take(50)
            .collect();
        for pid in &pids {
            invalidate_open_files_cache(*pid);
        }
        #[cfg(target_os = "windows")]
        {
            // Cost of one system-wide handle snapshot on its own: before the
            // shared snapshot every pid paid this once.
            let ts = Instant::now();
            let snap = win_handles::current_snapshot_max_age(win_handles::SNAPSHOT_TTL)
                .expect("handle snapshot");
            eprintln!(
                "open_files timing probe: one SystemHandleInformation snapshot = {:?} ({} pids, {} handles)",
                ts.elapsed(),
                snap.by_pid.len(),
                snap.by_pid.values().map(|v| v.len()).sum::<usize>()
            );
        }
        let t0 = Instant::now();
        let first: usize = pids.iter().map(|p| get_open_file_paths(*p).len()).sum();
        let t1 = Instant::now();
        let second: usize = pids.iter().map(|p| get_open_file_paths(*p).len()).sum();
        let t2 = Instant::now();
        eprintln!(
            "open_files timing probe: {} pids, {} paths; first pass {:?}, second pass {:?}",
            pids.len(),
            first,
            t1 - t0,
            t2 - t1
        );
        let _ = (first, second);
    }

    #[test]
    fn public_wrapper_populates_cache_for_own_pid() {
        // Other tests in this binary open and close files concurrently, so
        // two consecutive own-pid lookups may legitimately differ (the fd
        // fingerprint moved); only the cache population is asserted here.
        // Hit/miss semantics are covered by the injected-enumerator tests.
        let me = std::process::id();
        invalidate_open_files_cache(me);
        let _ = get_open_file_paths(me);
        assert!(OPEN_FILES_CACHE.get(&me).is_some());
        assert!(open_files_cache_len() >= 1);
        invalidate_open_files_cache(me);
    }

    #[test]
    fn test_aggregate_under_cap() {
        let paths: Vec<String> = (0..50).map(|i| format!("/tmp/file_{}.txt", i)).collect();
        let result = aggregate_open_files(paths.clone());
        assert!(result.len() <= MAX_OPEN_FILES);
        assert_eq!(result.len(), 50);
    }

    #[test]
    fn test_aggregate_over_cap() {
        let mut paths = Vec::new();
        for i in 0..80 {
            paths.push(format!("/usr/lib/libfoo_{}.so", i));
        }
        for i in 0..80 {
            paths.push(format!("/usr/share/data_{}.dat", i));
        }
        for i in 0..20 {
            paths.push(format!("/home/user/file_{}.txt", i));
        }
        let result = aggregate_open_files(paths);
        assert!(result.len() <= MAX_OPEN_FILES);
        assert!(result.iter().any(|e| e.ends_with('*')));
    }

    #[test]
    fn test_aggregate_preserves_unique_paths() {
        let mut paths: Vec<String> = (0..110).map(|i| format!("/usr/lib/lib_{}.so", i)).collect();
        paths.push("/home/user/.ssh/id_rsa".to_string());
        paths.push("/home/user/.aws/credentials".to_string());
        paths.push("/etc/passwd".to_string());
        let result = aggregate_open_files(paths);
        assert!(result.len() <= MAX_OPEN_FILES);
        assert!(result.iter().any(|e| e == "/usr/lib/*"));
    }

    #[test]
    fn test_aggregate_star_suffix() {
        let mut paths = Vec::new();
        for i in 0..150 {
            paths.push(format!("/opt/myapp/lib/dep_{}.jar", i));
        }
        let result = aggregate_open_files(paths);
        assert!(result.iter().any(|e| e == "/opt/myapp/lib/*"));
        assert!(result.len() <= MAX_OPEN_FILES);
    }

    #[test]
    fn test_aggregate_empty() {
        let result = aggregate_open_files(Vec::new());
        assert!(result.is_empty());
    }

    #[test]
    fn test_aggregate_dedup() {
        let paths = vec!["/tmp/a.txt".to_string(); 50];
        let result = aggregate_open_files(paths);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_aggregate_filters_root_noise() {
        let result =
            aggregate_open_files(vec!["/".to_string(), "/home/user/.ssh/id_rsa".to_string()]);
        assert_eq!(result, vec!["/home/user/.ssh/id_rsa".to_string()]);
    }

    #[test]
    fn test_aggregate_root_directory_glob_is_canonical() {
        let paths: Vec<String> = (0..150).map(|i| format!("/root_file_{}", i)).collect();
        let result = aggregate_open_files(paths);
        assert!(result.iter().any(|entry| entry == "/*"));
        assert!(!result.iter().any(|entry| entry == "//*"));
    }

    // --- get_open_file_paths tests ---

    #[test]
    fn test_get_open_file_paths_self() {
        let pid = std::process::id();
        let paths = get_open_file_paths(pid);
        eprintln!("open file paths for self (pid {}): {:?}", pid, paths);
        for p in &paths {
            assert!(!p.starts_with("/dev/"), "should filter /dev/ paths: {}", p);
            #[cfg(target_os = "linux")]
            assert!(
                !p.starts_with("/proc/"),
                "should filter /proc/ paths: {}",
                p
            );
            #[cfg(target_os = "windows")]
            assert!(!p.starts_with('\\'), "should filter device paths: {}", p);
        }
    }

    #[test]
    fn test_get_open_file_paths_dead_pid() {
        // PID 4_000_000 is far above typical OS ranges; should fail gracefully.
        let paths = get_open_file_paths(4_000_000);
        assert!(
            paths.is_empty(),
            "dead PID should return empty, got: {:?}",
            paths
        );
    }

    #[test]
    fn test_get_open_file_paths_pid_zero() {
        // PID 0 is the kernel idle process (Windows) or swapper (Linux).
        // Either way, we should not panic.
        let paths = get_open_file_paths(0);
        eprintln!("open file paths for PID 0: {:?}", paths);
    }

    #[test]
    fn test_get_open_file_paths_with_known_fd() {
        use std::fs::File;
        use std::io::Write;

        let dir = std::env::temp_dir().join("flodbadd_open_files_test");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join("sentinel.txt");
        File::create(&file_path)
            .and_then(|mut f| f.write_all(b"test"))
            .expect("write sentinel");
        // Held for reading: handles held for writing are never resolved on
        // Windows (their producer may be about to replace the file).
        let f = File::open(&file_path).expect("open sentinel");

        // Keep the file handle open while we query. Another test in this
        // process may have cached our pid's list before the sentinel was
        // opened; the cache is the subject of its own tests, this one wants
        // the live enumeration.
        let pid = std::process::id();
        invalidate_open_files_cache(pid);
        let paths = get_open_file_paths(pid);
        eprintln!("paths with sentinel open (pid {}): {:?}", pid, paths);

        // On Linux and macOS the sentinel should appear (we hold a File handle).
        // On Windows this also works via the NtQuerySystemInformation path.
        // CI environments running as non-root may lack /proc permissions on Linux,
        // so only assert when we got results at all.
        if !paths.is_empty() {
            let canonical = file_path.canonicalize().unwrap_or(file_path.clone());
            let canon_str = canonical.to_string_lossy().to_string();
            // On Windows, canonicalize() returns \\?\… but get_open_file_paths strips that prefix
            let canon_stripped = canon_str.strip_prefix("\\\\?\\").unwrap_or(&canon_str);
            let plain_str = file_path.to_string_lossy();
            assert!(
                paths.iter().any(|p| p == canon_stripped
                    || p == canon_str.as_str()
                    || p == plain_str.as_ref()),
                "sentinel {} not found in open files: {:?}",
                canon_stripped,
                paths,
            );
        }

        drop(f);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_get_open_file_paths_no_device_paths() {
        let pid = std::process::id();
        let paths = get_open_file_paths(pid);
        for p in &paths {
            assert!(
                !p.contains("/dev/") && !p.starts_with("\\Device\\"),
                "device path leaked through filter: {}",
                p,
            );
        }
    }

    #[test]
    fn test_short_lived_process_race() {
        use std::process::Command;

        // Spawn a process that exits immediately
        let child = Command::new(if cfg!(windows) { "cmd" } else { "true" })
            .args(if cfg!(windows) {
                vec!["/C", "exit"]
            } else {
                vec![]
            })
            .spawn()
            .expect("spawn short-lived process");

        let child_pid = child.id();

        // Wait for it to finish
        let _ = child.wait_with_output();

        // Now try to get open files for the dead PID -- must not panic, must return empty
        let paths = get_open_file_paths(child_pid);
        assert!(
            paths.is_empty(),
            "exited process should return empty open files, got: {:?}",
            paths,
        );
    }

    #[test]
    fn test_aggregate_pipeline_with_real_data() {
        use std::fs::File;
        use std::io::Write;

        let dir = std::env::temp_dir().join("flodbadd_pipeline_test");
        let _ = std::fs::create_dir_all(&dir);

        // Hold several file handles open to simulate a realistic process
        let mut handles = Vec::new();
        for i in 0..5 {
            let p = dir.join(format!("file_{}.dat", i));
            let mut f = File::create(&p).expect("create test file");
            f.write_all(b"data").expect("write test file");
            handles.push(f);
        }

        let pid = std::process::id();
        let raw = get_open_file_paths(pid);
        let aggregated = aggregate_open_files(raw.clone());

        eprintln!(
            "raw count: {}, aggregated count: {}",
            raw.len(),
            aggregated.len()
        );
        assert!(aggregated.len() <= MAX_OPEN_FILES);
        // Aggregated output must be sorted and deduplicated
        for w in aggregated.windows(2) {
            assert!(w[0] <= w[1], "output not sorted: {:?} > {:?}", w[0], w[1]);
        }

        drop(handles);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- ownership lock files (FP-MAC-29) ---

    /// `set_ownership_lock_file_names` installs a process-wide snapshot:
    /// every test that needs it installs this same list.
    fn install_test_lock_names() {
        set_ownership_lock_file_names(&[
            "LOCK".to_string(),
            "parent.lock".to_string(),
            "lockfile".to_string(),
        ]);
    }

    const HEADLESS: &str =
        "/Users/u/Library/Caches/ms-playwright/chromium_headless_shell-1234/chrome-headless-shell";
    const PROFILE_LOCKS: [&str; 2] = [
        "/w/browser-test-profile/Default/Local Storage/leveldb/LOCK",
        "/w/browser-test-profile/Default/Session Storage/LOCK",
    ];

    fn network_service_l7(pid: u32, parent_pid: Option<u32>, parent_image: &str) -> SessionL7 {
        SessionL7 {
            pid,
            parent_pid,
            start_time: 1_000,
            process_path: HEADLESS.to_string(),
            parent_process_path: parent_image.to_string(),
            open_files: vec!["/w/browser-test-profile/Default/Cookies".to_string()],
            ..Default::default()
        }
    }

    fn locks_by_pid(pid: u32) -> Vec<String> {
        match pid {
            // The browser process holds the profile's LevelDB locks.
            200 => PROFILE_LOCKS.iter().map(|p| p.to_string()).collect(),
            // The network service holds no lock of its own.
            _ => Vec::new(),
        }
    }

    #[test]
    fn the_first_attach_records_the_same_image_parent_s_locks() {
        install_test_lock_names();
        let mut l7 = network_service_l7(300, Some(200), HEADLESS);
        let mut asked = Vec::new();
        retain_ownership_lock_files_with(&mut l7, None, true, &mut |pid| {
            asked.push(pid);
            locks_by_pid(pid)
        });
        assert_eq!(asked, vec![300, 200]);
        assert_eq!(
            l7.open_files,
            vec![
                "/w/browser-test-profile/Default/Cookies".to_string(),
                PROFILE_LOCKS[0].to_string(),
                PROFILE_LOCKS[1].to_string(),
            ]
        );
    }

    #[test]
    fn a_parent_of_another_image_or_a_pid_zero_is_not_asked() {
        install_test_lock_names();
        let mut l7 = network_service_l7(300, Some(200), "/usr/bin/python3");
        let mut asked = Vec::new();
        retain_ownership_lock_files_with(&mut l7, None, true, &mut |pid| {
            asked.push(pid);
            locks_by_pid(pid)
        });
        assert_eq!(asked, vec![300]);
        assert_eq!(l7.open_files.len(), 1);

        let mut orphan = network_service_l7(0, Some(0), HEADLESS);
        retain_ownership_lock_files_with(&mut orphan, None, true, &mut |pid| {
            panic!("pid {pid} must not be asked")
        });
        assert_eq!(orphan.open_files.len(), 1);
    }

    /// The browser exited: the resolver's next answer carries no lock, the
    /// session's record keeps those of the same process without asking.
    #[test]
    fn the_same_process_keeps_its_locks_after_it_exits() {
        install_test_lock_names();
        let mut recorded = network_service_l7(300, Some(200), HEADLESS);
        retain_ownership_lock_files_with(&mut recorded, None, true, &mut locks_by_pid);
        let mut fresh = network_service_l7(300, Some(200), HEADLESS);
        retain_ownership_lock_files_with(&mut fresh, Some(&recorded), true, &mut |pid| {
            panic!("pid {pid} must not be asked again")
        });
        assert_eq!(fresh.open_files, recorded.open_files);
    }

    /// A recycled pid is another process: its predecessor's locks are not its
    /// own, so the record reads the new process's locks instead.
    #[test]
    fn a_recycled_pid_does_not_inherit_its_predecessor_s_locks() {
        install_test_lock_names();
        let mut recorded = network_service_l7(300, Some(200), HEADLESS);
        retain_ownership_lock_files_with(&mut recorded, None, true, &mut locks_by_pid);
        let mut reused = network_service_l7(300, None, "");
        reused.start_time = 2_000;
        reused.process_path = "/tmp/x/agent".to_string();
        retain_ownership_lock_files_with(&mut reused, Some(&recorded), true, &mut |_| Vec::new());
        assert!(!reused.open_files.iter().any(|p| is_ownership_lock_path(p)));
    }

    /// A first attach that could not ask the browser (its lineage named
    /// another image), then a resolution that names it: the record asks the
    /// same-image parent then, and carries its locks from there on.
    #[test]
    fn a_record_without_a_lock_asks_the_same_image_parent_again() {
        install_test_lock_names();
        let mut first = network_service_l7(300, Some(200), "/usr/bin/python3");
        let mut asked = Vec::new();
        retain_ownership_lock_files_with(&mut first, None, true, &mut |pid| {
            asked.push(pid);
            locks_by_pid(pid)
        });
        assert_eq!(asked, vec![300]);
        assert!(!first.open_files.iter().any(|p| is_ownership_lock_path(p)));

        let mut corrected = network_service_l7(300, Some(200), HEADLESS);
        asked.clear();
        retain_ownership_lock_files_with(&mut corrected, Some(&first), true, &mut |pid| {
            asked.push(pid);
            locks_by_pid(pid)
        });
        assert_eq!(asked, vec![200]);
        for lock in PROFILE_LOCKS {
            assert!(corrected.open_files.contains(&lock.to_string()));
        }

        // Found once: the record carries them without asking, after the
        // browser exited too.
        let mut later = network_service_l7(300, Some(200), HEADLESS);
        retain_ownership_lock_files_with(&mut later, Some(&corrected), true, &mut |pid| {
            panic!("pid {pid} must not be asked again")
        });
        for lock in PROFILE_LOCKS {
            assert!(later.open_files.contains(&lock.to_string()));
        }
    }

    /// A first read of the parent that came back without its locks is not
    /// final either.
    #[test]
    fn a_parent_whose_first_read_missed_is_asked_again() {
        install_test_lock_names();
        let mut first = network_service_l7(300, Some(200), HEADLESS);
        retain_ownership_lock_files_with(&mut first, None, true, &mut |_| Vec::new());
        assert!(!first.open_files.iter().any(|p| is_ownership_lock_path(p)));
        let mut next = network_service_l7(300, Some(200), HEADLESS);
        retain_ownership_lock_files_with(&mut next, Some(&first), true, &mut locks_by_pid);
        for lock in PROFILE_LOCKS {
            assert!(next.open_files.contains(&lock.to_string()));
        }
    }

    /// Where a lock never shows (Windows), and for a parent of another image,
    /// a record without a lock does not ask again.
    #[test]
    fn a_record_without_a_lock_asks_no_one_else() {
        install_test_lock_names();
        let mut first = network_service_l7(300, Some(200), HEADLESS);
        retain_ownership_lock_files_with(&mut first, None, false, &mut |_| Vec::new());
        let mut next = network_service_l7(300, Some(200), HEADLESS);
        retain_ownership_lock_files_with(&mut next, Some(&first), false, &mut |pid| {
            panic!("pid {pid} must not be asked without asks_parent_again")
        });
        assert!(!next.open_files.iter().any(|p| is_ownership_lock_path(p)));

        let mut other_image = network_service_l7(300, Some(200), "/usr/bin/python3");
        retain_ownership_lock_files_with(&mut other_image, Some(&first), true, &mut |pid| {
            panic!("pid {pid} runs another image and must not be asked")
        });
        assert!(!other_image
            .open_files
            .iter()
            .any(|p| is_ownership_lock_path(p)));
    }

    /// The resolver's read, against the OS: the test process stands in for
    /// the browser and holds a `LOCK` file; a child record of the same image
    /// gets it (not on Windows, where a lock file never shows).
    #[test]
    fn a_resolution_records_the_same_image_parent_s_locks() {
        install_test_lock_names();
        let dir = std::env::temp_dir().join(format!("flodbadd-parent-lock-{}", std::process::id()));
        let store = dir.join("Default").join("Local Storage").join("leveldb");
        std::fs::create_dir_all(&store).unwrap();
        let lock = store.join("LOCK");
        let held = std::fs::File::create(&lock).unwrap();
        invalidate_open_files_cache(std::process::id());

        let image = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .to_string();
        // The child's own material names the store (Windows asks the lock
        // holders by path, under the material's directory and its parent).
        let cookies = dir.join("Default").join("Cookies");
        let mut child = SessionL7 {
            pid: u32::MAX - 1,
            parent_pid: Some(std::process::id()),
            process_path: image.clone(),
            parent_process_path: image,
            open_files: vec![cookies.to_string_lossy().to_string()],
            ..Default::default()
        };
        add_same_image_parent_lock_files(&mut child);
        let recorded = child.open_files.iter().any(|path| {
            path.replace('\\', "/")
                .ends_with("Local Storage/leveldb/LOCK")
        });
        assert_eq!(recorded, READS_PARENT_LOCKS, "{:?}", child.open_files);

        let mut stranger = SessionL7 {
            pid: u32::MAX - 1,
            parent_pid: Some(std::process::id()),
            process_path: "/usr/bin/other".to_string(),
            parent_process_path: std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .to_string(),
            ..Default::default()
        };
        add_same_image_parent_lock_files(&mut stranger);
        assert!(stranger.open_files.is_empty());

        drop(held);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lock_files_survive_aggregation_and_re_resolution() {
        install_test_lock_names();
        let mut paths: Vec<String> = (0..(MAX_OPEN_FILES + 20))
            .map(|i| format!("/w/browser-test-profile/Default/Cache/data_{i:03}"))
            .collect();
        paths.push(PROFILE_LOCKS[0].to_string());
        let aggregated = aggregate_open_files(paths);
        assert!(aggregated.len() <= MAX_OPEN_FILES);
        assert!(aggregated.contains(&PROFILE_LOCKS[0].to_string()));

        let previous = vec![PROFILE_LOCKS[1].to_string(), "/w/other.dat".to_string()];
        let merged = merge_sensitive_open_files(vec!["/w/now.dat".to_string()], &previous);
        assert!(merged.contains(&PROFILE_LOCKS[1].to_string()));
        assert!(!merged.contains(&"/w/other.dat".to_string()));

        // At the cap, the other paths go before a carried lock file.
        let full: Vec<String> = (0..MAX_OPEN_FILES).map(|i| format!("/a/{i:03}")).collect();
        let merged = merge_sensitive_open_files(full, &[PROFILE_LOCKS[1].to_string()]);
        assert_eq!(merged.len(), MAX_OPEN_FILES);
        assert!(merged.contains(&PROFILE_LOCKS[1].to_string()));
    }

    #[test]
    fn lock_names_match_the_file_name_only_case_insensitively() {
        install_test_lock_names();
        assert!(is_ownership_lock_path("/p/Default/shared_proto_db/LOCK"));
        assert!(is_ownership_lock_path("C:\\Users\\x\\profile\\lockfile"));
        assert!(is_ownership_lock_path("/p/Parent.Lock"));
        assert!(!is_ownership_lock_path("/p/LOCK/Cookies"));
        assert!(!is_ownership_lock_path("/p/Default/Cookies"));
        // Backslash separators, mixed case and trailing whitespace, as the
        // Windows handle enumeration and a padded record hand them over.
        assert!(is_ownership_lock_path(
            "C:\\Users\\x\\Profile\\Default\\LOCK"
        ));
        assert!(is_ownership_lock_path("C:\\Users\\x\\Profile\\LockFile"));
        assert!(is_ownership_lock_path(
            "C:\\Users\\x\\Profile\\PARENT.LOCK  "
        ));
        assert!(is_ownership_lock_path("/p/Default/lock \t"));
        assert!(is_ownership_lock_path("/p/mixed\\separators/Lock"));
        assert!(!is_ownership_lock_path(
            "C:\\Users\\x\\Profile\\LOCK\\Cookies"
        ));
        assert!(!is_ownership_lock_path("C:\\Users\\x\\Profile\\LOCKS"));
        assert!(!is_ownership_lock_path(""));
        assert!(!is_ownership_lock_path("   "));
        assert!(!is_ownership_lock_path("/p/Default/"));
    }

    /// The lock files listed for a store: beside the material, a level
    /// above it, and in the store's own subdirectories, by name without
    /// case; nothing deeper, nothing that is not a lock name.
    #[test]
    fn lock_candidates_are_the_lock_files_around_the_material() {
        install_test_lock_names();
        let dir = std::env::temp_dir().join(format!("flodbadd-lock-cand-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let profile = dir.join("User Data");
        let default = profile.join("Default");
        let leveldb = default.join("Local Storage").join("leveldb");
        let deep = leveldb.join("too").join("deep");
        std::fs::create_dir_all(&deep).unwrap();
        for file in [
            profile.join("lockfile"),
            default.join("Cookies"),
            default.join("LOCK"),
            leveldb.join("LOCK"),
            leveldb.join("CURRENT"),
            deep.join("LOCK"),
        ] {
            std::fs::write(&file, "x").unwrap();
        }
        let material = vec![default.join("Cookies").to_string_lossy().to_string()];
        let mut found = lock_file_candidates(&material);
        found.sort();
        let mut expected: Vec<String> = [
            profile.join("lockfile"),
            default.join("LOCK"),
            leveldb.join("LOCK"),
        ]
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();
        expected.sort();
        assert_eq!(found, expected);
        assert!(lock_file_candidates(&[]).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Off Windows the holders are read from the enumeration, never by path.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn lock_file_holders_read_empty_where_the_enumeration_sees_writers() {
        assert!(lock_file_holders(&["/p/LOCK".to_string()]).is_empty());
    }

    /// The Restart Manager names this process for a file it holds open for
    /// writing, which the handle enumeration leaves out.
    #[cfg(target_os = "windows")]
    #[test]
    fn a_file_held_for_writing_names_this_process() {
        let dir = std::env::temp_dir().join(format!("flodbadd-lock-hold-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let lock = dir.join("LOCK");
        let held = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&lock)
            .unwrap();
        let path = lock.to_string_lossy().to_string();
        let holders = lock_file_holders(&[path.clone()]);
        assert!(
            holders
                .get(&path)
                .is_some_and(|pids| pids.contains(&std::process::id())),
            "{holders:?}"
        );
        drop(held);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
