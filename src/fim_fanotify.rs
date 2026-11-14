//! Kernel-time FIM writer attribution on Linux (FLODBADD2 §1b.2 "FIM writer
//! PID" row), the counterpart of the Endpoint Security file-attribution
//! table on macOS and the ETW FileIo table on Windows.
//!
//! `notify` (inotify) reports *what* changed but never *who*; until now the
//! Linux FIM resolved the writer after the fact by running `lsof` against
//! the path, which loses the race whenever the writer closes the file before
//! the poll -- the shape every credential-drop trigger has. The security
//! gate showed the consequence as `file_events` findings with a null writer
//! graded LOW (2026-09-07, ubuntu-arm64).
//!
//! fanotify delivers `FAN_MODIFY` / `FAN_CLOSE_WRITE` with the writer's pid
//! and an open fd on the file, at kernel time. This module marks every FIM
//! watch root and its subdirectories (bounded), resolves the path from the
//! event fd and the writer's image from `/proc/<pid>` while the writer is
//! still alive, and keeps a short-lived path -> writer table that
//! `fim::best_effort_process_attribution` consults before falling back to
//! `lsof`. Monitoring role only: notification class, no permission events,
//! fail-open (no fanotify => no table => the old behaviour).
//!
//! Needs CAP_SYS_ADMIN (the posture daemon / helper run as root). Marks
//! are per directory (`FAN_EVENT_ON_CHILD`), so a directory created after
//! start is attributed only once a mark lands on it. Two things do that: the
//! notify watcher calls `remark_directory` from its create events, and,
//! since 2.3.2, a second fanotify group in FID mode (`FAN_REPORT_DFID_NAME`)
//! reports `FAN_CREATE` on every marked directory, so the sensor thread
//! itself marks a new directory the moment the kernel reports it, with the
//! subdirectories that already exist in it, and records WHO created it. The
//! first files written into a new directory can still land before any mark
//! does (NSS creating `pki/nssdb/` and its `key4.db` within one millisecond:
//! FP-LIN-6, the CI lab's ubuntu-26.04 leg), and those are attributed to the
//! directory's creator as an INFERRED writer
//! (`get_inferred_creator_attribution`, [`CREATOR_TTL`]); a file's own
//! `FAN_CREATE` names its creator exactly. The table itself lives for the
//! process: a FIM restart with other paths calls `init` again, which marks
//! the roots not covered yet instead of returning.
//!
//! Both groups also feed the store-writer record (`crate::store_writers`)
//! for the files of the published stores: the writer group reports a write
//! with the file's size as the event's descriptor gives it, the creation
//! group a creation, a removal and a move with the process that made it
//! (`FAN_CREATE`, `FAN_DELETE`, `FAN_MOVED_FROM`, `FAN_MOVED_TO`), and a
//! queue overflow in either group (`FAN_Q_OVERFLOW`) is reported to the
//! record as dropped events.
//!
//! The creation group is inert, and says so once in the log, where the
//! kernel refuses its FID marks (a filesystem without file handles) or this
//! process cannot open the handle a record carries (`open_by_handle_at`
//! needs CAP_DAC_READ_SEARCH, which a Docker container's default
//! capabilities lack: the flodbadd CI's container legs, 2026-11-05). The
//! writer table then works as before 2.3.2, and the root test reads
//! `creation_marks_total` / `creation_unresolved_total` to skip there
//! instead of failing.

use dashmap::DashMap;
use nix::libc;
use nix::sys::fanotify::{EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags};
use once_cell::sync::OnceCell;
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};
use undeadlock::CustomDashMap;

/// Upper bound on directory marks (the kernel default `max_user_marks` is
/// 8192 per user; leave room for other consumers).
const MAX_DIRECTORY_MARKS: usize = 4096;
/// Marks the start-time walk leaves for directories created after start.
/// The walk is breadth-first over whatever already exists under a broad root
/// (a CI runner's whole home holds thousands of directories) and used to
/// spend the whole cap, so a directory created afterwards -- a credential or
/// agent-config directory, a new project -- was never marked and its writes
/// reached FIM without a writer. 512 leaves seven eighths of the cap to the
/// walk and is far more than the shallow directories a session creates.
const RUNTIME_MARK_RESERVE: usize = 512;
/// How deep below a watch root a directory created after start may still
/// take a reserved mark: the root itself (0), a new directory in it (1) and
/// one level more (`~/.cursor/rules`, `<project>/.claude`). Deeper new
/// directories (build trees) only get what the walk left.
const RESERVE_MAX_DEPTH: usize = 2;
/// How long a path -> writer entry stays valid. FIM events are translated
/// within milliseconds of the write; a minute covers hash-worker latency.
const ATTRIBUTION_TTL: Duration = Duration::from_secs(60);
const TABLE_MAX_ENTRIES: usize = 50_000;
/// How long the creator of a directory is taken as the writer of a file
/// written in it (or below it) that no mark attributed: the first files of a
/// new store land within milliseconds of its directory, before the mark the
/// creation event triggers. Short on purpose: past it a write in that
/// directory is somebody's, not the creator's by assumption.
const CREATOR_TTL: Duration = Duration::from_secs(15);
/// Subdirectories a directory-creation event marks along with the new
/// directory (the ones created in the race before its mark landed).
const CREATED_SUBTREE_MARKS: usize = 64;
/// Read buffer of the creation group: FID records carry file handles and
/// names, several per read.
const DIR_EVENT_BUFFER: usize = 64 * 1024;
/// Store files marked themselves at most: as many as the reader of the
/// files may hold. Past it a store file is recorded as one without a mark
/// ([`crate::store_writers::note_file_mark`]).
const MAX_STORE_FILE_MARKS: usize = 2_048;
/// How long either group may wait for an event before it records that its
/// queue was empty ([`crate::store_writers::note_delivered_through`]).
const DELIVERY_POLL_MS: i32 = 500;
/// How long before a new store directory's creation event was read its store
/// gap starts.
const NEW_DIRECTORY_SLACK_MS: u64 = 1_000;

#[derive(Debug, Clone)]
struct WriterAttribution {
    pid: u32,
    process_name: String,
    process_path: String,
    seen: Instant,
}

/// Who created a directory (the creation group's `FAN_CREATE | FAN_ONDIR`).
#[derive(Debug, Clone)]
struct DirectoryCreator {
    pid: u32,
    process_name: String,
    process_path: String,
    seen: Instant,
}

struct FanotifyTable {
    entries: DashMap<String, WriterAttribution>,
    fan: Fanotify,
    /// The creation group (FID mode, `FAN_CREATE | FAN_ONDIR` on every marked
    /// directory), `None` where the kernel refused it (before 5.9) : the
    /// writer table then works as before 2.3.2.
    dir_fan: Option<Fanotify>,
    /// Directories created since start, by path, with their creator.
    creators: DashMap<String, DirectoryCreator>,
    /// An open handle per watch root: the mount `open_by_handle_at` resolves
    /// a creation record's directory handle against.
    root_handles: CustomDashMap<String, std::fs::File>,
    marked: CustomDashMap<String, ()>,
    /// Every watch root `init` was given, existing yet or not: what
    /// [`remark_directory`] measures a new directory's depth against.
    roots: CustomDashMap<String, ()>,
    events_total: std::sync::atomic::AtomicU64,
    /// Creation events consumed (directories and files).
    created_total: std::sync::atomic::AtomicU64,
    /// FID marks the creation group holds, the marks the kernel refused and
    /// the last refusal's errno: a filesystem without file handles refuses
    /// every one, and the group is then inert on that root.
    creation_marks: std::sync::atomic::AtomicU64,
    creation_mark_failures: std::sync::atomic::AtomicU64,
    creation_mark_last_errno: std::sync::atomic::AtomicI32,
    /// Creation records whose parent handle this process could not open,
    /// and the last errno: `open_by_handle_at` needs CAP_DAC_READ_SEARCH,
    /// which a container's capability set lacks (EPERM). The group is then
    /// inert and new directories are marked from inotify only.
    creation_unresolved: std::sync::atomic::AtomicU64,
    creation_unresolved_last_errno: std::sync::atomic::AtomicI32,
    /// Queue overflows either group reported (`FAN_Q_OVERFLOW`).
    queue_overflows: std::sync::atomic::AtomicU64,
    /// Store roots that did not exist when they were given, by normalized
    /// path, and the directories marked for creations only on the way to
    /// them.
    awaited_roots: CustomDashMap<String, PathBuf>,
    sentinels: CustomDashMap<String, ()>,
    /// Store files marked themselves (inode marks, both groups), by
    /// `device:inode`, with the store path: a write or a change of names
    /// through another path reaches the record under this one. An entry is
    /// used only while its path still names that inode.
    inode_marks: CustomDashMap<String, String>,
    /// Up to when each group had read every event the kernel queued for it
    /// (epoch milliseconds; 0: not yet).
    writer_delivered_ms: std::sync::atomic::AtomicU64,
    creation_delivered_ms: std::sync::atomic::AtomicU64,
    /// Directories whose creation-group mark carries the store mask
    /// (removals and moves), and the parents of store roots marked for
    /// removals and moves of the roots themselves.
    store_masked: CustomDashMap<String, ()>,
}

static TABLE: OnceCell<Arc<FanotifyTable>> = OnceCell::new();

/// Start the fanotify writer-attribution table for the given FIM roots,
/// or, once it runs, extend its marks to the roots it does not cover yet.
/// Re-entrant on purpose: the FIM watcher is restarted whenever its paths
/// change (since 2.0.0 the daemon starts it with the default roots at
/// startup; the operator or the security gate restarts it with custom
/// roots later), and an `init` that merely returned on the second call
/// left every later root without kernel writer attribution -- the posture
/// gate's `package_install_lifecycle` scenario wrote under
/// `~/.cursor/rules`, a root the startup pass had never marked, and
/// resolved a null writer on both ubuntu legs (2026-09-19, runs
/// 35466191145 to 35480406093). Logs and returns on any failure
/// (fail-open).
pub fn init(roots: &[PathBuf]) {
    // One table per process. `get_or_try_init` serialises concurrent first
    // calls (two watchers starting at once): the second waits for the
    // first to finish instead of building a table of its own whose fd
    // nobody reads. A failure to open fanotify (no CAP_SYS_ADMIN) leaves
    // the cell empty so a later start can try again.
    let mut created = false;
    let table = TABLE.get_or_try_init(|| -> Result<Arc<FanotifyTable>, ()> {
        let fan = Fanotify::init(
            InitFlags::FAN_CLASS_NOTIF | InitFlags::FAN_CLOEXEC,
            EventFFlags::O_RDONLY | EventFFlags::O_CLOEXEC | EventFFlags::O_LARGEFILE,
        )
        .map_err(|e| {
            info!(
                "FIM fanotify writer attribution unavailable: {} (falling back to lsof)",
                e
            );
        })?;
        // The creation group: FID mode, so the kernel reports a creation
        // with its parent directory's handle and the new name
        // (FAN_REPORT_DFID_NAME, Linux 5.9). Fail-open: without it the
        // writer table works as before 2.3.2.
        let dir_fan = Fanotify::init(
            InitFlags::FAN_CLASS_NOTIF
                | InitFlags::FAN_CLOEXEC
                | InitFlags::from_bits_retain(libc::FAN_REPORT_DFID_NAME),
            EventFFlags::O_RDONLY | EventFFlags::O_CLOEXEC,
        )
        .map_err(|e| {
            info!(
                "FIM fanotify directory-creation group unavailable: {} (new directories are marked from inotify only)",
                e
            );
        })
        .ok();
        let table = Arc::new(FanotifyTable {
            entries: DashMap::new(),
            fan,
            dir_fan,
            creators: DashMap::new(),
            root_handles: CustomDashMap::new("fim_fanotify_root_handles"),
            marked: CustomDashMap::new("fim_fanotify_marked"),
            roots: CustomDashMap::new("fim_fanotify_roots"),
            events_total: std::sync::atomic::AtomicU64::new(0),
            created_total: std::sync::atomic::AtomicU64::new(0),
            creation_marks: std::sync::atomic::AtomicU64::new(0),
            creation_mark_failures: std::sync::atomic::AtomicU64::new(0),
            creation_mark_last_errno: std::sync::atomic::AtomicI32::new(0),
            creation_unresolved: std::sync::atomic::AtomicU64::new(0),
            creation_unresolved_last_errno: std::sync::atomic::AtomicI32::new(0),
            queue_overflows: std::sync::atomic::AtomicU64::new(0),
            awaited_roots: CustomDashMap::new("fim_fanotify_awaited_roots"),
            sentinels: CustomDashMap::new("fim_fanotify_sentinels"),
            inode_marks: CustomDashMap::new("fim_fanotify_inode_marks"),
            store_masked: CustomDashMap::new("fim_fanotify_store_masked"),
            writer_delivered_ms: std::sync::atomic::AtomicU64::new(0),
            creation_delivered_ms: std::sync::atomic::AtomicU64::new(0),
        });
        let reader = Arc::clone(&table);
        std::thread::Builder::new()
            .name("fim-fanotify".into())
            .spawn(move || reader_loop(reader))
            .map_err(|e| {
                warn!("FIM fanotify reader thread spawn failed: {}", e);
            })?;
        if table.dir_fan.is_some() {
            let reader = Arc::clone(&table);
            if let Err(e) = std::thread::Builder::new()
                .name("fim-fanotify-dir".into())
                .spawn(move || creation_loop(reader))
            {
                warn!("FIM fanotify creation reader thread spawn failed: {}", e);
            }
        }
        created = true;
        Ok(table)
    });
    let Ok(table) = table else {
        return;
    };
    for root in roots {
        table.roots.insert(root_key(root), ());
        // The mount to resolve creation records against: any directory of
        // the filesystem does, the root itself is the one known to exist.
        if let Ok(handle) = std::fs::File::open(root) {
            table.root_handles.insert(root_key(root), handle);
        }
    }
    if !created {
        extend(table, roots);
        remask_store_directories(table);
        return;
    }
    let marked = mark_roots(table, roots);
    remask_store_directories(table);
    if marked == 0 {
        info!("FIM fanotify: no directory could be marked yet (falling back to lsof)");
        return;
    }
    info!(
        "FIM fanotify writer attribution active: {} directories marked under {} root(s); directory-creation group {}",
        marked,
        roots.len(),
        if table.dir_fan.is_some() {
            "on"
        } else {
            "off (kernel without FAN_REPORT_DFID_NAME)"
        }
    );
}

/// Await the store roots in `roots` that do not exist yet: the nearest
/// directory above each that exists is marked for creations only, then each
/// directory created on the way to it the same, and the root, once created,
/// is marked with what is already in it. No-op before `init` or without the
/// creation group.
pub fn await_roots(roots: &[PathBuf]) {
    let Some(table) = TABLE.get() else {
        return;
    };
    if table.dir_fan.is_none() {
        return;
    }
    for root in roots {
        if root.exists() {
            continue;
        }
        table
            .awaited_roots
            .insert(normalize(&root.to_string_lossy()), root.clone());
        let mut ancestor = root.parent();
        while let Some(dir) = ancestor {
            if dir.is_dir() {
                sentinel_mark(table, dir);
                // A chain created between the test above and the mark
                // (`mkdir -p`) is followed down now.
                catch_up_awaited(table, dir);
                break;
            }
            ancestor = dir.parent();
        }
    }
}

/// After a creation-only mark on `dir`: the directory on the way to each
/// awaited root below it that already exists (created before the mark, a
/// `mkdir -p` faster than the marks) is taken as if its creation had been
/// reported.
fn catch_up_awaited(table: &FanotifyTable, dir: &Path) {
    let awaited: Vec<PathBuf> = table
        .awaited_roots
        .iter()
        .map(|entry| entry.value().clone())
        .collect();
    for root in awaited {
        let Ok(rest) = root.strip_prefix(dir) else {
            continue;
        };
        let Some(first) = rest.components().next() else {
            continue;
        };
        let child = dir.join(first);
        if child.is_dir() {
            awaited_root_created(table, dir, &child);
        }
    }
}

/// Mark `dir` in the creation group for the creations in it only.
fn sentinel_mark(table: &FanotifyTable, dir: &Path) {
    let key = root_key(dir);
    if table.sentinels.contains_key(&key) {
        return;
    }
    let (Some(dir_fan), Ok(handle)) = (table.dir_fan.as_ref(), std::fs::File::open(dir)) else {
        return;
    };
    let mask = MaskFlags::from_bits_retain(libc::FAN_CREATE) | MaskFlags::FAN_ONDIR;
    if dir_fan
        .mark::<_, Path>(MarkFlags::FAN_MARK_ADD, mask, &handle, None)
        .is_ok()
    {
        table.sentinels.insert(key.clone(), ());
        // Creation records under it resolve against this handle.
        table.root_handles.insert(key, handle);
    }
}

/// A directory created under a directory marked for an awaited root: the
/// root itself is marked with what is already in it; a directory on the way
/// is watched for creations in turn. `true` when the creation was one of
/// these (nothing else is done with it).
fn awaited_root_created(table: &FanotifyTable, parent: &Path, created: &Path) -> bool {
    if !table.sentinels.contains_key(&root_key(parent))
        || table.marked.contains_key(&root_key(parent))
    {
        return false;
    }
    let awaited: Vec<String> = table
        .awaited_roots
        .iter()
        .map(|entry| entry.key().clone())
        .collect();
    match crate::store_writers::awaited_root_step(&normalize(&created.to_string_lossy()), &awaited)
    {
        crate::store_writers::AwaitedRootStep::Root => {
            table
                .awaited_roots
                .remove(&normalize(&created.to_string_lossy()));
            table.roots.insert(root_key(created), ());
            if let Ok(handle) = std::fs::File::open(created) {
                table.root_handles.insert(root_key(created), handle);
            }
            let budget = MAX_DIRECTORY_MARKS.saturating_sub(table.marked.len());
            mark_tree(table, created, budget.min(RUNTIME_MARK_RESERVE));
        }
        crate::store_writers::AwaitedRootStep::Ancestor => {
            sentinel_mark(table, created);
            catch_up_awaited(table, created);
        }
        crate::store_writers::AwaitedRootStep::Unrelated => {}
    }
    true
}

/// Mark `roots` and their subtrees breadth-first, root by root, until the
/// walk's share of the cap ([`walk_budget`]). Returns the number of marks
/// added.
fn mark_roots(table: &FanotifyTable, roots: &[PathBuf]) -> usize {
    let mut added = 0usize;
    for root in roots {
        let budget = walk_budget().saturating_sub(table.marked.len());
        if budget == 0 {
            warn!(
                "FIM fanotify: directory walk budget ({} of {} marks) reached; {} and deeper directories are attributed by lsof only ({} marks stay reserved for directories created later)",
                walk_budget(),
                MAX_DIRECTORY_MARKS,
                root.display(),
                RUNTIME_MARK_RESERVE
            );
            break;
        }
        added += mark_tree(table, root, budget);
    }
    added
}

/// Mark the roots of a restarted watcher that the running table does not
/// cover yet, subtrees breadth-first within the remaining mark budget.
/// Earlier marks are kept: they only add coverage, and a root marked
/// before is skipped by key, so a restart with the same paths costs
/// nothing.
fn extend(table: &FanotifyTable, roots: &[PathBuf]) {
    remask_store_directories(table);
    let new_roots = roots_to_mark(&table.marked, roots);
    if new_roots.is_empty() {
        return;
    }
    let new_roots: Vec<PathBuf> = new_roots.into_iter().cloned().collect();
    let added = mark_roots(table, &new_roots);
    info!(
        "FIM fanotify writer attribution extended: {} directories marked under {} new root(s), {} marked in total",
        added,
        new_roots.len(),
        table.marked.len()
    );
}

/// The roots whose own directory carries no mark yet. A root nested in an
/// already-marked tree was marked with that tree, or fell past the cap,
/// in which case there is no budget left for it either way.
fn roots_to_mark<'a>(marked: &CustomDashMap<String, ()>, roots: &'a [PathBuf]) -> Vec<&'a PathBuf> {
    roots
        .iter()
        .filter(|root| !marked.contains_key(&root.to_string_lossy().to_string()))
        .collect()
}

/// Mark one directory the notify watcher just saw being created under a
/// watch root. Within the walk's share of the cap any directory is marked;
/// beyond it only a root or a directory at most [`RESERVE_MAX_DEPTH`] below
/// one takes a reserved mark. No-op before `init`, past the cap, or when
/// already marked.
pub fn remark_directory(dir: &Path) {
    if let Some(table) = TABLE.get() {
        let roots: Vec<String> = table.roots.iter().map(|root| root.key().clone()).collect();
        let depth = depth_below_roots(&dir.to_string_lossy(), &roots);
        if !may_mark_new_directory(table.marked.len(), depth) {
            // Past the cap: recorded as a store directory without a watch.
            if crate::store_writers::is_store_directory(&dir.to_string_lossy()) {
                crate::store_writers::note_store_directory_watch(&dir.to_string_lossy(), false);
            }
            return;
        }
        mark_one(table, dir);
    }
}

/// Forget the marks of a deleted directory and of everything under it. The
/// kernel drops a mark with its inode; the key left behind kept counting
/// against the cap and stopped a directory re-created at the same path from
/// being marked again. No-op before `init`.
pub fn forget_directory(dir: &Path) {
    if let Some(table) = TABLE.get() {
        let key = root_key(dir);
        let prefix = format!("{key}/");
        table
            .marked
            .retain(|marked, _| marked != &key && !marked.starts_with(&prefix));
        table
            .creators
            .retain(|created, _| created != &key && !created.starts_with(&prefix));
    }
}

/// The walk's share of the cap: what is left is reserved for directories
/// created after start ([`RUNTIME_MARK_RESERVE`]).
fn walk_budget() -> usize {
    MAX_DIRECTORY_MARKS - RUNTIME_MARK_RESERVE
}

/// A path as the tables key it: as given, without a trailing separator.
fn root_key(path: &Path) -> String {
    let key = path.to_string_lossy();
    let trimmed = key.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Depth of `dir` below the nearest watch root containing it (0: the root
/// itself), `None` outside every root.
fn depth_below_roots(dir: &str, roots: &[String]) -> Option<usize> {
    let dir = dir.trim_end_matches('/');
    roots
        .iter()
        .filter_map(|root| {
            let root = root.trim_end_matches('/');
            if dir == root || (root.is_empty() && dir.is_empty()) {
                return Some(0);
            }
            let rest = dir.strip_prefix(root)?.strip_prefix('/')?;
            Some(rest.split('/').filter(|part| !part.is_empty()).count())
        })
        .min()
}

/// Whether a directory created after start may take a mark now, `marked`
/// marks being held.
fn may_mark_new_directory(marked: usize, depth: Option<usize>) -> bool {
    if marked < walk_budget() {
        return true;
    }
    marked < MAX_DIRECTORY_MARKS && depth.is_some_and(|depth| depth <= RESERVE_MAX_DEPTH)
}

/// Kernel-attributed writer of `path`, if a write to it was seen within
/// [`ATTRIBUTION_TTL`]: `(pid, process_name, process_path)`.
pub fn get_file_attribution(path: &str) -> Option<(u32, String, String)> {
    let table = TABLE.get()?;
    let key = normalize(path);
    let entry = table.entries.get(&key)?;
    if entry.seen.elapsed() > ATTRIBUTION_TTL {
        drop(entry);
        table.entries.remove(&key);
        return None;
    }
    Some((
        entry.pid,
        entry.process_name.clone(),
        entry.process_path.clone(),
    ))
}

/// The creator of the nearest directory above `path` that the creation group
/// saw created within [`CREATOR_TTL`], as an INFERRED writer: `(pid,
/// process_name, process_path)`. The first files of a new store land before
/// the mark its directory's creation triggers (NSS writing `key4.db` into
/// the `pki/nssdb/` it just made), and the process that made the directory
/// a moment ago is the one filling it. Consulted after the exact table; the
/// caller reports it with `writer_inferred`. Never a watch root's creator:
/// the walk goes up to, not past, the roots.
pub fn get_inferred_creator_attribution(path: &str) -> Option<(u32, String, String)> {
    let table = TABLE.get()?;
    if table.dir_fan.is_none() || table.creators.is_empty() {
        return None;
    }
    let roots: Vec<String> = table.roots.iter().map(|root| root.key().clone()).collect();
    let mut dir = normalize(path);
    for _ in 0..8 {
        let Some((parent, _)) = dir.rsplit_once('/') else {
            return None;
        };
        if parent.is_empty() || roots.iter().any(|root| root == parent) {
            return None;
        }
        if let Some(creator) = table.creators.get(parent) {
            if creator.seen.elapsed() <= CREATOR_TTL {
                return Some((
                    creator.pid,
                    creator.process_name.clone(),
                    creator.process_path.clone(),
                ));
            }
            return None;
        }
        dir = parent.to_string();
    }
    None
}

/// Events consumed since start (sensor counter for status / tests).
pub fn events_total() -> u64 {
    TABLE
        .get()
        .map(|t| t.events_total.load(std::sync::atomic::Ordering::Relaxed))
        .unwrap_or(0)
}

pub fn is_active() -> bool {
    TABLE.get().is_some()
}

/// Whether the directory-creation group runs (FID mode accepted by the
/// kernel): creations are attributed and new directories marked at once.
pub fn creation_group_active() -> bool {
    TABLE.get().is_some_and(|table| table.dir_fan.is_some())
}

/// Creation events consumed since start (directories and files).
pub fn created_total() -> u64 {
    TABLE
        .get()
        .map(|t| t.created_total.load(std::sync::atomic::Ordering::Relaxed))
        .unwrap_or(0)
}

/// FID marks the creation group holds.
pub fn creation_marks_total() -> u64 {
    TABLE
        .get()
        .map(|t| t.creation_marks.load(std::sync::atomic::Ordering::Relaxed))
        .unwrap_or(0)
}

/// FID marks the kernel refused, and the last refusal's errno (a filesystem
/// without file handles refuses every mark on it).
pub fn creation_mark_failures() -> (u64, i32) {
    TABLE
        .get()
        .map(|t| {
            (
                t.creation_mark_failures
                    .load(std::sync::atomic::Ordering::Relaxed),
                t.creation_mark_last_errno
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
        })
        .unwrap_or((0, 0))
}

/// Creation records this process could not resolve to a directory, and the
/// last errno (EPERM: no CAP_DAC_READ_SEARCH, a container).
pub fn creation_unresolved_total() -> (u64, i32) {
    TABLE
        .get()
        .map(|t| {
            (
                t.creation_unresolved
                    .load(std::sync::atomic::Ordering::Relaxed),
                t.creation_unresolved_last_errno
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
        })
        .unwrap_or((0, 0))
}

/// Queue overflows the kernel reported to either group since start.
pub fn queue_overflows() -> u64 {
    TABLE
        .get()
        .map(|t| t.queue_overflows.load(std::sync::atomic::Ordering::Relaxed))
        .unwrap_or(0)
}

fn normalize(path: &str) -> String {
    path.trim().to_string()
}

/// The directory entry events the creation group asks for: a creation; on a
/// store directory, a removal and both ends of a move too, each with the
/// process that made it.
fn creation_group_mask(store_directory: bool) -> MaskFlags {
    let entries = if store_directory {
        libc::FAN_CREATE | libc::FAN_DELETE | libc::FAN_MOVED_FROM | libc::FAN_MOVED_TO
    } else {
        libc::FAN_CREATE
    };
    MaskFlags::from_bits_retain(entries) | MaskFlags::FAN_ONDIR | MaskFlags::FAN_EVENT_ON_CHILD
}

/// Feed the store-writer record with one operation on `path` by `pid`: the
/// process's start as the kernel records it (the one derivation every
/// sensor uses, `process_events::process_start_ms`), its image as resolved
/// for the attribution table, the time the event was read.
fn store_record(
    ops: u32,
    path: &str,
    pid: u32,
    process_path: &str,
    size: Option<u64>,
    identity: Option<crate::store_writers::FileId>,
) {
    crate::store_writers::record(&crate::store_writers::Operation {
        path,
        ops,
        pid,
        started_at_ms: crate::process_events::process_start_ms(pid),
        process_path,
        at_ms: crate::store_writers::now_ms(),
        size,
        identity,
    });
}

/// A queue overflow: the kernel dropped events of this group.
fn note_queue_overflow(table: &FanotifyTable) {
    table
        .queue_overflows
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    crate::store_writers::note_lost(crate::store_writers::now_ms());
}

fn mark_one(table: &FanotifyTable, dir: &Path) -> bool {
    let key = dir.to_string_lossy().to_string();
    if table.marked.contains_key(&key) {
        return false;
    }
    let Ok(handle) = std::fs::File::open(dir) else {
        if crate::store_writers::is_store_directory(&key) {
            crate::store_writers::note_store_directory_watch(&key, false);
        }
        return false;
    };
    match table.fan.mark::<_, Path>(
        MarkFlags::FAN_MARK_ADD,
        MaskFlags::FAN_MODIFY | MaskFlags::FAN_CLOSE_WRITE | MaskFlags::FAN_EVENT_ON_CHILD,
        &handle,
        None,
    ) {
        Ok(()) => {
            // The creation group marks the same directory: a file or
            // subdirectory created in it is reported with its creator.
            if let Some(dir_fan) = table.dir_fan.as_ref() {
                let store_directory =
                    crate::store_writers::is_store_directory(&dir.to_string_lossy());
                if store_directory {
                    table.store_masked.insert(root_key(dir), ());
                    crate::store_writers::note_store_directory_watch(&dir.to_string_lossy(), true);
                    mark_store_root_parent(table, dir);
                }
                match dir_fan.mark::<_, Path>(
                    MarkFlags::FAN_MARK_ADD,
                    creation_group_mask(store_directory),
                    &handle,
                    None,
                ) {
                    Ok(()) => {
                        table
                            .creation_marks
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(e) => {
                        table
                            .creation_mark_failures
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        table
                            .creation_mark_last_errno
                            .store(e as i32, std::sync::atomic::Ordering::Relaxed);
                        if store_directory {
                            // Recorded as a store directory without a
                            // watch.
                            let _ = table.store_masked.remove(&root_key(dir));
                            crate::store_writers::note_store_directory_watch(
                                &dir.to_string_lossy(),
                                false,
                            );
                        }
                        debug!(
                            "FIM fanotify: creation mark {} failed: {}",
                            dir.display(),
                            e
                        );
                    }
                }
            }
            table.marked.insert(key, ());
            true
        }
        Err(e) => {
            debug!("FIM fanotify: mark failed: {}", e);
            if crate::store_writers::is_store_directory(&dir.to_string_lossy()) {
                crate::store_writers::note_store_directory_watch(&dir.to_string_lossy(), false);
            }
            false
        }
    }
}

/// A store root's parent, marked in the creation group for removals and
/// moves: the root itself renamed or removed is reported (its contents
/// then name other files).
fn mark_store_root_parent(table: &FanotifyTable, dir: &Path) {
    if !crate::store_writers::is_store_root(&dir.to_string_lossy()) {
        return;
    }
    let (Some(dir_fan), Some(parent)) = (table.dir_fan.as_ref(), dir.parent()) else {
        return;
    };
    let key = format!("{}#parent", root_key(parent));
    if table.store_masked.contains_key(&key) {
        return;
    }
    let Ok(handle) = std::fs::File::open(parent) else {
        return;
    };
    let mask =
        MaskFlags::from_bits_retain(libc::FAN_DELETE | libc::FAN_MOVED_FROM | libc::FAN_MOVED_TO)
            | MaskFlags::FAN_ONDIR
            | MaskFlags::FAN_EVENT_ON_CHILD;
    if dir_fan
        .mark::<_, Path>(MarkFlags::FAN_MARK_ADD, mask, &handle, None)
        .is_ok()
    {
        table.store_masked.insert(key, ());
        table.root_handles.insert(root_key(parent), handle);
    }
}

/// Every marked directory that is a store directory now and whose
/// creation-group mark lacks the store mask gets it (stores published after
/// the directory was marked, a restart). `FAN_MARK_ADD` adds to a mark.
fn remask_store_directories(table: &FanotifyTable) {
    let Some(dir_fan) = table.dir_fan.as_ref() else {
        return;
    };
    let marked: Vec<String> = table
        .marked
        .iter()
        .map(|entry| entry.key().clone())
        .collect();
    for key in marked {
        if !crate::store_writers::is_store_directory(&key) {
            continue;
        }
        let dir = PathBuf::from(&key);
        mark_store_root_parent(table, &dir);
        if table.store_masked.contains_key(&root_key(&dir)) {
            continue;
        }
        let Ok(handle) = std::fs::File::open(&dir) else {
            continue;
        };
        if dir_fan
            .mark::<_, Path>(
                MarkFlags::FAN_MARK_ADD,
                creation_group_mask(true),
                &handle,
                None,
            )
            .is_ok()
        {
            table.store_masked.insert(root_key(&dir), ());
            crate::store_writers::note_store_directory_watch(&key, true);
        }
    }
}

/// Mark a store file itself (an inode mark) in both groups, and record
/// what that found: a write through any name of the file, and a change of
/// its attributes or of its number of names, reach the record under the
/// store path. The mark is added on every call (`FAN_MARK_ADD` is
/// idempotent): an entry of the table never stands for a mark. A file the
/// marks cannot reach (past [`MAX_STORE_FILE_MARKS`], a refused mark, a
/// symbolic link) is recorded as one without a mark, and a file with more
/// than one name when it is marked as one with a second name.
fn mark_store_file(table: &FanotifyTable, path: &str) {
    let at_ms = crate::store_writers::now_ms();
    if let Some((marked, second_name)) = add_store_file_mark(table, path) {
        crate::store_writers::note_file_mark(path, at_ms, marked, second_name);
    }
}

/// `None` when no regular file is at `path` (gone, a directory); else
/// whether both marks are in place, and whether the file has more than one
/// name.
fn add_store_file_mark(table: &FanotifyTable, path: &str) -> Option<(bool, bool)> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        // A symbolic link at a store path: recorded as a file without a
        // mark.
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Some((false, false)),
        Err(_) => return None,
    };
    let meta = file.metadata().ok()?;
    if !meta.is_file() {
        return None;
    }
    let second_name = meta.nlink() > 1;
    let key = inode_key(&meta);
    if !table.inode_marks.contains_key(&key) && table.inode_marks.len() >= MAX_STORE_FILE_MARKS {
        prune_inode_marks(table);
        if table.inode_marks.len() >= MAX_STORE_FILE_MARKS {
            return Some((false, second_name));
        }
    }
    if table
        .fan
        .mark::<_, Path>(
            MarkFlags::FAN_MARK_ADD,
            MaskFlags::FAN_MODIFY | MaskFlags::FAN_CLOSE_WRITE,
            &file,
            None,
        )
        .is_err()
    {
        return Some((false, second_name));
    }
    if let Some(dir_fan) = table.dir_fan.as_ref() {
        if dir_fan
            .mark::<_, Path>(
                MarkFlags::FAN_MARK_ADD,
                MaskFlags::from_bits_retain(libc::FAN_ATTRIB),
                &file,
                None,
            )
            .is_err()
        {
            return Some((false, second_name));
        }
    }
    table.inode_marks.insert(key, path.to_string());
    Some((true, second_name))
}

fn inode_key(meta: &std::fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    format!("{}:{}", meta.dev(), meta.ino())
}

/// Whether `path` still names the inode `key` was made for.
fn still_names(path: &str, key: &str) -> bool {
    std::fs::symlink_metadata(path)
        .map(|meta| meta.is_file() && inode_key(&meta) == key)
        .unwrap_or(false)
}

/// Drop every entry whose path no longer names its inode (renamed, removed,
/// the inode number given to another file).
fn prune_inode_marks(table: &FanotifyTable) {
    table.inode_marks.retain(|key, path| still_names(path, key));
}

/// The store path of the marked store file with this metadata, if any: an
/// entry whose path no longer names that inode is dropped, not used.
fn marked_store_path(table: &FanotifyTable, meta: &std::fs::Metadata) -> Option<String> {
    let key = inode_key(meta);
    let path = table
        .inode_marks
        .get(&key)
        .map(|entry| entry.value().clone())?;
    if still_names(&path, &key) {
        Some(path)
    } else {
        let _ = table.inode_marks.remove(&key);
        None
    }
}

/// Wait up to [`DELIVERY_POLL_MS`] for an event on `fd`. `true` when one is
/// ready; `false` when none came, after recording that the group had read
/// every event the kernel queued up to the start of the wait.
fn wait_for_events(
    fd: std::os::fd::BorrowedFd<'_>,
    delivered: &std::sync::atomic::AtomicU64,
) -> bool {
    let before = crate::store_writers::now_ms();
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid `pollfd` for a descriptor the group owns, for the
    // duration of the call.
    let ready = unsafe { libc::poll(&mut poll, 1, DELIVERY_POLL_MS) };
    if ready == 0 {
        note_group_delivered(delivered, before);
        return false;
    }
    true
}

/// After a read and the handling of what it returned: when the group's
/// queue holds nothing more, the group read every event queued up to the
/// start of that read.
fn note_if_drained(
    fd: std::os::fd::BorrowedFd<'_>,
    delivered: &std::sync::atomic::AtomicU64,
    read_started_ms: u64,
) {
    let mut pending: libc::c_int = 0;
    // SAFETY: FIONREAD writes one `c_int` through the pointer given, for a
    // descriptor the group owns.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::FIONREAD, &mut pending) };
    if rc == 0 && pending == 0 {
        note_group_delivered(delivered, read_started_ms);
    }
}

/// A group read every event queued up to `at_ms`: the sensor delivered
/// through the earlier of the two groups' times.
fn note_group_delivered(delivered: &std::sync::atomic::AtomicU64, at_ms: u64) {
    crate::store_writers::advance_delivery(delivered, at_ms);
    let Some(table) = TABLE.get() else {
        return;
    };
    let writer = table
        .writer_delivered_ms
        .load(std::sync::atomic::Ordering::Acquire);
    let through = if table.dir_fan.is_some() {
        writer.min(
            table
                .creation_delivered_ms
                .load(std::sync::atomic::Ordering::Acquire),
        )
    } else {
        writer
    };
    if through != 0 {
        crate::store_writers::note_delivered_through(through);
    }
}

/// Mark `root` and its subdirectories breadth-first (no symlink following),
/// up to `budget` marks. Returns the number of marks added.
fn mark_tree(table: &FanotifyTable, root: &Path, budget: usize) -> usize {
    if budget == 0 {
        return 0;
    }
    let mut added = 0usize;
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(root.to_path_buf());
    while let Some(dir) = queue.pop_front() {
        if added >= budget {
            // Past the budget: each store directory recorded as one without
            // a watch.
            for left in std::iter::once(dir).chain(queue.into_iter()) {
                if crate::store_writers::is_store_directory(&left.to_string_lossy()) {
                    crate::store_writers::note_store_directory_watch(
                        &left.to_string_lossy(),
                        false,
                    );
                }
            }
            break;
        }
        let Ok(meta) = std::fs::symlink_metadata(&dir) else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        if mark_one(table, &dir) {
            added += 1;
        }
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if let Ok(ft) = entry.file_type() {
                    if ft.is_dir() && !ft.is_symlink() {
                        queue.push_back(entry.path());
                    }
                }
            }
        }
    }
    added
}

/// Image of the writer: `/proc/<pid>` while it is alive, otherwise the
/// exec record the process-event ring kept for that pid (a `sh -c 'echo
/// > file'` writer is gone before the reader thread wakes up -- the very
/// race this module exists to close).
fn resolve_writer(pid: u32) -> (String, String) {
    let process_path = std::fs::read_link(format!("/proc/{pid}/exe"))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    if !process_path.is_empty() {
        let name = Path::new(&process_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        return (name, process_path);
    }
    if let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
        let comm = comm.trim().to_string();
        if !comm.is_empty() {
            return (comm, String::new());
        }
    }
    // Exited: the eBPF exec stream recorded the image at exec time. Searched
    // in the ring, not copied out of it: a copy per event held the ring lock
    // long enough to drop the sensor's pushes.
    crate::process_events::latest_exec_image(pid).unwrap_or_default()
}

fn reader_loop(table: Arc<FanotifyTable>) {
    loop {
        // With stores published, the group says up to when it delivered.
        let configured = crate::store_writers::is_configured();
        if configured && !wait_for_events(table.fan.as_fd(), &table.writer_delivered_ms) {
            continue;
        }
        let read_started = crate::store_writers::now_ms();
        let events = match table.fan.read_events() {
            Ok(events) => events,
            Err(nix::errno::Errno::EINTR) | Err(nix::errno::Errno::EAGAIN) => continue,
            Err(e) => {
                warn!("FIM fanotify reader stopped: {}", e);
                return;
            }
        };
        for event in events {
            if event.mask().bits() & libc::FAN_Q_OVERFLOW != 0 {
                note_queue_overflow(&table);
                continue;
            }
            // `event` owns the fd and closes it on drop.
            let Some(fd) = event.fd() else {
                continue;
            };
            let fd_link = format!("/proc/self/fd/{}", fd.as_raw_fd());
            let path = match std::fs::read_link(&fd_link) {
                Ok(p) => p.to_string_lossy().to_string(),
                Err(_) => continue,
            };
            let pid = event.pid();
            if pid <= 0 || pid as u32 == std::process::id() {
                continue;
            }
            let pid = pid as u32;
            table
                .events_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let (process_name, process_path) = resolve_writer(pid);
            // The store-writer record takes the write with the pid alone
            // when the image could not be resolved, and the file's size as
            // the event's descriptor gives it.
            // A store file by the name the event's descriptor carries, or a
            // marked store file written through another name.
            let meta = std::fs::metadata(&fd_link).ok();
            let store_path = if crate::store_writers::classify(&path).is_some() {
                mark_store_file(&table, &path);
                Some(path.clone())
            } else {
                meta.as_ref()
                    .and_then(|meta| marked_store_path(&table, meta))
            };
            if let Some(store_path) = store_path {
                use std::os::unix::fs::MetadataExt;
                store_record(
                    crate::store_writers::ops::WRITE,
                    &store_path,
                    pid,
                    &process_path,
                    meta.as_ref().map(|meta| meta.len()),
                    meta.as_ref().map(|meta| crate::store_writers::FileId {
                        device: meta.dev(),
                        inode: meta.ino(),
                    }),
                );
            }
            if process_name.is_empty() && process_path.is_empty() {
                continue;
            }
            if table.entries.len() >= TABLE_MAX_ENTRIES {
                let cutoff = Instant::now();
                table
                    .entries
                    .retain(|_, v| cutoff.duration_since(v.seen) <= ATTRIBUTION_TTL);
            }
            table.entries.insert(
                normalize(&path),
                WriterAttribution {
                    pid,
                    process_name,
                    process_path,
                    seen: Instant::now(),
                },
            );
        }
        if configured {
            note_if_drained(table.fan.as_fd(), &table.writer_delivered_ms, read_started);
        }
    }
}

/// One creation the FID group reported: who (`pid`), where (the parent
/// directory's file handle, resolved against a watch root's mount) and what
/// (`name`, a directory when `is_dir`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct CreationRecord {
    pid: i32,
    is_dir: bool,
    /// The event's mask: which of the creation group's events this is.
    mask: u64,
    handle_type: i32,
    handle: Vec<u8>,
    name: String,
}

/// Whether one of the events of `buf` is a queue overflow (`FAN_Q_OVERFLOW`:
/// an event with no record of its own).
fn events_report_overflow(buf: &[u8]) -> bool {
    let meta_size = std::mem::size_of::<libc::fanotify_event_metadata>();
    let mut offset = 0usize;
    while offset + meta_size <= buf.len() {
        // SAFETY: as in `parse_creation_records`: a complete metadata struct
        // lies at `offset` (the bounds check above), read as an unaligned copy.
        let meta: libc::fanotify_event_metadata =
            unsafe { std::ptr::read_unaligned(buf[offset..].as_ptr().cast()) };
        let event_len = meta.event_len as usize;
        if event_len < meta_size || offset + event_len > buf.len() {
            break;
        }
        if meta.mask & libc::FAN_Q_OVERFLOW != 0 {
            return true;
        }
        offset += event_len;
    }
    false
}

/// Parse the events a `FAN_REPORT_DFID_NAME` group returned: for each
/// `fanotify_event_metadata` the `FAN_EVENT_INFO_TYPE_DFID_NAME` record that
/// follows it (header, `fsid`, the parent directory's `file_handle`, the
/// NUL-terminated name). Events without such a record (a queue overflow,
/// another info type) are skipped; a malformed length ends the parse.
fn parse_creation_records(buf: &[u8]) -> Vec<CreationRecord> {
    let meta_size = std::mem::size_of::<libc::fanotify_event_metadata>();
    let header_size = std::mem::size_of::<libc::fanotify_event_info_header>();
    let fsid_size = std::mem::size_of::<libc::__kernel_fsid_t>();
    let mut records = Vec::new();
    let mut offset = 0usize;
    while offset + meta_size <= buf.len() {
        // SAFETY: the kernel wrote a complete metadata struct at `offset`
        // (the bounds check above) ; read unaligned copies, never references.
        let meta: libc::fanotify_event_metadata =
            unsafe { std::ptr::read_unaligned(buf[offset..].as_ptr().cast()) };
        let event_len = meta.event_len as usize;
        if event_len < meta_size || offset + event_len > buf.len() {
            break;
        }
        let mut info = offset + meta.metadata_len as usize;
        let end = offset + event_len;
        while info + header_size <= end {
            let header: libc::fanotify_event_info_header =
                unsafe { std::ptr::read_unaligned(buf[info..].as_ptr().cast()) };
            let len = header.len as usize;
            if len < header_size || info + len > end {
                break;
            }
            if header.info_type == libc::FAN_EVENT_INFO_TYPE_DFID_NAME {
                // fanotify_event_info_fid: header, fsid, then a file_handle
                // (handle_bytes u32, handle_type i32, f_handle[handle_bytes])
                // followed by the NUL-terminated name.
                let fh = info + header_size + fsid_size;
                if fh + 8 <= info + len {
                    let handle_bytes =
                        u32::from_ne_bytes([buf[fh], buf[fh + 1], buf[fh + 2], buf[fh + 3]])
                            as usize;
                    let handle_type =
                        i32::from_ne_bytes([buf[fh + 4], buf[fh + 5], buf[fh + 6], buf[fh + 7]]);
                    let handle_start = fh + 8;
                    let name_start = handle_start + handle_bytes;
                    if name_start <= info + len {
                        let name_bytes = &buf[name_start..info + len];
                        let name_end = name_bytes
                            .iter()
                            .position(|b| *b == 0)
                            .unwrap_or(name_bytes.len());
                        let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();
                        if !name.is_empty() {
                            records.push(CreationRecord {
                                pid: meta.pid,
                                is_dir: meta.mask & (libc::FAN_ONDIR as u64) != 0,
                                mask: meta.mask,
                                handle_type,
                                handle: buf[handle_start..name_start].to_vec(),
                                name,
                            });
                        }
                    }
                }
            }
            info += len;
        }
        offset += event_len;
    }
    records
}

/// The directory a creation record's parent handle names, resolved with
/// `open_by_handle_at` against the watch roots' mounts (the first that
/// accepts it), then `/proc/self/fd`.
fn resolve_parent_directory(table: &FanotifyTable, record: &CreationRecord) -> Option<PathBuf> {
    // A libc::file_handle followed by its bytes, in one allocation.
    let mut raw = vec![0u8; 8 + record.handle.len()];
    raw[..4].copy_from_slice(&(record.handle.len() as u32).to_ne_bytes());
    raw[4..8].copy_from_slice(&record.handle_type.to_ne_bytes());
    raw[8..].copy_from_slice(&record.handle);
    let mut last_errno = 0i32;
    for root in table.root_handles.iter() {
        // SAFETY: `raw` holds a well-formed file_handle (handle_bytes names
        // exactly the bytes that follow) and outlives the call.
        let fd = unsafe {
            libc::open_by_handle_at(
                root.value().as_raw_fd(),
                raw.as_mut_ptr().cast::<libc::file_handle>(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            last_errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            continue;
        }
        let path = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok();
        // SAFETY: `fd` was returned by open_by_handle_at above and is closed once.
        unsafe {
            libc::close(fd);
        }
        if let Some(path) = path {
            return Some(path);
        }
    }
    table
        .creation_unresolved
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    table
        .creation_unresolved_last_errno
        .store(last_errno, std::sync::atomic::Ordering::Relaxed);
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        info!(
            "FIM fanotify: a directory-creation record could not be resolved (open_by_handle_at: {}); without CAP_DAC_READ_SEARCH (a container) new directories are marked from inotify only",
            std::io::Error::from_raw_os_error(last_errno)
        );
    }
    None
}

/// Mark a directory the kernel just reported created, and the subdirectories
/// already in it (made in the race before this mark), within the reserve
/// rules of [`remark_directory`].
fn mark_created_directory(table: &FanotifyTable, dir: &Path) {
    remark_directory(dir);
    let mut marked = 0usize;
    let mut queue = std::collections::VecDeque::from([dir.to_path_buf()]);
    while let Some(current) = queue.pop_front() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() && !file_type.is_symlink() {
                let sub = entry.path();
                if marked >= CREATED_SUBTREE_MARKS {
                    // Past the bound: a store directory left without a
                    // watch is recorded as one.
                    note_unwatched_store_directory(table, &sub);
                    continue;
                }
                remark_directory(&sub);
                marked += 1;
                if table
                    .marked
                    .contains_key(&sub.to_string_lossy().to_string())
                {
                    queue.push_back(sub);
                }
            }
        }
    }
}

/// A store directory not marked (and not marked before): recorded as one
/// without a watch.
fn note_unwatched_store_directory(table: &FanotifyTable, dir: &Path) {
    let key = dir.to_string_lossy();
    if !table.marked.contains_key(&root_key(dir)) && crate::store_writers::is_store_directory(&key)
    {
        crate::store_writers::note_store_directory_watch(&key, false);
    }
}

/// A store directory created since the sensor started, just marked: the
/// window from its creation to its mark is recorded as a store gap, and
/// each file found in it is marked changed for its reader, as a record with
/// no creation.
fn new_store_directory(dir: &Path, read_at_ms: u64) {
    let now = crate::store_writers::now_ms();
    let from = Some(read_at_ms.saturating_sub(NEW_DIRECTORY_SLACK_MS));
    crate::store_writers::note_store_gap(&dir.to_string_lossy(), from, now, "new_directory");
    walk_store_directory(dir, from, now);
}

/// Each store file found in `dir` (a few levels down) is marked changed for
/// its reader, as a record with no creation. Past the walk's bound, the
/// files left are a gap of the store from `gap_from` to now.
fn walk_store_directory(dir: &Path, gap_from: Option<u64>, now: u64) {
    let mut queue = std::collections::VecDeque::from([(dir.to_path_buf(), 0usize)]);
    let mut seen = 0usize;
    while let Some((current, depth)) = queue.pop_front() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > CREATED_SUBTREE_MARKS * 16 {
                crate::store_writers::note_store_gap(
                    &dir.to_string_lossy(),
                    gap_from,
                    crate::store_writers::now_ms(),
                    "walk_bound",
                );
                return;
            }
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if file_type.is_dir() && !file_type.is_symlink() && depth < 3 {
                queue.push_back((path, depth + 1));
            } else if file_type.is_file()
                && crate::store_writers::classify(&path.to_string_lossy()).is_some()
            {
                crate::store_writers::note_change(&path.to_string_lossy(), now);
            }
        }
    }
}

/// The store-writer operations a creation-group event's mask stands for.
fn store_ops_for_mask(mask: u64) -> u32 {
    use crate::store_writers::ops;
    let mut out = 0u32;
    if mask & libc::FAN_CREATE != 0 {
        out |= ops::CREATE;
    }
    if mask & libc::FAN_DELETE != 0 {
        out |= ops::REMOVE;
    }
    if mask & libc::FAN_MOVED_FROM != 0 {
        out |= ops::RENAME_FROM;
    }
    if mask & libc::FAN_MOVED_TO != 0 {
        out |= ops::RENAME_TO;
    }
    out
}

fn creation_loop(table: Arc<FanotifyTable>) {
    let Some(dir_fan) = table.dir_fan.as_ref() else {
        return;
    };
    let mut buf = vec![0u8; DIR_EVENT_BUFFER];
    loop {
        let configured = crate::store_writers::is_configured();
        if configured && !wait_for_events(dir_fan.as_fd(), &table.creation_delivered_ms) {
            continue;
        }
        let read_started = crate::store_writers::now_ms();
        let nread = match nix::unistd::read(dir_fan.as_fd(), &mut buf) {
            Ok(n) => n,
            Err(nix::errno::Errno::EINTR) | Err(nix::errno::Errno::EAGAIN) => continue,
            Err(e) => {
                warn!("FIM fanotify creation reader stopped: {}", e);
                return;
            }
        };
        let own_pid = std::process::id() as i32;
        let read_at_ms = crate::store_writers::now_ms();
        if events_report_overflow(&buf[..nread]) {
            note_queue_overflow(&table);
        }
        for record in parse_creation_records(&buf[..nread]) {
            if record.pid <= 0 || record.pid == own_pid {
                continue;
            }
            let Some(parent) = resolve_parent_directory(&table, &record) else {
                continue;
            };
            let created = parent.join(&record.name);
            // Under a directory watched only for an awaited store root:
            // nothing else is done with it (no process is resolved).
            if record.mask & libc::FAN_CREATE != 0 && record.is_dir {
                if awaited_root_created(&table, &parent, &created) {
                    continue;
                }
            } else if table.sentinels.contains_key(&root_key(&parent))
                && !table.marked.contains_key(&root_key(&parent))
            {
                continue;
            }
            let pid = record.pid as u32;
            // An attribute change of a store file (its own mark): its
            // number of names above one is a link, else an attribute.
            if record.mask & libc::FAN_ATTRIB != 0 && record.mask & libc::FAN_CREATE == 0 {
                let path = created.to_string_lossy();
                if !record.is_dir && crate::store_writers::classify(&path).is_some() {
                    use std::os::unix::fs::MetadataExt;
                    let links = std::fs::symlink_metadata(&*path).map(|meta| meta.nlink());
                    let ops = match links {
                        Ok(1) => crate::store_writers::ops::ATTRIBUTES,
                        _ => crate::store_writers::ops::LINK,
                    };
                    let (_, process_path) = resolve_writer(pid);
                    store_record(ops, &path, pid, &process_path, None, None);
                }
                continue;
            }
            // A removal or a move (asked for on store directories and on
            // the parents of store roots): for a store file, the record; for
            // a directory, every record below it.
            if record.mask & libc::FAN_CREATE == 0 {
                let path = created.to_string_lossy();
                if record.is_dir && record.mask & libc::FAN_MOVED_TO != 0 {
                    // Moved into place: marked and walked as a new
                    // directory, its files of any age a gap of the store up
                    // to its mark.
                    mark_created_directory(&table, &created);
                    let marked_at = crate::store_writers::now_ms();
                    crate::store_writers::note_tree_moved_in(&path, marked_at);
                    if crate::store_writers::is_store_directory(&path) {
                        walk_store_directory(&created, None, marked_at);
                    }
                } else if record.is_dir {
                    crate::store_writers::note_tree_changed(&path, read_at_ms);
                    forget_directory(&created);
                } else if crate::store_writers::classify(&path).is_some() {
                    let ops = store_ops_for_mask(record.mask);
                    if ops != 0 {
                        let (_, process_path) = resolve_writer(pid);
                        store_record(ops, &path, pid, &process_path, None, None);
                    }
                    if record.mask & (libc::FAN_DELETE | libc::FAN_MOVED_FROM) != 0 {
                        table
                            .inode_marks
                            .retain(|_, store_path| store_path != &*path);
                    }
                    if record.mask & libc::FAN_MOVED_TO != 0 {
                        mark_store_file(&table, &path);
                    }
                }
                continue;
            }
            let (process_name, process_path) = resolve_writer(pid);
            // The store-writer record: a file's creation, with the process
            // that made it.
            if !record.is_dir {
                let path = created.to_string_lossy();
                if crate::store_writers::classify(&path).is_some() {
                    store_record(
                        store_ops_for_mask(record.mask),
                        &path,
                        pid,
                        &process_path,
                        None,
                        None,
                    );
                    mark_store_file(&table, &path);
                }
            }
            table
                .created_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if record.is_dir {
                // Mark it (and what is already in it) before anything else,
                // then remember who made it for the files that beat the mark.
                mark_created_directory(&table, &created);
                if crate::store_writers::is_store_directory(&created.to_string_lossy()) {
                    new_store_directory(&created, read_at_ms);
                }
                if !(process_name.is_empty() && process_path.is_empty()) {
                    if table.creators.len() >= TABLE_MAX_ENTRIES {
                        let cutoff = Instant::now();
                        table
                            .creators
                            .retain(|_, v| cutoff.duration_since(v.seen) <= CREATOR_TTL);
                    }
                    table.creators.insert(
                        normalize(&created.to_string_lossy()),
                        DirectoryCreator {
                            pid,
                            process_name,
                            process_path,
                            seen: Instant::now(),
                        },
                    );
                }
            } else if !(process_name.is_empty() && process_path.is_empty()) {
                // A file's creation names its first writer exactly.
                if table.entries.len() >= TABLE_MAX_ENTRIES {
                    let cutoff = Instant::now();
                    table
                        .entries
                        .retain(|_, v| cutoff.duration_since(v.seen) <= ATTRIBUTION_TTL);
                }
                table.entries.insert(
                    normalize(&created.to_string_lossy()),
                    WriterAttribution {
                        pid,
                        process_name,
                        process_path,
                        seen: Instant::now(),
                    },
                );
            }
        }
        if configured {
            note_if_drained(dir_fan.as_fd(), &table.creation_delivered_ms, read_started);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hand-built `FAN_REPORT_DFID_NAME` event: metadata, then one
    /// DFID_NAME record (header, fsid, file_handle, name). The parser reads
    /// what the kernel writes, so the layout is built by hand here, not from
    /// the struct definitions it is checked against.
    fn creation_event(pid: i32, is_dir: bool, handle: &[u8], name: &str) -> Vec<u8> {
        directory_entry_event(libc::FAN_CREATE, pid, is_dir, handle, name)
    }

    fn directory_entry_event(
        kind: u64,
        pid: i32,
        is_dir: bool,
        handle: &[u8],
        name: &str,
    ) -> Vec<u8> {
        let meta_size = std::mem::size_of::<libc::fanotify_event_metadata>();
        let header_size = std::mem::size_of::<libc::fanotify_event_info_header>();
        let fsid_size = std::mem::size_of::<libc::__kernel_fsid_t>();
        let record_len = header_size + fsid_size + 8 + handle.len() + name.len() + 1;
        // Records are padded to 8 bytes by the kernel.
        let record_len_padded = (record_len + 7) & !7;
        let mut meta: libc::fanotify_event_metadata = unsafe { std::mem::zeroed() };
        meta.event_len = (meta_size + record_len_padded) as u32;
        meta.vers = libc::FANOTIFY_METADATA_VERSION;
        meta.metadata_len = meta_size as u16;
        meta.mask = kind | if is_dir { libc::FAN_ONDIR } else { 0 };
        meta.fd = libc::FAN_NOFD;
        meta.pid = pid;
        let mut out = Vec::with_capacity(meta.event_len as usize);
        out.extend_from_slice(unsafe {
            std::slice::from_raw_parts(
                (&meta as *const libc::fanotify_event_metadata).cast::<u8>(),
                meta_size,
            )
        });
        out.push(libc::FAN_EVENT_INFO_TYPE_DFID_NAME);
        out.push(0);
        out.extend_from_slice(&(record_len_padded as u16).to_ne_bytes());
        out.extend(std::iter::repeat(0u8).take(fsid_size));
        out.extend_from_slice(&(handle.len() as u32).to_ne_bytes());
        out.extend_from_slice(&1i32.to_ne_bytes());
        out.extend_from_slice(handle);
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        while out.len() < meta.event_len as usize {
            out.push(0);
        }
        out
    }

    /// An entry of the store-file marks is used only while its path names
    /// the inode it was made for: a file removed, renamed, or replaced under
    /// the same path is another inode, and its entry no longer stands.
    #[test]
    fn an_inode_entry_stands_only_while_its_path_names_that_inode() {
        let dir = std::env::temp_dir().join(format!("fan-inode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("k.jsonl");
        std::fs::write(&path, b"{}\n").unwrap();
        let key = inode_key(&std::fs::metadata(&path).unwrap());
        let text = path.to_string_lossy().to_string();
        assert!(still_names(&text, &key));
        // Replaced under the same path: the old inode is kept alive by a
        // second name, so the new file cannot take its number.
        let kept = dir.join("kept");
        std::fs::hard_link(&path, &kept).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"{}\n").unwrap();
        assert!(!still_names(&text, &key));
        std::fs::remove_file(&path).unwrap();
        assert!(!still_names(&text, &key));
        // A directory is never a store file's inode.
        assert!(!still_names(
            &dir.to_string_lossy(),
            &inode_key(&std::fs::metadata(&dir).unwrap())
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn creation_records_are_parsed_from_the_kernel_layout() {
        let mut buf = creation_event(4242, true, &[1, 2, 3, 4, 5, 6, 7, 8], "nssdb");
        buf.extend(creation_event(4243, false, &[9, 9], "key4.db"));
        let records = parse_creation_records(&buf);
        assert_eq!(
            records,
            vec![
                CreationRecord {
                    pid: 4242,
                    is_dir: true,
                    mask: libc::FAN_CREATE | libc::FAN_ONDIR,
                    handle_type: 1,
                    handle: vec![1, 2, 3, 4, 5, 6, 7, 8],
                    name: "nssdb".to_string(),
                },
                CreationRecord {
                    pid: 4243,
                    is_dir: false,
                    mask: libc::FAN_CREATE,
                    handle_type: 1,
                    handle: vec![9, 9],
                    name: "key4.db".to_string(),
                },
            ]
        );
        // A truncated buffer ends the parse without a panic.
        assert!(parse_creation_records(&buf[..buf.len() - 40]).len() <= 1);
        assert!(parse_creation_records(&[]).is_empty());
    }

    /// A removal and both ends of a move are parsed like a creation and
    /// carry their mask; each maps to its store-writer operation.
    #[test]
    fn removals_and_moves_are_parsed_with_their_mask() {
        use crate::store_writers::ops;
        let mut buf = directory_entry_event(libc::FAN_DELETE, 10, false, &[1, 2], "s.jsonl");
        buf.extend(directory_entry_event(
            libc::FAN_MOVED_FROM,
            11,
            false,
            &[1, 2],
            "s.jsonl.tmp",
        ));
        buf.extend(directory_entry_event(
            libc::FAN_MOVED_TO,
            11,
            false,
            &[1, 2],
            "s.jsonl",
        ));
        let records = parse_creation_records(&buf);
        let seen: Vec<(i32, u32, &str)> = records
            .iter()
            .map(|record| {
                (
                    record.pid,
                    store_ops_for_mask(record.mask),
                    record.name.as_str(),
                )
            })
            .collect();
        assert_eq!(
            seen,
            vec![
                (10, ops::REMOVE, "s.jsonl"),
                (11, ops::RENAME_FROM, "s.jsonl.tmp"),
                (11, ops::RENAME_TO, "s.jsonl"),
            ]
        );
        assert_eq!(store_ops_for_mask(libc::FAN_CREATE), ops::CREATE);
        assert_eq!(
            store_ops_for_mask(libc::FAN_CREATE | libc::FAN_DELETE),
            ops::CREATE | ops::REMOVE
        );
        assert_eq!(store_ops_for_mask(libc::FAN_ONDIR), 0);
        assert!(!events_report_overflow(&buf));
    }

    /// Removals and moves are asked for on store directories only.
    #[test]
    fn removals_and_moves_are_asked_for_on_store_directories_only() {
        let store = creation_group_mask(true).bits();
        let ordinary = creation_group_mask(false).bits();
        for bit in [libc::FAN_DELETE, libc::FAN_MOVED_FROM, libc::FAN_MOVED_TO] {
            assert_ne!(store & bit, 0);
            assert_eq!(ordinary & bit, 0);
        }
        assert_ne!(ordinary & libc::FAN_CREATE, 0);
        assert_ne!(store & libc::FAN_CREATE, 0);
    }

    /// A queue overflow is an event without a record of its own: its mask
    /// carries `FAN_Q_OVERFLOW`, wherever it sits among the events read.
    #[test]
    fn a_queue_overflow_is_found_among_the_events() {
        let meta_size = std::mem::size_of::<libc::fanotify_event_metadata>();
        let mut overflow: libc::fanotify_event_metadata = unsafe { std::mem::zeroed() };
        overflow.event_len = meta_size as u32;
        overflow.vers = libc::FANOTIFY_METADATA_VERSION;
        overflow.metadata_len = meta_size as u16;
        overflow.mask = libc::FAN_Q_OVERFLOW;
        overflow.fd = libc::FAN_NOFD;
        overflow.pid = 0;
        let overflow_bytes = unsafe {
            std::slice::from_raw_parts(
                (&overflow as *const libc::fanotify_event_metadata).cast::<u8>(),
                meta_size,
            )
        }
        .to_vec();
        let mut buf = creation_event(4242, false, &[1, 2], "a.jsonl");
        buf.extend(overflow_bytes.clone());
        buf.extend(creation_event(4243, false, &[1, 2], "b.jsonl"));
        assert!(events_report_overflow(&buf));
        // The records around it are still parsed.
        assert_eq!(parse_creation_records(&buf).len(), 2);
        assert!(events_report_overflow(&overflow_bytes));
        assert!(!events_report_overflow(&creation_event(
            1,
            false,
            &[1],
            "x"
        )));
        assert!(!events_report_overflow(&[]));
    }

    /// A writer gone before the reader thread woke up is named from the exec
    /// the process-event ring kept for its pid. No fanotify needed.
    #[test]
    #[serial_test::serial]
    fn exited_writer_is_resolved_from_the_exec_ring() {
        use crate::process_events::{now_ms, push, ProcessEvent, ProcessEventKind};
        // Above the kernel's pid_max: no /proc entry, as for an exited writer.
        let pid = 4_000_000_123;
        let exec = ProcessEvent {
            timestamp_ms: now_ms(),
            kind: ProcessEventKind::Exec,
            pid,
            ppid: Some(1),
            uid: Some(0),
            process_name: "sh".to_string(),
            process_path: "/usr/bin/sh".to_string(),
            parent_process_path: None,
            argv_sha256: None,
            argv_len: None,
            signing_id: None,
            team_id: None,
            is_platform_binary: None,
            platform_path_marked: false,
            target_pid: None,
            target_process_path: None,
            task_access_mode: None,
            task_access_mask: None,
            net_dst: None,
            process_start_ms: None,
            creator_verified: None,
        };
        // The push and the lookup take a try-lock that can lose to a
        // concurrent reader: retry.
        let mut resolved = (String::new(), String::new());
        for _ in 0..100 {
            push(exec.clone());
            resolved = resolve_writer(pid);
            if !resolved.0.is_empty() {
                break;
            }
        }
        assert_eq!(resolved, ("sh".to_string(), "/usr/bin/sh".to_string()));
        assert_eq!(resolve_writer(pid + 1), (String::new(), String::new()));
    }

    #[test]
    fn roots_to_mark_skips_the_roots_the_table_already_covers() {
        let marked: CustomDashMap<String, ()> = CustomDashMap::new("test_marked");
        marked.insert("/tmp/first".to_string(), ());
        let roots = vec![
            PathBuf::from("/tmp/first"),
            PathBuf::from("/tmp/second"),
            PathBuf::from("/tmp/first"),
        ];
        let new: Vec<String> = roots_to_mark(&marked, &roots)
            .into_iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        assert_eq!(new, vec!["/tmp/second".to_string()]);
        assert!(roots_to_mark(&marked, &[PathBuf::from("/tmp/first")]).is_empty());
        assert!(roots_to_mark(&marked, &[]).is_empty());
    }

    #[test]
    fn depth_is_measured_from_the_nearest_root() {
        let roots = vec![
            "/home/runner".to_string(),
            "/home/runner/.cursor/rules".to_string(),
            "/tmp".to_string(),
        ];
        assert_eq!(depth_below_roots("/home/runner", &roots), Some(0));
        assert_eq!(depth_below_roots("/home/runner/.aws", &roots), Some(1));
        assert_eq!(
            depth_below_roots("/home/runner/.cursor/rules/sub", &roots),
            Some(1)
        );
        assert_eq!(
            depth_below_roots("/home/runner/demo/.claude", &roots),
            Some(2)
        );
        assert_eq!(
            depth_below_roots("/home/runner/work/app/target/debug/build", &roots),
            Some(5)
        );
        assert_eq!(depth_below_roots("/tmp/x/", &roots), Some(1));
        // A name sharing the root's prefix is not under it.
        assert_eq!(depth_below_roots("/home/runnerx/a", &roots), None);
        assert_eq!(depth_below_roots("/var/log", &roots), None);
        assert_eq!(depth_below_roots("/etc", &["/".to_string()]), Some(1));
    }

    #[test]
    fn the_reserve_goes_to_shallow_new_directories_only() {
        // Within the walk's share, any new directory.
        assert!(may_mark_new_directory(0, None));
        assert!(may_mark_new_directory(walk_budget() - 1, Some(7)));
        // Beyond it, a root or a shallow directory below one, up to the cap.
        assert!(may_mark_new_directory(walk_budget(), Some(0)));
        assert!(may_mark_new_directory(walk_budget(), Some(1)));
        assert!(may_mark_new_directory(
            MAX_DIRECTORY_MARKS - 1,
            Some(RESERVE_MAX_DEPTH)
        ));
        assert!(!may_mark_new_directory(
            walk_budget(),
            Some(RESERVE_MAX_DEPTH + 1)
        ));
        assert!(!may_mark_new_directory(walk_budget(), None));
        assert!(!may_mark_new_directory(MAX_DIRECTORY_MARKS, Some(0)));
    }

    /// Wait for a kernel-attributed writer of `file` (100 ms polls, 5 s).
    fn attributed_writer(file: &Path) -> Option<(u32, String, String)> {
        for _ in 0..50 {
            if let Some(att) = get_file_attribution(&file.to_string_lossy()) {
                return Some(att);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        None
    }

    /// Root only. The table is process-wide: the test spends the walk budget
    /// on purpose and gives it back when it ends (its tree removed, the marks
    /// forgotten), so the kernel tests that follow in the same serial run
    /// (`make` runs `--ignored fanotify --test-threads=1`) can still mark
    /// their roots. A root whose walk fills the budget, then a directory
    /// created under it afterwards: its writes are still attributed (the
    /// reserve), a deep new directory does not take the reserve, and a
    /// directory deleted and created again is marked again.
    #[test]
    #[ignore]
    fn a_directory_created_after_the_walk_budget_is_still_attributed() {
        // Give the budget back however the test ends.
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
                forget_directory(&self.0);
            }
        }
        let base =
            std::env::temp_dir().join(format!("flodbadd-fanotify-budget-{}", std::process::id()));
        let _cleanup = Cleanup(base.clone());
        let bulk = base.join("bulk");
        for i in 0..(walk_budget() + 16) {
            std::fs::create_dir_all(bulk.join(format!("d{i:05}"))).unwrap();
        }
        init(std::slice::from_ref(&base));
        assert!(is_active(), "fanotify init failed (are we root?)");
        let table = TABLE.get().unwrap();
        assert_eq!(
            table.marked.len(),
            walk_budget(),
            "the walk stops at its share"
        );

        // A directory created afterwards, one level below the root. Plain
        // names: a credential-shaped fixture (`.aws/credentials`) written
        // under /tmp is what the CI runner's own posture gate grades as
        // staging (flodbadd CI, 2026-10-06).
        let late = base.join("late");
        std::fs::create_dir_all(&late).unwrap();
        remark_directory(&late);
        let creds = late.join("written.txt");
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("echo key > {}; sleep 2", creds.display()))
            .spawn()
            .unwrap();
        let child_pid = child.id();
        let found = attributed_writer(&creds);
        let _ = child.wait();
        let (pid, name, path) =
            found.expect("write in a directory created after the walk attributed");
        assert_eq!(pid, child_pid, "attributed to {name} {path}");

        // A deep new directory (a build tree) does not take the reserve.
        let deep = bulk.join("d00000").join("target").join("debug");
        std::fs::create_dir_all(&deep).unwrap();
        remark_directory(&deep);
        assert!(!table
            .marked
            .contains_key(&deep.to_string_lossy().to_string()));

        // Deleted and created again: marked again.
        std::fs::remove_dir_all(&late).unwrap();
        forget_directory(&late);
        assert!(!table
            .marked
            .contains_key(&late.to_string_lossy().to_string()));
        std::fs::create_dir_all(&late).unwrap();
        remark_directory(&late);
        assert!(table
            .marked
            .contains_key(&late.to_string_lossy().to_string()));
    }

    /// Root only (`make` runs `--ignored fanotify --test-threads=1`). The
    /// creation group: a process makes a directory under a marked root and
    /// writes a file into it at once. The file's own creation names the
    /// process exactly where the directory's mark landed first; where the
    /// write beat the mark, the directory's creator is the inferred writer.
    /// Either way the write is attributed to the child, and a file directly
    /// under the root (no created directory above it) gets no inferred
    /// creator.
    #[test]
    #[ignore]
    fn a_file_written_into_a_directory_just_created_is_attributed_to_its_creator() {
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
                forget_directory(&self.0);
            }
        }
        let base =
            std::env::temp_dir().join(format!("flodbadd-fanotify-creator-{}", std::process::id()));
        let _cleanup = Cleanup(base.clone());
        std::fs::create_dir_all(&base).unwrap();
        init(std::slice::from_ref(&base));
        assert!(is_active(), "fanotify init failed (are we root?)");
        if !creation_group_active() {
            eprintln!("creation group unavailable on this kernel; the test cannot run here");
            return;
        }
        if creation_marks_total() == 0 {
            // Every FID mark refused: a filesystem without file handles (a
            // container's overlayfs). Production fails open the same way.
            let (failures, errno) = creation_mark_failures();
            eprintln!(
                "the creation group could not mark {} ({failures} mark(s) refused, last errno {errno}: a filesystem without file handles); the test cannot run here",
                base.display()
            );
            return;
        }
        let store = base.join("pki").join("nssdb");
        let key_db = store.join("key4.db");
        // One process makes the directories and writes the file, as NSS
        // does (a shell's `mkdir` is a child of its own: the inference names
        // the directory's creator, which would be that child). It stays
        // alive until the attribution is read: a creator is resolved from
        // /proc while it lives, and the creation thread can lag by seconds
        // in the serial run right after a build (one VM run in three).
        // Alpine's container legs ship no python3: nothing to measure with.
        let python_runs = std::process::Command::new("python3")
            .args(["-c", "pass"])
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if !python_runs {
            eprintln!(
                "python3 is not installed here (Alpine's container legs); the test cannot run here"
            );
            return;
        }
        let mut child = std::process::Command::new("python3")
            .arg("-c")
            .arg(format!(
                "import os, time; os.makedirs({store:?}); open({key_db:?}, 'w').write('key'); time.sleep(20)",
                store = store.to_string_lossy(),
                key_db = key_db.to_string_lossy()
            ))
            .spawn()
            .unwrap();
        let child_pid = child.id();
        let mut found = None;
        for _ in 0..80 {
            let key = key_db.to_string_lossy().to_string();
            if let Some(att) = get_file_attribution(&key) {
                found = Some((att, false));
                break;
            }
            if let Some(att) = get_inferred_creator_attribution(&key) {
                found = Some((att, true));
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
        if found.is_none() && created_total() == 0 {
            let (unresolved, errno) = creation_unresolved_total();
            if unresolved > 0 {
                // The kernel reported the creations; this process could not
                // open their parent handles (open_by_handle_at needs
                // CAP_DAC_READ_SEARCH, which a Docker container lacks: the
                // flodbadd CI's container legs). Production fails open the
                // same way, with the one-time log.
                eprintln!(
                    "{unresolved} creation record(s) could not be resolved (open_by_handle_at errno {errno}: no CAP_DAC_READ_SEARCH, a container); the test cannot run here"
                );
                return;
            }
        }
        let table = TABLE.get().unwrap();
        let ((pid, name, path), inferred) = found.unwrap_or_else(|| {
            panic!(
                "the write into the new directory is attributed (created {}, creation marks {}, refused {:?}, unresolved {:?}, creators {}, marked {}, entries {})",
                created_total(),
                creation_marks_total(),
                creation_mark_failures(),
                creation_unresolved_total(),
                table.creators.len(),
                table.marked.len(),
                table.entries.len()
            )
        });
        assert_eq!(
            pid, child_pid,
            "attributed to {name} {path} (inferred: {inferred})"
        );
        assert!(created_total() > 0, "the creation group saw the creations");
        // Nothing above a file directly under the root was created: no
        // creator to infer from.
        assert!(
            get_inferred_creator_attribution(&base.join("plain.txt").to_string_lossy()).is_none()
        );
    }

    /// Same privilege as the end-to-end test below. A second `init` -- the
    /// FIM watcher restarted with other paths -- must mark the new root: a
    /// write under it is attributed although the first init never saw it.
    #[test]
    #[ignore]
    fn fanotify_restart_extends_the_marks_to_a_new_root() {
        let base =
            std::env::temp_dir().join(format!("flodbadd-fanotify-restart-{}", std::process::id()));
        let first = base.join("first");
        let second = base.join("second");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        init(std::slice::from_ref(&first));
        assert!(is_active(), "fanotify init failed (are we root?)");
        init(std::slice::from_ref(&second));
        let file = second.join("persist.txt");
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("echo hello > {}; sleep 2", file.display()))
            .spawn()
            .unwrap();
        let child_pid = child.id();
        let mut found = None;
        for _ in 0..50 {
            if let Some(att) = get_file_attribution(&file.to_string_lossy()) {
                found = Some(att);
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&base);
        let (pid, name, path) = found.expect("write under the root added on restart attributed");
        // The writer is the shell spawned above. Its name is no portable
        // check: `sh` is BusyBox on Alpine, and a shell can exec its last
        // command in place.
        assert_eq!(pid, child_pid, "attributed to {name} {path}");
    }

    /// End-to-end on a real kernel; needs CAP_SYS_ADMIN, so it is ignored by
    /// default and run explicitly as root (`cargo test --features fim,ebpf
    /// -- --ignored fanotify`), e.g. on the core-ebpf-test VM.
    #[test]
    #[ignore]
    fn fanotify_attributes_a_write_to_the_writer_at_kernel_time() {
        let dir = std::env::temp_dir().join(format!("flodbadd-fanotify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        init(std::slice::from_ref(&dir));
        assert!(is_active(), "fanotify init failed (are we root?)");
        let file = dir.join("secret.txt");
        // Write from a child so the writer is not this process (which is
        // excluded), then let the reader thread catch up.
        // The writer stays alive for a moment after the write so procfs can
        // resolve it (an exited writer is resolved from the eBPF exec ring,
        // which a unit test cannot start).
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("echo hello > {}; sleep 2", file.display()))
            .spawn()
            .unwrap();
        let child_pid = child.id();
        let mut found = None;
        for _ in 0..50 {
            if let Some(att) = get_file_attribution(&file.to_string_lossy()) {
                found = Some(att);
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.wait();
        let (pid, name, path) = found.expect("writer attributed");
        // The shell spawned above, whatever its image is called (BusyBox on
        // Alpine).
        assert_eq!(pid, child_pid, "attributed to {name} {path}");
        assert!(events_total() >= 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Root only (`make` runs `--ignored fanotify --test-threads=1`). The
    /// store-writer record as the two groups feed it: a child creates a store
    /// file and appends to it, a second process appends, then the file is
    /// removed. The creator, both writers, the size and the removal are in
    /// the record. Skips where the creation group cannot run (as the test
    /// above), since a creation and a removal come from it.
    #[test]
    #[ignore]
    #[serial_test::serial(store_writers)]
    fn fanotify_feeds_the_store_writer_record() {
        use crate::store_writers::{self, ops, StoreFileKind, StoreSpec};
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                store_writers::clear();
                let _ = std::fs::remove_dir_all(&self.0);
                forget_directory(&self.0);
            }
        }
        let base =
            std::env::temp_dir().join(format!("flodbadd-fanotify-stores-{}", std::process::id()));
        let _cleanup = Cleanup(base.clone());
        let project = base.join("projects").join("p");
        std::fs::create_dir_all(&project).unwrap();
        store_writers::configure(&[StoreSpec {
            agent: "claude_code".to_string(),
            roots: vec![base.join("projects")],
            path_segment: String::new(),
            excluded_segments: Vec::new(),
            file_suffixes: vec![".jsonl".to_string()],
            pid_file_roots: Vec::new(),
            pid_file_suffixes: Vec::new(),
            creation_reorder_ms: 1_000,
        }]);
        init(std::slice::from_ref(&base));
        assert!(is_active(), "fanotify init failed (are we root?)");
        if !creation_group_active() || creation_marks_total() == 0 {
            eprintln!("the creation group cannot run here; the test cannot run here");
            return;
        }
        let file = project.join("s.jsonl");
        let rows_of = |path: &Path| {
            store_writers::rows_since("", 0, None)
                .expect("the record is free")
                .files
                .into_iter()
                .find(|rows| rows.path == path.to_string_lossy())
        };
        // The creator: creates, appends a line, stays alive to be resolved.
        let mut creator = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("echo first >> {}; sleep 3", file.display()))
            .spawn()
            .unwrap();
        let creator_pid = creator.id();
        let mut created = None;
        for _ in 0..50 {
            created = rows_of(&file).filter(|rows| {
                rows.rows
                    .iter()
                    .any(|row| row.writer.pid == creator_pid && row.ops & ops::WRITE != 0)
            });
            if created.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if created.is_none() && created_total() == 0 {
            let (unresolved, errno) = creation_unresolved_total();
            if unresolved > 0 {
                eprintln!(
                    "{unresolved} creation record(s) could not be resolved (errno {errno}); the test cannot run here"
                );
                let _ = creator.kill();
                let _ = creator.wait();
                return;
            }
        }
        let created = created.expect("the creator's write is recorded");
        assert_eq!(created.agent, "claude_code");
        assert_eq!(created.kind, StoreFileKind::Transcript);
        assert_eq!(
            created.creation.map(|creation| creation.writer.pid),
            Some(creator_pid),
            "the creation names the creator"
        );
        let row = created
            .rows
            .iter()
            .find(|row| row.writer.pid == creator_pid)
            .unwrap();
        assert!(row.ops & ops::CREATE != 0);
        assert!(
            row.writer.started_at_ms.is_some(),
            "the start is read while it lives"
        );

        // A second process appends: a second row, and the size at its close.
        let mut second = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("echo second >> {}; sleep 3", file.display()))
            .spawn()
            .unwrap();
        let second_pid = second.id();
        let mut both = None;
        for _ in 0..50 {
            both = rows_of(&file)
                .filter(|rows| rows.rows.iter().any(|row| row.writer.pid == second_pid));
            if both.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let both = both.expect("the second writer is recorded");
        assert_eq!(both.rows.len(), 2);
        assert_eq!(both.creation.map(|c| c.writer.pid), Some(creator_pid));
        let take = store_writers::take_dirty().expect("the record is free");
        let dirty = take
            .files
            .iter()
            .find(|dirty| dirty.path == file.to_string_lossy())
            .expect("the file is marked for its reader");
        assert_eq!(
            dirty.size_at_close,
            Some("first\nsecond\n".len() as u64),
            "the size after both appends"
        );
        assert!(dirty.spans.iter().any(|span| span.writer.pid == second_pid));

        // Removed by a third process.
        let mut remover = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("rm {}; sleep 3", file.display()))
            .spawn()
            .unwrap();
        let mut removed = None;
        for _ in 0..50 {
            removed = rows_of(&file).filter(|rows| rows.unlinked);
            if removed.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        for child in [&mut creator, &mut second, &mut remover] {
            let _ = child.kill();
            let _ = child.wait();
        }
        let removed = removed.expect("the removal is recorded");
        assert!(removed
            .rows
            .iter()
            .any(|row| row.ops & ops::REMOVE != 0 && row.writer.pid != creator_pid));

        // A file written into a directory made the same instant: whatever
        // the record holds of it, a creation in it names the process that
        // created the file.
        let fresh = base.join("projects").join("fresh");
        let fresh_file = fresh.join("t.jsonl");
        let mut maker = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "mkdir {} && echo line >> {}; sleep 3",
                fresh.display(),
                fresh_file.display()
            ))
            .spawn()
            .unwrap();
        let maker_pid = maker.id();
        std::thread::sleep(Duration::from_secs(2));
        let recorded = rows_of(&fresh_file);
        let _ = maker.kill();
        let _ = maker.wait();
        if let Some(rows) = recorded {
            if let Some(creation) = rows.creation {
                assert_eq!(creation.writer.pid, maker_pid);
            }
            assert!(rows.rows.iter().all(|row| row.writer.pid == maker_pid));
        }
        assert_eq!(queue_overflows(), 0);
    }
}
