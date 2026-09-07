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
//! start is attributed only once `remark_directory` is called for it; the
//! notify watcher does that from its create events.

use dashmap::DashMap;
use nix::sys::fanotify::{EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags};
use once_cell::sync::OnceCell;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Upper bound on directory marks (the kernel default `max_user_marks` is
/// 8192 per user; leave room for other consumers).
const MAX_DIRECTORY_MARKS: usize = 4096;
/// How long a path -> writer entry stays valid. FIM events are translated
/// within milliseconds of the write; a minute covers hash-worker latency.
const ATTRIBUTION_TTL: Duration = Duration::from_secs(60);
const TABLE_MAX_ENTRIES: usize = 50_000;

#[derive(Debug, Clone)]
struct WriterAttribution {
    pid: u32,
    process_name: String,
    process_path: String,
    seen: Instant,
}

struct FanotifyTable {
    entries: DashMap<String, WriterAttribution>,
    fan: Fanotify,
    marked: DashMap<String, ()>,
    events_total: std::sync::atomic::AtomicU64,
}

static TABLE: OnceCell<Arc<FanotifyTable>> = OnceCell::new();

/// Start the fanotify writer-attribution table for the given FIM roots.
/// Idempotent; logs and returns on any failure (fail-open).
pub fn init(roots: &[PathBuf]) {
    if TABLE.get().is_some() {
        return;
    }
    let fan = match Fanotify::init(
        InitFlags::FAN_CLASS_NOTIF | InitFlags::FAN_CLOEXEC,
        EventFFlags::O_RDONLY | EventFFlags::O_CLOEXEC | EventFFlags::O_LARGEFILE,
    ) {
        Ok(fan) => fan,
        Err(e) => {
            info!(
                "FIM fanotify writer attribution unavailable: {} (falling back to lsof)",
                e
            );
            return;
        }
    };
    let table = Arc::new(FanotifyTable {
        entries: DashMap::new(),
        fan,
        marked: DashMap::new(),
        events_total: std::sync::atomic::AtomicU64::new(0),
    });
    let mut marked = 0usize;
    for root in roots {
        marked += mark_tree(&table, root, MAX_DIRECTORY_MARKS.saturating_sub(marked));
        if marked >= MAX_DIRECTORY_MARKS {
            warn!(
                "FIM fanotify: directory mark cap ({}) reached; deeper directories are attributed by lsof only",
                MAX_DIRECTORY_MARKS
            );
            break;
        }
    }
    if marked == 0 {
        info!("FIM fanotify: no directory could be marked (falling back to lsof)");
        return;
    }
    if TABLE.set(Arc::clone(&table)).is_err() {
        return;
    }
    let reader = Arc::clone(&table);
    if let Err(e) = std::thread::Builder::new()
        .name("fim-fanotify".into())
        .spawn(move || reader_loop(reader))
    {
        warn!("FIM fanotify reader thread spawn failed: {}", e);
        return;
    }
    info!(
        "FIM fanotify writer attribution active: {} directories marked under {} root(s)",
        marked,
        roots.len()
    );
}

/// Mark one directory (e.g. a directory the notify watcher just saw being
/// created under a watch root). No-op before `init`, past the cap, or when
/// already marked.
pub fn remark_directory(dir: &Path) {
    if let Some(table) = TABLE.get() {
        if table.marked.len() >= MAX_DIRECTORY_MARKS {
            return;
        }
        mark_one(table, dir);
    }
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

fn normalize(path: &str) -> String {
    path.trim().to_string()
}

fn mark_one(table: &FanotifyTable, dir: &Path) -> bool {
    let key = dir.to_string_lossy().to_string();
    if table.marked.contains_key(&key) {
        return false;
    }
    let Ok(handle) = std::fs::File::open(dir) else {
        return false;
    };
    match table.fan.mark::<_, Path>(
        MarkFlags::FAN_MARK_ADD,
        MaskFlags::FAN_MODIFY | MaskFlags::FAN_CLOSE_WRITE | MaskFlags::FAN_EVENT_ON_CHILD,
        &handle,
        None,
    ) {
        Ok(()) => {
            table.marked.insert(key, ());
            true
        }
        Err(e) => {
            debug!("FIM fanotify: mark {} failed: {}", dir.display(), e);
            false
        }
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
    // Exited: the eBPF exec stream recorded the image at exec time.
    let ring = crate::process_events::recent(crate::process_events::PROCESS_EVENT_RING_MAX);
    if let Some(exec) = ring
        .iter()
        .rev()
        .find(|e| e.pid == pid && e.kind == crate::process_events::ProcessEventKind::Exec)
    {
        return (exec.process_name.clone(), exec.process_path.clone());
    }
    (String::new(), String::new())
}

fn reader_loop(table: Arc<FanotifyTable>) {
    loop {
        let events = match table.fan.read_events() {
            Ok(events) => events,
            Err(nix::errno::Errno::EINTR) | Err(nix::errno::Errno::EAGAIN) => continue,
            Err(e) => {
                warn!("FIM fanotify reader stopped: {}", e);
                return;
            }
        };
        for event in events {
            // `event` owns the fd and closes it on drop.
            let Some(fd) = event.fd() else {
                continue;
            };
            let path = match std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())) {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(pid > 0);
        assert!(name.contains("sh") || path.contains("sh"), "{name} {path}");
        assert!(events_total() >= 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
