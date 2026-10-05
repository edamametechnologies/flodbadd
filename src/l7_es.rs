// Endpoint Security process and file attribution for macOS.
//
// Uses Apple's Endpoint Security framework to maintain:
//   1. A live process table populated by kernel-delivered FORK/EXEC/EXIT events.
//   2. A file attribution table populated by NOTIFY_CREATE/CLOSE/RENAME/UNLINK
//      events, mapping recently-touched file paths to the responsible process.
//
// The process table provides high-fidelity process metadata (executable path,
// parent chain, code signing, arguments) without the race conditions inherent
// in polling sysinfo after the fact.
//
// The file attribution table is consumed by the FIM subsystem to attribute
// file events to processes at kernel-delivered time, avoiding the racy lsof
// probe that misses short-lived writes.
//
// Socket-to-PID mapping still comes from libproc (l7_macos.rs). This module
// enriches the PID with process metadata from the ES-maintained table, avoiding
// the need for a full System::refresh_specifics() call.
//
// On non-macOS platforms or when the `endpointsecurity` feature is not enabled,
// all public functions gracefully fall back to no-op stubs so the rest of the
// codebase does not need to care whether ES is available.

use crate::sessions::SessionL7;
use tracing::info;

/// Parent and grandparent of a process as the Endpoint Security handler
/// records them on its FORK and EXEC rows.
///
/// In an Endpoint Security message, `msg.process()` is the process that
/// INSTIGATED the event. For `NOTIFY_FORK` that is the forker, the child's
/// parent. For `NOTIFY_EXEC` it is the exec'ing process itself, in its
/// pre-exec image: the same pid as `exec.target()`, never its parent. The
/// exec arm recorded it as the parent until 2.0.5, so every macOS exec named
/// its own pid as ppid (and its own previous image, or the forker's image
/// copy, as the parent image), the core lineage walk stopped at the first
/// step, and agent-subtree binding never happened on macOS (`kernel_exec`
/// ancestry empty in every macOS export of FP lab run 37312097578).
///
/// Pure so it can be tested without Endpoint Security: the handler reads the
/// kernel facts from the message and hands a table lookup in.
#[cfg(any(test, all(target_os = "macos", feature = "endpointsecurity")))]
mod es_lineage {
    pub(crate) fn extract_process_name(path: &str) -> String {
        std::path::Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
    }

    /// The lineage half of a process-table row.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub(crate) struct KnownProcess {
        /// The parent the row names; 0 when it names none.
        pub ppid: u32,
        pub path: String,
        pub args: Vec<String>,
        pub parent_name: String,
        pub parent_path: String,
        pub parent_args: Vec<String>,
        pub grandparent_pid: Option<u32>,
        pub grandparent_name: String,
        pub grandparent_path: String,
        pub grandparent_args: Vec<String>,
    }

    /// The kernel's parent facts on the process performing an exec (the
    /// message's `es_process_t`).
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(crate) struct ExecKernelFacts {
        /// The exec'ing pid (`exec.target()` has the same one).
        pub pid: u32,
        /// `original_ppid`: the process that created this one. Unchanged
        /// when the process is re-parented after its creator exits.
        pub original_ppid: u32,
        /// `parent_audit_token()` pid (message version 4+): the parent now.
        pub parent_token_pid: Option<u32>,
        /// `ppid`: the parent now (launchd once re-parented).
        pub ppid: u32,
    }

    /// Parent and grandparent recorded on a row and pushed on the event.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub(crate) struct Lineage {
        /// `None` when no parent is known: never the process itself.
        pub ppid: Option<u32>,
        pub parent_name: String,
        pub parent_path: String,
        pub parent_args: Vec<String>,
        pub grandparent_pid: Option<u32>,
        pub grandparent_name: String,
        pub grandparent_path: String,
        pub grandparent_args: Vec<String>,
    }

    fn is_other_process(candidate: u32, pid: u32) -> bool {
        candidate != 0 && candidate != pid
    }

    /// The parent of an exec'ing process.
    ///
    /// The kernel's `original_ppid` is the process that created it, which is
    /// what the row the fork arm wrote for this pid records too. Where both
    /// exist and disagree, the row belongs to an earlier occupant of the pid
    /// whose exit (or this occupant's fork) was never seen, and the kernel
    /// wins. Without an `original_ppid`, the row (the forker as seen at fork
    /// time) comes before the current parent, which is launchd once the
    /// creator has exited. Nothing that names the pid itself is a parent.
    pub(crate) fn exec_parent_pid(facts: &ExecKernelFacts, row_ppid: Option<u32>) -> Option<u32> {
        let pid = facts.pid;
        if is_other_process(facts.original_ppid, pid) {
            return Some(facts.original_ppid);
        }
        row_ppid
            .into_iter()
            .chain(facts.parent_token_pid)
            .chain(std::iter::once(facts.ppid))
            .find(|candidate| is_other_process(*candidate, pid))
    }

    /// Parent and grandparent of an exec'ing process. `lookup` reads the
    /// process table (returning a copy, so no table guard is held across the
    /// caller's insert); `live_image` asks the kernel which image a pid runs
    /// now, for a parent the table never saw.
    ///
    /// The parent is named, in order, by its own row (its image now, as the
    /// Linux and Windows sensors name it), by the row the fork arm wrote for
    /// this pid when that row names the same parent (the forker's image at
    /// fork time), and by the parent's live image. The image this process ran
    /// before the exec is never used: after an exec in place it is the
    /// process's own previous image.
    pub(crate) fn exec_lineage(
        facts: &ExecKernelFacts,
        lookup: impl Fn(u32) -> Option<KnownProcess>,
        live_image: impl Fn(u32) -> Option<String>,
    ) -> Lineage {
        let pid = facts.pid;
        let own_row = lookup(pid);
        let Some(ppid) = exec_parent_pid(facts, own_row.as_ref().map(|row| row.ppid)) else {
            return Lineage::default();
        };
        let mut lineage = Lineage {
            ppid: Some(ppid),
            ..Lineage::default()
        };
        let grandparent = |candidate: Option<u32>| {
            candidate.filter(|gp| is_other_process(*gp, pid) && *gp != ppid)
        };
        if let Some(parent) = lookup(ppid) {
            lineage.parent_name = extract_process_name(&parent.path);
            lineage.parent_path = parent.path;
            lineage.parent_args = parent.args;
            lineage.grandparent_pid = grandparent(Some(parent.ppid));
            lineage.grandparent_name = parent.parent_name;
            lineage.grandparent_path = parent.parent_path;
            lineage.grandparent_args = parent.parent_args;
        } else if let Some(row) =
            own_row.filter(|row| row.ppid == ppid && !row.parent_path.is_empty())
        {
            lineage.parent_name = row.parent_name;
            lineage.parent_path = row.parent_path;
            lineage.parent_args = row.parent_args;
            lineage.grandparent_pid = grandparent(row.grandparent_pid);
            lineage.grandparent_name = row.grandparent_name;
            lineage.grandparent_path = row.grandparent_path;
            lineage.grandparent_args = row.grandparent_args;
        } else if let Some(path) = live_image(ppid).filter(|path| !path.is_empty()) {
            lineage.parent_name = extract_process_name(&path);
            lineage.parent_path = path;
        }
        lineage
    }

    /// Parent and grandparent of a forked child: the forker (the message's
    /// process, whose image the kernel reports) and the forker's own parent
    /// from its row.
    pub(crate) fn fork_lineage(
        child_pid: u32,
        forker_pid: u32,
        forker_path: &str,
        lookup: impl Fn(u32) -> Option<KnownProcess>,
    ) -> Lineage {
        if !is_other_process(forker_pid, child_pid) {
            return Lineage::default();
        }
        let mut lineage = Lineage {
            ppid: Some(forker_pid),
            parent_name: extract_process_name(forker_path),
            parent_path: forker_path.to_string(),
            ..Lineage::default()
        };
        if let Some(forker) = lookup(forker_pid) {
            lineage.parent_args = forker.args;
            lineage.grandparent_pid = Some(forker.ppid)
                .filter(|gp| is_other_process(*gp, child_pid) && *gp != forker_pid);
            lineage.grandparent_name = forker.parent_name;
            lineage.grandparent_path = forker.parent_path;
            lineage.grandparent_args = forker.parent_args;
        }
        lineage
    }
}

#[cfg(all(target_os = "macos", feature = "endpointsecurity"))]
mod macos {
    use super::es_lineage::{self, extract_process_name, ExecKernelFacts, KnownProcess};
    use super::*;
    use dashmap::DashMap;
    use endpoint_sec::version;
    use endpoint_sec::{Client, Event};
    use once_cell::sync::OnceCell;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::panic::AssertUnwindSafe;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Instant;
    use tracing::{debug, error, warn};

    use crate::process_events as proc_events;

    fn optional_identity(value: std::borrow::Cow<'_, str>) -> Option<String> {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_string())
    }

    /// BS-9 observe (FLODBADD2 §1b.2): `responsible` asked for `target`'s
    /// task port. Shared by the control-port (`GET_TASK`) and read-port
    /// (`GET_TASK_READ`) notifications: both hand out cross-process memory
    /// access, and `task_read_for_pid` is the primitive a modern reader
    /// uses, so watching only the control port misses it.
    /// `mode`: 2 for the control port (`GET_TASK`), 1 for the read-only
    /// port (`GET_TASK_READ`) -- the PTRACE_MODE vocabulary shared with the
    /// Linux kprobe (`ProcessEvent::task_access_mode`).
    fn push_task_access(
        responsible: &endpoint_sec::Process<'_>,
        responsible_pid: u32,
        target: &endpoint_sec::Process<'_>,
        mode: u32,
    ) {
        let requestor_path = responsible
            .executable()
            .path()
            .to_string_lossy()
            .to_string();
        let target_pid = target.audit_token().pid() as u32;
        let target_path = target.executable().path().to_string_lossy().to_string();
        proc_events::push(proc_events::ProcessEvent {
            timestamp_ms: proc_events::now_ms(),
            kind: proc_events::ProcessEventKind::TaskAccess,
            pid: responsible_pid,
            ppid: None,
            uid: Some(responsible.audit_token().euid()),
            process_name: extract_process_name(&requestor_path),
            process_path: requestor_path,
            parent_process_path: None,
            argv_sha256: None,
            argv_len: None,
            signing_id: optional_identity(responsible.signing_id().to_string_lossy()),
            team_id: optional_identity(responsible.team_id().to_string_lossy()),
            is_platform_binary: Some(responsible.is_platform_binary()),
            platform_path_marked: false,
            target_pid: Some(target_pid),
            target_process_path: Some(target_path),
            task_access_mode: Some(mode),
            task_access_mask: None,
            net_dst: None,
        });
    }

    const FILE_ATTR_MAX_ENTRIES: usize = 50_000;
    const FILE_ATTR_TTL_SECS: u64 = 30;
    const FILE_ATTR_PRUNE_INTERVAL: u64 = 1_000;

    #[derive(Clone, Debug)]
    pub struct FimEsAttribution {
        pub pid: u32,
        pub process_name: String,
        pub process_path: String,
        pub recorded_at: Instant,
    }

    #[derive(Clone, Debug)]
    pub struct EsProcessInfo {
        pub pid: u32,
        /// The parent pid; 0 when no parent is known (never `pid` itself).
        pub ppid: u32,
        pub uid: u32,
        pub process_name: String,
        pub process_path: String,
        pub cwd: Option<String>,
        pub args: Vec<String>,
        pub username: String,
        pub start_time: u64,
        pub code_signing_flags: u32,
        pub is_platform_binary: bool,
        /// Kernel-vouched signing identity from the exec message
        /// (FLODBADD2 §1b.2: makes publisher attestation unforgeable
        /// and free on macOS). Empty when ES did not deliver one
        /// (fork-created entries before their exec).
        pub signing_id: String,
        pub team_id: String,
        pub parent_process_name: String,
        pub parent_process_path: String,
        pub parent_args: Vec<String>,
        pub grandparent_pid: Option<u32>,
        pub grandparent_process_name: String,
        pub grandparent_process_path: String,
        pub grandparent_args: Vec<String>,
    }

    impl EsProcessInfo {
        fn known(&self) -> KnownProcess {
            KnownProcess {
                ppid: self.ppid,
                path: self.process_path.clone(),
                args: self.args.clone(),
                parent_name: self.parent_process_name.clone(),
                parent_path: self.parent_process_path.clone(),
                parent_args: self.parent_args.clone(),
                grandparent_pid: self.grandparent_pid,
                grandparent_name: self.grandparent_process_name.clone(),
                grandparent_path: self.grandparent_process_path.clone(),
                grandparent_args: self.grandparent_args.clone(),
            }
        }

        /// `None` for a row that names no parent (`ppid` 0).
        fn parent_pid(&self) -> Option<u32> {
            (self.ppid != 0 && self.ppid != self.pid).then_some(self.ppid)
        }
    }

    fn resolve_username(uid: u32) -> String {
        uzers::get_user_by_uid(uid)
            .map(|u| u.name().to_string_lossy().to_string())
            .unwrap_or_else(|| format!("uid-{}", uid))
    }

    pub struct FlodbaddL7Es {
        process_table: Arc<DashMap<u32, EsProcessInfo>>,
        file_attribution_table: Arc<DashMap<String, FimEsAttribution>>,
        #[allow(dead_code)]
        file_insert_counter: Arc<AtomicU64>,
        available: Arc<AtomicBool>,
        init_status: String,
        file_event_counters: Arc<FileEventCounters>,
    }

    pub struct FileEventCounters {
        pub create_received: AtomicU64,
        pub create_dest_some: AtomicU64,
        pub create_dest_none: AtomicU64,
        pub write_received: AtomicU64,
        pub close_received: AtomicU64,
        pub close_modified: AtomicU64,
        pub rename_received: AtomicU64,
        pub unlink_received: AtomicU64,
        pub other_event: AtomicU64,
    }

    impl Default for FileEventCounters {
        fn default() -> Self {
            Self {
                create_received: AtomicU64::new(0),
                create_dest_some: AtomicU64::new(0),
                create_dest_none: AtomicU64::new(0),
                write_received: AtomicU64::new(0),
                close_received: AtomicU64::new(0),
                close_modified: AtomicU64::new(0),
                rename_received: AtomicU64::new(0),
                unlink_received: AtomicU64::new(0),
                other_event: AtomicU64::new(0),
            }
        }
    }

    impl FlodbaddL7Es {
        fn init() -> Self {
            let os_version = Self::detect_macos_version();
            if let Some((major, minor)) = os_version {
                debug!("ES: macOS version {}.{}", major, minor);
                if major < 13 {
                    let msg = format!(
                        "Disabled: macOS {}.{} < 13.0 (Endpoint Security process events require macOS 13+)",
                        major, minor
                    );
                    warn!("ES disabled: {}", msg);
                    return Self {
                        process_table: Arc::new(DashMap::new()),
                        file_attribution_table: Arc::new(DashMap::new()),
                        file_insert_counter: Arc::new(AtomicU64::new(0)),
                        available: Arc::new(AtomicBool::new(false)),
                        init_status: msg,
                        file_event_counters: Arc::new(FileEventCounters::default()),
                    };
                }
                version::set_runtime_version(major as u64, minor as u64, 0);
            } else {
                version::set_runtime_version(13, 0, 0);
            }

            let process_table = Arc::new(DashMap::new());
            let file_attribution_table = Arc::new(DashMap::new());
            let file_insert_counter = Arc::new(AtomicU64::new(0));
            let available = Arc::new(AtomicBool::new(false));
            let file_event_counters = Arc::new(FileEventCounters::default());
            let table_for_thread = Arc::clone(&process_table);
            let file_table_for_thread = Arc::clone(&file_attribution_table);
            let file_counter_for_thread = Arc::clone(&file_insert_counter);
            let available_for_thread = Arc::clone(&available);
            let counters_for_thread = Arc::clone(&file_event_counters);

            if let Err(e) = std::thread::Builder::new()
                .name("es-client".into())
                .spawn(move || {
                    Self::run_es_client(
                        table_for_thread,
                        file_table_for_thread,
                        file_counter_for_thread,
                        available_for_thread,
                        counters_for_thread,
                    );
                })
            {
                error!("Failed to spawn ES client thread: {}", e);
            }

            // Give the ES thread a moment to start and report status
            std::thread::sleep(std::time::Duration::from_millis(200));

            let is_available = available.load(Ordering::Acquire);
            let version_str = os_version
                .map(|(maj, min)| format!("{}.{}", maj, min))
                .unwrap_or_else(|| "unknown".to_string());

            let init_status = if is_available {
                format!(
                    "Enabled: macOS {} with ES process + file + task-port tracking (FORK/EXEC/EXIT + GET_TASK/GET_TASK_READ + CREATE/WRITE/CLOSE/RENAME/UNLINK)",
                    version_str
                )
            } else {
                format!(
                    "Disabled: ES client failed to initialize on macOS {} (check entitlement and root)",
                    version_str
                )
            };

            if is_available {
                info!("ES helper initialized: {}", init_status);
            } else {
                warn!("ES helper: {}", init_status);
            }

            Self {
                process_table,
                file_attribution_table,
                file_insert_counter,
                available,
                init_status,
                file_event_counters,
            }
        }

        fn record_file_attribution(
            file_table: &DashMap<String, FimEsAttribution>,
            file_counter: &AtomicU64,
            process_table: &DashMap<u32, EsProcessInfo>,
            path: String,
            responsible_pid: u32,
            responsible_exe_path: &str,
        ) {
            // The only reader of this table is `fim::kernel_table_attribution`,
            // and it is only ever asked about paths under a FIM watch root.
            // Recording anything else fills the table with entries that expire
            // unread. The hot WRITE / CLOSE arms answer this before they
            // allocate; this guard covers CREATE, RENAME and UNLINK too, so
            // the table is confined wherever the entry came from.
            if !crate::fim_attribution::is_attributable(&path) {
                return;
            }
            let (process_name, process_path) =
                if let Some(info) = process_table.get(&responsible_pid) {
                    (info.process_name.clone(), info.process_path.clone())
                } else {
                    (
                        extract_process_name(responsible_exe_path),
                        responsible_exe_path.to_string(),
                    )
                };

            file_table.insert(
                path,
                FimEsAttribution {
                    pid: responsible_pid,
                    process_name,
                    process_path,
                    recorded_at: Instant::now(),
                },
            );

            let count = file_counter.fetch_add(1, Ordering::Relaxed);
            if count % FILE_ATTR_PRUNE_INTERVAL == 0 && count > 0 {
                Self::prune_file_attribution_table(file_table);
            }
        }

        fn prune_file_attribution_table(table: &DashMap<String, FimEsAttribution>) {
            // `Instant::now() - TTL` panics within TTL seconds of boot
            // (monotonic-from-boot clock underflow); keep all entries when
            // uptime < TTL since nothing can be older than the window.
            if let Some(cutoff) =
                Instant::now().checked_sub(std::time::Duration::from_secs(FILE_ATTR_TTL_SECS))
            {
                table.retain(|_, v| v.recorded_at > cutoff);
            }

            if table.len() > FILE_ATTR_MAX_ENTRIES {
                let mut entries: Vec<_> = table
                    .iter()
                    .map(|e| (e.key().clone(), e.value().recorded_at))
                    .collect();
                entries.sort_by_key(|(_, ts)| *ts);
                let to_remove = entries.len() - FILE_ATTR_MAX_ENTRIES;
                for (key, _) in entries.into_iter().take(to_remove) {
                    table.remove(&key);
                }
            }
        }

        /// Hand a file event under a FIM root to the watcher (FLODBADD2
        /// §1b.2 "ES as the FIM event source"). Name / path come from the
        /// process table when the pid is known, else from the message.
        #[cfg(feature = "fim")]
        fn fim_source_push(
            kind: crate::fim_es::FimSourceKind,
            path: &str,
            pid: u32,
            exe: &str,
            table: &DashMap<u32, EsProcessInfo>,
        ) {
            if !crate::fim_es::is_active() {
                return;
            }
            let (name, process_path) = match table.get(&pid) {
                Some(info) if !info.process_path.is_empty() => {
                    (info.process_name.clone(), info.process_path.clone())
                }
                _ => (extract_process_name(exe), exe.to_string()),
            };
            crate::fim_es::push(kind, path, pid, &name, &process_path);
        }

        fn run_es_client(
            table: Arc<DashMap<u32, EsProcessInfo>>,
            file_table: Arc<DashMap<String, FimEsAttribution>>,
            file_counter: Arc<AtomicU64>,
            available: Arc<AtomicBool>,
            event_counters: Arc<FileEventCounters>,
        ) {
            let table_for_handler = AssertUnwindSafe(Arc::clone(&table));
            let file_table_for_handler = AssertUnwindSafe(Arc::clone(&file_table));
            let file_counter_for_handler = AssertUnwindSafe(Arc::clone(&file_counter));
            let counters = AssertUnwindSafe(Arc::clone(&event_counters));

            let handler = move |_client: &mut Client<'_>, msg: endpoint_sec::Message| {
                let responsible = msg.process();
                let responsible_pid = responsible.audit_token().pid() as u32;

                match msg.event() {
                    Some(Event::NotifyFork(fork)) => {
                        let child = fork.child();
                        let child_pid = child.audit_token().pid() as u32;

                        // The forker (the message's process) is the parent;
                        // its own row names the grandparent. The lookup
                        // copies the row, so no read guard is held across
                        // the insert below (DashMap same-shard deadlock, see
                        // the exec arm).
                        let forker_path = responsible
                            .executable()
                            .path()
                            .to_string_lossy()
                            .to_string();
                        let lineage = es_lineage::fork_lineage(
                            child_pid,
                            responsible_pid,
                            &forker_path,
                            |pid| table_for_handler.get(&pid).map(|row| row.known()),
                        );
                        let child_path = child.executable().path().to_string_lossy().to_string();
                        // Fork-created entries carry the (pre-exec) child
                        // image's identity; the exec arm overwrites the row
                        // with the real target identity moments later.
                        let child_signing_id =
                            child.signing_id().to_string_lossy().trim().to_string();
                        let child_team_id = child.team_id().to_string_lossy().trim().to_string();

                        let info = EsProcessInfo {
                            pid: child_pid,
                            ppid: lineage.ppid.unwrap_or(0),
                            uid: child.audit_token().euid(),
                            process_name: extract_process_name(&child_path),
                            process_path: child_path,
                            cwd: None,
                            args: Vec::new(),
                            username: String::new(),
                            start_time: 0,
                            code_signing_flags: child.codesigning_flags(),
                            is_platform_binary: child.is_platform_binary(),
                            signing_id: child_signing_id,
                            team_id: child_team_id,
                            parent_process_name: lineage.parent_name,
                            parent_process_path: lineage.parent_path,
                            parent_args: lineage.parent_args,
                            grandparent_pid: lineage.grandparent_pid,
                            grandparent_process_name: lineage.grandparent_name,
                            grandparent_process_path: lineage.grandparent_path,
                            grandparent_args: lineage.grandparent_args,
                        };
                        let child_path_for_event = info.process_path.clone();
                        let child_name_for_event = info.process_name.clone();
                        let child_parent_path = (!info.parent_process_path.is_empty())
                            .then(|| info.parent_process_path.clone());
                        let child_uid = info.uid;
                        table_for_handler.insert(child_pid, info);
                        crate::process_events::push(crate::process_events::ProcessEvent {
                            timestamp_ms: crate::process_events::now_ms(),
                            kind: crate::process_events::ProcessEventKind::Fork,
                            pid: child_pid,
                            ppid: lineage.ppid,
                            uid: Some(child_uid),
                            process_name: child_name_for_event,
                            process_path: child_path_for_event,
                            parent_process_path: child_parent_path,
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
                        });
                    }
                    Some(Event::NotifyExec(exec)) => {
                        let target = exec.target();
                        let target_pid = target.audit_token().pid() as u32;
                        let target_path = target.executable().path().to_string_lossy().to_string();

                        let args: Vec<String> = exec
                            .args()
                            .map(|a| {
                                OsStr::from_bytes(a.as_bytes())
                                    .to_string_lossy()
                                    .to_string()
                            })
                            .collect();

                        let cs_flags = target.codesigning_flags();
                        let is_platform = target.is_platform_binary();
                        let signing_id = target.signing_id().to_string_lossy().to_string();
                        let team_id = target.team_id().to_string_lossy().to_string();

                        // The parent: `msg.process()` is the exec'ing
                        // process itself (pid == target pid), so it is never
                        // the parent (see `es_lineage`). The kernel's
                        // creator / parent facts and the rows the fork arm
                        // wrote name it instead.
                        //
                        // Every table read goes through `lookup`, which
                        // copies the row and drops the DashMap read guard
                        // BEFORE the insert below. Holding a `get()` Ref
                        // across `insert()` deadlocks DashMap whenever the
                        // target PID hashes to the read row's shard (same
                        // thread takes the shard read lock, then waits on its
                        // write lock). Inside the ES handler that freezes the
                        // serial dispatch queue and silently kills the whole
                        // event stream after the first colliding exec -- the
                        // FLODBADD2 §1b.2 bring-up freeze.
                        let facts = ExecKernelFacts {
                            pid: target_pid,
                            original_ppid: u32::try_from(responsible.original_ppid()).unwrap_or(0),
                            parent_token_pid: responsible
                                .parent_audit_token()
                                .and_then(|token| u32::try_from(token.pid()).ok()),
                            ppid: u32::try_from(responsible.ppid()).unwrap_or(0),
                        };
                        let lineage = es_lineage::exec_lineage(
                            &facts,
                            |pid| table_for_handler.get(&pid).map(|row| row.known()),
                            |pid| crate::l7_macos::process_identity(pid).map(|(_, path)| path),
                        );

                        let username = resolve_username(target.audit_token().euid());

                        let info = EsProcessInfo {
                            pid: target_pid,
                            ppid: lineage.ppid.unwrap_or(0),
                            uid: target.audit_token().euid(),
                            process_name: extract_process_name(&target_path),
                            process_path: target_path,
                            cwd: None,
                            args,
                            username,
                            start_time: 0,
                            code_signing_flags: cs_flags,
                            is_platform_binary: is_platform,
                            signing_id: signing_id.trim().to_string(),
                            team_id: team_id.trim().to_string(),
                            parent_process_name: lineage.parent_name,
                            parent_process_path: lineage.parent_path,
                            parent_args: lineage.parent_args,
                            grandparent_pid: lineage.grandparent_pid,
                            grandparent_process_name: lineage.grandparent_name,
                            grandparent_process_path: lineage.grandparent_path,
                            grandparent_args: lineage.grandparent_args,
                        };
                        // FLODBADD2 §1b.2 monitoring stream: exec with
                        // argv digested (I5) and the kernel-vouched
                        // signing identity from the message itself.
                        let event_path = info.process_path.clone();
                        let event_name = info.process_name.clone();
                        let event_uid = info.uid;
                        let event_parent_path = (!info.parent_process_path.is_empty())
                            .then(|| info.parent_process_path.clone());
                        let event_argc = info.args.len() as u32;
                        let argv_sha256 = proc_events::argv_digest(&info.args);
                        table_for_handler.insert(target_pid, info);
                        proc_events::push(proc_events::ProcessEvent {
                            timestamp_ms: proc_events::now_ms(),
                            kind: proc_events::ProcessEventKind::Exec,
                            pid: target_pid,
                            ppid: lineage.ppid,
                            uid: Some(event_uid),
                            process_name: event_name,
                            process_path: event_path,
                            parent_process_path: event_parent_path,
                            argv_sha256,
                            argv_len: (event_argc > 0).then_some(event_argc),
                            signing_id: optional_identity(target.signing_id().to_string_lossy()),
                            team_id: optional_identity(target.team_id().to_string_lossy()),
                            is_platform_binary: Some(is_platform),
                            platform_path_marked: false,
                            target_pid: None,
                            target_process_path: None,
                            task_access_mode: None,
                            task_access_mask: None,
                            net_dst: None,
                        });
                    }
                    Some(Event::NotifyExit(_)) => {
                        let removed = table_for_handler.remove(&responsible_pid);
                        let (
                            exit_name,
                            exit_path,
                            exit_ppid,
                            exit_signing,
                            exit_team,
                            exit_platform,
                        ) = match removed {
                            Some((_, info)) => {
                                let ppid = info.parent_pid();
                                (
                                    info.process_name,
                                    info.process_path,
                                    ppid,
                                    (!info.signing_id.is_empty()).then_some(info.signing_id),
                                    (!info.team_id.is_empty()).then_some(info.team_id),
                                    Some(info.is_platform_binary),
                                )
                            }
                            None => {
                                // Untracked (predates the client): still
                                // record the exit with what the message
                                // itself vouches for.
                                let path = responsible
                                    .executable()
                                    .path()
                                    .to_string_lossy()
                                    .to_string();
                                (
                                    extract_process_name(&path),
                                    path,
                                    None,
                                    optional_identity(responsible.signing_id().to_string_lossy()),
                                    optional_identity(responsible.team_id().to_string_lossy()),
                                    Some(responsible.is_platform_binary()),
                                )
                            }
                        };
                        proc_events::push(proc_events::ProcessEvent {
                            timestamp_ms: proc_events::now_ms(),
                            kind: proc_events::ProcessEventKind::Exit,
                            pid: responsible_pid,
                            ppid: exit_ppid,
                            uid: Some(responsible.audit_token().euid()),
                            process_name: exit_name,
                            process_path: exit_path,
                            parent_process_path: None,
                            argv_sha256: None,
                            argv_len: None,
                            signing_id: exit_signing,
                            team_id: exit_team,
                            is_platform_binary: exit_platform,
                            platform_path_marked: false,
                            target_pid: None,
                            target_process_path: None,
                            task_access_mode: None,
                            task_access_mask: None,
                            net_dst: None,
                        });
                    }
                    Some(Event::NotifyGetTask(get_task)) => {
                        push_task_access(&responsible, responsible_pid, &get_task.target(), 2);
                    }
                    Some(Event::NotifyGetTaskRead(get_task_read)) => {
                        push_task_access(&responsible, responsible_pid, &get_task_read.target(), 1);
                    }
                    Some(Event::NotifyCreate(ev)) => {
                        counters.create_received.fetch_add(1, Ordering::Relaxed);
                        if let Some(dest) = ev.destination() {
                            counters.create_dest_some.fetch_add(1, Ordering::Relaxed);
                            use endpoint_sec::EventCreateDestinationFile;
                            let path = match dest {
                                EventCreateDestinationFile::ExistingFile(f) => {
                                    f.path().to_string_lossy().to_string()
                                }
                                EventCreateDestinationFile::NewPath {
                                    directory,
                                    filename,
                                    ..
                                } => {
                                    let dir = directory.path().to_string_lossy();
                                    let name = filename.to_string_lossy();
                                    format!("{}/{}", dir.trim_end_matches('/'), name)
                                }
                            };
                            let exe = responsible
                                .executable()
                                .path()
                                .to_string_lossy()
                                .to_string();
                            FlodbaddL7Es::record_file_attribution(
                                &file_table_for_handler,
                                &file_counter_for_handler,
                                &table_for_handler,
                                path.clone(),
                                responsible_pid,
                                &exe,
                            );
                            #[cfg(feature = "fim")]
                            FlodbaddL7Es::fim_source_push(
                                crate::fim_es::FimSourceKind::Create,
                                &path,
                                responsible_pid,
                                &exe,
                                &table_for_handler,
                            );
                        } else {
                            counters.create_dest_none.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Some(Event::NotifyWrite(ev)) => {
                        counters.write_received.fetch_add(1, Ordering::Relaxed);
                        // NOTIFY_WRITE is the highest-volume event ES emits:
                        // every write syscall by every process on the machine.
                        // Nothing downstream is ever asked about a path outside
                        // a FIM watch root, so answer that on the borrowed path
                        // before allocating anything.
                        let target = ev.target().path().to_string_lossy();
                        if !crate::fim_attribution::is_attributable(&target) {
                            return;
                        }
                        let path = target.into_owned();
                        let exe = responsible
                            .executable()
                            .path()
                            .to_string_lossy()
                            .to_string();
                        FlodbaddL7Es::record_file_attribution(
                            &file_table_for_handler,
                            &file_counter_for_handler,
                            &table_for_handler,
                            path.clone(),
                            responsible_pid,
                            &exe,
                        );
                        #[cfg(feature = "fim")]
                        FlodbaddL7Es::fim_source_push(
                            crate::fim_es::FimSourceKind::Modify,
                            &path,
                            responsible_pid,
                            &exe,
                            &table_for_handler,
                        );
                    }
                    Some(Event::NotifyClose(ev)) => {
                        counters.close_received.fetch_add(1, Ordering::Relaxed);
                        // Only a modified close is a write. Recording every
                        // close made the last *reader* the writer: the FIM
                        // hash worker's own read of a freshly dropped
                        // `~/.env*` replaced the Python writer with
                        // `edamame_posture` (security gate `file_events`,
                        // macOS, 2026-09-08). New files are covered by
                        // CREATE and their first write by WRITE.
                        if ev.modified() {
                            counters.close_modified.fetch_add(1, Ordering::Relaxed);
                            let target = ev.target().path().to_string_lossy();
                            if !crate::fim_attribution::is_attributable(&target) {
                                return;
                            }
                            let path = target.into_owned();
                            let exe = responsible
                                .executable()
                                .path()
                                .to_string_lossy()
                                .to_string();
                            FlodbaddL7Es::record_file_attribution(
                                &file_table_for_handler,
                                &file_counter_for_handler,
                                &table_for_handler,
                                path.clone(),
                                responsible_pid,
                                &exe,
                            );
                            #[cfg(feature = "fim")]
                            FlodbaddL7Es::fim_source_push(
                                crate::fim_es::FimSourceKind::Modify,
                                &path,
                                responsible_pid,
                                &exe,
                                &table_for_handler,
                            );
                        }
                    }
                    Some(Event::NotifyRename(ev)) => {
                        counters.rename_received.fetch_add(1, Ordering::Relaxed);
                        let source = ev.source().path().to_string_lossy().to_string();
                        let exe = responsible
                            .executable()
                            .path()
                            .to_string_lossy()
                            .to_string();
                        // The destination is the path FIM reports for an
                        // atomic replace (`write tmp; rename tmp -> file`);
                        // recording only the source left such writers
                        // unattributed.
                        let destination = ev.destination().map(|dest| {
                            use endpoint_sec::EventRenameDestinationFile;
                            match dest {
                                EventRenameDestinationFile::ExistingFile(f) => {
                                    f.path().to_string_lossy().to_string()
                                }
                                EventRenameDestinationFile::NewPath {
                                    directory,
                                    filename,
                                    ..
                                } => {
                                    let dir = directory.path().to_string_lossy();
                                    let name = filename.to_string_lossy();
                                    format!("{}/{}", dir.trim_end_matches('/'), name)
                                }
                            }
                        });
                        #[cfg(feature = "fim")]
                        FlodbaddL7Es::fim_source_push(
                            crate::fim_es::FimSourceKind::Delete,
                            &source,
                            responsible_pid,
                            &exe,
                            &table_for_handler,
                        );
                        #[cfg(feature = "fim")]
                        if let Some(dest) = destination.as_deref() {
                            FlodbaddL7Es::fim_source_push(
                                crate::fim_es::FimSourceKind::Rename,
                                dest,
                                responsible_pid,
                                &exe,
                                &table_for_handler,
                            );
                        }
                        for path in std::iter::once(source).chain(destination) {
                            FlodbaddL7Es::record_file_attribution(
                                &file_table_for_handler,
                                &file_counter_for_handler,
                                &table_for_handler,
                                path,
                                responsible_pid,
                                &exe,
                            );
                        }
                    }
                    Some(Event::NotifyUnlink(ev)) => {
                        counters.unlink_received.fetch_add(1, Ordering::Relaxed);
                        let path = ev.target().path().to_string_lossy().to_string();
                        let exe = responsible
                            .executable()
                            .path()
                            .to_string_lossy()
                            .to_string();
                        FlodbaddL7Es::record_file_attribution(
                            &file_table_for_handler,
                            &file_counter_for_handler,
                            &table_for_handler,
                            path.clone(),
                            responsible_pid,
                            &exe,
                        );
                        #[cfg(feature = "fim")]
                        FlodbaddL7Es::fim_source_push(
                            crate::fim_es::FimSourceKind::Delete,
                            &path,
                            responsible_pid,
                            &exe,
                            &table_for_handler,
                        );
                    }
                    _ => {
                        counters.other_event.fetch_add(1, Ordering::Relaxed);
                    }
                }
            };

            let mut client = match Client::new(handler) {
                Ok(client) => client,
                Err(e) => {
                    warn!(
                        "ES client creation failed: {:?} (need entitlement + root)",
                        e
                    );
                    return;
                }
            };

            use endpoint_sec::sys::es_event_type_t;
            let events = [
                es_event_type_t::ES_EVENT_TYPE_NOTIFY_FORK,
                es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXEC,
                es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXIT,
                // FLODBADD2 §1b.2 (BS-9 observe): task-port access is the
                // macOS primitive for reading another process's memory.
                es_event_type_t::ES_EVENT_TYPE_NOTIFY_GET_TASK,
                es_event_type_t::ES_EVENT_TYPE_NOTIFY_GET_TASK_READ,
                es_event_type_t::ES_EVENT_TYPE_NOTIFY_CREATE,
                // WRITE fires at the first write to an open file, i.e.
                // before the writer closes it. The FIM watcher (FSEvents)
                // wakes on the write, so a CLOSE-only table was empty when
                // the watcher looked -- every macOS temp-staging finding
                // carried a null writer (security gate, 2026-09-08).
                es_event_type_t::ES_EVENT_TYPE_NOTIFY_WRITE,
                es_event_type_t::ES_EVENT_TYPE_NOTIFY_CLOSE,
                es_event_type_t::ES_EVENT_TYPE_NOTIFY_RENAME,
                es_event_type_t::ES_EVENT_TYPE_NOTIFY_UNLINK,
            ];
            if let Err(e) = client.subscribe(&events) {
                error!("ES subscribe failed: {:?}", e);
                return;
            }

            available.store(true, Ordering::Release);
            info!("ES client subscribed to FORK/EXEC/EXIT + GET_TASK(_READ) + CREATE/WRITE/CLOSE/RENAME/UNLINK");

            // Park this thread -- the client must stay alive for events to be
            // delivered. The handler closure runs on Apple's ES dispatch queue,
            // not on this thread, so parking is fine.
            loop {
                std::thread::park();
            }
        }

        fn detect_macos_version() -> Option<(u32, u32)> {
            let output = std::process::Command::new("sw_vers")
                .arg("-productVersion")
                .output()
                .ok()?;
            let version_str = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = version_str.trim().split('.').collect();
            let major = parts.first()?.parse::<u32>().ok()?;
            let minor = parts
                .get(1)
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);
            Some((major, minor))
        }

        pub fn get_process_info(&self, pid: u32) -> Option<EsProcessInfo> {
            self.process_table.get(&pid).map(|e| e.value().clone())
        }

        pub fn is_available(&self) -> bool {
            self.available.load(Ordering::Acquire)
        }

        pub fn init_status(&self) -> &str {
            &self.init_status
        }

        pub fn process_count(&self) -> usize {
            self.process_table.len()
        }

        pub fn get_file_attribution(&self, path: &str) -> Option<(u32, String, String)> {
            // ES records canonical paths (e.g. /private/tmp/...) while notify
            // may deliver user-provided paths (e.g. /tmp/...).  Try the raw
            // path first, then fall back to the canonicalized form.
            if let Some(hit) = self.lookup_file_attr(path) {
                return Some(hit);
            }
            if let Ok(canonical) = std::fs::canonicalize(path) {
                let canonical_str = canonical.to_string_lossy();
                if canonical_str.as_ref() != path {
                    return self.lookup_file_attr(&canonical_str);
                }
            }
            None
        }

        fn lookup_file_attr(&self, key: &str) -> Option<(u32, String, String)> {
            let entry = self.file_attribution_table.get(key)?;
            let attr = entry.value();
            if attr.recorded_at.elapsed().as_secs() > FILE_ATTR_TTL_SECS {
                return None;
            }
            Some((
                attr.pid,
                attr.process_name.clone(),
                attr.process_path.clone(),
            ))
        }

        pub fn file_attribution_count(&self) -> usize {
            self.file_attribution_table.len()
        }

        pub fn file_event_stats(&self) -> (u64, u64, u64, u64, u64, u64, u64, u64, u64) {
            let c = &self.file_event_counters;
            (
                c.create_received.load(Ordering::Relaxed),
                c.create_dest_some.load(Ordering::Relaxed),
                c.create_dest_none.load(Ordering::Relaxed),
                c.write_received.load(Ordering::Relaxed),
                c.close_received.load(Ordering::Relaxed),
                c.close_modified.load(Ordering::Relaxed),
                c.rename_received.load(Ordering::Relaxed),
                c.unlink_received.load(Ordering::Relaxed),
                c.other_event.load(Ordering::Relaxed),
            )
        }

        pub fn dump_file_attribution_paths(&self, max: usize) -> Vec<(String, u32, String)> {
            self.file_attribution_table
                .iter()
                .take(max)
                .map(|e| {
                    let v = e.value();
                    (e.key().clone(), v.pid, v.process_path.clone())
                })
                .collect()
        }

        /// Targeted session resolution: iterate ES-known PIDs and probe their
        /// sockets via libproc until the matching session is found.  Much faster
        /// than a full `scan_all_process_sockets()` because we only visit PIDs
        /// the kernel told us about and short-circuit on the first match.
        #[cfg(target_os = "macos")]
        pub fn get_l7_for_session(&self, session: &crate::sessions::Session) -> Option<SessionL7> {
            use crate::l7_macos;

            if !self.is_available() {
                return None;
            }

            // One shared libproc socket snapshot answers the lookup instead
            // of a sweep of every ES-known pid's socket fds per call. That
            // sweep ran on the packet task for each new session and again
            // for every parked entry on each populate pass; it was the
            // dominant helper cost on macOS (fmba-3, 2026-09-19).
            let pid = l7_macos::quick_lookup_session_pid(session)?;
            let entry = self.process_table.get(&pid)?;
            let es_info = entry.value();
            let mut l7 = SessionL7 {
                pid,
                process_name: es_info.process_name.clone(),
                process_path: es_info.process_path.clone(),
                username: es_info.username.clone(),
                cmd: es_info.args.clone(),
                cwd: es_info.cwd.clone(),
                start_time: es_info.start_time,
                parent_pid: es_info.parent_pid(),
                parent_process_name: es_info.parent_process_name.clone(),
                parent_process_path: es_info.parent_process_path.clone(),
                parent_cmd: es_info.parent_args.clone(),
                grandparent_pid: es_info.grandparent_pid,
                grandparent_process_name: es_info.grandparent_process_name.clone(),
                grandparent_process_path: es_info.grandparent_process_path.clone(),
                grandparent_cmd: es_info.grandparent_args.clone(),
                ..Default::default()
            };
            fn path_is_tmp(p: &str) -> bool {
                let lp = p.to_lowercase();
                lp.starts_with("/tmp/")
                    || lp.starts_with("/var/tmp/")
                    || lp.starts_with("/dev/shm/")
            }
            l7.spawned_from_tmp = path_is_tmp(&l7.process_path)
                || path_is_tmp(&l7.parent_process_path)
                || path_is_tmp(&l7.grandparent_process_path);
            Some(l7)
        }

        pub fn enrich_session_l7(&self, pid: u32, base_l7: &mut SessionL7) {
            if let Some(info) = self.process_table.get(&pid) {
                let info = info.value();
                if base_l7.process_path.is_empty() || base_l7.process_path.starts_with("/proc/") {
                    base_l7.process_path = info.process_path.clone();
                }
                if base_l7.process_name.is_empty() || base_l7.process_name.starts_with("pid-") {
                    base_l7.process_name = info.process_name.clone();
                }
                if base_l7.username.is_empty() || base_l7.username.starts_with("uid-") {
                    base_l7.username = info.username.clone();
                }
                if base_l7.cmd.is_empty() && !info.args.is_empty() {
                    base_l7.cmd = info.args.clone();
                }
                if base_l7.cwd.is_none() {
                    base_l7.cwd = info.cwd.clone();
                }
                if base_l7.parent_process_name.is_empty() {
                    base_l7.parent_pid = info.parent_pid();
                    base_l7.parent_process_name = info.parent_process_name.clone();
                    base_l7.parent_process_path = info.parent_process_path.clone();
                    base_l7.parent_cmd = info.parent_args.clone();
                }
                if base_l7.grandparent_process_name.is_empty() {
                    base_l7.grandparent_pid = info.grandparent_pid;
                    base_l7.grandparent_process_name = info.grandparent_process_name.clone();
                    base_l7.grandparent_process_path = info.grandparent_process_path.clone();
                    base_l7.grandparent_cmd = info.grandparent_args.clone();
                }
            }
        }
    }

    // FlodbaddL7Es only holds Arc<DashMap> and Arc<AtomicBool>, which are
    // themselves Send + Sync. The !Send Client lives exclusively on the
    // dedicated es-client thread and is never accessed from the struct.
    unsafe impl Send for FlodbaddL7Es {}
    unsafe impl Sync for FlodbaddL7Es {}

    pub fn global() -> &'static FlodbaddL7Es {
        static INSTANCE: OnceCell<FlodbaddL7Es> = OnceCell::new();
        INSTANCE.get_or_init(FlodbaddL7Es::init)
    }

    pub fn get_init_status() -> &'static str {
        global().init_status()
    }
}

#[cfg(not(all(target_os = "macos", feature = "endpointsecurity")))]
mod macos {
    #![allow(dead_code)]
    use super::*;

    #[derive(Clone, Debug)]
    pub struct EsProcessInfo;

    pub struct FlodbaddL7Es;

    impl FlodbaddL7Es {
        pub fn get_l7_for_session(&self, _session: &crate::sessions::Session) -> Option<SessionL7> {
            None
        }

        pub fn get_process_info(&self, _pid: u32) -> Option<EsProcessInfo> {
            None
        }

        pub fn is_available(&self) -> bool {
            false
        }

        pub fn init_status(&self) -> &str {
            "Not available: Endpoint Security requires macOS with 'endpointsecurity' feature"
        }

        pub fn process_count(&self) -> usize {
            0
        }

        pub fn get_file_attribution(&self, _path: &str) -> Option<(u32, String, String)> {
            None
        }

        pub fn file_attribution_count(&self) -> usize {
            0
        }

        pub fn file_event_stats(&self) -> (u64, u64, u64, u64, u64, u64, u64, u64, u64) {
            (0, 0, 0, 0, 0, 0, 0, 0, 0)
        }

        pub fn dump_file_attribution_paths(&self, _max: usize) -> Vec<(String, u32, String)> {
            Vec::new()
        }

        pub fn enrich_session_l7(&self, _pid: u32, _base_l7: &mut SessionL7) {}
    }

    pub fn global() -> &'static FlodbaddL7Es {
        static INSTANCE: FlodbaddL7Es = FlodbaddL7Es;
        &INSTANCE
    }

    pub fn get_init_status() -> &'static str {
        global().init_status()
    }
}

pub use macos::EsProcessInfo;

pub fn get_l7_for_session(session: &crate::sessions::Session) -> Option<SessionL7> {
    #[cfg(target_os = "macos")]
    {
        macos::global().get_l7_for_session(session)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = session;
        None
    }
}

pub fn get_process_info(pid: u32) -> Option<EsProcessInfo> {
    macos::global().get_process_info(pid)
}

pub fn enrich_session_l7(pid: u32, base_l7: &mut SessionL7) {
    macos::global().enrich_session_l7(pid, base_l7);
}

pub fn is_available() -> bool {
    #[cfg(all(target_os = "macos", feature = "endpointsecurity"))]
    {
        macos::global().is_available()
    }

    #[cfg(not(all(target_os = "macos", feature = "endpointsecurity")))]
    {
        false
    }
}

pub fn init_and_log_status() {
    let available = is_available();
    if available {
        info!(
            "ES process + file tracking ENABLED - process and file attribution from Endpoint Security framework"
        );
    } else {
        #[cfg(all(target_os = "macos", feature = "endpointsecurity"))]
        {
            tracing::warn!(
                "ES process + file tracking DISABLED - falling back to sysinfo/lsof-based resolution"
            );
        }
        #[cfg(not(all(target_os = "macos", feature = "endpointsecurity")))]
        {
            info!(
                "ES process + file tracking not available on this platform (non-macOS or feature disabled)"
            );
        }
    }
}

pub fn es_support() -> String {
    #[cfg(not(target_os = "macos"))]
    {
        return "Not supported: Endpoint Security requires macOS".to_string();
    }

    #[cfg(all(target_os = "macos", not(feature = "endpointsecurity")))]
    {
        return "Not enabled: compiled without 'endpointsecurity' feature flag".to_string();
    }

    #[cfg(all(target_os = "macos", feature = "endpointsecurity"))]
    {
        macos::get_init_status().to_string()
    }
}

pub fn process_count() -> usize {
    macos::global().process_count()
}

pub fn get_file_attribution(path: &str) -> Option<(u32, String, String)> {
    macos::global().get_file_attribution(path)
}

pub fn file_attribution_count() -> usize {
    macos::global().file_attribution_count()
}

/// `(create, create_dest_some, create_dest_none, write, close, close_modified, rename, unlink, other)`.
pub fn file_event_stats() -> (u64, u64, u64, u64, u64, u64, u64, u64, u64) {
    macos::global().file_event_stats()
}

pub fn dump_file_attribution_paths(max: usize) -> Vec<(String, u32, String)> {
    macos::global().dump_file_attribution_paths(max)
}

#[cfg(test)]
mod es_lineage_tests {
    //! The parent selection of the Endpoint Security handler, without
    //! Endpoint Security: a `HashMap` stands in for the process table and
    //! `apply_fork` / `apply_exec` write the rows the handler writes.
    use super::es_lineage::*;
    use std::collections::HashMap;

    type Table = HashMap<u32, KnownProcess>;

    fn row_from(lineage: Lineage, path: &str, args: &[&str]) -> KnownProcess {
        KnownProcess {
            ppid: lineage.ppid.unwrap_or(0),
            path: path.to_string(),
            args: args.iter().map(|a| a.to_string()).collect(),
            parent_name: lineage.parent_name,
            parent_path: lineage.parent_path,
            parent_args: lineage.parent_args,
            grandparent_pid: lineage.grandparent_pid,
            grandparent_name: lineage.grandparent_name,
            grandparent_path: lineage.grandparent_path,
            grandparent_args: lineage.grandparent_args,
        }
    }

    /// The fork arm: the forker's image is the child's image until its exec.
    fn apply_fork(table: &mut Table, forker: u32, child: u32) -> Lineage {
        let forker_path = table
            .get(&forker)
            .map(|r| r.path.clone())
            .unwrap_or_default();
        let lineage = fork_lineage(child, forker, &forker_path, |pid| table.get(&pid).cloned());
        table.insert(child, row_from(lineage.clone(), &forker_path, &[]));
        lineage
    }

    /// The exec arm, with the kernel reporting `creator` as the original
    /// parent and `current` as the parent now.
    fn apply_exec(table: &mut Table, pid: u32, creator: u32, current: u32, image: &str) -> Lineage {
        let facts = ExecKernelFacts {
            pid,
            original_ppid: creator,
            parent_token_pid: Some(current),
            ppid: current,
        };
        let lineage = exec_lineage(&facts, |p| table.get(&p).cloned(), |_| None);
        table.insert(pid, row_from(lineage.clone(), image, &[image]));
        lineage
    }

    fn seed(table: &mut Table, pid: u32, ppid: u32, image: &str) {
        table.insert(
            pid,
            KnownProcess {
                ppid,
                path: image.to_string(),
                args: vec![image.to_string()],
                ..KnownProcess::default()
            },
        );
    }

    /// The lineage gate's chain: python -> edl_p (a shell) -> edl_c. Each
    /// exec names the process that forked it, never itself, and the
    /// grandparent is the parent's parent.
    #[test]
    fn an_exec_names_its_forker_never_itself() {
        let mut t = Table::new();
        seed(&mut t, 100, 50, "/usr/bin/python3");
        apply_fork(&mut t, 100, 200);
        let shell = apply_exec(&mut t, 200, 100, 100, "/work/edl_p");
        assert_eq!(shell.ppid, Some(100));
        assert_eq!(shell.parent_path, "/usr/bin/python3");
        assert_eq!(shell.grandparent_pid, Some(50));

        apply_fork(&mut t, 200, 300);
        let child = apply_exec(&mut t, 300, 200, 200, "/work/edl_c");
        assert_eq!(child.ppid, Some(200));
        assert_eq!(child.parent_name, "edl_p");
        assert_eq!(child.parent_path, "/work/edl_p");
        assert_eq!(child.parent_args, vec!["/work/edl_p".to_string()]);
        assert_eq!(child.grandparent_pid, Some(100));
        assert_eq!(child.grandparent_path, "/usr/bin/python3");
    }

    /// The pre-2.0.5 shape: the exec'ing process is the message's process,
    /// so every pid the message offers can be the exec'ing pid itself. None
    /// of them is a parent.
    #[test]
    fn a_self_referential_parent_is_no_parent() {
        let facts = ExecKernelFacts {
            pid: 200,
            original_ppid: 200,
            parent_token_pid: Some(200),
            ppid: 200,
        };
        assert_eq!(exec_parent_pid(&facts, Some(200)), None);
        let lineage = exec_lineage(&facts, |_| None, |_| Some("/bin/zsh".into()));
        assert_eq!(lineage, Lineage::default());
    }

    /// A shell that execs in place keeps its parent, and its previous image
    /// is not that parent.
    #[test]
    fn an_exec_in_place_keeps_the_parent_and_not_the_previous_image() {
        let mut t = Table::new();
        seed(&mut t, 100, 1, "/usr/bin/login");
        apply_fork(&mut t, 100, 200);
        apply_exec(&mut t, 200, 100, 100, "/bin/bash");
        let again = apply_exec(&mut t, 200, 100, 100, "/usr/bin/python3");
        assert_eq!(again.ppid, Some(100));
        assert_eq!(again.parent_path, "/usr/bin/login");
        assert_ne!(again.parent_path, "/bin/bash");
    }

    /// The creator exited before the child exec'd: the kernel's current
    /// parent is launchd, the creator stays the parent, named from the row
    /// the fork arm wrote.
    #[test]
    fn a_reparented_child_keeps_its_creator() {
        let mut t = Table::new();
        seed(&mut t, 100, 1, "/opt/homebrew/bin/claude");
        apply_fork(&mut t, 100, 200);
        t.remove(&100);
        let lineage = apply_exec(&mut t, 200, 100, 1, "/usr/bin/curl");
        assert_eq!(lineage.ppid, Some(100));
        assert_eq!(lineage.parent_path, "/opt/homebrew/bin/claude");

        // Without an original ppid the fork row still beats launchd.
        let facts = ExecKernelFacts {
            pid: 200,
            original_ppid: 0,
            parent_token_pid: Some(1),
            ppid: 1,
        };
        assert_eq!(exec_parent_pid(&facts, Some(100)), Some(100));
        assert_eq!(exec_parent_pid(&facts, None), Some(1));
    }

    /// A row left by an earlier occupant of the pid (its exit was never
    /// seen) names another parent: the kernel's creator wins and the stale
    /// row lends nothing.
    #[test]
    fn a_stale_row_for_the_pid_lends_nothing() {
        let mut t = Table::new();
        seed(&mut t, 300, 1, "/tmp/stale/launcher");
        apply_fork(&mut t, 300, 200);
        let facts = ExecKernelFacts {
            pid: 200,
            original_ppid: 100,
            parent_token_pid: Some(100),
            ppid: 100,
        };
        let lineage = exec_lineage(
            &facts,
            |p| t.get(&p).cloned(),
            |p| (p == 100).then(|| "/Applications/Cursor.app/Contents/MacOS/Cursor".into()),
        );
        assert_eq!(lineage.ppid, Some(100));
        assert_eq!(
            lineage.parent_path,
            "/Applications/Cursor.app/Contents/MacOS/Cursor"
        );
        assert_eq!(lineage.grandparent_pid, None);
        assert!(lineage.grandparent_path.is_empty());
    }

    /// The fork arm's grandparent is the forker's parent, not the forker.
    #[test]
    fn a_fork_names_the_forkers_parent_as_grandparent() {
        let mut t = Table::new();
        seed(&mut t, 50, 1, "/bin/zsh");
        apply_fork(&mut t, 50, 100);
        apply_exec(&mut t, 100, 50, 50, "/usr/bin/python3");
        let lineage = apply_fork(&mut t, 100, 200);
        assert_eq!(lineage.ppid, Some(100));
        assert_eq!(lineage.parent_path, "/usr/bin/python3");
        assert_eq!(lineage.grandparent_pid, Some(50));
        assert_eq!(lineage.grandparent_path, "/bin/zsh");
        assert_eq!(fork_lineage(7, 7, "/bin/sh", |_| None), Lineage::default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_es_returns_none_without_entitlement() {
        assert!(get_process_info(1).is_none());
    }

    #[test]
    fn test_es_support_string() {
        let support = es_support();
        assert!(!support.is_empty());
    }

    /// Validates that the ES client initializes when the binary is codesigned
    /// with the Endpoint Security entitlement and running as root.
    ///
    /// Run via: make macos_test   (codesigns automatically)
    /// Or manually:
    ///   cargo test --features endpointsecurity,fim --no-run
    ///   codesign --force --sign - --entitlements ../edamame_helper/macos/edamame_helper.entitlements target/debug/deps/flodbadd-*
    ///   sudo -E target/debug/deps/flodbadd-* test_es_entitlement_active --nocapture
    #[test]
    #[cfg(all(target_os = "macos", feature = "endpointsecurity"))]
    fn test_es_entitlement_active() {
        let running_as_root = uzers::get_effective_uid() == 0;
        if !running_as_root {
            eprintln!("SKIP: test_es_entitlement_active requires root (run via `make macos_test`)");
            return;
        }

        init_and_log_status();

        let available = is_available();
        let support = es_support();

        eprintln!("ES available: {}", available);
        eprintln!("ES support:   {}", support);

        if !available {
            eprintln!(
                "SKIP: ES client could not initialize (SIP enabled + no Developer ID cert). \
                 ES validation will run in CI."
            );
            return;
        }

        // Give ES a moment to populate the process table from the running system
        std::thread::sleep(std::time::Duration::from_secs(2));

        let proc_count = process_count();
        eprintln!("ES processes after 2s: {}", proc_count);
        assert!(
            proc_count > 0,
            "ES initialized but process table is empty after 2s -- \
             FORK/EXEC events not being received"
        );

        let my_pid = std::process::id();
        eprintln!(
            "Own PID: {}, ES lookup: {:?}",
            my_pid,
            get_process_info(my_pid)
        );
    }
}
