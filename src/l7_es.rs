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

#[cfg(all(target_os = "macos", feature = "endpointsecurity"))]
mod macos {
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
        pub parent_process_name: String,
        pub parent_process_path: String,
        pub parent_args: Vec<String>,
        pub grandparent_pid: Option<u32>,
        pub grandparent_process_name: String,
        pub grandparent_process_path: String,
        pub grandparent_args: Vec<String>,
    }

    fn extract_process_name(path: &str) -> String {
        std::path::Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
    }

    fn resolve_username(uid: u32) -> String {
        users::get_user_by_uid(uid)
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
            let table_for_thread = Arc::clone(&process_table);
            let file_table_for_thread = Arc::clone(&file_attribution_table);
            let file_counter_for_thread = Arc::clone(&file_insert_counter);
            let available_for_thread = Arc::clone(&available);

            // Client is !Send + !Sync -- must be created and kept alive on a
            // dedicated thread. The DashMap process table is the shared
            // communication channel (lock-free, Arc-shared).
            if let Err(e) = std::thread::Builder::new()
                .name("es-client".into())
                .spawn(move || {
                    Self::run_es_client(
                        table_for_thread,
                        file_table_for_thread,
                        file_counter_for_thread,
                        available_for_thread,
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
                    "Enabled: macOS {} with ES process + file tracking (FORK/EXEC/EXIT + CREATE/CLOSE/RENAME/UNLINK)",
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
            let cutoff = Instant::now() - std::time::Duration::from_secs(FILE_ATTR_TTL_SECS);
            table.retain(|_, v| v.recorded_at > cutoff);

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

        fn run_es_client(
            table: Arc<DashMap<u32, EsProcessInfo>>,
            file_table: Arc<DashMap<String, FimEsAttribution>>,
            file_counter: Arc<AtomicU64>,
            available: Arc<AtomicBool>,
        ) {
            let table_for_handler = AssertUnwindSafe(Arc::clone(&table));
            let file_table_for_handler = AssertUnwindSafe(Arc::clone(&file_table));
            let file_counter_for_handler = AssertUnwindSafe(Arc::clone(&file_counter));

            let handler = move |_client: &mut Client<'_>, msg: endpoint_sec::Message| {
                let responsible = msg.process();
                let responsible_pid = responsible.audit_token().pid() as u32;

                match msg.event() {
                    Some(Event::NotifyFork(fork)) => {
                        let child = fork.child();
                        let child_pid = child.audit_token().pid() as u32;

                        let parent_info = table_for_handler.get(&responsible_pid);
                        let (gp_pid, gp_name, gp_path, gp_args) =
                            if let Some(parent) = parent_info.as_ref() {
                                (
                                    Some(parent.pid),
                                    parent.parent_process_name.clone(),
                                    parent.parent_process_path.clone(),
                                    parent.parent_args.clone(),
                                )
                            } else {
                                (None, String::new(), String::new(), Vec::new())
                            };

                        let parent_path = responsible
                            .executable()
                            .path()
                            .to_string_lossy()
                            .to_string();
                        let parent_name = extract_process_name(&parent_path);
                        let child_path = child.executable().path().to_string_lossy().to_string();

                        let info = EsProcessInfo {
                            pid: child_pid,
                            ppid: responsible_pid,
                            uid: child.audit_token().euid(),
                            process_name: extract_process_name(&child_path),
                            process_path: child_path,
                            cwd: None,
                            args: Vec::new(),
                            username: String::new(),
                            start_time: 0,
                            code_signing_flags: 0,
                            is_platform_binary: false,
                            parent_process_name: parent_name,
                            parent_process_path: parent_path,
                            parent_args: Vec::new(),
                            grandparent_pid: gp_pid,
                            grandparent_process_name: gp_name,
                            grandparent_process_path: gp_path,
                            grandparent_args: gp_args,
                        };
                        table_for_handler.insert(child_pid, info);
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

                        let parent_info = table_for_handler.get(&responsible_pid);
                        let (parent_name, parent_path, parent_args) =
                            if let Some(p) = parent_info.as_ref() {
                                (
                                    p.process_name.clone(),
                                    p.process_path.clone(),
                                    p.args.clone(),
                                )
                            } else {
                                let rpath = responsible
                                    .executable()
                                    .path()
                                    .to_string_lossy()
                                    .to_string();
                                (extract_process_name(&rpath), rpath, Vec::new())
                            };

                        let (gp_pid, gp_name, gp_path, gp_args) =
                            if let Some(p) = parent_info.as_ref() {
                                (
                                    Some(p.ppid),
                                    p.parent_process_name.clone(),
                                    p.parent_process_path.clone(),
                                    p.parent_args.clone(),
                                )
                            } else {
                                (None, String::new(), String::new(), Vec::new())
                            };

                        let username = resolve_username(target.audit_token().euid());

                        let info = EsProcessInfo {
                            pid: target_pid,
                            ppid: responsible_pid,
                            uid: target.audit_token().euid(),
                            process_name: extract_process_name(&target_path),
                            process_path: target_path,
                            cwd: None,
                            args,
                            username,
                            start_time: 0,
                            code_signing_flags: cs_flags,
                            is_platform_binary: is_platform,
                            parent_process_name: parent_name,
                            parent_process_path: parent_path,
                            parent_args,
                            grandparent_pid: gp_pid,
                            grandparent_process_name: gp_name,
                            grandparent_process_path: gp_path,
                            grandparent_args: gp_args,
                        };
                        table_for_handler.insert(target_pid, info);
                    }
                    Some(Event::NotifyExit(_)) => {
                        table_for_handler.remove(&responsible_pid);
                    }
                    Some(Event::NotifyCreate(ev)) => {
                        if let Some(dest) = ev.destination() {
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
                                path,
                                responsible_pid,
                                &exe,
                            );
                        }
                    }
                    Some(Event::NotifyClose(ev)) => {
                        if ev.modified() {
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
                                path,
                                responsible_pid,
                                &exe,
                            );
                        }
                    }
                    Some(Event::NotifyRename(ev)) => {
                        let source = ev.source().path().to_string_lossy().to_string();
                        let exe = responsible
                            .executable()
                            .path()
                            .to_string_lossy()
                            .to_string();
                        FlodbaddL7Es::record_file_attribution(
                            &file_table_for_handler,
                            &file_counter_for_handler,
                            &table_for_handler,
                            source,
                            responsible_pid,
                            &exe,
                        );
                    }
                    Some(Event::NotifyUnlink(ev)) => {
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
                            path,
                            responsible_pid,
                            &exe,
                        );
                    }
                    _ => {}
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
                es_event_type_t::ES_EVENT_TYPE_NOTIFY_CREATE,
                es_event_type_t::ES_EVENT_TYPE_NOTIFY_CLOSE,
                es_event_type_t::ES_EVENT_TYPE_NOTIFY_RENAME,
                es_event_type_t::ES_EVENT_TYPE_NOTIFY_UNLINK,
            ];
            if let Err(e) = client.subscribe(&events) {
                error!("ES subscribe failed: {:?}", e);
                return;
            }

            available.store(true, Ordering::Release);
            info!("ES client subscribed to FORK/EXEC/EXIT + CREATE/CLOSE/RENAME/UNLINK");

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
            let entry = self.file_attribution_table.get(path)?;
            let attr = entry.value();
            let elapsed = attr.recorded_at.elapsed().as_secs();
            if elapsed > FILE_ATTR_TTL_SECS {
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

            let reverse = crate::sessions::Session {
                protocol: session.protocol.clone(),
                src_ip: session.dst_ip,
                src_port: session.dst_port,
                dst_ip: session.src_ip,
                dst_port: session.src_port,
            };

            for entry in self.process_table.iter() {
                let pid = *entry.key();
                let es_info = entry.value();
                for sock in l7_macos::scan_process_sockets(pid) {
                    let sock_session = crate::sessions::Session {
                        protocol: sock.protocol.clone(),
                        src_ip: sock.local_ip,
                        src_port: sock.local_port,
                        dst_ip: sock.remote_ip,
                        dst_port: sock.remote_port,
                    };
                    if sock_session == *session || sock_session == reverse {
                        let mut l7 = SessionL7 {
                            pid,
                            process_name: es_info.process_name.clone(),
                            process_path: es_info.process_path.clone(),
                            username: es_info.username.clone(),
                            cmd: es_info.args.clone(),
                            cwd: es_info.cwd.clone(),
                            start_time: es_info.start_time,
                            parent_pid: Some(es_info.ppid),
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
                        return Some(l7);
                    }
                }
            }
            None
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
                    base_l7.parent_pid = Some(info.ppid);
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
}
