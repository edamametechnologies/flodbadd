// Endpoint Security process attribution for macOS.
//
// Uses Apple's Endpoint Security framework to maintain a live process table
// populated by kernel-delivered FORK/EXEC/EXIT events. This table provides
// high-fidelity process metadata (executable path, parent chain, code signing,
// arguments, cwd) without the race conditions inherent in polling sysinfo after
// the fact.
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tracing::{debug, error, warn};

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
                        available: Arc::new(AtomicBool::new(false)),
                        init_status: msg,
                    };
                }
                version::set_runtime_version(major as u64, minor as u64, 0);
            } else {
                version::set_runtime_version(13, 0, 0);
            }

            let process_table = Arc::new(DashMap::new());
            let available = Arc::new(AtomicBool::new(false));
            let table_for_thread = Arc::clone(&process_table);
            let available_for_thread = Arc::clone(&available);

            // Client is !Send + !Sync -- must be created and kept alive on a
            // dedicated thread. The DashMap process table is the shared
            // communication channel (lock-free, Arc-shared).
            if let Err(e) = std::thread::Builder::new()
                .name("es-client".into())
                .spawn(move || {
                    Self::run_es_client(table_for_thread, available_for_thread);
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
                    "Enabled: macOS {} with ES process tracking (FORK/EXEC/EXIT)",
                    version_str
                )
            } else {
                format!(
                    "Disabled: ES client failed to initialize on macOS {} (check entitlement and root)",
                    version_str
                )
            };

            if is_available {
                info!("ES L7 helper initialized: {}", init_status);
            } else {
                warn!("ES L7 helper: {}", init_status);
            }

            Self {
                process_table,
                available,
                init_status,
            }
        }

        fn run_es_client(
            table: Arc<DashMap<u32, EsProcessInfo>>,
            available: Arc<AtomicBool>,
        ) {
            let table_for_handler = AssertUnwindSafe(Arc::clone(&table));

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
                        let child_path = child
                            .executable()
                            .path()
                            .to_string_lossy()
                            .to_string();

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
                        let target_path = target
                            .executable()
                            .path()
                            .to_string_lossy()
                            .to_string();

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
            ];
            if let Err(e) = client.subscribe(&events) {
                error!("ES subscribe failed: {:?}", e);
                return;
            }

            available.store(true, Ordering::Release);
            info!("ES client created and subscribed to FORK/EXEC/EXIT events");

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
            let minor = parts.get(1).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
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
            "ES L7 process tracking is ENABLED - process metadata from Endpoint Security framework"
        );
    } else {
        #[cfg(all(target_os = "macos", feature = "endpointsecurity"))]
        {
            tracing::warn!(
                "ES L7 process tracking is DISABLED - falling back to sysinfo-based resolution"
            );
        }
        #[cfg(not(all(target_os = "macos", feature = "endpointsecurity")))]
        {
            info!(
                "ES L7 process tracking not available on this platform (non-macOS or feature disabled)"
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
