// Windows ETW (Event Tracing for Windows) process and file attribution.
//
// Uses the Windows kernel ETW providers (Microsoft-Windows-Kernel-Process,
// TCP/IP, and FileIo) to maintain:
//   1. A live process table populated by kernel Process Start/End events.
//   2. A connection-to-PID map from TCP/IP Connect/Accept events.
//   3. A file attribution table populated by FileIo Create / Write events,
//      mapping recently-written file paths to the process that wrote them.
//   4. A namespace table populated by FileIo Delete / Rename events (and
//      their DeletePath / RenamePath twins, and opens with
//      FILE_DELETE_ON_CLOSE), mapping recently deleted or renamed paths --
//      a rename's old and new name -- to the process that deleted or
//      renamed them. Kept apart from the writes so a delete never takes the
//      writer's identity, and a write looked up after the file was removed
//      never takes the remover's.
//
// The two tables are the Windows counterpart of the ES file attribution
// table on macOS (l7_es.rs).  They are consumed by the FIM subsystem in
// fim.rs to attribute file events to processes at kernel-delivered time,
// avoiding the race conditions inherent in polling.
//
// On non-Windows platforms or when the `etw` feature is not enabled,
// all public functions gracefully fall back to no-op stubs so the rest of
// the codebase does not need to care whether ETW is available.

use crate::sessions::{Session, SessionL7};
#[cfg(all(target_os = "windows", feature = "etw"))]
use crate::win_path_normalize::normalize_win_path;
use tracing::info;

// PTRACE_MODE vocabulary the detector shares across backends
// (`ProcessEvent::task_access_mode`).
const TASK_ACCESS_READ: u32 = 1;
const TASK_ACCESS_ATTACH: u32 = 2;

// PROCESS_* access rights (winnt.h), plus the generic and special rights an
// `OpenProcess` caller may put in the same mask. The PTRACE_MODE vocabulary
// maps onto the mask like this:
//   ATTACH (2): VM_WRITE / VM_OPERATION / CREATE_THREAD asked for on their
//               own -- the debugger-grade opens (task_for_pid / ptrace attach)
//   READ   (1): VM_READ without any of the above -- the read-only task port
//               shape (macOS GET_TASK_READ), which updaters, crash handlers
//               and process monitors take on every process -- and the
//               blanket asks (every right at once, see below)
//   neither   : query-only opens, never forwarded
// Before 2026-09-08 VM_READ alone was ATTACH-grade, so Google Updater
// reading svchost graded like a scraper on the idle baseline.
const PROCESS_CREATE_THREAD: u32 = 0x0002;
const PROCESS_VM_OPERATION: u32 = 0x0008;
const PROCESS_VM_READ: u32 = 0x0010;
const PROCESS_VM_WRITE: u32 = 0x0020;
/// `PROCESS_ALL_ACCESS` as the pre-Vista SDK spells it:
/// `STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF`. .NET Framework still
/// asks for exactly this (`NativeMethods.PROCESS_ALL_ACCESS`); the Vista+
/// value `0x1FFFFF` (0xFFFF specific rights) is a superset of it.
const PROCESS_ALL_ACCESS_LEGACY: u32 = 0x001F_0FFF;
const DEBUGGER_GRADE_RIGHTS: u32 = PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD;

/// Map an `OpenProcess` desired-access mask onto the PTRACE_MODE vocabulary
/// (`1` READ, `2` ATTACH). `None` is a query-only open, never forwarded.
///
/// Graded by the specific rights the mask carries:
///
/// - A blanket ask -- every right of the process object at once -- is READ,
///   not ATTACH. It is what managed frameworks request for any operation
///   (.NET's `System.Diagnostics.Process` asks for it to read a process name
///   or take `Process.Handle`), so grading it as an attach made every .NET
///   tool that walks processes a CRITICAL generator (Chocolatey opening the CI
///   runner worker on the `edamame_cli` / `edamame_helper` Windows gates). It
///   still carries VM_READ, so a named sensitive victim stays CRITICAL and
///   only the detector's enumeration breadth rule (>= 3 distinct read
///   targets) relieves it. Its spellings: the Vista+ `0x1FFFFF` and the
///   legacy `0x1F0FFF` that .NET Framework (Chocolatey) still sends -- until
///   2026-09-29 only the exact Vista value counted, so the legacy one graded
///   ATTACH and the read relief could never apply.
/// - A mask spelled only in generic rights or `MAXIMUM_ALLOWED` is not
///   forwarded. Expanding them (GENERIC_ALL / MAXIMUM_ALLOWED as the blanket
///   ask, GENERIC_READ / GENERIC_WRITE through the generic mapping) was tried
///   on 2026-09-29 and raised CRITICAL findings from benign helpers on an idle
///   Windows runner: conhost opening its console clients with
///   MAXIMUM_ALLOWED, Firefox's crashhelper opening firefox with GENERIC_ALL.
///   Forwarding them waits for a relief for a helper opening the program
///   that started it from the same install.
/// - The SPECIFIC rights a scrape or an injection needs -- VM_WRITE,
///   VM_OPERATION, CREATE_THREAD asked for on their own -- stay ATTACH.
/// - Read and query rights alone (VM_READ with or without
///   QUERY_[LIMITED_]INFORMATION) are READ; query rights alone are not
///   forwarded.
///
/// A READ-grade open is dropped before the ring only when its requester is
/// OS-shipped, and an image in a user-writable %SystemRoot% subtree never is
/// (`is_os_shipped_windows_image`).
///
/// DUP_HANDLE is not graded: the kernel's own System process (pid 4, no image
/// path) duplicates handles out of services all the time, so an ATTACH grade
/// made an idle Windows host a HIGH `process_memory_scrape` generator
/// (posture gate run 36113244867, windows-x64 idle baseline, 2026-09-25).
/// Handle theft out of lsass stays an open gap (DETECTIONGAPS G-49).
///
/// Pure and platform-neutral so the mapping is unit-tested on every host, not
/// only on a Windows build with the `etw` feature.
pub fn task_access_mode_for_desired_access(desired_access: u32) -> Option<u32> {
    if desired_access & PROCESS_ALL_ACCESS_LEGACY == PROCESS_ALL_ACCESS_LEGACY {
        return Some(TASK_ACCESS_READ);
    }
    if desired_access & DEBUGGER_GRADE_RIGHTS != 0 {
        return Some(TASK_ACCESS_ATTACH);
    }
    if desired_access & PROCESS_VM_READ != 0 {
        return Some(TASK_ACCESS_READ);
    }
    None
}

/// Whether a file event at `event_at` happened before the process now holding
/// its pid in the process table started (`process_started_at`); both are
/// FILETIMEs. Then the pid belonged to an earlier process at the time, and
/// the table's occupant is not the actor. `false` when either time is
/// unknown: the event is recorded as before, the occupant being the pid's
/// only candidate.
///
/// Pure and platform-neutral so it is unit-tested on every host.
pub fn file_event_predates_process(event_at: Option<i64>, process_started_at: Option<i64>) -> bool {
    matches!(
        (event_at, process_started_at),
        (Some(event_at), Some(started_at)) if event_at < started_at
    )
}

#[cfg(all(target_os = "windows", feature = "etw"))]
mod win {
    use super::*;
    use dashmap::DashMap;
    use once_cell::sync::OnceCell;
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tracing::{debug, error, warn};

    use std::sync::atomic::AtomicU64;
    use std::time::Instant;

    use windows::core::{GUID, PCWSTR};
    use windows::Win32::System::Diagnostics::Etw::{
        CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
        CONTROLTRACE_HANDLE, ENABLE_TRACE_PARAMETERS, EVENT_HEADER_FLAG_32_BIT_HEADER,
        EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_FLAG_FILE_IO_INIT,
        EVENT_TRACE_FLAG_NETWORK_TCPIP, EVENT_TRACE_FLAG_PROCESS, EVENT_TRACE_LOGFILEW,
        EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, PROCESS_TRACE_MODE_EVENT_RECORD,
        PROCESS_TRACE_MODE_REAL_TIME, TRACE_LEVEL_INFORMATION, WNODE_FLAG_TRACED_GUID,
    };
    use windows::Win32::System::Threading::GetCurrentProcessId;

    use crate::process_events as proc_events;

    const KERNEL_LOGGER_NAME: &str = "NT Kernel Logger";

    // Well-known GUIDs for kernel providers
    const SYSTEM_TRACE_CONTROL_GUID: GUID = GUID::from_u128(0x9e814aad_3204_11d2_9a82_006008a86939);

    // Event opcodes for TCP/IP events
    const EVENT_TRACE_TYPE_CONNECT: u8 = 12; // TcpIp/Connect (TCP connect complete)
    const EVENT_TRACE_TYPE_ACCEPT: u8 = 15; // TcpIp/Accept (incoming TCP accept)
    const EVENT_TRACE_TYPE_RECONNECT: u8 = 16; // TcpIp/Reconnect

    // Event opcodes for Process events
    const EVENT_TRACE_TYPE_START: u8 = 1; // Process/Start
    const EVENT_TRACE_TYPE_END: u8 = 2; // Process/End

    // Process/DCStart: the kernel logger's rundown, one per process already
    // running when the session starts (same payload as Process/Start).
    const EVENT_TRACE_TYPE_DC_START: u8 = 3;

    // FileIo event opcodes and payload layouts (all delivered by
    // EVENT_TRACE_FLAG_FILE_IO_INIT, i.e. initiation events in the caller's
    // process context) live in `crate::etw_fileio_payload`, which decodes
    // them on every host for the unit tests.

    // Open file objects seen at FileIo/Create by a foreign process, keyed by
    // the kernel `FileObject` pointer, so a later FileIo/Write on that
    // object can be attributed to the writer's path. Bounded; entries die
    // at Cleanup/Close or after `FILE_OBJECT_TTL_SECS`.
    const FILE_OBJECT_MAX_ENTRIES: usize = 16_384;
    const FILE_OBJECT_TTL_SECS: u64 = 120;

    // Provider GUIDs
    const TCP_IP_GUID: GUID = GUID::from_u128(0x9a280ac0_c8e0_11d1_84e2_00c04fb998a2);
    const PROCESS_GUID: GUID = GUID::from_u128(0x3d6fa8d0_fe05_11d0_9dda_00c04fd7ba7c);
    const FILEIO_GUID: GUID = GUID::from_u128(0x90cbdc39_4a3e_11d1_84f4_0000f80464e3);

    // BS-9 task access (FLODBADD2 §1b.2 Windows row): the kernel's
    // Microsoft-Windows-Kernel-Audit-API-Calls manifest provider reports
    // every PsOpenProcess with the target pid and the desired-access mask.
    // A manifest provider cannot ride the NT Kernel Logger, so it gets its
    // own private real-time session. No driver, admin session only.
    const KERNEL_AUDIT_API_CALLS_GUID: GUID =
        GUID::from_u128(0xe02a841c_75a3_4fa7_afc8_ae09cf9b7f23);
    const AUDIT_SESSION_NAME: &str = "EDAMAME-KernelAuditApiCalls";
    /// Event id of `PsOpenProcess` in that provider; payload
    /// `TargetProcessId: u32, DesiredAccess: u32, ReturnCode: u32`. The mask
    /// is graded by `super::task_access_mode_for_desired_access`.
    const AUDIT_EVENT_PS_OPEN_PROCESS: u16 = 5;

    // File attribution table limits -- same as ES on macOS (l7_es.rs)
    const FILE_ATTR_MAX_ENTRIES: usize = 50_000;
    const FILE_ATTR_TTL_SECS: u64 = 30;
    const FILE_ATTR_PRUNE_INTERVAL: u64 = 1_000;

    /// FILETIME of the UNIX epoch (100 ns intervals since 1601-01-01).
    const FILETIME_UNIX_EPOCH: i64 = 116_444_736_000_000_000;

    #[derive(Clone, Debug)]
    pub struct FimEtwAttribution {
        pub pid: u32,
        pub process_name: String,
        pub process_path: String,
        pub recorded_at: Instant,
    }

    pub struct FileEventCounters {
        pub create_received: AtomicU64,
    }

    impl Default for FileEventCounters {
        fn default() -> Self {
            Self {
                create_received: AtomicU64::new(0),
            }
        }
    }

    #[derive(Clone, Debug)]
    pub struct EtwProcessInfo {
        pub pid: u32,
        pub ppid: u32,
        pub process_name: String,
        pub process_path: String,
        pub username: String,
        pub session_id: u32,
        pub exit_code: Option<u32>,
        /// When this process came to exist, as a FILETIME (the clock of the
        /// event header timestamps): its Process/Start event's timestamp, or
        /// the kernel's creation time for a process found running. `None`
        /// when unknown. A file event older than this was not this
        /// process's: the pid was its predecessor's then.
        pub started_at: Option<i64>,
    }

    // 4-tuple key for TCP connection tracking
    #[derive(Clone, Debug, Hash, PartialEq, Eq)]
    pub struct TcpConnectionKey {
        pub src_ip: IpAddr,
        pub src_port: u16,
        pub dst_ip: IpAddr,
        pub dst_port: u16,
    }

    pub struct FlodbaddL7Etw {
        process_table: Arc<DashMap<u32, EtwProcessInfo>>,
        connection_table: Arc<DashMap<TcpConnectionKey, u32>>,
        file_attribution_table: Arc<DashMap<String, FimEtwAttribution>>,
        /// Who deleted or renamed a path (see the module header, table 4).
        file_namespace_table: Arc<DashMap<String, FimEtwAttribution>>,
        // Diagnostics counter; the read path lives on the trace-thread
        // clone, so the struct's own handle is retention-only.
        #[allow(dead_code)]
        file_insert_counter: Arc<AtomicU64>,
        file_event_counters: Arc<FileEventCounters>,
        available: Arc<AtomicBool>,
        init_status: String,
    }

    // Raw event payloads from the kernel trace.
    // These are C-layout structs matching the ETW manifest definitions.
    #[repr(C, packed)]
    #[allow(dead_code)]
    struct TcpIpConnectV4 {
        pid: u32,
        size: u32,
        src_addr: u32,
        dst_addr: u32,
        src_port: u16,
        dst_port: u16,
    }

    #[repr(C, packed)]
    #[allow(dead_code)]
    struct TcpIpConnectV6 {
        pid: u32,
        size: u32,
        src_addr: [u8; 16],
        dst_addr: [u8; 16],
        src_port: u16,
        dst_port: u16,
    }

    #[repr(C, packed)]
    #[allow(dead_code)]
    struct ProcessStartEvent {
        // Page directory base (virtual address)
        _page_dir_base: usize,
        pid: u32,
        ppid: u32,
        session_id: u32,
        exit_status: i32,
        // Followed by variable-length SID then ImageFileName (null-terminated wide string)
    }

    impl FlodbaddL7Etw {
        fn init() -> Self {
            let process_table = Arc::new(DashMap::new());
            let connection_table = Arc::new(DashMap::new());
            let file_attribution_table = Arc::new(DashMap::new());
            let file_namespace_table = Arc::new(DashMap::new());
            let file_insert_counter = Arc::new(AtomicU64::new(0));
            let file_event_counters = Arc::new(FileEventCounters::default());
            let available = Arc::new(AtomicBool::new(false));

            let pt = Arc::clone(&process_table);
            let ct = Arc::clone(&connection_table);
            let ft = Arc::clone(&file_attribution_table);
            let nt = Arc::clone(&file_namespace_table);
            let fc = Arc::clone(&file_insert_counter);
            let av = Arc::clone(&available);

            // Statics are never dropped, so nothing stops the sessions when
            // the host exits unless it calls `shutdown`; the CRT's exit hook
            // covers a host whose `main` returns (the helper service) or a
            // DLL being unloaded. `std::process::exit` bypasses it
            // (`ExitProcess`): such hosts call `shutdown` themselves.
            // SAFETY: registers a plain `extern "C"` function with the CRT.
            if unsafe { atexit(shutdown_at_exit) } != 0 {
                warn!("ETW: could not register the exit hook; sessions stop only on an explicit shutdown()");
            }

            if let Err(e) = std::thread::Builder::new()
                .name("etw-client".into())
                .spawn(move || {
                    Self::run_etw_session(pt, ct, ft, nt, fc, av);
                })
            {
                error!("Failed to spawn ETW client thread: {}", e);
            }

            // Task-access watch on its own session and thread; failure only
            // means "no task-access stream" (monitoring role, fail-open).
            let audit_pt = Arc::clone(&process_table);
            if let Err(e) = std::thread::Builder::new()
                .name("etw-audit-api-calls".into())
                .spawn(move || {
                    Self::run_audit_session(audit_pt);
                })
            {
                warn!("Failed to spawn ETW audit-api-calls thread: {}", e);
            }

            std::thread::sleep(std::time::Duration::from_millis(500));

            let is_available = available.load(Ordering::Acquire);
            let init_status = if is_available {
                "Enabled: Windows ETW kernel trace with TCP/IP, Process, and FileIo providers"
                    .to_string()
            } else {
                "Disabled: ETW kernel trace session failed to start (need Administrator)"
                    .to_string()
            };

            if is_available {
                info!("ETW helper initialized: {}", init_status);
            } else {
                warn!("ETW helper: {}", init_status);
            }

            Self {
                process_table,
                connection_table,
                file_attribution_table,
                file_namespace_table,
                file_insert_counter,
                file_event_counters,
                available,
                init_status,
            }
        }

        /// Pre-populate `process_table` with all currently-running processes
        /// so subsequent FileIo/Create + TcpIp/Connect events can be attributed
        /// to processes that predate the ETW session start.
        ///
        /// Without this, `FileIo/Create` for a long-running process (e.g. an
        /// already-open Chrome / Edge that survives helper restart) gets
        /// attributed as `pid-XXXX` because the `Process/Start` ETW event for
        /// that process never fires (it happened before we started listening).
        /// `pid-XXXX` defeats the detector's identity-token self-access
        /// suppression because the token list `["pid", "XXXX"]` does not
        /// overlap path tokens like `["chrome", "user", "data", ...]`.
        ///
        /// One-time cost: ~50-100 ms whole-system enumeration via sysinfo,
        /// run on the helper's ETW worker thread before `ProcessTrace` blocks.
        fn prime_process_table_from_running_processes(
            process_table: &Arc<DashMap<u32, EtwProcessInfo>>,
        ) {
            use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System, Users};
            let started = std::time::Instant::now();
            let mut system = System::new_with_specifics(
                RefreshKind::nothing()
                    .with_processes(ProcessRefreshKind::everything().without_cpu()),
            );
            system.refresh_specifics(
                RefreshKind::nothing()
                    .with_processes(ProcessRefreshKind::everything().without_cpu()),
            );
            let users = Users::new_with_refreshed_list();

            let mut primed = 0u64;
            for (pid, proc_) in system.processes() {
                let pid_u32 = pid.as_u32();
                let process_name = proc_.name().to_string_lossy().to_string();
                let process_path = proc_
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                let ppid = proc_.parent().map(Pid::as_u32).unwrap_or(0);
                let username = proc_
                    .user_id()
                    .and_then(|uid| users.get_user_by_id(uid))
                    .map(|u| u.name().to_string())
                    .unwrap_or_default();
                let session_id = proc_.session_id().map(Pid::as_u32).unwrap_or(0);
                // Whole seconds, rounded down: never later than the real
                // start, and every primed process predates the session.
                let started_at = i64::try_from(proc_.start_time())
                    .ok()
                    .filter(|secs| *secs > 0)
                    .and_then(|secs| secs.checked_mul(10_000_000))
                    .and_then(|ticks| ticks.checked_add(FILETIME_UNIX_EPOCH));

                process_table.insert(
                    pid_u32,
                    EtwProcessInfo {
                        pid: pid_u32,
                        ppid,
                        process_name,
                        process_path,
                        username,
                        session_id,
                        exit_code: None,
                        started_at,
                    },
                );
                primed += 1;
            }
            info!(
                "ETW process_table primed with {} pre-existing processes in {:?}",
                primed,
                started.elapsed()
            );
        }

        /// Private real-time session for `Microsoft-Windows-Kernel-Audit-API-Calls`
        /// (PsOpenProcess). Runs on its own thread; `ProcessTrace` blocks.
        fn run_audit_session(process_table: Arc<DashMap<u32, EtwProcessInfo>>) {
            if SHUTDOWN.load(Ordering::SeqCst) {
                return;
            }
            THREAD_PROCESS_TABLE.with(|t| {
                *t.borrow_mut() = Some(Arc::clone(&process_table));
            });
            unsafe {
                let name_wide: Vec<u16> = AUDIT_SESSION_NAME
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();
                let buf_size =
                    std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + (name_wide.len() * 2) + 1024;

                // Stop a stale session from a previous daemon instance.
                let mut stop_buf = vec![0u8; buf_size];
                let stop_props = &mut *(stop_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
                stop_props.Wnode.BufferSize = buf_size as u32;
                stop_props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
                let _ = ControlTraceW(
                    CONTROLTRACE_HANDLE::default(),
                    PCWSTR(name_wide.as_ptr()),
                    stop_props,
                    EVENT_TRACE_CONTROL_STOP,
                );

                let mut trace_buf = vec![0u8; buf_size];
                let props = &mut *(trace_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
                props.Wnode.BufferSize = buf_size as u32;
                props.Wnode.ClientContext = 1; // QPC
                props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
                props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
                props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
                std::ptr::copy_nonoverlapping(
                    name_wide.as_ptr() as *const u8,
                    trace_buf.as_mut_ptr().add(props.LoggerNameOffset as usize),
                    name_wide.len() * 2,
                );

                let mut session_handle = CONTROLTRACE_HANDLE::default();
                let start = StartTraceW(&mut session_handle, PCWSTR(name_wide.as_ptr()), props);
                if start.is_err() {
                    debug!(
                        "ETW audit-api-calls session not started: {:?} (task-access stream disabled)",
                        start
                    );
                    return;
                }
                if !AUDIT_SESSION.started(session_handle) {
                    // `shutdown` ran while the session was starting.
                    AUDIT_SESSION.ended();
                    let _ = ControlTraceW(
                        session_handle,
                        PCWSTR::null(),
                        props,
                        EVENT_TRACE_CONTROL_STOP,
                    );
                    return;
                }

                let mut params = ENABLE_TRACE_PARAMETERS::default();
                params.Version = 2;
                const ENABLE_PROVIDER: u32 = 1;
                let enabled = EnableTraceEx2(
                    session_handle,
                    &KERNEL_AUDIT_API_CALLS_GUID,
                    ENABLE_PROVIDER,
                    TRACE_LEVEL_INFORMATION as u8,
                    0xFFFFFFFF_FFFFFFFF,
                    0,
                    0,
                    Some(&params),
                );
                if enabled.is_err() {
                    debug!(
                        "ETW audit-api-calls provider not enabled: {:?} (task-access stream disabled)",
                        enabled
                    );
                    AUDIT_SESSION.ended();
                    let _ = ControlTraceW(
                        session_handle,
                        PCWSTR::null(),
                        props,
                        EVENT_TRACE_CONTROL_STOP,
                    );
                    return;
                }

                let mut logfile = EVENT_TRACE_LOGFILEW::default();
                logfile.LoggerName = windows::core::PWSTR(name_wide.as_ptr() as *mut u16);
                logfile.Anonymous1.ProcessTraceMode =
                    PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
                logfile.Anonymous2.EventRecordCallback = Some(audit_record_callback);
                let trace_handle = OpenTraceW(&mut logfile);
                if trace_handle.Value == u64::MAX {
                    debug!("ETW audit-api-calls OpenTrace failed (task-access stream disabled)");
                    AUDIT_SESSION.ended();
                    let _ = ControlTraceW(
                        session_handle,
                        PCWSTR::null(),
                        props,
                        EVENT_TRACE_CONTROL_STOP,
                    );
                    return;
                }
                info!("ETW audit-api-calls session open (PsOpenProcess task-access stream)");
                let handles = [trace_handle];
                let _ = ProcessTrace(&handles, None, None);
                // The session ended (`shutdown`, or another controller stopped
                // it): it is no longer ours to stop.
                AUDIT_SESSION.ended();
                let _ = CloseTrace(trace_handle);
                let _ = ControlTraceW(
                    session_handle,
                    PCWSTR::null(),
                    props,
                    EVENT_TRACE_CONTROL_STOP,
                );
                debug!("ETW audit-api-calls session ended");
            }
        }

        fn run_etw_session(
            process_table: Arc<DashMap<u32, EtwProcessInfo>>,
            connection_table: Arc<DashMap<TcpConnectionKey, u32>>,
            file_table: Arc<DashMap<String, FimEtwAttribution>>,
            namespace_table: Arc<DashMap<String, FimEtwAttribution>>,
            file_counter: Arc<AtomicU64>,
            available: Arc<AtomicBool>,
        ) {
            if SHUTDOWN.load(Ordering::SeqCst) {
                return;
            }
            Self::prime_process_table_from_running_processes(&process_table);

            THREAD_PROCESS_TABLE.with(|t| {
                *t.borrow_mut() = Some(Arc::clone(&process_table));
            });
            THREAD_CONNECTION_TABLE.with(|t| {
                *t.borrow_mut() = Some(Arc::clone(&connection_table));
            });
            THREAD_FILE_TABLE.with(|t| {
                *t.borrow_mut() = Some(Arc::clone(&file_table));
            });
            THREAD_FILE_COUNTER.with(|t| {
                *t.borrow_mut() = Some(Arc::clone(&file_counter));
            });
            THREAD_NAMESPACE_TABLE.with(|t| {
                *t.borrow_mut() = Some(Arc::clone(&namespace_table));
            });

            unsafe {
                // Encode logger name as wide string with null terminator
                let logger_name_wide: Vec<u16> = KERNEL_LOGGER_NAME
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();

                // Stop any pre-existing session
                let buf_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>()
                    + (logger_name_wide.len() * 2)
                    + 1024;
                let mut stop_buf = vec![0u8; buf_size];
                let stop_props = &mut *(stop_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
                stop_props.Wnode.BufferSize = buf_size as u32;
                stop_props.Wnode.Guid = SYSTEM_TRACE_CONTROL_GUID;
                stop_props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;

                let _ = ControlTraceW(
                    CONTROLTRACE_HANDLE::default(),
                    PCWSTR(logger_name_wide.as_ptr()),
                    stop_props,
                    EVENT_TRACE_CONTROL_STOP,
                );

                // Allocate buffer for the new trace session
                let mut trace_buf = vec![0u8; buf_size];
                let props = &mut *(trace_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
                props.Wnode.BufferSize = buf_size as u32;
                props.Wnode.Guid = SYSTEM_TRACE_CONTROL_GUID;
                props.Wnode.ClientContext = 1; // QPC for timestamps
                props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
                // EVENT_TRACE_FLAG_FILE_IO_INIT alone is sufficient: it delivers
                // the FileIo initiation events (Create=64, Cleanup=65, Close=66,
                // Write=68, Delete=70, Rename=71, DeletePath=79, RenamePath=80,
                // ...) in the caller's context; `handle_fileio_event` consumes
                // those and drops the rest at the decoder
                // (`etw_fileio_payload::decode`).
                //
                // EVENT_TRACE_FLAG_FILE_IO (TypeGroup1: Read/Write completion / OpEnd)
                // was previously also enabled, which made the NT Kernel Logger emit
                // an event for every file read/write completion across the entire
                // system. On dogfood Windows hosts this produced ~6-7 MB/s of
                // kernel->user event traffic that was 100% discarded in user space,
                // pegging the helper at ~120% of one core with kernel-time dominant.
                // Drop the flag -- correctness is unchanged because we never read
                // those opcodes anyway.
                props.EnableFlags = EVENT_TRACE_FLAG_NETWORK_TCPIP
                    | EVENT_TRACE_FLAG_PROCESS
                    | EVENT_TRACE_FLAG_FILE_IO_INIT;
                props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
                props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;

                // Copy logger name into the buffer after the properties struct
                let name_offset = props.LoggerNameOffset as usize;
                let name_bytes_len = logger_name_wide.len() * 2;
                std::ptr::copy_nonoverlapping(
                    logger_name_wide.as_ptr() as *const u8,
                    trace_buf.as_mut_ptr().add(name_offset),
                    name_bytes_len,
                );

                let mut session_handle = CONTROLTRACE_HANDLE::default();
                let start_result = StartTraceW(
                    &mut session_handle,
                    PCWSTR(logger_name_wide.as_ptr()),
                    props,
                );

                if start_result.is_err() {
                    warn!(
                        "ETW StartTrace failed: {:?} (need Administrator privileges)",
                        start_result
                    );
                    return;
                }
                if !KERNEL_SESSION.started(session_handle) {
                    // `shutdown` ran while the session was starting.
                    KERNEL_SESSION.ended();
                    let _ = ControlTraceW(
                        session_handle,
                        PCWSTR::null(),
                        props,
                        EVENT_TRACE_CONTROL_STOP,
                    );
                    return;
                }

                debug!("ETW kernel trace session started");

                // Enable TCP/IP provider
                let mut tcp_params = ENABLE_TRACE_PARAMETERS::default();
                tcp_params.Version = 2;
                const ENABLE_PROVIDER: u32 = 1;
                let _ = EnableTraceEx2(
                    session_handle,
                    &TCP_IP_GUID,
                    ENABLE_PROVIDER,
                    TRACE_LEVEL_INFORMATION as u8,
                    0xFFFFFFFF_FFFFFFFF,
                    0,
                    0,
                    Some(&tcp_params),
                );

                // Enable Process provider
                let mut proc_params = ENABLE_TRACE_PARAMETERS::default();
                proc_params.Version = 2;
                let _ = EnableTraceEx2(
                    session_handle,
                    &PROCESS_GUID,
                    ENABLE_PROVIDER,
                    TRACE_LEVEL_INFORMATION as u8,
                    0xFFFFFFFF_FFFFFFFF,
                    0,
                    0,
                    Some(&proc_params),
                );

                // Open the trace for consumption
                let mut logfile = EVENT_TRACE_LOGFILEW::default();
                logfile.LoggerName = windows::core::PWSTR(logger_name_wide.as_ptr() as *mut u16);
                logfile.Anonymous1.ProcessTraceMode =
                    PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
                logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);

                let trace_handle = OpenTraceW(&mut logfile);
                if trace_handle.Value == u64::MAX {
                    error!("ETW OpenTrace failed");
                    KERNEL_SESSION.ended();
                    let _ = ControlTraceW(
                        session_handle,
                        PCWSTR::null(),
                        props,
                        EVENT_TRACE_CONTROL_STOP,
                    );
                    return;
                }

                available.store(true, Ordering::Release);
                info!("ETW trace session open and consuming events");

                // ProcessTrace blocks until the session is stopped or an error occurs
                let handles = [trace_handle];
                let _ = ProcessTrace(&handles, None, None);
                // The session ended (`shutdown`, or another controller stopped
                // it): it is no longer ours to stop, and nothing is feeding
                // the tables any more.
                KERNEL_SESSION.ended();
                available.store(false, Ordering::Release);
                info!("ETW kernel trace session ended");

                let _ = CloseTrace(trace_handle);
                let _ = ControlTraceW(
                    session_handle,
                    PCWSTR::null(),
                    props,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
        }

        pub fn get_pid_for_session(&self, session: &Session) -> Option<u32> {
            let key = TcpConnectionKey {
                src_ip: session.src_ip,
                src_port: session.src_port,
                dst_ip: session.dst_ip,
                dst_port: session.dst_port,
            };
            self.connection_table.get(&key).map(|r| *r.value())
        }

        pub fn get_l7_for_session(&self, session: &Session) -> Option<SessionL7> {
            let pid = self.get_pid_for_session(session)?;
            let info = self.process_table.get(&pid)?;
            let info = info.value();

            Some(SessionL7 {
                pid,
                process_name: info.process_name.clone(),
                process_path: info.process_path.clone(),
                username: if info.username.is_empty() {
                    format!("sid-{}", info.session_id)
                } else {
                    info.username.clone()
                },
                parent_pid: Some(info.ppid),
                ..SessionL7::default()
            })
        }

        pub fn enrich_session_l7(&self, pid: u32, base_l7: &mut SessionL7) {
            if let Some(info) = self.process_table.get(&pid) {
                let info = info.value();
                if base_l7.process_path.is_empty() {
                    base_l7.process_path = info.process_path.clone();
                }
                if base_l7.process_name.is_empty() || base_l7.process_name.starts_with("pid-") {
                    base_l7.process_name = info.process_name.clone();
                }
                if base_l7.username.is_empty() || base_l7.username.starts_with("uid-") {
                    if !info.username.is_empty() {
                        base_l7.username = info.username.clone();
                    }
                }
                if base_l7.parent_process_name.is_empty() {
                    base_l7.parent_pid = Some(info.ppid);
                    if let Some(parent) = self.process_table.get(&info.ppid) {
                        base_l7.parent_process_name = parent.process_name.clone();
                        base_l7.parent_process_path = parent.process_path.clone();
                        if let Some(gp) = self.process_table.get(&parent.ppid) {
                            base_l7.grandparent_pid = Some(parent.ppid);
                            base_l7.grandparent_process_name = gp.process_name.clone();
                            base_l7.grandparent_process_path = gp.process_path.clone();
                        }
                    }
                }
            }
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

        pub fn connection_count(&self) -> usize {
            self.connection_table.len()
        }

        pub fn get_file_attribution(&self, path: &str) -> Option<(u32, String, String)> {
            Self::lookup_file_actor(&self.file_attribution_table, path)
        }

        /// The process that deleted or renamed `path` (a rename's old or new
        /// name), never its writer: `(pid, process_name, process_path)`.
        pub fn get_file_namespace_attribution(&self, path: &str) -> Option<(u32, String, String)> {
            Self::lookup_file_actor(&self.file_namespace_table, path)
        }

        fn lookup_file_actor(
            table: &DashMap<String, FimEtwAttribution>,
            path: &str,
        ) -> Option<(u32, String, String)> {
            // The lookup key is the canonical form. Callers from the
            // `notify` side typically supply Win32-shaped paths
            // (`C:\Users\...`), while ETW recorded NT-object paths
            // (`\Device\HarddiskVolume3\Users\...`). Both sides are
            // normalized through `normalize_win_path` so they collide
            // on a single key.
            let key = normalize_win_path(path);
            let entry = table.get(&key)?;
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

        pub fn file_event_stats(&self) -> u64 {
            self.file_event_counters
                .create_received
                .load(Ordering::Relaxed)
        }

        /// `at`: the FileIo event's header timestamp. The pid is the
        /// kernel's (the event runs in the actor's context); the image is
        /// the process table's, unless the process holding the pid there
        /// started after the event: the pid was then still its
        /// predecessor's, and the successor must not lend its identity
        /// (FP-WIN-29 class; the session delivers per-CPU buffers out of
        /// order, so a successor's Process/Start can be processed before its
        /// predecessor's last file operation). Then, as for a pid the table
        /// does not know, only the pid is recorded.
        fn record_file_attribution(
            file_table: &DashMap<String, FimEtwAttribution>,
            file_counter: &AtomicU64,
            process_table: &DashMap<u32, EtwProcessInfo>,
            path: String,
            pid: u32,
            at: Option<i64>,
        ) {
            let (process_name, process_path) = match process_table.get(&pid) {
                Some(info) if !super::file_event_predates_process(at, info.started_at) => {
                    (info.process_name.clone(), info.process_path.clone())
                }
                _ => (format!("pid-{}", pid), String::new()),
            };

            // Store the canonical form so lookups from any path shape
            // (NT object manager, Win32, long-path-prefixed) collide on
            // the same key.
            let key = normalize_win_path(&path);

            file_table.insert(
                key,
                FimEtwAttribution {
                    pid,
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

        fn prune_file_attribution_table(table: &DashMap<String, FimEtwAttribution>) {
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
    }

    /// Inserts into the namespace table, for its prune cadence (the write
    /// table's count is `file_insert_counter`).
    static NAMESPACE_INSERTS: AtomicU64 = AtomicU64::new(0);

    // Thread-local storage for the ETW callback to access the shared tables.
    // ETW callbacks are invoked on the ProcessTrace thread, so we set these
    // before calling ProcessTrace.
    thread_local! {
        static THREAD_PROCESS_TABLE: std::cell::RefCell<Option<Arc<DashMap<u32, EtwProcessInfo>>>> =
            const { std::cell::RefCell::new(None) };
        static THREAD_CONNECTION_TABLE: std::cell::RefCell<Option<Arc<DashMap<TcpConnectionKey, u32>>>> =
            const { std::cell::RefCell::new(None) };
        static THREAD_FILE_TABLE: std::cell::RefCell<Option<Arc<DashMap<String, FimEtwAttribution>>>> =
            const { std::cell::RefCell::new(None) };
        static THREAD_FILE_COUNTER: std::cell::RefCell<Option<Arc<AtomicU64>>> =
            const { std::cell::RefCell::new(None) };
        static THREAD_NAMESPACE_TABLE: std::cell::RefCell<Option<Arc<DashMap<String, FimEtwAttribution>>>> =
            const { std::cell::RefCell::new(None) };
        // Only the ProcessTrace thread touches it: no lock needed.
        static THREAD_FILE_OBJECTS: std::cell::RefCell<std::collections::HashMap<u64, (String, Instant)>> =
            std::cell::RefCell::new(std::collections::HashMap::new());
    }

    /// `Microsoft-Windows-Kernel-Audit-API-Calls` callback (audit session
    /// thread). `PsOpenProcess` is graded by requested access mask and
    /// forwarded as a `TaskAccess` ring event carrying the requester (the
    /// event header's process) and the target from the payload; both images
    /// come from the ETW process table primed at start. Query-only masks are
    /// never forwarded; READ-grade opens are, except from OS-shipped
    /// requesters, which are dropped as ring pre-filtering (the constant
    /// csrss / lsass / svchost / MsMpEng background). ATTACH-grade opens are
    /// forwarded regardless of the requester's path.
    unsafe extern "system" fn audit_record_callback(record: *mut EVENT_RECORD) {
        if record.is_null() {
            return;
        }
        let event = &*record;
        let header = &event.EventHeader;
        if header.ProviderId != KERNEL_AUDIT_API_CALLS_GUID {
            return;
        }
        let data_ptr = event.UserData as *const u8;
        let data_len = event.UserDataLength as usize;
        // Bounded diagnostic of the provider's raw shape (event id, version,
        // payload) so a daemon log answers "what does this kernel deliver"
        // without a debugger -- the PsOpenProcess layout below is decoded
        // from documentation, not from an SDK header.
        static AUDIT_DIAG_LINES: AtomicU64 = AtomicU64::new(0);
        if AUDIT_DIAG_LINES.fetch_add(1, Ordering::Relaxed) < 12 {
            let preview_len = data_len.min(32);
            let preview: Vec<String> = if data_ptr.is_null() {
                Vec::new()
            } else {
                std::slice::from_raw_parts(data_ptr, preview_len)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect()
            };
            info!(
                "ETW audit-api-calls event id={} version={} opcode={} level={} keyword={:#x} pid={} len={} payload={}",
                header.EventDescriptor.Id,
                header.EventDescriptor.Version,
                header.EventDescriptor.Opcode,
                header.EventDescriptor.Level,
                header.EventDescriptor.Keyword,
                header.ProcessId,
                data_len,
                preview.join("")
            );
        }
        if header.EventDescriptor.Id != AUDIT_EVENT_PS_OPEN_PROCESS {
            return;
        }
        if data_ptr.is_null() || data_len < 12 {
            return;
        }
        let read_u32 = |off: usize| {
            u32::from_le_bytes([
                *data_ptr.add(off),
                *data_ptr.add(off + 1),
                *data_ptr.add(off + 2),
                *data_ptr.add(off + 3),
            ])
        };
        let target_pid = read_u32(0);
        let desired_access = read_u32(4);
        let requester_pid = header.ProcessId;
        let own_pid = GetCurrentProcessId();
        if target_pid == 0 || requester_pid == 0 || requester_pid == target_pid {
            return;
        }
        if requester_pid == own_pid || target_pid == own_pid {
            return;
        }
        // The return code is deliberately not consulted: like the Linux
        // `ptrace_may_access` kprobe this records the attempt, and a denied
        // open of a sensitive target is evidence in its own right.
        let Some(task_access_mode) = task_access_mode_for_desired_access(desired_access) else {
            return;
        };
        THREAD_PROCESS_TABLE.with(|t| {
            if let Some(table) = t.borrow().as_ref() {
                let (mut requester_name, mut requester_path, requester_ppid, parent_path) = table
                    .get(&requester_pid)
                    .map(|p| {
                        let parent = table
                            .get(&p.ppid)
                            .map(|pp| pp.process_path.clone())
                            .filter(|s| !s.is_empty());
                        (
                            p.process_name.clone(),
                            p.process_path.clone(),
                            Some(p.ppid),
                            parent,
                        )
                    })
                    .unwrap_or_default();
                if requester_path.is_empty() {
                    // The opener is alive right now: ask the kernel.
                    if let Some(path) = query_image_path(requester_pid) {
                        requester_name = std::path::Path::new(&path)
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default();
                        requester_path = path;
                    }
                }
                let target_path = table
                    .get(&target_pid)
                    .map(|p| p.process_path.clone())
                    .filter(|s| !s.is_empty())
                    .or_else(|| query_image_path(target_pid));
                // Ring-level pre-filter (FLODBADD2 §1b.5): csrss, lsass,
                // svchost and Defender's MsMpEng open every process with
                // VM_READ, and Windows has no in-message signing fact like
                // ES. A path-under-%SystemRoot% / Defender-root check keeps
                // that background out of the ring; the grader in core does
                // not trust it -- it attaches the requester's measured
                // publisher verdict (in-process WinVerifyTrust + catalog,
                // edamame_foundation::publisher_attestation) and drops an
                // edge only for a Microsoft-signed binary at a canonical path.
                // The mark deliberately excludes the user-writable subtrees
                // of %SystemRoot% (Temp, Tasks, ...): a standard user can
                // drop a binary there without elevation, so its path vouches
                // for nothing (see is_os_shipped_windows_image).
                let path_marked = is_os_shipped_windows_image(&requester_path);
                // Read-grade opens by OS-shipped requesters (csrss, lsass,
                // svchost, MsMpEng, ...) are the constant background the
                // detector drops anyway; keep them out of the ring. The mark
                // rides the event as `platform_path_marked`, never as
                // `is_platform_binary`: a path is not a kernel fact. Since
                // the blanket asks grade READ, an OS-shipped binary making
                // one also stays out of the ring -- the same background, and
                // the detector drops a kernel-vouched platform requester at a
                // canonical path regardless of grade. A binary in a
                // user-writable %SystemRoot% subtree is not marked, so its
                // opens always reach the detector.
                if task_access_mode == TASK_ACCESS_READ && path_marked {
                    return;
                }
                proc_events::push(proc_events::ProcessEvent {
                    timestamp_ms: proc_events::now_ms(),
                    kind: proc_events::ProcessEventKind::TaskAccess,
                    pid: requester_pid,
                    ppid: requester_ppid,
                    uid: None,
                    process_name: requester_name,
                    process_path: requester_path,
                    parent_process_path: parent_path,
                    argv_sha256: None,
                    argv_len: None,
                    signing_id: None,
                    team_id: None,
                    is_platform_binary: None,
                    platform_path_marked: path_marked,
                    target_pid: Some(target_pid),
                    target_process_path: target_path,
                    task_access_mode: Some(task_access_mode),
                    task_access_mask: Some(desired_access),
                    net_dst: None,
                });
            }
        });
    }

    /// Full image path of a live process from the kernel
    /// (`QueryFullProcessImageNameW`), for processes whose start event we
    /// could not decode or that the audit stream names before the process
    /// table does. Query-limited access only (never an ATTACH-grade open,
    /// and our own opens are filtered by pid in the audit callback).
    fn query_image_path(pid: u32) -> Option<String> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
            PROCESS_QUERY_LIMITED_INFORMATION,
        };
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
            let mut buf = [0u16; 1024];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                windows::core::PWSTR(buf.as_mut_ptr()),
                &mut len,
            )
            .is_ok();
            let _ = CloseHandle(handle);
            if !ok || len == 0 {
                return None;
            }
            Some(String::from_utf16_lossy(&buf[..len as usize]))
        }
    }

    /// Creation time of the process holding `pid` now, as a FILETIME (100 ns
    /// since 1601), from the kernel. Query-limited access only.
    fn process_creation_filetime(pid: u32) -> Option<u64> {
        use windows::Win32::Foundation::{CloseHandle, FILETIME};
        use windows::Win32::System::Threading::{
            GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
            let mut created = FILETIME::default();
            let mut exited = FILETIME::default();
            let mut kernel = FILETIME::default();
            let mut user = FILETIME::default();
            let ok =
                GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user).is_ok();
            let _ = CloseHandle(handle);
            if !ok {
                return None;
            }
            let filetime =
                (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
            (filetime > 0).then_some(filetime)
        }
    }

    /// Image of the process holding `pid` now, provided it was created no
    /// later than `not_after` (a FILETIME): the parent of a process created
    /// at `not_after` is older than it, and a process that took the parent's
    /// pid after the parent exited is younger. `None` when the occupant is
    /// younger or its creation time cannot be read (unmeasured, never a
    /// guess).
    fn query_image_path_created_by(pid: u32, not_after: u64) -> Option<String> {
        let created = process_creation_filetime(pid)?;
        if !occupant_predates(created, not_after) {
            return None;
        }
        query_image_path(pid)
    }

    /// The parent of a process exists before it does.
    fn occupant_predates(occupant_created: u64, child_created: u64) -> bool {
        occupant_created <= child_created
    }

    #[cfg(test)]
    mod parent_occupant_tests {
        use super::{
            occupant_predates, process_creation_filetime, query_image_path_created_by,
            running_parent_verified,
        };

        #[test]
        fn a_parent_is_older_than_its_child_and_a_successor_is_not() {
            assert!(occupant_predates(100, 200));
            assert!(occupant_predates(200, 200));
            assert!(!occupant_predates(201, 200));
        }

        /// A process found running by the rundown keeps its parent pid only
        /// when the process holding that pid is verifiably no younger: a
        /// younger holder took the pid after the real parent exited, and an
        /// unreadable creation time is unmeasured, never a parent.
        #[test]
        fn a_running_process_names_only_a_verified_parent() {
            assert!(running_parent_verified(Some(200), Some(100)));
            assert!(running_parent_verified(Some(200), Some(200)));
            assert!(!running_parent_verified(Some(200), Some(201)));
            assert!(!running_parent_verified(None, Some(100)));
            assert!(!running_parent_verified(Some(200), None));
            assert!(!running_parent_verified(None, None));
        }

        /// Against the kernel: this test process is older than a child it
        /// spawns, so the child's parent pid verifies; the reverse does not.
        #[test]
        fn the_kernel_creation_times_verify_a_running_parent() {
            let own_created = process_creation_filetime(std::process::id());
            let mut child = std::process::Command::new("cmd")
                .args(["/c", "ping", "-n", "3", "127.0.0.1"])
                .stdout(std::process::Stdio::null())
                .spawn()
                .expect("spawn a child");
            let child_created = process_creation_filetime(child.id());
            assert!(running_parent_verified(child_created, own_created));
            assert!(!running_parent_verified(own_created, child_created));
            let _ = child.kill();
            let _ = child.wait();
        }

        /// Against the kernel: this test process is the parent of the child
        /// it spawns, and is refused as the parent of anything created before
        /// it (the shape of a successor holding a recycled parent pid).
        #[test]
        fn the_kernel_creation_time_tells_a_parent_from_a_successor() {
            let own = std::process::id();
            let own_created = process_creation_filetime(own).expect("own creation time");
            let mut child = std::process::Command::new("cmd")
                .args(["/c", "ping", "-n", "3", "127.0.0.1"])
                .stdout(std::process::Stdio::null())
                .spawn()
                .expect("spawn a child");
            let child_created = process_creation_filetime(child.id()).expect("child creation time");
            assert!(own_created <= child_created);
            let parent = query_image_path_created_by(own, child_created)
                .expect("the parent existed when the child was created");
            let own_exe = std::env::current_exe().unwrap();
            assert!(
                parent.eq_ignore_ascii_case(&own_exe.to_string_lossy()),
                "{parent} vs {own_exe:?}"
            );
            assert!(
                query_image_path_created_by(own, own_created - 1).is_none(),
                "a process younger than the child is not its parent"
            );
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Subtrees of the Windows directory that a standard (non-elevated) user
    /// can write to on a default Windows 10/11 install. `%SystemRoot%` as a
    /// whole is protected, but these leaf directories are created with ACLs
    /// that grant `BUILTIN\Users` / `NT AUTHORITY\Authenticated Users`
    /// create/write -- verifiable with `icacls` / `accesschk -w -d`, and the
    /// long-documented writable-`%WINDIR%` set used in DLL-search-order and
    /// privilege-escalation research. Paths are relative to the Windows
    /// directory, lowercased, `/`-separated, and matched as a prefix.
    ///
    /// Because a user can drop a binary here without elevation, an image
    /// under one of these does NOT count as OS-shipped: its path vouches for
    /// nothing. `serviceprofiles/` is writable by the LocalService /
    /// NetworkService accounts rather than an interactive user, but a helper
    /// a service unpacks there is likewise not something the path attests to,
    /// so it is treated the same way (conservative direction: fail toward
    /// NOT vouching).
    const USER_WRITABLE_WINDOWS_SUBTREES: &[&str] = &[
        "temp/",
        "tasks/",
        "tracing/",
        "debug/",
        "registration/crmlog/",
        "serviceprofiles/",
        "system32/tasks/",
        "system32/spool/drivers/color/",
        "system32/spool/printers/",
        "system32/fxstmp/",
        "system32/com/dmp/",
        "syswow64/tasks/",
        "syswow64/spool/drivers/color/",
        "syswow64/fxstmp/",
        "syswow64/com/dmp/",
    ];

    /// The portion of `p` (already lowercased, `/`-separated) below a Windows
    /// directory on any drive (`c:/windows/system32/csrss.exe` ->
    /// `system32/csrss.exe`), or `None` when `p` is not under one.
    fn windows_dir_relative(p: &str) -> Option<&str> {
        p.strip_prefix(|c: char| c.is_ascii_alphabetic())?
            .strip_prefix(":/windows/")
    }

    /// Windows has no kernel-vouched platform-binary fact; until the
    /// in-proc Authenticode check lands, an image under the Windows
    /// directory or the Defender platform roots counts as OS-shipped for
    /// the task-access stream. Interim and path-shaped by design -- the
    /// detector additionally requires `is_canonical_os_path`.
    ///
    /// The user-writable subtrees of `%SystemRoot%` are the one exception:
    /// an image sitting in `C:\Windows\Tasks`, `C:\Windows\Temp`, ... is
    /// under the Windows directory but was writable without elevation, so it
    /// is NOT treated as OS-shipped. Without this, an unsigned dumper staged
    /// in `C:\Windows\Tasks` opening lsass was pre-filtered out of the ring
    /// (mark set) and produced no finding.
    pub(crate) fn is_os_shipped_windows_image(path: &str) -> bool {
        let p = path.trim().to_ascii_lowercase().replace('\\', "/");
        if p.is_empty() {
            return false;
        }
        // Under the Windows directory (any drive): OS-shipped unless it sits
        // in a user-writable subtree of it.
        if let Some(win_relative) = windows_dir_relative(&p) {
            return !USER_WRITABLE_WINDOWS_SUBTREES
                .iter()
                .any(|sub| win_relative.starts_with(sub));
        }
        // Defender's engine lives outside %SystemRoot% but is OS-shipped
        // (c: only, as installed).
        const DEFENDER_ROOTS: [&str; 2] = [
            "c:/program files/windows defender/",
            "c:/programdata/microsoft/windows defender/",
        ];
        DEFENDER_ROOTS.iter().any(|r| p.starts_with(r))
    }

    #[cfg(test)]
    mod os_shipped_tests {
        use super::is_os_shipped_windows_image;

        #[test]
        fn windows_and_defender_roots_are_os_shipped() {
            assert!(is_os_shipped_windows_image(
                r"C:\Windows\System32\csrss.exe"
            ));
            assert!(is_os_shipped_windows_image(
                r"D:\WINDOWS\System32\lsass.exe"
            ));
            assert!(is_os_shipped_windows_image(
                r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe"
            ));
            assert!(is_os_shipped_windows_image(
                r"C:\Program Files\Windows Defender\MsMpEng.exe"
            ));
            // Non-writable %SystemRoot% content stays OS-shipped even when a
            // writable-subtree name appears deeper in the path.
            assert!(is_os_shipped_windows_image(
                r"C:\Windows\System32\svchost.exe"
            ));
            assert!(is_os_shipped_windows_image(
                r"C:\Windows\SysWOW64\ntdll.dll"
            ));
            assert!(is_os_shipped_windows_image(
                r"C:\Windows\System32\drivers\ndis.sys"
            ));
        }

        #[test]
        fn user_writable_windows_subtrees_are_not_os_shipped() {
            // The evasion this guards: a dumper staged in a user-writable
            // subtree of %SystemRoot% must NOT be marked OS-shipped, or the
            // read-grade ring pre-filter silently drops its open of lsass.
            for path in [
                r"C:\Windows\Tasks\dumper.exe",
                r"C:\Windows\Temp\stealer.exe",
                r"C:\Windows\Tracing\payload.exe",
                r"C:\Windows\debug\WIA\evil.exe",
                r"C:\Windows\Registration\CRMLog\evil.exe",
                r"C:\Windows\ServiceProfiles\LocalService\evil.exe",
                r"C:\Windows\System32\Tasks\evil.exe",
                r"C:\Windows\System32\spool\drivers\color\evil.exe",
                r"C:\Windows\System32\spool\PRINTERS\evil.exe",
                r"C:\Windows\System32\FxsTmp\evil.exe",
                r"C:\Windows\System32\com\dmp\evil.exe",
                r"C:\Windows\SysWOW64\Tasks\evil.exe",
                r"C:\Windows\SysWOW64\spool\drivers\color\evil.exe",
                // Any drive, mixed case, forward slashes all normalize.
                r"D:/WINDOWS/Temp/evil.exe",
            ] {
                assert!(
                    !is_os_shipped_windows_image(path),
                    "must not be OS-shipped: {path}"
                );
            }
        }

        #[test]
        fn non_windows_paths_are_not_os_shipped() {
            assert!(!is_os_shipped_windows_image(
                r"C:\Users\me\AppData\Local\Temp\stealer.exe"
            ));
            assert!(!is_os_shipped_windows_image(
                r"C:\Program Files\Python312\python.exe"
            ));
            // "windows" only as a non-root path segment does not qualify.
            assert!(!is_os_shipped_windows_image(
                r"C:\Users\me\windows\thing.exe"
            ));
            assert!(!is_os_shipped_windows_image(""));
        }
    }

    unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
        if record.is_null() {
            return;
        }
        let event = &*record;
        let header = &event.EventHeader;
        let provider = header.ProviderId;
        let opcode = header.EventDescriptor.Opcode;

        if provider == TCP_IP_GUID {
            handle_tcp_event(event, opcode);
        } else if provider == PROCESS_GUID {
            handle_process_event(event, opcode);
        } else if provider == FILEIO_GUID {
            handle_fileio_event(event, opcode);
        }
    }

    unsafe fn handle_tcp_event(event: &EVENT_RECORD, opcode: u8) {
        match opcode {
            EVENT_TRACE_TYPE_CONNECT | EVENT_TRACE_TYPE_ACCEPT | EVENT_TRACE_TYPE_RECONNECT => {
                let data_ptr = event.UserData;
                let data_len = event.UserDataLength as usize;

                if data_ptr.is_null() {
                    return;
                }

                // Determine IPv4 vs IPv6 from event version
                let version = event.EventHeader.EventDescriptor.Version;

                if version <= 1 && data_len >= std::mem::size_of::<TcpIpConnectV4>() {
                    let ev = &*(data_ptr as *const TcpIpConnectV4);
                    let src_ip = IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(ev.src_addr)));
                    let dst_ip = IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(ev.dst_addr)));
                    let src_port = u16::from_be(ev.src_port);
                    let dst_port = u16::from_be(ev.dst_port);
                    let pid = ev.pid;

                    if pid != 0 {
                        THREAD_CONNECTION_TABLE.with(|t| {
                            if let Some(table) = t.borrow().as_ref() {
                                table.insert(
                                    TcpConnectionKey {
                                        src_ip,
                                        src_port,
                                        dst_ip,
                                        dst_port,
                                    },
                                    pid,
                                );
                            }
                        });
                    }
                } else if version >= 2 && data_len >= std::mem::size_of::<TcpIpConnectV6>() {
                    let ev = &*(data_ptr as *const TcpIpConnectV6);
                    let src_ip = IpAddr::V6(std::net::Ipv6Addr::from(ev.src_addr));
                    let dst_ip = IpAddr::V6(std::net::Ipv6Addr::from(ev.dst_addr));
                    let src_port = u16::from_be(ev.src_port);
                    let dst_port = u16::from_be(ev.dst_port);
                    let pid = ev.pid;

                    if pid != 0 {
                        THREAD_CONNECTION_TABLE.with(|t| {
                            if let Some(table) = t.borrow().as_ref() {
                                table.insert(
                                    TcpConnectionKey {
                                        src_ip,
                                        src_port,
                                        dst_ip,
                                        dst_port,
                                    },
                                    pid,
                                );
                            }
                        });
                    }
                }
            }
            _ => {}
        }
    }

    /// What a `Process/Start` or `Process/DCStart` payload (MOF
    /// Process_TypeGroup1, shared by both) says about a process.
    struct DecodedProcess {
        pid: u32,
        ppid: u32,
        session_id: u32,
        process_name: String,
        image_path: String,
        argv_sha256: Option<String>,
    }

    unsafe fn decode_process_payload(event: &EVENT_RECORD) -> Option<DecodedProcess> {
        let data_ptr = event.UserData;
        let data_len = event.UserDataLength as usize;
        if data_ptr.is_null() || data_len < std::mem::size_of::<ProcessStartEvent>() {
            return None;
        }
        // Layout-aware decode (MOF Process_V3/V4, pointer size from
        // the header); the printable-run heuristics stay as a
        // fallback for kernels whose layout we have not seen.
        let full = std::slice::from_raw_parts(data_ptr as *const u8, data_len);
        let ptr_size = if (event.EventHeader.Flags as u32) & EVENT_HEADER_FLAG_32_BIT_HEADER != 0 {
            4
        } else {
            8
        };
        let version = event.EventHeader.EventDescriptor.Version;
        let parsed = crate::etw_process_payload::parse_process_start(full, version, ptr_size);
        let ev = &*(data_ptr as *const ProcessStartEvent);
        let (pid, ppid, session_id) = match parsed.as_ref() {
            Some(p) => (p.pid, p.ppid, p.session_id),
            None => (ev.pid, ev.ppid, ev.session_id),
        };

        let fixed_size = std::mem::size_of::<ProcessStartEvent>();
        let remaining_slice = &full[fixed_size.min(full.len())..];
        let (image_file_name, command_line) = match parsed.as_ref() {
            Some(p) if !p.image_file_name.is_empty() => (
                p.image_file_name.clone(),
                (!p.command_line.is_empty()).then(|| p.command_line.clone()),
            ),
            _ => (
                extract_image_path(remaining_slice),
                extract_command_line(remaining_slice),
            ),
        };
        // ImageFileName is usually a bare `image.exe`; the full path
        // comes from the command line's executable token or, while
        // the process is alive, from the kernel.
        let image_path = if image_file_name.contains('\\') || image_file_name.contains('/') {
            image_file_name.clone()
        } else {
            command_line
                .as_deref()
                .and_then(|cmd| {
                    crate::etw_process_payload::image_path_from_command_line(&image_file_name, cmd)
                })
                .or_else(|| query_image_path(pid))
                .unwrap_or_else(|| image_file_name.clone())
        };
        let process_name = std::path::Path::new(&image_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .filter(|n| !n.is_empty())
            .unwrap_or(image_file_name);
        let argv_sha256 = command_line.and_then(|cmd| proc_events::argv_digest(&[cmd]));
        Some(DecodedProcess {
            pid,
            ppid,
            session_id,
            process_name,
            image_path,
            argv_sha256,
        })
    }

    /// `Process/DCStart`: the rundown of a process that was already running
    /// when the session started. Its `Process/Start` is not in the stream, so
    /// without this record the ancestry of everything it starts afterwards
    /// stops one step short of it: the posture security gate's interpreter,
    /// started a few hundred milliseconds before the daemon's capture opened
    /// this session, never appeared above its own child (lineage gate,
    /// windows-x64, CI run 37342427407).
    ///
    /// A running process's parent pid is its creator's, recorded at creation
    /// and never updated: the creator may have exited long ago and its pid
    /// gone to a later process. It names the parent only when the process
    /// holding it now is no younger than this one (both creation times from
    /// the kernel); otherwise, or when either time cannot be read, the parent
    /// is unknown, never guessed (FP-WIN-29 class).
    unsafe fn handle_process_rundown(event: &EVENT_RECORD) {
        let Some(p) = decode_process_payload(event) else {
            return;
        };
        if p.pid == 0 || p.pid == GetCurrentProcessId() {
            return;
        }
        let created = process_creation_filetime(p.pid);
        let parent_verified = p.ppid != 0
            && p.ppid != p.pid
            && running_parent_verified(created, process_creation_filetime(p.ppid));
        let (ppid, parent_process_path) = if parent_verified {
            (
                Some(p.ppid),
                query_image_path(p.ppid).filter(|path| !path.is_empty()),
            )
        } else {
            (None, None)
        };
        THREAD_PROCESS_TABLE.with(|t| {
            if let Some(table) = t.borrow().as_ref() {
                proc_events::push(proc_events::ProcessEvent {
                    timestamp_ms: proc_events::now_ms(),
                    kind: proc_events::ProcessEventKind::Running,
                    pid: p.pid,
                    ppid,
                    uid: None,
                    process_name: p.process_name.clone(),
                    process_path: p.image_path.clone(),
                    parent_process_path,
                    argv_sha256: p.argv_sha256,
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
                // The attribution table was primed from a snapshot just before
                // the session started; it already holds this process (or a
                // Process/Start of it won the race). Only a gap is filled.
                table.entry(p.pid).or_insert_with(|| EtwProcessInfo {
                    pid: p.pid,
                    ppid: p.ppid,
                    process_name: p.process_name,
                    process_path: p.image_path,
                    username: String::new(),
                    session_id: p.session_id,
                    exit_code: None,
                    started_at: created.and_then(|t| i64::try_from(t).ok()),
                });
            }
        });
    }

    /// The parent pid of a process found running names its parent only when
    /// both creation times are known and the parent's is no later than the
    /// child's.
    fn running_parent_verified(child_created: Option<u64>, parent_created: Option<u64>) -> bool {
        matches!(
            (child_created, parent_created),
            (Some(child), Some(parent)) if occupant_predates(parent, child)
        )
    }

    unsafe fn handle_process_event(event: &EVENT_RECORD, opcode: u8) {
        let data_ptr = event.UserData;
        let data_len = event.UserDataLength as usize;

        if data_ptr.is_null() {
            return;
        }

        match opcode {
            EVENT_TRACE_TYPE_START => {
                let Some(DecodedProcess {
                    pid,
                    ppid,
                    session_id,
                    process_name,
                    image_path,
                    argv_sha256,
                }) = decode_process_payload(event)
                else {
                    return;
                };

                // Skip our own process
                let own_pid = GetCurrentProcessId();
                if pid == own_pid {
                    return;
                }

                // When the child came to exist: its own creation time while it
                // is alive (the same kernel clock as its parent's), else the
                // event's (system time: the session does not ask for raw
                // timestamps).
                let child_created = process_creation_filetime(pid).or_else(|| {
                    u64::try_from(event.EventHeader.TimeStamp)
                        .ok()
                        .filter(|t| *t > 0)
                });
                THREAD_PROCESS_TABLE.with(|t| {
                    if let Some(table) = t.borrow().as_ref() {
                        // The table is a pid -> image cache, and Windows
                        // recycles pids fast enough that a just-exited
                        // process can still hold the entry when its
                        // successor's child execs: an Azure
                        // `provjobd.exe<n>` under `\AppData\Local\Temp\`
                        // was attributed as the parent of cargo build
                        // scripts whose real parent is `cargo.exe`, and that
                        // Temp path then read as suspicious lineage on 48
                        // findings (`edamame_cli` Windows gate, 2026-09-18).
                        // Ask the kernel what currently owns the pid first;
                        // the cache is the fallback for a parent that has
                        // already exited.
                        //
                        // The kernel's answer is the pid's occupant NOW, which
                        // is the parent only if it already existed when the
                        // child was created: a launcher that exits right after
                        // CreateProcess frees its pid before this callback
                        // runs (the session delivers up to a second late), and
                        // the next process to take it is no parent (FP-WIN-29
                        // class). A later occupant is refused and the cache
                        // answers instead.
                        let parent_process_path = match child_created {
                            Some(child_created) => query_image_path_created_by(ppid, child_created),
                            None => query_image_path(ppid),
                        }
                        .filter(|path| !path.is_empty())
                        .or_else(|| {
                            table
                                .get(&ppid)
                                .map(|parent| parent.process_path.clone())
                                .filter(|path| !path.is_empty())
                        });
                        proc_events::push(proc_events::ProcessEvent {
                            timestamp_ms: proc_events::now_ms(),
                            kind: proc_events::ProcessEventKind::Exec,
                            pid,
                            ppid: Some(ppid),
                            uid: None,
                            process_name: process_name.clone(),
                            process_path: image_path.clone(),
                            parent_process_path,
                            argv_sha256: argv_sha256.clone(),
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
                        table.insert(
                            pid,
                            EtwProcessInfo {
                                pid,
                                ppid,
                                process_name,
                                process_path: image_path,
                                username: String::new(),
                                session_id,
                                exit_code: None,
                                // The Start event's own timestamp: the same
                                // clock as the FileIo events it is compared
                                // with, and earlier than any of them.
                                started_at: Some(event.EventHeader.TimeStamp).filter(|t| *t > 0),
                            },
                        );
                    }
                });
            }
            EVENT_TRACE_TYPE_DC_START => handle_process_rundown(event),
            EVENT_TRACE_TYPE_END => {
                if data_len < 8 {
                    return;
                }
                // Process/End has the same layout prefix; pid is at offset of the struct
                let ev = &*(data_ptr as *const ProcessStartEvent);
                let pid = ev.pid;

                THREAD_PROCESS_TABLE.with(|t| {
                    if let Some(table) = t.borrow().as_ref() {
                        if let Some((_, info)) = table.remove(&pid) {
                            proc_events::push(proc_events::ProcessEvent {
                                timestamp_ms: proc_events::now_ms(),
                                kind: proc_events::ProcessEventKind::Exit,
                                pid,
                                ppid: Some(info.ppid),
                                uid: None,
                                process_name: info.process_name,
                                process_path: info.process_path,
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
                            });
                        }
                    }
                });

                // Also clean up any connection table entries for this PID
                THREAD_CONNECTION_TABLE.with(|t| {
                    if let Some(table) = t.borrow().as_ref() {
                        table.retain(|_, v| *v != pid);
                    }
                });
            }
            _ => {}
        }
    }

    fn remember_file_object(file_object: u64, path: String) {
        THREAD_FILE_OBJECTS.with(|objects| {
            let mut objects = objects.borrow_mut();
            if objects.len() >= FILE_OBJECT_MAX_ENTRIES {
                let cutoff = Instant::now();
                objects.retain(|_, (_, seen)| {
                    cutoff.duration_since(*seen).as_secs() < FILE_OBJECT_TTL_SECS
                });
                if objects.len() >= FILE_OBJECT_MAX_ENTRIES {
                    return;
                }
            }
            objects.insert(file_object, (path, Instant::now()));
        });
    }

    fn take_file_object(file_object: u64) -> Option<String> {
        THREAD_FILE_OBJECTS
            .with(|objects| objects.borrow_mut().remove(&file_object).map(|(p, _)| p))
    }

    fn file_object_path(file_object: u64) -> Option<String> {
        THREAD_FILE_OBJECTS.with(|objects| {
            objects
                .borrow()
                .get(&file_object)
                .map(|(path, _)| path.clone())
        })
    }

    /// The attribution table a FileIo event feeds.
    #[derive(Clone, Copy)]
    enum FileActorTable {
        /// Who created, truncated or wrote a path.
        Write,
        /// Who deleted or renamed it.
        Namespace,
    }

    /// FileIo initiation events run in the calling process's context, so the
    /// header pid is the actor. Before 2026-09-08 every FileIo/Create -- a
    /// read-only open included -- overwrote the attribution table, so the
    /// last *reader* of a file became its writer (the FIM hash worker or any
    /// scanner replacing the real dropper). Now: a creating / truncating
    /// open records at once; a plain open is remembered by `FileObject` and
    /// recorded only when a FileIo/Write follows on that object.
    ///
    /// Deletes and renames go to the namespace table: FileIo/Delete and
    /// FileIo/Rename through the remembered object, FileIo/DeletePath and
    /// FileIo/RenamePath by name, and an open with `FILE_DELETE_ON_CLOSE`.
    /// Until 2026-10-06 they were dropped here, so the file monitor reported
    /// every Windows delete without a process: `git worktree remove` of a
    /// worktree in `%TEMP%` read as an unknown actor deleting its test and CI
    /// files during an agent session, which the divergence engine's
    /// evaluator-integrity policy raised as CRITICAL (FP lab run
    /// 37390270562, windows-x64), while the same scenario carried the
    /// remover on macOS (Endpoint Security UNLINK).
    unsafe fn handle_fileio_event(event: &EVENT_RECORD, opcode: u8) {
        use crate::etw_fileio_payload::{decode, FileIoAction};

        let data_ptr = event.UserData;
        let data_len = event.UserDataLength as usize;
        if data_ptr.is_null() || data_len == 0 {
            return;
        }

        let pid = event.EventHeader.ProcessId;
        if pid == 0 {
            return;
        }

        // Skip our own file I/O
        let own_pid = GetCurrentProcessId();
        if pid == own_pid {
            return;
        }

        let data = std::slice::from_raw_parts(data_ptr as *const u8, data_len);
        let ptr_size = if (event.EventHeader.Flags as u32) & EVENT_HEADER_FLAG_32_BIT_HEADER != 0 {
            4
        } else {
            8
        };
        let Some(action) = decode(opcode, data, ptr_size) else {
            return;
        };
        let at = Some(event.EventHeader.TimeStamp).filter(|t| *t > 0);

        match action {
            FileIoAction::Open {
                file_object,
                path,
                writes,
                deletes_on_close,
            } => {
                if let Some(file_object) = file_object {
                    remember_file_object(file_object, path.clone());
                }
                // BS-10: reads count too (an in-process key theft never
                // writes), so this does not depend on `writes`.
                // Every cold credential path is under a user profile; the
                // substring test (`credential_opens.windows_profile_marker`)
                // keeps label classification off the bulk of FileIo/Create
                // traffic (system DLLs, Program Files).
                let params = crate::sensitive_paths::credential_opens_params();
                let profile_marker = params.windows_profile_marker.as_str();
                if !profile_marker.is_empty()
                    && path.to_ascii_lowercase().contains(profile_marker)
                    && crate::credential_opens::is_cold_credential_path(&path)
                {
                    let process_path = THREAD_PROCESS_TABLE
                        .with(|pt| {
                            pt.borrow()
                                .as_ref()
                                .and_then(|t| t.get(&pid).map(|info| info.process_path.clone()))
                        })
                        .unwrap_or_default();
                    crate::credential_opens::record_open(
                        pid,
                        None,
                        &process_path,
                        &crate::win_path_normalize::nt_device_to_drive(&path),
                    );
                }
                if deletes_on_close {
                    record_file_actor(FileActorTable::Namespace, path.clone(), pid, at);
                }
                if writes {
                    record_file_actor(FileActorTable::Write, path, pid, at);
                }
            }
            FileIoAction::Write { file_object } => {
                if let Some(path) = file_object_path(file_object) {
                    record_file_actor(FileActorTable::Write, path, pid, at);
                }
            }
            FileIoAction::Release { file_object } => {
                let _ = take_file_object(file_object);
            }
            FileIoAction::Delete { file_object } | FileIoAction::Rename { file_object } => {
                if let Some(path) = file_object_path(file_object) {
                    record_file_actor(FileActorTable::Namespace, path, pid, at);
                }
            }
            FileIoAction::DeletePath { path, .. } => {
                record_file_actor(FileActorTable::Namespace, path, pid, at);
            }
            FileIoAction::RenamePath {
                file_object,
                new_path,
            } => {
                // The object still names the old path (FileIo/Rename records
                // it as well); from here on it names the new one, for a write
                // or a delete through it.
                if let Some(file_object) = file_object {
                    if let Some(old_path) = file_object_path(file_object) {
                        record_file_actor(FileActorTable::Namespace, old_path, pid, at);
                    }
                    remember_file_object(file_object, new_path.clone());
                }
                record_file_actor(FileActorTable::Namespace, new_path, pid, at);
            }
        }
    }

    fn record_file_actor(table: FileActorTable, path: String, pid: u32, at: Option<i64>) {
        // Same confinement as the macOS Endpoint Security path: the FileIo
        // session sees every file event on the machine, and the only readers
        // of these tables are `fim`'s kernel-table lookups, which are only
        // ever asked about paths under a FIM watch root.
        if !crate::fim_attribution::is_attributable(&path) {
            return;
        }

        THREAD_PROCESS_TABLE.with(|pt| {
            let pt = pt.borrow();
            let Some(proc_table) = pt.as_ref() else {
                return;
            };
            match table {
                FileActorTable::Write => THREAD_FILE_TABLE.with(|ft| {
                    THREAD_FILE_COUNTER.with(|fc| {
                        if let (Some(file_table), Some(file_counter)) =
                            (ft.borrow().as_ref(), fc.borrow().as_ref())
                        {
                            FlodbaddL7Etw::record_file_attribution(
                                file_table,
                                file_counter,
                                proc_table,
                                path,
                                pid,
                                at,
                            );
                        }
                    })
                }),
                FileActorTable::Namespace => THREAD_NAMESPACE_TABLE.with(|nt| {
                    if let Some(namespace_table) = nt.borrow().as_ref() {
                        FlodbaddL7Etw::record_file_attribution(
                            namespace_table,
                            &NAMESPACE_INSERTS,
                            proc_table,
                            path,
                            pid,
                            at,
                        );
                    }
                }),
            }
        });
    }

    fn extract_image_path(data: &[u8]) -> String {
        // The process image filename in kernel trace events is typically
        // a null-terminated ANSI string after the SID.
        // Try to find a printable ASCII sequence ending in null.
        if let Some(null_pos) = data.iter().position(|&b| b == 0) {
            if null_pos > 0 {
                let slice = &data[..null_pos];
                if slice.iter().all(|&b| b >= 0x20 && b < 0x7F) {
                    return String::from_utf8_lossy(slice).to_string();
                }
            }
        }
        // Fallback: try interpreting the whole buffer
        let s: String = data
            .iter()
            .take_while(|&&b| b >= 0x20 && b < 0x7F)
            .map(|&b| b as char)
            .collect();
        s
    }

    /// Best-effort CommandLine extraction from a `Process/Start`
    /// payload (FLODBADD2 §1b.2, monitoring role). The V3+ classic
    /// layout places a UTF-16LE null-terminated CommandLine after the
    /// ANSI ImageFileName; older layouts do not carry one, and the SID
    /// padding makes the wide string's alignment unreliable -- so both
    /// byte offsets are tried and the result is discarded unless it
    /// decodes as plausible text. `None` = unmeasured, never fabricated.
    fn extract_command_line(data: &[u8]) -> Option<String> {
        let null_pos = data.iter().position(|&b| b == 0)?;
        let mut rest = &data[null_pos + 1..];
        while rest.first() == Some(&0) {
            rest = &rest[1..];
        }
        if rest.len() < 4 {
            return None;
        }
        for offset in 0..=1usize {
            if rest.len() <= offset {
                break;
            }
            if let Some(cmd) = decode_wide_cstring(&rest[offset..]) {
                return Some(cmd);
            }
        }
        None
    }

    fn decode_wide_cstring(bytes: &[u8]) -> Option<String> {
        let mut wide: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
        for chunk in bytes.chunks_exact(2) {
            let ch = u16::from_le_bytes([chunk[0], chunk[1]]);
            if ch == 0 {
                break;
            }
            wide.push(ch);
        }
        if wide.len() < 2 {
            return None;
        }
        let text = String::from_utf16_lossy(&wide);
        let total = text.chars().count();
        let printable = text
            .chars()
            .filter(|c| !c.is_control() && *c != '\u{FFFD}')
            .count();
        // >= 90% printable and no replacement chars in the first token:
        // the plausibility bar that separates a real command line from
        // mis-aligned binary tail bytes.
        if total == 0 || printable * 10 < total * 9 {
            return None;
        }
        let trimmed = text.trim().to_string();
        (!trimmed.is_empty()).then_some(trimmed)
    }

    unsafe impl Send for FlodbaddL7Etw {}
    unsafe impl Sync for FlodbaddL7Etw {}

    static INSTANCE: OnceCell<FlodbaddL7Etw> = OnceCell::new();

    pub fn global() -> &'static FlodbaddL7Etw {
        INSTANCE.get_or_init(FlodbaddL7Etw::init)
    }

    pub fn get_init_status() -> &'static str {
        global().init_status()
    }

    /// Set by `shutdown`: no session starts after it, and a session that was
    /// starting while it ran stops itself (`SessionControl::started`).
    static SHUTDOWN: AtomicBool = AtomicBool::new(false);
    static KERNEL_SESSION: SessionControl = SessionControl::new();
    static AUDIT_SESSION: SessionControl = SessionControl::new();

    /// One trace session this process started. ETW sessions are kernel
    /// objects that outlive the process that started them: a real-time
    /// session nobody stops keeps producing events for no consumer until the
    /// machine reboots, and the NT Kernel Logger stays taken.
    struct SessionControl {
        /// `CONTROLTRACE_HANDLE` returned by our `StartTraceW`.
        handle: AtomicU64,
        /// From our `StartTraceW` until our `ProcessTrace` returns. Cleared
        /// as soon as the session ends, whoever ended it, so `shutdown`
        /// never stops a session that a later EDAMAME process has started
        /// under the same name.
        live: AtomicBool,
    }

    impl SessionControl {
        const fn new() -> Self {
            Self {
                handle: AtomicU64::new(0),
                live: AtomicBool::new(false),
            }
        }

        /// Record a session this process just started. `false` when
        /// `shutdown` already ran: the caller stops the session at once.
        /// `live` is published before `SHUTDOWN` is read, and `shutdown`
        /// sets `SHUTDOWN` before reading `live`, so one of the two always
        /// sees the other and the session cannot outlive a shutdown.
        fn started(&self, handle: CONTROLTRACE_HANDLE) -> bool {
            self.handle.store(handle.Value, Ordering::SeqCst);
            self.live.store(true, Ordering::SeqCst);
            !SHUTDOWN.load(Ordering::SeqCst)
        }

        fn ended(&self) {
            self.live.store(false, Ordering::SeqCst);
        }

        /// Stop the session if this process still runs it. Returns whether a
        /// stop was issued.
        fn stop_if_live(&self, kernel_logger: bool) -> bool {
            if !self.live.swap(false, Ordering::SeqCst) {
                return false;
            }
            let handle = CONTROLTRACE_HANDLE {
                Value: self.handle.load(Ordering::SeqCst),
            };
            // Stop by handle, not by name: the name is shared with every
            // other EDAMAME process on the host. The properties buffer only
            // receives the final session statistics.
            let buf_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 1024;
            let mut buf = vec![0u8; buf_size];
            // SAFETY: `buf` is sized and zeroed for an EVENT_TRACE_PROPERTIES
            // plus the logger-name area ControlTraceW may write back.
            let status = unsafe {
                let props = &mut *(buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
                props.Wnode.BufferSize = buf_size as u32;
                if kernel_logger {
                    props.Wnode.Guid = SYSTEM_TRACE_CONTROL_GUID;
                }
                props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
                ControlTraceW(handle, PCWSTR::null(), props, EVENT_TRACE_CONTROL_STOP)
            };
            if status.is_err() {
                debug!(
                    "ETW: stopping session {:#x} returned {:?}",
                    handle.Value, status
                );
            }
            true
        }
    }

    /// Stop the kernel trace session and the audit-API-calls session this
    /// process started, so they do not outlive it. Idempotent and final:
    /// nothing restarts them in this process, and `is_available` reads
    /// `false` afterwards. Does not initialize ETW when it never ran.
    pub fn shutdown() {
        if SHUTDOWN.swap(true, Ordering::SeqCst) {
            return;
        }
        let kernel = KERNEL_SESSION.stop_if_live(true);
        let audit = AUDIT_SESSION.stop_if_live(false);
        if let Some(instance) = INSTANCE.get() {
            instance.available.store(false, Ordering::Release);
        }
        if kernel || audit {
            info!(
                "ETW sessions stopped on shutdown (kernel trace: {}, audit-api-calls: {})",
                kernel, audit
            );
        }
    }

    extern "C" {
        fn atexit(callback: extern "C" fn()) -> std::os::raw::c_int;
    }

    extern "C" fn shutdown_at_exit() {
        shutdown();
    }
}

#[cfg(not(all(target_os = "windows", feature = "etw")))]
mod win {
    #![allow(dead_code)]
    use super::*;

    #[derive(Clone, Debug)]
    pub struct EtwProcessInfo;

    pub struct FlodbaddL7Etw;

    impl FlodbaddL7Etw {
        pub fn get_l7_for_session(&self, _session: &Session) -> Option<SessionL7> {
            None
        }

        pub fn enrich_session_l7(&self, _pid: u32, _base_l7: &mut SessionL7) {}

        pub fn is_available(&self) -> bool {
            false
        }

        pub fn init_status(&self) -> &str {
            "Not available: ETW requires Windows with 'etw' feature"
        }

        pub fn process_count(&self) -> usize {
            0
        }

        pub fn connection_count(&self) -> usize {
            0
        }

        pub fn get_file_attribution(&self, _path: &str) -> Option<(u32, String, String)> {
            None
        }

        pub fn get_file_namespace_attribution(&self, _path: &str) -> Option<(u32, String, String)> {
            None
        }

        pub fn file_attribution_count(&self) -> usize {
            0
        }

        pub fn file_event_stats(&self) -> u64 {
            0
        }
    }

    pub fn global() -> &'static FlodbaddL7Etw {
        static INSTANCE: FlodbaddL7Etw = FlodbaddL7Etw;
        &INSTANCE
    }

    pub fn get_init_status() -> &'static str {
        global().init_status()
    }

    pub fn shutdown() {}
}

pub use win::EtwProcessInfo;

/// Stop the ETW trace sessions this process started (Windows with the `etw`
/// feature; a no-op elsewhere). ETW sessions are kernel objects that outlive
/// their process, so a host that ends with `std::process::exit` -- which
/// bypasses the CRT exit hook registered when the sessions start -- calls
/// this on its shutdown path. Idempotent and final for the process.
pub fn shutdown() {
    win::shutdown();
}

pub fn get_l7_for_session(session: &Session) -> Option<SessionL7> {
    win::global().get_l7_for_session(session)
}

pub fn enrich_session_l7(pid: u32, base_l7: &mut SessionL7) {
    win::global().enrich_session_l7(pid, base_l7);
}

pub fn is_available() -> bool {
    #[cfg(all(target_os = "windows", feature = "etw"))]
    {
        win::global().is_available()
    }

    #[cfg(not(all(target_os = "windows", feature = "etw")))]
    {
        false
    }
}

pub fn init_and_log_status() {
    let available = is_available();
    if available {
        info!("ETW L7 process tracking is ENABLED - connection-to-PID mapping via kernel trace");
    } else {
        #[cfg(all(target_os = "windows", feature = "etw"))]
        {
            tracing::warn!(
                "ETW L7 process tracking is DISABLED - falling back to netstat-based resolution"
            );
        }
        #[cfg(not(all(target_os = "windows", feature = "etw")))]
        {
            info!(
                "ETW L7 process tracking not available on this platform (non-Windows or feature disabled)"
            );
        }
    }
}

pub fn etw_support() -> String {
    #[cfg(not(target_os = "windows"))]
    {
        return "Not supported: ETW requires Windows".to_string();
    }

    #[cfg(all(target_os = "windows", not(feature = "etw")))]
    {
        return "Not enabled: compiled without 'etw' feature flag".to_string();
    }

    #[cfg(all(target_os = "windows", feature = "etw"))]
    {
        win::get_init_status().to_string()
    }
}

pub fn process_count() -> usize {
    win::global().process_count()
}

pub fn connection_count() -> usize {
    win::global().connection_count()
}

/// Who last created, truncated or wrote `path`, seen by the FileIo session
/// within the table's TTL: `(pid, process_name, process_path)`.
pub fn get_file_attribution(path: &str) -> Option<(u32, String, String)> {
    win::global().get_file_attribution(path)
}

/// Who last deleted or renamed `path` -- for a rename, the old name and the
/// new one both answer -- seen by the FileIo session within the table's TTL:
/// `(pid, process_name, process_path)`. Never the path's writer: a delete
/// looked up in the write table would name whoever wrote the file, a
/// different process whenever one tool lays a tree down and another removes
/// it (`git worktree add` / `git worktree remove`).
pub fn get_file_namespace_attribution(path: &str) -> Option<(u32, String, String)> {
    win::global().get_file_namespace_attribution(path)
}

pub fn file_attribution_count() -> usize {
    win::global().file_attribution_count()
}

pub fn file_event_stats() -> u64 {
    win::global().file_event_stats()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::Protocol;
    use std::net::IpAddr;
    use std::str::FromStr;

    const CREATE_THREAD: u32 = 0x0002;
    const VM_OPERATION: u32 = 0x0008;
    const VM_READ: u32 = 0x0010;
    const VM_WRITE: u32 = 0x0020;
    const DUP_HANDLE: u32 = 0x0040;
    const TERMINATE: u32 = 0x0001;
    const QUERY_INFORMATION: u32 = 0x0400;
    const QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const READ: Option<u32> = Some(1);
    const ATTACH: Option<u32> = Some(2);

    /// The PTRACE_MODE mapping is the measurement the memory-scrape check
    /// grades on. Runs on every host: the mapping is pure, and a regression
    /// here otherwise shows only on a Windows CI gate as a CRITICAL.
    #[test]
    fn all_access_is_one_blanket_ask_whatever_the_sdk_calls_it() {
        use super::task_access_mode_for_desired_access as grade;
        // Vista+ `PROCESS_ALL_ACCESS` (.NET Core, native code built with a
        // current SDK) and the legacy value .NET Framework still sends
        // (Chocolatey's `Process.Handle`). Both are READ, never ATTACH: the
        // legacy one graded ATTACH until 2026-09-29, so the detector's read
        // relief could never apply to choco.exe on the Windows CI gates.
        const ALL_ACCESS_VISTA: u32 = 0x001F_FFFF;
        const ALL_ACCESS_LEGACY: u32 = 0x001F_0FFF;
        assert_eq!(grade(ALL_ACCESS_VISTA), READ);
        assert_eq!(grade(ALL_ACCESS_LEGACY), READ);
        assert_eq!(grade(ALL_ACCESS_LEGACY | QUERY_LIMITED_INFORMATION), READ);
        // The generic and special spellings of the same ask are not
        // forwarded (conhost and Firefox's crashhelper send them; see the
        // grader's doc).
        const GENERIC_ALL: u32 = 0x1000_0000;
        const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
        assert_eq!(grade(GENERIC_ALL), None);
        assert_eq!(grade(MAXIMUM_ALLOWED), None);
        assert_eq!(grade(MAXIMUM_ALLOWED | SYNCHRONIZE), None);
        // One right short of the blanket ask is a chosen set, and a chosen
        // set carrying VM_WRITE is an attach.
        assert_eq!(grade(ALL_ACCESS_LEGACY & !TERMINATE), ATTACH);
    }

    #[test]
    fn read_and_query_masks_grade_read_and_query_only_is_not_forwarded() {
        use super::task_access_mode_for_desired_access as grade;
        // VM_READ with or without query rights: the read-only task-port shape
        // (`Process.MainModule`, psapi `GetModuleFileNameEx`, psutil).
        assert_eq!(grade(VM_READ), READ);
        assert_eq!(grade(VM_READ | QUERY_INFORMATION), READ);
        assert_eq!(grade(VM_READ | QUERY_LIMITED_INFORMATION), READ);
        assert_eq!(grade(VM_READ | QUERY_INFORMATION | SYNCHRONIZE), READ);
        // Handle duplication with VM_READ is still a read.
        assert_eq!(grade(VM_READ | DUP_HANDLE), READ);
        // `GENERIC_READ` alone is not expanded.
        assert_eq!(grade(0x8000_0000), None);
        // Query-only opens (every process lister, Task Manager, sysinfo) and
        // handle duplication alone are never forwarded.
        assert_eq!(grade(QUERY_INFORMATION), None);
        assert_eq!(grade(QUERY_LIMITED_INFORMATION), None);
        assert_eq!(grade(QUERY_LIMITED_INFORMATION | SYNCHRONIZE), None);
        assert_eq!(
            grade(QUERY_LIMITED_INFORMATION | SYNCHRONIZE | TERMINATE),
            None
        );
        assert_eq!(grade(DUP_HANDLE), None);
        // `GENERIC_EXECUTE` maps onto SYNCHRONIZE-level rights only.
        assert_eq!(grade(0x2000_0000), None);
        assert_eq!(grade(0), None);
    }

    #[test]
    fn debugger_grade_rights_stay_attach() {
        use super::task_access_mode_for_desired_access as grade;
        assert_eq!(grade(VM_WRITE), ATTACH);
        assert_eq!(grade(VM_OPERATION), ATTACH);
        assert_eq!(grade(CREATE_THREAD), ATTACH);
        assert_eq!(grade(VM_READ | VM_WRITE), ATTACH);
        // The classic CreateRemoteThread injection mask.
        assert_eq!(
            grade(CREATE_THREAD | QUERY_INFORMATION | VM_OPERATION | VM_WRITE | VM_READ),
            ATTACH
        );
        // `GENERIC_WRITE` alone is not expanded.
        assert_eq!(grade(0x4000_0000), None);
    }

    /// A successor on a recycled pid must not lend its identity to its
    /// predecessor's file operation; an unknown time keeps the occupant.
    #[test]
    fn a_file_event_older_than_the_pid_occupant_is_not_the_occupants() {
        assert!(file_event_predates_process(Some(100), Some(101)));
        assert!(!file_event_predates_process(Some(101), Some(101)));
        assert!(!file_event_predates_process(Some(102), Some(101)));
        assert!(!file_event_predates_process(None, Some(101)));
        assert!(!file_event_predates_process(Some(100), None));
        assert!(!file_event_predates_process(None, None));
    }

    #[test]
    fn test_etw_returns_none_without_session() {
        let session = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::from_str("127.0.0.1").unwrap(),
            src_port: 12345,
            dst_ip: IpAddr::from_str("127.0.0.1").unwrap(),
            dst_port: 80,
        };
        assert!(get_l7_for_session(&session).is_none());
    }

    #[test]
    fn test_etw_support_string() {
        let support = etw_support();
        assert!(!support.is_empty());
    }
}
