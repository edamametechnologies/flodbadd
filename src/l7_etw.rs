// Windows ETW (Event Tracing for Windows) process and file attribution.
//
// Uses the Windows kernel ETW providers (Microsoft-Windows-Kernel-Process,
// TCP/IP, and FileIo) to maintain:
//   1. A live process table populated by kernel Process Start/End events.
//   2. A connection-to-PID map from TCP/IP Connect/Accept events.
//   3. A file attribution table populated by FileIo Create events, mapping
//      recently-opened file paths to the responsible process.
//
// The file attribution table is the Windows counterpart of the ES file
// attribution table on macOS (l7_es.rs).  It is consumed by the FIM
// subsystem in fim.rs to attribute file events to processes at kernel-
// delivered time, avoiding the race conditions inherent in polling.
//
// On non-Windows platforms or when the `etw` feature is not enabled,
// all public functions gracefully fall back to no-op stubs so the rest of
// the codebase does not need to care whether ETW is available.

use crate::sessions::{Session, SessionL7};
#[cfg(all(target_os = "windows", feature = "etw"))]
use crate::win_path_normalize::normalize_win_path;
use tracing::info;

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

    // FileIo event opcodes (all delivered by EVENT_TRACE_FLAG_FILE_IO_INIT,
    // i.e. initiation events in the caller's process context)
    const FILEIO_CREATE: u8 = 64; // FileIo/Create -- file open or create with full path
    const FILEIO_CLEANUP: u8 = 65; // FileIo/Cleanup -- last handle closed
    const FILEIO_CLOSE: u8 = 66; // FileIo/Close -- file object released
    const FILEIO_WRITE: u8 = 68; // FileIo/Write -- write initiation on an open file object

    // FileIo/Create `CreateOptions` carries the NT create disposition in its
    // top byte; these dispositions create or truncate the file, so the open
    // itself is a write even when no FileIo/Write follows.
    const FILE_SUPERSEDE: u32 = 0;
    const FILE_CREATE: u32 = 2;
    const FILE_OVERWRITE: u32 = 4;
    const FILE_OVERWRITE_IF: u32 = 5;

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
    /// `TargetProcessId: u32, DesiredAccess: u32, ReturnCode: u32`.
    const AUDIT_EVENT_PS_OPEN_PROCESS: u16 = 5;
    // PROCESS_* access rights (winnt.h). The PTRACE_MODE vocabulary the
    // detector shares across backends maps onto the mask like this:
    //   ATTACH (2): VM_WRITE / VM_OPERATION / CREATE_THREAD / ALL_ACCESS --
    //               the debugger-grade opens (task_for_pid / ptrace attach)
    //   READ   (1): VM_READ without any of the above -- the read-only task
    //               port shape (macOS GET_TASK_READ), which updaters, crash
    //               handlers and process monitors take on every process
    //   neither   : query-only opens, never forwarded
    // Before 2026-09-08 VM_READ alone was ATTACH-grade, so Google Updater
    // reading svchost graded like a scraper on the idle baseline.
    const PROCESS_CREATE_THREAD: u32 = 0x0002;
    const PROCESS_VM_OPERATION: u32 = 0x0008;
    const PROCESS_VM_READ: u32 = 0x0010;
    const PROCESS_VM_WRITE: u32 = 0x0020;
    const PROCESS_ALL_ACCESS_MASK: u32 = 0x001F_FFFF;

    // File attribution table limits -- same as ES on macOS (l7_es.rs)
    const FILE_ATTR_MAX_ENTRIES: usize = 50_000;
    const FILE_ATTR_TTL_SECS: u64 = 30;
    const FILE_ATTR_PRUNE_INTERVAL: u64 = 1_000;

    // Fixed-size prefix of the FileIo_Create payload (64-bit Windows):
    //   IrpPtr(8) + FileObject(8) + TTID(4) + CreateOptions(4) +
    //   FileAttributes(4) + ShareAccess(4) = 32 bytes
    // OpenPath (variable-length UTF-16) follows immediately.
    const FILEIO_CREATE_FIXED_PREFIX: usize = 32;
    const FILEIO_CREATE_FILE_OBJECT_OFFSET: usize = 8;
    const FILEIO_CREATE_OPTIONS_OFFSET: usize = 20;
    // FileIo_ReadWrite (64-bit): Offset(8) + IrpPtr(8) + FileObject(8) +
    // FileKey(8) + TTID(4) + IoSize(4) + IoFlags(4)
    const FILEIO_READWRITE_FILE_OBJECT_OFFSET: usize = 16;
    const FILEIO_READWRITE_MIN_LEN: usize = 24;
    // FileIo_SimpleOp (64-bit): IrpPtr(8) + FileObject(8) + FileKey(8) + TTID(4)
    const FILEIO_SIMPLEOP_FILE_OBJECT_OFFSET: usize = 8;
    const FILEIO_SIMPLEOP_MIN_LEN: usize = 16;

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
            let file_insert_counter = Arc::new(AtomicU64::new(0));
            let file_event_counters = Arc::new(FileEventCounters::default());
            let available = Arc::new(AtomicBool::new(false));

            let pt = Arc::clone(&process_table);
            let ct = Arc::clone(&connection_table);
            let ft = Arc::clone(&file_attribution_table);
            let fc = Arc::clone(&file_insert_counter);
            let av = Arc::clone(&available);

            if let Err(e) = std::thread::Builder::new()
                .name("etw-client".into())
                .spawn(move || {
                    Self::run_etw_session(pt, ct, ft, fc, av);
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
            file_counter: Arc<AtomicU64>,
            available: Arc<AtomicBool>,
        ) {
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
                // Write=68, ...) in the caller's context; `handle_fileio_event`
                // consumes Create/Write/Cleanup/Close and drops the rest at the
                // opcode check.
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
            // The lookup key is the canonical form. Callers from the
            // `notify` side typically supply Win32-shaped paths
            // (`C:\Users\...`), while ETW recorded NT-object paths
            // (`\Device\HarddiskVolume3\Users\...`). Both sides are
            // normalized through `normalize_win_path` so they collide
            // on a single key.
            let key = normalize_win_path(path);
            let entry = self.file_attribution_table.get(&key)?;
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

        fn record_file_attribution(
            file_table: &DashMap<String, FimEtwAttribution>,
            file_counter: &AtomicU64,
            process_table: &DashMap<u32, EtwProcessInfo>,
            path: String,
            pid: u32,
        ) {
            let (process_name, process_path) = if let Some(info) = process_table.get(&pid) {
                (info.process_name.clone(), info.process_path.clone())
            } else {
                (format!("pid-{}", pid), String::new())
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
        // Only the ProcessTrace thread touches it: no lock needed.
        static THREAD_FILE_OBJECTS: std::cell::RefCell<std::collections::HashMap<u64, (String, Instant)>> =
            std::cell::RefCell::new(std::collections::HashMap::new());
    }

    /// `Microsoft-Windows-Kernel-Audit-API-Calls` callback (audit session
    /// thread). Only `PsOpenProcess` with an ATTACH-grade access mask is
    /// forwarded, as a `TaskAccess` ring event carrying the requester (the
    /// event header's process) and the target from the payload; both images
    /// come from the ETW process table primed at start.
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
        let attach_grade =
            desired_access & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD) != 0
                || desired_access & PROCESS_ALL_ACCESS_MASK == PROCESS_ALL_ACCESS_MASK;
        let read_grade = !attach_grade && desired_access & PROCESS_VM_READ != 0;
        if !attach_grade && !read_grade {
            return;
        }
        let task_access_mode = if attach_grade { 2 } else { 1 };
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
                let path_marked = is_os_shipped_windows_image(&requester_path);
                // Read-grade opens by OS-shipped requesters (csrss, lsass,
                // svchost, MsMpEng, ...) are the constant background the
                // detector drops anyway; keep them out of the ring. The mark
                // rides the event as `platform_path_marked`, never as
                // `is_platform_binary`: a path is not a kernel fact.
                if !attach_grade && path_marked {
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

    /// Windows has no kernel-vouched platform-binary fact; until the
    /// in-proc Authenticode check lands, an image under the Windows
    /// directory or the Defender platform roots counts as OS-shipped for
    /// the task-access stream. Interim and path-shaped by design -- the
    /// detector additionally requires `is_canonical_os_path`.
    pub(crate) fn is_os_shipped_windows_image(path: &str) -> bool {
        let p = path.trim().to_ascii_lowercase().replace('\\', "/");
        if p.is_empty() {
            return false;
        }
        let roots = [
            "c:/windows/",
            "c:/program files/windows defender/",
            "c:/programdata/microsoft/windows defender/",
        ];
        // Any drive letter for the Windows directory (`d:/windows/...`).
        let other_drive = p.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && p.get(1..)
                .is_some_and(|rest| rest.starts_with(":/windows/"));
        roots.iter().any(|r| p.starts_with(r)) || other_drive
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
            assert!(!is_os_shipped_windows_image(
                r"C:\Users\me\AppData\Local\Temp\stealer.exe"
            ));
            assert!(!is_os_shipped_windows_image(
                r"C:\Program Files\Python312\python.exe"
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

    unsafe fn handle_process_event(event: &EVENT_RECORD, opcode: u8) {
        let data_ptr = event.UserData;
        let data_len = event.UserDataLength as usize;

        if data_ptr.is_null() {
            return;
        }

        match opcode {
            EVENT_TRACE_TYPE_START => {
                if data_len < std::mem::size_of::<ProcessStartEvent>() {
                    return;
                }
                // Layout-aware decode (MOF Process_V3/V4, pointer size from
                // the header); the printable-run heuristics stay as a
                // fallback for kernels whose layout we have not seen.
                let full = std::slice::from_raw_parts(data_ptr as *const u8, data_len);
                let ptr_size =
                    if (event.EventHeader.Flags as u32) & EVENT_HEADER_FLAG_32_BIT_HEADER != 0 {
                        4
                    } else {
                        8
                    };
                let version = event.EventHeader.EventDescriptor.Version;
                let parsed =
                    crate::etw_process_payload::parse_process_start(full, version, ptr_size);
                let ev = &*(data_ptr as *const ProcessStartEvent);
                let (pid, ppid, session_id) = match parsed.as_ref() {
                    Some(p) => (p.pid, p.ppid, p.session_id),
                    None => (ev.pid, ev.ppid, ev.session_id),
                };

                // Skip our own process
                let own_pid = GetCurrentProcessId();
                if pid == own_pid {
                    return;
                }

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
                let image_path = if image_file_name.contains('\\') || image_file_name.contains('/')
                {
                    image_file_name.clone()
                } else {
                    command_line
                        .as_deref()
                        .and_then(|cmd| {
                            crate::etw_process_payload::image_path_from_command_line(
                                &image_file_name,
                                cmd,
                            )
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

                THREAD_PROCESS_TABLE.with(|t| {
                    if let Some(table) = t.borrow().as_ref() {
                        let parent_process_path = table
                            .get(&ppid)
                            .map(|parent| parent.process_path.clone())
                            .filter(|path| !path.is_empty());
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
                            },
                        );
                    }
                });
            }
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

    fn read_u64_at(data: &[u8], off: usize) -> Option<u64> {
        data.get(off..off + 8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    fn read_u32_at(data: &[u8], off: usize) -> Option<u32> {
        data.get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Whether a FileIo/Create with this `CreateOptions` value creates or
    /// truncates the target (a write in itself).
    pub(crate) fn create_disposition_is_write(create_options: u32) -> bool {
        matches!(
            create_options >> 24,
            FILE_SUPERSEDE | FILE_CREATE | FILE_OVERWRITE | FILE_OVERWRITE_IF
        )
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

    /// FileIo initiation events run in the calling process's context, so the
    /// header pid is the actor. Before 2026-09-08 every FileIo/Create -- a
    /// read-only open included -- overwrote the attribution table, so the
    /// last *reader* of a file became its writer (the FIM hash worker or any
    /// scanner replacing the real dropper). Now: a creating / truncating
    /// open records at once; a plain open is remembered by `FileObject` and
    /// recorded only when a FileIo/Write follows on that object.
    unsafe fn handle_fileio_event(event: &EVENT_RECORD, opcode: u8) {
        if !matches!(
            opcode,
            FILEIO_CREATE | FILEIO_WRITE | FILEIO_CLEANUP | FILEIO_CLOSE
        ) {
            return;
        }

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

        let path = match opcode {
            FILEIO_CREATE => {
                if data_len <= FILEIO_CREATE_FIXED_PREFIX {
                    return;
                }
                // OpenPath starts after the fixed prefix as a null-terminated UTF-16 string
                let path_ptr =
                    (data_ptr as *const u8).add(FILEIO_CREATE_FIXED_PREFIX) as *const u16;
                let path_max_u16 = (data_len - FILEIO_CREATE_FIXED_PREFIX) / 2;
                let path_slice = std::slice::from_raw_parts(path_ptr, path_max_u16);
                let path = extract_utf16_path(path_slice);
                if path.is_empty() {
                    return;
                }
                let file_object = read_u64_at(data, FILEIO_CREATE_FILE_OBJECT_OFFSET);
                let create_options = read_u32_at(data, FILEIO_CREATE_OPTIONS_OFFSET);
                if let Some(file_object) = file_object {
                    remember_file_object(file_object, path.clone());
                }
                if !create_options.is_some_and(create_disposition_is_write) {
                    return;
                }
                path
            }
            FILEIO_WRITE => {
                if data_len < FILEIO_READWRITE_MIN_LEN {
                    return;
                }
                let Some(file_object) = read_u64_at(data, FILEIO_READWRITE_FILE_OBJECT_OFFSET)
                else {
                    return;
                };
                let Some(path) = file_object_path(file_object) else {
                    return;
                };
                path
            }
            _ => {
                if data_len >= FILEIO_SIMPLEOP_MIN_LEN {
                    if let Some(file_object) = read_u64_at(data, FILEIO_SIMPLEOP_FILE_OBJECT_OFFSET)
                    {
                        let _ = take_file_object(file_object);
                    }
                }
                return;
            }
        };

        // Same confinement as the macOS Endpoint Security path: the FileIo
        // session sees every file event on the machine, and the only reader of
        // this table is `fim::kernel_table_attribution`, which is only ever
        // asked about paths under a FIM watch root.
        if !crate::fim_attribution::is_attributable(&path) {
            return;
        }

        THREAD_FILE_TABLE.with(|ft| {
            THREAD_FILE_COUNTER.with(|fc| {
                THREAD_PROCESS_TABLE.with(|pt| {
                    if let (Some(file_table), Some(file_counter), Some(proc_table)) = (
                        ft.borrow().as_ref(),
                        fc.borrow().as_ref(),
                        pt.borrow().as_ref(),
                    ) {
                        FlodbaddL7Etw::record_file_attribution(
                            file_table,
                            file_counter,
                            proc_table,
                            path,
                            pid,
                        );
                    }
                });
            });
        });
    }

    fn extract_utf16_path(data: &[u16]) -> String {
        let len = data.iter().position(|&c| c == 0).unwrap_or(data.len());
        if len == 0 {
            return String::new();
        }
        String::from_utf16_lossy(&data[..len])
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

    pub fn global() -> &'static FlodbaddL7Etw {
        static INSTANCE: OnceCell<FlodbaddL7Etw> = OnceCell::new();
        INSTANCE.get_or_init(FlodbaddL7Etw::init)
    }

    pub fn get_init_status() -> &'static str {
        global().init_status()
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
}

pub use win::EtwProcessInfo;

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

pub fn get_file_attribution(path: &str) -> Option<(u32, String, String)> {
    win::global().get_file_attribution(path)
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
