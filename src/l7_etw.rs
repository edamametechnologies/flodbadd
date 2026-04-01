// Windows ETW (Event Tracing for Windows) process attribution.
//
// Uses the Windows kernel ETW providers (Microsoft-Windows-Kernel-Process
// and TCP/IP) to maintain a live process table and connection-to-PID map.
// This provides high-fidelity process metadata without the race conditions
// inherent in polling netstat2/sysinfo after the fact.
//
// On non-Windows platforms or when the `etw` feature is not enabled,
// all public functions gracefully fall back to no-op stubs so the rest of
// the codebase does not need to care whether ETW is available.

use crate::sessions::{Session, SessionL7};
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

    use windows::Win32::System::Diagnostics::Etw::{
        CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace,
        StartTraceW, CONTROLTRACE_HANDLE, ENABLE_TRACE_PARAMETERS,
        EVENT_RECORD, EVENT_TRACE_CONTROL_STOP,
        EVENT_TRACE_FLAG, EVENT_TRACE_FLAG_NETWORK_TCPIP, EVENT_TRACE_FLAG_PROCESS,
        EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE,
        PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
        TRACE_LEVEL_INFORMATION, WNODE_FLAG_TRACED_GUID,
    };
    use windows::Win32::System::Threading::GetCurrentProcessId;
    use windows::core::{GUID, PCWSTR};

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

    // TCP/IP group GUIDs
    const TCP_IP_GUID: GUID = GUID::from_u128(0x9a280ac0_c8e0_11d1_84e2_00c04fb998a2);
    const PROCESS_GUID: GUID = GUID::from_u128(0x3d6fa8d0_fe05_11d0_9dda_00c04fd7ba7c);

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
            let available = Arc::new(AtomicBool::new(false));

            let pt = Arc::clone(&process_table);
            let ct = Arc::clone(&connection_table);
            let av = Arc::clone(&available);

            if let Err(e) = std::thread::Builder::new()
                .name("etw-client".into())
                .spawn(move || {
                    Self::run_etw_session(pt, ct, av);
                })
            {
                error!("Failed to spawn ETW client thread: {}", e);
            }

            std::thread::sleep(std::time::Duration::from_millis(500));

            let is_available = available.load(Ordering::Acquire);
            let init_status = if is_available {
                "Enabled: Windows ETW kernel trace with TCP/IP and Process providers".to_string()
            } else {
                "Disabled: ETW kernel trace session failed to start (need Administrator)".to_string()
            };

            if is_available {
                info!("ETW L7 helper initialized: {}", init_status);
            } else {
                warn!("ETW L7 helper: {}", init_status);
            }

            Self {
                process_table,
                connection_table,
                available,
                init_status,
            }
        }

        fn run_etw_session(
            process_table: Arc<DashMap<u32, EtwProcessInfo>>,
            connection_table: Arc<DashMap<TcpConnectionKey, u32>>,
            available: Arc<AtomicBool>,
        ) {
            // Store tables in thread-local for the callback
            THREAD_PROCESS_TABLE.with(|t| {
                *t.borrow_mut() = Some(Arc::clone(&process_table));
            });
            THREAD_CONNECTION_TABLE.with(|t| {
                *t.borrow_mut() = Some(Arc::clone(&connection_table));
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
                let stop_props =
                    &mut *(stop_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
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
                let props =
                    &mut *(trace_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
                props.Wnode.BufferSize = buf_size as u32;
                props.Wnode.Guid = SYSTEM_TRACE_CONTROL_GUID;
                props.Wnode.ClientContext = 1; // QPC for timestamps
                props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
                props.EnableFlags =
                    EVENT_TRACE_FLAG_NETWORK_TCPIP | EVENT_TRACE_FLAG_PROCESS;
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
                logfile.LoggerName = windows::core::PWSTR(
                    logger_name_wide.as_ptr() as *mut u16,
                );
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

        pub fn get_process_info(&self, pid: u32) -> Option<EtwProcessInfo> {
            self.process_table.get(&pid).map(|e| e.value().clone())
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
    }

    // Thread-local storage for the ETW callback to access the shared tables.
    // ETW callbacks are invoked on the ProcessTrace thread, so we set these
    // before calling ProcessTrace.
    thread_local! {
        static THREAD_PROCESS_TABLE: std::cell::RefCell<Option<Arc<DashMap<u32, EtwProcessInfo>>>> =
            const { std::cell::RefCell::new(None) };
        static THREAD_CONNECTION_TABLE: std::cell::RefCell<Option<Arc<DashMap<TcpConnectionKey, u32>>>> =
            const { std::cell::RefCell::new(None) };
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
                let ev = &*(data_ptr as *const ProcessStartEvent);
                let pid = ev.pid;
                let ppid = ev.ppid;
                let session_id = ev.session_id;

                // Extract image file name from the variable-length data after the fixed struct.
                // The layout after the fixed fields is: SID (variable) then ImageFileName (wide string).
                // We skip the SID by scanning for the image path.
                let fixed_size = std::mem::size_of::<ProcessStartEvent>();
                let remaining = data_len.saturating_sub(fixed_size);
                let remaining_ptr = (data_ptr as *const u8).add(fixed_size);
                let remaining_slice =
                    std::slice::from_raw_parts(remaining_ptr, remaining);

                // The image path is a null-terminated ANSI string at the end of the payload
                // in older format, or a wide string. Try to extract it.
                let image_path = extract_image_path(remaining_slice);
                let process_name = std::path::Path::new(&image_path)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();

                // Skip our own process
                let own_pid = GetCurrentProcessId();
                if pid == own_pid {
                    return;
                }

                THREAD_PROCESS_TABLE.with(|t| {
                    if let Some(table) = t.borrow().as_ref() {
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
                        table.remove(&pid);
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

        pub fn get_process_info(&self, _pid: u32) -> Option<EtwProcessInfo> {
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
        info!(
            "ETW L7 process tracking is ENABLED - connection-to-PID mapping via kernel trace"
        );
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
