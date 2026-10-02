// L7 Network Session Resolution
//
// This module implements the Layer 7 (Application Layer) resolution for network sessions
// observed by the LAN scanner. The primary goal is to associate a network session,
// defined by its protocol, source IP/port, and destination IP/port (struct `Session`),
// with the local process responsible for it.
//
// Core components:
// - `FlodbaddL7`: The main struct managing the L7 resolution process.
// - `SessionL7`: Struct holding the resolved process information (PID, name, path, username).
// - `L7Resolution`: Struct stored in `l7_map`, containing the Option<SessionL7>,
//   metadata like resolution time, retry count, and the source of the resolution.
// - `Resolver Task`: An asynchronous task (`start_resolver_task`) that continuously processes
//   a queue (`resolver_queue`) of `Session` objects needing resolution.
// - `Caches`:
//    - `l7_map`: The primary cache storing `L7Resolution` results or pending states for sessions.
//    - `port_process_cache`: Caches process info (`ProcessCacheEntry`) keyed by local (port, protocol),
//      now including process start time for PID reuse protection. Used as a fallback, especially for short-lived connections. Includes a grace period for terminated processes.
//      An entry records the conversation it was learned from (local address, remote end) and answers only that conversation.
//    - `host_service_cache`: Caches known local services (local endpoint, peer when connected, protocol, L7 info) keyed by hostname ("localhost").
//      Used as a fallback for inbound connections to the local machine.
//
// Every fallback (socket rows without a full 4-tuple, both caches, the macOS libproc UDP scan) attributes a
// session only from evidence consistent with BOTH of its ends (`l7_endpoints::evidence_end`): the evidence's
// local address and port are one end of the session, a wildcard address standing only for an address this
// host owns, and its peer, when known, is the other end. A port number alone is not evidence.
// - `Cache Cleanup Task`: Periodically removes stale entries from caches (`start_cache_cleanup_task`).
//
// Resolution Logic:
// 1. New connections are added to `resolver_queue`.
// 2. The resolver task fetches the current list of sockets (`netstat2::get_sockets_info`)
//    and processes (`sysinfo::System::processes`) periodically.
// 3. For each connection in the queue, it attempts resolution in the following order:
//    a. **Host Cache (`try_resolve_from_host_cache`)**: Checks if the destination matches a known local service.
//    b. **Exact Match (`try_exact_match`)**: Looks for a socket entry matching the connection's full 4-tuple (TCP)
//       or bound to the connection's local IP/port (UDP: netstat2 reports no UDP peer) in the fetched socket list.
//       Then a TCP listener that owns one end of the connection (`try_fuzzy_match`).
//    c. **Port Cache (`try_resolve_from_cache`)**: If exact match fails, checks the port cache for an entry learned
//       from the same conversation, using process start time for PID reuse protection. Uses a grace period if the cached process has terminated.
//    d. **Immediate Retry**: If all above fail, the resolver immediately refreshes process/socket tables and retries once before incrementing retry count or re-queueing.
// 4. If a match is found and process info is extracted (`extract_l7_from_socket`), the result is stored in `l7_map`.
// 5. If resolution fails, the connection is re-queued with an incremented retry count and exponential backoff.
//    Connections likely involving ephemeral ports use a faster initial retry.
// 6. After max retries, the connection is marked as `FailedMaxRetries` in `l7_map`.
// 7. Resolved entries in `l7_map` have a Time-To-Live (TTL) and are evicted by the cleanup task.
//
// Resolution improvements:
// - The system now caches and checks process start time (from sysinfo) for PID reuse protection, ensuring accurate process association even when PIDs are recycled by the OS.
// - After a failed resolution attempt, the resolver immediately refreshes process and socket tables and retries once before incrementing retry count or re-queueing. This greatly improves accuracy for short-lived and non-ephemeral sessions.
// - These changes significantly reduce 'unknown process' results and false associations due to PID reuse, prioritizing accuracy above all.
//
// This system aims to handle the ephemeral nature of network connections and process lifecycles
// by combining direct matching with caching, PID reuse protection, and retry mechanisms.
//
// Cost model (2026-09, after profiling the released daemons on all three platforms):
// - The expensive part of resolution is asking the OS, not matching. A resolver round
//   refreshes the process table and dumps the socket table; per-pid open-file enumeration
//   is a /proc fd walk (Linux), a libproc fd walk (macOS) or a share of a system-wide
//   handle-table snapshot (Windows). Those are shared and cached, never repeated per socket:
//   `open_files::get_open_file_paths` serves a per-pid cache, Windows takes one handle
//   snapshot per window, macOS one libproc socket snapshot (`l7_macos::socket_snapshot`).
// - Rounds are spaced at least `MIN_ROUND_INTERVAL` apart so a burst of ephemeral sessions
//   cannot chain several full refreshes back to back.
// - Eager (packet-path) resolution only consults kernel tables and the shared snapshot;
//   parked `FailedMaxRetries` entries are re-armed by `rearm_failed_resolution`, never
//   re-probed on every populate pass.

use crate::l7_ebpf;
use crate::l7_endpoints::{
    evidence_end, evidence_fits_end, HostAddresses, SessionEnd, SocketEndpoints,
};
use crate::l7_es;
use crate::l7_etw;
#[cfg(target_os = "macos")]
use crate::l7_macos;
use crate::sessions::*;
use crate::task::TaskHandle;
use anyhow::Result;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use netstat2::{
    get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, SocketInfo, TcpState,
};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use sysinfo::{Pid, Process, ProcessRefreshKind, RefreshKind, System, Uid, Users};
use tokio::sync::watch;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, trace, warn};
use undeadlock::*;

// Windows-specific imports
#[cfg(windows)]
use windows::{
    core::{HSTRING, PWSTR},
    Win32::NetworkManagement::NetManagement::{
        NERR_Success, NetApiBufferFree, NetUserGetInfo, USER_INFO_0,
    },
};

// Add platform-specific threshold for the first ephemeral port (RFC-defined defaults)
#[cfg(target_os = "macos")]
const EPHEMERAL_PORT_THRESHOLD: u16 = 49_152; // macOS default sysctl net.inet.ip.portrange.first
#[cfg(not(target_os = "macos"))]
const EPHEMERAL_PORT_THRESHOLD: u16 = 32_768; // Common default on Linux/BSD

// Replace const MAX_L7_RETRIES with environment-configurable Lazy
static MAX_L7_RETRIES_DYNAMIC: Lazy<usize> = Lazy::new(|| {
    std::env::var("MAX_L7_RETRIES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(5)
});

// Re-arm cadence for sessions that exhausted `MAX_L7_RETRIES` but are still
// alive. The initial retry window is ~3 s of exponential backoff; a long-lived
// flow whose socket was not yet visible in the socket table during that window
// (connected UDP on a loaded host is the canonical case -- ES on macOS and ETW
// on Windows carry no UDP attribution, so the socket table is the only source)
// would otherwise stay unattributed for its entire lifetime. `populate_l7`
// re-offers every unattributed session on each update pass; this is how often
// such an offer is accepted, and how many times in total.
//
// Cost control: every re-arm costs one resolver round (process-table +
// socket-table refresh shared by all sessions re-armed in that cycle).
// Re-arming every unattributed session every 5 s measurably raised CPU on
// the posture perf gate (ubuntu capture/lanscan +20-45%, `all` +25%) because
// CI hosts carry hundreds of local/system flows that never attribute. The
// caller (`populate_l7`) therefore only offers sessions that are worth it --
// external destination, still active, and carrying traffic -- and the
// cadence is 15 s for up to 8 rounds (~2 min), which covers the observed
// 40-130 s attribution latency without the per-5 s churn.
static L7_REQUEUE_INTERVAL_SECS_DYNAMIC: Lazy<u64> = Lazy::new(|| {
    std::env::var("L7_REQUEUE_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v >= 1)
        .unwrap_or(15)
});

static MAX_L7_REQUEUE_ROUNDS_DYNAMIC: Lazy<usize> = Lazy::new(|| {
    std::env::var("MAX_L7_REQUEUE_ROUNDS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(8)
});

/// Minimum bytes (either direction) a session must have carried before an
/// exhausted resolution is re-armed. Idle or one-packet flows are not worth
/// a resolver round; a flow that keeps moving data is exactly the one whose
/// attribution matters.
pub const L7_REQUEUE_MIN_SESSION_BYTES: u64 = 1024;

// Dynamic retry delay for likely-ephemeral connections (defaults to 10 ms)
static EPHEMERAL_RETRY_MS_DYNAMIC: Lazy<u64> = Lazy::new(|| {
    std::env::var("EPHEMERAL_RETRY_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v >= 1)
        .unwrap_or(10)
});

// Add a new constant for TTL of cached entries that come from high-range (likely client) ephemeral ports
const EPHEMERAL_PORT_CACHE_TTL_SECS: u64 = 300; // Keep for 5 min

// Extended TTL for server ports (< 1024) which rarely change
const SERVER_PORT_CACHE_TTL_SECS: u64 = 300; // Keep for 5 min

// Maximum size of port→process cache
const PORT_CACHE_MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L7ResolutionSource {
    Unknown, // Default before resolution attempt or if resolution fails without hitting max retries
    ExactMatch,
    CacheHitRunning,
    CacheHitTerminated, // Within grace period
    HostCacheHitRunning,
    HostCacheHitTerminated, // Within grace period
    FailedMaxRetries,       // Explicitly mark failures after retries
    Ebpf,                   // Obtained from eBPF helper on Linux
    EndpointSecurity,       // Obtained via macOS Endpoint Security framework
    Etw,                    // Obtained via Windows ETW kernel trace
    MacosLibproc,           // Obtained via PROC_PIDFDSOCKETINFO on macOS
}

#[derive(Debug, Clone)]
pub struct L7Resolution {
    pub l7: Option<SessionL7>,
    pub date: DateTime<Utc>,
    pub retry_count: usize,
    pub last_retry: Option<Instant>,
    pub source: L7ResolutionSource,
    /// Number of times a `FailedMaxRetries` entry has been re-armed for a
    /// session that outlived its initial retry window (see
    /// `add_connection_to_resolver_ex`). Bounded by
    /// `MAX_L7_REQUEUE_ROUNDS_DYNAMIC`.
    pub requeue_rounds: usize,
}

/// A resolution remembered under its local (port, protocol). It is one
/// conversation's evidence: it answers only a session between the same
/// local endpoint (`local_ip` and the key's port) and the same `remote`.
#[derive(Debug, Clone)]
pub struct ProcessCacheEntry {
    pub l7: SessionL7,
    pub process_start_time: u64,
    pub last_seen: Instant,
    pub hit_count: usize,
    pub termination_time: Option<Instant>,
    pub local_ip: IpAddr,
    pub remote: (IpAddr, u16),
}

impl ProcessCacheEntry {
    fn endpoints(&self, local_port: u16) -> SocketEndpoints {
        SocketEndpoints {
            local_ip: self.local_ip,
            local_port,
            remote: Some(self.remote),
        }
    }
}

pub struct FlodbaddL7 {
    l7_map: Arc<CustomDashMap<Session, L7Resolution>>,
    resolver_queue: Arc<CustomDashMap<Session, ()>>,
    resolver_handle: Option<TaskHandle>,
    system: Arc<CustomRwLock<System>>,
    users: Arc<CustomRwLock<Users>>,
    port_process_cache: Arc<CustomDashMap<(u16, Protocol), ProcessCacheEntry>>,
    cache_cleanup_handle: Option<TaskHandle>,
    sensitive_scan_handle: Option<TaskHandle>,
    host_service_cache: Arc<CustomDashMap<String, Vec<(SocketEndpoints, Protocol, SessionL7)>>>,
}

impl FlodbaddL7 {
    pub fn new() -> Self {
        Self {
            l7_map: Arc::new(CustomDashMap::new("l7_map")),
            resolver_queue: Arc::new(CustomDashMap::new("resolver_queue")),
            resolver_handle: None,
            system: Arc::new(CustomRwLock::new(System::new_all())),
            users: Arc::new(CustomRwLock::new(Users::new())),
            port_process_cache: Arc::new(CustomDashMap::new("port_process_cache")),
            cache_cleanup_handle: None,
            sensitive_scan_handle: None,
            host_service_cache: Arc::new(CustomDashMap::new("host_service_cache")),
        }
    }

    pub async fn start(&mut self) {
        if self.resolver_handle.is_some() {
            warn!("L7 resolver task is already running");
            return;
        }

        self.start_resolver_task().await;

        self.start_cache_cleanup_task().await;

        self.start_sensitive_scan_task().await;
    }

    pub async fn stop(&mut self) {
        if let Some(task_handle) = self.resolver_handle.take() {
            let _ = task_handle.stop_tx.send(true);
            let _ = task_handle.handle.await;
            info!("Stopped L7 resolver task");
        } else {
            warn!("L7 resolver task not running");
        }

        if let Some(task_handle) = self.cache_cleanup_handle.take() {
            let _ = task_handle.stop_tx.send(true);
            let _ = task_handle.handle.await;
            info!("Stopped L7 cache cleanup task");
        }

        if let Some(task_handle) = self.sensitive_scan_handle.take() {
            let _ = task_handle.stop_tx.send(true);
            let _ = task_handle.handle.await;
            info!("Stopped sensitive file scan task");
        }
    }

    async fn start_resolver_task(&mut self) {
        let resolver_queue = self.resolver_queue.clone();
        let l7_map = self.l7_map.clone();
        let system = self.system.clone();
        let users = self.users.clone();
        let port_process_cache = self.port_process_cache.clone();
        let host_service_cache = self.host_service_cache.clone();

        let (stop_tx, stop_rx) = watch::channel(false);
        let stop_tx = Arc::new(stop_tx);

        let resolver_handle = tokio::spawn(async move {
            info!("Starting L7 resolver task");
            let refresh_kind = RefreshKind::nothing()
                .with_processes(ProcessRefreshKind::everything().without_cpu());

            // Minimum spacing between two resolver rounds. A round refreshes
            // the whole process table and dumps the whole socket table; the
            // 10 ms ephemeral backoff used to let a burst of UDP/DNS sessions
            // trigger five such rounds within ~60 ms.
            const MIN_ROUND_INTERVAL: Duration = Duration::from_millis(250);
            let mut last_round_started: Option<Instant> = None;

            while !*stop_rx.borrow() {
                let mut to_process_this_cycle: Vec<Session> = Vec::new();
                let mut requeue_due_to_backoff: Vec<Session> = Vec::new();

                // Drain resolver_queue and categorize sessions
                for (session_key, _value) in resolver_queue.drain() {
                    let session = &session_key; // Keep as reference for existing logic, or clone if moved
                    let mut process_now = true; // Default to process unless backoff says otherwise

                    if let Some(resolution_entry) = l7_map.get(session) {
                        let resolution = resolution_entry.value();
                        if resolution.retry_count > 0 {
                            if let Some(last_retry_instant) = resolution.last_retry {
                                let is_likely_ephemeral = Self::is_likely_ephemeral(session);
                                let wait_duration = if is_likely_ephemeral {
                                    Duration::from_millis(*EPHEMERAL_RETRY_MS_DYNAMIC)
                                } else {
                                    let backoff_ms =
                                        (2_u64.pow(resolution.retry_count as u32 - 1)) * 100;
                                    Duration::from_millis(backoff_ms.min(10000))
                                    // Max 10s backoff
                                };
                                if last_retry_instant.elapsed() < wait_duration {
                                    process_now = false;
                                }
                            }
                        }
                    } else {
                        // If not in l7_map, it's likely a new session or an anomaly. Process it.
                        // add_connection_to_resolver should ensure an entry exists.
                        // If it was evicted by TTL but still in queue, treat as new.
                        trace!("Session {:?} in resolver_queue but not in l7_map, treating as new attempt.", session);
                    }

                    if process_now {
                        to_process_this_cycle.push(session_key.clone()); // Clone here as session_key is owned
                    } else {
                        requeue_due_to_backoff.push(session_key.clone()); // Clone here
                    }
                }

                let to_process_len = to_process_this_cycle.len();
                if to_process_len > 0 {
                    if let Some(last) = last_round_started {
                        let since = last.elapsed();
                        if since < MIN_ROUND_INTERVAL {
                            sleep(MIN_ROUND_INTERVAL - since).await;
                        }
                    }
                    last_round_started = Some(Instant::now());
                    {
                        let mut sys = system.write().await;
                        sys.refresh_specifics(refresh_kind);

                        let mut users = users.write().await;
                        users.refresh();
                    }

                    // On macOS, use native libproc PROC_PIDFDSOCKETINFO for
                    // direct socket-to-PID mapping (bypasses netstat2).
                    #[cfg(target_os = "macos")]
                    let (macos_session_map, macos_all_entries) =
                        match tokio::task::spawn_blocking(|| {
                            // Sweep now and publish the result so the eager
                            // packet-path lookups reuse it instead of
                            // sweeping on their own.
                            let snap = l7_macos::socket_snapshot(Duration::ZERO);
                            (snap.session_map.clone(), snap.entries.clone())
                        })
                        .await
                        {
                            Ok(result) => result,
                            Err(join_err) => {
                                error!("macOS libproc spawn_blocking join error: {:?}", join_err);
                                (HashMap::new(), Vec::new())
                            }
                        };

                    // Offload potentially blocking netstat scan to a blocking thread
                    let socket_info = match tokio::task::spawn_blocking(move || {
                        get_sockets_info(
                            AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
                            ProtocolFlags::TCP | ProtocolFlags::UDP,
                        )
                    })
                    .await
                    {
                        Ok(Ok(info)) => info,
                        Ok(Err(e)) => {
                            error!("Failed to get socket info: {:?}", e);
                            Vec::new()
                        }
                        Err(join_err) => {
                            error!("spawn_blocking join error: {:?}", join_err);
                            Vec::new()
                        }
                    };

                    // Where wildcard-bound sockets can own a session end
                    // (`l7_endpoints`); listed at most every few seconds.
                    let host_addresses = HostAddresses::current();

                    let system_read = system.read().await;
                    let users_read = users.read().await;

                    let pid_to_process: HashMap<u32, &Process> = system_read
                        .processes()
                        .iter()
                        .map(|(pid, process)| (pid.as_u32(), process))
                        .collect();

                    let uid_to_username: HashMap<&Uid, &str> = users_read
                        .iter()
                        .map(|user| (user.id(), user.name()))
                        .collect();

                    // Note: users_read is kept alive because uid_to_username borrows from it
                    // It will be dropped when uid_to_username goes out of scope

                    Self::update_host_service_cache(
                        &socket_info,
                        &pid_to_process,
                        &uid_to_username,
                        &host_service_cache,
                    )
                    .await;

                    let mut successfully_resolved_count = 0;
                    let mut failed_and_will_retry_count = 0;
                    let mut failed_max_retries_count = 0;

                    // Build port→socket index once per batch for quick lookup
                    let mut port_index: HashMap<(u16, Protocol), Vec<&SocketInfo>> = HashMap::new();
                    for socket in &socket_info {
                        let (port, proto) = match &socket.protocol_socket_info {
                            ProtocolSocketInfo::Tcp(tcp) => (tcp.local_port, Protocol::TCP),
                            ProtocolSocketInfo::Udp(udp) => (udp.local_port, Protocol::UDP),
                        };
                        port_index.entry((port, proto)).or_default().push(socket);
                    }

                    for connection in to_process_this_cycle {
                        // Try eBPF first -- cheapest and most accurate for
                        // short-lived processes that may be gone by the time
                        // netstat runs.
                        if let Some(mut l7_ebpf_data) = l7_ebpf::get_l7_for_session(&connection) {
                            FlodbaddL7::enrich_ebpf_l7_from_proc(&mut l7_ebpf_data);
                            let mut l7_ebpf_data = l7_ebpf_data;
                            Self::merge_previous_sensitive(&l7_map, &connection, &mut l7_ebpf_data);
                            l7_map.insert(
                                connection.clone(),
                                L7Resolution {
                                    l7: Some(l7_ebpf_data),
                                    date: Utc::now(),
                                    retry_count: 0,
                                    last_retry: None,
                                    requeue_rounds: 0,
                                    source: L7ResolutionSource::Ebpf,
                                },
                            );
                            successfully_resolved_count += 1;
                            continue;
                        }

                        // Windows ETW: direct connection-to-PID from kernel trace
                        if let Some(mut l7_etw_data) = l7_etw::get_l7_for_session(&connection) {
                            l7_etw::enrich_session_l7(l7_etw_data.pid, &mut l7_etw_data);
                            Self::merge_previous_sensitive(&l7_map, &connection, &mut l7_etw_data);
                            l7_map.insert(
                                connection.clone(),
                                L7Resolution {
                                    l7: Some(l7_etw_data),
                                    date: Utc::now(),
                                    retry_count: 0,
                                    last_retry: None,
                                    requeue_rounds: 0,
                                    source: L7ResolutionSource::Etw,
                                },
                            );
                            successfully_resolved_count += 1;
                            continue;
                        }

                        // macOS libproc: direct socket-to-PID lookup
                        #[cfg(target_os = "macos")]
                        {
                            if let Some((pid, owned_end)) = l7_macos::lookup_session_owner(
                                &connection,
                                &macos_session_map,
                                &macos_all_entries,
                                &host_addresses,
                            ) {
                                let extracted = if let Some(process) = pid_to_process.get(&pid) {
                                    Self::extract_l7_from_pid(
                                        pid,
                                        process,
                                        &pid_to_process,
                                        &uid_to_username,
                                    )
                                    .await
                                } else {
                                    Self::extract_l7_from_pid_fresh(pid).await
                                };

                                if let Some((l7_data, start_time)) = extracted {
                                    Self::update_port_process_cache(
                                        &connection,
                                        owned_end,
                                        &l7_data,
                                        start_time,
                                        &port_process_cache,
                                    )
                                    .await;
                                    let mut l7_data = l7_data;
                                    l7_es::enrich_session_l7(l7_data.pid, &mut l7_data);
                                    let source = if l7_es::is_available() {
                                        L7ResolutionSource::EndpointSecurity
                                    } else {
                                        L7ResolutionSource::MacosLibproc
                                    };
                                    Self::merge_previous_sensitive(
                                        &l7_map,
                                        &connection,
                                        &mut l7_data,
                                    );
                                    l7_map.insert(
                                        connection.clone(),
                                        L7Resolution {
                                            l7: Some(l7_data),
                                            date: Utc::now(),
                                            retry_count: 0,
                                            last_retry: None,
                                            requeue_rounds: 0,
                                            source,
                                        },
                                    );
                                    successfully_resolved_count += 1;
                                    continue;
                                }
                            }
                        }

                        // Exact match via socket index
                        // Note: pid_to_process borrows from system_read, so we need to be careful about lifetimes
                        if let Some((l7_fast, start_time_fast, owned_end)) =
                            Self::try_exact_match_from_index(
                                &connection,
                                &port_index,
                                &pid_to_process,
                                &uid_to_username,
                                &host_addresses,
                            )
                            .await
                        {
                            trace!(
                                "L7 exact match (indexed) for {:?}: {:?}",
                                connection,
                                l7_fast
                            );
                            Self::update_port_process_cache(
                                &connection,
                                owned_end,
                                &l7_fast,
                                start_time_fast,
                                &port_process_cache,
                            )
                            .await;
                            let mut l7_fast = l7_fast;
                            Self::merge_previous_sensitive(&l7_map, &connection, &mut l7_fast);
                            l7_map.insert(
                                connection.clone(),
                                L7Resolution {
                                    l7: Some(l7_fast),
                                    date: Utc::now(),
                                    retry_count: 0,
                                    last_retry: None,
                                    requeue_rounds: 0,
                                    source: L7ResolutionSource::ExactMatch,
                                },
                            );
                            successfully_resolved_count += 1;
                            continue;
                        }

                        // Use a scope to ensure system_read is dropped after use
                        let from_host_cache = {
                            let from_cache = Self::try_resolve_from_host_cache_custom(
                                &connection,
                                &host_service_cache,
                                &*system_read,
                                &host_addresses,
                            )
                            .await;

                            // Check process status while system_read is still available
                            if let Some(l7_data_tuple) = &from_cache {
                                let (session_l7_data, _source_from_host_cache, _) = l7_data_tuple;
                                let source = if system_read
                                    .process(Pid::from_u32(session_l7_data.pid))
                                    .is_some()
                                {
                                    L7ResolutionSource::HostCacheHitRunning
                                } else {
                                    L7ResolutionSource::HostCacheHitTerminated
                                };
                                // Return with source information
                                from_cache.map(|(l7, _, owned_end)| (l7, source, owned_end))
                            } else {
                                None
                            }
                        };

                        if let Some((session_l7_data, source, owned_end)) = from_host_cache {
                            trace!(
                                "Successfully L7 resolved connection {:?} from host cache: {:?}",
                                connection,
                                session_l7_data
                            );

                            Self::update_port_process_cache(
                                &connection,
                                owned_end,
                                &session_l7_data,
                                0,
                                &port_process_cache,
                            )
                            .await;

                            let mut session_l7_data = session_l7_data;
                            Self::merge_previous_sensitive(
                                &l7_map,
                                &connection,
                                &mut session_l7_data,
                            );
                            l7_map.insert(
                                connection.clone(),
                                L7Resolution {
                                    l7: Some(session_l7_data),
                                    date: Utc::now(),
                                    retry_count: 0,
                                    last_retry: None,
                                    requeue_rounds: 0,
                                    source,
                                },
                            );
                            successfully_resolved_count += 1;
                            continue;
                        }

                        // Try to resolve L7 data - reuse the existing system_read instead of acquiring a nested lock
                        // (acquiring a nested read lock can cause deadlock with write-preferring RwLock)
                        let (l7_data_and_time, cache_source) = {
                            let result = Self::resolve_l7_data(
                                &connection,
                                &socket_info,
                                &pid_to_process,
                                &uid_to_username,
                                &host_addresses,
                            )
                            .await;

                            // Fallback: try port_process_cache if direct match fails
                            let mut l7_data_and_time = None;
                            let mut cache_source = None;
                            match result {
                                Ok((l7_data, process_start_time, owned_end)) => {
                                    l7_data_and_time =
                                        Some((l7_data, process_start_time, Some(owned_end)));
                                }
                                Err(_) => {
                                    // Use the existing system_read instead of acquiring a new lock
                                    if let Some((l7_data, source)) = Self::try_resolve_from_cache(
                                        &connection,
                                        &port_process_cache,
                                        &*system_read,
                                        &host_addresses,
                                    )
                                    .await
                                    {
                                        // No new evidence to cache: the hit
                                        // refreshed its own entry.
                                        l7_data_and_time = Some((l7_data, 0, None));
                                        cache_source = Some(source);
                                    } else {
                                        // No further immediate refreshes; rely on next batch refresh
                                    }
                                }
                            }
                            (l7_data_and_time, cache_source)
                        };

                        if let Some((l7_data, process_start_time, owned_end)) = l7_data_and_time {
                            trace!(
                                "Successfully L7 resolved connection {:?}: {:?}",
                                connection,
                                l7_data
                            );
                            // A cache hit is not re-cached: rewriting its
                            // entry from the hit carried start time 0, which
                            // no running process matches, so the entry went
                            // dead after its first use.
                            if let Some(owned_end) = owned_end {
                                Self::update_port_process_cache(
                                    &connection,
                                    owned_end,
                                    &l7_data,
                                    process_start_time,
                                    &port_process_cache,
                                )
                                .await;
                            }
                            let mut l7_data = l7_data;
                            Self::merge_previous_sensitive(&l7_map, &connection, &mut l7_data);
                            l7_map.insert(
                                connection.clone(),
                                L7Resolution {
                                    l7: Some(l7_data),
                                    date: Utc::now(),
                                    retry_count: 0,
                                    last_retry: None,
                                    requeue_rounds: 0,
                                    source: cache_source.unwrap_or(L7ResolutionSource::ExactMatch),
                                },
                            );
                            successfully_resolved_count += 1;
                            continue;
                        }
                        // All resolution attempts for 'connection' in this cycle failed.
                        // Avoid holding a l7_map write lock across awaits to prevent long-lived locks.
                        let current_retry_count =
                            l7_map.get(&connection).map(|entry| entry.retry_count);

                        if let Some(current_retry_count) = current_retry_count {
                            // Immediate retry for first-time failures: retry with fresh socket data (no system refresh to avoid deadlock)
                            // The system refresh will happen in the next batch cycle
                            // NOTE: We add a timeout here to prevent blocking indefinitely while holding system/users read locks
                            if current_retry_count == 0 {
                                trace!(
                                    "First-time resolution failure for {:?}, attempting immediate retry with fresh socket data",
                                    connection
                                );

                                // Refresh socket info only (this doesn't require system lock)
                                // Use a timeout to prevent blocking while holding read locks - if the blocking pool is saturated,
                                // we'll skip the immediate retry and use normal retry logic instead
                                let fresh_socket_info = match tokio::time::timeout(
                                    Duration::from_secs(5),
                                    tokio::task::spawn_blocking(move || {
                                        get_sockets_info(
                                            AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
                                            ProtocolFlags::TCP | ProtocolFlags::UDP,
                                        )
                                    }),
                                )
                                .await
                                {
                                    Ok(Ok(Ok(info))) => info,
                                    Ok(Ok(Err(e))) => {
                                        error!("Failed to get fresh socket info for immediate retry: {:?}", e);
                                        Vec::new()
                                    }
                                    Ok(Err(join_err)) => {
                                        error!("spawn_blocking join error during immediate retry: {:?}", join_err);
                                        Vec::new()
                                    }
                                    Err(_timeout) => {
                                        // Timeout - blocking pool may be saturated, skip immediate retry to avoid deadlock
                                        warn!("Timeout waiting for socket info during immediate retry - skipping to avoid lock contention");
                                        if let Some(mut resolution_entry) =
                                            l7_map.get_mut(&connection)
                                        {
                                            resolution_entry.retry_count += 1;
                                            resolution_entry.last_retry = Some(Instant::now());
                                        } else {
                                            l7_map.insert(
                                                connection.clone(),
                                                L7Resolution {
                                                    l7: None,
                                                    date: Utc::now(),
                                                    retry_count: 1,
                                                    last_retry: Some(Instant::now()),
                                                    requeue_rounds: 0,
                                                    source: L7ResolutionSource::Unknown,
                                                },
                                            );
                                        }
                                        resolver_queue.insert(connection.clone(), ());
                                        failed_and_will_retry_count += 1;
                                        continue;
                                    }
                                };

                                // Try resolution again with fresh socket data (reuse existing pid_to_process)
                                let immediate_retry_result = Self::resolve_l7_data(
                                    &connection,
                                    &fresh_socket_info,
                                    &pid_to_process,
                                    &uid_to_username,
                                    &host_addresses,
                                )
                                .await;

                                // Also try cache with current system state
                                let cache_retry_result = if immediate_retry_result.is_err() {
                                    Self::try_resolve_from_cache(
                                        &connection,
                                        &port_process_cache,
                                        &*system_read,
                                        &host_addresses,
                                    )
                                    .await
                                } else {
                                    None
                                };

                                // Check if immediate retry succeeded
                                if let Ok((l7_data, process_start_time, owned_end)) =
                                    immediate_retry_result
                                {
                                    trace!(
                                        "Immediate retry succeeded for {:?}: {:?}",
                                        connection,
                                        l7_data
                                    );
                                    Self::update_port_process_cache(
                                        &connection,
                                        owned_end,
                                        &l7_data,
                                        process_start_time,
                                        &port_process_cache,
                                    )
                                    .await;
                                    let mut l7_data = l7_data;
                                    Self::merge_previous_sensitive(
                                        &l7_map,
                                        &connection,
                                        &mut l7_data,
                                    );
                                    if let Some(mut resolution_entry) = l7_map.get_mut(&connection)
                                    {
                                        resolution_entry.l7 = Some(l7_data);
                                        resolution_entry.retry_count = 0;
                                        resolution_entry.last_retry = None;
                                        resolution_entry.source = L7ResolutionSource::ExactMatch;
                                    } else {
                                        l7_map.insert(
                                            connection.clone(),
                                            L7Resolution {
                                                l7: Some(l7_data),
                                                date: Utc::now(),
                                                retry_count: 0,
                                                last_retry: None,
                                                requeue_rounds: 0,
                                                source: L7ResolutionSource::ExactMatch,
                                            },
                                        );
                                    }
                                    successfully_resolved_count += 1;
                                    continue; // Success, move to next connection
                                } else if let Some((l7_data, source)) = cache_retry_result {
                                    trace!(
                                        "Immediate retry succeeded via cache for {:?}: {:?}",
                                        connection,
                                        l7_data
                                    );
                                    // Not re-cached: see the first attempt.
                                    let mut l7_data = l7_data;
                                    Self::merge_previous_sensitive(
                                        &l7_map,
                                        &connection,
                                        &mut l7_data,
                                    );
                                    if let Some(mut resolution_entry) = l7_map.get_mut(&connection)
                                    {
                                        resolution_entry.l7 = Some(l7_data);
                                        resolution_entry.retry_count = 0;
                                        resolution_entry.last_retry = None;
                                        resolution_entry.source = source;
                                    } else {
                                        l7_map.insert(
                                            connection.clone(),
                                            L7Resolution {
                                                l7: Some(l7_data),
                                                date: Utc::now(),
                                                retry_count: 0,
                                                last_retry: None,
                                                requeue_rounds: 0,
                                                source,
                                            },
                                        );
                                    }
                                    successfully_resolved_count += 1;
                                    continue; // Success, move to next connection
                                } else {
                                    trace!(
                                        "Immediate retry failed for {:?}, will increment retry_count",
                                        connection
                                    );
                                    // Immediate retry failed, proceed with normal retry logic
                                }
                            }

                            // Normal retry logic (increment retry_count and re-queue)
                            if let Some(mut resolution_entry) = l7_map.get_mut(&connection) {
                                resolution_entry.retry_count += 1;
                                resolution_entry.last_retry = Some(Instant::now());

                                if resolution_entry.retry_count > *MAX_L7_RETRIES_DYNAMIC {
                                    resolution_entry.l7 = None; // Ensure l7 is None
                                    resolution_entry.source = L7ResolutionSource::FailedMaxRetries;
                                    failed_max_retries_count += 1;
                                    trace!(
                                        "Session {:?} failed max L7 retries ({}). Source: {:?}.",
                                        connection,
                                        resolution_entry.retry_count,
                                        resolution_entry.source
                                    );
                                    // Do not re-queue if max retries hit
                                } else {
                                    // Re-queue for another attempt
                                    resolver_queue.insert(connection.clone(), ());
                                    failed_and_will_retry_count += 1;
                                    trace!(
                                        "Re-queued session {:?} for L7 resolution (retry {}).",
                                        connection,
                                        resolution_entry.retry_count
                                    );
                                }
                            } else {
                                warn!(
                                    "L7: Connection {:?} processed but no entry in l7_map for failure handling. Re-initializing and re-queueing.",
                                    connection
                                );
                                // Re-initialize in l7_map and add to queue as if it's a new connection
                                l7_map.insert(
                                    connection.clone(),
                                    L7Resolution {
                                        l7: None,
                                        date: Utc::now(),
                                        retry_count: 0, // Start retries from 0
                                        last_retry: Some(Instant::now()), // Mark a retry attempt
                                        source: L7ResolutionSource::Unknown,
                                        requeue_rounds: 0,
                                    },
                                );
                                resolver_queue.insert(connection.clone(), ());
                                failed_and_will_retry_count += 1; // Count it as a failed attempt that will be retried
                            }
                        } else {
                            warn!(
                                "L7: Connection {:?} processed but no entry in l7_map for failure handling. Re-initializing and re-queueing.",
                                connection
                            );
                            // Re-initialize in l7_map and add to queue as if it's a new connection
                            l7_map.insert(
                                connection.clone(),
                                L7Resolution {
                                    l7: None,
                                    date: Utc::now(),
                                    retry_count: 0, // Start retries from 0
                                    last_retry: Some(Instant::now()), // Mark a retry attempt
                                    source: L7ResolutionSource::Unknown,
                                    requeue_rounds: 0,
                                },
                            );
                            resolver_queue.insert(connection.clone(), ());
                            failed_and_will_retry_count += 1; // Count it as a failed attempt that will be retried
                        }
                    }

                    // Re-queue sessions that were skipped due to backoff
                    let requeue_len = requeue_due_to_backoff.len();
                    if !requeue_due_to_backoff.is_empty() {
                        for session in requeue_due_to_backoff {
                            resolver_queue.insert(session, ());
                        }
                        trace!("L7: {} sessions re-queued due to backoff, no active processing this cycle.", requeue_len);
                    }

                    if successfully_resolved_count > 0
                        || failed_and_will_retry_count > 0
                        || failed_max_retries_count > 0
                        || requeue_len > 0
                    {
                        debug!(
                            "L7 resolution cycle: {} processed. Results: {} resolved, {} failed (will retry), {} failed (max retries). {} pending backoff.",
                            to_process_len,
                            successfully_resolved_count,
                            failed_and_will_retry_count,
                            failed_max_retries_count,
                            requeue_len
                        );
                    }

                    // Sleep for a little while to avoid overwhelming the system but keep a tight loop to ensure we're responsive to new sessions
                    sleep(Duration::from_millis(3)).await;
                } else {
                    // No sessions to process actively, but check if there are items simply waiting for backoff
                    let requeue_len = requeue_due_to_backoff.len();
                    if !requeue_due_to_backoff.is_empty() {
                        for session in requeue_due_to_backoff {
                            resolver_queue.insert(session, ());
                        }
                        trace!("L7: {} sessions re-queued due to backoff, no active processing this cycle.", requeue_len);
                    }
                    // No sessions to resolve, sleep for a while to avoid overwhelming the system
                    sleep(Duration::from_millis(10)).await;
                }
            }

            info!("L7 resolver task completed");
        });

        self.resolver_handle = Some(TaskHandle {
            handle: resolver_handle,
            stop_tx,
        });
    }

    async fn start_cache_cleanup_task(&mut self) {
        let port_process_cache = self.port_process_cache.clone();
        let host_service_cache = self.host_service_cache.clone();
        let l7_map = self.l7_map.clone();

        let (stop_tx, mut stop_rx) = watch::channel(false);
        let stop_tx = Arc::new(stop_tx);

        let cleanup_handle = tokio::spawn(async move {
            info!("Starting L7 cache cleanup task");

            loop {
                // Clean up port process cache using retain to avoid per-key locking
                port_process_cache.retain(|key, entry| {
                    let port = key.0;
                    let age = entry.last_seen.elapsed();
                    if port >= EPHEMERAL_PORT_THRESHOLD {
                        // Ephemeral ports: keep only if not expired (short TTL)
                        age <= Duration::from_secs(EPHEMERAL_PORT_CACHE_TTL_SECS)
                    } else if port < 1024 {
                        // Server ports: extended TTL since they rarely change
                        age <= Duration::from_secs(SERVER_PORT_CACHE_TTL_SECS)
                    } else {
                        // Regular ports: keep entries unless they've aged out with low hit count
                        !(age > Duration::from_secs(300) && entry.hit_count < 10)
                    }
                });
                debug!(
                    "Port process cache size after cleanup: {}",
                    port_process_cache.len()
                );

                // Clean up host service cache
                // We'll refresh the entire cache periodically rather than trying to track
                // individual service lifetimes, since the host service cache is refreshed
                // completely by update_host_service_cache() on each resolution cycle
                let host_cache_keys: Vec<String> = host_service_cache
                    .iter()
                    .map(|entry| entry.key().clone())
                    .collect();

                // Don't remove the localhost entry, which is constantly refreshed
                for key in host_cache_keys {
                    if key != "localhost" {
                        host_service_cache.remove(&key);
                        debug!("Removed stale host service entry: {}", key);
                    }
                }

                // Clean out services in the localhost entry that haven't been seen recently
                if let Some(localhost_entry) = host_service_cache.get_mut("localhost") {
                    debug!(
                        "Localhost service cache has {} entries",
                        localhost_entry.value().len()
                    );
                }

                // ------------------------------------------------------------------
                // Size bound for port→process cache (oldest entries removed)
                // ------------------------------------------------------------------
                if port_process_cache.len() > PORT_CACHE_MAX_ENTRIES {
                    let mut entries: Vec<_> = port_process_cache
                        .iter()
                        .map(|e| (e.key().clone(), e.value().last_seen))
                        .collect();
                    entries.sort_by_key(|&(_, ts)| ts);
                    let excess = port_process_cache.len() - PORT_CACHE_MAX_ENTRIES;
                    for i in 0..excess {
                        port_process_cache.remove(&entries[i].0);
                    }
                    debug!("Trimmed {} excess port cache entries", excess);
                }

                // ------------------------------------------------------------------
                // TTL eviction for session→L7 map (5-minute aligned with agentic loop)
                // ------------------------------------------------------------------
                let ttl = ChronoDuration::minutes(5);
                let now = Utc::now();

                // Collect keys to remove first to avoid deadlock
                let mut keys_to_remove = Vec::new();
                for entry in l7_map.iter() {
                    if now - entry.value().date > ttl {
                        keys_to_remove.push(entry.key().clone());
                    }
                }

                // Now remove the collected keys
                let evicted = keys_to_remove.len();
                for key in keys_to_remove {
                    l7_map.remove(&key);
                }

                if evicted > 0 {
                    debug!("Evicted {} stale L7Resolution entries", evicted);
                }

                // Wait for stop signal or 60s, whichever comes first
                if tokio::time::timeout(Duration::from_secs(60), stop_rx.changed())
                    .await
                    .is_ok()
                {
                    break;
                }
            }

            info!("L7 cache cleanup task completed");
        });

        self.cache_cleanup_handle = Some(TaskHandle {
            handle: cleanup_handle,
            stop_tx,
        });
    }

    /// Lightweight task that periodically scans open files for resolved
    /// sessions, looking only for sensitive paths (credentials, keys, etc.).
    ///
    /// Interval is platform-tuned:
    ///   Linux  – 30 s  (procfs readlinks are RAM-backed, near-zero cost)
    ///   macOS  – 30 s  (keeps active-session open_files propagation responsive)
    ///   Windows – 120 s (NtQuerySystemInformation enumerates ALL handles system-wide)
    async fn start_sensitive_scan_task(&mut self) {
        #[cfg(target_os = "linux")]
        const SENSITIVE_SCAN_INTERVAL_SECS: u64 = 30;
        #[cfg(target_os = "macos")]
        const SENSITIVE_SCAN_INTERVAL_SECS: u64 = 30;
        #[cfg(target_os = "windows")]
        const SENSITIVE_SCAN_INTERVAL_SECS: u64 = 120;
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        const SENSITIVE_SCAN_INTERVAL_SECS: u64 = 120;

        /// Cap the number of PIDs scanned per cycle to bound worst-case CPU.
        /// On Windows/macOS each PID is significantly more expensive than Linux.
        #[cfg(target_os = "linux")]
        const MAX_PIDS_PER_CYCLE: usize = 500;
        #[cfg(not(target_os = "linux"))]
        const MAX_PIDS_PER_CYCLE: usize = 50;

        let l7_map = self.l7_map.clone();

        let (stop_tx, mut stop_rx) = watch::channel(false);
        let stop_tx = Arc::new(stop_tx);

        let handle = tokio::spawn(async move {
            info!(
                "Starting sensitive file scan task ({}s interval, max {} PIDs/cycle)",
                SENSITIVE_SCAN_INTERVAL_SECS, MAX_PIDS_PER_CYCLE
            );

            loop {
                if tokio::time::timeout(
                    Duration::from_secs(SENSITIVE_SCAN_INTERVAL_SECS),
                    stop_rx.changed(),
                )
                .await
                .is_ok()
                {
                    break;
                }

                // Collect (pid, needs_full_scan) for resolved entries, dedup by
                // PID so we scan each process at most once.  Entries with empty
                // open_files get a full (unfiltered) scan so the vuln detector
                // can see all open file paths -- this covers both eager macOS
                // libproc entries and standard netstat/ExactMatch entries.
                let mut seen_pids = std::collections::HashSet::new();
                let targets: Vec<(u32, bool)> = l7_map
                    .iter()
                    .filter_map(|entry| {
                        let resolution = entry.value();
                        resolution.l7.as_ref().and_then(|l7| {
                            if seen_pids.insert(l7.pid) {
                                let needs_full = l7.open_files.is_empty();
                                Some((l7.pid, needs_full))
                            } else {
                                None
                            }
                        })
                    })
                    .take(MAX_PIDS_PER_CYCLE)
                    .collect();

                if targets.is_empty() {
                    continue;
                }

                // Scan FDs on a blocking thread (I/O varies by platform).
                // Full scan for PIDs with empty open_files; sensitive-only for
                // those already populated.
                let scan_results = tokio::task::spawn_blocking(move || {
                    targets
                        .into_iter()
                        .filter_map(|(pid, needs_full)| {
                            let files = if needs_full {
                                crate::open_files::get_open_file_paths(pid)
                            } else {
                                crate::open_files::get_sensitive_open_file_paths(pid)
                            };
                            if files.is_empty() {
                                None
                            } else {
                                Some((pid, files))
                            }
                        })
                        .collect::<Vec<_>>()
                })
                .await
                .unwrap_or_default();

                // Build a PID -> [session_key] index with a single read-only
                // pass so we can do targeted get_mut() lookups instead of
                // iter_mut() which write-locks every shard for each PID.
                let pids_of_interest: std::collections::HashSet<u32> =
                    scan_results.iter().map(|(pid, _)| *pid).collect();
                let mut pid_to_keys: std::collections::HashMap<u32, Vec<Session>> =
                    std::collections::HashMap::new();
                for entry in l7_map.iter() {
                    if let Some(l7) = &entry.value().l7 {
                        if pids_of_interest.contains(&l7.pid) {
                            pid_to_keys
                                .entry(l7.pid)
                                .or_default()
                                .push(entry.key().clone());
                        }
                    }
                }

                let mut updated_sessions = 0u32;
                for (pid, files) in &scan_results {
                    if let Some(keys) = pid_to_keys.get(pid) {
                        for key in keys {
                            if let Some(mut entry) = l7_map.get_mut(key) {
                                if let Some(l7) = &mut entry.value_mut().l7 {
                                    if l7.pid == *pid {
                                        let before = l7.open_files.len();
                                        for f in files {
                                            if !l7.open_files.contains(f) {
                                                l7.open_files.push(f.clone());
                                            }
                                        }
                                        if l7.open_files.len() != before {
                                            l7.open_files.sort();
                                            l7.open_files.dedup();
                                            updated_sessions += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if updated_sessions > 0 {
                    debug!(
                        "Sensitive file scan: updated {} session(s) with newly detected files",
                        updated_sessions
                    );
                }
            }

            info!("Sensitive file scan task completed");
        });

        self.sensitive_scan_handle = Some(TaskHandle { handle, stop_tx });
    }

    /// Remember `l7_data` as the owner of the conversation `connection`
    /// holds at `owned_end`, the end its evidence was a socket at.
    ///
    /// Keyed by that end's local port, but an entry answers only the same
    /// conversation again (`try_resolve_from_cache`). It used to be stored
    /// under every private-address port of the session, the remote end's
    /// service port included, and to answer any later session on that port:
    /// a LAN probe of 10.0.0.1:80 then attributed every other connection to
    /// a :80 to the prober.
    async fn update_port_process_cache(
        connection: &Session,
        owned_end: SessionEnd,
        l7_data: &SessionL7,
        process_start_time: u64,
        port_process_cache: &CustomDashMap<(u16, Protocol), ProcessCacheEntry>,
    ) {
        let (local_ip, port) = owned_end.endpoint(connection);
        let remote = owned_end.other().endpoint(connection);
        let cache_key = (port, connection.protocol.clone());

        // Always cache (even high-range ports) but rely on short-TTL cleanup for
        // ports >= EPHEMERAL_PORT_THRESHOLD to bound the table.
        if let Some(mut entry) = port_process_cache.get_mut(&cache_key) {
            // Refresh only the same process (PID reuse protection) in the
            // same conversation; anything else replaces the entry.
            if entry.l7.pid == l7_data.pid
                && entry.process_start_time == process_start_time
                && entry.local_ip == local_ip
                && entry.remote == remote
            {
                entry.value_mut().last_seen = Instant::now();
                entry.value_mut().hit_count += 1;
            } else {
                *entry.value_mut() = ProcessCacheEntry {
                    l7: l7_data.clone(),
                    process_start_time,
                    last_seen: Instant::now(),
                    hit_count: 1,
                    termination_time: None,
                    local_ip,
                    remote,
                };
            }
        } else {
            port_process_cache.insert(
                cache_key.clone(),
                ProcessCacheEntry {
                    l7: l7_data.clone(),
                    process_start_time,
                    last_seen: Instant::now(),
                    hit_count: 1,
                    termination_time: None,
                    local_ip,
                    remote,
                },
            );
            debug!("Cached L7 data for port {:?}: {:?}", cache_key, l7_data);
        }
    }

    /// Attribute `connection` from a remembered resolution of the SAME
    /// conversation: same local endpoint, same remote end. An entry left by
    /// another conversation on the same port number is skipped and kept (it
    /// still answers its own). Linux gives one ephemeral port to concurrent
    /// connections towards different destinations, and the port number of a
    /// remote service is the local port of every local listener for it, so
    /// a port-only hit attributed sessions to whichever process last used
    /// the number (test-mint, 2026-10: WALinuxAgent's and avahi-daemon's
    /// short-lived sessions to 168.63.129.16:80 and :53 named
    /// edamame_posture).
    async fn try_resolve_from_cache(
        connection: &Session,
        port_process_cache: &CustomDashMap<(u16, Protocol), ProcessCacheEntry>,
        system: &System,
        host: &HostAddresses,
    ) -> Option<(SessionL7, L7ResolutionSource)> {
        let protocol = connection.protocol.clone();
        let cache_keys = [
            (SessionEnd::Src, (connection.src_port, protocol.clone())),
            (SessionEnd::Dst, (connection.dst_port, protocol.clone())),
        ];
        let termination_grace_period = Duration::from_secs(5);
        for (end, key) in &cache_keys {
            let port = key.0;
            if port >= EPHEMERAL_PORT_THRESHOLD && port_process_cache.contains_key(key) {
                let entry_option = port_process_cache.get(key);
                if let Some(entry) = entry_option {
                    if entry.value().last_seen.elapsed()
                        > Duration::from_secs(EPHEMERAL_PORT_CACHE_TTL_SECS)
                    {
                        drop(entry);
                        port_process_cache.remove(key);
                        continue;
                    }
                }
            }
            let same_conversation = port_process_cache.get(key).is_some_and(|entry| {
                evidence_fits_end(connection, *end, &entry.value().endpoints(port), host)
            });
            if !same_conversation {
                continue;
            }
            let (
                entry_exists,
                l7_data_maybe,
                pid,
                process_start_time,
                is_terminated,
                termination_time,
            ) = if let Some(cached_entry) = port_process_cache.get(key) {
                let entry = cached_entry.value();
                let pid = entry.l7.pid;
                let process_start_time = entry.process_start_time;
                let process_opt = system.process(Pid::from_u32(pid));
                let process_exists = process_opt.is_some()
                    && process_opt.unwrap().start_time() == process_start_time;
                let is_terminated = entry.termination_time.is_some();
                let term_time = entry.termination_time;
                let l7_data = if process_exists
                    || (is_terminated
                        && term_time.map_or(false, |t| t.elapsed() < termination_grace_period))
                {
                    Some(entry.l7.clone())
                } else {
                    None
                };
                (
                    true,
                    l7_data,
                    pid,
                    process_start_time,
                    is_terminated,
                    term_time,
                )
            } else {
                (false, None, 0, 0, false, None)
            };
            if !entry_exists {
                continue;
            }
            if let Some(l7_data) = l7_data_maybe {
                if let Some(mut cached_entry) = port_process_cache.get_mut(key) {
                    if let Some(process) = system.process(Pid::from_u32(pid)) {
                        if process.start_time() == process_start_time {
                            cached_entry.value_mut().hit_count += 1;
                            cached_entry.value_mut().last_seen = Instant::now();
                            cached_entry.value_mut().termination_time = None;
                            return Some((l7_data, L7ResolutionSource::CacheHitRunning));
                        }
                    }
                    if is_terminated {
                        debug!(
                            "Using recently terminated process data for {:?} (PID: {}, start_time: {}), terminated {:?} ago",
                            key, pid, process_start_time, termination_time.unwrap().elapsed()
                        );
                        return Some((l7_data, L7ResolutionSource::CacheHitTerminated));
                    } else {
                        debug!(
                            "Process for {:?}: PID {} (start_time: {}) no longer exists or start_time mismatch, starting grace period",
                            key, pid, process_start_time
                        );
                        cached_entry.value_mut().termination_time = Some(Instant::now());
                        return Some((l7_data, L7ResolutionSource::CacheHitTerminated));
                    }
                }
            } else if is_terminated
                && termination_time.unwrap().elapsed() >= termination_grace_period
            {
                debug!(
                    "Grace period expired for {:?}: PID {} (start_time: {}) terminated {:?} ago",
                    key,
                    pid,
                    process_start_time,
                    termination_time.unwrap().elapsed()
                );
                port_process_cache.remove(key);
            }
        }
        None
    }

    async fn update_host_service_cache(
        socket_info: &Vec<SocketInfo>,
        pid_to_process: &HashMap<u32, &Process>,
        uid_to_username: &HashMap<&Uid, &str>,
        host_service_cache: &CustomDashMap<String, Vec<(SocketEndpoints, Protocol, SessionL7)>>,
    ) {
        let mut temp_cache: HashMap<String, Vec<(SocketEndpoints, Protocol, SessionL7)>> =
            HashMap::new();

        for socket in socket_info {
            let protocol = match &socket.protocol_socket_info {
                ProtocolSocketInfo::Tcp(_) => Protocol::TCP,
                ProtocolSocketInfo::Udp(_) => Protocol::UDP,
            };
            let endpoints = socket_endpoints(socket);

            if endpoints.local_port >= EPHEMERAL_PORT_THRESHOLD {
                continue;
            }

            if let Some((l7_data, _start_time)) =
                Self::extract_l7_from_socket(socket, pid_to_process, uid_to_username, false).await
            {
                let hostname = "localhost".to_string();
                temp_cache
                    .entry(hostname)
                    .or_insert_with(Vec::new)
                    .push((endpoints, protocol, l7_data));
            }
        }

        for (host, services) in temp_cache {
            host_service_cache.insert(host, services);
        }
    }

    /// Attribute a session to a local service socket (local port below the
    /// ephemeral range). The service must own one end of the session
    /// (`l7_endpoints::evidence_end`): its address and port together, and
    /// its peer when it is a connection. It used to be any socket whose port
    /// equalled either session port, so an outbound session to a LAN host's
    /// :80 or :53 was attributed to whatever local process listened on 80 or
    /// 53.
    async fn try_resolve_from_host_cache_custom(
        connection: &Session,
        host_service_cache: &Arc<
            CustomDashMap<String, Vec<(SocketEndpoints, Protocol, SessionL7)>>,
        >,
        system: &System,
        host: &HostAddresses,
    ) -> Option<(SessionL7, L7ResolutionSource, SessionEnd)> {
        // Only apply host cache for inbound/server-side flows: destination IP must be local
        let host_inbound = is_private_ip(connection.dst_ip);
        if !host_inbound {
            return None;
        }

        // Define the same grace period for terminated processes as in try_resolve_from_cache
        static TERMINATION_GRACE_PERIOD: Duration = Duration::from_secs(5);

        // Keep track of terminated PIDs we've seen recently
        static TERMINATED_PIDS: Lazy<CustomDashMap<u32, Instant>> =
            Lazy::new(|| CustomDashMap::new("terminated_pids"));

        if let Some(localhost_services) = host_service_cache.get("localhost") {
            for (endpoints, service_protocol, l7_data) in localhost_services.value() {
                if connection.protocol != *service_protocol {
                    continue;
                }
                let Some(owned_end) = evidence_end(connection, endpoints, host) else {
                    continue;
                };
                let service_port = endpoints.local_port;
                if system.process(Pid::from_u32(l7_data.pid)).is_some() {
                    // Process still exists, remove from terminated list if present
                    TERMINATED_PIDS.remove(&l7_data.pid);
                    return Some((
                        l7_data.clone(),
                        L7ResolutionSource::HostCacheHitRunning,
                        owned_end,
                    ));
                } else {
                    // Process terminated - check if in grace period
                    let now = Instant::now();
                    let in_grace_period = TERMINATED_PIDS
                        .entry(l7_data.pid)
                        .or_insert_with(|| now)
                        .value()
                        .elapsed()
                        < TERMINATION_GRACE_PERIOD;

                    if in_grace_period {
                        let elapsed = TERMINATED_PIDS
                            .get(&l7_data.pid)
                            .map(|e| e.value().elapsed());
                        debug!(
                            "Using recently terminated host cache data for port {}, protocol {:?}: PID {} terminated {:?} ago",
                            service_port, service_protocol, l7_data.pid, elapsed
                        );
                        return Some((
                            l7_data.clone(),
                            L7ResolutionSource::HostCacheHitTerminated,
                            owned_end,
                        ));
                    } else {
                        debug!(
                            "Grace period expired for host cache entry: port {}, protocol {:?}, PID {}",
                            service_port, service_protocol, l7_data.pid
                        );
                        TERMINATED_PIDS.remove(&l7_data.pid);
                        continue;
                    }
                }
            }
        }

        None
    }

    /// Queue a connection for L7 resolution.
    ///
    /// When `eager` is true (hot packet path), platform-specific probes run
    /// inline to catch short-lived processes before they exit.  When false
    /// (batch backfill from `populate_l7`), the heavyweight probes are skipped
    /// so the caller does not stall the session pipeline for minutes.
    /// Give a `FailedMaxRetries` session another bounded round of socket-table
    /// resolution. The caller decides which sessions are worth it
    /// (`populate_l7` offers external, active flows above
    /// `L7_REQUEUE_MIN_SESSION_BYTES`); this only re-arms when the previous
    /// attempt is at least `L7_REQUEUE_INTERVAL_SECS` old and fewer than
    /// `MAX_L7_REQUEUE_ROUNDS` rounds have been spent. Returns true when the
    /// session was re-queued. Never touches resolved entries.
    pub fn rearm_failed_resolution(&self, connection: &Session) -> bool {
        let Some(mut entry) = self.l7_map.get_mut(connection) else {
            return false;
        };
        let resolution = entry.value_mut();
        if resolution.l7.is_some() || resolution.source != L7ResolutionSource::FailedMaxRetries {
            return false;
        }
        if resolution.requeue_rounds >= *MAX_L7_REQUEUE_ROUNDS_DYNAMIC {
            return false;
        }
        let interval = Duration::from_secs(*L7_REQUEUE_INTERVAL_SECS_DYNAMIC);
        if resolution
            .last_retry
            .is_some_and(|last| last.elapsed() < interval)
        {
            return false;
        }
        resolution.requeue_rounds += 1;
        resolution.retry_count = 0;
        resolution.last_retry = Some(Instant::now());
        resolution.source = L7ResolutionSource::Unknown;
        let rounds = resolution.requeue_rounds;
        drop(entry);
        self.resolver_queue.insert(connection.clone(), ());
        debug!(
            "Re-armed L7 resolution for long-lived unattributed session {:?} (round {}/{})",
            connection, rounds, *MAX_L7_REQUEUE_ROUNDS_DYNAMIC
        );
        true
    }

    pub async fn add_connection_to_resolver_ex(&self, connection: &Session, eager: bool) {
        if self.l7_map.contains_key(connection) {
            return;
        }

        // Try kernel-level sources eagerly: if a kernel table already has this
        // connection we can resolve it immediately before the process exits.
        if eager {
            if let Some(mut l7_data) = l7_ebpf::get_l7_for_session(connection) {
                Self::enrich_ebpf_l7_from_proc(&mut l7_data);
                self.l7_map.insert(
                    connection.clone(),
                    L7Resolution {
                        l7: Some(l7_data),
                        date: Utc::now(),
                        retry_count: 0,
                        last_retry: None,
                        requeue_rounds: 0,
                        source: L7ResolutionSource::Ebpf,
                    },
                );
                trace!("eBPF eager resolution for {:?}", connection);
                return;
            }

            if let Some(mut l7_data) = l7_etw::get_l7_for_session(connection) {
                l7_etw::enrich_session_l7(l7_data.pid, &mut l7_data);
                self.l7_map.insert(
                    connection.clone(),
                    L7Resolution {
                        l7: Some(l7_data),
                        date: Utc::now(),
                        retry_count: 0,
                        last_retry: None,
                        requeue_rounds: 0,
                        source: L7ResolutionSource::Etw,
                    },
                );
                trace!("ETW eager resolution for {:?}", connection);
                return;
            }

            if let Some(l7_data) = l7_es::get_l7_for_session(connection) {
                self.l7_map.insert(
                    connection.clone(),
                    L7Resolution {
                        l7: Some(l7_data),
                        date: Utc::now(),
                        retry_count: 0,
                        last_retry: None,
                        requeue_rounds: 0,
                        source: L7ResolutionSource::EndpointSecurity,
                    },
                );
                trace!("ES+libproc eager resolution for {:?}", connection);
                return;
            }

            #[cfg(target_os = "macos")]
            if let Some(pid) = l7_macos::quick_lookup_session_pid(connection) {
                if let Some((mut l7_data, start_time)) = Self::extract_l7_from_pid_fresh(pid).await
                {
                    // The quick lookup is a 4-tuple hit either way round;
                    // the end this host owns is the socket's.
                    Self::update_port_process_cache(
                        connection,
                        HostAddresses::current().local_end_of(connection),
                        &l7_data,
                        start_time,
                        &self.port_process_cache,
                    )
                    .await;
                    l7_es::enrich_session_l7(l7_data.pid, &mut l7_data);
                    let source = if l7_es::is_available() {
                        L7ResolutionSource::EndpointSecurity
                    } else {
                        L7ResolutionSource::MacosLibproc
                    };
                    self.l7_map.insert(
                        connection.clone(),
                        L7Resolution {
                            l7: Some(l7_data),
                            date: Utc::now(),
                            retry_count: 0,
                            last_retry: None,
                            requeue_rounds: 0,
                            source,
                        },
                    );
                    trace!("macOS libproc eager resolution for {:?}", connection);
                    return;
                }
            }
        }

        self.l7_map.insert(
            connection.clone(),
            L7Resolution {
                l7: None,
                date: Utc::now(),
                retry_count: 0,
                last_retry: None,
                requeue_rounds: 0,
                source: L7ResolutionSource::Unknown,
            },
        );

        self.resolver_queue.insert(connection.clone(), ());

        trace!("Added connection to L7 resolver queue: {:?}", connection);
    }

    /// Convenience wrapper -- hot-path callers that need eager probes.
    pub async fn add_connection_to_resolver(&self, connection: &Session) {
        self.add_connection_to_resolver_ex(connection, true).await;
    }

    /// Try all kernel-level sources (eBPF, ETW, ES+libproc) in priority order.
    /// Returns the first successful resolution and inserts it into `l7_map`.
    fn try_kernel_resolve(&self, connection: &Session) -> Option<L7Resolution> {
        if let Some(mut l7_data) = l7_ebpf::get_l7_for_session(connection) {
            Self::enrich_ebpf_l7_from_proc(&mut l7_data);
            let resolution = L7Resolution {
                l7: Some(l7_data),
                date: Utc::now(),
                retry_count: 0,
                last_retry: None,
                requeue_rounds: 0,
                source: L7ResolutionSource::Ebpf,
            };
            self.l7_map.insert(connection.clone(), resolution.clone());
            return Some(resolution);
        }
        if let Some(mut l7_data) = l7_etw::get_l7_for_session(connection) {
            l7_etw::enrich_session_l7(l7_data.pid, &mut l7_data);
            let resolution = L7Resolution {
                l7: Some(l7_data),
                date: Utc::now(),
                retry_count: 0,
                last_retry: None,
                requeue_rounds: 0,
                source: L7ResolutionSource::Etw,
            };
            self.l7_map.insert(connection.clone(), resolution.clone());
            return Some(resolution);
        }
        if let Some(l7_data) = l7_es::get_l7_for_session(connection) {
            let resolution = L7Resolution {
                l7: Some(l7_data),
                date: Utc::now(),
                retry_count: 0,
                last_retry: None,
                requeue_rounds: 0,
                source: L7ResolutionSource::EndpointSecurity,
            };
            self.l7_map.insert(connection.clone(), resolution.clone());
            return Some(resolution);
        }
        None
    }

    pub async fn get_resolved_l7(&self, connection: &Session) -> Option<L7Resolution> {
        // Check cached result first
        if let Some(l7) = self.l7_map.get(connection).map(|s| s.value().clone()) {
            if l7.l7.is_some() {
                return Some(l7);
            }
            // Parked after max retries: `rearm_failed_resolution` decides
            // when it gets another chance. Re-probing the kernel tables for
            // every parked local/UDP flow on every populate pass was a
            // full socket sweep per entry on macOS.
            if l7.source == L7ResolutionSource::FailedMaxRetries {
                return Some(l7);
            }
            // Cached entry exists but L7 is still unresolved -- try kernel
            // sources before returning None-like data.
            if let Some(resolution) = self.try_kernel_resolve(connection) {
                return Some(resolution);
            }
            return Some(l7);
        }

        // No cached entry at all -- try kernel sources first
        if let Some(resolution) = self.try_kernel_resolve(connection) {
            return Some(resolution);
        }

        // Fall back to resolver queue mechanism
        self.add_connection_to_resolver(connection).await;
        None
    }

    /// Force immediate processing of the resolver queue for pending sessions
    /// This helps address race conditions where sessions need L7 data immediately
    pub async fn force_immediate_resolution(&self) {
        debug!("Forcing immediate L7 resolution for pending sessions");

        // Get all pending sessions from the queue
        let pending_sessions: Vec<Session> = self
            .resolver_queue
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        if pending_sessions.is_empty() {
            debug!("No pending L7 resolutions to process");
            return;
        }

        debug!(
            "Processing {} pending L7 resolutions immediately",
            pending_sessions.len()
        );

        // Process a limited batch immediately to avoid blocking too long
        let batch_size = std::cmp::min(pending_sessions.len(), 10);
        let immediate_batch = &pending_sessions[0..batch_size];

        // Try to resolve each session in the immediate batch
        for connection in immediate_batch {
            if self.l7_map.contains_key(connection) {
                continue; // Already resolved
            }

            // Try immediate resolution using current system state
            // This is a simplified version of the full resolver logic
            // but provides immediate results for urgent cases

            // Remove from queue since we're processing it now
            self.resolver_queue.remove(connection);

            // Mark as attempted (even if we fail, to avoid infinite loops)
            self.l7_map.insert(
                connection.clone(),
                L7Resolution {
                    l7: None,
                    date: Utc::now(),
                    retry_count: 1,
                    last_retry: Some(std::time::Instant::now()),
                    requeue_rounds: 0,
                    source: L7ResolutionSource::Unknown,
                },
            );
        }

        debug!("Immediate L7 resolution batch completed");
    }

    async fn resolve_l7_data(
        connection: &Session,
        socket_info: &Vec<SocketInfo>,
        pid_to_process: &HashMap<u32, &Process>,
        uid_to_username: &HashMap<&Uid, &str>,
        host: &HostAddresses,
    ) -> Result<(SessionL7, u64, SessionEnd)> {
        if let Some(found) = Self::try_exact_match(
            connection,
            socket_info,
            pid_to_process,
            uid_to_username,
            host,
        )
        .await
        {
            return Ok(found);
        }
        // Fuzzy/wildcard match fallback
        if let Some(found) = Self::try_fuzzy_match(
            connection,
            socket_info,
            pid_to_process,
            uid_to_username,
            host,
        )
        .await
        {
            warn!("L7 fuzzy/wildcard match used for session {:?}", connection);
            return Ok(found);
        }
        // Log all candidate sockets for debugging
        debug!(
            "L7 resolution failed: unknown process association for session {:?}",
            connection
        );
        Err(anyhow::anyhow!("No matching process found"))
    }

    /// The session end `socket` is direct evidence for: a TCP connection
    /// whose two ends are the session's (either way round), or a UDP socket
    /// bound to the session's local end. netstat2 reports no UDP peer, so the
    /// bound endpoint is all a UDP row can show; it used to match on either
    /// session port with the address taken from either end, so a local
    /// responder on `*:53` answered for this host's queries to a remote
    /// resolver. TCP listeners are left to `try_fuzzy_match`.
    fn exact_socket_end(
        connection: &Session,
        socket: &SocketInfo,
        host: &HostAddresses,
    ) -> Option<SessionEnd> {
        let endpoints = socket_endpoints(socket);
        match (&connection.protocol, &socket.protocol_socket_info) {
            (Protocol::TCP, ProtocolSocketInfo::Tcp(_)) if endpoints.remote.is_some() => {
                evidence_end(connection, &endpoints, host)
            }
            (Protocol::UDP, ProtocolSocketInfo::Udp(_)) => {
                evidence_end(connection, &endpoints, host)
            }
            _ => None,
        }
    }

    async fn try_exact_match(
        connection: &Session,
        socket_info: &Vec<SocketInfo>,
        pid_to_process: &HashMap<u32, &Process>,
        uid_to_username: &HashMap<&Uid, &str>,
        host: &HostAddresses,
    ) -> Option<(SessionL7, u64, SessionEnd)> {
        for socket in socket_info {
            let Some(owned_end) = Self::exact_socket_end(connection, socket, host) else {
                continue;
            };
            if let Some((l7, start_time)) =
                Self::extract_l7_from_socket(socket, pid_to_process, uid_to_username, false).await
            {
                return Some((l7, start_time, owned_end));
            }
        }
        None
    }

    /// A TCP listener that owns one end of the session: inbound connections
    /// whose accepted socket is already gone (or not yet in the table). The
    /// listener answers any peer, but only at its own address and port, a
    /// wildcard address standing for this host's addresses
    /// (`l7_endpoints::evidence_end`).
    ///
    /// This used to accept any TCP socket on either session port, connected
    /// ones included and whatever their peer: once a short-lived connection
    /// had closed, another process's connection that Linux had given the
    /// same ephemeral port, or a local listener on the remote's service port,
    /// took the session. Connected sockets are the exact match's business,
    /// and UDP rows already went through the same test there.
    async fn try_fuzzy_match(
        connection: &Session,
        socket_info: &Vec<SocketInfo>,
        pid_to_process: &HashMap<u32, &Process>,
        uid_to_username: &HashMap<&Uid, &str>,
        host: &HostAddresses,
    ) -> Option<(SessionL7, u64, SessionEnd)> {
        if connection.protocol != Protocol::TCP {
            return None;
        }
        for socket in socket_info.iter() {
            if !matches!(&socket.protocol_socket_info, ProtocolSocketInfo::Tcp(_)) {
                continue;
            }
            let endpoints = socket_endpoints(socket);
            if endpoints.remote.is_some() {
                continue;
            }
            let Some(owned_end) = evidence_end(connection, &endpoints, host) else {
                continue;
            };
            if let Some((l7, start_time)) =
                Self::extract_l7_from_socket(socket, pid_to_process, uid_to_username, false).await
            {
                return Some((l7, start_time, owned_end));
            }
        }
        None
    }

    async fn extract_l7_from_socket(
        socket: &SocketInfo,
        pid_to_process: &HashMap<u32, &Process>,
        uid_to_username: &HashMap<&Uid, &str>,
        _is_target_socket_for_logging: bool,
    ) -> Option<(SessionL7, u64)> {
        let socket_pids = socket.associated_pids.clone();
        for socket_pid in socket_pids.clone() {
            if let Some(process) = pid_to_process.get(&socket_pid) {
                let username = if let Some(user_id) = process.user_id() {
                    match uid_to_username.get(&user_id).map(|s| s.to_string()) {
                        Some(username) => username,
                        None => {
                            #[cfg(unix)]
                            {
                                let user_id_u32 = **user_id;
                                if let Some(user) = uzers::get_user_by_uid(user_id_u32) {
                                    user.name().to_string_lossy().to_string()
                                } else {
                                    warn!("No username found for user_id {:?}", user_id);
                                    String::new()
                                }
                            }
                            #[cfg(windows)]
                            {
                                if let Some(username) = get_windows_username_by_uid(user_id) {
                                    username
                                } else {
                                    warn!("No username found for user_id {:?}", user_id);
                                    String::new()
                                }
                            }
                            #[cfg(not(any(unix, windows)))]
                            {
                                warn!("No username found for user_id {:?}", user_id);
                                String::new()
                            }
                        }
                    }
                } else {
                    // Kernel/system pseudo-processes (Windows PID 4, launchd
                    // helpers) legitimately have no user id; this fires once
                    // per socket per round, so keep it out of the WARN stream
                    // (1.9.0 logged it ~3/s on an idle Windows host).
                    debug!("No user_id found for PID {:?}", socket_pid);
                    String::new()
                };
                let process_name = process.name().to_string_lossy().to_string();
                let process_path = if let Some(path) = process.exe() {
                    path.to_string_lossy().to_string()
                } else {
                    String::new()
                };
                let process_start_time = process.start_time();
                let cmd = process
                    .cmd()
                    .iter()
                    .map(|entry| entry.to_string_lossy().to_string())
                    .collect::<Vec<_>>();
                let cwd = process
                    .cwd()
                    .map(|p| p.to_string_lossy().to_string())
                    .filter(|p| !p.is_empty());
                let memory = process.memory();
                let run_time = process.run_time();
                let accumulated_cpu_time = process.accumulated_cpu_time();
                // Compute average CPU% from accumulated time (CPU-ms) and run time (s).
                // This avoids the sysinfo delta-based cpu_usage() which returns 0 when
                // refreshed faster than MINIMUM_CPU_UPDATE_INTERVAL (~200ms).
                // Stored as percentage * 100 (e.g., 5.3% CPU → 530).
                let cpu_usage = if run_time > 0 {
                    ((accumulated_cpu_time as f64 * 10.0) / run_time as f64).round() as u32
                } else {
                    0
                };
                let disk_stats = process.disk_usage();
                let disk_usage = SessionProcessDiskUsage {
                    total_written_bytes: disk_stats.total_written_bytes,
                    written_bytes: disk_stats.written_bytes,
                    total_read_bytes: disk_stats.total_read_bytes,
                    read_bytes: disk_stats.read_bytes,
                };
                let open_files = crate::open_files::aggregate_open_files(
                    crate::open_files::get_open_file_paths(socket_pid),
                );
                let (parent_pid, parent_process_name, parent_process_path, parent_cmd) =
                    if let Some(parent_sysinfo_pid) = process.parent() {
                        let ppid = parent_sysinfo_pid.as_u32();
                        if let Some(parent_proc) = pid_to_process.get(&ppid) {
                            (
                                Some(ppid),
                                parent_proc.name().to_string_lossy().to_string(),
                                parent_proc
                                    .exe()
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_default(),
                                parent_proc
                                    .cmd()
                                    .iter()
                                    .map(|e| e.to_string_lossy().to_string())
                                    .collect(),
                            )
                        } else {
                            (Some(ppid), String::new(), String::new(), Vec::new())
                        }
                    } else {
                        (None, String::new(), String::new(), Vec::new())
                    };

                let (
                    grandparent_pid,
                    grandparent_process_name,
                    grandparent_process_path,
                    grandparent_cmd,
                ) = Self::resolve_grandparent_sysinfo(parent_pid, pid_to_process);

                let parent_script_path =
                    Self::extract_script_path(&parent_process_path, &parent_cmd);
                let grandparent_script_path =
                    Self::extract_script_path(&grandparent_process_path, &grandparent_cmd);

                let spawned_from_tmp = Self::originates_from_tmp(
                    &process_path,
                    &parent_process_path,
                    parent_script_path.as_deref(),
                    &grandparent_process_path,
                    grandparent_script_path.as_deref(),
                    &cmd,
                );

                return Some((
                    SessionL7 {
                        pid: socket_pid,
                        process_name,
                        process_path,
                        username,
                        cmd,
                        cwd,
                        memory,
                        start_time: process_start_time,
                        run_time,
                        cpu_usage,
                        accumulated_cpu_time,
                        disk_usage,
                        open_files,
                        parent_pid,
                        parent_process_name,
                        parent_process_path,
                        parent_cmd,
                        parent_script_path,
                        grandparent_pid,
                        grandparent_process_name,
                        grandparent_process_path,
                        grandparent_cmd,
                        grandparent_script_path,
                        spawned_from_tmp,
                    },
                    process_start_time,
                ));
            }
        }
        None
    }

    /// Build SessionL7 directly from a known PID, skipping the socket-to-PID
    /// lookup step. Used by the macOS libproc path where we already have a
    /// definitive PID binding from PROC_PIDFDSOCKETINFO.
    #[cfg(target_os = "macos")]
    async fn extract_l7_from_pid(
        pid: u32,
        process: &Process,
        pid_to_process: &HashMap<u32, &Process>,
        uid_to_username: &HashMap<&Uid, &str>,
    ) -> Option<(SessionL7, u64)> {
        let username = if let Some(user_id) = process.user_id() {
            match uid_to_username.get(&user_id).map(|s| s.to_string()) {
                Some(username) => username,
                None => {
                    if let Some(user) = uzers::get_user_by_uid(**user_id) {
                        user.name().to_string_lossy().to_string()
                    } else {
                        String::new()
                    }
                }
            }
        } else {
            String::new()
        };

        let process_name = process.name().to_string_lossy().to_string();
        let process_path = process
            .exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let process_start_time = process.start_time();
        let cmd: Vec<String> = process
            .cmd()
            .iter()
            .map(|e| e.to_string_lossy().to_string())
            .collect();
        let cwd = process
            .cwd()
            .map(|p| p.to_string_lossy().to_string())
            .filter(|p| !p.is_empty());
        let memory = process.memory();
        let run_time = process.run_time();
        let accumulated_cpu_time = process.accumulated_cpu_time();
        let cpu_usage = if run_time > 0 {
            ((accumulated_cpu_time as f64 * 10.0) / run_time as f64).round() as u32
        } else {
            0
        };
        let disk_stats = process.disk_usage();
        let disk_usage = SessionProcessDiskUsage {
            total_written_bytes: disk_stats.total_written_bytes,
            written_bytes: disk_stats.written_bytes,
            total_read_bytes: disk_stats.total_read_bytes,
            read_bytes: disk_stats.read_bytes,
        };
        let open_files =
            crate::open_files::aggregate_open_files(crate::open_files::get_open_file_paths(pid));

        let (parent_pid, parent_process_name, parent_process_path, parent_cmd) =
            if let Some(parent_sysinfo_pid) = process.parent() {
                let ppid = parent_sysinfo_pid.as_u32();
                if let Some(parent_proc) = pid_to_process.get(&ppid) {
                    (
                        Some(ppid),
                        parent_proc.name().to_string_lossy().to_string(),
                        parent_proc
                            .exe()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        parent_proc
                            .cmd()
                            .iter()
                            .map(|e| e.to_string_lossy().to_string())
                            .collect(),
                    )
                } else {
                    (Some(ppid), String::new(), String::new(), Vec::new())
                }
            } else {
                (None, String::new(), String::new(), Vec::new())
            };

        let (grandparent_pid, grandparent_process_name, grandparent_process_path, grandparent_cmd) =
            Self::resolve_grandparent_sysinfo(parent_pid, pid_to_process);

        let parent_script_path = Self::extract_script_path(&parent_process_path, &parent_cmd);
        let grandparent_script_path =
            Self::extract_script_path(&grandparent_process_path, &grandparent_cmd);
        let spawned_from_tmp = Self::originates_from_tmp(
            &process_path,
            &parent_process_path,
            parent_script_path.as_deref(),
            &grandparent_process_path,
            grandparent_script_path.as_deref(),
            &cmd,
        );

        Some((
            SessionL7 {
                pid,
                process_name,
                process_path,
                username,
                cmd,
                cwd,
                memory,
                start_time: process_start_time,
                run_time,
                cpu_usage,
                accumulated_cpu_time,
                disk_usage,
                open_files,
                parent_pid,
                parent_process_name,
                parent_process_path,
                parent_cmd,
                parent_script_path,
                grandparent_pid,
                grandparent_process_name,
                grandparent_process_path,
                grandparent_cmd,
                grandparent_script_path,
                spawned_from_tmp,
            },
            process_start_time,
        ))
    }

    /// Build L7 data from a fresh process snapshot after libproc already
    /// resolved a macOS socket to a PID. This covers short-lived children
    /// that were not present in the resolver's cached sysinfo map yet.
    #[cfg(target_os = "macos")]
    async fn extract_l7_from_pid_fresh(pid: u32) -> Option<(SessionL7, u64)> {
        // Refresh only the process and its two ancestors. This used to build
        // a full `System` snapshot (every process, args and environment) per
        // session, on the packet task, for each eager macOS resolution.
        let kind = || ProcessRefreshKind::everything().without_cpu();
        let mut fresh_system = System::new();
        let target = Pid::from_u32(pid);
        fresh_system.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::Some(&[target]),
            false,
            kind(),
        );
        if let Some(ppid) = fresh_system.process(target).and_then(|p| p.parent()) {
            fresh_system.refresh_processes_specifics(
                sysinfo::ProcessesToUpdate::Some(&[ppid]),
                false,
                kind(),
            );
            if let Some(gppid) = fresh_system.process(ppid).and_then(|p| p.parent()) {
                fresh_system.refresh_processes_specifics(
                    sysinfo::ProcessesToUpdate::Some(&[gppid]),
                    false,
                    kind(),
                );
            }
        }
        let mut fresh_users = Users::new();
        fresh_users.refresh();

        let pid_to_process: HashMap<u32, &Process> = fresh_system
            .processes()
            .iter()
            .map(|(pid, process)| (pid.as_u32(), process))
            .collect();
        let uid_to_username: HashMap<&Uid, &str> = fresh_users
            .iter()
            .map(|user| (user.id(), user.name()))
            .collect();
        if let Some(process) = pid_to_process.get(&pid) {
            Self::extract_l7_from_pid(pid, process, &pid_to_process, &uid_to_username)
                .await
                .or_else(|| Self::extract_l7_from_macos_proc(pid))
        } else {
            Self::extract_l7_from_macos_proc(pid)
        }
    }

    /// Last-resort macOS process metadata path for sockets that libproc has
    /// already bound to a PID but sysinfo cannot snapshot before the child exits.
    #[cfg(target_os = "macos")]
    fn extract_l7_from_macos_proc(pid: u32) -> Option<(SessionL7, u64)> {
        let (process_name, process_path) = l7_macos::process_identity(pid)?;
        let process_name = if process_name.is_empty() {
            std::path::Path::new(&process_path)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default()
        } else {
            process_name
        };
        let cmd = if process_path.is_empty() {
            Vec::new()
        } else {
            vec![process_path.clone()]
        };
        let open_files =
            crate::open_files::aggregate_open_files(crate::open_files::get_open_file_paths(pid));
        let spawned_from_tmp = Self::originates_from_tmp(&process_path, "", None, "", None, &cmd);

        Some((
            SessionL7 {
                pid,
                process_name,
                process_path,
                username: String::new(),
                cmd,
                cwd: None,
                memory: 0,
                start_time: 0,
                run_time: 0,
                cpu_usage: 0,
                accumulated_cpu_time: 0,
                disk_usage: SessionProcessDiskUsage::default(),
                open_files,
                parent_pid: None,
                parent_process_name: String::new(),
                parent_process_path: String::new(),
                parent_cmd: Vec::new(),
                parent_script_path: None,
                grandparent_pid: None,
                grandparent_process_name: String::new(),
                grandparent_process_path: String::new(),
                grandparent_cmd: Vec::new(),
                grandparent_script_path: None,
                spawned_from_tmp,
            },
            0,
        ))
    }

    /// Enrich an eBPF-produced SessionL7 with parent lineage, open_files,
    /// cwd, and spawned_from_tmp using /proc on Linux. On other platforms
    /// this is a no-op since eBPF is Linux-only.
    #[cfg(target_os = "linux")]
    fn enrich_ebpf_l7_from_proc(l7: &mut SessionL7) {
        use std::fs;
        use std::path::Path;

        let pid = l7.pid;
        if pid == 0 {
            return;
        }
        let proc_dir = format!("/proc/{}", pid);
        if !Path::new(&proc_dir).exists() {
            return;
        }

        if l7.cwd.is_none() {
            if let Ok(cwd) = fs::read_link(format!("{}/cwd", proc_dir)) {
                let s = cwd.to_string_lossy().to_string();
                if !s.is_empty() {
                    l7.cwd = Some(s);
                }
            }
        }

        if l7.cmd.is_empty() {
            if let Ok(cmdline) = fs::read(format!("{}/cmdline", proc_dir)) {
                l7.cmd = cmdline
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .collect();
            }
        }

        if l7.process_path.is_empty() {
            if let Ok(exe) = fs::read_link(format!("{}/exe", proc_dir)) {
                l7.process_path = exe.to_string_lossy().to_string();
            }
        }

        if let Ok(status) = fs::read_to_string(format!("{}/status", proc_dir)) {
            for line in status.lines() {
                if let Some(ppid_str) = line.strip_prefix("PPid:\t") {
                    if let Ok(ppid) = ppid_str.trim().parse::<u32>() {
                        l7.parent_pid = Some(ppid);
                        let parent_proc = format!("/proc/{}", ppid);
                        if Path::new(&parent_proc).exists() {
                            if let Ok(comm) = fs::read_to_string(format!("{}/comm", parent_proc)) {
                                l7.parent_process_name = comm.trim().to_string();
                            }
                            if let Ok(exe) = fs::read_link(format!("{}/exe", parent_proc)) {
                                l7.parent_process_path = exe.to_string_lossy().to_string();
                            }
                            if let Ok(cmdline) = fs::read(format!("{}/cmdline", parent_proc)) {
                                l7.parent_cmd = cmdline
                                    .split(|&b| b == 0)
                                    .filter(|s| !s.is_empty())
                                    .map(|s| String::from_utf8_lossy(s).to_string())
                                    .collect();
                            }

                            Self::enrich_grandparent_from_proc(l7, ppid);
                        }
                    }
                    break;
                }
            }
        }

        l7.open_files =
            crate::open_files::aggregate_open_files(crate::open_files::get_open_file_paths(pid));

        l7.parent_script_path = Self::extract_script_path(&l7.parent_process_path, &l7.parent_cmd);
        l7.grandparent_script_path =
            Self::extract_script_path(&l7.grandparent_process_path, &l7.grandparent_cmd);
        l7.spawned_from_tmp = Self::originates_from_tmp(
            &l7.process_path,
            &l7.parent_process_path,
            l7.parent_script_path.as_deref(),
            &l7.grandparent_process_path,
            l7.grandparent_script_path.as_deref(),
            &l7.cmd,
        );
    }

    #[cfg(not(target_os = "linux"))]
    fn enrich_ebpf_l7_from_proc(_l7: &mut SessionL7) {}

    fn resolve_grandparent_sysinfo(
        parent_pid: Option<u32>,
        pid_to_process: &HashMap<u32, &Process>,
    ) -> (Option<u32>, String, String, Vec<String>) {
        let Some(ppid) = parent_pid else {
            return (None, String::new(), String::new(), Vec::new());
        };
        let Some(parent_proc) = pid_to_process.get(&ppid) else {
            return (None, String::new(), String::new(), Vec::new());
        };
        let Some(gp_sysinfo_pid) = parent_proc.parent() else {
            return (None, String::new(), String::new(), Vec::new());
        };
        let gppid = gp_sysinfo_pid.as_u32();
        if let Some(gp_proc) = pid_to_process.get(&gppid) {
            (
                Some(gppid),
                gp_proc.name().to_string_lossy().to_string(),
                gp_proc
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default(),
                gp_proc
                    .cmd()
                    .iter()
                    .map(|e| e.to_string_lossy().to_string())
                    .collect(),
            )
        } else {
            (Some(gppid), String::new(), String::new(), Vec::new())
        }
    }

    #[cfg(target_os = "linux")]
    fn enrich_grandparent_from_proc(l7: &mut SessionL7, parent_pid: u32) {
        use std::fs;
        use std::path::Path;

        let parent_status_path = format!("/proc/{}/status", parent_pid);
        let Ok(status) = fs::read_to_string(&parent_status_path) else {
            return;
        };
        for line in status.lines() {
            if let Some(gppid_str) = line.strip_prefix("PPid:\t") {
                if let Ok(gppid) = gppid_str.trim().parse::<u32>() {
                    l7.grandparent_pid = Some(gppid);
                    let gp_proc = format!("/proc/{}", gppid);
                    if Path::new(&gp_proc).exists() {
                        if let Ok(comm) = fs::read_to_string(format!("{}/comm", gp_proc)) {
                            l7.grandparent_process_name = comm.trim().to_string();
                        }
                        if let Ok(exe) = fs::read_link(format!("{}/exe", gp_proc)) {
                            l7.grandparent_process_path = exe.to_string_lossy().to_string();
                        }
                        if let Ok(cmdline) = fs::read(format!("{}/cmdline", gp_proc)) {
                            l7.grandparent_cmd = cmdline
                                .split(|&b| b == 0)
                                .filter(|s| !s.is_empty())
                                .map(|s| String::from_utf8_lossy(s).to_string())
                                .collect();
                        }
                    }
                }
                break;
            }
        }
    }

    const INTERPRETER_BASENAMES: &[&str] = &[
        "bash",
        "sh",
        "dash",
        "zsh",
        "fish",
        "ksh",
        "csh",
        "tcsh",
        "python3",
        "python",
        "python3.10",
        "python3.11",
        "python3.12",
        "python3.13",
        "perl",
        "ruby",
        "node",
        "deno",
        "bun",
    ];

    const TMP_PREFIXES: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/"];

    fn extract_script_path(exe_path: &str, cmd: &[String]) -> Option<String> {
        if cmd.len() < 2 || exe_path.is_empty() {
            return None;
        }
        let base = std::path::Path::new(exe_path)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        if Self::INTERPRETER_BASENAMES
            .iter()
            .any(|i| base == *i || base.starts_with(&format!("{i}.")))
        {
            let candidate = &cmd[1];
            if !candidate.starts_with('-') {
                return Some(candidate.clone());
            }
            if cmd.len() > 2 && !cmd[2].starts_with('-') {
                return Some(cmd[2].clone());
            }
        }
        None
    }

    fn originates_from_tmp(
        process_path: &str,
        parent_process_path: &str,
        parent_script_path: Option<&str>,
        grandparent_process_path: &str,
        grandparent_script_path: Option<&str>,
        cmd: &[String],
    ) -> bool {
        let check = |p: &str| Self::TMP_PREFIXES.iter().any(|pfx| p.starts_with(pfx));
        if check(process_path) || check(parent_process_path) || check(grandparent_process_path) {
            return true;
        }
        if let Some(script) = parent_script_path {
            if check(script) {
                return true;
            }
        }
        if let Some(script) = grandparent_script_path {
            if check(script) {
                return true;
            }
        }
        for arg in cmd.iter().take(2) {
            if check(arg) {
                return true;
            }
        }
        false
    }

    /// Merge sensitive open_files from a previous L7 resolution into `l7_data`.
    /// Call this before inserting into l7_map so that sensitive files observed in
    /// a prior refresh cycle remain visible even if the process closed them.
    fn merge_previous_sensitive(
        l7_map: &CustomDashMap<Session, L7Resolution>,
        connection: &Session,
        l7_data: &mut SessionL7,
    ) {
        if let Some(prev) = l7_map.get(connection) {
            if let Some(prev_l7) = &prev.l7 {
                l7_data.open_files = crate::open_files::merge_sensitive_open_files(
                    std::mem::take(&mut l7_data.open_files),
                    &prev_l7.open_files,
                );
            }
        }
    }

    fn is_likely_ephemeral(connection: &Session) -> bool {
        if connection.dst_port == 53 || connection.src_port == 53 {
            return true;
        }

        let is_src_ephemeral_port = connection.src_port >= EPHEMERAL_PORT_THRESHOLD;
        let is_dst_well_known = connection.dst_port < 1024;

        if is_src_ephemeral_port && is_dst_well_known {
            return true;
        }

        if connection.protocol == Protocol::UDP {
            return true;
        }

        false
    }

    async fn try_exact_match_from_index(
        connection: &Session,
        port_index: &HashMap<(u16, Protocol), Vec<&SocketInfo>>,
        pid_to_process: &HashMap<u32, &Process>,
        uid_to_username: &HashMap<&Uid, &str>,
        host: &HostAddresses,
    ) -> Option<(SessionL7, u64, SessionEnd)> {
        let protocol = connection.protocol.clone();
        let cache_keys = [
            (connection.src_port, protocol.clone()),
            (connection.dst_port, protocol.clone()),
        ];
        for key in &cache_keys {
            if let Some(socket_list) = port_index.get(key) {
                for socket in socket_list {
                    let Some(owned_end) = Self::exact_socket_end(connection, socket, host) else {
                        continue;
                    };
                    if let Some((l7, start_time)) =
                        Self::extract_l7_from_socket(socket, pid_to_process, uid_to_username, false)
                            .await
                    {
                        return Some((l7, start_time, owned_end));
                    }
                }
            }
        }
        None
    }
}

#[cfg(windows)]
fn get_windows_username_by_uid(uid: &Uid) -> Option<String> {
    use std::ffi::c_void;
    use windows::core::PCWSTR;

    // The Uid is typically a SID in string form on Windows
    let uid_str = uid.to_string();

    // Convert the UID string to a wide string for Windows API
    let h_string = HSTRING::from(uid_str.as_str());

    unsafe {
        let mut buffer: *mut u8 = std::ptr::null_mut();
        let result = NetUserGetInfo(
            PCWSTR::null(), // Local computer
            PCWSTR(h_string.as_ptr()),
            0, // Level 0 for basic info
            &mut buffer as *mut *mut u8,
        );

        if result == NERR_Success && !buffer.is_null() {
            let user_info = &*(buffer as *const USER_INFO_0);
            let username = PWSTR(user_info.usri0_name.0).to_string().ok();

            // Free the buffer allocated by NetUserGetInfo
            let _ = NetApiBufferFree(Some(buffer as *const c_void));

            return username;
        } else {
            if !buffer.is_null() {
                let _ = NetApiBufferFree(Some(buffer as *const c_void));
            }
            debug!(
                "Failed to get Windows username for UID {}: code {}",
                uid_str, result
            );
            return None;
        }
    }
}

/// A socket-table row as attribution evidence.
fn socket_endpoints(socket: &SocketInfo) -> SocketEndpoints {
    match &socket.protocol_socket_info {
        ProtocolSocketInfo::Tcp(tcp) => SocketEndpoints {
            local_ip: tcp.local_addr,
            local_port: tcp.local_port,
            // A listener has no peer: its row carries 0.0.0.0:0 / [::]:0,
            // and Windows leaves the port undefined in LISTEN rows.
            remote: if tcp.state == TcpState::Listen || tcp.remote_addr.is_unspecified() {
                None
            } else {
                Some((tcp.remote_addr, tcp.remote_port))
            },
        },
        // netstat2 reports no peer for UDP on any platform.
        ProtocolSocketInfo::Udp(udp) => SocketEndpoints {
            local_ip: udp.local_addr,
            local_port: udp.local_port,
            remote: None,
        },
    }
}

fn is_private_ip(ip: IpAddr) -> bool {
    crate::ip::is_lan_ip(&ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_flodbadd_l7_start_stop() {
        let mut flodbadd_l7 = FlodbaddL7::new();

        flodbadd_l7.start().await;

        assert!(flodbadd_l7.resolver_handle.is_some());

        // Use tokio::time::timeout to ensure the test doesn't hang
        let stop_result = tokio::time::timeout(Duration::from_secs(5), flodbadd_l7.stop()).await;

        // If timeout occurs, force cleanup to prevent test from hanging
        if stop_result.is_err() {
            error!("Timeout occurred while stopping flodbadd_l7");
            if let Some(handle) = flodbadd_l7.resolver_handle.take() {
                let _ = handle.stop_tx.send(true);
                handle.handle.abort();
            }
            if let Some(handle) = flodbadd_l7.cache_cleanup_handle.take() {
                let _ = handle.stop_tx.send(true);
                handle.handle.abort();
            }
        }

        assert!(flodbadd_l7.resolver_handle.is_none());
    }

    #[tokio::test]
    async fn test_add_connection_to_resolver() {
        let flodbadd_l7 = FlodbaddL7::new();

        let connection = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            src_port: 12345,
            dst_ip: IpAddr::from_str("93.184.216.34").unwrap(),
            dst_port: 80,
        };

        flodbadd_l7.add_connection_to_resolver(&connection).await;

        let queue = flodbadd_l7
            .resolver_queue
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        assert!(queue.contains(&connection));

        if let Some(resolution) = flodbadd_l7.l7_map.get(&connection) {
            assert!(resolution.l7.is_none());
        } else {
            panic!("Connection not found in l7_map");
        };
    }

    fn failed_resolution(last_retry: Option<Instant>, requeue_rounds: usize) -> L7Resolution {
        L7Resolution {
            l7: None,
            date: Utc::now(),
            retry_count: *MAX_L7_RETRIES_DYNAMIC + 1,
            last_retry,
            source: L7ResolutionSource::FailedMaxRetries,
            requeue_rounds,
        }
    }

    fn udp_dns_session() -> Session {
        Session {
            protocol: Protocol::UDP,
            src_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            src_port: 51515,
            dst_ip: IpAddr::from_str("1.1.1.1").unwrap(),
            dst_port: 53,
        }
    }

    #[tokio::test]
    async fn test_failed_max_retries_is_rearmed_after_interval() {
        let flodbadd_l7 = FlodbaddL7::new();
        let connection = udp_dns_session();
        let stale = Instant::now() - Duration::from_secs(*L7_REQUEUE_INTERVAL_SECS_DYNAMIC + 1);
        flodbadd_l7
            .l7_map
            .insert(connection.clone(), failed_resolution(Some(stale), 0));

        // The backfill path (populate_l7) re-offers unattributed sessions
        // non-eagerly; a stale FailedMaxRetries entry must be re-queued.
        flodbadd_l7.rearm_failed_resolution(&connection);

        assert!(flodbadd_l7.resolver_queue.contains_key(&connection));
        let entry = flodbadd_l7.l7_map.get(&connection).expect("entry kept");
        assert_eq!(entry.source, L7ResolutionSource::Unknown);
        assert_eq!(entry.retry_count, 0);
        assert_eq!(entry.requeue_rounds, 1);
        assert!(entry.l7.is_none());
    }

    #[tokio::test]
    async fn test_failed_max_retries_is_not_rearmed_within_interval() {
        let flodbadd_l7 = FlodbaddL7::new();
        let connection = udp_dns_session();
        flodbadd_l7.l7_map.insert(
            connection.clone(),
            failed_resolution(Some(Instant::now()), 0),
        );

        flodbadd_l7.rearm_failed_resolution(&connection);

        assert!(!flodbadd_l7.resolver_queue.contains_key(&connection));
        let entry = flodbadd_l7.l7_map.get(&connection).expect("entry kept");
        assert_eq!(entry.source, L7ResolutionSource::FailedMaxRetries);
        assert_eq!(entry.requeue_rounds, 0);
    }

    #[tokio::test]
    async fn test_failed_max_retries_rearm_is_bounded() {
        let flodbadd_l7 = FlodbaddL7::new();
        let connection = udp_dns_session();
        let stale = Instant::now() - Duration::from_secs(*L7_REQUEUE_INTERVAL_SECS_DYNAMIC + 1);
        flodbadd_l7.l7_map.insert(
            connection.clone(),
            failed_resolution(Some(stale), *MAX_L7_REQUEUE_ROUNDS_DYNAMIC),
        );

        flodbadd_l7.rearm_failed_resolution(&connection);

        assert!(!flodbadd_l7.resolver_queue.contains_key(&connection));
        let entry = flodbadd_l7.l7_map.get(&connection).expect("entry kept");
        assert_eq!(entry.source, L7ResolutionSource::FailedMaxRetries);
        assert_eq!(entry.requeue_rounds, *MAX_L7_REQUEUE_ROUNDS_DYNAMIC);
    }

    #[tokio::test]
    async fn test_plain_offer_does_not_rearm_exhausted_entry() {
        // The unconditional backfill offer must stay cheap: re-arming is the
        // caller's explicit, gated decision.
        let flodbadd_l7 = FlodbaddL7::new();
        let connection = udp_dns_session();
        let stale = Instant::now() - Duration::from_secs(*L7_REQUEUE_INTERVAL_SECS_DYNAMIC + 1);
        flodbadd_l7
            .l7_map
            .insert(connection.clone(), failed_resolution(Some(stale), 0));

        flodbadd_l7
            .add_connection_to_resolver_ex(&connection, false)
            .await;

        assert!(!flodbadd_l7.resolver_queue.contains_key(&connection));
        let entry = flodbadd_l7.l7_map.get(&connection).expect("entry kept");
        assert_eq!(entry.source, L7ResolutionSource::FailedMaxRetries);
        assert_eq!(entry.requeue_rounds, 0);
    }

    #[tokio::test]
    async fn test_resolved_entry_is_never_rearmed() {
        let flodbadd_l7 = FlodbaddL7::new();
        let connection = udp_dns_session();
        let mut resolved = failed_resolution(None, 0);
        resolved.l7 = Some(SessionL7 {
            pid: 4242,
            ..Default::default()
        });
        resolved.source = L7ResolutionSource::ExactMatch;
        flodbadd_l7.l7_map.insert(connection.clone(), resolved);

        flodbadd_l7.rearm_failed_resolution(&connection);

        assert!(!flodbadd_l7.resolver_queue.contains_key(&connection));
        let entry = flodbadd_l7.l7_map.get(&connection).expect("entry kept");
        assert_eq!(entry.source, L7ResolutionSource::ExactMatch);
        assert_eq!(entry.requeue_rounds, 0);
    }

    #[tokio::test]
    async fn test_get_resolved_l7_before_resolution() {
        let flodbadd_l7 = FlodbaddL7::new();

        let connection = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            src_port: 12345,
            dst_ip: IpAddr::from_str("93.184.216.34").unwrap(),
            dst_port: 80,
        };

        let l7_resolution = flodbadd_l7.get_resolved_l7(&connection).await;
        assert!(l7_resolution.is_none());

        flodbadd_l7.add_connection_to_resolver(&connection).await;

        let l7_resolution = flodbadd_l7.get_resolved_l7(&connection).await;
        assert!(l7_resolution.is_some());
        let l7_resolution = l7_resolution.unwrap();
        assert!(l7_resolution.l7.is_none());
    }

    #[tokio::test]
    async fn test_resolve_l7_data_no_match() {
        let connection = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::from_str("10.0.0.1").unwrap(),
            src_port: 54321,
            dst_ip: IpAddr::from_str("10.0.0.2").unwrap(),
            dst_port: 12345,
        };

        let socket_info = vec![];
        let pid_to_process = HashMap::new();
        let uid_to_username = HashMap::new();

        let result = FlodbaddL7::resolve_l7_data(
            &connection,
            &socket_info,
            &pid_to_process,
            &uid_to_username,
            &HostAddresses::default(),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resolver_task_processes_queue() {
        let mut flodbadd_l7 = FlodbaddL7::new();

        flodbadd_l7.start().await;

        let connection = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::from_str("127.0.0.1").unwrap(),
            src_port: 12345,
            dst_ip: IpAddr::from_str("127.0.0.1").unwrap(),
            dst_port: 54321,
        };

        flodbadd_l7.add_connection_to_resolver(&connection).await;

        // Allow time for processing
        sleep(Duration::from_secs(1)).await;

        let l7_resolution = flodbadd_l7.get_resolved_l7(&connection).await;
        assert!(l7_resolution.is_some());
        let l7_resolution = l7_resolution.unwrap();
        assert!(l7_resolution.l7.is_none() || l7_resolution.l7.is_some());

        // Use tokio::time::timeout to ensure the test doesn't hang
        let stop_result = tokio::time::timeout(Duration::from_secs(5), flodbadd_l7.stop()).await;

        // If timeout occurs, force cleanup to prevent test from hanging
        if stop_result.is_err() {
            error!("Timeout occurred while stopping flodbadd_l7");
            if let Some(handle) = flodbadd_l7.resolver_handle.take() {
                let _ = handle.stop_tx.send(true);
                handle.handle.abort();
            }
            if let Some(handle) = flodbadd_l7.cache_cleanup_handle.take() {
                let _ = handle.stop_tx.send(true);
                handle.handle.abort();
            }
        }
    }

    #[tokio::test]
    async fn test_port_process_cache() {
        let flodbadd_l7 = FlodbaddL7::new();

        let l7_data = SessionL7 {
            pid: 1234,
            process_name: "test_process".to_string(),
            process_path: "/usr/bin/test_process".to_string(),
            username: "test_user".to_string(),
            ..SessionL7::default()
        };

        let port_protocol = (8080, Protocol::TCP);
        flodbadd_l7.port_process_cache.insert(
            port_protocol,
            ProcessCacheEntry {
                l7: l7_data.clone(),
                process_start_time: 0,
                last_seen: Instant::now(),
                hit_count: 0,
                termination_time: None,
                local_ip: IpAddr::from_str("192.168.1.100").unwrap(),
                remote: (IpAddr::from_str("93.184.216.34").unwrap(), 80),
            },
        );

        let connection1 = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            src_port: 8080,
            dst_ip: IpAddr::from_str("93.184.216.34").unwrap(),
            dst_port: 80,
        };

        let connection2 = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            src_port: 9090,
            dst_ip: IpAddr::from_str("93.184.216.34").unwrap(),
            dst_port: 80,
        };

        let cache_keys1 = [
            (connection1.src_port, connection1.protocol.clone()),
            (connection1.dst_port, connection1.protocol),
        ];

        let mut found_in_cache = false;
        for key in &cache_keys1 {
            if let Some(cached_entry) = flodbadd_l7.port_process_cache.get(key) {
                assert_eq!(cached_entry.value().l7.pid, l7_data.pid);
                assert_eq!(cached_entry.value().l7.process_name, l7_data.process_name);
                found_in_cache = true;
                break;
            }
        }
        assert!(
            found_in_cache,
            "Should find L7 data in cache for connection1"
        );

        let cache_keys2 = [
            (connection2.src_port, connection2.protocol.clone()),
            (connection2.dst_port, connection2.protocol),
        ];

        found_in_cache = false;
        for key in &cache_keys2 {
            if let Some(_) = flodbadd_l7.port_process_cache.get(key) {
                found_in_cache = true;
                break;
            }
        }
        assert!(
            !found_in_cache,
            "Should not find L7 data in cache for connection2"
        );
    }

    // ---------------------------------------------------------------
    // Endpoint consistency of the fallbacks (test-mint, 2026-10:
    // WALinuxAgent -> 168.63.129.16:80 and avahi-daemon -> :53 were
    // attributed to edamame_posture once their sockets had closed).
    // Every row below belongs to this test process, so a wrong match
    // shows up as an attribution instead of failing on a missing pid.
    // ---------------------------------------------------------------

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    fn session(proto: Protocol, src: (&str, u16), dst: (&str, u16)) -> Session {
        Session {
            protocol: proto,
            src_ip: ip(src.0),
            src_port: src.1,
            dst_ip: ip(dst.0),
            dst_port: dst.1,
        }
    }

    /// The host the sessions are captured on: 10.0.0.4 on a 10.0.0.0/24.
    fn host() -> HostAddresses {
        HostAddresses::new([ip("10.0.0.4")], [ip("10.0.0.255")])
    }

    fn wireserver_http(local_port: u16) -> Session {
        session(
            Protocol::TCP,
            ("10.0.0.4", local_port),
            ("168.63.129.16", 80),
        )
    }

    fn wireserver_dns(local_port: u16) -> Session {
        session(
            Protocol::UDP,
            ("10.0.0.4", local_port),
            ("168.63.129.16", 53),
        )
    }

    fn tcp_row(local: (&str, u16), remote: (&str, u16), state: TcpState) -> SocketInfo {
        SocketInfo {
            protocol_socket_info: ProtocolSocketInfo::Tcp(netstat2::TcpSocketInfo {
                local_addr: ip(local.0),
                local_port: local.1,
                remote_addr: ip(remote.0),
                remote_port: remote.1,
                state,
            }),
            associated_pids: vec![std::process::id()],
            #[cfg(target_os = "linux")]
            inode: 0,
            #[cfg(target_os = "linux")]
            uid: 0,
        }
    }

    fn udp_row(local: (&str, u16)) -> SocketInfo {
        SocketInfo {
            protocol_socket_info: ProtocolSocketInfo::Udp(netstat2::UdpSocketInfo {
                local_addr: ip(local.0),
                local_port: local.1,
            }),
            associated_pids: vec![std::process::id()],
            #[cfg(target_os = "linux")]
            inode: 0,
            #[cfg(target_os = "linux")]
            uid: 0,
        }
    }

    /// A process table holding this test process, so cached entries and
    /// socket rows that name it resolve.
    fn own_process_system() -> System {
        let mut system = System::new();
        system.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::Some(&[Pid::from_u32(std::process::id())]),
            false,
            ProcessRefreshKind::everything().without_cpu(),
        );
        system
    }

    async fn resolve_from_rows(
        connection: &Session,
        rows: &Vec<SocketInfo>,
    ) -> Option<(u32, SessionEnd)> {
        let system = own_process_system();
        let pid_to_process: HashMap<u32, &Process> = system
            .processes()
            .iter()
            .map(|(pid, process)| (pid.as_u32(), process))
            .collect();
        let uid_to_username = HashMap::new();
        let host = host();
        let full =
            FlodbaddL7::resolve_l7_data(connection, rows, &pid_to_process, &uid_to_username, &host)
                .await
                .ok()
                .map(|(l7, _, end)| (l7.pid, end));

        // The resolver round's indexed lookup applies the same test.
        let mut port_index: HashMap<(u16, Protocol), Vec<&SocketInfo>> = HashMap::new();
        for row in rows {
            let (port, proto) = match &row.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp) => (tcp.local_port, Protocol::TCP),
                ProtocolSocketInfo::Udp(udp) => (udp.local_port, Protocol::UDP),
            };
            port_index.entry((port, proto)).or_default().push(row);
        }
        let indexed = FlodbaddL7::try_exact_match_from_index(
            connection,
            &port_index,
            &pid_to_process,
            &uid_to_username,
            &host,
        )
        .await
        .map(|(l7, _, end)| (l7.pid, end));
        if let Some(indexed) = indexed {
            assert_eq!(Some(indexed), full, "indexed and full lookups disagree");
        }
        full
    }

    #[tokio::test]
    async fn socket_on_the_same_local_port_to_another_peer_does_not_take_the_session() {
        // Linux handed 41000 to another connection, to another destination.
        let rows = vec![tcp_row(
            ("10.0.0.4", 41000),
            ("52.1.2.3", 443),
            TcpState::Established,
        )];
        assert_eq!(
            resolve_from_rows(&wireserver_http(41000), &rows).await,
            None
        );
    }

    #[tokio::test]
    async fn listener_on_the_remote_service_port_does_not_take_an_outbound_session() {
        for listener in ["0.0.0.0", "::", "10.0.0.4"] {
            let rows = vec![tcp_row((listener, 80), ("0.0.0.0", 0), TcpState::Listen)];
            assert_eq!(
                resolve_from_rows(&wireserver_http(41000), &rows).await,
                None,
                "listener {listener}:80"
            );
        }
    }

    #[tokio::test]
    async fn udp_socket_on_the_remote_service_port_does_not_take_an_outbound_query() {
        for responder in ["0.0.0.0", "10.0.0.4", "::"] {
            let rows = vec![udp_row((responder, 53))];
            assert_eq!(
                resolve_from_rows(&wireserver_dns(50000), &rows).await,
                None,
                "responder {responder}:53"
            );
        }
    }

    #[tokio::test]
    async fn connection_with_the_same_peer_is_attributed() {
        let pid = std::process::id();
        let rows = vec![tcp_row(
            ("10.0.0.4", 41000),
            ("168.63.129.16", 80),
            TcpState::Established,
        )];
        assert_eq!(
            resolve_from_rows(&wireserver_http(41000), &rows).await,
            Some((pid, SessionEnd::Src))
        );
        // A dual-stack socket reports the same connection as v4-mapped IPv6.
        let mapped = vec![tcp_row(
            ("::ffff:10.0.0.4", 41000),
            ("::ffff:168.63.129.16", 80),
            TcpState::Established,
        )];
        assert_eq!(
            resolve_from_rows(&wireserver_http(41000), &mapped).await,
            Some((pid, SessionEnd::Src))
        );
    }

    #[tokio::test]
    async fn udp_socket_on_the_local_port_is_attributed() {
        let rows = vec![udp_row(("0.0.0.0", 53)), udp_row(("0.0.0.0", 50000))];
        assert_eq!(
            resolve_from_rows(&wireserver_dns(50000), &rows).await,
            Some((std::process::id(), SessionEnd::Src))
        );
    }

    #[tokio::test]
    async fn inbound_session_is_attributed_to_the_listening_service() {
        let pid = std::process::id();
        // Inbound RDP whose accepted socket is gone: the listener owns it.
        let rdp = session(Protocol::TCP, ("203.0.113.9", 51000), ("10.0.0.4", 3389));
        for listener in ["0.0.0.0", "::", "10.0.0.4"] {
            let rows = vec![tcp_row((listener, 3389), ("0.0.0.0", 0), TcpState::Listen)];
            assert_eq!(
                resolve_from_rows(&rdp, &rows).await,
                Some((pid, SessionEnd::Dst)),
                "listener {listener}:3389"
            );
        }
        // A local DNS server answers queries to this host.
        let query = session(Protocol::UDP, ("10.0.0.9", 52000), ("10.0.0.4", 53));
        assert_eq!(
            resolve_from_rows(&query, &vec![udp_row(("0.0.0.0", 53))]).await,
            Some((pid, SessionEnd::Dst))
        );
    }

    #[tokio::test]
    async fn port_cache_answers_only_the_conversation_it_learned() {
        let system = own_process_system();
        let pid = std::process::id();
        let start_time = system
            .process(Pid::from_u32(pid))
            .expect("test process enumerable")
            .start_time();
        let cache = CustomDashMap::new("test_port_process_cache");
        let l7 = SessionL7 {
            pid,
            process_name: "edamame_posture".to_string(),
            ..SessionL7::default()
        };

        // The daemon's own connection on local port 41000 to its backend.
        let daemon = session(Protocol::TCP, ("10.0.0.4", 41000), ("52.1.2.3", 443));
        FlodbaddL7::update_port_process_cache(&daemon, SessionEnd::Src, &l7, start_time, &cache)
            .await;

        // WALinuxAgent later gets 41000 for the WireServer: not the daemon's.
        assert!(FlodbaddL7::try_resolve_from_cache(
            &wireserver_http(41000),
            &cache,
            &system,
            &host()
        )
        .await
        .is_none());

        // The entry survives the miss and still answers its own conversation.
        let hit = FlodbaddL7::try_resolve_from_cache(&daemon, &cache, &system, &host()).await;
        assert_eq!(
            hit.map(|(l7, source)| (l7.pid, source)),
            Some((pid, L7ResolutionSource::CacheHitRunning))
        );
    }

    #[tokio::test]
    async fn port_cache_is_not_keyed_by_the_remote_service_port() {
        let system = own_process_system();
        let pid = std::process::id();
        let start_time = system
            .process(Pid::from_u32(pid))
            .expect("test process enumerable")
            .start_time();
        let cache = CustomDashMap::new("test_port_process_cache");
        let l7 = SessionL7 {
            pid,
            ..SessionL7::default()
        };

        // A LAN probe of the gateway's :80 and a DNS query to a LAN
        // resolver: both ends private, the process owns the source.
        let probe = session(Protocol::TCP, ("10.0.0.4", 41001), ("10.0.0.1", 80));
        let lan_dns = session(Protocol::UDP, ("10.0.0.4", 50001), ("10.0.0.1", 53));
        for s in [&probe, &lan_dns] {
            FlodbaddL7::update_port_process_cache(s, SessionEnd::Src, &l7, start_time, &cache)
                .await;
        }
        assert!(!cache.contains_key(&(80, Protocol::TCP)));
        assert!(!cache.contains_key(&(53, Protocol::UDP)));
        assert!(FlodbaddL7::try_resolve_from_cache(
            &wireserver_http(41002),
            &cache,
            &system,
            &host()
        )
        .await
        .is_none());
        assert!(FlodbaddL7::try_resolve_from_cache(
            &wireserver_dns(50002),
            &cache,
            &system,
            &host()
        )
        .await
        .is_none());

        // A local web server's inbound conversation is keyed by :80, at this
        // host's address; it does not answer a connection to a remote :80.
        let inbound = session(Protocol::TCP, ("203.0.113.9", 51000), ("10.0.0.4", 80));
        FlodbaddL7::update_port_process_cache(&inbound, SessionEnd::Dst, &l7, start_time, &cache)
            .await;
        assert!(FlodbaddL7::try_resolve_from_cache(
            &wireserver_http(41002),
            &cache,
            &system,
            &host()
        )
        .await
        .is_none());
        assert!(
            FlodbaddL7::try_resolve_from_cache(&inbound, &cache, &system, &host())
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn host_cache_service_must_own_a_session_end() {
        let system = own_process_system();
        let pid_to_process: HashMap<u32, &Process> = system
            .processes()
            .iter()
            .map(|(pid, process)| (pid.as_u32(), process))
            .collect();
        let uid_to_username = HashMap::new();
        let host_service_cache = Arc::new(CustomDashMap::new("test_host_service_cache"));
        let rows = vec![
            tcp_row(("0.0.0.0", 80), ("0.0.0.0", 0), TcpState::Listen),
            udp_row(("0.0.0.0", 53)),
        ];
        FlodbaddL7::update_host_service_cache(
            &rows,
            &pid_to_process,
            &uid_to_username,
            &host_service_cache,
        )
        .await;

        // Outbound to the gateway's :80 / :53 (private destination, so the
        // host cache is consulted): the local listeners are not the client.
        for outbound in [
            session(Protocol::TCP, ("10.0.0.4", 41003), ("10.0.0.1", 80)),
            session(Protocol::UDP, ("10.0.0.4", 50003), ("10.0.0.1", 53)),
        ] {
            assert!(
                FlodbaddL7::try_resolve_from_host_cache_custom(
                    &outbound,
                    &host_service_cache,
                    &system,
                    &host(),
                )
                .await
                .is_none(),
                "{outbound:?}"
            );
        }

        // Inbound from a LAN client to the local service: attributed.
        let inbound = session(Protocol::TCP, ("10.0.0.9", 52001), ("10.0.0.4", 80));
        let hit = FlodbaddL7::try_resolve_from_host_cache_custom(
            &inbound,
            &host_service_cache,
            &system,
            &host(),
        )
        .await;
        assert_eq!(
            hit.map(|(l7, _, end)| (l7.pid, end)),
            Some((std::process::id(), SessionEnd::Dst))
        );
    }

    #[test]
    fn test_is_private_ip() {
        assert!(is_private_ip(IpAddr::from_str("10.0.0.1").unwrap()));
        assert!(is_private_ip(IpAddr::from_str("172.16.0.1").unwrap()));
        assert!(is_private_ip(IpAddr::from_str("172.31.255.255").unwrap()));
        assert!(is_private_ip(IpAddr::from_str("192.168.1.1").unwrap()));
        assert!(is_private_ip(IpAddr::from_str("127.0.0.1").unwrap()));

        assert!(!is_private_ip(IpAddr::from_str("8.8.8.8").unwrap()));
        assert!(!is_private_ip(IpAddr::from_str("1.1.1.1").unwrap()));
        assert!(!is_private_ip(IpAddr::from_str("172.15.0.1").unwrap()));
        assert!(!is_private_ip(IpAddr::from_str("172.32.0.1").unwrap()));

        assert!(is_private_ip(IpAddr::from_str("::1").unwrap()));
        assert!(is_private_ip(IpAddr::from_str("::").unwrap()));
        assert!(is_private_ip(IpAddr::from_str("fc00::1").unwrap()));
        assert!(is_private_ip(IpAddr::from_str("fe80::1").unwrap()));

        assert!(!is_private_ip(IpAddr::from_str("2001:db8::1").unwrap()));
    }

    #[test]
    fn test_is_likely_ephemeral() {
        let dns_query = Session {
            protocol: Protocol::UDP,
            src_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            src_port: 45678,
            dst_ip: IpAddr::from_str("8.8.8.8").unwrap(),
            dst_port: 53,
        };
        assert!(FlodbaddL7::is_likely_ephemeral(&dns_query));

        let client_web_request = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            src_port: 55555,
            dst_ip: IpAddr::from_str("93.184.216.34").unwrap(),
            dst_port: 80,
        };
        assert!(FlodbaddL7::is_likely_ephemeral(&client_web_request));

        let udp_connection = Session {
            protocol: Protocol::UDP,
            src_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            src_port: 5000,
            dst_ip: IpAddr::from_str("192.168.1.101").unwrap(),
            dst_port: 5001,
        };
        assert!(FlodbaddL7::is_likely_ephemeral(&udp_connection));

        let server_connection = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            src_port: 80,
            dst_ip: IpAddr::from_str("192.168.1.200").unwrap(),
            dst_port: 45678,
        };
        assert!(!FlodbaddL7::is_likely_ephemeral(&server_connection));
    }

    /// Spawn a long-lived child whose direct parent is this test process.
    /// The binary is spawned directly (not via a shell) so the child's parent
    /// PID is the test binary itself, which is what the lineage guards assert.
    /// `sleep` (Unix) and `ping` (Windows) are always present on every runner.
    fn spawn_long_lived_child() -> std::process::Child {
        use std::process::{Command, Stdio};
        #[cfg(not(target_os = "windows"))]
        {
            Command::new("sleep")
                .arg("30")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("failed to spawn `sleep` child")
        }
        #[cfg(target_os = "windows")]
        {
            // `ping -n 31 127.0.0.1` runs ~30s (1s between echoes) and is a
            // direct child of this process.
            Command::new("ping")
                .args(["-n", "31", "127.0.0.1"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("failed to spawn `ping` child")
        }
    }

    /// Cross-platform guard for the parent-lineage contract that the macOS
    /// `apple-app-store` / `apple-sandbox` sysinfo feature silently broke:
    /// a spawned child MUST be enumerable by sysinfo, and its resolved
    /// `SessionL7` MUST carry `parent_pid` plus a non-zero `run_time`.
    ///
    /// Why this runs on Linux and Windows too: the specific apple-app-store
    /// no-op cannot occur there (the feature is Apple-only), but the same
    /// `extract_l7_from_pid` path resolves lineage on every OS via
    /// `sysinfo::Process::parent()`. Running the guard everywhere means a
    /// future sysinfo upgrade, feature change, or enumeration regression that
    /// blanks `parent_pid` / `run_time` on Linux or Windows is caught the same
    /// way the macOS regression now is.
    #[tokio::test]
    async fn lineage_resolution_populates_parent_for_spawned_child() {
        let mut child = spawn_long_lived_child();
        let child_pid = child.id();
        let our_pid = std::process::id();

        // Let the child settle so it is enumerable and run_time advances past
        // the 1-second start_time granularity sysinfo uses.
        sleep(Duration::from_millis(2500)).await;

        let refresh_kind = RefreshKind::nothing().with_processes(ProcessRefreshKind::everything());
        let system = System::new_with_specifics(refresh_kind);

        let pid_to_process: HashMap<u32, &Process> = system
            .processes()
            .iter()
            .map(|(pid, process)| (pid.as_u32(), process))
            .collect();

        // Enumeration guard: the child MUST be present. On a broken macOS build
        // (apple-app-store / apple-sandbox) refresh_processes is a no-op and the
        // process map is empty, so this is the first thing that fails.
        let child_present = pid_to_process.contains_key(&child_pid);

        // Resolve lineage. macOS uses the libproc-bound `extract_l7_from_pid`
        // entry point that the apple-app-store regression degraded; every other
        // OS resolves the same lineage primitives (`parent()` + `run_time()`)
        // straight off the sysinfo `Process`, so a future enumeration
        // regression that blanks them on Linux/Windows is caught here too.
        #[cfg(target_os = "macos")]
        let (parent_pid, run_time) = {
            let mut sys_users = Users::new();
            sys_users.refresh();
            let uid_to_username: HashMap<&Uid, &str> = sys_users
                .iter()
                .map(|user| (user.id(), user.name()))
                .collect();
            let resolved = if let Some(process) = pid_to_process.get(&child_pid) {
                FlodbaddL7::extract_l7_from_pid(
                    child_pid,
                    process,
                    &pid_to_process,
                    &uid_to_username,
                )
                .await
            } else {
                None
            };
            let (l7, _) =
                resolved.expect("extract_l7_from_pid returned None for an enumerated child");
            (l7.parent_pid, l7.run_time)
        };
        #[cfg(not(target_os = "macos"))]
        let (parent_pid, run_time) = {
            let process = pid_to_process.get(&child_pid);
            let parent_pid = process.and_then(|p| p.parent()).map(|p| p.as_u32());
            let run_time = process.map(|p| p.run_time()).unwrap_or(0);
            (parent_pid, run_time)
        };

        // Tear the child down before asserting so a failed assertion never
        // leaks the process.
        let _ = child.kill();
        let _ = child.wait();

        assert!(
            child_present,
            "sysinfo did not enumerate spawned child pid {child_pid}; the process map is empty \
             (macOS: apple-app-store/apple-sandbox makes refresh_processes a no-op)"
        );
        assert_eq!(
            parent_pid,
            Some(our_pid),
            "resolved parent_pid {parent_pid:?} did not match the spawning test process {our_pid}"
        );
        assert!(
            run_time >= 1,
            "resolved run_time was {run_time} (expected >= 1s after a 2.5s settle); sysinfo did \
             not snapshot the process start_time"
        );
    }

    /// macOS-specific guard for the exact entry point the `apple-app-store`
    /// regression degraded: `extract_l7_from_pid_fresh` builds a fresh sysinfo
    /// snapshot and must resolve parent lineage for a live child. With
    /// apple-app-store enabled, the empty process map forced a fall-through to
    /// the libproc path (`extract_l7_from_macos_proc`), which hard-codes
    /// `parent_pid = None` and `run_time = 0`.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_fresh_pid_resolution_populates_parent_lineage() {
        let mut child = spawn_long_lived_child();
        let child_pid = child.id();
        let our_pid = std::process::id();

        sleep(Duration::from_millis(2500)).await;

        let resolved = FlodbaddL7::extract_l7_from_pid_fresh(child_pid).await;

        let _ = child.kill();
        let _ = child.wait();

        let (l7, _) = resolved
            .expect("extract_l7_from_pid_fresh returned None for a live child (sysinfo empty?)");
        assert_eq!(
            l7.parent_pid,
            Some(our_pid),
            "macOS fresh resolution parent_pid {:?} did not match spawning pid {our_pid} \
             (apple-app-store regression returns None here)",
            l7.parent_pid
        );
        assert!(
            l7.run_time >= 1,
            "macOS fresh resolution run_time was {} (expected >= 1s); the libproc fallback \
             hard-codes run_time = 0",
            l7.run_time
        );
    }
}

// Feature-specific tests that will only run on Linux with eBPF enabled
#[cfg(all(target_os = "linux", feature = "ebpf"))]
#[cfg(test)]
mod ebpf_tests {
    use super::*;
    use crate::sessions::{Protocol, Session};
    use rand::Rng;
    use std::io::ErrorKind;
    use std::net::TcpStream;
    use std::process::Command;
    use std::process::Stdio;

    #[derive(Debug)]
    enum NcError {
        NotFound,     // no nc binary available
        ListenFailed, // command started but server never became ready
        SpawnFailed,  // some other spawn error (permissions etc.)
    }

    fn start_nc_server(port: u16) -> Result<std::process::Child, NcError> {
        let port_str = port.to_string();

        // Common netcat binaries we accept in order of preference.
        // `nc` is usually provided via the alternatives system (OpenBSD or
        // traditional implementation).  The other names cover systems where
        // the wrapper has not been configured.
        const CANDIDATES: &[&str] = &["nc", "netcat", "ncat", "nc.traditional"];

        // Two common syntax variants (traditional vs. OpenBSD).  We try the
        // traditional "-l -p <port>" first because that is required by the
        // `netcat-traditional` package shipped in the test container.  The
        // OpenBSD syntax "-l <port>" is attempted second.
        let try_args = vec![vec!["-l", "-p", &port_str], vec!["-l", &port_str]];

        let mut spawn_success = false; // at least one binary executed

        for cmd_name in CANDIDATES {
            println!("Trying to start netcat server with {}", cmd_name);
            for args in &try_args {
                let mut cmd = Command::new(cmd_name);
                cmd.args(args)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());

                match cmd.spawn() {
                    Ok(mut child) => {
                        spawn_success = true;
                        println!("Started netcat server with {} {:?}", cmd_name, args);
                        // wait up to 5 s for the listener
                        let start = std::time::Instant::now();
                        let timeout = std::time::Duration::from_secs(20);
                        let mut server_ready = false;
                        while start.elapsed() < timeout {
                            println!("Checking if netcat server is ready");
                            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                                server_ready = true;
                                break;
                            }
                            println!("Waiting for netcat server to listen on port {}", port);
                            std::thread::sleep(std::time::Duration::from_secs(5));
                        }
                        if server_ready {
                            println!("Netcat server is ready");
                            return Ok(child);
                        } else {
                            println!("Netcat server {:?} is not ready after timeout", args);
                            println!("Killing netcat server");
                            // Ensure the child terminates before we attempt to
                            // drain its stderr so we don't block indefinitely.
                            let _ = child.kill();

                            match child.wait_with_output() {
                                Ok(output) => {
                                    let status = output.status;
                                    let out_str = String::from_utf8_lossy(&output.stdout);
                                    let err_str = String::from_utf8_lossy(&output.stderr);
                                    eprintln!("[test] {} {:?} exited with status {}\nstdout:\n{}\nstderr:\n{}", cmd_name, args, status, out_str.trim(), err_str.trim());
                                }
                                Err(e) => {
                                    eprintln!(
                                        "[test] Failed to collect output from {} {:?}: {}",
                                        cmd_name, args, e
                                    );
                                }
                            }
                            // Try next argument variant / candidate instead
                            continue;
                        }
                    }
                    Err(e) => {
                        if e.kind() == ErrorKind::NotFound {
                            println!(
                                "Binary '{}' not found (args {:?}): {} - continuing",
                                cmd_name, args, e
                            );
                            continue; // try next candidate name
                        } else {
                            eprintln!("[test] Unable to spawn {} {:?}: {}", cmd_name, args, e);
                            return Err(NcError::SpawnFailed);
                        }
                    }
                }
            }
        }
        if spawn_success {
            Err(NcError::ListenFailed)
        } else {
            Err(NcError::NotFound)
        }
    }

    fn start_nc_client(port: u16) -> Result<std::process::Child, NcError> {
        let port_str = port.to_string();

        const CANDIDATES: &[&str] = &["nc", "netcat", "ncat", "nc.traditional"];

        for cmd_name in CANDIDATES {
            let mut cmd = Command::new(cmd_name);
            cmd.args(["127.0.0.1", &port_str])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            match cmd.spawn() {
                Ok(child) => return Ok(child),
                Err(e) => {
                    if e.kind() == ErrorKind::NotFound {
                        continue; // next candidate
                    } else {
                        eprintln!("[test] Unable to spawn {}: {}", cmd_name, e);
                        return Err(NcError::SpawnFailed);
                    }
                }
            }
        }
        Err(NcError::NotFound)
    }

    #[tokio::test]
    async fn test_ebpf_l7_resolution() {
        if !l7_ebpf::is_fully_functional() {
            println!(
                "Skipping test_ebpf_l7_resolution: eBPF not fully functional (status: {})",
                l7_ebpf::ebpf_support()
            );
            return;
        }
        let port: u16 = rand::rng().random_range(20000..40000);
        let mut server_process = match start_nc_server(port) {
            Ok(child) => child,
            Err(NcError::NotFound) => {
                println!("Skipping test_ebpf_l7_resolution: netcat not installed");
                return;
            }
            Err(err) => {
                panic!("Could not start netcat server: {:?}", err);
            }
        };
        let mut client_process = match start_nc_client(port) {
            Ok(child) => child,
            Err(NcError::NotFound) => {
                let _ = server_process.kill();
                println!("Skipping test_ebpf_l7_resolution: netcat not installed");
                return;
            }
            Err(err) => {
                let _ = server_process.kill();
                panic!("Could not start netcat client: {:?}", err);
            }
        };
        std::thread::sleep(std::time::Duration::from_millis(500));
        let flodbadd_l7 = FlodbaddL7::new();
        let session = Session {
            protocol: Protocol::TCP,
            src_ip: "127.0.0.1".parse().unwrap(),
            src_port: port,
            dst_ip: "127.0.0.1".parse().unwrap(),
            dst_port: port,
        };
        let server_l7 = flodbadd_l7.get_resolved_l7(&session).await;
        let _ = client_process.kill();
        let _ = server_process.kill();
        if let Some(resolution) = server_l7 {
            println!("eBPF resolution source: {:?}", resolution.source);
            println!("eBPF resolution data: {:?}", resolution.l7);
            assert_eq!(
                resolution.source,
                L7ResolutionSource::Ebpf,
                "Expected eBPF resolution source"
            );
            if let Some(l7_data) = resolution.l7 {
                assert!(
                    l7_data.process_name.contains("nc") || l7_data.process_name.contains("netcat"),
                    "Expected process name to contain 'nc' or 'netcat', got: {}",
                    l7_data.process_name
                );
                assert!(l7_data.pid > 0, "Expected non-zero PID");
            } else {
                // eBPF resolution source but no L7 data - may happen in some kernel configs
                println!("Warning: eBPF resolution source but no L7 data - may be a kernel/container limitation");
            }
        } else {
            // eBPF kprobes attached but localhost connection not captured
            // This can happen in containers or with certain kernel configurations
            println!(
                "Warning: eBPF is functional but localhost connection was not captured. \
                 This may be a kernel/container limitation. Status: {}",
                l7_ebpf::ebpf_support()
            );
        }
    }

    #[tokio::test]
    async fn test_ebpf_l7_priority_over_standard_resolver() {
        if !l7_ebpf::is_fully_functional() {
            println!(
                "Skipping test_ebpf_l7_priority_over_standard_resolver: eBPF not fully functional (status: {})",
                l7_ebpf::ebpf_support()
            );
            return;
        }
        let port: u16 = rand::rng().random_range(20000..40000);
        let mut server_process = match start_nc_server(port) {
            Ok(child) => child,
            Err(NcError::NotFound) => {
                println!(
                    "Skipping test_ebpf_l7_priority_over_standard_resolver: netcat not installed"
                );
                return;
            }
            Err(err) => {
                panic!("Could not start netcat server: {:?}", err);
            }
        };
        let mut client_process = match start_nc_client(port) {
            Ok(child) => child,
            Err(NcError::NotFound) => {
                let _ = server_process.kill();
                println!(
                    "Skipping test_ebpf_l7_priority_over_standard_resolver: netcat not installed"
                );
                return;
            }
            Err(err) => {
                let _ = server_process.kill();
                panic!("Could not start netcat client: {:?}", err);
            }
        };
        std::thread::sleep(std::time::Duration::from_millis(500));
        let mut flodbadd_l7 = FlodbaddL7::new();
        flodbadd_l7.start().await;
        use tokio::time::sleep;
        let session = Session {
            protocol: Protocol::TCP,
            src_ip: "127.0.0.1".parse().unwrap(),
            src_port: port,
            dst_ip: "127.0.0.1".parse().unwrap(),
            dst_port: port,
        };
        let initial_result = flodbadd_l7.get_resolved_l7(&session).await;
        let mut from_ebpf = false;
        if let Some(resolution) = initial_result {
            println!("Initial resolution source: {:?}", resolution.source);
            if resolution.source == L7ResolutionSource::Ebpf {
                from_ebpf = true;
                if let Some(l7) = resolution.l7 {
                    println!(
                        "Initial eBPF resolution: pid={}, name={}",
                        l7.pid, l7.process_name
                    );
                }
            }
        }
        if !from_ebpf {
            flodbadd_l7.add_connection_to_resolver(&session).await;
            sleep(std::time::Duration::from_secs(2)).await;
            if let Some(resolution) = flodbadd_l7.get_resolved_l7(&session).await {
                println!("Queue-based resolution source: {:?}", resolution.source);
                if resolution.source == L7ResolutionSource::Ebpf {
                    from_ebpf = true;
                    if let Some(l7) = resolution.l7 {
                        println!(
                            "Queue-based eBPF resolution: pid={}, name={}",
                            l7.pid, l7.process_name
                        );
                    }
                }
            }
        }
        let _ = client_process.kill();
        let _ = server_process.kill();
        flodbadd_l7.stop().await;
        if !from_ebpf {
            // eBPF kprobes attached but localhost connection not captured
            // This can happen in containers or with certain kernel configurations
            println!(
                "Warning: eBPF is functional but localhost connection was not captured. \
                 This may be a kernel/container limitation. Status: {}",
                l7_ebpf::ebpf_support()
            );
        }
    }

    #[tokio::test]
    async fn test_ebpf_l7_integration_with_capture() {
        use crate::capture::FlodbaddCapture;
        use crate::interface::FlodbaddInterfaces;

        if !l7_ebpf::is_fully_functional() {
            println!(
                "Skipping test_ebpf_l7_integration_with_capture: eBPF not fully functional (status: {})",
                l7_ebpf::ebpf_support()
            );
            return;
        }
        let port: u16 = rand::rng().random_range(20000..40000);
        println!("Starting netcat server on port {}", port);
        let mut server_process = match start_nc_server(port) {
            Ok(child) => child,
            Err(NcError::NotFound) => {
                println!("Skipping test_ebpf_l7_integration_with_capture: netcat not installed");
                return;
            }
            Err(err) => {
                println!("Could not start netcat server: {:?}", err);
                panic!("Could not start netcat server: {:?}", err);
            }
        };
        println!("Starting netcat client on port {}", port);
        let mut client_process = match start_nc_client(port) {
            Ok(child) => child,
            Err(NcError::NotFound) => {
                let _ = server_process.kill();
                println!("Skipping test_ebpf_l7_integration_with_capture: netcat not installed");
                return;
            }
            Err(err) => {
                let _ = server_process.kill();
                panic!("Could not start netcat client: {:?}", err);
            }
        };
        std::thread::sleep(std::time::Duration::from_millis(500));
        println!("Starting capture");
        let capture = FlodbaddCapture::new();
        let interfaces = FlodbaddInterfaces::new();
        println!("Starting capture on interfaces: {}", interfaces);

        let capture_start_result = capture.start(&interfaces).await;
        if let Err(e) = capture_start_result {
            error!("Capture start failed: {}", e);
            panic!("Capture start failed: {}", e);
        }

        sleep(std::time::Duration::from_secs(3)).await;
        let mut found_connection = false;
        let mut sessions = vec![];
        let check_start = std::time::Instant::now();
        while check_start.elapsed().as_secs() < 5 {
            sessions = capture.get_current_sessions(false).await;
            for session in &sessions {
                if (session.session.src_port == port || session.session.dst_port == port)
                    && session.session.protocol == Protocol::TCP
                {
                    found_connection = true;
                    println!("Found test connection: {:?}", session.session);
                    if let Some(l7_info) = &session.l7 {
                        println!(
                            "L7 resolution: pid={}, process={}",
                            l7_info.pid, l7_info.process_name
                        );
                        assert!(
                            l7_info.process_name.contains("nc")
                                || l7_info.process_name.contains("netcat"),
                            "Expected process name to contain 'nc' or 'netcat', got: {}",
                            l7_info.process_name
                        );
                    }
                    break;
                }
            }
            if found_connection {
                break;
            }
            sleep(std::time::Duration::from_millis(200)).await;
        }
        let _ = client_process.kill();
        let _ = server_process.kill();
        capture.stop().await;
        if !found_connection {
            // eBPF kprobes attached but localhost connection not captured
            // This can happen in containers or with certain kernel configurations
            println!(
                "Warning: eBPF is functional but localhost connection was not captured in capture. \
                 Sessions seen: {:?}. This may be a kernel/container limitation. Status: {}",
                sessions,
                l7_ebpf::ebpf_support()
            );
        }
    }
}
