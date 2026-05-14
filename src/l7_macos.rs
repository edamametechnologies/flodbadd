// macOS-native socket-to-PID resolution via libproc's PROC_PIDFDSOCKETINFO.
//
// Builds a Session -> PID map by iterating every process's file descriptors
// and calling proc_pidfdinfo(PROC_PIDFDSOCKETINFO) on socket FDs. This is a
// direct replacement for the netstat2 code path on macOS, eliminating the
// external dependency for socket enumeration and giving us:
//   - Direct PID binding (no separate associated_pids lookup)
//   - TCP state visibility (via tcpsi_state)
//   - Better UDP accuracy (socket FDs carry the binding info)

#![cfg(target_os = "macos")]

use crate::sessions::{Protocol, Session};
use std::collections::HashMap;
use std::ffi::CStr;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::raw::c_char;
use tracing::trace;

// --- Constants from <sys/proc_info.h> ---

const PROC_PIDLISTFDS: i32 = 1;
const PROC_PIDFDSOCKETINFO: i32 = 3;
const PROX_FDTYPE_SOCKET: u32 = 2;
const AF_INET: i32 = 2;
const AF_INET6: i32 = 30;
const IPPROTO_TCP: i32 = 6;
const IPPROTO_UDP: i32 = 17;
const SOCKINFO_TCP: i32 = 2;
const SOCKINFO_IN: i32 = 1;
const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;

// --- FFI struct definitions ---
// Layouts validated against macOS arm64/x86_64 headers via offsetof/sizeof tests.

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
struct proc_fdinfo {
    proc_fd: i32,
    proc_fdtype: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
struct proc_fileinfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
struct in4in6_addr {
    i46a_pad32: [u32; 3],
    i46a_addr4: [u8; 4],
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
struct in_sockinfo {
    insi_fport: i32, // foreign port (network byte order in the struct, but kernel fills host order)
    insi_lport: i32, // local port
    insi_gencnt: u64,
    insi_flags: u32,
    insi_flow: u32,
    insi_vflag: u8, // INI_IPV4 = 1, INI_IPV6 = 2
    insi_ip_ttl: u8,
    _pad: [u8; 6],      // alignment to offset 32
    insi_faddr: InAddr, // foreign address (union)
    insi_laddr: InAddr, // local address (union)
    insi_v4: u8,
    insi_v6: u8,
    _pad2: [u8; 10], // pad to 80 bytes total
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
union InAddr {
    ina_46: in4in6_addr,
    ina_6: [u8; 16],
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
struct tcp_sockinfo {
    tcpsi_ini: in_sockinfo,
    tcpsi_state: i32,
    tcpsi_timer: [i32; 4],
    tcpsi_mss: i32,
    tcpsi_flags: u32,
    _pad: [u8; 4],
    tcpsi_tp: u64,
}

// vinfo_stat: 136 bytes (exact layout from offsetof checks)
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
struct vinfo_stat {
    _data: [u8; 136],
}

// sockbuf_info: 24 bytes
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
struct sockbuf_info {
    _data: [u8; 24],
}

// The soi_proto union is 528 bytes (largest member: un_sockinfo at 528).
// We only read tcp_sockinfo (120) or in_sockinfo (80) from it.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
union soi_proto_union {
    pri_tcp: tcp_sockinfo, // SOCKINFO_TCP
    pri_in: in_sockinfo,   // SOCKINFO_IN
    _pad: [u8; 528],
}

// socket_info: 768 bytes total
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
struct socket_info {
    soi_stat: vinfo_stat,       // off 0,   size 136
    soi_so: u64,                // off 136,  size 8
    soi_pcb: u64,               // off 144,  size 8
    soi_type: i32,              // off 152
    soi_protocol: i32,          // off 156
    soi_family: i32,            // off 160
    soi_options: i16,           // off 164
    soi_linger: i16,            // off 166
    soi_state: i16,             // off 168
    soi_qlen: i16,              // off 170
    soi_incqlen: i16,           // off 172
    soi_qlimit: i16,            // off 174
    soi_timeo: i16,             // off 176
    soi_error: u16,             // off 178
    soi_oobmark: u32,           // off 180
    soi_rcv: sockbuf_info,      // off 184, size 24
    soi_snd: sockbuf_info,      // off 208, size 24
    soi_kind: i32,              // off 232
    _pad_kind: [u8; 4],         // alignment pad to offset 240
    soi_proto: soi_proto_union, // off 240, size 528
}

// socket_fdinfo: 792 bytes total (24 + 768)
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
struct socket_fdinfo {
    pfi: proc_fileinfo, // off 0,  size 24
    psi: socket_info,   // off 24, size 768
}

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
    fn proc_listallpids(buffer: *mut i32, buffersize: i32) -> i32;
    fn proc_pidpath(pid: i32, buffer: *mut std::ffi::c_void, buffersize: u32) -> i32;
    fn proc_name(pid: i32, buffer: *mut std::ffi::c_void, buffersize: u32) -> i32;
}

/// Lightweight process identity from libproc. Unlike sysinfo's process
/// snapshot, this can resolve very short-lived child processes immediately
/// after socket-to-PID attribution.
pub fn process_identity(pid: u32) -> Option<(String, String)> {
    let mut name_buf = vec![0u8; 1024];
    let name_len = unsafe {
        proc_name(
            pid as i32,
            name_buf.as_mut_ptr() as *mut std::ffi::c_void,
            name_buf.len() as u32,
        )
    };
    let process_name = if name_len > 0 {
        let len = (name_len as usize).min(name_buf.len());
        String::from_utf8_lossy(&name_buf[..len])
            .trim_end_matches('\0')
            .to_string()
    } else {
        String::new()
    };

    let mut path_buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE];
    let path_len = unsafe {
        proc_pidpath(
            pid as i32,
            path_buf.as_mut_ptr() as *mut std::ffi::c_void,
            path_buf.len() as u32,
        )
    };
    let process_path = if path_len > 0 {
        unsafe { CStr::from_ptr(path_buf.as_ptr() as *const c_char) }
            .to_string_lossy()
            .to_string()
    } else {
        String::new()
    };

    if process_name.is_empty() && process_path.is_empty() {
        None
    } else {
        Some((process_name, process_path))
    }
}

fn decode_addr(addr: &InAddr, vflag: u8, family: i32) -> Option<IpAddr> {
    unsafe {
        if family == AF_INET || vflag == 1 {
            Some(IpAddr::V4(Ipv4Addr::from(addr.ina_46.i46a_addr4)))
        } else if family == AF_INET6 || vflag == 2 {
            Some(IpAddr::V6(Ipv6Addr::from(addr.ina_6)))
        } else {
            None
        }
    }
}

/// Information about a single socket owned by a process.
#[derive(Debug, Clone)]
pub struct MacosSocketEntry {
    pub pid: u32,
    pub protocol: Protocol,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub tcp_state: Option<i32>,
}

/// Scan all socket FDs for a single process. Returns entries for AF_INET/AF_INET6
/// TCP and UDP sockets only. Silently skips FDs that cannot be queried (permission
/// denied, race with process exit, etc.).
pub fn scan_process_sockets(pid: u32) -> Vec<MacosSocketEntry> {
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

    let mut entries = Vec::new();
    let sfd_size = mem::size_of::<socket_fdinfo>() as i32;

    for fd_info in &fd_buf {
        if fd_info.proc_fdtype != PROX_FDTYPE_SOCKET {
            continue;
        }

        let mut sfd: socket_fdinfo = unsafe { mem::zeroed() };
        let ret = unsafe {
            proc_pidfdinfo(
                pid as i32,
                fd_info.proc_fd,
                PROC_PIDFDSOCKETINFO,
                &mut sfd as *mut _ as *mut std::ffi::c_void,
                sfd_size,
            )
        };
        if ret < sfd_size {
            continue;
        }

        let family = sfd.psi.soi_family;
        if family != AF_INET && family != AF_INET6 {
            continue;
        }

        let proto_raw = sfd.psi.soi_protocol;
        let kind = sfd.psi.soi_kind;

        let (protocol, ini, tcp_state) = if proto_raw == IPPROTO_TCP && kind == SOCKINFO_TCP {
            let tcp = unsafe { sfd.psi.soi_proto.pri_tcp };
            (Protocol::TCP, tcp.tcpsi_ini, Some(tcp.tcpsi_state))
        } else if proto_raw == IPPROTO_UDP && kind == SOCKINFO_IN {
            let udp = unsafe { sfd.psi.soi_proto.pri_in };
            (Protocol::UDP, udp, None)
        } else {
            continue;
        };

        let local_ip = match decode_addr(&ini.insi_laddr, ini.insi_vflag, family) {
            Some(ip) => ip,
            None => continue,
        };
        let remote_ip = match decode_addr(&ini.insi_faddr, ini.insi_vflag, family) {
            Some(ip) => ip,
            None => continue,
        };

        let local_port = (ini.insi_lport as u16).to_be();
        let remote_port = (ini.insi_fport as u16).to_be();

        entries.push(MacosSocketEntry {
            pid,
            protocol,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            tcp_state,
        });
    }

    entries
}

/// List all PIDs on the system.
pub fn list_all_pids() -> Vec<u32> {
    let estimated = unsafe { proc_listallpids(std::ptr::null_mut(), 0) };
    if estimated <= 0 {
        return Vec::new();
    }

    let capacity = (estimated as usize) * 2;
    let mut buf: Vec<i32> = vec![0i32; capacity];
    let ret =
        unsafe { proc_listallpids(buf.as_mut_ptr(), (capacity * mem::size_of::<i32>()) as i32) };
    if ret <= 0 {
        return Vec::new();
    }

    buf.truncate(ret as usize);
    buf.into_iter()
        .filter(|&p| p > 0)
        .map(|p| p as u32)
        .collect()
}

/// Build a complete Session -> PID map by scanning every process on the system.
/// For TCP sockets with a full 4-tuple, creates an exact Session key.
/// For UDP sockets (often unconnected), maps by (local_port, protocol) so the
/// caller can use port-based fallback matching.
///
/// `filter_pids` optionally restricts scanning to a subset of PIDs (useful for tests).
pub fn scan_all_process_sockets(
    filter_pids: Option<&[u32]>,
) -> (HashMap<Session, u32>, Vec<MacosSocketEntry>) {
    let pids = match filter_pids {
        Some(subset) => subset.to_vec(),
        None => list_all_pids(),
    };

    let mut session_map: HashMap<Session, u32> = HashMap::new();
    let mut all_entries: Vec<MacosSocketEntry> = Vec::new();

    for pid in pids {
        let entries = scan_process_sockets(pid);
        for entry in entries {
            let session = Session {
                protocol: entry.protocol.clone(),
                src_ip: entry.local_ip,
                src_port: entry.local_port,
                dst_ip: entry.remote_ip,
                dst_port: entry.remote_port,
            };
            session_map.insert(session, entry.pid);

            // Also insert reverse direction for TCP (our capture may see
            // packets in either direction)
            if entry.protocol == Protocol::TCP {
                let reverse = Session {
                    protocol: Protocol::TCP,
                    src_ip: entry.remote_ip,
                    src_port: entry.remote_port,
                    dst_ip: entry.local_ip,
                    dst_port: entry.local_port,
                };
                session_map.insert(reverse, entry.pid);
            }

            all_entries.push(entry);
        }
    }

    trace!(
        "macOS libproc socket scan: {} PIDs scanned, {} session map entries, {} raw socket entries",
        match filter_pids {
            Some(s) => s.len(),
            None => 0,
        },
        session_map.len(),
        all_entries.len(),
    );

    (session_map, all_entries)
}

/// Try to find a PID for a session using the pre-built session map.
/// Falls back to port-based matching for UDP sessions.
pub fn lookup_session_pid(
    session: &Session,
    session_map: &HashMap<Session, u32>,
    all_entries: &[MacosSocketEntry],
) -> Option<u32> {
    if let Some(&pid) = session_map.get(session) {
        return Some(pid);
    }

    // Reverse lookup for the session
    let reverse = Session {
        protocol: session.protocol.clone(),
        src_ip: session.dst_ip,
        src_port: session.dst_port,
        dst_ip: session.src_ip,
        dst_port: session.src_port,
    };
    if let Some(&pid) = session_map.get(&reverse) {
        return Some(pid);
    }

    // Port-based fuzzy match for UDP
    if session.protocol == Protocol::UDP {
        for entry in all_entries {
            if entry.protocol != Protocol::UDP {
                continue;
            }
            let port_match =
                entry.local_port == session.src_port || entry.local_port == session.dst_port;
            let addr_match = entry.local_ip.is_unspecified()
                || entry.local_ip == session.src_ip
                || entry.local_ip == session.dst_ip;
            if port_match && addr_match {
                return Some(entry.pid);
            }
        }
    }

    None
}

/// Fast single-session PID lookup: scans all PIDs but short-circuits when
/// the matching socket is found. Cheaper than building a full session map
/// when only one session needs attribution.
pub fn quick_lookup_session_pid(session: &Session) -> Option<u32> {
    let pids = list_all_pids();
    let reverse = Session {
        protocol: session.protocol.clone(),
        src_ip: session.dst_ip,
        src_port: session.dst_port,
        dst_ip: session.src_ip,
        dst_port: session.src_port,
    };
    for pid in pids {
        let entries = scan_process_sockets(pid);
        for entry in entries {
            let entry_session = Session {
                protocol: entry.protocol.clone(),
                src_ip: entry.local_ip,
                src_port: entry.local_port,
                dst_ip: entry.remote_ip,
                dst_port: entry.remote_port,
            };
            if entry_session == *session || entry_session == reverse {
                return Some(pid);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_struct_sizes() {
        assert_eq!(mem::size_of::<proc_fdinfo>(), 8);
        assert_eq!(mem::size_of::<proc_fileinfo>(), 24);
        assert_eq!(mem::size_of::<in4in6_addr>(), 16);
        assert_eq!(mem::size_of::<in_sockinfo>(), 80);
        assert_eq!(mem::size_of::<tcp_sockinfo>(), 120);
        assert_eq!(mem::size_of::<sockbuf_info>(), 24);
        assert_eq!(mem::size_of::<socket_info>(), 768);
        assert_eq!(mem::size_of::<socket_fdinfo>(), 792);
    }

    #[test]
    fn test_list_all_pids_returns_nonempty() {
        let pids = list_all_pids();
        assert!(!pids.is_empty(), "should list at least one PID");
        assert!(pids.contains(&1), "PID 1 (launchd) should always exist");
    }

    #[test]
    fn test_scan_self_finds_nothing_or_sockets() {
        let pid = std::process::id();
        let entries = scan_process_sockets(pid);
        // The test runner process may or may not have sockets open.
        // Just verify it doesn't panic.
        eprintln!("self (pid {}) has {} socket entries", pid, entries.len());
    }

    #[test]
    fn test_scan_dead_pid_returns_empty() {
        let entries = scan_process_sockets(4_000_000);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_scan_all_finds_system_sockets() {
        let (session_map, all_entries) = scan_all_process_sockets(None);
        // A running macOS system always has network sockets
        assert!(
            !all_entries.is_empty(),
            "expected at least one socket on the system"
        );
        eprintln!(
            "system scan: {} session map entries, {} raw entries",
            session_map.len(),
            all_entries.len()
        );
    }
}
