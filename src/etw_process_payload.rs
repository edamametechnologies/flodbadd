//! Layout-aware decoding of the ETW kernel `Process` provider's
//! `Process_TypeGroup1` payload (MOF `Process_V3` / `Process_V4`), shared by
//! the Windows ETW backend and its host-side unit tests.
//!
//! Layout (native pointer size `P`, all little-endian):
//!
//! ```text
//! UniqueProcessKey    P
//! ProcessId           u32
//! ParentId            u32
//! SessionId           u32
//! ExitStatus          i32
//! DirectoryTableBase  P
//! Flags               u32          (V4 and later only)
//! UserSID             variable     (see `sid_len`)
//! ImageFileName       ANSI, NUL-terminated
//! CommandLine         UTF-16LE, NUL-terminated
//! PackageFullName     UTF-16LE     (V4, ignored)
//! ApplicationId       UTF-16LE     (V4, ignored)
//! ```
//!
//! `UserSID` is an ETW "object(SID)" property: a pointer-sized `PSID`; when
//! it is zero that is the whole field, otherwise a `TOKEN_USER`-shaped
//! header (`PSID` + pointer-sized `Attributes`) is followed by the SID
//! itself (`Revision`, `SubAuthorityCount`, 6-byte authority, then
//! `SubAuthorityCount` u32 sub-authorities).
//!
//! The previous decoder scanned the bytes right after `ExitStatus` for a
//! printable ANSI run and therefore never found the image name of a live
//! process start (the scan began inside `DirectoryTableBase`); only the
//! process table primed from a snapshot at startup carried paths, which is
//! why task-access requesters that started after the daemon resolved to
//! nothing on the security gate (2026-09-07).

/// Decoded `Process_TypeGroup1` payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcessStartPayload {
    pub pid: u32,
    pub ppid: u32,
    pub session_id: u32,
    pub exit_status: i32,
    /// `ImageFileName` as delivered (a bare `image.exe` on most kernels,
    /// occasionally a device path); empty when absent.
    pub image_file_name: String,
    /// `CommandLine` (UTF-16LE), empty when absent.
    pub command_line: String,
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_ptr(data: &[u8], off: usize, ptr: usize) -> Option<u64> {
    let b = data.get(off..off + ptr)?;
    Some(if ptr == 8 {
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    } else {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64
    })
}

/// Length in bytes of the `UserSID` field starting at `off`.
fn sid_len(data: &[u8], off: usize, ptr: usize) -> Option<usize> {
    let psid = read_ptr(data, off, ptr)?;
    if psid == 0 {
        return Some(ptr);
    }
    let sid_start = off + 2 * ptr;
    let sub_count = *data.get(sid_start + 1)? as usize;
    Some(2 * ptr + 8 + 4 * sub_count)
}

fn read_ansi_cstring(data: &[u8], off: usize) -> Option<(String, usize)> {
    let rest = data.get(off..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    Some((
        String::from_utf8_lossy(&rest[..end]).to_string(),
        off + end + 1,
    ))
}

fn read_wide_cstring(data: &[u8], off: usize) -> Option<(String, usize)> {
    let rest = data.get(off..)?;
    let mut wide = Vec::new();
    let mut i = 0usize;
    while i + 1 < rest.len() {
        let ch = u16::from_le_bytes([rest[i], rest[i + 1]]);
        i += 2;
        if ch == 0 {
            return Some((String::from_utf16_lossy(&wide), off + i));
        }
        wide.push(ch);
    }
    None
}

/// Decode a `Process_TypeGroup1` payload. `version` is the event
/// descriptor version (`Flags` is present from V4), `ptr` the header's
/// pointer size (4 or 8). Returns `None` when the fixed part does not fit;
/// the variable strings are best-effort (empty when truncated).
pub fn parse_process_start(data: &[u8], version: u8, ptr: usize) -> Option<ProcessStartPayload> {
    let ptr = if ptr == 4 { 4 } else { 8 };
    let mut off = ptr; // UniqueProcessKey
    let pid = read_u32(data, off)?;
    off += 4;
    let ppid = read_u32(data, off)?;
    off += 4;
    let session_id = read_u32(data, off)?;
    off += 4;
    let exit_status = read_u32(data, off)? as i32;
    off += 4;
    off += ptr; // DirectoryTableBase
    if version >= 4 {
        off += 4; // Flags
    }
    let mut out = ProcessStartPayload {
        pid,
        ppid,
        session_id,
        exit_status,
        ..Default::default()
    };
    let Some(sid) = sid_len(data, off, ptr) else {
        return Some(out);
    };
    off += sid;
    if let Some((image, next)) = read_ansi_cstring(data, off) {
        out.image_file_name = image;
        if let Some((cmd, _)) = read_wide_cstring(data, next) {
            out.command_line = cmd;
        }
    }
    Some(out)
}

/// The executable's path from the command line when the image name is a
/// bare file name: the first token (quoted or up to the first space) when it
/// ends with the image name, so `python.exe` becomes
/// `C:\hostedtoolcache\...\python.exe` without touching the filesystem.
pub fn image_path_from_command_line(image_file_name: &str, command_line: &str) -> Option<String> {
    let cmd = command_line.trim();
    if cmd.is_empty() {
        return None;
    }
    let first = if let Some(rest) = cmd.strip_prefix('"') {
        rest.split('"').next().unwrap_or("")
    } else {
        cmd.split(' ').next().unwrap_or("")
    };
    let first = first.trim();
    if first.is_empty() || !(first.contains('\\') || first.contains('/')) {
        return None;
    }
    let base = first.rsplit(['\\', '/']).next().unwrap_or("");
    if image_file_name.is_empty() || base.eq_ignore_ascii_case(image_file_name) {
        Some(first.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(version: u8, ptr: usize, with_sid: bool) -> Vec<u8> {
        let mut v = Vec::new();
        let push_ptr = |v: &mut Vec<u8>, val: u64| {
            if ptr == 8 {
                v.extend_from_slice(&val.to_le_bytes());
            } else {
                v.extend_from_slice(&(val as u32).to_le_bytes());
            }
        };
        push_ptr(&mut v, 0xffff_8000_1234_5678); // UniqueProcessKey
        v.extend_from_slice(&4242u32.to_le_bytes()); // pid
        v.extend_from_slice(&1000u32.to_le_bytes()); // ppid
        v.extend_from_slice(&1u32.to_le_bytes()); // session
        v.extend_from_slice(&0u32.to_le_bytes()); // exit status
        push_ptr(&mut v, 0x1a2b_3000); // DirectoryTableBase
        if version >= 4 {
            v.extend_from_slice(&0u32.to_le_bytes()); // Flags
        }
        if with_sid {
            push_ptr(&mut v, 0x7fff_0000_0000_0010); // PSID
            push_ptr(&mut v, 0); // Attributes
                                 // SID S-1-5-21-a-b-c-1001: revision 1, 5 sub-authorities
            v.extend_from_slice(&[1, 5, 0, 0, 0, 0, 0, 5]);
            for sub in [21u32, 11, 22, 33, 1001] {
                v.extend_from_slice(&sub.to_le_bytes());
            }
        } else {
            push_ptr(&mut v, 0);
        }
        v.extend_from_slice(b"python.exe\0");
        let cmd: Vec<u16> = "\"C:\\hostedtoolcache\\windows\\Python\\3.12.10\\x64\\python.exe\" trigger.py --duration 300\0"
            .encode_utf16()
            .collect();
        for ch in cmd {
            v.extend_from_slice(&ch.to_le_bytes());
        }
        v
    }

    #[test]
    fn decodes_v4_x64_with_sid() {
        let p = parse_process_start(&payload(4, 8, true), 4, 8).unwrap();
        assert_eq!(p.pid, 4242);
        assert_eq!(p.ppid, 1000);
        assert_eq!(p.session_id, 1);
        assert_eq!(p.image_file_name, "python.exe");
        assert!(p.command_line.starts_with("\"C:\\hostedtoolcache"));
        assert_eq!(
            image_path_from_command_line(&p.image_file_name, &p.command_line).as_deref(),
            Some("C:\\hostedtoolcache\\windows\\Python\\3.12.10\\x64\\python.exe")
        );
    }

    #[test]
    fn decodes_v3_x64_without_sid_and_x86() {
        let p = parse_process_start(&payload(3, 8, false), 3, 8).unwrap();
        assert_eq!(p.image_file_name, "python.exe");
        let p = parse_process_start(&payload(4, 4, true), 4, 4).unwrap();
        assert_eq!(p.pid, 4242);
        assert_eq!(p.image_file_name, "python.exe");
    }

    #[test]
    fn truncated_payload_keeps_fixed_fields() {
        let full = payload(4, 8, true);
        let p = parse_process_start(&full[..24], 4, 8).unwrap();
        assert_eq!(p.pid, 4242);
        assert!(p.image_file_name.is_empty());
        assert!(parse_process_start(&full[..10], 4, 8).is_none());
    }

    #[test]
    fn command_line_path_only_when_it_matches_the_image() {
        assert_eq!(
            image_path_from_command_line("cmd.exe", "C:\\Windows\\System32\\cmd.exe /c dir"),
            Some("C:\\Windows\\System32\\cmd.exe".to_string())
        );
        assert_eq!(image_path_from_command_line("cmd.exe", "cmd /c dir"), None);
        assert_eq!(
            image_path_from_command_line(
                "node.exe",
                "\"C:\\Program Files\\nodejs\\node.exe\" app.js"
            ),
            Some("C:\\Program Files\\nodejs\\node.exe".to_string())
        );
        assert_eq!(
            image_path_from_command_line("python.exe", "\"C:\\x\\other.exe\" a"),
            None
        );
    }
}
