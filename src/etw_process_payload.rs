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
///
/// The token is returned in its Win32 form: a namespace prefix in front of a
/// drive path (`\??\C:\...`, the way the console subsystem starts
/// `conhost.exe`, or the long-path `\\?\C:\...`) is dropped. Path predicates
/// downstream (the OS-shipped mark, canonical system paths) compare the
/// Win32 form; with the prefix, conhost read as a binary outside the Windows
/// directory.
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
    let first = strip_namespace_prefix(first.trim());
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

/// `\??\C:\x`, `\\?\C:\x` and `\\.\C:\x` name the file `C:\x`. Only a
/// prefix followed by a drive path is dropped; `\\?\UNC\...` and device
/// paths stay as they are.
fn strip_namespace_prefix(path: &str) -> &str {
    for prefix in ["\\??\\", "\\\\?\\", "\\\\.\\"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            let b = rest.as_bytes();
            if b.len() >= 3
                && b[0].is_ascii_alphabetic()
                && b[1] == b':'
                && matches!(b[2], b'\\' | b'/')
            {
                return rest;
            }
        }
    }
    path
}

/// Decode an NT Kernel Logger `Image/Load` payload (MOF `Image_Load`, V2 and
/// V3: V3 only splits `Reserved0` into signature fields of the same size)
/// into the process the image was mapped into and the image's NT path.
/// `ptr` is the header's pointer size (4 or 8). `None` when the payload is
/// too short or `FileName` is not a rooted path.
///
/// ```text
/// ImageBase       P
/// ImageSize       P
/// ProcessId       u32
/// ImageCheckSum   u32
/// TimeDateStamp   u32
/// Reserved0       u32
/// DefaultBase     P
/// Reserved1..4    4 x u32
/// FileName        UTF-16LE, NUL-terminated
/// ```
pub fn parse_image_load(data: &[u8], ptr: usize) -> Option<(u32, String)> {
    let ptr = if ptr == 4 { 4 } else { 8 };
    let pid = read_u32(data, 2 * ptr)?;
    let file_name_at = 3 * ptr + 8 * 4;
    let rest = data.get(file_name_at..)?;
    let wide: Vec<u16> = rest
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&ch| ch != 0)
        .collect();
    let file_name = String::from_utf16_lossy(&wide);
    let rooted = file_name.starts_with('\\')
        || (file_name.len() >= 3
            && file_name.as_bytes()[0].is_ascii_alphabetic()
            && file_name.as_bytes()[1] == b':');
    (pid != 0 && rooted).then_some((pid, file_name))
}

/// Whether an image path names a program image (`.exe`) rather than a
/// library. Only those are kept from the image-load stream: the first one
/// mapped into a new process is its own image. A program started from a
/// file with another extension keeps the name its Start event gave it.
pub fn is_program_image(path: &str) -> bool {
    path.len() >= 4 && path[path.len() - 4..].eq_ignore_ascii_case(".exe")
}

/// How many characters of an image's file name the kernel keeps in a
/// process's `ImageFileName` (EPROCESS: 15 bytes with the terminator). A
/// name of this length may be the head of a longer one.
const KERNEL_IMAGE_FILE_NAME_CHARS: usize = 14;

/// Whether `kernel_path`, the full image path the kernel reported for a
/// process, should replace `current`, the image a process-table entry
/// carries for that process: only an entry without a path (nothing, or the
/// bare `image.exe` the NT Kernel Logger's `ImageFileName` delivers) naming
/// the same image. An entry that already has a path keeps it, and a bare
/// name of another image is another process.
pub fn kernel_image_path_upgrades(current: &str, kernel_path: &str) -> bool {
    fn is_path(s: &str) -> bool {
        s.contains('\\') || s.contains('/')
    }
    let current = current.trim();
    let kernel_path = kernel_path.trim();
    if !is_path(kernel_path) {
        return false;
    }
    if current.is_empty() {
        return true;
    }
    if is_path(current) {
        return false;
    }
    let kernel_name = kernel_path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let current = current.to_ascii_lowercase();
    kernel_name == current
        || (current.chars().count() >= KERNEL_IMAGE_FILE_NAME_CHARS
            && kernel_name.starts_with(&current))
}

/// FILETIME units (100 ns) within which two creation stamps of one pid are
/// the same process: the NT Kernel Logger stamps its `Process/Start` as the
/// process is created, the Kernel-Process provider carries the creation
/// time itself. A pid reused by a later process is created well after.
const SAME_PROCESS_CREATION_TOLERANCE: u64 = 10_000_000;

/// Whether two records of a pid describe the same process, judged on their
/// creation times (FILETIME). An unknown time on either side is not the
/// same process: Windows recycles pids quickly, and an image is only ever
/// carried over from a record that is provably the same one.
pub fn same_process_creation(a: Option<u64>, b: Option<u64>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) if a > 0 && b > 0 => a.abs_diff(b) <= SAME_PROCESS_CREATION_TOLERANCE,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image_load_payload(ptr: usize, pid: u32, file_name: &str) -> Vec<u8> {
        let mut v = Vec::new();
        let push_ptr = |v: &mut Vec<u8>, val: u64| {
            if ptr == 8 {
                v.extend_from_slice(&val.to_le_bytes());
            } else {
                v.extend_from_slice(&(val as u32).to_le_bytes());
            }
        };
        push_ptr(&mut v, 0x7ff6_1234_0000); // ImageBase
        push_ptr(&mut v, 0x5_6000); // ImageSize
        v.extend_from_slice(&pid.to_le_bytes());
        v.extend_from_slice(&0xabcdu32.to_le_bytes()); // ImageCheckSum
        v.extend_from_slice(&0x6500_0000u32.to_le_bytes()); // TimeDateStamp
        v.extend_from_slice(&[0x0c, 0x01, 0, 0]); // SignatureLevel / Type / reserved
        push_ptr(&mut v, 0x1_4000_0000); // DefaultBase
        v.extend_from_slice(&[0u8; 16]); // Reserved1..4
        for c in file_name.encode_utf16() {
            v.extend_from_slice(&c.to_le_bytes());
        }
        v.extend_from_slice(&[0, 0]);
        v
    }

    #[test]
    fn an_image_load_names_its_process_and_nt_path() {
        let path = r"\Device\HarddiskVolume3\Windows\System32\wbem\WMIC.exe";
        assert_eq!(
            parse_image_load(&image_load_payload(8, 628, path), 8),
            Some((628, path.to_string()))
        );
        assert_eq!(
            parse_image_load(&image_load_payload(4, 4242, path), 4),
            Some((4242, path.to_string()))
        );
        // Too short, a zero pid, or a name that is no rooted path: nothing.
        assert_eq!(
            parse_image_load(&image_load_payload(8, 628, path)[..40], 8),
            None
        );
        assert_eq!(parse_image_load(&image_load_payload(8, 0, path), 8), None);
        assert_eq!(
            parse_image_load(&image_load_payload(8, 628, "WMIC.exe"), 8),
            None
        );
    }

    #[test]
    fn only_program_images_are_kept() {
        assert!(is_program_image(
            r"\Device\HarddiskVolume3\Windows\System32\wbem\WMIC.exe"
        ));
        assert!(is_program_image(r"C:\x\SETUP.EXE"));
        assert!(!is_program_image(
            r"\Device\HarddiskVolume3\Windows\System32\ntdll.dll"
        ));
        assert!(!is_program_image(r"C:\x\payload.exe.dat"));
        assert!(!is_program_image("exe"));
    }

    /// The WMIC case: a process started by bare name exited before its
    /// NT Kernel Logger Start event was consumed, so the table only knew
    /// `WMIC.exe`; the Kernel-Process provider's path for the same image
    /// replaces it.
    #[test]
    fn a_bare_image_name_takes_the_kernel_path_of_the_same_image() {
        let kernel = r"C:\Windows\System32\wbem\WMIC.exe";
        assert!(kernel_image_path_upgrades("WMIC.exe", kernel));
        assert!(kernel_image_path_upgrades("wmic.EXE", kernel));
        assert!(kernel_image_path_upgrades("", kernel));
        // ImageFileName keeps 14 characters of a longer name.
        assert!(kernel_image_path_upgrades(
            "build-script-b",
            r"C:\w\target\release\build\core-0123456789abcdef\build-script-build.exe"
        ));
    }

    #[test]
    fn a_path_or_another_image_is_never_replaced() {
        let kernel = r"C:\Windows\System32\wbem\WMIC.exe";
        // Already a path: kept, even a different one.
        assert!(!kernel_image_path_upgrades(r"C:\Users\x\WMIC.exe", kernel));
        assert!(!kernel_image_path_upgrades(
            r"C:\Windows\System32\wbem\WMIC.exe",
            kernel
        ));
        // Another image under the same pid is another process.
        assert!(!kernel_image_path_upgrades("node.exe", kernel));
        // A short name is not a prefix match: `wmi.exe` is not `wmic.exe`.
        assert!(!kernel_image_path_upgrades("WMI", kernel));
        // The kernel side must be a path.
        assert!(!kernel_image_path_upgrades("WMIC.exe", "WMIC.exe"));
        assert!(!kernel_image_path_upgrades("WMIC.exe", ""));
    }

    #[test]
    fn only_provably_the_same_creation_is_the_same_process() {
        let t = 134_000_000_000_000_000u64;
        assert!(same_process_creation(Some(t), Some(t)));
        assert!(same_process_creation(Some(t), Some(t + 5_000_000)));
        assert!(same_process_creation(Some(t + 5_000_000), Some(t)));
        // A pid reused two seconds later is another process.
        assert!(!same_process_creation(Some(t), Some(t + 20_000_000)));
        // Unknown is not the same.
        assert!(!same_process_creation(None, Some(t)));
        assert!(!same_process_creation(Some(t), None));
        assert!(!same_process_creation(Some(0), Some(0)));
    }

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

    #[test]
    fn namespace_prefixed_executable_tokens_read_as_win32_paths() {
        // How the console subsystem starts conhost.exe.
        assert_eq!(
            image_path_from_command_line(
                "conhost.exe",
                r"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1"
            ),
            Some(r"C:\Windows\system32\conhost.exe".to_string())
        );
        assert_eq!(
            image_path_from_command_line("app.exe", r#""\\?\D:\Tools\app.exe" --flag"#),
            Some(r"D:\Tools\app.exe".to_string())
        );
        assert_eq!(
            image_path_from_command_line("app.exe", r"\\.\C:\Tools\app.exe"),
            Some(r"C:\Tools\app.exe".to_string())
        );
        // No drive path after the prefix: kept as it is.
        assert_eq!(
            image_path_from_command_line("app.exe", r"\\?\UNC\server\share\app.exe"),
            Some(r"\\?\UNC\server\share\app.exe".to_string())
        );
    }
}
