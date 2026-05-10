// Windows file path normalization for cross-source matching.
//
// On Windows the same file can be referred to by several path shapes
// depending on which API surfaced it:
//
//   * `notify` (Win32 `ReadDirectoryChangesW`) emits paths rooted at
//     the watch root we registered, e.g.
//     `C:\Users\frank\AppData/Local\Microsoft\Edge\User Data\...`
//     (the mixed slashes come from the watch root sometimes being
//     assembled from environment variables that already contain `/`).
//
//   * Kernel ETW `FileIo/Create` events report the path the way the
//     kernel saw it inside `IRP_MJ_CREATE`, typically as an NT object
//     manager path, e.g.
//     `\Device\HarddiskVolume3\Users\frank\AppData\Local\...`. Less
//     commonly `\??\C:\...` (NT-DOS device prefix) or
//     `\\?\C:\...` (long-path Win32 prefix).
//
//   * Restart Manager (`RmRegisterResources` / `RmGetList`) consumes
//     the plain Win32 form, e.g. `C:\Users\frank\AppData\Local\...`.
//
// Cross-source attribution -- e.g. "did this `notify` event match an
// ETW writer record?" -- requires both forms to canonicalize to the
// same key. This module provides that canonicalizer:
//
//   normalize_win_path(path) -> canonical String
//
// The canonical form is:
//
//   * Long-path / NT-DOS prefixes stripped (`\\?\`, `\??\`).
//   * `\Device\HarddiskVolume<N>\...` rewritten to `<drive>:\...`
//     using a cached `QueryDosDeviceW` mapping. If no drive maps to
//     the volume (e.g. shadow copies, mounted VHD without drive
//     letter, network reparse), the NT path is preserved verbatim
//     after lowercase + separator normalization so two copies of the
//     same NT path still match.
//   * All `/` separators converted to `\`.
//   * Trailing `\` trimmed (except for bare drive roots like `c:\`
//     which we keep as-is to remain a syntactically valid path).
//   * Lowercased -- Windows file system semantics are case-insensitive
//     for default volume mounts, which is the case we care about.
//
// The volume->drive mapping is built on first use and refreshed if a
// lookup misses an unknown volume number (handles late-mounted
// drives, mapped network drives, etc.). The cache is a single
// `Lazy<DashMap<String, String>>` so the cost is one syscall pair on
// boot plus the occasional refresh.
//
// On non-Windows targets the module compiles down to an identity
// function so call sites do not need their own `#[cfg]` guards. The
// pure-string normalization helpers (prefix strip, separator
// normalize, lowercase) are also exposed cross-platform so they can
// be unit-tested on macOS / Linux without a real Win32 environment.

#[cfg(target_os = "windows")]
use dashmap::DashMap;
#[cfg(target_os = "windows")]
use once_cell::sync::Lazy;

const NT_DEVICE_PREFIX: &str = r"\Device\";
const HARDDISK_VOLUME_PREFIX: &str = r"\Device\HarddiskVolume";
const LONG_PATH_PREFIX: &str = r"\\?\";
const NT_DOS_PREFIX: &str = r"\??\";

/// Canonicalize a Windows file path into a single comparable form.
///
/// On non-Windows targets this is a `to_string()`-equivalent pass-
/// through that still does the cross-platform separator + case
/// normalization, so test fixtures stay portable.
pub fn normalize_win_path(path: &str) -> String {
    let stripped = strip_long_or_nt_prefix(path);
    let with_drive = nt_device_to_drive(stripped);
    canonicalize_separators_and_case(&with_drive)
}

/// Strip `\\?\` (long-path) and `\??\` (NT-DOS device) prefixes if
/// present. The remaining path is whatever the caller originally
/// supplied to `CreateFileW` / friends.
pub fn strip_long_or_nt_prefix(path: &str) -> &str {
    if let Some(rest) = path.strip_prefix(LONG_PATH_PREFIX) {
        return rest;
    }
    if let Some(rest) = path.strip_prefix(NT_DOS_PREFIX) {
        return rest;
    }
    path
}

/// Translate `\Device\HarddiskVolume<N>\...` to `<drive>:\...` using
/// the cached volume->drive table. If the volume doesn't map to any
/// drive (shadow copy, unmounted VHD, etc.) the NT path is returned
/// verbatim so it still canonicalizes consistently with other copies
/// of the same NT path.
pub fn nt_device_to_drive(path: &str) -> String {
    if !path.starts_with(NT_DEVICE_PREFIX) {
        return path.to_string();
    }

    if !path.starts_with(HARDDISK_VOLUME_PREFIX) {
        // Some other `\Device\...` path (named pipe, mailslot, etc.).
        // Nothing to translate; leave it intact.
        return path.to_string();
    }

    // Find where the volume identifier ends -- after the digits, at the
    // first `\` or end of string.
    let after_prefix = &path[HARDDISK_VOLUME_PREFIX.len()..];
    let digit_end = after_prefix
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(after_prefix.len());
    if digit_end == 0 {
        return path.to_string();
    }

    let volume_key = &path[..HARDDISK_VOLUME_PREFIX.len() + digit_end];
    let remainder = &after_prefix[digit_end..];

    #[cfg(target_os = "windows")]
    {
        if let Some(drive) = lookup_drive_for_volume(volume_key) {
            // remainder will start with `\` for a real path, or be
            // empty for the bare device root.
            if remainder.is_empty() {
                return format!("{}\\", drive);
            }
            return format!("{}{}", drive, remainder);
        }
    }

    // Volume->drive mapping unavailable (non-Windows test target, or a
    // volume without a drive letter). Preserve the NT path so two
    // copies still canonicalize consistently.
    let _ = volume_key;
    let _ = remainder;
    path.to_string()
}

/// Final-stage normalization: lowercase, all backslashes, collapsed
/// repeats, and trailing slash trimmed except when the path is a bare
/// drive root (`c:\`) or a UNC share root (`\\server\share`).
///
/// The implementation walks the string once and emits at most one
/// backslash per run, preserving the meaningful leading prefix:
///
///   * `\\` (UNC or extended-length): two leading backslashes
///   * `\`  (NT-rooted, e.g. `\Device\HarddiskVolume3\...`): one leading
///   * none (drive-rooted, `C:\...`): none
pub fn canonicalize_separators_and_case(path: &str) -> String {
    let lowered = path.replace('/', "\\").to_ascii_lowercase();

    // Determine the leading-backslash count we want to preserve.
    let leading: &str = if lowered.starts_with(r"\\") {
        r"\\"
    } else if lowered.starts_with('\\') {
        "\\"
    } else {
        ""
    };

    let body_start = leading.len();
    let body = &lowered[body_start..];

    // Collapse runs of backslashes in the body to a single backslash.
    let mut out = String::with_capacity(lowered.len());
    out.push_str(leading);
    let mut prev_backslash = false;
    for ch in body.chars() {
        if ch == '\\' {
            if !prev_backslash {
                out.push('\\');
            }
            prev_backslash = true;
        } else {
            out.push(ch);
            prev_backslash = false;
        }
    }

    // Trim a trailing backslash unless it makes the path syntactically
    // ambiguous. Two cases need to keep a trailing `\`:
    //
    //   * Bare drive root: `c:\`  (trimming yields `c:` which is a
    //     drive-relative current directory, NOT the root).
    //   * Bare NT root after device translation: e.g. `\` alone.
    //
    // For everything else (`c:\users\frank\`, `\\server\share\dir\`,
    // `\device\harddiskvolume3\users\`) the trailing slash is just
    // formatting noise and we drop it.
    if out.ends_with('\\') && !is_bare_root(&out) {
        out.pop();
    }
    out
}

/// True for paths that MUST keep their trailing backslash to remain
/// syntactically valid.
fn is_bare_root(s: &str) -> bool {
    if s == "\\" {
        return true;
    }
    // Drive root: exactly three chars, e.g. `c:\`, `d:\`.
    let bytes = s.as_bytes();
    if bytes.len() == 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\' {
        return true;
    }
    false
}

#[cfg(target_os = "windows")]
fn lookup_drive_for_volume(volume_key: &str) -> Option<String> {
    let key_lower = volume_key.to_ascii_lowercase();
    if let Some(drive) = VOLUME_TO_DRIVE.get(&key_lower) {
        return Some(drive.clone());
    }

    // Cache miss -- could be a freshly mounted drive. Refresh once
    // and retry.
    refresh_volume_table();
    VOLUME_TO_DRIVE.get(&key_lower).map(|d| d.clone())
}

#[cfg(target_os = "windows")]
static VOLUME_TO_DRIVE: Lazy<DashMap<String, String>> = Lazy::new(|| {
    let table = DashMap::new();
    populate_volume_table(&table);
    table
});

#[cfg(target_os = "windows")]
fn refresh_volume_table() {
    populate_volume_table(&VOLUME_TO_DRIVE);
}

#[cfg(target_os = "windows")]
fn populate_volume_table(table: &DashMap<String, String>) {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{GetLogicalDriveStringsW, QueryDosDeviceW};

    // First pass: how big a buffer do we need for the drive list.
    let needed = unsafe { GetLogicalDriveStringsW(None) };
    if needed == 0 {
        return;
    }
    let mut buf = vec![0u16; needed as usize];
    let written = unsafe { GetLogicalDriveStringsW(Some(&mut buf)) };
    if written == 0 || written as usize > buf.len() {
        return;
    }

    // The buffer is a sequence of null-terminated wide strings ended
    // by an extra null. Iterate the slices.
    let mut start = 0usize;
    let mut drives: Vec<String> = Vec::new();
    for (i, &c) in buf[..written as usize].iter().enumerate() {
        if c == 0 {
            if i > start {
                let drive = String::from_utf16_lossy(&buf[start..i]);
                drives.push(drive);
            }
            start = i + 1;
        }
    }

    for drive in drives {
        // drive is "C:\" — strip the trailing backslash to get "C:".
        let drive_no_slash = drive.trim_end_matches('\\').to_string();
        let mut wide: Vec<u16> = drive_no_slash.encode_utf16().collect();
        wide.push(0);
        let mut target = vec![0u16; 1024];
        let len = unsafe { QueryDosDeviceW(PCWSTR(wide.as_ptr()), Some(&mut target)) };
        if len == 0 {
            continue;
        }
        // The result is a (possibly multi-string) sequence terminated
        // by a double null. We only care about the first string --
        // that's the primary device path.
        let end = target.iter().position(|&c| c == 0).unwrap_or(target.len());
        if end == 0 {
            continue;
        }
        let device_path = String::from_utf16_lossy(&target[..end]);
        // Store key in canonical lowercase form so lookups work
        // regardless of the casing kernel ETW used.
        let key = device_path.to_ascii_lowercase();
        let value = drive_no_slash.to_ascii_lowercase();
        table.insert(key, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_long_path_prefix() {
        assert_eq!(strip_long_or_nt_prefix(r"\\?\C:\Foo\bar"), r"C:\Foo\bar");
    }

    #[test]
    fn strip_nt_dos_prefix() {
        assert_eq!(strip_long_or_nt_prefix(r"\??\C:\Foo\bar"), r"C:\Foo\bar");
    }

    #[test]
    fn strip_no_prefix_returns_input() {
        assert_eq!(strip_long_or_nt_prefix(r"C:\Foo"), r"C:\Foo");
        assert_eq!(
            strip_long_or_nt_prefix(r"\Device\HarddiskVolume3\X"),
            r"\Device\HarddiskVolume3\X"
        );
    }

    #[test]
    fn canonical_lowercases_and_normalizes_slashes() {
        assert_eq!(
            canonicalize_separators_and_case(r"C:\Users\Frank\AppData/Local\X.txt"),
            r"c:\users\frank\appdata\local\x.txt"
        );
    }

    #[test]
    fn canonical_collapses_repeated_separators() {
        assert_eq!(
            canonicalize_separators_and_case(r"C:\\Users\\Frank\\Foo"),
            r"c:\users\frank\foo"
        );
    }

    #[test]
    fn canonical_trims_trailing_slash() {
        assert_eq!(
            canonicalize_separators_and_case(r"C:\Users\Frank\"),
            r"c:\users\frank"
        );
    }

    #[test]
    fn canonical_keeps_bare_drive_root() {
        assert_eq!(canonicalize_separators_and_case(r"C:\"), r"c:\");
    }

    #[test]
    fn canonical_preserves_unc_double_slash() {
        assert_eq!(
            canonicalize_separators_and_case(r"\\server\share\dir\file.txt"),
            r"\\server\share\dir\file.txt"
        );
    }

    #[test]
    fn canonical_preserves_nt_device_path_when_unmappable() {
        // Non-Windows test target: nt_device_to_drive returns the NT
        // path verbatim; the final canonicalize pass still lowercases
        // and tightens separators.
        assert_eq!(
            canonicalize_separators_and_case(r"\Device\HarddiskVolumeShadowCopy7\Users\X"),
            r"\device\harddiskvolumeshadowcopy7\users\x"
        );
    }

    #[test]
    fn nt_device_to_drive_passes_other_devices_through() {
        assert_eq!(
            nt_device_to_drive(r"\Device\NamedPipe\foo"),
            r"\Device\NamedPipe\foo"
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn nt_device_to_drive_returns_input_on_non_windows() {
        // No volume table on macOS/Linux; the NT path is preserved so
        // both sides of an attribution comparison still see the same
        // form even if drive translation is unavailable.
        assert_eq!(
            nt_device_to_drive(r"\Device\HarddiskVolume3\Users\frank\X"),
            r"\Device\HarddiskVolume3\Users\frank\X"
        );
    }

    #[test]
    fn normalize_full_pipeline_handles_long_path_and_mixed_slashes() {
        // Simulates the `notify`-emitted shape we observed on shiawase.
        let notify =
            r"C:\Users\frank\AppData/Local\Microsoft\Edge\User Data\Default\Network\Cookies";
        let canonical = normalize_win_path(notify);
        assert_eq!(
            canonical,
            r"c:\users\frank\appdata\local\microsoft\edge\user data\default\network\cookies"
        );
    }

    #[test]
    fn normalize_handles_long_path_prefix_to_same_canonical() {
        let long =
            r"\\?\C:\Users\frank\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies";
        let plain =
            r"C:\Users\frank\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies";
        assert_eq!(normalize_win_path(long), normalize_win_path(plain));
    }

    #[test]
    fn normalize_handles_nt_dos_prefix_to_same_canonical() {
        let nt_dos =
            r"\??\C:\Users\frank\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies";
        let plain =
            r"C:\Users\frank\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies";
        assert_eq!(normalize_win_path(nt_dos), normalize_win_path(plain));
    }

    #[test]
    fn normalize_is_idempotent() {
        let p = r"C:\Users\frank\AppData/Local\Microsoft\Edge\User Data\Default\Network\Cookies";
        let once = normalize_win_path(p);
        let twice = normalize_win_path(&once);
        assert_eq!(once, twice);
    }

    /// Cross-source matching is the actual point of this module: the
    /// `notify` event arrives with one path shape, the ETW writer
    /// record was stored under another shape, and both must collapse
    /// to the same key. On non-Windows targets the volume->drive table
    /// is empty so NT-device paths cannot translate to drive letters,
    /// but the test stays meaningful by exercising every other shape
    /// transformation: prefix strip, case fold, separator collapse,
    /// trailing-slash trim.
    #[test]
    fn normalize_collapses_long_path_and_mixed_slashes_to_same_key() {
        // Five different ways the *same* file path can show up depending
        // on which API surfaced it. Without normalization these would
        // hash to five different DashMap keys -- which is exactly the
        // FP-WIN-16 root cause: ETW writes its key, `notify` looks up a
        // different key, miss, no PID, self-access suppression dies.
        let plain =
            r"C:\Users\frank\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies";
        let mixed_slashes =
            r"C:\Users\frank\AppData/Local\Microsoft\Edge\User Data\Default\Network\Cookies";
        let mixed_case =
            r"C:\users\Frank\AppData\Local\Microsoft\Edge\User Data\Default\Network\COOKIES";
        let long_prefix =
            r"\\?\C:\Users\frank\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies";
        let nt_dos_prefix =
            r"\??\C:\Users\frank\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies";

        let key = normalize_win_path(plain);
        assert_eq!(normalize_win_path(mixed_slashes), key);
        assert_eq!(normalize_win_path(mixed_case), key);
        assert_eq!(normalize_win_path(long_prefix), key);
        assert_eq!(normalize_win_path(nt_dos_prefix), key);
    }

    /// On Windows the NT object manager path (`\Device\HarddiskVolume3\...`)
    /// is what kernel ETW reports inside `IRP_MJ_CREATE`. On non-Windows
    /// targets we cannot resolve the volume number to a drive letter, but
    /// canonicalization should at least drive both NT-form copies to the
    /// same key.
    #[test]
    fn normalize_makes_nt_device_paths_self_consistent() {
        let nt_a = r"\Device\HarddiskVolume3\Users\frank\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies";
        let nt_b = r"\Device\HarddiskVolume3\Users\Frank\AppData\Local\Microsoft\Edge\User Data\Default\Network\COOKIES";
        assert_eq!(normalize_win_path(nt_a), normalize_win_path(nt_b));
    }

    /// Sanity: completely unrelated paths still produce different keys.
    /// (Defends against an over-aggressive canonicalizer that flattens
    /// distinct paths into a single bucket and produces wrong PIDs.)
    #[test]
    fn normalize_keeps_distinct_paths_distinct() {
        let chrome =
            r"C:\Users\frank\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies";
        let edge = r"C:\Users\frank\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies";
        assert_ne!(normalize_win_path(chrome), normalize_win_path(edge));
    }
}
