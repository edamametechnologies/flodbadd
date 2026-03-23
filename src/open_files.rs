use crate::sensitive_paths::SENSITIVE_PATHS;
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

pub const MAX_OPEN_FILES: usize = 100;

/// Compiled-in fallback patterns used before the cloud model snapshot is populated.
const FALLBACK_COMMON: &[&str] = &[
    "/.ssh/",
    "/.gnupg/",
    "/.aws/credentials",
    "/.aws/config",
    "/.kube/config",
    "/.docker/config.json",
    "/.npmrc",
    "/.env",
    "/.netrc",
    "/.pgpass",
    "/.pypirc",
    "/credentials.json",
    "/id_rsa",
    "/id_ed25519",
    "/id_ecdsa",
    "/id_dsa",
    "/Login Data",
    "/Cookies",
    "/Web Data",
];

#[cfg(target_os = "macos")]
const FALLBACK_PLATFORM: &[&str] = &["/Library/Keychains/", "/MobileSyncBackup/"];

#[cfg(target_os = "linux")]
const FALLBACK_PLATFORM: &[&str] =
    &["/etc/shadow", "/etc/gshadow", "/etc/security/opasswd"];

#[cfg(target_os = "windows")]
const FALLBACK_PLATFORM: &[&str] = &[
    "/AppData/Roaming/Microsoft/Credentials/",
    "/AppData/Roaming/Microsoft/Protect/",
    "/Windows/System32/config/SAM",
    "/Windows/System32/config/SECURITY",
    "/Windows/NTDS/ntds.dit",
    "/AppData/Local/Google/Chrome/User Data/",
    "/AppData/Roaming/Mozilla/Firefox/Profiles/",
];

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
const FALLBACK_PLATFORM: &[&str] = &[];

fn build_fallback_patterns() -> Vec<String> {
    let mut patterns: Vec<String> = FALLBACK_COMMON.iter().map(|s| s.to_string()).collect();
    patterns.extend(FALLBACK_PLATFORM.iter().map(|s| s.to_string()));
    patterns
}

lazy_static::lazy_static! {
    static ref PATTERNS_SNAPSHOT: ArcSwap<Vec<String>> =
        ArcSwap::from_pointee(build_fallback_patterns());
}

/// Refresh the sync-accessible pattern snapshot from the cloud model.
/// Called after `sensitive_paths::update()` succeeds.
pub async fn refresh_patterns_snapshot() {
    let db = SENSITIVE_PATHS.data.read().await;
    let patterns: Vec<String> = db
        .get_patterns_for_platform()
        .into_iter()
        .map(str::to_string)
        .collect();
    PATTERNS_SNAPSHOT.store(Arc::new(patterns));
}

/// Returns true if `path` matches a known credential / secret pattern.
/// Uses a lock-free snapshot refreshed from the cloud model.
pub fn is_sensitive_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let patterns = PATTERNS_SNAPSHOT.load();
    patterns.iter().any(|pat| normalized.contains(pat.as_str()))
}

/// Returns the combined list of sensitive patterns (common + platform).
pub fn sensitive_patterns() -> Vec<String> {
    PATTERNS_SNAPSHOT.load().as_ref().clone()
}

fn should_keep_open_file_path(path: &str) -> bool {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return false;
    }

    let normalized = trimmed.replace('\\', "/");
    normalized != "/"
}

fn directory_glob_entry(dir: &str) -> String {
    let trimmed = dir.trim_end_matches('/');
    if trimmed.is_empty() {
        "/*".to_string()
    } else {
        format!("{}/*", trimmed)
    }
}

/// Aggregate file paths when the list exceeds MAX_OPEN_FILES.
/// Sensitive paths (credentials, keys, etc.) are always preserved individually;
/// only non-sensitive paths are subject to directory-level aggregation.
pub fn aggregate_open_files(mut paths: Vec<String>) -> Vec<String> {
    paths.retain(|path| should_keep_open_file_path(path));
    paths.sort();
    paths.dedup();

    if paths.len() <= MAX_OPEN_FILES {
        return paths;
    }

    // Partition: sensitive paths survive aggregation unconditionally
    let (sensitive, regular): (Vec<_>, Vec<_>) =
        paths.into_iter().partition(|p| is_sensitive_path(p));

    let budget = MAX_OPEN_FILES.saturating_sub(sensitive.len());
    let mut result = sensitive;
    result.extend(aggregate_regular(regular, budget));
    result.sort();
    result.dedup();
    result.truncate(MAX_OPEN_FILES);
    result
}

/// Directory-level aggregation for non-sensitive paths, capped to `budget`.
fn aggregate_regular(paths: Vec<String>, budget: usize) -> Vec<String> {
    if paths.len() <= budget {
        return paths;
    }

    let mut dir_counts: HashMap<String, Vec<String>> = HashMap::new();
    for p in &paths {
        let parent = Path::new(p)
            .parent()
            .map(|d| d.to_string_lossy().to_string())
            .unwrap_or_else(|| "/".to_string());
        dir_counts.entry(parent).or_default().push(p.clone());
    }

    let mut ranked: Vec<(String, Vec<String>)> = dir_counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

    let mut result: Vec<String> = Vec::new();
    let mut remaining = budget;

    for (dir, files) in &ranked {
        if remaining == 0 {
            break;
        }
        if files.len() > 1 && result.len() + files.len() > budget {
            let entry = directory_glob_entry(dir);
            if !result.contains(&entry) {
                result.push(entry);
                remaining = remaining.saturating_sub(1);
            }
        } else {
            for f in files {
                if remaining == 0 {
                    let entry = directory_glob_entry(dir);
                    if !result.contains(&entry) {
                        result.push(entry);
                    }
                    break;
                }
                result.push(f.clone());
                remaining = remaining.saturating_sub(1);
            }
        }
    }

    result
}

/// Merge sensitive paths from a previous snapshot into the current one.
/// Sensitive files that were observed in `previous` but are absent from
/// `current` are carried forward (sticky), so a file that was open during
/// one L7 refresh cycle remains visible even if the process closed it
/// before the next cycle. Non-sensitive paths are NOT carried forward.
pub fn merge_sensitive_open_files(mut current: Vec<String>, previous: &[String]) -> Vec<String> {
    for p in previous {
        if is_sensitive_path(p) && !current.contains(p) {
            current.push(p.clone());
        }
    }
    current.sort();
    current.dedup();
    current.truncate(MAX_OPEN_FILES);
    current
}

/// Lightweight scan: only returns open file paths that match sensitive
/// patterns.  Same procfs / libproc I/O as `get_open_file_paths` but skips
/// aggregation, making it cheap enough to run every 30 s.
pub fn get_sensitive_open_file_paths(pid: u32) -> Vec<String> {
    get_open_file_paths(pid)
        .into_iter()
        .filter(|p| is_sensitive_path(p))
        .collect()
}

#[cfg(target_os = "linux")]
pub fn get_open_file_paths(pid: u32) -> Vec<String> {
    let fd_dir = format!("/proc/{}/fd", pid);
    let entries = match std::fs::read_dir(&fd_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut paths = Vec::new();
    for entry in entries.flatten() {
        if let Ok(target) = std::fs::read_link(entry.path()) {
            let s = target.to_string_lossy().to_string();
            if s.starts_with('/')
                && !s.starts_with("/dev/")
                && !s.starts_with("/proc/")
                && should_keep_open_file_path(&s)
            {
                paths.push(s);
            }
        }
    }
    paths
}

#[cfg(target_os = "macos")]
pub fn get_open_file_paths(pid: u32) -> Vec<String> {
    use std::mem;

    #[allow(non_camel_case_types)]
    #[repr(C)]
    struct proc_fdinfo {
        proc_fd: i32,
        proc_fdtype: u32,
    }

    #[allow(non_camel_case_types)]
    #[repr(C)]
    struct vnode_fdinfowithpath {
        pfi: proc_fileinfo,
        pvip: vnode_info_path,
    }

    #[allow(non_camel_case_types)]
    #[repr(C)]
    struct proc_fileinfo {
        fi_openflags: u32,
        fi_status: u32,
        fi_offset: i64,
        fi_type: i32,
        fi_guardflags: u32,
    }

    #[allow(non_camel_case_types)]
    #[repr(C)]
    struct vnode_info_path {
        vip_vi: vnode_info,
        vip_path: [u8; 1024],
    }

    #[allow(non_camel_case_types)]
    #[repr(C)]
    struct vnode_info {
        vi_stat: vinfo_stat,
        vi_type: i32,
        vi_pad: i32,
        vi_fsid: fsid_t,
    }

    #[allow(non_camel_case_types)]
    #[repr(C)]
    struct vinfo_stat {
        vst_dev: u32,
        vst_mode: u16,
        vst_nlink: u16,
        vst_ino: u64,
        vst_uid: u32,
        vst_gid: u32,
        vst_atime: i64,
        vst_atimensec: i64,
        vst_mtime: i64,
        vst_mtimensec: i64,
        vst_ctime: i64,
        vst_ctimensec: i64,
        vst_birthtime: i64,
        vst_birthtimensec: i64,
        vst_size: i64,
        vst_blocks: i64,
        vst_blksize: i32,
        vst_flags: u32,
        vst_gen: u32,
        vst_rdev: u32,
        vst_qspare: [i64; 2],
    }

    #[allow(non_camel_case_types)]
    #[repr(C)]
    struct fsid_t {
        val: [i32; 2],
    }

    const PROC_PIDLISTFDS: i32 = 1;
    const PROC_PIDFDVNODEPATHINFO: i32 = 2;
    const PROX_FDTYPE_VNODE: u32 = 1;

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
    }

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

    let mut paths = Vec::new();
    let vpath_size = mem::size_of::<vnode_fdinfowithpath>() as i32;

    for fd_info in &fd_buf {
        if fd_info.proc_fdtype != PROX_FDTYPE_VNODE {
            continue;
        }
        let mut vpath: vnode_fdinfowithpath = unsafe { mem::zeroed() };
        let ret = unsafe {
            proc_pidfdinfo(
                pid as i32,
                fd_info.proc_fd,
                PROC_PIDFDVNODEPATHINFO,
                &mut vpath as *mut _ as *mut std::ffi::c_void,
                vpath_size,
            )
        };
        if ret <= 0 {
            continue;
        }
        let path_bytes = &vpath.pvip.vip_path;
        let nul_pos = path_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(path_bytes.len());
        let s = String::from_utf8_lossy(&path_bytes[..nul_pos]).to_string();
        if s.starts_with('/') && !s.starts_with("/dev/") && should_keep_open_file_path(&s) {
            paths.push(s);
        }
    }
    paths
}

#[cfg(target_os = "windows")]
pub fn get_open_file_paths(pid: u32) -> Vec<String> {
    use std::ffi::c_void;
    use std::ptr;

    type HANDLE = *mut c_void;
    type NTSTATUS = i32;

    const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = 0xC0000004_u32 as i32;
    const STATUS_SUCCESS: NTSTATUS = 0;
    const SYSTEM_HANDLE_INFORMATION_CLASS: u32 = 16;
    const PROCESS_DUP_HANDLE: u32 = 0x0040;
    const DUPLICATE_SAME_ACCESS: u32 = 0x0002;
    const FILE_TYPE_DISK: u32 = 0x0001;

    // Stable NT ABI -- layout verified against ntifs.h SYSTEM_HANDLE_TABLE_ENTRY_INFO.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct HandleEntry {
        unique_process_id: u16,
        creator_back_trace_index: u16,
        object_type_index: u8,
        handle_attributes: u8,
        handle_value: u16,
        object: usize,
        granted_access: u32,
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtQuerySystemInformation(
            class: u32,
            info: *mut c_void,
            len: u32,
            ret_len: *mut u32,
        ) -> NTSTATUS;
    }

    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> HANDLE;
        fn DuplicateHandle(
            src_proc: HANDLE,
            src: HANDLE,
            dst_proc: HANDLE,
            dst: *mut HANDLE,
            access: u32,
            inherit: i32,
            options: u32,
        ) -> i32;
        fn GetCurrentProcess() -> HANDLE;
        fn CloseHandle(h: HANDLE) -> i32;
        fn GetFileType(h: HANDLE) -> u32;
        fn GetFinalPathNameByHandleW(h: HANDLE, buf: *mut u16, buf_len: u32, flags: u32) -> u32;
    }

    let proc_handle = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, pid) };
    if proc_handle.is_null() {
        return Vec::new();
    }

    let mut buf_size: u32 = 1 << 20;
    let mut buffer: Vec<u8>;
    let mut ret_len: u32 = 0;

    loop {
        buffer = vec![0u8; buf_size as usize];
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_HANDLE_INFORMATION_CLASS,
                buffer.as_mut_ptr() as *mut c_void,
                buf_size,
                &mut ret_len,
            )
        };
        if status == STATUS_INFO_LENGTH_MISMATCH {
            buf_size = ret_len.max(buf_size).saturating_mul(2);
            if buf_size > 512 << 20 {
                unsafe { CloseHandle(proc_handle) };
                return Vec::new();
            }
            continue;
        }
        if status != STATUS_SUCCESS {
            unsafe { CloseHandle(proc_handle) };
            return Vec::new();
        }
        break;
    }

    let num_handles = unsafe { *(buffer.as_ptr() as *const u32) };
    let entry_align = std::mem::align_of::<HandleEntry>();
    let entries_offset = (std::mem::size_of::<u32>() + entry_align - 1) & !(entry_align - 1);
    let needed = entries_offset + num_handles as usize * std::mem::size_of::<HandleEntry>();
    if needed > buffer.len() {
        unsafe { CloseHandle(proc_handle) };
        return Vec::new();
    }

    let entries = unsafe {
        std::slice::from_raw_parts(
            buffer.as_ptr().add(entries_offset) as *const HandleEntry,
            num_handles as usize,
        )
    };

    let current = unsafe { GetCurrentProcess() };
    let mut paths = Vec::new();

    for entry in entries {
        if entry.unique_process_id as u32 != pid {
            continue;
        }

        let mut dup: HANDLE = ptr::null_mut();
        let ok = unsafe {
            DuplicateHandle(
                proc_handle,
                entry.handle_value as usize as HANDLE,
                current,
                &mut dup,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if ok == 0 || dup.is_null() {
            continue;
        }

        // Only query disk-backed files; pipes/devices/mailslots can deadlock
        // GetFinalPathNameByHandleW on synchronous I/O handles.
        if unsafe { GetFileType(dup) } != FILE_TYPE_DISK {
            unsafe { CloseHandle(dup) };
            continue;
        }

        let mut name_buf = [0u16; 1024];
        let len = unsafe { GetFinalPathNameByHandleW(dup, name_buf.as_mut_ptr(), 1024, 0) };
        unsafe { CloseHandle(dup) };

        if len == 0 || len as usize >= name_buf.len() {
            continue;
        }

        let raw = String::from_utf16_lossy(&name_buf[..len as usize]);
        let s = raw.strip_prefix("\\\\?\\").unwrap_or(&raw);
        if !s.starts_with('\\') {
            paths.push(s.to_string());
        }
    }

    unsafe { CloseHandle(proc_handle) };
    paths
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn get_open_file_paths(_pid: u32) -> Vec<String> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- aggregate_open_files tests ---

    #[test]
    fn test_aggregate_under_cap() {
        let paths: Vec<String> = (0..50).map(|i| format!("/tmp/file_{}.txt", i)).collect();
        let result = aggregate_open_files(paths.clone());
        assert!(result.len() <= MAX_OPEN_FILES);
        assert_eq!(result.len(), 50);
    }

    #[test]
    fn test_aggregate_over_cap() {
        let mut paths = Vec::new();
        for i in 0..80 {
            paths.push(format!("/usr/lib/libfoo_{}.so", i));
        }
        for i in 0..80 {
            paths.push(format!("/usr/share/data_{}.dat", i));
        }
        for i in 0..20 {
            paths.push(format!("/home/user/file_{}.txt", i));
        }
        let result = aggregate_open_files(paths);
        assert!(result.len() <= MAX_OPEN_FILES);
        assert!(result.iter().any(|e| e.ends_with('*')));
    }

    #[test]
    fn test_aggregate_preserves_unique_paths() {
        let mut paths: Vec<String> = (0..110).map(|i| format!("/usr/lib/lib_{}.so", i)).collect();
        paths.push("/home/user/.ssh/id_rsa".to_string());
        paths.push("/home/user/.aws/credentials".to_string());
        paths.push("/etc/passwd".to_string());
        let result = aggregate_open_files(paths);
        assert!(result.len() <= MAX_OPEN_FILES);
        assert!(result.iter().any(|e| e == "/usr/lib/*"));
    }

    #[test]
    fn test_aggregate_star_suffix() {
        let mut paths = Vec::new();
        for i in 0..150 {
            paths.push(format!("/opt/myapp/lib/dep_{}.jar", i));
        }
        let result = aggregate_open_files(paths);
        assert!(result.iter().any(|e| e == "/opt/myapp/lib/*"));
        assert!(result.len() <= MAX_OPEN_FILES);
    }

    #[test]
    fn test_aggregate_empty() {
        let result = aggregate_open_files(Vec::new());
        assert!(result.is_empty());
    }

    #[test]
    fn test_aggregate_dedup() {
        let paths = vec!["/tmp/a.txt".to_string(); 50];
        let result = aggregate_open_files(paths);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_aggregate_filters_root_noise() {
        let result =
            aggregate_open_files(vec!["/".to_string(), "/home/user/.ssh/id_rsa".to_string()]);
        assert_eq!(result, vec!["/home/user/.ssh/id_rsa".to_string()]);
    }

    #[test]
    fn test_aggregate_root_directory_glob_is_canonical() {
        let paths: Vec<String> = (0..150).map(|i| format!("/root_file_{}", i)).collect();
        let result = aggregate_open_files(paths);
        assert!(result.iter().any(|entry| entry == "/*"));
        assert!(!result.iter().any(|entry| entry == "//*"));
    }

    // --- get_open_file_paths tests ---

    #[test]
    fn test_get_open_file_paths_self() {
        let pid = std::process::id();
        let paths = get_open_file_paths(pid);
        eprintln!("open file paths for self (pid {}): {:?}", pid, paths);
        for p in &paths {
            assert!(!p.starts_with("/dev/"), "should filter /dev/ paths: {}", p);
            #[cfg(target_os = "linux")]
            assert!(
                !p.starts_with("/proc/"),
                "should filter /proc/ paths: {}",
                p
            );
            #[cfg(target_os = "windows")]
            assert!(!p.starts_with('\\'), "should filter device paths: {}", p);
        }
    }

    #[test]
    fn test_get_open_file_paths_dead_pid() {
        // PID 4_000_000 is far above typical OS ranges; should fail gracefully.
        let paths = get_open_file_paths(4_000_000);
        assert!(
            paths.is_empty(),
            "dead PID should return empty, got: {:?}",
            paths
        );
    }

    #[test]
    fn test_get_open_file_paths_pid_zero() {
        // PID 0 is the kernel idle process (Windows) or swapper (Linux).
        // Either way, we should not panic.
        let paths = get_open_file_paths(0);
        eprintln!("open file paths for PID 0: {:?}", paths);
    }

    #[test]
    fn test_get_open_file_paths_with_known_fd() {
        use std::fs::File;
        use std::io::Write;

        let dir = std::env::temp_dir().join("flodbadd_open_files_test");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join("sentinel.txt");
        let mut f = File::create(&file_path).expect("create sentinel");
        f.write_all(b"test").expect("write sentinel");

        // Keep the file handle open while we query
        let pid = std::process::id();
        let paths = get_open_file_paths(pid);
        eprintln!("paths with sentinel open (pid {}): {:?}", pid, paths);

        // On Linux and macOS the sentinel should appear (we hold a File handle).
        // On Windows this also works via the NtQuerySystemInformation path.
        // CI environments running as non-root may lack /proc permissions on Linux,
        // so only assert when we got results at all.
        if !paths.is_empty() {
            let canonical = file_path.canonicalize().unwrap_or(file_path.clone());
            let canon_str = canonical.to_string_lossy().to_string();
            // On Windows, canonicalize() returns \\?\… but get_open_file_paths strips that prefix
            let canon_stripped = canon_str.strip_prefix("\\\\?\\").unwrap_or(&canon_str);
            let plain_str = file_path.to_string_lossy();
            assert!(
                paths.iter().any(|p| p == canon_stripped
                    || p == canon_str.as_str()
                    || p == plain_str.as_ref()),
                "sentinel {} not found in open files: {:?}",
                canon_stripped,
                paths,
            );
        }

        drop(f);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_get_open_file_paths_no_device_paths() {
        let pid = std::process::id();
        let paths = get_open_file_paths(pid);
        for p in &paths {
            assert!(
                !p.contains("/dev/") && !p.starts_with("\\Device\\"),
                "device path leaked through filter: {}",
                p,
            );
        }
    }

    #[test]
    fn test_short_lived_process_race() {
        use std::process::Command;

        // Spawn a process that exits immediately
        let child = Command::new(if cfg!(windows) { "cmd" } else { "true" })
            .args(if cfg!(windows) {
                vec!["/C", "exit"]
            } else {
                vec![]
            })
            .spawn()
            .expect("spawn short-lived process");

        let child_pid = child.id();

        // Wait for it to finish
        let _ = child.wait_with_output();

        // Now try to get open files for the dead PID -- must not panic, must return empty
        let paths = get_open_file_paths(child_pid);
        assert!(
            paths.is_empty(),
            "exited process should return empty open files, got: {:?}",
            paths,
        );
    }

    #[test]
    fn test_aggregate_pipeline_with_real_data() {
        use std::fs::File;
        use std::io::Write;

        let dir = std::env::temp_dir().join("flodbadd_pipeline_test");
        let _ = std::fs::create_dir_all(&dir);

        // Hold several file handles open to simulate a realistic process
        let mut handles = Vec::new();
        for i in 0..5 {
            let p = dir.join(format!("file_{}.dat", i));
            let mut f = File::create(&p).expect("create test file");
            f.write_all(b"data").expect("write test file");
            handles.push(f);
        }

        let pid = std::process::id();
        let raw = get_open_file_paths(pid);
        let aggregated = aggregate_open_files(raw.clone());

        eprintln!(
            "raw count: {}, aggregated count: {}",
            raw.len(),
            aggregated.len()
        );
        assert!(aggregated.len() <= MAX_OPEN_FILES);
        // Aggregated output must be sorted and deduplicated
        for w in aggregated.windows(2) {
            assert!(w[0] <= w[1], "output not sorted: {:?} > {:?}", w[0], w[1]);
        }

        drop(handles);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
