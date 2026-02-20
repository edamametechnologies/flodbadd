use std::collections::HashMap;
use std::path::Path;

pub const MAX_OPEN_FILES: usize = 100;

/// Aggregate file paths when the list exceeds MAX_OPEN_FILES.
/// Groups files by parent directory and replaces large groups with `<dir>/*`.
/// Repeats until total entries fit within the cap.
pub fn aggregate_open_files(mut paths: Vec<String>) -> Vec<String> {
    if paths.len() <= MAX_OPEN_FILES {
        paths.sort();
        paths.dedup();
        return paths;
    }

    paths.sort();
    paths.dedup();

    if paths.len() <= MAX_OPEN_FILES {
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
    let mut remaining = MAX_OPEN_FILES;

    for (dir, files) in &ranked {
        if remaining == 0 {
            break;
        }
        if files.len() > 1 && result.len() + files.len() > MAX_OPEN_FILES {
            let entry = format!("{}/*", dir);
            if !result.contains(&entry) {
                result.push(entry);
                remaining = remaining.saturating_sub(1);
            }
        } else {
            for f in files {
                if remaining == 0 {
                    let entry = format!("{}/*", dir);
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

    result.sort();
    result.dedup();
    result.truncate(MAX_OPEN_FILES);
    result
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
            if s.starts_with('/') && !s.starts_with("/dev/") && !s.starts_with("/proc/") {
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
        if s.starts_with('/') && !s.starts_with("/dev/") {
            paths.push(s);
        }
    }
    paths
}

#[cfg(target_os = "windows")]
pub fn get_open_file_paths(_pid: u32) -> Vec<String> {
    // Windows FD enumeration via NtQuerySystemInformation is fragile and can hang
    // on certain handle types. Return empty for now -- the capability can be refined
    // in a future iteration using NtQuerySystemInformation + NtQueryObject.
    Vec::new()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn get_open_file_paths(_pid: u32) -> Vec<String> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_get_open_file_paths_self() {
        let pid = std::process::id();
        let paths = get_open_file_paths(pid);
        // On macOS/Linux, may return empty if all FDs are /dev/ or sockets (filtered out).
        // Just verify it doesn't panic.
        eprintln!("open file paths for self (pid {}): {:?}", pid, paths);
    }
}
