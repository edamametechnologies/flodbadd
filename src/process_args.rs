// A process's command line on macOS, read from `KERN_PROCARGS2` with an exact
// parse.
//
// The buffer is argc, the executable path, alignment padding, then exactly argc
// NUL-terminated arguments, then the environment. sysinfo's parser skips every
// run of NUL bytes between arguments. A process that rewrote its title into its
// argument area (libuv's `uv_set_process_title`: Node, Electron and every app
// built on them) leaves the title followed by zeros there, and sysinfo then
// reads the environment as the remaining arguments. The environment is never
// part of a command line here: the argument area ends after argc strings,
// empty ones included, and the empty ones are dropped.
//
// Linux (`/proc/<pid>/cmdline`) and Windows (the PEB command line) expose the
// argument area only, so they keep reading through sysinfo.

/// Parses a `KERN_PROCARGS2` buffer into the process's arguments. `None` when
/// the buffer is too short to hold argc and the executable path.
pub fn parse_procargs2(buf: &[u8]) -> Option<Vec<String>> {
    let argc = i32::from_ne_bytes(buf.get(..4)?.try_into().ok()?);
    let mut rest = &buf[4..];
    let exe_end = rest.iter().position(|b| *b == 0)?;
    rest = &rest[exe_end..];
    // Alignment padding between the executable path and the first argument.
    let Some(first) = rest.iter().position(|b| *b != 0) else {
        return Some(Vec::new());
    };
    rest = &rest[first..];
    let mut args = Vec::new();
    for _ in 0..argc.max(0) {
        if rest.is_empty() {
            break;
        }
        let end = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
        if end > 0 {
            args.push(String::from_utf8_lossy(&rest[..end]).into_owned());
        }
        rest = rest.get(end + 1..).unwrap_or(&[]);
    }
    Some(args)
}

#[cfg(target_os = "macos")]
mod macos {
    use std::os::raw::{c_int, c_uint, c_void};

    const CTL_KERN: c_int = 1;
    const KERN_PROCARGS2: c_int = 49;

    extern "C" {
        fn sysctl(
            name: *mut c_int,
            namelen: c_uint,
            oldp: *mut c_void,
            oldlenp: *mut usize,
            newp: *mut c_void,
            newlen: usize,
        ) -> c_int;
    }

    /// The raw `KERN_PROCARGS2` buffer of `pid`, or `None` when the kernel
    /// refuses it (process gone, or another user's process without root).
    pub(super) fn procargs2(pid: u32) -> Option<Vec<u8>> {
        let mut mib = [CTL_KERN, KERN_PROCARGS2, c_int::try_from(pid).ok()?];
        let mut size: usize = 0;
        // SAFETY: a size query (null output buffer) on a 3-element MIB.
        let rc = unsafe {
            sysctl(
                mib.as_mut_ptr(),
                3,
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 || size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size];
        // SAFETY: `buf` holds `size` bytes and the kernel writes at most that.
        let rc = unsafe {
            sysctl(
                mib.as_mut_ptr(),
                3,
                buf.as_mut_ptr() as *mut c_void,
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return None;
        }
        buf.truncate(size);
        Some(buf)
    }
}

/// The arguments of `pid` on macOS, or `None` when they cannot be read.
#[cfg(target_os = "macos")]
pub fn macos_command_line(pid: u32) -> Option<Vec<String>> {
    parse_procargs2(&macos::procargs2(pid)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn procargs(argc: i32, exe: &str, padding: usize, area: &[u8], environ: &[&str]) -> Vec<u8> {
        let mut buf = argc.to_ne_bytes().to_vec();
        buf.extend_from_slice(exe.as_bytes());
        buf.extend(std::iter::repeat(0u8).take(1 + padding));
        buf.extend_from_slice(area);
        for var in environ {
            buf.extend_from_slice(var.as_bytes());
            buf.push(0);
        }
        buf
    }

    #[test]
    fn arguments_stop_at_argc_and_never_read_the_environment() {
        let buf = procargs(
            3,
            "/opt/homebrew/bin/node",
            5,
            b"node\0/Users/u/app/server.js\0--port=8080\0",
            &["HOME=/Users/u", "API_TOKEN=not-a-real-token"],
        );
        assert_eq!(
            parse_procargs2(&buf).unwrap(),
            vec!["node", "/Users/u/app/server.js", "--port=8080"]
        );
    }

    #[test]
    fn a_rewritten_title_does_not_pull_the_environment_in() {
        // libuv writes the title over the argument area and zero-fills the
        // rest of it: 24 arguments become the title and 23 empty strings.
        let title = "Cursor Helper (Plugin): extension-host (user) project";
        let mut area = title.as_bytes().to_vec();
        area.extend(std::iter::repeat(0u8).take(900));
        let buf = procargs(
            24,
            "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper (Plugin).app/Contents/MacOS/Cursor Helper (Plugin)",
            3,
            &area,
            &["ANTHROPIC_API_KEY=not-a-real-key", "APPLE_DEVELOPER_ID_APPLICATION_KEY=not-a-real-key"],
        );
        let args = parse_procargs2(&buf).unwrap();
        assert_eq!(args, vec![title]);
        assert!(args.iter().all(|a| !a.contains('=')), "{args:?}");
    }

    #[test]
    fn empty_arguments_count_toward_argc() {
        let buf = procargs(3, "/bin/echo", 0, b"echo\0\0last\0", &["SECRET=x"]);
        assert_eq!(parse_procargs2(&buf).unwrap(), vec!["echo", "last"]);
    }

    #[test]
    fn short_or_argumentless_buffers_do_not_panic() {
        assert_eq!(parse_procargs2(&[]), None);
        assert_eq!(parse_procargs2(&[1, 0, 0]), None);
        assert_eq!(parse_procargs2(&procargs(0, "/bin/x", 2, b"", &[])).unwrap(), Vec::<String>::new());
        assert_eq!(parse_procargs2(&procargs(5, "/bin/x", 0, b"x\0", &[])).unwrap(), vec!["x"]);
        assert_eq!(parse_procargs2(&procargs(-1, "/bin/x", 0, b"x\0", &[])).unwrap(), Vec::<String>::new());
    }

    /// A live Node process that sets its title: the reader returns the title,
    /// not the environment it was started with.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_live_retitled_node_process_keeps_its_environment_out() {
        let Some(node) = ["/opt/homebrew/bin/node", "/usr/local/bin/node"]
            .iter()
            .find(|p| std::path::Path::new(p).exists())
        else {
            eprintln!("node not installed; the live retitle check did not run");
            return;
        };
        let mut child = std::process::Command::new(node)
            .args(["-e", "process.title = 'flodbadd-retitled'; setTimeout(() => {}, 5000)", "a", "b"])
            .env("FLODBADD_PROCARGS_TEST", "not-a-real-secret")
            .spawn()
            .expect("spawn node");
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let args = macos_command_line(child.id());
        let _ = child.kill();
        let _ = child.wait();
        let args = args.expect("own child's arguments are readable");
        assert!(
            args.iter().all(|a| !a.contains("FLODBADD_PROCARGS_TEST")),
            "environment read as arguments: {args:?}"
        );
        assert_eq!(args.first().map(String::as_str), Some("flodbadd-retitled"), "{args:?}");
    }
}
