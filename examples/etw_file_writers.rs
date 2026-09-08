//! Windows-only check of the ETW FIM writer-attribution table: starts the
//! kernel trace, has a child PowerShell create + write a temp file, then a
//! second child only *read* it, and prints who the table names as the
//! writer. Correct output names the first child (the writer) both times:
//! same pid before and after the read.
//!
//! ```text
//! cargo build --example etw_file_writers --features etw,examples
//! target\debug\examples\etw_file_writers.exe
//! ```
//! Needs an elevated token (the NT Kernel Logger session).

#[cfg(all(target_os = "windows", feature = "etw"))]
fn main() {
    use std::process::Command;
    use std::time::Duration;

    flodbadd::l7_etw::init_and_log_status();
    println!("ETW: {}", flodbadd::l7_etw::etw_support());
    std::thread::sleep(Duration::from_secs(3));

    let temp = std::env::temp_dir().join(format!("edamame_etw_writers_{}.txt", std::process::id()));
    let path = temp.to_string_lossy().to_string();

    let writer = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("Set-Content -Path '{}' -Value 'hello'", path),
        ])
        .status();
    println!("writer child: {:?}", writer);
    std::thread::sleep(Duration::from_secs(2));
    let after_write = flodbadd::l7_etw::get_file_attribution(&path);
    println!("after write : {:?}", after_write);

    // Another PowerShell so only the pid tells the two apart.
    let reader = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("Get-Content -Path '{}' | Out-Null", path),
        ])
        .status();
    println!("reader child: {:?}", reader);
    std::thread::sleep(Duration::from_secs(2));
    let after_read = flodbadd::l7_etw::get_file_attribution(&path);
    println!("after read  : {:?}", after_read);

    let _ = std::fs::remove_file(&temp);
    let ok = match (&after_write, &after_read) {
        (Some((wpid, wname, _)), Some((rpid, _, _))) => {
            wname.eq_ignore_ascii_case("powershell.exe") && wpid == rpid
        }
        _ => false,
    };
    println!("RESULT: {}", if ok { "PASS" } else { "FAIL" });
    std::process::exit(if ok { 0 } else { 1 });
}

#[cfg(not(all(target_os = "windows", feature = "etw")))]
fn main() {
    println!("etw_file_writers is Windows-only and needs the `etw` feature");
}
