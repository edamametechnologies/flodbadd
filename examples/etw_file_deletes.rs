//! Windows-only end-to-end check that the file monitor names the process
//! that deletes or renames a file, the way it names the one that writes it.
//!
//! Starts the ETW kernel trace and a `FimWatcher` on a probe directory under
//! `%TEMP%`, then:
//!   1. `git worktree add` a worktree of a scratch repository into the probe
//!      directory and `git worktree remove --force` it (a different git
//!      process from the one that wrote the files: the remover must be named,
//!      never the writer);
//!   2. has a child PowerShell create a tree, rename a file, replace one over
//!      another (`File.Replace`), write a `DeleteOnClose` file and
//!      `Remove-Item -Recurse` the tree.
//!
//! It then prints every event under the probe directory with the process the
//! monitor attributed it to, and the attributed / total counts per event
//! type. PASS = every delete and rename is attributed, and to the process
//! that performed it (same pid as the child that ran the command), and no
//! write under the worktree is given to the remover.
//!
//! ```text
//! cargo build --example etw_file_deletes --features etw,fim,examples
//! target\debug\examples\etw_file_deletes.exe
//! ```
//! Needs an elevated token (the NT Kernel Logger session) and `git` on PATH.

#[cfg(all(target_os = "windows", feature = "etw", feature = "fim"))]
fn main() {
    use flodbadd::fim::{FimConfig, FimWatcher};
    use flodbadd::fim_events::FimEventType;
    use std::path::Path;
    use std::process::Command;
    use std::time::Duration;

    fn run(cmd: &mut Command) -> u32 {
        let mut child = cmd.spawn().expect("spawn child");
        let pid = child.id();
        let status = child.wait().expect("wait child");
        println!("  pid {pid}: {status}");
        pid
    }

    flodbadd::l7_etw::init_and_log_status();
    println!("ETW: {}", flodbadd::l7_etw::etw_support());
    std::thread::sleep(Duration::from_secs(3));

    let own = std::process::id();
    let temp = std::env::temp_dir();
    let root = temp.join(format!("edamame_fimdel_probe_{own}"));
    let repo = temp.join(format!("edamame_fimdel_repo_{own}"));
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&repo);
    std::fs::create_dir_all(&root).expect("probe root");
    std::fs::create_dir_all(repo.join("tests")).expect("repo tests");
    std::fs::create_dir_all(repo.join(".github").join("workflows")).expect("repo workflows");
    std::fs::write(repo.join("README.md"), "probe\n").unwrap();
    std::fs::write(repo.join("tests").join("__init__.py"), "").unwrap();
    std::fs::write(
        repo.join("tests").join("test_app.py"),
        "def test_x():\n    pass\n",
    )
    .unwrap();
    std::fs::write(
        repo.join(".github").join("workflows").join("ci.yml"),
        "on: push\n",
    )
    .unwrap();
    // Git for Windows' `cmd\git.exe` is a launcher that runs the real git
    // as its child; run the real one, so the child pid is the actor.
    let exec_path = Command::new("git")
        .arg("--exec-path")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|p| !p.is_empty())
        .expect("git on PATH");
    let git_exe = Path::new(&exec_path).join("git.exe");
    println!("git: {}", git_exe.display());
    let git = |args: &[&str]| {
        let mut cmd = Command::new(&git_exe);
        cmd.arg("-C")
            .arg(&repo)
            .args([
                "-c",
                "user.name=probe",
                "-c",
                "user.email=probe@example.invalid",
            ])
            .args(args);
        cmd
    };
    println!("scratch repository {}", repo.display());
    run(&mut git(&["init", "-q"]));
    run(&mut git(&["add", "-A"]));
    run(&mut git(&["commit", "-q", "-m", "probe"]));

    let watcher = FimWatcher::start(vec![root.clone()], FimConfig::default())
        .expect("start the file monitor");
    std::thread::sleep(Duration::from_secs(3));

    let wt = root.join("wt");
    let wt_arg = wt.to_string_lossy().to_string();
    println!("git worktree add {wt_arg}");
    let git_add = run(&mut git(&[
        "worktree",
        "add",
        "-q",
        "-b",
        &format!("probe-{own}"),
        &wt_arg,
    ]));
    std::thread::sleep(Duration::from_millis(500));
    println!("git worktree remove --force {wt_arg}");
    let git_remove = run(&mut git(&["worktree", "remove", "--force", &wt_arg]));

    let ps = root.join("ps");
    let script = format!(
        "$d = '{d}'; New-Item -ItemType Directory -Force -Path \"$d\\tests\" | Out-Null; \
         Set-Content -Path \"$d\\tests\\test_probe.py\" -Value 'x'; \
         Set-Content -Path \"$d\\a.txt\" -Value 'a'; Start-Sleep -Milliseconds 300; \
         Rename-Item -Path \"$d\\a.txt\" -NewName 'b.txt'; \
         Set-Content -Path \"$d\\c.txt\" -Value 'old'; Set-Content -Path \"$d\\c.tmp\" -Value 'new'; \
         [System.IO.File]::Replace(\"$d\\c.tmp\", \"$d\\c.txt\", [NullString]::Value); \
         $f = [System.IO.File]::Create(\"$d\\doc.tmp\", 4096, [System.IO.FileOptions]::DeleteOnClose); \
         $f.WriteByte(1); $f.Close(); Start-Sleep -Milliseconds 300; \
         Remove-Item -Recurse -Force -Path $d",
        d = ps.display()
    );
    println!(
        "powershell create, rename, replace, delete-on-close, Remove-Item -Recurse {}",
        ps.display()
    );
    let powershell = run(Command::new("powershell").args(["-NoProfile", "-Command", &script]));

    // The deferred attribution worker retries at 2 s and 8 s.
    std::thread::sleep(Duration::from_secs(12));

    let mut events: Vec<_> = watcher
        .store()
        .get_all_events()
        .into_iter()
        .filter(|e| Path::new(&e.path).starts_with(&root))
        .collect();
    events.sort_by_key(|e| e.timestamp);
    let root_str = root.to_string_lossy().to_string();
    for e in &events {
        println!(
            "{} {:<6} {:<38} name={:<16} pid={:<6} path={}",
            e.timestamp.format("%H:%M:%S%.3f"),
            e.event_type.to_string(),
            e.path.strip_prefix(&root_str).unwrap_or(&e.path),
            e.process_name.as_deref().unwrap_or("-"),
            e.process_pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".into()),
            e.process_path.as_deref().unwrap_or("-"),
        );
    }

    let mut ok = true;
    for kind in [
        FimEventType::Create,
        FimEventType::Modify,
        FimEventType::Delete,
        FimEventType::Rename,
    ] {
        let of_kind: Vec<_> = events.iter().filter(|e| e.event_type == kind).collect();
        let attributed = of_kind
            .iter()
            .filter(|e| e.process_name.is_some() || e.process_path.is_some())
            .count();
        println!("{kind}: {attributed}/{} attributed", of_kind.len());
        if matches!(kind, FimEventType::Delete | FimEventType::Rename) {
            ok &= !of_kind.is_empty() && attributed == of_kind.len();
        }
    }
    // The remover, never the writer: under `wt` the deletes are git's
    // `worktree remove` (pid `git_remove`), the creates its `worktree add`
    // or a child of it; under `ps` everything is the PowerShell child.
    let wt_str = wt.to_string_lossy().to_string();
    let ps_str = ps.to_string_lossy().to_string();
    for e in events
        .iter()
        .filter(|e| matches!(e.event_type, FimEventType::Delete | FimEventType::Rename))
    {
        let expected = if e.path.starts_with(&wt_str) {
            git_remove
        } else if e.path.starts_with(&ps_str) {
            powershell
        } else {
            continue;
        };
        if e.process_pid != Some(expected) {
            println!(
                "WRONG ACTOR: {} {} -> pid {:?}, expected {expected} (git add was {git_add})",
                e.event_type, e.path, e.process_pid
            );
            ok = false;
        }
    }
    // Nor the other way round: no write under `wt` is given to the remover.
    for e in events.iter().filter(|e| {
        matches!(e.event_type, FimEventType::Create | FimEventType::Modify)
            && e.path.starts_with(&wt_str)
            && e.process_pid == Some(git_remove)
    }) {
        println!(
            "REMOVER LENT TO A WRITE: {} {} -> pid {git_remove}",
            e.event_type, e.path
        );
        ok = false;
    }

    watcher.stop();
    let _ = Command::new(&git_exe)
        .arg("-C")
        .arg(&repo)
        .args(["worktree", "prune"])
        .status();
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&repo);
    flodbadd::l7_etw::shutdown();
    println!("RESULT: {}", if ok { "PASS" } else { "FAIL" });
    std::process::exit(if ok { 0 } else { 1 });
}

#[cfg(not(all(target_os = "windows", feature = "etw", feature = "fim")))]
fn main() {
    println!("etw_file_deletes is Windows-only and needs the `etw` and `fim` features");
}
