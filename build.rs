#[cfg(all(target_os = "windows", feature = "packetcapture"))]
use reqwest;
#[cfg(any(all(feature = "ebpf", target_os = "linux"), target_os = "windows"))]
use std::env;
#[cfg(any(all(feature = "ebpf", target_os = "linux"), target_os = "windows"))]
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::process::Command;
#[cfg(all(target_os = "windows", feature = "packetcapture"))]
use zip;

fn main() {
    // Always execute the Npcap download logic on Windows
    #[cfg(target_os = "windows")]
    {
        // Warn if Npcap runtime is not detected (non-fatal)
        check_npcap_runtime();

        println!("cargo:rerun-if-env-changed=NPCAP_SDK_PATH");

        if let Ok(npcap_path) = env::var("NPCAP_SDK_PATH") {
            println!("cargo:rustc-link-search=native={}/Lib/x64", npcap_path);
            println!("cargo:rustc-link-lib=dylib=Packet");
            println!("cargo:rustc-link-lib=dylib=wpcap");
            println!("Using user-provided Npcap SDK at: {}", npcap_path);
        } else {
            println!("cargo:warning=Attempting to download Npcap SDK");

            let out_dir = env::var("OUT_DIR").unwrap();
            let npcap_dir = Path::new(&out_dir).join("npcap");

            if !npcap_dir.exists() {
                match download_npcap_sdk(&npcap_dir) {
                    Ok(_) => println!("Npcap SDK downloaded successfully"),
                    Err(e) => println!("cargo:warning=Failed to download Npcap SDK: {}", e),
                }
            }

            // Determine arch-specific lib subdirectory (x64 vs x86)
            let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".into());
            let lib_subdir = if target_arch == "x86_64" {
                "x64"
            } else {
                "x86"
            };

            // Try installed SDK first (Program Files), then fallback to downloaded one
            let mut linked = false;
            if let Some(installed_lib_dir) = find_installed_npcap_sdk_lib_dir(lib_subdir) {
                println!(
                    "cargo:rustc-link-search=native={}",
                    installed_lib_dir.display()
                );
                linked = true;
            }

            if !linked && npcap_dir.exists() {
                if let Some(lib_dir) = find_npcap_lib_dir(&npcap_dir, lib_subdir) {
                    println!("cargo:rustc-link-search=native={}", lib_dir.display());
                    linked = true;
                } else {
                    println!(
                        "cargo:warning=Could not locate Lib/{} under extracted Npcap SDK at {}",
                        lib_subdir,
                        npcap_dir.display()
                    );
                    let fallback = npcap_dir.join("Lib").join(lib_subdir);
                    if contains_wpcap_and_packet(&fallback) {
                        println!("cargo:rustc-link-search=native={}", fallback.display());
                        linked = true;
                    } else {
                        println!("cargo:warning=No {} libraries found in downloaded SDK; set NPCAP_SDK_PATH to a matching SDK (e.g., C:\\Program Files\\Npcap\\SDK) or set NPCAP_SDK_URL to a zip that contains Lib\\{}", lib_subdir, lib_subdir);
                    }
                }
            }

            if linked {
                println!("cargo:rustc-link-lib=dylib=Packet");
                println!("cargo:rustc-link-lib=dylib=wpcap");
            } else {
                println!(
                    "cargo:warning=Npcap SDK libs not found; set NPCAP_SDK_PATH to the SDK root"
                );
            }
        }
    }

    // Handle eBPF program compilation on Linux
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    {
        handle_ebpf_build();
    }
}

#[cfg(target_os = "windows")]
fn check_npcap_runtime() {
    let system_root = env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let npcap_dir = Path::new(&system_root).join("System32").join("Npcap");
    let dll_to_check = npcap_dir.join("wpcap.dll");

    if dll_to_check.exists() {
        println!(
            "cargo:warning=Npcap runtime detected at {}",
            npcap_dir.display()
        );
    } else {
        println!(
            "cargo:warning=Npcap runtime not found at {}",
            npcap_dir.display()
        );
        println!(
            "cargo:warning=The build will succeed, but packet capture will not work at runtime."
        );
        println!("cargo:warning=Install Npcap from https://npcap.com to enable packet capture functionality.");
        println!("cargo:warning=The application will detect Npcap at startup and run in limited mode if not found.");
    }
}

#[cfg(target_os = "windows")]
fn download_npcap_sdk(npcap_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    // Allow overriding the SDK download URL via env var, default to archived link
    let url = env::var("NPCAP_SDK_URL").unwrap_or_else(|_| {
        // Archive of the Npcap SDK zip to improve reliability when npcap.com is unavailable
        // If you need a different version, set NPCAP_SDK_URL accordingly.
        "https://web.archive.org/web/20220523140209/https://npcap.com/dist/npcap-sdk-0.1.zip"
            .to_string()
    });
    let zip_path = npcap_dir.with_extension("zip");

    println!("Downloading Npcap SDK from: {}", url);

    // Download the zip file
    let response = reqwest::blocking::get(url)?;
    let bytes = response.bytes()?;

    // Create output directory
    if let Some(parent) = zip_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write zip file
    let mut file = std::fs::File::create(&zip_path)?;
    file.write_all(&bytes)?;

    println!("Downloaded {} bytes to {}", bytes.len(), zip_path.display());

    // Extract the zip file
    let file = std::fs::File::open(&zip_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = npcap_dir.join(file.name());

        if file.name().ends_with('/') {
            std::fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    std::fs::create_dir_all(p)?;
                }
            }
            let mut outfile = std::fs::File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }
    }

    println!("Extracted Npcap SDK to {}", npcap_dir.display());

    // Clean up zip file
    let _ = std::fs::remove_file(&zip_path);

    Ok(())
}

#[cfg(target_os = "windows")]
fn find_npcap_lib_dir(root: &Path, lib_subdir: &str) -> Option<PathBuf> {
    // 1) Prefer a direct Lib/x64 under root
    let direct = root.join("Lib").join(lib_subdir);
    if contains_wpcap_and_packet(&direct) {
        return Some(direct);
    }

    // 2) If SDK extracted under a subfolder (e.g., npcap-sdk-0.1), check those first
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                let candidate = p.join("Lib").join(lib_subdir);
                if contains_wpcap_and_packet(&candidate) {
                    return Some(candidate);
                }
            }
        }
    }

    // 3) Fallback: recursive search but prefer any path containing x64
    let mut best: Option<PathBuf> = None;
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                    if name.eq_ignore_ascii_case("wpcap.lib") {
                        if let Some(parent) = path.parent() {
                            let parent_dir = parent.to_path_buf();
                            let parent_sl = parent_dir.to_string_lossy().to_ascii_lowercase();
                            if parent_sl.contains(&lib_subdir.to_ascii_lowercase()) {
                                return Some(parent_dir);
                            }
                            best.get_or_insert(parent_dir);
                        }
                    }
                }
            }
        }
    }
    best
}

#[cfg(target_os = "windows")]
fn contains_wpcap_and_packet(dir: &Path) -> bool {
    dir.is_dir() && dir.join("wpcap.lib").is_file() && dir.join("Packet.lib").is_file()
}

#[cfg(target_os = "windows")]
fn find_installed_npcap_sdk_lib_dir(lib_subdir: &str) -> Option<PathBuf> {
    let possible_roots = [
        r"C:\\npcap-sdk",
        r"C:\\Program Files\\Npcap\\SDK",
        r"C:\\Program Files (x86)\\Npcap\\SDK",
    ];
    for root in possible_roots {
        let path = Path::new(root).join("Lib").join(lib_subdir);
        if path.is_dir() {
            return Some(path);
        }
    }
    None
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn handle_ebpf_build() {
    println!("cargo:rerun-if-changed=ebpf/l7_ebpf_program/src/l7_ebpf.c");
    println!("cargo:rerun-if-changed=ebpf/l7_ebpf_program/build.rs");

    // The eBPF program should be built by its own build.rs
    // We just need to ensure the path is available to our code

    // Check if the eBPF program was built
    let out_dir = env::var("OUT_DIR").unwrap();
    let ebpf_dir = Path::new(&out_dir).join("ebpf");
    let obj_file = ebpf_dir.join("l7_ebpf.o");

    if !obj_file.exists() {
        // Try to build it manually if the build dependency didn't work
        println!("cargo:warning=eBPF object file not found, attempting manual build");

        if let Err(e) = build_ebpf_program(&obj_file) {
            println!("cargo:warning=Failed to build eBPF program: {}", e);
        }
    }

    if obj_file.exists() {
        println!("cargo:rustc-env=L7_EBPF_OBJECT={}", obj_file.display());
        println!("eBPF program available at: {}", obj_file.display());
    } else {
        println!(
            "cargo:warning=eBPF program not available - L7 resolution will use fallback methods"
        );
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn build_ebpf_program(obj_file: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let src_file = Path::new(&manifest_dir).join("ebpf/l7_ebpf_program/src/l7_ebpf.c");

    if !src_file.exists() {
        return Err("eBPF source file not found".into());
    }

    // Create output directory
    if let Some(parent) = obj_file.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Check for required tools
    if !Command::new("clang").arg("--version").output().is_ok() {
        return Err("clang not found - required for eBPF compilation".into());
    }

    // Compile the eBPF program
    let output = Command::new("clang")
        .args([
            "-target",
            "bpf",
            "-D__BPF_TRACING__",
            "-Wall",
            "-Wextra",
            "-O2",
            "-g",
            "-c",
            "-o",
            obj_file.to_str().unwrap(),
            src_file.to_str().unwrap(),
        ])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "Failed to compile eBPF program:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    // Strip debug symbols if llvm-strip is available
    if Command::new("llvm-strip").arg("--version").output().is_ok() {
        let output = Command::new("llvm-strip")
            .args(["-g", obj_file.to_str().unwrap()])
            .output()?;

        if !output.status.success() {
            println!("cargo:warning=Failed to strip eBPF program (non-fatal)");
        }
    }

    Ok(())
}
