#[cfg(all(target_os = "windows", feature = "packetcapture"))]
use reqwest;
#[cfg(any(all(feature = "ebpf", target_os = "linux"), target_os = "windows"))]
use std::env;
#[cfg(target_os = "windows")]
use std::fs;
#[cfg(any(all(feature = "ebpf", target_os = "linux"), target_os = "windows"))]
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::process::Command;
#[cfg(all(target_os = "windows", feature = "packetcapture"))]
use zip;

// Reuse shared Npcap helpers from src/npcap_utils.rs to avoid duplication
// (scoped under a distinct module name to prevent symbol collisions)
#[path = "src/npcap_utils.rs"]
mod build_npcap_utils;

// All Windows helpers/constants are sourced from build_npcap_utils

fn main() {
    // Always execute the Npcap download logic on Windows
    #[cfg(target_os = "windows")]
    {
        // Check Npcap runtime installation status
        check_npcap_runtime();

        // Install Npcap SDK if it is not detected
        println!("cargo:rerun-if-env-changed=NPCAP_SDK_PATH");
        if let Ok(npcap_path) = env::var("NPCAP_SDK_PATH") {
            println!("cargo:rustc-link-search=native={}/Lib/x64", npcap_path);
            println!("cargo:rustc-link-lib=dylib=Packet");
            println!("cargo:rustc-link-lib=dylib=wpcap");
            println!("Using user-provided Npcap SDK at: {}", npcap_path);
        } else {
            println!("cargo:warning=[Npcap SDK] NPCAP_SDK_PATH not set, attempting download");

            let out_dir = env::var("OUT_DIR").unwrap();
            let npcap_dir = Path::new(&out_dir).join("npcap");

            println!(
                "cargo:warning=[Npcap SDK] Target directory: {}",
                npcap_dir.display()
            );

            if !npcap_dir.exists() {
                println!(
                    "cargo:warning=[Npcap SDK] Directory does not exist, starting download..."
                );
                match download_npcap_sdk(&npcap_dir) {
                    Ok(_) => println!("cargo:warning=[Npcap SDK] ✓ Download and extraction completed successfully"),
                    Err(e) => println!("cargo:warning=[Npcap SDK] ✗ Failed to download: {}", e),
                }
            } else {
                println!("cargo:warning=[Npcap SDK] Directory already exists, skipping download");
            }

            // Determine arch-specific lib subdirectory (x64 vs x86)
            let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".into());
            let lib_subdir = if target_arch == "x86_64" {
                "x64"
            } else {
                "x86"
            };
            println!(
                "cargo:warning=[Npcap SDK] Target architecture: {} (lib subdir: {})",
                target_arch, lib_subdir
            );

            // Try installed SDK first (Program Files), then fallback to downloaded one
            let mut linked = false;
            println!("cargo:warning=[Npcap SDK] Searching for installed SDK in Program Files...");
            if let Some(installed_lib_dir) = find_installed_npcap_sdk_lib_dir(lib_subdir) {
                println!(
                    "cargo:warning=[Npcap SDK] ✓ Found installed SDK at: {}",
                    installed_lib_dir.display()
                );
                println!(
                    "cargo:rustc-link-search=native={}",
                    installed_lib_dir.display()
                );
                linked = true;
            } else {
                println!("cargo:warning=[Npcap SDK] No installed SDK found in Program Files");
            }

            if !linked && npcap_dir.exists() {
                println!("cargo:warning=[Npcap SDK] Searching in downloaded SDK...");
                if let Some(lib_dir) = find_npcap_lib_dir(&npcap_dir, lib_subdir) {
                    println!(
                        "cargo:warning=[Npcap SDK] ✓ Found libs at: {}",
                        lib_dir.display()
                    );
                    println!("cargo:rustc-link-search=native={}", lib_dir.display());
                    linked = true;
                } else {
                    println!(
                        "cargo:warning=[Npcap SDK] Could not locate Lib/{} under extracted SDK at {}",
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
                // On MSVC, use delay-load so we can set DLL search path at runtime before first use
                #[cfg(target_env = "msvc")]
                {
                    println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
                    println!("cargo:rustc-link-arg=/DELAYLOAD:Packet.dll");
                    println!("cargo:rustc-link-lib=dylib=delayimp");
                }

                // Add the Npcap runtime directory to the DLL search path
                let npcap_runtime = build_npcap_utils::get_npcap_dir();
                if npcap_runtime.exists() {
                    // Add to link search path for runtime DLL resolution
                    println!("cargo:rustc-link-search=native={}", npcap_runtime.display());
                    println!("cargo:rustc-env=NPCAP_DLL_PATH={}", npcap_runtime.display());
                    println!(
                        "cargo:warning=[Npcap SDK] ✓ Runtime DLL path: {}",
                        npcap_runtime.display()
                    );

                    // Best-effort: place DLLs next to produced binaries so the loader finds them without PATH edits
                    if let Err(e) = copy_npcap_runtime_dlls(&npcap_runtime) {
                        println!(
                            "cargo:warning=[Npcap SDK] ⚠ Failed to copy runtime DLLs next to binaries: {}",
                            e
                        );
                    }
                } else {
                    println!(
                        "cargo:warning=[Npcap SDK] ⚠ Runtime DLLs not found at: {}",
                        npcap_runtime.display()
                    );
                }

                println!("cargo:warning=[Npcap SDK] ✓ Linking configured - tests auto-configure DLL path");
            } else {
                println!(
                    "cargo:warning=[Npcap SDK] ✗ SDK libs not found; set NPCAP_SDK_PATH to the SDK root"
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
fn copy_npcap_runtime_dlls(npcap_runtime: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")?;
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let target_dir = env::var("CARGO_TARGET_DIR")
        .unwrap_or_else(|_| format!("{}{}target", manifest_dir, std::path::MAIN_SEPARATOR));

    let profile_dir = Path::new(&target_dir).join(&profile);
    let deps_dir = profile_dir.join("deps");

    let wpcap = npcap_runtime.join("wpcap.dll");
    let packet = npcap_runtime.join("Packet.dll");

    // Only proceed if the source DLLs exist
    if !wpcap.is_file() || !packet.is_file() {
        return Err("Npcap runtime DLLs not found".into());
    }

    // Ensure target directories exist
    fs::create_dir_all(&profile_dir)?;
    fs::create_dir_all(&deps_dir)?;

    let targets = [
        profile_dir.join("wpcap.dll"),
        profile_dir.join("Packet.dll"),
        deps_dir.join("wpcap.dll"),
        deps_dir.join("Packet.dll"),
    ];

    for dest in targets.iter() {
        let src = if dest
            .file_name()
            .unwrap()
            .to_string_lossy()
            .eq_ignore_ascii_case("wpcap.dll")
        {
            &wpcap
        } else {
            &packet
        };

        // Copy only if missing or source is newer
        let do_copy = match (fs::metadata(dest), fs::metadata(src)) {
            (Ok(dest_meta), Ok(src_meta)) => src_meta.modified().ok() > dest_meta.modified().ok(),
            (Err(_), Ok(_)) => true,
            _ => true,
        };

        if do_copy {
            fs::copy(src, dest)?;
        }
    }

    println!(
        "cargo:warning=[Npcap SDK] ✓ Copied Npcap DLLs to {} and {}",
        profile_dir.display(),
        deps_dir.display()
    );

    Ok(())
}

#[cfg(target_os = "windows")]
fn check_npcap_runtime() {
    let npcap_dir = build_npcap_utils::get_npcap_dir();
    let dll_to_check = npcap_dir.join("wpcap.dll");

    if dll_to_check.exists() {
        println!(
            "cargo:warning=[Npcap Runtime] ✓ Already installed at {}",
            npcap_dir.display()
        );
    } else {
        println!(
            "cargo:warning=[Npcap Runtime] Not found at {} - attempting auto-install",
            npcap_dir.display()
        );

        // Attempt auto-installation
        match auto_install_npcap() {
            Ok(_) => {
                println!("cargo:warning=[Npcap Runtime] ✓ Installation completed successfully");
                println!("cargo:warning=[Npcap Runtime] Tests will automatically configure DLL path at runtime");
                println!("cargo:warning=[Npcap Runtime] Run: cargo test --features packetcapture,asyncpacketcapture");
            }
            Err(e) => {
                println!("cargo:warning=[Npcap Runtime] ✗ Auto-install failed: {}", e);
                println!("cargo:warning=[Npcap Runtime] The build will succeed, but packet capture will not work.");
                println!(
                    "cargo:warning=[Npcap Runtime] Install Npcap manually from https://npcap.com"
                );
                println!("cargo:warning=[Npcap Runtime] The application will run in limited mode without Npcap.");
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn auto_install_npcap() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    let npcap_dir = build_npcap_utils::get_npcap_dir();
    let dll_to_check = npcap_dir.join("wpcap.dll");

    // Check if already installed
    if dll_to_check.exists() {
        println!("Npcap already detected at {}", npcap_dir.display());
        return Ok(());
    }

    println!(
        "Npcap not found at {} — attempting silent install",
        npcap_dir.display()
    );

    // Determine download location
    let temp_dir = std::env::temp_dir();
    let installer_path = temp_dir.join("npcap-installer.exe");

    // Use archived version for reliability
    let url = env::var("NPCAP_INSTALLER_URL")
        .unwrap_or_else(|_| build_npcap_utils::NPCAP_INSTALLER_URL.to_string());

    println!("cargo:warning=[Npcap] Downloading installer from: {}", url);

    // Download installer
    let response = reqwest::blocking::get(&url)?;
    println!("cargo:warning=[Npcap] Received HTTP response, reading bytes...");
    let bytes = response.bytes()?;
    println!(
        "cargo:warning=[Npcap] Downloaded {} bytes ({:.2} MB)",
        bytes.len(),
        bytes.len() as f64 / 1024.0 / 1024.0
    );

    // Write to temp file
    {
        let mut file = std::fs::File::create(&installer_path)?;
        file.write_all(&bytes)?;
        // Explicitly drop the file handle to ensure it's closed
        drop(file);
    }

    println!(
        "cargo:warning=[Npcap] Installer saved to: {}",
        installer_path.display()
    );

    // Small delay to allow antivirus/security software to finish scanning the file
    std::thread::sleep(std::time::Duration::from_millis(500));
    println!("cargo:warning=[Npcap] File handle closed, ready for installation");

    // Try msiexec silent install first
    println!("cargo:warning=[Npcap] Attempting installation via msiexec...");
    let msiexec_status = Command::new("msiexec")
        .args([
            "/i",
            installer_path.to_str().unwrap_or_default(),
            "/quiet",
            "/norestart",
        ])
        .status();

    let mut installed = dll_to_check.exists();

    if msiexec_status
        .as_ref()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        println!("cargo:warning=[Npcap] msiexec installation completed");
    }

    // If msiexec failed, try direct EXE execution
    if msiexec_status.map(|s| !s.success()).unwrap_or(true) && !installed {
        println!(
            "cargo:warning=[Npcap] msiexec install did not succeed, trying direct EXE execution"
        );

        let exe_status = Command::new(&installer_path)
            .args(["/S"]) // Silent install flag for NSIS installer
            .status();

        if let Err(e) = exe_status {
            println!("cargo:warning=[Npcap] Failed to execute installer: {}", e);
        } else {
            println!(
                "cargo:warning=[Npcap] Installer executed, waiting for installation to complete..."
            );
        }

        // Wait a bit for installation to complete
        std::thread::sleep(std::time::Duration::from_secs(5));
        installed = dll_to_check.exists();
    }

    // Clean up installer
    if let Ok(_) = std::fs::remove_file(&installer_path) {
        println!("cargo:warning=[Npcap] Cleaned up installer file");
    }

    if installed {
        println!(
            "cargo:warning=[Npcap] ✓ Installation successful - runtime detected at {}",
            npcap_dir.display()
        );

        // Configure DLL directory immediately for the build process
        if build_npcap_utils::configure_dll_directory(&npcap_dir) {
            println!("cargo:warning=[Npcap] ✓ DLL directory configured for build process");
        } else {
            println!("cargo:warning=[Npcap] ⚠ Could not set DLL directory (non-critical)");
        }

        // Also update PATH environment variable for this build process
        if build_npcap_utils::add_npcap_to_path(&npcap_dir) {
            println!("cargo:warning=[Npcap] ✓ Added to PATH for build process");
        }

        Ok(())
    } else {
        println!(
            "cargo:warning=[Npcap] ✗ Installation failed - DLL not found at {}",
            dll_to_check.display()
        );
        Err(format!(
            "Npcap installation failed. Manual installation may be required.\n\
             Please install Npcap manually with administrator privileges from https://npcap.com"
        )
        .into())
    }
}

#[cfg(target_os = "windows")]
fn download_npcap_sdk(npcap_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    // Allow overriding the SDK download URL via env var, default to archived link
    let url =
        env::var("NPCAP_SDK_URL").unwrap_or_else(|_| build_npcap_utils::NPCAP_SDK_URL.to_string());
    let zip_path = npcap_dir.with_extension("zip");

    println!("cargo:warning=[Npcap SDK] Downloading from: {}", url);

    // Download the zip file
    let response = reqwest::blocking::get(url)?;
    println!("cargo:warning=[Npcap SDK] Received HTTP response, reading bytes...");
    let bytes = response.bytes()?;
    println!(
        "cargo:warning=[Npcap SDK] Downloaded {} bytes ({:.2} MB)",
        bytes.len(),
        bytes.len() as f64 / 1024.0 / 1024.0
    );

    // Create output directory
    if let Some(parent) = zip_path.parent() {
        std::fs::create_dir_all(parent)?;
        println!(
            "cargo:warning=[Npcap SDK] Created directory: {}",
            parent.display()
        );
    }

    // Write zip file
    let mut file = std::fs::File::create(&zip_path)?;
    file.write_all(&bytes)?;

    println!(
        "cargo:warning=[Npcap SDK] Saved zip file to: {}",
        zip_path.display()
    );

    // Extract the zip file
    let file = std::fs::File::open(&zip_path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    let total_files = archive.len();

    println!(
        "cargo:warning=[Npcap SDK] Extracting {} files to {}",
        total_files,
        npcap_dir.display()
    );

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

    println!(
        "cargo:warning=[Npcap SDK] ✓ Extracted {} files to {}",
        total_files,
        npcap_dir.display()
    );

    // Clean up zip file
    if let Ok(_) = std::fs::remove_file(&zip_path) {
        println!("cargo:warning=[Npcap SDK] Cleaned up zip file");
    }

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
