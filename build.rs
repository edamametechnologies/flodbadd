#[cfg(all(target_os = "windows", feature = "packetcapture"))]
use reqwest;
#[cfg(all(target_os = "windows", feature = "packetcapture"))]
use std::env;
#[cfg(any(all(feature = "ebpf", target_os = "linux"), target_os = "windows"))]
use std::env;
#[cfg(any(all(feature = "ebpf", target_os = "linux"), target_os = "windows"))]
use std::path::Path;
#[cfg(all(target_os = "windows", feature = "packetcapture"))]
use zip;

fn main() {
    // Always execute the Npcap download logic on Windows
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rerun-if-env-changed=NPCAP_SDK_PATH");

        if let Ok(npcap_path) = env::var("NPCAP_SDK_PATH") {
            println!("cargo:rustc-link-search=native={}/Lib/x64", npcap_path);
            println!("cargo:rustc-link-lib=static=Packet");
            println!("cargo:rustc-link-lib=static=wpcap");
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

            if npcap_dir.exists() {
                println!(
                    "cargo:rustc-link-search=native={}/Lib/x64",
                    npcap_dir.display()
                );
                println!("cargo:rustc-link-lib=static=Packet");
                println!("cargo:rustc-link-lib=static=wpcap");
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
fn download_npcap_sdk(npcap_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    let url = "https://npcap.com/dist/npcap-sdk-1.13.zip";
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
