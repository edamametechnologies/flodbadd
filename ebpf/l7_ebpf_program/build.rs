use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Debug: confirm this build.rs is running
    println!("cargo:warning=[l7_ebpf_program] build.rs running on {}", std::env::consts::OS);
    
    // Only build eBPF program on Linux with ebpf feature
    if cfg!(not(target_os = "linux")) || !cfg!(feature = "ebpf") {
        println!("cargo:warning=[l7_ebpf_program] Skipping: not linux or no ebpf feature");
        return;
    }
    
    println!("cargo:warning=[l7_ebpf_program] Proceeding with eBPF compilation");

    let out_dir = env::var("OUT_DIR").unwrap();
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // Create eBPF output directory
    let ebpf_dir = PathBuf::from(&out_dir).join("ebpf");
    if let Err(e) = std::fs::create_dir_all(&ebpf_dir) {
        println!("cargo:warning=Failed to create eBPF output directory: {}", e);
        return;
    }

    // Set up paths
    let src_file = PathBuf::from(&manifest_dir).join("src/l7_ebpf.c");
    let obj_file = ebpf_dir.join("l7_ebpf.o");

    // Check if we need to rebuild
    if let Ok(obj_metadata) = std::fs::metadata(&obj_file) {
        if let Ok(src_metadata) = std::fs::metadata(&src_file) {
            if obj_metadata.modified().unwrap() > src_metadata.modified().unwrap() {
                // Object file is newer than source, no need to rebuild
                set_env_vars(&obj_file);
                return;
            }
        }
    }

    println!("cargo:rerun-if-changed=src/l7_ebpf.c");
    println!("cargo:rerun-if-changed=build.rs");

    // Check for required tools - gracefully skip if not available
    if !check_tool("clang") {
        println!("cargo:warning=clang not found - eBPF program will not be compiled");
        println!("cargo:warning=Install clang/llvm to enable eBPF L7 process resolution");
        return;
    }

    // Determine target architecture for eBPF
    let target_arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x86",
        "x86" => "x86",
        arch => {
            println!(
                "cargo:warning=Unknown architecture {}, defaulting to x86 for eBPF",
                arch
            );
            "x86"
        }
    };

    // Determine architecture-specific include directory
    let arch_include = match std::env::consts::ARCH {
        "aarch64" => "/usr/include/aarch64-linux-gnu",
        "x86_64" | "x86" => "/usr/include/x86_64-linux-gnu",
        _ => "/usr/include",
    };

    let target_arch_define = format!("-D__TARGET_ARCH_{}", target_arch);
    let src_dir = PathBuf::from(&manifest_dir).join("src");

    // Compile the eBPF program with proper architecture flags
    let output = match Command::new("clang")
        .args([
            "-target",
            "bpf",
            "-D__BPF_TRACING__",
            &target_arch_define,
            "-Wall",
            "-O2",
            "-g",
            "-c",
            &format!("-I{}", arch_include),
            &format!("-I{}", src_dir.to_str().unwrap()),
            "-o",
            obj_file.to_str().unwrap(),
            src_file.to_str().unwrap(),
        ])
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            println!("cargo:warning=Failed to execute clang: {}", e);
            return;
        }
    };

    if !output.status.success() {
        println!(
            "cargo:warning=eBPF compilation failed (this is expected in containers without full eBPF support)"
        );
        println!(
            "cargo:warning=clang stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    // Note: We intentionally do NOT strip the eBPF object file.
    // The BTF (BPF Type Format) information is embedded alongside debug info
    // and is required for the eBPF loader (aya) to work correctly.
    // Running llvm-strip -g would remove BTF sections (.BTF, .BTF.ext).

    println!(
        "cargo:warning=eBPF program compiled successfully: {}",
        obj_file.display()
    );

    // Set environment variables for the main program
    set_env_vars(&obj_file);
}

fn check_tool(tool: &str) -> bool {
    // Use --version instead of 'which' for portability (Alpine doesn't have which by default)
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn set_env_vars(obj_file: &PathBuf) {
    // Set the path to the compiled eBPF object file
    println!("cargo:rustc-env=L7_EBPF_OBJECT={}", obj_file.display());

    // Also set it as a link search path for runtime discovery
    if let Some(parent) = obj_file.parent() {
        println!("cargo:rustc-env=L7_EBPF_DIR={}", parent.display());
    }
}
