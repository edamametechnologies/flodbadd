use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Only build eBPF program on Linux with ebpf feature
    if cfg!(not(target_os = "linux")) || !cfg!(feature = "ebpf") {
        return;
    }

    let out_dir = env::var("OUT_DIR").unwrap();
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    
    // Create eBPF output directory
    let ebpf_dir = PathBuf::from(&out_dir).join("ebpf");
    std::fs::create_dir_all(&ebpf_dir).unwrap();
    
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
    
    // Check for required tools
    if !check_tool("clang") {
        panic!("clang not found - required for eBPF compilation");
    }
    
    if !check_tool("llvm-strip") {
        panic!("llvm-strip not found - required for eBPF compilation");
    }
    
    // Compile the eBPF program
    let output = Command::new("clang")
        .args([
            "-target", "bpf",
            "-D__BPF_TRACING__",
            "-Wall",
            "-Wextra",
            "-O2",
            "-g",
            "-c",
            "-o", obj_file.to_str().unwrap(),
            src_file.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute clang");
    
    if !output.status.success() {
        panic!(
            "Failed to compile eBPF program:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    
    // Strip debug symbols
    let output = Command::new("llvm-strip")
        .args(["-g", obj_file.to_str().unwrap()])
        .output()
        .expect("Failed to execute llvm-strip");
    
    if !output.status.success() {
        panic!(
            "Failed to strip eBPF program:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    
    println!("eBPF program compiled successfully: {}", obj_file.display());
    
    // Set environment variables for the main program
    set_env_vars(&obj_file);
}

fn check_tool(tool: &str) -> bool {
    Command::new("which")
        .arg(tool)
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