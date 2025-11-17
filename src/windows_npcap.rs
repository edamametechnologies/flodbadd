use std::env;
#[cfg(target_os = "windows")]
use std::fs;
#[cfg(target_os = "windows")]
use std::io::Write;
use std::path::{Path, PathBuf};

// Public constants (used by build.rs and callers)
pub const NPCAP_INSTALLER_URL: &str =
    "https://web.archive.org/web/20220523140209/https://npcap.com/dist/npcap-0.96.exe";
pub const NPCAP_SDK_URL: &str =
    "https://web.archive.org/web/20220523140209/https://npcap.com/dist/npcap-sdk-0.1.zip";

#[cfg(target_os = "windows")]
pub const BUILD_ENV_NPCAP_LIB_DIR: &str = "DEP_FLODBADD_NPCAP_NPCAP_LIB_DIR";
#[cfg(target_os = "windows")]
pub const BUILD_ENV_NPCAP_RUNTIME_DIR: &str = "DEP_FLODBADD_NPCAP_NPCAP_RUNTIME_DIR";

pub fn ensure_wayback_raw(url: &str) -> String {
    if !url.contains("web.archive.org/web/") || url.contains("id_/") {
        return url.to_string();
    }

    const MARKER: &str = "/web/";
    if let Some(idx) = url.find(MARKER) {
        let prefix = &url[..idx + MARKER.len()];
        let suffix = &url[idx + MARKER.len()..];
        if let Some(pos) = suffix.find('/') {
            let (timestamp, remainder) = suffix.split_at(pos);
            if timestamp.ends_with("id_") {
                return url.to_string();
            }
            if remainder.len() > 1 {
                let remainder = &remainder[1..];
                return format!("{prefix}{timestamp}id_/{remainder}");
            }
        }
    }

    url.to_string()
}

// --- Detection helpers ---

fn find_npcap_runtime_dir_internal() -> Option<PathBuf> {
    let system_root = env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let candidates = [
        Path::new(&system_root).join("System32").join("Npcap"),
        Path::new(&system_root).join("SysWOW64").join("Npcap"),
        Path::new(&system_root).join("Sysnative").join("Npcap"),
        Path::new(&system_root).join("System32"),
        Path::new(&system_root).join("SysWOW64"),
    ];
    for dir in candidates.into_iter() {
        let wpcap = dir.join("wpcap.dll");
        let packet = dir.join("Packet.dll");
        if wpcap.is_file() && packet.is_file() {
            return Some(dir);
        }
    }
    None
}

pub fn find_npcap_runtime_dir() -> Option<PathBuf> {
    find_npcap_runtime_dir_internal()
}

pub fn get_npcap_dir() -> PathBuf {
    find_npcap_runtime_dir_internal().unwrap_or_else(|| {
        let system_root = env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        Path::new(&system_root).join("System32").join("Npcap")
    })
}

pub fn is_npcap_installed() -> bool {
    find_npcap_runtime_dir_internal().is_some()
}

// --- Runtime configuration ---

#[cfg(target_os = "windows")]
pub fn configure_dll_directory(npcap_dir: &Path) -> bool {
    unsafe {
        use std::os::windows::ffi::OsStrExt;
        let npcap_path_wide: Vec<u16> = std::ffi::OsStr::new(npcap_dir.to_str().unwrap())
            .encode_wide()
            .chain(Some(0))
            .collect();
        use windows::core::PCWSTR;
        use windows::Win32::System::LibraryLoader::SetDllDirectoryW;
        SetDllDirectoryW(PCWSTR(npcap_path_wide.as_ptr())).is_ok()
    }
}

pub fn add_npcap_to_path(npcap_dir: &Path) -> bool {
    if let Ok(current_path) = env::var("PATH") {
        let npcap_path_str = npcap_dir.to_string_lossy();
        if current_path.contains(npcap_path_str.as_ref()) {
            return true;
        }
        let new_path = format!("{};{}", npcap_path_str, current_path);
        env::set_var("PATH", new_path);
        true
    } else {
        false
    }
}

#[cfg(target_os = "windows")]
pub fn configure_npcap_runtime() -> Result<(), String> {
    let npcap_dir = find_npcap_runtime_dir_internal()
        .ok_or_else(|| "Npcap directory not found in standard locations".to_string())?;
    if !configure_dll_directory(&npcap_dir) {
        return Err("Failed to set DLL directory".to_string());
    }
    if !add_npcap_to_path(&npcap_dir) {
        return Err("Failed to update PATH".to_string());
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn configure_npcap_runtime() -> Result<(), String> {
    Ok(())
}

// --- Installer ---

#[cfg(target_os = "windows")]
pub fn auto_install_npcap_silent(installer_url: Option<String>) -> Result<(), String> {
    use std::io::Write;
    use std::process::Command;

    let npcap_dir = get_npcap_dir();
    let dll_to_check = npcap_dir.join("wpcap.dll");
    if dll_to_check.exists() {
        return Ok(());
    }

    let temp_dir = std::env::temp_dir();
    let installer_path = temp_dir.join("npcap-installer.exe");
    let raw_url = installer_url.unwrap_or_else(|| NPCAP_INSTALLER_URL.to_string());
    let url = ensure_wayback_raw(&raw_url);

    let response = reqwest::blocking::get(&url).map_err(|e| format!("download failed: {}", e))?;
    let bytes = response
        .bytes()
        .map_err(|e| format!("read failed: {}", e))?;
    if !bytes.starts_with(b"MZ") {
        return Err(
            "downloaded installer is not a valid Windows executable (missing MZ header)".into(),
        );
    }

    {
        let mut f =
            std::fs::File::create(&installer_path).map_err(|e| format!("create failed: {}", e))?;
        f.write_all(&bytes)
            .map_err(|e| format!("write failed: {}", e))?;
    }
    std::thread::sleep(std::time::Duration::from_millis(500));

    let is_msi = installer_path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.eq_ignore_ascii_case("msi"))
        .unwrap_or(false);
    if is_msi {
        let _ = Command::new("msiexec")
            .args([
                "/i",
                installer_path.to_str().unwrap_or_default(),
                "/quiet",
                "/norestart",
            ])
            .status();
    } else {
        let mut attempts = 0;
        while attempts < 3 {
            match Command::new(&installer_path).args(["/S"]).status() {
                Ok(_) => break,
                Err(_) => {
                    attempts += 1;
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
        }
    }

    let mut installed = dll_to_check.exists();
    for _ in 0..15 {
        if dll_to_check.exists() {
            installed = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let _ = std::fs::remove_file(&installer_path);
    if installed {
        let _ = configure_npcap_runtime();
        Ok(())
    } else {
        Err("Npcap installation failed".to_string())
    }
}

#[cfg(not(target_os = "windows"))]
pub fn auto_install_npcap_silent(_installer_url: Option<String>) -> Result<(), String> {
    Err("Npcap auto-install is only supported on Windows".to_string())
}

// Build helper: copy runtime DLLs next to produced binaries
pub fn copy_npcap_dlls_next_to_binaries() -> Result<(), String> {
    let npcap_dir = get_npcap_dir();
    let wpcap = npcap_dir.join("wpcap.dll");
    let packet = npcap_dir.join("Packet.dll");
    if !wpcap.is_file() || !packet.is_file() {
        return Err("Npcap runtime not found".to_string());
    }

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let target_dir = env::var("CARGO_TARGET_DIR")
        .unwrap_or_else(|_| format!("{}{}target", manifest_dir, std::path::MAIN_SEPARATOR));
    let profile_dir = std::path::Path::new(&target_dir).join(&profile);
    let deps_dir = profile_dir.join("deps");
    let _ = std::fs::create_dir_all(&profile_dir);
    let _ = std::fs::create_dir_all(&deps_dir);
    let _ = std::fs::copy(&wpcap, profile_dir.join("wpcap.dll"));
    let _ = std::fs::copy(&packet, profile_dir.join("Packet.dll"));
    let _ = std::fs::copy(&wpcap, deps_dir.join("wpcap.dll"));
    let _ = std::fs::copy(&packet, deps_dir.join("Packet.dll"));
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn configure_build_linking_from_metadata() {
    use std::env;

    let mut sdk_path_available = false;

    if let Ok(lib_dir) = env::var(BUILD_ENV_NPCAP_LIB_DIR) {
        println!("cargo:rustc-link-search=native={lib_dir}");
        sdk_path_available = true;
    } else {
        match ensure_local_npcap_sdk_lib_dir() {
            Ok(local_lib_dir) => {
                println!(
                    "cargo:warning=[Npcap SDK] Using locally downloaded SDK at {}",
                    local_lib_dir.display()
                );
                println!("cargo:rustc-link-search=native={}", local_lib_dir.display());
                sdk_path_available = true;
            }
            Err(err) => {
                println!(
                    "cargo:warning=Npcap SDK library path missing ({}). wpcap.lib may be unresolved. {}",
                    BUILD_ENV_NPCAP_LIB_DIR, err
                );
            }
        }
    }

    if let Ok(runtime_dir) = env::var(BUILD_ENV_NPCAP_RUNTIME_DIR) {
        println!("cargo:rustc-link-search=native={runtime_dir}");
        println!("cargo:rustc-env=NPCAP_DLL_PATH={runtime_dir}");
    }

    #[cfg(target_env = "msvc")]
    {
        println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:Packet.dll");
        println!("cargo:rustc-link-lib=dylib=delayimp");
    }

    let npcap_dir = get_npcap_dir();
    if npcap_dir.exists() {
        let _ = copy_npcap_dlls_next_to_binaries();
        println!("cargo:rustc-link-search=native={}", npcap_dir.display());
        if env::var(BUILD_ENV_NPCAP_RUNTIME_DIR).is_err() {
            println!("cargo:rustc-env=NPCAP_DLL_PATH={}", npcap_dir.display());
        }
    } else if !sdk_path_available {
        println!(
            "cargo:warning=Npcap runtime not found; packet capture features will be disabled."
        );
    }
}

#[cfg(not(target_os = "windows"))]
pub fn configure_build_linking_from_metadata() {}

#[cfg(target_os = "windows")]
fn contains_wpcap_and_packet(dir: &Path) -> bool {
    dir.is_dir() && dir.join("wpcap.lib").is_file() && dir.join("Packet.lib").is_file()
}

#[cfg(target_os = "windows")]
fn ensure_local_npcap_sdk_lib_dir() -> Result<PathBuf, String> {
    let out_dir = env::var("OUT_DIR").map_err(|e| format!("OUT_DIR not set: {}", e))?;
    let sdk_root = Path::new(&out_dir).join("npcap-sdk");
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".to_string());
    let lib_subdir = if target_arch == "x86_64" {
        "x64"
    } else {
        "x86"
    };
    let lib_dir = sdk_root.join("Lib").join(lib_subdir);

    if contains_wpcap_and_packet(&lib_dir) {
        return Ok(lib_dir);
    }

    if sdk_root.exists() {
        fs::remove_dir_all(&sdk_root).map_err(|e| {
            format!(
                "failed to clean existing Npcap SDK dir {}: {}",
                sdk_root.display(),
                e
            )
        })?;
    }
    fs::create_dir_all(&sdk_root).map_err(|e| {
        format!(
            "failed to create Npcap SDK dir {}: {}",
            sdk_root.display(),
            e
        )
    })?;

    let zip_path = sdk_root.with_extension("zip");
    let url = ensure_wayback_raw(NPCAP_SDK_URL);
    let response =
        reqwest::blocking::get(&url).map_err(|e| format!("Npcap SDK download failed: {}", e))?;
    let bytes = response
        .bytes()
        .map_err(|e| format!("Npcap SDK download read failed: {}", e))?;
    {
        let mut file = std::fs::File::create(&zip_path)
            .map_err(|e| format!("failed to create SDK zip {}: {}", zip_path.display(), e))?;
        file.write_all(&bytes)
            .map_err(|e| format!("failed to write SDK zip {}: {}", zip_path.display(), e))?;
    }

    let file = std::fs::File::open(&zip_path)
        .map_err(|e| format!("failed to open SDK zip {}: {}", zip_path.display(), e))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| {
        format!(
            "failed to read SDK zip archive {}: {}",
            zip_path.display(),
            e
        )
    })?;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| format!("failed to read SDK zip entry {}: {}", i, e))?;
        let outpath = sdk_root.join(entry.mangled_name());
        if entry.is_dir() {
            fs::create_dir_all(&outpath)
                .map_err(|e| format!("failed to create dir {}: {}", outpath.display(), e))?;
        } else {
            if let Some(parent) = outpath.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("failed to create dir {}: {}", parent.display(), e))?;
            }
            let mut outfile = std::fs::File::create(&outpath)
                .map_err(|e| format!("failed to create file {}: {}", outpath.display(), e))?;
            std::io::copy(&mut entry, &mut outfile)
                .map_err(|e| format!("failed to extract {}: {}", outpath.display(), e))?;
        }
    }
    let _ = std::fs::remove_file(&zip_path);

    if contains_wpcap_and_packet(&lib_dir) {
        Ok(lib_dir)
    } else {
        Err(format!(
            "Npcap SDK downloaded to {} but Lib/{} is missing wpcap.lib",
            sdk_root.display(),
            lib_subdir
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_constants() {
        assert!(NPCAP_INSTALLER_URL.contains("web.archive.org"));
        assert!(NPCAP_SDK_URL.contains("web.archive.org"));
    }
}
