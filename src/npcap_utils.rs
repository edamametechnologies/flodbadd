// Common Npcap utilities for Windows
// This module is shared between build.rs, runtime, and tests

use std::env;
use std::path::{Path, PathBuf};

/// Npcap installer URL - archived version for reliability
pub const NPCAP_INSTALLER_URL: &str =
    "https://web.archive.org/web/20220523140209/https://npcap.com/dist/npcap-0.96.exe";

/// Npcap SDK URL - archived version for reliability  
pub const NPCAP_SDK_URL: &str =
    "https://web.archive.org/web/20220523140209/https://npcap.com/dist/npcap-sdk-0.1.zip";

/// Get the Npcap installation directory on Windows
pub fn get_npcap_dir() -> PathBuf {
    let system_root = env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    Path::new(&system_root).join("System32").join("Npcap")
}

/// Check if Npcap is installed by looking for wpcap.dll
#[allow(dead_code)]
pub fn is_npcap_installed() -> bool {
    get_npcap_dir().join("wpcap.dll").exists()
}

/// Configure DLL directory for Windows process
/// This allows the process to find Npcap DLLs at runtime
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

/// Add Npcap directory to PATH environment variable
pub fn add_npcap_to_path(npcap_dir: &Path) -> bool {
    if let Ok(current_path) = env::var("PATH") {
        let npcap_path_str = npcap_dir.to_string_lossy();

        // Check if already in PATH
        if current_path.contains(npcap_path_str.as_ref()) {
            return true;
        }

        // Add to PATH
        let new_path = format!("{};{}", npcap_path_str, current_path);
        env::set_var("PATH", new_path);
        true
    } else {
        false
    }
}

/// Complete Npcap DLL path configuration
/// Combines both SetDllDirectoryW and PATH update
#[cfg(target_os = "windows")]
#[allow(dead_code)]
pub fn configure_npcap_runtime() -> Result<(), String> {
    let npcap_dir = get_npcap_dir();

    if !npcap_dir.exists() {
        return Err(format!(
            "Npcap directory not found at {}",
            npcap_dir.display()
        ));
    }

    // Configure DLL directory
    if !configure_dll_directory(&npcap_dir) {
        return Err("Failed to set DLL directory".to_string());
    }

    // Add to PATH
    if !add_npcap_to_path(&npcap_dir) {
        return Err("Failed to update PATH".to_string());
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn configure_npcap_runtime() -> Result<(), String> {
    Ok(()) // No-op on non-Windows platforms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "windows")]
    fn test_get_npcap_dir() {
        let dir = get_npcap_dir();
        assert!(dir.to_string_lossy().contains("Npcap"));
    }

    #[test]
    fn test_constants() {
        assert!(NPCAP_INSTALLER_URL.contains("web.archive.org"));
        assert!(NPCAP_SDK_URL.contains("web.archive.org"));
        assert!(NPCAP_INSTALLER_URL.contains("20220523140209")); // Ensure using 2022 archive
        assert!(NPCAP_SDK_URL.contains("20220523140209"));
    }
}
