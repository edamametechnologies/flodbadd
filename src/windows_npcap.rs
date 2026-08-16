use std::env;
#[cfg(target_os = "windows")]
use std::fs;
#[cfg(target_os = "windows")]
use std::io::Write;
use std::path::{Path, PathBuf};

// Public constants (used by build.rs and callers)

/// Npcap 0.96 installer. Archive-only by necessity: upstream rotated this
/// version away and `npcap.com/dist/npcap-0.96.exe` answers 404, so there is no
/// direct source to fall back to.
pub const NPCAP_INSTALLER_URL: &str =
    "https://web.archive.org/web/20220523140209/https://npcap.com/dist/npcap-0.96.exe";

/// Npcap SDK 0.1 sources, tried in order. Every download is verified against
/// `NPCAP_SDK_SHA256`, so whichever source answers first cannot change what we
/// link against; order is purely an availability choice. Upstream still serves
/// this version, and the archive covers the day it stops.
pub const NPCAP_SDK_URLS: &[&str] = &[
    "https://npcap.com/dist/npcap-sdk-0.1.zip",
    "https://web.archive.org/web/20220523140209/https://npcap.com/dist/npcap-sdk-0.1.zip",
];

/// Primary source. Prefer `NPCAP_SDK_URLS` for downloads so the fallback is used.
pub const NPCAP_SDK_URL: &str = NPCAP_SDK_URLS[0];

/// SHA256 of `npcap-sdk-0.1.zip` (827969 bytes), taken from upstream. The
/// integrity pin that makes multi-source fetching safe: a source serving
/// different bytes fails the build with an explicit mismatch instead of
/// silently changing what we link against.
pub const NPCAP_SDK_SHA256: &str =
    "fcc32fcddef57a424c9a9ca59689ba138e0c69718d692a8c67d732c9f48143ec";

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

/// Builds the blocking HTTP client used for Npcap downloads.
///
/// In the compiled flodbadd *library* (marked by the `flodbadd_lib` cfg emitted
/// from build.rs) with `platform_certs` enabled, this routes through the shared
/// workspace TLS helper so the download trusts the platform certificate store
/// (system CAs, incl. enterprise TLS-inspection proxies such as Netskope). In
/// the `build.rs` include context -- where `threatmodels_rs` is intentionally
/// NOT a build-dependency to keep the build script light -- and when the feature
/// is off, it falls back to a plain reqwest blocking client (bundled webpki
/// roots).
#[cfg(all(flodbadd_lib, feature = "platform_certs"))]
fn npcap_blocking_client() -> Result<reqwest::blocking::Client, String> {
    threatmodels_rs::tls::blocking_client_builder()
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))
}

#[cfg(not(all(flodbadd_lib, feature = "platform_certs")))]
fn npcap_blocking_client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))
}

pub fn download_file_with_retry(url: &str) -> Result<reqwest::blocking::Response, String> {
    download_file_with_attempts(url, 10)
}

/// `download_file_with_retry` with an explicit attempt budget.
///
/// The default budget of 10 spends ~13 minutes of exponential backoff before
/// giving up. That is right for a single-source download and wrong when the
/// caller has other sources to try: there, a short budget per source with more
/// passes over the list reaches a healthy source far sooner than draining the
/// full backoff against a dead one.
pub fn download_file_with_attempts(
    url: &str,
    max_attempts: u32,
) -> Result<reqwest::blocking::Response, String> {
    let mut attempts = 0;
    let max_wait_secs = 300; // 5 minutes
                             // Assigned on every loop path before the failure branch reads it.
    let mut last_error: String;
    let client = npcap_blocking_client()?;
    loop {
        match client.get(url).send() {
            Ok(response) => {
                if response.status().is_success() {
                    return Ok(response);
                }
                last_error = format!("HTTP error: {}", response.status());
            }
            Err(e) => {
                last_error = e.to_string();
            }
        }
        attempts += 1;
        if attempts >= max_attempts {
            return Err(format!(
                "Failed to download {} after {} attempts: {}",
                url, max_attempts, last_error
            ));
        }
        // Exponential backoff: 2^attempts seconds, capped at 5 minutes
        let wait_secs = std::cmp::min(2u64.pow(attempts), max_wait_secs);
        std::thread::sleep(std::time::Duration::from_secs(wait_secs));
    }
}

/// Downloads the Npcap SDK zip, trying each entry of `NPCAP_SDK_URLS` in order
/// and verifying the payload against `NPCAP_SDK_SHA256`.
///
/// `NPCAP_SDK_URL` in the environment overrides the source list entirely. That
/// escape hatch exists to point a build at a different SDK build, so the
/// checksum pin cannot apply to it; the zip header is still validated.
pub fn fetch_npcap_sdk_zip() -> Result<Vec<u8>, String> {
    if let Ok(override_url) = env::var("NPCAP_SDK_URL") {
        let url = ensure_wayback_raw(&override_url);
        println!(
            "cargo:warning=[Npcap SDK] NPCAP_SDK_URL override in use ({url}); checksum pin skipped"
        );
        let bytes = download_file_with_retry(&url)
            .and_then(|r| r.bytes().map_err(|e| format!("read failed: {e}")))
            .map_err(|e| format!("Npcap SDK download failed from {url}: {e}"))?;
        verify_zip_header(&bytes)?;
        return Ok(bytes.to_vec());
    }

    let mut errors: Vec<String> = Vec::new();
    // Several short passes over the source list rather than one long backoff per
    // source: a transient 5xx on either source still recovers, while both being
    // genuinely down fails in ~2 minutes instead of ~27.
    const ROUNDS: u32 = 3;
    for round in 1..=ROUNDS {
        for url in NPCAP_SDK_URLS {
            let url = ensure_wayback_raw(url);
            match download_file_with_attempts(&url, 4)
                .and_then(|r| r.bytes().map_err(|e| format!("read failed: {e}")))
            {
                Ok(bytes) => {
                    if let Err(e) = verify_zip_header(&bytes) {
                        errors.push(format!("{url}: {e}"));
                        continue;
                    }
                    let digest = sha256_hex(&bytes);
                    if digest != NPCAP_SDK_SHA256 {
                        errors.push(format!(
                            "{url}: checksum mismatch (expected {NPCAP_SDK_SHA256}, got {digest})"
                        ));
                        continue;
                    }
                    println!(
                        "cargo:warning=[Npcap SDK] Verified {} bytes from {url}",
                        bytes.len()
                    );
                    return Ok(bytes.to_vec());
                }
                Err(e) => errors.push(format!("{url}: {e}")),
            }
        }
        if round < ROUNDS {
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
    }

    errors.sort();
    errors.dedup();
    Err(format!(
        "Npcap SDK unavailable from all {} sources: {}",
        NPCAP_SDK_URLS.len(),
        errors.join("; ")
    ))
}

fn verify_zip_header(bytes: &[u8]) -> Result<(), String> {
    if bytes.starts_with(b"PK\x03\x04") {
        Ok(())
    } else {
        Err(format!(
            "not a zip payload ({} bytes, no PK header)",
            bytes.len()
        ))
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
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
        // Explicitly convert to &str to avoid type ambiguity with Cow<str>::as_ref()
        if current_path.contains(&*npcap_path_str) {
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

    let response = download_file_with_retry(&url).map_err(|e| format!("download failed: {}", e))?;
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
fn locate_npcap_lib_dir(root: &Path, lib_subdir: &str) -> Option<PathBuf> {
    let preferred = root.join("Lib").join(lib_subdir);
    if contains_wpcap_and_packet(&preferred) {
        return Some(preferred);
    }

    let target_lower = lib_subdir.to_ascii_lowercase();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        if dir
            .file_name()
            .and_then(|n| n.to_str())
            .map(|name| name.to_ascii_lowercase() == target_lower)
            .unwrap_or(false)
            && contains_wpcap_and_packet(&dir)
        {
            return Some(dir);
        }

        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                }
            }
        }
    }

    None
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

    if let Some(existing) = locate_npcap_lib_dir(&sdk_root, lib_subdir) {
        return Ok(existing);
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
    let bytes = fetch_npcap_sdk_zip()?;
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

    if let Some(found) = locate_npcap_lib_dir(&sdk_root, lib_subdir) {
        Ok(found)
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
        // Archive-pinned because upstream 404s for this installer version.
        assert!(NPCAP_INSTALLER_URL.contains("web.archive.org"));

        // A single SDK source is what wedged Windows CI: when it answered 503,
        // every Windows build failed at link time with
        // `LNK1181: cannot open input file 'wpcap.lib'`.
        assert!(
            NPCAP_SDK_URLS.len() >= 2,
            "SDK needs a fallback source, got {NPCAP_SDK_URLS:?}"
        );
        assert!(NPCAP_SDK_URLS
            .iter()
            .any(|u| !u.contains("web.archive.org")));
        assert!(NPCAP_SDK_URLS.iter().any(|u| u.contains("web.archive.org")));
        // One checksum covers every source, so they must all serve the same
        // pinned artifact.
        assert!(NPCAP_SDK_URLS
            .iter()
            .all(|u| u.ends_with("npcap-sdk-0.1.zip")));
        assert_eq!(NPCAP_SDK_URL, NPCAP_SDK_URLS[0]);

        assert_eq!(NPCAP_SDK_SHA256.len(), 64);
        assert!(NPCAP_SDK_SHA256
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn test_zip_header_validation() {
        assert!(verify_zip_header(b"PK\x03\x04rest-of-archive").is_ok());
        // The archive-outage failure mode: an error page written out as if it
        // were the SDK.
        assert!(verify_zip_header(b"<html>503 Service Unavailable</html>").is_err());
    }

    #[test]
    fn test_sha256_hex_matches_known_vector() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
