//! Temp-directory path predicate shared by the FIM status flag
//! (`FimEventStore::has_suspicious_events_with`) and the edamame_core
//! attack-pattern detector. Always compiled (no `fim` / OS gate) so every
//! consumer -- including mobile targets that carry no FIM engine -- links
//! the same function (DETECTIONGAPSPLAN-2026-09 Inc 6.8 / B-02; same shape
//! as `dns_patterns`).

/// Platform temp roots every consumer agrees on. The CloudModel adds
/// `fim_temp_executable_patterns`; callers that have the model pass them
/// through [`is_temp_directory_path_with`].
pub fn is_temp_directory_path(path: &str) -> bool {
    is_temp_directory_path_with(path, &[])
}

/// [`is_temp_directory_path`] plus caller-supplied patterns (prefix or
/// substring, case-insensitive, `\\` folded to `/`).
pub fn is_temp_directory_path_with(path: &str, extra_patterns: &[String]) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/tmp/")
        || normalized.starts_with("/private/var/tmp/")
        || macos_per_user_temp(&normalized)
        || normalized.contains("/temp/")
        || normalized.contains("/appdata/local/temp/")
        || extra_patterns.iter().any(|pattern| {
            let pattern = pattern.replace('\\', "/").to_ascii_lowercase();
            !pattern.is_empty()
                && (normalized.starts_with(&pattern) || normalized.contains(pattern.as_str()))
        })
}

/// macOS per-user temp (`/var/folders/<xx>/<hash>/T/`), also under
/// `/private`. `notify` delivers the canonicalized `/private/...` spelling.
fn macos_per_user_temp(normalized: &str) -> bool {
    let rest = normalized
        .strip_prefix("/private/var/folders/")
        .or_else(|| normalized.strip_prefix("/var/folders/"));
    match rest {
        Some(rest) => rest.contains("/t/"),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_temp_roots() {
        assert!(is_temp_directory_path("/tmp/x"));
        assert!(is_temp_directory_path("/private/tmp/x"));
        assert!(is_temp_directory_path("/var/folders/ab/cdef/T/x"));
        assert!(is_temp_directory_path("/private/var/folders/ab/cdef/T/x"));
        assert!(is_temp_directory_path("C:\\Users\\u\\AppData\\Local\\Temp\\x.exe"));
        assert!(!is_temp_directory_path("/Users/u/Documents/x"));
        assert!(!is_temp_directory_path("/var/folders/ab/cdef/C/x"));
    }

    #[test]
    fn cloudmodel_patterns_extend_the_roots() {
        let extra = vec!["/opt/scratch/".to_string()];
        assert!(is_temp_directory_path_with("/opt/scratch/payload", &extra));
        assert!(!is_temp_directory_path("/opt/scratch/payload"));
    }
}
