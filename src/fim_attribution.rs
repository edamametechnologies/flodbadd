//! Which paths are worth recording kernel-time write attribution for.
//!
//! The macOS Endpoint Security client and the Windows ETW FileIo session both
//! see every file event on the machine. Both used to record an attribution
//! entry -- writer pid, process name, image path -- for every one of them, into
//! a table whose only consumer is `fim::kernel_table_attribution`, which is
//! ever asked about paths under a FIM watch root. On a build machine that is
//! thousands of wasted entries a minute, each costing two string allocations
//! and a map insert, so that a thirty-second TTL can throw them away unread.
//!
//! This module carries the roots so both sensors can answer "will anyone ever
//! ask about this path?" before doing any work. It is deliberately NOT behind
//! the `fim` feature: the sensors that consult it are gated on
//! `endpointsecurity` / `etw`, which are independent features, and a predicate
//! that disappears under a `#[cfg]` would silently stop confining anything.
//!
//! Linux needs none of this. fanotify is mark-based, so the kernel already
//! filters to the marked roots and `fim_fanotify` only ever sees paths it
//! asked for.
//!
//! Roots are published by the FIM watcher on start, whatever event source it
//! then chooses, so the Endpoint Security source and the FSEvents fallback are
//! both covered. With no roots installed nothing is attributable: FIM is not
//! running, so nothing will look the table up.

use std::path::PathBuf;
use std::sync::RwLock;

use once_cell::sync::Lazy;

/// Lower-cased, forward-slash form used for prefix matching.
pub fn normalize(path: &str) -> String {
    path.replace('\\', "/").to_lowercase()
}

/// Whether `path` (normalized) falls under `root` (normalized) for the given
/// recursion mode.
pub fn path_under_root(path: &str, root: &str, recursive: bool) -> bool {
    let root = root.trim_end_matches('/');
    if root.is_empty() {
        return false;
    }
    let Some(rest) = path.strip_prefix(root) else {
        return false;
    };
    let Some(rest) = rest.strip_prefix('/') else {
        // Exact match is the root itself (a directory), never a file event we
        // want; a longer name sharing the prefix is a sibling.
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    recursive || !rest.contains('/')
}

#[derive(Default)]
struct Roots {
    roots: Vec<String>,
    recursive: bool,
}

static ROOTS: Lazy<RwLock<Roots>> = Lazy::new(|| RwLock::new(Roots::default()));

/// Publish the FIM watch roots. Both the raw and the canonical spelling of
/// each root are kept: Endpoint Security reports `/private/var/...` where
/// callers pass `/var/...`, and an attribution dropped on that mismatch would
/// be a silent loss of the writer pid.
///
/// Replaces any previous set, so a watcher restart re-publishes rather than
/// accumulating.
pub fn set_roots(roots: &[PathBuf], recursive: bool) {
    let mut set = std::collections::BTreeSet::new();
    for root in roots {
        let raw = normalize(&root.to_string_lossy());
        if !raw.is_empty() {
            set.insert(raw);
        }
        if let Ok(canonical) = std::fs::canonicalize(root) {
            let canonical = normalize(&canonical.to_string_lossy());
            if !canonical.is_empty() {
                set.insert(canonical);
            }
        }
    }
    if let Ok(mut guard) = ROOTS.write() {
        guard.roots = set.into_iter().collect();
        guard.recursive = recursive;
    }
}

/// Forget the roots. After this nothing is attributable until a watcher
/// publishes again.
pub fn clear_roots() {
    if let Ok(mut guard) = ROOTS.write() {
        guard.roots.clear();
        guard.recursive = false;
    }
}

/// Number of installed root spellings. For logging and tests.
pub fn root_count() -> usize {
    ROOTS.read().map(|g| g.roots.len()).unwrap_or(0)
}

/// Whether a kernel-time write to `path` is worth recording.
///
/// `false` when no roots are installed. That is the "FIM is not running" case,
/// where the attribution table has no reader at all -- an absent capability,
/// not a permissive verdict: the effect is that less is recorded, never that
/// something unwatched is treated as watched.
pub fn is_attributable(path: &str) -> bool {
    let Ok(guard) = ROOTS.read() else {
        return false;
    };
    if guard.roots.is_empty() {
        return false;
    }
    let normalized = normalize(path);
    guard
        .roots
        .iter()
        .any(|root| path_under_root(&normalized, root, guard.recursive))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One test, not several: the roots are process-wide state and Rust runs
    /// tests in parallel, so separate cases would race each other's `set_roots`
    /// and flake. `path_under_root` is pure and gets its own test below.
    #[test]
    fn roots_confine_recording_and_survive_replacement() {
        clear_roots();
        assert!(!is_attributable("/users/me/.ssh/id_rsa"));
        assert_eq!(root_count(), 0);

        set_roots(&[PathBuf::from("/tmp/fim-attr-test")], true);
        assert!(is_attributable("/tmp/fim-attr-test/dropped.sh"));
        assert!(is_attributable("/tmp/fim-attr-test/nested/deep.sh"));
        assert!(!is_attributable("/tmp/other/dropped.sh"));
        // The root itself is a directory, not a file event worth attributing.
        assert!(!is_attributable("/tmp/fim-attr-test"));
        // Case and separator normalisation.
        assert!(is_attributable("/TMP/FIM-ATTR-TEST/Dropped.sh"));

        // Non-recursive mode admits direct children only.
        set_roots(&[PathBuf::from("/tmp/fim-attr-test")], false);
        assert!(is_attributable("/tmp/fim-attr-test/dropped.sh"));
        assert!(!is_attributable("/tmp/fim-attr-test/nested/deep.sh"));

        // A replacement set drops the previous roots rather than adding to them.
        set_roots(&[PathBuf::from("/tmp/fim-attr-other")], true);
        assert!(!is_attributable("/tmp/fim-attr-test/dropped.sh"));
        assert!(is_attributable("/tmp/fim-attr-other/dropped.sh"));

        clear_roots();
    }

    #[test]
    fn path_under_root_rejects_prefix_siblings() {
        assert!(!path_under_root("/tmp/foobar/x", "/tmp/foo", true));
        assert!(path_under_root("/tmp/foo/x", "/tmp/foo", true));
        assert!(!path_under_root("/tmp/foo", "/tmp/foo", true));
        assert!(!path_under_root("/tmp/foo/x", "", true));
    }
}
