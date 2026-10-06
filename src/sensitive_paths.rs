use crate::sensitive_paths_db::*;
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use threatmodels_rs::*;
use tracing::{info, warn};

const SENSITIVE_PATHS_NAME: &str = "sensitive-paths-db.json";

/// Per-platform watch-root configuration shipped via the CloudModel so the
/// FIM watcher does not hardcode the directory list in Rust. Every entry is a
/// HOME-relative POSIX path (no leading `/`, no backslashes); the runtime
/// resolves it against the calling user's home.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct WatchRootsJSON {
    pub common_home_relative: Vec<String>,
    pub linux_home_relative: Vec<String>,
    pub macos_home_relative: Vec<String>,
    pub windows_home_relative: Vec<String>,
}

/// Directories the FIM watcher must never watch recursively, whatever asked
/// for them: a filesystem root or a top-level system tree. Watching one
/// means walking (and watching) the whole tree beneath it -- on Linux
/// through `/proc` and `/sys`, which never finishes and grows the daemon
/// without bound. `unix` applies on macOS, Linux and the mobile targets,
/// `windows` on Windows; compared case-insensitively with `\` folded to `/`
/// and trailing separators ignored. The filesystem root itself is always
/// refused, listed or not.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct FimForbiddenWatchRootsJSON {
    pub unix: Vec<String>,
    pub windows: Vec<String>,
}

/// One lowercase catalog label prefix and its case-preserved home-relative
/// location (`credential_opens.label_home_roots`): macOS
/// `/application support/` lives at `~/Library/Application Support/`.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct LabelHomeRootJSON {
    pub label_prefix: String,
    pub home_prefix: String,
}

/// `credential_opens.label_home_roots`, per platform.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct LabelHomeRootsJSON {
    pub macos: Vec<LabelHomeRootJSON>,
    pub linux: Vec<LabelHomeRootJSON>,
    pub windows: Vec<LabelHomeRootJSON>,
}

/// The cold credential set of the kernel open-notification clients
/// (`crate::credential_opens`, BS-10): the catalog labels whose files are
/// opened rarely enough to take one notification each, the sub-paths inside
/// them that are hot (left to the open-file poll), how long a closed open
/// stays attached to its process, where the labels' prefixes live under a
/// home, and the user-profile segment the ETW backend prefilters on.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CredentialOpensJSON {
    pub cold_labels: Vec<String>,
    pub hot_subpaths: Vec<String>,
    pub open_ttl_secs: u64,
    pub label_home_roots: LabelHomeRootsJSON,
    pub windows_profile_marker: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SensitivePathsJSON {
    pub date: String,
    pub signature: String,
    pub common_patterns: Vec<String>,
    pub platform_patterns: HashMap<String, Vec<String>>,
    pub labels: HashMap<String, Vec<String>>,
    pub watch_roots: WatchRootsJSON,
    pub fim_excluded_path_patterns: Vec<String>,
    pub fim_forbidden_watch_roots: FimForbiddenWatchRootsJSON,
    pub credential_opens: CredentialOpensJSON,
}

#[derive(Clone)]
pub struct SensitivePathsDB {
    pub date: String,
    pub signature: String,
    pub common_patterns: Vec<String>,
    pub platform_patterns: HashMap<String, Vec<String>>,
    pub labels: HashMap<String, Vec<String>>,
    pub watch_roots: WatchRootsJSON,
    pub fim_excluded_path_patterns: Vec<String>,
    pub fim_forbidden_watch_roots: FimForbiddenWatchRootsJSON,
    pub credential_opens: CredentialOpensJSON,
}

impl CloudSignature for SensitivePathsDB {
    fn get_signature(&self) -> String {
        self.signature.clone()
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

/// Whether a normalized path matches one catalog pattern.
///
/// A pattern is a substring of the path, except that a trailing `$` anchors
/// it at the END of the path: `/cookies$` is a file named exactly `Cookies`
/// (Chromium's cookie store at a profile or Electron app root), not every
/// path that merely contains `/cookies` (pip's vendored
/// `requests/cookies.py`, `undici-types/cookies.d.ts`). The caller normalizes
/// the haystack (separators always, case where the table is lowercase).
///
/// A client older than the anchor never matches a `$` pattern, so an anchored
/// entry ships next to the plain substring that keeps older clients covered
/// where one exists (`/network/cookies`).
pub fn catalog_pattern_matches(haystack: &str, pattern: &str) -> bool {
    match pattern.strip_suffix('$') {
        Some(anchored) if !anchored.is_empty() => haystack.ends_with(anchored),
        _ => haystack.contains(pattern),
    }
}

impl SensitivePathsDB {
    pub fn new_from_json(json: &SensitivePathsJSON) -> Self {
        info!(
            "Loading sensitive paths DB: {} common, {} platform sets, {} label groups, {} fim exclusions",
            json.common_patterns.len(),
            json.platform_patterns.len(),
            json.labels.len(),
            json.fim_excluded_path_patterns.len(),
        );

        SensitivePathsDB {
            date: json.date.clone(),
            signature: json.signature.clone(),
            common_patterns: json.common_patterns.clone(),
            platform_patterns: json.platform_patterns.clone(),
            labels: json.labels.clone(),
            watch_roots: json.watch_roots.clone(),
            fim_excluded_path_patterns: json.fim_excluded_path_patterns.clone(),
            fim_forbidden_watch_roots: json.fim_forbidden_watch_roots.clone(),
            credential_opens: json.credential_opens.clone(),
        }
    }

    pub fn get_patterns_for_platform(&self) -> Vec<&str> {
        let platform_key = if cfg!(target_os = "macos") {
            "macos"
        } else if cfg!(target_os = "linux") {
            "linux"
        } else if cfg!(target_os = "windows") {
            "windows"
        } else {
            ""
        };

        let mut patterns: Vec<&str> = self.common_patterns.iter().map(|s| s.as_str()).collect();
        if let Some(platform) = self.platform_patterns.get(platform_key) {
            patterns.extend(platform.iter().map(|s| s.as_str()));
        }
        patterns
    }

    /// HOME-relative directory list for the current platform: the common
    /// credential-store dirs (`.ssh`, `.gnupg`, `.aws`, ...) plus whatever
    /// the platform-specific bucket adds (e.g. `Library/Keychains` on macOS,
    /// `AppData/Roaming` + `AppData/Local` on Windows). Used by the FIM
    /// watcher to bootstrap recursive watches without hardcoding paths.
    pub fn watch_roots_for_platform(&self) -> Vec<&str> {
        let mut out: Vec<&str> = self
            .watch_roots
            .common_home_relative
            .iter()
            .map(|s| s.as_str())
            .collect();

        let platform_specific: &[String] = if cfg!(target_os = "macos") {
            &self.watch_roots.macos_home_relative
        } else if cfg!(target_os = "linux") {
            &self.watch_roots.linux_home_relative
        } else if cfg!(target_os = "windows") {
            &self.watch_roots.windows_home_relative
        } else {
            &[]
        };
        out.extend(platform_specific.iter().map(|s| s.as_str()));
        out
    }

    pub fn classify_labels(&self, paths: &[String]) -> Vec<String> {
        let mut result = std::collections::BTreeSet::new();
        for path in paths {
            let normalized = path.trim().to_ascii_lowercase().replace('\\', "/");
            if normalized.is_empty() {
                continue;
            }
            for (label, patterns) in &self.labels {
                if patterns
                    .iter()
                    .any(|pat| catalog_pattern_matches(&normalized, pat))
                {
                    result.insert(label.clone());
                }
            }
        }
        result.into_iter().collect()
    }
}

lazy_static! {
    pub static ref SENSITIVE_PATHS: CloudModel<SensitivePathsDB> = {
        let model = CloudModel::initialize(
            SENSITIVE_PATHS_NAME.to_string(),
            &SENSITIVE_PATHS_DB,
            |data| {
                let json: SensitivePathsJSON = serde_json::from_str(data)
                    .with_context(|| "Failed to parse sensitive paths JSON")?;
                Ok(SensitivePathsDB::new_from_json(&json))
            },
        );
        match model {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "FATAL: Failed to initialize CloudModel for sensitive paths: {:?}",
                    e
                );
                panic!(
                    "Failed to initialize CloudModel for sensitive paths: {:?}",
                    e
                );
            }
        }
    };
}

fn build_fallback_labels() -> HashMap<String, Vec<String>> {
    match serde_json::from_str::<SensitivePathsJSON>(&SENSITIVE_PATHS_DB) {
        Ok(json) => json.labels,
        Err(_) => HashMap::new(),
    }
}

fn build_fallback_watch_roots() -> WatchRootsJSON {
    serde_json::from_str::<SensitivePathsJSON>(&SENSITIVE_PATHS_DB)
        .map(|json| json.watch_roots)
        .unwrap_or_default()
}

fn build_fallback_fim_forbidden_watch_roots() -> FimForbiddenWatchRootsJSON {
    serde_json::from_str::<SensitivePathsJSON>(&SENSITIVE_PATHS_DB)
        .map(|json| json.fim_forbidden_watch_roots)
        .unwrap_or_default()
}

fn build_fallback_credential_opens() -> CredentialOpensJSON {
    serde_json::from_str::<SensitivePathsJSON>(&SENSITIVE_PATHS_DB)
        .map(|json| json.credential_opens)
        .unwrap_or_default()
}

fn build_fallback_fim_excluded_patterns() -> Vec<String> {
    serde_json::from_str::<SensitivePathsJSON>(&SENSITIVE_PATHS_DB)
        .map(|json| {
            json.fim_excluded_path_patterns
                .into_iter()
                .map(|p| p.to_lowercase())
                .collect()
        })
        .unwrap_or_default()
}

lazy_static! {
    static ref LABELS_SNAPSHOT: ArcSwap<HashMap<String, Vec<String>>> =
        ArcSwap::from_pointee(build_fallback_labels());
    static ref WATCH_ROOTS_SNAPSHOT: ArcSwap<WatchRootsJSON> =
        ArcSwap::from_pointee(build_fallback_watch_roots());
    static ref FIM_EXCLUDED_PATTERNS_SNAPSHOT: ArcSwap<Vec<String>> =
        ArcSwap::from_pointee(build_fallback_fim_excluded_patterns());
    static ref FIM_FORBIDDEN_WATCH_ROOTS_SNAPSHOT: ArcSwap<FimForbiddenWatchRootsJSON> =
        ArcSwap::from_pointee(build_fallback_fim_forbidden_watch_roots());
    static ref CREDENTIAL_OPENS_SNAPSHOT: ArcSwap<CredentialOpensJSON> =
        ArcSwap::from_pointee(build_fallback_credential_opens());
}

pub async fn refresh_labels_snapshot() {
    let db = SENSITIVE_PATHS.data.read().await;
    LABELS_SNAPSHOT.store(Arc::new(db.labels.clone()));
    WATCH_ROOTS_SNAPSHOT.store(Arc::new(db.watch_roots.clone()));
    let exclusions: Vec<String> = db
        .fim_excluded_path_patterns
        .iter()
        .map(|p| p.to_lowercase())
        .collect();
    FIM_EXCLUDED_PATTERNS_SNAPSHOT.store(Arc::new(exclusions));
    FIM_FORBIDDEN_WATCH_ROOTS_SNAPSHOT.store(Arc::new(db.fim_forbidden_watch_roots.clone()));
    CREDENTIAL_OPENS_SNAPSHOT.store(Arc::new(db.credential_opens.clone()));
}

/// Synchronous label classifier backed by the cloud model snapshot.
/// Falls back to the ArcSwap snapshot of labels loaded at init / last update.
pub fn classify_sensitive_path_labels_sync(paths: &[String]) -> Vec<String> {
    let labels = LABELS_SNAPSHOT.load();
    let mut result = std::collections::BTreeSet::new();
    for path in paths {
        let normalized = path.trim().to_ascii_lowercase().replace('\\', "/");
        if normalized.is_empty() {
            continue;
        }
        for (label, patterns) in labels.as_ref() {
            if patterns
                .iter()
                .any(|pat| catalog_pattern_matches(&normalized, pat))
            {
                result.insert(label.clone());
            }
        }
    }
    result.into_iter().collect()
}

/// Lowercase label patterns for the given labels, from the same snapshot
/// `classify_sensitive_path_labels_sync` reads.
pub fn label_patterns_sync(labels: &[&str]) -> Vec<String> {
    let snapshot = LABELS_SNAPSHOT.load();
    let mut out: Vec<String> = labels
        .iter()
        .filter_map(|label| snapshot.get(*label))
        .flatten()
        .cloned()
        .collect();
    out.sort();
    out.dedup();
    out
}

pub async fn update(branch: &str, force: bool) -> Result<UpdateStatus> {
    info!("Starting sensitive paths update from backend");

    let status = SENSITIVE_PATHS
        .update(branch, force, |data| {
            let json: SensitivePathsJSON = serde_json::from_str(data)?;
            Ok(SensitivePathsDB::new_from_json(&json))
        })
        .await?;

    match status {
        UpdateStatus::Updated => info!("Sensitive paths were successfully updated."),
        UpdateStatus::NotUpdated => info!("Sensitive paths are already up to date."),
        UpdateStatus::FormatError => warn!("There was a format error in the sensitive paths data."),
        UpdateStatus::SkippedCustom => {
            info!("Update skipped because custom sensitive paths are in use.")
        }
    }

    // Refresh for every status, not just Updated. `SENSITIVE_PATHS.data` always holds
    // at least the embedded snapshot, whereas the sync snapshots are seeded from the
    // much smaller hardcoded `FALLBACK_*` consts. Refreshing only on Updated left a
    // healthy install (embedded signature == remote, so NotUpdated) permanently
    // serving those consts, silently dropping every pattern that exists only in the
    // model.
    crate::open_files::refresh_patterns_snapshot().await;
    refresh_labels_snapshot().await;

    Ok(status)
}

pub async fn is_sensitive_path_from_model(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let db = SENSITIVE_PATHS.data.read().await;
    for pat in db.get_patterns_for_platform() {
        if catalog_pattern_matches(&normalized, pat) {
            return true;
        }
    }
    false
}

pub async fn get_patterns() -> Vec<String> {
    let db = SENSITIVE_PATHS.data.read().await;
    db.get_patterns_for_platform()
        .iter()
        .map(|s| s.to_string())
        .collect()
}

pub async fn classify_sensitive_path_labels(paths: &[String]) -> Vec<String> {
    let db = SENSITIVE_PATHS.data.read().await;
    db.classify_labels(paths)
}

/// HOME-relative sensitive watch directories for the current platform,
/// resolved against `home`. Backed by the lock-free `WATCH_ROOTS_SNAPSHOT`
/// so this is callable from sync code (FIM startup, tests). Replaces the
/// previously-hardcoded list embedded in `flodbadd::fim`; the source of
/// truth is `sensitive-paths-db.json::watch_roots` shipped via CloudModel
/// with the embedded fallback as last-resort default.
pub fn default_sensitive_watch_paths_for_home(home: &Path) -> Vec<PathBuf> {
    let snap = WATCH_ROOTS_SNAPSHOT.load();
    let platform_specific: &[String] = if cfg!(target_os = "macos") {
        &snap.macos_home_relative
    } else if cfg!(target_os = "linux") {
        &snap.linux_home_relative
    } else if cfg!(target_os = "windows") {
        &snap.windows_home_relative
    } else {
        &[]
    };

    let mut paths = Vec::new();
    for entry in snap
        .common_home_relative
        .iter()
        .chain(platform_specific.iter())
    {
        let p = home.join(entry);
        if p.exists() && !paths.contains(&p) {
            paths.push(p);
        }
    }
    paths
}

/// Returns true if `path` matches one of the FIM exclusion substrings
/// shipped via `sensitive-paths-db.json::fim_excluded_path_patterns`. These
/// are build-tool churn paths (cargo target, gradle caches, node_modules,
/// browser content caches, ...) that we never want to hash, attribute, or
/// store as FIM events because they generate enormous CPU load on dev
/// machines without producing security-relevant signal.
pub fn is_fim_excluded_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_lowercase();
    let patterns = FIM_EXCLUDED_PATTERNS_SNAPSHOT.load();
    patterns.iter().any(|pat| normalized.contains(pat.as_str()))
}

/// Returns a copy of the current FIM exclusion pattern list (already
/// lowercased) for diagnostics / tests.
pub fn fim_excluded_path_patterns() -> Vec<String> {
    FIM_EXCLUDED_PATTERNS_SNAPSHOT.load().as_ref().clone()
}

/// The FIM forbidden watch roots of the current platform
/// (`sensitive-paths-db.json::fim_forbidden_watch_roots`): `windows` on
/// Windows, `unix` everywhere else.
pub fn fim_forbidden_watch_roots() -> Vec<String> {
    let snap = FIM_FORBIDDEN_WATCH_ROOTS_SNAPSHOT.load();
    if cfg!(target_os = "windows") {
        snap.windows.clone()
    } else {
        snap.unix.clone()
    }
}

/// The cold credential set (`sensitive-paths-db.json::credential_opens`),
/// lock-free; refreshed with the labels.
pub fn credential_opens_params() -> Arc<CredentialOpensJSON> {
    CREDENTIAL_OPENS_SNAPSHOT.load_full()
}

/// `credential_opens.label_home_roots` of the current platform.
pub fn credential_opens_label_home_roots() -> Vec<LabelHomeRootJSON> {
    let params = CREDENTIAL_OPENS_SNAPSHOT.load();
    let roots = &params.label_home_roots;
    if cfg!(target_os = "macos") {
        roots.macos.clone()
    } else if cfg!(target_os = "linux") {
        roots.linux.clone()
    } else if cfg!(target_os = "windows") {
        roots.windows.clone()
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Regression guard (helper/app/posture startup): the embedded sensitive-
    /// paths snapshot MUST decode and parse. If a bad regen makes it
    /// unparseable, the `SENSITIVE_PATHS` CloudModel `lazy_static` panics on its
    /// first deref and the daemon dies at startup. This catches it in CI
    /// instead. See also whitelists/blacklists/threats/cve_params.
    #[test]
    fn test_embedded_sensitive_paths_snapshot_parses() {
        serde_json::from_str::<SensitivePathsJSON>(&SENSITIVE_PATHS_DB)
            .expect("embedded sensitive paths snapshot must parse as SensitivePathsJSON");
    }

    #[tokio::test]
    #[serial]
    async fn test_sensitive_paths_loaded() {
        let db = SENSITIVE_PATHS.data.read().await;
        assert!(
            !db.common_patterns.is_empty(),
            "Common patterns should not be empty"
        );
        assert!(!db.labels.is_empty(), "Labels should not be empty");
    }

    #[tokio::test]
    #[serial]
    async fn test_is_sensitive_path() {
        assert!(is_sensitive_path_from_model("/home/user/.ssh/id_rsa").await);
        assert!(is_sensitive_path_from_model("/home/user/.aws/credentials").await);
        assert!(!is_sensitive_path_from_model("/tmp/some_file.txt").await);
    }

    #[tokio::test]
    #[serial]
    async fn test_classify_labels() {
        let paths = vec![
            "/home/user/.ssh/id_rsa".to_string(),
            "/home/user/.aws/credentials".to_string(),
        ];
        let labels = classify_sensitive_path_labels(&paths).await;
        assert!(labels.contains(&"ssh".to_string()));
        assert!(labels.contains(&"aws".to_string()));
    }

    #[tokio::test]
    #[serial]
    async fn test_update_sensitive_paths() {
        let status = update("main", false).await.expect("Update failed");
        // A FormatError means the published `sensitive-paths-db.json` does not
        // parse with this code: every client keeps its embedded fallback and
        // silently ignores the published catalog. That is a failure, not a
        // transient state -- the release order publishes threatmodels first,
        // so the published JSON carries every field the code on main reads.
        assert!(
            matches!(status, UpdateStatus::Updated | UpdateStatus::NotUpdated),
            "Unexpected update status: {:?}",
            status
        );
    }

    /// Regression guard: after an `update()` attempt the sync snapshot MUST serve
    /// the model's patterns, not the smaller hardcoded `FALLBACK_*` consts.
    ///
    /// `refresh_patterns_snapshot()` used to run only on `UpdateStatus::Updated`.
    /// A healthy install whose embedded signature already matches remote returns
    /// `NotUpdated`, so the refresh never fired and `is_sensitive_path()` kept
    /// serving the consts for the whole process lifetime -- silently dropping
    /// every pattern that exists only in the model (at the time of the fix, 23 of
    /// 63, including the dir-form `/.aws/` and the browser-extension wallet
    /// paths). Asserting the invariant rather than a specific pattern string
    /// keeps this test valid if a pattern is later promoted into the consts.
    #[tokio::test]
    #[serial]
    async fn test_sync_snapshot_covers_every_model_pattern() {
        let _ = update("main", false).await.expect("update failed");

        let model_patterns: Vec<String> = {
            let db = SENSITIVE_PATHS.data.read().await;
            db.get_patterns_for_platform()
                .into_iter()
                .map(str::to_string)
                .collect()
        };
        assert!(
            !model_patterns.is_empty(),
            "model must expose patterns for this platform"
        );

        let missing: Vec<&String> = model_patterns
            .iter()
            .filter(|pat| {
                let probe = pat.strip_suffix('$').unwrap_or(pat);
                !crate::open_files::is_sensitive_path(&format!("/home/user{probe}"))
            })
            .collect();
        assert!(
            missing.is_empty(),
            "sync snapshot is missing {} model pattern(s): {:?}",
            missing.len(),
            missing,
        );
    }

    /// Cross-platform well-formedness guard for patterns this host cannot exercise.
    ///
    /// `is_sensitive_path` normalizes the *haystack* with `replace('\\', "/")` but
    /// preserves its case, so a pattern carrying a literal backslash can never match
    /// on any platform, and a Windows pattern must use real on-disk casing. Only the
    /// running platform's table is covered by
    /// `test_sync_snapshot_covers_every_model_pattern`, so a typo in the `windows`
    /// table would otherwise ship undetected from a macOS or Linux dev box.
    #[tokio::test]
    #[serial]
    async fn test_every_platform_pattern_is_well_formed() {
        let db = SENSITIVE_PATHS.data.read().await;

        // Assert presence explicitly: the loop below iterates whatever keys exist, so a
        // dropped `windows` table would otherwise skip silently on a macOS dev box.
        for platform in ["macos", "linux", "windows"] {
            assert!(
                db.platform_patterns.contains_key(platform),
                "platform_patterns is missing the {platform:?} table; got {:?}",
                db.platform_patterns.keys().collect::<Vec<_>>(),
            );
        }

        let mut tables: Vec<(&str, &Vec<String>)> = vec![("common", &db.common_patterns)];
        tables.extend(db.platform_patterns.iter().map(|(k, v)| (k.as_str(), v)));

        for (table, patterns) in tables {
            assert!(!patterns.is_empty(), "{table} pattern table is empty");
            for pat in patterns {
                assert!(
                    !pat.contains('\\'),
                    "{table} pattern {pat:?} contains a backslash; the haystack is \
                     normalized to forward slashes so this can never match",
                );
                assert_eq!(
                    pat.trim(),
                    pat.as_str(),
                    "{table} pattern {pat:?} has leading/trailing whitespace",
                );
                assert!(
                    pat.starts_with('/'),
                    "{table} pattern {pat:?} must start with '/' to anchor at a path \
                     component boundary",
                );
            }
        }
    }

    /// A catalog pattern with no matching label is detected by FIM but counts for
    /// nothing in `credential_harvest`, which thresholds on the number of
    /// *distinct labels*. That gap is invisible from the pattern list alone,
    /// which is how `~/.npmrc` and the Windows/Linux OS credential stores ended
    /// up flagged-but-uncounted while the macOS keychain counted.
    ///
    /// Directory-prefix patterns are exempt when a label matches files *inside*
    /// them (e.g. `browser_store` matches `/network/cookies`, which fires on
    /// `.../User Data/Default/Network/Cookies`), so the check is on the label
    /// substrings, not on the pattern strings being equal.
    #[tokio::test]
    async fn test_catalog_patterns_carry_a_label_or_are_documented() {
        // Patterns that intentionally carry no label. Each entry needs a reason:
        // either a label matches files beneath it, or labeling it would regress a
        // known false-positive case.
        const LABELLESS_BY_DESIGN: &[&str] = &[
            // browser_store matches the credential files inside these dirs
            // (Cookies, /login data, /web data, /key4.db, /logins.json).
            // Windows-only today; the macOS/Linux profile roots are absent from
            // the catalog, so browser credential stores are classified as
            // sensitive on Windows only. Tracked as a residual BS-12 gap rather
            // than widened here, since adding the profile roots makes every
            // browser's own cookie/login-data access sensitive-flagged and needs
            // a dogfood FP pass first.
            "/AppData/Local/Google/Chrome/User Data/",
            "/AppData/Roaming/Mozilla/Firefox/Profiles/",
            // Ubiquitous in ordinary developer and CI workflows (git over
            // HTTPS, psql, curl). Labeling them would push routine tooling over
            // credential_harvest's distinct-label threshold. Tracked as a
            // deliberate gap rather than an oversight.
            "/.netrc",
            "/.pgpass",
            // Generic container/orchestrator secret mount. The Kubernetes
            // service-account subtree is labeled `kube`; the bare mount point
            // is too generic to attribute to a credential category.
            "/run/secrets/",
        ];

        let db = SENSITIVE_PATHS.data.read().await;

        // Every label pattern, lowercased once (classify_labels lowercases the
        // haystack before matching).
        let label_patterns: Vec<String> = db
            .labels
            .values()
            .flatten()
            .map(|p| p.to_ascii_lowercase())
            .collect();
        assert!(!label_patterns.is_empty(), "catalog publishes no labels");

        let mut tables: Vec<(&str, &Vec<String>)> = vec![("common", &db.common_patterns)];
        tables.extend(db.platform_patterns.iter().map(|(k, v)| (k.as_str(), v)));

        let mut unlabeled: Vec<String> = Vec::new();
        for (table, patterns) in tables {
            for pat in patterns {
                if LABELLESS_BY_DESIGN.contains(&pat.as_str()) {
                    continue;
                }
                let lowered = pat.to_ascii_lowercase();
                // A label covers the pattern if the label pattern appears in it
                // (label is a file/leaf under a directory pattern) or if the
                // pattern appears in the label pattern (label is more specific).
                let covered = label_patterns
                    .iter()
                    .any(|lp| lowered.contains(lp.as_str()) || lp.contains(lowered.as_str()));
                if !covered {
                    unlabeled.push(format!("{table}:{pat}"));
                }
            }
        }
        unlabeled.sort();
        assert!(
            unlabeled.is_empty(),
            "sensitive-path patterns carry no label, so they contribute nothing \
             to credential_harvest's distinct-label threshold: {unlabeled:?}. \
             Add a label in sensitive-paths-db.json, or add the pattern to \
             LABELLESS_BY_DESIGN with a reason."
        );

        // Guard the exemption list itself against drift: an entry that no longer
        // exists in the catalog is stale and hides the next real gap.
        let all_patterns: Vec<&String> = db
            .common_patterns
            .iter()
            .chain(db.platform_patterns.values().flatten())
            .collect();
        let mut stale: Vec<&str> = LABELLESS_BY_DESIGN
            .iter()
            .copied()
            .filter(|e| !all_patterns.iter().any(|p| p.as_str() == *e))
            .collect();
        stale.sort();
        assert!(
            stale.is_empty(),
            "LABELLESS_BY_DESIGN entries are no longer in the catalog: {stale:?}"
        );
    }

    /// `classify_labels` lowercases the haystack (`to_ascii_lowercase()`), so any label
    /// pattern containing an uppercase character is dead -- it can never match. This is
    /// the exact failure shape for Windows label entries, whose real on-disk paths are
    /// mixed-case (`/AppData/Roaming/...`) and so tempt a copy-paste from the
    /// case-sensitive `platform_patterns` table.
    #[tokio::test]
    #[serial]
    async fn test_every_label_pattern_is_lowercase_and_forward_slashed() {
        let db = SENSITIVE_PATHS.data.read().await;
        assert!(!db.labels.is_empty(), "label table is empty");

        for (label, patterns) in &db.labels {
            assert!(!patterns.is_empty(), "label {label:?} has no patterns");
            for pat in patterns {
                assert_eq!(
                    pat.to_ascii_lowercase(),
                    pat.as_str(),
                    "label {label:?} pattern {pat:?} is not lowercase; classify_labels \
                     lowercases the haystack so this can never match",
                );
                assert!(
                    !pat.contains('\\'),
                    "label {label:?} pattern {pat:?} contains a backslash; the haystack \
                     is normalized to forward slashes so this can never match",
                );
            }
        }
    }

    #[test]
    fn test_catalog_pattern_anchor() {
        assert!(catalog_pattern_matches("/a/b/cookies", "/cookies$"));
        assert!(!catalog_pattern_matches("/a/b/cookies.py", "/cookies$"));
        assert!(!catalog_pattern_matches("/a/cookies/x", "/cookies$"));
        assert!(catalog_pattern_matches("/a/cookies.py", "/cookies"));
        // A lone `$` is not an anchor.
        assert!(catalog_pattern_matches("/a/$", "$"));
    }

    /// Browser cookie stores are the files browsers name so: Chromium and
    /// Electron `Cookies` (profile root, or `Network/` since Chromium 96),
    /// Firefox `cookies.sqlite`, Safari `Cookies.binarycookies`. A source file
    /// NAMED after cookies (pip's vendored `requests/cookies.py`, its `.pyc`,
    /// `undici-types/cookies.d.ts`) is not one.
    #[tokio::test]
    #[serial]
    async fn test_browser_cookie_stores_are_labeled_and_cookie_sources_are_not() {
        let stores = [
            "/Users/u/Library/Application Support/Google/Chrome/Default/Cookies",
            "/Users/u/Library/Application Support/Google/Chrome/Profile 1/Network/Cookies",
            "/Users/u/Library/Application Support/Google/Chrome/Default/Network/Cookies-journal",
            "C:\\Users\\u\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies",
            "/home/u/.config/Slack/Cookies",
            "/home/u/.mozilla/firefox/abcd.default-release/cookies.sqlite",
            "/Users/u/Library/Application Support/Firefox/Profiles/x.default/cookies.sqlite-wal",
            "/Users/u/Library/Cookies/Cookies.binarycookies",
            "/Users/u/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies",
        ];
        for path in stores {
            let labels = classify_sensitive_path_labels(&[path.to_string()]).await;
            assert!(
                labels.contains(&"browser_store".to_string()),
                "{path} must carry browser_store, got {labels:?}"
            );
            assert!(
                classify_sensitive_path_labels_sync(&[path.to_string()])
                    .contains(&"browser_store".to_string()),
                "{path}: sync classifier disagrees"
            );
        }
        let sources = [
            "/private/var/tmp/x/.venv/lib/python3.14/site-packages/pip/_vendor/requests/cookies.py",
            "/tmp/x/.venv/lib/python3.14/site-packages/pip/_vendor/requests/__pycache__/cookies.cpython-314.pyc",
            "/tmp/b/node_modules/undici-types/cookies.d.ts",
            "/home/u/src/app/cookies/handler.go",
        ];
        for path in sources {
            let labels = classify_sensitive_path_labels(&[path.to_string()]).await;
            assert!(
                !labels.contains(&"browser_store".to_string()),
                "{path} must not carry browser_store, got {labels:?}"
            );
            assert!(
                !is_sensitive_path_from_model(path).await,
                "{path} must not be a sensitive path"
            );
            assert!(
                !crate::open_files::is_sensitive_path(path),
                "{path}: sync sensitive-path check disagrees"
            );
        }
    }

    #[test]
    fn test_watch_roots_snapshot_includes_common_dirs() {
        let snap = WATCH_ROOTS_SNAPSHOT.load();
        assert!(
            snap.common_home_relative.iter().any(|d| d == ".ssh"),
            "common_home_relative must include .ssh; got {:?}",
            snap.common_home_relative,
        );
        assert!(
            snap.common_home_relative.iter().any(|d| d == ".aws"),
            "common_home_relative must include .aws; got {:?}",
            snap.common_home_relative,
        );
    }

    #[test]
    fn test_default_sensitive_watch_paths_for_home_resolves_existing_dirs() {
        let temp = tempfile::tempdir().expect("create temp dir");
        std::fs::create_dir_all(temp.path().join(".ssh")).expect("mkdir .ssh");
        std::fs::create_dir_all(temp.path().join(".aws")).expect("mkdir .aws");

        let resolved = default_sensitive_watch_paths_for_home(temp.path());

        assert!(
            resolved.iter().any(|p| p.ends_with(".ssh")),
            ".ssh should be picked up; got {:?}",
            resolved
        );
        assert!(
            resolved.iter().any(|p| p.ends_with(".aws")),
            ".aws should be picked up; got {:?}",
            resolved
        );

        // Non-existent dirs from the snapshot must NOT show up.
        let missing = temp.path().join(".gnupg");
        assert!(!resolved.contains(&missing));
    }

    #[test]
    fn test_default_sensitive_watch_paths_no_hardcoded_paths_in_rust() {
        // Snapshot contents drive everything; if the JSON loses .ssh, the
        // helper drops it. This is the property "no hardcoded Rust list".
        let snap = WATCH_ROOTS_SNAPSHOT.load();
        let common: std::collections::HashSet<&str> = snap
            .common_home_relative
            .iter()
            .map(|s| s.as_str())
            .collect();
        // Sanity: the embedded fallback is a non-empty set including common
        // credential directories. If this trips, somebody emptied the JSON.
        assert!(!common.is_empty(), "common_home_relative must not be empty");
    }

    #[test]
    fn test_is_fim_excluded_path_matches_build_artifacts() {
        assert!(is_fim_excluded_path(
            "/Users/me/repo/target/debug/build/foo-1234/out"
        ));
        assert!(is_fim_excluded_path(
            "/Users/me/repo/target/release/deps/libfoo.rlib"
        ));
        assert!(is_fim_excluded_path(
            "/home/me/proj/node_modules/lib/index.js"
        ));
        assert!(is_fim_excluded_path(
            "C:\\Users\\me\\proj\\target\\release\\deps\\foo.exe"
        ));
        assert!(is_fim_excluded_path(
            "/Users/me/proj/build/windows/x64/runner/Debug/edamame_app.exe"
        ));
        assert!(is_fim_excluded_path(
            "/Users/me/Library/Caches/com.google.Chrome/Code Cache/js/index"
        ));
    }

    #[test]
    fn test_is_fim_excluded_path_does_not_match_credential_paths() {
        assert!(!is_fim_excluded_path("/home/user/.ssh/id_rsa"));
        assert!(!is_fim_excluded_path("/home/user/.aws/credentials"));
        assert!(!is_fim_excluded_path(
            "/Users/user/Library/Application Support/edamame/agentic_config.json"
        ));
        assert!(!is_fim_excluded_path("/etc/shadow"));
        assert!(!is_fim_excluded_path(
            "C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Credentials\\foo"
        ));
    }
}
