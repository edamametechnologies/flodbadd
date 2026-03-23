use crate::sensitive_paths_db::*;
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use threatmodels_rs::*;
use tracing::{info, warn};

const SENSITIVE_PATHS_NAME: &str = "sensitive-paths-db.json";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SensitivePathsJSON {
    pub date: String,
    pub signature: String,
    pub common_patterns: Vec<String>,
    pub platform_patterns: HashMap<String, Vec<String>>,
    pub labels: HashMap<String, Vec<String>>,
}

#[derive(Clone)]
pub struct SensitivePathsDB {
    pub date: String,
    pub signature: String,
    pub common_patterns: Vec<String>,
    pub platform_patterns: HashMap<String, Vec<String>>,
    pub labels: HashMap<String, Vec<String>>,
}

impl CloudSignature for SensitivePathsDB {
    fn get_signature(&self) -> String {
        self.signature.clone()
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

impl SensitivePathsDB {
    pub fn new_from_json(json: &SensitivePathsJSON) -> Self {
        info!(
            "Loading sensitive paths DB: {} common, {} platform sets, {} label groups",
            json.common_patterns.len(),
            json.platform_patterns.len(),
            json.labels.len()
        );

        SensitivePathsDB {
            date: json.date.clone(),
            signature: json.signature.clone(),
            common_patterns: json.common_patterns.clone(),
            platform_patterns: json.platform_patterns.clone(),
            labels: json.labels.clone(),
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

    pub fn classify_labels(&self, paths: &[String]) -> Vec<String> {
        let mut result = std::collections::BTreeSet::new();
        for path in paths {
            let normalized = path.trim().to_ascii_lowercase().replace('\\', "/");
            if normalized.is_empty() {
                continue;
            }
            for (label, patterns) in &self.labels {
                if patterns.iter().any(|pat| normalized.contains(pat.as_str())) {
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
            SENSITIVE_PATHS_DB,
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
    match serde_json::from_str::<SensitivePathsJSON>(SENSITIVE_PATHS_DB) {
        Ok(json) => json.labels,
        Err(_) => HashMap::new(),
    }
}

lazy_static! {
    static ref LABELS_SNAPSHOT: ArcSwap<HashMap<String, Vec<String>>> =
        ArcSwap::from_pointee(build_fallback_labels());
}

pub async fn refresh_labels_snapshot() {
    let db = SENSITIVE_PATHS.data.read().await;
    LABELS_SNAPSHOT.store(Arc::new(db.labels.clone()));
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
            if patterns.iter().any(|pat| normalized.contains(pat.as_str())) {
                result.insert(label.clone());
            }
        }
    }
    result.into_iter().collect()
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
        UpdateStatus::Updated => {
            info!("Sensitive paths were successfully updated.");
            crate::open_files::refresh_patterns_snapshot().await;
            refresh_labels_snapshot().await;
        }
        UpdateStatus::NotUpdated => info!("Sensitive paths are already up to date."),
        UpdateStatus::FormatError => warn!("There was a format error in the sensitive paths data."),
        UpdateStatus::SkippedCustom => {
            info!("Update skipped because custom sensitive paths are in use.")
        }
    }

    Ok(status)
}

pub async fn is_sensitive_path_from_model(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let db = SENSITIVE_PATHS.data.read().await;
    for pat in db.get_patterns_for_platform() {
        if normalized.contains(pat) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

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
        assert!(
            matches!(status, UpdateStatus::Updated | UpdateStatus::NotUpdated),
            "Update status should be either Updated or NotUpdated"
        );
    }
}
