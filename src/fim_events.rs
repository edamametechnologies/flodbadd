use chrono::{DateTime, Duration as ChronoDuration, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::fmt;
use tracing::debug;

pub static FIM_EVENT_RETENTION_TIMEOUT: ChronoDuration = ChronoDuration::hours(8);
pub const FIM_MAX_EVENTS: usize = 10000;
pub const FIM_HASH_SIZE_THRESHOLD: u64 = 10 * 1024 * 1024; // 10MB

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FimEventType {
    Create,
    Modify,
    Delete,
    Rename,
}

impl fmt::Display for FimEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FimEventType::Create => write!(f, "CREATE"),
            FimEventType::Modify => write!(f, "MODIFY"),
            FimEventType::Delete => write!(f, "DELETE"),
            FimEventType::Rename => write!(f, "RENAME"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimEvent {
    pub path: String,
    pub event_type: FimEventType,
    pub timestamp: DateTime<Utc>,
    pub size: Option<u64>,
    pub hash: Option<String>,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    /// Parent process name when attribution is available (ES, lsof).
    pub parent_process_name: Option<String>,
    /// Parent process path when attribution is available (ES, lsof).
    pub parent_process_path: Option<String>,
    pub is_sensitive: bool,
    pub labels: Vec<String>,
    pub uid: String,
    /// Wall-clock time at which the event was last mutated -- either
    /// when it was first inserted, or when one of its mutable fields
    /// (`process_name` / `process_path` / `hash`) was backfilled by a
    /// later attribution / content-hash pass. Used by the helper-to-app
    /// incremental fetch pipeline so the app cache only needs to ship
    /// events whose state has actually changed since the last tick.
    #[serde(default = "Utc::now")]
    pub last_modified: DateTime<Utc>,
}

impl FimEvent {
    pub fn compute_uid(path: &str, event_type: &FimEventType, timestamp: &DateTime<Utc>) -> String {
        let input = format!(
            "{}:{}:{}",
            path,
            event_type,
            timestamp.timestamp_nanos_opt().unwrap_or(0)
        );
        let hash = blake3::hash(input.as_bytes());
        hash.to_hex()[..24].to_string()
    }
}

pub struct FimEventStore {
    events: DashMap<String, FimEvent>,
    max_events: usize,
    retention: ChronoDuration,
}

impl FimEventStore {
    pub fn new() -> Self {
        Self {
            events: DashMap::new(),
            max_events: FIM_MAX_EVENTS,
            retention: FIM_EVENT_RETENTION_TIMEOUT,
        }
    }

    pub fn with_limits(max_events: usize, retention: ChronoDuration) -> Self {
        Self {
            events: DashMap::new(),
            max_events,
            retention,
        }
    }

    pub fn insert(&self, event: FimEvent) {
        self.events.insert(event.uid.clone(), event);
        self.prune_if_needed();
    }

    pub fn get_all_events(&self) -> Vec<FimEvent> {
        let mut events: Vec<FimEvent> = self.events.iter().map(|e| e.value().clone()).collect();
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        events
    }

    pub fn get_events_since(&self, since: DateTime<Utc>) -> Vec<FimEvent> {
        let mut events: Vec<FimEvent> = self
            .events
            .iter()
            .filter(|e| e.value().timestamp >= since)
            .map(|e| e.value().clone())
            .collect();
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        events
    }

    /// Return events whose `last_modified` is strictly newer than `since`.
    /// Mirrors `FlodbaddCapture::get_sessions(incremental=true)` semantics:
    /// the caller stores its own cursor (`since`) and asks the store "what
    /// changed since I last looked", picking up both fresh inserts AND
    /// later backfill updates (process attribution, content hash) on
    /// existing events.
    pub fn get_events_modified_since(&self, since: DateTime<Utc>) -> Vec<FimEvent> {
        let mut events: Vec<FimEvent> = self
            .events
            .iter()
            .filter(|e| e.value().last_modified > since)
            .map(|e| e.value().clone())
            .collect();
        events.sort_by(|a, b| b.last_modified.cmp(&a.last_modified));
        events
    }

    pub fn get_sensitive_events(&self) -> Vec<FimEvent> {
        let mut events: Vec<FimEvent> = self
            .events
            .iter()
            .filter(|e| e.value().is_sensitive)
            .map(|e| e.value().clone())
            .collect();
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        events
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn clear(&self) {
        self.events.clear();
    }

    pub fn get_recent_events_missing_process_attribution(
        &self,
        max_events: usize,
    ) -> Vec<FimEvent> {
        let mut events: Vec<FimEvent> = self
            .events
            .iter()
            .filter(|e| process_attribution_missing(e.value()))
            .map(|e| e.value().clone())
            .collect();
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        if events.len() > max_events {
            events.truncate(max_events);
        }
        events
    }

    /// Like [`Self::get_recent_events_missing_process_attribution`], but only
    /// returns events that the drain-time backfill will actually probe:
    /// sensitive, non-delete, attribution still missing.
    ///
    /// Selecting at the store layer (instead of taking any missing-attribution
    /// event and filtering later) keeps `/tmp` / explicit-watch churn from
    /// occupying the backfill window and starving Keychain / credential-store
    /// candidates that need Tier-3 `lsof` / Restart Manager probes.
    pub fn get_recent_sensitive_events_missing_process_attribution(
        &self,
        max_events: usize,
    ) -> Vec<FimEvent> {
        let mut events: Vec<FimEvent> = self
            .events
            .iter()
            .filter(|e| {
                let event = e.value();
                process_attribution_missing(event)
                    && event.is_sensitive
                    && event.event_type != FimEventType::Delete
            })
            .map(|e| e.value().clone())
            .collect();
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        if events.len() > max_events {
            events.truncate(max_events);
        }
        events
    }

    pub fn update_process_attribution(
        &self,
        uid: &str,
        process_name: Option<String>,
        process_path: Option<String>,
    ) {
        if process_name.is_none() && process_path.is_none() {
            return;
        }

        if let Some(mut event) = self.events.get_mut(uid) {
            let mut changed = false;
            if event
                .process_name
                .as_deref()
                .map(|value| value.trim().is_empty())
                .unwrap_or(true)
            {
                if process_name.is_some() {
                    changed = true;
                }
                event.process_name = process_name;
            }

            if event
                .process_path
                .as_deref()
                .map(|value| value.trim().is_empty())
                .unwrap_or(true)
            {
                if process_path.is_some() {
                    changed = true;
                }
                event.process_path = process_path;
            }

            if changed {
                event.last_modified = Utc::now();
            }
        }
    }

    pub fn update_content_hash(&self, uid: &str, hash: Option<String>) {
        let Some(hash) = hash else {
            return;
        };

        if let Some(mut event) = self.events.get_mut(uid) {
            if event.hash.is_none() {
                event.hash = Some(hash);
                event.last_modified = Utc::now();
            }
        }
    }

    pub fn has_suspicious_events(&self) -> bool {
        self.events.iter().any(|e| {
            let ev = e.value();
            ev.is_sensitive || is_temp_directory_path(&ev.path)
        })
    }

    fn prune_if_needed(&self) {
        let now = Utc::now();
        let cutoff = now - self.retention;

        // Remove expired events
        self.events.retain(|_, v| v.timestamp > cutoff);

        // Cap by snapshot length with saturating_sub: concurrent DashMap
        // mutations can shrink live len below max_events after the check.
        if self.events.len() > self.max_events {
            let mut events: Vec<(String, DateTime<Utc>)> = self
                .events
                .iter()
                .map(|e| (e.key().clone(), e.value().timestamp))
                .collect();
            events.sort_by(|a, b| a.1.cmp(&b.1));

            let to_remove = events.len().saturating_sub(self.max_events);
            for (uid, _) in events.into_iter().take(to_remove) {
                self.events.remove(&uid);
                debug!("FIM: pruned event {}", uid);
            }
        }
    }
}

fn process_attribution_missing(event: &FimEvent) -> bool {
    event
        .process_name
        .as_deref()
        .map(|value| value.trim().is_empty())
        .unwrap_or(true)
        && event
            .process_path
            .as_deref()
            .map(|value| value.trim().is_empty())
            .unwrap_or(true)
}

impl Default for FimEventStore {
    fn default() -> Self {
        Self::new()
    }
}

pub fn is_temp_directory_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/tmp/")
        || normalized.contains("/Temp/")
        || normalized.contains("/AppData/Local/Temp/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fim_event_uid_deterministic() {
        let ts = Utc::now();
        let uid1 = FimEvent::compute_uid("/test/file.txt", &FimEventType::Create, &ts);
        let uid2 = FimEvent::compute_uid("/test/file.txt", &FimEventType::Create, &ts);
        assert_eq!(uid1, uid2);
    }

    #[test]
    fn test_fim_event_uid_differs_for_different_inputs() {
        let ts = Utc::now();
        let uid1 = FimEvent::compute_uid("/test/file1.txt", &FimEventType::Create, &ts);
        let uid2 = FimEvent::compute_uid("/test/file2.txt", &FimEventType::Create, &ts);
        assert_ne!(uid1, uid2);
    }

    #[test]
    fn test_fim_event_store_insert_and_retrieve() {
        let store = FimEventStore::new();
        let ts = Utc::now();
        let event = FimEvent {
            path: "/test/file.txt".to_string(),
            event_type: FimEventType::Create,
            timestamp: ts,
            size: Some(100),
            hash: Some("abc123".to_string()),
            process_name: None,
            process_path: None,
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: false,
            labels: vec![],
            uid: FimEvent::compute_uid("/test/file.txt", &FimEventType::Create, &ts),
            last_modified: ts,
        };
        store.insert(event.clone());
        assert_eq!(store.event_count(), 1);
        let events = store.get_all_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].path, "/test/file.txt");
    }

    #[test]
    fn test_fim_event_store_sensitive_filtering() {
        let store = FimEventStore::new();
        let ts = Utc::now();

        let sensitive = FimEvent {
            path: "/home/user/.ssh/id_rsa".to_string(),
            event_type: FimEventType::Modify,
            timestamp: ts,
            size: Some(2048),
            hash: None,
            process_name: None,
            process_path: None,
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: true,
            labels: vec!["ssh".to_string()],
            uid: FimEvent::compute_uid("/home/user/.ssh/id_rsa", &FimEventType::Modify, &ts),
            last_modified: ts,
        };

        let normal = FimEvent {
            path: "/tmp/build.log".to_string(),
            event_type: FimEventType::Create,
            timestamp: ts + ChronoDuration::seconds(1),
            size: Some(500),
            hash: None,
            process_name: None,
            process_path: None,
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: false,
            labels: vec![],
            uid: FimEvent::compute_uid(
                "/tmp/build.log",
                &FimEventType::Create,
                &(ts + ChronoDuration::seconds(1)),
            ),
            last_modified: ts + ChronoDuration::seconds(1),
        };

        store.insert(sensitive);
        store.insert(normal);
        assert_eq!(store.event_count(), 2);
        assert_eq!(store.get_sensitive_events().len(), 1);
        assert_eq!(store.get_sensitive_events()[0].labels, vec!["ssh"]);
    }

    #[test]
    fn test_recent_events_missing_process_attribution_only_returns_missing_recent_first() {
        let store = FimEventStore::new();
        let older_ts = Utc::now() - ChronoDuration::minutes(2);
        let newer_ts = Utc::now() - ChronoDuration::minutes(1);

        store.insert(FimEvent {
            path: "/tmp/with-process.txt".to_string(),
            event_type: FimEventType::Modify,
            timestamp: older_ts,
            size: None,
            hash: None,
            process_name: Some("cursor".to_string()),
            process_path: Some("/Applications/Cursor.app".to_string()),
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: false,
            labels: vec![],
            uid: FimEvent::compute_uid("/tmp/with-process.txt", &FimEventType::Modify, &older_ts),
            last_modified: older_ts,
        });
        store.insert(FimEvent {
            path: "/tmp/missing-older.txt".to_string(),
            event_type: FimEventType::Modify,
            timestamp: older_ts,
            size: None,
            hash: None,
            process_name: None,
            process_path: None,
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: false,
            labels: vec![],
            uid: FimEvent::compute_uid("/tmp/missing-older.txt", &FimEventType::Modify, &older_ts),
            last_modified: older_ts,
        });
        let newest_uid =
            FimEvent::compute_uid("/tmp/missing-newer.txt", &FimEventType::Create, &newer_ts);
        store.insert(FimEvent {
            path: "/tmp/missing-newer.txt".to_string(),
            event_type: FimEventType::Create,
            timestamp: newer_ts,
            size: None,
            hash: None,
            process_name: None,
            process_path: None,
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: false,
            labels: vec![],
            uid: newest_uid.clone(),
            last_modified: newer_ts,
        });

        let missing = store.get_recent_events_missing_process_attribution(1);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].uid, newest_uid);
    }

    #[test]
    fn test_get_recent_sensitive_events_missing_skips_temp_and_delete() {
        let store = FimEventStore::new();
        let now = Utc::now();
        let older = now - chrono::Duration::seconds(5);

        // Non-sensitive /tmp churn -- must not occupy the sensitive window.
        store.insert(FimEvent {
            path: "/tmp/churn.bin".to_string(),
            event_type: FimEventType::Modify,
            timestamp: now,
            size: None,
            hash: None,
            process_name: None,
            process_path: None,
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: false,
            labels: vec![],
            uid: FimEvent::compute_uid("/tmp/churn.bin", &FimEventType::Modify, &now),
            last_modified: now,
        });

        // Sensitive delete -- backfill skips deletes.
        store.insert(FimEvent {
            path: "/Users/test/.ssh/id_rsa".to_string(),
            event_type: FimEventType::Delete,
            timestamp: now,
            size: None,
            hash: None,
            process_name: None,
            process_path: None,
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: true,
            labels: vec![],
            uid: FimEvent::compute_uid("/Users/test/.ssh/id_rsa", &FimEventType::Delete, &now),
            last_modified: now,
        });

        let keychain_uid = FimEvent::compute_uid(
            "/Users/test/Library/Keychains/login.keychain-db",
            &FimEventType::Rename,
            &older,
        );
        store.insert(FimEvent {
            path: "/Users/test/Library/Keychains/login.keychain-db".to_string(),
            event_type: FimEventType::Rename,
            timestamp: older,
            size: None,
            hash: None,
            process_name: None,
            process_path: None,
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: true,
            labels: vec![],
            uid: keychain_uid.clone(),
            last_modified: older,
        });

        let any_missing = store.get_recent_events_missing_process_attribution(10);
        assert_eq!(any_missing.len(), 3);

        let sensitive_missing =
            store.get_recent_sensitive_events_missing_process_attribution(10);
        assert_eq!(sensitive_missing.len(), 1);
        assert_eq!(sensitive_missing[0].uid, keychain_uid);
    }

    #[test]
    fn test_update_process_attribution_backfills_missing_fields() {
        let store = FimEventStore::new();
        let ts = Utc::now();
        let uid = FimEvent::compute_uid("/tmp/event.txt", &FimEventType::Modify, &ts);
        store.insert(FimEvent {
            path: "/tmp/event.txt".to_string(),
            event_type: FimEventType::Modify,
            timestamp: ts,
            size: None,
            hash: None,
            process_name: None,
            process_path: None,
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: false,
            labels: vec![],
            uid: uid.clone(),
            last_modified: ts,
        });

        store.update_process_attribution(
            &uid,
            Some("cursor".to_string()),
            Some("/Applications/Cursor.app/Contents/MacOS/Cursor".to_string()),
        );

        let events = store.get_all_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].process_name.as_deref(), Some("cursor"));
        assert_eq!(
            events[0].process_path.as_deref(),
            Some("/Applications/Cursor.app/Contents/MacOS/Cursor")
        );
    }

    #[test]
    fn test_update_content_hash_backfills_missing_hash() {
        let store = FimEventStore::new();
        let ts = Utc::now();
        let uid = FimEvent::compute_uid("/tmp/event.txt", &FimEventType::Modify, &ts);
        store.insert(FimEvent {
            path: "/tmp/event.txt".to_string(),
            event_type: FimEventType::Modify,
            timestamp: ts,
            size: Some(12),
            hash: None,
            process_name: None,
            process_path: None,
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: false,
            labels: vec![],
            uid: uid.clone(),
            last_modified: ts,
        });

        store.update_content_hash(&uid, Some("abc123".to_string()));

        let events = store.get_all_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].hash.as_deref(), Some("abc123"));
    }

    #[test]
    fn test_update_content_hash_preserves_existing_hash() {
        let store = FimEventStore::new();
        let ts = Utc::now();
        let uid = FimEvent::compute_uid("/tmp/event.txt", &FimEventType::Modify, &ts);
        store.insert(FimEvent {
            path: "/tmp/event.txt".to_string(),
            event_type: FimEventType::Modify,
            timestamp: ts,
            size: Some(12),
            hash: Some("original".to_string()),
            process_name: None,
            process_path: None,
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: false,
            labels: vec![],
            uid: uid.clone(),
            last_modified: ts,
        });

        store.update_content_hash(&uid, Some("replacement".to_string()));

        let events = store.get_all_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].hash.as_deref(), Some("original"));
    }

    #[test]
    fn test_fim_event_store_clear() {
        let store = FimEventStore::new();
        let ts = Utc::now();
        store.insert(FimEvent {
            path: "/test".to_string(),
            event_type: FimEventType::Create,
            timestamp: ts,
            size: None,
            hash: None,
            process_name: None,
            process_path: None,
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: false,
            labels: vec![],
            uid: FimEvent::compute_uid("/test", &FimEventType::Create, &ts),
            last_modified: ts,
        });
        assert_eq!(store.event_count(), 1);
        store.clear();
        assert_eq!(store.event_count(), 0);
    }

    #[test]
    fn test_fim_event_store_max_events_pruning() {
        let store = FimEventStore::with_limits(5, FIM_EVENT_RETENTION_TIMEOUT);
        let base = Utc::now();
        for i in 0..10 {
            let ts = base + ChronoDuration::seconds(i);
            let path = format!("/test/file_{}.txt", i);
            store.insert(FimEvent {
                path: path.clone(),
                event_type: FimEventType::Create,
                timestamp: ts,
                size: None,
                hash: None,
                process_name: None,
                process_path: None,
                parent_process_name: None,
                parent_process_path: None,
                is_sensitive: false,
                labels: vec![],
                uid: FimEvent::compute_uid(&path, &FimEventType::Create, &ts),
                last_modified: ts,
            });
        }
        assert!(store.event_count() <= 5);
    }

    #[test]
    fn test_fim_event_store_concurrent_prune_does_not_overflow() {
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(FimEventStore::with_limits(32, FIM_EVENT_RETENTION_TIMEOUT));
        let mut handles = Vec::new();
        for t in 0..4 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let base = Utc::now();
                for i in 0..200 {
                    if i % 17 == 0 {
                        store.clear();
                    }
                    let ts = base + ChronoDuration::milliseconds(i);
                    let path = format!("/test/t{}_{}.txt", t, i);
                    store.insert(FimEvent {
                        path: path.clone(),
                        event_type: FimEventType::Create,
                        timestamp: ts,
                        size: None,
                        hash: None,
                        process_name: None,
                        process_path: None,
                        parent_process_name: None,
                        parent_process_path: None,
                        is_sensitive: false,
                        labels: vec![],
                        uid: FimEvent::compute_uid(&path, &FimEventType::Create, &ts),
                        last_modified: ts,
                    });
                }
            }));
        }
        for handle in handles {
            handle.join().expect("prune worker panicked");
        }
        assert!(store.event_count() <= 32);
    }

    #[test]
    fn test_fim_event_store_has_suspicious() {
        let store = FimEventStore::new();
        let ts = Utc::now();
        store.insert(FimEvent {
            path: "/home/user/.ssh/id_rsa".to_string(),
            event_type: FimEventType::Modify,
            timestamp: ts,
            size: None,
            hash: None,
            process_name: None,
            process_path: None,
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: true,
            labels: vec!["ssh".to_string()],
            uid: FimEvent::compute_uid("/home/user/.ssh/id_rsa", &FimEventType::Modify, &ts),
            last_modified: ts,
        });
        assert!(store.has_suspicious_events());
    }

    #[test]
    fn test_is_temp_directory_path() {
        assert!(is_temp_directory_path("/tmp/evil.sh"));
        assert!(is_temp_directory_path("/var/tmp/payload"));
        assert!(is_temp_directory_path(
            "C:\\Users\\user\\AppData\\Local\\Temp\\script.ps1"
        ));
        assert!(!is_temp_directory_path("/home/user/project/src/main.rs"));
        assert!(!is_temp_directory_path("/usr/bin/bash"));
    }

    #[test]
    fn test_fim_event_type_display() {
        assert_eq!(format!("{}", FimEventType::Create), "CREATE");
        assert_eq!(format!("{}", FimEventType::Modify), "MODIFY");
        assert_eq!(format!("{}", FimEventType::Delete), "DELETE");
        assert_eq!(format!("{}", FimEventType::Rename), "RENAME");
    }

    #[test]
    fn test_fim_event_serialization() {
        let ts = Utc::now();
        let event = FimEvent {
            path: "/test/file.txt".to_string(),
            event_type: FimEventType::Create,
            timestamp: ts,
            size: Some(100),
            hash: Some("abc123".to_string()),
            process_name: Some("node".to_string()),
            process_path: Some("/usr/bin/node".to_string()),
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: false,
            labels: vec!["env".to_string()],
            uid: FimEvent::compute_uid("/test/file.txt", &FimEventType::Create, &ts),
            last_modified: ts,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let deserialized: FimEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.path, event.path);
        assert_eq!(deserialized.uid, event.uid);
        assert_eq!(deserialized.labels, event.labels);
    }

    #[test]
    fn test_fim_event_store_get_events_since() {
        let store = FimEventStore::new();
        let base = Utc::now();
        let old_ts = base - ChronoDuration::hours(2);
        let new_ts = base;

        store.insert(FimEvent {
            path: "/old".to_string(),
            event_type: FimEventType::Create,
            timestamp: old_ts,
            size: None,
            hash: None,
            process_name: None,
            process_path: None,
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: false,
            labels: vec![],
            uid: FimEvent::compute_uid("/old", &FimEventType::Create, &old_ts),
            last_modified: old_ts,
        });
        store.insert(FimEvent {
            path: "/new".to_string(),
            event_type: FimEventType::Modify,
            timestamp: new_ts,
            size: None,
            hash: None,
            process_name: None,
            process_path: None,
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: false,
            labels: vec![],
            uid: FimEvent::compute_uid("/new", &FimEventType::Modify, &new_ts),
            last_modified: new_ts,
        });

        let since = base - ChronoDuration::hours(1);
        let recent = store.get_events_since(since);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].path, "/new");
    }

    /// F2 incremental fetch: a fresh insert after the cursor must be
    /// returned by `get_events_modified_since`, and an event whose
    /// `last_modified` predates the cursor must be filtered out.
    #[test]
    fn test_get_events_modified_since_returns_new_inserts() {
        let store = FimEventStore::new();
        let base = Utc::now();
        let pre_ts = base - ChronoDuration::seconds(10);
        let post_ts = base + ChronoDuration::seconds(10);

        store.insert(FimEvent {
            path: "/before".to_string(),
            event_type: FimEventType::Create,
            timestamp: pre_ts,
            size: None,
            hash: None,
            process_name: None,
            process_path: None,
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: false,
            labels: vec![],
            uid: FimEvent::compute_uid("/before", &FimEventType::Create, &pre_ts),
            last_modified: pre_ts,
        });
        store.insert(FimEvent {
            path: "/after".to_string(),
            event_type: FimEventType::Modify,
            timestamp: post_ts,
            size: None,
            hash: None,
            process_name: None,
            process_path: None,
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: false,
            labels: vec![],
            uid: FimEvent::compute_uid("/after", &FimEventType::Modify, &post_ts),
            last_modified: post_ts,
        });

        let delta = store.get_events_modified_since(base);
        assert_eq!(delta.len(), 1, "only the post-cursor insert should appear");
        assert_eq!(delta[0].path, "/after");
    }

    /// F2: a backfilled process-attribution update on an already-inserted
    /// event must bump `last_modified` so the next incremental tick picks
    /// up the now-attributed event. Without this, the app-side cache never
    /// learns about process_name / process_path attached after the fact by
    /// `backfill_missing_process_attribution`.
    #[test]
    fn test_get_events_modified_since_picks_up_backfilled_process_attribution() {
        let store = FimEventStore::new();
        let insert_ts = Utc::now() - ChronoDuration::seconds(5);
        let uid = FimEvent::compute_uid("/tmp/missing.txt", &FimEventType::Modify, &insert_ts);

        store.insert(FimEvent {
            path: "/tmp/missing.txt".to_string(),
            event_type: FimEventType::Modify,
            timestamp: insert_ts,
            size: None,
            hash: None,
            process_name: None,
            process_path: None,
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: false,
            labels: vec![],
            uid: uid.clone(),
            last_modified: insert_ts,
        });

        // Cursor advances PAST the original insert, simulating "the app
        // has already pulled this event in a previous incremental tick".
        let cursor = Utc::now();

        // Backfill happens AFTER the cursor.
        std::thread::sleep(std::time::Duration::from_millis(5));
        store.update_process_attribution(
            &uid,
            Some("cursor".to_string()),
            Some("/Applications/Cursor.app/Contents/MacOS/Cursor".to_string()),
        );

        let delta = store.get_events_modified_since(cursor);
        assert_eq!(
            delta.len(),
            1,
            "the backfilled event should reappear in the delta"
        );
        assert_eq!(delta[0].uid, uid);
        assert_eq!(delta[0].process_name.as_deref(), Some("cursor"));
    }

    /// F2: a backfilled content-hash update must bump `last_modified` for
    /// the same reason as the process-attribution case above. The hashing
    /// happens out-of-band (Tier-2/Tier-3 hash backfill in the FIM
    /// watcher), so the app-side cache only learns the hash via the next
    /// incremental delta.
    #[test]
    fn test_get_events_modified_since_picks_up_backfilled_content_hash() {
        let store = FimEventStore::new();
        let insert_ts = Utc::now() - ChronoDuration::seconds(5);
        let uid = FimEvent::compute_uid("/tmp/needs-hash.txt", &FimEventType::Modify, &insert_ts);

        store.insert(FimEvent {
            path: "/tmp/needs-hash.txt".to_string(),
            event_type: FimEventType::Modify,
            timestamp: insert_ts,
            size: Some(12),
            hash: None,
            process_name: None,
            process_path: None,
            parent_process_name: None,
            parent_process_path: None,
            is_sensitive: false,
            labels: vec![],
            uid: uid.clone(),
            last_modified: insert_ts,
        });

        let cursor = Utc::now();
        std::thread::sleep(std::time::Duration::from_millis(5));
        store.update_content_hash(&uid, Some("blake3-abc".to_string()));

        let delta = store.get_events_modified_since(cursor);
        assert_eq!(
            delta.len(),
            1,
            "the now-hashed event should reappear in the delta"
        );
        assert_eq!(delta[0].uid, uid);
        assert_eq!(delta[0].hash.as_deref(), Some("blake3-abc"));
    }

    /// F2: incremental fetches must be sorted newest-first on
    /// `last_modified` so the cache merge order matches the helper-side
    /// store order (most recent at index 0). Matches the
    /// `get_all_events` sort contract.
    #[test]
    fn test_get_events_modified_since_sort_order() {
        let store = FimEventStore::new();
        let base = Utc::now();
        let cursor = base - ChronoDuration::hours(1);

        for offset in [1_i64, 5, 3] {
            let ts = base + ChronoDuration::seconds(offset);
            let path = format!("/tmp/file_{}.txt", offset);
            store.insert(FimEvent {
                path: path.clone(),
                event_type: FimEventType::Create,
                timestamp: ts,
                size: None,
                hash: None,
                process_name: None,
                process_path: None,
                parent_process_name: None,
                parent_process_path: None,
                is_sensitive: false,
                labels: vec![],
                uid: FimEvent::compute_uid(&path, &FimEventType::Create, &ts),
                last_modified: ts,
            });
        }

        let delta = store.get_events_modified_since(cursor);
        assert_eq!(delta.len(), 3);
        // Newest first: offset=5 then 3 then 1.
        assert!(delta[0].path.contains("file_5"), "{}", delta[0].path);
        assert!(delta[1].path.contains("file_3"), "{}", delta[1].path);
        assert!(delta[2].path.contains("file_1"), "{}", delta[2].path);
    }
}
