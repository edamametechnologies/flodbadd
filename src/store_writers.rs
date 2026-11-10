//! The processes recorded per file under the configured store roots.
//!
//! A store is a set of directories an application keeps one file per unit of
//! work in (an agent's transcripts, the files that name its running
//! processes). The file monitor publishes the stores when it starts
//! ([`configure`]) and withdraws them when it stops ([`clear`]). While they
//! are published, the kernel-time sensors (Endpoint Security, fanotify, the
//! ETW FileIo session) call [`record`] from their handlers for each file
//! operation under a store root, and this module keeps, per file:
//!
//! - one row per process that operated on it (pid, the process's start as the
//!   sensor gives it, first and last operation time, the operations as a bit
//!   mask, a count);
//! - whether the file's creation was reported, and by which process;
//! - since when its rows hold every reported operation;
//! - what the reader of the file has not taken yet ([`take_dirty`]): the
//!   processes that operated on it since the last take, as spans in time, the
//!   file's size where an event carried it, and whether the sensor reported
//!   dropped events in between.
//!
//! This module never opens a file and holds no file content: it holds what
//! the sensors reported. A reader waits for a change with [`wait_dirty`] and
//! reads the files itself.
//!
//! The record is bounded ([`MAX_FILES`] files, [`MAX_WRITERS_PER_FILE`] rows
//! and [`MAX_SPANS_PER_FILE`] spans each). What leaves the record is counted
//! and moves the file's `complete_since_ms` forward, and every reply names
//! the record's `instance`: a consumer compares both with what it read
//! before.
//!
//! Always compiled, like `fim_attribution`: the sensors that feed it are
//! gated on independent features.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::{ArcSwap, ArcSwapOption};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use undeadlock::{CustomMutex, CustomMutexExt};

use crate::fim_attribution::{normalize, path_under_root};

/// Files with a record (the least recently active one leaves first).
pub const MAX_FILES: usize = 1_024;
/// Rows per file (one per process).
pub const MAX_WRITERS_PER_FILE: usize = 4;
/// Spans per file between two takes.
pub const MAX_SPANS_PER_FILE: usize = 8;

/// How far after a record was opened the report of the file's creation may
/// still arrive and be taken as the creation the record opened with. The
/// sensors deliver a creation and the first write on different threads or in
/// different buffers, and a change can be noted before either.
const CREATION_REORDER_MS: u64 = 1_000;

/// How long a sensor handler retries a contended record before it counts the
/// operation as not recorded. Handlers run on kernel-callback threads and
/// must not stall; the holders are a reader copying a few rows.
const SENSOR_RETRY_BUDGET: Duration = Duration::from_millis(2);
/// How long a reader retries a contended record before it reports that it
/// read nothing.
const READ_RETRY_BUDGET: Duration = Duration::from_millis(25);

/// The operations a row or a span carries, as bits.
pub mod ops {
    /// The file was created.
    pub const CREATE: u32 = 1 << 0;
    /// The file was written (a write, or a close after writes).
    pub const WRITE: u32 = 1 << 1;
    /// The file's size was set (a truncation, a truncating open).
    pub const TRUNCATE: u32 = 1 << 2;
    /// Another file was moved to this path.
    pub const RENAME_TO: u32 = 1 << 3;
    /// The file was moved away from this path.
    pub const RENAME_FROM: u32 = 1 << 4;
    /// The file was removed.
    pub const REMOVE: u32 = 1 << 5;
    /// A hard link to the file was made, or the path was made a hard link.
    pub const LINK: u32 = 1 << 6;
    /// The path was made a clone of another file.
    pub const CLONE: u32 = 1 << 7;
    /// The file's content was exchanged with another file's.
    pub const EXCHANGE: u32 = 1 << 8;
    /// The file's attributes were set (times, flags).
    pub const ATTRIBUTES: u32 = 1 << 9;

    /// The operations after which the bytes at the path are not the bytes
    /// that were appended there before.
    pub const REPLACING: u32 = TRUNCATE | RENAME_TO | RENAME_FROM | REMOVE | CLONE | EXCHANGE;
    /// The operations after which the path names no file, or another one.
    pub const UNLINKING: u32 = RENAME_FROM | REMOVE;

    /// The names of the bits set in `mask`, in bit order.
    pub fn names(mask: u32) -> Vec<&'static str> {
        const TABLE: [(u32, &str); 10] = [
            (CREATE, "create"),
            (WRITE, "write"),
            (TRUNCATE, "truncate"),
            (RENAME_TO, "rename_to"),
            (RENAME_FROM, "rename_from"),
            (REMOVE, "remove"),
            (LINK, "link"),
            (CLONE, "clone"),
            (EXCHANGE, "exchange"),
            (ATTRIBUTES, "attributes"),
        ];
        TABLE
            .iter()
            .filter(|(bit, _)| mask & bit != 0)
            .map(|(_, name)| *name)
            .collect()
    }
}

/// One application's store, as the file monitor publishes it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreSpec {
    /// The application's slug (`claude_code`, `codex`, ...).
    pub agent: String,
    /// The store's directories, absolute. A file anywhere below one of them
    /// is a store file when its name ends with one of `file_suffixes` and,
    /// when `path_segment` is not empty, one of its directories below the
    /// root is named `path_segment`.
    pub roots: Vec<PathBuf>,
    pub path_segment: String,
    pub file_suffixes: Vec<String>,
    /// The directories, absolute, whose direct children ending with one of
    /// `pid_file_suffixes` name a running process of the application.
    pub pid_file_roots: Vec<PathBuf>,
    pub pid_file_suffixes: Vec<String>,
}

/// What a recorded file is to its store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreFileKind {
    /// A file of the store proper (a transcript).
    Transcript,
    /// A file that names a running process of the application.
    PidFile,
}

/// A process as a sensor identifies it: its pid and, where the sensor gives
/// it, when the process started (epoch milliseconds). Two processes that held
/// the same pid at different times differ by their start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WriterInstance {
    pub pid: u32,
    /// `None`: the sensor gave no start for this process.
    pub started_at_ms: Option<u64>,
}

/// One row: what one process did to one file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriterRow {
    pub writer: WriterInstance,
    /// The process's image as the sensor names it; empty when it named none.
    pub process_path: String,
    /// Time of the first and of the last operation (epoch milliseconds).
    pub first_ms: u64,
    pub last_ms: u64,
    /// The operations, as [`ops`] bits.
    pub ops: u32,
    /// How many operations.
    pub count: u64,
}

/// The creation a sensor reported for a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreationSeen {
    pub writer: WriterInstance,
    pub at_ms: u64,
}

/// The operations of one process on one file between two takes, as a span in
/// time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriterSpan {
    pub writer: WriterInstance,
    pub first_ms: u64,
    pub last_ms: u64,
    pub ops: u32,
}

/// One operation, as a sensor reports it.
#[derive(Debug, Clone, Copy)]
pub struct Operation<'a> {
    pub path: &'a str,
    /// [`ops`] bits.
    pub ops: u32,
    pub pid: u32,
    /// When the process started, where the sensor knows.
    pub started_at_ms: Option<u64>,
    /// The process's image, or empty.
    pub process_path: &'a str,
    /// When the operation happened, on the wall clock (epoch milliseconds).
    pub at_ms: u64,
    /// The file's size, where the event carries it.
    pub size: Option<u64>,
}

/// A file's rows, as [`rows_since`] returns them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRows {
    /// The path as the sensor spelled it (on Windows, with its drive letter).
    pub path: String,
    pub agent: String,
    pub kind: StoreFileKind,
    /// Identifies this record of the path: a path whose record left the
    /// table and came back carries another id.
    pub record_id: u64,
    /// When the record was opened (the first operation reported for it).
    pub first_seen_ms: u64,
    /// The creation reported for the file, when the record opened with it.
    pub creation: Option<CreationSeen>,
    /// The latest creation reported at the path: `creation`, or a later one
    /// (the file was unlinked and a file was created at the path again).
    pub last_creation: Option<CreationSeen>,
    /// The rows hold every operation reported since this instant.
    pub complete_since_ms: u64,
    pub rows: Vec<WriterRow>,
    /// Rows that left the record to make room.
    pub rows_evicted: u64,
    /// The last operation reported unlinked the path.
    pub unlinked: bool,
    /// The record's sequence number when this file last changed.
    pub changed_seq: u64,
}

/// Counters of the record since the process started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreWriterCounters {
    /// Operations recorded.
    pub operations: u64,
    /// Changes noted without a process ([`note_change`]).
    pub changes_noted: u64,
    /// Files whose record left the table to make room.
    pub files_evicted: u64,
    /// Rows that left a file's record to make room.
    pub rows_evicted: u64,
    /// Times a file's spans between two takes exceeded
    /// [`MAX_SPANS_PER_FILE`].
    pub spans_overflowed: u64,
    /// Times a sensor reported dropped events ([`note_lost`]).
    pub lost_signals: u64,
    /// Operations a handler could not record because the record was held.
    pub dropped_locked: u64,
}

/// Reply of [`rows_since`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreWriterRows {
    /// Identifies the record: it changes when the process restarts and each
    /// time the stores are published again.
    pub instance: String,
    /// Whether stores are published (the file monitor runs).
    pub configured: bool,
    /// When this instance started recording (epoch milliseconds).
    pub recording_since_ms: u64,
    /// The record's sequence number at the read: ask again from it.
    pub seq: u64,
    /// The files that changed after the asked sequence number.
    pub files: Vec<FileRows>,
    /// Files with a record now.
    pub files_recorded: usize,
    /// When a sensor last reported dropped events, and how many times it did
    /// for this instance.
    pub last_lost_ms: Option<u64>,
    pub lost_signals: u64,
    pub counters: StoreWriterCounters,
}

/// A file that changed since the last take, as [`take_dirty`] returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirtyFile {
    pub path: String,
    pub agent: String,
    pub kind: StoreFileKind,
    pub record_id: u64,
    /// The creation reported for the file, when the record opened with it.
    pub creation: Option<CreationSeen>,
    /// The latest creation reported at the path (see [`FileRows`]).
    pub last_creation: Option<CreationSeen>,
    /// When the first change since the last take was reported.
    pub dirty_since_ms: u64,
    /// Who operated on the file since the last take, in order of first
    /// operation.
    pub spans: Vec<WriterSpan>,
    /// More processes alternated than the spans hold: `spans` is incomplete.
    pub spans_overflowed: bool,
    /// The file's size at the last event that carried one.
    pub size_at_close: Option<u64>,
    /// A sensor reported dropped events since the last take.
    pub lost: bool,
    /// The last operation reported unlinked the path.
    pub unlinked: bool,
}

/// Reply of [`take_dirty`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirtyTake {
    pub instance: String,
    pub configured: bool,
    pub files: Vec<DirtyFile>,
}

// ---------------------------------------------------------------------------
// Which paths are store files
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct StoreMatcher {
    stores: Vec<MatchedStore>,
    /// Every ending of every store, for the test that runs before a path is
    /// normalized: the sensors ask about every file event under a watch
    /// root, and most paths end otherwise.
    endings: Vec<String>,
}

#[derive(Debug)]
struct MatchedStore {
    agent: String,
    /// Normalized spellings of the roots (raw and canonical).
    roots: Vec<String>,
    path_segment: String,
    file_suffixes: Vec<String>,
    pid_file_roots: Vec<String>,
    pid_file_suffixes: Vec<String>,
}

fn normalized_spellings(roots: &[PathBuf]) -> Vec<String> {
    // As `fim_attribution::set_roots`: a sensor may report the canonical
    // spelling of a root the caller gave through a link.
    let mut set = std::collections::BTreeSet::new();
    for root in roots {
        let raw = normalize(&root.to_string_lossy());
        let raw = raw.trim_end_matches('/').to_string();
        if !raw.is_empty() {
            set.insert(raw);
        }
        if let Ok(canonical) = std::fs::canonicalize(root) {
            let canonical = normalize(&canonical.to_string_lossy());
            let canonical = canonical.trim_end_matches('/').to_string();
            if !canonical.is_empty() {
                set.insert(canonical);
            }
        }
    }
    set.into_iter().collect()
}

impl StoreMatcher {
    fn from_specs(specs: &[StoreSpec]) -> Self {
        let lower = |values: &[String]| -> Vec<String> {
            values
                .iter()
                .map(|value| value.to_lowercase())
                .filter(|value| !value.is_empty())
                .collect()
        };
        let stores: Vec<MatchedStore> = specs
            .iter()
            .filter(|spec| !spec.agent.is_empty())
            .map(|spec| MatchedStore {
                agent: spec.agent.clone(),
                roots: normalized_spellings(&spec.roots),
                path_segment: spec.path_segment.to_lowercase(),
                file_suffixes: lower(&spec.file_suffixes),
                pid_file_roots: normalized_spellings(&spec.pid_file_roots),
                pid_file_suffixes: lower(&spec.pid_file_suffixes),
            })
            .collect();
        let mut endings: Vec<String> = stores
            .iter()
            .flat_map(|store| {
                store
                    .file_suffixes
                    .iter()
                    .chain(store.pid_file_suffixes.iter())
                    .cloned()
            })
            .collect();
        endings.sort();
        endings.dedup();
        Self { stores, endings }
    }

    /// Whether `path`, as a sensor spelled it, ends like a file of one of
    /// the stores (compared without case). `false` rules the path out
    /// before it is normalized.
    fn ends_like_a_store_file(&self, path: &str) -> bool {
        let bytes = path.as_bytes();
        self.endings.iter().any(|ending| {
            let ending = ending.as_bytes();
            bytes.len() >= ending.len()
                && bytes[bytes.len() - ending.len()..].eq_ignore_ascii_case(ending)
        })
    }

    /// The store and kind of a normalized path.
    fn classify(&self, normalized: &str) -> Option<(&str, StoreFileKind)> {
        for store in &self.stores {
            if store
                .file_suffixes
                .iter()
                .any(|suffix| normalized.ends_with(suffix.as_str()))
            {
                for root in &store.roots {
                    if !path_under_root(normalized, root, true) {
                        continue;
                    }
                    if store.path_segment.is_empty() {
                        return Some((&store.agent, StoreFileKind::Transcript));
                    }
                    // The directories between the root and the file name.
                    let below = &normalized[root.len() + 1..];
                    let mut parts: Vec<&str> = below.split('/').collect();
                    parts.pop();
                    if parts.iter().any(|part| *part == store.path_segment) {
                        return Some((&store.agent, StoreFileKind::Transcript));
                    }
                }
            }
            if store
                .pid_file_suffixes
                .iter()
                .any(|suffix| normalized.ends_with(suffix.as_str()))
                && store
                    .pid_file_roots
                    .iter()
                    .any(|root| path_under_root(normalized, root, false))
            {
                return Some((&store.agent, StoreFileKind::PidFile));
            }
        }
        None
    }
}

/// Published snapshot of the stores, replaced whole. Read by the sensor
/// handlers on every file event under a watch root, so it is lock-free.
static MATCHER: Lazy<ArcSwap<StoreMatcher>> =
    Lazy::new(|| ArcSwap::from_pointee(StoreMatcher::default()));

/// The store and kind of `path`, when it is a file of a published store.
pub fn classify(path: &str) -> Option<(String, StoreFileKind)> {
    let matcher = MATCHER.load();
    if matcher.stores.is_empty() || !matcher.ends_like_a_store_file(path) {
        return None;
    }
    matcher
        .classify(&normalize(path))
        .map(|(agent, kind)| (agent.to_string(), kind))
}

/// Whether stores are published.
pub fn is_configured() -> bool {
    !MATCHER.load().stores.is_empty()
}

// ---------------------------------------------------------------------------
// The record
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct FileRecord {
    path: String,
    agent: String,
    kind: StoreFileKind,
    record_id: u64,
    first_seen_ms: u64,
    creation: Option<CreationSeen>,
    last_creation: Option<CreationSeen>,
    complete_since_ms: u64,
    rows: Vec<WriterRow>,
    rows_evicted: u64,
    unlinked: bool,
    changed_seq: u64,
    last_event_ms: u64,
    // What the reader has not taken yet.
    dirty: bool,
    dirty_since_ms: u64,
    spans: Vec<WriterSpan>,
    spans_overflowed: bool,
    size_at_close: Option<u64>,
    lost: bool,
}

#[derive(Debug)]
struct Table {
    instance: String,
    recording_since_ms: u64,
    seq: u64,
    next_record_id: u64,
    files: HashMap<String, FileRecord>,
    last_lost_ms: Option<u64>,
    lost_signals: u64,
}

impl Table {
    fn new(now_ms: u64) -> Self {
        Self {
            instance: uuid::Uuid::new_v4().simple().to_string(),
            recording_since_ms: now_ms,
            seq: 0,
            next_record_id: 1,
            files: HashMap::new(),
            last_lost_ms: None,
            lost_signals: 0,
        }
    }

    fn bump(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    /// Make room for one more file: the least recently active record leaves,
    /// one the reader has taken before one it has not.
    fn make_room(&mut self, counters: &Counters) {
        while self.files.len() >= MAX_FILES {
            let victim = self
                .files
                .iter()
                .min_by_key(|(_, record)| (record.dirty, record.last_event_ms, record.record_id))
                .map(|(key, _)| key.clone());
            match victim {
                Some(key) => {
                    self.files.remove(&key);
                    counters.files_evicted.fetch_add(1, Ordering::Relaxed);
                }
                None => break,
            }
        }
    }

    fn open_record(
        &mut self,
        key: &str,
        path: &str,
        agent: &str,
        kind: StoreFileKind,
        now_ms: u64,
        counters: &Counters,
    ) -> &mut FileRecord {
        if !self.files.contains_key(key) {
            self.make_room(counters);
            let record_id = self.next_record_id;
            self.next_record_id += 1;
            self.files.insert(
                key.to_string(),
                FileRecord {
                    path: path.to_string(),
                    agent: agent.to_string(),
                    kind,
                    record_id,
                    first_seen_ms: now_ms,
                    creation: None,
                    last_creation: None,
                    complete_since_ms: now_ms,
                    rows: Vec::new(),
                    rows_evicted: 0,
                    unlinked: false,
                    changed_seq: 0,
                    last_event_ms: now_ms,
                    dirty: false,
                    dirty_since_ms: now_ms,
                    spans: Vec::new(),
                    spans_overflowed: false,
                    size_at_close: None,
                    lost: false,
                },
            );
        }
        self.files
            .get_mut(key)
            .expect("the record was just inserted")
    }

    fn record(
        &mut self,
        key: &str,
        agent: &str,
        kind: StoreFileKind,
        display_path: &str,
        op: &Operation<'_>,
        counters: &Counters,
    ) {
        let writer = WriterInstance {
            pid: op.pid,
            started_at_ms: op.started_at_ms,
        };
        let opened = !self.files.contains_key(key);
        let seq = self.bump();
        let record = self.open_record(key, display_path, agent, kind, op.at_ms, counters);
        if op.ops & ops::CREATE != 0 {
            // The creation the record opens with is the first report for
            // the path, or one delivered just after the record was opened by
            // the creator's own first operations or by a noted change: no
            // other process has a row, nothing was replaced, and the rows
            // hold everything since the record opened.
            let delivered_late = !opened
                && record.creation.is_none()
                && !record.unlinked
                && record.rows_evicted == 0
                && record.complete_since_ms == record.first_seen_ms
                && op.at_ms <= record.first_seen_ms.saturating_add(CREATION_REORDER_MS)
                && record
                    .rows
                    .iter()
                    .all(|row| row.writer == writer && row.ops & ops::REPLACING == 0);
            if delivered_late {
                record.first_seen_ms = record.first_seen_ms.min(op.at_ms);
                record.complete_since_ms = record.first_seen_ms;
            }
            let creation = CreationSeen {
                writer,
                at_ms: op.at_ms.min(record.first_seen_ms),
            };
            // The record keeps the creation it opened with. A file created
            // at the path after the first one was unlinked is the path's
            // latest creation; the rows stay those of the path.
            if opened || delivered_late {
                record.creation = Some(creation);
            }
            if opened || delivered_late || record.unlinked {
                record.last_creation = Some(CreationSeen {
                    writer,
                    at_ms: if opened || delivered_late {
                        creation.at_ms
                    } else {
                        op.at_ms
                    },
                });
            }
        }
        record.changed_seq = seq;
        record.last_event_ms = record.last_event_ms.max(op.at_ms);
        if op.ops & ops::UNLINKING != 0 {
            record.unlinked = true;
        } else if op.ops & (ops::CREATE | ops::RENAME_TO | ops::LINK | ops::CLONE) != 0 {
            record.unlinked = false;
        }
        if op.size.is_some() {
            record.size_at_close = op.size;
        }

        // The row of this process.
        match record.rows.iter_mut().find(|row| row.writer == writer) {
            Some(row) => {
                row.first_ms = row.first_ms.min(op.at_ms);
                row.last_ms = row.last_ms.max(op.at_ms);
                row.ops |= op.ops;
                row.count += 1;
                if row.process_path.is_empty() && !op.process_path.is_empty() {
                    row.process_path = op.process_path.to_string();
                }
            }
            None => {
                if record.rows.len() >= MAX_WRITERS_PER_FILE {
                    // The least recently active row leaves, the creator's
                    // last. From now on the rows are complete since now only.
                    let creator = record.creation.map(|creation| creation.writer);
                    let victim = record
                        .rows
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, row)| (Some(row.writer) == creator, row.last_ms))
                        .map(|(index, _)| index);
                    if let Some(index) = victim {
                        record.rows.remove(index);
                        record.rows_evicted += 1;
                        record.complete_since_ms = record.complete_since_ms.max(op.at_ms);
                        counters.rows_evicted.fetch_add(1, Ordering::Relaxed);
                    }
                }
                record.rows.push(WriterRow {
                    writer,
                    process_path: op.process_path.to_string(),
                    first_ms: op.at_ms,
                    last_ms: op.at_ms,
                    ops: op.ops,
                    count: 1,
                });
            }
        }

        // The span of this process since the last take.
        if !record.dirty {
            record.dirty = true;
            record.dirty_since_ms = op.at_ms;
        }
        match record.spans.last_mut() {
            Some(span) if span.writer == writer => {
                span.first_ms = span.first_ms.min(op.at_ms);
                span.last_ms = span.last_ms.max(op.at_ms);
                span.ops |= op.ops;
            }
            _ => {
                if record.spans.len() >= MAX_SPANS_PER_FILE {
                    if !record.spans_overflowed {
                        counters.spans_overflowed.fetch_add(1, Ordering::Relaxed);
                    }
                    record.spans_overflowed = true;
                } else {
                    record.spans.push(WriterSpan {
                        writer,
                        first_ms: op.at_ms,
                        last_ms: op.at_ms,
                        ops: op.ops,
                    });
                }
            }
        }
    }

    fn note_change(
        &mut self,
        key: &str,
        agent: &str,
        kind: StoreFileKind,
        display_path: &str,
        at_ms: u64,
        counters: &Counters,
    ) {
        let record = self.open_record(key, display_path, agent, kind, at_ms, counters);
        record.last_event_ms = record.last_event_ms.max(at_ms);
        if !record.dirty {
            record.dirty = true;
            record.dirty_since_ms = at_ms;
        }
    }

    fn note_lost(&mut self, at_ms: u64) {
        self.lost_signals += 1;
        self.last_lost_ms = Some(self.last_lost_ms.map_or(at_ms, |known| known.max(at_ms)));
        let seq = self.bump();
        for record in self.files.values_mut() {
            record.lost = true;
            record.complete_since_ms = record.complete_since_ms.max(at_ms);
            record.changed_seq = seq;
            if !record.dirty {
                record.dirty = true;
                record.dirty_since_ms = at_ms;
            }
        }
    }

    fn take_dirty(&mut self) -> Vec<DirtyFile> {
        let mut files: Vec<DirtyFile> = self
            .files
            .values_mut()
            .filter(|record| record.dirty)
            .map(|record| {
                record.dirty = false;
                DirtyFile {
                    path: record.path.clone(),
                    agent: record.agent.clone(),
                    kind: record.kind,
                    record_id: record.record_id,
                    creation: record.creation,
                    last_creation: record.last_creation,
                    dirty_since_ms: record.dirty_since_ms,
                    spans: std::mem::take(&mut record.spans),
                    spans_overflowed: std::mem::take(&mut record.spans_overflowed),
                    size_at_close: record.size_at_close.take(),
                    lost: std::mem::take(&mut record.lost),
                    unlinked: record.unlinked,
                }
            })
            .collect();
        files.sort_by(|left, right| {
            (left.dirty_since_ms, left.record_id).cmp(&(right.dirty_since_ms, right.record_id))
        });
        files
    }

    fn rows_since(&self, since_seq: u64) -> Vec<FileRows> {
        let mut files: Vec<FileRows> = self
            .files
            .values()
            .filter(|record| record.changed_seq > since_seq)
            .map(|record| FileRows {
                path: record.path.clone(),
                agent: record.agent.clone(),
                kind: record.kind,
                record_id: record.record_id,
                first_seen_ms: record.first_seen_ms,
                creation: record.creation,
                last_creation: record.last_creation,
                complete_since_ms: record.complete_since_ms,
                rows: record.rows.clone(),
                rows_evicted: record.rows_evicted,
                unlinked: record.unlinked,
                changed_seq: record.changed_seq,
            })
            .collect();
        files.sort_by_key(|file| (file.changed_seq, file.record_id));
        files
    }
}

#[derive(Default)]
struct Counters {
    operations: AtomicU64,
    changes_noted: AtomicU64,
    files_evicted: AtomicU64,
    rows_evicted: AtomicU64,
    spans_overflowed: AtomicU64,
    lost_signals: AtomicU64,
    dropped_locked: AtomicU64,
}

static COUNTERS: Lazy<Counters> = Lazy::new(Counters::default);

// undeadlock `CustomMutex`, taken with the non-blocking `try_with` only: the
// writers are synchronous kernel-callback threads (the crate's pattern, as
// `process_events` and `credential_opens`).
static TABLE: Lazy<CustomMutex<Table>> = Lazy::new(|| CustomMutex::new(Table::new(now_ms())));

/// An operation or a dropped-event report that could not reach the record
/// because it was held: the next holder writes it as dropped events.
static PENDING_LOST: AtomicBool = AtomicBool::new(false);

/// The reader's wake-up: the thread parked in [`wait_dirty`], and whether a
/// change was reported since it last looked.
static WAITER: ArcSwapOption<std::thread::Thread> = ArcSwapOption::const_empty();
static WAKE: AtomicBool = AtomicBool::new(false);

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn wake_reader() {
    WAKE.store(true, Ordering::Release);
    if let Some(thread) = WAITER.load_full() {
        thread.unpark();
    }
}

fn with_table<R>(budget: Duration, mut f: impl FnMut(&mut Table) -> R) -> Option<R> {
    let deadline = Instant::now() + budget;
    loop {
        let result = TABLE.try_with(|table| {
            if PENDING_LOST.swap(false, Ordering::AcqRel) {
                table.note_lost(now_ms());
            }
            f(table)
        });
        if result.is_some() {
            return result;
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::yield_now();
    }
}

/// The path a row reports: as the sensor spelled it, on Windows with its
/// drive letter in place of the device name.
fn display_path(path: &str) -> String {
    #[cfg(target_os = "windows")]
    {
        crate::win_path_normalize::nt_device_to_drive(path)
    }
    #[cfg(not(target_os = "windows"))]
    {
        path.to_string()
    }
}

/// Publish the stores. Replaces any previous set and starts a new instance
/// of the record: what was recorded for the previous set is dropped.
pub fn configure(specs: &[StoreSpec]) {
    MATCHER.store(Arc::new(StoreMatcher::from_specs(specs)));
    restart_instance();
}

/// Withdraw the stores (the file monitor stopped). Nothing is recorded until
/// they are published again, and the record starts a new instance.
pub fn clear() {
    MATCHER.store(Arc::new(StoreMatcher::default()));
    restart_instance();
}

fn restart_instance() {
    // A configuration change is not a kernel callback: it may wait for the
    // record.
    let restarted = with_table(Duration::from_secs(5), |table| {
        *table = Table::new(now_ms());
    });
    if restarted.is_none() {
        // The next holder writes the gap; the instance stays.
        PENDING_LOST.store(true, Ordering::Release);
    }
    wake_reader();
}

/// Record one operation a sensor reported. Called from the sensors' handler
/// threads: cheap for a path outside every store, never blocking.
pub fn record(op: &Operation<'_>) {
    let matcher = MATCHER.load();
    if matcher.stores.is_empty() || op.ops == 0 || !matcher.ends_like_a_store_file(op.path) {
        return;
    }
    let key = normalize(op.path);
    let Some((agent, kind)) = matcher.classify(&key) else {
        return;
    };
    let display = display_path(op.path);
    COUNTERS.operations.fetch_add(1, Ordering::Relaxed);
    let recorded = with_table(SENSOR_RETRY_BUDGET, |table| {
        table.record(&key, agent, kind, &display, op, &COUNTERS);
    });
    if recorded.is_none() {
        COUNTERS.dropped_locked.fetch_add(1, Ordering::Relaxed);
        PENDING_LOST.store(true, Ordering::Release);
    }
    wake_reader();
}

/// Note that a store file changed, without naming a process (a directory
/// notification): the file is marked for the reader, no row is written.
pub fn note_change(path: &str, at_ms: u64) {
    let matcher = MATCHER.load();
    if matcher.stores.is_empty() || !matcher.ends_like_a_store_file(path) {
        return;
    }
    let key = normalize(path);
    let Some((agent, kind)) = matcher.classify(&key) else {
        return;
    };
    let display = display_path(path);
    COUNTERS.changes_noted.fetch_add(1, Ordering::Relaxed);
    let noted = with_table(SENSOR_RETRY_BUDGET, |table| {
        table.note_change(&key, agent, kind, &display, at_ms, &COUNTERS);
    });
    if noted.is_none() {
        COUNTERS.dropped_locked.fetch_add(1, Ordering::Relaxed);
        PENDING_LOST.store(true, Ordering::Release);
    }
    wake_reader();
}

/// A sensor reported that it dropped events: every file is marked for the
/// reader with `lost`, and its rows are complete since `at_ms` only.
pub fn note_lost(at_ms: u64) {
    if !is_configured() {
        return;
    }
    COUNTERS.lost_signals.fetch_add(1, Ordering::Relaxed);
    let noted = with_table(SENSOR_RETRY_BUDGET, |table| table.note_lost(at_ms));
    if noted.is_none() {
        PENDING_LOST.store(true, Ordering::Release);
    }
    wake_reader();
}

/// Block the calling thread until a change is reported or `timeout` elapses.
/// `true` when a change was reported. One reader thread at a time: the last
/// caller is the one woken.
pub fn wait_dirty(timeout: Duration) -> bool {
    WAITER.store(Some(Arc::new(std::thread::current())));
    let deadline = Instant::now() + timeout;
    loop {
        if WAKE.swap(false, Ordering::AcqRel) {
            return true;
        }
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        std::thread::park_timeout(deadline - now);
    }
}

/// The files that changed since the last take, each with what was reported
/// for it in between. `None` when the record was held (nothing was taken:
/// ask again), never an empty list standing for "no change".
pub fn take_dirty() -> Option<DirtyTake> {
    let configured = is_configured();
    with_table(READ_RETRY_BUDGET, |table| DirtyTake {
        instance: table.instance.clone(),
        configured,
        files: table.take_dirty(),
    })
}

/// The files whose rows changed after `since_seq` (0: every file), with the
/// record's instance and counters. `None` when the record was held (nothing
/// was read: ask again), never an empty reply standing for "no rows".
pub fn rows_since(since_seq: u64) -> Option<StoreWriterRows> {
    let configured = is_configured();
    with_table(READ_RETRY_BUDGET, |table| StoreWriterRows {
        instance: table.instance.clone(),
        configured,
        recording_since_ms: table.recording_since_ms,
        seq: table.seq,
        files: table.rows_since(since_seq),
        files_recorded: table.files.len(),
        last_lost_ms: table.last_lost_ms,
        lost_signals: table.lost_signals,
        counters: counters(),
    })
}

pub fn counters() -> StoreWriterCounters {
    StoreWriterCounters {
        operations: COUNTERS.operations.load(Ordering::Relaxed),
        changes_noted: COUNTERS.changes_noted.load(Ordering::Relaxed),
        files_evicted: COUNTERS.files_evicted.load(Ordering::Relaxed),
        rows_evicted: COUNTERS.rows_evicted.load(Ordering::Relaxed),
        spans_overflowed: COUNTERS.spans_overflowed.load(Ordering::Relaxed),
        lost_signals: COUNTERS.lost_signals.load(Ordering::Relaxed),
        dropped_locked: COUNTERS.dropped_locked.load(Ordering::Relaxed),
    }
}

/// The kernel-time sensor that feeds the record in this build, and its state
/// now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreWriterSensor {
    /// `endpoint_security`, `fanotify`, `etw`, or `none` when this build
    /// runs no such sensor.
    pub kind: String,
    /// The sensor delivers events now.
    pub active: bool,
    /// Creations, removals and moves are delivered with their process.
    pub entry_events: bool,
    /// The operations that set a file's size or its names without a write
    /// are delivered.
    pub extended_events: bool,
    /// Times the sensor reported dropped events since the process started.
    pub dropped_reports: u64,
}

/// The state of the sensor that feeds the record in this build.
pub fn sensor() -> StoreWriterSensor {
    #[cfg(all(target_os = "macos", feature = "endpointsecurity"))]
    {
        let active = crate::l7_es::is_available();
        StoreWriterSensor {
            kind: "endpoint_security".to_string(),
            active,
            entry_events: active,
            extended_events: active && crate::l7_es::extended_file_events(),
            dropped_reports: crate::l7_es::dropped_message_gaps(),
        }
    }
    #[cfg(all(target_os = "linux", feature = "fim", feature = "ebpf"))]
    {
        let active = crate::fim_fanotify::is_active();
        StoreWriterSensor {
            kind: "fanotify".to_string(),
            active,
            entry_events: active
                && crate::fim_fanotify::creation_group_active()
                && crate::fim_fanotify::creation_marks_total() > 0,
            extended_events: false,
            dropped_reports: crate::fim_fanotify::queue_overflows(),
        }
    }
    #[cfg(all(target_os = "windows", feature = "etw"))]
    {
        let active = crate::l7_etw::is_available();
        StoreWriterSensor {
            kind: "etw".to_string(),
            active,
            entry_events: active,
            extended_events: active,
            dropped_reports: crate::l7_etw::lost_event_reports(),
        }
    }
    #[cfg(not(any(
        all(target_os = "macos", feature = "endpointsecurity"),
        all(target_os = "linux", feature = "fim", feature = "ebpf"),
        all(target_os = "windows", feature = "etw")
    )))]
    {
        // No sensor in this build: nothing is delivered, nothing recorded.
        StoreWriterSensor {
            kind: "none".to_string(),
            active: false,
            entry_events: false,
            extended_events: false,
            dropped_reports: 0,
        }
    }
}

/// `btime` of `/proc/stat`: the boot time in seconds since the epoch.
pub fn parse_boot_time_secs(proc_stat: &str) -> Option<u64> {
    proc_stat
        .lines()
        .find_map(|line| line.strip_prefix("btime "))
        .and_then(|value| value.trim().parse::<u64>().ok())
}

/// Field 22 of `/proc/<pid>/stat` (`starttime`, in clock ticks since boot):
/// with the boot time, when a process started, for the sensors that receive
/// a pid only. The second field is the command name in parentheses and may
/// itself hold spaces and parentheses, so the fields are counted after the
/// last `)`.
pub fn parse_stat_start_ticks(stat: &str) -> Option<u64> {
    let after_comm = &stat[stat.rfind(')')? + 1..];
    // Fields 3.. follow; `starttime` is field 22, the 20th of them.
    after_comm
        .split_ascii_whitespace()
        .nth(19)
        .and_then(|value| value.parse::<u64>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(root: &str) -> StoreSpec {
        StoreSpec {
            agent: "claude_code".to_string(),
            roots: vec![PathBuf::from(format!("{root}/projects"))],
            path_segment: String::new(),
            file_suffixes: vec![".jsonl".to_string()],
            pid_file_roots: vec![PathBuf::from(format!("{root}/sessions"))],
            pid_file_suffixes: vec![".json".to_string()],
        }
    }

    fn op(path: &str, ops: u32, pid: u32, started: u64, at_ms: u64) -> Operation<'_> {
        Operation {
            path,
            ops,
            pid,
            started_at_ms: Some(started),
            process_path: "/opt/tool/bin/tool",
            at_ms,
            size: None,
        }
    }

    /// The table without the process-wide lock: the policies are tested on a
    /// table of their own, as `process_events` tests its ring.
    fn new_table() -> (Table, Counters) {
        (Table::new(1_000), Counters::default())
    }

    fn put(table: &mut Table, counters: &Counters, operation: &Operation<'_>) {
        let key = normalize(operation.path);
        table.record(
            &key,
            "claude_code",
            StoreFileKind::Transcript,
            operation.path,
            operation,
            counters,
        );
    }

    #[test]
    fn a_path_is_classified_by_root_segment_and_ending() {
        let matcher = StoreMatcher::from_specs(&[
            spec("/home/u/.claude"),
            StoreSpec {
                agent: "cursor".to_string(),
                roots: vec![PathBuf::from("/home/u/.cursor/projects")],
                path_segment: "Agent-Transcripts".to_string(),
                file_suffixes: vec![".JSONL".to_string(), ".txt".to_string()],
                pid_file_roots: Vec::new(),
                pid_file_suffixes: Vec::new(),
            },
        ]);
        let classify = |path: &str| {
            matcher
                .classify(&normalize(path))
                .map(|(agent, kind)| (agent.to_string(), kind))
        };
        let transcript = |agent: &str| Some((agent.to_string(), StoreFileKind::Transcript));
        assert_eq!(
            classify("/home/u/.claude/projects/p/s.jsonl"),
            transcript("claude_code")
        );
        assert_eq!(
            classify("/home/u/.claude/projects/p/s/subagents/a.jsonl"),
            transcript("claude_code")
        );
        // Another ending, a sibling of the root, the root itself.
        assert_eq!(classify("/home/u/.claude/projects/p/s.json"), None);
        assert_eq!(classify("/home/u/.claude/projects-old/p/s.jsonl"), None);
        assert_eq!(classify("/home/u/.claude/projects"), None);
        // A pid file is a direct child of its root.
        assert_eq!(
            classify("/home/u/.claude/sessions/4242.json"),
            Some(("claude_code".to_string(), StoreFileKind::PidFile))
        );
        assert_eq!(classify("/home/u/.claude/sessions/deep/4242.json"), None);
        assert_eq!(classify("/home/u/.claude/sessions/4242.key"), None);
        // The segment is one of the directories below the root, compared
        // without case, never the file name.
        assert_eq!(
            classify("/home/u/.cursor/projects/p/agent-transcripts/t.txt"),
            transcript("cursor")
        );
        assert_eq!(
            classify("/home/u/.cursor/projects/p/agent-transcripts/sub/T.JSONL"),
            transcript("cursor")
        );
        assert_eq!(classify("/home/u/.cursor/projects/p/notes/t.txt"), None);
        assert_eq!(
            classify("/home/u/.cursor/projects/p/agent-transcripts.txt"),
            None
        );
        // Separators as Windows spells them.
        assert_eq!(
            classify("\\home\\u\\.claude\\projects\\p\\s.jsonl"),
            transcript("claude_code")
        );
        // The test that runs before a path is normalized: by ending, without
        // case, over every store.
        for path in [
            "/home/u/.claude/projects/p/s.jsonl",
            "C:\\Users\\u\\.cursor\\projects\\p\\agent-transcripts\\T.TXT",
            "/home/u/.claude/sessions/4242.JSON",
        ] {
            assert!(matcher.ends_like_a_store_file(path), "{path}");
        }
        for path in ["/home/u/.claude/projects/p/s.json5", "/a/b.rs", "jsonl", ""] {
            assert!(!matcher.ends_like_a_store_file(path), "{path}");
        }
        assert!(!StoreMatcher::default().ends_like_a_store_file("/a/s.jsonl"));
    }

    /// A root is matched under the spelling the caller gave and under its
    /// canonical one: a sensor may report either.
    #[test]
    fn a_root_is_matched_under_its_given_and_its_canonical_spelling() {
        let base = std::env::temp_dir().join(format!("flodbadd-sw-roots-{}", std::process::id()));
        let given = base.join("projects");
        std::fs::create_dir_all(&given).unwrap();
        let canonical = std::fs::canonicalize(&given).unwrap();
        let matcher = StoreMatcher::from_specs(&[StoreSpec {
            agent: "claude_code".to_string(),
            roots: vec![given.clone()],
            path_segment: String::new(),
            file_suffixes: vec![".jsonl".to_string()],
            pid_file_roots: Vec::new(),
            pid_file_suffixes: Vec::new(),
        }]);
        for root in [&given, &canonical] {
            let file = root.join("p").join("s.jsonl");
            assert!(
                matcher
                    .classify(&normalize(&file.to_string_lossy()))
                    .is_some(),
                "{}",
                file.display()
            );
        }
        // A root that does not exist yet is matched as given.
        let later = StoreMatcher::from_specs(&[StoreSpec {
            agent: "codex".to_string(),
            roots: vec![base.join("not-there-yet")],
            path_segment: String::new(),
            file_suffixes: vec![".jsonl".to_string()],
            pid_file_roots: Vec::new(),
            pid_file_suffixes: Vec::new(),
        }]);
        let file = base.join("not-there-yet").join("s.jsonl");
        assert!(later
            .classify(&normalize(&file.to_string_lossy()))
            .is_some());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn two_writers_within_a_millisecond_are_two_rows() {
        let (mut table, counters) = new_table();
        let path = "/home/u/.claude/projects/p/s.jsonl";
        put(
            &mut table,
            &counters,
            &op(path, ops::CREATE, 10, 500, 2_000),
        );
        put(&mut table, &counters, &op(path, ops::WRITE, 11, 600, 2_000));
        let rows = table.rows_since(0);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].rows.len(), 2);
        assert_eq!(rows[0].rows[0].writer.pid, 10);
        assert_eq!(rows[0].rows[1].writer.pid, 11);
        assert_eq!(
            rows[0].creation,
            Some(CreationSeen {
                writer: WriterInstance {
                    pid: 10,
                    started_at_ms: Some(500)
                },
                at_ms: 2_000
            })
        );
        // The same pid with another start is another process.
        put(&mut table, &counters, &op(path, ops::WRITE, 10, 900, 2_001));
        assert_eq!(table.rows_since(0)[0].rows.len(), 3);
    }

    #[test]
    fn appends_grow_a_counter_and_a_burst_is_one_dirty_entry() {
        let (mut table, counters) = new_table();
        let path = "/home/u/.claude/projects/p/s.jsonl";
        put(
            &mut table,
            &counters,
            &op(path, ops::CREATE, 10, 500, 2_000),
        );
        for i in 0..314u64 {
            put(
                &mut table,
                &counters,
                &op(path, ops::WRITE, 10, 500, 2_001 + i),
            );
        }
        let rows = table.rows_since(0);
        assert_eq!(rows[0].rows.len(), 1);
        assert_eq!(rows[0].rows[0].count, 315);
        assert_eq!(rows[0].rows[0].ops, ops::CREATE | ops::WRITE);
        assert_eq!(rows[0].rows[0].first_ms, 2_000);
        assert_eq!(rows[0].rows[0].last_ms, 2_314);

        let dirty = table.take_dirty();
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].dirty_since_ms, 2_000);
        assert_eq!(
            dirty[0].spans,
            vec![WriterSpan {
                writer: WriterInstance {
                    pid: 10,
                    started_at_ms: Some(500)
                },
                first_ms: 2_000,
                last_ms: 2_314,
                ops: ops::CREATE | ops::WRITE,
            }]
        );
        // Taken once: nothing is dirty until the next operation.
        assert!(table.take_dirty().is_empty());
        put(&mut table, &counters, &op(path, ops::WRITE, 10, 500, 3_000));
        let dirty = table.take_dirty();
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].spans.len(), 1);
        assert_eq!(dirty[0].spans[0].first_ms, 3_000);
        // The rows keep the whole history across takes.
        assert_eq!(table.rows_since(0)[0].rows[0].count, 316);
    }

    #[test]
    fn spans_follow_the_order_in_which_processes_alternate() {
        let (mut table, counters) = new_table();
        let path = "/home/u/.claude/projects/p/s.jsonl";
        put(&mut table, &counters, &op(path, ops::WRITE, 10, 500, 2_000));
        put(
            &mut table,
            &counters,
            &op(path, ops::TRUNCATE, 11, 600, 2_010),
        );
        put(&mut table, &counters, &op(path, ops::WRITE, 10, 500, 2_020));
        let dirty = table.take_dirty();
        let pids: Vec<(u32, u32)> = dirty[0]
            .spans
            .iter()
            .map(|span| (span.writer.pid, span.ops))
            .collect();
        assert_eq!(
            pids,
            vec![(10, ops::WRITE), (11, ops::TRUNCATE), (10, ops::WRITE)]
        );
        assert!(!dirty[0].spans_overflowed);

        // More alternations than the spans hold are reported as such.
        for i in 0..(2 * MAX_SPANS_PER_FILE as u64) {
            let pid = if i % 2 == 0 { 10 } else { 11 };
            put(
                &mut table,
                &counters,
                &op(path, ops::WRITE, pid, 500, 3_000 + i),
            );
        }
        let dirty = table.take_dirty();
        assert_eq!(dirty[0].spans.len(), MAX_SPANS_PER_FILE);
        assert!(dirty[0].spans_overflowed);
        assert_eq!(counters.spans_overflowed.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_row_that_leaves_moves_complete_since_forward_and_keeps_the_creator() {
        let (mut table, counters) = new_table();
        let path = "/home/u/.claude/projects/p/s.jsonl";
        put(
            &mut table,
            &counters,
            &op(path, ops::CREATE, 10, 500, 2_000),
        );
        for (i, pid) in (11..=13u32).enumerate() {
            put(
                &mut table,
                &counters,
                &op(path, ops::WRITE, pid, 500, 2_100 + i as u64),
            );
        }
        let rows = table.rows_since(0);
        assert_eq!(rows[0].rows.len(), MAX_WRITERS_PER_FILE);
        assert_eq!(rows[0].complete_since_ms, 2_000);
        assert_eq!(rows[0].rows_evicted, 0);

        put(&mut table, &counters, &op(path, ops::WRITE, 14, 500, 2_500));
        let rows = table.rows_since(0);
        assert_eq!(rows[0].rows.len(), MAX_WRITERS_PER_FILE);
        assert_eq!(rows[0].rows_evicted, 1);
        assert_eq!(rows[0].complete_since_ms, 2_500);
        let pids: Vec<u32> = rows[0].rows.iter().map(|row| row.writer.pid).collect();
        // The creator stays; the least recently active of the others left.
        assert_eq!(pids, vec![10, 12, 13, 14]);
        assert_eq!(counters.rows_evicted.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_file_that_leaves_comes_back_as_another_record() {
        let (mut table, counters) = new_table();
        let first = "/home/u/.claude/projects/p/first.jsonl";
        put(
            &mut table,
            &counters,
            &op(first, ops::CREATE, 10, 500, 2_000),
        );
        let first_id = table.rows_since(0)[0].record_id;
        table.take_dirty();
        for i in 0..MAX_FILES as u64 {
            let path = format!("/home/u/.claude/projects/p/f{i}.jsonl");
            put(
                &mut table,
                &counters,
                &op(&path, ops::CREATE, 10, 500, 3_000 + i),
            );
        }
        assert_eq!(table.files.len(), MAX_FILES);
        assert!(counters.files_evicted.load(Ordering::Relaxed) >= 1);
        assert!(!table.files.contains_key(&normalize(first)));

        // The same path again: a record of its own, opened by a write, with
        // no creation and rows complete since now only.
        put(
            &mut table,
            &counters,
            &op(first, ops::WRITE, 10, 500, 9_000),
        );
        let rows = table.rows_since(0);
        let back = rows
            .iter()
            .find(|file| file.path == first)
            .expect("the file has a record again");
        assert_ne!(back.record_id, first_id);
        assert_eq!(back.creation, None);
        assert_eq!(back.first_seen_ms, 9_000);
        assert_eq!(back.complete_since_ms, 9_000);
    }

    #[test]
    fn dropped_events_mark_every_file_and_move_complete_since() {
        let (mut table, counters) = new_table();
        let a = "/home/u/.claude/projects/p/a.jsonl";
        let b = "/home/u/.claude/projects/p/b.jsonl";
        put(&mut table, &counters, &op(a, ops::CREATE, 10, 500, 2_000));
        put(&mut table, &counters, &op(b, ops::CREATE, 10, 500, 2_001));
        table.take_dirty();
        let seq = table.seq;

        table.note_lost(5_000);
        assert_eq!(table.lost_signals, 1);
        assert_eq!(table.last_lost_ms, Some(5_000));
        let dirty = table.take_dirty();
        assert_eq!(dirty.len(), 2);
        assert!(dirty.iter().all(|file| file.lost && file.spans.is_empty()));
        let rows = table.rows_since(seq);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|file| file.complete_since_ms == 5_000));
        // The flag is taken with the file.
        put(&mut table, &counters, &op(a, ops::WRITE, 10, 500, 6_000));
        assert!(!table.take_dirty()[0].lost);
    }

    #[test]
    fn rows_are_returned_from_a_sequence_number() {
        let (mut table, counters) = new_table();
        let a = "/home/u/.claude/projects/p/a.jsonl";
        let b = "/home/u/.claude/projects/p/b.jsonl";
        put(&mut table, &counters, &op(a, ops::CREATE, 10, 500, 2_000));
        let after_a = table.seq;
        put(&mut table, &counters, &op(b, ops::CREATE, 10, 500, 2_001));
        assert_eq!(table.rows_since(0).len(), 2);
        let since = table.rows_since(after_a);
        assert_eq!(since.len(), 1);
        assert_eq!(since[0].path, b);
        assert!(table.rows_since(table.seq).is_empty());
    }

    #[test]
    fn a_creation_after_a_removal_stays_in_the_record_of_the_path() {
        let (mut table, counters) = new_table();
        let path = "/home/u/.claude/projects/p/s.jsonl";
        put(
            &mut table,
            &counters,
            &op(path, ops::CREATE, 10, 500, 2_000),
        );
        put(
            &mut table,
            &counters,
            &op(path, ops::REMOVE, 11, 600, 2_100),
        );
        let removed = table.rows_since(0);
        assert!(removed[0].unlinked);
        let record_id = removed[0].record_id;
        assert!(table.take_dirty()[0].unlinked);

        // Created again by another process: the same record, its first
        // creation, the rows of the three processes, and the new creation as
        // the path's latest.
        put(
            &mut table,
            &counters,
            &op(path, ops::CREATE, 12, 700, 2_200),
        );
        let rows = table.rows_since(0);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].record_id, record_id);
        assert!(!rows[0].unlinked);
        assert_eq!(rows[0].rows.len(), 3);
        assert_eq!(rows[0].creation.map(|c| c.writer.pid), Some(10));
        assert_eq!(rows[0].last_creation.map(|c| c.writer.pid), Some(12));
        let dirty = table.take_dirty();
        assert_eq!(dirty[0].last_creation.map(|c| c.at_ms), Some(2_200));

        // A creation reported while the file is there changes neither.
        put(
            &mut table,
            &counters,
            &op(path, ops::CREATE, 13, 800, 2_300),
        );
        let rows = table.rows_since(0);
        assert_eq!(rows[0].creation.map(|c| c.writer.pid), Some(10));
        assert_eq!(rows[0].last_creation.map(|c| c.writer.pid), Some(12));
        assert_eq!(rows[0].rows.len(), 4);
    }

    #[test]
    fn a_creation_delivered_just_after_the_record_opened_is_its_creation() {
        let path = "/home/u/.claude/projects/p/s.jsonl";
        let key = normalize(path);
        let creator = WriterInstance {
            pid: 10,
            started_at_ms: Some(500),
        };

        // The creator's first write is delivered before its creation.
        let (mut table, counters) = new_table();
        put(&mut table, &counters, &op(path, ops::WRITE, 10, 500, 2_003));
        put(
            &mut table,
            &counters,
            &op(path, ops::CREATE, 10, 500, 2_005),
        );
        let rows = table.rows_since(0);
        assert_eq!(
            rows[0].creation,
            Some(CreationSeen {
                writer: creator,
                at_ms: 2_003
            })
        );
        assert_eq!(rows[0].last_creation, rows[0].creation);
        assert_eq!(rows[0].complete_since_ms, 2_003);
        assert_eq!(rows[0].rows.len(), 1);

        // A change noted without a process, then the creation with the time
        // it happened at (before the note).
        let (mut table, counters) = new_table();
        table.note_change(
            &key,
            "claude_code",
            StoreFileKind::Transcript,
            path,
            2_010,
            &counters,
        );
        put(
            &mut table,
            &counters,
            &op(path, ops::CREATE, 10, 500, 2_000),
        );
        let rows = table.rows_since(0);
        assert_eq!(
            rows[0].creation.map(|c| (c.writer, c.at_ms)),
            Some((creator, 2_000))
        );
        assert_eq!(rows[0].first_seen_ms, 2_000);
        assert_eq!(rows[0].complete_since_ms, 2_000);

        // Not taken as the record's creation: another process wrote first,
        // the creation comes long after the record opened, or events were
        // dropped in between.
        let (mut table, counters) = new_table();
        put(&mut table, &counters, &op(path, ops::WRITE, 11, 600, 2_000));
        put(
            &mut table,
            &counters,
            &op(path, ops::CREATE, 10, 500, 2_001),
        );
        assert_eq!(table.rows_since(0)[0].creation, None);

        let (mut table, counters) = new_table();
        put(&mut table, &counters, &op(path, ops::WRITE, 10, 500, 2_000));
        put(
            &mut table,
            &counters,
            &op(path, ops::CREATE, 10, 500, 2_001 + CREATION_REORDER_MS),
        );
        assert_eq!(table.rows_since(0)[0].creation, None);

        let (mut table, counters) = new_table();
        put(&mut table, &counters, &op(path, ops::WRITE, 10, 500, 2_000));
        table.note_lost(2_001);
        put(
            &mut table,
            &counters,
            &op(path, ops::CREATE, 10, 500, 2_002),
        );
        assert_eq!(table.rows_since(0)[0].creation, None);

        let (mut table, counters) = new_table();
        put(
            &mut table,
            &counters,
            &op(path, ops::TRUNCATE, 10, 500, 2_000),
        );
        put(
            &mut table,
            &counters,
            &op(path, ops::CREATE, 10, 500, 2_001),
        );
        assert_eq!(table.rows_since(0)[0].creation, None);
    }

    #[test]
    fn a_noted_change_marks_the_file_without_a_row() {
        let (mut table, counters) = new_table();
        let path = "/home/u/.claude/projects/p/s.jsonl";
        let key = normalize(path);
        table.note_change(
            &key,
            "claude_code",
            StoreFileKind::Transcript,
            path,
            2_000,
            &counters,
        );
        let dirty = table.take_dirty();
        assert_eq!(dirty.len(), 1);
        assert!(dirty[0].spans.is_empty());
        assert_eq!(dirty[0].creation, None);
        // No row was written, so nothing is returned as changed rows.
        assert!(table.rows_since(0).is_empty());
    }

    #[test]
    fn the_size_an_event_carries_is_taken_once() {
        let (mut table, counters) = new_table();
        let path = "/home/u/.claude/projects/p/s.jsonl";
        let mut write = op(path, ops::WRITE, 10, 500, 2_000);
        write.size = Some(4_096);
        put(&mut table, &counters, &write);
        assert_eq!(table.take_dirty()[0].size_at_close, Some(4_096));
        put(&mut table, &counters, &op(path, ops::WRITE, 10, 500, 2_001));
        assert_eq!(table.take_dirty()[0].size_at_close, None);
    }

    /// Through the process-wide record: publication, the wake-up, a new
    /// instance when the stores are published again, and nothing recorded
    /// while none is published.
    #[test]
    #[serial_test::serial(store_writers)]
    fn the_published_record_wakes_its_reader_and_restarts_with_the_stores() {
        clear();
        let outside = op(
            "/tmp/sw-test/.claude/projects/p/s.jsonl",
            ops::WRITE,
            10,
            500,
            2_000,
        );
        record(&outside);
        assert!(!is_configured());
        assert_eq!(classify("/tmp/sw-test/.claude/projects/p/s.jsonl"), None);
        let before = rows_since(0).expect("the record is free");
        assert!(!before.configured);
        assert!(before.files.is_empty());

        configure(&[spec("/tmp/sw-test/.claude")]);
        // Publishing wakes the reader; drain that wake-up first.
        assert!(wait_dirty(Duration::from_millis(200)));
        assert!(!wait_dirty(Duration::from_millis(20)));
        let configured = rows_since(0).expect("the record is free");
        assert!(configured.configured);
        assert_ne!(configured.instance, before.instance);

        let path = "/tmp/sw-test/.claude/projects/p/s.jsonl";
        let reader = std::thread::spawn(|| wait_dirty(Duration::from_secs(10)));
        // Let the reader park, then record from this thread.
        std::thread::sleep(Duration::from_millis(50));
        record(&op(path, ops::CREATE, 10, 500, 2_000));
        assert!(reader.join().expect("reader thread"));
        // Outside every store: counted nowhere, no record.
        record(&op(
            "/tmp/sw-test/elsewhere/s.jsonl",
            ops::WRITE,
            10,
            500,
            2_000,
        ));
        let take = take_dirty().expect("the record is free");
        assert_eq!(take.instance, configured.instance);
        assert_eq!(take.files.len(), 1);
        assert_eq!(take.files[0].path, path);
        assert_eq!(take.files[0].agent, "claude_code");
        assert_eq!(take.files[0].kind, StoreFileKind::Transcript);
        let rows = rows_since(0).expect("the record is free");
        assert_eq!(rows.files.len(), 1);
        assert_eq!(rows.files_recorded, 1);

        // A dropped-event report reaches the published record.
        note_lost(7_000);
        let rows = rows_since(0).expect("the record is free");
        assert_eq!(rows.lost_signals, 1);
        assert_eq!(rows.last_lost_ms, Some(7_000));

        // Published again: another instance, an empty record.
        configure(&[spec("/tmp/sw-test/.claude")]);
        let again = rows_since(0).expect("the record is free");
        assert_ne!(again.instance, configured.instance);
        assert!(again.files.is_empty());
        assert_eq!(again.lost_signals, 0);
        clear();
        assert!(!rows_since(0).expect("the record is free").configured);
    }

    #[test]
    fn proc_stat_fields_are_read_after_the_command_name() {
        // A command name with spaces and a parenthesis.
        let stat = "4242 (tmux: server (1)) S 1 4242 4242 0 -1 4194560 1 2 3 4 5 6 7 8 20 0 1 0 987654 1000 2000";
        assert_eq!(parse_stat_start_ticks(stat), Some(987_654));
        assert_eq!(parse_stat_start_ticks("4242 (sh) S 1"), None);
        assert_eq!(parse_stat_start_ticks("no parenthesis"), None);
        assert_eq!(
            parse_boot_time_secs("cpu  1 2 3\nbtime 1762790000\nprocesses 5\n"),
            Some(1_762_790_000)
        );
        assert_eq!(parse_boot_time_secs("cpu 1 2 3\n"), None);
    }

    #[test]
    fn operation_names_follow_the_bits() {
        assert_eq!(
            ops::names(ops::CREATE | ops::TRUNCATE | ops::REMOVE),
            vec!["create", "truncate", "remove"]
        );
        assert!(ops::names(0).is_empty());
        assert_eq!(ops::REPLACING & ops::WRITE, 0);
        assert_eq!(ops::REPLACING & ops::CREATE, 0);
    }
}
