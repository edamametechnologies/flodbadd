//! The processes recorded per file under the configured store roots.
//!
//! A store is a set of directories an application keeps one file per unit of
//! work in (an agent's transcripts, the files that name its running
//! processes). The file monitor publishes the stores when it starts
//! ([`configure`]) and withdraws its own publication when it stops
//! ([`clear_if`]). While they
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
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
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
/// Rows that left one file's record to make room and are kept with it (the
/// first ones; later ones are counted).
pub const MAX_EVICTED_ROWS_PER_FILE: usize = 16;
/// Records that left the table to make room and that no reader asked past
/// yet.
pub const MAX_TOMBSTONES: usize = 1_024;

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
    /// How long after a file's record was opened the report of the file's
    /// creation is still taken as the creation the record opened with
    /// (milliseconds; 0: never). The sensors deliver a creation and the
    /// first write on different threads or in different buffers, and a
    /// change can be noted before either.
    pub creation_reorder_ms: u64,
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

/// A file's identity on its device, as a sensor gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileId {
    pub device: u64,
    pub inode: u64,
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
    /// The identity of the file the operation was made on, where the event
    /// carries it. `None` for an operation after which the path names
    /// another file or none (a creation of a new path, a removal, a move).
    pub identity: Option<FileId>,
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
    /// The rows that left the record to make room, the first
    /// [`MAX_EVICTED_ROWS_PER_FILE`] of them (a process that left twice is
    /// one entry), and how many more left than are kept.
    pub evicted_rows: Vec<WriterRow>,
    pub evicted_rows_dropped: u64,
    /// The last operation reported unlinked the path.
    pub unlinked: bool,
    /// The record's sequence number when this file last changed.
    pub changed_seq: u64,
}

/// A file record that left the table to make room, with everything it held:
/// what [`rows_since`] returns once for it, from the sequence number of its
/// removal. A reader that asks past it no longer gets it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileTombstone {
    /// The record as it was when it left (its `changed_seq` is the record's
    /// last change before it left).
    pub file: FileRows,
    /// When it left, and the sequence number of its leaving.
    pub evicted_at_ms: u64,
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
    /// Rows that left a file's record beyond the ones it keeps
    /// ([`MAX_EVICTED_ROWS_PER_FILE`]).
    pub evicted_rows_dropped: u64,
    /// Records that left the table while more than [`MAX_TOMBSTONES`] were
    /// waiting for a reader: each is reported as dropped events.
    pub tombstones_dropped: u64,
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
    /// The records that left the table after the asked sequence number.
    pub tombstones: Vec<FileTombstone>,
    /// Records that left the table up to this sequence number are no longer
    /// returned (a reader asked past them, or more were waiting than
    /// [`MAX_TOMBSTONES`]): a reader whose own position is below it has not
    /// been told of every record that left.
    pub tombstones_pruned_through: u64,
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
    /// The identity the latest operation on the path carried (`None`: that
    /// operation carried none): a reader that opens another file at the path
    /// reads a file no operation was recorded on.
    pub identity: Option<FileId>,
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
    /// Which publication this set is (0: none): what [`configure`] returned
    /// to the file monitor that published it.
    generation: u64,
    /// The file monitor runs and published no store because it was given no
    /// home to resolve them under.
    unresolved: bool,
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
    creation_reorder_ms: u64,
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
                creation_reorder_ms: spec.creation_reorder_ms,
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
        Self {
            generation: 0,
            unresolved: false,
            stores,
            endings,
        }
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
    fn classify(&self, normalized: &str) -> Option<(&MatchedStore, StoreFileKind)> {
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
                        return Some((store, StoreFileKind::Transcript));
                    }
                    // The directories between the root and the file name.
                    let below = &normalized[root.len() + 1..];
                    let mut parts: Vec<&str> = below.split('/').collect();
                    parts.pop();
                    if parts.iter().any(|part| *part == store.path_segment) {
                        return Some((store, StoreFileKind::Transcript));
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
                return Some((store, StoreFileKind::PidFile));
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
        .map(|(store, kind)| (store.agent.clone(), kind))
}

/// Whether stores are published.
pub fn is_configured() -> bool {
    !MATCHER.load().stores.is_empty()
}

/// Whether the file monitor runs and published no store because it was given
/// no home to resolve the stores under.
pub fn stores_unresolved() -> bool {
    MATCHER.load().unresolved
}

/// The generation of the publication in place; 0 when there is none.
pub fn stores_generation() -> u64 {
    MATCHER.load().generation
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
    evicted_rows: Vec<WriterRow>,
    evicted_rows_dropped: u64,
    unlinked: bool,
    changed_seq: u64,
    last_event_ms: u64,
    // What the reader has not taken yet.
    dirty: bool,
    dirty_since_ms: u64,
    spans: Vec<WriterSpan>,
    spans_overflowed: bool,
    size_at_close: Option<u64>,
    identity: Option<FileId>,
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
    /// Records that left the table, oldest first.
    tombstones: std::collections::VecDeque<FileTombstone>,
    /// The highest sequence number of a tombstone no longer kept.
    tombstones_pruned_through: u64,
    /// The sequence number a reader of this instance asked past.
    rows_acked: u64,
}

impl FileRecord {
    fn rows(&self) -> FileRows {
        FileRows {
            path: self.path.clone(),
            agent: self.agent.clone(),
            kind: self.kind,
            record_id: self.record_id,
            first_seen_ms: self.first_seen_ms,
            creation: self.creation,
            last_creation: self.last_creation,
            complete_since_ms: self.complete_since_ms,
            rows: self.rows.clone(),
            rows_evicted: self.rows_evicted,
            evicted_rows: self.evicted_rows.clone(),
            evicted_rows_dropped: self.evicted_rows_dropped,
            unlinked: self.unlinked,
            changed_seq: self.changed_seq,
        }
    }

    /// Keep a row that left the record to make room.
    fn keep_evicted(&mut self, row: WriterRow, counters: &Counters) {
        if let Some(known) = self
            .evicted_rows
            .iter_mut()
            .find(|known| known.writer == row.writer)
        {
            known.first_ms = known.first_ms.min(row.first_ms);
            known.last_ms = known.last_ms.max(row.last_ms);
            known.ops |= row.ops;
            known.count = known.count.saturating_add(row.count);
            return;
        }
        if self.evicted_rows.len() < MAX_EVICTED_ROWS_PER_FILE {
            self.evicted_rows.push(row);
        } else {
            self.evicted_rows_dropped += 1;
            counters
                .evicted_rows_dropped
                .fetch_add(1, Ordering::Relaxed);
        }
    }
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
            tombstones: std::collections::VecDeque::new(),
            tombstones_pruned_through: 0,
            rows_acked: 0,
        }
    }

    fn bump(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    /// Make room for one more file: the least recently active record leaves,
    /// one the reader has taken before one it has not, and is kept as a
    /// tombstone until a reader asks past it.
    fn make_room(&mut self, now_ms: u64, counters: &Counters) {
        while self.files.len() >= MAX_FILES {
            let victim = self
                .files
                .iter()
                .min_by_key(|(_, record)| (record.dirty, record.last_event_ms, record.record_id))
                .map(|(key, _)| key.clone());
            let Some(record) = victim.and_then(|key| self.files.remove(&key)) else {
                break;
            };
            counters.files_evicted.fetch_add(1, Ordering::Relaxed);
            let seq = self.bump();
            self.tombstones.push_back(FileTombstone {
                file: record.rows(),
                evicted_at_ms: now_ms,
                changed_seq: seq,
            });
            self.prune_tombstones(counters);
        }
    }

    /// Drop the tombstones a reader asked past, then the oldest ones beyond
    /// [`MAX_TOMBSTONES`].
    fn prune_tombstones(&mut self, counters: &Counters) {
        while self
            .tombstones
            .front()
            .is_some_and(|tombstone| tombstone.changed_seq <= self.rows_acked)
        {
            if let Some(tombstone) = self.tombstones.pop_front() {
                self.tombstones_pruned_through =
                    self.tombstones_pruned_through.max(tombstone.changed_seq);
            }
        }
        while self.tombstones.len() > MAX_TOMBSTONES {
            if let Some(tombstone) = self.tombstones.pop_front() {
                self.tombstones_pruned_through =
                    self.tombstones_pruned_through.max(tombstone.changed_seq);
                counters.tombstones_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// The tombstones whose sequence number is above `since_seq`.
    fn tombstones_since(&self, since_seq: u64) -> Vec<FileTombstone> {
        self.tombstones
            .iter()
            .filter(|tombstone| tombstone.changed_seq > since_seq)
            .cloned()
            .collect()
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
            self.make_room(now_ms, counters);
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
                    evicted_rows: Vec::new(),
                    evicted_rows_dropped: 0,
                    unlinked: false,
                    changed_seq: 0,
                    last_event_ms: now_ms,
                    dirty: false,
                    dirty_since_ms: now_ms,
                    spans: Vec::new(),
                    spans_overflowed: false,
                    size_at_close: None,
                    identity: None,
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
        creation_reorder_ms: u64,
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
                && creation_reorder_ms > 0
                && op.at_ms <= record.first_seen_ms.saturating_add(creation_reorder_ms)
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
        record.identity = op.identity;

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
                        let left = record.rows.remove(index);
                        record.rows_evicted += 1;
                        record.complete_since_ms = record.complete_since_ms.max(op.at_ms);
                        counters.rows_evicted.fetch_add(1, Ordering::Relaxed);
                        record.keep_evicted(left, counters);
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
                    identity: record.identity,
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
            .map(FileRecord::rows)
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
    evicted_rows_dropped: AtomicU64,
    tombstones_dropped: AtomicU64,
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

/// Numbers the publications of this process, from 1.
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// A sensor thread to wake when the stores are published or withdrawn: a
/// sensor that asks for some events only while stores are published.
static LISTENER: ArcSwapOption<std::thread::Thread> = ArcSwapOption::const_empty();

/// Wake `thread` (unpark it) each time the stores are published or
/// withdrawn. One thread: the last one registered.
pub fn wake_on_store_change(thread: std::thread::Thread) {
    LISTENER.store(Some(Arc::new(thread)));
}

fn stores_changed() {
    if let Some(thread) = LISTENER.load_full() {
        thread.unpark();
    }
}

fn publish(mut matcher: StoreMatcher) -> u64 {
    let generation = GENERATION.fetch_add(1, Ordering::Relaxed) + 1;
    matcher.generation = generation;
    let stores = matcher.stores.len();
    let unresolved = matcher.unresolved;
    let previous = MATCHER.swap(Arc::new(matcher));
    restart_instance();
    stores_changed();
    if unresolved {
        tracing::info!("store writers: no store published, no home was given for the stores");
    } else if stores > 0 {
        tracing::info!("store writers: {} store(s) published", stores);
    } else if !previous.stores.is_empty() || previous.unresolved {
        tracing::info!("store writers: stores withdrawn");
    }
    generation
}

/// Publish the stores. Replaces any previous set and starts a new instance
/// of the record: what was recorded for the previous set is dropped. Returns
/// the generation of this publication: the file monitor that stops withdraws
/// it with [`clear_if`].
pub fn configure(specs: &[StoreSpec]) -> u64 {
    publish(StoreMatcher::from_specs(specs))
}

/// Publish that the file monitor runs and has no store to publish because it
/// was given no home to resolve them under ([`stores_unresolved`]). Nothing
/// is recorded. Returns the generation of this publication, as
/// [`configure`].
pub fn configure_unresolved() -> u64 {
    publish(StoreMatcher {
        unresolved: true,
        ..StoreMatcher::default()
    })
}

/// Withdraw the stores, whoever published them. Nothing is recorded until
/// they are published again, and the record starts a new instance.
pub fn clear() {
    let previous = MATCHER.swap(Arc::new(StoreMatcher::default()));
    withdrawn(&previous);
}

/// Withdraw the stores when they are still the publication `generation`
/// names: a file monitor that stops withdraws its own stores, and leaves in
/// place, with the record's instance, the stores a file monitor started
/// after it published. `true` when they were withdrawn.
pub fn clear_if(generation: u64) -> bool {
    let current = MATCHER.load_full();
    if generation == 0 || current.generation != generation {
        return false;
    }
    let previous = MATCHER.compare_and_swap(&current, Arc::new(StoreMatcher::default()));
    if !Arc::ptr_eq(&*previous, &current) {
        return false;
    }
    withdrawn(&current);
    true
}

fn withdrawn(previous: &StoreMatcher) {
    restart_instance();
    stores_changed();
    if !previous.stores.is_empty() || previous.unresolved {
        tracing::info!("store writers: stores withdrawn");
    }
}

/// Whether the first dropped-event report of this instance was logged.
static LOST_LOGGED: AtomicBool = AtomicBool::new(false);

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
    LOST_LOGGED.store(false, Ordering::Release);
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
    let Some((store, kind)) = matcher.classify(&key) else {
        return;
    };
    let display = display_path(op.path);
    COUNTERS.operations.fetch_add(1, Ordering::Relaxed);
    let recorded = with_table(SENSOR_RETRY_BUDGET, |table| {
        table.record(
            &key,
            &store.agent,
            kind,
            &display,
            op,
            store.creation_reorder_ms,
            &COUNTERS,
        );
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
    let Some((store, kind)) = matcher.classify(&key) else {
        return;
    };
    let display = display_path(path);
    COUNTERS.changes_noted.fetch_add(1, Ordering::Relaxed);
    let noted = with_table(SENSOR_RETRY_BUDGET, |table| {
        table.note_change(&key, &store.agent, kind, &display, at_ms, &COUNTERS);
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
    // Once per instance of the record; the reports are counted.
    if !LOST_LOGGED.swap(true, Ordering::AcqRel) {
        tracing::info!("store writers: a sensor reported dropped events");
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

/// The files whose rows changed, and the records that left the table, after
/// `since_seq`, for a reader that last read the record's instance
/// `instance` (another instance, or an empty one: everything, from 0), with
/// the record's counters. A reader of the running instance asks past
/// `since_seq` by asking: the tombstones up to it are no longer kept. `None`
/// when the record was held (nothing was read: ask again), never an empty
/// reply standing for "no rows".
pub fn rows_since(instance: &str, since_seq: u64) -> Option<StoreWriterRows> {
    let configured = is_configured();
    with_table(READ_RETRY_BUDGET, |table| {
        let since_seq = if instance == table.instance {
            table.rows_acked = table.rows_acked.max(since_seq);
            table.prune_tombstones(&COUNTERS);
            since_seq
        } else {
            0
        };
        StoreWriterRows {
            instance: table.instance.clone(),
            configured,
            recording_since_ms: table.recording_since_ms,
            seq: table.seq,
            files: table.rows_since(since_seq),
            tombstones: table.tombstones_since(since_seq),
            tombstones_pruned_through: table.tombstones_pruned_through,
            files_recorded: table.files.len(),
            last_lost_ms: table.last_lost_ms,
            lost_signals: table.lost_signals,
            counters: counters(),
        }
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
        evicted_rows_dropped: COUNTERS.evicted_rows_dropped.load(Ordering::Relaxed),
        tombstones_dropped: COUNTERS.tombstones_dropped.load(Ordering::Relaxed),
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
    /// The file monitor runs and published no store because it was given no
    /// home to resolve the stores under ([`stores_unresolved`]).
    pub stores_unresolved: bool,
}

/// The state [`sensor`] last logged (`u32::MAX`: none yet).
static SENSOR_LOGGED: AtomicU32 = AtomicU32::new(u32::MAX);

/// The state of the sensor that feeds the record in this build. A change of
/// that state since the previous call is logged, once.
pub fn sensor() -> StoreWriterSensor {
    let sensor = sensor_now();
    let published = is_configured();
    let state = u32::from(sensor.active)
        | u32::from(sensor.entry_events) << 1
        | u32::from(sensor.extended_events) << 2
        | u32::from(sensor.stores_unresolved) << 3
        | u32::from(published) << 4;
    if SENSOR_LOGGED.swap(state, Ordering::AcqRel) != state {
        tracing::info!(
            "store writers: sensor {} active={} entry_events={} extended_events={} stores_published={} stores_unresolved={}",
            sensor.kind,
            sensor.active,
            sensor.entry_events,
            sensor.extended_events,
            published,
            sensor.stores_unresolved
        );
    }
    sensor
}

fn sensor_now() -> StoreWriterSensor {
    let stores_unresolved = stores_unresolved();
    #[cfg(all(target_os = "macos", feature = "endpointsecurity"))]
    {
        let active = crate::l7_es::is_available();
        StoreWriterSensor {
            kind: "endpoint_security".to_string(),
            active,
            entry_events: active,
            extended_events: active && crate::l7_es::extended_file_events(),
            dropped_reports: crate::l7_es::dropped_message_gaps(),
            stores_unresolved,
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
            stores_unresolved,
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
            stores_unresolved,
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
            stores_unresolved,
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
            creation_reorder_ms: REORDER_MS,
        }
    }

    /// The reorder bound the tests publish.
    const REORDER_MS: u64 = 1_000;

    fn op(path: &str, ops: u32, pid: u32, started: u64, at_ms: u64) -> Operation<'_> {
        Operation {
            path,
            ops,
            pid,
            started_at_ms: Some(started),
            process_path: "/opt/tool/bin/tool",
            at_ms,
            size: None,
            identity: None,
        }
    }

    /// The table without the process-wide lock: the policies are tested on a
    /// table of their own, as `process_events` tests its ring.
    fn new_table() -> (Table, Counters) {
        (Table::new(1_000), Counters::default())
    }

    fn put(table: &mut Table, counters: &Counters, operation: &Operation<'_>) {
        put_with(table, counters, operation, REORDER_MS);
    }

    fn put_with(
        table: &mut Table,
        counters: &Counters,
        operation: &Operation<'_>,
        creation_reorder_ms: u64,
    ) {
        let key = normalize(operation.path);
        table.record(
            &key,
            "claude_code",
            StoreFileKind::Transcript,
            operation.path,
            operation,
            creation_reorder_ms,
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
                creation_reorder_ms: 250,
            },
        ]);
        let classify = |path: &str| {
            matcher
                .classify(&normalize(path))
                .map(|(store, kind)| (store.agent.clone(), kind))
        };
        // Each store carries its own published reorder bound.
        let reorder = |path: &str| {
            matcher
                .classify(&normalize(path))
                .map(|(store, _)| store.creation_reorder_ms)
        };
        assert_eq!(
            reorder("/home/u/.claude/projects/p/s.jsonl"),
            Some(REORDER_MS)
        );
        assert_eq!(
            reorder("/home/u/.cursor/projects/p/agent-transcripts/t.txt"),
            Some(250)
        );
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
            creation_reorder_ms: REORDER_MS,
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
            creation_reorder_ms: REORDER_MS,
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

    /// A row that leaves the record stays with the file, with its
    /// operations and times: the evidence of a write is not lost to make
    /// room. A process that leaves twice is one entry; beyond the bound,
    /// what leaves is counted.
    #[test]
    fn a_row_that_leaves_is_kept_with_its_file() {
        let (mut table, counters) = new_table();
        let path = "/home/u/.claude/projects/p/s.jsonl";
        put(
            &mut table,
            &counters,
            &op(path, ops::CREATE | ops::WRITE, 10, 500, 2_000),
        );
        // The writer whose row will leave first.
        put(
            &mut table,
            &counters,
            &op(path, ops::WRITE | ops::TRUNCATE, 99, 900, 2_050),
        );
        for (i, pid) in (11..=13u32).enumerate() {
            put(
                &mut table,
                &counters,
                &op(path, ops::WRITE, pid, 500, 2_100 + i as u64),
            );
        }
        let rows = table.rows_since(0);
        assert_eq!(rows[0].rows_evicted, 1);
        assert_eq!(rows[0].evicted_rows.len(), 1);
        let left = &rows[0].evicted_rows[0];
        assert_eq!(left.writer.pid, 99);
        assert_eq!(left.writer.started_at_ms, Some(900));
        assert_eq!(left.ops, ops::WRITE | ops::TRUNCATE);
        assert_eq!((left.first_ms, left.last_ms), (2_050, 2_050));
        assert!(!rows[0].rows.iter().any(|row| row.writer.pid == 99));

        // It writes again, leaves again: one entry, its operations joined.
        put(
            &mut table,
            &counters,
            &op(path, ops::REMOVE, 99, 900, 2_200),
        );
        for (i, pid) in (20..=22u32).enumerate() {
            put(
                &mut table,
                &counters,
                &op(path, ops::WRITE, pid, 500, 2_300 + i as u64),
            );
        }
        let rows = table.rows_since(0);
        let left: Vec<&WriterRow> = rows[0]
            .evicted_rows
            .iter()
            .filter(|row| row.writer.pid == 99)
            .collect();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].ops, ops::WRITE | ops::TRUNCATE | ops::REMOVE);
        assert_eq!((left[0].first_ms, left[0].last_ms), (2_050, 2_200));

        // Beyond the bound: the first ones stay, the others are counted.
        for pid in 100..(100 + 2 * MAX_EVICTED_ROWS_PER_FILE as u32) {
            put(
                &mut table,
                &counters,
                &op(path, ops::WRITE, pid, 500, 3_000 + u64::from(pid)),
            );
        }
        let rows = table.rows_since(0);
        assert_eq!(rows[0].evicted_rows.len(), MAX_EVICTED_ROWS_PER_FILE);
        assert!(rows[0].evicted_rows.iter().any(|row| row.writer.pid == 99));
        assert!(rows[0].evicted_rows_dropped > 0);
        assert_eq!(
            counters.evicted_rows_dropped.load(Ordering::Relaxed),
            rows[0].evicted_rows_dropped
        );
    }

    /// A record that leaves the table to make room is returned as a
    /// tombstone, with its rows and the rows that left it, from the
    /// sequence number of its leaving, until a reader of the instance asks
    /// past it. Beyond the bound the oldest goes unread, and the reply says
    /// how far tombstones were dropped.
    #[test]
    fn a_record_that_leaves_the_table_is_returned_as_a_tombstone() {
        let (mut table, counters) = new_table();
        let first = "/home/u/.claude/projects/p/first.jsonl";
        put(
            &mut table,
            &counters,
            &op(first, ops::CREATE | ops::WRITE, 10, 500, 2_000),
        );
        put(
            &mut table,
            &counters,
            &op(first, ops::WRITE, 66, 600, 2_010),
        );
        table.take_dirty();
        let before = table.seq;
        for i in 0..MAX_FILES as u64 {
            let path = format!("/home/u/.claude/projects/p/f{i}.jsonl");
            put(
                &mut table,
                &counters,
                &op(&path, ops::CREATE, 10, 500, 3_000 + i),
            );
        }
        assert!(!table.files.contains_key(&normalize(first)));
        let tombstones = table.tombstones_since(before);
        assert_eq!(tombstones.len(), 1);
        let gone = &tombstones[0];
        assert_eq!(gone.file.path, first);
        assert!(gone.changed_seq > before);
        let pids: Vec<u32> = gone.file.rows.iter().map(|row| row.writer.pid).collect();
        assert_eq!(pids, vec![10, 66]);
        assert!(gone.file.creation.is_some());
        // Already read past: not returned again.
        assert!(table.tombstones_since(gone.changed_seq).is_empty());
        assert_eq!(table.tombstones_pruned_through, 0);

        // A reader asks past it: it is dropped, and the reply says so.
        table.rows_acked = gone.changed_seq;
        table.prune_tombstones(&counters);
        assert!(table.tombstones.is_empty());
        assert_eq!(table.tombstones_pruned_through, gone.changed_seq);
        assert_eq!(counters.tombstones_dropped.load(Ordering::Relaxed), 0);

        // Nobody reads: beyond the bound the oldest is dropped unread.
        let (mut table, counters) = new_table();
        for i in 0..(MAX_FILES + MAX_TOMBSTONES + 1) as u64 {
            let path = format!("/home/u/.claude/projects/p/g{i}.jsonl");
            put(
                &mut table,
                &counters,
                &op(&path, ops::CREATE, 10, 500, 3_000 + i),
            );
            table.take_dirty();
        }
        assert_eq!(table.tombstones.len(), MAX_TOMBSTONES);
        assert_eq!(counters.tombstones_dropped.load(Ordering::Relaxed), 1);
        assert!(table.tombstones_pruned_through > 0);
        assert!(table
            .tombstones
            .iter()
            .all(|tombstone| tombstone.changed_seq > table.tombstones_pruned_through));
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
            &op(path, ops::CREATE, 10, 500, 2_001 + REORDER_MS),
        );
        assert_eq!(table.rows_since(0)[0].creation, None);

        // The bound is the store's: a shorter one refuses a creation the
        // longer one takes, and 0 takes none delivered late.
        let (mut table, counters) = new_table();
        put_with(
            &mut table,
            &counters,
            &op(path, ops::WRITE, 10, 500, 2_000),
            100,
        );
        put_with(
            &mut table,
            &counters,
            &op(path, ops::CREATE, 10, 500, 2_101),
            100,
        );
        assert_eq!(table.rows_since(0)[0].creation, None);
        let (mut table, counters) = new_table();
        put_with(
            &mut table,
            &counters,
            &op(path, ops::WRITE, 10, 500, 2_000),
            100,
        );
        put_with(
            &mut table,
            &counters,
            &op(path, ops::CREATE, 10, 500, 2_100),
            100,
        );
        assert!(table.rows_since(0)[0].creation.is_some());
        let (mut table, counters) = new_table();
        put_with(
            &mut table,
            &counters,
            &op(path, ops::WRITE, 10, 500, 2_000),
            0,
        );
        put_with(
            &mut table,
            &counters,
            &op(path, ops::CREATE, 10, 500, 2_000),
            0,
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
        let before = rows_since("", 0).expect("the record is free");
        assert!(!before.configured);
        assert!(before.files.is_empty());

        configure(&[spec("/tmp/sw-test/.claude")]);
        // Publishing wakes the reader; drain that wake-up first.
        assert!(wait_dirty(Duration::from_millis(200)));
        assert!(!wait_dirty(Duration::from_millis(20)));
        let configured = rows_since("", 0).expect("the record is free");
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
        let rows = rows_since("", 0).expect("the record is free");
        assert_eq!(rows.files.len(), 1);
        assert_eq!(rows.files_recorded, 1);

        // A dropped-event report reaches the published record.
        note_lost(7_000);
        let rows = rows_since("", 0).expect("the record is free");
        assert_eq!(rows.lost_signals, 1);
        assert_eq!(rows.last_lost_ms, Some(7_000));

        // Published again: another instance, an empty record.
        configure(&[spec("/tmp/sw-test/.claude")]);
        let again = rows_since("", 0).expect("the record is free");
        assert_ne!(again.instance, configured.instance);
        assert!(again.files.is_empty());
        assert_eq!(again.lost_signals, 0);
        clear();
        assert!(!rows_since("", 0).expect("the record is free").configured);
    }

    /// A publication is withdrawn by the generation it was given: the one a
    /// later publication replaced withdraws nothing, and the record keeps
    /// its instance.
    #[test]
    #[serial_test::serial(store_writers)]
    fn a_replaced_publication_withdraws_nothing() {
        clear();
        assert_eq!(stores_generation(), 0);
        let first = configure(&[spec("/tmp/sw-first/.claude")]);
        let second = configure(&[spec("/tmp/sw-second/.claude")]);
        assert_ne!(first, second);
        assert_eq!(stores_generation(), second);
        let instance = rows_since("", 0).expect("the record is free").instance;

        assert!(!clear_if(first));
        assert!(is_configured());
        assert_eq!(stores_generation(), second);
        assert!(classify("/tmp/sw-second/.claude/projects/p/s.jsonl").is_some());
        assert_eq!(
            rows_since("", 0).expect("the record is free").instance,
            instance
        );

        assert!(clear_if(second));
        assert!(!is_configured());
        assert_eq!(stores_generation(), 0);
        assert_ne!(
            rows_since("", 0).expect("the record is free").instance,
            instance
        );
        // Nothing in place is no publication to withdraw.
        assert!(!clear_if(0));
        assert!(!clear_if(second));
    }

    /// A file monitor that was given no home publishes that, not an empty
    /// set of stores: nothing is recorded and the sensor's state says why.
    #[test]
    #[serial_test::serial(store_writers)]
    fn stores_that_could_not_be_resolved_are_published_as_such() {
        clear();
        assert!(!stores_unresolved());
        assert!(!sensor().stores_unresolved);

        let generation = configure_unresolved();
        assert!(stores_unresolved());
        assert!(!is_configured());
        assert!(sensor().stores_unresolved);
        assert!(!rows_since("", 0).expect("the record is free").configured);
        record(&op(
            "/tmp/sw-test/.claude/projects/p/s.jsonl",
            ops::CREATE,
            10,
            500,
            2_000,
        ));
        assert!(rows_since("", 0)
            .expect("the record is free")
            .files
            .is_empty());

        // Stores published afterwards replace it; an empty publication is
        // not "unresolved".
        configure(&[spec("/tmp/sw-test/.claude")]);
        assert!(!stores_unresolved());
        assert!(!clear_if(generation));
        configure(&[]);
        assert!(!stores_unresolved());
        assert!(!sensor().stores_unresolved);
        let generation = configure_unresolved();
        assert!(clear_if(generation));
        assert!(!stores_unresolved());
    }

    /// The thread a sensor registered is woken when the stores are published
    /// and when they are withdrawn.
    #[test]
    #[serial_test::serial(store_writers)]
    fn the_registered_thread_is_woken_when_the_stores_change() {
        clear();
        let (ready, is_ready) = std::sync::mpsc::channel::<()>();
        let (woken, was_woken) = std::sync::mpsc::channel::<bool>();
        let listener = std::thread::spawn(move || {
            wake_on_store_change(std::thread::current());
            ready.send(()).expect("the test waits");
            for expected in [true, false] {
                let deadline = Instant::now() + Duration::from_secs(10);
                while is_configured() != expected && Instant::now() < deadline {
                    std::thread::park_timeout(Duration::from_secs(10));
                }
                woken
                    .send(is_configured() == expected)
                    .expect("the test waits");
            }
        });
        is_ready
            .recv_timeout(Duration::from_secs(10))
            .expect("the listener registered");
        let started = Instant::now();
        // Let the listener park, then publish from this thread.
        std::thread::sleep(Duration::from_millis(50));
        let generation = configure(&[spec("/tmp/sw-test/.claude")]);
        assert!(was_woken
            .recv_timeout(Duration::from_secs(10))
            .expect("woken by the publication"));
        std::thread::sleep(Duration::from_millis(50));
        assert!(clear_if(generation));
        assert!(was_woken
            .recv_timeout(Duration::from_secs(10))
            .expect("woken by the withdrawal"));
        // Woken, not timed out.
        assert!(started.elapsed() < Duration::from_secs(8));
        listener.join().expect("listener thread");
        LISTENER.store(None);
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
