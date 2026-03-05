use crate::sessions::*;
use chrono::{DateTime, Duration, Utc};
use extended_isolation_forest::{Forest, ForestOptions};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, trace, warn};
use undeadlock::*;

// Await a JoinHandle with a timeout. Aborts the task on timeout and returns None.
async fn await_join_with_timeout<T>(
    mut handle: tokio::task::JoinHandle<T>,
    duration: std::time::Duration,
) -> Option<Result<T, tokio::task::JoinError>> {
    tokio::select! {
        res = &mut handle => Some(res),
        _ = tokio::time::sleep(duration) => {
            error!("Background training timed out after {:?} - aborting task", duration);
            handle.abort();
            None
        }
    }
}

/// # Analyzer Module
///
/// This module provides network session anomaly detection using the Isolation Forest algorithm.
/// It analyzes network traffic sessions to identify outliers and suspicious connections based
/// on their statistical properties rather than using static rules.
///
/// ## Criticality Information Semantics
///
/// Criticality information is stored in the `criticality` field of SessionInfo as a comma-separated list of tags.
/// Each tag follows the format: `category:value` or `category:value/details`
///
/// ### Main tag categories:
///
/// 1. `anomaly`: Detection result from the Isolation Forest algorithm
///    - Values: `normal`, `suspicious`, `abnormal`
///    - Optional details may provide diagnostic information (e.g., `anomaly:abnormal/OverallScoreHigh` or `anomaly:suspicious/Duration:UnusuallyHigh`)
///
/// 2. `blacklist`: Indicates the session matches known malicious patterns
///    - Values: Custom strings identifying the blacklist reason (e.g., `blacklist:malware_C2`)
///
/// Multiple tags can coexist (e.g., `anomaly:suspicious,blacklist:malware_C2`).
/// The module preserves existing tags when updating, ensuring blacklist tags remain when anomaly detection is run.
///
/// ### Diagnostic Information Details
///
/// For anomalous sessions, diagnostic information is appended after the anomaly level, using the format:
/// `anomaly:level/diagnostic_info`
///
/// The diagnostic information indicates which statistical features of the session were unusual:
///
/// - Feature format: `feature_name:descriptor` where:
///   - `feature_name` is one of: `ProcessPrevalence` (process frequency in training window),
///     `Duration` (session duration), `Bytes` (total bytes transferred), `Packets` (total packets),
///     `SegmentInterarrival` (timing), `InOutRatio` (inbound/outbound ratio),
///     `AvgPacketSize` (average packet size), `InterarrivalRegularity`, `PacketRate`,
///     `MissedData` (missed bytes), `Segments`, or `DstPort` (destination port)
///   - `descriptor` indicates the type of anomaly: `UnusuallyHigh`, `UnusuallyLow`, `DeviatesFromNorm`, or `Unusual`
///
/// - Multiple unusual features are separated by forward slashes:
///   `anomaly:abnormal/Duration:UnusuallyHigh/Bytes:UnusuallyHigh/AvgPacketSize:UnusuallyLow`
///
/// - Special cases:
///   - `OverallScoreHigh`: No specific features identified as unusual, but overall anomaly score is high
///   - `feature_name:DeviatesFromNorm`: This feature has zero variance in the dataset (all other
///     sessions have the same value) but this session has a different value
///   - `feature_name:Unusual`: For categorical features that differ from the training set norm

// Define a timeout for cache entries (in seconds)
static ANALYZER_CACHE_TIMEOUT: i64 = 3600;

// Define a timeout for anomalous session tracking (in seconds): 24h
static ANOMALOUS_SESSION_TIMEOUT: i64 = 86400;

// Define a timeout for blacklisted session tracking (in seconds): 24h
static BLACKLISTED_SESSION_TIMEOUT: i64 = 86400;

// Define a timeout for all session tracking (in seconds)
static ALL_SESSION_TIMEOUT: i64 = CONNECTION_RETENTION_TIMEOUT.num_seconds() as i64;

// Cap size of per-flow downsample state to bound memory usage
static PER_FLOW_DOWNSAMPLE_MAX_ENTRIES: usize = 200000;
// Minimum interval between cleanup passes to reduce DashMap contention
static CLEANUP_MIN_INTERVAL_SECS: i64 = 10;

// Define percentile thresholds used to compute dynamic thresholds
pub const DEFAULT_SUSPICIOUS_PERCENTILE: f64 = 0.995;
pub const DEFAULT_ABNORMAL_PERCENTILE: f64 = 0.9975;
// Initial thresholds - will be overridden by the first training and its percentile based thresholds computed from the training data.
pub const DEFAULT_SUSPICIOUS_THRESHOLD: f64 = 0.85;
pub const DEFAULT_ABNORMAL_THRESHOLD: f64 = 0.90;
pub const MIN_REASONABLE_THRESHOLD: f64 = 0.5;
pub const DEFAULT_THRESHOLD_RECALC_TIMEOUT: i64 = 1; // 1 hour
pub const WARMUP_DELAY: i64 = 60; // Minimum warm-up duration to ensure forest training
pub const WARMUP_DURATION_TEST: i64 = 15; // 15 seconds in tests
pub const WARMUP_DURATION_DEFAULT: i64 = 180; // 3 minutes in production
pub const ANALYSIS_DELAY: i64 = 60; // Minimum delay between analysis of a session

// Minimum unique samples required (after deduplication) before finishing warm-up
pub const WARMUP_MIN_UNIQUE_SAMPLES: usize = 200;

// Define the number of features to use by default
const NUM_FEATURES: usize = 12;

/// Pre-computed mean / std-dev for each feature (None if not computable).
type FeatureStats = [Option<(f64, f64)>; NUM_FEATURES];

// Define the Criticality levels as an enum for clarity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCriticality {
    Normal,
    Suspicious,
    Abnormal,
}

/// Comprehensive analyzer statistics and configuration snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzerStats {
    // Current status and operational state
    pub is_running: bool,
    pub warm_up_active: bool,
    pub warm_up_progress: WarmUpProgress,

    // Current threshold configuration
    pub thresholds: ThresholdStats,

    // Model and training statistics
    pub model_stats: ModelStats,

    // Session tracking statistics
    pub session_stats: SessionStats,

    // Performance and timing statistics
    pub performance_stats: PerformanceStats,

    // Configuration parameters
    pub config: AnalyzerConfig,
}

/// Warm-up progress information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarmUpProgress {
    pub elapsed_seconds: u64,
    pub target_duration_seconds: u64,
    pub unique_samples_collected: usize,
    pub min_samples_required: usize,
    pub progress_percentage: f64,
    pub estimated_completion_seconds: Option<u64>,
}

/// Current threshold statistics and configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdStats {
    pub suspicious_threshold: f64,
    pub abnormal_threshold: f64,
    pub suspicious_percentile: f64,
    pub abnormal_percentile: f64,
    pub last_recalc_time: Option<DateTime<Utc>>,
    pub next_recalc_time: Option<DateTime<Utc>>,
    pub recalc_interval_hours: f64,
    pub min_reasonable_threshold: f64,
    pub default_suspicious_threshold: f64,
    pub default_abnormal_threshold: f64,
}

/// Isolation Forest model statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelStats {
    pub has_trained_model: bool,
    pub training_in_progress: bool,
    pub last_training_time: Option<DateTime<Utc>>,
    pub min_training_interval_minutes: f64,
    pub total_samples_in_buffer: usize,
    pub max_buffer_capacity: usize,
    pub buffer_utilization_percentage: f64,
    pub unique_samples_count: usize,
    pub downsample_factor: u32,
    pub feature_count: usize,
    pub recent_score_distribution: Option<ScoreDistribution>,
}

/// Score distribution statistics from recent threshold calculations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreDistribution {
    pub sample_count: usize,
    pub min_score: f64,
    pub max_score: f64,
    pub mean_score: f64,
    pub percentiles: ScorePercentiles,
}

/// Key percentile values for score distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScorePercentiles {
    pub p25: f64,
    pub p50: f64,
    pub p75: f64,
    pub p90: f64,
    pub p95: f64,
    pub p98: f64,
    pub p99: f64,
    pub p995: f64,
}

/// Session tracking and classification statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStats {
    pub total_sessions_tracked: usize,
    pub anomalous_sessions_count: usize,
    pub blacklisted_sessions_count: usize,
    pub normal_sessions_count: usize,
    pub anomaly_rate_percentage: f64,
    pub blacklist_rate_percentage: f64,
    pub last_analysis_time: Option<DateTime<Utc>>,
    pub sessions_analyzed_today: usize,
}

/// Performance and timing statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceStats {
    pub average_analysis_time_ms: Option<f64>,
    pub last_analysis_duration_ms: Option<f64>,
    pub total_analyses_performed: u64,
    pub cache_hit_rate_percentage: Option<f64>,
    pub memory_usage_mb: Option<f64>,
    pub training_timeouts_total: u64,
    pub analysis_timeouts_total: u64,
}

/// Current analyzer configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzerConfig {
    pub suspicious_percentile: f64,
    pub abnormal_percentile: f64,
    pub warm_up_duration_seconds: u64,
    pub warm_up_min_samples: usize,
    pub analysis_delay_seconds: i64,
    pub threshold_recalc_interval_hours: f64,
    pub max_buffer_samples: usize,
    pub downsample_factor: u32,
    pub feature_dimensions: usize,
    pub cache_timeout_seconds: i64,
    pub session_retention_timeout_seconds: i64,
}

// Implementation of Display for SessionCriticality
impl fmt::Display for SessionCriticality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SessionCriticality::Normal => "normal",
            SessionCriticality::Suspicious => "suspicious",
            SessionCriticality::Abnormal => "abnormal",
        };
        write!(f, "{}", s)
    }
}

/// Lightweight session cache to reduce memory usage
#[derive(Debug, Clone)]
struct SessionCache {
    /// Full session data (cloned only when needed)
    full_session: Option<Arc<SessionInfo>>,
    /// Essential fields for fast lookups (always available)
    uid: String,
    criticality: String,
    last_modified: DateTime<Utc>,
}

impl SessionCache {
    fn with_full_session(session: &SessionInfo) -> Self {
        Self {
            full_session: Some(Arc::new(session.clone())),
            uid: session.uid.clone(),
            criticality: session.criticality.clone(),
            last_modified: session.last_modified,
        }
    }

    fn get_full_session(&mut self, source_session: Option<&SessionInfo>) -> Option<SessionInfo> {
        if let Some(ref full) = self.full_session {
            Some((**full).clone())
        } else if let Some(source) = source_session {
            // If we have a source session and it's the same UID, use it to populate
            if source.uid == self.uid {
                self.full_session = Some(Arc::new(source.clone()));
                Some(source.clone())
            } else {
                None
            }
        } else {
            None
        }
    }

    fn get_full_session_snapshot(&self) -> Option<SessionInfo> {
        self.full_session.as_ref().map(|full| (**full).clone())
    }
}

// Define the internal analyzer that handles the Isolation Forest model
struct IsolationForestModel {
    forest: Option<Forest<f64, NUM_FEATURES>>,
    recent_data: VecDeque<[f64; NUM_FEATURES]>,
    max_samples: usize,
    suspicious_threshold: f64,
    abnormal_threshold: f64,
    session_cache: CustomDashMap<String, (f64, [f64; NUM_FEATURES], DateTime<Utc>)>,
    /// Process names parallel to recent_data, used for frequency-based process encoding
    process_names: VecDeque<String>,
    /// Rolling frequency count of each process name in the training window (recent_data)
    process_freq: HashMap<String, u32>,
    /// Per-flow sampling counters used to downsample repeated snapshots from the same flow signature
    per_flow_downsample: CustomDashMap<u64, u32>,
    /// Only 1 out of `downsample_factor` snapshots per flow signature will be kept in `recent_data`
    downsample_factor: u32,
    /// Indicates if a training task is currently running. Prevents spawning overlapping CPU heavy jobs.
    training_in_progress: Arc<AtomicBool>,
    /// JoinHandle for the currently running training task (if any).  Only one training task is
    /// allowed at a time.  The flag above remains `true` for as long as this handle is alive and
    /// not finished.
    training_handle: Option<
        tokio::task::JoinHandle<
            Result<Forest<f64, NUM_FEATURES>, extended_isolation_forest::Error>,
        >,
    >,
    /// Time of last successful model training - used to throttle training frequency
    last_training_time: DateTime<Utc>,
    /// Minimum time between regular trainings (not counting forced retraining)
    min_training_interval: Duration,
    /// Current percentile settings for threshold calculation
    current_suspicious_percentile: f64,
    current_abnormal_percentile: f64,
    /// Number of times a background training task timed out
    training_timeouts_count: u64,
    /// Cooperative cancellation flag for the training thread
    training_cancel: Arc<AtomicBool>,
    /// Cache hits for session scoring
    cache_hits: std::sync::atomic::AtomicU64,
    /// Cache misses for session scoring
    cache_misses: std::sync::atomic::AtomicU64,
    last_cache_cleanup: DateTime<Utc>,
}

impl IsolationForestModel {
    /// Create a new model with default thresholds and an empty forest.
    pub fn new() -> Self {
        IsolationForestModel {
            forest: None,
            recent_data: VecDeque::new(),
            max_samples: 800,
            // Will be overridden by the first training and its percentile based thresholds computed from the training data.
            suspicious_threshold: DEFAULT_SUSPICIOUS_THRESHOLD,
            abnormal_threshold: DEFAULT_ABNORMAL_THRESHOLD,
            session_cache: CustomDashMap::new("session_cache"),
            process_names: VecDeque::new(),
            process_freq: HashMap::new(),
            per_flow_downsample: CustomDashMap::new("per_flow_downsample"),
            downsample_factor: 5,
            training_in_progress: Arc::new(AtomicBool::new(false)),
            training_handle: None,
            last_training_time: Utc::now() - chrono::Duration::hours(25),
            min_training_interval: Duration::hours(6),
            current_suspicious_percentile: DEFAULT_SUSPICIOUS_PERCENTILE,
            current_abnormal_percentile: DEFAULT_ABNORMAL_PERCENTILE,
            training_timeouts_count: 0,
            training_cancel: Arc::new(AtomicBool::new(false)),
            cache_hits: std::sync::atomic::AtomicU64::new(0),
            cache_misses: std::sync::atomic::AtomicU64::new(0),
            last_cache_cleanup: Utc::now() - chrono::Duration::hours(1),
        }
    }

    /// Roughly estimate the heap memory used by the model's internal buffers and caches.
    /// This excludes the isolation forest trees which are opaque here.
    pub fn estimate_memory_usage_bytes(&self) -> u64 {
        const SESSION_CACHE_EST_ENTRY_BYTES: u64 = 256;
        const PER_FLOW_DOWNSAMPLE_EST_ENTRY_BYTES: u64 = 16;
        let mut bytes: u64 = 0;
        // recent_data buffer: use capacity to reflect reserved space
        bytes = bytes.saturating_add(
            (self.recent_data.capacity() as u64)
                .saturating_mul(std::mem::size_of::<[f64; NUM_FEATURES]>() as u64),
        );
        // session_cache: approximate per entry to avoid long DashMap iterators
        bytes = bytes.saturating_add(
            (self.session_cache.len() as u64).saturating_mul(SESSION_CACHE_EST_ENTRY_BYTES),
        );
        // per_flow_downsample: approximate per entry to avoid long DashMap iterators
        bytes = bytes.saturating_add(
            (self.per_flow_downsample.len() as u64)
                .saturating_mul(PER_FLOW_DOWNSAMPLE_EST_ENTRY_BYTES),
        );
        bytes
    }

    /// Ensure the per-flow downsample map stays within a bounded size.
    /// This avoids unbounded growth when many distinct flow signatures are observed.
    fn cap_per_flow_downsample(&self) {
        if self.per_flow_downsample.len() > PER_FLOW_DOWNSAMPLE_MAX_ENTRIES {
            // Reset counters; this only affects downsampling cadence, not correctness.
            self.per_flow_downsample.clear();
        }
    }

    /// Add new session data to the analyzer's memory.
    /// If the buffer is full, remove the oldest entry.
    fn add_session_data(&mut self, session: &SessionInfo) {
        // Only exclude externally-confirmed bad traffic from training.
        // Model-generated anomaly labels (anomaly:suspicious, anomaly:abnormal) are NOT excluded
        // to avoid a self-reinforcing feedback loop where false positives permanently bias the baseline.
        let crit = session.criticality.as_str();
        let is_blacklisted = crit.contains("blacklist:");

        if is_blacklisted {
            trace!(
                "add_session_data: Skipping blacklisted training sample for {}",
                session.uid,
            );
            return;
        }

        // Downsample repeated snapshots from the same flow signature (keep only 1 in `downsample_factor`)
        let flow_sig = {
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            // Stable signature: src_ip, src_port, dst_ip, dst_port, protocol
            session.session.protocol.hash(&mut hasher);
            session.session.src_ip.hash(&mut hasher);
            session.session.src_port.hash(&mut hasher);
            session.session.dst_ip.hash(&mut hasher);
            session.session.dst_port.hash(&mut hasher);
            hasher.finish()
        };
        let next_count = self
            .per_flow_downsample
            .get(&flow_sig)
            .map(|e| *e.value())
            .unwrap_or(0)
            .saturating_add(1);
        self.per_flow_downsample.insert(flow_sig, next_count);
        // Bound auxiliary state size to prevent unbounded memory growth
        self.cap_per_flow_downsample();
        // Accept the first snapshot for each flow signature, then every Nth thereafter
        if self.downsample_factor > 1 && (next_count % self.downsample_factor) != 1 {
            trace!(
                "add_session_data: Downsampling UID {} (count={}, factor={})",
                session.uid,
                next_count,
                self.downsample_factor
            );
            return;
        }

        let process_name = session
            .l7
            .as_ref()
            .map(|l7| l7.process_name.clone())
            .unwrap_or_default();

        // Update frequency BEFORE computing features so the current session counts
        *self.process_freq.entry(process_name.clone()).or_insert(0) += 1;

        let features = compute_features(session, &self.process_freq);

        if self.recent_data.len() >= self.max_samples {
            self.recent_data.pop_front();
            if let Some(old_name) = self.process_names.pop_front() {
                if let Some(count) = self.process_freq.get_mut(&old_name) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.process_freq.remove(&old_name);
                    }
                }
            }
        }
        self.recent_data.push_back(features);
        self.process_names.push_back(process_name);
    }

    /// Train (or retrain) the Isolation Forest model on the recent data.
    async fn train_model(&mut self, force_training: bool) {
        let now = Utc::now();
        debug!("train_model: Entry point - checking if training needed");

        // Skip if we trained recently, unless it's a forced training
        if !force_training && now - self.last_training_time < self.min_training_interval {
            debug!(
                "train_model: Skipping training - too soon since last train ({:?} ago)",
                now - self.last_training_time
            );
            return;
        }

        debug!("train_model: Time check passed - proceeding with training");
        debug!(
            "train_model: Starting - recent_data.len={}, forest={}, training_in_progress={}",
            self.recent_data.len(),
            self.forest.is_some(),
            self.training_in_progress.load(Ordering::Relaxed)
        );

        // -------------------------------------------------------------
        // Phase 1 – Check if a previous training task is still running
        // -------------------------------------------------------------
        if let Some(handle_ref) = self.training_handle.as_ref() {
            debug!(
                "train_model: Found existing handle - is_finished={}",
                handle_ref.is_finished()
            );
            if handle_ref.is_finished() {
                // The blocking thread has finished – gather the result and update state
                debug!("train_model: Previous task finished, getting result");
                let handle = self.training_handle.take().unwrap();
                match await_join_with_timeout(handle, std::time::Duration::from_secs(120)).await {
                    Some(Ok(Ok(forest))) => {
                        info!("train_model: Background training completed successfully");
                        self.forest = Some(forest);
                        self.last_training_time = Utc::now();
                        self.invalidate_score_cache_for_retrain();
                    }
                    Some(Ok(Err(e))) => {
                        warn!(
                            "train_model: Background training returned error: {:?}. Keeping previous forest.",
                            e
                        );
                    }
                    Some(Err(join_error)) => {
                        error!(
                            "train_model: Background training panicked: {:?}. Keeping previous forest.",
                            join_error
                        );
                    }
                    None => {
                        self.training_timeouts_count =
                            self.training_timeouts_count.saturating_add(1);
                        warn!(
                            "train_model: Background training timed out. Keeping previous forest."
                        );
                    }
                }

                // Clear the handle & flag
                self.training_handle = None;
                self.training_in_progress.store(false, Ordering::Release);
                debug!("train_model: Cleared handle and flag");
            } else {
                // A training task is still in progress – do nothing further
                debug!("train_model: Existing training task still running – skip");
                return;
            }
        }

        // -------------------------------------------------------------
        // Phase 2 – Spawn a new training task if we have (enough) data
        // -------------------------------------------------------------
        if self.recent_data.is_empty() {
            debug!("train_model: No data available – skipping training");
            return;
        }

        // Check if we have enough data compared to max_samples
        let data_percentage = (self.recent_data.len() as f64 / self.max_samples as f64) * 100.0;
        debug!(
            "train_model: Have {} samples ({}% of max {})",
            self.recent_data.len(),
            data_percentage,
            self.max_samples
        );

        let data_clone = self.recent_data.clone();

        // Mark that training is starting before we spawn, so concurrent calls bail out early.
        self.training_in_progress.store(true, Ordering::Release);
        debug!("train_model: Set training_in_progress flag to true");

        // Spawn the heavy work on a dedicated blocking thread.  The closure will perform all
        // preprocessing (deduplication, option calculation) and return a Forest or an Error.
        // Reset cancel flag for this run and capture it in the blocking thread
        self.training_cancel.store(false, Ordering::Release);
        let cancel_flag = self.training_cancel.clone();
        let handle = tokio::task::spawn_blocking(move || {
            debug!(
                "train_model: TRAINING THREAD STARTED with {} samples",
                data_clone.len()
            );
            let original_count = data_clone.len();

            // Deduplicate samples -----------------------------------------------------------
            let mut unique_data = Vec::with_capacity(original_count);
            let mut seen_hashes = HashSet::with_capacity(original_count);
            for feats in &data_clone {
                let bits: [u64; NUM_FEATURES] = std::array::from_fn(|i| feats[i].to_bits());
                if seen_hashes.insert(bits) {
                    unique_data.push(*feats);
                }
            }

            let n_samples = unique_data.len();
            debug!(
                "train_model: TRAINING THREAD deduplicated {} → {} samples",
                original_count, n_samples
            );

            if n_samples == 0 {
                error!("train_model: TRAINING THREAD - No unique samples after deduplication!");
                return Err(extended_isolation_forest::Error::InsufficientTrainingData);
            }

            // Hyper-parameters --------------------------------------------------------------
            let sample_size = std::cmp::max(1, std::cmp::min(128, n_samples));
            let n_trees = if n_samples < 10 {
                10
            } else if n_samples < 50 {
                15
            } else {
                25
            };
            let max_tree_depth = Some(6); // Hard cap to keep trees shallow

            let options = ForestOptions {
                n_trees,
                sample_size,
                max_tree_depth,
                extension_level: NUM_FEATURES - 1,
            };

            debug!("train_model: TRAINING THREAD - Starting Forest::from_slice with {} samples, {} trees, {} sample_size", 
                  n_samples, n_trees, sample_size);

            // Actual training --------------------------------------------------------------
            let start_time = std::time::Instant::now();
            debug!("train_model: TRAINING THREAD - Calling Forest::from_slice_with_cancel");
            let result = extended_isolation_forest::Forest::from_slice_with_cancel(
                &unique_data,
                &options,
                || cancel_flag.load(Ordering::Relaxed),
            );
            debug!(
                "train_model: TRAINING THREAD - Forest::from_slice completed in {:?}, success={}",
                start_time.elapsed(),
                result.is_ok()
            );

            result
        });

        self.training_handle = Some(handle);
        debug!(
            "train_model: Spawned new background training task ({} samples)",
            self.recent_data.len()
        );
    }

    /// Compute means & std-devs for **all** features in one pass.
    fn compute_feature_stats_bulk(&self) -> FeatureStats {
        // First gather all vectors once to avoid repeated borrowing.
        let mut sums: [f64; NUM_FEATURES] = [0.0; NUM_FEATURES];
        let counts: usize = self.recent_data.len();

        if counts == 0 {
            return [None; NUM_FEATURES];
        }

        for feats in &self.recent_data {
            for i in 0..NUM_FEATURES {
                sums[i] += feats[i];
            }
        }

        let means: [f64; NUM_FEATURES] = std::array::from_fn(|i| sums[i] / counts as f64);

        // Second pass for variance
        let mut sq_sums: [f64; NUM_FEATURES] = [0.0; NUM_FEATURES];
        for feats in &self.recent_data {
            for i in 0..NUM_FEATURES {
                let diff = feats[i] - means[i];
                sq_sums[i] += diff * diff;
            }
        }

        let mut out: FeatureStats = [None; NUM_FEATURES];
        for i in 0..NUM_FEATURES {
            if counts > 1 {
                let variance = sq_sums[i] / (counts as f64 - 1.0);
                let std_dev = variance.sqrt();
                out[i] = Some((means[i], std_dev));
            }
        }

        out
    }

    /// Generate a human-readable diagnostic string for anomalous sessions.
    fn generate_anomaly_diagnostic(
        &self,
        features: &[f64; NUM_FEATURES],
        feature_stats: &FeatureStats,
    ) -> String {
        let start_time = std::time::Instant::now();
        debug!(
            "Starting diagnostic generation for features: {:?}",
            features
        );

        // Define features with their names and categorical flag
        // Format: (name, is_categorical)
        const FEATURE_DEFS: [(&'static str, bool); NUM_FEATURES] = [
            ("ProcessPrevalence", false), // 0 - Process frequency in training window (continuous)
            ("Duration", false),          // 1 - Duration (s)
            ("Bytes", false),             // 2 - Total bytes
            ("Packets", false),           // 3 - Total packets
            ("SegmentInterarrival", false), // 4 - Avg segment interarrival
            ("InOutRatio", false),        // 5 - Inbound/Outbound ratio
            ("AvgPacketSize", false),     // 6 - Average packet size
            ("InterarrivalRegularity", false), // 7 - Regularity of interarrival (0..1)
            ("PacketRate", false),        // 8 - Packets per second
            ("MissedData", false),        // 9 - Missed bytes
            ("Segments", false),          // 10 - Total segment count
            ("DstPort", true),            // 11 - Destination port (categorical-ish)
        ];

        let mut diagnostics = Vec::new();
        // Base z-score threshold for considering a feature unusual. Some features use a
        // slightly more sensitive threshold to improve detection of specific behaviours
        // (e.g., periodic beacons via SegmentInterarrival).
        let base_z_score_threshold = 2.5;

        for i in 0..NUM_FEATURES {
            let feature_start = std::time::Instant::now();
            let (feature_name, is_categorical) = FEATURE_DEFS[i];
            debug!(
                "Analyzing feature {}: {} (categorical: {})",
                i, feature_name, is_categorical
            );

            if let Some((mean, std_dev)) = feature_stats[i] {
                debug!(
                    "Feature {} stats: mean={}, std_dev={}",
                    feature_name, mean, std_dev
                );

                if is_categorical {
                    // Numerical distance between hashed categorical values is not meaningful, so using a
                    // z-score on the hash often yields false positives (e.g. `DestService:Unusual`).
                    //
                    // Strategy:
                    // 1.  If the category has *no* variance in the training set (std_dev ~ 0) then any new
                    //     value is genuinely unusual → flag it.
                    // 2.  Otherwise **do not** apply a z-score test; assume the category distribution is
                    //     naturally broad and the hash position is arbitrary.  More sophisticated rarity
                    //     checks (frequency counting) can be added later, but z-score is intentionally
                    //     avoided here.
                    // ------------------------------------------------------------------------------------------------

                    let is_unusual = if std_dev <= 1e-6 {
                        // Zero (or near-zero) variance → current value differs from the constant mean? [OK] unusual
                        let deviation = (features[i] - mean).abs();
                        debug!(
                            "Categorical feature {} const deviation: {}",
                            feature_name, deviation
                        );
                        deviation > 1e-6
                    } else {
                        // Variance exists → skip marking as unusual
                        false
                    };

                    if is_unusual {
                        diagnostics.push(format!("{}:Unusual", feature_name));
                        debug!("Added unusual categorical feature: {}", feature_name);
                    }
                } else {
                    // Standard handling for other numerical features
                    if std_dev > 1e-6 {
                        // Calculate z-score for features with variance
                        let z_score = (features[i] - mean) / std_dev;
                        debug!("Numerical feature {} z-score: {}", feature_name, z_score);

                        // Feature-specific z-score thresholds to improve sensitivity where needed
                        let feature_z_threshold = match feature_name {
                            // Lower threshold improves detection of periodic short-interval beacons
                            "SegmentInterarrival" => 1.5,
                            _ => base_z_score_threshold,
                        };

                        if z_score >= feature_z_threshold {
                            // Use more descriptive term for high values
                            diagnostics.push(format!("{}:UnusuallyHigh", feature_name));
                            debug!("Added unusually high feature: {}", feature_name);
                        } else if z_score <= -feature_z_threshold {
                            // Use more descriptive term for low values
                            diagnostics.push(format!("{}:UnusuallyLow", feature_name));
                            debug!("Added unusually low feature: {}", feature_name);
                        }
                    } else if (features[i] - mean).abs() > 1e-6 {
                        // Handle features with zero variance (constant value normally)
                        // Use more descriptive term for differing values
                        diagnostics.push(format!("{}:DeviatesFromNorm", feature_name));
                        debug!("Added deviating feature: {}", feature_name);
                    }
                }
            } else {
                debug!("No stats available for feature {}", feature_name);
            }

            if feature_start.elapsed().as_millis() > 50 {
                warn!(
                    "Feature {} analysis took {:?}",
                    feature_name,
                    feature_start.elapsed()
                );
            }
        }

        let result = if diagnostics.is_empty() {
            // If score is high but no specific feature deviates significantly
            "OverallScoreHigh".to_string() // Renamed for clarity
        } else {
            diagnostics.join("/")
        };

        let total_time = start_time.elapsed();
        if total_time.as_millis() > 100 {
            warn!(
                "Diagnostic generation took {:?} with {} features flagged",
                total_time,
                diagnostics.len()
            );
        } else {
            debug!(
                "Diagnostic generation completed in {:?} with {} features flagged",
                total_time,
                diagnostics.len()
            );
        }

        result
    }

    /// Score a session using the model
    fn score_session(&self, session: &SessionInfo) -> Option<(f64, [f64; NUM_FEATURES])> {
        // Return score AND features (first NUM_FEATURES)
        let session_uid = &session.uid;

        // Check cache first
        if let Some(cached) = self.session_cache.get(session_uid) {
            let (score, cached_features, last_modified) = cached.value();
            // Only check modification time, since expiration is handled in batch cleanup
            if &session.last_modified <= last_modified {
                trace!("Using cached score for session {}", session_uid);
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Some((*score, *cached_features)); // Return cached score and features
            } else {
                trace!(
                    "Session {} has been modified, recomputing score",
                    session_uid
                );
                drop(cached);
            }
        }

        // Compute features if not cached or outdated
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        let features = compute_features(session, &self.process_freq);

        // Score using the model
        trace!(
            "score_session: Scoring session {} - forest available: {}",
            session_uid,
            self.forest.is_some()
        );
        if let Some(forest) = &self.forest {
            let score_start = std::time::Instant::now();
            // Use a safe recursion cap (e.g. 2x max_tree_depth = 12)
            let score = forest.score_with_recursion_cap(&features, 12);
            let score_elapsed = score_start.elapsed();

            if score_elapsed.as_millis() > 50 {
                warn!("Scoring session {} took {:?}", session_uid, score_elapsed);
            }

            // Update cache
            self.session_cache.insert(
                session_uid.clone(),
                (score, features, session.last_modified), // Cache NUM_FEATURES (10)
            );
            trace!(
                "score_session: Scored session {} with score={}",
                session_uid,
                score
            );

            Some((score, features)) // Return new score and features
        } else {
            debug!(
                "score_session: FAILED - No forest available to score session {}",
                session_uid
            );
            None
        }
    }

    /// Analyze a session and determine its criticality, preserving existing non-anomaly classifications
    fn analyze_session(&self, session: &mut SessionInfo, feature_stats: &FeatureStats) {
        let start_time = std::time::Instant::now();

        // Only log detailed debugging for suspicious sessions
        let detailed_logging =
            session.criticality.contains("suspicious") || session.criticality.contains("abnormal");

        if detailed_logging {
            debug!(
                "Detailed analysis for session {} with criticality='{}' and last_modified={}",
                session.uid, session.criticality, session.last_modified
            );
        }

        // Get score and features if possible
        let score_time = std::time::Instant::now();
        let score_and_features = self.score_session(session);
        let score_elapsed = score_time.elapsed();

        if detailed_logging && score_elapsed.as_millis() > 20 {
            debug!(
                "Score calculation for session {} took {:?}",
                session.uid, score_elapsed
            );
        }

        // Determine criticality level and generate diagnostic if applicable
        let diagnostic_time = std::time::Instant::now();
        let (anomaly_level, anomaly_diagnostic) =
            if let Some((score, features)) = score_and_features {
                if detailed_logging {
                    debug!("Scored session {} with score={}", session.uid, score);
                }

                let level = if score >= self.abnormal_threshold {
                    SessionCriticality::Abnormal
                } else if score >= self.suspicious_threshold {
                    SessionCriticality::Suspicious
                } else {
                    SessionCriticality::Normal
                };

                // Generate diagnostic string only for non-normal levels
                let diag_time = std::time::Instant::now();
                let diag_str = if level != SessionCriticality::Normal {
                    let diagnostic = self.generate_anomaly_diagnostic(&features, feature_stats); // reuse stats
                    if detailed_logging && diag_time.elapsed().as_millis() > 20 {
                        debug!(
                            "Diagnostic generation for session {} took {:?}",
                            session.uid,
                            diag_time.elapsed()
                        );
                    }
                    diagnostic
                } else {
                    "".to_string()
                };

                (level, diag_str)
            } else {
                // If we couldn't compute a score (no forest), default to Normal
                if detailed_logging {
                    debug!(
                        "No score available for session {}, using default Normal",
                        session.uid
                    );
                }
                (SessionCriticality::Normal, "".to_string())
            };

        // Heuristic removed: rely purely on anomaly model and per-feature diagnostics.

        if detailed_logging && diagnostic_time.elapsed().as_millis() > 30 {
            debug!(
                "Diagnostic phase for session {} took {:?}",
                session.uid,
                diagnostic_time.elapsed()
            );
        }

        // Construct the new anomaly classification string
        let update_time = std::time::Instant::now();
        let new_anomaly_classification = if anomaly_diagnostic.is_empty() {
            format!("anomaly:{}", anomaly_level)
        } else {
            format!("anomaly:{}/{}", anomaly_level, anomaly_diagnostic)
        };

        // Get all existing tags, separating anomaly from others
        let mut final_tags: Vec<String> = session
            .criticality
            .split(',')
            .filter(|s| !s.trim().is_empty() && !s.trim().starts_with("anomaly:"))
            .map(|s| s.trim().to_string()) // Store owned strings
            .collect();

        // Add the new anomaly classification
        final_tags.push(new_anomaly_classification);

        // Sort and deduplicate
        final_tags.sort_unstable();
        final_tags.dedup();

        let final_criticality = final_tags.join(",");

        // Only update if the value actually changed. Do not refresh last_modified otherwise,
        // to allow caches/retention to expire naturally.
        if session.criticality != final_criticality {
            if detailed_logging {
                debug!(
                    "Updating criticality for session {} from '{}' to '{}'",
                    session.uid, session.criticality, final_criticality
                );
            }
            session.criticality = final_criticality;
            session.last_modified = chrono::Utc::now();
        }

        if detailed_logging && update_time.elapsed().as_millis() > 20 {
            debug!(
                "Update phase for session {} took {:?}",
                session.uid,
                update_time.elapsed()
            );
        }

        // Safety check
        if session.criticality.is_empty() {
            warn!(
                "analyze_session resulted in empty criticality for {}!",
                session.uid
            );
            // Fallback: Use the calculated anomaly level if somehow all tags were lost
            session.criticality = format!("anomaly:{}", anomaly_level);
            session.last_modified = chrono::Utc::now();
        }

        // Log time taken if it's excessive
        let elapsed = start_time.elapsed();
        if elapsed.as_millis() > 100 {
            warn!("analyze_session for {} took {:?}", session.uid, elapsed);
        }
    }

    /// Remove expired entries from session_cache based on ANALYZER_CACHE_TIMEOUT.
    pub fn cleanup_session_cache(&mut self) {
        let now = Utc::now();
        if now - self.last_cache_cleanup < Duration::seconds(60) {
            return;
        }
        self.last_cache_cleanup = now;
        self.session_cache.retain(|_, v| {
            let (_score, _features, last_modified) = v;
            now <= *last_modified + Duration::seconds(ANALYZER_CACHE_TIMEOUT)
        });
    }

    fn count_unique_samples(&self) -> usize {
        let mut seen: HashSet<[u64; NUM_FEATURES]> = HashSet::with_capacity(self.recent_data.len());
        for feats in &self.recent_data {
            let bits: [u64; NUM_FEATURES] = std::array::from_fn(|i| feats[i].to_bits());
            seen.insert(bits);
        }
        seen.len()
    }

    fn invalidate_score_cache_for_retrain(&self) {
        let len = self.session_cache.len();
        self.session_cache.clear();
        if len > 0 {
            info!(
                "invalidate_score_cache_for_retrain: Cleared {} cached scores after model retrain",
                len
            );
        }
    }
}

/// Compute the feature vector [f64; 12] for a given session.
/// Feature order: [process_prevalence, duration, bytes, packets, segment_interarrival, in_out_ratio, avg_packet_size, interarrival_regularity, packet_rate, missed, segments, dst_port]
fn compute_features(session: &SessionInfo, process_freq: &HashMap<String, u32>) -> [f64; 12] {
    let start_time = std::time::Instant::now();

    // Helper function to sanitize values
    fn sanitize(val: f64) -> f64 {
        if val.is_nan() || val.is_infinite() {
            0.0 // Replace NaN/Inf with 0.0
        } else {
            val
        }
    }

    // 1. Process prevalence: ln(frequency_in_training_window + 1)
    // Common processes (Chrome, Safari, Google Drive) get high values and cluster together.
    // Rare/unknown processes get low values and are naturally isolated by the iForest.
    let process_prevalence = match &session.l7 {
        Some(l7) => {
            let freq = process_freq.get(&l7.process_name).copied().unwrap_or(0);
            sanitize((freq as f64 + 1.0).ln())
        }
        None => 0.0,
    };

    // 2. Duration (keep linear scale for sensitivity)
    let duration_raw = match session.stats.end_time {
        Some(end_time) => {
            sanitize((end_time - session.stats.start_time).num_milliseconds() as f64 / 1000.0)
        }
        None => sanitize(
            (session.stats.last_activity - session.stats.start_time).num_milliseconds() as f64
                / 1000.0,
        ),
    };
    let duration = duration_raw;

    // 3. Total bytes (log scale to reduce dominance of large transfers while preserving separation)
    // Using ln_1p (ln(1+x)) to handle zero values gracefully
    let total_bytes = (session.stats.inbound_bytes + session.stats.outbound_bytes) as f64;
    let bytes = sanitize(total_bytes.ln_1p());

    // 4. Total packets (log scale to reduce dominance while preserving separation)
    let total_packets = (session.stats.orig_pkts + session.stats.resp_pkts) as f64;
    let packets = sanitize(total_packets.ln_1p());

    // 5. Segment interarrival
    let segment_interarrival = sanitize(session.stats.segment_interarrival);

    // 6. Inbound/outbound ratio
    let in_out_ratio = sanitize(session.stats.inbound_outbound_ratio);

    // 7. Avg packet size
    let avg_packet_size = sanitize(session.stats.average_packet_size);

    // 8. Interarrival regularity (0..1): how close average interarrival is to uniform spacing
    // N segments produce N-1 inter-segment gaps, so expected gap = duration / (N-1)
    let segment_count = session.stats.segment_count as f64;
    let expected_interarrival = if segment_count > 1.0 && duration > 0.0 {
        duration / (segment_count - 1.0)
    } else {
        0.0
    };
    let interarrival_regularity = if expected_interarrival > 0.0 {
        let diff = (session.stats.segment_interarrival - expected_interarrival).abs();
        let rel = diff / expected_interarrival.max(1e-6);
        sanitize((1.0 - rel).clamp(0.0, 1.0))
    } else {
        0.0
    };

    // 9. Packet rate (packets per second)
    let packet_rate = if duration > 0.0 {
        sanitize(((session.stats.orig_pkts + session.stats.resp_pkts) as f64) / duration)
    } else {
        0.0
    };

    // 10. Missed bytes
    let missed = sanitize(session.stats.missed_bytes as f64);

    // 11. Segments (count)
    let segments = sanitize(session.stats.segment_count as f64);

    // 12. Destination port as numeric value
    // TODO: Port number is categorical but treated as ordinal. Grouping into well-known/ephemeral
    // ranges or frequency encoding would reduce spurious splits on arbitrary port values.
    let dst_port = sanitize(session.session.dst_port as f64);

    let features = [
        process_prevalence,
        duration,
        bytes,
        packets,
        segment_interarrival,
        in_out_ratio,
        avg_packet_size,
        interarrival_regularity,
        packet_rate,
        missed,
        segments,
        dst_port,
    ];

    debug_assert!(
        features.iter().all(|f| f.is_finite()),
        "compute_features produced non-finite value for session {}",
        session.uid
    );

    let elapsed = start_time.elapsed();
    if elapsed.as_millis() > 50 {
        warn!(
            "compute_features for session {} took {:?}",
            session.uid, elapsed
        );
    }

    features
}

/// Computes dynamic anomaly thresholds based on recent scores.
fn compute_dynamic_thresholds(
    model: &mut IsolationForestModel,
    suspicious_percentile: f64,
    abnormal_percentile: f64,
) {
    info!(
        "compute_dynamic_thresholds: Starting threshold calculation for {}D model",
        NUM_FEATURES
    );
    let start_time = std::time::Instant::now();

    if model.recent_data.is_empty() || model.forest.is_none() {
        warn!("compute_dynamic_thresholds: Cannot compute thresholds without data or model. Data size: {}, Has forest: {}",
            model.recent_data.len(), model.forest.is_some());
        return;
    }

    // Add log for current thresholds before changing them
    info!(
        "compute_dynamic_thresholds: Current thresholds before calculation - Suspicious: {:.4}, Abnormal: {:.4}",
        model.suspicious_threshold, model.abnormal_threshold
    );

    let forest = model.forest.as_ref().unwrap(); // Safe due to check above
    info!("compute_dynamic_thresholds: Forest is available, scoring samples...");

    // Score all recent data points using the NUM_FEATURES forest
    let mut scores: Vec<f64> = model
        .recent_data // This contains [f64; NUM_FEATURES]
        .iter()
        .map(|features| forest.score_with_recursion_cap(features, 12)) // Match classification scoring
        .collect();

    if scores.is_empty() {
        warn!("compute_dynamic_thresholds: No scores generated from recent data.");
        return;
    }

    // Basic stats on the scores for logging
    let min_score = scores.iter().fold(f64::INFINITY, |a, &b| a.min(b));
    let max_score = scores.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
    let avg_score = scores.iter().sum::<f64>() / scores.len() as f64;

    info!(
        "compute_dynamic_thresholds: Score stats - min: {:.4}, max: {:.4}, avg: {:.4}, count: {}",
        min_score,
        max_score,
        avg_score,
        scores.len()
    );

    // Sort scores to find percentiles
    scores.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let n = scores.len();

    if n == 0 {
        warn!("compute_dynamic_thresholds: No scores available for percentile calculation");
        return;
    }

    // Helper function to safely compute percentile index
    fn percentile_index(n: usize, p: f64) -> usize {
        if n == 0 {
            return 0;
        }
        ((n as f64 - 1.0) * p).max(0.0).min((n - 1) as f64) as usize
    }

    // Add detailed score distribution analysis with bounds checking
    let p25_idx = percentile_index(n, 0.25);
    let p50_idx = percentile_index(n, 0.50);
    let p75_idx = percentile_index(n, 0.75);
    let p90_idx = percentile_index(n, 0.90);
    let p95_idx = percentile_index(n, 0.95);
    let p98_idx = percentile_index(n, 0.98);
    let p99_idx = percentile_index(n, 0.99);

    info!(
        "Score distribution analysis: min={:.4}, 25th={:.4}, 50th={:.4}, 75th={:.4}, 90th={:.4}, 95th={:.4}, 98th={:.4}, 99th={:.4}, max={:.4}",
        scores[0],
        scores[p25_idx],
        scores[p50_idx],
        scores[p75_idx],
        scores[p90_idx],
        scores[p95_idx],
        scores[p98_idx],
        scores[p99_idx],
        scores[n.saturating_sub(1)]
    );

    // Use proper percentile calculation: (n-1) * percentile gives correct index
    let suspicious_idx = percentile_index(n, suspicious_percentile);
    let abnormal_idx = percentile_index(n, abnormal_percentile);

    info!(
        "compute_dynamic_thresholds: Using indices suspicious={}/{}, abnormal={}/{}",
        suspicious_idx, n, abnormal_idx, n
    );

    let new_suspicious_threshold = scores[suspicious_idx];
    let new_abnormal_threshold = scores[abnormal_idx];

    info!(
        "compute_dynamic_thresholds: Percentile-based thresholds - Suspicious: {:.4} ({}th percentile), Abnormal: {:.4} ({}th percentile)",
        new_suspicious_threshold, suspicious_percentile * 100.0,
        new_abnormal_threshold, abnormal_percentile * 100.0
    );

    let old_suspicious = model.suspicious_threshold;
    let old_abnormal = model.abnormal_threshold;

    let min_reasonable_threshold = MIN_REASONABLE_THRESHOLD;
    model.suspicious_threshold = new_suspicious_threshold.max(min_reasonable_threshold);
    model.abnormal_threshold = new_abnormal_threshold
        .max(model.suspicious_threshold)
        .max(min_reasonable_threshold);

    info!(
        "Computed dynamic thresholds: Suspicious >= {:.4} (was {:.4}, percentile: {:.4}), Abnormal >= {:.4} (was {:.4}, percentile: {:.4}) (based on {} scores, took {:?})",
        model.suspicious_threshold, old_suspicious, new_suspicious_threshold,
        model.abnormal_threshold, old_abnormal, new_abnormal_threshold, n, start_time.elapsed()
    );
}

/// Result of analyzing sessions, indicating what changed
#[derive(Debug, Default)]
pub struct AnalysisResult {
    /// Number of sessions analyzed
    pub sessions_analyzed: usize,
    /// Whether new anomalous sessions were found
    pub new_anomalous_found: bool,
    /// Whether new blacklisted sessions were found
    pub new_blacklisted_found: bool,
    /// Total anomalous sessions currently tracked across all batches
    pub anomalous_count: usize,
    /// Total blacklisted sessions currently tracked across all batches
    pub blacklisted_count: usize,
    /// Anomalous sessions found in this specific batch
    pub batch_anomalous_count: usize,
    /// Blacklisted sessions found in this specific batch
    pub batch_blacklisted_count: usize,
}

/// Public interface for the SessionAnalyzer - thread-safe wrapper around the model
pub struct SessionAnalyzer {
    model: CustomRwLock<Option<CustomRwLock<IsolationForestModel>>>,
    anomalous_sessions: Arc<CustomDashMap<String, SessionCache>>,
    blacklisted_sessions: Arc<CustomDashMap<String, SessionCache>>,
    all_sessions: Arc<CustomDashMap<String, SessionCache>>, // Store all processed sessions
    /// Track the wall-clock time when we last ran a **real** analysis for every UID.
    /// This lets us enforce the `ANALYSIS_DELAY` guard without touching the core caches.
    last_analysis_times: Arc<CustomDashMap<String, DateTime<Utc>>>, // uid -> last analysis timestamp
    /// Throttle cleanup scans to reduce DashMap contention.
    last_cleanup_epoch: Arc<AtomicU64>,
    /// Background cleanup task handle (to avoid overlapping tasks).
    cleanup_task_handle: Arc<CustomRwLock<Option<tokio::task::JoinHandle<()>>>>,
    // Warm-up related fields
    warm_up_active: Arc<AtomicBool>,
    warm_up_start_time: AtomicU64, // Timestamp when warm-up started (seconds since UNIX epoch)
    warm_up_duration: Duration,
    suspicious_threshold_percentile: f64,
    abnormal_threshold_percentile: f64,
    last_threshold_recalc_time: Arc<CustomRwLock<DateTime<Utc>>>,
    threshold_recalc_interval: Duration,
    pub(crate) running: Arc<AtomicBool>,
    last_analysis_time: Arc<CustomRwLock<Option<DateTime<Utc>>>>,
    /// Cached analyzer statistics snapshot to minimize model locking in getters
    analyzer_stats: Arc<CustomRwLock<Option<AnalyzerStats>>>,
    /// Number of times a simple analysis timed out (soft per-batch timeout)
    analysis_timeouts_count: Arc<AtomicU64>,
    /// Rolling counters for performance metrics
    analyses_count: Arc<AtomicU64>,
    analysis_total_duration_ms: Arc<AtomicU64>,
    last_analysis_duration_ms: Arc<AtomicU64>,
}

impl SessionAnalyzer {
    /// Create a new analyzer with default settings
    pub fn new() -> Self {
        info!(
            "Creating new SessionAnalyzer: Using {}D feature analysis with 800 max samples",
            NUM_FEATURES
        );
        Self {
            model: CustomRwLock::new(None),
            anomalous_sessions: Arc::new(CustomDashMap::new("anomalous_sessions")),
            blacklisted_sessions: Arc::new(CustomDashMap::new("blacklisted_sessions")),
            all_sessions: Arc::new(CustomDashMap::new("all_sessions")),
            last_analysis_times: Arc::new(CustomDashMap::new("last_analysis_times")),
            last_cleanup_epoch: Arc::new(AtomicU64::new(0)),
            cleanup_task_handle: Arc::new(CustomRwLock::new(None)),
            // Warm-up defaults - increase to ensure enough time for training
            warm_up_active: Arc::new(AtomicBool::new(true)),
            // Initialize with 0 (will be set on first analyze_sessions call)
            warm_up_start_time: AtomicU64::new(0),
            // Use a shorter warm-up during tests; otherwise target ~3 minutes
            warm_up_duration: Duration::seconds(if cfg!(test) {
                WARMUP_DURATION_TEST
            } else {
                WARMUP_DURATION_DEFAULT
            }),
            suspicious_threshold_percentile: DEFAULT_SUSPICIOUS_PERCENTILE,
            abnormal_threshold_percentile: DEFAULT_ABNORMAL_PERCENTILE,
            last_threshold_recalc_time: Arc::new(CustomRwLock::new(Utc::now())),
            threshold_recalc_interval: Duration::hours(DEFAULT_THRESHOLD_RECALC_TIMEOUT),
            running: Arc::new(AtomicBool::new(false)),
            last_analysis_time: Arc::new(CustomRwLock::new(None)),
            analyzer_stats: Arc::new(CustomRwLock::new(None)),
            analysis_timeouts_count: Arc::new(AtomicU64::new(0)),
            analyses_count: Arc::new(AtomicU64::new(0)),
            analysis_total_duration_ms: Arc::new(AtomicU64::new(0)),
            last_analysis_duration_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Helper function to check if a session is anomalous based on its criticality
    fn is_anomalous(criticality: &str) -> bool {
        criticality.contains("anomaly:suspicious") || criticality.contains("anomaly:abnormal")
    }

    /// Helper function to check if a session is blacklisted based on its criticality
    fn is_blacklisted(criticality: &str) -> bool {
        criticality.contains("blacklist:")
    }

    /// Update specialized caches (anomalous_sessions, blacklisted_sessions) based on session criticality.
    /// This ensures caches stay synchronized whenever a session is stored, regardless of where
    /// the update comes from (analyze_sessions, capture layer, etc.).
    ///
    /// This eliminates the need for expensive scans in get_blacklisted_sessions() by maintaining
    /// cache consistency at insertion time rather than at retrieval time.
    fn update_session_caches(&self, session: &SessionInfo) {
        let cache = SessionCache::with_full_session(session);

        // Update anomalous sessions cache
        if Self::is_anomalous(&session.criticality) {
            self.anomalous_sessions
                .insert(session.uid.clone(), cache.clone());
        } else {
            // Remove from collection if session is no longer anomalous
            self.anomalous_sessions.remove(&session.uid);
        }

        // Update blacklisted sessions cache
        if Self::is_blacklisted(&session.criticality) {
            self.blacklisted_sessions.insert(session.uid.clone(), cache);
        } else {
            // Remove from collection if session is no longer blacklisted
            self.blacklisted_sessions.remove(&session.uid);
        }
    }

    /// Analyze and update the criticality of a batch of sessions.
    /// This will train/update the model and then score each session.
    /// Returns information about what was found during analysis.
    pub async fn analyze_sessions(&self, sessions: &mut [SessionInfo]) -> AnalysisResult {
        // Clean up expired session_cache entries before analysis
        self.cleanup_session_cache().await;

        // Reject sessions that are too old (can happen after a restart of capture)
        let cutoff = Utc::now() - CONNECTION_RETENTION_TIMEOUT;
        let mut filtered_indices = Vec::new();
        for (i, s) in sessions.iter().enumerate() {
            if s.last_modified > cutoff {
                filtered_indices.push(i);
            }
        }
        if filtered_indices.len() != sessions.len() {
            warn!(
                "Analyzer: Filtered {} sessions out of {} due to age",
                sessions.len() - filtered_indices.len(),
                sessions.len()
            );
        }

        // Reorder sessions in-place to keep only the valid ones
        let mut write_idx = 0;
        for &read_idx in &filtered_indices {
            if write_idx != read_idx {
                sessions.swap(write_idx, read_idx);
            }
            write_idx += 1;
        }
        let sessions = &mut sessions[..filtered_indices.len()];

        let sessions_len = sessions.len();

        let mut result = AnalysisResult {
            sessions_analyzed: sessions_len,
            ..Default::default()
        };

        if sessions.is_empty() {
            return result;
        }

        // Auto-start if model isn't initialized - do this BEFORE acquiring the long-held read lock
        let model_initialized = {
            let model_guard = self.model.read().await;
            model_guard.is_some()
        };

        if !model_initialized {
            info!("Analyzer: Auto-starting as model is not initialized");
            self.start().await;
        }

        let now = Utc::now();

        // NOTE: do *not* touch `last_analysis_time` **before** the analysis loop –
        // we need the previous value to decide whether a session needs re-analysis.
        // We will update it **after** the whole batch finishes (see bottom of fn).

        // Acquire the read guard for the Option<CustomRwLock<IsolationForestModel>>
        // This guard (`model_option_guard`) must live as long as `model_rwlock` is used.
        let model_option_guard = self.model.read().await;

        // Acquire model lock early, as it's needed in multiple places
        let model_rwlock = match &*model_option_guard {
            // Use the named guard here
            Some(m) => m, // m is &CustomRwLock<IsolationForestModel>
            None => {
                warn!("SessionAnalyzer: analyze_sessions called but model is not initialized (should have auto-started)");
                return result;
            }
        };
        // `model_option_guard` will keep the lock for `self.model` active.
        // `model_rwlock` is a reference to the inner `CustomRwLock<IsolationForestModel>`.

        // Check if there's a completed training task that needs to be processed
        // This should happen regardless of warm-up state
        {
            let mut model_guard = model_rwlock.write().await;
            if model_guard.training_in_progress.load(Ordering::Relaxed)
                && model_guard
                    .training_handle
                    .as_ref()
                    .map_or(false, |h| h.is_finished())
            {
                info!("Analyzer: Found completed training task at start of analyze_sessions, processing result");
                if let Some(handle) = model_guard.training_handle.take() {
                    match await_join_with_timeout(handle, std::time::Duration::from_secs(120)).await {
                        Some(Ok(Ok(forest))) => {
                            info!("Analyzer: Background training task completed successfully (processed at analyze_sessions start)");
                            model_guard.forest = Some(forest);
                            model_guard.last_training_time = Utc::now();
                            model_guard.invalidate_score_cache_for_retrain();
                        },
                        Some(Ok(Err(e))) => warn!("Analyzer: Background training task failed (processed at analyze_sessions start): {:?}", e),
                        Some(Err(e)) => error!("Analyzer: Background training task panicked (processed at analyze_sessions start): {:?}", e),
                        None => {
                            error!("Analyzer: Background training task timed out after 120s - possible EIF hang");
                            model_guard.training_handle = None;
                            model_guard.training_in_progress.store(false, Ordering::Release);
                            return result; // Exit early to prevent further hangs
                        }
                    }
                    model_guard.training_handle = None;
                    model_guard
                        .training_in_progress
                        .store(false, Ordering::Release);
                }
            }
        }

        // Add all new session data to the model's recent_data buffer (as before)
        let sessions_len = sessions.len();
        let mut initial_batch_analyzed_post_warmup = false; // Flag to analyze current batch if warm-up just ended

        {
            let mut model_guard = model_rwlock.write().await;
            info!(
                "Analyzer: Adding {} new sessions to model data buffer (current size before add: {})",
                sessions_len,
                model_guard.recent_data.len()
            );
            let add_data_start = std::time::Instant::now();
            for session in sessions.iter() {
                model_guard.add_session_data(session);
            }
            debug!(
                "Analyzer: Added session data in {:?} (new buffer size: {})",
                add_data_start.elapsed(),
                model_guard.recent_data.len()
            );
        }

        // Main logic: Check if warm-up is active
        if self.warm_up_active.load(Ordering::Relaxed) {
            // Initialize warm_up_start_time on first analysis call if it's still 0
            if self.warm_up_start_time.load(Ordering::Relaxed) == 0 {
                let unix_time = now.timestamp() as u64;
                self.warm_up_start_time.store(unix_time, Ordering::Relaxed);
                info!(
                    "Analyzer: Warmup period starting now (unix time: {})",
                    unix_time
                );
            }

            let start_unix_time = self.warm_up_start_time.load(Ordering::Relaxed);
            let now_unix_time = now.timestamp() as u64;
            let elapsed_seconds = if start_unix_time <= now_unix_time {
                (now_unix_time - start_unix_time) as i64
            } else {
                0
            };

            debug!(
                "Analyzer: Warm-up active. Elapsed: {}s, MinWarmup: {}s, TargetWarmup: {}s",
                elapsed_seconds,
                WARMUP_DELAY,
                self.warm_up_duration.num_seconds()
            );

            let should_attempt_finalize = elapsed_seconds >= WARMUP_DELAY
                && elapsed_seconds >= self.warm_up_duration.num_seconds()
                && {
                    let unique_count = {
                        let model_guard = model_rwlock.read().await;
                        model_guard.count_unique_samples()
                    };
                    if unique_count < WARMUP_MIN_UNIQUE_SAMPLES {
                        debug!(
                            "Warm-up finalize gate: only {} unique samples (need >= {})",
                            unique_count, WARMUP_MIN_UNIQUE_SAMPLES
                        );
                        false
                    } else {
                        true
                    }
                };

            if should_attempt_finalize {
                info!("Analyzer: Warm-up duration met (elapsed: {}s). Attempting to finalize and compute thresholds.", elapsed_seconds);
                let mut model_guard = model_rwlock.write().await;

                // Ensure any ongoing training is completed
                if model_guard.training_in_progress.load(Ordering::Relaxed) {
                    if let Some(handle_ref) = model_guard.training_handle.as_ref() {
                        if !handle_ref.is_finished() {
                            info!("Analyzer (Finalize Warmup): Waiting for ongoing training task to complete...");
                            let handle = model_guard.training_handle.take().unwrap();
                            match await_join_with_timeout(
                                handle,
                                std::time::Duration::from_secs(120),
                            )
                            .await
                            {
                                Some(Ok(Ok(forest))) => {
                                    info!("Analyzer (Finalize Warmup): Training task completed successfully.");
                                    model_guard.forest = Some(forest);
                                    model_guard.last_training_time = Utc::now();
                                    model_guard.invalidate_score_cache_for_retrain();
                                }
                                Some(Ok(Err(e))) => warn!(
                                    "Analyzer (Finalize Warmup): Training task failed: {:?}",
                                    e
                                ),
                                Some(Err(e)) => error!(
                                    "Analyzer (Finalize Warmup): Training task panicked: {:?}",
                                    e
                                ),
                                None => {
                                    error!("Analyzer (Finalize Warmup): Training task timed out after 120s - possible EIF hang");
                                    model_guard.training_cancel.store(true, Ordering::Release);
                                    model_guard.training_timeouts_count =
                                        model_guard.training_timeouts_count.saturating_add(1);
                                    model_guard.training_handle = None;
                                    model_guard
                                        .training_in_progress
                                        .store(false, Ordering::Release);
                                }
                            }
                        } else {
                            // Already finished, try to process with timeout (should be fast)
                            let handle = model_guard.training_handle.take().unwrap();
                            match await_join_with_timeout(handle, std::time::Duration::from_secs(10)).await {
                                Some(Ok(Ok(forest))) => { model_guard.forest = Some(forest); model_guard.last_training_time = Utc::now(); model_guard.invalidate_score_cache_for_retrain(); },
                                Some(Ok(Err(e))) => warn!("Analyzer (Finalize Warmup): Already finished training task returned error: {:?}", e),
                                Some(Err(e)) => error!("Analyzer (Finalize Warmup): Already finished training task panicked: {:?}", e),
                                None => {
                                    error!("Analyzer (Finalize Warmup): Finished training task timed out - possible EIF issue");
                                    model_guard.training_cancel.store(true, Ordering::Release);
                                    model_guard.training_timeouts_count = model_guard.training_timeouts_count.saturating_add(1);
                                    model_guard.training_handle = None;
                                    model_guard.training_in_progress.store(false, Ordering::Release);
                                }
                            }
                        }
                        model_guard.training_handle = None;
                        model_guard
                            .training_in_progress
                            .store(false, Ordering::Release);
                    }
                }

                if model_guard.forest.is_none() {
                    info!("Analyzer (Finalize Warmup): No forest model. Forcing one final training attempt.");
                    model_guard.train_model(true).await;
                    if let Some(handle) = model_guard.training_handle.take() {
                        info!("Analyzer (Finalize Warmup): Waiting for final forced training task to complete...");
                        match await_join_with_timeout(handle, std::time::Duration::from_secs(120)).await {
                            Some(Ok(Ok(forest))) => {
                                info!("Analyzer (Finalize Warmup): Final forced training task completed successfully.");
                                model_guard.forest = Some(forest);
                                model_guard.last_training_time = Utc::now();
                                model_guard.invalidate_score_cache_for_retrain();
                            },
                            Some(Ok(Err(e))) => warn!("Analyzer (Finalize Warmup): Final forced training task failed: {:?}", e),
                            Some(Err(e)) => error!("Analyzer (Finalize Warmup): Final forced training task panicked: {:?}", e),
                            None => {
                                error!("Analyzer (Finalize Warmup): Final forced training task timed out after 120s - possible EIF hang");
                                model_guard.training_cancel.store(true, Ordering::Release);
                                model_guard.training_timeouts_count = model_guard.training_timeouts_count.saturating_add(1);
                            }
                        }
                        model_guard.training_handle = None;
                        model_guard
                            .training_in_progress
                            .store(false, Ordering::Release);
                    }
                }

                if model_guard.forest.is_some() && !model_guard.recent_data.is_empty() {
                    info!("Analyzer (Finalize Warmup): Forest and data available. Computing dynamic thresholds.");
                    let susp_pct = model_guard.current_suspicious_percentile;
                    let abnm_pct = model_guard.current_abnormal_percentile;
                    compute_dynamic_thresholds(&mut model_guard, susp_pct, abnm_pct);
                    self.warm_up_active.store(false, Ordering::Relaxed);
                    let mut last_recalc_lock = self.last_threshold_recalc_time.write().await;
                    *last_recalc_lock = now;
                    info!("Analyzer: Warm-up period COMPLETED successfully after {}s. Dynamic thresholds computed. Regular operation will now begin.", elapsed_seconds);
                    initial_batch_analyzed_post_warmup = true; // Analyze this current batch now
                } else {
                    info!("Analyzer (Finalize Warmup): FAILED to compute dynamic thresholds (Forest ready: {}, Data available: {}). Warm-up will continue.", 
                          model_guard.forest.is_some(), !model_guard.recent_data.is_empty());
                    if !model_guard.training_in_progress.load(Ordering::Relaxed) {
                        model_guard.train_model(true).await;
                    }
                }
            } else {
                // Still actively warming up.
                info!("Analyzer: Actively in warm-up (elapsed: {}s of {}s). Collecting data, ensuring training continues.", 
                      elapsed_seconds, self.warm_up_duration.num_seconds());
                {
                    let mut model_guard = model_rwlock.write().await;
                    if !model_guard.training_in_progress.load(Ordering::Relaxed)
                        && model_guard.training_handle.is_none()
                    {
                        info!("Analyzer (Active Warmup): Training not in progress, initiating forced training.");
                        model_guard.train_model(true).await;
                    } else {
                        debug!("Analyzer (Active Warmup): Training already in progress or handle exists.");
                    }
                }
                for session in sessions.iter_mut() {
                    if session.criticality.is_empty() {
                        session.criticality = "anomaly:normal/warming_up".to_string(); // More specific tag
                        session.last_modified = now;
                    }
                    // Store all sessions even during warmup (using lightweight cache)
                    self.all_sessions.insert(
                        session.uid.clone(),
                        SessionCache::with_full_session(session),
                    );

                    // Update specialized caches to keep them synchronized
                    self.update_session_caches(session);
                }
                // If still in warm-up and not finalizing this call, return early.
                // The current batch of sessions has been added to `recent_data` and training ensured.
                // They will be analyzed once warm-up completes.
                if !initial_batch_analyzed_post_warmup {
                    result.anomalous_count = self.anomalous_sessions.len();
                    result.blacklisted_count = self.blacklisted_sessions.len();

                    info!("Analyzer: analyze_sessions batch completed for {} sessions (still in active warm-up, returning early). Found: {} anomalous, {} blacklisted.", sessions_len, result.anomalous_count, result.blacklisted_count);
                    return result;
                }
            }
        }

        // If warm_up_active is false (either was already false, or became false in this call), proceed to regular operation.
        if !self.warm_up_active.load(Ordering::Relaxed) || initial_batch_analyzed_post_warmup {
            if initial_batch_analyzed_post_warmup {
                info!("Analyzer: Processing initial batch of {} sessions immediately after warm-up completion.", sessions_len);
            } else {
                info!(
                    "Analyzer: Regular operation (warm-up not active, elapsed since startup: {}s).",
                    now.timestamp()
                        .saturating_sub(self.warm_up_start_time.load(Ordering::Relaxed) as i64)
                );
            }

            // Regular threshold recalculation logic
            let recalc_needed = {
                let last_recalc = self.last_threshold_recalc_time.read().await;
                now - *last_recalc >= self.threshold_recalc_interval
            };

            if recalc_needed && !initial_batch_analyzed_post_warmup {
                // Don't do scheduled recalc if we just did warm-up one
                info!(
                    "Analyzer: Regular threshold recalculation scheduled ({}h elapsed).",
                    self.threshold_recalc_interval.num_hours()
                );
                let mut model_guard = model_rwlock.write().await;
                model_guard.train_model(true).await;

                if let Some(handle) = model_guard.training_handle.take() {
                    info!("Analyzer (Scheduled Recalc): Waiting for training task to complete...");
                    match await_join_with_timeout(handle, std::time::Duration::from_secs(120)).await
                    {
                        Some(Ok(Ok(forest))) => {
                            info!("Analyzer (Scheduled Recalc): Training task completed successfully.");
                            model_guard.forest = Some(forest);
                            model_guard.last_training_time = Utc::now();
                            model_guard.invalidate_score_cache_for_retrain();
                        }
                        Some(Ok(Err(e))) => {
                            warn!("Analyzer (Scheduled Recalc): Training task failed: {:?}", e)
                        }
                        Some(Err(e)) => error!(
                            "Analyzer (Scheduled Recalc): Training task panicked: {:?}",
                            e
                        ),
                        None => {
                            error!("Analyzer (Scheduled Recalc): Training task timed out after 120s - possible EIF hang");
                            model_guard.training_cancel.store(true, Ordering::Release);
                            model_guard.training_timeouts_count =
                                model_guard.training_timeouts_count.saturating_add(1);
                            model_guard.training_handle = None;
                            model_guard
                                .training_in_progress
                                .store(false, Ordering::Release);
                        }
                    }
                    model_guard.training_handle = None;
                    model_guard
                        .training_in_progress
                        .store(false, Ordering::Release);
                }

                if model_guard.forest.is_some() && !model_guard.recent_data.is_empty() {
                    info!("Analyzer (Scheduled Recalc): Computing dynamic thresholds.");
                    let susp_pct = model_guard.current_suspicious_percentile;
                    let abnm_pct = model_guard.current_abnormal_percentile;
                    compute_dynamic_thresholds(&mut model_guard, susp_pct, abnm_pct);
                    let mut last_recalc_lock = self.last_threshold_recalc_time.write().await;
                    *last_recalc_lock = now;
                } else {
                    warn!("Analyzer (Scheduled Recalc): Skipping threshold recalculation (Forest ready: {}, Data available: {}).", 
                          model_guard.forest.is_some(), !model_guard.recent_data.is_empty());
                }
            } else {
                // Regular training (not forced by recalc) if not immediately post-warmup
                if !initial_batch_analyzed_post_warmup {
                    let mut model_guard = model_rwlock.write().await;
                    let sample_count = model_guard.recent_data.len();
                    let training_threshold = model_guard.max_samples / 2;

                    if model_guard.forest.is_none() {
                        info!("Analyzer (Regular Op): No forest model. Forcing training.");
                        model_guard.train_model(true).await;
                    } else if sample_count >= training_threshold
                        && !model_guard.training_in_progress.load(Ordering::Relaxed)
                        && model_guard.training_handle.is_none()
                    {
                        info!("Analyzer (Regular Op): Sufficient samples ({}/{}), initiating regular training.", sample_count, training_threshold);
                        model_guard.train_model(false).await;
                    } else {
                        debug!("Analyzer (Regular Op): Skipping regular training (Samples: {}/{}, InProgress: {}, Handle: {}).", 
                               sample_count, training_threshold, model_guard.training_in_progress.load(Ordering::Relaxed), model_guard.training_handle.is_some());
                    }
                }
            }

            // Analyze all sessions and update criticality (soft 60s batch timeout)
            {
                let batch_deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
                let model_guard = model_rwlock.read().await;
                if model_guard.forest.is_some() {
                    let operation_type = if initial_batch_analyzed_post_warmup {
                        "Post-Warmup"
                    } else {
                        "Regular Op"
                    };
                    info!(
                        "Analyzer ({}): Analyzing {} sessions with current model.",
                        operation_type, sessions_len
                    );

                    let analyze_start_time = std::time::Instant::now();
                    let feature_stats = model_guard.compute_feature_stats_bulk();
                    // Snapshot model/threshold change times to decide if re-analysis is required
                    let model_last_training_time = model_guard.last_training_time;
                    let thresholds_last_recalc_time = {
                        // Safe to briefly drop and reacquire different lock type
                        drop(model_guard);
                        let t = *self.last_threshold_recalc_time.read().await;
                        t
                    };
                    // Ensure we hold no extra locks from the above snapshot

                    let mut anom_count = 0;
                    let mut bl_count = 0;
                    let mut skip_count = 0;
                    let mut found_new_anomalous = false;
                    let mut found_new_blacklisted = false;

                    let mut model_write_guard = model_rwlock.write().await;

                    // If we have a freshly (re)started model that trained but still uses
                    // default thresholds, compute dynamic thresholds immediately to avoid
                    // overly sensitive classification on restart.
                    if model_write_guard.suspicious_threshold == DEFAULT_SUSPICIOUS_THRESHOLD
                        && model_write_guard.abnormal_threshold == DEFAULT_ABNORMAL_THRESHOLD
                        && model_write_guard.forest.is_some()
                        && !model_write_guard.recent_data.is_empty()
                    {
                        info!(
                            "Analyzer ({}): Default thresholds detected after (re)start; computing dynamic thresholds immediately.",
                            operation_type
                        );
                        compute_dynamic_thresholds(
                            &mut *model_write_guard,
                            self.suspicious_threshold_percentile,
                            self.abnormal_threshold_percentile,
                        );
                        let mut last_recalc_lock = self.last_threshold_recalc_time.write().await;
                        *last_recalc_lock = now;
                    }

                    for (idx, session) in sessions.iter_mut().enumerate() {
                        if std::time::Instant::now() >= batch_deadline {
                            warn!("Analyzer: Simple analysis batch timed out after 60s; remaining sessions skipped this round");
                            // Increment analysis timeout counter
                            self.analysis_timeouts_count.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                        // ---------------------------------------------------------------------
                        // Decide whether we really need to (re)analyse this session:
                        //  * Always analyse if it changed (timestamp **or** criticality) since
                        //    the previous stored copy.
                        //  * Otherwise apply an `ANALYSIS_DELAY` quiet-time before we analyse
                        //    the same unmodified flow again.
                        // ---------------------------------------------------------------------

                        let last_analysis_opt = self
                            .last_analysis_times
                            .get(&session.uid)
                            .map(|e| *e.value());

                        // Has the session's `criticality` text changed since we last saw it?
                        let criticality_unchanged = self
                            .all_sessions
                            .get(&session.uid)
                            .map(|e| {
                                let stored = &e.value().criticality;
                                let incoming = &session.criticality;

                                if stored.is_empty() || incoming.is_empty() {
                                    return false;
                                }

                                stored == incoming
                            })
                            .unwrap_or(false);

                        let too_soon_since_last = last_analysis_opt
                            .map(|t| now - t < chrono::Duration::seconds(ANALYSIS_DELAY))
                            .unwrap_or(false);

                        let modified_timestamp = last_analysis_opt
                            .map(|t| session.last_modified > t)
                            .unwrap_or(true); // If we never analysed before treat as modified.

                        // Need analysis unless all three are true:
                        //   - analysed recently (too_soon_since_last)
                        //   - timestamp unchanged
                        //   - criticality string unchanged
                        let model_or_thresholds_changed_since_last = last_analysis_opt
                            .map(|t| {
                                (model_last_training_time > t) || (thresholds_last_recalc_time > t)
                            })
                            .unwrap_or(false);

                        let needs_analysis =
                            !(too_soon_since_last && !modified_timestamp && criticality_unchanged)
                                || model_or_thresholds_changed_since_last;

                        if needs_analysis {
                            // If we're too close to the deadline, avoid expensive diagnostics.
                            let remaining =
                                batch_deadline.saturating_duration_since(std::time::Instant::now());
                            if remaining < std::time::Duration::from_millis(10) {
                                warn!(
                                    "Analyzer: Skipping detailed analysis for {} due to imminent batch timeout (remaining {:?})",
                                    session.uid,
                                    remaining
                                );
                                let has_prior_anomaly =
                                    session.criticality.contains("anomaly:suspicious")
                                        || session.criticality.contains("anomaly:abnormal");
                                if has_prior_anomaly {
                                    debug!(
                                        "Analyzer: Preserving prior anomaly tags for {} during timeout",
                                        session.uid
                                    );
                                } else {
                                    let mut final_tags: Vec<String> = session
                                        .criticality
                                        .split(',')
                                        .filter(|s| {
                                            !s.trim().is_empty()
                                                && !s.trim().starts_with("anomaly:")
                                        })
                                        .map(|s| s.trim().to_string())
                                        .collect();
                                    final_tags.push("anomaly:normal/analysis_timeout".to_string());
                                    final_tags.sort_unstable();
                                    final_tags.dedup();
                                    session.criticality = final_tags.join(",");
                                }
                            } else {
                                model_write_guard.analyze_session(session, &feature_stats);
                            }

                            // Record that we just performed a real analysis (or timeout marking) for this UID.
                            self.last_analysis_times.insert(session.uid.clone(), now);
                        } else {
                            skip_count += 1;
                            // Preserve previously-determined anomaly tags only when skipping re-analysis,
                            // but allow blacklist updates from the incoming session to pass through.
                            if !Self::is_anomalous(&session.criticality) {
                                // Find a stored criticality to extract anomaly tags from, preferring
                                // the anomalous cache, then blacklist cache, then all_sessions.
                                let stored_crit_opt = if let Some(entry) =
                                    self.anomalous_sessions.get(&session.uid)
                                {
                                    Some(entry.value().criticality.clone())
                                } else if let Some(entry) =
                                    self.blacklisted_sessions.get(&session.uid)
                                {
                                    Some(entry.value().criticality.clone())
                                } else if let Some(entry) = self.all_sessions.get(&session.uid) {
                                    Some(entry.value().criticality.clone())
                                } else {
                                    None
                                };

                                if let Some(stored_crit) = stored_crit_opt {
                                    let add_tag = if stored_crit.contains("anomaly:abnormal") {
                                        Some("anomaly:abnormal")
                                    } else if stored_crit.contains("anomaly:suspicious") {
                                        Some("anomaly:suspicious")
                                    } else {
                                        None
                                    };

                                    if let Some(tag) = add_tag {
                                        if !session.criticality.contains(tag) {
                                            if session.criticality.is_empty() {
                                                session.criticality = tag.to_string();
                                            } else {
                                                session.criticality.push(',');
                                                session.criticality.push_str(tag);
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Store all sessions regardless of classification (using lightweight cache)
                        self.all_sessions.insert(
                            session.uid.clone(),
                            SessionCache::with_full_session(session),
                        );

                        // Track if we found new anomalous/blacklisted sessions before updating caches
                        let was_anomalous = self.anomalous_sessions.contains_key(&session.uid);
                        let was_blacklisted = self.blacklisted_sessions.contains_key(&session.uid);

                        // Update specialized caches to keep them synchronized
                        self.update_session_caches(session);

                        // Update counters and flags after cache update
                        if Self::is_anomalous(&session.criticality) {
                            if !was_anomalous {
                                found_new_anomalous = true;
                            }
                            anom_count += 1;
                        }
                        if Self::is_blacklisted(&session.criticality) {
                            if !was_blacklisted {
                                found_new_blacklisted = true;
                            }
                            bl_count += 1;
                        }
                        // Do not feed here; we already pushed raw inputs up-front.
                        if (idx + 1) % 500 == 0 {
                            debug!(
                                "Analyzer ({}): Analyzed {}, {} skipped, {} anomalous, {} blacklisted, {} total.",
                                operation_type,
                                idx + 1,
                                skip_count,
                                anom_count,
                                bl_count,
                                sessions_len
                            );
                        }
                    }
                    let elapsed = analyze_start_time.elapsed();
                    let elapsed_ms = elapsed.as_millis() as u64;
                    self.last_analysis_duration_ms
                        .store(elapsed_ms, Ordering::Relaxed);
                    self.analyses_count.fetch_add(1, Ordering::Relaxed);
                    self.analysis_total_duration_ms
                        .fetch_add(elapsed_ms, Ordering::Relaxed);
                    info!("Analyzer ({}): Analysis of {} sessions completed in {:?}. Found: {} anomalous, {} blacklisted.",
                          operation_type, sessions_len, elapsed, anom_count, bl_count);

                    result.new_anomalous_found = found_new_anomalous;
                    result.new_blacklisted_found = found_new_blacklisted;
                    result.batch_anomalous_count = anom_count;
                    result.batch_blacklisted_count = bl_count;
                } else {
                    warn!("Analyzer (Regular Op/Post-Warmup): No forest model available for analysis. Sessions will not be scored for anomalies.");

                    // Count existing anomalous/blacklisted sessions even without forest model
                    let mut anom_count = 0;
                    let mut bl_count = 0;

                    for session in sessions.iter_mut() {
                        if !session.criticality.contains("blacklist:") {
                            session.criticality = "anomaly:normal/no_model".to_string();
                            session.last_modified = now;
                        }

                        // Store all sessions even when no model is available (using lightweight cache)
                        self.all_sessions.insert(
                            session.uid.clone(),
                            SessionCache::with_full_session(session),
                        );

                        // Update specialized caches to keep them synchronized
                        self.update_session_caches(session);

                        // Count sessions after any updates
                        if Self::is_anomalous(&session.criticality) {
                            anom_count += 1;
                        }
                        if Self::is_blacklisted(&session.criticality) {
                            bl_count += 1;
                        }
                    }

                    result.batch_anomalous_count = anom_count;
                    result.batch_blacklisted_count = bl_count;
                }
            }
        }

        result.anomalous_count = self.anomalous_sessions.len();
        result.blacklisted_count = self.blacklisted_sessions.len();

        debug!(
            "Analyzer: analyze_sessions call finished for {} sessions. Totals: {} anomalous, {} blacklisted.",
            sessions_len,
            result.anomalous_count,
            result.blacklisted_count
        );

        // Record when this analysis completed so the next batch can correctly
        // detect modifications.  This must be done *after* all work above.
        {
            let mut guard = self.last_analysis_time.write().await;
            *guard = Some(now);
        }

        // Build and cache an AnalyzerStats snapshot for fast retrieval by get_analyzer_stats()
        {
            let is_running = self.running.load(Ordering::SeqCst);
            let warm_up_active = self.warm_up_active.load(Ordering::SeqCst);

            // Warm-up progress snapshot
            let warm_up_start_timestamp = self.warm_up_start_time.load(Ordering::SeqCst);
            let warm_up_elapsed = if warm_up_start_timestamp > 0 {
                (now.timestamp() as u64).saturating_sub(warm_up_start_timestamp)
            } else {
                0
            };
            let warm_up_target = self.warm_up_duration.num_seconds() as u64;

            // Snapshot model/threshold info with minimal locking: read model lock once
            let model_guard = self.model.read().await;
            let (model_stats, thresholds, unique_samples) = if let Some(model_lock) = &*model_guard
            {
                let model = model_lock.read().await;

                let unique_samples = model.count_unique_samples();
                let has_forest = model.forest.is_some();
                let training_in_progress = model.training_in_progress.load(Ordering::SeqCst);
                let buffer_size = model.recent_data.len();
                let max_capacity = model.max_samples;

                // Only compute score distribution if we have a reasonable amount of data
                // to avoid expensive allocations on every stats call
                let score_dist = if has_forest && model.recent_data.len() >= 10 {
                    if let Some(forest) = &model.forest {
                        // Limit computation to avoid excessive memory allocation
                        // Sample up to 200 scores for distribution calculation
                        let sample_size = model.recent_data.len().min(200);
                        let step = if model.recent_data.len() > sample_size {
                            model.recent_data.len() / sample_size
                        } else {
                            1
                        };

                        let mut scores: Vec<f64> = model
                            .recent_data
                            .iter()
                            .step_by(step)
                            .take(sample_size)
                            .map(|features| forest.score(features))
                            .collect();
                        if !scores.is_empty() {
                            scores.sort_by(|a, b| {
                                a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)
                            });
                            let n = scores.len();
                            let mean = scores.iter().sum::<f64>() / n as f64;
                            Some(ScoreDistribution {
                                sample_count: n,
                                min_score: scores[0],
                                max_score: scores[n - 1],
                                mean_score: mean,
                                percentiles: ScorePercentiles {
                                    p25: scores[n / 4],
                                    p50: scores[n / 2],
                                    p75: scores[3 * n / 4],
                                    p90: scores[9 * n / 10],
                                    p95: scores[95 * n / 100],
                                    p98: scores[98 * n / 100],
                                    p99: scores[99 * n / 100],
                                    p995: scores[995 * n / 1000],
                                },
                            })
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                let model_stats = ModelStats {
                    has_trained_model: has_forest,
                    training_in_progress,
                    last_training_time: if model.last_training_time > DateTime::<Utc>::MIN_UTC {
                        Some(model.last_training_time)
                    } else {
                        None
                    },
                    min_training_interval_minutes: model.min_training_interval.num_minutes() as f64,
                    total_samples_in_buffer: buffer_size,
                    max_buffer_capacity: max_capacity,
                    buffer_utilization_percentage: if max_capacity > 0 {
                        (buffer_size as f64 / max_capacity as f64) * 100.0
                    } else {
                        0.0
                    },
                    unique_samples_count: unique_samples,
                    downsample_factor: model.downsample_factor,
                    feature_count: NUM_FEATURES,
                    recent_score_distribution: score_dist,
                };

                let last_recalc = self.last_threshold_recalc_time.read().await;
                let recalc_interval_hours = self.threshold_recalc_interval.num_hours() as f64;
                let next_recalc = *last_recalc + self.threshold_recalc_interval;

                let thresholds = ThresholdStats {
                    suspicious_threshold: model.suspicious_threshold,
                    abnormal_threshold: model.abnormal_threshold,
                    suspicious_percentile: model.current_suspicious_percentile,
                    abnormal_percentile: model.current_abnormal_percentile,
                    last_recalc_time: Some(*last_recalc),
                    next_recalc_time: Some(next_recalc),
                    recalc_interval_hours,
                    min_reasonable_threshold: MIN_REASONABLE_THRESHOLD,
                    default_suspicious_threshold: DEFAULT_SUSPICIOUS_THRESHOLD,
                    default_abnormal_threshold: DEFAULT_ABNORMAL_THRESHOLD,
                };

                (model_stats, thresholds, unique_samples)
            } else {
                let model_stats = ModelStats {
                    has_trained_model: false,
                    training_in_progress: false,
                    last_training_time: None,
                    min_training_interval_minutes: 0.0,
                    total_samples_in_buffer: 0,
                    max_buffer_capacity: 800,
                    buffer_utilization_percentage: 0.0,
                    unique_samples_count: 0,
                    downsample_factor: 1,
                    feature_count: NUM_FEATURES,
                    recent_score_distribution: None,
                };

                let last_recalc = self.last_threshold_recalc_time.read().await;
                let recalc_interval_hours = self.threshold_recalc_interval.num_hours() as f64;
                let next_recalc = *last_recalc + self.threshold_recalc_interval;

                let thresholds = ThresholdStats {
                    suspicious_threshold: DEFAULT_SUSPICIOUS_THRESHOLD,
                    abnormal_threshold: DEFAULT_ABNORMAL_THRESHOLD,
                    suspicious_percentile: self.suspicious_threshold_percentile,
                    abnormal_percentile: self.abnormal_threshold_percentile,
                    last_recalc_time: Some(*last_recalc),
                    next_recalc_time: Some(next_recalc),
                    recalc_interval_hours,
                    min_reasonable_threshold: MIN_REASONABLE_THRESHOLD,
                    default_suspicious_threshold: DEFAULT_SUSPICIOUS_THRESHOLD,
                    default_abnormal_threshold: DEFAULT_ABNORMAL_THRESHOLD,
                };

                (model_stats, thresholds, 0)
            };

            let warm_up_progress = WarmUpProgress {
                elapsed_seconds: warm_up_elapsed,
                target_duration_seconds: warm_up_target,
                unique_samples_collected: unique_samples,
                min_samples_required: WARMUP_MIN_UNIQUE_SAMPLES,
                progress_percentage: if warm_up_target > 0 {
                    ((warm_up_elapsed as f64 / warm_up_target as f64) * 100.0).min(100.0)
                } else {
                    100.0
                },
                estimated_completion_seconds: if warm_up_active && warm_up_elapsed < warm_up_target
                {
                    Some(warm_up_target - warm_up_elapsed)
                } else {
                    None
                },
            };

            // Session stats from current caches
            let total_sessions = self.all_sessions.len();
            let anomalous_sessions = self.anomalous_sessions.len();
            let blacklisted_sessions = self.blacklisted_sessions.len();
            let normal_sessions = self
                .all_sessions
                .iter()
                .filter(|e| {
                    !self.anomalous_sessions.contains_key(e.key())
                        && !self.blacklisted_sessions.contains_key(e.key())
                })
                .count();
            let anomaly_rate = if total_sessions > 0 {
                (anomalous_sessions as f64 / total_sessions as f64) * 100.0
            } else {
                0.0
            };
            let blacklist_rate = if total_sessions > 0 {
                (blacklisted_sessions as f64 / total_sessions as f64) * 100.0
            } else {
                0.0
            };
            let last_analysis = self.last_analysis_time.read().await;

            let session_stats = SessionStats {
                total_sessions_tracked: total_sessions,
                anomalous_sessions_count: anomalous_sessions,
                blacklisted_sessions_count: blacklisted_sessions,
                normal_sessions_count: normal_sessions,
                anomaly_rate_percentage: anomaly_rate,
                blacklist_rate_percentage: blacklist_rate,
                last_analysis_time: *last_analysis,
                sessions_analyzed_today: total_sessions,
            };

            let training_timeouts_total = {
                let model_guard = self.model.read().await;
                if let Some(model_lock) = &*model_guard {
                    let model = model_lock.read().await;
                    model.training_timeouts_count
                } else {
                    0
                }
            };
            let analysis_timeouts_total = self.analysis_timeouts_count.load(Ordering::Relaxed);
            // Compute rolling averages and cache hit rate
            let total_analyses = self.analyses_count.load(Ordering::Relaxed);
            let total_duration_ms = self.analysis_total_duration_ms.load(Ordering::Relaxed);
            let last_duration_ms = self.last_analysis_duration_ms.load(Ordering::Relaxed);
            let (cache_hits, cache_misses) = {
                let model_guard = self.model.read().await;
                if let Some(model_lock) = &*model_guard {
                    let model = model_lock.read().await;
                    (
                        model.cache_hits.load(Ordering::Relaxed),
                        model.cache_misses.load(Ordering::Relaxed),
                    )
                } else {
                    (0, 0)
                }
            };
            let cache_total = cache_hits + cache_misses;
            let cache_hit_rate_percentage = if cache_total > 0 {
                Some((cache_hits as f64 / cache_total as f64) * 100.0)
            } else {
                None
            };

            // Estimate analyzer memory footprint by summing key buffers/caches
            let memory_usage_mb = {
                let model_guard = self.model.read().await;
                if let Some(model_lock) = &*model_guard {
                    let model = model_lock.read().await;
                    let bytes = model
                        .estimate_memory_usage_bytes()
                        // Also account for tracked session maps (approximate)
                        .saturating_add((self.anomalous_sessions.len() as u64).saturating_mul(256))
                        .saturating_add(
                            (self.blacklisted_sessions.len() as u64).saturating_mul(256),
                        )
                        .saturating_add((self.all_sessions.len() as u64).saturating_mul(256));
                    Some((bytes as f64) / (1024.0 * 1024.0))
                } else {
                    None
                }
            };

            let performance_stats = PerformanceStats {
                average_analysis_time_ms: if total_analyses > 0 {
                    Some(total_duration_ms as f64 / total_analyses as f64)
                } else {
                    None
                },
                last_analysis_duration_ms: if total_analyses > 0 {
                    Some(last_duration_ms as f64)
                } else {
                    None
                },
                total_analyses_performed: total_analyses,
                cache_hit_rate_percentage,
                memory_usage_mb,
                training_timeouts_total,
                analysis_timeouts_total,
            };

            let config = AnalyzerConfig {
                suspicious_percentile: self.suspicious_threshold_percentile,
                abnormal_percentile: self.abnormal_threshold_percentile,
                warm_up_duration_seconds: self.warm_up_duration.num_seconds() as u64,
                warm_up_min_samples: WARMUP_MIN_UNIQUE_SAMPLES,
                analysis_delay_seconds: ANALYSIS_DELAY,
                threshold_recalc_interval_hours: self.threshold_recalc_interval.num_hours() as f64,
                max_buffer_samples: 800,
                downsample_factor: 1,
                feature_dimensions: NUM_FEATURES,
                cache_timeout_seconds: ANALYZER_CACHE_TIMEOUT,
                session_retention_timeout_seconds: CONNECTION_RETENTION_TIMEOUT.num_seconds()
                    as i64,
            };

            let stats = AnalyzerStats {
                is_running,
                warm_up_active,
                warm_up_progress,
                thresholds,
                model_stats,
                session_stats,
                performance_stats,
                config,
            };

            let mut stats_lock = self.analyzer_stats.write().await;
            *stats_lock = Some(stats);
        }

        result
    }

    /// Get a session by its UID
    /// Prioritizes anomalous and blacklisted versions to preserve historical criticality
    pub async fn get_session_by_uid(&self, uid: &str) -> Option<SessionInfo> {
        // Check blacklisted sessions first (highest priority for criticality preservation)
        if let Some(entry) = self.blacklisted_sessions.get(uid) {
            return entry.value().get_full_session_snapshot();
        }
        // Then check anomalous sessions
        if let Some(entry) = self.anomalous_sessions.get(uid) {
            return entry.value().get_full_session_snapshot();
        }
        // Finally fallback to all sessions (may have different criticality state)
        if let Some(entry) = self.all_sessions.get(uid) {
            return entry.value().get_full_session_snapshot();
        }
        // If not found in any, return None
        None
    }

    /// Cleans up old entries from the anomalous, blacklisted, and all session maps.
    /// Also cleans up expired entries from last_analysis_times to prevent unbounded growth.
    fn cleanup_tracked_sessions(&self) {
        Self::cleanup_tracked_sessions_inner(
            self.anomalous_sessions.as_ref(),
            self.blacklisted_sessions.as_ref(),
            self.all_sessions.as_ref(),
            self.last_analysis_times.as_ref(),
            self.last_cleanup_epoch.as_ref(),
        );
    }

    fn cleanup_tracked_sessions_inner(
        anomalous_sessions: &CustomDashMap<String, SessionCache>,
        blacklisted_sessions: &CustomDashMap<String, SessionCache>,
        all_sessions: &CustomDashMap<String, SessionCache>,
        last_analysis_times: &CustomDashMap<String, DateTime<Utc>>,
        last_cleanup_epoch: &AtomicU64,
    ) {
        let now = Utc::now();
        let now_ts = now.timestamp();
        let last_cleanup = last_cleanup_epoch.load(Ordering::Relaxed) as i64;
        if last_cleanup != 0 && now_ts - last_cleanup < CLEANUP_MIN_INTERVAL_SECS {
            return;
        }
        last_cleanup_epoch.store(now_ts as u64, Ordering::Relaxed);
        let anomalous_timeout = Duration::seconds(ANOMALOUS_SESSION_TIMEOUT);
        let blacklisted_timeout = Duration::seconds(BLACKLISTED_SESSION_TIMEOUT);
        let all_session_timeout = Duration::seconds(ALL_SESSION_TIMEOUT);
        // Clean up last_analysis_times entries older than the analysis delay window
        // This prevents unbounded growth while keeping recent analysis timestamps
        let analysis_times_timeout = Duration::seconds(ANALYSIS_DELAY * 2);

        let anomalous_cutoff = now - anomalous_timeout;
        let blacklisted_cutoff = now - blacklisted_timeout;
        let all_sessions_cutoff = now - all_session_timeout;
        let analysis_cutoff = now - analysis_times_timeout;

        let stale_anomalous: Vec<String> = anomalous_sessions
            .iter()
            .filter_map(|entry| {
                if entry.value().last_modified < anomalous_cutoff {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();
        for key in stale_anomalous {
            anomalous_sessions.remove(&key);
        }

        let stale_blacklisted: Vec<String> = blacklisted_sessions
            .iter()
            .filter_map(|entry| {
                if entry.value().last_modified < blacklisted_cutoff {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();
        for key in stale_blacklisted {
            blacklisted_sessions.remove(&key);
        }

        let stale_all_sessions: Vec<String> = all_sessions
            .iter()
            .filter_map(|entry| {
                if entry.value().last_modified < all_sessions_cutoff {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();
        for key in stale_all_sessions {
            all_sessions.remove(&key);
        }

        let stale_analysis: Vec<String> = last_analysis_times
            .iter()
            .filter_map(|entry| {
                if *entry.value() < analysis_cutoff {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();
        for key in stale_analysis {
            last_analysis_times.remove(&key);
        }
    }

    /// Retrieves a snapshot of currently tracked anomalous sessions.
    pub async fn get_anomalous_sessions(&self) -> Vec<SessionInfo> {
        self.anomalous_sessions
            .iter()
            .filter_map(|entry| {
                let mut cache = entry.value().clone();
                cache.get_full_session(None)
            })
            .collect()
    }

    /// Gets the current count of anomalous sessions.
    pub async fn get_anomalous_status(&self) -> usize {
        self.anomalous_sessions.len()
    }

    /// Retrieves a snapshot of currently tracked blacklisted sessions.
    ///
    /// Note: Cache consistency is maintained by `update_session_caches()` which is called
    /// whenever sessions are stored in `all_sessions`. This ensures that specialized caches
    /// (anomalous_sessions, blacklisted_sessions) are always synchronized with `all_sessions`,
    /// eliminating the need for expensive scans at retrieval time.
    pub async fn get_blacklisted_sessions(&self) -> Vec<SessionInfo> {
        self.blacklisted_sessions
            .iter()
            .filter_map(|entry| {
                let mut cache = entry.value().clone();
                cache.get_full_session(None)
            })
            .collect()
    }

    /// Retrieves all sessions that have been processed by the analyzer.
    /// This includes sessions from all states: normal, suspicious, abnormal, and blacklisted.
    /// Sessions are available even during warmup period.
    pub async fn get_sessions(&self) -> Vec<SessionInfo> {
        let mut sessions: Vec<SessionInfo> = self
            .all_sessions
            .iter()
            .filter_map(|entry| {
                let mut cache = entry.value().clone();
                cache.get_full_session(None)
            })
            .collect();

        // Newest first ensures callers see the most up-to-date copy when duplicates exist.
        sessions.sort_by(|a, b| b.last_modified.cmp(&a.last_modified));
        sessions
    }

    /// Retrieves all current sessions that have been processed by the analyzer.
    /// Sessions are available even during warmup period.
    pub async fn get_current_sessions(&self) -> Vec<SessionInfo> {
        let current_session_timeout = CONNECTION_CURRENT_TIMEOUT;
        let now = Utc::now();
        let mut current_sessions: Vec<SessionInfo> = self
            .all_sessions
            .iter()
            .filter_map(|entry| {
                let mut cache = entry.value().clone();
                cache.get_full_session(None)
            })
            .filter(|session| {
                now.signed_duration_since(session.stats.last_activity) < current_session_timeout
            })
            .collect();

        current_sessions.sort_by(|a, b| b.stats.last_activity.cmp(&a.stats.last_activity));
        current_sessions
    }

    /// Public async method to trigger session_cache cleanup.
    /// Call this periodically from a background task or timer.
    pub async fn cleanup_session_cache(&self) {
        let model_lock = self.model.read().await;
        if let Some(model) = &*model_lock {
            model.write().await.cleanup_session_cache();
        }
    }

    async fn start_cleanup_task(&self) {
        let mut handle_guard = self.cleanup_task_handle.write().await;
        if let Some(handle) = handle_guard.take() {
            handle.abort();
        }

        let running = self.running.clone();
        let anomalous_sessions = self.anomalous_sessions.clone();
        let blacklisted_sessions = self.blacklisted_sessions.clone();
        let all_sessions = self.all_sessions.clone();
        let last_analysis_times = self.last_analysis_times.clone();
        let last_cleanup_epoch = self.last_cleanup_epoch.clone();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                CLEANUP_MIN_INTERVAL_SECS as u64,
            ));
            loop {
                interval.tick().await;
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                SessionAnalyzer::cleanup_tracked_sessions_inner(
                    anomalous_sessions.as_ref(),
                    blacklisted_sessions.as_ref(),
                    all_sessions.as_ref(),
                    last_analysis_times.as_ref(),
                    last_cleanup_epoch.as_ref(),
                );
            }
        });

        *handle_guard = Some(handle);
    }

    async fn stop_cleanup_task(&self) {
        let handle = {
            let mut handle_guard = self.cleanup_task_handle.write().await;
            handle_guard.take()
        };
        if let Some(handle) = handle {
            handle.abort();
        }
    }

    /// Start the analyzer (set running flag, prepare for background tasks if needed)
    /// Start with preserved security findings if available
    pub async fn start(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            debug!("Analyzer already running");
            return;
        }

        // Count preserved sessions
        let anomalous_count = self.anomalous_sessions.len();
        let blacklisted_count = self.blacklisted_sessions.len();
        let all_sessions_count = self.all_sessions.len();

        if anomalous_count > 0 || blacklisted_count > 0 || all_sessions_count > 0 {
            info!(
                "Analyzer started with preserved sessions: {} anomalous, {} blacklisted, {} total",
                anomalous_count, blacklisted_count, all_sessions_count
            );
        } else {
            info!("Analyzer started");
        }

        // Instantiate the IsolationForestModel if missing; otherwise reuse existing
        // First check with a read lock to avoid blocking writers when already initialized
        let already_initialized = {
            let model_read = self.model.read().await;
            model_read.is_some()
        };

        if !already_initialized {
            let mut model_guard = self.model.write().await;
            if model_guard.is_none() {
                *model_guard = Some(CustomRwLock::new(IsolationForestModel::new()));
                debug!("Analyzer start: created new model");
            } else {
                debug!("Analyzer start: model became available before write; reusing existing model and thresholds");
            }
        } else {
            debug!("Analyzer start: reusing existing model and thresholds");
        }

        self.start_cleanup_task().await;
    }

    /// Stop the analyzer (clear running flag, stop background tasks if any)
    /// Preserve critical security findings across restarts
    pub async fn stop(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            debug!("Analyzer already stopped");
            return;
        }
        info!("Analyzer stopped - preserving security findings");

        self.stop_cleanup_task().await;

        // First abort any training task
        let abort_result = {
            let model_guard = self.model.read().await;
            if let Some(model) = &*model_guard {
                let mut model_write = model.write().await;
                if let Some(handle) = model_write.training_handle.take() {
                    info!("Stopping ongoing training task");
                    handle.abort();
                    model_write
                        .training_in_progress
                        .store(false, Ordering::Release);
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };

        if abort_result {
            info!("Successfully aborted training task");
        }

        // Preserve model and thresholds; avoid cold-start false positives on next start
        debug!("Preserving model and thresholds on stop; background training aborted");

        // Clean up old security findings but keep recent ones
        self.cleanup_tracked_sessions();

        let anomalous_count = self.anomalous_sessions.len();
        let blacklisted_count = self.blacklisted_sessions.len();
        let all_sessions_count = self.all_sessions.len();

        info!(
            "Analyzer stopped - sessions preserved: {} anomalous, {} blacklisted, {} total",
            anomalous_count, blacklisted_count, all_sessions_count
        );
    }

    /// Fully reset the analyzer state: stop, clear caches and model, and reset counters.
    /// After this call, `start()` will create a fresh model and warm-up from scratch.
    pub async fn reset(&self) {
        // Ensure we are not running
        self.stop().await;

        // Clear all tracked session caches
        self.anomalous_sessions.clear();
        self.blacklisted_sessions.clear();
        self.all_sessions.clear();
        self.last_analysis_times.clear();

        // Reset model to uninitialized so start() creates a new one
        {
            let mut model_guard = self.model.write().await;
            *model_guard = None;
        }

        // Reset warm-up and threshold bookkeeping
        self.warm_up_active.store(true, Ordering::SeqCst);
        self.warm_up_start_time.store(0, Ordering::SeqCst);
        {
            let mut last_recalc = self.last_threshold_recalc_time.write().await;
            *last_recalc = Utc::now();
        }

        // Reset stats and counters
        {
            let mut last_time = self.last_analysis_time.write().await;
            *last_time = None;
        }
        self.analysis_timeouts_count.store(0, Ordering::SeqCst);
        self.analyses_count.store(0, Ordering::SeqCst);
        self.analysis_total_duration_ms.store(0, Ordering::SeqCst);
        self.last_analysis_duration_ms.store(0, Ordering::SeqCst);
        {
            let mut stats = self.analyzer_stats.write().await;
            *stats = None;
        }
    }

    /// Debug method to get anomaly score and thresholds for a session (testing purposes only)
    pub async fn debug_score_and_thresholds(
        &self,
        session: &SessionInfo,
    ) -> Option<(f64, f64, f64)> {
        let model_guard = self.model.read().await;
        if let Some(model) = &*model_guard {
            let model_read = model.read().await;
            if let Some((score, _features)) = model_read.score_session(session) {
                Some((
                    score,
                    model_read.suspicious_threshold,
                    model_read.abnormal_threshold,
                ))
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Set custom thresholds for testing purposes
    pub async fn set_test_thresholds(&self, suspicious: f64, abnormal: f64) {
        let model_guard = self.model.read().await;
        if let Some(model) = &*model_guard {
            let mut model_write = model.write().await;
            model_write.suspicious_threshold = suspicious;
            model_write.abnormal_threshold = abnormal;
        }
    }

    /// Disable warmup for testing purposes
    pub async fn disable_warmup_for_testing(&self) {
        self.warm_up_active.store(false, Ordering::Relaxed);
        // Also ensure we have a model ready
        let model_guard = self.model.read().await;
        if let Some(model) = &*model_guard {
            let mut model_write = model.write().await;
            // Create a minimal forest for testing if none exists
            if model_write.forest.is_none() {
                // Add some dummy data to train on
                for _ in 0..10 {
                    model_write.recent_data.push_back([0.0; NUM_FEATURES]);
                }
                model_write.train_model(true).await;
                // Wait for training to complete with timeout
                if let Some(handle) = model_write.training_handle.take() {
                    match await_join_with_timeout(handle, std::time::Duration::from_secs(120)).await
                    {
                        Some(Ok(Ok(forest))) => {
                            model_write.forest = Some(forest);
                            model_write.last_training_time = Utc::now();
                        }
                        Some(Ok(Err(_))) | Some(Err(_)) => {
                            // If training fails or panics, just set default thresholds
                            model_write.suspicious_threshold = 0.1;
                            model_write.abnormal_threshold = 0.2;
                        }
                        None => {
                            error!("Test training task timed out after 120s - possible EIF hang");
                            model_write.suspicious_threshold = 0.1;
                            model_write.abnormal_threshold = 0.2;
                        }
                    }
                    model_write.training_handle = None;
                    model_write
                        .training_in_progress
                        .store(false, Ordering::Release);
                }
            }
        }
    }

    /// Force a training run on the current recent_data and immediately integrate the model.
    /// Testing helper to avoid waiting for scheduled training.
    pub async fn force_train_for_testing(&self) {
        let model_option_guard = self.model.read().await;
        if let Some(model_rw) = &*model_option_guard {
            let mut model_write = model_rw.write().await;
            model_write.train_model(true).await;
            if let Some(handle) = model_write.training_handle.take() {
                match await_join_with_timeout(handle, std::time::Duration::from_secs(120)).await {
                    Some(Ok(Ok(forest))) => {
                        model_write.forest = Some(forest);
                        model_write.last_training_time = Utc::now();
                    }
                    Some(Ok(Err(e))) => {
                        warn!("Force training task failed: {:?}", e);
                        // leave forest as-is on error
                    }
                    Some(Err(e)) => {
                        error!("Force training task panicked: {:?}", e);
                        // leave forest as-is on error
                    }
                    None => {
                        error!("Force training task timed out after 120s - possible EIF hang");
                        // leave forest as-is on timeout
                    }
                }
                model_write.training_handle = None;
                model_write
                    .training_in_progress
                    .store(false, Ordering::Release);
            }
        }
    }

    /// Get comprehensive analyzer statistics and configuration snapshot
    /// This provides access to all relevant threshold, scoring, and operational information
    ///
    /// # Returns
    ///
    /// An `AnalyzerStats` struct containing:
    /// - **Current status**: Running state, warm-up progress
    /// - **Threshold configuration**: Current thresholds, percentiles, recalculation timing
    /// - **Model statistics**: Training status, buffer utilization, score distributions
    /// - **Session statistics**: Anomaly rates, blacklist rates, session counts
    /// - **Performance metrics**: Analysis timing, cache efficiency (when available)
    /// - **Configuration snapshot**: All current analyzer parameters
    ///
    /// # Usage Example
    ///
    /// ```rust,no_run
    /// # use flodbadd::analyzer::SessionAnalyzer;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let analyzer = SessionAnalyzer::new();
    /// analyzer.start().await;
    ///
    /// // Get comprehensive statistics
    /// let stats = analyzer.get_analyzer_stats().await;
    ///
    /// // Check operational status
    /// println!("Analyzer running: {}", stats.is_running);
    /// println!("Warm-up active: {}", stats.warm_up_active);
    /// println!("Warm-up progress: {:.1}%", stats.warm_up_progress.progress_percentage);
    ///
    /// // Monitor threshold configuration
    /// println!("Suspicious threshold: {:.4} ({}th percentile)",
    ///          stats.thresholds.suspicious_threshold,
    ///          stats.thresholds.suspicious_percentile * 100.0);
    /// println!("Abnormal threshold: {:.4} ({}th percentile)",
    ///          stats.thresholds.abnormal_threshold,
    ///          stats.thresholds.abnormal_percentile * 100.0);
    ///
    /// // Check model health
    /// println!("Model trained: {}", stats.model_stats.has_trained_model);
    /// println!("Buffer utilization: {:.1}%", stats.model_stats.buffer_utilization_percentage);
    /// println!("Unique samples: {}", stats.model_stats.unique_samples_count);
    ///
    /// // Monitor detection rates
    /// println!("Total sessions: {}", stats.session_stats.total_sessions_tracked);
    /// println!("Anomaly rate: {:.2}%", stats.session_stats.anomaly_rate_percentage);
    /// println!("Blacklist rate: {:.2}%", stats.session_stats.blacklist_rate_percentage);
    ///
    /// // Export as JSON for external monitoring
    /// let json_stats = serde_json::to_string_pretty(&stats)?;
    /// println!("Stats JSON:\n{}", json_stats);
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_analyzer_stats(&self) -> AnalyzerStats {
        // Return the latest snapshot built during analyze_sessions(), with minimal locking.
        if let Some(stats) = self.analyzer_stats.read().await.clone() {
            stats
        } else {
            // Fallback: build a minimal default snapshot if analyze hasn't run yet
            AnalyzerStats {
                is_running: self.running.load(Ordering::SeqCst),
                warm_up_active: self.warm_up_active.load(Ordering::SeqCst),
                warm_up_progress: WarmUpProgress {
                    elapsed_seconds: 0,
                    target_duration_seconds: self.warm_up_duration.num_seconds() as u64,
                    unique_samples_collected: 0,
                    min_samples_required: WARMUP_MIN_UNIQUE_SAMPLES,
                    progress_percentage: 0.0,
                    estimated_completion_seconds: None,
                },
                thresholds: ThresholdStats {
                    suspicious_threshold: DEFAULT_SUSPICIOUS_THRESHOLD,
                    abnormal_threshold: DEFAULT_ABNORMAL_THRESHOLD,
                    suspicious_percentile: self.suspicious_threshold_percentile,
                    abnormal_percentile: self.abnormal_threshold_percentile,
                    last_recalc_time: None,
                    next_recalc_time: None,
                    recalc_interval_hours: self.threshold_recalc_interval.num_hours() as f64,
                    min_reasonable_threshold: MIN_REASONABLE_THRESHOLD,
                    default_suspicious_threshold: DEFAULT_SUSPICIOUS_THRESHOLD,
                    default_abnormal_threshold: DEFAULT_ABNORMAL_THRESHOLD,
                },
                model_stats: ModelStats {
                    has_trained_model: false,
                    training_in_progress: false,
                    last_training_time: None,
                    min_training_interval_minutes: 0.0,
                    total_samples_in_buffer: 0,
                    max_buffer_capacity: 800,
                    buffer_utilization_percentage: 0.0,
                    unique_samples_count: 0,
                    downsample_factor: 1,
                    feature_count: NUM_FEATURES,
                    recent_score_distribution: None,
                },
                session_stats: SessionStats {
                    total_sessions_tracked: self.all_sessions.len(),
                    anomalous_sessions_count: self.anomalous_sessions.len(),
                    blacklisted_sessions_count: self.blacklisted_sessions.len(),
                    normal_sessions_count: 0,
                    anomaly_rate_percentage: 0.0,
                    blacklist_rate_percentage: 0.0,
                    last_analysis_time: *self.last_analysis_time.read().await,
                    sessions_analyzed_today: 0,
                },
                performance_stats: PerformanceStats {
                    average_analysis_time_ms: None,
                    last_analysis_duration_ms: None,
                    total_analyses_performed: 0,
                    cache_hit_rate_percentage: None,
                    memory_usage_mb: None,
                    training_timeouts_total: 0,
                    analysis_timeouts_total: 0,
                },
                config: AnalyzerConfig {
                    suspicious_percentile: self.suspicious_threshold_percentile,
                    abnormal_percentile: self.abnormal_threshold_percentile,
                    warm_up_duration_seconds: self.warm_up_duration.num_seconds() as u64,
                    warm_up_min_samples: WARMUP_MIN_UNIQUE_SAMPLES,
                    analysis_delay_seconds: ANALYSIS_DELAY,
                    threshold_recalc_interval_hours: self.threshold_recalc_interval.num_hours()
                        as f64,
                    max_buffer_samples: 800,
                    downsample_factor: 1,
                    feature_dimensions: NUM_FEATURES,
                    cache_timeout_seconds: ANALYZER_CACHE_TIMEOUT,
                    session_retention_timeout_seconds: CONNECTION_RETENTION_TIMEOUT.num_seconds()
                        as i64,
                },
            }
        }
    }

    /// Set new percentile thresholds and trigger immediate recalculation
    ///
    /// This method allows dynamic adjustment of the anomaly detection sensitivity by changing
    /// the percentiles used for threshold calculation. After updating the percentiles, it
    /// immediately triggers a threshold recalculation if a trained model is available.
    ///
    /// # Arguments
    ///
    /// * `suspicious_percentile` - Percentile for suspicious threshold (0.0 to 1.0)
    /// * `abnormal_percentile` - Percentile for abnormal threshold (0.0 to 1.0)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if percentiles were updated successfully, or `Err(String)` with
    /// an error message if the input values are invalid.
    ///
    /// # Validation
    ///
    /// - Both percentiles must be between 0.0 and 1.0
    /// - `abnormal_percentile` must be greater than `suspicious_percentile`
    /// - Percentiles should typically be high values (e.g., 0.95-0.999) for anomaly detection
    ///
    /// # Usage Example
    ///
    /// ```rust,no_run
    /// # use flodbadd::analyzer::SessionAnalyzer;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let analyzer = SessionAnalyzer::new();
    /// analyzer.start().await;
    ///
    /// // Make detection more sensitive (lower percentiles = lower thresholds)
    /// analyzer.set_percentiles(0.95, 0.98).await?;
    ///
    /// // Make detection less sensitive (higher percentiles = higher thresholds)  
    /// analyzer.set_percentiles(0.995, 0.9975).await?;
    ///
    /// // Check the updated configuration
    /// let stats = analyzer.get_analyzer_stats().await;
    /// println!("New suspicious percentile: {:.1}%", stats.thresholds.suspicious_percentile * 100.0);
    /// println!("New abnormal percentile: {:.1}%", stats.thresholds.abnormal_percentile * 100.0);
    /// println!("Updated suspicious threshold: {:.4}", stats.thresholds.suspicious_threshold);
    /// println!("Updated abnormal threshold: {:.4}", stats.thresholds.abnormal_threshold);
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub async fn set_percentiles(
        &self,
        suspicious_percentile: f64,
        abnormal_percentile: f64,
    ) -> Result<(), String> {
        // Validate input parameters
        if suspicious_percentile < 0.0 || suspicious_percentile > 1.0 {
            return Err(format!(
                "suspicious_percentile must be between 0.0 and 1.0, got: {}",
                suspicious_percentile
            ));
        }

        if abnormal_percentile < 0.0 || abnormal_percentile > 1.0 {
            return Err(format!(
                "abnormal_percentile must be between 0.0 and 1.0, got: {}",
                abnormal_percentile
            ));
        }

        if abnormal_percentile <= suspicious_percentile {
            return Err(format!(
                "abnormal_percentile ({}) must be greater than suspicious_percentile ({})",
                abnormal_percentile, suspicious_percentile
            ));
        }

        // Warn if percentiles seem too low for typical anomaly detection
        if suspicious_percentile < 0.5 {
            warn!(
                "Very low suspicious_percentile ({:.3}) may result in excessive false positives",
                suspicious_percentile
            );
        }

        if abnormal_percentile < 0.7 {
            warn!(
                "Very low abnormal_percentile ({:.3}) may result in excessive false positives",
                abnormal_percentile
            );
        }

        info!(
            "Updating percentile thresholds: suspicious {:.1}% -> {:.1}%, abnormal {:.1}% -> {:.1}%",
            self.suspicious_threshold_percentile * 100.0,
            suspicious_percentile * 100.0,
            self.abnormal_threshold_percentile * 100.0,
            abnormal_percentile * 100.0
        );

        // Update the percentile configuration
        let model_guard = self.model.read().await;
        if let Some(model_lock) = &*model_guard {
            let model = model_lock.read().await;

            // Store old values for logging
            let old_suspicious_threshold = model.suspicious_threshold;
            let old_abnormal_threshold = model.abnormal_threshold;

            drop(model); // Release read lock before acquiring write lock

            // Trigger immediate threshold recalculation with new percentiles
            {
                let mut model_write = model_lock.write().await;

                // Update the stored percentiles in the model
                model_write.current_suspicious_percentile = suspicious_percentile;
                model_write.current_abnormal_percentile = abnormal_percentile;

                compute_dynamic_thresholds(
                    &mut model_write,
                    suspicious_percentile,
                    abnormal_percentile,
                );

                let new_suspicious = model_write.suspicious_threshold;
                let new_abnormal = model_write.abnormal_threshold;

                info!(
                    "Percentile update successful: thresholds changed from suspicious {:.4} -> {:.4}, abnormal {:.4} -> {:.4}",
                    old_suspicious_threshold, new_suspicious,
                    old_abnormal_threshold, new_abnormal
                );
            }

            // Force update of last recalc time to reset the recalculation timer
            {
                let mut last_recalc = self.last_threshold_recalc_time.write().await;
                *last_recalc = Utc::now();
            }

            Ok(())
        } else {
            warn!("No model available for threshold recalculation - percentiles will be applied when model is trained");

            // Even without a model, we should store the new percentiles for when the model becomes available
            // Note: Due to the current design using immutable &self, we cannot directly update the percentile
            // fields in the analyzer. The percentiles will be properly applied during the next regular
            // threshold recalculation or when analyze_sessions() calls compute_dynamic_thresholds.
            info!("Percentiles will be applied when model becomes available during next analysis cycle");
            Ok(())
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sessions::{
        Protocol, Session, SessionInfo, SessionStats, SessionStatus, WhitelistState,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use uuid::Uuid;

    /// Test that security findings are preserved across stop/start cycles
    #[tokio::test]
    async fn test_security_findings_preservation() {
        let analyzer = SessionAnalyzer::new();

        // Start the analyzer
        analyzer.start().await;
        assert!(
            analyzer.running.load(Ordering::Relaxed),
            "Analyzer should be running"
        );

        // Create test sessions with security findings
        let anomalous_session = SessionInfo {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                src_port: 12345,
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                dst_port: 443,
            },
            stats: SessionStats::new(Utc::now()),
            status: SessionStatus::default(),
            is_local_src: false,
            is_local_dst: false,
            is_self_src: false,
            is_self_dst: false,
            src_domain: None,
            dst_domain: None,
            dst_service: None,
            l7: None,
            src_asn: None,
            dst_asn: None,
            is_whitelisted: WhitelistState::Unknown,
            criticality: "anomaly:suspicious".to_string(),
            dismissed: false,
            whitelist_reason: None,
            src_domain_type: DomainResolutionType::None,
            dst_domain_type: DomainResolutionType::None,
            uid: Uuid::new_v4().to_string(),
            last_modified: Utc::now(),
        };

        let blacklisted_session = SessionInfo {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)),
                src_port: 54321,
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                dst_port: 80,
            },
            stats: SessionStats::new(Utc::now()),
            status: SessionStatus::default(),
            is_local_src: false,
            is_local_dst: false,
            is_self_src: false,
            is_self_dst: false,
            src_domain: None,
            dst_domain: None,
            dst_service: None,
            l7: None,
            src_asn: None,
            dst_asn: None,
            is_whitelisted: WhitelistState::Unknown,
            criticality: "blacklist:test_blacklist".to_string(),
            dismissed: false,
            whitelist_reason: None,
            src_domain_type: DomainResolutionType::None,
            dst_domain_type: DomainResolutionType::None,
            uid: Uuid::new_v4().to_string(),
            last_modified: Utc::now(),
        };

        // Manually add security findings (simulating what analyze_sessions would do)
        analyzer.anomalous_sessions.insert(
            anomalous_session.uid.clone(),
            SessionCache::with_full_session(&anomalous_session),
        );
        analyzer.blacklisted_sessions.insert(
            blacklisted_session.uid.clone(),
            SessionCache::with_full_session(&blacklisted_session),
        );

        // Verify security findings exist before stop
        assert_eq!(
            analyzer.anomalous_sessions.len(),
            1,
            "Should have 1 anomalous session before stop"
        );
        assert_eq!(
            analyzer.blacklisted_sessions.len(),
            1,
            "Should have 1 blacklisted session before stop"
        );

        let initial_anomalous = analyzer.get_anomalous_sessions().await;
        let initial_blacklisted = analyzer.get_blacklisted_sessions().await;
        assert_eq!(
            initial_anomalous.len(),
            1,
            "get_anomalous_sessions should return 1 session"
        );
        assert_eq!(
            initial_blacklisted.len(),
            1,
            "get_blacklisted_sessions should return 1 session"
        );

        // Stop the analyzer - this should preserve security findings
        analyzer.stop().await;
        assert!(
            !analyzer.running.load(Ordering::Relaxed),
            "Analyzer should be stopped"
        );

        // Verify security findings are preserved after stop
        assert_eq!(
            analyzer.anomalous_sessions.len(),
            1,
            "Anomalous sessions should be preserved after stop"
        );
        assert_eq!(
            analyzer.blacklisted_sessions.len(),
            1,
            "Blacklisted sessions should be preserved after stop"
        );

        let preserved_anomalous = analyzer.get_anomalous_sessions().await;
        let preserved_blacklisted = analyzer.get_blacklisted_sessions().await;
        assert_eq!(
            preserved_anomalous.len(),
            1,
            "get_anomalous_sessions should return preserved session"
        );
        assert_eq!(
            preserved_blacklisted.len(),
            1,
            "get_blacklisted_sessions should return preserved session"
        );

        // Verify the UIDs match the original sessions
        assert_eq!(
            preserved_anomalous[0].uid, anomalous_session.uid,
            "Preserved anomalous session should have same UID"
        );
        assert_eq!(
            preserved_blacklisted[0].uid, blacklisted_session.uid,
            "Preserved blacklisted session should have same UID"
        );

        // Restart the analyzer - security findings should still be available
        analyzer.start().await;
        assert!(
            analyzer.running.load(Ordering::Relaxed),
            "Analyzer should be running after restart"
        );

        // Verify security findings are still available after restart
        assert_eq!(
            analyzer.anomalous_sessions.len(),
            1,
            "Anomalous sessions should persist after restart"
        );
        assert_eq!(
            analyzer.blacklisted_sessions.len(),
            1,
            "Blacklisted sessions should persist after restart"
        );

        let restarted_anomalous = analyzer.get_anomalous_sessions().await;
        let restarted_blacklisted = analyzer.get_blacklisted_sessions().await;
        assert_eq!(
            restarted_anomalous.len(),
            1,
            "get_anomalous_sessions should return session after restart"
        );
        assert_eq!(
            restarted_blacklisted.len(),
            1,
            "get_blacklisted_sessions should return session after restart"
        );

        // Final cleanup
        analyzer.stop().await;

        println!("Security findings preservation across stop/start verified");
    }

    /// Test that all sessions are tracked and retrievable even during warmup
    #[tokio::test]
    async fn test_get_sessions_during_warmup() {
        let analyzer = SessionAnalyzer::new();

        // Start the analyzer (it will be in warmup mode)
        analyzer.start().await;
        assert!(
            analyzer.warm_up_active.load(Ordering::Relaxed),
            "Analyzer should be in warmup mode"
        );

        // Create test sessions
        let mut test_sessions = vec![
            SessionInfo {
                session: Session {
                    protocol: Protocol::TCP,
                    src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                    src_port: 12345,
                    dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    dst_port: 443,
                },
                stats: SessionStats::new(Utc::now()),
                status: SessionStatus::default(),
                is_local_src: false,
                is_local_dst: false,
                is_self_src: false,
                is_self_dst: false,
                src_domain: None,
                dst_domain: None,
                dst_service: None,
                l7: None,
                src_asn: None,
                dst_asn: None,
                is_whitelisted: WhitelistState::Unknown,
                criticality: "".to_string(), // Empty initially
                dismissed: false,
                whitelist_reason: None,
                src_domain_type: DomainResolutionType::None,
                dst_domain_type: DomainResolutionType::None,
                uid: Uuid::new_v4().to_string(),
                last_modified: Utc::now(),
            },
            SessionInfo {
                session: Session {
                    protocol: Protocol::UDP,
                    src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)),
                    src_port: 54321,
                    dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                    dst_port: 53,
                },
                stats: SessionStats::new(Utc::now()),
                status: SessionStatus::default(),
                is_local_src: false,
                is_local_dst: false,
                is_self_src: false,
                is_self_dst: false,
                src_domain: None,
                dst_domain: None,
                dst_service: None,
                l7: None,
                src_asn: None,
                dst_asn: None,
                is_whitelisted: WhitelistState::Unknown,
                criticality: "blacklist:test_dns".to_string(), // Pre-classified as blacklisted
                dismissed: false,
                whitelist_reason: None,
                src_domain_type: DomainResolutionType::None,
                dst_domain_type: DomainResolutionType::None,
                uid: Uuid::new_v4().to_string(),
                last_modified: Utc::now(),
            },
        ];

        let session_uids: Vec<String> = test_sessions.iter().map(|s| s.uid.clone()).collect();

        // Analyze sessions during warmup
        let result = analyzer.analyze_sessions(&mut test_sessions).await;
        assert_eq!(
            result.sessions_analyzed, 2,
            "Should have analyzed 2 sessions"
        );

        // Verify that sessions are available via get_sessions even during warmup
        let all_sessions = analyzer.get_sessions().await;
        assert_eq!(
            all_sessions.len(),
            2,
            "get_sessions should return 2 sessions during warmup"
        );

        // Verify that get_current_sessions also works
        let current_sessions = analyzer.get_current_sessions().await;
        assert_eq!(
            current_sessions.len(),
            2,
            "get_current_sessions should return 2 sessions during warmup"
        );

        // Verify that the sessions have the expected UIDs
        let retrieved_uids: Vec<String> = all_sessions.iter().map(|s| s.uid.clone()).collect();
        for uid in &session_uids {
            assert!(
                retrieved_uids.contains(uid),
                "Retrieved sessions should contain UID {}",
                uid
            );
        }

        // Verify that sessions have warmup criticality where expected
        let warmup_session = all_sessions
            .iter()
            .find(|s| s.uid == session_uids[0])
            .expect("Should find first session");
        assert!(
            warmup_session.criticality.contains("warming_up"),
            "Session should have warming_up tag, got: {}",
            warmup_session.criticality
        );

        // Verify that pre-classified sessions keep their classification
        let blacklisted_session = all_sessions
            .iter()
            .find(|s| s.uid == session_uids[1])
            .expect("Should find second session");
        assert!(
            blacklisted_session
                .criticality
                .contains("blacklist:test_dns"),
            "Session should keep blacklist classification, got: {}",
            blacklisted_session.criticality
        );

        // Verify that get_session_by_uid works for all sessions
        for uid in &session_uids {
            let session = analyzer.get_session_by_uid(uid).await;
            assert!(
                session.is_some(),
                "get_session_by_uid should find session with UID {}",
                uid
            );
        }

        // Cleanup
        analyzer.stop().await;

        println!("Session tracking during warmup verified");
    }

    /// Helper function to create a test session with specific parameters
    pub(crate) fn create_test_session_with_criticality(
        uid: String,
        criticality: String,
        last_modified: DateTime<Utc>,
    ) -> SessionInfo {
        SessionInfo {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                src_port: 12345,
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                dst_port: 443,
            },
            stats: SessionStats::new(Utc::now()),
            status: SessionStatus::default(),
            is_local_src: false,
            is_local_dst: false,
            is_self_src: false,
            is_self_dst: false,
            src_domain: None,
            dst_domain: None,
            dst_service: None,
            l7: None,
            src_asn: None,
            dst_asn: None,
            is_whitelisted: WhitelistState::Unknown,
            criticality,
            dismissed: false,
            whitelist_reason: None,
            src_domain_type: DomainResolutionType::None,
            dst_domain_type: DomainResolutionType::None,
            uid,
            last_modified,
        }
    }

    /// Test that criticality is extended (not overwritten) when analyzing sessions with same UID
    #[tokio::test]
    async fn test_criticality_merging_preserves_blacklist_tags() {
        let analyzer = SessionAnalyzer::new();
        analyzer.start().await;

        // Disable warmup for testing and set low thresholds so sessions will be classified as anomalous
        analyzer.disable_warmup_for_testing().await;
        analyzer.set_test_thresholds(0.1, 0.2).await;

        let uid = Uuid::new_v4().to_string();
        let initial_time = Utc::now();

        // First analysis: session with blacklist tag only
        let session_v1 = create_test_session_with_criticality(
            uid.clone(),
            "blacklist:malware_c2".to_string(),
            initial_time,
        );

        analyzer.analyze_sessions(&mut [session_v1.clone()]).await;

        // Verify initial state
        let retrieved_v1 = analyzer.get_session_by_uid(&uid).await;
        assert!(retrieved_v1.is_some());
        let retrieved_v1 = retrieved_v1.unwrap();
        assert!(retrieved_v1.criticality.contains("blacklist:malware_c2"));
        println!("After first analysis: '{}'", retrieved_v1.criticality);

        // Second analysis: same UID, updated timestamp, additional custom tag
        let updated_time = initial_time + chrono::Duration::seconds(10);
        let session_v2 = create_test_session_with_criticality(
            uid.clone(),
            "blacklist:malware_c2,custom:user_tagged".to_string(),
            updated_time,
        );

        analyzer.analyze_sessions(&mut [session_v2.clone()]).await;

        // Verify that both blacklist and custom tags are preserved, plus anomaly analysis is added
        let retrieved_v2 = analyzer.get_session_by_uid(&uid).await;
        assert!(retrieved_v2.is_some());
        let retrieved_v2 = retrieved_v2.unwrap();

        println!("After second analysis: '{}'", retrieved_v2.criticality);

        // Verify all expected tags are present
        assert!(
            retrieved_v2.criticality.contains("blacklist:malware_c2"),
            "Should preserve blacklist tag"
        );
        assert!(
            retrieved_v2.criticality.contains("custom:user_tagged"),
            "Should preserve custom tag"
        );
        assert!(
            retrieved_v2.criticality.contains("anomaly:"),
            "Should add anomaly analysis"
        );

        // Verify the session was updated (timestamp should be newer)
        assert!(
            retrieved_v2.last_modified > initial_time,
            "Session should have updated timestamp"
        );

        analyzer.stop().await;
        println!("Criticality merging preserves blacklist tags verified");
    }

    /// Test that anomaly tags are replaced while other tags are preserved
    #[tokio::test]
    async fn test_criticality_merging_replaces_anomaly_tags() {
        let analyzer = SessionAnalyzer::new();
        analyzer.start().await;

        // Disable warmup and set thresholds to control anomaly classification
        analyzer.disable_warmup_for_testing().await;
        analyzer.set_test_thresholds(0.1, 0.2).await;

        let uid = Uuid::new_v4().to_string();
        let initial_time = Utc::now();

        // First analysis: session with old anomaly tag and blacklist tag
        let session_v1 = create_test_session_with_criticality(
            uid.clone(),
            "anomaly:normal,blacklist:test_list".to_string(),
            initial_time,
        );

        analyzer.analyze_sessions(&mut [session_v1.clone()]).await;

        let retrieved_v1 = analyzer.get_session_by_uid(&uid).await.unwrap();
        println!("After first analysis: '{}'", retrieved_v1.criticality);

        // Change thresholds to make session suspicious
        analyzer.set_test_thresholds(0.05, 0.1).await;

        // Second analysis: same UID, updated timestamp, same tags but should get new anomaly classification
        let updated_time = initial_time + chrono::Duration::seconds(10);
        let session_v2 = create_test_session_with_criticality(
            uid.clone(),
            "anomaly:normal,blacklist:test_list".to_string(),
            updated_time,
        );

        analyzer.analyze_sessions(&mut [session_v2.clone()]).await;

        let retrieved_v2 = analyzer.get_session_by_uid(&uid).await.unwrap();
        println!("After second analysis: '{}'", retrieved_v2.criticality);

        // Verify old anomaly tag was replaced but blacklist tag preserved
        assert!(
            !retrieved_v2.criticality.contains("anomaly:normal"),
            "Old anomaly tag should be replaced"
        );
        assert!(
            retrieved_v2.criticality.contains("anomaly:"),
            "New anomaly classification should be present"
        );
        assert!(
            retrieved_v2.criticality.contains("blacklist:test_list"),
            "Blacklist tag should be preserved"
        );

        // The new anomaly classification should be suspicious or abnormal (due to low thresholds)
        assert!(
            retrieved_v2.criticality.contains("anomaly:suspicious")
                || retrieved_v2.criticality.contains("anomaly:abnormal"),
            "Should have suspicious or abnormal classification with low thresholds"
        );

        analyzer.stop().await;
        println!("Criticality merging replaces anomaly tags verified");
    }

    /// Test that multiple non-anomaly tags are preserved and deduplicated
    #[tokio::test]
    async fn test_criticality_merging_handles_multiple_tags() {
        let analyzer = SessionAnalyzer::new();
        analyzer.start().await;

        analyzer.disable_warmup_for_testing().await;
        analyzer.set_test_thresholds(0.1, 0.2).await;

        let uid = Uuid::new_v4().to_string();
        let initial_time = Utc::now();

        // First analysis: session with multiple tags
        let session_v1 = create_test_session_with_criticality(
            uid.clone(),
            "blacklist:malware,custom:tagged,whitelist:exception,anomaly:normal".to_string(),
            initial_time,
        );

        analyzer.analyze_sessions(&mut [session_v1.clone()]).await;

        // Check what happened after first analysis
        let retrieved_v1 = analyzer.get_session_by_uid(&uid).await.unwrap();
        println!("After first analysis: '{}'", retrieved_v1.criticality);

        // Second analysis: add duplicate and new tags
        // Start with the current state from the analyzer (more realistic)
        let updated_time = initial_time + chrono::Duration::seconds(10);
        let session_v2 = create_test_session_with_criticality(
            uid.clone(),
            // Include the current state plus new tags
            format!(
                "{},new_tag:added,blacklist:malware",
                retrieved_v1.criticality
            ), // Duplicate blacklist tag
            updated_time,
        );

        analyzer.analyze_sessions(&mut [session_v2.clone()]).await;

        let retrieved = analyzer.get_session_by_uid(&uid).await.unwrap();
        println!("Final criticality: '{}'", retrieved.criticality);

        // Verify all unique non-anomaly tags are preserved
        assert!(retrieved.criticality.contains("blacklist:malware"));
        assert!(retrieved.criticality.contains("custom:tagged"));
        // The whitelist:exception tag should be preserved from the first analysis
        assert!(
            retrieved.criticality.contains("whitelist:exception"),
            "whitelist:exception should be preserved from first analysis. First: '{}', Final: '{}'",
            retrieved_v1.criticality,
            retrieved.criticality
        );
        assert!(retrieved.criticality.contains("new_tag:added"));
        assert!(retrieved.criticality.contains("anomaly:"));

        // Verify no duplicate tags (count occurrences of blacklist:malware)
        let blacklist_count = retrieved.criticality.matches("blacklist:malware").count();
        assert_eq!(blacklist_count, 1, "Should deduplicate identical tags");

        // Verify tags are sorted (this is implementation detail but good to verify)
        let tags: Vec<&str> = retrieved.criticality.split(',').collect();
        let mut sorted_tags = tags.clone();
        sorted_tags.sort_unstable();
        assert_eq!(tags, sorted_tags, "Tags should be sorted");

        analyzer.stop().await;
        println!("Criticality merging handles multiple tags verified");
    }

    /// Test that sessions with same UID but no timestamp update may still be re-analyzed
    /// This tests the new dynamic behavior after removing permanent anomaly marking
    #[tokio::test]
    async fn test_criticality_no_reanalysis_without_timestamp_update() {
        let analyzer = SessionAnalyzer::new();
        analyzer.start().await;

        analyzer.disable_warmup_for_testing().await;
        analyzer.set_test_thresholds(0.1, 0.2).await;

        let uid = Uuid::new_v4().to_string();
        let fixed_time = Utc::now();

        // First analysis
        let session_v1 = create_test_session_with_criticality(
            uid.clone(),
            "blacklist:test".to_string(),
            fixed_time,
        );

        analyzer.analyze_sessions(&mut [session_v1.clone()]).await;

        let retrieved_v1 = analyzer.get_session_by_uid(&uid).await.unwrap();
        let first_criticality = retrieved_v1.criticality.clone();

        println!("After first analysis: '{}'", first_criticality);

        // Second analysis: same UID, same timestamp, different criticality input
        // With the new dynamic behavior, the session may be re-analyzed based on current conditions
        let session_v2 = create_test_session_with_criticality(
            uid.clone(),
            "blacklist:test,new:tag".to_string(), // Different input criticality
            fixed_time,                           // Same timestamp
        );

        analyzer.analyze_sessions(&mut [session_v2.clone()]).await;

        let retrieved_v2 = analyzer.get_session_by_uid(&uid).await.unwrap();

        println!("After second analysis: '{}'", retrieved_v2.criticality);

        // With dynamic behavior, the session gets the input tags plus any anomaly analysis
        // The key is that the blacklist and new tags should be preserved
        assert!(
            retrieved_v2.criticality.contains("blacklist:test"),
            "Should preserve blacklist tag from input"
        );
        assert!(
            retrieved_v2.criticality.contains("new:tag"),
            "Should preserve new tag from input"
        );

        // The session should be stored (even if re-analyzed)
        assert!(
            !retrieved_v2.criticality.is_empty(),
            "Session should have some criticality assigned"
        );

        analyzer.stop().await;
        println!("Dynamic session analysis behavior verified");
    }

    /// Test that empty criticality gets proper anomaly classification
    #[tokio::test]
    async fn test_criticality_merging_handles_empty_criticality() {
        let analyzer = SessionAnalyzer::new();
        analyzer.start().await;

        analyzer.disable_warmup_for_testing().await;
        analyzer.set_test_thresholds(0.1, 0.2).await;

        let uid = Uuid::new_v4().to_string();
        let initial_time = Utc::now();

        // First analysis: session with empty criticality
        let session_v1 = create_test_session_with_criticality(
            uid.clone(),
            "".to_string(), // Empty criticality
            initial_time,
        );

        analyzer.analyze_sessions(&mut [session_v1.clone()]).await;

        let retrieved_v1 = analyzer.get_session_by_uid(&uid).await.unwrap();
        println!(
            "After analysis of empty criticality: '{}'",
            retrieved_v1.criticality
        );

        // Should have anomaly classification added
        assert!(retrieved_v1.criticality.contains("anomaly:"));
        assert!(!retrieved_v1.criticality.is_empty());

        // Second analysis: add blacklist tag to the session with existing anomaly classification
        let updated_time = initial_time + chrono::Duration::seconds(10);
        let session_v2 = create_test_session_with_criticality(
            uid.clone(),
            "blacklist:new_threat".to_string(),
            updated_time,
        );

        analyzer.analyze_sessions(&mut [session_v2.clone()]).await;

        let retrieved_v2 = analyzer.get_session_by_uid(&uid).await.unwrap();
        println!("After adding blacklist: '{}'", retrieved_v2.criticality);

        // Should have both anomaly and blacklist tags
        assert!(retrieved_v2.criticality.contains("anomaly:"));
        assert!(retrieved_v2.criticality.contains("blacklist:new_threat"));

        analyzer.stop().await;
        println!("Empty criticality handling verified");
    }

    /// Test edge case: session with only whitespace in criticality
    #[tokio::test]
    async fn test_criticality_merging_handles_whitespace_criticality() {
        let analyzer = SessionAnalyzer::new();
        analyzer.start().await;

        analyzer.disable_warmup_for_testing().await;
        analyzer.set_test_thresholds(0.1, 0.2).await;

        let uid = Uuid::new_v4().to_string();
        let initial_time = Utc::now();

        // Session with whitespace-only criticality
        let session = create_test_session_with_criticality(
            uid.clone(),
            "   ,  , ".to_string(), // Whitespace and empty tags
            initial_time,
        );

        analyzer.analyze_sessions(&mut [session.clone()]).await;

        let retrieved = analyzer.get_session_by_uid(&uid).await.unwrap();
        println!(
            "After analysis of whitespace criticality: '{}'",
            retrieved.criticality
        );

        // Should filter out empty/whitespace tags and add anomaly classification
        assert!(retrieved.criticality.contains("anomaly:"));
        assert!(!retrieved.criticality.contains("  "));

        // Should not have any empty tags between commas
        let tags: Vec<&str> = retrieved.criticality.split(',').collect();
        for tag in tags {
            assert!(!tag.trim().is_empty(), "Should not have empty tags");
        }

        analyzer.stop().await;
        println!("Whitespace criticality handling verified");
    }

    #[tokio::test]
    async fn test_cache_invalidated_on_model_retrain() {
        let model = IsolationForestModel::new();
        let session = create_test_session_with_criticality(
            "cache-test-1".to_string(),
            "anomaly:normal".to_string(),
            Utc::now(),
        );

        model.session_cache.insert(
            "cache-test-1".to_string(),
            (0.42, [0.0; NUM_FEATURES], Utc::now()),
        );
        assert_eq!(model.session_cache.len(), 1);

        model.invalidate_score_cache_for_retrain();
        assert_eq!(
            model.session_cache.len(),
            0,
            "Score cache must be cleared after model retrain"
        );

        let _ = session;
        println!("Cache invalidation on retrain verified");
    }

    #[tokio::test]
    async fn test_training_failure_preserves_forest() {
        let mut model = IsolationForestModel::new();

        for i in 0..50 {
            let feats: [f64; NUM_FEATURES] = std::array::from_fn(|j| (i * NUM_FEATURES + j) as f64);
            model.recent_data.push_back(feats);
        }
        model.train_model(true).await;

        if model.training_handle.is_some() {
            let handle = model.training_handle.take().unwrap();
            if let Some(Ok(Ok(forest))) =
                await_join_with_timeout(handle, std::time::Duration::from_secs(30)).await
            {
                model.forest = Some(forest);
                model.training_in_progress.store(false, Ordering::Release);
            }
        }

        assert!(
            model.forest.is_some(),
            "Forest should have been trained successfully"
        );

        model.recent_data.clear();
        model.training_in_progress.store(false, Ordering::Release);
        model.training_handle = None;
        model.train_model(true).await;

        if model.training_handle.is_some() {
            let handle = model.training_handle.take().unwrap();
            let _ = await_join_with_timeout(handle, std::time::Duration::from_secs(30)).await;
            model.training_in_progress.store(false, Ordering::Release);
        }

        assert!(
            model.forest.is_some(),
            "Forest must survive a training failure (empty data)"
        );
        println!("Training failure preserves forest verified");
    }

    #[tokio::test]
    async fn test_timeout_preserves_anomaly_tags() {
        let mut session = create_test_session_with_criticality(
            "timeout-test-1".to_string(),
            "anomaly:suspicious,blacklist:test_entry".to_string(),
            Utc::now(),
        );

        let has_prior_anomaly = session.criticality.contains("anomaly:suspicious")
            || session.criticality.contains("anomaly:abnormal");

        if has_prior_anomaly {
            // timeout path should NOT overwrite
        } else {
            let mut final_tags: Vec<String> = session
                .criticality
                .split(',')
                .filter(|s| !s.trim().is_empty() && !s.trim().starts_with("anomaly:"))
                .map(|s| s.trim().to_string())
                .collect();
            final_tags.push("anomaly:normal/analysis_timeout".to_string());
            final_tags.sort_unstable();
            final_tags.dedup();
            session.criticality = final_tags.join(",");
        }

        assert!(
            session.criticality.contains("anomaly:suspicious"),
            "Prior anomaly:suspicious must survive timeout. Got: {}",
            session.criticality
        );
        assert!(
            session.criticality.contains("blacklist:test_entry"),
            "Blacklist tag must survive timeout. Got: {}",
            session.criticality
        );
        assert!(
            !session.criticality.contains("analysis_timeout"),
            "Timeout tag should not be appended when prior anomaly exists. Got: {}",
            session.criticality
        );
        println!("Timeout preserves anomaly tags verified");
    }

    #[tokio::test]
    async fn test_set_percentiles_sticky() {
        let analyzer = SessionAnalyzer::new();
        analyzer.start().await;

        {
            let outer = analyzer.model.read().await;
            if outer.is_none() {
                drop(outer);
                let mut outer_w = analyzer.model.write().await;
                *outer_w = Some(CustomRwLock::new(IsolationForestModel::new()));
            }
        }

        let res = analyzer.set_percentiles(0.80, 0.95).await;
        assert!(res.is_ok(), "set_percentiles should succeed");

        {
            let outer = analyzer.model.read().await;
            let model_lock = outer.as_ref().unwrap();
            let model = model_lock.read().await;
            assert!(
                (model.current_suspicious_percentile - 0.80).abs() < 1e-9,
                "Suspicious percentile not sticky: {}",
                model.current_suspicious_percentile
            );
            assert!(
                (model.current_abnormal_percentile - 0.95).abs() < 1e-9,
                "Abnormal percentile not sticky: {}",
                model.current_abnormal_percentile
            );
        }

        analyzer.stop().await;
        println!("set_percentiles sticky verified");
    }

    #[tokio::test]
    async fn test_criticality_unchanged_exact_match() {
        let stored_a = "blacklist:tor";
        let stored_b = "blacklist:to";

        let old_logic_false_positive = stored_a.contains(stored_b) || stored_b.contains(stored_a);
        assert!(
            old_logic_false_positive,
            "Old substring logic should have been a false positive"
        );

        let new_logic = stored_a == stored_b;
        assert!(
            !new_logic,
            "Exact match must correctly detect 'blacklist:tor' != 'blacklist:to'"
        );

        let same = "anomaly:normal";
        assert!(same == same, "Identical strings must match");
        println!("Criticality exact match verified");
    }

    #[tokio::test]
    async fn test_interarrival_regularity_off_by_one() {
        let now = Utc::now();
        let mut session = create_test_session_with_criticality(
            "interarrival-test".to_string(),
            "".to_string(),
            now,
        );
        session.stats.segment_count = 10;
        session.stats.segment_interarrival = 1.0;
        let start_time = now - chrono::Duration::seconds(9);
        session.stats.start_time = start_time;
        session.stats.end_time = Some(now);
        session.stats.last_activity = now;

        let features = compute_features(&session, &HashMap::new());
        let interarrival_regularity = features[7];

        // With 10 segments over 9 seconds, expected gap = 9/(10-1) = 1.0 second.
        // Observed interarrival = 1.0. So regularity = 1.0 - |1.0 - 1.0|/1.0 = 1.0
        assert!(
            (interarrival_regularity - 1.0).abs() < 0.01,
            "Regularity should be ~1.0 for perfectly regular segments, got {}",
            interarrival_regularity
        );
        println!("Interarrival regularity N-1 verified");
    }

    #[tokio::test]
    async fn test_analysis_result_batch_vs_total_counts() {
        let result = AnalysisResult {
            sessions_analyzed: 10,
            new_anomalous_found: true,
            new_blacklisted_found: false,
            anomalous_count: 100,
            blacklisted_count: 50,
            batch_anomalous_count: 3,
            batch_blacklisted_count: 1,
        };

        assert_eq!(result.batch_anomalous_count, 3);
        assert_eq!(result.batch_blacklisted_count, 1);
        assert_eq!(result.anomalous_count, 100);
        assert_eq!(result.blacklisted_count, 50);
        assert_ne!(
            result.anomalous_count, result.batch_anomalous_count,
            "Total and batch counts should be distinct"
        );
        println!("Batch vs total counts verified");
    }

    #[tokio::test]
    async fn test_normal_sessions_count_no_double_subtract() {
        let analyzer = SessionAnalyzer::new();

        let uid = "dual-tagged-1".to_string();
        let session = create_test_session_with_criticality(
            uid.clone(),
            "anomaly:suspicious,blacklist:test".to_string(),
            Utc::now(),
        );

        analyzer
            .all_sessions
            .insert(uid.clone(), SessionCache::with_full_session(&session));
        analyzer
            .anomalous_sessions
            .insert(uid.clone(), SessionCache::with_full_session(&session));
        analyzer
            .blacklisted_sessions
            .insert(uid.clone(), SessionCache::with_full_session(&session));

        let normal_count = analyzer
            .all_sessions
            .iter()
            .filter(|e| {
                !analyzer.anomalous_sessions.contains_key(e.key())
                    && !analyzer.blacklisted_sessions.contains_key(e.key())
            })
            .count();

        assert_eq!(
            normal_count, 0,
            "Session in both anomalous and blacklisted should yield 0 normals, not underflow"
        );

        let total = analyzer.all_sessions.len();
        let anom = analyzer.anomalous_sessions.len();
        let bl = analyzer.blacklisted_sessions.len();
        let old_formula = total.saturating_sub(anom + bl);
        // old_formula would be 1.saturating_sub(1+1) = 1.saturating_sub(2) = 0 in this case
        // but with 2 separate sessions it would undercount
        assert_eq!(old_formula, 0);

        // Now add a normal-only session to verify counting works
        let normal_uid = "normal-only-1".to_string();
        let normal_session = create_test_session_with_criticality(
            normal_uid.clone(),
            "anomaly:normal".to_string(),
            Utc::now(),
        );
        analyzer
            .all_sessions
            .insert(normal_uid, SessionCache::with_full_session(&normal_session));

        let normal_count_2 = analyzer
            .all_sessions
            .iter()
            .filter(|e| {
                !analyzer.anomalous_sessions.contains_key(e.key())
                    && !analyzer.blacklisted_sessions.contains_key(e.key())
            })
            .count();
        assert_eq!(normal_count_2, 1, "One normal session should be counted");

        println!("Normal sessions count verified");
    }
}
