use crate::sessions::SessionInfo;
use chrono::{DateTime, Duration, Utc};
use extended_isolation_forest::{Forest, ForestOptions};
use std::collections::HashSet;
use std::fmt;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, trace, warn};
use undeadlock::*;

/// # LanscanAnalyzer Module
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
///    - Optional details may provide diagnostic information (e.g., `anomaly:abnormal/score_high` or `anomaly:suspicious/port:1234(z=4.5)`)
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
/// - Feature format: `feature_name:value(z=score)` where:
///   - `feature_name` is one of: `proc_hash` (process name hash), `port` (destination port),
///     `duration` (session duration in seconds), `bytes` (total bytes transferred),
///     `packets` (total packets), or `missed` (missed bytes)
///   - `value` is the actual value in scientific notation (e.g., `1.2e3` for 1200)
///   - `z=score` is the z-score showing how many standard deviations this value is from the mean
///
/// - Multiple unusual features are separated by forward slashes:
///   `anomaly:abnormal/port:1234(z=4.5)/bytes:1.2e6(z=3.2)/duration:0.1e0(z=-2.7)`
///
/// - Special cases:
///   - `score_high`: No specific features identified as unusual, but overall anomaly score is high
///   - `feature_name:value(const)`: This feature has zero variance in the dataset (all other
///     sessions have the same value) but this session has a different value

// Define a timeout for cache entries (in seconds)
static ANALYZER_CACHE_TIMEOUT: i64 = 3600; // 1 hour by default

// Define a timeout for anomalous session tracking (in seconds)
static ANOMALOUS_SESSION_TIMEOUT: i64 = 86400; // 24 hours

// Define a timeout for blacklisted session tracking (in seconds)
static BLACKLISTED_SESSION_TIMEOUT: i64 = 86400; // 24 hours

// Define a timeout for all session tracking (in seconds)
static ALL_SESSION_TIMEOUT: i64 = 86400; // 24 hours

// Define default values for warm-up settings
pub const DEFAULT_SUSPICIOUS_PERCENTILE: f64 = 0.93; // 93rd percentile
pub const DEFAULT_ABNORMAL_PERCENTILE: f64 = 0.95; // 95th percentile
pub const DEFAULT_SUSPICIOUS_THRESHOLD_10D: f64 = 0.75;
pub const DEFAULT_ABNORMAL_THRESHOLD_10D: f64 = 0.80;
pub const DEFAULT_THRESHOLD_RECALC_HOURS: i64 = 24; // 24 hours
pub const MIN_WARMUP_SECONDS: i64 = 30; // Minimum warm-up duration to ensure forest training

// Define the number of features to use by default
const NUM_FEATURES: usize = 10;

/// Pre-computed mean / std-dev for each feature (None if not computable).
type FeatureStats = [Option<(f64, f64)>; NUM_FEATURES];

// Define the Criticality levels as an enum for clarity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCriticality {
    Normal,
    Suspicious,
    Abnormal,
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

// Define the internal analyzer that handles the Isolation Forest model
struct IsolationForestModel {
    forest: Option<Forest<f64, NUM_FEATURES>>,
    recent_data: Vec<[f64; NUM_FEATURES]>,
    max_samples: usize,
    suspicious_threshold: f64,
    abnormal_threshold: f64,
    session_cache: CustomDashMap<String, (f64, [f64; NUM_FEATURES], DateTime<Utc>)>,
    /// Indicates if a training task is currently running. Prevents spawning overlapping CPU heavy jobs.
    training_in_progress: AtomicBool,
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
}

impl IsolationForestModel {
    /// Create a new model with default thresholds and an empty forest.
    pub fn new() -> Self {
        IsolationForestModel {
            forest: None,
            recent_data: Vec::new(),
            max_samples: 300,
            // Will be overridden by the first training and its percentile based thresholds computed from the training data.
            suspicious_threshold: DEFAULT_SUSPICIOUS_THRESHOLD_10D,
            abnormal_threshold: DEFAULT_ABNORMAL_THRESHOLD_10D,
            session_cache: CustomDashMap::new("session_cache"),
            training_in_progress: AtomicBool::new(false),
            training_handle: None,
            last_training_time: Utc::now() - chrono::Duration::hours(25),
            min_training_interval: Duration::hours(24),
        }
    }

    /// Add new session data to the analyzer's memory.
    /// If the buffer is full, remove the oldest entry.
    fn add_session_data(&mut self, session: &SessionInfo) {
        let features = compute_features(session); // Compute and use all 10 features

        if self.recent_data.len() >= self.max_samples {
            self.recent_data.remove(0);
        }
        self.recent_data.push(features);
    }

    /// Train (or retrain) the Isolation Forest model on the recent data.
    /// This function is now async and includes a timeout for training.
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
        if let Some(handle) = &mut self.training_handle {
            debug!(
                "train_model: Found existing handle - is_finished={}",
                handle.is_finished()
            );
            if handle.is_finished() {
                // The blocking thread has finished – gather the result and update state
                debug!("train_model: Previous task finished, getting result");
                match handle.await {
                    Ok(Ok(forest)) => {
                        info!("train_model: Background training completed successfully");
                        self.forest = Some(forest);
                        self.last_training_time = Utc::now(); // Update last successful training time
                    }
                    Ok(Err(e)) => {
                        warn!("train_model: Background training returned error: {:?}", e);
                        self.forest = None;
                    }
                    Err(join_error) => {
                        error!(
                            "train_model: Background training panicked: {:?}",
                            join_error
                        );
                        self.forest = None;
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

        let data_clone = self.recent_data.clone(); // lightweight (Vec of 10-element arrays)

        // Mark that training is starting before we spawn, so concurrent calls bail out early.
        self.training_in_progress.store(true, Ordering::Release);
        debug!("train_model: Set training_in_progress flag to true");

        // Spawn the heavy work on a dedicated blocking thread.  The closure will perform all
        // preprocessing (deduplication, option calculation) and return a Forest or an Error.
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
            debug!("train_model: TRAINING THREAD - Calling Forest::from_slice");
            let result = Forest::from_slice(&unique_data, &options);
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
            ("Process", true),              // Index 0 - Process hash - categorical
            ("Duration", false),            // Index 1 - Duration - numeric
            ("Bytes", false),               // Index 2 - Total bytes - numeric
            ("Packets", false),             // Index 3 - Total packets - numeric
            ("SegmentInterarrival", false), // Index 4 - Timing - numeric
            ("InOutRatio", false),          // Index 5 - Ratio - numeric
            ("DestService", true),          // Index 6 - Destination service - categorical
            ("AvgPacketSize", false),       // Index 7 - Avg packet size - numeric
            ("SelfDestination", true),      // Index 8 - Self destination - categorical/binary
            ("MissedData", false),          // Index 9 - Missed bytes - numeric
        ];

        let mut diagnostics = Vec::new();
        let z_score_threshold = 2.5; // Threshold for considering a feature unusual

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
                    // Revised handling for categorical/binary features -------------------------------------
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
                        // Zero (or near-zero) variance → current value differs from the constant mean? ✅ unusual
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

                        if z_score >= z_score_threshold {
                            // Use more descriptive term for high values
                            diagnostics.push(format!("{}:UnusuallyHigh", feature_name));
                            debug!("Added unusually high feature: {}", feature_name);
                        } else if z_score <= -z_score_threshold {
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
        let features = compute_features(session); // Compute and use all 10 features

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

        // --- Revised Merging Logic ---
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
        // --- End Revised Merging Logic ---

        // Only update if the value actually changed
        if session.criticality != final_criticality {
            if detailed_logging {
                debug!(
                    "Updating criticality for session {} from '{}' to '{}'",
                    session.uid, session.criticality, final_criticality
                );
            }
            session.criticality = final_criticality;
            session.last_modified = chrono::Utc::now();
        } else {
            // Ensure last_modified is updated ONLY if analysis happened.
            if score_and_features.is_some() {
                session.last_modified = chrono::Utc::now();
                if detailed_logging {
                    debug!(
                        "Re-analyzed session {} but criticality '{}' remains unchanged",
                        session.uid, session.criticality
                    );
                }
            }
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
    pub fn cleanup_session_cache(&self) {
        let now = Utc::now();
        self.session_cache.retain(|_, v| {
            let (_score, _features, last_modified) = v;
            now <= *last_modified + Duration::seconds(ANALYZER_CACHE_TIMEOUT)
        });
    }
}

/// Compute the feature vector [f64; 10] for a given session.
/// Feature order: [process_hash, duration, bytes, packets, segment_interarrival, in_out_ratio, avg_packet_size, dest_service, self_destination, missed]
/// NOTE: This still computes 10 features, the selection to NUM_FEATURES happens in the calling functions.
fn compute_features(session: &SessionInfo) -> [f64; 10] {
    let start_time = std::time::Instant::now();

    // Helper function to sanitize values
    fn sanitize(val: f64) -> f64 {
        if val.is_nan() || val.is_infinite() {
            0.0 // Replace NaN/Inf with 0.0
        } else {
            val
        }
    }

    // 1. Process name hashed to f64
    let process_hash = match &session.l7 {
        Some(l7) => {
            let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
            hasher.write(l7.process_name.as_bytes());
            let hash_val = hasher.finish();
            sanitize((hash_val % 1_000_000) as f64) // Scale down and sanitize
        }
        None => 0.0,
    };

    // 2. Duration
    let duration = match session.stats.end_time {
        Some(end_time) => {
            sanitize((end_time - session.stats.start_time).num_milliseconds() as f64 / 1000.0)
        }
        None => sanitize(
            (session.stats.last_activity - session.stats.start_time).num_milliseconds() as f64
                / 1000.0,
        ),
    };

    // 3. Total bytes
    let bytes = sanitize((session.stats.inbound_bytes + session.stats.outbound_bytes) as f64);

    // 4. Total packets
    let packets = sanitize((session.stats.orig_pkts + session.stats.resp_pkts) as f64);

    // 5. Segment interarrival
    let segment_interarrival = sanitize(session.stats.segment_interarrival);

    // 6. Inbound/outbound ratio
    let in_out_ratio = sanitize(session.stats.inbound_outbound_ratio);

    // 7. Avg packet size
    let avg_packet_size = sanitize(session.stats.average_packet_size);

    // 8. Dest service
    let dest_service = match &session.dst_service {
        Some(service) => {
            let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
            hasher.write(service.as_bytes());
            let hash_val = hasher.finish();
            sanitize((hash_val % 1_000_000) as f64) // Scale down and sanitize
        }
        None => 0.0,
    };

    // 9. Self destination (swapped with Dest service)
    let self_destination = if session.is_self_dst { 1.0 } else { 0.0 };

    // 10. Missed bytes
    let missed = sanitize(session.stats.missed_bytes as f64);

    let features = [
        process_hash,
        duration,
        bytes,
        packets,
        segment_interarrival,
        in_out_ratio,
        avg_packet_size,
        dest_service,
        self_destination,
        missed,
    ];

    // Double check that no NaN/Inf values made it through
    for (i, &f) in features.iter().enumerate() {
        if f.is_nan() || f.is_infinite() {
            warn!(
                "Sanitization failed for feature {} in session {}",
                i, session.uid
            );
            // Force a valid value as a last resort
            let fixed_features = [
                if process_hash.is_nan() || process_hash.is_infinite() {
                    0.0
                } else {
                    process_hash
                },
                if duration.is_nan() || duration.is_infinite() {
                    0.0
                } else {
                    duration
                },
                if bytes.is_nan() || bytes.is_infinite() {
                    0.0
                } else {
                    bytes
                },
                if packets.is_nan() || packets.is_infinite() {
                    0.0
                } else {
                    packets
                },
                if segment_interarrival.is_nan() || segment_interarrival.is_infinite() {
                    0.0
                } else {
                    segment_interarrival
                },
                if in_out_ratio.is_nan() || in_out_ratio.is_infinite() {
                    0.0
                } else {
                    in_out_ratio
                },
                if avg_packet_size.is_nan() || avg_packet_size.is_infinite() {
                    0.0
                } else {
                    avg_packet_size
                },
                if dest_service.is_nan() || dest_service.is_infinite() {
                    0.0
                } else {
                    dest_service
                },
                if self_destination.is_nan() || self_destination.is_infinite() {
                    0.0
                } else {
                    self_destination
                },
                if missed.is_nan() || missed.is_infinite() {
                    0.0
                } else {
                    missed
                },
            ];

            let elapsed = start_time.elapsed();
            if elapsed.as_millis() > 50 {
                warn!(
                    "compute_features (with sanitization) for session {} took {:?}",
                    session.uid, elapsed
                );
            }

            return fixed_features;
        }
    }

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
        .map(|features| forest.score(features)) // Score using NUM_FEATURES
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
    let suspicious_idx = ((n as f64 * suspicious_percentile).ceil() as usize).saturating_sub(1);
    let abnormal_idx = ((n as f64 * abnormal_percentile).ceil() as usize).saturating_sub(1);

    info!(
        "compute_dynamic_thresholds: Using indices suspicious={}/{}, abnormal={}/{}",
        suspicious_idx, n, abnormal_idx, n
    );

    let new_suspicious_threshold = scores[suspicious_idx];
    let new_abnormal_threshold = scores[abnormal_idx];

    // Add a small epsilon to avoid classifying the percentile boundary itself
    let epsilon = 1e-6;
    let final_suspicious_threshold = new_suspicious_threshold + epsilon;
    let final_abnormal_threshold = new_abnormal_threshold + epsilon;

    // Use default thresholds suitable for 10D
    let default_suspicious = DEFAULT_SUSPICIOUS_THRESHOLD_10D;
    let default_abnormal = DEFAULT_ABNORMAL_THRESHOLD_10D;

    // Store the old thresholds for logging
    let old_suspicious = model.suspicious_threshold;
    let old_abnormal = model.abnormal_threshold;

    model.suspicious_threshold = final_suspicious_threshold.max(default_suspicious);
    // Ensure abnormal is strictly greater than suspicious
    model.abnormal_threshold = final_abnormal_threshold
        .max(model.suspicious_threshold + epsilon)
        .max(default_abnormal);

    info!(
        "Computed dynamic thresholds: Suspicious >= {:.4} (was {:.4}), Abnormal >= {:.4} (was {:.4}) (based on {} scores, took {:?})",
        model.suspicious_threshold, old_suspicious, model.abnormal_threshold, old_abnormal, n, start_time.elapsed()
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
    /// Number of anomalous sessions found in this batch
    pub anomalous_count: usize,
    /// Number of blacklisted sessions found in this batch
    pub blacklisted_count: usize,
}

/// Public interface for the SessionAnalyzer - thread-safe wrapper around the model
pub struct SessionAnalyzer {
    model: CustomRwLock<Option<CustomRwLock<IsolationForestModel>>>,
    anomalous_sessions: CustomDashMap<String, SessionInfo>,
    blacklisted_sessions: CustomDashMap<String, SessionInfo>,
    all_sessions: CustomDashMap<String, SessionInfo>, // Store all processed sessions
    // Warm-up related fields
    warm_up_active: AtomicBool,
    warm_up_start_time: AtomicU64, // Timestamp when warm-up started (seconds since UNIX epoch)
    warm_up_duration: Duration,
    suspicious_threshold_percentile: f64,
    abnormal_threshold_percentile: f64,
    last_threshold_recalc_time: Arc<CustomRwLock<DateTime<Utc>>>,
    threshold_recalc_interval: Duration,
    running: AtomicBool,
    last_analysis_time: Arc<CustomRwLock<Option<DateTime<Utc>>>>,
}

impl SessionAnalyzer {
    /// Create a new analyzer with default settings
    pub fn new() -> Self {
        info!(
            "Creating new SessionAnalyzer: Using {}D feature analysis with 300 max samples",
            NUM_FEATURES
        );
        Self {
            model: CustomRwLock::new(None),
            anomalous_sessions: CustomDashMap::new("anomalous_sessions"),
            blacklisted_sessions: CustomDashMap::new("blacklisted_sessions"),
            all_sessions: CustomDashMap::new("all_sessions"),
            // Warm-up defaults - increase to ensure enough time for training
            warm_up_active: AtomicBool::new(true),
            // Initialize with 0 (will be set on first analyze_sessions call)
            warm_up_start_time: AtomicU64::new(0),
            warm_up_duration: Duration::seconds(120), // Increased from 60 to 120 seconds
            suspicious_threshold_percentile: DEFAULT_SUSPICIOUS_PERCENTILE,
            abnormal_threshold_percentile: DEFAULT_ABNORMAL_PERCENTILE,
            last_threshold_recalc_time: Arc::new(CustomRwLock::new(Utc::now())),
            threshold_recalc_interval: Duration::hours(DEFAULT_THRESHOLD_RECALC_HOURS),
            running: AtomicBool::new(false),
            last_analysis_time: Arc::new(CustomRwLock::new(None)),
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

    /// Analyze and update the criticality of a batch of sessions.
    /// This will train/update the model and then score each session.
    /// Returns information about what was found during analysis.
    pub async fn analyze_sessions(&self, sessions: &mut [SessionInfo]) -> AnalysisResult {
        // Clean up expired session_cache entries before analysis
        self.cleanup_session_cache().await;

        let mut result = AnalysisResult {
            sessions_analyzed: sessions.len(),
            ..Default::default()
        };

        if sessions.is_empty() {
            return result;
        }

        // Auto-start if model isn't initialized
        let model_initialized = {
            let model_guard = self.model.read().await;
            model_guard.is_some()
        };

        if !model_initialized {
            info!("LanscanAnalyzer: Auto-starting as model is not initialized");
            self.start().await;
        }

        let now = Utc::now();

        // Update last_analysis_time at the start
        {
            let mut last_analysis_time_guard = self.last_analysis_time.write().await;
            *last_analysis_time_guard = Some(now);
        }

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
                if let Some(handle) = &mut model_guard.training_handle {
                    match handle.await {
                        Ok(Ok(forest)) => {
                            info!("Analyzer: Background training task completed successfully (processed at analyze_sessions start)");
                            model_guard.forest = Some(forest);
                            model_guard.last_training_time = Utc::now();
                        },
                        Ok(Err(e)) => warn!("Analyzer: Background training task failed (processed at analyze_sessions start): {:?}", e),
                        Err(e) => error!("Analyzer: Background training task panicked (processed at analyze_sessions start): {:?}", e),
                    }
                    model_guard.training_handle = None;
                    model_guard
                        .training_in_progress
                        .store(false, Ordering::Release);
                }
            }
        }

        // Add all new session data to the model's recent_data buffer
        let sessions_len = sessions.len();
        let mut initial_batch_analyzed_post_warmup = false; // Flag to analyze current batch if warm-up just ended

        {
            let mut model_guard = model_rwlock.write().await;
            // info! used here as it's a key data ingestion point.
            info!("Analyzer: Adding {} new sessions to model data buffer (current size before add: {})", sessions_len, model_guard.recent_data.len());
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
                MIN_WARMUP_SECONDS,
                self.warm_up_duration.num_seconds()
            );

            let should_attempt_finalize = elapsed_seconds >= MIN_WARMUP_SECONDS
                && elapsed_seconds >= self.warm_up_duration.num_seconds();

            if should_attempt_finalize {
                info!("Analyzer: Warm-up duration met (elapsed: {}s). Attempting to finalize and compute thresholds.", elapsed_seconds);
                let mut model_guard = model_rwlock.write().await;

                // Ensure any ongoing training is completed
                if model_guard.training_in_progress.load(Ordering::Relaxed) {
                    if let Some(handle) = &mut model_guard.training_handle {
                        if !handle.is_finished() {
                            info!("Analyzer (Finalize Warmup): Waiting for ongoing training task to complete...");
                            match handle.await {
                                Ok(Ok(forest)) => {
                                    info!("Analyzer (Finalize Warmup): Training task completed successfully.");
                                    model_guard.forest = Some(forest);
                                    model_guard.last_training_time = Utc::now();
                                }
                                Ok(Err(e)) => warn!(
                                    "Analyzer (Finalize Warmup): Training task failed: {:?}",
                                    e
                                ),
                                Err(e) => error!(
                                    "Analyzer (Finalize Warmup): Training task panicked: {:?}",
                                    e
                                ),
                            }
                        } else {
                            // Already finished, try to process
                            match handle.await {
                                Ok(Ok(forest)) => { model_guard.forest = Some(forest); model_guard.last_training_time = Utc::now(); },
                                Ok(Err(e)) => warn!("Analyzer (Finalize Warmup): Already finished training task returned error: {:?}", e),
                                Err(e) => error!("Analyzer (Finalize Warmup): Already finished training task panicked: {:?}", e),
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
                    if let Some(handle) = &mut model_guard.training_handle {
                        info!("Analyzer (Finalize Warmup): Waiting for final forced training task to complete...");
                        match handle.await {
                            Ok(Ok(forest)) => {
                                info!("Analyzer (Finalize Warmup): Final forced training task completed successfully.");
                                model_guard.forest = Some(forest);
                                model_guard.last_training_time = Utc::now();
                            },
                            Ok(Err(e)) => warn!("Analyzer (Finalize Warmup): Final forced training task failed: {:?}", e),
                            Err(e) => error!("Analyzer (Finalize Warmup): Final forced training task panicked: {:?}", e),
                        }
                        model_guard.training_handle = None;
                        model_guard
                            .training_in_progress
                            .store(false, Ordering::Release);
                    }
                }

                if model_guard.forest.is_some() && !model_guard.recent_data.is_empty() {
                    info!("Analyzer (Finalize Warmup): Forest and data available. Computing dynamic thresholds.");
                    compute_dynamic_thresholds(
                        &mut model_guard,
                        self.suspicious_threshold_percentile,
                        self.abnormal_threshold_percentile,
                    );
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
                let anom_count = 0;
                let mut bl_count = 0;
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
                    // Store all sessions even during warmup
                    self.all_sessions
                        .insert(session.uid.clone(), session.clone());

                    // No analysis yet, so we can't determine if they are anomalous

                    // Populate the blacklisted sessions
                    if Self::is_blacklisted(&session.criticality) {
                        self.blacklisted_sessions
                            .insert(session.uid.clone(), session.clone());
                        bl_count += 1;
                    }
                }
                // If still in warm-up and not finalizing this call, return early.
                // The current batch of sessions has been added to `recent_data` and training ensured.
                // They will be analyzed once warm-up completes.
                if !initial_batch_analyzed_post_warmup {
                    result.anomalous_count = anom_count;
                    result.blacklisted_count = bl_count;

                    info!("Analyzer: analyze_sessions batch completed for {} sessions (still in active warm-up, returning early). Found: {} anomalous, {} blacklisted.", sessions_len, anom_count, bl_count);
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
                    now.timestamp() - self.warm_up_start_time.load(Ordering::Relaxed) as i64
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

                if let Some(handle) = &mut model_guard.training_handle {
                    info!("Analyzer (Scheduled Recalc): Waiting for training task to complete...");
                    match handle.await {
                        Ok(Ok(forest)) => {
                            info!("Analyzer (Scheduled Recalc): Training task completed successfully.");
                            model_guard.forest = Some(forest);
                            model_guard.last_training_time = Utc::now();
                        }
                        Ok(Err(e)) => {
                            warn!("Analyzer (Scheduled Recalc): Training task failed: {:?}", e)
                        }
                        Err(e) => error!(
                            "Analyzer (Scheduled Recalc): Training task panicked: {:?}",
                            e
                        ),
                    }
                    model_guard.training_handle = None;
                    model_guard
                        .training_in_progress
                        .store(false, Ordering::Release);
                }

                if model_guard.forest.is_some() && !model_guard.recent_data.is_empty() {
                    info!("Analyzer (Scheduled Recalc): Computing dynamic thresholds.");
                    compute_dynamic_thresholds(
                        &mut model_guard,
                        self.suspicious_threshold_percentile,
                        self.abnormal_threshold_percentile,
                    );
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

            // Analyze all sessions and update criticality
            {
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
                    drop(model_guard);

                    let mut anom_count = 0;
                    let mut bl_count = 0;
                    let mut found_new_anomalous = false;
                    let mut found_new_blacklisted = false;

                    let prev_analysis_time = {
                        let last_analysis_time_guard = self.last_analysis_time.read().await;
                        last_analysis_time_guard.unwrap_or(now)
                    };

                    let model_write_guard = model_rwlock.write().await;

                    for (idx, session) in sessions.iter_mut().enumerate() {
                        let needs_analysis = {
                            let in_cache =
                                model_write_guard.session_cache.get(&session.uid).is_some();
                            !in_cache || session.last_modified > prev_analysis_time
                        };
                        if needs_analysis {
                            model_write_guard.analyze_session(session, &feature_stats);
                        }

                        // Store all sessions regardless of classification
                        self.all_sessions
                            .insert(session.uid.clone(), session.clone());

                        if Self::is_anomalous(&session.criticality) {
                            if !self.anomalous_sessions.contains_key(&session.uid) {
                                found_new_anomalous = true;
                            }
                            self.anomalous_sessions
                                .insert(session.uid.clone(), session.clone());
                            anom_count += 1;
                        }
                        if Self::is_blacklisted(&session.criticality) {
                            if !self.blacklisted_sessions.contains_key(&session.uid) {
                                found_new_blacklisted = true;
                            }
                            self.blacklisted_sessions
                                .insert(session.uid.clone(), session.clone());
                            bl_count += 1;
                        }
                        if (idx + 1) % 100 == 0 {
                            debug!(
                                "Analyzer ({}): Analyzed {}/{} sessions.",
                                operation_type,
                                idx + 1,
                                sessions_len
                            );
                        }
                    }
                    info!("Analyzer ({}): Analysis of {} sessions completed in {:?}. Found: {} anomalous, {} blacklisted.",
                          operation_type, sessions_len, analyze_start_time.elapsed(), anom_count, bl_count);

                    // Update result with findings
                    result.new_anomalous_found = found_new_anomalous;
                    result.new_blacklisted_found = found_new_blacklisted;
                    result.anomalous_count = anom_count;
                    result.blacklisted_count = bl_count;
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

                        // Store all sessions even when no model is available
                        self.all_sessions
                            .insert(session.uid.clone(), session.clone());

                        // Count sessions after any updates
                        if Self::is_anomalous(&session.criticality) {
                            anom_count += 1;
                        }
                        if Self::is_blacklisted(&session.criticality) {
                            bl_count += 1;
                        }
                    }

                    result.anomalous_count = anom_count;
                    result.blacklisted_count = bl_count;
                }
            }
        }

        // Overall batch completion log - use a simple Instant for this function's total time.
        // This was complex before, so simplifying. If add_data_time was the start:
        // info!("Analyzer: analyze_sessions batch completed for {} sessions (total processing time: {:?})",
        //       sessions_len, add_data_time.elapsed());
        // For a true total time of the function, a start_time at the function beginning is needed.
        // Let's omit this specific complex log for now as it was potentially incorrect.
        debug!(
            "Analyzer: analyze_sessions call finished for {} sessions.",
            sessions_len
        );

        result
    }

    /// Get a session by its UID
    pub async fn get_session_by_uid(&self, uid: &str) -> Option<SessionInfo> {
        // Check all sessions first (most comprehensive)
        if let Some(entry) = self.all_sessions.get(uid) {
            return Some(entry.value().clone());
        }
        // Fallback to anomalous sessions for backward compatibility
        if let Some(entry) = self.anomalous_sessions.get(uid) {
            return Some(entry.value().clone());
        }
        // Finally check blacklisted sessions
        if let Some(entry) = self.blacklisted_sessions.get(uid) {
            return Some(entry.value().clone());
        }
        // If not found in any, return None
        None
    }

    /// Cleans up old entries from the anomalous, blacklisted, and all session maps.
    fn cleanup_tracked_sessions(&self) {
        let now = Utc::now();
        let anomalous_timeout = Duration::seconds(ANOMALOUS_SESSION_TIMEOUT);
        let blacklisted_timeout = Duration::seconds(BLACKLISTED_SESSION_TIMEOUT);
        let all_session_timeout = Duration::seconds(ALL_SESSION_TIMEOUT);

        self.anomalous_sessions.retain(|_, session| {
            now.signed_duration_since(session.last_modified) < anomalous_timeout
        });

        self.blacklisted_sessions.retain(|_, session| {
            now.signed_duration_since(session.last_modified) < blacklisted_timeout
        });

        self.all_sessions.retain(|_, session| {
            now.signed_duration_since(session.last_modified) < all_session_timeout
        });
    }

    /// Retrieves a snapshot of currently tracked anomalous sessions.
    /// Also cleans up old entries.
    pub async fn get_anomalous_sessions(&self) -> Vec<SessionInfo> {
        self.cleanup_tracked_sessions();
        self.anomalous_sessions
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Gets the current count of anomalous sessions.
    /// Also cleans up old entries.
    pub async fn get_anomalous_status(&self) -> usize {
        self.cleanup_tracked_sessions();
        self.anomalous_sessions.len()
    }

    /// Retrieves a snapshot of currently tracked blacklisted sessions.
    /// Also cleans up old entries.
    pub async fn get_blacklisted_sessions(&self) -> Vec<SessionInfo> {
        self.cleanup_tracked_sessions();
        self.blacklisted_sessions
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Retrieves all sessions that have been processed by the analyzer.
    /// This includes sessions from all states: normal, suspicious, abnormal, and blacklisted.
    /// Sessions are available even during warmup period.
    /// Also cleans up old entries.
    pub async fn get_sessions(&self) -> Vec<SessionInfo> {
        self.cleanup_tracked_sessions();
        self.all_sessions
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Retrieves all current sessions that have been processed by the analyzer.
    /// Sessions are available even during warmup period.
    /// Also cleans up old entries.
    pub async fn get_current_sessions(&self) -> Vec<SessionInfo> {
        self.cleanup_tracked_sessions();
        let current_session_timeout = crate::capture::CONNECTION_CURRENT_TIMEOUT;
        let now = Utc::now();
        self.all_sessions
            .iter()
            .filter(|entry| {
                now.signed_duration_since(entry.value().last_modified) < current_session_timeout
            })
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Public async method to trigger session_cache cleanup.
    /// Call this periodically from a background task or timer.
    pub async fn cleanup_session_cache(&self) {
        let model_lock = self.model.read().await;
        if let Some(model) = &*model_lock {
            model.read().await.cleanup_session_cache();
        }
    }

    /// Start the analyzer (set running flag, prepare for background tasks if needed)
    /// Start with preserved security findings if available
    pub async fn start(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            debug!("LanscanAnalyzer already running");
            return;
        }

        // Count preserved sessions
        let anomalous_count = self.anomalous_sessions.len();
        let blacklisted_count = self.blacklisted_sessions.len();
        let all_sessions_count = self.all_sessions.len();

        if anomalous_count > 0 || blacklisted_count > 0 || all_sessions_count > 0 {
            info!(
                "LanscanAnalyzer started with preserved sessions: {} anomalous, {} blacklisted, {} total",
                anomalous_count, blacklisted_count, all_sessions_count
            );
        } else {
            info!("LanscanAnalyzer started");
        }

        // Instantiate the IsolationForestModel
        let mut model_guard = self.model.write().await;
        *model_guard = Some(CustomRwLock::new(IsolationForestModel::new()));
    }

    /// Stop the analyzer (clear running flag, stop background tasks if any)
    /// Preserve critical security findings across restarts
    pub async fn stop(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            debug!("LanscanAnalyzer already stopped");
            return;
        }
        info!("LanscanAnalyzer stopped - preserving security findings");

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

        // Clear temporary analysis data but preserve security findings
        let mut model_guard = self.model.write().await;
        if let Some(model) = &*model_guard {
            let mut model_write = model.write().await;

            // Clear temporary data
            model_write.recent_data.clear();
            model_write.session_cache.clear();

            // Reset training state
            model_write.forest = None;
            model_write.training_handle = None;
            model_write
                .training_in_progress
                .store(false, Ordering::Release);

            debug!("Cleared temporary analysis data while preserving security findings");
        }

        // Drop the model but keep security findings
        *model_guard = None;

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
}

#[cfg(test)]
mod tests {
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
            stats: SessionStats::default(),
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
            stats: SessionStats::default(),
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
            uid: Uuid::new_v4().to_string(),
            last_modified: Utc::now(),
        };

        // Manually add security findings (simulating what analyze_sessions would do)
        analyzer
            .anomalous_sessions
            .insert(anomalous_session.uid.clone(), anomalous_session.clone());
        analyzer
            .blacklisted_sessions
            .insert(blacklisted_session.uid.clone(), blacklisted_session.clone());

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

        println!("✅ Security findings preservation across stop/start verified");
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
                stats: SessionStats::default(),
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
                stats: SessionStats::default(),
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

        println!("✅ Session tracking during warmup verified");
    }
}
