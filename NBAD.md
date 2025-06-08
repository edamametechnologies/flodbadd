# Rust Isolation Forest Module for Session Criticality (SessionAnalyzer)

## Overview and Requirements

Flodbadd already ships with an async-friendly **`SessionAnalyzer`** (see `src/analyzer.rs`).
It labels every `SessionInfo` with a **criticality** level (`"normal"`, `"suspicious"`, or
`"abnormal"`) using an **Extended Isolation Forest** model implemented in pure Rust.  Below we
summarise the design goals and the feature-engineering approach used by the `SessionAnalyzer`.

- **Feature Selection:** Use meaningful behavioural features (excluding raw IPs/domains) for anomaly
  detection. For example:
  - **Process name:** Converted to a numeric hash so the model sees a stable categorical value.
  - **Destination port:** Numeric and directly usable.
  - **Session statistics:** Duration, byte/packet counts, missed bytes, etc.
- **Pure Rust Isolation Forest:** Implemented via the `extended_isolation_forest` crate – no Python
  or FFI required.
- **SessionAnalyzer Design:**
  - Maintains a sliding window of recent sessions (default: 300 samples).
  - Trains an Isolation Forest in a background blocking task when enough new data is available.
  - Scores new sessions on-the-fly; thresholds map the anomaly score to one of the three
    criticality levels.
  - Preserves any existing `blacklist:*` tags when updating the criticality string.
- **Performance:** Model training is off-loaded to a blocking thread; scoring is lock-free and fast
  enough for per-packet updates.

*(The remainder of this document retains the original, in-depth rationale and code example but has
all references renamed from `LanscanAnalyzer` → `SessionAnalyzer` for consistency with the
codebase.)*

## Feature Selection and Encoding

For effective anomaly detection, we select features that characterize a session's behavior, and we avoid identifiers that are unique per session (like IP addresses or domain names). Using unique identifiers as features would cause the model to consider every new value as an outlier. Instead, we use features with repeatable patterns:

- **Process Name:** This is a categorical/string feature. We **encode it to a numeric value** because isolation forests work on numerical features. A common approach is to apply a hash function to the process name to get a quasi-unique integer. This avoids introducing a high-dimensional one-hot encoding and keeps the value in a numeric range.
- **Destination Port:** This is already numeric (e.g., 80, 443, 65432, etc.). We can use it directly as a feature. Ports have patterns (common ports vs. high random ports) that might be useful for detecting anomalies.
- **SessionStats:** We include various statistics from the session:
  - Duration of the session (e.g., in seconds or milliseconds).
  - Total bytes transferred (or bytes sent and received separately).
  - Number of packets sent/received.
  - Missed bytes (if this field represents lost bytes or retransmissions).
  - Potentially other derived metrics (packets per second, bytes per packet, etc.) if available or needed.

All these features are numeric or can be converted to numeric. We should consider normalizing or scaling features if they have vastly different ranges. However, Isolation Forests are tree-based and less sensitive to scaling than distance-based algorithms. They isolate anomalies by random splits on feature ranges, so as long as each feature is within a reasonable numeric range, explicit normalization isn't strictly required.

**Excluding IP addresses and domains:** We will **not use IP addresses, hostnames, or domains** as features. Those are typically high-cardinality identifiers; including them could cause the model to mark every unseen IP/domain as anomalous, which is not desired. Instead, the focus is on behavioral metrics (ports and traffic characteristics).

## Using a Pure Rust Isolation Forest

To implement the anomaly detection, we leverage a Rust crate for Isolation Forest. Two example crates are:

- **`isoforest` crate:** A Rust isolation forest implementation (with optional Python bindings) that uses the Linfa machine learning framework. It works with NDArray for data and provides fitting (`.fit`) and prediction (`.predict` or `.decision_function`) capabilities similar to scikit-learn.
- **`smartcore` crate:** A comprehensive ML library in Rust which includes anomaly detection algorithms like Isolation Forest and One-Class SVM.
- **`extended_isolation_forest` crate:** Another pure-Rust implementation of the Extended Isolation Forest algorithm, which returns an anomaly score between 0 and 1 for data points.

Any of these would satisfy the "pure Rust" requirement. For our example, we will use `extended_isolation_forest` for simplicity, as it allows straightforward training from slices of data and provides a normalized anomaly score. The concepts will be similar if using `isoforest` or `smartcore` (the main difference is in API usage).

## `SessionAnalyzer` Design

The `SessionAnalyzer` struct will manage the sessions data and the Isolation Forest model. Key design points:

- **Storing Recent Sessions:** The analyzer can keep a buffer (Vec) of recent `SessionInfo` or just their feature vectors. This data will be used to train or update the model. We might limit the buffer size (for example, keep only the last N sessions or last T minutes of sessions) to adapt to concept drift and to limit memory use.
- **Training the Model:** We provide a method (e.g., `train_model`) that takes the collected feature vectors and fits a new Isolation Forest model. Training involves building many isolation trees on random subsets of the data:
  - We can set parameters like number of trees (e.g., 100 trees) and sub-sample size per tree (e.g., 256 samples) to balance performance and accuracy.
  - The model fitting is unsupervised (no labels needed). After training, the model can assign anomaly scores to any session's feature vector.
  - Isolation Forest yields an **anomaly score** for each sample. In some implementations the score is normalized to [0, 1], where values near 1 indicate very anomalous points.
- **Scoring Sessions:** After training (or when a new session comes in), we compute its feature vector and get an anomaly score from the model. Based on this score, we classify the session's `criticality`:
  - We define two threshold levels: one for *suspicious* and one for *abnormal*. For example, if using a [0,1] anomaly score, we might choose 0.8 as the cutoff for "abnormal" and 0.6 for "suspicious" (these can be tuned based on desired sensitivity).
  - If the anomaly score ≥ abnormal threshold, mark as **"abnormal"** (highly likely an outlier).
  - If the score is between the suspicious and abnormal threshold, mark as **"suspicious"** (moderate anomaly).
  - If below the suspicious threshold, mark as **"normal"**.
  - *Note:* If using a library that gives a binary prediction (e.g., `isoforest.predict` yields just normal vs anomaly), we would instead use the raw score (if available) to differentiate suspicious vs abnormal. For instance, the `extended_isolation_forest` crate's `score()` provides a continuous anomaly measure that we can threshold.
- **Updating and Retraining:** As new sessions come in over time, the analyzer should retrain the model periodically to keep up with evolving traffic:
  - **Batch retraining:** A simple strategy is to accumulate new session features in the buffer and retrain the Isolation Forest from scratch at intervals (say every X minutes or after Y new sessions). Isolation Forest training is relatively fast, but doing it for each new session might be overkill, so periodic retraining is a good compromise.
  - **Sliding window:** We can also use a sliding window of recent sessions (e.g., keep only last 1000 sessions). This way the model "forgets" old data and focuses on current behavior.
  - **Why retraining:** Without retraining, the model might become stale – it might treat new legitimate behavior as anomalous if it wasn't present in the training data. Regular retraining with fresh data ensures the model adapts.
- **Concurrency Considerations:** 
  - Ensure that the `SessionAnalyzer` and its model are thread-safe. This might involve using thread-safe data structures or locking if the model is updated from multiple threads. For example, training the model (which is a heavy operation) could be done in a background thread or under a mutex lock, while scoring could be done concurrently on a read-only model reference.
  - The `extended_isolation_forest` or `isoforest` model objects are plain Rust structs (containing trees and numeric data) and should implement `Send` (and possibly `Sync` if they don't use interior mutability). We can wrap the model in an `Arc<RwLock<...>>` if we need to update it asynchronously while another thread might be reading from it.
  - If integrating in an async environment (like a Tokio runtime), one could call training in a blocking task (to avoid blocking the async reactor), then update the shared model. The scoring function itself is just CPU-bound computations, which can be done quickly for each session.
  - In summary, design the analyzer such that model updates and usage won't cause race conditions: e.g., use interior mutability or require exclusive access in `update_sessions`.

With these considerations, let's outline the `flodbadd_analyzer` module with the `SessionAnalyzer` struct and its key methods. We assume `SessionInfo` and `SessionStats` are given (with fields as described). We'll add a new field `criticality` to `SessionInfo` and use an enum for its value. The code will use the `extended_isolation_forest` crate to train and score the model. (If using a different crate, the API calls would differ, but the structure of the code remains similar.)

## Example Implementation

Below is a Rust code example illustrating the `flodbadd_analyzer` module. This includes the data structures, the analyzer with model training and scoring, and comments explaining each part:

```rust
// Assume these structs are provided by the application:
pub struct SessionStats {
    pub duration_secs: f64,   // e.g., duration of session in seconds
    pub bytes_transferred: u64,  // total bytes (could be split into sent/received if needed)
    pub packets: u32,         // total packets
    pub missed_bytes: u64,    // e.g., bytes lost or missing in capture
    // ... other stats fields (packets_in, packets_out, etc.) ...
}

pub struct SessionInfo {
    pub process_name: String,   // process initiating the session
    pub dest_port: u16,         // destination port of the session
    pub stats: SessionStats,    // embedded stats
    pub criticality: Criticality, // field to be set by analyzer
    // ... other fields like src IP, dst IP, etc., which we won't use for features ...
}

// Define the Criticality levels as an enum for clarity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Criticality {
    Normal,
    Suspicious,
    Abnormal,
}

// Implementation of Display for Criticality (optional, for nice printing)
impl std::fmt::Display for Criticality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Criticality::Normal => "normal",
            Criticality::Suspicious => "suspicious",
            Criticality::Abnormal => "abnormal",
        };
        write!(f, "{}", s)
    }
}

// The SessionAnalyzer struct holds the Isolation Forest model and recent data
pub struct SessionAnalyzer {
    // The Isolation Forest model (from the extended_isolation_forest crate in this example)
    forest: extended_isolation_forest::Forest<f64, 10>, // Using 10 features in the actual implementation
    // We choose 6 features: [process_hash, dest_port, duration, bytes, packets, missed_bytes]
    recent_data: Vec<[f64; 10]>,   // buffer of recent session feature vectors (10D)
    max_samples: usize,           // max number of recent sessions to keep for training
    // Thresholds for scoring
    suspicious_threshold: f64,
    abnormal_threshold: f64,
}

impl SessionAnalyzer {
    /// Create a new analyzer with default thresholds and an empty model.
    pub fn new() -> Self {
        // Initialize with an empty forest (we'll train it before use).
        // We need to initialize the Forest with some parameters. We can start with 0 trees and then create later.
        let empty_forest = extended_isolation_forest::Forest::new(0, 0); 
        SessionAnalyzer {
            forest: empty_forest,
            recent_data: Vec::new(),
            max_samples: 1000,              // for example, keep up to 1000 recent sessions
            suspicious_threshold: 0.6,      // anomaly score above 0.6 -> suspicious
            abnormal_threshold: 0.8,        // anomaly score above 0.8 -> abnormal
        }
    }

    /// Add new session data to the analyzer's memory.
    /// If the buffer is full, remove the oldest entry.
    fn add_session_data(&mut self, session: &SessionInfo) {
        let features = self.compute_features(session);
        if self.recent_data.len() >= self.max_samples {
            // remove oldest data to maintain sliding window
            self.recent_data.remove(0);
        }
        self.recent_data.push(features);
    }

    /// Compute the feature vector [f64; 6] for a given session.
    /// Feature order: [process_hash, dest_port, duration, bytes, packets, missed_bytes]
    fn compute_features(&self, session: &SessionInfo) -> [f64; 10] {
        // 1. Process name hashed to f64.
        // We'll use a simple hash (std::hash) to get a u64, then convert to f64.
        use std::hash::{Hasher, BuildHasher};
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write(session.process_name.as_bytes());
        let hash_val = hasher.finish();
        // Scale down the hash to a reasonable range (f64).
        let process_hash = (hash_val % 1_000_000) as f64;  
        // (We mod by 1e6 to keep the number smaller; this is arbitrary but keeps values in a range.)

        // 2. Destination port as f64
        let port_val = session.dest_port as f64;

        // 3. Duration (already a f64 in seconds in SessionStats for this example)
        let duration = session.stats.duration_secs;

        // 4. Total bytes transferred
        let bytes = session.stats.bytes_transferred as f64;

        // 5. Total packets
        let packets = session.stats.packets as f64;

        // 6. Missed bytes
        let missed = session.stats.missed_bytes as f64;

        [process_hash, port_val, duration, bytes, packets, missed, 0.0, 0.0, 0.0, 0.0]
    }

    /// Train (or retrain) the Isolation Forest model on the recent data.
    fn train_model(&mut self) {
        if self.recent_data.is_empty() {
            return; // nothing to train on
        }
        // Configure Isolation Forest parameters.
        let options = extended_isolation_forest::ForestOptions {
            n_trees: 50,               // Tuned: Reduced from 100 for performance stability in the Rust crate.
            sample_size: 128,          // Tuned: Reduced from 256 for performance stability.
            max_tree_depth: None,      // no explicit max depth (let it default)
            extension_level: 9,        // Tuned: Using N-1 (9 for 10D data) based on EIF paper for robustness.
                                      // Also observed to be more performant than level=0 in this crate.
        };
        // Build a new forest using the recent data. from_slice takes a slice of feature vectors.
        if let Ok(forest) = extended_isolation_forest::Forest::from_slice(self.recent_data.as_slice(), &options) {
            self.forest = forest;
        }
        // If training fails (e.g., due to any error), we keep the old model (or empty if first time).
    }

    /// Analyze and update the criticality of a batch of sessions.
    /// This will train/update the model and then score each session.
    pub fn update_sessions(&mut self, sessions: &mut [SessionInfo]) {
        // First, update our data buffer and retrain the model with all these sessions included.
        for session in sessions {
            self.add_session_data(session);
        }
        // In a real scenario, you might not retrain on *every* call for performance reasons.
        // You could decide to retrain periodically. Here, for simplicity, we retrain whenever update_sessions is called.
        self.train_model();

        // Now score each session and assign criticality.
        for session in sessions {
            let features = self.compute_features(session);
            // Get anomaly score from the Isolation Forest.
            let score = self.forest.score(&features);
            // The score is between 0 and 1 (extended isolation forest). 
            // Higher score means more likely to be an anomaly.
            let crit = if score >= self.abnormal_threshold {
                Criticality::Abnormal
            } else if score >= self.suspicious_threshold {
                Criticality::Suspicious
            } else {
                Criticality::Normal
            };
            session.criticality = crit;
        }
    }
}

// Example usage (not part of the module, just for illustration):
fn main() {
    let mut analyzer = SessionAnalyzer::new();
    let mut sessions: Vec<SessionInfo> = get_current_sessions(); // assume this fetches current sessions
    analyzer.update_sessions(&mut sessions);
    // Now each SessionInfo in sessions has its criticality set.
    for s in &sessions {
        println!("Session {} -> criticality: {}", s.process_name, s.criticality);
    }
}
```

**Explanation of the code:** 

- We define `Criticality` as an enum to represent the three levels. This is more type-safe than a string and makes it easy to set or check the level in code.
- In `SessionAnalyzer`, we define a fixed feature vector length of 10 (as an example) corresponding to the features chosen. The `Forest<f64, 10>` is a generic type from `extended_isolation_forest` indicating it works on 10-dimensional data of type f64.
- The `compute_features` method transforms a `SessionInfo` into the numeric feature array:
  - We hash the `process_name` to a numeric value. We used Rust's `BuildHasher` to get a u64 hash and then reduced it modulo 1,000,000. This keeps the hash in a moderate range (0 to 1e6) instead of a full 64-bit number, which is arbitrary but helps limit the range of that feature. Another approach could be to take only the lower 20 bits of the hash, etc. The idea is to represent different process names by different numeric values. Sessions with the same process will have the same `process_hash` feature, allowing the model to learn if a particular process's traffic is typical or not.
  - We directly cast the `dest_port` and various stats to f64.
  - All features go into an array of f64.
- The `add_session_data` method appends the feature vector to the `recent_data` buffer (and trims the oldest if over capacity). We call this for each session we want to include in training. In an online system, you might call this as sessions arrive.
- The `train_model` method constructs the Isolation Forest (`Forest`) using the buffered data. We specify:
  - `n_trees: 50` – this creates 50 isolation trees. More trees can increase accuracy but also increase computation. 50 is a common choice.
  - `sample_size: 128` – each tree will be built on a random sample of 128 points from `recent_data`. This is a typical setting from the original paper to ensure trees are not too deep and to improve efficiency. If `recent_data` has fewer than 128 points, the crate will likely use all points.
  - `extension_level: 9` – by setting this to 9, we use the extended Isolation Forest (with splits along hyperplanes). This is fine for our purposes.
  - We call `Forest::from_slice` with our data. This returns a new `Forest` which we store in `self.forest`. (If it errors, we simply skip updating the model.)
- The `update_sessions` method is the main interface:
  1. It adds all provided sessions to the recent data and retrains the model. In a real deployment, you might decide to retrain less frequently (e.g., based on a timer or count of new sessions) to save CPU. Here we retrain on each call for simplicity.
  2. It then computes the features and gets an anomaly `score` for each session using `self.forest.score(&features)`. The `extended_isolation_forest` returns a score in [0,1] where >0.5 indicates an anomaly. We use our configured thresholds (0.8 and 0.6 in this example) to classify:
     - If `score >= 0.8`, we mark **Abnormal** (very high anomaly score).
     - Else if `score >= 0.6`, we mark **Suspicious** (moderate anomaly).
     - Else, **Normal**.
  3. We assign the `criticality` back into the `SessionInfo`. We used an enum, but this could also be a string field set to `"normal"`/`"suspicious"`/`"abnormal"` if that is easier for integration.
- The example `main` function (for illustration) shows how one might use the analyzer: get the current sessions, call `update_sessions`, and then act on the criticality (e.g., print or alert on abnormal sessions).

## Multi-threading and Async Considerations

The above implementation is single-threaded in design, but it can be adapted for concurrent environments:

- **Thread Safety:** The `SessionAnalyzer` does not use any global mutable state except its own fields. If you ensure that each instance is used by one thread at a time or protect calls with a mutex, it will be fine. The `Forest` from `extended_isolation_forest` is just data (trees with random splits), and scoring is read-only on that data. So you could share the trained `forest` across threads (after training) for scoring new sessions concurrently. If using `Arc<...>` for the analyzer or model, ensure to lock or only mutate it in one thread.
- **Async usage:** In an async runtime, you might offload `train_model` to a blocking thread since it may perform a lot of computation (especially if the dataset is large). For example, using `tokio::task::spawn_blocking` to retrain, then update the analyzer's `forest`. The scoring of a single session is very fast (just traversing ~100 trees), which can typically be done inline even in async context without issue.
- **Non-blocking scoring:** Alternatively, you could maintain the model inside an `Arc<RwLock<...>>` so that the main thread can score sessions quickly by reading the model (holding a read lock) while occasionally a background task acquires a write lock to update the model with new training data. This design would let incoming sessions be labeled in real-time without waiting for retraining to finish.

## Periodic Retraining with Fresh Data

To keep the model up-to-date:
- You might call `update_sessions` (which retrains in our design) periodically, say every minute or whenever 100 new sessions have been collected. This batch-update approach is common for Isolation Forest since true incremental updates are not part of the basic algorithm.
- If memory or concept drift is a concern, use the `max_samples` sliding window (as we did) to drop old data. This ensures the model forgets old patterns that might no longer be relevant.
- Optionally, you could maintain separate models for different time segments or categories of traffic if needed (beyond our scope here).

---

By using this `flodbadd_analyzer` module, each new network session can be evaluated in near real-time. Most sessions will be labeled "normal", whereas unusual sessions (e.g., a rare process connecting to an uncommon port with an abnormal byte/packet count) will get tagged as "suspicious" or "abnormal". This enriched `criticality` field can then be used by the rest of the system to trigger alerts or further analysis. The solution is implemented entirely in Rust using available libraries, ensuring it can run efficiently within a Rust network monitoring application without external dependencies.

**Implementation Notes & Tuning:**

- **Crate Choice:** The `extended_isolation_forest` crate was chosen.
- **Extension Level:** Following the recommendations of the EIF paper [Hariri et al., 2018] for improved score robustness and to avoid artifacts seen with standard Isolation Forest (level 0), the maximum extension level (`N-1`, which is 9 for our 10D features) is used. Empirically, using `extension_level > 0` also resolved significant performance instability observed with `extension_level = 0` in this specific crate implementation.
- **Performance Tuning:** Initial parameters based on common defaults (`n_trees=100`, `sample_size=256`) led to performance bottlenecks (hangs) during training with 10D data. The parameters were tuned down to `n_trees=50` and `sample_size=128` to achieve stable and acceptable training times while using the preferred `extension_level=9`.

**Sources:**

- Rust `isoforest` crate – an Isolation Forest implementation in pure Rust.
- *SmartCore* machine learning crate – includes algorithms like Isolation Forest and one-class SVM for anomaly detection.
- Extended Isolation Forest (EIF) usage example – anomaly score above 0.5 indicates an outlier.
- Encoding categorical features for Isolation Forest – hashing as a method to handle categories without one-hot exploding feature count.
- Isolation Forest model retraining strategy – typically retrain with new data rather than incremental update (online learning not common for IF).

## Test Coverage

A comprehensive synthetic test-suite exercises the `SessionAnalyzer` under a variety of benign and malicious traffic patterns.  The generators, expectations and run-instructions live in [`ANOMALYTEST.md`](./ANOMALYTEST.md).  All tests are compiled only when the `packetcapture` feature is enabled and can be run with:

```bash
cargo test --features packetcapture anomaly -- --nocapture
```

The suite validates that:

* Clearly abnormal sessions are classified at least *suspicious* with the test thresholds (0.60 / 0.72).
* Pre-existing `blacklist:*` tags survive re-analysis.
* False-positive rate on baseline HTTPS traffic remains acceptable (< 10 from 100 normal sessions).

Having these checks in CI ensures that future code changes cannot silently degrade the anomaly-detection quality or tamper with the production thresholds. 