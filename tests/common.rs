#![allow(dead_code)]
use flodbadd::analyzer::SessionAnalyzer;
use flodbadd::sessions::SessionInfo;

/// Calibrate thresholds from a baseline: set suspicious at the chosen percentile of
/// normal scores (+epsilon) and abnormal slightly above it.
pub async fn calibrate_thresholds_from_baseline(
    analyzer: &SessionAnalyzer,
    baseline: &Vec<SessionInfo>,
    percentile: f64,
) {
    let mut scores: Vec<f64> = Vec::new();
    for s in baseline {
        if let Some((score, _, _)) = analyzer.debug_score_and_thresholds(s).await {
            scores.push(score);
        }
    }
    if scores.is_empty() {
        // Fallback to defaults
        analyzer
            .set_test_thresholds(
                flodbadd::analyzer::DEFAULT_SUSPICIOUS_THRESHOLD,
                flodbadd::analyzer::DEFAULT_ABNORMAL_THRESHOLD,
            )
            .await;
        return;
    }
    scores.sort_by(|a, b| a.partial_cmp(b).unwrap());
    // Use proper percentile calculation: (n-1) * percentile
    let n = scores.len();
    let idx = if n == 0 {
        0
    } else {
        ((n as f64 - 1.0) * percentile).max(0.0).min((n - 1) as f64) as usize
    };
    let p = scores[idx];
    analyzer.set_test_thresholds(p + 1e-6, p + 0.05).await;
}

/// Assert that a target session's score lies outside the [low, high] band of normal scores.
pub async fn assert_score_outside_band(
    analyzer: &SessionAnalyzer,
    target: &SessionInfo,
    normals: &[SessionInfo],
    low_percentile: f64,
    high_percentile: f64,
    context: &str,
) {
    let mut scores: Vec<f64> = Vec::new();
    for s in normals {
        if let Some((sc, _, _)) = analyzer.debug_score_and_thresholds(s).await {
            scores.push(sc);
        }
    }
    assert!(!scores.is_empty(), "{}: normal scores are empty", context);
    scores.sort_by(|a, b| a.partial_cmp(b).unwrap());
    // Use proper percentile calculation: (n-1) * percentile
    let n = scores.len();
    let low_idx = if n == 0 {
        0
    } else {
        ((n as f64 - 1.0) * low_percentile)
            .max(0.0)
            .min((n - 1) as f64) as usize
    };
    let high_idx = if n == 0 {
        0
    } else {
        ((n as f64 - 1.0) * high_percentile)
            .max(0.0)
            .min((n - 1) as f64) as usize
    };
    let band_low = scores[low_idx];
    let band_high = scores[high_idx];

    let target_score = analyzer
        .debug_score_and_thresholds(target)
        .await
        .map(|(s, _, _)| s)
        .unwrap_or(f64::NAN);
    assert!(
        target_score.is_finite(),
        "{}: target score not finite",
        context
    );
    assert!(
        target_score <= band_low || target_score >= band_high,
        "{}: score {:.4} not outside band [{:.4}, {:.4}]",
        context,
        target_score,
        band_low,
        band_high
    );
}

/// Assert that session criticality diagnostics contain all expected substrings.
pub fn assert_diag_contains(session: &SessionInfo, fragments: &[&str], context: &str) {
    for frag in fragments {
        assert!(
            session.criticality.contains(frag),
            "{}: expected diagnostic fragment '{}' in '{}'",
            context,
            frag,
            session.criticality
        );
    }
}

/// Assert that session diagnostic contains at least one of the provided fragments.
pub fn assert_diag_contains_any(session: &SessionInfo, fragments: &[&str], context: &str) {
    let mut found = false;
    for frag in fragments {
        if session.criticality.contains(frag) {
            found = true;
            break;
        }
    }
    assert!(
        found,
        "{}: expected at least one of {:?} in '{}'",
        context, fragments, session.criticality
    );
}
