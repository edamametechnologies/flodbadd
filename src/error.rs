// Crate-level error type for the public API surface.
//
// Internal code continues to use `anyhow::Result` for convenience. This enum
// is intended for functions exposed to consumers (edamame_core, edamame_helper)
// so they can pattern-match on error categories without depending on anyhow
// downcasting.
//
// NOTE: Existing functions have not been converted yet. This definition is a
// first step toward a uniform public error contract.

use std::fmt;

/// Categorised error type for the flodbadd public API.
#[derive(Debug)]
pub enum FlodbaddError {
    /// Packet capture initialization or runtime failure
    /// (e.g. interface not found, permission denied, pcap error).
    Capture(String),

    /// ML anomaly-detection engine failure
    /// (e.g. model load error, feature extraction panic).
    Analyzer(String),

    /// Invalid or missing configuration
    /// (e.g. bad filter expression, unknown interface name).
    Configuration(String),

    /// Underlying I/O error (file, network, OS call).
    Io(std::io::Error),
}

impl fmt::Display for FlodbaddError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlodbaddError::Capture(msg) => write!(f, "capture error: {}", msg),
            FlodbaddError::Analyzer(msg) => write!(f, "analyzer error: {}", msg),
            FlodbaddError::Configuration(msg) => write!(f, "configuration error: {}", msg),
            FlodbaddError::Io(err) => write!(f, "I/O error: {}", err),
        }
    }
}

impl std::error::Error for FlodbaddError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FlodbaddError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for FlodbaddError {
    fn from(err: std::io::Error) -> Self {
        FlodbaddError::Io(err)
    }
}
