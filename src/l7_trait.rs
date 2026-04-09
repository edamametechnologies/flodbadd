// Shared trait defining the common L7 backend surface.
//
// Each platform-specific L7 backend (eBPF on Linux, Endpoint Security on macOS,
// ETW on Windows) exposes the same three capabilities:
//   - Session-to-process resolution
//   - Availability check
//   - Initialization with status logging
//
// This trait captures that contract so future refactoring can unify dispatch
// through a single trait object or generic parameter instead of the current
// per-module free functions.
//
// Backends that should implement this trait (future struct wrappers around
// existing free-function modules):
//   - l7_ebpf module  (Linux eBPF kprobe-based resolution)
//   - l7_es module    (macOS Endpoint Security framework)
//   - l7_etw module   (Windows ETW kernel trace)
//
// l7_macos is a lower-level libproc socket scanner without a singleton pattern;
// it does not fit this trait directly but could be wrapped in an adapter.
//
// NOTE: The trait is defined but not yet implemented on any backend. That
// conversion is tracked as follow-up work to avoid a large cross-platform
// refactor in a single change.

use crate::sessions::{Session, SessionL7};

/// Common interface for platform-specific L7 (process attribution) backends.
///
/// Each backend resolves network sessions to the local process that owns them,
/// reports whether the backend is operational, and provides a one-shot
/// initialization routine that logs its status.
pub trait L7Backend: Send + Sync {
    /// Attempt to resolve a network session to its owning process.
    /// Returns `None` if the backend cannot attribute the session.
    fn get_l7_for_session(&self, session: &Session) -> Option<SessionL7>;

    /// Whether the backend successfully initialized and is ready for lookups.
    fn is_available(&self) -> bool;

    /// Perform any deferred initialization and log the resulting status
    /// (enabled/disabled and the reason).
    fn init_and_log_status(&self);
}
