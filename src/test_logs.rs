//! Test-only log capture: counts the WARN/ERROR and the DEBUG/TRACE events
//! whose message contains a needle, on the current thread.
//!
//! Atomics only. An undeadlock lock here would report its own diagnostics
//! through `tracing`, i.e. back into this subscriber, and a raw lock is
//! banned by the crate's lock rule.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tracing::dispatcher::{self, DefaultGuard, Dispatch};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};

/// Events seen so far whose message contains the needle.
pub(crate) struct NeedleCounts {
    needle: &'static str,
    warn_or_error: AtomicUsize,
    debug_or_trace: AtomicUsize,
}

impl NeedleCounts {
    pub(crate) fn warn_or_error(&self) -> usize {
        self.warn_or_error.load(Ordering::SeqCst)
    }

    pub(crate) fn debug_or_trace(&self) -> usize {
        self.debug_or_trace.load(Ordering::SeqCst)
    }
}

struct NeedleSubscriber {
    counts: Arc<NeedleCounts>,
    next_span: AtomicU64,
}

#[derive(Default)]
struct MessageVisitor(String);

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

impl Subscriber for NeedleSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(self.next_span.fetch_add(1, Ordering::Relaxed) + 1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut message = MessageVisitor::default();
        event.record(&mut message);
        if !message.0.contains(self.counts.needle) {
            return;
        }
        let counter = match *event.metadata().level() {
            Level::ERROR | Level::WARN => &self.counts.warn_or_error,
            Level::INFO => return,
            _ => &self.counts.debug_or_trace,
        };
        counter.fetch_add(1, Ordering::SeqCst);
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

/// Count the events containing `needle` that this thread logs while the
/// returned guard lives.
pub(crate) fn capture(needle: &'static str) -> (DefaultGuard, Arc<NeedleCounts>) {
    let counts = Arc::new(NeedleCounts {
        needle,
        warn_or_error: AtomicUsize::new(0),
        debug_or_trace: AtomicUsize::new(0),
    });
    let subscriber = NeedleSubscriber {
        counts: counts.clone(),
        next_span: AtomicU64::new(0),
    };
    let guard = dispatcher::set_default(&Dispatch::new(subscriber));
    (guard, counts)
}
