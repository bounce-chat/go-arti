//! Arti's own log records, made available to the caller.
//!
//! Arti reports what it is doing through `tracing`. Without a subscriber those
//! records are discarded, which leaves an embedding application with no view of
//! bootstrap or publication at all. This installs one and queues the records
//! for the caller to drain and route into its own logging.
//!
//! The queue is deliberately separate from the event queue in [`crate::events`]:
//! log volume is unbounded and bursty, and must never crowd out the status
//! events a caller may be blocked on.

use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde::Serialize;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

/// One log record.
#[derive(Debug, Clone, Serialize)]
pub struct LogRecord {
    /// `ERROR`, `WARN`, `INFO`, `DEBUG` or `TRACE`.
    pub level: String,
    /// The emitting module, e.g. `tor_dirmgr::bootstrap`.
    pub target: String,
    /// The formatted message, including any structured fields.
    pub message: String,
}

/// Depth of the log queue.
///
/// Records are dropped rather than queued once this fills. Logs are diagnostic:
/// blocking Arti to deliver them, or growing without bound when nobody drains,
/// would both be worse than losing some.
const LOG_QUEUE_DEPTH: usize = 4096;

/// The process-wide log queue.
///
/// `tracing` allows only one subscriber per process, so this is global rather
/// than per-client.
type LogQueue = (SyncSender<LogRecord>, Mutex<Receiver<LogRecord>>);

/// See [`LogQueue`].
static QUEUE: OnceLock<LogQueue> = OnceLock::new();

/// Return the log queue, creating it on first use.
fn queue() -> &'static LogQueue {
    QUEUE.get_or_init(|| {
        let (tx, rx) = sync_channel(LOG_QUEUE_DEPTH);
        (tx, Mutex::new(rx))
    })
}

/// Wait up to `timeout` for the next log record.
pub fn next(timeout: Duration) -> Option<LogRecord> {
    let rx = queue().1.lock().ok()?;
    rx.recv_timeout(timeout).ok()
}

/// Install the subscriber, at the given `EnvFilter` directives.
///
/// Idempotent, and returns false if a subscriber was already installed —
/// including one belonging to the host application, which is left alone.
pub fn install(directives: &str, mirror_to_stderr: bool) -> bool {
    let filter = match EnvFilter::try_new(directives) {
        Ok(f) => f,
        Err(_) => return false,
    };

    // Touch the queue first, so records emitted during setup have somewhere to
    // go rather than initialising it from inside the layer.
    let _ = queue();

    let stderr =
        mirror_to_stderr.then(|| tracing_subscriber::fmt::layer().with_writer(std::io::stderr));

    tracing_subscriber::registry()
        .with(filter)
        .with(QueueLayer)
        .with(stderr)
        .try_init()
        .is_ok()
}

/// A `tracing` layer that queues records for the caller.
struct QueueLayer;

impl<S: tracing::Subscriber> Layer<S> for QueueLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = Message::default();
        event.record(&mut visitor);

        let record = LogRecord {
            level: event.metadata().level().to_string(),
            target: event.metadata().target().to_string(),
            message: visitor.finish(),
        };

        match queue().0.try_send(record) {
            Ok(()) | Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

/// Collects an event's fields into a single line.
#[derive(Default)]
struct Message {
    /// The `message` field, which carries the human-readable text.
    message: String,
    /// Everything else, rendered as `key=value`.
    fields: Vec<String>,
}

impl Message {
    /// Render the collected fields.
    fn finish(self) -> String {
        if self.fields.is_empty() {
            return self.message;
        }
        if self.message.is_empty() {
            return self.fields.join(" ");
        }
        format!("{} {}", self.message, self.fields.join(" "))
    }

    /// Record a field, keeping `message` separate from the rest.
    fn push(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = value;
        } else {
            self.fields.push(format!("{}={}", field.name(), value));
        }
    }
}

impl Visit for Message {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.push(field, format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field, value.to_string());
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn renders_message_and_fields() {
        let mut m = Message::default();
        assert_eq!(m.clone_finish(), "");

        m = Message::default();
        m.fields.push("attempt=1".into());
        m.message = "Looking for a consensus.".into();
        assert_eq!(m.finish(), "Looking for a consensus. attempt=1");
    }

    #[test]
    fn renders_fields_without_a_message() {
        let mut m = Message::default();
        m.fields.push("a=1".into());
        m.fields.push("b=2".into());
        assert_eq!(m.finish(), "a=1 b=2");
    }

    #[test]
    fn an_empty_queue_times_out() {
        assert!(next(Duration::from_millis(10)).is_none());
    }

    impl Message {
        /// Helper so a test can render without consuming a fresh value.
        fn clone_finish(&self) -> String {
            Message {
                message: self.message.clone(),
                fields: self.fields.clone(),
            }
            .finish()
        }
    }
}
