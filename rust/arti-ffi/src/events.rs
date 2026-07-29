//! Asynchronous events, queued for the Go control shim to drain.
//!
//! The Go side polls with a timeout rather than receiving callbacks: calling
//! back into Go from a Rust-owned thread needs `//export` plus a runtime
//! attach, and a polling goroutine avoids that entirely.

use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::time::Duration;

use serde::Serialize;

/// One asynchronous notification, mirroring the control-port events that bine
/// actually subscribes to.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum Event {
    /// Maps onto a `STATUS_CLIENT ... BOOTSTRAP` event.
    #[serde(rename = "status_client")]
    StatusClient {
        /// Bootstrap completion, 0-100.
        progress: u8,
        /// Machine-readable phase name.
        tag: String,
        /// Human-readable phase description.
        summary: String,
    },
    /// Maps onto an `HS_DESC` event.
    #[serde(rename = "hs_desc")]
    HsDesc {
        /// `UPLOAD`, `UPLOADED` or `FAILED`.
        action: String,
        /// The service ID, without the `.onion` suffix.
        address: String,
        /// Populated for `FAILED`.
        reason: String,
    },
}

/// Sending half, cloned into each producing task.
#[derive(Clone)]
pub struct Sender(SyncSender<Event>);

impl Sender {
    /// Queue an event, dropping it if the Go side has stopped draining.
    ///
    /// Dropping is deliberate: a wedged consumer must not be able to grow this
    /// queue without bound, and every event we emit is advisory.
    pub fn send(&self, ev: Event) {
        match self.0.try_send(ev) {
            Ok(()) | Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

/// Receiving half, drained by `arti_next_event`.
pub struct Queue(Receiver<Event>);

impl Queue {
    /// Block for up to `timeout` waiting for the next event.
    pub fn next(&self, timeout: Duration) -> Option<Event> {
        match self.0.recv_timeout(timeout) {
            Ok(ev) => Some(ev),
            Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => None,
        }
    }
}

/// Create a queue with room for a burst of events between polls.
pub fn channel() -> (Sender, Queue) {
    let (tx, rx) = std::sync::mpsc::sync_channel(256);
    (Sender(tx), Queue(rx))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn round_trips_an_event() {
        let (tx, rx) = channel();
        tx.send(Event::HsDesc {
            action: "UPLOADED".into(),
            address: "abc".into(),
            reason: String::new(),
        });
        let got = rx.next(Duration::from_secs(1)).expect("event");
        let json = serde_json::to_string(&got).unwrap();
        assert!(json.contains(r#""type":"hs_desc""#));
        assert!(json.contains(r#""action":"UPLOADED""#));
    }

    #[test]
    fn times_out_when_empty() {
        let (_tx, rx) = channel();
        assert!(rx.next(Duration::from_millis(10)).is_none());
    }

    #[test]
    fn drops_rather_than_blocking_when_full() {
        let (tx, rx) = channel();
        for i in 0..1000 {
            tx.send(Event::StatusClient {
                progress: 0,
                tag: format!("{i}"),
                summary: String::new(),
            });
        }
        // Still readable, and we never blocked getting here.
        assert!(rx.next(Duration::from_millis(10)).is_some());
    }
}
