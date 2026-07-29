//! A minimal C ABI over [Arti](https://gitlab.torproject.org/tpo/core/arti),
//! built as a static library and linked into Go by the `libtor` package.
//!
//! Arti deliberately has no control port — it replaced it with a JSON-RPC API
//! — so this crate does not try to reimplement one. It exposes just enough of
//! Arti (bootstrap, SOCKS, onion services, status events) for the Go side to
//! present a control-port-compatible face to
//! [bine](https://github.com/alexballas/bine).
//!
//! See `src/ffi.rs` for the exported surface and its calling conventions.

#![deny(missing_docs)]

pub mod client;
pub mod config;
pub mod events;
pub mod ffi;
pub mod logs;
pub mod onion;
pub mod socks;

/// The Arti version this library is built against, as reported to callers.
///
/// NUL-terminated so `arti_version` can hand out a pointer to it directly,
/// without allocating or leaking. Kept in step with `Cargo.toml` by
/// `arti_version_matches_manifest` below.
pub(crate) const ARTI_VERSION_C: &str = "Arti 0.44\0";

/// The Arti version this library is built against.
pub const ARTI_VERSION: &str = "0.44";

#[cfg(test)]
mod test {
    /// The manifest is the single source of truth; this catches a dependency
    /// bump that forgets to update the version we report to callers.
    #[test]
    fn arti_version_matches_manifest() {
        let manifest = include_str!("../Cargo.toml");
        let line = manifest
            .lines()
            .find(|l| l.trim_start().starts_with("arti-client"))
            .expect("arti-client dependency");
        let declared = line
            .split("version = \"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("version in arti-client dependency");
        assert_eq!(declared, super::ARTI_VERSION);
    }

    /// The C-facing string must stay in step with the Rust one.
    #[test]
    fn c_version_string_matches() {
        assert_eq!(
            super::ARTI_VERSION_C,
            format!("Arti {}\0", super::ARTI_VERSION)
        );
    }
}
