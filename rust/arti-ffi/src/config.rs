//! The configuration blob handed across the FFI boundary.
//!
//! The Go side owns the job of turning bine's torrc-style command line into
//! this struct; everything here is already normalised.

use std::path::PathBuf;

use arti_client::config::{TorClientConfig, TorClientConfigBuilder};
use serde::Deserialize;

/// How the SOCKS listener should be bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SocksPort {
    /// Do not run a SOCKS listener at all.
    Disabled,
    /// Bind to an arbitrary free port and report it back.
    #[default]
    Auto,
    /// Bind to this specific port.
    Fixed(u16),
}

impl<'de> Deserialize<'de> for SocksPort {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Accepts `"auto"`, `"0"`, `9050`, or `"disabled"`, mirroring torrc.
        let raw = String::deserialize(d)?;
        Ok(match raw.as_str() {
            "auto" | "0" => SocksPort::Auto,
            "" | "disabled" => SocksPort::Disabled,
            other => match other.parse::<u16>() {
                Ok(0) => SocksPort::Auto,
                Ok(p) => SocksPort::Fixed(p),
                Err(_) => SocksPort::Disabled,
            },
        })
    }
}

/// Everything the Rust side needs in order to stand up a client.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Equivalent of torrc `DataDirectory`. Required.
    pub data_directory: String,
    /// Equivalent of torrc `SocksPort`.
    pub socks_port: SocksPort,
    /// Address to bind the SOCKS listener on.
    pub socks_bind_address: String,
    /// Equivalent of torrc `DisableNetwork`; bine sets this at startup.
    pub disable_network: bool,
    /// Equivalent of torrc `UseBridges`.
    pub use_bridges: bool,
    /// Equivalent of torrc `Bridge` lines.
    #[serde(deserialize_with = "null_as_default")]
    pub bridges: Vec<String>,
}

/// Deserialize `null` as the type's default rather than failing.
///
/// `#[serde(default)]` only covers a *missing* field, but Go marshals a nil
/// slice as an explicit `null`, which would otherwise be a hard error.
fn null_as_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

impl Default for Config {
    fn default() -> Self {
        Config {
            data_directory: String::new(),
            socks_port: SocksPort::default(),
            socks_bind_address: "127.0.0.1".to_string(),
            disable_network: false,
            use_bridges: false,
            bridges: Vec::new(),
        }
    }
}

impl Config {
    /// Parse the JSON blob handed over from Go.
    pub fn from_json(raw: &str) -> Result<Self, String> {
        let cfg: Config = serde_json::from_str(raw).map_err(|e| format!("invalid config: {e}"))?;
        if cfg.data_directory.is_empty() {
            return Err("config: data_directory is required".to_string());
        }
        Ok(cfg)
    }

    /// Arti keeps state and cache separately; both live under the single
    /// `DataDirectory` that bine hands us, so the layout stays self-contained.
    pub fn state_dir(&self) -> PathBuf {
        PathBuf::from(&self.data_directory).join("arti-state")
    }

    /// See [`Config::state_dir`].
    pub fn cache_dir(&self) -> PathBuf {
        PathBuf::from(&self.data_directory).join("arti-cache")
    }

    /// Build the Arti client configuration this config describes.
    pub fn to_tor_client_config(&self) -> Result<TorClientConfig, String> {
        let mut builder =
            TorClientConfigBuilder::from_directories(self.state_dir(), self.cache_dir());

        // Only police the directories we create ourselves. Arti otherwise
        // walks the whole ancestor chain and refuses to start if any of it is
        // group- or world-writable, which fails for a data directory under
        // /tmp or a shared home. C tor checks the data directory itself and
        // stops there, so this keeps the guarantee that matters - the
        // directories holding keys and state are private - without rejecting
        // locations C tor accepted.
        builder
            .storage()
            .permissions()
            .ignore_prefix(PathBuf::from(&self.data_directory));

        // ADD_ONION services are ephemeral in C tor: the controller holds the
        // key and the daemon forgets it on shutdown. An in-memory keystore is
        // the faithful equivalent, and it keeps onion keys off disk.
        builder
            .storage()
            .keystore()
            .primary()
            .kind(tor_keymgr::config::ArtiKeystoreKind::Ephemeral.into());

        if self.use_bridges && !self.bridges.is_empty() {
            let bridges: Vec<_> = self
                .bridges
                .iter()
                .map(|b| {
                    b.parse::<arti_client::config::BridgeConfigBuilder>()
                        .map_err(|e| format!("invalid bridge {b:?}: {e}"))
                })
                .collect::<Result<_, _>>()?;
            *builder.bridges().bridges() = bridges;
            builder
                .bridges()
                .enabled(tor_config::BoolOrAuto::Explicit(true));
        }

        builder.build().map_err(|e| format!("invalid config: {e}"))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn data_directory_is_required() {
        assert!(Config::from_json("{}").is_err());
    }

    #[test]
    fn socks_port_forms() {
        let parse = |s: &str| {
            Config::from_json(&format!(
                r#"{{"data_directory":"/tmp/x","socks_port":"{s}"}}"#
            ))
            .unwrap()
            .socks_port
        };
        assert_eq!(parse("auto"), SocksPort::Auto);
        assert_eq!(parse("0"), SocksPort::Auto);
        assert_eq!(parse("9050"), SocksPort::Fixed(9050));
        assert_eq!(parse("disabled"), SocksPort::Disabled);
    }

    /// Go marshals a nil slice as `null`, so the config must survive it.
    #[test]
    fn null_bridges_are_accepted() {
        let cfg =
            Config::from_json(r#"{"data_directory":"/tmp/x","bridges":null}"#).expect("parse");
        assert!(cfg.bridges.is_empty());

        let cfg = Config::from_json(r#"{"data_directory":"/tmp/x","bridges":[]}"#).expect("parse");
        assert!(cfg.bridges.is_empty());

        let cfg = Config::from_json(r#"{"data_directory":"/tmp/x"}"#).expect("parse");
        assert!(cfg.bridges.is_empty());
    }

    #[test]
    fn dirs_live_under_the_data_directory() {
        let cfg = Config::from_json(r#"{"data_directory":"/tmp/dd"}"#).unwrap();
        assert_eq!(cfg.state_dir(), PathBuf::from("/tmp/dd/arti-state"));
        assert_eq!(cfg.cache_dir(), PathBuf::from("/tmp/dd/arti-cache"));
    }
}
