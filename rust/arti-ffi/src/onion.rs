//! ADD_ONION / DEL_ONION, expressed in Arti terms.
//!
//! The key formats line up exactly: control-spec's `ED25519-V3` blob is a
//! base64'd 64-byte expanded ed25519 secret key, and `HsIdKeypair` stores
//! precisely that, in `(a,r)` form, for C tor compatibility.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use arti_client::TorClient;
use base64::Engine as _;
use futures::StreamExt as _;
use safelog::DisplayRedacted as _;
use serde::{Deserialize, Serialize};
use tor_hscrypto::pk::{HsId, HsIdKey, HsIdKeypair};
use tor_hsrproxy::config::{
    Encapsulation, ProxyAction, ProxyConfigBuilder, ProxyPattern, ProxyRule, TargetAddr,
};
use tor_hsrproxy::OnionServiceReverseProxy;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{HsNickname, RunningOnionService};
use tor_llcrypto::pk::ed25519;
use tor_rtcompat::PreferredRuntime;

use crate::events::{Event, Sender};

/// One `Port=` mapping from an ADD_ONION request.
#[derive(Debug, Clone, Deserialize)]
pub struct PortMap {
    /// The port exposed on the onion address.
    pub virtual_port: u16,
    /// Where to forward it, e.g. `127.0.0.1:8080`.
    pub target: String,
}

/// An ADD_ONION request, already parsed by the Go control shim.
#[derive(Debug, Clone, Deserialize)]
pub struct AddRequest {
    /// `NEW` or `ED25519-V3`.
    pub key_type: String,
    /// `BEST`/`ED25519-V3` for `NEW`, otherwise the base64 secret key.
    pub key_blob: String,
    /// Virtual-to-local port mappings; at least one is required.
    pub ports: Vec<PortMap>,
    /// Whether the caller asked us not to hand the private key back.
    #[serde(default)]
    pub discard_pk: bool,
}

/// The response to an ADD_ONION request.
#[derive(Debug, Clone, Serialize)]
pub struct AddResponse {
    /// The onion address, without the `.onion` suffix.
    pub service_id: String,
    /// The base64 secret key, unless the caller asked us to discard it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<String>,
}

/// A launched service, retained so DEL_ONION can tear it down.
pub struct Service {
    /// Keeps the service alive; the service stops once this is dropped.
    _service: Arc<RunningOnionService>,
    /// The reverse proxy forwarding rendezvous requests to local ports.
    proxy: Arc<OnionServiceReverseProxy>,
    /// Background tasks: the proxy loop and the status watcher.
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Service {
    /// Stop the service and its background tasks.
    ///
    /// This stops the service serving traffic, but it does not synchronously
    /// release everything the service held: the state directory keeps its lock
    /// until Arti's own background tasks have wound down, which can outlast
    /// this call. That is why each launch takes a fresh nickname — see
    /// [`launch`].
    pub fn shutdown(self) {
        self.proxy.shutdown();
        for task in self.tasks {
            task.abort();
        }
    }
}

/// Turn an ADD_ONION key specification into a keypair.
///
/// Returns the keypair alongside its base64 `ED25519-V3` blob, so the caller
/// can echo a generated key back to the controller.
pub fn keypair_for(key_type: &str, key_blob: &str) -> Result<(HsIdKeypair, String), String> {
    match key_type {
        "NEW" => match key_blob {
            "BEST" | "ED25519-V3" => {
                let kp = ed25519::Keypair::generate(&mut rand::rng());
                let expanded = ed25519::ExpandedKeypair::from(&kp);
                let blob = base64::engine::general_purpose::STANDARD
                    .encode(expanded.to_secret_key_bytes());
                Ok((HsIdKeypair::from(expanded), blob))
            }
            other => Err(format!("unsupported key algorithm {other:?}")),
        },
        "ED25519-V3" => {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(key_blob)
                .map_err(|e| format!("malformed private key: {e}"))?;
            let bytes: [u8; 64] = raw
                .try_into()
                .map_err(|_| "private key must be 64 bytes".to_string())?;
            let expanded = ed25519::ExpandedKeypair::from_secret_key_bytes(bytes)
                .ok_or_else(|| "private key is not a valid ed25519 secret".to_string())?;
            // Echo the caller's own bytes rather than our re-encoding. Arti
            // reduces the scalar mod the group order on import, which leaves
            // the public key (and so the .onion address) untouched but does
            // change the 64-byte representation of a key that C tor generated.
            // Handing back what we were given keeps a controller-persisted key
            // byte-stable across implementations.
            Ok((HsIdKeypair::from(expanded), key_blob.to_string()))
        }
        other => Err(format!("unsupported key type {other:?}")),
    }
}

/// Derive the `.onion` service ID (without suffix) for a keypair.
pub fn service_id_of(keypair: &HsIdKeypair) -> String {
    let id: HsId = HsIdKey::from(keypair).id();
    let full = id.display_unredacted().to_string();
    full.trim_end_matches(".onion").to_string()
}

/// Launch an onion service for an ADD_ONION request.
pub fn launch(
    client: &TorClient<PreferredRuntime>,
    req: &AddRequest,
    events: Sender,
) -> Result<(AddResponse, Service), String> {
    if req.ports.is_empty() {
        return Err("at least one Port= mapping is required".to_string());
    }
    let (keypair, blob) = keypair_for(&req.key_type, &req.key_blob)?;
    let service_id = service_id_of(&keypair);

    // Every launch gets a fresh nickname, unique across restarts as well as
    // within a process.
    //
    // It cannot be derived from the service ID: the keystore rejects
    // re-inserting an identity key it already holds under that nickname, and
    // the state directory keeps its lock until the previous instance's tasks
    // have wound down, which DEL_ONION does not wait for.
    //
    // Nor can it be a per-process counter. Our keystore is ephemeral, so the
    // introduction point keys never survive a restart — but the state
    // directory does. Reusing `svc-0` on the next run makes Arti find
    // persisted introduction points whose keys are gone, which it reports as
    // an internal bug and recovers from by regenerating every one of them.
    // That churn tears down circuits faster than guards can be replaced.
    let nickname = HsNickname::new(format!("svc-{}", unique_service_slug()))
        .map_err(|e| format!("cannot build service nickname: {e}"))?;

    let mut proxy_builder = ProxyConfigBuilder::default();
    let mut rules = Vec::with_capacity(req.ports.len());
    for port in &req.ports {
        let target: SocketAddr = SocketAddr::from_str(&port.target)
            .map_err(|e| format!("invalid target {:?}: {e}", port.target))?;
        let pattern = ProxyPattern::one_port(port.virtual_port)
            .map_err(|e| format!("invalid virtual port {}: {e}", port.virtual_port))?;
        rules.push(ProxyRule::new(
            pattern,
            ProxyAction::Forward(Encapsulation::Simple, TargetAddr::Inet(target)),
        ));
    }
    *proxy_builder.proxy_ports() = rules;
    let proxy_config = proxy_builder
        .build()
        .map_err(|e| format!("invalid port mapping: {e}"))?;

    let svc_config = OnionServiceConfigBuilder::default()
        .nickname(nickname.clone())
        .build()
        .map_err(|e| format!("invalid onion service config: {e}"))?;

    let (service, rend_requests) = client
        .launch_onion_service_with_hsid(svc_config, keypair)
        .map_err(|e| format!("failed to launch onion service: {e}"))?
        .ok_or_else(|| "onion service was disabled by configuration".to_string())?;

    let proxy = OnionServiceReverseProxy::new(proxy_config);
    let mut tasks = Vec::with_capacity(2);

    let proxy_task = {
        let proxy = proxy.clone();
        let runtime = client.runtime().clone();
        let nickname = nickname.clone();
        tokio::spawn(async move {
            let _ = proxy
                .handle_requests(runtime, nickname, rend_requests)
                .await;
        })
    };
    tasks.push(proxy_task);

    tasks.push(spawn_status_watcher(&service, service_id.clone(), events));

    Ok((
        AddResponse {
            service_id,
            secret_key: if req.discard_pk { None } else { Some(blob) },
        },
        Service {
            _service: service,
            proxy,
            tasks,
        },
    ))
}

/// A slug that has not been used before, on this run or any previous one.
///
/// Random rather than sequential precisely so that it does not collide with
/// the state left behind by an earlier process; see [`launch`].
fn unique_service_slug() -> String {
    let mut bytes = [0u8; 8];
    rand::fill(&mut bytes);
    // Lowercase hex keeps this a valid nickname slug.
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Translate Arti's onion service status into the `HS_DESC` events bine waits
/// on when publishing a service.
///
/// The mapping is necessarily lossy: Arti reports one aggregate state rather
/// than per-HSDir upload results, so a single `UPLOAD` is emitted when
/// publishing starts and a single `UPLOADED` once a descriptor has gone up.
fn spawn_status_watcher(
    service: &Arc<RunningOnionService>,
    service_id: String,
    events: Sender,
) -> tokio::task::JoinHandle<()> {
    use tor_hsservice::status::State;

    let mut stream = service.status_events();
    tokio::spawn(async move {
        let mut announced_upload = false;
        let mut announced_uploaded = false;

        let announce = |action: &str, reason: String| {
            events.send(Event::HsDesc {
                action: action.into(),
                address: service_id.clone(),
                reason,
            });
        };

        while let Some(status) = stream.next().await {
            let state = status.state();
            if matches!(state, State::Shutdown) {
                continue;
            }

            if !announced_upload {
                announced_upload = true;
                announce("UPLOAD", String::new());
            }

            // `UPLOADED` means the service is believed fully reachable, which
            // is the strongest thing Arti's status can actually tell us.
            //
            // It is deliberately not a proxy for "a descriptor has been
            // uploaded". Arti aggregates the introduction point manager and the
            // publisher into one state, and reports `Bootstrapping` while
            // either is still working — so the publisher can have a descriptor
            // up minutes before this fires. There is no public accessor for the
            // publisher alone. Callers that must not block on reachability
            // should use `NoWait` and treat the service as usable once it
            // exists, rather than waiting on this.
            if state.is_fully_reachable() && !announced_uploaded {
                announced_uploaded = true;
                announce("UPLOADED", String::new());
            }

            if matches!(state, State::Broken) {
                let reason = status
                    .current_problem()
                    .map(|p| format!("{p:?}"))
                    .unwrap_or_else(|| "unknown".into());
                announce("FAILED", reason);
            }
        }
    })
}

/// Derive the public half of an expanded ed25519 secret key.
///
/// Returns the 32-byte public key, or `None` if the secret is malformed.
pub fn public_key_of(secret: &[u8]) -> Option<[u8; 32]> {
    let bytes: [u8; 64] = secret.try_into().ok()?;
    let expanded = ed25519::ExpandedKeypair::from_secret_key_bytes(bytes)?;
    Some(expanded.public().to_bytes())
}

/// Sign a message with an expanded ed25519 secret key.
///
/// Onion service keys only ever exist in expanded form, so this cannot go
/// through an API that expects a seed.
pub fn sign_with_expanded(secret: &[u8], message: &[u8]) -> Option<[u8; 64]> {
    let bytes: [u8; 64] = secret.try_into().ok()?;
    let expanded = ed25519::ExpandedKeypair::from_secret_key_bytes(bytes)?;
    Some(expanded.sign(message).to_bytes())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn generated_key_round_trips_through_the_blob() {
        let (kp, blob) = keypair_for("NEW", "BEST").unwrap();
        let id = service_id_of(&kp);
        assert_eq!(id.len(), 56, "v3 onion ids are 56 base32 chars");

        // Re-importing the blob must land on the same onion address, which is
        // what makes a bine-persisted key usable across restarts.
        let (kp2, blob2) = keypair_for("ED25519-V3", &blob).unwrap();
        assert_eq!(blob, blob2);
        assert_eq!(id, service_id_of(&kp2));
    }

    #[test]
    fn matches_the_c_tor_test_vector() {
        // From tor-hscrypto's own C-tor-generated vector: this pins the
        // expanded-key interpretation that control-spec's ED25519-V3 uses.
        let secret: [u8; 64] = [
            0xD8, 0xC7, 0xFF, 0x0E, 0x31, 0x29, 0x5B, 0x66, 0x54, 0x0D, 0x78, 0x9A, 0xF3, 0xE3,
            0xDF, 0x99, 0x20, 0x38, 0xA9, 0x59, 0x2E, 0xEA, 0x01, 0xD8, 0xB7, 0xCB, 0xA0, 0x6D,
            0x6E, 0x66, 0xD1, 0x59, 0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x57, 0x6F, 0x72, 0x64,
            0x73, 0x3A, 0x20, 0x73, 0x70, 0x65, 0x69, 0x73, 0x73, 0x63, 0x6F, 0x62, 0x61, 0x6C,
            0x74, 0x20, 0x62, 0x69, 0x76, 0x69, 0x75, 0x6D,
        ];
        let blob = base64::engine::general_purpose::STANDARD.encode(secret);
        let (kp, echoed) = keypair_for("ED25519-V3", &blob).unwrap();
        // An imported key is echoed verbatim, even though Arti's internal
        // representation reduces the scalar.
        assert_eq!(blob, echoed);

        let expected = HsIdKey::try_from(HsId::from([
            0x83, 0x39, 0x90, 0xB0, 0x85, 0xC1, 0xA6, 0x88, 0xC1, 0xD4, 0xC8, 0xB1, 0xF6, 0xB5,
            0x6A, 0xFA, 0xF5, 0xA2, 0xEC, 0xA6, 0x74, 0x44, 0x9E, 0x1D, 0x70, 0x4F, 0x83, 0x76,
            0x5C, 0xCB, 0x7B, 0xC6,
        ]))
        .unwrap()
        .id();
        let expected = expected.display_unredacted().to_string();
        let expected = expected.trim_end_matches(".onion");
        assert_eq!(service_id_of(&kp), expected);
    }

    #[test]
    fn rejects_bad_keys() {
        assert!(keypair_for("RSA1024", "whatever").is_err());
        assert!(keypair_for("NEW", "RSA1024").is_err());
        assert!(keypair_for("ED25519-V3", "not base64!!").is_err());
        // Right encoding, wrong length.
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        assert!(keypair_for("ED25519-V3", &short).is_err());
    }
}
