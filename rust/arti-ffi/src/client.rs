//! The long-lived object behind an `arti_client_t` handle.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use arti_client::{BootstrapBehavior, DormantMode, TorClient};
use futures::StreamExt as _;
use serde::Serialize;
use tor_rtcompat::PreferredRuntime;

use crate::config::{Config, SocksPort};
use crate::events::{self, Event, Queue, Sender};
use crate::onion::{self, AddRequest, AddResponse, Service};

/// The bootstrap snapshot reported by `GETINFO status/bootstrap-phase`.
#[derive(Debug, Clone, Serialize)]
pub struct BootstrapStatus {
    /// Completion percentage, 0-100.
    pub progress: u8,
    /// Machine-readable phase name.
    pub tag: String,
    /// Human-readable phase description.
    pub summary: String,
    /// `"up"` or `"down"`, backing `GETINFO network-liveness`.
    pub liveness: &'static str,
}

/// A running Arti client, plus everything the control shim needs to describe it.
pub struct Client {
    /// The tokio runtime every Arti task runs on.
    runtime: tokio::runtime::Runtime,
    /// The Arti client itself.
    tor: Arc<TorClient<PreferredRuntime>>,
    /// Parsed configuration, retained for the SOCKS bind address.
    config: Config,
    /// Where the SOCKS listener ended up, once started.
    socks_addr: Mutex<Option<SocketAddr>>,
    /// Producer handle for asynchronous events.
    events: Sender,
    /// Consumer side, drained by `arti_next_event`.
    queue: Mutex<Queue>,
    /// Live onion services, keyed by service ID.
    services: Mutex<HashMap<String, Service>>,
    /// Whether the network is currently enabled.
    net_enabled: AtomicBool,
    /// Whether `start` has run.
    started: AtomicBool,
    /// Signalled by `shutdown`, awaited by `wait`.
    exit: (Mutex<bool>, Condvar),
}

impl Client {
    /// Build a client from the JSON configuration handed over by Go.
    ///
    /// This creates the Arti client but does not touch the network: bine
    /// starts Tor with `DisableNetwork 1` and enables it later over the
    /// control connection.
    pub fn new(config_json: &str) -> Result<Client, String> {
        install_crypto_provider();
        install_log_subscriber();

        let config = Config::from_json(config_json)?;
        let tor_config = config.to_tor_client_config()?;

        create_private_dir(&config.state_dir())
            .map_err(|e| format!("cannot create state directory: {e}"))?;
        purge_stale_onion_state(&config.state_dir());
        create_private_dir(&config.cache_dir())
            .map_err(|e| format!("cannot create cache directory: {e}"))?;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("cannot start async runtime: {e}"))?;

        let tor = runtime.block_on(async {
            let rt = PreferredRuntime::current()
                .map_err(|e| format!("cannot obtain async runtime: {e}"))?;
            TorClient::with_runtime(rt)
                .config(tor_config)
                .bootstrap_behavior(BootstrapBehavior::Manual)
                .create_unbootstrapped()
                .map_err(|e| format!("cannot create Tor client: {e}"))
        })?;

        let (events, queue) = events::channel();

        Ok(Client {
            runtime,
            tor,
            config,
            socks_addr: Mutex::new(None),
            events,
            queue: Mutex::new(queue),
            services: Mutex::new(HashMap::new()),
            net_enabled: AtomicBool::new(false),
            started: AtomicBool::new(false),
            exit: (Mutex::new(false), Condvar::new()),
        })
    }

    /// Start the SOCKS listener and the bootstrap-status pump.
    pub fn start(&self) -> Result<(), String> {
        if self.started.swap(true, Ordering::SeqCst) {
            return Err("already started".to_string());
        }

        if let Some(bind) = self.socks_bind_addr()? {
            let tor = Arc::clone(&self.tor);
            let (addr, _task) = self
                .runtime
                .block_on(async move { crate::socks::spawn(tor, bind).await })
                .map_err(|e| format!("cannot bind SOCKS listener: {e}"))?;
            *self.socks_addr.lock().expect("poisoned lock") = Some(addr);
        }

        self.spawn_bootstrap_watcher();

        if !self.config.disable_network {
            self.set_network_enabled(true)?;
        }
        Ok(())
    }

    /// Resolve the configured SOCKS bind address, if a listener is wanted.
    fn socks_bind_addr(&self) -> Result<Option<SocketAddr>, String> {
        let port = match self.config.socks_port {
            SocksPort::Disabled => return Ok(None),
            SocksPort::Auto => 0,
            SocksPort::Fixed(p) => p,
        };
        let host = self.config.socks_bind_address.trim();
        let addr = format!("{host}:{port}")
            .parse::<SocketAddr>()
            .map_err(|e| format!("invalid SOCKS bind address {host:?}: {e}"))?;
        Ok(Some(addr))
    }

    /// Forward Arti's bootstrap progress to the event queue as STATUS_CLIENT.
    fn spawn_bootstrap_watcher(&self) {
        let mut stream = self.tor.bootstrap_events();
        let events = self.events.clone();
        self.runtime.spawn(async move {
            let mut last = u8::MAX;
            while let Some(status) = stream.next().await {
                let snapshot = summarize(&status);
                if snapshot.progress != last {
                    last = snapshot.progress;
                    events.send(Event::StatusClient {
                        progress: snapshot.progress,
                        tag: snapshot.tag,
                        summary: snapshot.summary,
                    });
                }
            }
        });
    }

    /// The address the SOCKS listener is bound to, if any.
    pub fn socks_addr(&self) -> Option<SocketAddr> {
        *self.socks_addr.lock().expect("poisoned lock")
    }

    /// The current bootstrap phase.
    pub fn bootstrap_status(&self) -> BootstrapStatus {
        summarize(&self.tor.bootstrap_status())
    }

    /// Enable or disable use of the wider Tor network.
    ///
    /// This backs `SETCONF DisableNetwork`, which bine uses to defer bootstrap
    /// until the caller actually wants it.
    pub fn set_network_enabled(&self, enabled: bool) -> Result<(), String> {
        if self.net_enabled.swap(enabled, Ordering::SeqCst) == enabled {
            return Ok(());
        }
        if enabled {
            self.tor.set_dormant(DormantMode::Normal);
            let tor = Arc::clone(&self.tor);
            self.runtime.spawn(async move {
                // Errors surface through the bootstrap status; a failed attempt
                // must not take down the client.
                let _ = tor.bootstrap().await;
            });
        } else {
            self.tor.set_dormant(DormantMode::Soft);
        }
        Ok(())
    }

    /// Whether the network is currently enabled.
    pub fn network_enabled(&self) -> bool {
        self.net_enabled.load(Ordering::SeqCst)
    }

    /// Handle an ADD_ONION request.
    pub fn onion_add(&self, req: &AddRequest) -> Result<AddResponse, String> {
        // Onion services need a bootstrapped client, and C tor implicitly
        // bootstraps for ADD_ONION too.
        self.set_network_enabled(true)?;

        // Wait for it rather than racing the background bootstrap task.
        // `set_network_enabled` only spawns bootstrapping, and this client is
        // built with `BootstrapBehavior::Manual`, so Arti refuses to launch a
        // service on a client that has not finished — it does not wait on our
        // behalf. `bootstrap` is idempotent and returns immediately once the
        // client is ready, so this costs nothing on an already-running client.
        //
        // Note this must happen before entering the runtime below: calling
        // `block_on` from inside a runtime context panics.
        self.runtime
            .block_on(self.tor.bootstrap())
            .map_err(|e| format!("failed to bootstrap: {e}"))?;

        let _guard = self.runtime.enter();
        let (resp, service) = onion::launch(&self.tor, req, self.events.clone())?;
        self.services
            .lock()
            .expect("poisoned lock")
            .insert(resp.service_id.clone(), service);
        Ok(resp)
    }

    /// Handle a DEL_ONION request.
    pub fn onion_del(&self, service_id: &str) -> Result<(), String> {
        let service = self
            .services
            .lock()
            .expect("poisoned lock")
            .remove(service_id);
        match service {
            Some(svc) => {
                svc.shutdown();
                Ok(())
            }
            None => Err(format!("no such onion service: {service_id}")),
        }
    }

    /// Wait up to `timeout` for the next asynchronous event.
    pub fn next_event(&self, timeout: Duration) -> Option<Event> {
        let queue = self.queue.lock().expect("poisoned lock");
        queue.next(timeout)
    }

    /// Ask the client to stop; `wait` returns once this has been called.
    pub fn shutdown(&self) {
        let services: Vec<_> = self
            .services
            .lock()
            .expect("poisoned lock")
            .drain()
            .map(|(_, svc)| svc)
            .collect();
        for svc in services {
            svc.shutdown();
        }

        let (lock, cvar) = &self.exit;
        *lock.lock().expect("poisoned lock") = true;
        cvar.notify_all();
    }

    /// Block until `shutdown` is called.
    pub fn wait(&self) {
        let (lock, cvar) = &self.exit;
        let mut done = lock.lock().expect("poisoned lock");
        while !*done {
            done = cvar.wait(done).expect("poisoned lock");
        }
    }
}

/// Discard onion service state left by earlier runs.
///
/// Our keystore is ephemeral, so the introduction point keys backing any
/// persisted service state are gone the moment the process exits. Leaving that
/// state behind means the next launch either adopts it and finds the keys
/// missing, or simply accumulates a directory per run forever. Neither is
/// useful, so it goes.
///
/// Best-effort: a failure here costs disk space, not correctness, and Arti's
/// own liveness checks keep this from touching an instance another process is
/// using.
fn purge_stale_onion_state(state_dir: &std::path::Path) {
    use fs_mistrust::Mistrust;
    use tor_persist::slug::SlugRef;
    use tor_persist::state_dir::{
        InstancePurgeHandler, InstancePurgeInfo, InstanceStateHandle, Liveness, StateDirectory,
    };

    /// Disposes of every instance offered to it.
    struct PurgeAll;

    impl InstancePurgeHandler for PurgeAll {
        fn kind(&self) -> &'static str {
            // Matches the directory tor-hsservice stores its instances under.
            "hss"
        }
        fn name_filter(
            &mut self,
            _: &SlugRef,
        ) -> std::result::Result<Liveness, tor_persist::Error> {
            Ok(Liveness::PossiblyUnused)
        }
        fn age_filter(
            &mut self,
            _: &SlugRef,
            _: Duration,
        ) -> std::result::Result<Liveness, tor_persist::Error> {
            Ok(Liveness::PossiblyUnused)
        }
        fn dispose(
            &mut self,
            _info: &InstancePurgeInfo,
            handle: InstanceStateHandle,
        ) -> std::result::Result<(), tor_persist::Error> {
            handle.purge()
        }
    }

    // Match the permission policy used for the client itself: police what we
    // create, not the directories above it.
    let mut mistrust = Mistrust::builder();
    mistrust.ignore_prefix(state_dir.to_path_buf());
    let Ok(mistrust) = mistrust.build() else {
        return;
    };

    let Ok(dir) = StateDirectory::new(state_dir, &mistrust) else {
        return;
    };
    let _ = dir.purge_instances(std::time::SystemTime::now(), &mut PurgeAll);
}

/// Create a directory that only its owner can read.
///
/// These hold onion keys and directory state, and Arti refuses to use them if
/// they are group- or world-accessible, so the mode has to be set at creation
/// rather than left to the umask.
fn create_private_dir(path: &std::path::Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    match builder.create(path) {
        // recursive(true) already tolerates an existing directory, but a
        // pre-existing one keeps whatever mode it had; Arti will complain if
        // that is too permissive, which is the right outcome.
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

/// Install Arti's log subscriber from the `LIBTOR_LOG` environment variable.
///
/// Records are queued for the caller either way; `LIBTOR_LOG` additionally
/// mirrors them to stderr, which is the quickest way to see what Arti is doing
/// without wiring anything up. A library has no business installing a global
/// subscriber uninvited, so this does nothing unless the variable is set or
/// the caller asks via `arti_log_enable`.
fn install_log_subscriber() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let Ok(directives) = std::env::var("LIBTOR_LOG") else {
            return;
        };
        if directives.trim().is_empty() {
            return;
        }
        crate::logs::install(&directives, true);
    });
}

/// Select the rustls crypto provider for this process.
///
/// rustls 0.23 requires the application to choose, and Arti deliberately does
/// not choose on our behalf. Installing it is idempotent and racy-safe: a
/// second call returns an error, which is exactly the "someone already chose"
/// case and is fine to ignore.
fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Condense Arti's bootstrap status into the shape a control-port client wants.
///
/// Arti has no equivalent of C tor's bootstrap tags, so we synthesize a small
/// set that spans the same range. Only `done` is load-bearing: bine treats
/// progress 100 as "bootstrapped".
fn summarize(status: &arti_client::status::BootstrapStatus) -> BootstrapStatus {
    use arti_client::status::BlockageKind;

    // `ready_for_traffic` is the authority for everything here. Arti's
    // `as_frac` is an explicitly heuristic progress estimate that can reach 1.0
    // shortly before the client can actually act on a request, and a caller
    // that sees `TAG=done` will immediately try to use Tor — bine's
    // EnableNetwork returns on exactly that. Deriving completion and liveness
    // from the same signal keeps the two from disagreeing.
    let ready = status.ready_for_traffic();

    let mut progress = (status.as_frac() * 100.0).round().clamp(0.0, 100.0) as u8;
    if ready {
        progress = 100;
    } else {
        progress = progress.min(99);
    }

    let (tag, summary) = if ready {
        ("done", "Done".to_string())
    } else if let Some(blockage) = status.blocked() {
        // Being disabled is the normal state before the controller enables the
        // network, and briefly after, until the bootstrap task gets going. It
        // is not a fault, so it must not be reported as one.
        if matches!(blockage.kind(), BlockageKind::Disabled) {
            ("starting", "Waiting to bootstrap".to_string())
        } else {
            ("problem", blockage.to_string())
        }
    } else if progress > 0 {
        ("loading_status", status.to_string())
    } else {
        ("starting", "Starting".to_string())
    };

    BootstrapStatus {
        progress,
        tag: tag.to_string(),
        summary,
        // C tor reports whether it believes the network is reachable; the
        // closest thing Arti offers is whether it could act on a request right
        // now, which is what a caller polling this actually wants to know.
        liveness: if ready { "up" } else { "down" },
    }
}
