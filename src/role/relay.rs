//! Relay mode — [`LensCore::relay`] + [`RelayHandle`].
//!
//! `LensCore::relay` builds an Edge runtime, registers the
//! [`LensCoreHandler`], spawns the listener, and hands back a
//! [`RelayHandle`] the caller drives shutdown through. After it
//! returns, lens-core is a key-addressable Edge endpoint: a peer
//! holding the relay's `key_id` can route `AccordEventsBatch`
//! traffic to it.
//!
//! `relay` is an associated function on [`LensCore`] (FSD §3's
//! `LensCore::client / relay / node` mode-entry surface) — it is a
//! namespaced constructor, not a method; it returns a
//! [`RelayHandle`], not a `LensCore`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ciris_edge::transport::http::{HttpTransport, HttpTransportConfig};
use ciris_edge::{AccordEventsBatch, Edge, EdgeError, LocalSigner, TransportError};
use ciris_persist::prelude::Engine;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::pipeline::lifecycle::LensCore;
use crate::role::handler::LensCoreHandler;

/// Default outbound-request timeout for the relay's HTTP transport.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

impl LensCore {
    /// Start lens-core in **relay mode** — a key-addressable
    /// store-and-forward Edge endpoint.
    ///
    /// Builds an Edge runtime over the host `Engine`'s shared
    /// `SqliteBackend` (directory + queue), a keyring-loaded
    /// transport-signing identity, and an HTTP transport bound to
    /// `listen_addr`; registers the [`LensCoreHandler`]; spawns the
    /// listener on the ambient tokio runtime; returns a
    /// [`RelayHandle`].
    ///
    /// # Arguments
    ///
    /// - `engine` — the host's persist `Engine` (CIRIS 3.0
    ///   process-singleton). Must be SQLite-backed; a Postgres-backed
    ///   Engine yields [`RelayError::NotSqliteBacked`].
    /// - `key_id` — the relay's `federation_keys.key_id`; the
    ///   identity peers address it by.
    /// - `seed_dir` — directory holding `ed25519.seed` and,
    ///   optionally, `ml_dsa_65.seed` for the transport-signing
    ///   identity.
    /// - `listen_addr` — socket the Edge HTTP listener binds.
    /// - `peer_urls` — `destination_key_id` → base-URL map for
    ///   outbound routing (forwarding upstream).
    ///
    /// # Runtime ownership
    ///
    /// The Edge listener is spawned with [`tokio::spawn`] onto the
    /// **caller's** runtime — the same runtime persist's singleton
    /// `Engine` was built on. Relay mode never constructs its own
    /// runtime; that is the dual-runtime deadlock persist v1.6.8
    /// closed.
    pub async fn relay(
        engine: Arc<Engine>,
        key_id: impl Into<String>,
        seed_dir: PathBuf,
        listen_addr: SocketAddr,
        peer_urls: HashMap<String, String>,
    ) -> Result<RelayHandle, RelayError> {
        let key_id = key_id.into();

        // Directory + queue: share the host Engine's existing
        // SqliteBackend. Cohabitation requires ONE connection pool —
        // not a second one opened from the same db_path. `Arc<Sqlite
        // Backend>` coerces to Edge's `Arc<dyn VerifyDirectory>` /
        // `Arc<dyn OutboundHandle>` via Edge's blanket impls over
        // persist's `FederationDirectory` / `OutboundQueue`.
        let backend = engine
            .sqlite_backend()
            .ok_or(RelayError::NotSqliteBacked)?
            .clone();

        // Transport-signing identity. Edge's `LocalSigner` is
        // keyring-trait-object based, distinct from persist's
        // raw-seed `LocalSigner`; the relay loads its own via
        // keyring. See `load_edge_signer`.
        let signer = Arc::new(load_edge_signer(&key_id, &seed_dir).await?);

        let transport = Arc::new(HttpTransport::new(HttpTransportConfig {
            listen_addr,
            peer_urls,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        })?);

        let edge = Edge::builder()
            .directory(backend.clone())
            .queue(backend)
            .signer(signer)
            .transport(transport)
            .build()?;

        edge.register_handler::<AccordEventsBatch, _>(LensCoreHandler::new(engine))
            .await?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let join = tokio::spawn(async move { edge.run(shutdown_rx).await });

        Ok(RelayHandle {
            shutdown_tx,
            join,
            listen_addr,
        })
    }

    /// Register lens-core's relay handler on a **pre-built shared
    /// Edge** — the CIRIS 3.0 cohabitation entry point.
    ///
    /// The host has already constructed the Edge (via the agent's
    /// `ciris_edge::ffi::pyo3::init_edge_runtime` in Python, or
    /// `EdgeBuilder` in pure Rust); lens-core attaches its
    /// `Handler<AccordEventsBatch>` to that shared `Edge` rather than
    /// building a second one. Cohabitation invariant: **one** Edge per
    /// process, owned by the host, shared by sibling consumers.
    ///
    /// Standalone-mode callers (no co-resident agent) use
    /// [`relay`](Self::relay) instead — it builds its own Edge and
    /// returns a [`RelayHandle`] for orderly shutdown.
    pub async fn attach_handler(edge: &Edge, engine: Arc<Engine>) -> Result<(), EdgeError> {
        edge.register_handler::<AccordEventsBatch, _>(LensCoreHandler::new(engine))
            .await
    }
}

/// Load an Edge [`LocalSigner`] from a seed directory via
/// `ciris_keyring::load_local_seed`.
///
/// This mirrors the seed-loading half of Edge's own
/// `EdgeBuilder::from_keyring_seed_dir` — lens-core can't call that
/// directly because it *also* opens a fresh `FederationDirectory` /
/// `OutboundQueue` from a `db_path`, whereas relay mode shares the
/// host Engine's backend instead (cohabitation).
///
/// FOLLOW-UP (CIRISEdge): if Edge extracts a standalone
/// `LocalSigner::from_keyring_seed_dir`, this helper collapses to one
/// call and the seed-layout convention stops being duplicated here.
/// Non-blocking cleanup.
async fn load_edge_signer(key_id: &str, seed_dir: &Path) -> Result<LocalSigner, RelayError> {
    let pqc_seed = seed_dir.join("ml_dsa_65.seed");
    let (pqc_key_id, pqc_key_path) = if pqc_seed.exists() {
        (Some(format!("{key_id}-pqc")), Some(pqc_seed))
    } else {
        (None, None)
    };

    let config = ciris_keyring::LocalSeedConfig {
        key_id: key_id.to_string(),
        key_path: seed_dir.join("ed25519.seed"),
        pqc_key_id,
        pqc_key_path,
    };

    let (classical, pqc) = ciris_keyring::load_local_seed(config)
        .await
        .map_err(|e| RelayError::Signer(e.to_string()))?;

    Ok(LocalSigner {
        key_id: key_id.to_string(),
        classical,
        pqc,
    })
}

/// Handle to a running relay-mode Edge runtime.
///
/// Dropping the handle does **not** stop the relay — the spawned
/// listener task keeps running. Call [`shutdown`](Self::shutdown) for
/// an orderly stop.
pub struct RelayHandle {
    shutdown_tx: watch::Sender<bool>,
    join: JoinHandle<Result<(), EdgeError>>,
    listen_addr: SocketAddr,
}

impl RelayHandle {
    /// The socket address the relay's Edge listener is bound to.
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Signal the Edge runtime to stop and await the listener task.
    ///
    /// Consumes the handle. Returns the Edge runtime's own exit
    /// result — `Ok(())` on a clean shutdown.
    pub async fn shutdown(self) -> Result<(), RelayError> {
        // `send` errors only if every receiver is already dropped —
        // i.e. the runtime task already ended. Either way we await
        // the join below, so the error is not actionable.
        let _ = self.shutdown_tx.send(true);
        match self.join.await {
            Ok(run_result) => run_result.map_err(RelayError::Edge),
            Err(join_err) => Err(RelayError::Join(join_err.to_string())),
        }
    }
}

/// Errors from [`LensCore::relay`] and [`RelayHandle::shutdown`].
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    /// The host `Engine` is Postgres-backed. Relay mode shares the
    /// Engine's `SqliteBackend` as the Edge directory + queue, so it
    /// requires a SQLite-backed Engine.
    #[error("relay mode requires a SQLite-backed Engine; this Engine is Postgres-backed")]
    NotSqliteBacked,
    /// Loading the relay's transport-signing identity from the seed
    /// directory failed — missing/unreadable seed, or a malformed
    /// keyring config.
    #[error("load relay signer: {0}")]
    Signer(String),
    /// Edge HTTP transport construction failed (e.g. the listen
    /// address could not be bound).
    #[error("edge transport: {0}")]
    Transport(#[from] TransportError),
    /// Edge builder, handler-registration, or runtime error.
    #[error("edge: {0}")]
    Edge(#[from] EdgeError),
    /// The spawned Edge listener task panicked or was cancelled.
    #[error("edge runtime task: {0}")]
    Join(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_error_messages_are_actionable() {
        assert!(RelayError::NotSqliteBacked
            .to_string()
            .contains("SQLite-backed Engine"));
        assert_eq!(
            RelayError::Signer("seed missing".into()).to_string(),
            "load relay signer: seed missing",
        );
        assert_eq!(
            RelayError::Join("panicked".into()).to_string(),
            "edge runtime task: panicked",
        );
    }

    // `ciris_edge::LocalSigner` holds `Arc<dyn HardwareSigner>` trait
    // objects and is not `Debug`, so the `Ok` arm can't go through
    // `expect_err`/`unwrap_err` — match the `Result` directly.

    #[tokio::test]
    async fn load_edge_signer_errors_on_missing_seed_dir() {
        // No ed25519.seed at this path — keyring's load fails and the
        // error surfaces as RelayError::Signer rather than panicking.
        let result = load_edge_signer("relay-test", Path::new("/nonexistent/ciris/seeds")).await;
        assert!(
            matches!(result, Err(RelayError::Signer(_))),
            "missing seed dir must surface RelayError::Signer",
        );
    }

    #[tokio::test]
    async fn load_edge_signer_skips_pqc_when_seed_absent() {
        // A seed dir with no ml_dsa_65.seed must not fault on PQC —
        // it degrades to classical-only (pqc_key_path = None). The
        // classical seed is still absent here, so the call errors at
        // the ed25519 load; the point is it reaches that far without
        // a PQC-related panic.
        let result = load_edge_signer("relay-test", Path::new("/nonexistent")).await;
        assert!(matches!(result, Err(RelayError::Signer(_))));
    }
}
