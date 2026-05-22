//! `role/` — lens-core's deployment-mode runtimes (FSD §3).
//!
//! Lens-core runs in one of three modes. v0.2 ships **relay**:
//!
//! - **client** (v0.3) — co-located with a CIRISAgent; captures the
//!   agent's own traces locally and filters on egress.
//! - **relay** (v0.2, this module) — store-and-forward federation
//!   transit. Accepts verified [`AccordEventsBatch`] traffic from
//!   peers over Edge, persists it to the host's shared persist
//!   `Engine`, and is itself a key-addressable Edge endpoint.
//! - **node** (v0.4) — adds the scoring oracle + egress filter on
//!   top of relay.
//!
//! [`AccordEventsBatch`]: ciris_edge::AccordEventsBatch
//!
//! # What relay mode delivers
//!
//! Before this module, lens-core could *sign as* a key (its signed
//! detection events carry `signing_key_id`, verifiable via
//! `verify_hybrid_via_directory`) but could not *receive at* one —
//! it had no Edge listener. [`LensCore::relay`] opens that listener:
//! a peer that puts the relay's `key_id` in its `peer_urls` map can
//! route an `AccordEventsBatch` to it and have it persisted.
//!
//! [`LensCore::relay`]: crate::LensCore::relay
//!
//! # Substrate boundaries
//!
//! Relay mode composes — it writes ~zero substrate code:
//!
//! - **Directory + queue** — the host `Engine`'s existing
//!   `SqliteBackend`, shared (cohabitation: one connection pool, not
//!   a second opened from the same db_path). `SqliteBackend`
//!   satisfies Edge's `VerifyDirectory` + `OutboundHandle` via Edge's
//!   blanket impls over persist's `FederationDirectory` /
//!   `OutboundQueue`.
//! - **Ingest** — persist's `Engine::receive_and_persist`
//!   (CIRISPersist#89), called with `&NullScrubber` (see
//!   [`handler`]).
//! - **Transport-signing identity** — loaded via
//!   `ciris_keyring::load_local_seed`.

pub mod handler;
pub mod relay;

pub use handler::LensCoreHandler;
pub use relay::{RelayError, RelayHandle};
