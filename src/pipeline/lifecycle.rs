//! Per-trace lifecycle orchestration. Bounded latency budget;
//! backpressure to upstream; never silent drop. See MISSION.md §2
//! pipeline/.
//!
//! # Substrate inheritance
//!
//! `VerifiedTrace` arrives from edge — its existence is the AV-9
//! structural attestation that verify already ran (lens-core never
//! re-verifies). Detection events leave via persist's
//! `StewardSigner` + `Journal`, both held as `Arc` handles
//! constructed once at startup.
//!
//! ```text
//! ciris_edge::VerifiedTrace ──► LensCore::process
//!                                    ├── scrub / extract / cohort / detector / scoring
//!                                    ├── persist::prelude::canonicalize_envelope_for_signing
//!                                    ├── persist::prelude::StewardSigner::sign_hybrid
//!                                    └── persist::Journal::append
//! ```

use std::sync::Arc;

use ciris_edge::VerifiedTrace;
use ciris_persist::{prelude::StewardSigner, Journal};

use crate::scoring::result::Score;

/// Lens-core hot-path handle. Holds substrate handles wired once at
/// startup; per trace, `process` walks the eight-stage pipeline under
/// one shared SLO budget (LC-AV-11).
pub struct LensCore {
    #[allow(dead_code)] // wired in subsequent commits as stages land
    signer: Arc<StewardSigner>,
    #[allow(dead_code)]
    journal: Arc<Journal>,
}

impl LensCore {
    pub fn new(signer: Arc<StewardSigner>, journal: Arc<Journal>) -> Self {
        Self { signer, journal }
    }

    /// Hot path: scrub → extract → cohort → detector → scoring →
    /// canonicalize → steward_sign → journal append. Phase 1 stages
    /// land per-commit.
    pub async fn process(&self, _trace: VerifiedTrace) -> Outcome {
        todo!("phase 1 implementation lands per stage")
    }
}

/// Result of [`LensCore::process`]. Carries the score; signed
/// detection events themselves are persisted internally by `process`.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub score: Score,
}
