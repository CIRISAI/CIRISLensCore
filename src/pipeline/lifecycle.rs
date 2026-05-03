//! Per-trace lifecycle orchestration. Bounded latency budget;
//! backpressure to upstream; never silent drop. See MISSION.md §2
//! pipeline/.

use crate::scoring::result::Score;

/// Builder + handle for the lens-core hot path.
///
/// Construction: `LensCore::builder().persist(engine).build()`.
/// Hot path: `core.process(verified_trace).await`.
#[derive(Debug)]
pub struct LensCore {
    // Implementation pending Phase 1.
    _placeholder: (),
}

/// Result of LensCore::process. Carries the score + signed-and-
/// persisted detection events.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub score: Score,
}
