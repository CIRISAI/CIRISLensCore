//! Detector module — manifold-conformity + 5 ratchet detectors.
//!
//! # v0.1.0 status
//!
//! Ships a **no-op detector** that returns [`DetectionResult::None`]
//! for every trace. Combined with [`crate::scoring::assemble`] this
//! routes every v0.1.0 trace through
//! [`crate::scoring::AssemblyInput::CohortColdStart`] →
//! [`ManifoldConformity::Indeterminate { CohortColdStart }`][ind].
//!
//! That's the architecturally-correct fail-secure behavior per
//! LC-AV-9 (cold-start window): until RATCHET delivers the
//! calibration bundle (CIRISLensCore#3) with per-cohort centroids,
//! no trace can be scored against the manifold, so every trace
//! reports Indeterminate. Federation acceptance routes through
//! M1+M2 fallback during this window.
//!
//! # Real detectors (Phase 2)
//!
//! Phase 2 ports the four §F detectors from
//! `CIRISLens/api/analysis/coherence_ratchet.py`
//! (`_detect_cross_agent_divergence_via_persist` + 3 siblings) plus
//! the manifold-conformity scorer that consumes
//! [`crate::extract::project`]'s 16-feature output against
//! RATCHET-shipped centroids. All four detectors compose against
//! persist v0.7.x §F primitives directly via the rlib path; no
//! PyO3 hop.
//!
//! [ind]: crate::scoring::ManifoldConformity::Indeterminate

use ciris_persist::pipeline::extract::Features;

pub mod coherence_ratchet;
pub mod correlated_action;
pub mod distributive_access;

pub use coherence_ratchet::CoherenceRatchetDetector;
pub use correlated_action::{CorrelatedActionAxis, CorrelatedActionInput};
pub use distributive_access::{DistributiveAccessInput, DistributiveAccessResource};

/// Per-trace detection outcome from the detector stage. Maps to an
/// [`AssemblyInput`][ai] variant in the orchestrator.
///
/// [ai]: crate::scoring::AssemblyInput
#[derive(Debug, Clone)]
pub enum DetectionResult {
    /// No detector flagged — the v0.1.0 default. Orchestrator routes
    /// to [`AssemblyInput::CohortColdStart`][ccs] (LC-AV-9 cold-start
    /// window until RATCHET centroids ship via CIRISLensCore#3).
    ///
    /// [ccs]: crate::scoring::AssemblyInput::CohortColdStart
    None,

    /// Manifold-conformity scorer produced a Mahalanobis-σ distance
    /// against the inferred cohort's centroid. Carried with the
    /// cohort's `sample_count` so [`crate::scoring::assemble`] can
    /// apply the LC-AV-18 sample-size gate.
    Manifold {
        /// Mahalanobis distance in σ-units.
        mahalanobis: f64,
        /// Sample count for the inferred cohort (from the calibration
        /// bundle's `CohortCentroid.sample_count`).
        cohort_sample_count: u32,
    },

    /// LC-AV-2 declared-vs-inferred cohort disagreement. The agent
    /// declared one cohort identity; the inferred classifier landed
    /// the trace in a different cohort. Federation evidence; signed
    /// with severity `warning` by the orchestrator.
    DeclaredInferredMismatch {
        /// Agent-declared 6-tuple (from `Features.declared`).
        declared: serde_json::Value,
        /// Inferred 6-tuple (from cohort classifier).
        inferred: serde_json::Value,
    },
}

/// v0.1.0 no-op detector. Returns [`DetectionResult::None`] for every
/// trace until RATCHET delivers calibration centroids and Phase 2
/// lands the real detector implementations.
///
/// This is not laziness — it's the architecturally correct
/// fail-secure behavior during the LC-AV-9 cold-start window. A
/// detector that fired without calibrated centroids would emit
/// fabricated scores; we explicitly refuse and route every trace to
/// [`crate::scoring::ManifoldConformity::Indeterminate`] instead.
pub fn detect(_features: &Features) -> DetectionResult {
    DetectionResult::None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_persist::pipeline::extract::Features;
    use std::collections::HashMap;

    fn empty_features() -> Features {
        Features {
            declared: Default::default(),
            step_timestamps: Default::default(),
            observation_weights: Default::default(),
            models_used: vec![],
            component_blobs: HashMap::new(),
            cost_estimate: 0.0,
            total_tokens: 0,
            model_class: Default::default(),
        }
    }

    #[test]
    fn v010_detector_always_returns_none() {
        // LC-AV-9 cold-start: every trace returns None until
        // RATCHET delivers centroids. Phase 2 replaces this body
        // with the real implementations.
        match detect(&empty_features()) {
            DetectionResult::None => (),
            other => panic!("v0.1.0 must return None, got {other:?}"),
        }
    }
}
