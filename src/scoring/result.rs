//! Score result types. Type-system enforces the LC-AV-18 + LC-AV-11
//! P0 invariants: insufficient sample → `Indeterminate`, never a
//! fabricated `Numeric`; SLO breach → `Unavailable`, never a
//! pass-through pretending to be a score.

use std::time::Duration;

/// Result of `LensCore::process(trace)`. Carries the score variant +
/// the cohort + the version + any detection events produced.
#[derive(Debug, Clone)]
pub struct Score {
    pub conformity: ManifoldConformity,
    pub cohort_id: String,
    pub lens_core_version: &'static str,
    /// Empty when no detector flagged. Detection events are signed
    /// + persisted internally; this field is for caller observability.
    pub detection_events: Vec<DetectionEvent>,
}

/// Manifold-conformity score variants. **Never collapse to f64.**
/// The enum IS the contract: `Indeterminate` and `Unavailable` are
/// not magic numeric values, they're typed signals to the caller
/// that scoring fell through to fail-secure mode.
#[derive(Debug, Clone)]
pub enum ManifoldConformity {
    /// Sufficient sample size; score in band; standard case.
    /// Cohort-relative; published-signal discretization happens at
    /// federation publication boundary, not here.
    Numeric(f64),

    /// LC-AV-18 fail-secure. Sample size below cohort gate, OR
    /// inferred cohort cannot be computed (insufficient features),
    /// OR cohort is in cold-start (centroid not yet calibrated).
    /// Federation acceptance falls through to M1+M2 fallback.
    Indeterminate { reason: IndeterminateReason },

    /// LC-AV-11 fail-secure. SLO budget exceeded OR persist read
    /// failure. **Operationally visible** — not a silent
    /// pass-through.
    Unavailable { reason: UnavailableReason },
}

#[derive(Debug, Clone)]
pub enum IndeterminateReason {
    /// Cohort centroid not yet calibrated (cold-start window per
    /// LC-AV-9). Federation tolerates the agent under M1+M2 only
    /// until enough corpus accumulates.
    CohortColdStart,
    /// Sample size below per-cohort minimum-sample-size gate
    /// (LC-AV-18). Calendar-time-windowed gate per LC-AV-17.
    SampleSizeBelowGate { current: u32, gate: u32 },
    /// Inferred-cohort classifier cannot disambiguate (LC-AV-2 edge case).
    InferredCohortAmbiguous,
}

#[derive(Debug, Clone)]
pub enum UnavailableReason {
    /// LC-AV-11 SLO breach. Bounded queue dropped this trace's score.
    SloBreach { budget: Duration, observed: Duration },
    /// Persist read failed; cohort centroid lookup unavailable.
    PersistReadFailure,
    /// Detector implementation panicked. Marked with
    /// lens_core_version per LC-AV-19.
    DetectorPanic { detector: &'static str },
    /// Steward-sign failure on the detection event side; the score
    /// itself was computed, but the signed-record path didn't land.
    /// Caller decides whether to surface or retry.
    StewardSignFailure,
}

/// A single detection event from one of the layered detectors
/// (cohort mismatch, manifold conformity, 5 ratchet detectors).
/// Signed via persist.steward_sign before this struct surfaces;
/// caller observes for alerting + audit.
#[derive(Debug, Clone)]
pub struct DetectionEvent {
    pub detector: &'static str,
    pub severity: Severity,
    /// Hex sha256 of the signed canonical bytes; join key to
    /// persist's detection-event row.
    pub event_hash: String,
}

#[derive(Debug, Clone, Copy)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}
