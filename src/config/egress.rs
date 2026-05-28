//! `EgressFilter` — per-upstream forwarding policy (FSD §3).
//!
//! The agent's lens-core captures FULL_TRACES locally **always**;
//! `trace_level` becomes a per-recipient egress decision, not a
//! per-emission capture decision (FSD §1, §2.2). One upstream lens
//! gets `Generic` (cohort + score only); a sovereign-mode peer in
//! the trust circle gets `FullTraces`; one capture, N forwarding
//! decisions.
//!
//! v0.3 ships **trace_level only** (per CIRISLensCore#11 acceptance:
//! "single-upstream filtering via trace_level only"). v0.4
//! (CIRISLensCore#14) extends with severity gating, detection-event
//! / score inclusion bits, and per-modality content redaction.
//! `#[non_exhaustive]` keeps that extension a minor-version
//! operation.

use serde::{Deserialize, Serialize};

use crate::wire::TraceLevel;

/// Per-upstream forwarding policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct EgressFilter {
    /// Maximum content level allowed out to this upstream. The
    /// originating client always captures `FullTraces` locally; this
    /// is the *ceiling* for what crosses the wire toward the named
    /// destination. See [`TraceLevel`] for the three levels'
    /// semantics.
    pub trace_level: TraceLevel,
}

impl EgressFilter {
    /// Construct an `EgressFilter` with only the v0.3 fields set.
    /// v0.4 additions default to permissive (forward unchanged).
    pub fn new(trace_level: TraceLevel) -> Self {
        Self { trace_level }
    }
}

impl Default for EgressFilter {
    /// `Generic` — the most-privacy-conservative posture. Forwards
    /// only the structural / numeric signal (cohort, scores), no
    /// content text.
    fn default() -> Self {
        Self::new(TraceLevel::Generic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_generic_most_conservative() {
        // Forwarding without explicit operator opt-in must never
        // leak content. `Generic` is the floor and the default.
        assert_eq!(EgressFilter::default().trace_level, TraceLevel::Generic);
    }

    #[test]
    fn new_sets_trace_level() {
        let f = EgressFilter::new(TraceLevel::FullTraces);
        assert_eq!(f.trace_level, TraceLevel::FullTraces);
    }

    #[test]
    fn serde_roundtrip_each_level() {
        for level in [
            TraceLevel::Generic,
            TraceLevel::Detailed,
            TraceLevel::FullTraces,
        ] {
            let f = EgressFilter::new(level);
            let json = serde_json::to_string(&f).unwrap();
            let back: EgressFilter = serde_json::from_str(&json).unwrap();
            assert_eq!(f, back);
        }
    }

    #[test]
    fn serde_uses_snake_case_trace_level() {
        // Wire-stable: federation peers parse the persist TraceLevel
        // representation. snake_case matches persist's schema.
        let f = EgressFilter::new(TraceLevel::FullTraces);
        let json = serde_json::to_value(&f).unwrap();
        assert_eq!(json["trace_level"], "full_traces");
    }
}
