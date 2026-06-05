//! CEG §5.5.5 — Distributive-access detector.
//!
//! Population-scale resource-concentration detector. Same F-3
//! machinery as [`crate::detector::correlated_action`]; different
//! trace source (resource events vs action events) and a **closed**
//! resource-type vocabulary.
//!
//! # Wire format
//!
//! `detection:distributive:access:{resource_type}`, where
//! `{resource_type}` is one of the five CEG §5.5.5 enumerated
//! resource types. Unlike F-3's open-vocab axis, distributive-access
//! is a closed enum because CEG §5.5.5 fully enumerates the
//! federation-relevant resource categories. Adding a sixth resource
//! type requires a CEG amendment AND a lens-core release.
//!
//! Per CIRISLensCore#24 (Magnifica Humanitas "Universal Destination
//! of Goods" mapping), the closed-enum lock is load-bearing —
//! distributive-access claims about an unspecified resource would
//! pull the verdict semantics out of the calibration package's
//! per-resource specification (Gini / HHI / floor / threshold).
//!
//! # v0.3 status — wire-format reserved only
//!
//! Same discipline as [`crate::detector::correlated_action`]: every
//! call to [`score`] returns
//! [`ManifoldConformity::Indeterminate { AxisAwaitingCalibration }`]
//! until the CIRISAI/RATCHET calibration package ships per-resource
//! operational definitions.
//! [#24](https://github.com/CIRISAI/CIRISLensCore/issues/24) +
//! [#26 umbrella](https://github.com/CIRISAI/CIRISLensCore/issues/26)
//! track the v0.5+ implementation.

use crate::scoring::result::{AxisFamily, IndeterminateReason, ManifoldConformity};

/// The resource type a `detection:distributive:access:{resource_type}`
/// envelope is reporting against. **Closed enumeration** per CEG
/// §5.5.5 — these are the five federation-relevant distributive
/// categories the calibration workshop has scoped.
///
/// Adding a variant requires:
/// 1. CEG §5.5.5 amendment (governance per §11.2).
/// 2. RATCHET calibration package update (per-resource operational
///    spec + statistical floor + threshold function).
/// 3. Lens-core release that lands the new variant + maps its
///    wire suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributiveAccessResource {
    /// `compute` — concentration of federation compute consumption.
    /// Calibration: HHI over per-participant compute, cohort floor
    /// per RATCHET spec.
    Compute,
    /// `models` — concentration of model-access licensing / hosting.
    Models,
    /// `training_data` — concentration of training-data access /
    /// holding rights.
    TrainingData,
    /// `agent_capabilities` — concentration of capability-token
    /// holding across federation actors.
    AgentCapabilities,
    /// `federation_membership` — concentration of membership /
    /// voting weight across the federation.
    FederationMembership,
}

impl DistributiveAccessResource {
    /// CEG wire-stable resource-type suffix.
    pub const fn wire_suffix(self) -> &'static str {
        match self {
            Self::Compute => "compute",
            Self::Models => "models",
            Self::TrainingData => "training_data",
            Self::AgentCapabilities => "agent_capabilities",
            Self::FederationMembership => "federation_membership",
        }
    }

    /// Full CEG `detection:distributive:access:{resource_type}` wire
    /// label.
    pub fn dimension_label(self) -> String {
        format!("detection:distributive:access:{}", self.wire_suffix())
    }

    /// Closed-enum membership lock. Adding a variant requires updating
    /// this constant + the [`wire_suffix`] match. Both are checked at
    /// compile-time by the exhaustiveness checker.
    ///
    /// [`wire_suffix`]: Self::wire_suffix
    pub const ALL: [DistributiveAccessResource; 5] = [
        Self::Compute,
        Self::Models,
        Self::TrainingData,
        Self::AgentCapabilities,
        Self::FederationMembership,
    ];
}

/// Population-level input to the distributive-access scorer. Opaque
/// in v0.3 (we never inspect the corpus — the scorer always returns
/// `AxisAwaitingCalibration`). Defined here so the wire-shape is
/// callable without a downstream rewrite when the scorer body lands.
#[derive(Debug, Clone)]
pub struct DistributiveAccessInput<'a> {
    /// Which resource type is being scored.
    pub resource: DistributiveAccessResource,
    /// Federation-emitted signed-trace corpus (resource events) that
    /// the v0.5+ detector will aggregate. v0.3 ignores this.
    pub corpus: &'a [serde_json::Value],
}

/// Distributive-access scorer. v0.3 always returns
/// `ManifoldConformity::Indeterminate { AxisAwaitingCalibration }`
/// regardless of input — same discipline as F-3 / `correlated_action`.
pub fn score(_input: &DistributiveAccessInput<'_>) -> ManifoldConformity {
    ManifoldConformity::Indeterminate {
        reason: IndeterminateReason::AxisAwaitingCalibration {
            family: AxisFamily::DistributiveAccess,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_label_locked_for_every_variant() {
        // CEG §5.5.5 names the five resource_type strings exactly.
        // If any string drifts, federation consumers can't recognize
        // the dimension.
        let expected = [
            (
                DistributiveAccessResource::Compute,
                "detection:distributive:access:compute",
            ),
            (
                DistributiveAccessResource::Models,
                "detection:distributive:access:models",
            ),
            (
                DistributiveAccessResource::TrainingData,
                "detection:distributive:access:training_data",
            ),
            (
                DistributiveAccessResource::AgentCapabilities,
                "detection:distributive:access:agent_capabilities",
            ),
            (
                DistributiveAccessResource::FederationMembership,
                "detection:distributive:access:federation_membership",
            ),
        ];
        for (resource, expected) in expected {
            assert_eq!(resource.dimension_label(), expected);
        }
    }

    #[test]
    fn all_constant_has_exactly_five_variants() {
        // CEG §5.5.5 lock: the closed enum is exactly five resources.
        // Adding a sixth requires CEG amendment + RATCHET update.
        // This test makes the addition deliberate at code-review time.
        assert_eq!(DistributiveAccessResource::ALL.len(), 5);
    }

    #[test]
    fn all_constant_contains_each_variant_exactly_once() {
        // Exhaustiveness + dedup check on the ALL constant.
        let mut sorted: Vec<_> = DistributiveAccessResource::ALL.iter().collect();
        sorted.sort_by_key(|r| r.wire_suffix());
        sorted.dedup();
        assert_eq!(sorted.len(), 5);
    }

    #[test]
    fn score_always_returns_axis_awaiting_calibration_for_every_resource() {
        // Run the v0.3 stub over every resource type — all must
        // return Indeterminate { AxisAwaitingCalibration { DistributiveAccess } }.
        for resource in DistributiveAccessResource::ALL {
            let input = DistributiveAccessInput {
                resource,
                corpus: &[],
            };
            match score(&input) {
                ManifoldConformity::Indeterminate {
                    reason:
                        IndeterminateReason::AxisAwaitingCalibration {
                            family: AxisFamily::DistributiveAccess,
                        },
                } => (),
                other => panic!(
                    "v0.3 distributive-access must return Indeterminate \
                     {{ AxisAwaitingCalibration {{ DistributiveAccess }} }} for {resource:?}; \
                     got {other:?}"
                ),
            }
        }
    }
}
