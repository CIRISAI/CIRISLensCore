//! CEG §5.5.3 — F-3 correlated-action / structural-injustice detector.
//!
//! Population-scale detector that reads federation-emitted signed
//! traces and reports correlation structure (`ρ`, `k_eff`) over goal-
//! aligned individually-compliant pursuit by groups whose aggregate
//! trajectory affects individuals or groups outside the pursuit.
//!
//! # Wire format
//!
//! The emitted prefix is `detection:correlated_action:{axis}`, where
//! `{axis}` is **open vocabulary** per CEG §5.5.3 (new axes admitted
//! via the §11.2 amendment process). CEG names a canonical seed
//! taxonomy of eight axes; lens-core ships these as known variants
//! and accepts unknown axes as `Custom(String)` so calibration-package
//! amendments don't require a lens-core release.
//!
//! # Historical name — `detection:emergent_deception:{axis}`
//!
//! FSD-002 v1.1 originally named this prefix `emergent_deception`
//! (the Magnifica-Humanitas-encyclical-derived name); CEG §5.5.3
//! adopted `correlated_action` as the framework-native operational
//! name. The two name the SAME detector. A CEG §6 `delegates_to`
//! rename-chain (`correlated_action_v{N+1}:from:emergent_deception_v
//! {N}`) will land at the same release that ships the first
//! calibrated operating point; until then, lens-core emits the
//! CEG-canonical name only.
//!
//! # v0.3 status — wire-format reserved only
//!
//! No detector logic. Every call to [`score`] returns
//! [`ManifoldConformity::Indeterminate { AxisAwaitingCalibration }`].
//! This is the MISSION.md §3 anti-pattern #9 discipline: shipping a
//! numeric verdict before the CIRISAI/RATCHET calibration package
//! defines the per-axis operational semantics + statistical floor +
//! threshold function would be a CEG §11.2 governance bypass.
//! [#26 umbrella](https://github.com/CIRISAI/CIRISLensCore/issues/26)
//! tracks the v0.5+ implementation per FSD-002 §3.5.3 + LENS_CORE_V0_5
//! §4.7 phasing.
//!
//! See [MISSION.md §2 `detector/`](../../../MISSION.md) for the
//! categorical-not-redundant layering argument (§5.5.1 catches
//! individual deviation, §5.5.3 catches coordinated compliance,
//! §5.5.5 catches the concentration substrate).

use crate::scoring::result::{AxisFamily, IndeterminateReason, ManifoldConformity};

/// The axis a `detection:correlated_action:{axis}` envelope is
/// reporting against. **Open vocabulary** per CEG §5.5.3 — the
/// canonical-name variants are the seed taxonomy; `Custom` admits
/// calibration-package-amendment axes without a lens-core release.
///
/// # Canonical axes (CEG §5.5.3)
///
/// - `rights_asymmetry:{population}` — rights distribution asymmetry
///   across a named population.
/// - `participation_exclusion:{cohort}` /
///   `participation_inclusion:{cohort}` — who has / lacks a seat at
///   the goal-articulation table.
/// - `informational_asymmetry:{scope}` /
///   `informational_symmetry:{scope}` — who knows / doesn't know
///   what the goal-pursuit's aggregate trajectory entails.
/// - `aggregate_footprint:{harm_class}` /
///   `aggregate_benefit:{class}` — aggregate-impact distribution.
/// - `ecology_of_communication:{aspect}` — echo-chamber / coordinated-
///   messaging / cross-cohort information-flow patterns (CIRISLensCore
///   #24's Magnifica Humanitas T-3 candidate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorrelatedActionAxis {
    /// `rights_asymmetry:{population}`
    RightsAsymmetry {
        /// Population name; opaque to lens-core, defined by the
        /// calibration package.
        population: String,
    },
    /// `participation_exclusion:{cohort}`
    ParticipationExclusion { cohort: String },
    /// `participation_inclusion:{cohort}`
    ParticipationInclusion { cohort: String },
    /// `informational_asymmetry:{scope}`
    InformationalAsymmetry { scope: String },
    /// `informational_symmetry:{scope}`
    InformationalSymmetry { scope: String },
    /// `aggregate_footprint:{harm_class}`
    AggregateFootprint { harm_class: String },
    /// `aggregate_benefit:{class}`
    AggregateBenefit { class: String },
    /// `ecology_of_communication:{aspect}` — known aspects per
    /// CIRISLensCore#24: `echo_chamber_density`,
    /// `information_silo_correlation`, `coordinated_messaging_pattern`,
    /// `cross_cohort_information_flow`. Aspect membership is
    /// calibration-package-owned; lens-core treats `{aspect}` as
    /// opaque string.
    EcologyOfCommunication { aspect: String },
    /// Axis introduced by a CEG §11.2 amendment after this lens-core
    /// release; the raw `{axis}` substring is preserved verbatim for
    /// forward-compatibility. Calibration package owns the operational
    /// definition.
    Custom { axis: String },
}

impl CorrelatedActionAxis {
    /// CEG wire-stable suffix — the `{axis}` portion of
    /// `detection:correlated_action:{axis}`. Joined with the prefix
    /// at envelope-construction time.
    pub fn wire_suffix(&self) -> String {
        match self {
            Self::RightsAsymmetry { population } => format!("rights_asymmetry:{population}"),
            Self::ParticipationExclusion { cohort } => {
                format!("participation_exclusion:{cohort}")
            }
            Self::ParticipationInclusion { cohort } => {
                format!("participation_inclusion:{cohort}")
            }
            Self::InformationalAsymmetry { scope } => format!("informational_asymmetry:{scope}"),
            Self::InformationalSymmetry { scope } => format!("informational_symmetry:{scope}"),
            Self::AggregateFootprint { harm_class } => format!("aggregate_footprint:{harm_class}"),
            Self::AggregateBenefit { class } => format!("aggregate_benefit:{class}"),
            Self::EcologyOfCommunication { aspect } => {
                format!("ecology_of_communication:{aspect}")
            }
            Self::Custom { axis } => axis.clone(),
        }
    }

    /// Full CEG `detection:correlated_action:{axis}` wire label.
    pub fn dimension_label(&self) -> String {
        format!("detection:correlated_action:{}", self.wire_suffix())
    }
}

/// Population-level input to the F-3 scorer. Opaque in v0.3 (we
/// never inspect the corpus — the scorer always returns
/// `AxisAwaitingCalibration` regardless of input). Defined here so
/// the wire-shape is callable without a downstream rewrite when
/// the scorer body lands in v0.5+ per #26.
#[derive(Debug, Clone)]
pub struct CorrelatedActionInput<'a> {
    /// The axis being scored. Carries through to the emitted envelope.
    pub axis: CorrelatedActionAxis,
    /// Federation-emitted signed-trace corpus that the v0.5+ detector
    /// will aggregate. v0.3 ignores this.
    pub corpus: &'a [serde_json::Value],
}

/// F-3 scorer. v0.3 always returns
/// `ManifoldConformity::Indeterminate { AxisAwaitingCalibration }`
/// regardless of input — the CEG slot is reserved; the detector
/// body lands at v0.5+ per #26 + RATCHET calibration package.
///
/// **Why `Indeterminate` not `Unavailable`:** the substrate is healthy
/// and the corpus is present. What's missing is the calibration-package
/// operational definition for `axis`. That's exactly LC-AV-18 /
/// anti-pattern #2 shape, not LC-AV-11 substrate failure.
pub fn score(_input: &CorrelatedActionInput<'_>) -> ManifoldConformity {
    ManifoldConformity::Indeterminate {
        reason: IndeterminateReason::AxisAwaitingCalibration {
            family: AxisFamily::F3CorrelatedAction,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_label_for_canonical_axes() {
        // CEG §5.5.3 canonical axes round-trip through the wire-label
        // function. If any of these strings drift, the federation
        // can't recognize the dimension.
        let cases = [
            (
                CorrelatedActionAxis::RightsAsymmetry {
                    population: "indigenous_nations".into(),
                },
                "detection:correlated_action:rights_asymmetry:indigenous_nations",
            ),
            (
                CorrelatedActionAxis::ParticipationExclusion {
                    cohort: "cohort_42".into(),
                },
                "detection:correlated_action:participation_exclusion:cohort_42",
            ),
            (
                CorrelatedActionAxis::EcologyOfCommunication {
                    aspect: "echo_chamber_density".into(),
                },
                "detection:correlated_action:ecology_of_communication:echo_chamber_density",
            ),
        ];
        for (axis, expected) in cases {
            assert_eq!(axis.dimension_label(), expected);
        }
    }

    #[test]
    fn wire_label_custom_axis_passes_through_verbatim() {
        // Open-vocab discipline: an axis introduced by post-release
        // CEG amendment is preserved without modification. The
        // amendment process owns the operational definition; lens-
        // core just transports the string.
        let axis = CorrelatedActionAxis::Custom {
            axis: "future_amendment_axis:some_facet".into(),
        };
        assert_eq!(
            axis.dimension_label(),
            "detection:correlated_action:future_amendment_axis:some_facet"
        );
    }

    #[test]
    fn score_always_returns_axis_awaiting_calibration() {
        // MISSION.md §3 anti-pattern #9: never ship a numeric verdict
        // before RATCHET calibrates. This test locks the discipline.
        let input = CorrelatedActionInput {
            axis: CorrelatedActionAxis::RightsAsymmetry {
                population: "p".into(),
            },
            corpus: &[],
        };
        match score(&input) {
            ManifoldConformity::Indeterminate {
                reason:
                    IndeterminateReason::AxisAwaitingCalibration {
                        family: AxisFamily::F3CorrelatedAction,
                    },
            } => (),
            other => panic!(
                "v0.3 F-3 must return Indeterminate {{ AxisAwaitingCalibration {{ F3CorrelatedAction }} }}; \
                 got {other:?}"
            ),
        }
    }

    #[test]
    fn score_indeterminate_regardless_of_corpus_size() {
        // Sweep corpus size from empty through "definitely enough
        // signal" — the result MUST NOT change. The substrate not
        // being calibrated is independent of how much data we have.
        for size in [0usize, 1, 100, 10_000] {
            let corpus: Vec<serde_json::Value> =
                (0..size).map(|i| serde_json::json!({ "i": i })).collect();
            let input = CorrelatedActionInput {
                axis: CorrelatedActionAxis::AggregateFootprint {
                    harm_class: "h".into(),
                },
                corpus: &corpus,
            };
            assert!(matches!(
                score(&input),
                ManifoldConformity::Indeterminate {
                    reason: IndeterminateReason::AxisAwaitingCalibration {
                        family: AxisFamily::F3CorrelatedAction
                    }
                }
            ));
        }
    }
}
