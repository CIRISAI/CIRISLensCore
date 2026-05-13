//! Per-trace lifecycle orchestration. The rlib-path entry point that
//! drives the eight-stage science-layer pipeline on a single
//! [`VerifiedTrace`]:
//!
//! ```text
//! VerifiedTrace ──► LensCore::process
//!                       ├── parse declared 6-tuple from envelope
//!                       ├── extract features (persist's free fn)
//!                       ├── build cohort_cell JSON
//!                       ├── detector (v0.1.0 no-op → cold start)
//!                       ├── scoring assembly (LC-AV-18 gate)
//!                       ├── sign detection event (hybrid)
//!                       └── return Outcome { score, event }
//! ```
//!
//! # Substrate inheritance
//!
//! `VerifiedTrace` arrives from edge with verify already complete —
//! lens-core never re-verifies (AV-9 structural attestation).
//! Detection events are signed via persist's `StewardSigner`; the
//! caller writes them to persist via `DerivedSchema::put_detection_event`
//! after [`process`] returns.
//!
//! The orchestrator does NOT call `Engine.put_detection_event` itself
//! — that's the caller's responsibility. Two reasons:
//! 1. Keeps `LensCore` free of `Arc<dyn DerivedSchema>` (smaller
//!    handle surface, easier to test).
//! 2. PyO3 path can route writes through the deployed lens's already-
//!    constructed `Engine` rather than constructing a second one
//!    inside lens-core.
//!
//! # Phase 1 status
//!
//! - Detector stage is no-op (returns
//!   [`DetectionResult::None`][crate::detector::DetectionResult::None])
//!   so every trace lands in
//!   [`AssemblyInput::CohortColdStart`][crate::scoring::AssemblyInput::CohortColdStart]
//!   → `Indeterminate { CohortColdStart }`. Architecturally correct
//!   during the LC-AV-9 cold-start window — RATCHET's calibration
//!   bundle (CIRISLensCore#3) lands the real centroids and Phase 2
//!   replaces detector with real implementations.
//! - SLO budget enforcement (LC-AV-11
//!   [`ManifoldConformity::Unavailable`]) is **not** wired in this
//!   commit; lifecycle is currently best-effort. Production
//!   deployments wrap [`process`] in a `tokio::time::timeout` until
//!   the orchestrator-level budget machinery lands.

use std::sync::Arc;

use ciris_edge::VerifiedTrace;
use ciris_persist::pipeline::extract::extract_features;
use ciris_persist::prelude::{DetectionEvent, StewardSigner};
use ciris_persist::Journal;
use serde_json::Value;

use crate::cohort;
use crate::detector::{detect, DetectionResult};
use crate::scoring::result::{IndeterminateReason, ManifoldConformity, Score, Severity};
use crate::scoring::{assemble, AssemblyInput};
use crate::signing::{sign_detection, DetectionInputs, SigningError};

/// Lens-core's `&'static str` version stamp for LC-AV-19
/// reproducibility — populated from `CARGO_PKG_VERSION` at compile
/// time.
pub const LENS_CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Hot-path handle. Holds substrate handles wired once at startup;
/// per trace, [`process`] walks the science-layer pipeline.
///
/// [`Journal`] is held but not yet consumed by lifecycle — reserved
/// for the SLO budget + observability spans landing in Phase 2.
pub struct LensCore {
    signer: Arc<StewardSigner>,
    #[allow(dead_code)]
    journal: Arc<Journal>,
}

impl LensCore {
    /// Construct a `LensCore` from substrate handles. Both must be
    /// shared (`Arc`) because the orchestrator may be invoked from
    /// multiple worker threads in the deployed lens.
    pub fn new(signer: Arc<StewardSigner>, journal: Arc<Journal>) -> Self {
        Self { signer, journal }
    }

    /// Process one [`VerifiedTrace`] through the science-layer
    /// pipeline. Returns the [`Outcome`] for the caller to act on
    /// (write event to persist via `DerivedSchema::put_detection_event`,
    /// surface score via API, etc.).
    ///
    /// `sample_size_gate` and `ratchet_calibration_version` come from
    /// the calibration bundle the caller loaded at startup. In v0.1.0
    /// (no calibration bundle yet) the detector returns `None` and
    /// the gate is unused — every trace produces Indeterminate.
    pub async fn process(
        &self,
        trace: VerifiedTrace,
        sample_size_gate: u32,
        ratchet_calibration_version: i32,
    ) -> Result<Outcome, ProcessError> {
        // 1. Parse the envelope body once.
        let body: Value = serde_json::from_str(trace.envelope.body.get())
            .map_err(|e| ProcessError::ParseBody(e.to_string()))?;

        let trace_id = body
            .get("trace_id")
            .and_then(Value::as_str)
            .ok_or(ProcessError::MissingTraceId)?
            .to_string();

        // 2. Pull declared 6-tuple from the deployment_profile block.
        let declared = cohort::parse_from_envelope(&body);

        // 3. Extract typed Features via persist's free function.
        let features = extract_features(&body, declared.clone());

        // 4. Build the cohort_cell JSON for the signed event.
        let cohort_cell = cohort::cohort_cell(&declared);

        // 5. Detector → DetectionResult. v0.1.0 no-op: None.
        let detection = detect(&features);

        // 6. Convert detection outcome to assembly input.
        let assembly_input = match detection {
            DetectionResult::None => AssemblyInput::CohortColdStart,
            DetectionResult::Manifold {
                mahalanobis,
                cohort_sample_count,
            } => AssemblyInput::Scored {
                mahalanobis,
                cohort_sample_count,
            },
            DetectionResult::DeclaredInferredMismatch { .. } => {
                AssemblyInput::AmbiguousCohort
            }
        };

        // 7. LC-AV-18 gate — produces ManifoldConformity.
        let conformity = assemble(assembly_input, sample_size_gate);

        // 8. Sign the detection event.
        let inputs = DetectionInputs {
            trace_id: trace_id.clone(),
            body_sha256: trace.body_sha256.to_vec(),
            detector: "manifold_conformity",
            severity: severity_from(&conformity),
            cohort_cell,
            conformity: &conformity,
            lens_core_version: LENS_CORE_VERSION,
            ratchet_calibration_version,
        };
        let (event, summary) = sign_detection(&self.signer, inputs).await?;

        let cohort_id = format_cohort_id(&features.declared);

        Ok(Outcome {
            score: Score {
                conformity,
                cohort_id,
                lens_core_version: LENS_CORE_VERSION,
                detection_events: vec![summary],
            },
            event,
        })
    }
}

/// Per-trace pipeline result. `score` is the lens-core observability
/// view; `event` is the signed, persist-ready row the caller writes
/// via `DerivedSchema::put_detection_event`.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub score: Score,
    pub event: DetectionEvent,
}

/// Errors from [`LensCore::process`].
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    /// Envelope body was not valid JSON.
    #[error("parse body: {0}")]
    ParseBody(String),
    /// Envelope body had no `trace_id` field — wire spec §3 requires
    /// it; pre-2.7.0 envelopes may omit. Treat as a malformed input.
    #[error("missing trace_id in envelope body")]
    MissingTraceId,
    /// Signing the detection event failed.
    #[error("sign: {0}")]
    Sign(#[from] SigningError),
}

/// Map a [`ManifoldConformity`] to the detection-event severity
/// bucket. v0.1.0 policy:
///
/// - Cold-start / sample-below-gate / ambiguous-cohort → `Info`
///   (telemetry; no operator action implied)
/// - Numeric in expected band → `Info`
/// - Unavailable (SLO breach, persist read failure) → `Warning`
///
/// Phase 2 elaborates: Numeric outliers > N σ → `Warning`/`Critical`
/// per RATCHET-calibrated thresholds.
fn severity_from(c: &ManifoldConformity) -> Severity {
    match c {
        ManifoldConformity::Numeric(_) => Severity::Info,
        ManifoldConformity::Indeterminate { .. } => Severity::Info,
        ManifoldConformity::Unavailable { .. } => Severity::Warning,
    }
}

/// Render a compact cohort identifier for the observability `Score`.
/// Format: `role/template/domain/type/region/trust_mode`, with `?`
/// for absent axes. Not federation-stable; for logs only.
fn format_cohort_id(
    declared: &ciris_persist::pipeline::extract::DeclaredCohortAxes,
) -> String {
    let q = |o: &Option<String>| o.as_deref().unwrap_or("?").to_string();
    format!(
        "{}/{}/{}/{}/{}/{}",
        q(&declared.agent_role),
        q(&declared.agent_template),
        q(&declared.deployment_domain),
        q(&declared.deployment_type),
        q(&declared.deployment_region),
        q(&declared.deployment_trust_mode),
    )
}

// Suppress unused warning when IndeterminateReason isn't matched —
// the type is part of the public scoring API surface and is consumed
// by signing/event.rs via the ManifoldConformity payload.
#[allow(dead_code)]
fn _silence_indeterminate_reason() -> Option<IndeterminateReason> {
    None
}
