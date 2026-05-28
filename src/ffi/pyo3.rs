//! PyO3 surface — v0.1.0 drop-in module for the deployed CIRISLens product.
//!
//! # Swap contract
//!
//! Deployed Python lens swaps from `cirislens_core` to
//! `ciris_lens_core` with a one-line import alias:
//!
//! ```python
//! # before:
//! import cirislens_core
//! # after:
//! import ciris_lens_core as cirislens_core
//! ```
//!
//! # Functional disposition
//!
//! | v0.1.0 fn | Disposition |
//! |---|---|
//! | `process_trace_batch(engine, events, ...)` | **lens-core orchestrates the science layer; persist signs + persists.** Engine is the deployed lens's `ciris_persist.Engine` — lens-core calls `engine.local_sign` + `engine.local_pqc_sign` + `engine.put_detection_event` dynamically. Lens-core never holds keys. |
//! | `scrub_trace(trace_json, level)` | **delegates to `ciris_persist::pipeline::scrub::scrub_trace`** |
//! | `scrub_traces_batch(traces_json, level)` | **delegates to `ciris_persist::pipeline::scrub::scrub_traces_batch`** |
//! | `ner_is_configured()` | **delegates to `ciris_persist::pipeline::scrub::ner::is_configured`** |
//!
//! # Why Engine as first parameter
//!
//! Lens-core is a science layer, not a federation identity. The
//! signing identity belongs to the host (the deployed lens today;
//! the agent post-fold). The host constructs the persist Engine
//! with its own local keys; lens-core uses the Engine as a signing
//! oracle. This pattern survives the PoB §3.1 fold-into-agent —
//! agents pass their Engine the same way the deployed lens does
//! today.

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use ciris_persist::pipeline::extract::{extract_features, Features};
use ciris_persist::pipeline::scrub::{self as persist_scrub, ner, ScrubStats, ScrubbedTrace};
use ciris_persist::prelude::body_sha256;
use ciris_persist::schema::envelope::TraceLevel;
use serde_json::value::RawValue;
use serde_json::Value;
use uuid::Uuid;

use crate::cohort;
use crate::detector::{detect, DetectionResult};
use crate::pipeline::lifecycle::LENS_CORE_VERSION;
use crate::scoring::result::{ManifoldConformity, Severity};
use crate::scoring::{assemble, AssemblyInput};
use crate::signing::event::{assemble_event, prepare_detection, DetectionInputs};

/// Parse a wire-format trace-level string into the typed enum.
fn parse_level(level: &str) -> PyResult<TraceLevel> {
    match level {
        "generic" => Ok(TraceLevel::Generic),
        "detailed" => Ok(TraceLevel::Detailed),
        "full_traces" => Ok(TraceLevel::FullTraces),
        other => Err(PyValueError::new_err(format!(
            "invalid trace_level {other:?}; expected one of: generic, detailed, full_traces"
        ))),
    }
}

/// Convert persist's `ScrubStats` into a Python dict carrying the
/// per-trace telemetry the deployed lens aggregates. Mirrors
/// **legacy `cirislens-core` exactly** — 7 fields including
/// `ner_cache_misses` — so callers that read specific fields by
/// name don't break across the swap. Drift here was caught at
/// v0.1.0 review against `CIRISLens/api/scrubber_v2.py`.
fn stats_to_dict<'py>(py: Python<'py>, stats: &ScrubStats) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("entities_redacted", stats.entities_redacted)?;
    dict.set_item("regex_redactions", stats.regex_redactions)?;
    dict.set_item("fields_modified", stats.fields_modified)?;
    dict.set_item("walker_max_depth", stats.walker_max_depth)?;
    dict.set_item("ner_ran", stats.ner_ran)?;
    dict.set_item("ner_cache_hits", stats.ner_cache_hits)?;
    dict.set_item("ner_cache_misses", stats.ner_cache_misses)?;
    Ok(dict)
}

/// Convert one `ScrubbedTrace` into the legacy dict shape
/// `{"trace": "<json string>", "level": <str>, "stats": <dict>}`.
///
/// **`trace` is emitted as a JSON STRING**, not a pre-parsed
/// Python object. Matches legacy `cirislens-core::scrub_trace`
/// exactly — `CIRISLens/api/scrubber_v2.py:195` does
/// `json.loads(result["trace"])` and would error on a pre-parsed
/// dict. Drift here was caught at v0.1.0 review and is exactly
/// the kind of "matched legacy precisely" the swap requires.
fn scrubbed_to_dict<'py>(
    py: Python<'py>,
    scrubbed: ScrubbedTrace,
    level_str: &str,
) -> PyResult<Bound<'py, PyDict>> {
    let trace_json = serde_json::to_string(&scrubbed.value)
        .map_err(|e| PyRuntimeError::new_err(format!("serialize scrubbed trace: {e}")))?;
    let dict = PyDict::new(py);
    dict.set_item("trace", trace_json)?;
    dict.set_item("level", level_str)?;
    dict.set_item("stats", stats_to_dict(py, &scrubbed.stats)?)?;
    Ok(dict)
}

/// Map a [`ManifoldConformity`] to the detection-event severity bucket.
/// Mirrors `pipeline::lifecycle::severity_from` policy.
fn severity_from(c: &ManifoldConformity) -> Severity {
    match c {
        ManifoldConformity::Numeric(_) => Severity::Info,
        ManifoldConformity::Indeterminate { .. } => Severity::Info,
        ManifoldConformity::Unavailable { .. } => Severity::Warning,
    }
}

/// Severity → wire string (matches persist's `DetectionSeverity::as_db_str`).
fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Critical => "critical",
    }
}

// ─── Science layer (lens-core implements; persist signs + persists) ──

/// Process a batch of trace events. v0.1.0 orchestrates the science
/// layer (cohort + projection + no-op detector + scoring + signing
/// preparation) and routes signing + persistence through the
/// provided `engine`.
///
/// # Engine contract
///
/// `engine` is a `ciris_persist.Engine` instance constructed by the
/// deployed lens with its own local identity. Lens-core calls four
/// methods dynamically:
///
/// - `engine.local_key_id()` — string identifier stamped onto rows
/// - `engine.local_sign(canonical_bytes)` → 64-byte Ed25519 signature
/// - `engine.local_pqc_sign(bound_bytes)` → 3309-byte ML-DSA-65 signature
/// - `engine.put_detection_event(event_json)` — verify-then-insert; verifies the hybrid signature under `HybridPolicy::Strict` before storing
///
/// Lens-core never holds keys. Same Engine the deployed lens already
/// uses for trace ingest does the signing here.
///
/// # Return shape (locked v0.1.0)
///
/// ```python
/// {
///     "batch_id":         "<uuid>",
///     "traces_received":  100,
///     "traces_processed": 98,
///     "detections": [
///         {
///             "detection_id": "<uuid>",
///             "trace_id":     "<trace_id>",
///             "severity":     "info"
///         },
///         ...
///     ]
/// }
/// ```
///
/// # Phase 1 behavior
///
/// Detector is no-op (always `DetectionResult::None`) per LC-AV-9
/// cold-start window — RATCHET's calibration bundle (v1 shipped
/// 2026-05-13; centroid sample counts below the 500 gate) is the
/// architecturally-correct "score everything Indeterminate" state.
/// Every trace lands in `ManifoldConformity::Indeterminate { CohortColdStart }`
/// at severity `info`. Phase 2 replaces detector with real
/// implementations.
#[pyfunction]
#[pyo3(signature = (engine, events, batch_timestamp, consent_timestamp=None, trace_level="detailed".to_string(), correlation_metadata=None))]
fn process_trace_batch<'py>(
    py: Python<'py>,
    engine: &Bound<'py, PyAny>,
    events: Vec<String>,
    batch_timestamp: String,
    consent_timestamp: Option<String>,
    trace_level: String,
    correlation_metadata: Option<String>,
) -> PyResult<Bound<'py, PyDict>> {
    let _ = (
        batch_timestamp,
        consent_timestamp,
        trace_level,
        correlation_metadata,
    );

    let batch_id = Uuid::new_v4().to_string();
    let signing_key_id: String = engine
        .call_method0("local_key_id")
        .map_err(|e| PyRuntimeError::new_err(format!("engine.local_key_id(): {e}")))?
        .extract()?;

    let detections = PyList::empty(py);
    let mut traces_processed: usize = 0;

    for (idx, event_json) in events.iter().enumerate() {
        match process_one(py, engine, event_json, &signing_key_id) {
            Ok(summary) => {
                let entry = PyDict::new(py);
                entry.set_item("detection_id", summary.detection_id)?;
                entry.set_item("trace_id", summary.trace_id)?;
                entry.set_item("severity", summary.severity)?;
                detections.append(entry)?;
                traces_processed += 1;
            }
            Err(e) => {
                // Skip-and-continue: malformed input, signing failure,
                // or put rejection on one trace shouldn't drop the
                // whole batch. Surface to stderr; production
                // observability comes when Phase 2's tracing/
                // metrics land.
                eprintln!("ciris_lens_core.process_trace_batch: trace {idx} skipped: {e}");
            }
        }
    }

    let result = PyDict::new(py);
    result.set_item("batch_id", batch_id)?;
    result.set_item("traces_received", events.len())?;
    result.set_item("traces_processed", traces_processed)?;
    result.set_item("detections", detections)?;
    Ok(result)
}

/// Per-trace outcome record extracted for the batch's `detections`
/// list. Three fields — same shape as locked in
/// `process_trace_batch`'s docstring.
struct PerTraceSummary {
    detection_id: String,
    trace_id: String,
    severity: &'static str,
}

/// Process one trace through the v0.1.0 science layer + sign + put.
/// All persist primitives invoked via the `engine` argument; no key
/// material touches lens-core.
fn process_one<'py>(
    py: Python<'py>,
    engine: &Bound<'py, PyAny>,
    event_json: &str,
    signing_key_id: &str,
) -> PyResult<PerTraceSummary> {
    let trace: Value = serde_json::from_str(event_json)
        .map_err(|e| PyValueError::new_err(format!("invalid trace JSON: {e}")))?;
    let trace_id = trace
        .get("trace_id")
        .and_then(Value::as_str)
        .ok_or_else(|| PyValueError::new_err("missing trace_id"))?
        .to_string();

    // persist's body_sha256 takes &RawValue (not raw bytes) so the
    // hash matches the canonicalization persist applies on its own
    // ingest path — same value persist would store on the joined
    // trace_events row.
    let raw: Box<RawValue> = serde_json::from_str(event_json)
        .map_err(|e| PyValueError::new_err(format!("invalid trace RawValue: {e}")))?;
    let body_sha = body_sha256(&raw).to_vec();

    let declared = cohort::parse_from_envelope(&trace);
    let features: Features = extract_features(&trace, declared.clone());
    let cohort_cell = cohort::cohort_cell(&declared);

    // v0.1.0 detector: always None → CohortColdStart per LC-AV-9.
    let assembly_input = match detect(&features) {
        DetectionResult::None => AssemblyInput::CohortColdStart,
        DetectionResult::Manifold {
            mahalanobis,
            cohort_sample_count,
        } => AssemblyInput::Scored {
            mahalanobis,
            cohort_sample_count,
        },
        DetectionResult::DeclaredInferredMismatch { .. } => AssemblyInput::AmbiguousCohort,
    };
    let conformity = assemble(assembly_input, /* sample_size_gate */ 500);
    let severity = severity_from(&conformity);

    let inputs = DetectionInputs {
        trace_id: trace_id.clone(),
        body_sha256: body_sha,
        detector: "manifold_conformity",
        severity,
        cohort_cell,
        conformity: &conformity,
        lens_core_version: LENS_CORE_VERSION,
        // RATCHET v1 bundle landed 2026-05-13 (crc-v1, unsigned;
        // integration is Phase 2 work). Until the bundle is signed +
        // loaded into persist.calibration_bundles, lens-core stamps
        // a sentinel 0 — every Phase 1 detection event is anchored
        // to "no calibration applied" (matches the every-trace-
        // Indeterminate scoring behavior).
        ratchet_calibration_version: 0,
    };
    let prepared = prepare_detection(&inputs, signing_key_id)
        .map_err(|e| PyRuntimeError::new_err(format!("prepare: {e}")))?;

    // Sign via engine — lens-core never holds keys.
    let canonical_pybytes = PyBytes::new(py, &prepared.canonical_bytes);
    let ed25519_obj = engine
        .call_method1("local_sign", (canonical_pybytes,))
        .map_err(|e| PyRuntimeError::new_err(format!("engine.local_sign: {e}")))?;
    let ed25519_sig: Vec<u8> = ed25519_obj.cast::<PyBytes>()?.as_bytes().to_vec();

    // Hybrid binding: PQC signs (canonical_bytes ++ ed25519_sig).
    // Replicates LocalSigner::sign_hybrid's internal construction
    // so verify_hybrid_via_directory (invoked inside
    // engine.put_detection_event) recognizes it.
    let mut bound_msg = Vec::with_capacity(prepared.canonical_bytes.len() + 64);
    bound_msg.extend_from_slice(&prepared.canonical_bytes);
    bound_msg.extend_from_slice(&ed25519_sig);
    let bound_pybytes = PyBytes::new(py, &bound_msg);
    let pqc_obj = engine
        .call_method1("local_pqc_sign", (bound_pybytes,))
        .map_err(|e| PyRuntimeError::new_err(format!("engine.local_pqc_sign: {e}")))?;
    let ml_dsa_65_sig: Vec<u8> = pqc_obj.cast::<PyBytes>()?.as_bytes().to_vec();

    let (event, _summary) = assemble_event(
        &inputs,
        prepared,
        ed25519_sig,
        ml_dsa_65_sig,
        signing_key_id.to_string(),
    )
    .map_err(|e| PyRuntimeError::new_err(format!("assemble: {e}")))?;

    let event_json_str = serde_json::to_string(&event)
        .map_err(|e| PyRuntimeError::new_err(format!("serialize event: {e}")))?;
    engine
        .call_method1("put_detection_event", (event_json_str,))
        .map_err(|e| PyRuntimeError::new_err(format!("engine.put_detection_event: {e}")))?;

    Ok(PerTraceSummary {
        detection_id: event.detection_id.to_string(),
        trace_id,
        severity: severity_str(severity),
    })
}

// ─── Substrate-delegated (thin wrappers over ciris_persist) ───────

/// Scrub a single trace per the requested trace-level. Returns
/// `{"trace": "<json string>", "level": <level_str>, "stats": <stats_dict>}`.
#[pyfunction]
fn scrub_trace<'py>(
    py: Python<'py>,
    trace_json: &str,
    level: &str,
) -> PyResult<Bound<'py, PyDict>> {
    let value: serde_json::Value = serde_json::from_str(trace_json)
        .map_err(|e| PyValueError::new_err(format!("invalid trace JSON: {e}")))?;
    let parsed_level = parse_level(level)?;
    let scrubbed = persist_scrub::scrub_trace(value, parsed_level)
        .map_err(|e| PyRuntimeError::new_err(format!("scrub failed: {e}")))?;
    scrubbed_to_dict(py, scrubbed, level)
}

/// Scrub a batch of traces with one shared NER forward pass. Returns
/// a Python list of per-trace dicts matching `scrub_trace`'s shape.
#[pyfunction]
fn scrub_traces_batch<'py>(
    py: Python<'py>,
    traces_json: Vec<String>,
    level: &str,
) -> PyResult<Bound<'py, PyList>> {
    let mut values = Vec::with_capacity(traces_json.len());
    for (i, s) in traces_json.iter().enumerate() {
        let v: serde_json::Value = serde_json::from_str(s)
            .map_err(|e| PyValueError::new_err(format!("invalid trace JSON at index {i}: {e}")))?;
        values.push(v);
    }
    let parsed_level = parse_level(level)?;
    let scrubbed_batch = persist_scrub::scrub_traces_batch(values, parsed_level)
        .map_err(|e| PyRuntimeError::new_err(format!("batch scrub failed: {e}")))?;
    let out = PyList::empty(py);
    for scrubbed in scrubbed_batch {
        out.append(scrubbed_to_dict(py, scrubbed, level)?)?;
    }
    Ok(out)
}

/// Whether the persist scrubber has the NER backend configured
/// (XLM-R / DistilBERT via candle, or ORT INT8). Deployed lens
/// gates `full_traces` scrubbing on this.
#[pyfunction]
fn ner_is_configured() -> PyResult<bool> {
    Ok(ner::is_configured())
}

// ─── Cohabitation: relay-handler install (CIRIS 3.0) ──────────────

/// Register lens-core's relay handler on a shared `ciris_edge.Edge`
/// — the CIRIS 3.0 cohabitation bootstrap entry for the lens.
///
/// Mirrors `ciris_node_core.install_from_dispatch(...)`. The agent
/// (Python) has already constructed the shared persist `Engine` and
/// `Edge` (`ciris_edge.init_edge_runtime(...)`); this call hooks
/// lens-core's `Handler<AccordEventsBatch>` onto that shared Edge.
/// After this returns, the lens is a key-addressable Edge endpoint:
/// peers routing `AccordEventsBatch` to its `key_id` land here and
/// flow into `engine.receive_and_persist` (CIRISPersist#89) via
/// [`LensCoreHandler`](crate::role::LensCoreHandler).
///
/// # Cohabitation invariant
///
/// One `Edge` per process, owned by the agent, shared by sibling
/// consumers (lens, NodeCore). The `Arc<Engine>` is fetched from the
/// persist singleton (`current_rust_engine`) — same engine `PyEngine`
/// dispatches to; no second engine, runtime, or connection pool.
///
/// # Python signature
///
/// `ciris_lens_core.install_relay(edge)` — `edge` is the
/// `ciris_edge.Edge` instance returned by `ciris_edge.
/// init_edge_runtime(...)`. Engine is implicit (singleton).
///
/// # Errors
///
/// - `RuntimeError("persist Engine not initialized")` — host hasn't
///   constructed `ciris_persist.Engine` yet, or `close()` cleared it.
/// - `RuntimeError("persist runtime handle not available")` — same
///   condition; the singleton runtime is gone.
/// - `RuntimeError("attach lens-core relay handler: …")` — edge
///   refused the handler registration (typically already-registered
///   for `AccordEventsBatch`).
#[pyfunction]
fn install_relay(edge: PyRef<'_, ciris_edge::ffi::pyo3::PyEdge>) -> PyResult<()> {
    let engine = ciris_persist::ffi::pyo3::current_rust_engine().ok_or_else(|| {
        PyRuntimeError::new_err(
            "persist Engine not initialized — construct ciris_persist.Engine first",
        )
    })?;
    let handle = ciris_persist::ffi::pyo3::current_runtime_handle()
        .ok_or_else(|| PyRuntimeError::new_err("persist runtime handle not available"))?;
    let edge_arc = edge.edge_handle();
    handle
        .block_on(crate::LensCore::attach_handler(&edge_arc, engine))
        .map_err(|e| PyRuntimeError::new_err(format!("attach lens-core relay handler: {e}")))
}

// ─── Module entry ─────────────────────────────────────────────────

/// PyO3 cdylib entry. The original 4 deployed-lens drop-in functions
/// plus the v0.2 cohabitation bootstrap (`install_relay`).
#[pymodule]
fn ciris_lens_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(process_trace_batch, m)?)?;
    m.add_function(wrap_pyfunction!(scrub_trace, m)?)?;
    m.add_function(wrap_pyfunction!(scrub_traces_batch, m)?)?;
    m.add_function(wrap_pyfunction!(ner_is_configured, m)?)?;
    m.add_function(wrap_pyfunction!(install_relay, m)?)?;
    m.add(
        "PROJECTION_VERSION",
        crate::extract::projection::PROJECTION_VERSION,
    )?;
    Ok(())
}
