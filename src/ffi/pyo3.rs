//! PyO3 surface — v0.1.0 drop-in module for the deployed CIRISLens product.
//!
//! # Swap contract
//!
//! The deployed Python lens swaps from `cirislens_core` to
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
//! Legacy `cirislens-core` exposed 11 functions. v0.1.0 lens-core
//! exposes the **4 that remain meaningful** after the architecture
//! shift (CIRISPersist#19 absorbed scrub + classify + extract;
//! CIRISEdge owns verify; legacy schema + public-key caches retire
//! with the Grafana paths that consumed them):
//!
//! | v0.1.0 fn | Disposition |
//! |---|---|
//! | `process_trace_batch` | **lens-core implements** — orchestrates persist's pipeline + cohort + detector + scoring + signing. Current body returns `NotImplementedError` until Phase 1 stages land; signature is locked. |
//! | `scrub_trace` | **delegates to `ciris_persist::pipeline::scrub::scrub_trace`** — JSON-string-in / dict-out, matching legacy shape |
//! | `scrub_traces_batch` | **delegates to `ciris_persist::pipeline::scrub::scrub_traces_batch`** — one batched NER pass per call |
//! | `ner_is_configured` | **delegates to `ciris_persist::pipeline::scrub::ner::is_configured`** |
//!
//! Legacy `load_schemas_from_db` / `refresh_schema_cache` /
//! `get_loaded_schemas` / `load_public_keys_from_db` /
//! `refresh_public_key_cache` / `get_public_key_count` /
//! `check_cache_status` are **NOT exposed** in v0.1.0. The deployed
//! lens must drop those calls; the schema-cache + public-key-cache
//! responsibilities they served migrated to persist's
//! `Engine.lookup_public_key` + the federation_keys table, and the
//! Grafana paths they fed are out of scope for v0.1.0.

use pyo3::exceptions::{PyNotImplementedError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use ciris_persist::pipeline::scrub::{self as persist_scrub, ner, ScrubStats, ScrubbedTrace};
use ciris_persist::schema::envelope::TraceLevel;

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

/// Serialize a `serde_json::Value` to a Python object via `json.loads`.
fn pythonize(py: Python<'_>, value: &serde_json::Value) -> PyResult<PyObject> {
    let s = serde_json::to_string(value)
        .map_err(|e| PyRuntimeError::new_err(format!("serialize trace: {e}")))?;
    let json_mod = py.import("json")?;
    json_mod.call_method1("loads", (s,)).map(Into::into)
}

/// Convert persist's `ScrubStats` into a Python dict carrying the
/// per-trace telemetry the deployed lens aggregates.
fn stats_to_dict<'py>(py: Python<'py>, stats: &ScrubStats) -> PyResult<&'py PyDict> {
    let dict = PyDict::new(py);
    dict.set_item("entities_redacted", stats.entities_redacted)?;
    dict.set_item("regex_redactions", stats.regex_redactions)?;
    dict.set_item("fields_modified", stats.fields_modified)?;
    dict.set_item("walker_max_depth", stats.walker_max_depth)?;
    dict.set_item("ner_ran", stats.ner_ran)?;
    dict.set_item("ner_cache_hits", stats.ner_cache_hits)?;
    Ok(dict)
}

/// Convert one `ScrubbedTrace` into the
/// `{"trace": <object>, "level": <str>, "stats": <dict>}` shape.
fn scrubbed_to_dict<'py>(
    py: Python<'py>,
    scrubbed: ScrubbedTrace,
    level_str: &str,
) -> PyResult<&'py PyDict> {
    let dict = PyDict::new(py);
    dict.set_item("trace", pythonize(py, &scrubbed.value)?)?;
    dict.set_item("level", level_str)?;
    dict.set_item("stats", stats_to_dict(py, &scrubbed.stats)?)?;
    Ok(dict)
}

// ─── Science layer (lens-core implements) ─────────────────────────

/// Process a batch of trace events. v0.1.0 orchestrates persist's
/// post-ingest pipeline (scrub + classify + extract) and lens-core's
/// science layer (cohort routing + manifold-conformity detection +
/// scoring + signed detection events).
///
/// # Return shape (locked v0.1.0)
///
/// ```python
/// {
///     "batch_id":         "<uuid>",            # str — correlation handle
///     "traces_received":  100,                  # int — trace count in the input list
///     "traces_processed": 100,                  # int — pipeline completion count; mismatch with received means batch-level errors
///     "detections": [                           # list[dict] — one entry per detection_events row landed
///         {
///             "detection_id": "<uuid>",        # str — points to cirislens_derived.detection_events
///             "trace_id":     "<trace_id>",    # str — joins to cirislens.trace_events
///             "severity":     "info"            # str — "info" | "warning" | "critical"
///         },
///         ...
///     ]
/// }
/// ```
///
/// The deployed lens calls `Engine.get_detection_events([id, ...])`
/// to fetch full conformity payloads + signed canonical bytes for
/// any detection_id it wants to act on; the PyO3 return stays minimal
/// to avoid duplicating that data through the FFI boundary.
///
/// Legacy `cirislens-core` returned a richer dict (per-trace
/// `destination`, `schema_version`, `accepted`) that fed Grafana
/// dashboards. v0.1.0 drops those fields — Grafana paths are out
/// of scope.
///
/// # Phase 1 status
///
/// Scaffolding — returns `NotImplementedError` until cohort +
/// detector + scoring stages land. Signature + return-shape contract
/// are locked.
#[pyfunction]
#[pyo3(signature = (events, batch_timestamp, consent_timestamp=None, trace_level="detailed".to_string(), correlation_metadata=None))]
fn process_trace_batch(
    _py: Python<'_>,
    events: Vec<String>,
    batch_timestamp: String,
    consent_timestamp: Option<String>,
    trace_level: String,
    correlation_metadata: Option<String>,
) -> PyResult<PyObject> {
    let _ = (
        events,
        batch_timestamp,
        consent_timestamp,
        trace_level,
        correlation_metadata,
    );
    Err(PyNotImplementedError::new_err(
        "process_trace_batch: Phase 1 stages land per commit (cohort + detector + scoring + signing); see CIRISLensCore MISSION.md §2",
    ))
}

// ─── Substrate-delegated (thin wrappers over ciris_persist) ───────

/// Scrub a single trace per the requested trace-level. Returns
/// `{"trace": <scrubbed_object>, "level": <level_str>, "stats": <stats_dict>}`.
#[pyfunction]
fn scrub_trace(py: Python<'_>, trace_json: &str, level: &str) -> PyResult<PyObject> {
    let value: serde_json::Value = serde_json::from_str(trace_json)
        .map_err(|e| PyValueError::new_err(format!("invalid trace JSON: {e}")))?;
    let parsed_level = parse_level(level)?;
    let scrubbed = persist_scrub::scrub_trace(value, parsed_level)
        .map_err(|e| PyRuntimeError::new_err(format!("scrub failed: {e}")))?;
    Ok(scrubbed_to_dict(py, scrubbed, level)?.into())
}

/// Scrub a batch of traces with one shared NER forward pass. Returns
/// a Python list of per-trace dicts matching `scrub_trace`'s shape.
#[pyfunction]
fn scrub_traces_batch<'py>(
    py: Python<'py>,
    traces_json: Vec<&str>,
    level: &str,
) -> PyResult<&'py PyList> {
    let mut values = Vec::with_capacity(traces_json.len());
    for (i, s) in traces_json.iter().enumerate() {
        let v: serde_json::Value = serde_json::from_str(s).map_err(|e| {
            PyValueError::new_err(format!("invalid trace JSON at index {i}: {e}"))
        })?;
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

// ─── Module entry ─────────────────────────────────────────────────

/// PyO3 cdylib entry. v0.1.0 exposes the 4 function names the
/// deployed lens still calls into post-cutover. See module docstring
/// for the swap contract.
#[pymodule]
fn ciris_lens_core(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(process_trace_batch, m)?)?;
    m.add_function(wrap_pyfunction!(scrub_trace, m)?)?;
    m.add_function(wrap_pyfunction!(scrub_traces_batch, m)?)?;
    m.add_function(wrap_pyfunction!(ner_is_configured, m)?)?;
    // Lens-core's own constants for inspection.
    m.add("PROJECTION_VERSION", crate::extract::projection::PROJECTION_VERSION)?;
    Ok(())
}
