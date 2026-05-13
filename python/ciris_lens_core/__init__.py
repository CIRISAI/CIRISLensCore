"""ciris_lens_core — Science-layer runtime for the CIRIS federation.

Cohort routing + manifold-conformity scoring + hybrid-signed detection
events. Folds into the agent post-PoB §3.1; v0.1.0 ships as a PyO3
cdylib the deployed CIRISLens product consumes during the cutover
window.

Mission alignment: see ``MISSION.md`` in the repo root.

# Phase 1 swap contract (deployed-lens cutover)

The deployed Python lens replaces its in-tree ``cirislens_core``
import with this package via one-line alias:

>>> # before:
>>> # import cirislens_core
>>> # after:
>>> import ciris_lens_core as cirislens_core

# Engine-as-parameter — lens-core never holds keys

``process_trace_batch`` takes a ``ciris_persist.Engine`` instance as
its first parameter. Lens-core calls ``engine.steward_sign`` +
``engine.steward_pqc_sign`` + ``engine.put_detection_event`` to
sign and persist detection events through the host's identity.
Lens-core never reads key material directly — same pattern survives
the PoB §3.1 fold-into-agent (agent's Engine replaces deployed-lens's
Engine, lens-core sub-module is unchanged).

>>> import ciris_lens_core
>>> import ciris_persist as cp
>>> engine = cp.Engine(...)  # host constructs with steward keys
>>> result = ciris_lens_core.process_trace_batch(
...     engine,
...     events=trace_json_list,
...     batch_timestamp="2026-05-13T12:00:00Z",
... )
>>> # result["detections"] is a list of {detection_id, trace_id, severity}

# v0.1.0 surface

- ``process_trace_batch(engine, events, batch_timestamp, ...)`` — full
  pipeline (cohort + projection + no-op detector + scoring +
  signing). Every trace produces ``ManifoldConformity::Indeterminate
  {CohortColdStart}`` until RATCHET centroids ship via persist's
  ``calibration_bundles`` in Phase 2.
- ``scrub_trace(trace_json, level)`` — delegates to
  ``ciris_persist::pipeline::scrub::scrub_trace``. Returns
  ``{"trace": <json string>, "level": <str>, "stats": <dict>}``.
- ``scrub_traces_batch(traces_json, level)`` — delegates to
  ``ciris_persist::pipeline::scrub::scrub_traces_batch``.
- ``ner_is_configured() -> bool`` — delegates to
  ``ciris_persist::pipeline::scrub::ner::is_configured``.

# What's deliberately NOT in v0.1.0

Seven legacy ``cirislens_core`` functions are absent
(``load_schemas_from_db``, ``refresh_schema_cache``,
``get_loaded_schemas``, ``load_public_keys_from_db``,
``refresh_public_key_cache``, ``get_public_key_count``,
``check_cache_status``). Schema validation moved to edge
(verify-via-persist); public key lookup moved to persist's
``federation_keys`` table + ``Engine.lookup_public_key``. Deployed
lens deletes the obsolete call sites at swap time.
"""

from .ciris_lens_core import (  # type: ignore[attr-defined]
    PROJECTION_VERSION,
    ner_is_configured,
    process_trace_batch,
    scrub_trace,
    scrub_traces_batch,
)

__all__ = [
    "PROJECTION_VERSION",
    "ner_is_configured",
    "process_trace_batch",
    "scrub_trace",
    "scrub_traces_batch",
]
