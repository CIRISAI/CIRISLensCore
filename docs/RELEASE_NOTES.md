# CIRISLensCore Release Notes

# v0.2.1 — `install_relay` re-export hotfix

**2026-06-05** — Patch release. v0.2.0's PyO3 cdylib correctly registers
`install_relay` (the cohabitation bootstrap entry — see v0.2.0 notes
below), but the Python `__init__.py` shim at
`python/ciris_lens_core/__init__.py` did not re-export the symbol;
`dir(ciris_lens_core)` on the v0.2.0 wheel surfaced
`process_trace_batch / scrub_trace / scrub_traces_batch /
ner_is_configured / PROJECTION_VERSION` only, and `install_relay`
was unreachable from the top-level module despite the v0.2.0
release notes naming it the cohabitation entry. Every cohabitation
agent post-fold-in calls `ciris_lens_core.install_relay(edge)`; on
v0.2.0 that resolves to `AttributeError`.

CIRISConformance `test_ciris_lens_core_exposes_install_relay`
(`tests/test_010_solo_imports.py`) is the regression gate going
forward — locks `install_relay in dir(ciris_lens_core)` for every
matrix entry.

Also folds in the MISSION.md three-pass refresh (drift fix + CEG
§5.5 alignment + F-3 / distributive reconciliation to v0.2.0 source
state) and refreshes the `__init__.py` docstring to current
cohabitation terminology (`local_sign` not `steward_sign`; fold-in
in past tense not future).

No Rust source changes. The cdylib bytes are identical to v0.2.0
modulo build-stamp; the wheel deliverable changes only in the
Python shim and the version metadata.

**Upgrade path:** `pip install --upgrade ciris-lens-core` is
sufficient. Cohabitation agents that were calling
`install_relay` and failing with `AttributeError` on v0.2.0 work
out of the box on v0.2.1.

---

# v0.2.0 — federation cohabitation + CEG §5.5 foundations

**2026-05-30** — The lens-core release the deployed Python lens
adopts to track the persist 3.x + edge 1.x federation. Triple-bump
to the CIRISConformance matrix (persist v3.14.3 + edge v1.1.10 +
verify v4.8.0) + v0.2 cohabitation surface + v0.4 retention &
scoring + CEG §5.5 type-system foundations.

## What v0.2.0 ships

### v0.2 cohabitation — lens-core as a key-addressable Edge endpoint

The agent constructs ONE persist `Engine` + ONE `Edge` per process
(CIRIS 3.0 in-process model); sibling consumers — NodeCore,
lens-core — install handlers onto the shared `Arc<Edge>`. Three
ways in:

- `LensCore::relay(engine, key_id, seed_dir, listen_addr,
  peer_urls)` — standalone rlib ctor; builds its own Edge,
  registers `LensCoreHandler<AccordEventsBatch>`, spawns the
  listener, returns a `RelayHandle` with orderly `shutdown()`.
  Used by the deployed-Python-lens cutover where lens-core is
  the only consumer in the process.
- `LensCore::attach_handler(&edge, engine)` — cohabitation rlib
  entry; registers on a host-built shared `Edge`. Used by
  pure-Rust embeddings (agent linking lens-core as a library).
- `ciris_lens_core.install_relay(edge)` — PyO3 cohabitation
  bootstrap. Python form of `attach_handler`. Mirrors
  `ciris_node_core.install_from_dispatch(...)`. The agent's
  Python startup calls `ciris_edge.init_edge_runtime(...)` →
  `ciris_node_core.install_from_dispatch(...)` →
  `ciris_lens_core.install_relay(edge)` — three lines, full
  federation participation.

After `install_relay`, lens-core IS a key-addressable Edge
endpoint: peers routing `AccordEventsBatch` to its `key_id` land
on `LensCoreHandler` and flow into `engine.receive_and_persist(
&bytes, &NullScrubber)`. Relay mode is store-and-forward transit;
scrubbing is the originating client node's egress responsibility,
NOT the relay's (federation contract — re-scrubbing at relays
causes NER-version content drift).

### v0.3 config foundation — pan-mode shared shapes

`#[non_exhaustive]` config structs every `LensCore` mode shares:

- `UpstreamLens { lens_steward_key_id, egress_filter }` — a
  destination in the multi-recipient fan-out, keyed by federation
  `key_id` (not hostname)
- `EgressFilter { trace_level }` — what gets forwarded to a given
  upstream; v0.4 extends with severity/redaction/inclusion bits
- `RetentionPolicy { max_disk_gb, max_age_days, per_level_max_age,
  detection_events_max_age_days, audit_log_max_age_days }` — local-
  store eviction bounds

### v0.4 retention enforcement (CIRISLensCore#13)

`src/retention/` composes on top of persist v2.7.0+'s retention
primitives (CIRISPersist#107):

- `plan_eviction(summary, policy, now)` — pure function over
  storage summary + policy + clock. Returns an `EvictionPlan`.
- `execute_plan(engine, plan)` — async; calls
  `Engine::delete_traces_older_than` in a bounded batch loop.
- `evict_per_retention_policy(engine, policy)` — convenience entry.

v0.4 enforces three of five `RetentionPolicy` dimensions:
`max_age_days`, `max_disk_gb` (90% threshold), and
`audit_log_max_age_days` planning. The other two
(`per_level_max_age`, `detection_events_max_age_days`) are
documented; planner emits the planned action; executor records a
`tracing::debug!` note. Awaits per-level + detection-events delete
primitive expansion on persist.

### v0.4 scoring oracle (CIRISLensCore#19)

`src/scores/` ships the agent-side score read path per FSD §4.6 —
closes the agent's self-awareness loop:

- `ScoresOracle<'a>::for_trace(trace_id)` — `Vec<DetectionEvent>`
- `ScoresOracle<'a>::for_agent_window(start, end, detectors?)` →
  `AgentScoreAggregate` (per-detector + per-severity +
  per-conformity counts)
- `ScoresOracle<'a>::detector_history(detector, since,
  min_severity)` → filtered `Vec<DetectionEvent>` (>= min_severity)
- Pure `compute_aggregate` reduction over `&[DetectionEvent]` —
  testable without an `Engine`

### CEG §5.5 foundations — load-bearing invariants at the type level

CIRISRegistry shipped CEG 0.1 + 0.2 (FSD/CEG/) during this window.
Lens-core's §5.5 share gets three foundations, each enforcing a
spec-level invariant in the type system rather than as best-effort
validation:

- **§5.5.1 — `CoherenceRatchetDetector` closed enum** — the five
  Coherence-Ratchet detection dimensions (cross_agent_divergence,
  intra_agent_consistency, hash_chain_integrity, temporal_drift,
  conscience_override_rate). `const fn dimension_label()` makes
  the wire mapping a compile-time property. Wire-label-exactness
  test locks the dimension labels against silent rename.
- **§5.5.4 — `CapacityFactors`** — typed C·I_int·R·I_inc·S product
  with range-validated factors and multiplicative composite. Any
  factor at zero zeros the composite (CEG design: a single failed
  dimension can't be averaged away). Serde re-validates on the wire.
- **§7.5 — `CapacityAttestation`** — anti-Goodhart self-attestation
  rejected at construction. `attesting_key_id == attested_key_id`
  is a typed error, not a validation failure. Serde re-validates
  so bytes can't bypass via `Deserialize`.

Plus `src/wire/` re-exports for the typed Goal primitive from
persist v2.10.0 (CIRISPersist#114) — Goal, MetaGoalAlignment,
M1Dimension (closed enum: Sustainability / Adaptivity / Coherence
/ Plurality / Flourishing / Justice / Wonder), GoalScope,
GoalsFilter, DeliberationRef. Every Goal in the federation carries
M-1 alignment by structural construction-time invariant.

### Federation pin discipline — CIRISConformance-tracked

Lens-core's `Cargo.toml` + `pyproject.toml` pins now track the
CIRISConformance matrix. The conformance harness pins the current
cohabitation triple; lens-core re-pins in lockstep. Single-
version-clean is the contract — all co-resident consumers
(lens-core + edge + NodeCore + agent) link the identical persist
in one process.

Triple as of v0.2.0:

```
ciris-persist   v3.14.3
ciris-edge      v1.1.10
ciris-verify    v4.8.0     (transitive)
python floor    3.10
abi3            py310
```

### PyO3 surface — v0.1.1 contract preserved

The v0.1.1 four-function deployed-lens drop-in surface
(`process_trace_batch`, `scrub_trace`, `scrub_traces_batch`,
`ner_is_configured`) is preserved verbatim. v0.2.0 adds
`install_relay(edge)` for the cohabitation bootstrap. Existing
v0.1.x callers do not need source changes; `import ciris_lens_core
as cirislens_core` continues to work.

## What v0.2.0 does NOT yet ship

- `LensCore.client(...)` PyO3 ctor — replaces ~3000 LOC of
  CIRISAgent's metrics service (CIRISLensCore#11). Design forks
  on capture sub-namespace shape; v0.3.0 milestone.
- `LensCore.audit.*` PyO3 — typed action vocabulary
  (CIRISLensCore#12). v0.3.0.
- Wire-contract v1.0 freeze (CIRISLensCore#18). Depends on the
  CI/docs spike landing first.
- Node-mode UX endpoints — `/scores`, `/detection_events` HTTP
  read API (CIRISLensCore#15). v0.4.x.
- Per-upstream EgressFilter behaviors beyond `trace_level`
  (CIRISLensCore#14). v0.4.x.
- F-3 detector family + ECF UI surfaces (CIRISLensCore#23 / #24 /
  #25 / #26 / #29). Calibration package gates from RATCHET.

## Lens-core issues closed in v0.2.0

#6, #10, #13, #16, #19 — all shipped during this window.

## Verification

Both `--features python` and `--no-default-features` compile clean.
106 tests passing each. clippy `-D warnings` clean both feature
builds. fmt clean. cargo deny check: advisories ok, bans ok,
licenses ok, sources ok.

---

# v0.1.1 — abi3-py311 wheel + macos-14 CI fix

**2026-05-20** — Bug-fix release for the v0.1.0 CI breakage.
v0.1.0's tag run failed on (a) `pyo3 0.20` RUSTSEC-2025-0020 and
the resulting `cp311-cp311` (not abi3) wheel shape, and (b)
`macos-14` rust-cache restoring a `rustup-init` stub over the
real `cargo` binary. v0.1.1 fixes both:

- `pyo3 0.20 → 0.28` + `abi3-py311` feature → cp311-abi3 wheels
  consumable on Python 3.11+
- `Bound` API migration to satisfy the pyo3 0.28 shape
- `cache-bin: false` on macos-14 jobs (per persist v0.7.3
  precedent) so the rust-cache restore doesn't shadow dtolnay's
  cargo install

Functionality identical to v0.1.0 — the v0.1.0 → v0.1.1 delta is
all CI / wheel-shape repair.

---

# v0.1.0 — Phase 1 science layer + deployed-lens drop-in

**2026-05-15** — First PyPI release. Phase 1 of the science-layer
runtime + the four-function deployed-lens drop-in surface.

## What v0.1.0 ships

### Science layer (Phase 1)

- `src/cohort/` — declared 6-tuple parsing + `cohort_cell` JSON
  building + LC-AV-2 declared-vs-inferred mismatch tracking
- `src/detector/` — no-op detector for v0.1.0 (architecturally
  correct fail-secure during LC-AV-9 cold-start window until
  RATCHET delivers calibration centroids)
- `src/scoring/` — Kish `n_eff`, capacity-band gate, LC-AV-18
  sample-size assembly, `ManifoldConformity` enum
  (`Numeric`/`Indeterminate`/`Unavailable`)
- `src/extract/projection.rs` — `crc-v1` 16-feature projection
  (10 floats + 6 bools) against RATCHET-calibrated cohort
  centroids
- `src/pipeline/lifecycle.rs` — `LensCore { signer, journal }` +
  per-trace `process(trace, sample_size_gate,
  ratchet_calibration_version)` orchestrator
- `src/signing/event.rs` — hybrid (Ed25519 + ML-DSA-65) signed
  detection events; bound construction (PQC signs canonical
  bytes ++ ed25519 sig)
- `src/wire/` — federation-public ABI: BatchEnvelope,
  CompleteTrace, TraceComponent, ReasoningEventType re-exports
  from persist's `schema::*` (single-source-of-truth canonical
  bytes via `canonicalize_envelope_for_signing`)

### Deployed-lens drop-in (PyO3)

Four free functions the existing Python deployed lens can swap
into in place of `cirislens_core` with a one-line import alias:

```python
import ciris_lens_core as cirislens_core  # one line
```

- `process_trace_batch(engine, events, ...)` — orchestrates the
  science layer; persist signs + persists. Engine-as-parameter
  (lens-core never holds keys).
- `scrub_trace(trace_json, level)` — delegates to
  `ciris_persist::pipeline::scrub::scrub_trace`
- `scrub_traces_batch(traces_json, level)` — batch scrub
- `ner_is_configured()` — reports whether the persist scrubber's
  NER backend is configured

### Engine-as-parameter pattern

Lens-core is a science layer, not a federation identity. The
signing identity belongs to the host (the deployed lens today;
the agent post-PoB §3.1 fold). The host constructs the persist
`Engine` with its own local keys; lens-core uses the `Engine`
as a signing oracle via `engine.local_sign` /
`engine.local_pqc_sign`. This pattern survives the fold — agents
pass their `Engine` the same way the deployed lens does.

### Pin (initial federation)

```
ciris-persist   v0.6.0   (extract feature)
ciris-edge      v0.1.0
ciris-verify    v0.6.0   (transitive)
python floor    3.11
abi3            py311
```

## Threat model

`docs/THREAT_MODEL.md` enumerates 21 LC-AVs. P0 must-have-at-v0.1.0:

- LC-AV-2 — declared-vs-inferred cohort mismatch detection
- LC-AV-11 — bounded queue; `score_unavailable` on SLO breach
- LC-AV-18 — insufficient sample → `Indeterminate`, never numeric
