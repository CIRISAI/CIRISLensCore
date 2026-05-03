# Open Questions — CIRISLensCore

Decisions deferred to implementation kickoff. The threat model
(`docs/THREAT_MODEL.md`) closed most of the architectural questions
already (cohort routing, fail-secure floor, layered defense across 5
ratchet detectors); what's left is integration shape + naming +
calibration ownership.

Each question states the choice, the trade-off, and a starting
position. Resolutions move to `CLOSED` at the bottom.

---

## OQ-01: Persist integration mechanism — pure-Rust rlib link or PyO3 bridge

**Question:** How does `ciris-lens-core` (Rust) call into
`ciris-persist` (Rust + PyO3) at runtime?

**Options:**
- **A — Pure-Rust rlib link.** Persist's `Cargo.toml` already declares
  `crate-type = ["cdylib", "rlib"]`. Lens-core depends on persist as a
  Rust crate, links the `rlib` directly. No Python in the path.
  Cleanest for the post-fold-into-agent trajectory (agent is Rust).
- **B — PyO3 bridge.** Lens-core is itself a PyO3 cdylib; at runtime
  it imports `ciris_persist` Python module and gets the `Engine`
  handle. Same pattern lens currently uses.
- **C — Both.** Pure-Rust path for agent post-fold; PyO3 path for
  lens-deployed-product during the cutover. Behind a Cargo feature
  flag.

**Trade-offs:**

| Dimension | rlib | PyO3 | Both |
|---|---|---|---|
| Post-fold readiness | ✓ already correct | needs rewrite | ✓ |
| Lens-deployed-product readiness | needs persist's rlib publish | ✓ already works | ✓ |
| Build complexity | One target | Two | Two with feature gate |
| FFI boundary | Rust-Rust (clean) | Rust-Python-Rust (more layers) | Both |

**Starting position:** A (rlib). The fold trajectory dominates;
lens-deployed-product can consume via PyO3 by wrapping the rlib in a
thin lens-core-py bindings crate if needed.

**Status:** OPEN — depends on whether persist publishes its rlib as a
crates.io artifact or stays internal to its own repo.

---

## OQ-02: Cohort centroid storage + delivery

**Question:** Where do cohort centroids (calibrated by RATCHET) live
+ how does lens-core get them?

**Options:**
- **A — Persist substrate table** (`cirislens.cohort_centroids`).
  RATCHET writes; lens-core reads via Engine. Centroids signed by
  RATCHET's steward identity; lens-core verifies + uses.
- **B — Per-release static config baked into lens-core's binary.**
  Centroids ship as a compile-time embedded JSON. Updates require
  lens-core release.
- **C — File-mounted at deploy.** Centroids in `/etc/ciris-lens-core/centroids.json`;
  operator updates by replacing the file.

**Trade-offs:**

| Dimension | Persist table | Embedded | File-mount |
|---|---|---|---|
| Update cadence | RATCHET-driven, federation-wide | Lens-core release-driven | Operator-driven |
| Federation determinism | All peers see same centroids (after replication) | All peers see same centroids (per release) | Per-deployment |
| RATCHET workflow integration | Direct | Indirect | Indirect |
| Cold-start handling (LC-AV-9) | Centroid absent → fail-secure naturally | Same | Same |

**Starting position:** A (persist table). RATCHET's calibration
output is itself federation evidence; storing centroids in persist
makes them auditable + replicable across peers + signature-verifiable.

**Status:** OPEN — coordinate with RATCHET on the calibration→centroid
publication workflow + with persist on the schema (likely a new
schema-versioned migration).

---

## OQ-03: Detector parameter rotation cadence + delivery

**Question:** Detector operating points are CIRIS-RED-incubated and
must rotate between calibration cycles (LC-AV-14 closure). How are
parameters delivered to lens-core + how often do they rotate?

**Options:**
- **A — Quarterly calibration cycle** with parameter rotation at each
  cycle boundary. Parameters delivered via persist (similar to OQ-02)
  or via a separate config crate.
- **B — Continuous calibration** with RATCHET publishing updated
  parameters on a faster cadence (monthly?) as new red-team fixtures
  validate.
- **C — Per-cohort independent cadence.** Cohorts with high
  trace volume calibrate faster; cohorts with low volume stay on
  older parameters longer.

**Starting position:** A (quarterly). Faster cadence is research-
team's domain; lens-core's contract is "consume what RATCHET ships,
on whatever cadence." A quarterly default is operationally
predictable.

**Status:** OPEN — RATCHET-owned. Decision sits with the calibration
team, not lens-core implementation.

---

## OQ-04: SLO budget for the per-trace pipeline

**Question:** What's the bounded latency budget that
`LC-AV-11` enforces? When `score_unavailable` should fire?

**Options:**
- **A — 50 ms p99**, mirroring lens's existing trace ingest latency
  envelope. Aggressive but matches today's hot-path expectation.
- **B — 100 ms p99**, more headroom for cold-cache cohort lookups +
  detector recompute.
- **C — Per-cohort SLO**, derived from the cohort's centroid-lookup
  cost + its detector parameter density.

**Starting position:** A (50 ms p99) for Phase 1. Move to C in Phase
2 once production data shows real per-cohort latency distributions.

**Status:** OPEN — empirical, depends on detector implementation
costs; revisit during Phase 1 benchmarking.

---

## OQ-05: Detection event schema in persist

**Question:** What's the SQL shape for the detection-event records
lens-core writes back to persist?

**Options:**
- **A — New persist table** (`cirislens.detection_events`) with
  schema designed for lens-core's outputs (cohort, detector, score,
  ManifoldConformity variant, signed envelope, lens_core_version).
- **B — Extend `trace_events`** with detection-event rows tagged by
  a new `event_type='LENS_DETECTION'`. Reuses the existing audit
  pattern.
- **C — Lens-derived schema** (`cirislens_derived.detection_events`)
  per the discussion in CIRISLens#8. Lens-core writes to lens-derived;
  persist substrate stays untouched.

**Starting position:** C (lens-derived schema). Detection events are
analytical output, not substrate. Same architectural distinction as
`coherence_ratchet_alerts` and other lens-derived tables. Keeps
persist's substrate clean.

**Status:** OPEN — depends on the lens-derived schema work tracked at
CIRISLens#8.

---

## OQ-06: Lens-deployed-product cutover path

**Question:** How does the existing CIRISLens Python lens (with
`cirislens-core` Rust crate) consume `ciris-lens-core` once it ships?

**Options:**
- **A — Replace `cirislens-core` wholesale.** CIRISLens links
  `ciris-lens-core` instead. The existing `cirislens-core` retires.
- **B — Sit alongside.** `cirislens-core` keeps doing what it does
  today (scrub callback for persist + validation/security/sanitize);
  `ciris-lens-core` adds the cohort + scoring layer. Both run in the
  same Python lens process.
- **C — Lift the scrubber into `ciris-lens-core`** (gift it from
  patterns_from_cirislens_core/scrubber/), retire that subset of
  `cirislens-core`, leave the rest (validate/security/sanitize/route)
  in CIRISLens until those concerns are handled by Edge or retired.

**Starting position:** C. The scrubber is the only piece of today's
`cirislens-core` that genuinely belongs in lens-core's per-trace
pipeline. The rest either migrates to Edge (validation, security
sanitization) or stays with the lens-deployed-product (storage
routing, mock detection) or gets retired (Engine.receive_and_persist
already does signature verification).

**Status:** OPEN — sequencing decision; depends on Phase 1 implementation
landing the scrubber port first.

---

## OQ-07: ManifoldConformity discretization at federation publication

**Question:** LC-AV-14 closure says federation-published scores get
discretized (coarse bands) to defeat differential-observation attacks.
What's the discretization shape?

**Options:**
- **A — Five-band discretization**: high / above-average / typical /
  below-average / low. Per-cohort adjusted.
- **B — Quartiles within the cohort** with explicit
  "below-min-sample" indicator for cold-start.
- **C — Three-band**: conforms / atypical / anomalous. Coarse;
  hard to invert; loses information.

**Starting position:** B (quartiles + cold-start indicator).
Operationally meaningful; harder to invert than five bands; preserves
the cold-start signal that LC-AV-18's `indeterminate` produces.

**Status:** OPEN — RATCHET will weigh in based on the published-
signal information-leak budget.

---

## OQ-08: Build attestation parity with persist + edge

**Question:** Should `ciris-lens-core` publish a signed BuildManifest
to CIRISRegistry on every release, same shape as persist + edge?

**Starting position:** Yes. Every signed primitive in the federation
publishes its own provenance — there's no "library exemption."

**Status:** OPEN, but trivial yes. Confirm at v0.1.0 release prep.

---

## CLOSED

(Empty until questions get resolved.)

The threat model (`docs/THREAT_MODEL.md`) closed these architectural
questions before this OQ list got written, so they don't need to be
re-litigated:

- ✓ Library vs sidecar — library (consumes Edge + Persist as Rust deps)
- ✓ Wire format — n/a, lens-core consumes verified bytes from Edge
- ✓ Hosting — folds into agent per PoB §3.1
- ✓ Detector layering — five ratchet detectors + manifold conformity
  per `coherence_ratchet_detection.md`; layered defense per LC-AV-6
- ✓ Fail-secure shape — `ManifoldConformity` enum (Numeric /
  Indeterminate / Unavailable); never silently elevated
- ✓ Detector parameter visibility — incubated in CIRIS-RED;
  framework public, operating point internal
