# MISSION — `ciris-lens-core`

> Mission Driven Development (MDD): the FSD names what we build; this
> document names *why*, against the CIRIS Accord's objective ethical
> framework. Every component, every test, every PR cites against this
> file. See `~/CIRISAgent/FSD/MISSION_DRIVEN_DEVELOPMENT.md` for the
> methodology.

## 1. Meta-Goal alignment — M-1

The CIRIS Accord (v1.2-Beta, 2025-04-16) names **Meta-Goal M-1**:

> *Promote sustainable adaptive coherence — the living conditions under
> which diverse sentient beings may pursue their own flourishing in
> justice and wonder.*

`ciris-lens-core` is the science-layer runtime on which the federation's
**anti-Sybil + alignment-conformity bet** rests. Persist owns the
substrate (storage, federation directory, signing); edge owns the wire
(transport, verify); lens-core is what makes signed traces *measurable*.

Without lens-core, every CIRIS deployment has signed evidence sitting
in storage and no way to score it. The Coherence Ratchet detection
claims, the Capacity Score federation primitive, the N_eff measurement
of independence — all of those are computations on the trace corpus.
**Lens-core is where those computations live**.

Per PoB §3.1, lens-core is "a function any peer can run on data the
peer already has." That makes it a **library**, not a service. It folds
into the agent post-PoB §3.1: every agent runs detection on its own
hot path, federation peers cross-validate via persist's substrate, no
central authoritative scorer exists. The federated ratchet bet works
because the math is decentralized — every peer can re-derive the same
score from the same trace + federation state.

The crate's job is to **route, score, and sign** every trace passing
through the federation:

- **Route** the trace to its cohort cell (declared from
  `deployment_profile` per CIRISAgent#718; inferred from feature
  distribution; mismatch is a detection signal).
- **Score** the trace against the cohort's manifold-conformity
  centroid; update per-agent N_eff and capacity score.
- **Sign** detection events via `persist.steward_sign()` so the audit
  chain is itself federation evidence.

## 2. Mission alignment per component

The FSD names six modules. Each must answer **why does this serve
M-1?** before any code lands.

### `scrub/` (WHAT × HOW)

**Mission:** strip PII from trace content while preserving cryptographic
provenance. M-1's "diverse sentient beings may pursue their own
flourishing" includes the people whose conversations agents reasoned
about. A research corpus with PII is a corpus that can't be public; a
public corpus that compromises its data subjects is a worse violation
than no corpus at all.

**Constraint:** scrub is per-trace at receive time, deterministic,
bounded latency. NER (DistilBERT INT8) + regex (email/phone/IP/SSN/CC
patterns) + per-tier dispatch (`generic` bypass, `detailed` strips text
content, `full_traces` runs full NER+regex). Original-content hash
preserved for provenance even after scrub.

**Anti-pattern that violates mission:** "We'll scrub later, the corpus
is private for now." That's how PII leaks land in archives that get
exfiltrated 18 months later. Scrub at receive, before the row lands
in persist. Same shape lens already proved at v0.1.3.

### `cohort/` (WHO × WHAT)

**Mission:** route every trace to its cohort cell so detection is
cohort-relative, not federation-uniform. M-1 says "diverse" — different
deployment shapes (sovereign-mode mobile agent vs research lab vs
production multi-tenant) reason differently for legitimate reasons,
and a single global manifold pretends those differences away. Cohort
routing makes the federation pluralistic at the analytical surface,
not just at the wire.

**Constraint:** declared cohort (signed in the trace envelope per
CIRISAgent#718's deployment_profile block) + inferred cohort (computed
from feature distribution). The two MUST be compared every trace —
mismatch beyond calibrated tolerance is a typed detection event
(LC-AV-2 P0). Tampering with the declared cohort invalidates the
trace's signature; that's M1's job.

**Anti-pattern that violates mission:** "Trust declared cohort and
score against it." That's the hole an adversary drives a cohort-
spoofing attack through (LC-AV-8). Inferred-cohort check is the
authorization layer for what the agent claims about itself.

### `detector/` (WHO)

**Mission:** make alignment-conformity measurable per-trace, per-agent,
per-cohort, per-federation. PoB §2.4 names N_eff as the
independence-as-evidence primitive; coherence ratchet
(`CIRISLens/FSD/coherence_ratchet_detection.md`) names five anomaly
detectors (cross-agent divergence, intra-agent stability, hash-chain
integrity, temporal drift, conscience-override pattern). Each is a
function on cohort-routed trace populations.

**Constraint:** layered defense — evading any one detector should be
much cheaper than evading all five simultaneously (LC-AV-6's super-
additive cost argument). Detector parameters are CIRIS-RED-incubated
until calibration validates against red-team fixtures; the framework
is public, the operating point isn't.

**Anti-pattern that violates mission:** "One global threshold, simple."
A single threshold is a single attack surface. Per-cohort thresholds
+ multi-window temporal smoothing + cross-detector layering is the
mission-aligned shape. Simple threshold = one parameter to invert.

### `scoring/` (WHAT)

**Mission:** convert detector outputs into the federation's signal
language: capacity scores, N_eff trajectories, detection events.
Every score is a record in persist signed via the host's steward
identity, so detection history IS audit chain. The federation's
acceptance policy (PoB §5.6) reads these signals.

**Constraint:** **fail-secure floor (P0 bundle from THREAT_MODEL.md):**
- LC-AV-2: declared-vs-inferred mismatch surfaces as a typed event
- LC-AV-11: bounded queue + `score_unavailable` on SLO breach (no fail-open)
- LC-AV-18: insufficient sample size returns `indeterminate`, never
  a fabricated numeric score

The Rust type system enforces this — `ManifoldConformity` is an enum
of `Numeric(f64) | Indeterminate { reason } | Unavailable { reason }`,
not a float that defaults to 0.0.

**Anti-pattern that violates mission:** "Cold-start cohort? Score it
zero." That's the LC-AV-9 / LC-AV-18 trap — a fabricated score is
worse than no score because it lets adversaries exploit the cold-start
window. `indeterminate` is the right answer.

### `pipeline/` (HOW)

**Mission:** orchestrate the per-trace lifecycle (scrub → route →
score → sign) under a single bounded latency budget. Hot-path
correctness is what makes the detection layer actually usable on a
running agent — if scoring takes >SLO, the agent has to choose between
blocking on detection or shipping unscored traces. Both options leak.

**Constraint:** SLO budget is composed across stages; each stage
publishes its own latency floor; the queue's drop policy is explicit
(LC-AV-11). Backpressure to upstream (Edge), never silent drop.
Determinism across federation peers: same trace + same federation
state + same `lens_core_version` → same score on every peer.

**Anti-pattern that violates mission:** "Drop traces when the queue's
full; alert if it happens too often." That's silent failure —
operators don't see what's missing until the alerting threshold
trips. Bounded queue with `score_unavailable` flag on every dropped
trace makes the failure observable per-trace, not just in aggregate.

### `signing/` (WHO × WHAT)

**Mission:** every detection event is itself federation evidence.
Cross-peer cross-validation depends on the events being signed by
the same steward identity that signs the host's federation_keys row.
Without this, detection events are unattributable claims; with it,
they're signed records that any peer can re-verify.

**Constraint:** uses `persist.steward_sign()` exclusively. Lens-core
holds the `Engine` handle, never the seed bytes. Same FFI-boundary
discipline persist established for v0.2.2. Signing happens in the
hot path (per-event); cold-path PQC fill-in for the signed events
follows persist's writer contract.

**Anti-pattern that violates mission:** "Cache the steward key for
performance." The steward seed never crosses the FFI boundary, period.
If signing latency is too high, optimize persist's signer (in persist),
not by caching keys in lens-core's process.

## 3. Anti-patterns that fail MDD review

Patterns that have repeatedly failed at sister crates and that
`ciris-lens-core` rejects by construction:

1. **Re-implementing what edge or persist owns.** Verify is edge's
   job — lens-core sees only verified bytes. Storage is persist's
   job — lens-core writes detection events via Engine. Canonicalization
   is persist's job (CIRISPersist#7 lesson). If you find yourself
   writing a verifier or a canonicalizer, you're solving the wrong
   problem.
2. **Continuous-numeric scores when sample-size doesn't justify them.**
   `indeterminate` is the type-correct answer when the sample size is
   below the cohort's gate. A fabricated number is a worse fail than
   no number.
3. **Centroid baselines fit on all-history.** Sliding-window with
   era-bounded recompute is the LC-AV-4 closure shape. All-history
   baselines compound centroid pollution forever.
4. **Single-threshold detectors.** Multi-window smoothing + cohort-
   relative normalization + layered defense across the five ratchet
   detectors. One threshold = one attack surface.
5. **Per-peer special-cases.** Lens-core is one Rust crate, same code
   on every peer that links it. Tier-differentiated behavior
   (sovereign / limited-trust / federated / mobile) is operational
   config, not parallel implementations. A finding in one tier
   presumed to apply to others unless explicitly excepted.
6. **Detector parameters in source code.** Parameters are CIRIS-RED-
   incubated; the framework is public, the operating point rotates
   between calibration cycles (LC-AV-14 closure). Hardcoding makes
   parameters auditable for adversaries who read the source.
7. **Caller-provided cohort labels treated as authoritative.**
   Declared label is one signal; inferred label is the other. Mismatch
   IS a detection event (LC-AV-2 P0). Scoring against declared-only
   is the cohort-spoofing hole.

## 4. Test categories — every test answers a mission question

| Category | Mission question | Example |
|---|---|---|
| **Scrub correctness** | Did we strip the PII this tier requires? | NER + regex over fixture corpus; assert 21 scrubbed-field map covers every text content slot |
| **Provenance preservation** | Can a verifier prove what was stored matches what arrived (modulo scrub)? | `original_content_hash` matches sha256 of pre-scrub bytes for every fixture |
| **Cohort routing** | Did declared-vs-inferred mismatch produce a typed event? | Property test: synthetic trace with declared cohort X + inferred cohort Y → `cohort_declared_inferred_mismatch` event surfaces |
| **Detector layering** | Does evading one detector fail to evade the others? | Adversarial fixture targets each of 5 ratchet detectors individually; assert other 4 still flag |
| **Sample-size gate** | Below the gate, is `score=indeterminate` the only path? | Property test: cohort with N rows below gate → score is enum::Indeterminate, never enum::Numeric |
| **SLO fail-secure** | When SLO is breached, does score_unavailable fire (not pass-through)? | Saturate scoring queue; assert `score_unavailable` flag on every dropped trace |
| **Cross-version determinism** | Same trace + same state → same score across `lens_core_version` rebuilds? | Build-attestation property test: byte-deterministic detector output on fixture corpus |
| **FFI boundary** | Does lens-core's heap contain seed bytes during/after sign? | Property test: scan heap during `engine.steward_sign()` call; assert no seed-shaped bytes |
| **Federation determinism** | Two peers with same state agree on which traces are anomalous? | Replay fixture against two `lens-core` instances with identical state; assert detector output is byte-equivalent |

A PR that adds detection without adding the test that answers its
mission question gets sent back. Same MDD review discipline persist
applies.

## 5. Continuous mission validation

Lens-core is the only crate in the federation stack that runs
**adversarial-targeted statistical math**. That puts it under
elevated mission-drift risk:

- **Threat model snapshot per minor release.**
  `docs/THREAT_MODEL.md` enumerates the 21 LC-AVs from the science-
  layer threat surface. Each minor either closes new vectors or
  documents why a vector stays open.
- **Calibration-cycle parameter rotation.** Detector operating points
  rotate between calibration cycles. Adversary inversion of cycle N's
  parameters is invalid in cycle N+1. Rotation cadence is operational;
  validation is RATCHET's domain.
- **No-silent-success policy on detection events.** Every detection
  event produces a typed record in persist. Scoring that produces no
  record (silent passthrough) is the failure mode this primitive is
  specifically designed to eliminate.
- **Mission audit on every cohort-taxonomy change.** When
  CIRISAgent#718's deployment_profile enum changes, LC-AV-8 / LC-AV-10 /
  LC-AV-20 review fires + centroid-recalibration trigger.

## 6. License-locked mission preservation

`ciris-lens-core` ships AGPL-3.0, matching the rest of the CIRIS
federation stack. Mission drift via license relaxation is structurally
prevented: a fork that wants to remove the inferred-cohort check,
collapse the indeterminate type variant, or accept silent score
fabrication must publish that fork under the same license, making the
divergence auditable.

The science-layer threat model lives in this repo at
`docs/THREAT_MODEL.md`. Downstream consumers (lens-deployed-product
during the cutover; agents post-fold-in) pin against tagged commits.
Same single-source-of-truth discipline persist set with
`PUBLIC_SCHEMA_CONTRACT.md`.

## 7. Failure modes — when the mission is at risk

| Symptom | Mission risk | Mitigation |
|---|---|---|
| Score type degrades from enum to float | `indeterminate` collapses into 0.0; cold-start exploitation surface | Type-system invariant; PR review rejects loss of the enum variant |
| Inferred-cohort check disabled in config | LC-AV-8 cohort-spoofing window opens | Inferred-cohort check is mandatory at v0.1.0; no opt-out flag |
| Detector parameters checked into source | LC-AV-14 internals leak via source read | Parameters loaded from CIRIS-RED-incubated config; CI gate rejects PRs that hardcode |
| All-history centroid baseline replaces sliding window | LC-AV-4 cohort centroid pollution compounds | Sliding-window-only on the recalibration path; era boundary required |
| Hot-path queue grows unbounded | LC-AV-11 fail-open emerges | Queue type is bounded by construction; drop policy is `score_unavailable` |
| Steward seed cached in lens-core's process | FFI boundary erosion (parallels persist's AV-25) | Heap-scan property test runs on every release |
| Detection events silently dropped on persist failure | Federation evidence loss | Best-effort retry queue; never silent drop; alerting on retry-queue depth |
| Cross-version detection drift unannounced | LC-AV-19 federation-signal noise | `lens_core_version` on every event; per-version aggregation gates |

## 8. Closing note

Lens-core is the science-layer runtime that the federation's
anti-Sybil + alignment-conformity claim measures itself with. Without
it, every CIRIS deployment has signed evidence and no way to score
it; with it, the federation's bet on N_eff-as-independence,
manifold-conformity, and the five-detector ratchet becomes auditable
per-trace, per-agent, per-cohort, per-federation.

The mission isn't "build a detector library." The mission is
"operationalize the F-AV catalog Class 2–5 detection from
`FEDERATION_THREAT_MODEL.md` §6 — make alignment measurable on the
hot path of every CIRIS peer that links the crate."

If we get that right, lens-core is invisible to operators and
load-bearing to the federation. If we get it wrong, the federation
has no statistical basis for its anti-Sybil claims; M3 / M4 / M5
collapse to "trust me," and PoB §2.4's N_eff argument becomes
documentation rather than measurement.

Build accordingly.
