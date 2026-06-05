# PUBLIC_SCHEMA_CONTRACT.md

`ciris-lens-core`'s public ABI is the surface every federation peer
that imports lens-core composes against — the deployed Python lens,
CIRISAgent (post-PoB §3.1 fold), NodeCore, RATCHET calibration
consumers, and sovereign-mode operators running lens-core as an
rlib. This doc defines what shape that surface has and what stability
guarantees lens-core makes against it.

Sister doc to
[`CIRISPersist/docs/PUBLIC_SCHEMA_CONTRACT.md`](https://github.com/CIRISAI/CIRISPersist/blob/main/docs/PUBLIC_SCHEMA_CONTRACT.md)
(persist's SQL column contract) — same tier model, different surface
shape: persist contracts SQL columns its readers SELECT; lens-core
contracts Rust types + PyO3 functions its consumers `import` /
`use ciris_lens_core::...`.

## Scope

This contract applies to:

1. **Top-level Rust re-exports** from `lib.rs` (everything reachable
   as `ciris_lens_core::Foo`)
2. **The `wire` module** (`ciris_lens_core::wire::*`) — federation-
   public ABI re-exported from persist
3. **The PyO3 surface** — every `#[pyfunction]` registered in the
   `ciris_lens_core` Python module
4. **The CEG §5.5 typed primitives** (`capacity::*`,
   `detector::CoherenceRatchetDetector`, etc.) — load-bearing
   invariants enforced by the type system

This contract does **NOT** apply to:

- `src/pipeline/lifecycle.rs` internals — `LensCore::process` is
  changing through v0.4/v0.5 as the detector family lands
- `src/scoring/` internal types — `ManifoldConformity` is in the
  contract; the assembly routing inside `scoring::assemble` is not
- Anything under `src/extract/` beyond the re-exported persist
  `Features` — projection internals can change as RATCHET ships
  calibration anchors
- Anything under `src/role/handler.rs` — relay handler internals

## Stability tiers

Mirrors persist's tier model:

- **`stable`** — semver-guaranteed. Removal or signature change
  requires a major version bump *and* a deprecation window of one
  minor version minimum. Downstream code can rely on these existing
  across patch and minor versions of lens-core.
- **`stable-frozen`** — same guarantees as `stable`, **plus** a
  promise that the shape doesn't change in any v0.x → v1.0
  transition. The wire types under `crate::wire::*` are
  `stable-frozen` because federation peers parsing them off the
  wire can't tolerate a rename even at a major version. Renames
  there require the entire federation re-cutting.
- **`internal`** — no stability guarantee. May change shape,
  semantics, or disappear at any minor version. Documented here
  only so consumers know not to depend on them.

The v0.5 wire-contract freeze (CIRISLensCore#18) ships when every
type currently marked `stable` is also marked `stable-frozen`. That's
the v1.0 ship gate.

---

## Rust crate surface

### `LensCore` — the mode-entry handle

```rust
// src/pipeline/lifecycle.rs
pub struct LensCore { /* … */ }

impl LensCore {
    pub fn new(signer: Arc<LocalSigner>, journal: Arc<Journal>) -> Self;     // stable
    pub async fn process(&self, trace: VerifiedTrace,                        // stable-frozen
        sample_size_gate: u32, ratchet_calibration_version: i32)
        -> Result<Outcome, ProcessError>;
    pub async fn relay(engine: Arc<Engine>, key_id: impl Into<String>,       // stable
        seed_dir: PathBuf, listen_addr: SocketAddr,
        peer_urls: HashMap<String, String>)
        -> Result<RelayHandle, RelayError>;
    pub async fn attach_handler(edge: &Edge, engine: Arc<Engine>)            // stable-frozen
        -> Result<(), EdgeError>;
}
```

`attach_handler` is `stable-frozen` because it's the cohabitation
entry point — every agent + NodeCore deployment in production after
v1.0 calls it. The signature locks: `&Edge` + `Arc<Engine>`, returns
`Result<(), EdgeError>`. Adding a parameter is a major break.

### `LensCoreHandler` — the Edge handler

```rust
// src/role/handler.rs
pub struct LensCoreHandler;                                                  // stable

impl LensCoreHandler {
    pub fn new(engine: Arc<Engine>) -> Self;                                 // stable
}

#[async_trait]
impl Handler<AccordEventsBatch> for LensCoreHandler {                        // stable-frozen
    async fn handle(&self, msg: AccordEventsBatch, ctx: HandlerContext)
        -> Result<AccordEventsResponse, HandlerError>;
}
```

The `Handler<AccordEventsBatch>` impl is `stable-frozen`: it's the
trait signature that edge's dispatch loop calls. Federation peers
expect lens-core's handler to match `AccordEventsBatch` →
`AccordEventsResponse` exactly. Changing the `Message::Response`
type would require a coordinated three-repo bump (persist + edge +
lens-core).

### `RelayHandle` — standalone-mode shutdown

```rust
// src/role/relay.rs
pub struct RelayHandle { /* … */ }                                           // stable

impl RelayHandle {
    pub fn listen_addr(&self) -> SocketAddr;                                 // stable
    pub async fn shutdown(self) -> Result<(), RelayError>;                   // stable
}

pub enum RelayError {                                                        // stable
    NotSqliteBacked,
    Signer(String),
    Transport(TransportError),
    Edge(EdgeError),
    Join(String),
}
```

`#[non_exhaustive]` on `RelayError` — new variants are minor-version
additions; downstream `match` arms must include `_ => ...`.

### `Score` / `Outcome` / `ManifoldConformity` — per-trace results

```rust
// src/pipeline/lifecycle.rs + src/scoring/result.rs
pub struct Outcome {                                                         // stable-frozen
    pub score: Score,
    pub event: DetectionEvent,
}

pub struct Score {                                                           // stable-frozen
    pub conformity: ManifoldConformity,
    pub cohort_id: String,
    pub lens_core_version: &'static str,
    pub detection_events: Vec<DetectionEvent>,
}

pub enum ManifoldConformity {                                                // stable-frozen
    Numeric(f64),
    Indeterminate { reason: IndeterminateReason },
    Unavailable { reason: UnavailableReason },
}
```

`ManifoldConformity` is `stable-frozen` because the enum **IS** the
contract — `Indeterminate` and `Unavailable` are not magic numeric
values, they're typed signals federation peers join on. Collapsing
to `f64` would silently lose the fail-secure information that
LC-AV-18 / LC-AV-11 / LC-AV-9 depend on.

### `ScoresOracle` — agent-side read path

```rust
// src/scores/oracle.rs
pub struct ScoresOracle<'a> { /* … */ }                                      // stable

impl<'a> ScoresOracle<'a> {
    pub fn new(engine: &'a Engine) -> Self;                                  // stable
    pub async fn for_trace(&self, trace_id: &str)                            // stable
        -> Result<Vec<DetectionEvent>, OracleError>;
    pub async fn for_agent_window(&self,                                     // stable
        window_start: DateTime<Utc>, window_end: DateTime<Utc>,
        detector_filter: Option<&[String]>)
        -> Result<AgentScoreAggregate, OracleError>;
    pub async fn detector_history(&self,                                     // stable
        detector: &str, since: DateTime<Utc>,
        min_severity: DetectionSeverity)
        -> Result<Vec<DetectionEvent>, OracleError>;
}

pub struct AgentScoreAggregate { /* … */ }                                   // stable
pub struct SeverityDistribution { /* … */ }                                  // stable
pub fn compute_aggregate(...) -> AgentScoreAggregate;                        // stable
```

### `RetentionPolicy` + the eviction primitives

```rust
// src/config/retention.rs + src/retention/eviction.rs
#[non_exhaustive]
pub struct RetentionPolicy {                                                 // stable
    pub max_disk_gb: Option<u64>,
    pub max_age_days: Option<u32>,
    pub per_level_max_age: Option<HashMap<TraceLevel, u32>>,
    pub detection_events_max_age_days: Option<u32>,
    pub audit_log_max_age_days: Option<u32>,
}

pub struct EvictionPlan { /* … */ }                                          // stable
pub struct EvictionSummary { /* … */ }                                       // stable
pub fn plan_eviction(...) -> EvictionPlan;                                   // stable
pub async fn execute_plan(...) -> Result<EvictionSummary, EvictionError>;    // stable
pub async fn evict_per_retention_policy(...)                                 // stable
    -> Result<EvictionSummary, EvictionError>;
```

`RetentionPolicy` is `#[non_exhaustive]`. Adding fields is a
minor-version operation; v0.4 → v0.5 will not add fields in this
struct in any case (the deferred enforcement is documented in
`docs/RELEASE_NOTES.md`).

### `UpstreamLens` / `EgressFilter` — pan-mode config

```rust
// src/config/upstream.rs + src/config/egress.rs
#[non_exhaustive]
pub struct UpstreamLens {                                                    // stable
    pub lens_steward_key_id: String,
    pub egress_filter: EgressFilter,
}

#[non_exhaustive]
pub struct EgressFilter {                                                    // stable
    pub trace_level: TraceLevel,
    // v0.4 — CIRISLensCore#14 will add: min_severity,
    //   include_detection_events, include_scores,
    //   redact_user_prompts, redact_completions
}
```

v0.4 extends `EgressFilter` with five behaviors. The struct is
`#[non_exhaustive]` so additions are minor-version operations;
existing `EgressFilter::new(level)` calls keep working.

---

## CEG §5.5 typed primitives — load-bearing invariants

These types encode CEG-spec invariants at the type-system level
rather than as runtime validation. The construction-time invariants
are part of the contract — anyone relying on lens-core's CEG
primitives gets the invariant for free.

### `CoherenceRatchetDetector` — CEG §5.5.1

```rust
// src/detector/coherence_ratchet.rs
#[non_exhaustive]
pub enum CoherenceRatchetDetector {                                          // stable-frozen
    CrossAgentDivergence,
    IntraAgentConsistency,
    HashChainIntegrity,
    TemporalDrift,
    ConscienceOverrideRate,
}

impl CoherenceRatchetDetector {
    pub const fn dimension_label(&self) -> &'static str;                     // stable-frozen
    pub const ALL: [Self; 5];                                                // stable
}
```

`dimension_label()` mappings are `stable-frozen` — every variant's
return string is the wire-stable `detection:*` dimension label
federation peers join on. A rename is a substrate-MAJOR break (not
just lens-core major). The `wire_label_exactness` test locks them.

### `CapacityAttestation` — CEG §7.5 anti-Goodhart

```rust
// src/capacity/attestation.rs
pub struct CapacityAttestation {                                             // stable-frozen
    pub attesting_key_id: String,
    pub attested_key_id: String,
}

impl CapacityAttestation {
    pub fn new(attesting: impl Into<String>, attested: impl Into<String>)    // stable-frozen
        -> Result<Self, AntiGoodhartViolation>;
}

pub enum AntiGoodhartViolation {                                             // stable
    SelfAttestation { key_id: String },
}
```

`CapacityAttestation::new` is `stable-frozen`: returning
`Err(AntiGoodhartViolation::SelfAttestation)` when
`attesting == attested` is the *type* contract, not a validation
hook. Implementations must preserve this invariant; `Deserialize`
re-validates so wire bytes can't bypass.

### `CapacityFactors` — CEG §5.5.4 𝒞_CIRIS composite

```rust
// src/capacity/score.rs
pub struct CapacityFactors {                                                 // stable-frozen
    pub core_identity: f64,
    pub integrity: f64,
    pub resilience: f64,
    pub incompleteness_awareness: f64,
    pub sustained_coherence: f64,
}

impl CapacityFactors {
    pub fn new(c: f64, i_int: f64, r: f64, i_inc: f64, s: f64)               // stable-frozen
        -> Result<Self, CapacityFactorError>;
    pub fn composite(&self) -> f64;                                          // stable-frozen
}
```

The multiplicative composite (𝒞_CIRIS = C·I_int·R·I_inc·S) is
`stable-frozen` — switching to an additive or weighted-average
form would silently invalidate every existing detection event that
included a capacity composite. Locked by spec (CEG §5.5.4) + the
`any_zero_zeros_composite_per_ceg_design` test.

---

## `crate::wire::*` — federation-public ABI

The `wire` module re-exports persist's federation-public types under
a single stable path. **Every type here is `stable-frozen`** — they
cross the wire to federation peers parsing canonical-JSON bytes;
renames or shape changes break the federation at the protocol
level, not just at lens-core's source level.

```rust
// src/wire/mod.rs

// from ciris_persist::schema::envelope
pub use BatchEnvelope;                                                       // stable-frozen
pub use BatchEvent;                                                          // stable-frozen
pub use CorrelationMetadata;                                                 // stable-frozen
pub use TraceLevel;                                                          // stable-frozen

// from ciris_persist::schema::trace
pub use CompleteTrace;                                                       // stable-frozen
pub use DeploymentProfile;                                                   // stable-frozen
pub use TraceComponent;                                                      // stable-frozen

// from ciris_persist::schema::events
pub use AuditAnchor;                                                         // stable-frozen
pub use ComponentType;                                                       // stable-frozen
pub use CostSummary;                                                         // stable-frozen
pub use LlmCallStatus;                                                       // stable-frozen
pub use LlmCallSummary;                                                      // stable-frozen
pub use ReasoningEventType;                                                  // stable-frozen

// from ciris_persist::federation::goal (CIRISPersist#114)
pub use DeliberationRef;                                                     // stable-frozen
pub use Goal;                                                                // stable-frozen
pub use GoalScope;                                                           // stable-frozen
pub use GoalsFilter;                                                         // stable
pub use M1Dimension;                                                         // stable-frozen
pub use MetaGoalAlignment;                                                   // stable-frozen
```

`GoalsFilter` is `stable` (not `-frozen`) because it's a query-time
filter — adding fields is additive and doesn't change wire bytes.

### Compile-time enforcement — `re_export_accessibility`

`src/wire/mod.rs` contains a `re_export_accessibility` test that
declares dummy functions accepting `&BatchEnvelope`, `&Goal`,
`&MetaGoalAlignment`, etc. Any persist relocation that breaks one
of the re-exports breaks this test with a precise compiler error
pointing at the moved type — the contract drift is caught at PR
time, not after a federation peer fails to parse bytes.

---

## PyO3 surface

The `ciris_lens_core` Python module:

```python
import ciris_lens_core
```

Top-level functions:

| Function                                  | Tier            | Notes |
|---                                        |---              |---    |
| `process_trace_batch(engine, events, …)`  | stable          | v0.1.1 drop-in for the deployed lens; orchestrates the science layer over a batch |
| `scrub_trace(trace_json, level)`          | stable          | Delegates to `ciris_persist.pipeline.scrub.scrub_trace`; returns scrubbed JSON |
| `scrub_traces_batch(traces_json, level)`  | stable          | Batch form of `scrub_trace` |
| `ner_is_configured() -> bool`             | stable          | Whether persist's scrubber has NER backend configured |
| `install_relay(edge)`                     | **stable-frozen** | v0.2.0 cohabitation bootstrap; agent post-fold + post-cutover both call this |

Module attributes:

| Attribute            | Tier   | Notes |
|---                   |---     |---    |
| `PROJECTION_VERSION` | stable | Currently `"crc-v1"`; v0.5 may bump to `"crc-v2"` after RATCHET calibration ships |

`install_relay` is `stable-frozen` because every cohabitation agent
in production after v1.0 calls it. The signature is locked:
`install_relay(edge: ciris_edge.Edge) -> None`.

---

## Semver discipline

Pre-1.0 (current — v0.X.Y):

- **major (0.X.0 → 0.(X+1).0):** new feature surface; pre-1.0
  callers may need source changes. Examples: v0.1.1 → v0.2.0 added
  `install_relay` cohabitation entry.
- **minor (0.X.Y → 0.X.(Y+1)):** bug fix, CI fix, doc-only,
  CIRISConformance-tracked pin bump that doesn't change lens-core's
  surface.
- **breaking (0.X.* → 0.(X+1).0):** wire-contract changes, removed
  PyO3 functions, persist-pin majors that cascade through the
  lens-core surface (e.g. signer API shift LocalSigner →
  HardwareSigner).

Post-1.0 (CIRISLensCore#18 wire-contract freeze):

- **major (X.Y.Z → (X+1).0.0):** removal or shape change of any
  `stable-frozen` item. Requires coordinated federation cutover.
- **minor (X.Y.Z → X.(Y+1).0):** new functionality compatible with
  the contract; additions to `#[non_exhaustive]` structs/enums;
  new PyO3 functions.
- **patch (X.Y.Z → X.Y.(Z+1)):** bug fixes that don't change the
  surface; CI fixes; documentation; CIRISConformance-tracked pin
  bumps.

The post-1.0 ship gate is CIRISLensCore#18 — the wire-contract
freeze that promotes every `stable` item to `stable-frozen`.

---

## CIRISConformance harness participation

Lens-core's contract is verified against the federation's
[cross-artifact conformance harness](https://github.com/CIRISAI/CIRISConformance)
at the matrix level — every cohabitation triple bump in
CIRISConformance re-runs the harness against lens-core's pinned
artifact. The harness's `requires_lens` pytest mark gates the
suite to deployments where lens-core is installed; once the harness
entry lands (per the spike's Phase 0c deliverable), CIRISConformance
becomes the authoritative verification surface for this contract.

---

## References

- [CIRISPersist `docs/PUBLIC_SCHEMA_CONTRACT.md`](https://github.com/CIRISAI/CIRISPersist/blob/main/docs/PUBLIC_SCHEMA_CONTRACT.md)
  — sister contract for the SQL schema
- [CIRISLensCore#18](https://github.com/CIRISAI/CIRISLensCore/issues/18)
  — v0.5 wire-contract freeze (ships the `stable` → `stable-frozen`
  promotion)
- [`docs/RELEASE_NOTES.md`](RELEASE_NOTES.md) — what shipped when
- [`docs/COHABITATION.md`](COHABITATION.md) — the install paths
  whose signatures this contract locks
- [`Cargo.toml`](../Cargo.toml) — current cohabitation triple pin
- [CIRISConformance](https://github.com/CIRISAI/CIRISConformance)
  — the cross-artifact harness this contract is verified against
