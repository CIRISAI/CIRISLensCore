//! `canonicalize` — `crate::wire::canonical_bytes(&BatchEnvelope)` over a
//! synthesized envelope, swept geometrically across body size
//! (docs/BENCHMARKS.md).
//!
//! Lens-core's signing hot path canonicalizes the envelope once per
//! detection event; the throughput here is what bounds the
//! `sign_detection` curve at the bottom (canonicalization → hash →
//! sign).
//!
//! # Expected curve (per BENCHMARKS.md "Reading the curves")
//!
//! Linear in body size — persist's canonicalizer writes `RawValue`
//! bytes verbatim plus a fixed-size domain-separated frame. Non-linear
//! ⇒ canonicalization started re-serializing the body (AV-5
//! regression, CIRISPersist#7 trap).

#![allow(
    clippy::pedantic,
    clippy::needless_pass_by_value,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::items_after_statements,
    clippy::needless_raw_string_hashes
)]

use ciris_lens_core::wire::{canonical_bytes, BatchEnvelope};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

/// Build a `BatchEnvelope` whose batch body is a JSON object of
/// approximately the requested byte size. We deserialize from JSON
/// rather than construct field-by-field because `BatchEnvelope`'s
/// schema fields move across persist minor versions; the canonical
/// path doesn't care about semantic, only bytes.
fn make_envelope(body_size: usize) -> BatchEnvelope {
    // Surrounding envelope JSON adds ≈ 250 bytes; subtract for the
    // payload filler to land near the requested total size.
    let payload_size = body_size.saturating_sub(250);
    let filler = "x".repeat(payload_size);

    // Minimal-but-valid envelope shape. The body's `events` array
    // holds one entry with a `correlation_metadata` block large
    // enough to dominate the byte count.
    let envelope_json = format!(
        r#"{{
            "schema_version": "2.7.9",
            "batch_id": "bench-batch-{body_size}",
            "agent_id_hash": "bench-agent",
            "agent_name": "bench",
            "trace_id": "bench-trace",
            "batch_sent_at": "2026-06-05T12:00:00Z",
            "events": [{{
                "trace_id": "bench-trace",
                "thought_id": "bench-thought",
                "task_id": null,
                "step_point": "STEP_START",
                "event_type": "THOUGHT_START",
                "attempt_index": 0,
                "ts": "2026-06-05T12:00:00Z",
                "cognitive_state": "wakeup",
                "trace_level": "generic",
                "payload": {{ "filler": "{filler}" }},
                "cost": {{ "llm_calls": 0, "tokens": 0, "usd": 0.0 }}
            }}],
            "signature": "",
            "signing_key_id": "bench-sender",
            "signature_pqc": null
        }}"#
    );

    serde_json::from_str(&envelope_json).expect("bench fixture must be a valid BatchEnvelope")
}

fn bench_canonicalize(c: &mut Criterion) {
    // Sweep body size geometrically — same shape persist + edge bench
    // their canonical paths against. Picks up linearity violations
    // visually across the curve, not from a single fixed-size sample.
    let sizes = [256usize, 1_024, 4_096, 16_384, 65_536, 262_144];
    let mut group = c.benchmark_group("canonicalize");
    for size in sizes {
        let envelope = make_envelope(size);
        // Account each iteration as the *envelope bytes processed*.
        // criterion's Throughput::Bytes lets the report give MB/s.
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &envelope, |b, env| {
            b.iter(|| canonical_bytes(black_box(env)))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_canonicalize);
criterion_main!(benches);
