//! Trace sealing — canonical signing-bytes construction for a sealed
//! [`CompleteTrace`] (CIRISLensCore#11 Cut 3).
//!
//! # The signature-critical contract
//!
//! When `ACTION_RESULT` seals a trace, lens-core canonicalizes it,
//! signs the canonical bytes (Ed25519 + ML-DSA-65 hybrid via the host
//! `Engine`), and persists it. The **canonical bytes must be
//! byte-identical** to what every federation verifier recomputes, or
//! the signature fails to verify. This module owns the canonical-
//! envelope *structure*; the byte serialization is delegated to
//! persist's `canonicalize_envelope_for_signing` — which canonicalizes
//! the trace-signing path with `PythonJsonDumpsCanonicalizer`
//! (`json.dumps(sort_keys=True, separators=(",",":"))`), byte-identical
//! to CIRISAgent's `_build_canonical_message`. (The JCS/RFC-8785
//! canonicalizer persist gained in v4.6.0 is for the *attestation*
//! promote path, a different surface; trace signing stays on
//! json.dumps.) Lens-core never re-implements canonicalization rules
//! (MISSION.md boundary; the CIRISPersist#7 lesson).
//!
//! # The 9(+1)-field canonical (FSD/TRACE_WIRE_FORMAT.md §8, post-
//! CIRISAgent#710)
//!
//! ```text
//! {
//!   trace_id, thought_id, task_id, agent_id_hash,
//!   started_at, completed_at, trace_level, trace_schema_version,
//!   components: [ strip_empty({agent_id_hash, component_type, data,
//!                              event_type, timestamp}), … ],
//!   deployment_profile?   // 2.7.9+ cohort block, present iff set
//! }
//! ```
//!
//! `strip_empty` (recursive) drops `null` / `""` / `[]` / `{}` — but
//! **keeps `0` and `false`** (valid values, CIRISAgent
//! `_strip_empty`). The per-component `agent_id_hash` is denormalized
//! from the trace envelope (2.7.9 / CIRISAgent#712 item 1).
//!
//! # Not in this cut
//!
//! The async sign + persist wrapper (`engine.local_sign` /
//! `local_pqc_sign` → `receive_and_persist`) is the Engine-coupled
//! follow-on; it reuses `crate::signing::event`'s hybrid machinery.
//! This module is the pure, signature-critical canonical-bytes core.

use serde_json::{json, Map, Value};

use super::partial::CompleteTrace;

/// Recursively strip `null` / `""` / `[]` / `{}` from a JSON value,
/// matching CIRISAgent's `_strip_empty`. **`0` and `false` are kept** —
/// they are valid values, not "empty". Object keys whose stripped value
/// is empty are dropped; array elements that are `null` are dropped
/// (other empties survive inside arrays, mirroring the Python which only
/// filters `None` from lists).
pub fn strip_empty(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                let stripped = strip_empty(v);
                if !is_empty(&stripped) {
                    out.insert(k, stripped);
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(
            arr.into_iter()
                .filter(|v| !v.is_null())
                .map(strip_empty)
                .collect(),
        ),
        other => other,
    }
}

/// Is this value one of the four "empty" forms the agent strips
/// (`null` / `""` / `[]` / `{}`)? Numbers (incl. `0`) and booleans
/// (incl. `false`) are never empty.
fn is_empty(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    }
}

/// Build the canonical signing envelope for a sealed trace. Pure — no
/// Engine, no I/O. The returned [`Value`] is handed to persist's
/// `canonicalize_envelope_for_signing` (see [`canonical_bytes`]) for the
/// bytes; this function owns only the *shape*.
///
/// `task_id` / `completed_at` are emitted as JSON `null` when absent
/// (they are top-level envelope fields the verifier expects present;
/// `strip_empty` applies to the per-component payload, NOT the nine
/// top-level keys — matching the agent's `_build_canonical_message`
/// which strips only inside `components`).
pub fn build_canonical_envelope(trace: &CompleteTrace) -> Value {
    let components: Vec<Value> = trace
        .components
        .iter()
        .map(|c| {
            // Per-component 5-field shape, then strip_empty (so an empty
            // `data` / blank field drops out of the signed bytes exactly
            // as the agent emits).
            let agent_id_hash = if c.agent_id_hash.is_empty() {
                trace.agent_id_hash.clone()
            } else {
                c.agent_id_hash.clone()
            };
            strip_empty(json!({
                "agent_id_hash": agent_id_hash,
                "component_type": c.component_type.as_wire_str(),
                "data": c.data,
                "event_type": c.event_type.as_wire_str(),
                "timestamp": c.timestamp,
            }))
        })
        .collect();

    let mut envelope = Map::new();
    envelope.insert("trace_id".into(), json!(trace.trace_id));
    envelope.insert("thought_id".into(), json!(trace.thought_id));
    envelope.insert("task_id".into(), json!(trace.task_id)); // null when None
    envelope.insert("agent_id_hash".into(), json!(trace.agent_id_hash));
    envelope.insert("started_at".into(), json!(trace.started_at));
    envelope.insert("completed_at".into(), json!(trace.completed_at)); // null when unsealed
    envelope.insert("trace_level".into(), json!(trace.trace_level));
    envelope.insert(
        "trace_schema_version".into(),
        json!(trace.trace_schema_version),
    );
    envelope.insert("components".into(), Value::Array(components));
    // deployment_profile is present in the signed bytes iff the trace
    // carries it (2.7.9 cohort block; absent at 2.7.0).
    if let Some(dp) = &trace.deployment_profile {
        envelope.insert("deployment_profile".into(), dp.clone());
    }
    Value::Object(envelope)
}

/// Canonical signing bytes for a sealed trace: build the envelope, then
/// delegate to persist's `canonicalize_envelope_for_signing` — the
/// federation-wide canonicalization authority. Persist canonicalizes the
/// trace-signing path with `PythonJsonDumpsCanonicalizer`
/// (`json.dumps(sort_keys=True, separators=(",",":"))`), so these bytes
/// are byte-identical to what CIRISAgent's `_build_canonical_message`
/// produces and what every federation verifier recomputes. Lens-core
/// signs over exactly these bytes; it never re-implements the rules.
/// The error is stringified (matching `crate::signing::event`'s
/// handling) to avoid coupling to persist's internal error enum.
pub fn canonical_bytes(trace: &CompleteTrace) -> Result<Vec<u8>, String> {
    let envelope = build_canonical_envelope(trace);
    ciris_persist::prelude::canonicalize_envelope_for_signing(&envelope)
        .map_err(|e| format!("canonicalize trace: {e}"))
}

// ── Signature application + verification ────────────────────────────
//
// Trace signing is **Ed25519-only** over the canonical bytes (NOT a
// hybrid Ed25519+ML-DSA pair — that is the detection-event / attestation
// surface). The signature is stored URL-safe-base64-no-pad, the
// `signature_key_id` names the signing key. This mirrors CIRISAgent's
// `Ed25519TraceSigner.sign_trace` (`unified_key.sign_base64(message)`) +
// `verify_trace` (`Ed25519.verify(sig, message)`) exactly, so a trace
// lens-core seals verifies under the agent's verify path and vice-versa.

/// Encode an Ed25519 signature for the `CompleteTrace.signature` field:
/// URL-safe base64, no padding — the form CIRISAgent's `verify_trace`
/// decodes (it re-appends `==` before `urlsafe_b64decode`).
pub fn encode_signature(sig_bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig_bytes)
}

/// Stamp a computed signature onto a sealed trace. Pure — the caller
/// (the Engine-coupled `sign_trace`, Cut 3b glue) obtains `sig_bytes`
/// from `engine.local_sign(canonical_bytes(trace))` and the host's
/// signing `key_id`.
pub fn apply_signature(trace: &mut CompleteTrace, sig_bytes: &[u8], key_id: &str) {
    trace.signature = Some(encode_signature(sig_bytes));
    trace.signature_key_id = Some(key_id.to_string());
}

/// Verify a sealed trace's Ed25519 signature against `verifying_key`,
/// recomputing the canonical bytes (sign/verify can never drift — both
/// go through [`canonical_bytes`]). Returns `false` on any failure
/// (missing/garbled signature, canonicalization error, bad signature) —
/// the same fail-closed shape as CIRISAgent's `verify_trace`. This is
/// the federation-verifier algorithm; a trace lens-core seals must pass
/// it under the producer's public key.
pub fn verify_trace_signature(
    trace: &CompleteTrace,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> bool {
    use base64::Engine as _;
    use ed25519_dalek::Verifier;

    let Some(sig_b64) = &trace.signature else {
        return false;
    };
    let Ok(sig_raw) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig_b64) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_raw.as_slice()) else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
    let Ok(message) = canonical_bytes(trace) else {
        return false;
    };
    verifying_key.verify(&message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::event::{ComponentType, ReasoningEventType};
    use crate::capture::partial::{CompleteTrace, TraceComponent, TRACE_SCHEMA_VERSION};

    fn component(
        event_type: ReasoningEventType,
        ct: ComponentType,
        ts: &str,
        data: Value,
    ) -> TraceComponent {
        TraceComponent {
            component_type: ct,
            event_type,
            timestamp: ts.into(),
            attempt_index: 0,
            data,
            agent_id_hash: "agenthash".into(),
        }
    }

    fn sealed_trace() -> CompleteTrace {
        CompleteTrace {
            trace_id: "trace-1".into(),
            thought_id: "t1".into(),
            task_id: Some("task-1".into()),
            agent_id_hash: "agenthash".into(),
            started_at: "2026-06-08T00:00:00Z".into(),
            completed_at: Some("2026-06-08T00:00:02Z".into()),
            components: vec![
                component(
                    ReasoningEventType::ThoughtStart,
                    ComponentType::Observation,
                    "2026-06-08T00:00:00Z",
                    json!({"thought": "hi"}),
                ),
                component(
                    ReasoningEventType::ActionResult,
                    ComponentType::Action,
                    "2026-06-08T00:00:02Z",
                    json!({"action": "SPEAK"}),
                ),
            ],
            signature: None,
            signature_key_id: None,
            trace_level: Some("FULL_TRACES".into()),
            trace_schema_version: TRACE_SCHEMA_VERSION.into(),
            deployment_profile: None,
        }
    }

    #[test]
    fn strip_empty_keeps_zero_and_false() {
        // The load-bearing subtlety: 0 and false are NOT empty.
        let v = json!({"a": 0, "b": false, "c": null, "d": "", "e": [], "f": {}, "g": "x"});
        let stripped = strip_empty(v);
        assert_eq!(stripped, json!({"a": 0, "b": false, "g": "x"}));
    }

    #[test]
    fn strip_empty_is_recursive() {
        let v = json!({"outer": {"keep": 1, "drop": "", "nested": {"empty": null}}});
        // inner `nested` becomes {} after its only key drops → then drops itself.
        assert_eq!(strip_empty(v), json!({"outer": {"keep": 1}}));
    }

    #[test]
    fn strip_empty_filters_null_from_arrays() {
        let v = json!({"xs": [1, null, 2, "", 0]});
        // Only null is filtered from arrays (matching the Python list comp);
        // "" and 0 survive inside the array.
        assert_eq!(strip_empty(v), json!({"xs": [1, 2, "", 0]}));
    }

    #[test]
    fn envelope_has_nine_top_level_fields_no_deployment_profile() {
        let env = build_canonical_envelope(&sealed_trace());
        let obj = env.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "agent_id_hash",
                "completed_at",
                "components",
                "started_at",
                "task_id",
                "thought_id",
                "trace_id",
                "trace_level",
                "trace_schema_version",
            ]
        );
    }

    #[test]
    fn deployment_profile_present_iff_set() {
        let mut t = sealed_trace();
        assert!(build_canonical_envelope(&t)
            .get("deployment_profile")
            .is_none());
        t.deployment_profile = Some(json!({"agent_role": "scout"}));
        assert_eq!(
            build_canonical_envelope(&t)["deployment_profile"],
            json!({"agent_role": "scout"})
        );
    }

    #[test]
    fn component_carries_five_field_shape_and_wire_strings() {
        let env = build_canonical_envelope(&sealed_trace());
        let comp0 = &env["components"][0];
        // component_type + event_type are the WIRE strings, not enum debug.
        assert_eq!(comp0["component_type"], "observation");
        assert_eq!(comp0["event_type"], "THOUGHT_START");
        assert_eq!(comp0["agent_id_hash"], "agenthash");
        assert_eq!(comp0["timestamp"], "2026-06-08T00:00:00Z");
        assert_eq!(comp0["data"], json!({"thought": "hi"}));
    }

    #[test]
    fn component_agent_id_hash_falls_back_to_trace() {
        let mut t = sealed_trace();
        t.components[0].agent_id_hash = String::new(); // blank → denormalize from trace
        let env = build_canonical_envelope(&t);
        assert_eq!(env["components"][0]["agent_id_hash"], "agenthash");
    }

    #[test]
    fn task_id_and_completed_at_null_when_absent() {
        let mut t = sealed_trace();
        t.task_id = None;
        t.completed_at = None;
        let env = build_canonical_envelope(&t);
        // Top-level fields stay present as null (strip_empty applies only
        // inside components) — the verifier expects all nine keys.
        assert!(env.get("task_id").is_some());
        assert_eq!(env["task_id"], Value::Null);
        assert_eq!(env["completed_at"], Value::Null);
    }

    #[test]
    fn canonical_bytes_are_byte_exact_sorted_compact() {
        // Signature-critical: the bytes persist's canonicalizer produces
        // (JCS / RFC 8785) MUST equal the agent's
        // json.dumps(sort_keys=True, separators=(",",":")) for string
        // data. A minimal fixture lets us assert the exact bytes.
        let t = CompleteTrace {
            trace_id: "tr".into(),
            thought_id: "th".into(),
            task_id: None,
            agent_id_hash: "ah".into(),
            started_at: "2026-06-08T00:00:00Z".into(),
            completed_at: Some("2026-06-08T00:00:01Z".into()),
            components: vec![TraceComponent {
                component_type: ComponentType::Action,
                event_type: ReasoningEventType::ActionResult,
                timestamp: "2026-06-08T00:00:01Z".into(),
                attempt_index: 0,
                data: json!({"k": "v"}),
                // Equal to the trace's hash (FSD §712: agents MUST emit equal).
                agent_id_hash: "ah".into(),
            }],
            signature: None,
            signature_key_id: None,
            trace_level: Some("GENERIC".into()),
            trace_schema_version: "2.7.9".into(),
            deployment_profile: None,
        };
        let bytes = canonical_bytes(&t).expect("canonicalize");
        let got = String::from_utf8(bytes).unwrap();
        // Sorted keys, compact separators. components sorted-keys-per-object.
        let expected = concat!(
            r#"{"agent_id_hash":"ah","completed_at":"2026-06-08T00:00:01Z","#,
            r#""components":[{"agent_id_hash":"ah","component_type":"action","#,
            r#""data":{"k":"v"},"event_type":"ACTION_RESULT","#,
            r#""timestamp":"2026-06-08T00:00:01Z"}],"started_at":"2026-06-08T00:00:00Z","#,
            r#""task_id":null,"thought_id":"th","trace_id":"tr","#,
            r#""trace_level":"GENERIC","trace_schema_version":"2.7.9"}"#
        );
        assert_eq!(got, expected);
    }

    #[test]
    fn encode_signature_is_urlsafe_no_pad() {
        // 64-byte Ed25519 sig → 86-char URL-safe base64, no '=' padding,
        // no '+'/'/' (the form the agent's verify_trace decodes).
        let sig = [0xFBu8; 64];
        let enc = encode_signature(&sig);
        assert_eq!(enc.len(), 86);
        assert!(!enc.contains('='));
        assert!(!enc.contains('+') && !enc.contains('/'));
    }

    #[test]
    fn sign_verify_round_trip_matches_agent_algorithm() {
        // The signature-critical end-to-end proof, no Engine needed:
        // Ed25519-sign canonical_bytes, stamp via apply_signature, and
        // verify_trace_signature (recompute canonical + Ed25519-verify)
        // passes — exactly CIRISAgent's sign_trace/verify_trace pair.
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[7u8; 32]); // deterministic, no rng
        let vk = sk.verifying_key();

        let mut t = sealed_trace();
        let msg = canonical_bytes(&t).expect("canonicalize");
        let sig = sk.sign(&msg);
        apply_signature(&mut t, &sig.to_bytes(), "agent-unified-key");

        assert_eq!(t.signature_key_id.as_deref(), Some("agent-unified-key"));
        assert!(
            verify_trace_signature(&t, &vk),
            "freshly signed trace must verify"
        );
    }

    #[test]
    fn tampering_any_signed_field_invalidates() {
        // Mutating ANY canonical field after signing must break verify —
        // that's the whole point of binding provenance into the bytes.
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let vk = sk.verifying_key();

        let mut t = sealed_trace();
        let sig = sk.sign(&canonical_bytes(&t).unwrap());
        apply_signature(&mut t, &sig.to_bytes(), "k");
        assert!(verify_trace_signature(&t, &vk));

        // Tamper the trace_id (a top-level signed field).
        let mut tampered = t.clone();
        tampered.trace_id = "swapped".into();
        assert!(!verify_trace_signature(&tampered, &vk));

        // Tamper a component's data (inside the signed components array).
        let mut tampered2 = t.clone();
        tampered2.components[0].data = json!({"thought": "EVIL"});
        assert!(!verify_trace_signature(&tampered2, &vk));

        // Wrong key fails too.
        let other = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        assert!(!verify_trace_signature(&t, &other));
    }

    #[test]
    fn verify_fails_closed_on_missing_or_garbled_signature() {
        use ed25519_dalek::SigningKey;
        let vk = SigningKey::from_bytes(&[3u8; 32]).verifying_key();
        let mut t = sealed_trace();
        // No signature → false (not a panic).
        assert!(!verify_trace_signature(&t, &vk));
        // Non-base64 garbage → false.
        t.signature = Some("!!!not base64!!!".into());
        assert!(!verify_trace_signature(&t, &vk));
        // Right base64 but wrong length → false.
        t.signature = Some(encode_signature(&[0u8; 10]));
        assert!(!verify_trace_signature(&t, &vk));
    }
}
