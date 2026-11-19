//! Helpers for tests that build PSBTs and observe rules through the evaluation graph.
#![allow(dead_code)]

use psbt_spec::algebra::{each, BoxNode, Trace, TraceStatus};
use psbt_spec::encoding::{put_compact_size, Psbt, Record, MAGIC};
use psbt_spec::context::{InputContext, PsbtContext};
use psbt_spec::{FinalizerTransitionContext, SignerTransitionContext};
use psbt_spec::spec;
use base64::{engine::general_purpose::STANDARD, Engine};
use psbt_spec::context::unique_id;
use psbt_spec::encoding::{is_p2sh, is_witness_program};
use psbt_spec::{
    evaluate, evaluate_combining, evaluate_extracting, evaluate_for_finalizing, evaluate_for_signing, Bip,
    Evaluation, SignatureKind,
};
use serde_json::Value;

pub fn field(key_type: u64, key_data: Vec<u8>, value: Vec<u8>) -> Record {
    Record { key_type, key_data, value }
}

pub fn encode(psbt: &Psbt) -> Vec<u8> {
    let mut raw = MAGIC.to_vec();
    for map in &psbt.maps {
        for record in map {
            let mut key = Vec::new();
            put_compact_size(&mut key, record.key_type as usize);
            key.extend(&record.key_data);
            put_compact_size(&mut raw, key.len());
            raw.extend(key);
            put_compact_size(&mut raw, record.value.len());
            raw.extend(&record.value);
        }
        raw.push(0);
    }
    raw
}

pub fn txout(amount: i64, script: &[u8]) -> Vec<u8> {
    let mut bytes = amount.to_le_bytes().to_vec();
    put_compact_size(&mut bytes, script.len());
    bytes.extend(script);
    bytes
}

pub fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// Every status `node` records for `id` on `ctx`.
pub fn graph_statuses<C: ?Sized>(node: BoxNode<C>, ctx: &C, id: &str) -> Vec<(TraceStatus, String)> {
    let mut trace = Trace::default();
    node.evaluate_traced(ctx, &mut trace);
    trace.observations.into_iter().filter(|o| o.id == id).map(|o| (o.status, o.detail)).collect()
}

/// Every status the General rule graph records for `id` on `psbt`.
pub fn statuses(psbt: &[u8], id: &str) -> Vec<(TraceStatus, String)> {
    graph_statuses(spec::general_rules(&[]), psbt, id)
}

fn context(psbt: &[u8]) -> PsbtContext {
    PsbtContext::new(&spec::parse(psbt, &[]))
}

fn inputs(psbt: &PsbtContext) -> Vec<InputContext> {
    psbt.inputs()
}

/// The most significant status of `id` in the Input Finalizer preconditions.
pub fn finalizer_status(psbt: &[u8], id: &str) -> TraceStatus {
    most_significant(id, graph_statuses(each(inputs, spec::finalizer_obligations()), &context(psbt), id))
}

/// The most significant status of `id` in the Input Finalizer obligations on a
/// finalized PSBT.
pub fn finalized_status(psbt: &[u8], id: &str) -> TraceStatus {
    most_significant(id, graph_statuses(each(inputs, spec::finalizer_role_obligations()), &context(psbt), id))
}

/// The most significant status of `id` comparing each input of the PSBT the
/// Finalizer received with the same input of the PSBT it returned.
pub fn finalizing_status(received: &[u8], returned: &[u8], id: &str) -> TraceStatus {
    let pairs: Vec<FinalizerTransitionContext> = context(received)
        .inputs()
        .into_iter()
        .zip(context(returned).inputs())
        .map(|(b, a)| FinalizerTransitionContext::new(b, a))
        .collect();
    let node = each(|p: &Vec<FinalizerTransitionContext>| p.clone(), spec::finalizer_transition_obligations());
    most_significant(id, graph_statuses(node, &pairs, id))
}

/// The most significant status of `id` comparing the PSBT the Signer received
/// with the PSBT it returned.
pub fn signing_status(received: &[u8], returned: &[u8], id: &str) -> TraceStatus {
    let transition = SignerTransitionContext::new(context(received), context(returned));
    most_significant(id, graph_statuses(spec::signer_transition_obligations(), &transition, id))
}

/// The single most significant status of `id`: Failed, then Incomplete, then
/// Passed, then NotApplicable. Panics if the rule was blocked or never reached.
pub fn status(psbt: &[u8], id: &str) -> TraceStatus {
    most_significant(id, statuses(psbt, id))
}

fn most_significant(id: &str, all: Vec<(TraceStatus, String)>) -> TraceStatus {
    for wanted in [TraceStatus::Failed, TraceStatus::Incomplete, TraceStatus::Passed, TraceStatus::NotApplicable] {
        if all.iter().any(|(s, _)| *s == wanted) {
            return wanted;
        }
    }
    panic!("{id} was not evaluated: {all:?}");
}

pub fn vectors(name: &str) -> Vec<Value> {
    let path = format!("{}/../vectors/{name}.json", env!("CARGO_MANIFEST_DIR"));
    let file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    // Schema v1 files wrap the array with `bip_revision`; bip370_locktime is a bare array.
    match file.get("vectors") {
        Some(wrapped) => wrapped.as_array().unwrap().clone(),
        None => file.as_array().unwrap().clone(),
    }
}

pub fn psbt(v: &Value) -> Vec<u8> {
    STANDARD.decode(v["psbt"].as_str().unwrap()).unwrap()
}

pub fn passed(e: &Evaluation) -> bool {
    matches!(e, Evaluation::Verified | Evaluation::NotApplicable)
}

/// Every input as a Signer would sign it, the signature kind inferred from the
/// spent script; the first input that does not pass.
fn for_signing(bytes: &[u8], bips: &[Bip]) -> Evaluation {
    let inputs = PsbtContext::new(&spec::parse(bytes, bips)).inputs();
    inputs
        .iter()
        .map(|input| {
            let witness = match input.spent_output() {
                None => true,
                Some(out) if is_p2sh(&out.script_pubkey) => input.value(0x04).is_some_and(is_witness_program),
                Some(out) => is_witness_program(&out.script_pubkey),
            };
            let kind = if witness { SignatureKind::Witness } else { SignatureKind::NonWitness };
            evaluate_for_signing(bytes, bips, input.index, kind)
        })
        .find(|e| !passed(e))
        .unwrap_or(Evaluation::Verified)
}

/// The vector's outcome under the entry point its `task` names (default:
/// the General rules).
pub fn outcome(v: &Value, bips: &[Bip]) -> Evaluation {
    let bytes = psbt(v);
    match v["task"].as_str().unwrap_or("validity") {
        "validity" => evaluate(&bytes, bips),
        "signing" => for_signing(&bytes, bips),
        "finalizing" => evaluate_for_finalizing(&bytes, bips),
        "extraction" => evaluate_extracting(&bytes, bips),
        "combining" => {
            let sources: Vec<Vec<u8>> =
                v["combine"].as_array().unwrap().iter().map(|p| STANDARD.decode(p.as_str().unwrap()).unwrap()).collect();
            let sources: Vec<&[u8]> = sources.iter().map(Vec::as_slice).collect();
            if let Some(expected) = v["unique_id"].as_str() {
                let id = unique_id(&PsbtContext::new(&spec::parse(&bytes, bips)));
                let hex: String = id.iter().rev().map(|b| format!("{b:02x}")).collect();
                assert_eq!(hex, expected, "{}", v["description"]);
            }
            evaluate_combining(&sources, &bytes, bips)
        }
        other => panic!("unknown task {other}"),
    }
}

/// The BIPs a role vector enables.
pub fn vector_bips(v: &Value) -> Vec<Bip> {
    v["bips"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| match b.as_u64() {
            Some(375) => Bip::Bip375,
            Some(376) => Bip::Bip376,
            other => panic!("unknown BIP {other:?}"),
        })
        .collect()
}
