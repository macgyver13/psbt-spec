//! Tests for the rows of `plans/bip373-inventory.md`, by row number, using the
//! published BIP373 vectors and mutations of them (local fixtures).
mod common;

use base64::{engine::general_purpose::STANDARD, Engine};
use common::{encode, field, finalizer_status, status};
use psbt_spec::algebra::TraceStatus;
use psbt_spec::context::*;
use psbt_spec::encoding::{scan, Psbt, Record};
use psbt_spec::{evaluate, evaluate_combining, Evaluation};
use serde_json::Value;

const OUTPUT_KEY: &str = "output key is a MuSig2 Aggregate Pubkey";
const INTERNAL_KEY: &str = "internal key is a MuSig2 Aggregate Pubkey";
const SCRIPT_KEY: &str = "key in a script is a MuSig2 Aggregate Pubkey";
const DERIVED_KEY: &str = "internal key is derived from a MuSig2 Aggregate Pubkey";

/// The published valid vector for `case` at `stage`: "participant pubkeys only",
/// "all pubnonces" or "all partial signatures".
fn vector(case: &str, stage: &str) -> Psbt {
    let vectors: Vec<Value> = serde_json::from_str::<Value>(include_str!("../../vectors/bip373.json")).unwrap()["vectors"].as_array().unwrap().clone();
    let v = vectors
        .iter()
        .filter(|v| v["valid"] == true)
        .find(|v| {
            let d = v["description"].as_str().unwrap();
            d.contains(case) && d.contains(stage)
        })
        .unwrap_or_else(|| panic!("no vector {case} {stage}"));
    let Ok(psbt) = scan(&STANDARD.decode(v["psbt"].as_str().unwrap()).unwrap()) else { panic!() };
    psbt
}

/// The "all partial signatures" vector for `case` without the aggregated
/// signature some of them carry, so the partial signatures are the ones a
/// Finalizer would use.
fn partials_only(case: &str) -> Psbt {
    let mut psbt = vector(case, "all partial signatures");
    psbt.maps[1].retain(|r| r.key_type != IN_TAP_KEY_SIG && r.key_type != IN_TAP_SCRIPT_SIG);
    psbt
}

fn records(psbt: &mut Psbt, key_type: u64) -> impl Iterator<Item = &mut Record> {
    psbt.maps[1].iter_mut().filter(move |r| r.key_type == key_type)
}

fn rule_of(bytes: &[u8]) -> Option<&'static str> {
    evaluate(bytes, &[]).into_verdict().err().map(|e| e.rule)
}

// Rows 4 and 5: nonce and partial-signature encodings.

#[test]
fn row_4_public_nonce_is_two_points() {
    let mut psbt = vector(OUTPUT_KEY, "all pubnonces");
    records(&mut psbt, IN_MUSIG2_PUB_NONCE).next().unwrap().value[1..33].copy_from_slice(&[0xff; 32]);
    assert_eq!(rule_of(&encode(&psbt)), Some("GEN-F-5"));
    assert_eq!(status(&encode(&psbt), "GEN-F-5"), TraceStatus::Failed);
}

#[test]
fn row_5_partial_signature_is_below_the_order() {
    let mut psbt = vector(OUTPUT_KEY, "all partial signatures");
    records(&mut psbt, IN_MUSIG2_PARTIAL_SIG).next().unwrap().value = vec![0xff; 32];
    assert_eq!(rule_of(&encode(&psbt)), Some("GEN-F-5"));
}

// Row 6: GEN-MS-2, KeyAgg of the listed participants.

#[test]
fn row_6_aggregate_key_is_key_agg_of_participants() {
    for case in [OUTPUT_KEY, INTERNAL_KEY, SCRIPT_KEY, DERIVED_KEY] {
        assert_eq!(status(&encode(&vector(case, "participant pubkeys only")), "GEN-MS-2"), TraceStatus::Passed, "{case}");
    }
    // Swapping two participants changes the KeyAgg result.
    let mut psbt = vector(OUTPUT_KEY, "participant pubkeys only");
    let list = &mut records(&mut psbt, IN_MUSIG2_PARTICIPANT_PUBKEYS).next().unwrap().value;
    let first: Vec<u8> = list[..33].to_vec();
    list.copy_within(33..66, 0);
    list[33..66].copy_from_slice(&first);
    assert_eq!(status(&encode(&psbt), "GEN-MS-2"), TraceStatus::Failed);
    // The output field is checked the same way.
    let mut psbt = vector(OUTPUT_KEY, "participant pubkeys only");
    let input = records(&mut psbt, IN_MUSIG2_PARTICIPANT_PUBKEYS).next().unwrap().clone();
    let mut bad = input.clone();
    bad.value.truncate(66);
    psbt.maps.last_mut().unwrap().push(field(OUT_MUSIG2_PARTICIPANT_PUBKEYS, bad.key_data, bad.value));
    assert_eq!(status(&encode(&psbt), "GEN-MS-2"), TraceStatus::Failed);
    // Without the fields the rule does not apply.
    let mut none = vector(OUTPUT_KEY, "participant pubkeys only");
    none.maps[1].retain(|r| r.key_type != IN_MUSIG2_PARTICIPANT_PUBKEYS);
    assert_eq!(status(&encode(&none), "GEN-MS-2"), TraceStatus::NotApplicable);
}

// Rows 14 and 15: ROLE-F-5 verifies partial signatures before aggregation;
// ROLE-F-3 verifies the aggregated Taproot signature.

#[test]
fn row_14_published_partial_signatures_verify() {
    // Each published vector passes: an aggregated signature through ROLE-F-3,
    // partial signatures alone through ROLE-F-5.
    for case in [OUTPUT_KEY, INTERNAL_KEY, SCRIPT_KEY, DERIVED_KEY] {
        let psbt = encode(&vector(case, "all partial signatures"));
        let statuses = [finalizer_status(&psbt, "ROLE-F-3"), finalizer_status(&psbt, "ROLE-F-5")];
        assert!(statuses.iter().all(|s| matches!(s, TraceStatus::Passed | TraceStatus::NotApplicable)), "{case}: {statuses:?}");
        assert!(statuses.contains(&TraceStatus::Passed), "{case}: {statuses:?}");
    }
    // Before aggregation, the partial signatures verify: untweaked, Taproot-tweaked,
    // script path, and an internal key derived from the aggregate key (BIP328).
    for case in [OUTPUT_KEY, INTERNAL_KEY, SCRIPT_KEY, DERIVED_KEY] {
        assert_eq!(finalizer_status(&encode(&partials_only(case)), "ROLE-F-5"), TraceStatus::Passed, "{case}");
    }
}

#[test]
fn row_14_wrong_tweak_or_signature_fails() {
    // A changed partial signature (still below the order) does not verify.
    for case in [INTERNAL_KEY, SCRIPT_KEY, DERIVED_KEY] {
        let mut psbt = partials_only(case);
        records(&mut psbt, IN_MUSIG2_PARTIAL_SIG).next().unwrap().value[31] ^= 1;
        assert_eq!(finalizer_status(&encode(&psbt), "ROLE-F-5"), TraceStatus::Failed, "{case}");
    }
    // A different Merkle root changes the Taproot tweak, so no listed aggregate
    // key produces the plain key.
    let mut psbt = partials_only(INTERNAL_KEY);
    psbt.maps[1].push(field(IN_TAP_MERKLE_ROOT, vec![], vec![7; 32]));
    assert_eq!(finalizer_status(&encode(&psbt), "ROLE-F-5"), TraceStatus::Incomplete);
}

#[test]
fn row_14_incomplete_round() {
    let mut psbt = vector(OUTPUT_KEY, "all partial signatures");
    let missing = records(&mut psbt, IN_MUSIG2_PUB_NONCE).nth(1).unwrap().key_data.clone();
    psbt.maps[1].retain(|r| !(r.key_type == IN_MUSIG2_PUB_NONCE && r.key_data == missing));
    assert_eq!(finalizer_status(&encode(&psbt), "ROLE-F-5"), TraceStatus::Incomplete);
    // Nonces alone: nothing to verify yet.
    assert_eq!(finalizer_status(&encode(&vector(OUTPUT_KEY, "all pubnonces")), "ROLE-F-5"), TraceStatus::NotApplicable);
}

#[test]
fn row_15_aggregated_session_is_not_rechecked() {
    // With an aggregated key-path signature, the partial signatures are not used;
    // ROLE-F-3 checks the aggregated signature instead (here a placeholder, which fails).
    let mut psbt = vector(OUTPUT_KEY, "all partial signatures");
    records(&mut psbt, IN_MUSIG2_PARTIAL_SIG).next().unwrap().value[31] ^= 1;
    psbt.maps[1].push(field(IN_TAP_KEY_SIG, vec![], vec![1; 64]));
    let statuses = common::graph_statuses(
        psbt_spec::algebra::each(|p: &PsbtContext| p.inputs(), psbt_spec::spec::finalizer_obligations()),
        &PsbtContext::new(&psbt),
        "ROLE-F-3",
    );
    assert!(statuses[0].1.contains("Taproot signature does not verify"), "{}", statuses[0].1);
}

// Rows 17 and 18: regression targets.

#[test]
fn row_17_partial_signatures_are_not_signatures() {
    let psbt = vector(OUTPUT_KEY, "all partial signatures");
    let input = PsbtContext::new(&psbt).inputs().remove(0);
    assert!(psbt_spec::silent_payments::input_signatures(&input).is_empty());
}

#[test]
fn row_18_combiner_merges_participant_records() {
    let full = vector(OUTPUT_KEY, "all partial signatures");
    let sigs: Vec<Record> = full.maps[1].iter().filter(|r| r.key_type == IN_MUSIG2_PARTIAL_SIG).cloned().collect();
    let only = |keep: usize| {
        let mut p = full.clone();
        p.maps[1].retain(|r| r.key_type != IN_MUSIG2_PARTIAL_SIG || r.key_data == sigs[keep].key_data);
        encode(&p)
    };
    let (a, b, c) = (only(0), only(1), only(2));
    assert_eq!(evaluate_combining(&[&a, &b, &c], &encode(&full), &[]), Evaluation::Verified);
    assert!(matches!(evaluate_combining(&[&a, &b, &c], &a, &[]), Evaluation::Failed(_)), "dropping a participant's partial signature");
}

#[test]
fn row_14_bip328_derivation_must_match() {
    // Without the derivation record, the derived internal key cannot be related
    // to the aggregate key.
    let mut psbt = partials_only(DERIVED_KEY);
    psbt.maps[1].retain(|r| r.key_type != IN_TAP_BIP32_DERIVATION);
    assert_eq!(finalizer_status(&encode(&psbt), "ROLE-F-5"), TraceStatus::Incomplete);
}

