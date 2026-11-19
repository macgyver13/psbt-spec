//! PSBT_OUT_DNSSEC_PROOF syntax and GEN-DNS-1 using the published BIP353 proofs,
//! each wrapped in a local PSBT.
mod common;

use common::{encode, field, hex, status};
use psbt_spec::algebra::TraceStatus;
use psbt_spec::context::*;
use psbt_spec::encoding::Psbt;
use serde_json::Value;

fn with_proof(value: Vec<u8>) -> Vec<u8> {
    encode(&Psbt {
        maps: vec![
            vec![
                field(GLOBAL_VERSION, vec![], 2u32.to_le_bytes().to_vec()),
                field(GLOBAL_TX_VERSION, vec![], 2u32.to_le_bytes().to_vec()),
                field(GLOBAL_INPUT_COUNT, vec![], vec![0]),
                field(GLOBAL_OUTPUT_COUNT, vec![], vec![1]),
            ],
            vec![
                field(OUT_AMOUNT, vec![], 50_000i64.to_le_bytes().to_vec()),
                field(OUT_SCRIPT, vec![], vec![0x51]),
                field(0x35, vec![], value),
            ],
        ],
        bips: vec![],
    })
}

fn proofs() -> Vec<Vec<u8>> {
    let proofs: Vec<Value> = serde_json::from_str(include_str!("../../vectors/bip353_proofs.json")).unwrap();
    proofs.iter().map(|p| hex(p["proof_hex"].as_str().unwrap())).collect()
}

#[test]
fn published_proofs() {
    for proof in proofs() {
        let bytes = with_proof(proof);
        assert_eq!(psbt_spec::evaluate(&bytes, &[]).into_verdict(), Ok(()));
        assert_eq!(status(&bytes, "GEN-DNS-1"), TraceStatus::Passed);
    }
}

#[test]
fn name_without_separator_fails() {
    let mut proof = proofs().remove(0);
    let at = proof.iter().position(|&b| b == b'@').unwrap();
    proof[at] = b'.';
    assert_eq!(status(&with_proof(proof), "GEN-DNS-1"), TraceStatus::Failed);
}

#[test]
fn name_longer_than_field_is_a_format_error() {
    let bytes = with_proof(vec![10, b'a', b'@']);
    assert_eq!(psbt_spec::evaluate(&bytes, &[]).into_verdict().err().map(|e| e.rule), Some("GEN-F-5"));
}

// ROLE-S-6: a Signer validating the proof, at an injected time.

/// Noon UTC on 6 and 7 August 2025, the dates BIP353 gives for its proofs.
const AUG_6: u64 = 1_754_481_600;
const AUG_7: u64 = 1_754_568_000;

fn proof_status(proof: Vec<u8>, time: u64, delay: bool) -> psbt_spec::Evaluation {
    psbt_spec::evaluate_dnssec_proofs(&with_proof(proof), &[], time, delay)
}

#[test]
fn published_proofs_validate_on_their_dates() {
    let p = proofs();
    assert_eq!(proof_status(p[0].clone(), AUG_7, false), psbt_spec::Evaluation::Verified, "simple");
    assert_eq!(proof_status(p[1].clone(), AUG_6, false), psbt_spec::Evaluation::Verified, "override");
    assert_eq!(proof_status(p[2].clone(), AUG_6, false), psbt_spec::Evaluation::Verified, "CNAME to another domain");
}

#[test]
fn published_invalid_proofs_fail() {
    let p = proofs();
    let failed = |e: psbt_spec::Evaluation| matches!(e, psbt_spec::Evaluation::Failed(v) if v.rule == "ROLE-S-6");
    assert!(failed(proof_status(p[3].clone(), AUG_7, false)), "two bitcoin: records");
    assert!(failed(proof_status(p[4].clone(), AUG_6, false)), "missing NSEC3");
}

#[test]
fn proof_time_window() {
    let p = proofs();
    let failed = |e: psbt_spec::Evaluation| matches!(e, psbt_spec::Evaluation::Failed(v) if v.rule == "ROLE-S-6");
    // Long before inception, and long after expiry, the proof does not validate.
    assert!(failed(proof_status(p[0].clone(), AUG_7 - 365 * 86_400, false)));
    assert!(failed(proof_status(p[0].clone(), AUG_7 + 365 * 86_400, false)));
    // Without a time the rule cannot run.
    let ctx = psbt_spec::context::PsbtContext::new(&psbt_spec::spec::parse(&with_proof(p[0].clone()), &[]));
    let proof = psbt_spec::rules::dnssec::DnssecProofContext { output: ctx.outputs().remove(0), time: None, allow_construction_delay: false };
    assert!(matches!(psbt_spec::rules::dnssec::validate_dnssec_proof_validation(&proof), psbt_spec::algebra::CheckOutcome::Incomplete(_)));
}

#[test]
fn proof_bip353_rules_and_construction_delay() {
    let p = proofs();
    // The chain is valid; BIP353 refuses two bitcoin: records.
    let detail = match proof_status(p[3].clone(), AUG_7, false) {
        psbt_spec::Evaluation::Failed(v) => v.detail,
        other => panic!("{other:?}"),
    };
    assert!(detail.contains("2 bitcoin: TXT records"), "{detail}");

    // Half an hour after the earliest RRSIG expiry: only with the delay allowance.
    let name_len = p[0][0] as usize;
    let rrs = dnssec_prover::ser::parse_rr_stream(&p[0][1 + name_len..]).unwrap();
    let expires = dnssec_prover::validation::verify_rr_stream(&rrs).unwrap().expires;
    let failed = |e: psbt_spec::Evaluation| matches!(e, psbt_spec::Evaluation::Failed(v) if v.rule == "ROLE-S-6");
    assert_eq!(proof_status(p[0].clone(), expires + 1800, true), psbt_spec::Evaluation::Verified);
    assert!(failed(proof_status(p[0].clone(), expires + 1800, false)));
    assert!(failed(proof_status(p[0].clone(), expires + 7200, true)));
}
