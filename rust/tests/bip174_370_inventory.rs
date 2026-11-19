//! Tests for the rows of `plans/bip174-370-inventory.md`, by row number, using
//! mutations of the published BIP174 vectors (local fixtures).
mod common;

use base64::{engine::general_purpose::STANDARD, Engine};
use bitcoin_hashes::{hash160, ripemd160, sha256, sha256d, Hash};
use common::{encode, field, finalizer_status, finalizing_status, graph_statuses, signing_status, status, txout};
use k256::schnorr::SigningKey;
use psbt_spec::algebra::{Evaluation, TraceStatus};
use psbt_spec::context::*;
use psbt_spec::encoding::{scan, Psbt, Record};
use psbt_spec::taproot::taproot_sighash;
use psbt_spec::{evaluate, evaluate_finalizing, evaluate_signing, spec, Bip};
use serde_json::Value;

const XPUB_VECTOR: &str = "PSBT with `PSBT_GLOBAL_XPUB`.";

fn vector(needle: &str) -> Psbt {
    let vectors: Vec<Value> = serde_json::from_str::<Value>(include_str!("../../vectors/bip174.json")).unwrap()["vectors"].as_array().unwrap().clone();
    let v = vectors
        .iter()
        .find(|v| v["valid"] == true && v["description"].as_str().unwrap().contains(needle))
        .unwrap_or_else(|| panic!("no vector {needle}"));
    let Ok(psbt) = scan(&STANDARD.decode(v["psbt"].as_str().unwrap()).unwrap()) else { panic!() };
    psbt
}

fn rule_of(bytes: &[u8]) -> Option<&'static str> {
    evaluate(bytes, &[]).into_verdict().err().map(|e| e.rule)
}

// Rows 9 to 12: field encodings.

#[test]
fn row_9_preimages_hash_to_their_key() {
    let preimage = b"preimage".to_vec();
    let cases: [(u64, Vec<u8>); 4] = [
        (0x0a, ripemd160::Hash::hash(&preimage).to_byte_array().to_vec()),
        (0x0b, sha256::Hash::hash(&preimage).to_byte_array().to_vec()),
        (0x0c, hash160::Hash::hash(&preimage).to_byte_array().to_vec()),
        (0x0d, sha256d::Hash::hash(&preimage).to_byte_array().to_vec()),
    ];
    for (key_type, hash) in cases {
        let mut psbt = vector(XPUB_VECTOR);
        psbt.maps[1].push(field(key_type, hash.clone(), preimage.clone()));
        let bytes = encode(&psbt);
        assert_eq!(rule_of(&bytes), None, "{key_type:#04x} matching preimage");
        assert_eq!(status(&bytes, "GEN-F-5"), TraceStatus::Passed);

        let mut psbt = vector(XPUB_VECTOR);
        psbt.maps[1].push(field(key_type, hash, b"other".to_vec()));
        let bytes = encode(&psbt);
        assert_eq!(rule_of(&bytes), Some("GEN-F-5"), "{key_type:#04x} wrong preimage");
        assert_eq!(status(&bytes, "GEN-F-5"), TraceStatus::Failed);
    }
}

#[test]
fn row_10_xpub_path_length_matches_depth() {
    let psbt = vector(XPUB_VECTOR);
    assert_eq!(status(&encode(&psbt), "GEN-F-5"), TraceStatus::Passed);

    let mut psbt = vector(XPUB_VECTOR);
    let xpub = psbt.maps[0].iter_mut().find(|r| r.key_type == 0x01).unwrap();
    xpub.value.extend([0, 0, 0, 0]);
    let bytes = encode(&psbt);
    assert_eq!(rule_of(&bytes), Some("GEN-F-5"));
    assert_eq!(status(&bytes, "GEN-F-5"), TraceStatus::Failed);
}

#[test]
fn row_11_proprietary_keys_have_identifier_and_subtype() {
    // Identifier "id", subtype 1, key data 0xaa.
    let good = vec![0x02, b'i', b'd', 0x01, 0xaa];
    // Identifier length 5 with only two identifier bytes.
    let short = vec![0x05, b'i', b'd'];
    // Subtype 1 encoded non-minimally.
    let wide_subtype = vec![0x02, b'i', b'd', 0xfd, 0x01, 0x00];

    for (map, code) in [(0, "global"), (1, "input"), (2, "output")] {
        let mut psbt = vector(XPUB_VECTOR);
        let map = if map == 2 { psbt.maps.len() - 1 } else { map };
        psbt.maps[map].push(field(0xfc, good.clone(), vec![1]));
        assert_eq!(rule_of(&encode(&psbt)), None, "{code} well-formed");
        for bad in [&short, &wide_subtype] {
            let mut psbt = vector(XPUB_VECTOR);
            psbt.maps[map].push(field(0xfc, bad.clone(), vec![1]));
            assert_eq!(rule_of(&encode(&psbt)), Some("GEN-F-5"), "{code} {bad:02x?}");
        }
    }
}

#[test]
fn row_12_xpub_key_is_on_the_curve() {
    let mut psbt = vector(XPUB_VECTOR);
    let xpub = psbt.maps[0].iter_mut().find(|r| r.key_type == 0x01).unwrap();
    xpub.key_data[46..].copy_from_slice(&[0xff; 32]);
    let bytes = encode(&psbt);
    assert_eq!(rule_of(&bytes), Some("GEN-F-5"));
    assert_eq!(status(&bytes, "GEN-F-5"), TraceStatus::Failed);
}

// Row 44 and the Signer phase fixes: ROLE-S-10 and ROLE-S-11.

const WORKFLOW: &str = "Single-input P2WPKH to silent payment workflow (global-share): ";

fn bip375(step: &str) -> Psbt {
    let vectors: Vec<Value> = serde_json::from_str::<Value>(include_str!("../../vectors/bip375.json")).unwrap()["vectors"].as_array().unwrap().clone();
    let needle = format!("{WORKFLOW}{step}");
    let v = vectors
        .iter()
        .find(|v| v["description"].as_str().unwrap().starts_with(&needle))
        .unwrap_or_else(|| panic!("no vector {needle}"));
    let Ok(mut psbt) = scan(&STANDARD.decode(v["psbt"].as_str().unwrap()).unwrap()) else { panic!() };
    psbt.bips = vec![Bip::Bip375];
    psbt
}

fn updated() -> Psbt {
    bip375("Updater")
}

fn signed() -> Psbt {
    bip375("Signer")
}

fn record(map: &mut [Record], key_type: u64) -> &mut Record {
    map.iter_mut().find(|r| r.key_type == key_type).unwrap()
}

#[test]
fn signer_workflow_passes_through_the_entry_point() {
    let (received, returned) = (encode(&updated()), encode(&signed()));
    assert_eq!(evaluate_signing(&received, &returned, &[Bip::Bip375]), Evaluation::Verified);
    // No signature added: nothing for the added-signature rules to check.
    for id in ["ROLE-S-10", "ROLE-S-11"] {
        assert_eq!(signing_status(&received, &received, id), TraceStatus::NotApplicable, "{id}");
    }
}

#[test]
fn role_s_1_signer_keeps_unknown_fields() {
    // BIP174: unknown types are passed through by signers that do not know them.
    let unknown = field(0xf0, vec![1, 2], vec![3]);
    let with_unknown = |mut psbt: Psbt| {
        psbt.maps[1].push(unknown.clone());
        encode(&psbt)
    };
    let received = with_unknown(updated());
    assert_eq!(signing_status(&received, &with_unknown(signed()), "ROLE-S-9"), TraceStatus::Passed);
    assert_eq!(signing_status(&received, &encode(&signed()), "ROLE-S-9"), TraceStatus::Failed);
}

#[test]
fn row_44_added_signatures_use_the_sighash_type() {
    let with_type = |t: u32| {
        let mut p = updated();
        p.maps[1].push(field(IN_SIGHASH_TYPE, vec![], t.to_le_bytes().to_vec()));
        p
    };
    let returned = |t: u32| {
        let mut p = signed();
        p.maps[1].push(field(IN_SIGHASH_TYPE, vec![], t.to_le_bytes().to_vec()));
        encode(&p)
    };
    // The published signature uses SIGHASH_ALL.
    assert_eq!(signing_status(&encode(&with_type(1)), &returned(1), "ROLE-S-10"), TraceStatus::Passed);
    assert_eq!(signing_status(&encode(&with_type(2)), &returned(2), "ROLE-S-10"), TraceStatus::Failed);
    // Without the field the rule does not apply.
    assert_eq!(signing_status(&encode(&updated()), &encode(&signed()), "ROLE-S-10"), TraceStatus::NotApplicable);
}

// A Signer that leaves a flag, a sighash type or the scripts wrong returns a
// PSBT that fails a General rule, which evaluate_signing reports first.

#[test]
fn signer_duties_are_general_rules() {
    let received = encode(&updated());
    let fails = |returned: &Psbt, rule: &str| {
        matches!(evaluate_signing(&received, &encode(returned), &[Bip::Bip375]), Evaluation::Failed(v) if v.rule == rule)
    };
    // Inputs reopened after a SIGHASH_ALL signature.
    let mut reopened = signed();
    record(&mut reopened.maps[0], GLOBAL_TX_MODIFIABLE).value = vec![0x01];
    assert!(fails(&reopened, "GEN-T-2"));
    // A SIGHASH_NONE signature with silent-payment outputs.
    let mut none = signed();
    *record(&mut none.maps[1], IN_PARTIAL_SIG).value.last_mut().unwrap() = 0x02;
    assert!(fails(&none, "GEN-SP-4"));
    // PSBT_IN_SIGHASH_TYPE other than SIGHASH_ALL with silent-payment outputs.
    let mut typed = updated();
    typed.maps[1].push(field(IN_SIGHASH_TYPE, vec![], 2u32.to_le_bytes().to_vec()));
    assert!(matches!(evaluate(&encode(&typed), &[Bip::Bip375]), Evaluation::Failed(v) if v.rule == "GEN-SP-4"));
    // Scripts set, with the shares they are derived from, while both flags stay set.
    let mut open = updated();
    record(&mut open.maps[0], GLOBAL_TX_MODIFIABLE).value = vec![0x03];
    let signed = signed();
    open.maps[0].extend(signed.maps[0].iter().filter(|r| [GLOBAL_SP_ECDH_SHARE, GLOBAL_SP_DLEQ].contains(&r.key_type)).cloned());
    open.maps[2].extend(signed.maps[2].iter().filter(|r| r.key_type == OUT_SCRIPT).cloned());
    assert!(fails(&open, "GEN-SP-2"));
}

#[test]
fn gen_sp_7_no_signature_while_a_script_is_missing() {
    let mut unscripted = signed();
    unscripted.maps[2].retain(|r| r.key_type != OUT_SCRIPT);
    let got = evaluate_signing(&encode(&updated()), &encode(&unscripted), &[Bip::Bip375]);
    assert!(matches!(got, Evaluation::Failed(v) if v.rule == "GEN-SP-7"));
}

/// A v2 PSBT spending the P2TR output of key [7; 32], with PSBT_IN_SP_TWEAK,
/// and the extra input records given.
fn sp_input(extra: Vec<Record>) -> Psbt {
    let key: [u8; 32] = SigningKey::from_bytes(&[7; 32]).unwrap().verifying_key().to_bytes().into();
    let spk = [&[0x51, 0x20][..], &key].concat();
    let mut input = vec![
        field(IN_PREVIOUS_TXID, vec![], vec![5; 32]),
        field(IN_OUTPUT_INDEX, vec![], 0u32.to_le_bytes().to_vec()),
        field(IN_WITNESS_UTXO, vec![], txout(10_000, &spk)),
        field(IN_SP_TWEAK, vec![], vec![1; 32]),
    ];
    input.extend(extra);
    Psbt {
        maps: vec![
            vec![
                field(GLOBAL_VERSION, vec![], 2u32.to_le_bytes().to_vec()),
                field(GLOBAL_TX_VERSION, vec![], 2u32.to_le_bytes().to_vec()),
                field(GLOBAL_INPUT_COUNT, vec![], vec![1]),
                field(GLOBAL_OUTPUT_COUNT, vec![], vec![1]),
            ],
            input,
            vec![field(OUT_AMOUNT, vec![], 9_000i64.to_le_bytes().to_vec()), field(OUT_SCRIPT, vec![], vec![0x51])],
        ],
        bips: vec![],
    }
}

/// A valid SIGHASH_DEFAULT key-path signature for `sp_input`.
fn sp_signature() -> Vec<u8> {
    let psbt = sp_input(vec![]);
    let ctx = PsbtContext::new(&psbt);
    let digest = taproot_sighash(&signing_tx(&ctx).unwrap(), 0, &spent_outputs(&ctx).unwrap(), 0x00, None, None).unwrap();
    SigningKey::from_bytes(&[7; 32]).unwrap().sign_raw(&digest, &[0; 32]).unwrap().to_bytes().to_vec()
}

#[test]
fn role_s_11_sp_signature_is_a_key_path_signature() {
    let received = encode(&sp_input(vec![]));
    let sig = sp_signature();
    let returned = encode(&sp_input(vec![field(IN_TAP_KEY_SIG, vec![], sig.clone())]));
    assert_eq!(signing_status(&received, &returned, "ROLE-S-11"), TraceStatus::Passed);
    let mut bad = sig.clone();
    bad[0] ^= 1;
    let tampered = encode(&sp_input(vec![field(IN_TAP_KEY_SIG, vec![], bad)]));
    assert_eq!(signing_status(&received, &tampered, "ROLE-S-11"), TraceStatus::Failed);

    assert_eq!(evaluate_signing(&received, &returned, &[]), Evaluation::Verified);

    let key = sp_input(vec![]).maps[1][2].value[11..].to_vec();
    let script_sig = encode(&sp_input(vec![field(IN_TAP_SCRIPT_SIG, [&key[..], &[0; 32]].concat(), sig)]));
    assert_eq!(signing_status(&received, &script_sig, "ROLE-S-11"), TraceStatus::Failed);
}

// The Finalizer phase fixes: ROLE-F-7 to ROLE-F-8.

#[test]
fn role_f_4_and_f_5_sp_finalization() {
    let sig = sp_signature();
    let signed = encode(&sp_input(vec![field(IN_TAP_KEY_SIG, vec![], sig.clone())]));
    assert_eq!(finalizer_status(&signed, "ROLE-F-2"), TraceStatus::Passed);
    assert_eq!(finalizer_status(&encode(&sp_input(vec![])), "ROLE-F-2"), TraceStatus::Failed);

    let finalized = |items: &[&[u8]], keep: Option<Record>| {
        let mut p = sp_input(vec![]);
        p.maps[1].retain(|r| r.key_type != IN_SP_TWEAK);
        let mut w = vec![items.len() as u8];
        for item in items {
            w.push(item.len() as u8);
            w.extend(*item);
        }
        p.maps[1].push(field(IN_FINAL_SCRIPTWITNESS, vec![], w));
        p.maps[1].extend(keep);
        encode(&p)
    };
    let good = finalized(&[&sig], None);
    assert_eq!(finalizing_status(&signed, &good, "ROLE-F-8"), TraceStatus::Passed);
    assert_eq!(evaluate_finalizing(&signed, &good, &[]), Evaluation::Verified);

    let mut other = sig.clone();
    other[0] ^= 1;
    assert_eq!(finalizing_status(&signed, &finalized(&[&other], None), "ROLE-F-8"), TraceStatus::Failed, "not the key signature");
    assert_eq!(finalizing_status(&signed, &finalized(&[&sig, &[0x50]], None), "ROLE-F-8"), TraceStatus::Failed, "annex");
    let kept = field(IN_TAP_KEY_SIG, vec![], sig.clone());
    assert_eq!(finalizing_status(&signed, &finalized(&[&sig], Some(kept)), "ROLE-F-8"), TraceStatus::Failed, "key signature kept");
    // An input without a tweak is not an SP input.
    let plain = {
        let mut p = sp_input(vec![field(IN_TAP_KEY_SIG, vec![], sig.clone())]);
        p.maps[1].retain(|r| r.key_type != IN_SP_TWEAK);
        encode(&p)
    };
    assert_eq!(finalizing_status(&plain, &good, "ROLE-F-8"), TraceStatus::NotApplicable);
}

#[test]
fn role_f_3_retention_through_the_entry_point() {
    let sig = sp_signature();
    let signed = encode(&sp_input(vec![field(IN_TAP_KEY_SIG, vec![], sig.clone())]));
    let mut dropped = sp_input(vec![field(IN_FINAL_SCRIPTWITNESS, vec![], [&[1u8, 64][..], &sig].concat())]);
    dropped.maps[1].retain(|r| r.key_type != IN_SP_TWEAK);
    let keeps = encode(&dropped);
    assert_eq!(finalizing_status(&signed, &keeps, "ROLE-F-7"), TraceStatus::Passed);
    dropped.maps[1].push(field(IN_SEQUENCE, vec![], vec![0; 4]));
    let mut received = sp_input(vec![field(IN_TAP_KEY_SIG, vec![], sig), field(IN_SEQUENCE, vec![], vec![1; 4])]);
    received.maps[1].sort_by_key(|r| r.key_type);
    assert_eq!(finalizing_status(&encode(&received), &encode(&dropped), "ROLE-F-7"), TraceStatus::Failed);
}

// Row 51: ROLE-F-6 checks final fields against the spent script's template.

/// Every published valid PSBT with a finalized input, by corpus.
fn finalized_vectors() -> Vec<(String, Psbt)> {
    let corpora = [
        ("bip174", include_str!("../../vectors/bip174.json")),
        ("bip370", include_str!("../../vectors/bip370.json")),
        ("bip371", include_str!("../../vectors/bip371.json")),
        ("bip375", include_str!("../../vectors/bip375.json")),
    ];
    let mut out = Vec::new();
    for (name, json) in corpora {
        let vectors: Vec<Value> = serde_json::from_str::<Value>(json).unwrap()["vectors"].as_array().unwrap().clone();
        for (i, v) in vectors.iter().enumerate() {
            if v["valid"] != true {
                continue;
            }
            let Ok(psbt) = scan(&STANDARD.decode(v["psbt"].as_str().unwrap()).unwrap()) else { continue };
            let finalized = psbt.maps[1..].iter().any(|m| m.iter().any(|r| r.key_type == IN_FINAL_SCRIPTSIG || r.key_type == IN_FINAL_SCRIPTWITNESS));
            if finalized && evaluate(&encode(&psbt), &[Bip::Bip375]).into_verdict().is_ok() {
                out.push((format!("{name}:{}", i + 1), psbt));
            }
        }
    }
    out
}

#[test]
fn row_51_published_finalized_inputs_match_their_templates() {
    let vectors = finalized_vectors();
    assert!(vectors.len() >= 10, "{} finalized vectors", vectors.len());
    let mut inputs = 0;
    for (id, psbt) in &vectors {
        for input in PsbtContext::new(psbt).inputs() {
            if input.value(IN_FINAL_SCRIPTSIG).is_none() && input.value(IN_FINAL_SCRIPTWITNESS).is_none() {
                continue;
            }
            let (status, detail) = graph_statuses(spec::finalizer_role_obligations(), &input, "ROLE-F-6").remove(0);
            // A Finalizer may drop the UTXO (BIP174 says it should keep it);
            // without it the template cannot be checked.
            if status == TraceStatus::Incomplete && detail.ends_with("has no spent scriptPubKey") {
                continue;
            }
            inputs += 1;
            // The template matches; what ROLE-F-6 cannot verify is Incomplete.
            let unverified = status == TraceStatus::Incomplete && detail.contains("satisfaction is not checked");
            assert!(status == TraceStatus::Passed || unverified, "{id} input {}: {status:?} {detail}", input.index);
        }
    }
    assert!(inputs >= 20, "{inputs} finalized inputs");
}

/// A finalized input of a published vector spending `script_type`, with its PSBT.
fn finalized_input(is_type: fn(&[u8]) -> bool) -> (Psbt, usize) {
    for (_, psbt) in finalized_vectors() {
        let ctx = PsbtContext::new(&psbt);
        for input in ctx.inputs() {
            let finalized = input.value(IN_FINAL_SCRIPTSIG).is_some() || input.value(IN_FINAL_SCRIPTWITNESS).is_some();
            if finalized && psbt_spec::silent_payments::spent_script(&input).is_ok_and(|s| is_type(&s)) {
                return (psbt.clone(), input.index + 1);
            }
        }
    }
    panic!("no finalized input of that type");
}

#[test]
fn row_51_wrong_final_fields_fail() {
    use psbt_spec::silent_payments::{is_p2pkh, is_p2wpkh};
    let f1 = |p: &Psbt| common::finalized_status(&encode(p), "ROLE-F-6");

    let (mut psbt, m) = finalized_input(is_p2wpkh);
    psbt.maps[m].push(field(IN_FINAL_SCRIPTSIG, vec![], vec![0x01, 0x00]));
    assert_eq!(f1(&psbt), TraceStatus::Failed, "native segwit with a scriptSig");

    let (mut psbt, m) = finalized_input(is_p2wpkh);
    let w = record(&mut psbt.maps[m], IN_FINAL_SCRIPTWITNESS);
    *w.value.last_mut().unwrap() ^= 1;
    assert_eq!(f1(&psbt), TraceStatus::Failed, "witness key does not hash to the program");

    let (mut psbt, m) = finalized_input(is_p2pkh);
    psbt.maps[m].push(field(IN_FINAL_SCRIPTWITNESS, vec![], vec![0x01, 0x01, 0x00]));
    assert_eq!(f1(&psbt), TraceStatus::Failed, "P2PKH with a witness");

    // A spent script of an unchecked type: a bare 1-of-1 multisig.
    let (mut psbt, m) = finalized_input(is_p2wpkh);
    psbt.maps[m].retain(|r| r.key_type != IN_WITNESS_UTXO && r.key_type != IN_NON_WITNESS_UTXO);
    psbt.maps[m].retain(|r| r.key_type != IN_FINAL_SCRIPTWITNESS);
    psbt.maps[m].push(field(IN_WITNESS_UTXO, vec![], txout(1_000, &[0x51, 0x21, 2, 0xae])));
    psbt.maps[m].push(field(IN_FINAL_SCRIPTSIG, vec![], vec![0x00, 0x01, 0x30]));
    assert_eq!(common::finalized_status(&encode(&psbt), "ROLE-F-6"), TraceStatus::Incomplete);
}

// Row 52: a finalized Taproot script-path witness does not label its
// signatures, so ROLE-F-1 checks the labeled fields of the input the Finalizer
// received and reports a lone finalized script-path input as Incomplete.

/// A v2 P2TR script-path spend of a one-leaf tree with a placeholder 64-byte
/// (SIGHASH_DEFAULT) signature: labeled in PSBT_IN_TAP_SCRIPT_SIG, or finalized.
fn script_path(sighash_type: Option<u32>, finalized: bool) -> Vec<u8> {
    use psbt_spec::taproot::{leaf_hash, taproot_output_key};
    // x(G), used as both the leaf key and the internal key.
    let key = common::hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    let script = [&[0x20][..], &key, &[0xac]].concat();
    let leaf = leaf_hash(0xc0, &script);
    let (output_key, odd) = taproot_output_key(key[..].try_into().unwrap(), Some(&leaf)).unwrap();
    let spk = [&[0x51, 0x20][..], &output_key].concat();
    let control_block = [&[0xc0 | u8::from(odd)][..], &key].concat();
    let sig = vec![1u8; 64];
    let mut input = vec![
        field(IN_PREVIOUS_TXID, vec![], vec![5; 32]),
        field(IN_OUTPUT_INDEX, vec![], 0u32.to_le_bytes().to_vec()),
        field(IN_WITNESS_UTXO, vec![], txout(10_000, &spk)),
    ];
    if finalized {
        let mut w = vec![3u8];
        for item in [&sig[..], &script, &control_block] {
            w.push(item.len() as u8);
            w.extend(item);
        }
        input.push(field(IN_FINAL_SCRIPTWITNESS, vec![], w));
    } else {
        input.push(field(IN_TAP_SCRIPT_SIG, [&key[..], &leaf].concat(), sig));
    }
    if let Some(t) = sighash_type {
        input.push(field(IN_SIGHASH_TYPE, vec![], t.to_le_bytes().to_vec()));
    }
    encode(&Psbt {
        maps: vec![
            vec![
                field(GLOBAL_VERSION, vec![], 2u32.to_le_bytes().to_vec()),
                field(GLOBAL_TX_VERSION, vec![], 2u32.to_le_bytes().to_vec()),
                field(GLOBAL_INPUT_COUNT, vec![], vec![1]),
                field(GLOBAL_OUTPUT_COUNT, vec![], vec![1]),
            ],
            input,
            vec![field(OUT_AMOUNT, vec![], 9_000i64.to_le_bytes().to_vec()), field(OUT_SCRIPT, vec![], vec![0x51])],
        ],
        bips: vec![],
    })
}

#[test]
fn row_52_script_path_signatures_before_and_after_finalizing() {
    // Labeled: the Finalizer's received input.
    assert_eq!(finalizer_status(&script_path(Some(0), false), "ROLE-F-1"), TraceStatus::Passed);
    assert_eq!(finalizer_status(&script_path(Some(1), false), "ROLE-F-1"), TraceStatus::Failed);
    assert_eq!(
        evaluate_finalizing(&script_path(Some(1), false), &script_path(Some(1), true), &[]),
        Evaluation::Failed(psbt_spec::Violation { rule: "ROLE-F-1", detail: "input 0 has a signature without sighash type 1".into() })
    );
    // Unlabeled: a lone finalized script-path input.
    assert_eq!(finalizer_status(&script_path(Some(0), true), "ROLE-F-1"), TraceStatus::Incomplete);
    assert_eq!(finalizer_status(&script_path(None, true), "ROLE-F-1"), TraceStatus::NotApplicable);
    // Script-path satisfaction is not checked.
    assert_eq!(common::finalized_status(&script_path(None, true), "ROLE-F-6"), TraceStatus::Incomplete);
}

// ROLE-F-6 judges the final fields the Finalizer returned, not only the
// signature fields it received: a final signature it cannot verify is never
// Verified, and an input it changed or unfinalized is still evaluated.

/// `psbt` with the final fields of input map `m` removed.
fn unfinalized(psbt: &Psbt, m: usize) -> Psbt {
    let mut p = psbt.clone();
    p.maps[m].retain(|r| r.key_type != IN_FINAL_SCRIPTSIG && r.key_type != IN_FINAL_SCRIPTWITNESS);
    p
}

/// A finalized P2WPKH input of a published vector whose General rules pass
/// with and without that input's final fields, with its PSBT. Every such input
/// is in a BIP375 vector, where removing the final witness removes the public
/// key GEN-SP-2 needs, so these checks run without BIP375 enabled.
fn finalized_p2wpkh() -> (Psbt, usize) {
    use psbt_spec::silent_payments::{is_p2wpkh, spent_script};
    let passes = |p: &Psbt| psbt_spec::evaluate(&encode(p), &[]) == Evaluation::Verified;
    for (_, psbt) in finalized_vectors() {
        for input in PsbtContext::new(&psbt).inputs() {
            let m = input.index + 1;
            let finalized = input.value(IN_FINAL_SCRIPTWITNESS).is_some();
            if finalized && spent_script(&input).is_ok_and(|s| is_p2wpkh(&s)) && passes(&psbt) && passes(&unfinalized(&psbt, m)) {
                return (psbt.clone(), m);
            }
        }
    }
    panic!("no finalized P2WPKH input with passing General rules");
}

#[test]
fn role_f_6_final_signatures_are_verified() {
    let (psbt, m) = finalized_p2wpkh();
    let received = encode(&unfinalized(&psbt, m));
    assert_eq!(evaluate_finalizing(&received, &encode(&psbt), &[]), Evaluation::Verified);
    // The last byte of the witness signature's S: the template still matches.
    let mut forged = psbt.clone();
    let witness = &mut record(&mut forged.maps[m], IN_FINAL_SCRIPTWITNESS).value;
    let sig_len = witness[1] as usize;
    witness[1 + sig_len - 1] ^= 1;
    assert!(matches!(
        evaluate_finalizing(&received, &encode(&forged), &[]),
        Evaluation::Failed(v) if v.rule == "ROLE-F-6" && v.detail.contains("ECDSA signature does not verify")
    ));
}

#[test]
fn finalizing_evaluates_inputs_it_changed_or_unfinalized() {
    let (psbt, m) = finalized_p2wpkh();
    let mut changed = psbt.clone();
    *record(&mut changed.maps[m], IN_FINAL_SCRIPTWITNESS).value.last_mut().unwrap() ^= 1;
    assert!(matches!(
        evaluate_finalizing(&encode(&psbt), &encode(&changed), &[]),
        Evaluation::Failed(v) if v.rule == "ROLE-F-6"
    ));
    assert!(matches!(
        evaluate_finalizing(&encode(&psbt), &encode(&unfinalized(&psbt, m)), &[]),
        Evaluation::Failed(v) if v.rule == "ROLE-F-6"
    ));
}

// ROLE-F-4: ECDSA partial signatures verify against the BIP143 message.

#[test]
fn role_f_4_verifies_ecdsa_partial_signatures() {
    // The workflow's Signer step: one P2WPKH input with a partial signature.
    let signed_psbt = signed();
    let signed = encode(&signed_psbt);
    let statuses = graph_statuses(each_input_finalizer(), &PsbtContext::new(&scan(&signed).ok().unwrap()), "ROLE-F-4");
    assert_eq!(statuses[0].0, TraceStatus::Passed, "{}", statuses[0].1);

    let finalized = encode(&bip375("Input Finalizer"));
    assert_eq!(evaluate_finalizing(&signed, &finalized, &[Bip::Bip375]), Evaluation::Verified);

    // The last byte of S in the DER signature, before the sighash type byte.
    let mut forged = signed_psbt.clone();
    let sig = &mut record(&mut forged.maps[1], IN_PARTIAL_SIG).value;
    let at = sig.len() - 2;
    sig[at] ^= 1;
    assert_eq!(finalizer_status(&encode(&forged), "ROLE-F-4"), TraceStatus::Failed);

    // A failing Taproot signature (ROLE-F-3) still fails before ROLE-F-4.
    let sig = sp_signature();
    let mut bad = sig.clone();
    bad[0] ^= 1;
    let mut both = sp_input(vec![field(IN_TAP_KEY_SIG, vec![], bad)]);
    both.maps[1].push(field(IN_PARTIAL_SIG, common::hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"), vec![0x30, 0x01]));
    assert_eq!(finalizer_status(&encode(&both), "ROLE-F-3"), TraceStatus::Failed);
    // Without signatures the rule does not apply.
    let mut unsigned = sp_input(vec![]);
    unsigned.maps[1].retain(|r| r.key_type != IN_SP_TWEAK);
    assert_eq!(finalizer_status(&encode(&unsigned), "ROLE-F-3"), TraceStatus::NotApplicable);
    assert_eq!(finalizer_status(&encode(&unsigned), "ROLE-F-4"), TraceStatus::NotApplicable);
}

fn each_input_finalizer() -> psbt_spec::algebra::BoxNode<PsbtContext> {
    psbt_spec::algebra::each(|p: &PsbtContext| p.inputs(), spec::finalizer_obligations())
}



#[test]
fn role_entry_points_on_the_bip375_workflow() {
    use psbt_spec::{evaluate_combining, evaluate_creating, evaluate_extracting};
    let bips = [Bip::Bip375];
    let (created, updated_bytes) = (encode(&bip375("Creator")), encode(&updated()));

    let empty = encode(&Psbt {
        maps: vec![vec![
            field(GLOBAL_VERSION, vec![], 2u32.to_le_bytes().to_vec()),
            field(GLOBAL_TX_VERSION, vec![], 2u32.to_le_bytes().to_vec()),
            field(GLOBAL_INPUT_COUNT, vec![], vec![0]),
            field(GLOBAL_OUTPUT_COUNT, vec![], vec![0]),
        ]],
        bips: vec![],
    });
    assert_eq!(evaluate_creating(&empty, false, &bips), Evaluation::Verified);
    // The published Creator step also adds inputs and outputs.
    assert!(matches!(evaluate_creating(&created, false, &bips), Evaluation::Failed(v) if v.rule == "ROLE-C-1"));

    assert_eq!(evaluate_extracting(&encode(&bip375("Input Finalizer")), &bips), Evaluation::Verified);

    assert_eq!(evaluate_combining(&[&created, &updated_bytes], &updated_bytes, &bips), Evaluation::Verified);
    let mut other = updated();
    record(&mut other.maps[2], OUT_AMOUNT).value[0] ^= 1;
    assert!(matches!(
        evaluate_combining(&[&updated_bytes, &encode(&other)], &updated_bytes, &bips),
        Evaluation::Failed(v) if v.rule == "ROLE-B-1"
    ));
    assert!(matches!(
        evaluate_combining(&[&updated_bytes, &encode(&signed())], &updated_bytes, &bips),
        Evaluation::Failed(v) if v.rule == "ROLE-B-2"
    ));
}
