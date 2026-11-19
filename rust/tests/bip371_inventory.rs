//! Tests for the rows of `plans/bip371-inventory.md`, by row number, using
//! mutations of the published BIP371 vectors (local fixtures).
mod common;

use base64::{engine::general_purpose::STANDARD, Engine};
use common::{encode, field, finalized_status, finalizer_status, finalizing_status, status, txout};
use psbt_spec::algebra::TraceStatus;
use psbt_spec::context::*;
use psbt_spec::encoding::{put_compact_size, scan, Psbt, Record};
use psbt_spec::{evaluate, evaluate_combining, Evaluation};
use serde_json::Value;

const KEY_PATH_SIGNED: &str = "key only input with internal key, its derivation path, and signature";
const KEY_PATH_INPUT: &str = "P2TR key only input with internal key and its derivation path";
const KEY_PATH_OUTPUT: &str = "P2TR key only output with internal key";
const SCRIPT_OUTPUT: &str = "script path only output with dummy internal key";
const SCRIPT_INPUT_SIGS: &str = "script path only input with dummy internal key, scripts, script key derivation paths, merkle root, and script path signatures";

/// x(2G), a valid x-only key different from every key in the vectors.
const OTHER_KEY: &str = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

fn vector(needle: &str) -> Psbt {
    let vectors: Vec<Value> = serde_json::from_str::<Value>(include_str!("../../vectors/bip371.json")).unwrap()["vectors"].as_array().unwrap().clone();
    let v = vectors
        .iter()
        .find(|v| v["valid"] == true && v["description"].as_str().unwrap().contains(needle))
        .unwrap_or_else(|| panic!("no vector {needle}"));
    let Ok(psbt) = scan(&STANDARD.decode(v["psbt"].as_str().unwrap()).unwrap()) else { panic!() };
    psbt
}

fn hex(s: &str) -> Vec<u8> {
    common::hex(s)
}

/// The record of `key_type` in the last map (the output) or the second (the input).
fn record(map: &mut [Record], key_type: u64) -> &mut Record {
    map.iter_mut().find(|r| r.key_type == key_type).unwrap()
}

fn input(psbt: &mut Psbt) -> &mut Vec<Record> {
    &mut psbt.maps[1]
}

fn output(psbt: &mut Psbt) -> &mut Vec<Record> {
    psbt.maps.last_mut().unwrap()
}

fn rule_of(bytes: &[u8]) -> Option<&'static str> {
    evaluate(bytes, &[]).into_verdict().err().map(|e| e.rule)
}

fn tree(tuples: &[(u8, u8, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (depth, version, script) in tuples {
        out.extend([*depth, *version]);
        put_compact_size(&mut out, script.len());
        out.extend(*script);
    }
    out
}

// Rows 10 to 12: field formats.

#[test]
fn row_10_x_only_keys_lift_to_the_curve() {
    let mut psbt = vector(KEY_PATH_INPUT);
    record(input(&mut psbt), IN_TAP_INTERNAL_KEY).value = vec![0xff; 32];
    assert_eq!(rule_of(&encode(&psbt)), Some("GEN-F-5"), "input internal key");

    let mut psbt = vector(KEY_PATH_OUTPUT);
    record(output(&mut psbt), OUT_TAP_INTERNAL_KEY).value = vec![0xff; 32];
    assert_eq!(rule_of(&encode(&psbt)), Some("GEN-F-5"), "output internal key");

    let mut psbt = vector(SCRIPT_INPUT_SIGS);
    record(input(&mut psbt), IN_TAP_SCRIPT_SIG).key_data[..32].copy_from_slice(&[0xff; 32]);
    assert_eq!(rule_of(&encode(&psbt)), Some("GEN-F-5"), "script signature key");
}

#[test]
fn row_11_tree_is_complete_and_shallow() {
    let base = vector(SCRIPT_OUTPUT);
    let script: &[u8] = &[0x51];
    for (label, value, ok) in [
        ("published", None, true),
        ("single leaf at depth 0", Some(tree(&[(0, 0xc0, script)])), true),
        ("two leaves at depth 1", Some(tree(&[(1, 0xc0, script), (1, 0xc0, script)])), true),
        ("one leaf at depth 1", Some(tree(&[(1, 0xc0, script)])), false),
        ("depth 129", Some(tree(&[(129, 0xc0, script), (129, 0xc0, script)])), false),
        ("leaf after a complete tree", Some(tree(&[(0, 0xc0, script), (0, 0xc0, script)])), false),
        ("leaf, then a two-leaf subtree", Some(tree(&[(1, 0xc0, script), (2, 0xc0, script), (2, 0xc0, script)])), true),
        ("not depth-first", Some(tree(&[(2, 0xc0, script), (1, 0xc0, script), (2, 0xc0, script)])), false),
        ("deeper leaf missing its sibling", Some(tree(&[(1, 0xc0, script), (2, 0xc0, script)])), false),
    ] {
        let mut psbt = base.clone();
        if let Some(value) = value {
            record(output(&mut psbt), OUT_TAP_TREE).value = value;
        }
        let got = rule_of(&encode(&psbt));
        assert_eq!(got != Some("GEN-F-5"), ok, "{label}: {got:?}");
    }
}

#[test]
fn row_12_leaf_versions_are_even_and_not_annex() {
    let script: &[u8] = &[0x51];
    for (version, ok) in [(0xc0u8, true), (0xc2, true), (0xc1, false), (0x50, false)] {
        let mut psbt = vector(SCRIPT_OUTPUT);
        record(output(&mut psbt), OUT_TAP_TREE).value = tree(&[(0, version, script)]);
        assert_eq!(rule_of(&encode(&psbt)) != Some("GEN-F-5"), ok, "tree leaf version {version:#04x}");

        let mut psbt = vector(SCRIPT_INPUT_SIGS);
        let leaf = record(input(&mut psbt), IN_TAP_LEAF_SCRIPT);
        *leaf.value.last_mut().unwrap() = version;
        assert_eq!(rule_of(&encode(&psbt)) != Some("GEN-F-5"), ok, "leaf script version {version:#04x}");
    }
}

// Rows 13 to 17: General rules.

#[test]
fn row_13_control_block_failure_through_the_graph() {
    let mut psbt = vector(SCRIPT_INPUT_SIGS);
    assert_eq!(status(&encode(&psbt), "GEN-TR-1"), TraceStatus::Passed);
    record(input(&mut psbt), IN_TAP_LEAF_SCRIPT).key_data[1..33].copy_from_slice(&hex(OTHER_KEY));
    assert_eq!(status(&encode(&psbt), "GEN-TR-1"), TraceStatus::Failed);
}

#[test]
fn row_15_internal_key_without_merkle_root() {
    let mut psbt = vector(KEY_PATH_INPUT);
    assert_eq!(status(&encode(&psbt), "GEN-TR-2"), TraceStatus::Passed, "key-only match");
    record(input(&mut psbt), IN_TAP_INTERNAL_KEY).value = hex(OTHER_KEY);
    assert_eq!(status(&encode(&psbt), "GEN-TR-2"), TraceStatus::Incomplete, "mismatch without a Merkle root");
}

#[test]
fn row_16_output_commitment() {
    let mut psbt = vector(SCRIPT_OUTPUT);
    assert_eq!(status(&encode(&psbt), "GEN-TR-3"), TraceStatus::Passed, "with tree");
    record(output(&mut psbt), OUT_TAP_INTERNAL_KEY).value = hex(OTHER_KEY);
    assert_eq!(status(&encode(&psbt), "GEN-TR-3"), TraceStatus::Failed, "wrong key with tree");

    let mut psbt = vector(KEY_PATH_OUTPUT);
    assert_eq!(status(&encode(&psbt), "GEN-TR-3"), TraceStatus::Passed, "key only");
    record(output(&mut psbt), OUT_TAP_INTERNAL_KEY).value = hex(OTHER_KEY);
    assert_eq!(status(&encode(&psbt), "GEN-TR-3"), TraceStatus::Incomplete, "wrong key without tree");
}

#[test]
fn row_17_output_derivation_leaves() {
    let psbt = vector(SCRIPT_OUTPUT);
    assert_eq!(status(&encode(&psbt), "GEN-TR-4"), TraceStatus::Passed);

    let mut wrong = psbt.clone();
    let derivation = output(&mut wrong).iter_mut().find(|r| r.key_type == OUT_TAP_BIP32_DERIVATION && r.value[0] > 0).unwrap();
    derivation.value[1] ^= 1;
    assert_eq!(status(&encode(&wrong), "GEN-TR-4"), TraceStatus::Failed);

    let mut no_tree = psbt;
    // Without the internal key too, so GEN-TR-3 does not stop the graph first.
    output(&mut no_tree).retain(|r| r.key_type != OUT_TAP_TREE && r.key_type != OUT_TAP_INTERNAL_KEY);
    assert_eq!(status(&encode(&no_tree), "GEN-TR-4"), TraceStatus::Incomplete);
}

// Rows 22 and 24: finalization.

fn witness(items: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    put_compact_size(&mut out, items.len());
    for item in items {
        put_compact_size(&mut out, item.len());
        out.extend(*item);
    }
    out
}

/// The published key-path vector finalized: the signature moved into the witness
/// and the Taproot fields removed.
fn finalized_key_path(extra: &[&[u8]]) -> Psbt {
    let mut psbt = vector(KEY_PATH_SIGNED);
    let sig = record(input(&mut psbt), IN_TAP_KEY_SIG).value.clone();
    let mut items: Vec<&[u8]> = vec![&sig];
    items.extend(extra);
    let final_witness = witness(&items);
    input(&mut psbt).retain(|r| ![IN_TAP_KEY_SIG, IN_TAP_INTERNAL_KEY, IN_TAP_BIP32_DERIVATION].contains(&r.key_type));
    input(&mut psbt).push(field(IN_FINAL_SCRIPTWITNESS, vec![], final_witness));
    psbt
}

#[test]
fn row_24_key_path_finalization() {
    let bytes = encode(&finalized_key_path(&[]));
    assert_eq!(evaluate(&bytes, &[]).into_verdict(), Ok(()));
    assert_eq!(finalized_status(&bytes, "ROLE-F-10"), TraceStatus::Passed);
    // Row 30: a finalized P2TR input without SP fields is not an SP input.
    let received = encode(&vector(KEY_PATH_SIGNED));
    assert_eq!(finalizer_status(&received, "ROLE-F-2"), TraceStatus::NotApplicable);
    assert_eq!(finalizing_status(&received, &bytes, "ROLE-F-8"), TraceStatus::NotApplicable);

    // The signature was made without an annex, so a witness with one fails.
    let with_annex = encode(&finalized_key_path(&[&[0x50, 0x01]]));
    assert_eq!(finalized_status(&with_annex, "ROLE-F-10"), TraceStatus::Failed);

    let mut tampered = finalized_key_path(&[]);
    let w = record(input(&mut tampered), IN_FINAL_SCRIPTWITNESS);
    w.value[5] ^= 1;
    assert_eq!(finalized_status(&encode(&tampered), "ROLE-F-10"), TraceStatus::Failed);
}

#[test]
fn row_22_script_path_finalization_failure_through_the_graph() {
    // A P2TR spend whose witness ends with a script and a control block that
    // does not commit to the spent key.
    let other = hex(OTHER_KEY);
    let control_block = [&[0xc0][..], &other].concat();
    let mut psbt = finalized_key_path(&[]);
    *record(input(&mut psbt), IN_FINAL_SCRIPTWITNESS) = field(IN_FINAL_SCRIPTWITNESS, vec![], witness(&[&[1; 64], &[0x51], &control_block]));
    assert_eq!(finalized_status(&encode(&psbt), "ROLE-F-9"), TraceStatus::Failed);
}

// Rows 27 to 29: regression targets.

#[test]
fn row_27_combiner_merges_compound_keys() {
    let full = vector(SCRIPT_INPUT_SIGS);
    let sigs: Vec<Record> = full.maps[1].iter().filter(|r| r.key_type == IN_TAP_SCRIPT_SIG).cloned().collect();
    assert!(sigs.len() >= 2);
    let without = |keep: usize| {
        let mut p = full.clone();
        p.maps[1].retain(|r| r.key_type != IN_TAP_SCRIPT_SIG || r.key_data == sigs[keep].key_data);
        encode(&p)
    };
    let (a, b) = (without(0), without(1));
    let mut both = full.clone();
    both.maps[1].retain(|r| r.key_type != IN_TAP_SCRIPT_SIG || r.key_data == sigs[0].key_data || r.key_data == sigs[1].key_data);
    assert_eq!(evaluate_combining(&[&a, &b], &encode(&both), &[]), Evaluation::Verified);
    assert!(matches!(evaluate_combining(&[&a, &b], &a, &[]), Evaluation::Failed(_)), "dropping a compound-key record");
}

#[test]
fn row_28_sighash_type_with_script_path_signature() {
    let mut psbt = vector(SCRIPT_INPUT_SIGS);
    let sig = record(input(&mut psbt), IN_TAP_SCRIPT_SIG);
    sig.value.truncate(64);
    sig.value.push(0x01);
    input(&mut psbt).push(field(IN_SIGHASH_TYPE, vec![], 0x02u32.to_le_bytes().to_vec()));
    assert_eq!(finalizer_status(&encode(&psbt), "ROLE-F-1"), TraceStatus::Failed);
}

/// A v2 PSBT spending a P2TR output, with one 65-byte key-path signature of
/// `hash_type` when given.
fn v2_signed(hash_type: Option<u8>, flags: u8) -> Vec<u8> {
    let spk = [&[0x51, 0x20][..], &hex(OTHER_KEY)].concat();
    encode(&Psbt {
        maps: vec![
            vec![
                field(GLOBAL_VERSION, vec![], 2u32.to_le_bytes().to_vec()),
                field(GLOBAL_TX_VERSION, vec![], 2u32.to_le_bytes().to_vec()),
                field(GLOBAL_INPUT_COUNT, vec![], vec![1]),
                field(GLOBAL_OUTPUT_COUNT, vec![], vec![1]),
                field(GLOBAL_TX_MODIFIABLE, vec![], vec![flags]),
            ],
            vec![
                field(IN_PREVIOUS_TXID, vec![], vec![3; 32]),
                field(IN_OUTPUT_INDEX, vec![], 0u32.to_le_bytes().to_vec()),
                field(IN_WITNESS_UTXO, vec![], txout(10_000, &spk)),
            ]
            .into_iter()
            .chain(hash_type.map(|t| field(IN_TAP_KEY_SIG, vec![], [&[1u8; 64][..], &[t]].concat())))
            .collect(),
            vec![field(OUT_AMOUNT, vec![], 9_000i64.to_le_bytes().to_vec()), field(OUT_SCRIPT, vec![], vec![0x51])],
        ],
        bips: vec![],
    })
}

#[test]
fn row_29_signer_flags_with_taproot_single() {
    // SINGLE|ANYONECANPAY: inputs may stay modifiable, outputs may not, and the
    // Has SIGHASH_SINGLE flag must be set.
    let flags = |flags| status(&v2_signed(Some(0x83), flags), "GEN-T-2");
    assert_eq!(flags(0x05), TraceStatus::Passed, "ANYONECANPAY leaves inputs modifiable");
    assert_eq!(flags(0x01), TraceStatus::Failed, "Has SIGHASH_SINGLE clear");
    assert_eq!(flags(0x07), TraceStatus::Failed, "outputs modifiable");
}
