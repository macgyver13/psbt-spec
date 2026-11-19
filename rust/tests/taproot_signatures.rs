//! GEN-TR-2 through the General rule graph, ROLE-F-9 through the Input Finalizer graph, the BIP341 scriptPubKey
//! vectors, and hash type syntax.
mod common;

use base64::{engine::general_purpose::STANDARD, Engine};
use common::{encode, field, finalizer_status, hex, status, txout};
use k256::schnorr::SigningKey;
use psbt_spec::algebra::TraceStatus;
use psbt_spec::context::*;
use psbt_spec::encoding::{put_compact_size, scan, Psbt, Record};
use psbt_spec::taproot::{tagged_hash, taproot_output_key, taproot_sighash, verify_taproot_control_block};
use serde_json::Value;

fn bip371(needle: &str) -> Psbt {
    let vectors: Vec<Value> = serde_json::from_str::<Value>(include_str!("../../vectors/bip371.json")).unwrap()["vectors"].as_array().unwrap().clone();
    let v = vectors.iter().find(|v| v["description"].as_str().unwrap().contains(needle)).unwrap();
    let Ok(psbt) = scan(&STANDARD.decode(v["psbt"].as_str().unwrap()).unwrap()) else { panic!() };
    psbt
}

fn find(psbt: &mut Psbt, key_type: u64) -> &mut Record {
    psbt.maps[1].iter_mut().find(|r| r.key_type == key_type).unwrap()
}

#[test]
fn published_key_path_signature() {
    let mut psbt = bip371("key only input with internal key, its derivation path, and signature");
    assert_eq!(finalizer_status(&encode(&psbt), "ROLE-F-3"), TraceStatus::Passed);
    find(&mut psbt, IN_TAP_KEY_SIG).value[0] ^= 1;
    assert_eq!(finalizer_status(&encode(&psbt), "ROLE-F-3"), TraceStatus::Failed);
}

#[test]
fn signature_needs_every_spent_output() {
    let mut psbt = bip371("key only input with internal key, its derivation path, and signature");
    psbt.maps[1].retain(|r| r.key_type != IN_WITNESS_UTXO && r.key_type != IN_NON_WITNESS_UTXO);
    assert_eq!(finalizer_status(&encode(&psbt), "ROLE-F-3"), TraceStatus::Incomplete);
}

#[test]
fn hash_types_in_signatures() {
    let mut psbt = bip371("key only input with internal key, its derivation path, and signature");
    let sig = &mut find(&mut psbt, IN_TAP_KEY_SIG).value;
    sig.truncate(64);
    for (byte, ok) in [(0x00u8, false), (0x01, true), (0x04, false), (0x80, false), (0x83, true), (0x84, false)] {
        let mut p = psbt.clone();
        let s = &mut find(&mut p, IN_TAP_KEY_SIG).value;
        s.truncate(64);
        s.push(byte);
        let format_error = psbt_spec::evaluate(&encode(&p), &[]).into_verdict().err().map(|e| e.rule) == Some("GEN-F-5");
        assert_eq!(!format_error, ok, "hash type {byte:#04x}");
    }
}

/// A local script-path case: a one-leaf tree signed with secret key 3, checked
/// through GEN-TR-1, GEN-TR-2 and ROLE-F-9.
#[test]
fn script_path_signature() {
    let signer = SigningKey::from_bytes(&[3; 32]).unwrap();
    let key: [u8; 32] = signer.verifying_key().to_bytes().into();
    let script = [&[0x20][..], &key, &[0xac]].concat();
    let mut leaf_msg = vec![0xc0];
    put_compact_size(&mut leaf_msg, script.len());
    leaf_msg.extend(&script);
    let leaf = tagged_hash("TapLeaf", &leaf_msg);
    // x(G) as the internal key.
    let internal: [u8; 32] = hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").try_into().unwrap();
    let (output_key, odd) = taproot_output_key(&internal, Some(&leaf)).unwrap();
    let spk = [&[0x51, 0x20][..], &output_key].concat();
    let control_block = [&[0xc0 | u8::from(odd)][..], &internal].concat();

    let mut psbt = Psbt {
        maps: vec![
            vec![
                field(GLOBAL_VERSION, vec![], 2u32.to_le_bytes().to_vec()),
                field(GLOBAL_TX_VERSION, vec![], 2u32.to_le_bytes().to_vec()),
                field(GLOBAL_INPUT_COUNT, vec![], vec![1]),
                field(GLOBAL_OUTPUT_COUNT, vec![], vec![1]),
            ],
            vec![
                field(IN_PREVIOUS_TXID, vec![], vec![5; 32]),
                field(IN_OUTPUT_INDEX, vec![], 0u32.to_le_bytes().to_vec()),
                field(IN_WITNESS_UTXO, vec![], txout(10_000, &spk)),
                field(IN_TAP_LEAF_SCRIPT, control_block, [&script[..], &[0xc0]].concat()),
                field(IN_TAP_INTERNAL_KEY, vec![], internal.to_vec()),
                field(IN_TAP_MERKLE_ROOT, vec![], leaf.to_vec()),
            ],
            vec![field(OUT_AMOUNT, vec![], 9_000i64.to_le_bytes().to_vec()), field(OUT_SCRIPT, vec![], vec![0x51])],
        ],
        bips: vec![],
    };
    let ctx = PsbtContext::new(&psbt);
    let tx = signing_tx(&ctx).unwrap();
    let spent = spent_outputs(&ctx).unwrap();
    let digest = taproot_sighash(&tx, 0, &spent, 0x00, Some((&leaf, u32::MAX)), None).unwrap();
    let sig = signer.sign_raw(&digest, &[0; 32]).unwrap().to_bytes().to_vec();
    psbt.maps[1].push(field(IN_TAP_SCRIPT_SIG, [&key[..], &leaf].concat(), sig));

    let bytes = encode(&psbt);
    assert_eq!(psbt_spec::evaluate(&bytes, &[]).into_verdict(), Ok(()));
    for id in ["GEN-TR-1", "GEN-TR-2"] {
        assert_eq!(status(&bytes, id), TraceStatus::Passed, "{id}");
    }
    assert_eq!(finalizer_status(&bytes, "ROLE-F-3"), TraceStatus::Passed);

    let mut wrong_root = psbt.clone();
    find(&mut wrong_root, IN_TAP_MERKLE_ROOT).value[0] ^= 1;
    assert_eq!(status(&encode(&wrong_root), "GEN-TR-2"), TraceStatus::Failed);

    let mut wrong_leaf = psbt.clone();
    find(&mut wrong_leaf, IN_TAP_SCRIPT_SIG).key_data[63] ^= 1;
    assert_eq!(finalizer_status(&encode(&wrong_leaf), "ROLE-F-3"), TraceStatus::Failed);
}

fn leaves(tree: &Value, out: &mut Vec<(u64, Vec<u8>, u8)>) {
    match tree {
        Value::Array(nodes) => nodes.iter().for_each(|n| leaves(n, out)),
        Value::Object(leaf) => out.push((
            leaf["id"].as_u64().unwrap(),
            hex(leaf["script"].as_str().unwrap()),
            leaf["leafVersion"].as_u64().unwrap() as u8,
        )),
        _ => {}
    }
}

#[test]
fn bip341_script_pubkey_vectors() {
    let data: Value = serde_json::from_str(include_str!("../../vectors/bip341_wallet_vectors.json")).unwrap();
    for case in data["scriptPubKey"].as_array().unwrap() {
        let internal: [u8; 32] = hex(case["given"]["internalPubkey"].as_str().unwrap()).try_into().unwrap();
        let root = case["intermediary"]["merkleRoot"].as_str().map(|r| <[u8; 32]>::try_from(hex(r)).unwrap());
        let (output_key, _) = taproot_output_key(&internal, root.as_ref()).unwrap();
        assert_eq!(output_key.to_vec(), hex(case["intermediary"]["tweakedPubkey"].as_str().unwrap()));

        let mut found = Vec::new();
        leaves(&case["given"]["scriptTree"], &mut found);
        found.sort_by_key(|(id, ..)| *id);
        let blocks = case["expected"]["scriptPathControlBlocks"].as_array().map(Vec::as_slice).unwrap_or(&[]);
        assert_eq!(blocks.len(), found.len());
        for ((_, script, version), block) in found.iter().zip(blocks) {
            assert!(verify_taproot_control_block(&output_key, &hex(block.as_str().unwrap()), script, *version));
        }
    }
}
