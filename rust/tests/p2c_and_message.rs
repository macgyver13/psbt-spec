//! GEN-P2C-1, BIP322 PSBT recognition and GEN-MSG-1 to GEN-MSG-4 on synthetic PSBTs (local fixtures),
//! observed through the General rule graph, and the published BIP322 hashes.
mod common;

use bitcoin_hashes::{hash160, Hash};
use common::{encode, field, hex, status, txout};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use psbt_spec::algebra::TraceStatus;
use psbt_spec::context::*;
use psbt_spec::encoding::{Psbt, Record, Transaction, TxIn, TxOut};
use psbt_spec::rules::message::{bip322_to_spend_txid, is_bip322, GLOBAL_GENERIC_SIGNED_MESSAGE};
use serde_json::Value;

fn v2(global: Vec<Record>, input: Vec<Record>, outputs: Vec<Vec<Record>>, prevout: [u8; 32]) -> Psbt {
    let mut g = vec![
        field(GLOBAL_VERSION, vec![], 2u32.to_le_bytes().to_vec()),
        field(GLOBAL_TX_VERSION, vec![], 2u32.to_le_bytes().to_vec()),
        field(GLOBAL_INPUT_COUNT, vec![], vec![1]),
        field(GLOBAL_OUTPUT_COUNT, vec![], vec![outputs.len() as u8]),
    ];
    g.extend(global);
    let mut i = vec![
        field(IN_PREVIOUS_TXID, vec![], prevout.to_vec()),
        field(IN_OUTPUT_INDEX, vec![], 0u32.to_le_bytes().to_vec()),
    ];
    i.extend(input);
    let mut maps = vec![g, i];
    maps.extend(outputs);
    Psbt { maps, bips: vec![] }
}

fn output(amount: i64, script: &[u8]) -> Vec<Record> {
    vec![field(OUT_AMOUNT, vec![], amount.to_le_bytes().to_vec()), field(OUT_SCRIPT, vec![], script.to_vec())]
}

// P2C: original key G, tweak 1, so the tweaked key is 2G.
fn keys() -> (Vec<u8>, Vec<u8>) {
    let compressed = |p: ProjectivePoint| p.to_affine().to_encoded_point(true).as_bytes().to_vec();
    (compressed(ProjectivePoint::GENERATOR), compressed(ProjectivePoint::GENERATOR * Scalar::from(2u64)))
}

fn p2c(spent_script: Vec<u8>, tweak: u8) -> Vec<u8> {
    let (original, _) = keys();
    let mut t = [0u8; 32];
    t[31] = tweak;
    encode(&v2(
        vec![],
        vec![field(IN_WITNESS_UTXO, vec![], txout(10_000, &spent_script)), field(IN_P2C_TWEAK, original, t.to_vec())],
        vec![output(9_000, &[0x51])],
        [7; 32],
    ))
}

#[test]
fn p2c_tweaked_key_commitment() {
    let (_, tweaked) = keys();
    let hash = hash160::Hash::hash(&tweaked).to_byte_array();
    let p2wpkh = [&[0x00, 0x14][..], &hash].concat();
    let p2pkh = [&[0x76, 0xa9, 0x14][..], &hash, &[0x88, 0xac]].concat();
    let p2pk = [&[0x21][..], &tweaked, &[0xac]].concat();
    assert_eq!(status(&p2c(p2wpkh.clone(), 1), "GEN-P2C-1"), TraceStatus::Passed, "P2WPKH");
    assert_eq!(status(&p2c(p2pkh, 1), "GEN-P2C-1"), TraceStatus::Passed, "P2PKH");
    assert_eq!(status(&p2c(p2pk, 1), "GEN-P2C-1"), TraceStatus::Passed, "P2PK");
    assert_eq!(status(&p2c(p2wpkh, 2), "GEN-P2C-1"), TraceStatus::Failed, "wrong tweak");
    assert_eq!(status(&p2c([&[0x51, 0x20][..], &tweaked[1..]].concat(), 1), "GEN-P2C-1"), TraceStatus::Incomplete, "Taproot");
}

/// ROLE-S-9 for a Signer that signs a P2C input and removes its tweak, with `bips`.
fn signer_removes_tweak(bips: &[psbt_spec::Bip], signed: bool) -> TraceStatus {
    let (_, tweaked) = keys();
    let p2wpkh = [&[0x00, 0x14][..], &hash160::Hash::hash(&tweaked).to_byte_array()].concat();
    let Ok(mut before) = psbt_spec::encoding::scan(&p2c(p2wpkh, 1)) else { panic!() };
    before.bips = bips.to_vec();
    let mut after = before.clone();
    after.maps[1].retain(|r| r.key_type != IN_P2C_TWEAK);
    if signed {
        after.maps[1].push(field(IN_PARTIAL_SIG, tweaked, vec![0x30, 0x01, 0x01]));
    }
    let transition = psbt_spec::SignerTransitionContext::new(PsbtContext::new(&before), PsbtContext::new(&after));
    common::graph_statuses(psbt_spec::spec::signer_transition_obligations(), &transition, "ROLE-S-9").remove(0).0
}

#[test]
fn bip372_signer_may_remove_tweak_after_signing() {
    use psbt_spec::Bip;
    assert_eq!(signer_removes_tweak(&[Bip::Bip372], true), TraceStatus::Passed);
    assert_eq!(signer_removes_tweak(&[], true), TraceStatus::Failed, "BIP174 alone: only add data");
    assert_eq!(signer_removes_tweak(&[Bip::Bip372], false), TraceStatus::Failed, "no partial signature");
}

fn message_psbt_v2(version: u32, out_script: &[u8], prevout_ok: bool, with_utxo: bool) -> Vec<u8> {
    let msg = b"Hello World".to_vec();
    let challenge = vec![0x00, 0x14, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44];
    let prevout = if prevout_ok { bip322_to_spend_txid(&msg, &challenge) } else { [9; 32] };
    let mut psbt = v2(
        vec![field(GLOBAL_GENERIC_SIGNED_MESSAGE, vec![], msg)],
        if with_utxo { vec![field(IN_WITNESS_UTXO, vec![], txout(0, &challenge))] } else { vec![] },
        vec![output(0, out_script)],
        prevout,
    );
    psbt.maps[0][1].value = version.to_le_bytes().to_vec();
    encode(&psbt)
}

/// Whether `bytes` is a BIP322 PSBT, as the Definitions define it.
fn recognized(bytes: &[u8]) -> Result<bool, String> {
    is_bip322(&PsbtContext::new(&psbt_spec::encoding::scan(bytes).ok().unwrap()))
}

#[test]
fn bip322_recognition_and_version() {
    assert_eq!(recognized(&message_psbt_v2(2, &[0x6a], true, true)), Ok(true));
    assert_eq!(recognized(&message_psbt_v2(2, &[0x51], true, true)), Ok(false), "not OP_RETURN: ordinary PSBT");
    assert_eq!(recognized(&message_psbt_v2(2, &[0x6a], false, true)), Ok(false), "not to_spend: ordinary PSBT");
    let unknown = message_psbt_v2(2, &[0x6a], true, false);
    assert!(recognized(&unknown).is_err(), "no spent output");
    assert_eq!(status(&unknown, "GEN-MSG-1"), TraceStatus::Incomplete, "rules about BIP322 PSBTs cannot apply");
}

/// A v0 PSBT reads the version and outputs from the unsigned transaction.
fn message_psbt_v0(version: u32) -> Vec<u8> {
    let msg = b"Hello World".to_vec();
    let challenge = vec![0x51, 0x20, 0x01, 0x02];
    let tx = Transaction {
        version,
        inputs: vec![TxIn { txid: bip322_to_spend_txid(&msg, &challenge), vout: 0, script_sig: vec![], sequence: 0, witness: vec![] }],
        outputs: vec![TxOut { amount: 0, script_pubkey: vec![0x6a] }],
        locktime: 0,
    };
    encode(&Psbt {
        maps: vec![
            vec![field(GLOBAL_UNSIGNED_TX, vec![], tx.serialize_without_witness()), field(GLOBAL_GENERIC_SIGNED_MESSAGE, vec![], msg)],
            vec![field(IN_WITNESS_UTXO, vec![], txout(0, &challenge))],
            vec![],
        ],
        bips: vec![],
    })
}

#[test]
fn bip322_v0_to_sign_version() {
    assert_eq!(recognized(&message_psbt_v0(0)), Ok(true));
    // A to_sign version other than 0 or 2 is an upgradeable rule: still a BIP322
    // PSBT, but inconclusive (GEN-MSG-4), not invalid.
    assert_eq!(recognized(&message_psbt_v0(1)), Ok(true));
    assert_eq!(status(&message_psbt_v0(1), "GEN-MSG-4"), TraceStatus::Incomplete);
    assert_eq!(status(&message_psbt_v0(0), "GEN-MSG-4"), TraceStatus::Passed);
}

// BIP322 rows: the published hashes, and GEN-MSG-1 to GEN-MSG-4 on local fixtures.

#[test]
fn bip322_published_message_and_to_spend_hashes() {
    let vectors: Value = serde_json::from_str(include_str!("../../vectors/bip322_basic.json")).unwrap();
    // Every tx_hashes case uses bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l, whose
    // witness program is 2b05d564e6a7a33c087f16e0f730d1440123799d.
    let challenge = hex("00142b05d564e6a7a33c087f16e0f730d1440123799d");
    let cases = vectors["tx_hashes"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for case in cases {
        let message = case["message"].as_str().unwrap().as_bytes();
        assert_eq!(address_of(case), "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l");
        let hash = psbt_spec::taproot::tagged_hash("BIP0322-signed-message", message);
        assert_eq!(hash.to_vec(), hex(case["message_hash"].as_str().unwrap()));
        let mut txid = bip322_to_spend_txid(message, &challenge);
        txid.reverse();
        assert_eq!(txid.to_vec(), hex(case["to_spend_tx_hash"].as_str().unwrap()));
    }
}

fn address_of(case: &Value) -> &str {
    case["address"].as_str().unwrap()
}

#[test]
fn bip322_challenge_utxo_amount() {
    assert_eq!(status(&message_psbt_v2(2, &[0x6a], true, true), "GEN-MSG-1"), TraceStatus::Passed);
    let msg = b"Hello World".to_vec();
    let challenge = vec![0x00, 0x14, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44];
    let psbt = v2(
        vec![field(GLOBAL_GENERIC_SIGNED_MESSAGE, vec![], msg.clone())],
        vec![field(IN_WITNESS_UTXO, vec![], txout(5, &challenge))],
        vec![output(0, &[0x6a])],
        bip322_to_spend_txid(&msg, &challenge),
    );
    assert_eq!(status(&encode(&psbt), "GEN-MSG-1"), TraceStatus::Failed);
    // An ordinary PSBT is not checked.
    assert_eq!(status(&message_psbt_v2(2, &[0x51], true, true), "GEN-MSG-1"), TraceStatus::NotApplicable);
}

/// The v2 message PSBT with extra inputs (prevout txid, records) appended.
fn with_inputs(extra: Vec<([u8; 32], Vec<Record>)>) -> Vec<u8> {
    let Ok(mut psbt) = psbt_spec::encoding::scan(&message_psbt_v2(2, &[0x6a], true, true)) else { panic!() };
    for (txid, records) in extra {
        let mut map = vec![field(IN_PREVIOUS_TXID, vec![], txid.to_vec()), field(IN_OUTPUT_INDEX, vec![], 0u32.to_le_bytes().to_vec())];
        map.extend(records);
        psbt.maps.insert(psbt.maps.len() - 1, map);
    }
    psbt.maps[0].iter_mut().find(|r| r.key_type == GLOBAL_INPUT_COUNT).unwrap().value = vec![psbt.maps.len() as u8 - 2];
    encode(&psbt)
}

#[test]
fn bip322_proof_of_funds_inputs_carry_utxos() {
    let utxo = || field(IN_WITNESS_UTXO, vec![], txout(1_000, &[0x51, 0x20, 1, 2]));
    assert_eq!(status(&message_psbt_v2(2, &[0x6a], true, true), "GEN-MSG-2"), TraceStatus::NotApplicable);
    assert_eq!(status(&with_inputs(vec![([4; 32], vec![utxo()])]), "GEN-MSG-2"), TraceStatus::Passed);
    assert_eq!(status(&with_inputs(vec![([4; 32], vec![])]), "GEN-MSG-2"), TraceStatus::Failed);
}

#[test]
fn bip322_signatures_use_sighash_all() {
    let sig = |hash_type: u8| field(IN_PARTIAL_SIG, hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"), vec![0x30, 0x01, hash_type]);
    let signed = |hash_type: u8| {
        let Ok(mut psbt) = psbt_spec::encoding::scan(&message_psbt_v2(2, &[0x6a], true, true)) else { panic!() };
        psbt.maps[1].push(sig(hash_type));
        encode(&psbt)
    };
    assert_eq!(status(&signed(0x01), "GEN-MSG-3"), TraceStatus::Passed);
    assert_eq!(status(&signed(0x02), "GEN-MSG-3"), TraceStatus::Failed);
    assert_eq!(status(&message_psbt_v2(2, &[0x6a], true, true), "GEN-MSG-3"), TraceStatus::NotApplicable);
}

#[test]
fn bip322_upgradeable_features_are_inconclusive() {
    let v3 = message_psbt_v2(3, &[0x6a], true, true);
    assert_eq!(recognized(&v3), Ok(true));
    assert_eq!(status(&v3, "GEN-MSG-4"), TraceStatus::Incomplete);
    let segwit_v2 = with_inputs(vec![([4; 32], vec![field(IN_WITNESS_UTXO, vec![], txout(1_000, &[0x52, 0x02, 1, 2]))])]);
    assert_eq!(status(&segwit_v2, "GEN-MSG-4"), TraceStatus::Incomplete);
    assert_eq!(status(&message_psbt_v2(2, &[0x6a], true, true), "GEN-MSG-4"), TraceStatus::Passed);
}
