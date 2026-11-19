use psbt_spec::context::*;
use psbt_spec::encoding::{
    p2sh_script, p2wsh_script, put_compact_size, Psbt, Record, Transaction, TxIn, TxOut, MAGIC,
};
use psbt_spec::{evaluate_for_signing, Evaluation, SignatureKind};

fn field(key_type: u64, value: Vec<u8>) -> Record {
    Record {
        key_type,
        key_data: Vec::new(),
        value,
    }
}

fn witness_utxo(output: &TxOut) -> Record {
    let mut bytes = output.amount.to_le_bytes().to_vec();
    put_compact_size(&mut bytes, output.script_pubkey.len());
    bytes.extend(&output.script_pubkey);
    field(IN_WITNESS_UTXO, bytes)
}

fn fixture(script_pubkey: Vec<u8>) -> (Psbt, Transaction) {
    let funding = Transaction {
        version: 2,
        inputs: vec![TxIn {
            txid: [0; 32],
            vout: u32::MAX,
            script_sig: vec![1, 1],
            sequence: u32::MAX,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            amount: 10_000,
            script_pubkey,
        }],
        locktime: 0,
    };
    let psbt = Psbt {
        maps: vec![
            vec![
                field(GLOBAL_VERSION, 2u32.to_le_bytes().to_vec()),
                field(GLOBAL_TX_VERSION, 2u32.to_le_bytes().to_vec()),
                field(GLOBAL_INPUT_COUNT, vec![1]),
                field(GLOBAL_OUTPUT_COUNT, vec![1]),
            ],
            vec![
                field(IN_PREVIOUS_TXID, funding.txid().to_vec()),
                field(IN_OUTPUT_INDEX, 0u32.to_le_bytes().to_vec()),
            ],
            vec![
                field(0x03, 9_000i64.to_le_bytes().to_vec()),
                field(OUT_SCRIPT, vec![0x51]),
            ],
        ],
        bips: vec![],
    };
    (psbt, funding)
}

fn encode(psbt: &Psbt) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    for map in &psbt.maps {
        for record in map {
            let mut key = Vec::new();
            put_compact_size(&mut key, record.key_type.try_into().unwrap());
            key.extend(&record.key_data);
            put_compact_size(&mut bytes, key.len());
            bytes.extend(key);
            put_compact_size(&mut bytes, record.value.len());
            bytes.extend(&record.value);
        }
        bytes.push(0);
    }
    bytes
}

fn check(psbt: &Psbt, kind: SignatureKind) -> Evaluation {
    evaluate_for_signing(&encode(psbt), &[], 0, kind)
}

/// The BIP174 signer data checks, split from the former ROLE-S-1.
const DATA_CHECKS: [&str; 4] = ["ROLE-S-1", "ROLE-S-2", "ROLE-S-3", "ROLE-S-4"];

fn assert_incomplete(outcome: Evaluation) {
    assert!(
        matches!(outcome, Evaluation::Incomplete(ref error) if DATA_CHECKS.contains(&error.rule)),
        "{outcome:?}"
    );
}

fn assert_failed(outcome: Evaluation) {
    assert!(
        matches!(outcome, Evaluation::Failed(ref error) if DATA_CHECKS.contains(&error.rule)),
        "{outcome:?}"
    );
}

#[test]
fn missing_utxo_is_incomplete() {
    let (psbt, _) = fixture([&[0, 20][..], &[1; 20]].concat());
    assert_incomplete(check(&psbt, SignatureKind::Witness));
}

#[test]
fn supplied_witness_utxo_requires_the_witness_signature_operation() {
    let (mut psbt, funding) = fixture([&[0, 20][..], &[1; 20]].concat());
    psbt.maps[1].push(witness_utxo(&funding.outputs[0]));
    assert_eq!(check(&psbt, SignatureKind::Witness), Evaluation::Verified);
    assert_failed(check(&psbt, SignatureKind::NonWitness));
}

#[test]
fn non_witness_utxo_authenticates_txid_and_output_index() {
    let (mut psbt, funding) = fixture([&[0x76, 0xa9, 20][..], &[1; 20], &[0x88, 0xac]].concat());
    psbt.maps[1].push(field(
        IN_NON_WITNESS_UTXO,
        funding.serialize_without_witness(),
    ));
    assert_eq!(
        check(&psbt, SignatureKind::NonWitness),
        Evaluation::Verified
    );
    assert_failed(check(&psbt, SignatureKind::Witness));
    psbt.maps[1][0].value[0] ^= 1;
    assert_failed(check(&psbt, SignatureKind::NonWitness));
    psbt.maps[1][0].value[0] ^= 1;
    psbt.maps[1][1].value = 1u32.to_le_bytes().to_vec();
    assert_failed(check(&psbt, SignatureKind::NonWitness));
}

#[test]
fn supplied_utxos_must_agree() {
    let (mut psbt, funding) = fixture([&[0, 20][..], &[1; 20]].concat());
    psbt.maps[1].push(field(
        IN_NON_WITNESS_UTXO,
        funding.serialize_without_witness(),
    ));
    psbt.maps[1].push(witness_utxo(&funding.outputs[0]));
    assert_eq!(check(&psbt, SignatureKind::Witness), Evaluation::Verified);
    let mut conflicting = funding.outputs[0].clone();
    conflicting.amount += 1;
    *psbt.maps[1].last_mut().unwrap() = witness_utxo(&conflicting);
    assert_failed(check(&psbt, SignatureKind::Witness));
}

#[test]
fn nested_witness_redeem_script_must_be_available_and_match() {
    let redeem_script = [&[0, 20][..], &[1; 20]].concat();
    let (mut psbt, funding) = fixture(p2sh_script(&redeem_script));
    psbt.maps[1].push(witness_utxo(&funding.outputs[0]));
    assert_incomplete(check(&psbt, SignatureKind::Witness));
    psbt.maps[1].push(field(IN_REDEEM_SCRIPT, vec![0x51]));
    assert_failed(check(&psbt, SignatureKind::Witness));
    psbt.maps[1].last_mut().unwrap().value = redeem_script;
    assert_eq!(check(&psbt, SignatureKind::Witness), Evaluation::Verified);
}

#[test]
fn native_and_nested_witness_scripts_must_match_when_provided() {
    let witness_script = vec![0x51];
    let program = p2wsh_script(&witness_script);
    for nested in [false, true] {
        let script = if nested {
            p2sh_script(&program)
        } else {
            program.clone()
        };
        let (mut psbt, funding) = fixture(script);
        psbt.maps[1].push(witness_utxo(&funding.outputs[0]));
        if nested {
            psbt.maps[1].push(field(IN_REDEEM_SCRIPT, program.clone()));
        }
        // BIP174 checks a witnessScript only when one is provided.
        assert_eq!(check(&psbt, SignatureKind::Witness), Evaluation::Verified);
        psbt.maps[1].push(field(IN_WITNESS_SCRIPT, vec![0x52]));
        assert_failed(check(&psbt, SignatureKind::Witness));
        psbt.maps[1].last_mut().unwrap().value = witness_script.clone();
        assert_eq!(check(&psbt, SignatureKind::Witness), Evaluation::Verified);
    }
}

#[test]
fn provided_scripts_the_spent_script_does_not_commit_to_fail() {
    // BIP174: a provided redeemScript or witnessScript must match, even on a
    // P2WPKH spend that needs neither.
    let (mut psbt, funding) = fixture([&[0, 20][..], &[1; 20]].concat());
    psbt.maps[1].push(witness_utxo(&funding.outputs[0]));
    psbt.maps[1].push(field(IN_REDEEM_SCRIPT, vec![0x51]));
    assert!(matches!(check(&psbt, SignatureKind::Witness), Evaluation::Failed(ref v) if v.rule == "ROLE-S-2"));
    psbt.maps[1].pop();
    psbt.maps[1].push(field(IN_WITNESS_SCRIPT, vec![0x52]));
    assert!(matches!(check(&psbt, SignatureKind::Witness), Evaluation::Failed(ref v) if v.rule == "ROLE-S-3"));
}

#[test]
fn signing_evaluation_targets_only_the_selected_input() {
    let (mut psbt, funding) = fixture([&[0, 20][..], &[1; 20]].concat());
    let second = psbt.maps[1].clone();
    psbt.maps[1].push(witness_utxo(&funding.outputs[0]));
    psbt.maps.insert(2, second);
    psbt.maps[0]
        .iter_mut()
        .find(|field| field.key_type == GLOBAL_INPUT_COUNT)
        .unwrap()
        .value = vec![2];
    assert_eq!(check(&psbt, SignatureKind::Witness), Evaluation::Verified);
    assert_incomplete(evaluate_for_signing(
        &encode(&psbt),
        &[],
        1,
        SignatureKind::Witness,
    ));
    assert_failed(evaluate_for_signing(
        &encode(&psbt),
        &[],
        2,
        SignatureKind::Witness,
    ));
}

#[test]
fn malformed_fields_fail_before_signing_context_projection() {
    let (mut psbt, _) = fixture(vec![0x51]);
    psbt.maps[1][0].value.pop();
    assert!(
        matches!(check(&psbt, SignatureKind::NonWitness), Evaluation::Failed(ref error) if error.rule == "GEN-F-5")
    );
}
