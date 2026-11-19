
use base64::{engine::general_purpose::STANDARD, Engine};
use psbt_spec::algebra::CheckOutcome;
use psbt_spec::context::PsbtContext;
use psbt_spec::encoding::scan;
use psbt_spec::rules::taproot::*;
use serde_json::Value;

#[test]
fn test_taproot_rules_on_bip371_valid_vectors() {
    let json_str = include_str!("../../vectors/bip371.json");
    let vectors: Vec<Value> = serde_json::from_str::<Value>(json_str).unwrap()["vectors"].as_array().unwrap().clone();

    for v in vectors {
        if v["valid"] == true {
            let b64 = v["psbt"].as_str().unwrap();
            let bytes = STANDARD.decode(b64).ok().unwrap();
            let psbt = scan(&bytes).ok().unwrap();
            let ctx = PsbtContext::new(&psbt);

            for input in ctx.inputs() {
                let outcome_cb = validate_taproot_control_block_commitment(&input);
                assert!(
                    matches!(outcome_cb, CheckOutcome::Verified | CheckOutcome::NotApplicable),
                    "GEN-TR-1 failed on valid vector {}: {:?}",
                    v["description"],
                    outcome_cb
                );

                let outcome_km = validate_taproot_key_commitments(&input);
                assert!(
                    matches!(outcome_km, CheckOutcome::Verified | CheckOutcome::NotApplicable),
                    "GEN-TR-2 failed on valid vector {}: {:?}",
                    v["description"],
                    outcome_km
                );
            }
        }
    }
}

mod synthetic {
    use psbt_spec::algebra::CheckOutcome;
    use psbt_spec::context::*;
    use psbt_spec::encoding::{put_compact_size, Psbt, Record, Transaction, TxIn, TxOut};
    use psbt_spec::rules::taproot::*;
    use psbt_spec::taproot::{tagged_hash, taproot_output_key};

    /// x(G), a valid x-only internal key.
    const INTERNAL: [u8; 32] = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
        0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    ];
    const SCRIPT: [u8; 1] = [0x51];
    const LEAF_VERSION: u8 = 0xc0;

    fn field(key_type: u64, key_data: Vec<u8>, value: Vec<u8>) -> Record {
        Record { key_type, key_data, value }
    }

    /// A single-leaf tree: its P2TR script and the leaf's control block.
    fn tree() -> (Vec<u8>, Vec<u8>) {
        let leaf = tagged_hash("TapLeaf", &[LEAF_VERSION, 1, SCRIPT[0]]);
        let (output_key, odd) = taproot_output_key(&INTERNAL, Some(&leaf)).unwrap();
        let mut control_block = vec![LEAF_VERSION | u8::from(odd)];
        control_block.extend(INTERNAL);
        ([&[0x51, 0x20][..], &output_key[..]].concat(), control_block)
    }

    fn txout(spk: &[u8]) -> Vec<u8> {
        let mut bytes = 10_000i64.to_le_bytes().to_vec();
        put_compact_size(&mut bytes, spk.len());
        bytes.extend(spk);
        bytes
    }

    fn witness(items: &[&[u8]]) -> Vec<u8> {
        let mut bytes = Vec::new();
        put_compact_size(&mut bytes, items.len());
        for item in items {
            put_compact_size(&mut bytes, item.len());
            bytes.extend(*item);
        }
        bytes
    }

    fn psbt(input: Vec<Record>) -> Psbt {
        let mut map = vec![
            field(IN_PREVIOUS_TXID, vec![], vec![0; 32]),
            field(IN_OUTPUT_INDEX, vec![], 0u32.to_le_bytes().to_vec()),
        ];
        map.extend(input);
        Psbt {
            maps: vec![
                vec![
                    field(GLOBAL_VERSION, vec![], 2u32.to_le_bytes().to_vec()),
                    field(GLOBAL_TX_VERSION, vec![], 2u32.to_le_bytes().to_vec()),
                    field(GLOBAL_INPUT_COUNT, vec![], vec![1]),
                    field(GLOBAL_OUTPUT_COUNT, vec![], vec![0]),
                ],
                map,
            ],
            bips: vec![],
        }
    }

    fn leaf_check(input: Vec<Record>) -> CheckOutcome {
        let psbt = psbt(input);
        validate_taproot_control_block_commitment(&PsbtContext::new(&psbt).inputs()[0])
    }

    fn final_check(input: Vec<Record>) -> CheckOutcome {
        let psbt = psbt(input);
        validate_taproot_script_path_finalization(&PsbtContext::new(&psbt).inputs()[0])
    }

    fn leaf_record(control_block: Vec<u8>, version: u8) -> Record {
        field(IN_TAP_LEAF_SCRIPT, control_block, vec![SCRIPT[0], version])
    }

    #[test]
    fn leaf_script_commitment() {
        let (spk, cb) = tree();
        let utxo = field(IN_WITNESS_UTXO, vec![], txout(&spk));
        assert_eq!(leaf_check(vec![utxo.clone()]), CheckOutcome::NotApplicable, "no leaf scripts");
        assert_eq!(leaf_check(vec![utxo.clone(), leaf_record(cb.clone(), LEAF_VERSION)]), CheckOutcome::Verified);
        assert!(matches!(leaf_check(vec![leaf_record(cb.clone(), LEAF_VERSION)]), CheckOutcome::Incomplete(_)));

        let mut other_version = cb.clone();
        other_version[0] ^= 0x02;
        assert!(
            matches!(leaf_check(vec![utxo.clone(), leaf_record(other_version, LEAF_VERSION)]), CheckOutcome::Failed(_)),
            "control block leaf version differs from the value's"
        );

        let mut wrong_key = spk.clone();
        wrong_key[2] ^= 1;
        let wrong_utxo = field(IN_WITNESS_UTXO, vec![], txout(&wrong_key));
        assert!(matches!(leaf_check(vec![wrong_utxo, leaf_record(cb.clone(), LEAF_VERSION)]), CheckOutcome::Failed(_)));

        let p2wpkh = field(IN_WITNESS_UTXO, vec![], txout(&[[0x00, 0x14].as_slice(), &[0; 20]].concat()));
        assert!(matches!(leaf_check(vec![p2wpkh, leaf_record(cb, LEAF_VERSION)]), CheckOutcome::Failed(_)));
    }

    #[test]
    fn non_witness_utxo_is_a_spent_output() {
        let (spk, cb) = tree();
        let funding = Transaction {
            version: 2,
            inputs: vec![TxIn { txid: [0; 32], vout: 0, script_sig: vec![], sequence: 0, witness: vec![] }],
            outputs: vec![TxOut { amount: 10_000, script_pubkey: spk }],
            locktime: 0,
        };
        let utxo = field(IN_NON_WITNESS_UTXO, vec![], funding.serialize_without_witness());
        assert_eq!(leaf_check(vec![utxo.clone(), leaf_record(cb.clone(), LEAF_VERSION)]), CheckOutcome::Verified);
        let final_witness = field(IN_FINAL_SCRIPTWITNESS, vec![], witness(&[&[1; 64], &SCRIPT, &cb]));
        assert_eq!(final_check(vec![utxo, final_witness]), CheckOutcome::Verified);
    }

    #[test]
    fn script_path_final_witness() {
        let (spk, cb) = tree();
        let utxo = field(IN_WITNESS_UTXO, vec![], txout(&spk));
        let fin = |items: &[&[u8]]| field(IN_FINAL_SCRIPTWITNESS, vec![], witness(items));

        assert_eq!(final_check(vec![utxo.clone(), fin(&[&[1; 64], &SCRIPT, &cb])]), CheckOutcome::Verified);
        assert_eq!(final_check(vec![utxo.clone(), fin(&[&[1; 64], &SCRIPT, &cb, &[0x50, 1]])]), CheckOutcome::Verified, "annex");
        assert_eq!(final_check(vec![utxo.clone(), fin(&[&[1; 64]])]), CheckOutcome::NotApplicable, "key path");
        assert_eq!(final_check(vec![utxo.clone(), fin(&[&[1; 64], &[0x50, 1]])]), CheckOutcome::NotApplicable, "key path with annex");
        assert_eq!(
            final_check(vec![utxo.clone(), fin(&[&[1; 64], &SCRIPT, &cb]), field(IN_TAP_KEY_SIG, vec![], vec![1; 64])]),
            CheckOutcome::Verified,
            "cleanup is guidance, not checked by this rule"
        );

        let mut tampered = cb.clone();
        tampered[1] ^= 1;
        assert!(matches!(final_check(vec![utxo.clone(), fin(&[&[1; 64], &SCRIPT, &tampered])]), CheckOutcome::Failed(_)));
        assert!(matches!(final_check(vec![utxo.clone(), fin(&[&[1; 64], &[0x52], &cb])]), CheckOutcome::Failed(_)), "wrong leaf script");
        assert!(matches!(final_check(vec![utxo, fin(&[&[1; 64], &SCRIPT, &[0xc0; 34]])]), CheckOutcome::Failed(_)), "malformed control block");
        assert!(matches!(final_check(vec![fin(&[&[1; 64], &SCRIPT, &cb])]), CheckOutcome::Incomplete(_)), "no spent output");
    }
}
