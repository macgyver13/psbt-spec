use psbt_spec::encoding::decode_exact;
use psbt_spec::taproot::*;
use serde_json::Value;

#[test]
fn test_bip340_verification_vectors() {
    let csv = include_str!("../../vectors/bip340_vectors.csv");
    for line in csv.lines().skip(1) {
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split(',').collect();
        let pubkey_hex = parts[2];
        let msg_hex = parts[4];
        let sig_hex = parts[5];
        let result_str = parts[6];

        let mut pubkey = [0u8; 32];
        match hex::decode_to_slice(pubkey_hex, &mut pubkey) {
            Ok(_) => {},
            Err(_) => {
                assert_eq!(result_str, "FALSE", "invalid pubkey encoding");
                continue;
            }
        };

        let msg = hex::decode(msg_hex).unwrap();

        let mut sig = [0u8; 64];
        match hex::decode_to_slice(sig_hex, &mut sig) {
            Ok(_) => {},
            Err(_) => {
                assert_eq!(result_str, "FALSE", "invalid signature encoding");
                continue;
            }
        };

        let expected_ok = result_str == "TRUE";
        let actual_ok = psbt_spec::signature::verify_bip340(&pubkey, &msg, &sig) == psbt_spec::signature::Validity::Valid;
        assert_eq!(actual_ok, expected_ok, "vector index {} failed", parts[0]);
    }
}

#[test]
fn test_bip341_wallet_test_vectors() {
    let json_str = include_str!("../../vectors/bip341_wallet_vectors.json");
    let data: Value = serde_json::from_str(json_str).unwrap();

    for case in data["keyPathSpending"].as_array().unwrap() {
        let raw_tx_hex = case["given"]["rawUnsignedTx"].as_str().unwrap();
        let tx_bytes = hex::decode(raw_tx_hex).unwrap();
        let tx = decode_exact(&tx_bytes, |r| psbt_spec::encoding::read_tx(r, false)).unwrap();

        let utxos: Vec<psbt_spec::encoding::TxOut> = case["given"]["utxosSpent"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| {
                let amount = u["amountSats"].as_i64().unwrap();
                let spk = hex::decode(u["scriptPubKey"].as_str().unwrap()).unwrap();
                psbt_spec::encoding::TxOut {
                    amount,
                    script_pubkey: spk,
                }
            })
            .collect();

        for spend in case["inputSpending"].as_array().unwrap() {
            let txin_index = spend["given"]["txinIndex"].as_u64().unwrap() as usize;
            let hash_type = spend["given"]["hashType"].as_u64().unwrap() as u8;
            let expected_sighash = spend["intermediary"]["sigHash"].as_str().unwrap();

            let calculated_sighash = taproot_sighash(&tx, txin_index, &utxos, hash_type, None, None).unwrap();
            assert_eq!(
                hex::encode(calculated_sighash),
                expected_sighash,
                "input {txin_index} sighash mismatch"
            );
        }
    }
}

mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        let mut v = Vec::with_capacity(s.len() / 2);
        for chunk in s.as_bytes().chunks_exact(2) {
            let h = std::str::from_utf8(chunk).map_err(|_| ())?;
            let b = u8::from_str_radix(h, 16).map_err(|_| ())?;
            v.push(b);
        }
        Ok(v)
    }

    pub fn decode_to_slice(s: &str, slice: &mut [u8]) -> Result<(), ()> {
        if s.len() != slice.len() * 2 {
            return Err(());
        }
        for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
            let h = std::str::from_utf8(chunk).map_err(|_| ())?;
            let b = u8::from_str_radix(h, 16).map_err(|_| ())?;
            slice[i] = b;
        }
        Ok(())
    }

    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[test]
fn test_verify_taproot_control_block() {
    use base64::Engine;
    let json_str = include_str!("../../vectors/bip371.json");
    let vectors: Vec<Value> = serde_json::from_str::<Value>(json_str).unwrap()["vectors"].as_array().unwrap().clone();

    for v in &vectors {
        if v["valid"] == true && v["description"].as_str().unwrap().contains("script path only") {
            let b64 = v["psbt"].as_str().unwrap();
            let bytes = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
            let psbt = psbt_spec::encoding::scan(&bytes).ok().unwrap();
            let ctx = psbt_spec::context::PsbtContext::new(&psbt);

            for input in ctx.inputs() {
                if let Some(utxo) = input.witness_utxo() {
                    if utxo.script_pubkey.len() == 34 && utxo.script_pubkey[..2] == [0x51, 0x20] {
                        let output_key: &[u8; 32] = utxo.script_pubkey[2..].try_into().unwrap();
                        for record in psbt_spec::context::records(input.map(), psbt_spec::context::IN_TAP_LEAF_SCRIPT) {
                            let control_block = &record.key_data;
                            let leaf_val = &record.value;
                            let leaf_version = leaf_val[leaf_val.len() - 1];
                            let leaf_script = &leaf_val[..leaf_val.len() - 1];
                            let valid = verify_taproot_control_block(output_key, control_block, leaf_script, leaf_version);
                            assert!(valid, "Control block verification failed for {}", v["description"]);
                        }
                    }
                }
            }
        }
    }
}
