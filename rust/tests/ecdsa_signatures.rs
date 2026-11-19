//! Legacy and BIP143 signature messages and ECDSA verification, against
//! Bitcoin Core's sighash.json and BIP143's P2SH-P2WSH example.

mod common;

use common::hex;
use psbt_spec::ecdsa::{legacy_sighash, segwit_v0_sighash};
use psbt_spec::encoding::{decode_exact, read_tx};
use psbt_spec::signature::{verify_ecdsa, Validity};
use serde_json::Value;

/// Bitcoin Core `src/test/data/sighash.json` (43cb41859e). Its digests are shown
/// byte-reversed. Scripts with a 0xab byte are skipped: legacy_sighash does not
/// remove OP_CODESEPARATOR, and the evaluator reports such scripts as Incomplete.
#[test]
fn legacy_sighash_matches_bitcoin_core() {
    let vectors: Vec<Value> = serde_json::from_str(include_str!("../../vectors/bitcoin_core_sighash.json")).unwrap();
    let mut checked = 0;
    for v in &vectors[1..] {
        let script = hex(v[1].as_str().unwrap());
        if script.contains(&0xab) {
            continue;
        }
        let tx = decode_exact(&hex(v[0].as_str().unwrap()), |r| read_tx(r, false)).unwrap();
        let index = v[2].as_u64().unwrap() as usize;
        let hash_type = v[3].as_i64().unwrap() as u32;
        let mut expected = hex(v[4].as_str().unwrap());
        expected.reverse();
        assert_eq!(legacy_sighash(&tx, index, &script, hash_type).to_vec(), expected, "{v}");
        checked += 1;
    }
    assert!(checked > 250, "{checked} vectors");
}

/// BIP143's P2SH-P2WSH 6-of-6 example: one digest and one signature per
/// sighash type, covering NONE, SINGLE and ANYONECANPAY.
#[test]
fn segwit_v0_sighash_and_signatures_match_bip143() {
    let tx = decode_exact(&hex("010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000"), |r| read_tx(r, false)).unwrap();
    let witness_script = hex("56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae");
    let amount = 987_654_321;
    let cases = [
        (0x01, "185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c", "0307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3", "304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce"),
        (0x02, "e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36", "03b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b", "3044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce2715"),
        (0x03, "1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea", "034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a", "3044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c767954"),
        (0x81, "2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e", "033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f4", "3045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d163"),
        (0x82, "781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a", "03a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac16", "3045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a08"),
        (0x83, "511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b", "02d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b", "30440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b47"),
    ];
    for (hash_type, digest, pubkey, der) in cases {
        let sighash = segwit_v0_sighash(&tx, 0, &witness_script, amount, hash_type);
        assert_eq!(sighash.to_vec(), hex(digest), "hash type {hash_type:#04x}");
        assert_eq!(verify_ecdsa(&hex(pubkey), &sighash, &hex(der)), Validity::Valid, "hash type {hash_type:#04x}");
        let other = segwit_v0_sighash(&tx, 0, &witness_script, amount + 1, hash_type);
        assert_eq!(verify_ecdsa(&hex(pubkey), &other, &hex(der)), Validity::Invalid, "hash type {hash_type:#04x}");
    }
}
