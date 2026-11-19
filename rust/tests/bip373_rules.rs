//! GEN-MS-1 on the published BIP373 vectors and on mutations of them, observed
//! through the General rule graph.
mod common;

use base64::{engine::general_purpose::STANDARD, Engine};
use common::{encode, status};
use psbt_spec::algebra::TraceStatus;
use psbt_spec::context::{IN_MUSIG2_PARTIAL_SIG, IN_MUSIG2_PUB_NONCE, IN_TAP_LEAF_SCRIPT};
use psbt_spec::encoding::{scan, Psbt};
use serde_json::Value;

fn valid_vectors() -> Vec<(String, Psbt)> {
    let vectors: Vec<Value> = serde_json::from_str::<Value>(include_str!("../../vectors/bip373.json")).unwrap()["vectors"].as_array().unwrap().clone();
    vectors
        .into_iter()
        .filter(|v| v["valid"] == true)
        .map(|v| {
            let bytes = STANDARD.decode(v["psbt"].as_str().unwrap()).unwrap();
            let Ok(psbt) = scan(&bytes) else { panic!() };
            (v["description"].as_str().unwrap().to_owned(), psbt)
        })
        .collect()
}

fn has_session_records(psbt: &Psbt) -> bool {
    psbt.maps.iter().flatten().any(|r| r.key_type == IN_MUSIG2_PUB_NONCE || r.key_type == IN_MUSIG2_PARTIAL_SIG)
}

#[test]
fn published_vectors() {
    let mut passed = 0;
    for (description, psbt) in valid_vectors() {
        let expected = if has_session_records(&psbt) { TraceStatus::Passed } else { TraceStatus::NotApplicable };
        assert_eq!(status(&encode(&psbt), "GEN-MS-1"), expected, "{description}");
        passed += usize::from(expected == TraceStatus::Passed);
    }
    assert!(passed > 0, "no published vector reaches Passed");
}

/// The first input map of the first vector whose description contains `needle`.
fn mutated(needle: &str, edit: impl FnOnce(&mut Psbt)) -> Vec<u8> {
    let (_, mut psbt) = valid_vectors().into_iter().find(|(d, _)| d.contains(needle)).unwrap();
    edit(&mut psbt);
    encode(&psbt)
}

#[test]
fn key_path_plain_key_must_be_output_key() {
    let bytes = mutated("output key is a MuSig2 Aggregate Pubkey (With all pubnonces)", |psbt| {
        let record = psbt.maps.iter_mut().flatten().find(|r| r.key_type == IN_MUSIG2_PUB_NONCE).unwrap();
        // Replace the plain key with the participant key, a different valid point.
        let participant = record.key_data[..33].to_vec();
        record.key_data[33..66].copy_from_slice(&participant);
    });
    assert_eq!(status(&bytes, "GEN-MS-1"), TraceStatus::Failed);
}

#[test]
fn script_path_plain_key_must_be_in_leaf() {
    let bytes = mutated("key in a script is a MuSig2 Aggregate Pubkey (With all pubnonces)", |psbt| {
        let record = psbt.maps.iter_mut().flatten().find(|r| r.key_type == IN_MUSIG2_PUB_NONCE).unwrap();
        let participant = record.key_data[..33].to_vec();
        record.key_data[33..66].copy_from_slice(&participant);
    });
    assert_eq!(status(&bytes, "GEN-MS-1"), TraceStatus::Failed);
}

#[test]
fn unknown_leaf_is_incomplete() {
    let bytes = mutated("key in a script is a MuSig2 Aggregate Pubkey (With all pubnonces)", |psbt| {
        for map in &mut psbt.maps {
            map.retain(|r| r.key_type != IN_TAP_LEAF_SCRIPT);
        }
    });
    assert_eq!(status(&bytes, "GEN-MS-1"), TraceStatus::Incomplete);
}
