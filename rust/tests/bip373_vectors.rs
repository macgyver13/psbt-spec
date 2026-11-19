
use base64::{engine::general_purpose::STANDARD, Engine};
use psbt_spec::evaluate;
use serde_json::Value;

#[test]
fn test_bip373_test_vectors() {
    let json_str = include_str!("../../vectors/bip373.json");
    let vectors: Vec<Value> = serde_json::from_str::<Value>(json_str).unwrap()["vectors"].as_array().unwrap().clone();

    for v in vectors {
        let b64 = v["psbt"].as_str().unwrap();
        let bytes = STANDARD.decode(b64).unwrap();
        let expected_err = v["rule"].as_str();

        let res = evaluate(&bytes, &[]).into_verdict();
        match expected_err {
            Some(err) => {
                assert!(res.is_err(), "expected error {err} for {}, got Ok", v["description"]);
                let actual_err = res.unwrap_err();
                assert_eq!(actual_err.rule, err, "error rule mismatch for {}", v["description"]);
            }
            None => {
                assert!(res.is_ok(), "expected valid for {}, got {:?}", v["description"], res.err());
            }
        }
    }
}
