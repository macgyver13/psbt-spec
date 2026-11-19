use base64::{engine::general_purpose::STANDARD, Engine};
use psbt_spec::spec;
use serde_json::Value;

#[test]
fn rule_bindings_execute_real_checks() {
    let vectors: Vec<Value> = serde_json::from_str::<Value>(include_str!("../../vectors/bip174.json")).unwrap()["vectors"].as_array().unwrap().clone();
    let valid = vectors
        .iter()
        .find(|v| v["valid"] == true)
        .unwrap();
    let mut bytes = STANDARD.decode(valid["psbt"].as_str().unwrap()).unwrap();
    assert_eq!(spec::general_rules(&[]).validate(&bytes), Ok(()));

    bytes[0] ^= 1;
    assert_eq!(spec::general_rules(&[]).validate(&bytes).unwrap_err().rule, "GEN-F-1");
}
