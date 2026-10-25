use base64::Engine;
fn main() {
    let path = std::env::args().nth(1).unwrap_or("../vectors/bip375.json".into());
    let v: Vec<serde_json::Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    for (i, t) in v.iter().enumerate() {
        let b = base64::engine::general_purpose::STANDARD.decode(t["psbt"].as_str().unwrap()).unwrap();
        let r = psbt_spec::validate_for_signing(&b, &[psbt_spec::Bip::Bip375]).err().map(|e| (e.rule, e.detail));
        println!("{i} exp={} got={r:?} | {}", t["error"], t["description"]);
    }
}
