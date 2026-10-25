use base64::Engine;
fn main() {
    for f in ["bip174", "bip370"] {
        let s = std::fs::read_to_string(format!("../vectors/{f}.raw.json")).unwrap();
        for line in s.lines().filter(|l| l.contains("\"psbt\"") || l.contains("\"description\"") || l.contains("\"section\"")) {
            let v = line.split(": ").nth(1).unwrap().trim_end_matches(',').trim_matches('"');
            if line.contains("\"psbt\"") {
                let b = base64::engine::general_purpose::STANDARD.decode(v).unwrap();
                println!("   validity={:?}\n   signer={:?}", psbt_spec::validate(&b, &[]).err().map(|e| (e.rule, e.detail)), psbt_spec::validate_for_signing(&b, &[]).err().map(|e| (e.rule, e.detail)));
            } else { println!("{v}"); }
        }
    }
}
