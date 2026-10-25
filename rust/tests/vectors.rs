use std::collections::HashSet;

use base64::{engine::general_purpose::STANDARD, Engine};
use psbt_spec::algebra::{Doc, Entry};
use psbt_spec::context::{determine_locktime, unique_id, PsbtContext};
use psbt_spec::{
    encoding::scan, spec, validate, validate_combination, validate_for_extraction, validate_for_finalizing,
    validate_for_signing, Bip,
};
use serde_json::Value;

fn vectors(name: &str) -> Vec<Value> {
    let path = format!("{}/../vectors/{name}.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn psbt(v: &Value) -> Vec<u8> {
    STANDARD.decode(v["psbt"].as_str().unwrap()).unwrap()
}

/// Each vector must fail at exactly the rule it names, or pass when `error` is null.
/// Signer rule failures must still pass the validity rules on their own.
fn run(name: &str, bips: &[Bip]) {
    let mut mismatches = Vec::new();
    for v in vectors(name) {
        let bytes = psbt(&v);
        let expected = v["error"].as_str();
        let got = validate_for_signing(&bytes, bips).err();
        if got.as_ref().map(|e| e.rule) != expected {
            mismatches.push(format!("{}: expected {expected:?}, got {got:?}", v["description"]));
        }
        if expected.is_some_and(|r| r.starts_with('S')) {
            assert_eq!(validate(&bytes, bips), Ok(()), "{}", v["description"]);
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[test]
fn bip174_vectors() {
    run("bip174", &[]);
}

#[test]
fn bip370_vectors() {
    run("bip370", &[]);
}

#[test]
fn bip375_vectors() {
    run("bip375", &[Bip::Bip375]);
}

/// Signer snapshot, Input Finalizer, Transaction Extractor and Combiner vectors.
/// Each names its check and enabled BIPs.
#[test]
fn role_vectors() {
    let mut mismatches = Vec::new();
    for v in vectors("roles") {
        let bytes = psbt(&v);
        let bips: Vec<Bip> = v["bips"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| match b.as_u64() {
                Some(375) => Bip::Bip375,
                Some(376) => Bip::Bip376,
                other => panic!("unknown BIP {other:?}"),
            })
            .collect();
        let got = match v["check"].as_str() {
            Some("validity") => validate(&bytes, &bips),
            Some("finalizing") => validate_for_finalizing(&bytes, &bips),
            Some("extraction") => validate_for_extraction(&bytes, &bips),
            Some("combining") => {
                let combine: Vec<Vec<u8>> =
                    v["combine"].as_array().unwrap().iter().map(|p| STANDARD.decode(p.as_str().unwrap()).unwrap()).collect();
                let combine: Vec<&[u8]> = combine.iter().map(Vec::as_slice).collect();
                if let Some(expected) = v["unique_id"].as_str() {
                    let id = unique_id(&PsbtContext::new(&spec::parse(&bytes, &bips)));
                    let hex: String = id.iter().rev().map(|b| format!("{b:02x}")).collect();
                    assert_eq!(hex, expected, "{}", v["description"]);
                }
                validate_combination(&combine, &bytes, &bips)
            }
            other => panic!("unknown check {other:?}"),
        }
        .err();
        if got.as_ref().map(|e| e.rule) != v["error"].as_str() {
            mismatches.push(format!("{}: expected {}, got {got:?}", v["description"], v["error"]));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

/// A validator without BIP-376 treats its fields as unknown and accepts every vector.
#[test]
fn bip376_vectors() {
    run("bip376", &[Bip::Bip376]);
    for v in vectors("bip376") {
        assert_eq!(validate(&psbt(&v), &[]), Ok(()), "{}", v["description"]);
    }
}

#[test]
fn bip370_locktime_vectors() {
    for v in vectors("bip370_locktime") {
        let bytes = psbt(&v);
        let ctx = PsbtContext::new(&scan(&bytes).ok().unwrap());
        let expected = v["locktime"].as_u64().map(|l| l as u32);
        assert_eq!(determine_locktime(&ctx), expected, "{}", v["description"]);
        let rule = validate(&bytes, &[]).err().map(|e| e.rule);
        assert_eq!(rule, expected.is_none().then_some("T01"), "{}", v["description"]);
    }
}

#[test]
fn rule_ids_are_unique() {
    let mut doc = Doc::default();
    spec::validity_rules(&[]).describe(&mut doc);
    spec::signer_rules(&[]).describe(&mut doc);
    spec::extractor_rules(&[]).describe(&mut doc);
    spec::finalizer_rules(&[]).describe(&mut doc);
    spec::combiner_rules(&[]).describe(&mut doc);
    let mut seen = HashSet::new();
    for entry in doc.entries {
        if let Entry::Rule { id, .. } = entry {
            assert!(seen.insert(id), "duplicate rule ID {id}");
        }
    }
}
