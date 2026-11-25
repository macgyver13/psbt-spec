mod common;

use common::{outcome, passed, psbt, vectors};
use psbt_spec::context::{determine_locktime, PsbtContext};
use psbt_spec::encoding::scan;
use psbt_spec::{evaluate, Bip, Evaluation};
use serde_json::Value;

/// Each vector names the rule its entry point stops at (`rule`, Failed unless
/// `outcome` says incomplete), or passes when `valid` is true.
fn check(v: &Value, bips: &[Bip]) -> Option<String> {
    let got = outcome(v, bips);
    let expected = v["rule"].as_str();
    let incomplete = v["outcome"].as_str() == Some("incomplete");
    let ok = match (&got, expected) {
        (e, None) => passed(e),
        (Evaluation::Failed(x), Some(rule)) => !incomplete && x.rule == rule,
        (Evaluation::Incomplete(x), Some(rule)) => incomplete && x.rule == rule,
        _ => false,
    };
    (!ok).then(|| format!("{}: expected {expected:?}{}, got {got:?}", v["description"], if incomplete { " (incomplete)" } else { "" }))
}

fn run(name: &str, bips: &[Bip]) {
    let mismatches: Vec<_> = vectors(name).iter().filter_map(|v| check(v, bips)).collect();
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

#[test]
fn bip376_vectors() {
    run("bip376", &[Bip::Bip376]);
    assert_disabled_results("bip376");
}

/// Without the extension enabled, every registered field is still known and
/// format-checked, but the silent-payment rules (GEN-SP) do not run. Without
/// BIP375, PSBT_OUT_SP_V0_INFO does not stand in for PSBT_OUT_SCRIPT, so such
/// outputs fail GEN-ST-2. Rules no BIP gates, such as Taproot's, still apply.
fn assert_disabled_results(name: &str) {
    for v in vectors(name) {
        let bytes = psbt(&v);
        let Ok(parsed) = scan(&bytes) else { panic!("{}", v["description"]) };
        let ctx = PsbtContext::new(&parsed);
        let info_without_script = ctx.version == 2
            && ctx.outputs().iter().any(|o| o.value(0x09).is_some() && o.value(0x04).is_none());
        let expected = match v["rule"].as_str() {
            Some(e) if !e.starts_with("GEN-SP-") && v["outcome"].is_null() => Some(e),
            _ if info_without_script => Some("GEN-ST-2"),
            _ => None,
        };
        let got = match evaluate(&bytes, &[]) {
            Evaluation::Failed(x) => Some(x.rule),
            _ => None,
        };
        assert_eq!(got, expected, "{}", v["description"]);
    }
}

#[test]
fn bip375_disabled_vectors() {
    assert_disabled_results("bip375");
}

#[test]
fn bip370_locktime_vectors() {
    for v in vectors("bip370_locktime") {
        let bytes = psbt(&v);
        let ctx = PsbtContext::new(&scan(&bytes).ok().unwrap());
        let expected = v["locktime"].as_u64().map(|l| l as u32);
        assert_eq!(determine_locktime(&ctx), expected, "{}", v["description"]);
        let rule = match evaluate(&bytes, &[]) {
            Evaluation::Failed(x) => Some(x.rule),
            _ => None,
        };
        assert_eq!(rule, expected.is_none().then_some("GEN-T-1"), "{}", v["description"]);
    }
}
