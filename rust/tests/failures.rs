//! The `failed` / `incomplete` split of the all-failures entry points, and the
//! received-and-returned forms of signing and finalizing.

mod common;

use common::{psbt, vectors};
use psbt_spec::{failing_rules_finalizing, failing_rules_signing, Bip, Failures};

#[test]
fn merge_keeps_a_rule_failed_anywhere_only_in_failed() {
    let a = Failures { failed: vec!["GEN-T-2"], incomplete: vec!["ROLE-F-1", "ROLE-F-4"], passed: vec!["GEN-F-1"] };
    let b = Failures { failed: vec!["ROLE-F-1", "GEN-T-2"], incomplete: vec!["ROLE-F-4"], passed: vec!["ROLE-F-4"] };
    let merged = a.merge(b);
    assert_eq!(merged.failed, ["GEN-T-2", "ROLE-F-1"]);
    assert_eq!(merged.incomplete, ["ROLE-F-4"]);
    assert_eq!(merged.passed, ["GEN-F-1"]);
}

/// A role that returns the PSBT it was given unchanged changed nothing, so a
/// valid PSBT attributes no failure under either received-and-returned form.
#[test]
fn returning_a_valid_psbt_unchanged_fails_nothing() {
    for (corpus, bips) in [("bip174", &[][..]), ("bip375", &[Bip::Bip375][..])] {
        for v in vectors(corpus).iter().filter(|v| v["valid"] == true && v["task"] == "finalizing") {
            let bytes = psbt(v);
            assert!(failing_rules_finalizing(&bytes, &bytes, bips).is_empty(), "{}", v["description"]);
            assert!(failing_rules_signing(&bytes, &bytes, bips).is_empty(), "{}", v["description"]);
        }
    }
}

/// A returned PSBT with other inputs than the received one is ROLE-S-9 alone,
/// as in `evaluate_signing`.
#[test]
fn signing_that_changes_the_inputs_fails_role_s_11_alone() {
    let all = vectors("bip375");
    let valid: Vec<Vec<u8>> = all.iter().filter(|v| v["valid"] == true && v["task"] == "finalizing").map(psbt).collect();
    let other = valid.iter().find(|p| **p != valid[0]).unwrap();
    assert_eq!(failing_rules_signing(&valid[0], other, &[Bip::Bip375]).failed, ["ROLE-S-9"]);
}
