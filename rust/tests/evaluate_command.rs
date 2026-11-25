//! `psbt-spec evaluate` against a test-only adapter reproduces the verdict rows
//! of docs/examples/report.json, and `vectors` accepts the corpus.
//!
//! The adapter (tests/fixtures/example_adapter.py, needs python3) replays the
//! invented example-wallet of the report example over rust/tests/fixtures/roles.json.

use std::process::Command;

use serde_json::Value;

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");

fn read(path: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{ROOT}/{path}")).unwrap()).unwrap()
}

#[test]
fn evaluate_reproduces_the_example_report() {
    let out = std::env::temp_dir().join(format!("psbt-spec-evaluate-test-{}", std::process::id()));
    let status = Command::new(env!("CARGO_BIN_EXE_psbt-spec"))
        .current_dir(ROOT)
        .args(["evaluate", "--out"])
        .arg(&out)
        .args(["--corpus", "rust/tests/fixtures/roles.json", "--", "python3", "rust/tests/fixtures/example_adapter.py"])
        .args(["docs/examples/report.json", "rust/tests/fixtures/roles.json"])
        .status()
        .unwrap();
    assert!(status.success());
    let actual: Value = serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap()).unwrap();
    let markdown = std::fs::read_to_string(out.join("report.md")).unwrap();
    let expected = read("docs/examples/report.json");
    let _ = std::fs::remove_dir_all(&out);

    assert_eq!(actual["format"], expected["format"]);
    assert_eq!(actual["project"], expected["project"]);
    assert_eq!(actual["adapter"], expected["adapter"]);
    assert_eq!(actual["declared"], expected["declared"]);
    assert_eq!(actual["summary"], expected["summary"]);
    assert_eq!(actual["rows"], expected["rows"]);
    assert_eq!(actual["vectors"], expected["vectors"]);
    assert_eq!(actual["corpus"][0]["file"], "rust/tests/fixtures/roles.json");
    assert_eq!(actual["corpus"][0]["vectors"], 50);

    assert!(markdown.starts_with("# example-wallet PSBT behavior vs. psbt-spec "));
    assert!(markdown.contains("| ROLE-B-1 | combine | 174, 370 | MATCH | not located | #38, #39 | rejected #38, #39 | unconfirmed MATCH (project named no rule in rules.json): rust/tests/fixtures/roles.json#38, rust/tests/fixtures/roles.json#39 |"));
    assert!(markdown.contains("- Valid vectors passed: 14 of 18"));
}

/// Runs `evaluate` over rust/tests/fixtures/roles.json with tests/fixtures/stage_adapter.py
/// in `mode` and returns report.json.
fn evaluate_stage_adapter(mode: &str) -> Value {
    let out = std::env::temp_dir().join(format!("psbt-spec-stage-test-{mode}-{}", std::process::id()));
    let status = Command::new(env!("CARGO_BIN_EXE_psbt-spec"))
        .current_dir(ROOT)
        .args(["evaluate", "--out"])
        .arg(&out)
        .args(["--corpus", "rust/tests/fixtures/roles.json", "--", "python3", "rust/tests/fixtures/stage_adapter.py", mode])
        .status()
        .unwrap();
    assert!(status.success());
    let report = serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap()).unwrap();
    let _ = std::fs::remove_dir_all(&out);
    report
}

fn row<'a>(report: &'a Value, rule: &str, task: &str) -> Option<&'a Value> {
    report["rows"].as_array().unwrap().iter().find(|r| r["rule"] == rule && r["task"] == task)
}

fn vector<'a>(report: &'a Value, reference: &str) -> &'a Value {
    report["vectors"].as_array().unwrap().iter().find(|v| v["ref"] == reference).unwrap()
}

/// GEN-SP-7 and GEN-T-2 name the Signer in `roles`: a project that accepts
/// their vectors at deserialize and refuses them at sign is MATCH at sign, and
/// its parser's answer is a note, not evidence.
#[test]
fn role_owned_rule_accepted_at_deserialize_refused_at_sign_is_match() {
    let report = evaluate_stage_adapter("refuse-sign");
    let sp7 = row(&report, "GEN-SP-7", "sign").unwrap();
    assert_eq!(sp7["verdicts"], serde_json::json!(["MATCH"]));
    assert_eq!(sp7["evidence"], serde_json::json!([{"vector": "rust/tests/fixtures/roles.json#12", "verdict": "MATCH"}]));
    assert!(sp7["notes"].as_str().unwrap().contains("deserialize (informational, the BIP assigns this duty to Signer): accepted rust/tests/fixtures/roles.json#12"));
    assert!(row(&report, "GEN-SP-7", "deserialize").is_none());
    assert!(row(&report, "GEN-T-2", "deserialize").is_none());
    let t2 = row(&report, "GEN-T-2", "sign").unwrap();
    assert_eq!(t2["verdicts"], serde_json::json!(["MATCH"]));
    assert_eq!(t2["evidence"].as_array().unwrap().len(), 5);

    let v = vector(&report, "rust/tests/fixtures/roles.json#12");
    assert_eq!((v["task"].as_str(), v["outcome"].as_str()), (Some("deserialize"), Some("accept")));
    assert_eq!(v["evidence"], serde_json::json!([]));
    assert_eq!(v["stages"].as_array().unwrap().len(), 1);
    assert_eq!(v["stages"][0]["task"], "sign");
    assert_eq!(v["stages"][0]["outcome"], "reject");
    assert_eq!(v["stages"][0]["evidence"], serde_json::json!([{"rule": "GEN-SP-7", "verdict": "MATCH"}]));
    // 5 GEN-T-2 vectors and #12; the sign vectors of the file are its own.
    assert_eq!(report["summary"]["stages"], serde_json::json!({"total": 6, "withheld": 0, "not_run": 0, "accepted": 0, "rejected": 6}));

    // A General rule with no roles is still judged at deserialize.
    let st2 = row(&report, "GEN-ST-2", "deserialize").unwrap();
    assert_eq!(st2["verdicts"], serde_json::json!(["LOOSER"]));
}

/// The same vectors accepted at both stages: LOOSER at sign only.
#[test]
fn role_owned_rule_accepted_at_deserialize_and_sign_is_looser_at_sign() {
    let report = evaluate_stage_adapter("accept-all");
    for rule in ["GEN-SP-7", "GEN-T-2"] {
        assert_eq!(row(&report, rule, "sign").unwrap()["verdicts"], serde_json::json!(["LOOSER"]), "{rule}");
        assert!(row(&report, rule, "deserialize").is_none(), "{rule}");
    }
    assert_eq!(vector(&report, "rust/tests/fixtures/roles.json#12")["stages"][0]["evidence"], serde_json::json!([{"rule": "GEN-SP-7", "verdict": "LOOSER"}]));
    assert_eq!(report["summary"]["stages"]["accepted"], 6);
}

/// A refusal counts as MATCH only when the rule the project names (if any)
/// is the vector's: tests/fixtures/stage_adapter.py in mode named rejects
/// chosen vectors at deserialize, at sign stage requests and at sign with the
/// same rule, another rule, no rule and an unknown rule.
#[test]
fn named_rule_decides_whether_a_refusal_is_match() {
    let out = std::env::temp_dir().join(format!("psbt-spec-named-test-{}", std::process::id()));
    let corpora = ["vectors/bip174.json", "rust/tests/fixtures/roles.json"];
    let status = Command::new(env!("CARGO_BIN_EXE_psbt-spec"))
        .current_dir(ROOT)
        .args(["evaluate", "--out"])
        .arg(&out)
        .args(["--corpus", corpora[0], "--corpus", corpora[1], "--", "python3", "rust/tests/fixtures/stage_adapter.py", "named"])
        .args(corpora)
        .status()
        .unwrap();
    assert!(status.success());
    let report: Value = serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap()).unwrap();
    let markdown = std::fs::read_to_string(out.join("report.md")).unwrap();
    let _ = std::fs::remove_dir_all(&out);
    let evidence = |rule: &str, task: &str| -> Vec<(String, String)> {
        let row = row(&report, rule, task).unwrap();
        row["evidence"].as_array().unwrap().iter().map(|e| (e["vector"].as_str().unwrap().to_owned(), e["verdict"].as_str().unwrap().to_owned())).collect()
    };
    let notes = |rule: &str, task: &str| row(&report, rule, task).unwrap()["notes"].as_str().unwrap_or_default().to_owned();
    let pair = |r: &str, v: &str| (r.to_owned(), v.to_owned());

    assert_eq!(report["format"], "psbt-spec.report/2");

    // deserialize, same rule: MATCH, confirmed.
    assert_eq!(evidence("GEN-F-1", "deserialize"), [pair("vectors/bip174.json#0", "MATCH")]);
    assert!(!notes("GEN-F-1", "deserialize").contains("unconfirmed"));
    // deserialize, another rule: NOT RUN for the vector's rule, a note on both.
    assert_eq!(row(&report, "GEN-ST-3", "deserialize").unwrap()["verdicts"], serde_json::json!(["NOT RUN"]));
    assert_eq!(evidence("GEN-ST-3", "deserialize"), [pair("vectors/bip174.json#1", "NOT RUN"), pair("vectors/bip174.json#15", "NOT RUN")]);
    assert!(notes("GEN-ST-3", "deserialize").contains("vectors/bip174.json#1 rejected naming GEN-F-1, not this rule (NOT RUN)"));
    assert!(notes("GEN-F-1", "deserialize").contains("vectors/bip174.json#1: project names GEN-F-1 on rejecting it, but attribution finds GEN-ST-3 failing there"));
    // deserialize, no rule: MATCH, unconfirmed.
    assert_eq!(evidence("GEN-F-4", "deserialize"), [pair("vectors/bip174.json#4", "MATCH")]);
    assert!(notes("GEN-F-4", "deserialize").contains("unconfirmed MATCH (project named no rule in rules.json): vectors/bip174.json#4"));
    // deserialize, unknown rule: as no rule, with a warning.
    assert!(evidence("GEN-ST-2", "deserialize").contains(&pair("vectors/bip174.json#3", "MATCH")));
    assert!(notes("GEN-ST-2", "deserialize").contains("vectors/bip174.json#3: project names GEN-ST-99, not in rules.json (treated as no rule)"));
    assert!(notes("GEN-ST-2", "deserialize").contains("unconfirmed MATCH (project named no rule in rules.json): vectors/bip174.json#3"));
    assert_eq!(vector(&report, "vectors/bip174.json#3")["rule"], "GEN-ST-99");

    // sign stage requests: the same four cases on GEN-T-2, and GEN-SP-7 named
    // for a GEN-T-2 vector gets a note, not evidence.
    let t2 = ["#6 MATCH", "#7 NOT RUN", "#8 MATCH", "#9 MATCH", "#10 NOT RUN"]
        .map(|e| { let (n, v) = e.split_once(' ').unwrap(); pair(&format!("rust/tests/fixtures/roles.json{n}"), v) });
    assert_eq!(evidence("GEN-T-2", "sign"), t2);
    assert_eq!(row(&report, "GEN-T-2", "sign").unwrap()["verdicts"], serde_json::json!(["MATCH"]));
    assert!(notes("GEN-T-2", "sign").contains("rust/tests/fixtures/roles.json#7 rejected naming GEN-SP-7, not this rule (NOT RUN)"));
    assert!(notes("GEN-T-2", "sign").contains("rust/tests/fixtures/roles.json#9: project names GEN-T-99, not in rules.json"));
    assert!(notes("GEN-T-2", "sign").contains("unconfirmed MATCH (project named no rule in rules.json): rust/tests/fixtures/roles.json#8, rust/tests/fixtures/roles.json#9"));
    assert_eq!(evidence("GEN-SP-7", "sign"), [pair("rust/tests/fixtures/roles.json#12", "MATCH")]);
    assert!(notes("GEN-SP-7", "sign").contains("rust/tests/fixtures/roles.json#7: project names GEN-SP-7 on rejecting it, but attribution finds GEN-T-2 failing there"));
    assert_eq!(vector(&report, "rust/tests/fixtures/roles.json#7")["stages"][0]["evidence"], serde_json::json!([{"rule": "GEN-T-2", "verdict": "NOT RUN"}]));

    // Confounded sign vectors: naming one of its failing rules is MATCH for
    // that rule alone; naming another gives nothing.
    assert!(evidence("ROLE-S-4", "sign").contains(&pair("vectors/bip174.json#31", "MATCH")));
    assert!(!evidence("ROLE-S-2", "sign").iter().any(|(r, _)| r == "vectors/bip174.json#31"));
    assert!(notes("ROLE-S-2", "sign").contains("confounded vector vectors/bip174.json#31 rejected naming ROLE-S-4 (no evidence)"));
    assert_eq!(vector(&report, "vectors/bip174.json#32")["evidence"], serde_json::json!([]));
    assert!(notes("ROLE-S-1", "sign").contains("vectors/bip174.json#32: project names ROLE-S-1 on rejecting it"));

    // confirmed: bip174 #0, #31, roles #6, #12; unconfirmed: bip174 #3, #4,
    // roles #8, #9; other: bip174 #1, #15, #32, roles #7, #10.
    assert_eq!(report["summary"]["rejects"], serde_json::json!({"confirmed": 4, "unconfirmed": 4, "other_rule": 5, "unknown_rule": 2}));
    assert!(markdown.contains("- Rejections behind MATCH evidence: 4 confirmed (the project named the rule), 4 unconfirmed (it named no rule in rules.json)"));
    assert!(markdown.contains("Rejected naming ROLE-S-4, so only that rule gets evidence (MATCH)."));
}

#[test]
fn vectors_accepts_the_corpus() {
    let files = ["bip174", "bip370", "bip371", "bip373", "bip375", "bip376"].map(|n| format!("vectors/{n}.json"));
    let output = Command::new(env!("CARGO_BIN_EXE_psbt-spec")).current_dir(ROOT).arg("vectors").args(&files).output().unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{text}");
    assert!(text.contains("0 vectors neither isolate their rule nor carry a triage note"));
}
