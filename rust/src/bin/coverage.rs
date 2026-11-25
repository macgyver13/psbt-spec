//! Generate a self-contained rule/vector execution report.
//! Usage: cargo run --bin coverage > ../coverage.html

use std::collections::BTreeMap;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine};
use psbt_spec::algebra::{
    all, each, BoxNode, Check, CheckOutcome, Doc, Entry, Evaluation, Rule, Trace, TraceStatus,
};
use psbt_spec::context::{determine_locktime, PsbtContext, TransitionContext};
use psbt_spec::spec::{self, Statement};
use psbt_spec::encoding::{is_p2sh, is_witness_program};
use psbt_spec::{
    evaluate, evaluate_combining, evaluate_extracting, evaluate_for_finalizing,
    evaluate_for_signing, Bip, SignatureKind,
};
use serde_json::{json, Value};

fn scope(statement: &Statement) -> &'static str {
    if statement.id.starts_with("GEN-") {
        "general"
    } else {
        match statement.id.split('-').nth(1) {
            Some("C") => {
                if matches!(statement.id, "ROLE-C-1" | "ROLE-C-2") {
                    "creator"
                } else {
                    "constructor"
                }
            }
            Some("U") => "updater",
            Some("S") => "signer",
            Some("F") => "finalizer",
            Some("X") => "extractor",
            Some("B") => "combiner",
            _ => "documentation",
        }
    }
}

fn rule_json(statement: &Statement, category: &str) -> Value {
    let id = if statement.id.is_empty() {
        statement.topic
    } else {
        statement.id
    };
    let sp = ["bip-0352", "bip-0374", "bip-0375", "bip-0376"]
        .iter()
        .any(|bip| statement.evidence.url.contains(bip));
    json!({
        "id": id, "text": statement.text, "topic": statement.topic,
        "category": category, "scope": scope(statement), "sp": sp,
        "implemented": !statement.implementations.is_empty(),
        "gap": statement.enforcement.gap,
    })
}

fn outcome_text(outcome: &Evaluation) -> String {
    match outcome {
        Evaluation::Verified => "Passed implemented checks".into(),
        Evaluation::NotApplicable => "Not applicable".into(),
        Evaluation::Failed(v) => format!("Failed {}: {}", v.rule, v.detail),
        Evaluation::Incomplete(v) => format!("Incomplete {}: {}", v.rule, v.detail),
    }
}

fn status_name(status: TraceStatus) -> &'static str {
    match status {
        TraceStatus::Passed => "passed",
        TraceStatus::Failed => "failed",
        TraceStatus::Incomplete => "incomplete",
        TraceStatus::NotApplicable => "not_applicable",
        TraceStatus::Gated => "gated",
        TraceStatus::Blocked => "blocked",
        TraceStatus::Empty => "empty",
    }
}

// Snapshot adapters use the bound check's catalog metadata and verify its identity.
// They assess supplied data only; duties requiring operation intent stay unassessed.
fn snapshot_rule<C: ?Sized + 'static, R: Into<CheckOutcome> + 'static>(
    id: &str,
    function: &str,
    check: Check<C, R>,
) -> BoxNode<C> {
    let specification = spec::specification();
    let statement = specification
        .sections
        .iter()
        .flat_map(|section| &section.entries)
        .find(|statement| statement.id == id)
        .expect("catalog snapshot rule");
    let implementation = statement
        .implementations
        .iter()
        .find(|i| i.func.strip_prefix("crate::") == function.strip_prefix("psbt_spec::"))
        .unwrap_or_else(|| panic!("snapshot adapter must use a catalog binding for {id}"));
    Box::new(Rule {
        id: statement.id,
        text: statement.text,
        func: implementation.func,
        file: implementation.file,
        line: implementation.line,
        check,
    })
}

macro_rules! snapshot {
    ($id:literal, $check:path) => {
        snapshot_rule($id, stringify!($check), $check)
    };
}

/// Every input as a Signer would sign it, the signature kind inferred from the
/// spent script; the first input that does not pass.
fn for_signing(bytes: &[u8], bips: &[Bip]) -> Evaluation {
    let inputs = PsbtContext::new(&spec::parse(bytes, bips)).inputs();
    inputs
        .iter()
        .map(|input| {
            let witness = match input.spent_output() {
                None => true,
                Some(out) if is_p2sh(&out.script_pubkey) => input.value(0x04).is_some_and(is_witness_program),
                Some(out) => is_witness_program(&out.script_pubkey),
            };
            let kind = if witness { SignatureKind::Witness } else { SignatureKind::NonWitness };
            evaluate_for_signing(bytes, bips, input.index, kind)
        })
        .find(|e| !matches!(e, Evaluation::Verified | Evaluation::NotApplicable))
        .unwrap_or(Evaluation::Verified)
}

fn snapshot_rules(operation: &str) -> Option<BoxNode<PsbtContext>> {
    match operation {
        "finalizing" => Some(all(vec![
            each(
                |context: &PsbtContext| context.inputs(),
                snapshot!(
                    "ROLE-F-9",
                    psbt_spec::rules::taproot::validate_taproot_script_path_finalization
                ),
            ),
            each(
                |context: &PsbtContext| context.inputs(),
                snapshot!(
                    "ROLE-F-10",
                    psbt_spec::rules::taproot::validate_taproot_key_path_finalization
                ),
            ),
            // Preconditions last, so a placeholder signature does not hide
            // the other Finalizer observations.
            each(|context: &PsbtContext| context.inputs(), spec::finalizer_obligations()),
        ])),
        "extraction" => Some(snapshot!(
            "ROLE-X-1",
            psbt_spec::rules::extractor::validate_extraction_readiness
        )),
        "signing" | "validity" | "combining" | "locktime" => None,
        _ => panic!("unsupported vector operation: {operation}"),
    }
}

fn observe<C: ?Sized>(
    node: BoxNode<C>,
    context: &C,
    subject: &str,
    cells: &mut BTreeMap<String, Vec<Value>>,
) -> Evaluation {
    let mut trace = Trace::exhaustive();
    let result = node.evaluate_traced(context, &mut trace);
    #[cfg(test)]
    assert_eq!(
        result,
        node.evaluate(context),
        "tracing must preserve evaluation"
    );
    for event in trace.observations {
        cells.entry(event.id.into()).or_default().push(json!({
            "status": status_name(event.status), "detail": event.detail, "path": event.path, "subject": subject,
        }));
    }
    result
}

fn mark<C: ?Sized>(
    node: BoxNode<C>,
    status: &str,
    detail: &str,
    cells: &mut BTreeMap<String, Vec<Value>>,
) {
    let mut doc = Doc::default();
    node.describe(&mut doc);
    for entry in doc.entries {
        if let Entry::Rule { id, .. } = entry {
            cells.entry(id.into()).or_default().push(json!({
                "status": status, "detail": detail, "path": [],
            }));
        }
    }
}

fn succeeded(outcome: &Evaluation) -> bool {
    matches!(outcome, Evaluation::Verified | Evaluation::NotApplicable)
}

fn vector_report(corpus: &str, index: usize, vector: &Value, rules: &[Value]) -> Value {
    let bytes = STANDARD
        .decode(vector["psbt"].as_str().expect("PSBT string"))
        .expect("base64 PSBT");
    let bips: Vec<Bip> = if let Some(bips) = vector["bips"].as_array() {
        bips.iter()
            .map(|bip| match bip.as_u64() {
                Some(375) => Bip::Bip375,
                Some(376) => Bip::Bip376,
                other => panic!("unsupported vector BIP: {other:?}"),
            })
            .collect()
    } else {
        match corpus {
            "bip375" => vec![Bip::Bip375],
            "derived/bip376" => vec![Bip::Bip376],
            _ => vec![],
        }
    };
    let operation = vector["task"]
        .as_str()
        .unwrap_or(if corpus == "bip370_locktime" {
            "locktime"
        } else {
            "signing"
        });
    let mut cells = BTreeMap::new();
    let mut outcome = observe(
        spec::general_rules(&bips),
        bytes.as_slice(),
        "PSBT under test",
        &mut cells,
    );
    let general_result = outcome_text(&outcome);
    let base_general_result = outcome_text(&spec::general_rules(&[]).evaluate(&bytes));
    // Snapshot fixtures do not establish signature intent or before/after states.
    // Only role checks supported by the recorded operation and supplied data run.
    let role = snapshot_rules(operation);
    if let Some(role) = role {
        if succeeded(&outcome) {
            let context = PsbtContext::new(&spec::parse(&bytes, &bips));
            outcome = observe(role, &context, "PSBT under test", &mut cells);
        } else {
            mark(role, "blocked", &outcome_text(&outcome), &mut cells);
        }
    }
    let sources: Vec<Vec<u8>> = vector["combine"]
        .as_array()
        .map(|sources| {
            sources
                .iter()
                .map(|source| {
                    STANDARD
                        .decode(source.as_str().expect("source PSBT"))
                        .expect("source base64")
                })
                .collect()
        })
        .unwrap_or_default();
    let mut prerequisite_subject = String::new();
    if operation == "combining" {
        if succeeded(&outcome) {
            for (index, source) in sources.iter().enumerate() {
                let subject = format!("Combiner source {}", index + 1);
                let prerequisite = observe(
                    spec::general_rules(&bips),
                    source.as_slice(),
                    &subject,
                    &mut cells,
                );
                if !succeeded(&prerequisite) {
                    prerequisite_subject = subject;
                    outcome = prerequisite;
                    break;
                }
            }
        }
        if succeeded(&outcome) {
            let context = TransitionContext {
                before: sources
                    .iter()
                    .map(|source| PsbtContext::new(&spec::parse(source, &bips)))
                    .collect(),
                after: PsbtContext::new(&spec::parse(&bytes, &bips)),
            };
            outcome = observe(
                spec::combiner_obligations(),
                &context,
                "Combiner transition",
                &mut cells,
            );
        } else {
            mark(
                spec::combiner_obligations(),
                "blocked",
                &format!("{prerequisite_subject}: {}", outcome_text(&outcome)),
                &mut cells,
            );
        }
    }
    // The fixture's expectation, under the entry point its check names.
    let observed = match vector["task"].as_str().unwrap_or("validity") {
        "signing" => for_signing(&bytes, &bips),
        "finalizing" => evaluate_for_finalizing(&bytes, &bips),
        "extraction" => evaluate_extracting(&bytes, &bips),
        "combining" => {
            let sources: Vec<&[u8]> = sources.iter().map(Vec::as_slice).collect();
            evaluate_combining(&sources, &bytes, &bips)
        }
        _ => evaluate(&bytes, &bips),
    };
    let actual = match &observed {
        Evaluation::Failed(v) => Some(v.rule.to_string()),
        Evaluation::Incomplete(v) => Some(format!("{} (incomplete)", v.rule)),
        Evaluation::Verified | Evaluation::NotApplicable => None,
    };
    let expected = if operation == "locktime" {
        vector["locktime"].is_null().then(|| "GEN-T-1".to_string())
    } else {
        vector["rule"].as_str().map(|rule| match vector["outcome"].as_str() {
            Some("incomplete") => format!("{rule} (incomplete)"),
            _ => rule.to_string(),
        })
    };
    let mut expected_matches = actual == expected;
    let mut expected_result = format!(
        "expected {}, observed {}",
        expected.as_deref().unwrap_or("success"),
        actual.as_deref().unwrap_or("success")
    );
    if operation == "locktime" {
        let actual = determine_locktime(&PsbtContext::new(&spec::parse(&bytes, &bips)));
        let expected = vector["locktime"].as_u64().map(|v| v as u32);
        expected_matches &= actual == expected;
        expected_result.push_str(&format!(
            "; locktime expected {expected:?}, observed {actual:?}"
        ));
    }
    if let Some(expected) = vector["unique_id"].as_str() {
        let context = PsbtContext::new(&spec::parse(&bytes, &bips));
        let id = psbt_spec::context::unique_id(&context);
        let actual: String = id.iter().rev().map(|byte| format!("{byte:02x}")).collect();
        expected_matches &= actual == expected;
        expected_result.push_str(&format!(
            "; unique ID expected {expected}, observed {actual}"
        ));
    }
    expected_result = format!(
        "{}: {expected_result}",
        if expected_matches { "Match" } else { "Mismatch" }
    );
    for rule in rules {
        let id = rule["id"].as_str().unwrap();
        if !cells.contains_key(id) {
            let scope = rule["scope"].as_str().unwrap();
            let (status, detail) = if scope == "documentation" {
                (
                    "descriptive",
                    "Reference or guidance; no executable check".to_owned(),
                )
            } else if !rule["implemented"].as_bool().unwrap() {
                (
                    "not_implemented",
                    "No executable check is bound to this rule".to_owned(),
                )
            } else {
                (
                    "context_missing",
                    match id {
                        "ROLE-S-1" | "ROLE-S-2" | "ROLE-S-3" | "ROLE-S-4" => {
                            "Fixture has no selected input and intended signature kind".into()
                        }
                        "ROLE-S-9" | "ROLE-S-10" | "ROLE-S-11" | "ROLE-F-6" | "ROLE-F-7"
                        | "ROLE-F-8" => {
                            "Fixture has no before/after state for this operation".into()
                        }
                        _ => format!(
                            "Fixture does not supply the {scope} operation context for this check"
                        ),
                    },
                )
            };
            cells.insert(
                id.into(),
                vec![json!({"status": status, "detail": detail, "path": []})],
            );
        }
    }
    json!({
        "id": format!("{corpus}:{}", index + 1), "corpus": corpus,
        "description": vector["description"], "note": vector["note"].as_str().unwrap_or(""),
        "expected": expected, "operation": operation,
        "bips": bips.iter().map(|bip| bip.name()).collect::<Vec<_>>(),
        "result": if prerequisite_subject.is_empty() { outcome_text(&outcome) }
            else { format!("{prerequisite_subject}: {}", outcome_text(&outcome)) },
        "general_result": general_result,
        "base_general_result": base_general_result,
        "expected_result": expected_result, "cells": cells,
    })
}

fn report(root: &Path) -> Value {
    let specification = spec::specification();
    let rules: Vec<Value> = specification
        .preamble
        .iter()
        .map(|statement| rule_json(statement, "Context"))
        .chain(specification.sections.iter().flat_map(|section| {
            section
                .entries
                .iter()
                .map(move |statement| rule_json(statement, section.title))
        }))
        .collect();
    let mut vectors = Vec::new();
    for corpus in [
        "bip174",
        "bip370",
        "bip370_locktime",
        "bip371",
        "bip373",
        "bip375",
        "derived/bip376",
    ] {
        let path = root.join(format!("{corpus}.json"));
        let file: Value = serde_json::from_str(&std::fs::read_to_string(path).expect("read vector corpus"))
            .expect("parse vector corpus");
        // bip370_locktime is a bare array; the schema v1 files wrap theirs.
        let fixtures: Vec<Value> = match file.get("vectors") {
            Some(wrapped) => wrapped.as_array().expect("vectors array").clone(),
            None => file.as_array().expect("vector array").clone(),
        };
        vectors.extend(
            fixtures
                .iter()
                .enumerate()
                .map(|(index, vector)| vector_report(corpus, index, vector, &rules)),
        );
    }
    json!({"rules": rules, "vectors": vectors})
}

fn render_report(data: &Value) -> String {
    let embedded = data.to_string().replace('<', "\\u003c");
    include_str!("coverage.template.html").replace("__COVERAGE_DATA__", &embedded)
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors");
    print!("{}", render_report(&report(&root)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generated_report_embeds_json_without_external_file_loading() {
        let data = json!({"rules": [], "vectors": [], "note": "</script>"});
        let html = render_report(&data);
        assert!(!html.contains("__COVERAGE_DATA__"));
        let embedded = html.split_once("<script id=\"coverage-data\" type=\"application/json\">")
            .unwrap().1.split_once("</script>").unwrap().0;
        assert!(!embedded.contains('<'));
        assert_eq!(serde_json::from_str::<Value>(embedded).unwrap(), data);
    }

    #[test]
    fn every_fixture_and_catalog_statement_has_an_observation() {
        let data = report(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors"));
        let rules = data["rules"].as_array().unwrap();
        let ids: HashSet<_> = rules
            .iter()
            .map(|rule| rule["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids.len(), rules.len(), "rule IDs must be unique");
        let vectors = data["vectors"].as_array().unwrap();
        for vector in vectors {
            let cells = vector["cells"].as_object().unwrap();
            assert_eq!(cells.len(), rules.len(), "{}", vector["id"]);
            assert!(ids
                .iter()
                .all(|id| !cells[*id].as_array().unwrap().is_empty()));
            assert!(
                vector["expected_result"]
                    .as_str()
                    .unwrap()
                    .starts_with("Match"),
                "{vector}"
            );
        }
        assert!(rules.iter().any(|rule| rule["sp"] == true));
        for vector in vectors
            .iter()
            .filter(|vector| vector["bips"].as_array().unwrap().is_empty())
        {
            for id in ["ROLE-S-11", "ROLE-F-8"] {
                assert!(
                    vector["cells"][id]
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|event| matches!(
                            event["status"].as_str(),
                            Some("gated" | "blocked" | "context_missing")
                        )),
                    "disabled extension check {id} ran for {}",
                    vector["id"]
                );
            }
        }
        let finalizer = vectors
            .iter()
            .find(|vector| vector["id"] == "bip174:35")
            .unwrap();
        assert_eq!(
            finalizer["cells"]["ROLE-F-6"][0]["status"],
            "context_missing"
        );
        assert_eq!(finalizer["cells"]["ROLE-F-1"][0]["status"], "passed");
        let combiner = vectors
            .iter()
            .find(|vector| vector["id"] == "bip174:37")
            .unwrap();
        assert!(combiner["cells"]["GEN-F-1"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["status"] == "passed"
                && event["subject"]
                    .as_str()
                    .unwrap()
                    .starts_with("Combiner source")));
    }
}
