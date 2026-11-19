//! The corpus schema (vectors/corpus.schema.json) and vector isolation: each
//! invalid vector isolates its `rule` (it is the only refusal rule, or the only
//! Result rule of a result vector, or the only Incomplete rule of an
//! `outcome: "incomplete"` vector), or carries a note that starts with a
//! triage class (PRINCIPLES.md, principle 28).

use std::collections::BTreeSet;

use psbt_spec::attribution::{attribute, classify};
use psbt_spec::corpus;
use serde_json::Value;

const TRIAGE_CLASSES: [&str; 4] = ["confounded", "lagging", "ambiguous", "defect"];

fn read(path: &str) -> Value {
    let path = format!("{}/../vectors/{path}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// Whether `value` has the JSON type or constant `spec` (a schema property) names.
fn conforms(value: &Value, spec: &Value) -> bool {
    if let Some(c) = spec.get("const") {
        return value == c;
    }
    if let Some(options) = spec.get("enum") {
        return options.as_array().unwrap().contains(value);
    }
    let types = match &spec["type"] {
        Value::Array(types) => types.iter().map(|t| t.as_str().unwrap()).collect(),
        single => vec![single.as_str().unwrap()],
    };
    types.into_iter().any(|t| match t {
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        "array" => value.as_array().is_some_and(|items| items.iter().all(|i| conforms(i, &spec["items"]))),
        other => panic!("unhandled schema type {other}"),
    })
}

/// A hand-written check of the schema's required keys, property types, no extra
/// keys, and the rule: valid rule if and only if the vector is invalid. A JSON
/// Schema crate was not added for this.
#[test]
fn corpus_files_follow_the_schema() {
    let schema = read("corpus.schema.json");
    let props = &schema["$defs"]["vector"]["properties"];
    let required: Vec<&str> = schema["$defs"]["vector"]["required"].as_array().unwrap().iter().map(|k| k.as_str().unwrap()).collect();
    let mut problems = Vec::new();
    for (name, _) in corpus::FILES {
        let file = read(&format!("{name}.json"));
        let keys: BTreeSet<&str> = file.as_object().unwrap().keys().map(String::as_str).collect();
        if keys != BTreeSet::from(["bip_revision", "bips", "vectors"]) {
            problems.push(format!("{name}: file keys {keys:?}"));
        }
        let listed = file["bips"].as_array().is_some_and(|bips| bips.iter().all(|b| b.as_u64().is_some_and(|n| n >= 1)));
        if !listed {
            problems.push(format!("{name}: bips must be positive integers"));
        }
        let revision = file["bip_revision"].as_str().unwrap_or_default();
        if !(7..=40).contains(&revision.len()) || !revision.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
            problems.push(format!("{name}: bip_revision {revision:?}"));
        }
        for v in file["vectors"].as_array().unwrap() {
            let label = format!("{name}: {}", v["description"]);
            for key in &required {
                if v.get(key).is_none() {
                    problems.push(format!("{label}: missing {key}"));
                }
            }
            for (key, value) in v.as_object().unwrap() {
                match props.get(key) {
                    None => problems.push(format!("{label}: unknown key {key}")),
                    Some(spec) if !conforms(value, spec) => problems.push(format!("{label}: bad {key}")),
                    Some(_) => {}
                }
            }
            if (v["valid"] == true) == v.get("rule").is_some() {
                problems.push(format!("{label}: rule must be present exactly when valid is false"));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn invalid_vectors_isolate_their_rule_or_are_triaged() {
    let mut problems = Vec::new();
    for (name, text) in corpus::FILES {
        for v in corpus::parse(text).unwrap().vectors.iter().filter(|v| !v.valid) {
            let rule = v.rule.as_deref().unwrap();
            let failures = attribute(v.task, &v.request);
            let classified = classify(&v.request, false, &failures);
            let isolated = corpus::isolates(v, &failures);
            let triaged = v.note.as_deref().is_some_and(|n| {
                TRIAGE_CLASSES.iter().any(|class| n.strip_prefix(class).is_some_and(|rest| rest.starts_with(':')))
            });
            if !isolated && !triaged {
                problems.push(format!(
                    "{name}: {} (rule {rule}): {} fails {:?}, incomplete {:?}",
                    v.description, classified.class.name(), failures.failed, failures.incomplete
                ));
            }
        }
    }
    assert!(problems.is_empty(), "{} not isolated:\n{}", problems.len(), problems.join("\n"));
}
