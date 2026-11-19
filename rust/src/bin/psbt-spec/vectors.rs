//! `vectors`: audit corpus files. For each vector, the rules the certifier
//! says it fails against its label, and whether it isolates its rule.
//!
//! TODO: docs/ does not specify this command beyond one line of the plan
//! ("schema, labels, isolation, and every other rule each vector fails"). The
//! output format and exit codes here are an implementation choice. Schema
//! checks are the structural ones of `corpus::parse` plus "rule present exactly
//! when invalid"; full JSON Schema validation is not done.

use psbt_spec::attribution::{attribute, classify, Class};

use crate::evaluate;

const TRIAGE_CLASSES: [&str; 4] = ["confounded", "lagging", "ambiguous", "defect"];

/// Prints the audit of each file; the exit code is 1 when a vector neither
/// isolates its label nor carries a triage note, 2 when a file is unreadable.
pub fn run(paths: &[String]) -> i32 {
    let mut problems = 0;
    for path in paths {
        let corpus = match evaluate::load(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{e}");
                return 2;
            }
        };
        let file = &corpus.file;
        println!("{path}: bip_revision {}, bips {:?}, {} vectors", file.bip_revision, file.bips, file.vectors.len());
        let mut triaged = 0;
        for v in &file.vectors {
            let failures = attribute(v.task, &v.request);
            let c = classify(&v.request, v.valid, &failures);
            let attributed = c.attributed();
            let label = v.rule.as_deref();
            let note_class = v.note.as_deref().and_then(|n| {
                TRIAGE_CLASSES.iter().find(|class| n.strip_prefix(**class).is_some_and(|rest| rest.starts_with(':'))).copied()
            });
            let problem = if v.valid != label.is_none() {
                Some("rule must be present exactly when valid is false".to_owned())
            } else if v.valid {
                (!failures.failed.is_empty()).then(|| format!("valid vector fails {}", failures.failed.join(", ")))
            } else if v.incomplete_label {
                (!(failures.failed.is_empty() && failures.incomplete == [label.unwrap()]))
                    .then(|| format!("labeled incomplete on {}, attribution failed {:?} incomplete {:?}", label.unwrap(), failures.failed, failures.incomplete))
            } else {
                match c.class {
                    Class::Isolated | Class::Result if attributed == [label.unwrap()] => None,
                    Class::Isolated | Class::Result => Some(format!("labeled {}, attribution {}", label.unwrap(), attributed.join(", "))),
                    Class::Confounded => Some(format!("labeled {}, confounded: fails {}", label.unwrap(), attributed.join(", "))),
                    Class::None => Some(format!("labeled {}, fails no rule", label.unwrap())),
                    Class::Undecided => Some(format!("labeled {}, only incomplete on {}", label.unwrap(), failures.incomplete.join(", "))),
                    Class::Valid => unreachable!(),
                }
            };
            let others: Vec<&str> = failures.failed.iter().copied().filter(|id| Some(*id) != label).collect();
            match (problem, note_class) {
                (None, _) => {
                    if !others.is_empty() {
                        println!("  #{} ok, {}; also fails {}: {}", v.index, c.class.name(), others.join(", "), v.description);
                    }
                }
                (Some(p), Some(class)) => {
                    triaged += 1;
                    println!("  #{} triaged ({class}): {p}: {}", v.index, v.description);
                }
                (Some(p), None) => {
                    problems += 1;
                    println!("  #{} PROBLEM: {p}: {}", v.index, v.description);
                }
            }
        }
        println!("  {} valid, {} invalid, {triaged} triaged", file.vectors.iter().filter(|v| v.valid).count(), file.vectors.iter().filter(|v| !v.valid).count());
    }
    println!("{problems} vectors neither isolate their rule nor carry a triage note");
    i32::from(problems > 0)
}
