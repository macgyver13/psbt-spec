use std::collections::HashSet;

use psbt_spec::algebra::Entry;
use psbt_spec::spec::{self, Specification, Statement};

fn statements(specification: &Specification) -> impl Iterator<Item = &Statement> {
    specification.preamble.iter().chain(
        specification
            .sections
            .iter()
            .flat_map(|section| &section.entries),
    )
}

#[test]
fn statement_ids_are_unique() {
    let specification = spec::specification();
    let mut ids = HashSet::new();
    for statement in statements(&specification).filter(|statement| !statement.id.is_empty()) {
        assert!(
            ids.insert(statement.id),
            "duplicate statement ID {} at sheet row {}",
            statement.id,
            statement.sheet_row,
        );
    }
}

#[test]
fn every_partial_rule_documents_its_gap() {
    use psbt_spec::spec::Coverage;
    let specification = spec::specification();
    for statement in statements(&specification).filter(|s| s.coverage == Some(Coverage::Partial)) {
        assert!(!statement.enforcement.gap.trim().is_empty(), "{} is Partial with no gap", statement.id);
    }
}

#[test]
fn implementations_match_catalog_graph() {
    let doc = spec::describe();
    let specification = spec::specification();
    let mut rules: std::collections::HashMap<_, Vec<_>> = std::collections::HashMap::new();
    for entry in &doc.entries {
        if let Entry::Rule { id, text, func, file, line, gates, .. } = entry {
            rules.entry(*id).or_default().push((*text, *func, *file, *line, gates));
        }
    }
    assert!(!rules.is_empty(), "catalog graph must describe implemented rules");
    for statement in statements(&specification) {
        let key = if statement.id.is_empty() { statement.topic } else { statement.id };
        let bindings = rules.remove(key).unwrap_or_default();
        assert_eq!(bindings.len(), statement.implementations.len(), "bindings for {key}");
        for (implementation, (text, func, file, line, gates)) in statement.implementations.iter().zip(bindings) {
            if !text.is_empty() {
                assert_eq!(statement.text, text, "wording for {key}");
            }
            assert_eq!(implementation.func, func, "function for {key}");
            assert_eq!(implementation.file, file, "file for {key}");
            assert_eq!(implementation.line, line, "line for {key}");
            assert_eq!(&implementation.gates, gates, "gates for {key}");
            assert!(!func.is_empty() && !file.is_empty() && line > 0);
        }
    }
    assert!(rules.is_empty(), "graph rules absent from catalog: {:?}", rules.keys());
}

#[test]
fn every_role_rule_has_one_phase_and_general_rules_none() {
    let specification = spec::specification();
    for section in &specification.sections {
        for statement in section.entries.iter().filter(|s| !s.implementations.is_empty()) {
            let phases: HashSet<_> = statement.implementations.iter().map(|i| i.phase).collect();
            assert_eq!(phases.len(), 1, "{} has phases {phases:?}", statement.id);
            let phase = *phases.iter().next().unwrap();
            match section.category {
                "role" => assert!(matches!(phase, Some("Precondition" | "Result")), "{} has phase {phase:?}", statement.id),
                _ => assert_eq!(phase, None, "{} is not a role rule", statement.id),
            }
        }
    }
}

#[test]
fn strength_and_coverage_follow_the_statement_kind() {
    use psbt_spec::spec::Coverage;
    let specification = spec::specification();
    for section in &specification.sections {
        for statement in &section.entries {
            let id = if statement.id.is_empty() { statement.topic } else { statement.id };
            match section.category {
                "general" | "role" => {
                    let coverage = statement.coverage.unwrap_or_else(|| panic!("{id} has no coverage"));
                    assert!(statement.strength.is_some(), "{id} has no strength");
                    // Declared rules may call a declared check; Pending ones have none.
                    let bound = !statement.implementations.is_empty();
                    match coverage {
                        Coverage::Full | Coverage::Partial => assert!(bound, "{id}: {coverage:?} needs a check"),
                        Coverage::Pending => assert!(!bound, "{id}: Pending has no check"),
                        Coverage::Declared => {}
                    }
                }
                "guidance" => {
                    assert!(statement.strength.is_some(), "{id} has no strength");
                    assert!(statement.coverage.is_none(), "{id} is guidance, not a rule");
                }
                _ => {
                    assert!(statement.strength.is_none() && statement.coverage.is_none(), "{id} is not a rule");
                }
            }
        }
    }
}
