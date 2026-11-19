use psbt_spec::algebra::{
    all, each, from, section, seq, when, with, Bip, BoxNode, CheckOutcome, Doc, Entry,
    Evaluation, Node, Rule, Violation,
};
use psbt_spec::rule;

fn outcome(value: &u8) -> CheckOutcome {
    match value {
        0 => CheckOutcome::NotApplicable,
        1 => CheckOutcome::Verified,
        2 => CheckOutcome::Incomplete("missing signing data".into()),
        3 => CheckOutcome::Failed("invalid signing data".into()),
        _ => panic!("evaluation continued after a terminal outcome"),
    }
}

fn binary(value: &u8) -> Result<(), String> {
    if *value == 1 { Ok(()) } else { Err("binary failure".into()) }
}

fn fails(_: &Vec<u8>) -> Result<(), String> {
    Err("fails".into())
}

fn unreachable_binary(_: &Vec<u8>) -> Result<(), String> {
    panic!("a rule after a failure in an ordered group must not execute")
}

fn unreachable(_: &u8) -> CheckOutcome {
    panic!("gated or later rule must not execute")
}

fn violation(id: &'static str, detail: &str) -> Violation {
    Violation { rule: id, detail: detail.into() }
}

#[test]
fn leaf_outcomes_attach_rule_ids_and_preserve_verdict_details() {
    let node = rule!("E01", outcome, "Evaluate a check.");
    let cases = [
        (0, Evaluation::NotApplicable, Ok(())),
        (1, Evaluation::Verified, Ok(())),
        (2, Evaluation::Incomplete(violation("E01", "missing signing data")),
            Err(violation("E01", "missing signing data"))),
        (3, Evaluation::Failed(violation("E01", "invalid signing data")),
            Err(violation("E01", "invalid signing data"))),
    ];
    for (input, expected, verdict) in cases {
        assert_eq!(node.evaluate(&input), expected);
        assert_eq!(expected.into_verdict(), verdict);
        assert_eq!(node.validate(&input), verdict);
    }
}

#[test]
fn old_binary_macro_and_default_rule_type_keep_their_behavior() {
    let node: BoxNode<u8> = rule!("B01", binary, "A binary check.");
    assert_eq!(node.evaluate(&1), Evaluation::Verified);
    assert_eq!(node.validate(&1), Ok(()));
    assert_eq!(node.evaluate(&0), Evaluation::Failed(violation("B01", "binary failure")));
    assert_eq!(node.validate(&0), Err(violation("B01", "binary failure")));
    assert_eq!(CheckOutcome::from(Ok(())), CheckOutcome::Verified);
    assert_eq!(CheckOutcome::from(Err("detail".into())), CheckOutcome::Failed("detail".into()));

    let direct: Rule<u8> = Rule {
        id: "B02", text: "Direct binary check.", func: "binary",
        file: file!(), line: line!(), check: binary,
    };
    assert_eq!(direct.validate(&1), Ok(()));

    let sequence = all(vec![
        rule!("B01", binary, "First binary check."),
        rule!("B02", binary, "Second binary check."),
        rule!("NEVER", unreachable, "Must not execute."),
    ]);
    assert_eq!(sequence.validate(&0), Err(violation("B01", "binary failure")));
}

#[test]
fn gates_skip_children_and_enabled_gates_delegate_all_states() {
    let disabled = when("disabled", |_| false, rule!("NEVER", unreachable, "Must not execute."));
    assert_eq!(disabled.evaluate(&1), Evaluation::NotApplicable);
    assert_eq!(disabled.validate(&1), Ok(()));
    let disabled_bip = from(Bip::Bip375, &[], rule!("NEVER", unreachable, "Must not execute."));
    assert_eq!(disabled_bip.evaluate(&1), Evaluation::NotApplicable);
    let enabled = when("enabled", |_| true, rule!("E01", outcome, "Evaluate a check."));
    let enabled_bip = from(Bip::Bip375, &[Bip::Bip375], rule!("E01", outcome, "Evaluate a check."));
    for input in 0..=3 {
        assert_eq!(enabled.evaluate(&input), rule!("E01", outcome, "Check.").evaluate(&input));
        assert_eq!(enabled_bip.evaluate(&input), enabled.evaluate(&input));
    }
}

#[test]
fn all_aggregates_applicability_and_stops_at_first_terminal_outcome() {
    assert_eq!(all::<u8>(vec![]).evaluate(&1), Evaluation::NotApplicable);
    let skipped = || when("skip", |_| false, rule!("NEVER", unreachable, "Must not execute."));
    assert_eq!(all(vec![skipped(), skipped()]).evaluate(&1), Evaluation::NotApplicable);
    let mixed = all(vec![skipped(), rule!("E01", outcome, "Check."), skipped()]);
    assert_eq!(mixed.evaluate(&1), Evaluation::Verified);
    assert_eq!(mixed.evaluate(&0), Evaluation::NotApplicable);
    for input in [2, 3] {
        let sequence = all(vec![
            rule!("PASS", binary, "Earlier successful check."),
            with(move |_: &u8| input, rule!("FIRST", outcome, "First terminal check.")),
            rule!("NEVER", unreachable, "Must not execute."),
        ]);
        let expected = rule!("FIRST", outcome, "Check.").evaluate(&input);
        assert_eq!(sequence.evaluate(&1), expected);
        assert_eq!(sequence.validate(&1), expected.into_verdict());
    }
}

#[test]
fn each_aggregates_applicability_and_stops_in_enumeration_order() {
    let node = each(|items: &Vec<u8>| items.clone(), rule!("ITEM", outcome, "Check each item."));
    for items in [vec![], vec![0], vec![0, 0]] {
        assert_eq!(node.evaluate(&items), Evaluation::NotApplicable);
        assert_eq!(node.validate(&items), Ok(()));
    }
    for items in [vec![1], vec![0, 1, 0], vec![1, 0]] {
        assert_eq!(node.evaluate(&items), Evaluation::Verified);
    }
    for items in [vec![0, 1, 2, 3, 4], vec![0, 1, 3, 2, 4]] {
        let expected = rule!("ITEM", outcome, "Check.").evaluate(&items[2]);
        assert_eq!(node.evaluate(&items), expected);
        assert_eq!(node.validate(&items), expected.into_verdict());
    }
}

#[test]
fn section_and_projection_delegate_all_states() {
    let node = section("Projected checks", with(|value: &(u8,)| value.0,
        rule!("E01", outcome, "Evaluate projected value.")));
    for input in 0..=3u8 {
        assert_eq!(node.evaluate(&(input,)), rule!("E01", outcome, "Check.").evaluate(&input));
    }
}

#[test]
fn macro_metadata_and_inherited_gates_remain_available() {
    let node = section("Checks", from(Bip::Bip375, &[Bip::Bip375],
        when("condition", |_| true, rule!("E01", outcome, "Normative sentence."))));
    let mut doc = Doc::default();
    node.describe(&mut doc);
    assert!(matches!(doc.entries[0], Entry::Section("Checks")));
    match &doc.entries[1] {
        Entry::Rule { id, text, func, file, line, gates, .. } => {
            assert_eq!(*id, "E01");
            assert_eq!(*text, "Normative sentence.");
            assert_eq!(*func, "outcome");
            assert_eq!(*file, file!());
            assert!(*line > 0);
            assert_eq!(gates, &["From BIP-375", "condition"]);
        }
        _ => panic!("expected rule metadata"),
    }
}

#[test]
fn tracing_preserves_outcomes_and_records_gates_blockers_and_iteration_paths() {
    use psbt_spec::algebra::{Trace, TraceStatus};

    let node = all(vec![
        when("disabled", |_| false, with(|_: &Vec<u8>| 4u8,
            rule!("GATED", unreachable, "Must not execute."))),
        each(|items: &Vec<u8>| items.clone(), all(vec![
            rule!("ITEM", outcome, "Evaluate an item."),
            rule!("LATER", outcome, "Only after the first check succeeds."),
        ])),
        with(|_: &Vec<u8>| 4u8, rule!("BLOCKED", unreachable, "Must not execute.")),
    ]);
    let values = vec![1, 2, 4];
    let mut trace = Trace::default();
    assert_eq!(node.evaluate_traced(&values, &mut trace), node.evaluate(&values));
    let observations: Vec<_> = trace.observations.iter()
        .map(|event| (event.id, event.status, event.path.clone())).collect();
    assert_eq!(observations, vec![
        ("GATED", TraceStatus::Gated, vec![]),
        ("ITEM", TraceStatus::Passed, vec![0]),
        ("LATER", TraceStatus::Passed, vec![0]),
        ("ITEM", TraceStatus::Incomplete, vec![1]),
        ("LATER", TraceStatus::Blocked, vec![1]),
        ("ITEM", TraceStatus::Blocked, vec![2]),
        ("LATER", TraceStatus::Blocked, vec![2]),
        ("BLOCKED", TraceStatus::Blocked, vec![]),
    ]);
    assert!(trace.observations.last().unwrap().detail.contains("ITEM"));

    // Exhaustive: the same outcome, but later rules and items still run, except
    // a later projection and the rest of an ordered group.
    let node = all(vec![
        each(|items: &Vec<u8>| items.clone(), rule!("ITEM", binary, "Evaluate an item.")),
        rule!("SIBLING", fails, "An independent sibling."),
        seq(vec![rule!("FIRST", fails, "First."), rule!("SECOND", unreachable_binary, "Relies on FIRST.")]),
        with(|_: &Vec<u8>| 4u8, rule!("PROJECTED", unreachable, "Must not execute.")),
    ]);
    let values = vec![3, 1, 3];
    let mut trace = Trace::exhaustive();
    assert_eq!(node.evaluate_traced(&values, &mut trace), node.evaluate(&values));
    let statuses: Vec<_> = trace.observations.iter().map(|event| (event.id, event.status)).collect();
    assert_eq!(statuses, vec![
        ("ITEM", TraceStatus::Failed),
        ("ITEM", TraceStatus::Passed),
        ("ITEM", TraceStatus::Failed),
        ("SIBLING", TraceStatus::Failed),
        ("FIRST", TraceStatus::Failed),
        ("SECOND", TraceStatus::Blocked),
        ("PROJECTED", TraceStatus::Blocked),
    ]);

    for values in [vec![], vec![0], vec![1], vec![3], vec![1, 3, 4]] {
        let mut trace = Trace::default();
        let items = section("Items", each(|items: &Vec<u8>| items.clone(),
            rule!("ITEM", outcome, "Evaluate an item.")));
        assert_eq!(items.evaluate_traced(&values, &mut trace), items.evaluate(&values));
        if values.is_empty() {
            assert_eq!(trace.observations[0].status, TraceStatus::Empty);
        } else if values == vec![0] {
            assert_eq!(trace.observations[0].status, TraceStatus::NotApplicable);
        }
    }
}
