//! Catalog metadata joined with the specification's rule and text definitions.

use std::collections::BTreeMap;

use crate::algebra::{Doc, Entry};

#[derive(Debug, Clone)]
pub struct Specification {
    pub title: &'static str,
    pub status: &'static str,
    pub preamble: Vec<Statement>,
    pub sections: Vec<Section>,
    pub open_questions: &'static [Question],
}

#[derive(Debug, Clone)]
pub struct Section {
    pub category: &'static str,
    pub title: &'static str,
    pub entries: Vec<Statement>,
}

#[derive(Debug, Clone)]
pub struct Statement {
    pub sheet_row: usize,
    pub id: &'static str,
    pub topic: &'static str,
    pub text: &'static str,
    /// Set for rules and guidance; definitions and references have none.
    pub strength: Option<Strength>,
    /// Set for rules only.
    pub coverage: Option<Coverage>,
    pub evidence: Evidence,
    /// Further sources, each with its own link.
    pub also: &'static [Evidence],
    pub basis: Basis,
    /// For a Derived or Resolution rule, the project's reading and its basis.
    pub reading: &'static str,
    pub notes: &'static str,
    /// Reader-facing guidance; imported review metadata is retained separately.
    pub implementation_note: &'static str,
    pub review: &'static str,
    pub enforcement: Enforcement,
    /// Every graph binding of the rule, in graph order; empty for text.
    pub implementations: Vec<Implementation>,
    /// For guidance, the role section it is shown with.
    pub role: &'static str,
    /// For a General rule, the role sections whose BIP text assigns its
    /// duty; each of those roles must refuse, or must not produce, a PSBT
    /// that fails it.
    pub roles: &'static [&'static str],
}

/// The normative strength a statement keeps from its BIP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strength {
    Must,
    MustNot,
    Should,
    May,
}

impl Strength {
    pub fn label(self) -> &'static str {
        match self {
            Strength::Must => "MUST",
            Strength::MustNot => "MUST NOT",
            Strength::Should => "SHOULD",
            Strength::May => "MAY",
        }
    }
}

/// Where a rule's wording comes from (PRINCIPLES item 12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    /// Restates one BIP sentence at its strength.
    Direct,
    /// Follows from BIP text without restating one sentence: it merges
    /// sentences, or reads a requirement from a field description or
    /// another BIP.
    Derived,
    /// The BIP text is ambiguous or silent and the project decided.
    Resolution,
}

impl Basis {
    pub fn label(self) -> &'static str {
        match self {
            Basis::Direct => "direct",
            Basis::Derived => "derived",
            Basis::Resolution => "resolution",
        }
    }
}

/// How far a rule's check decides its statement. Missing context makes a check
/// Incomplete without making its coverage Partial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// The check decides the stated property whenever its context is present.
    Full,
    /// The check decides only part of the stated property.
    Partial,
    /// This reference cannot decide the property: it needs cryptography the
    /// reference does not carry, or behavior a PSBT does not show.
    Declared,
    /// No check yet.
    Pending,
}

impl Coverage {
    pub fn label(self) -> &'static str {
        match self {
            Coverage::Full => "Full",
            Coverage::Partial => "Partial",
            Coverage::Declared => "Declared",
            Coverage::Pending => "Pending",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Implementation {
    pub func: &'static str,
    pub file: &'static str,
    pub line: u32,
    pub gates: Vec<String>,
    pub phase: Option<&'static str>,
}

#[derive(Debug, Clone, Copy)]
pub struct Evidence {
    pub label: &'static str,
    pub url: &'static str,
}

/// A correspondence to existing checks, not a claim of equivalent enforcement.
#[derive(Debug, Clone, Copy)]
pub struct Enforcement {
    pub gap: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct Question {
    pub topic: &'static str,
    pub text: &'static str,
}

/// One entry of the specification, declared once in spec.rs. A rule's checks
/// are bound to it in the graph with `check!`, which carries no wording.
#[derive(Debug, Clone, Copy)]
pub struct Declaration {
    pub id: &'static str,
    pub topic: &'static str,
    pub text: &'static str,
    pub strength: Option<Strength>,
    pub coverage: Option<Coverage>,
    pub evidence: Evidence,
    /// Further sources, each with its own link.
    pub also: &'static [Evidence],
    pub basis: Basis,
    /// For a Derived or Resolution rule, the project's reading and its basis.
    pub reading: &'static str,
    /// Reader-facing note on prerequisites and limits.
    pub note: &'static str,
    /// What a Partial check leaves undecided.
    pub gap: &'static str,
    /// For guidance, the role section it is shown with.
    pub role: &'static str,
    /// For a General rule, the role sections whose BIP text assigns its
    /// duty; each of those roles must refuse, or must not produce, a PSBT
    /// that fails it.
    pub roles: &'static [&'static str],
}

impl Declaration {
    pub const fn rule(id: &'static str, strength: Strength, coverage: Coverage, evidence: Evidence, text: &'static str) -> Self {
        Self { id, topic: "", text, strength: Some(strength), coverage: Some(coverage), evidence, also: &[], basis: Basis::Direct, reading: "", note: "", gap: "", role: "", roles: &[] }
    }

    pub const fn guidance(id: &'static str, strength: Strength, topic: &'static str, evidence: Evidence, text: &'static str) -> Self {
        Self { id, topic, text, strength: Some(strength), coverage: None, evidence, also: &[], basis: Basis::Direct, reading: "", note: "", gap: "", role: "", roles: &[] }
    }

    pub const fn reference(id: &'static str, topic: &'static str, evidence: Evidence, text: &'static str) -> Self {
        Self { id, topic, text, strength: None, coverage: None, evidence, also: &[], basis: Basis::Direct, reading: "", note: "", gap: "", role: "", roles: &[] }
    }

    /// A definition, listed by its term.
    pub const fn term(term: &'static str, evidence: Evidence, text: &'static str) -> Self {
        Self { id: "", topic: term, text, strength: None, coverage: None, evidence, also: &[], basis: Basis::Direct, reading: "", note: "", gap: "", role: "", roles: &[] }
    }

    /// Shows guidance with the named role section.
    pub const fn role(self, role: &'static str) -> Self {
        Self { role, ..self }
    }

    pub const fn roles(self, roles: &'static [&'static str]) -> Self {
        Self { roles, ..self }
    }

    pub const fn note(self, note: &'static str) -> Self {
        Self { note, ..self }
    }

    pub const fn gap(self, gap: &'static str) -> Self {
        Self { gap, ..self }
    }

    /// Marks the rule as derived, with the reading that derives it.
    pub const fn derived(self, reading: &'static str) -> Self {
        Self { basis: Basis::Derived, reading, ..self }
    }

    /// Marks the rule as a project resolution, with its basis.
    pub const fn resolution(self, reading: &'static str) -> Self {
        Self { basis: Basis::Resolution, reading, ..self }
    }

    /// Adds sources after the first, each with its own link.
    pub const fn cite(self, also: &'static [Evidence]) -> Self {
        Self { also, ..self }
    }
}

/// Evidence for a local definition with no BIP source.
pub const NO_EVIDENCE: Evidence = Evidence { label: "", url: "" };

/// A section of declarations, in display order.
#[derive(Debug, Clone, Copy)]
pub struct DeclaredSection {
    pub category: &'static str,
    pub title: &'static str,
    pub entries: &'static [Declaration],
}

#[derive(Debug, Clone, Copy)]
pub struct Text {
    pub key: &'static str,
    pub text: &'static str,
}

pub const fn text(key: &'static str, text: &'static str) -> Text {
    Text { key, text }
}

#[derive(Debug, Clone, Copy)]
struct StatementMetadata {
    sheet_row: usize,
    id: &'static str,
    topic: &'static str,
    strength: Option<Strength>,
    coverage: Option<Coverage>,
    evidence: Evidence,
    notes: &'static str,
    implementation_note: &'static str,
    review: &'static str,
    enforcement: Enforcement,
}

/// Joins exactly one rule or text definition to every catalog metadata entry.
///
/// Panics if a definition is duplicated, missing, or has no matching metadata.
pub fn build(doc: &Doc, descriptions: &[Text], declared: &[DeclaredSection]) -> Specification {
    let mut definitions = BTreeMap::new();
    for entry in &doc.entries {
        if let Entry::Rule {
            id,
            text,
            func,
            file,
            line,
            gates,
            phase,
        } = entry
        {
            let implementation = Implementation {
                func,
                file,
                line: *line,
                gates: gates.clone(),
                phase: *phase,
            };
            // A rule bound at several graph points keeps one statement.
            let (wording, bindings) = definitions.entry(*id).or_insert((*text, Vec::new()));
            assert_eq!(*wording, *text, "rule {id} is bound with different wording");
            bindings.push(implementation);
        }
    }
    for description in descriptions {
        assert!(
            definitions
                .insert(description.key, (description.text, Vec::new()))
                .is_none(),
            "duplicate catalog definition: {}",
            description.key,
        );
    }

    let mut resolve = |metadata: &StatementMetadata| {
        let key = if metadata.id.is_empty() {
            metadata.topic
        } else {
            metadata.id
        };
        let (text, implementations) = definitions
            .remove(key)
            .unwrap_or_else(|| panic!("missing catalog definition: {key}"));
        Statement {
            sheet_row: metadata.sheet_row,
            id: metadata.id,
            topic: metadata.topic,
            text,
            strength: metadata.strength,
            coverage: metadata.coverage,
            evidence: metadata.evidence,
            also: &[],
            basis: Basis::Direct,
            reading: "",
            notes: metadata.notes,
            implementation_note: metadata.implementation_note,
            review: metadata.review,
            enforcement: metadata.enforcement,
            implementations,
            role: "",
            roles: &[],
        }
    };
    let preamble = PREAMBLE.iter().map(&mut resolve).collect();
    let sections: Vec<Section> = declared
        .iter()
        .map(|section| Section {
            category: section.category,
            title: section.title,
            entries: section.entries.iter().map(|d| declared_statement(d, &mut definitions)).collect(),
        })
        .collect();
    assert!(
        definitions.is_empty(),
        "unknown catalog definitions: {:?}",
        definitions.keys()
    );

    Specification {
        title: TITLE,
        status: STATUS,
        preamble,
        sections,
        open_questions: OPEN_QUESTIONS,
    }
}

/// A declared entry with the checks bound to it. Its bindings carry no wording.
fn declared_statement(d: &Declaration, definitions: &mut BTreeMap<&'static str, (&'static str, Vec<Implementation>)>) -> Statement {
    let key = if d.id.is_empty() { d.topic } else { d.id };
    let implementations = match definitions.remove(key) {
        Some((wording, implementations)) => {
            assert!(wording.is_empty(), "declared rule {key} must be bound with check!, not rule!");
            implementations
        }
        None => Vec::new(),
    };
    Statement {
        sheet_row: 0,
        id: d.id,
        topic: d.topic,
        text: d.text,
        strength: d.strength,
        coverage: d.coverage,
        evidence: d.evidence,
        also: d.also,
        basis: d.basis,
        reading: d.reading,
        notes: "",
        implementation_note: d.note,
        review: "",
        enforcement: Enforcement { gap: d.gap },
        implementations,
        role: d.role,
        roles: d.roles,
    }
}

// Imported metadata. Statement wording lives in spec.rs rule and Text definitions.
const TITLE: &str = "PSBT Conformance Specification";
const STATUS: &str = "Draft. Rule IDs may change until version 1.0.";
#[rustfmt::skip]
const PREAMBLE: &[StatementMetadata] = &[
    StatementMetadata {
        sheet_row: 3,
        id: "",
        topic: "Scope",
        strength: None, coverage: None,
        evidence: Evidence { label: "BIP174 - Version Numbers", url: "https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#version-numbers" },
        notes: "Other versions are unsupported by this specification.",
        implementation_note: "",
        review: "",
        enforcement: Enforcement { gap: "Existing version check; unsupported versions fail validation." },
    },
    StatementMetadata {
        sheet_row: 4,
        id: "",
        topic: "Applicability",
        strength: None, coverage: None,
        evidence: Evidence { label: "", url: "" },
        notes: "Review draft: published-versus-development differences remain identified below.",
        implementation_note: "",
        review: "",
        enforcement: Enforcement { gap: "The existing graph gates extensions, but several role duties are currently placed in universal validity." },
    },
    StatementMetadata {
        sheet_row: 5,
        id: "",
        topic: "Validation context",
        strength: None, coverage: None,
        evidence: Evidence { label: "BIP174 - Signer", url: "https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#signer" },
        notes: "No blanket requirement to embed every public key in a BIP32 derivation field.",
        implementation_note: "Evaluate role checks only after framing, field formats, required fields and map counts have passed. The evaluation API distinguishes Verified, NotApplicable, Incomplete and Failed; compatibility validate APIs expose only success or failure. Public keys need not always come from BIP32 derivation fields.",
        review: "",
        enforcement: Enforcement { gap: "The validator returns only success or failure. It does not expose a distinct incomplete-check outcome." },
    },
];

#[rustfmt::skip]
const OPEN_QUESTIONS: &[Question] = &[
    Question { topic: "SP output ordering", text: "REF-4 follows the BIP375 prose ordering of silent-payment codes; the published helper uses output-map ordering, which can produce different scripts." },
];

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptions() -> Vec<Text> {
        PREAMBLE
            .iter()
            .map(|metadata| {
                let key = if metadata.id.is_empty() {
                    metadata.topic
                } else {
                    metadata.id
                };
                text(key, "test definition")
            })
            .collect()
    }

    fn rule() -> Entry {
        Entry::Rule {
            id: "Scope",
            text: "test rule definition",
            func: "validate_scope",
            file: "test.rs",
            line: 12,
            gates: vec!["test gate".into()],
            phase: None,
        }
    }

    #[test]
    fn metadata_order_and_rule_details_are_preserved() {
        let mut descriptions = descriptions();
        descriptions.remove(0);
        descriptions.reverse();
        let mut doc = Doc::default();
        doc.entries.push(Entry::Section("ignored graph grouping"));
        doc.entries.push(rule());
        let specification = build(&doc, &descriptions, &[]);
        assert_eq!(specification.preamble[0].id, "");
        assert_eq!(specification.preamble[0].topic, "Scope");
        assert_eq!(specification.preamble[0].text, "test rule definition");
        let implementation = &specification.preamble[0].implementations[0];
        assert_eq!(implementation.func, "validate_scope");
        assert_eq!(implementation.file, "test.rs");
        assert_eq!(implementation.line, 12);
        assert_eq!(implementation.gates, ["test gate"]);
        assert!(specification.preamble[1].implementations.is_empty());
    }

    const TEST_SECTION: DeclaredSection = DeclaredSection { category: "general", title: "Test", entries: &[
        Declaration::rule("GEN-X-1", Strength::Must, Coverage::Full, NO_EVIDENCE, "declared wording"),
    ]};

    fn binding(text: &'static str) -> Entry {
        Entry::Rule { id: "GEN-X-1", text, func: "validate_x", file: "test.rs", line: 3, gates: vec![], phase: None }
    }

    #[test]
    fn a_declared_rule_takes_its_wording_from_the_declaration() {
        let mut doc = Doc::default();
        doc.entries.extend([rule(), binding(""), binding("")]);
        let specification = build(&doc, &descriptions()[1..], &[TEST_SECTION]);
        let statement = &specification.sections[0].entries[0];
        assert_eq!((statement.id, statement.text), ("GEN-X-1", "declared wording"));
        assert_eq!(statement.implementations.len(), 2);
    }

    #[test]
    #[should_panic(expected = "declared rule GEN-X-1 must be bound with check!")]
    fn a_declared_rule_bound_with_wording_is_rejected() {
        let mut doc = Doc::default();
        doc.entries.extend([rule(), binding("other wording")]);
        build(&doc, &descriptions()[1..], &[TEST_SECTION]);
    }

    #[test]
    #[should_panic(expected = "duplicate catalog definition: Scope")]
    fn duplicate_text_is_rejected() {
        let mut descriptions = descriptions();
        descriptions.push(descriptions[0]);
        build(&Doc::default(), &descriptions, &[]);
    }

    #[test]
    #[should_panic(expected = "duplicate catalog definition: Scope")]
    fn rule_and_text_collision_is_rejected() {
        let mut doc = Doc::default();
        doc.entries.push(rule());
        build(&doc, &descriptions(), &[]);
    }

    #[test]
    fn a_rule_bound_twice_keeps_both_bindings() {
        let mut doc = Doc::default();
        doc.entries.extend([rule(), rule()]);
        let specification = build(&doc, &descriptions()[1..], &[]);
        assert_eq!(specification.preamble[0].implementations.len(), 2);
    }

    #[test]
    #[should_panic(expected = "rule Scope is bound with different wording")]
    fn a_rule_bound_with_different_wording_is_rejected() {
        let mut other = rule();
        if let Entry::Rule { text, .. } = &mut other {
            *text = "other wording";
        }
        let mut doc = Doc::default();
        doc.entries.extend([rule(), other]);
        build(&doc, &descriptions()[1..], &[]);
    }

    #[test]
    #[should_panic(expected = "missing catalog definition: Scope")]
    fn missing_definition_is_rejected() {
        build(&Doc::default(), &descriptions()[1..], &[]);
    }

    #[test]
    #[should_panic(expected = "unknown catalog definitions")]
    fn unexpected_definition_is_rejected() {
        let mut descriptions = descriptions();
        descriptions.push(text("unknown", "unexpected definition"));
        build(&Doc::default(), &descriptions, &[]);
    }

    #[test]
    #[should_panic(expected = "missing catalog definition: Scope")]
    fn correct_count_with_wrong_key_is_rejected() {
        let mut descriptions = descriptions();
        descriptions[0] = text("unknown", "unexpected definition");
        build(&Doc::default(), &descriptions, &[]);
    }
}
