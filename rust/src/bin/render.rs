//! Renders spec.html from the typed catalog, validation graphs and field registry.
//! Usage: cargo run --bin render > ../spec.html
//!        cargo run --bin render -- --json > ../rules.json
//!        cargo run --bin render -- --markdown > ../rules.md
//!        PSBT_SPEC_SOURCE_BASE=... cargo run --bin render -- --site ../site
//! Function links are relative to the repository root; set
//! PSBT_SPEC_SOURCE_BASE (for example a GitHub blob URL at a pinned commit,
//! ending in "/") to publish the page with absolute, pinned links, and
//! PSBT_SPEC_REVISION to the commit it was rendered from.

use std::collections::BTreeMap;

use psbt_spec::attribution::attribute;
use psbt_spec::corpus;
use psbt_spec::registry::{Field, FIELDS};
use psbt_spec::spec;
use psbt_spec::spec::{Basis, Evidence, Specification, Statement};
use serde_json::json;

/// Notable changes, newest first: (date, change).
const CHANGELOG: &[(&str, &str)] = &[
    ("2026-11-25", "BIP375 pinned to bips 21e48c11 (v0.3.0, tag psbt-spec-bip375-21e48c11 on macgyver13/bips), which accepts SIGHASH_DEFAULT in place of SIGHASH_ALL on a taproot input; bip375.json re-imported from it with vectors/tools/import_bip375.py. Input eligibility excludes uncompressed P2PKH inputs and P2SH inputs whose redeemScript does not match. The synthetic roles.json corpus became a test fixture, with its BIP174 and BIP375 role vectors moved into those corpora. The SP output ordering open question is closed, and bip376.json is marked as generated locally."),
    ("2026-11-12", "Per-rule corpus coverage, the Markdown export (rules.md), the rules.json schema and llms.txt."),
    ("2026-11-12", "Signer rules renumbered to close the ID gaps; the Creator, Constructor and Updater sections say how to evaluate them."),
    ("2026-11-11", "BIP375 pinned to bips 9c5b825 (v1.2.2); the signing-order duty becomes General rule GEN-SP-7."),
    ("2026-11-11", "The evaluate, vectors and attribute commands, the adapter contract and corpus schema v1."),
    ("2026-10-29", "Every rule, definition, procedure and guidance entry declared once in spec.rs; rules.json added."),
];

/// A corpus vector, as `psbt-spec vectors` numbers it.
struct VectorRef {
    file: &'static str,
    index: usize,
    description: String,
}

/// The corpus vectors that exercise one rule.
#[derive(Default)]
struct RuleCorpus {
    /// Invalid vectors labeled with the rule that isolate it (tests/corpus.rs).
    isolating: Vec<VectorRef>,
    /// Valid vectors whose entry point observed the rule Passed.
    passing: Vec<VectorRef>,
}

/// Per-rule corpus coverage, computed by the certifier over every corpus file.
fn corpus_coverage() -> BTreeMap<String, RuleCorpus> {
    let mut map: BTreeMap<String, RuleCorpus> = BTreeMap::new();
    for (file, text) in corpus::FILES {
        for v in corpus::parse(text).expect("corpus file").vectors {
            let failures = attribute(v.task, &v.request);
            let at = || VectorRef { file, index: v.index, description: v.description.clone() };
            if v.valid {
                for id in &failures.passed {
                    map.entry((*id).to_owned()).or_default().passing.push(at());
                }
            } else if corpus::isolates(&v, &failures) {
                map.entry(v.rule.clone().unwrap()).or_default().isolating.push(at());
            }
        }
    }
    map
}

/// corpus: a vector isolates the rule; tests only: it has a check, which
/// tests/rule_ids.rs observes Failed; none: it has no check.
fn corpus_status(statement: &Statement, corpus: Option<&RuleCorpus>) -> &'static str {
    if corpus.is_some_and(|c| !c.isolating.is_empty()) {
        "corpus"
    } else if !statement.implementations.is_empty() {
        "tests only"
    } else {
        "none"
    }
}

/// Vector indices grouped by file: "bip174 #0 #3; roles #2".
fn grouped(vectors: &[VectorRef]) -> Vec<(&'static str, Vec<usize>)> {
    let mut groups: Vec<(&'static str, Vec<usize>)> = Vec::new();
    for v in vectors {
        match groups.last_mut() {
            Some((file, indices)) if *file == v.file => indices.push(v.index),
            _ => groups.push((v.file, vec![v.index])),
        }
    }
    groups
}

fn corpus_cell(statement: &Statement, corpus: Option<&RuleCorpus>) -> String {
    let status = corpus_status(statement, corpus);
    let empty = RuleCorpus::default();
    let c = corpus.unwrap_or(&empty);
    if c.isolating.is_empty() && c.passing.is_empty() {
        return format!("<span class=corpus>Vectors: <a href=\"#vector-coverage\">{status}</a></span>");
    }
    let isolating: String = c.isolating.iter().map(|v| format!(
        "<li><a href=\"vectors/{0}.json\">{0}</a> #{1}: {2}</li>", v.file, v.index, esc(&v.description)
    )).collect();
    let passing = grouped(&c.passing).iter().map(|(file, indices)| format!(
        "<a href=\"vectors/{file}.json\">{file}</a> {}", indices.iter().map(|i| format!("#{i}")).collect::<Vec<_>>().join(" ")
    )).collect::<Vec<_>>().join("; ");
    let mut body = String::new();
    if !isolating.is_empty() {
        body += &format!("<p>Isolate:</p><ul>{isolating}</ul>");
    }
    if !passing.is_empty() {
        body += &format!("<p>Pass: {passing}</p>");
    }
    format!(
        "<details class=corpus><summary>Vectors: {status}, {} isolate, {} pass</summary>{body}</details>",
        c.isolating.len(), c.passing.len()
    )
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

/// Every source of a statement, each with its own link.
fn sources(statement: &Statement) -> impl Iterator<Item = &Evidence> {
    std::iter::once(&statement.evidence).chain(statement.also)
}

fn evidence_link(statement: &Statement) -> String {
    sources(statement).map(|evidence| if evidence.url.is_empty() {
        esc(evidence.label)
    } else {
        format!("<a href=\"{}\">{}</a>", esc(evidence.url), esc(evidence.label))
    }).collect::<Vec<_>>().join("; ")
}

/// The basis tag of a Derived or Resolution rule; Direct rules show none.
fn basis_tag(statement: &Statement) -> String {
    match statement.basis {
        Basis::Direct => String::new(),
        Basis::Derived => "<span class=basis>Derived</span>".into(),
        Basis::Resolution => "<span class=basis>Resolution</span>".into(),
    }
}

fn reading(statement: &Statement) -> String {
    if statement.reading.is_empty() {
        String::new()
    } else {
        format!("<span class=reading>Reading: {}</span>", linked_text(statement.reading))
    }
}

/// The note and, for a Partial rule, what its check leaves undecided.
fn implementation_note(statement: &Statement) -> String {
    let gap = statement.enforcement.gap;
    if statement.implementation_note.is_empty() && gap.is_empty() {
        return String::new();
    }
    let mut body = esc(statement.implementation_note);
    if !gap.is_empty() {
        body += &format!("{}<em>Not decided:</em> {}", if body.is_empty() { "" } else { " " }, esc(gap));
    }
    format!("<details><summary>Implementation note</summary><p>{body}</p></details>")
}

/// Where function links point: the repository root unless PSBT_SPEC_SOURCE_BASE says otherwise.
fn source_base() -> String {
    std::env::var("PSBT_SPEC_SOURCE_BASE").unwrap_or_default()
}

fn function_source(function: &str) -> Option<(&'static str, usize)> {
    let (module, name) = function.strip_prefix("crate::rules::")?.split_once("::")?;
    let module_file = format!("src/rules/{module}.rs");
    let sources = [
        ("src/rules/catalog.rs", include_str!("../rules/catalog.rs")),
        ("src/rules/combiner.rs", include_str!("../rules/combiner.rs")),
        ("src/rules/constructor.rs", include_str!("../rules/constructor.rs")),
        ("src/rules/creator.rs", include_str!("../rules/creator.rs")),
        ("src/rules/extractor.rs", include_str!("../rules/extractor.rs")),
        ("src/rules/finalizer.rs", include_str!("../rules/finalizer.rs")),
        ("src/rules/framing.rs", include_str!("../rules/framing.rs")),
        ("src/rules/global.rs", include_str!("../rules/global.rs")),
        ("src/rules/input_output.rs", include_str!("../rules/input_output.rs")),
        ("src/rules/sending.rs", include_str!("../rules/sending.rs")),
        ("src/rules/signer.rs", include_str!("../rules/signer.rs")),
        ("src/rules/spending.rs", include_str!("../rules/spending.rs")),
        ("src/rules/dnssec.rs", include_str!("../rules/dnssec.rs")),
        ("src/rules/message.rs", include_str!("../rules/message.rs")),
        ("src/rules/p2c.rs", include_str!("../rules/p2c.rs")),
        ("src/rules/musig.rs", include_str!("../rules/musig.rs")),
        ("src/rules/taproot.rs", include_str!("../rules/taproot.rs")),
    ];
    let (file, source) = sources.iter().find(|(file, _)| *file == module_file)?;
    let declaration = format!("pub fn {name}(");
    source.lines().position(|line| line.trim_start().starts_with(&declaration))
        .map(|line| (*file, line + 1))
}

fn validation_cell(statement: &Statement) -> String {
    let coverage = statement.coverage.map(|c| c.label()).unwrap_or("-");
    if statement.implementations.is_empty() {
        return coverage.to_owned();
    }
    let mut previous: Option<&Vec<String>> = None;
    let bindings: Vec<String> = statement.implementations.iter().map(|implementation| {
        // A rule bound once per subcheck repeats its gates; show them when they change.
        let conditions: String = if previous == Some(&implementation.gates) { String::new() } else {
            implementation.gates.iter().map(|gate| format!("<span class=gate>{}</span><br>", esc(gate))).collect()
        };
        previous = Some(&implementation.gates);
        let name = implementation.func.rsplit("::").next().unwrap();
        let function = match function_source(implementation.func) {
            Some((file, line)) => format!(
                "<a href=\"{}rust/{}#L{line}\"><code>{}</code></a>",
                esc(&source_base()), esc(file), esc(name)
            ),
            None => format!("<code>{}</code>", esc(name)),
        };
        format!("{conditions}{function}")
    }).collect();
    format!("{}<span class=coverage>{coverage}</span>", bindings.join("<br>"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_lookup_requires_the_declaring_module() {
        for identity in [
            "validate_magic",
            "rules::framing::validate_magic",
            "crate::rules::global::validate_magic",
            "crate::rules::missing::validate_magic",
            "crate::rules::framing::missing",
            "crate::rules::framing::nested::validate_magic",
        ] {
            assert_eq!(function_source(identity), None, "{identity}");
        }
        let (file, line) = function_source("crate::rules::framing::validate_magic")
            .expect("qualified declaration");
        assert_eq!(file, "src/rules/framing.rs");
        assert!(include_str!("../rules/framing.rs").lines().nth(line - 1).unwrap()
            .starts_with("pub fn validate_magic("));
    }

    #[test]
    fn unresolved_identity_has_a_short_label_without_a_source_link() {
        let mut statement = spec::specification().sections.into_iter()
            .flat_map(|section| section.entries)
            .find(|statement| statement.implementations.len() == 1)
            .expect("implemented statement");
        let implementation = &mut statement.implementations[0];
        implementation.func = "crate::rules::global::validate_magic";
        implementation.gates.clear();
        assert_eq!(validation_cell(&statement), "<code>validate_magic</code><span class=coverage>Full</span>");
    }
}

/// The anchor of a definition, from its term.
fn term_anchor(term: &str) -> String {
    format!("term-{}", slug(term))
}

fn slug(text: &str) -> String {
    text.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' }).collect()
}

/// The strength tag for a rule or guidance entry, if it has one.
fn strength_tag(statement: &Statement) -> String {
    statement.strength
        .map(|s| format!("<span class=strength>{}</span>", s.label()))
        .unwrap_or_default()
}

/// The phase of a role rule: Precondition or Result.
fn phase(statement: &Statement) -> Option<&'static str> {
    statement.implementations.first().and_then(|i| i.phase)
}

fn phase_tag(statement: &Statement) -> String {
    phase(statement)
        .map(|phase| format!("<span class=phase>{}</span>", esc(phase)))
        .unwrap_or_default()
}

/// The registry field names a text uses, in order of first use.
fn field_names(text: &str) -> Vec<&'static str> {
    let mut names: Vec<&'static str> = FIELDS.iter().map(|f| f.name)
        .filter(|name| text.match_indices(name).any(|(at, _)| {
            let after = text[at + name.len()..].chars().next();
            !after.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        }))
        .collect();
    names.sort_by_key(|name| text.find(name));
    names
}

/// Escaped text with each registry field name linked to its row.
fn linked_text(text: &str) -> String {
    let html = esc(text);
    let mut out = String::new();
    let mut rest = html.as_str();
    while let Some(at) = rest.find("PSBT_") {
        let len = rest[at..].find(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')).unwrap_or(rest.len() - at);
        let word = &rest[at..at + len];
        out += &rest[..at];
        if FIELDS.iter().any(|f| f.name == word) {
            out += &format!("<a class=field href=\"#field-{word}\">{word}</a>");
        } else {
            out += word;
        }
        rest = &rest[at + len..];
    }
    let mut out = out + rest;
    // Background BIPs the rules name without an evidence link of their own.
    for bip in ["352", "374"] {
        out = out.replace(&format!("BIP{bip}"), &format!(
            "<a href=\"https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0{bip}.mediawiki\">BIP{bip}</a>"));
    }
    out
}

/// The BIP numbers a statement's evidence cites, for the extension filter.
fn bips(statement: &Statement) -> String {
    let mut found: Vec<String> = Vec::new();
    for label in sources(statement).map(|e| e.label) {
        for (at, _) in label.match_indices("BIP") {
            let digits: String = label[at + 3..].chars().take_while(char::is_ascii_digit).collect();
            if !digits.is_empty() && !found.contains(&digits) { found.push(digits); }
        }
    }
    found.join(" ")
}

fn statement_row(statement: &Statement, show_topic: bool, corpus: &BTreeMap<String, RuleCorpus>) -> String {
    let anchor = if statement.id.is_empty() { term_anchor(statement.topic) } else { statement.id.to_owned() };
    let topic = if show_topic { format!("<strong>{}.</strong> ", esc(statement.topic)) } else { String::new() };
    let id = if statement.id.is_empty() {
        String::new()
    } else {
        format!("<a href=\"#{0}\">{0}</a>", esc(statement.id))
    };
    let evidence = if statement.evidence.label.is_empty() {
        String::new()
    } else {
        format!("<span class=evidence>From {}</span>", evidence_link(statement))
    };
    format!(
        "<tr id=\"{}\" data-rule data-strength=\"{}\" data-bips=\"{}\"><td class=id>{id}{}{}{}</td><td>{topic}<span class=statement-text>{}</span>{}{evidence}{}</td><td class=validation>{}</td></tr>\n",
        esc(&anchor),
        statement.strength.map(|s| s.label()).unwrap_or(""),
        bips(statement),
        strength_tag(statement), basis_tag(statement), phase_tag(statement), linked_text(statement.text),
        reading(statement), implementation_note(statement), validation_cell(statement)
            + &if statement.coverage.is_some() { corpus_cell(statement, corpus.get(statement.id)) } else { String::new() }
    )
}

fn band(label: &str, html: &str) -> String {
    format!("<tr class=band><td colspan=3>{label}</td></tr>\n{html}")
}

/// A role section: the General rules as its implicit precondition, then its
/// Precondition rules, rules a PSBT cannot show, Result rules and guidance.
fn role_section(title: &str, entries: &[Statement], general: &[&Statement], guidance: &[&Statement], corpus: &BTreeMap<String, RuleCorpus>) -> String {
    let rows = |pick: &dyn Fn(&Statement) -> bool| -> String {
        entries.iter().filter(|s| pick(s)).map(|s| statement_row(s, false, corpus)).collect()
    };
    let mut html = format!(
        "<tr class=section id=\"role-{}\"><td colspan=3>{}</td></tr>\n<tr class=band><td colspan=3>Receives a PSBT that satisfies the <a href=\"#general\">General rules</a></td></tr>\n",
        slug(title), esc(title)
    );
    let owned: String = general
        .iter()
        .filter(|s| s.roles.contains(&title))
        .map(|s| format!("<li><a href=\"#{0}\">{0}</a> {1}</li>", esc(s.id), esc(s.text)))
        .collect();
    if title == "Updater" {
        html += &band(
            "How to evaluate",
            "<tr><td colspan=3>The adapter contract has no update request, and ROLE-U-1 is declared: only the Updater knows that an input spends a silent payment output, so no check decides it, and a report shows it as NOT RUN. What the PSBT does show is checked by the General rules (GEN-SP-6 rejects a spend-key derivation without the tweak): run <code>psbt-spec attribute</code> with task <code>deserialize</code> on what your Updater returns. Interoperability harnesses check it on each hop of a real workflow.</td></tr>\n",
        );
    }
    if title == "Creator and Constructor" {
        html += &band(
            "How to evaluate",
            "<tr><td colspan=3>The adapter contract has no request that asks a project to build a PSBT, so a report shows these rules as NOT RUN. Check them on PSBTs your builder produces: run <code>psbt-spec attribute</code> with task <code>create</code> or <code>construct</code> on what it returns. Interoperability harnesses check them on each hop of a real workflow.</td></tr>\n",
        );
    }
    if !owned.is_empty() {
        html += &band(
            "General rules this role must enforce",
            &format!("<tr><td colspan=3>The BIP assigns these duties to this role. It must refuse a PSBT that fails one, and must not return one that does.<ul>{owned}</ul></td></tr>\n"),
        );
    }
    for (label, wanted) in [("Precondition", Some("Precondition")), ("Not shown in the PSBT", None), ("Result", Some("Result"))] {
        let part = rows(&|s| phase(s) == wanted);
        if !part.is_empty() {
            html += &band(label, &part);
        }
    }
    let advice: String = guidance.iter().map(|s| statement_row(s, true, corpus)).collect();
    if !advice.is_empty() {
        html += &band("Guidance", &advice);
    }
    html
}

fn table(id: &str, heading: &str, description: &str, column: &str, check: &str, body: &str) -> String {
    format!("<h2 id=\"{id}\">{heading}</h2>\n<p>{description}</p>\n<div class=scroll><table class=rules><tr><th>ID</th><th>{column}</th><th>{check}</th></tr>\n{body}</table></div>\n")
}

fn catalog(specification: &Specification, corpus: &BTreeMap<String, RuleCorpus>) -> String {
    let sections = |category: &'static str| specification.sections.iter().filter(move |s| s.category == category);
    let guidance: Vec<&Statement> = sections("guidance").flat_map(|s| &s.entries).collect();
    let role_titles: Vec<&str> = sections("role").map(|s| s.title).collect();
    let general_rules: Vec<&Statement> = sections("general").flat_map(|s| &s.entries).collect();

    let general: String = sections("general")
        .map(|s| format!("<tr class=section><td colspan=3>{}</td></tr>\n{}", esc(s.title), s.entries.iter().map(|e| statement_row(e, false, corpus)).collect::<String>()))
        .collect();
    let strip: String = sections("role")
        .map(|s| format!("<a href=\"#role-{}\">{} <span class=count>{}</span></a>", slug(s.title), esc(s.title), s.entries.len()))
        .collect::<Vec<_>>()
        .join(" &middot; ");
    let roles: String = sections("role")
        .map(|s| {
            let advice: Vec<&Statement> = guidance.iter().copied().filter(|g| g.role == s.title).collect();
            role_section(s.title, &s.entries, &general_rules, &advice, corpus)
        })
        .collect();
    let rows = |category: &'static str| -> String {
        sections(category).flat_map(|s| &s.entries).map(|e| statement_row(e, true, corpus)).collect()
    };
    let unassigned: String = guidance.iter().filter(|g| !role_titles.contains(&g.role)).map(|g| statement_row(g, true, corpus)).collect();

    let mut html = table("general", "General rules", "Properties a PSBT must satisfy under the applicable version and extensions. They are the precondition of every role.", "Rule", "Check", &general);
    html += &format!(
        "<h2 id=\"roles\">Role obligations</h2>\n<p>Requirements that apply when performing the named operation. A <em>Precondition</em> is checked on the PSBT the role received. Failing it means the role must refuse. A <em>Result</em> is checked on the PSBT the role returned, alone or against what it received. Each role's SHOULD and MAY guidance follows its rules.</p>\n<p class=strip>{strip}</p>\n<div class=scroll><table class=rules><tr><th>ID</th><th>Obligation</th><th>Check</th></tr>\n{roles}</table></div>\n"
    );
    html += &table("definitions", "Definitions", "Terms the rules use.", "Definition", "", &rows("definition"));
    html += &table("procedures", "Procedures", "Procedures the rules cite.", "Procedure", "", &rows("reference"));
    if !unassigned.is_empty() {
        html += &table("guidance", "Guidance", "Recommendations and permitted actions not tied to one role.", "Guidance", "", &unassigned);
    }
    html
}

fn preamble(specification: &Specification) -> String {
    specification.preamble.iter().map(|statement| {
        let validation = if statement.implementations.is_empty() {
            String::new()
        } else {
            format!("<p>Validation: {}</p>", validation_cell(statement))
        };
        format!(
            "<div id=\"context-{}\"><p><strong>{}.</strong> <span class=statement-text>{}</span> <span class=evidence>From {}</span></p>{}{validation}</div>\n",
            statement.sheet_row, esc(statement.topic), linked_text(statement.text),
            evidence_link(statement), implementation_note(statement)
        )
    }).collect()
}

fn versions(v: &[u32]) -> String {
    v.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ")
}

/// The versions that require `f`, and the fields that may replace it.
fn required(f: &Field) -> String {
    let mut s = versions(f.required_in);
    for &t in f.replaced_by {
        let alt = FIELDS.iter().find(|a| a.scope == f.scope && a.key_type == t).unwrap();
        s += &format!(" (or {} from BIP-{})", alt.name, alt.bip);
    }
    s
}

/// The IDs of the rules, definitions and procedures whose text names `field`.
fn citing(specification: &Specification, field: &str) -> String {
    specification.sections.iter().flat_map(|s| &s.entries)
        .filter(|e| !e.id.is_empty() && field_names(e.text).contains(&field))
        .map(|e| format!("<a href=\"#{0}\">{0}</a>", esc(e.id)))
        .collect::<Vec<_>>()
        .join(" ")
}

/// What the key data and value of a silent payment field hold (BIP375), shown
/// after the format so the registry says more than the sizes.
const FIELD_CONTENTS: &[(&str, &str, &str)] = &[
    ("PSBT_GLOBAL_SP_ECDH_SHARE", "the scan key this share is for", "the ECDH share for that scan key, summed over all eligible inputs"),
    ("PSBT_GLOBAL_SP_DLEQ", "the scan key this proof covers", "a BIP374 DLEQ proof for the matching global ECDH share"),
    ("PSBT_IN_SP_ECDH_SHARE", "the scan key this share is for", "this input's ECDH share for that scan key"),
    ("PSBT_IN_SP_DLEQ", "the scan key this proof covers", "a BIP374 DLEQ proof for the matching input ECDH share"),
    ("PSBT_OUT_SP_V0_INFO", "", "the recipient's scan key, then their spend key"),
    ("PSBT_OUT_SP_V0_LABEL", "", "the label the recipient applied to the spend key, as a little-endian integer (used for change)"),
];

fn field_row(specification: &Specification, f: &Field) -> String {
    let contents = FIELD_CONTENTS.iter().find(|(name, ..)| *name == f.name);
    let cell = |format: &str, meaning: Option<&str>| match meaning {
        Some(m) if !m.is_empty() => format!("{}: {}", esc(format), esc(m)),
        _ => esc(format),
    };
    format!(
        "<tr id=\"field-{name}\"><td><code>{name}</code></td><td><code>{:#04x}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
        f.key_type, cell(f.key.constraint(), contents.map(|c| c.1)), cell(f.value.constraint(), contents.map(|c| c.2)), required(f), versions(f.excluded_in), f.bip,
        citing(specification, f.name), name = f.name
    )
}

fn field_tables(specification: &Specification) -> String {
    ["Global", "Input", "Output"].iter().map(|scope| {
        let rows: String = FIELDS.iter().filter(|f| format!("{:?}", f.scope) == *scope).map(|f| field_row(specification, f)).collect();
        format!("<h3 id=\"fields-{}\">{scope} fields</h3>\n<div class=scroll><table class=fields><tr><th>Field</th><th>Type</th><th>Key data</th><th>Value</th><th>Required</th><th>Excluded</th><th>BIP</th><th>Rules</th></tr>\n{rows}</table></div>\n", scope.to_lowercase())
    }).collect()
}

fn open_questions(specification: &Specification) -> String {
    if specification.open_questions.is_empty() {
        return String::new();
    }
    let items: String = specification.open_questions.iter()
        .map(|q| format!("<li><strong>{}.</strong> {}</li>\n", esc(q.topic), esc(q.text)))
        .collect();
    format!("<h2 id=\"questions\">Open questions</h2>\n<ul>\n{items}</ul>\n")
}

/// The spec revision: the package version, and the commit when rendering for publication.
fn revision() -> String {
    match std::env::var("PSBT_SPEC_REVISION") {
        Ok(commit) if !commit.is_empty() => format!("{} ({commit})", env!("CARGO_PKG_VERSION")),
        _ => env!("CARGO_PKG_VERSION").to_owned(),
    }
}

/// Each corpus file: name, the bips revision it pins, its BIPs and vector count.
fn corpora() -> Vec<(&'static str, String, Vec<u64>, usize)> {
    corpus::FILES.iter().map(|(name, text)| {
        let file = corpus::parse(text).expect("corpus file");
        (*name, file.bip_revision, file.bips, file.vectors.len())
    }).collect()
}

fn corpus_json(statement: &Statement, corpus: Option<&RuleCorpus>) -> serde_json::Value {
    let refs = |vectors: &[VectorRef], described: bool| -> Vec<serde_json::Value> {
        vectors.iter().map(|v| if described {
            json!({ "file": v.file, "index": v.index, "description": v.description })
        } else {
            json!({ "file": v.file, "index": v.index })
        }).collect()
    };
    json!({
        "status": corpus_status(statement, corpus),
        "isolating": corpus.map(|c| refs(&c.isolating, true)).unwrap_or_default(),
        "passing": corpus.map(|c| refs(&c.passing, false)).unwrap_or_default(),
    })
}

/// Every declared entry, for machine audits.
fn rules_json(specification: &Specification, corpus: &BTreeMap<String, RuleCorpus>) -> serde_json::Value {
    let entries: Vec<_> = specification.sections.iter().flat_map(|section| section.entries.iter().map(move |e| {
        json!({
            "id": e.id,
            "topic": e.topic,
            "category": section.category,
            "section": section.title,
            "text": e.text,
            "strength": e.strength.map(|s| s.label()),
            "coverage": e.coverage.map(|c| c.label()),
            "phase": phase(e),
            "gates": e.implementations.first().map(|i| i.gates.clone()).unwrap_or_default(),
            "checks": e.implementations.iter().map(|i| i.func.trim_start_matches("crate::")).collect::<Vec<_>>(),
            "basis": e.coverage.map(|_| e.basis.label()),
            "reading": e.reading,
            "evidence": sources(e).map(|s| json!({ "label": s.label, "url": s.url })).collect::<Vec<_>>(),
            "note": e.implementation_note,
            "gap": e.enforcement.gap,
            "role": e.role,
            "roles": e.roles,
            "corpus": e.coverage.map(|_| corpus_json(e, corpus.get(e.id))),
        })
    })).collect();
    let corpora: Vec<_> = corpora().into_iter().map(|(file, bip_revision, bips, vectors)| {
        json!({ "file": format!("vectors/{file}.json"), "bip_revision": bip_revision, "bips": bips, "vectors": vectors })
    }).collect();
    json!({
        "title": specification.title,
        "status": specification.status,
        "revision": revision(),
        "corpora": corpora,
        "entries": entries,
    })
}

/// The version, status, corpus pins and changelog.
fn version_block(specification: &Specification) -> String {
    let pins: String = corpora().into_iter().map(|(file, bip_revision, bips, vectors)| format!(
        "<tr><td><a href=\"vectors/{file}.json\">{file}.json</a></td><td>{}</td><td>{}</td><td>{vectors}</td></tr>\n",
        if file == "bip376" {
            "none: generated locally by vectors/tools/gen_bip376.py; BIP376 publishes no test vectors".to_owned()
        } else {
            let repo = if file == "bip375" { "macgyver13/bips" } else { "bitcoin/bips" };
            format!("<a href=\"https://github.com/{repo}/tree/{bip_revision}\"><code>{bip_revision}</code></a>")
        },
        if bips.is_empty() { "set per vector".to_owned() } else { bips.iter().map(|b| format!("BIP{b}")).collect::<Vec<_>>().join(", ") }
    )).collect();
    let changes: String = CHANGELOG.iter().map(|(date, change)| format!("<li>{date}: {}</li>\n", esc(change))).collect();
    format!(
        "<h2 id=\"version\">Version</h2>\n<p><strong>Revision:</strong> {}. <strong>Status:</strong> {} From 1.0, rule IDs are append-only: never reused or redefined.</p>\n<p>Each corpus file pins the bitcoin/bips revision it was labeled against.</p>\n<div class=scroll><table class=pins><tr><th>Corpus</th><th>bips revision</th><th>BIPs</th><th>Vectors</th></tr>\n{pins}</table></div>\n<details><summary>Changelog</summary><ul>\n{changes}</ul></details>\n",
        esc(&revision()), esc(specification.status)
    )
}

/// How a project evaluates itself, and where cross-implementation results are.
fn evaluate_section() -> String {
    let base = esc(&source_base());
    // TODO: link bip375-interop-v2 once it has a public URL; its interop-v2
    // branch is not on github.com/macgyver13/bip375-interop.
    format!(
        "<h2 id=\"evaluate\">Evaluate your project</h2>\n\
<p>A project judges its own compliance by rule ID. <code>psbt-spec evaluate</code> puts every corpus vector to the project through an adapter and writes a report with one verdict per rule and operation. <code>psbt-spec attribute</code> reads a PSBT and the task that produced it, then lists the rules it fails.</p>\n\
<p>To run an evaluation, build <code>psbt-spec</code> from source and point it at your adapter and one or more corpus files:</p>\n\
<pre>git clone https://github.com/macgyver13/psbt-spec\n\
cd psbt-spec/rust\n\
cargo run --release --bin psbt-spec -- evaluate --out DIR \\\n\
\x20   --corpus ../vectors/bip174.json --corpus ../vectors/bip375.json \\\n\
\x20   -- ADAPTER [ARGS ...]</pre>\n\
<p>The report is written to <code>DIR/report.json</code> and <code>DIR/report.md</code>. Each row gives one verdict for a rule at one task:</p>\n\
<dl class=legend>\n\
<dt>MATCH</dt><dd>The project accepts and rejects what the rule does. A MATCH from a refusal that named no rule is marked unconfirmed.</dd>\n\
<dt>STRICTER</dt><dd>The project rejects something the rule accepts.</dd>\n\
<dt>LOOSER</dt><dd>The project accepts something the rule rejects, or has no check.</dd>\n\
<dt>NOT IMPLEMENTED</dt><dd>The project does not declare the task or BIP the vectors need.</dd>\n\
<dt>NOT RUN</dt><dd>No vector gave evidence: the corpus has none for the rule, or the project answered <code>n/a</code> or failed. NOT RUN is not a pass.</dd>\n\
</dl>\n\
<ul>\n\
<li><a href=\"docs/adapter.md\">Adapter contract</a>: the JSON lines an adapter reads and answers.</li>\n\
<li><a href=\"docs/report.md\">Report format</a>: verdicts and how they are decided.</li>\n\
<li><a href=\"docs/attribute.md\">The attribute command</a>: which rules a PSBT fails.</li>\n\
<li>Example adapters: <a href=\"{base}adapters/bip375-reference\">bip375-reference</a> (Python, 138 lines), <a href=\"{base}adapters/rust-psbt\">rust-psbt</a> (Rust, 325 lines) and <a href=\"{base}adapters/spdk\">spdk</a> (Rust, 265 lines). A minimal adapter is a loop of a few dozen lines; see the skeleton in the adapter contract.</li>\n\
</ul>\n\
<p>This page publishes no project's results. Cross-implementation results live in the interoperability harnesses: bip375-interop-v2 and <a href=\"https://github.com/GautamBytes/psbt-interop-lab\">psbt-interop-lab</a>.</p>\n\
<p id=\"vector-coverage\">Each rule's Check column shows its corpus coverage: the invalid vectors that isolate it, the valid vectors that pass it, and a status. <em>corpus</em>: a vector isolates the rule. <code>evaluate</code> judges projects on it. <em>tests only</em>: no vector isolates it yet; its check is observed failing only by the repository's tests. <em>none</em>: the rule has no check. Vectors are numbered from 0 within their file.</p>\n"
    )
}

/// A rule, definition or procedure as Markdown, under a heading at `level`.
fn markdown_entry(e: &Statement, level: usize, corpus: &BTreeMap<String, RuleCorpus>) -> String {
    let heading = "#".repeat(level);
    let title = match (e.id.is_empty(), e.strength) {
        (true, _) => e.topic.to_owned(),
        (false, Some(strength)) if e.basis != Basis::Direct => format!("{} ({}, {}) {}", e.id, strength.label(), e.basis.label(), e.topic),
        (false, Some(strength)) => format!("{} ({}) {}", e.id, strength.label(), e.topic),
        (false, None) => format!("{} {}", e.id, e.topic),
    };
    let mut md = format!("{heading} {}\n\n{}\n\n", title.trim_end(), e.text);
    if let Some(phase) = phase(e) {
        md += &format!("- Phase: {phase}\n");
    }
    let mut gates: Vec<&String> = Vec::new();
    for gate in e.implementations.iter().flat_map(|i| &i.gates) {
        if !gates.contains(&gate) { gates.push(gate); }
    }
    if !gates.is_empty() {
        md += &format!("- Applies when: {}\n", gates.iter().map(|g| g.as_str()).collect::<Vec<_>>().join("; "));
    }
    if let Some(coverage) = e.coverage {
        md += &format!("- Coverage: {}\n", coverage.label());
        let c = corpus.get(e.id);
        md += &format!("- Vectors: {}\n", corpus_status(e, c));
        if let Some(c) = c {
            for v in &c.isolating {
                md += &format!("  - isolates: vectors/{}.json #{}: {}\n", v.file, v.index, v.description);
            }
            for (file, indices) in grouped(&c.passing) {
                md += &format!("  - passes: vectors/{file}.json {}\n", indices.iter().map(|i| format!("#{i}")).collect::<Vec<_>>().join(" "));
            }
        }
    }
    if !e.roles.is_empty() {
        md += &format!("- Enforced by: {}\n", e.roles.join(", "));
    }
    if !e.reading.is_empty() {
        md += &format!("- Basis: {}. {}\n", e.basis.label(), e.reading);
    }
    if !e.evidence.label.is_empty() {
        md += &format!("- From: {}\n", sources(e).map(|s| if s.url.is_empty() {
            s.label.to_owned()
        } else {
            format!("[{}]({})", s.label, s.url)
        }).collect::<Vec<_>>().join(", "));
    }
    if !e.implementation_note.is_empty() {
        md += &format!("- Note: {}\n", e.implementation_note);
    }
    if !e.enforcement.gap.is_empty() {
        md += &format!("- Not decided: {}\n", e.enforcement.gap);
    }
    md + "\n"
}

/// Every entry as Markdown: General rules, each role, then Definitions,
/// Procedures and guidance tied to no role.
fn markdown(specification: &Specification, corpus: &BTreeMap<String, RuleCorpus>) -> String {
    let sections = |category: &'static str| specification.sections.iter().filter(move |s| s.category == category);
    let guidance: Vec<&Statement> = sections("guidance").flat_map(|s| &s.entries).collect();
    let general: Vec<&Statement> = sections("general").flat_map(|s| &s.entries).collect();
    let mut md = format!(
        "# {}\n\nStatus: {}\nRevision: {}\n\nGenerated from `rust/src/spec.rs`, like `spec.html` and `rules.json`. A PSBT is well formed if it satisfies the General rules. A role conforms if its rules hold on the PSBT it received and the PSBT it returned. Every role receives a PSBT that satisfies the General rules. Vector numbers count from 0 within each corpus file.\n\n## General rules\n\n",
        specification.title, specification.status, revision()
    );
    for s in sections("general") {
        md += &format!("### {}\n\n", s.title);
        for e in &s.entries {
            md += &markdown_entry(e, 4, corpus);
        }
    }
    for s in sections("role") {
        md += &format!("## {}\n\n", s.title);
        let owned: Vec<&str> = general.iter().filter(|g| g.roles.contains(&s.title)).map(|g| g.id).collect();
        if !owned.is_empty() {
            md += &format!("General rules this role must enforce: {}.\n\n", owned.join(", "));
        }
        for (label, wanted) in [("Precondition", Some("Precondition")), ("Not shown in the PSBT", None), ("Result", Some("Result"))] {
            let part: Vec<&Statement> = s.entries.iter().filter(|e| phase(e) == wanted).collect();
            if !part.is_empty() {
                md += &format!("### {label}\n\n");
                for e in part {
                    md += &markdown_entry(e, 4, corpus);
                }
            }
        }
        let advice: Vec<&&Statement> = guidance.iter().filter(|g| g.role == s.title).collect();
        if !advice.is_empty() {
            md += "### Guidance\n\n";
            for e in advice {
                md += &markdown_entry(e, 4, corpus);
            }
        }
    }
    let role_titles: Vec<&str> = sections("role").map(|s| s.title).collect();
    let unassigned: Vec<&&Statement> = guidance.iter().filter(|g| !role_titles.contains(&g.role)).collect();
    if !unassigned.is_empty() {
        md += "## Guidance\n\n";
        for e in unassigned {
            md += &markdown_entry(e, 3, corpus);
        }
    }
    for (category, title) in [("definition", "Definitions"), ("reference", "Procedures")] {
        md += &format!("## {title}\n\n");
        for e in sections(category).flat_map(|s| &s.entries) {
            md += &markdown_entry(e, 3, corpus);
        }
    }
    md.trim_end().to_owned() + "\n"
}

const SCRIPT: &str = r#"<script>
(() => {
  const strength = document.getElementById('filter-strength');
  const bip = document.getElementById('filter-bip');
  const text = document.getElementById('filter-text');
  const apply = () => {
    const words = text.value.toLowerCase();
    for (const row of document.querySelectorAll('tr[data-rule]')) {
      const show = (!strength.value || row.dataset.strength === strength.value)
        && (!bip.value || row.dataset.bips.split(' ').includes(bip.value))
        && (!words || row.textContent.toLowerCase().includes(words));
      row.hidden = !show;
    }
  };
  for (const control of [strength, bip, text]) control.addEventListener('input', apply);
})();
</script>"#;

/// Repository files the published site serves unchanged, by site path.
const SITE_FILES: &[(&str, &str)] = &[
    ("llms.txt", include_str!("../../../llms.txt")),
    ("PRINCIPLES.md", include_str!("../../../PRINCIPLES.md")),
    ("ROADMAP.md", include_str!("../../../ROADMAP.md")),
    ("docs/adapter.md", include_str!("../../../docs/adapter.md")),
    ("docs/adapter.schema.json", include_str!("../../../docs/adapter.schema.json")),
    ("docs/attribute.md", include_str!("../../../docs/attribute.md")),
    ("docs/attribute.schema.json", include_str!("../../../docs/attribute.schema.json")),
    ("docs/report.md", include_str!("../../../docs/report.md")),
    ("docs/report.schema.json", include_str!("../../../docs/report.schema.json")),
    ("docs/rules.md", include_str!("../../../docs/rules.md")),
    ("docs/rules.schema.json", include_str!("../../../docs/rules.schema.json")),
    ("docs/examples/adapter-session.jsonl", include_str!("../../../docs/examples/adapter-session.jsonl")),
    ("docs/examples/attribute-session.jsonl", include_str!("../../../docs/examples/attribute-session.jsonl")),
    ("docs/examples/report.json", include_str!("../../../docs/examples/report.json")),
    ("docs/examples/report.md", include_str!("../../../docs/examples/report.md")),
    ("vectors/corpus.schema.json", include_str!("../../../vectors/corpus.schema.json")),
];

/// Writes the static site to `dir`: the page as index.html (and spec.html,
/// the name llms.txt and the repository use), rules.json, rules.md, the
/// corpus files and SITE_FILES. Existing files are overwritten; files from an
/// earlier build that are no longer produced are left in place.
fn write_site(dir: &std::path::Path, page: &str, rules: &str, markdown: &str) -> std::io::Result<()> {
    let corpus = corpus::FILES.iter().map(|(name, text)| (format!("vectors/{name}.json"), *text));
    let generated = [("index.html", page), ("spec.html", page), ("rules.json", rules), ("rules.md", markdown)]
        .into_iter()
        .map(|(path, text)| (path.to_owned(), text));
    let fixed = SITE_FILES.iter().map(|(path, text)| ((*path).to_owned(), *text));
    for (path, text) in generated.chain(corpus).chain(fixed) {
        let target = dir.join(&path);
        std::fs::create_dir_all(target.parent().unwrap())?;
        std::fs::write(target, text)?;
    }
    Ok(())
}

fn main() {
    let specification = spec::specification();
    let corpus = corpus_coverage();
    let rules = format!("{}\n", serde_json::to_string_pretty(&rules_json(&specification, &corpus)).unwrap());
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--json") {
        print!("{rules}");
        return;
    }
    if args.iter().any(|arg| arg == "--markdown") {
        print!("{}", markdown(&specification, &corpus));
        return;
    }
    if let Some(at) = args.iter().position(|arg| arg == "--site") {
        let Some(dir) = args.get(at + 1) else {
            eprintln!("usage: render --site DIR");
            std::process::exit(2);
        };
        if source_base().is_empty() {
            eprintln!("--site needs PSBT_SPEC_SOURCE_BASE (a blob URL at the published commit, ending in /): the site has no rust/ or adapters/ directory");
            std::process::exit(2);
        }
        if let Err(e) = write_site(std::path::Path::new(dir), &page(&specification, &corpus), &rules, &markdown(&specification, &corpus)) {
            eprintln!("cannot write {dir}: {e}");
            std::process::exit(1);
        }
        return;
    }
    print!("{}", page(&specification, &corpus));
}

/// spec.html.
fn page(specification: &Specification, corpus: &BTreeMap<String, RuleCorpus>) -> String {
    let mut cited: Vec<String> = specification.sections.iter().flat_map(|s| &s.entries)
        .flat_map(|e| bips(e).split(' ').filter(|b| !b.is_empty()).map(str::to_owned).collect::<Vec<_>>())
        .collect();
    cited.sort_by_key(|b| b.parse::<u32>().unwrap());
    cited.dedup();
    let bip_options: String = cited.iter().map(|b| format!("<option value=\"{b}\">BIP{b}</option>")).collect();
    format!(
        r##"<!doctype html>
<html lang=en>
<head>
<meta charset=utf-8>
<meta name=viewport content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{ --bg: #fff; --fg: #1d1d1f; --muted: #6e6e73; --line: #d2d2d7; --band: #f5f5f7; --accent: #8a5a00; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg: #161617; --fg: #f5f5f7; --muted: #a1a1a6; --line: #3a3a3c; --band: #232325; --accent: #f0b450; }} }}
body {{ background: var(--bg); color: var(--fg); font: 15px/1.5 -apple-system, system-ui, sans-serif; max-width: 1100px; margin: 0 auto; padding: 0 16px 24px; }}
nav.toc {{ position: sticky; top: 0; background: var(--bg); border-bottom: 1px solid var(--line); padding: 8px 0; z-index: 1; display: flex; flex-wrap: wrap; gap: 4px 14px; font-size: 14px; }}
.filters {{ display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0; font-size: 14px; }}
.filters input, .filters select {{ font: inherit; color: inherit; background: var(--bg); border: 1px solid var(--line); border-radius: 4px; padding: 2px 6px; }}
table {{ border-collapse: collapse; width: 100%; margin: 12px 0 28px; }}
th, td {{ border-bottom: 1px solid var(--line); padding: 6px 8px; text-align: left; vertical-align: top; }}
tr.section td {{ font-weight: 600; background: var(--band); }}
tr.band td {{ font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }}
td.id {{ font-family: ui-monospace, monospace; white-space: nowrap; }}
.gate {{ color: var(--accent); font-weight: 600; }}
.strength, .phase, .coverage, .evidence {{ display: block; font: 12px/1.4 -apple-system, system-ui, sans-serif; color: var(--muted); }}
.strength, .phase {{ white-space: nowrap; }}
.basis {{ display: block; font: italic 12px/1.4 -apple-system, system-ui, sans-serif; color: var(--muted); }}
.reading {{ display: block; font: 13px/1.4 -apple-system, system-ui, sans-serif; margin-top: 4px; }}
.strip {{ font-size: 14px; }}
.count {{ color: var(--muted); }}
dl.legend {{ display: grid; grid-template-columns: max-content 1fr; gap: 2px 12px; font-size: 14px; }}
dl.legend dt {{ font-weight: 600; }}
dl.legend dd {{ margin: 0; }}
pre {{ overflow-x: auto; }}
.corpus {{ display: block; font: 12px/1.4 -apple-system, system-ui, sans-serif; color: var(--muted); margin-top: 4px; }}
details.corpus ul {{ margin: 2px 0; padding-left: 16px; }}
details.corpus p {{ margin: 2px 0; }}
code {{ font-size: 13px; }}
a {{ color: inherit; }}
a.field {{ text-decoration-style: dotted; }}
.scroll {{ overflow-x: auto; }}
</style>
</head>
<body>
<nav class=toc><a href="#version">Version</a><a href="#evaluate">Evaluate</a><a href="#general">General rules</a><a href="#roles">Role obligations</a><a href="#definitions">Definitions</a><a href="#procedures">Procedures</a><a href="#fields">Field registry</a></nav>
<h1>{title}</h1>
<p><strong>Status:</strong> {status}</p>
<p>Covers PSBT versions 0 and 2 (BIP174, BIP370) with the extensions of BIP371, BIP372 (Draft), BIP373, BIP353, BIP322, BIP375 and BIP376, as written at bitcoin/bips <a href="https://github.com/bitcoin/bips/tree/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793"><code>5aadddb</code></a>, except BIP375, which is pinned at <a href="https://github.com/bitcoin/bips/tree/9c5b825e4ba43fab0431fa042ddb00afdf251a95"><code>9c5b825e4b</code></a>. A PSBT is well formed if it satisfies the General rules. A role conforms if its rules hold on the PSBT it received and the PSBT it returned. Each statement keeps its BIP's MUST, SHOULD or MAY and links its source. A rule marked Derived or Resolution is the project's reading, not BIP wording, and says why.</p>
<p>Silent payments: BIP375 covers sending to a silent payment address with a PSBT, and BIP376 covers spending a silent payment output. Both build on <a href="https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0352.mediawiki">BIP352</a> (silent payments) and <a href="https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0374.mediawiki">BIP374</a> (DLEQ proofs); the silent payment terms are in <a href="#definitions">Definitions</a>.</p>
<dl class=legend>
<dt>Verified</dt><dd>The check found the property holds.</dd>
<dt>Failed</dt><dd>The check found it does not; the rule's ID is the error code.</dd>
<dt>NotApplicable</dt><dd>The statement does not apply to this PSBT.</dd>
<dt>Incomplete</dt><dd>The PSBT lacks the context to decide; this is not a pass.</dd>
<dt>Full</dt><dd>Coverage: the check decides the stated property whenever the PSBT carries the context it needs.</dd>
<dt>Partial</dt><dd>Coverage: it decides part of the property; the implementation note says what it leaves undecided.</dd>
<dt>Declared</dt><dd>Coverage: this reference cannot decide it. It needs cryptography the reference does not carry or behavior a PSBT does not show.</dd>
<dt>Pending</dt><dd>Coverage: there is no check yet.</dd>
<dt>Derived</dt><dd>Basis: the rule follows from BIP text but does not restate one sentence; it merges sentences, or reads a requirement from a field description or another BIP. An unmarked rule restates one BIP sentence.</dd>
<dt>Resolution</dt><dd>Basis: the BIP text is ambiguous or silent and the project decided. The reading gives the basis.</dd>
</dl>
<p><a href="{source}rust/src/spec.rs">Rust specification source</a> &middot; <a href="rules.json">rules.json</a> (<a href="docs/rules.md">schema</a>) &middot; <a href="rules.md">rules.md</a> &middot; <a href="llms.txt">llms.txt</a> &middot; <a href="PRINCIPLES.md">Principles</a> &middot; <a href="ROADMAP.md">Roadmap</a></p>
{version}{evaluate}{questions}{preamble}
<div class=filters><label>Strength <select id=filter-strength><option value="">All</option><option>MUST</option><option>MUST NOT</option><option>SHOULD</option><option>MAY</option></select></label><label>BIP <select id=filter-bip><option value="">All</option>{bip_options}</select></label><label>Search <input id=filter-text type=search></label></div>
{catalog}
<h2 id="fields">Field registry</h2>
<p>The source of truth for PSBT field type numbers and names is the BIP174 <a href="https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174/type-registry.mediawiki">type registry</a>. New fields must be added there, and each field's definition is in its BIP. These tables restate them only to show what this specification adds: the format constraints the validators enforce (collected across BIPs) and the version and replacement rules that extensions introduce. Where they differ, the upstream registry and BIPs govern.</p>
<p>Every listed field is checked whatever extensions the caller enables; enabling a BIP adds its semantic rules, not its field formats. Unlisted field types pass unchecked. Key data and value constraints are enforced by <a href="#GEN-F-5">GEN-F-5</a>. Under <a href="#GEN-ST-2">GEN-ST-2</a>, a version listed under <em>Required</em> or <em>Excluded</em> must include or must omit the field, unless a known field listed with it stands in its place. <em>Rules</em> lists the statements that name the field.</p>
{fields}{script}
</body>
</html>
"##,
        title = esc(specification.title),
        status = esc(specification.status),
        questions = open_questions(specification),
        preamble = preamble(specification),
        catalog = catalog(specification, corpus),
        version = version_block(specification),
        evaluate = evaluate_section(),
        fields = field_tables(specification),
        script = SCRIPT,
        source = esc(&source_base()),
    )
}
