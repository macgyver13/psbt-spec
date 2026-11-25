use std::{fs, path::Path, process::Command};

use psbt_spec::spec;

fn render_with(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_render"))
        .args(args)
        .env_remove("PSBT_SPEC_SOURCE_BASE")
        .env_remove("PSBT_SPEC_REVISION")
        .output()
        .expect("run render");
    assert!(
        output.status.success(),
        "render failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("render emits UTF-8")
}

fn render() -> String {
    render_with(&[])
}

/// The row for `anchor`, from its opening tag to its closing tag.
fn row<'a>(html: &'a str, anchor: &str) -> &'a str {
    let start = html.find(&format!("<tr id=\"{anchor}\"")).unwrap_or_else(|| panic!("no row for {anchor}"));
    let end = html[start..].find("</tr>").unwrap() + start;
    &html[start..end]
}

// Decode text independently of the renderer's HTML escaping and layout.
fn text(html: &str) -> String {
    let mut in_tag = false;
    html.chars()
        .filter(|&ch| match ch {
            '<' => {
                in_tag = true;
                false
            }
            '>' => {
                in_tag = false;
                false
            }
            _ => !in_tag,
        })
        .collect::<String>()
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

#[test]
fn rendered_catalog_matches_rust_statements() {
    let html = render();
    let specification = spec::specification();
    for statement in &specification.preamble {
        assert!(html.contains(&format!("<div id=\"context-{}\">", statement.sheet_row)), "preamble {}", statement.topic);
    }
    let mut count = specification.preamble.len();
    for section in &specification.sections {
        for statement in &section.entries {
            count += 1;
            let anchor = if statement.id.is_empty() {
                let slug: String = statement.topic.chars()
                    .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
                    .collect();
                format!("term-{slug}")
            } else {
                statement.id.to_owned()
            };
            assert_eq!(html.matches(&format!("<tr id=\"{anchor}\"")).count(), 1, "one row for {anchor}");
            let row = row(&html, &anchor);
            assert_eq!(row.matches("<td").count(), 3, "three columns for {anchor}");
            let wording = row.split_once("<span class=statement-text>").expect("statement text").1;
            let wording = &wording[..wording.find("</span><").unwrap_or(wording.len())];
            assert_eq!(text(wording), statement.text, "wording for {anchor}");
            let rendered = text(row);
            assert!(rendered.contains(statement.evidence.label), "evidence for {anchor}");
            for also in statement.also {
                assert!(row.contains(&format!("\">{}</a>", also.label)), "cited source {} for {anchor}", also.label);
            }
            assert_eq!(statement.reading.is_empty(), statement.basis == psbt_spec::spec::Basis::Direct, "a reading exactly when not direct, for {anchor}");
            assert_eq!(row.contains("<span class=basis>"), statement.basis != psbt_spec::spec::Basis::Direct, "basis tag for {anchor}");
            assert!(statement.reading.is_empty() || rendered.contains("Reading: "), "reading for {anchor}");
            assert_eq!(
                row.contains("<summary>Implementation note</summary>"),
                !statement.implementation_note.is_empty() || !statement.enforcement.gap.is_empty(),
                "implementation note visibility for {anchor}"
            );
            if let Some(strength) = statement.strength {
                assert!(row.contains(&format!("<span class=strength>{}</span>", strength.label())), "strength for {anchor}");
            }
            match (statement.coverage, statement.implementations.is_empty()) {
                (Some(coverage), false) => assert!(row.contains(&format!("<span class=coverage>{}</span>", coverage.label())), "coverage for {anchor}"),
                (Some(coverage), true) => assert!(row.contains(&format!("<td class=validation>{}<", coverage.label())), "coverage for {anchor}"),
                (None, _) => assert!(row.contains("<td class=validation>-</td>"), "no check for {anchor}"),
            }
            for implementation in &statement.implementations {
                let (module, function) = implementation.func
                    .strip_prefix("crate::rules::")
                    .expect("fully qualified rule identity")
                    .split_once("::")
                    .expect("module and function");
                let label = format!("<code>{function}</code></a>");
                let link = row.split("<a href=\"").find(|link| link.contains(&label)).expect("linked validation function");
                let (file, line) = link.split_once('"').unwrap().0.strip_prefix("rust/").unwrap().split_once("#L").unwrap();
                assert_eq!(file, format!("src/rules/{module}.rs"), "implementation file for {anchor}");
                let source = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(file)).unwrap();
                let declaration = source.lines().nth(line.parse::<usize>().unwrap() - 1).unwrap();
                assert!(declaration.trim_start().starts_with(&format!("pub fn {function}(")), "link for {anchor}");
                for gate in &implementation.gates {
                    assert!(rendered.contains(gate.as_str()), "condition for {anchor}: {gate}");
                }
            }
        }
    }
    assert_eq!(html.matches("<span class=statement-text>").count(), count, "every statement rendered once");
    for section in specification.sections.iter().filter(|s| s.category == "role") {
        let slug: String = section.title.chars()
            .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
            .collect();
        assert!(html.contains(&format!("<tr class=section id=\"role-{slug}\">")), "role section {}", section.title);
    }
    assert_eq!(html.contains("<h2 id=\"questions\">Open questions</h2>"), !specification.open_questions.is_empty());
    for question in specification.open_questions {
        assert!(html.contains(&format!("<strong>{}.</strong>", question.topic)), "open question {}", question.topic);
    }
    for internal_label in ["Recorded review:", "Related legacy checks", "Migration record", "Historical import provenance"] {
        assert!(!html.contains(internal_label), "internal commentary: {internal_label}");
    }
}

#[test]
fn field_registry_rows_and_cross_links() {
    let html = render();
    assert_eq!(html.matches("<table class=fields>").count(), 3);
    for field in psbt_spec::registry::FIELDS {
        assert_eq!(html.matches(&format!("<tr id=\"field-{}\">", field.name)).count(), 1, "{}", field.name);
    }
    // A rule naming a field links to its row, and the row links back.
    let rule = row(&html, "GEN-SP-1");
    assert!(rule.contains("<a class=field href=\"#field-PSBT_OUT_SP_V0_LABEL\">"));
    assert!(row(&html, "field-PSBT_OUT_SP_V0_LABEL").contains("<a href=\"#GEN-SP-1\">GEN-SP-1</a>"));
}

#[test]
fn checked_in_spec_is_current() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec.html");
    let checked_in = fs::read_to_string(path).expect("read checked-in spec.html");
    assert!(
        checked_in == render(),
        "spec.html is stale; regenerate with: cd rust && cargo run --bin render > ../spec.html"
    );
}

#[test]
fn checked_in_rules_json_is_current() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../rules.json");
    let checked_in = fs::read_to_string(path).expect("read checked-in rules.json");
    assert!(
        checked_in == render_with(&["--json"]),
        "rules.json is stale; regenerate with: cd rust && cargo run --bin render -- --json > ../rules.json"
    );
}

#[test]
fn checked_in_rules_md_is_current() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../rules.md");
    let checked_in = fs::read_to_string(path).expect("read checked-in rules.md");
    assert!(
        checked_in == render_with(&["--markdown"]),
        "rules.md is stale; regenerate with: cd rust && cargo run --bin render -- --markdown > ../rules.md"
    );
}

/// Every rule, procedure and guidance entry is anchored at its ID, every
/// anchor is unique, and every in-page link resolves.
#[test]
fn anchors_are_unique_and_in_page_links_resolve() {
    let html = render();
    let ids: Vec<&str> = html.split(" id=\"").skip(1).map(|rest| &rest[..rest.find('"').unwrap()]).collect();
    let unique: std::collections::BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(unique.len(), ids.len(), "duplicate anchors");
    for statement in spec::specification().sections.iter().flat_map(|s| &s.entries).filter(|e| !e.id.is_empty()) {
        assert!(unique.contains(statement.id), "no anchor for {}", statement.id);
    }
    for link in html.split("href=\"#").skip(1) {
        let target = &link[..link.find('"').unwrap()];
        assert!(unique.contains(target), "link to missing anchor #{target}");
    }
}

/// Every rule shows its corpus status; one isolated by a vector and one only
/// the repository tests fail.
#[test]
fn rules_show_corpus_coverage() {
    let html = render();
    for statement in spec::specification().sections.iter().flat_map(|s| &s.entries).filter(|e| e.coverage.is_some()) {
        assert!(row(&html, statement.id).contains("Vectors: "), "corpus status for {}", statement.id);
    }
    assert!(row(&html, "GEN-SP-1").contains("<summary>Vectors: corpus, "));
    assert!(row(&html, "GEN-F-2").contains("Vectors: tests only"));
}

/// Whether `value` matches the schema node `node` (type, enum, required keys,
/// no extra keys, items), resolving local `$ref`s against `root`. A hand-written
/// subset of JSON Schema, enough for docs/rules.schema.json.
fn matches_schema(value: &serde_json::Value, node: &serde_json::Value, root: &serde_json::Value, at: &str, problems: &mut Vec<String>) {
    use serde_json::Value;
    if let Some(reference) = node.get("$ref").and_then(Value::as_str) {
        let name = reference.strip_prefix("#/$defs/").expect("local ref");
        return matches_schema(value, &root["$defs"][name], root, at, problems);
    }
    if let Some(options) = node.get("enum").and_then(Value::as_array) {
        if !options.contains(value) {
            problems.push(format!("{at}: {value} not in enum"));
        }
        return;
    }
    let types: Vec<&str> = match &node["type"] {
        Value::Array(types) => types.iter().map(|t| t.as_str().unwrap()).collect(),
        Value::String(t) => vec![t.as_str()],
        _ => return,
    };
    let kind = match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_u64() || n.is_i64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    };
    if !types.contains(&kind) {
        problems.push(format!("{at}: {kind}, expected {types:?}"));
        return;
    }
    match value {
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                matches_schema(item, &node["items"], root, &format!("{at}[{i}]"), problems);
            }
        }
        Value::Object(object) => {
            for key in node["required"].as_array().into_iter().flatten() {
                if !object.contains_key(key.as_str().unwrap()) {
                    problems.push(format!("{at}: missing {key}"));
                }
            }
            for (key, item) in object {
                match node["properties"].get(key) {
                    Some(property) => matches_schema(item, property, root, &format!("{at}.{key}"), problems),
                    None => problems.push(format!("{at}: unknown key {key}")),
                }
            }
        }
        _ => {}
    }
}

#[test]
fn rules_json_follows_its_schema() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let schema: serde_json::Value = serde_json::from_str(&fs::read_to_string(root.join("docs/rules.schema.json")).unwrap()).unwrap();
    let rules: serde_json::Value = serde_json::from_str(&render_with(&["--json"])).unwrap();
    let mut problems = Vec::new();
    matches_schema(&rules, &schema, &schema, "rules.json", &mut problems);
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Every relative link in llms.txt names a file in the repository.
#[test]
fn llms_txt_links_exist() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let text = fs::read_to_string(root.join("llms.txt")).unwrap();
    for link in text.split("](").skip(1) {
        let target = &link[..link.find(')').unwrap()];
        assert!(target.contains("://") || root.join(target).exists(), "llms.txt links missing {target}");
    }
}

/// The relative links in a site file: `href` values in HTML, `](...)` targets
/// in Markdown and llms.txt. Absolute URLs and in-page anchors are skipped.
fn relative_links(path: &Path, text: &str) -> Vec<String> {
    let (open, close) = match path.extension().and_then(|e| e.to_str()) {
        Some("html") => ("href=\"", '"'),
        Some("md" | "txt") => ("](", ')'),
        _ => return Vec::new(),
    };
    text.split(open).skip(1)
        .map(|rest| rest[..rest.find(close).unwrap()].to_owned())
        .filter(|link| !link.contains("://") && !link.starts_with('#') && !link.starts_with("mailto:"))
        .collect()
}

/// `render --site` writes the published files, and every relative link in
/// them resolves to a file in the site.
#[test]
fn site_links_resolve() {
    let site = Path::new(env!("CARGO_TARGET_TMPDIR")).join("site");
    let output = Command::new(env!("CARGO_BIN_EXE_render"))
        .args(["--site", site.to_str().unwrap()])
        .env("PSBT_SPEC_SOURCE_BASE", "https://github.com/macgyver13/psbt-spec/blob/0000000/")
        .env_remove("PSBT_SPEC_REVISION")
        .output()
        .expect("run render --site");
    assert!(output.status.success(), "render --site failed: {}", String::from_utf8_lossy(&output.stderr));
    for required in ["index.html", "spec.html", "rules.json", "rules.md", "llms.txt", "docs/rules.schema.json", "vectors/corpus.schema.json", "vectors/bip375.json"] {
        assert!(site.join(required).is_file(), "site is missing {required}");
    }
    assert_eq!(fs::read_to_string(site.join("rules.json")).unwrap(), render_with(&["--json"]));
    let mut pending = vec![site.clone()];
    let mut problems = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let Ok(text) = fs::read_to_string(&path) else { continue };
            for link in relative_links(&path, &text) {
                let file = link.split('#').next().unwrap();
                if !path.parent().unwrap().join(file).exists() {
                    problems.push(format!("{}: {link}", path.strip_prefix(&site).unwrap().display()));
                }
            }
        }
    }
    assert!(problems.is_empty(), "unresolved site links:\n{}", problems.join("\n"));
}

#[test]
fn site_needs_a_source_base() {
    let output = Command::new(env!("CARGO_BIN_EXE_render"))
        .args(["--site", Path::new(env!("CARGO_TARGET_TMPDIR")).join("site-without-base").to_str().unwrap()])
        .env_remove("PSBT_SPEC_SOURCE_BASE")
        .output()
        .expect("run render --site");
    assert!(!output.status.success());
}
