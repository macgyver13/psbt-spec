//! `evaluate`: put every corpus vector to an adapter, judge the answers by the
//! verdict rules of docs/report.md and build the report.

use std::collections::BTreeSet;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use psbt_spec::attribution::{attribute, classify, enabled_bips, rule_infos, rules, Class, Classified, Task};
use psbt_spec::corpus::{self, Vector};
use psbt_spec::Failures;
use serde_json::{json, Value};

use crate::adapter::{Adapter, Hello, Reply, PROTOCOL, TASKS};
use crate::pins::{self, Pins};

pub const FORMAT: &str = "psbt-spec.report/2";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    Match,
    Stricter,
    Looser,
    NotImplemented,
    NotRun,
}

impl Verdict {
    pub fn name(self) -> &'static str {
        match self {
            Verdict::Match => "MATCH",
            Verdict::Stricter => "STRICTER",
            Verdict::Looser => "LOOSER",
            Verdict::NotImplemented => "NOT IMPLEMENTED",
            Verdict::NotRun => "NOT RUN",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    Accept,
    Reject,
    NotApplicable,
    Error,
    Withheld,
}

impl Outcome {
    fn name(self) -> &'static str {
        match self {
            Outcome::Accept => "accept",
            Outcome::Reject => "reject",
            Outcome::NotApplicable => "n/a",
            Outcome::Error => "error",
            Outcome::Withheld => "withheld",
        }
    }
}

pub struct Corpus {
    /// The path as given.
    pub path: String,
    pub sha256: String,
    pub file: corpus::File,
}

struct Record<'a> {
    file: usize,
    reference: String,
    vector: &'a Vector,
    /// The task the vector is put to: its own, or for a stage request the
    /// task of a role that owns the General rule it isolates.
    task: Task,
    /// A stage request (docs/report.md), listed under its vector.
    stage: bool,
    failures: Failures,
    classified: Classified,
    outcome: Outcome,
    reason: Option<String>,
    named: Option<String>,
    error: Option<&'static str>,
    returned: Option<Failures>,
    evidence: Vec<(Option<String>, Verdict)>,
}

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn request_json(id: u64, task: Task, vector: &Vector) -> Value {
    let mut request = json!({"id": id, "task": task.name(), "bips": vector.bips});
    match &vector.request.sources {
        Some(sources) => request["sources"] = json!(sources.iter().map(|s| b64(s)).collect::<Vec<_>>()),
        None => request["psbt"] = json!(b64(vector.request.psbt.as_ref().unwrap())),
    }
    request
}

/// Why the adapter is not sent the vector under `task`, if it is not.
fn withheld(task: Task, vector: &Vector, declared: &Hello) -> Option<String> {
    if !declared.tasks.iter().any(|t| t == task.name()) {
        return Some(format!("task {} not declared", task.name()));
    }
    vector.bips.iter().find(|b| !declared.bips.contains(b)).map(|b| format!("BIP {b} not declared"))
}

/// The attribution of the PSBT the project returned, under the record's task.
fn attribute_returned(task: Task, vector: &Vector, returned: &[u8]) -> Failures {
    let mut request = vector.request.clone();
    request.returned = Some(returned.to_vec());
    attribute(task, &request)
}

/// The tasks of the roles whose BIP text assigns a General rule's duty, in
/// task order; empty for a rule with no `roles`.
fn owning_tasks(rule: &str) -> Vec<Task> {
    let Some(info) = rule_infos().get(rule).filter(|i| i.general) else { return vec![] };
    let mut tasks: Vec<Task> = info.roles.iter().flat_map(|r| Task::of_role(r).iter().copied()).collect();
    tasks.sort_unstable();
    tasks.dedup();
    tasks
}

/// Whether evidence on `rule` is judged at `task`. A General rule whose BIP
/// text assigns its duty to roles is not judged at `deserialize`: no BIP asks
/// a parser to refuse it, so a parser's answer is recorded as a note on the
/// owning roles' rows instead.
fn judged(rule: &str, task: Task) -> bool {
    task != Task::Deserialize || owning_tasks(rule).is_empty()
}

impl Record<'_> {
    /// The rule the project named for its refusal, when it is in `rules.json`.
    /// An unknown ID counts as no rule (docs/report.md).
    fn named_known(&self) -> Option<&str> {
        self.named.as_deref().filter(|n| rule_infos().contains_key(n))
    }

    /// The rule ID the project named that is not in `rules.json`, if any.
    fn named_unknown(&self) -> Option<&str> {
        self.named.as_deref().filter(|n| !rule_infos().contains_key(n))
    }

    /// A refusal of an isolated or confounded vector that names a rule in
    /// `rules.json` other than its refusal rules: the project refused for a
    /// property the vector does not isolate, so it gives no MATCH.
    fn named_other(&self) -> Option<&str> {
        let invalid = matches!(self.classified.class, Class::Isolated | Class::Confounded);
        self.named_known().filter(|n| self.outcome == Outcome::Reject && invalid && !self.classified.refusal.contains(n))
    }
}

fn evidence(r: &Record) -> Vec<(Option<String>, Verdict)> {
    let valid = r.vector.valid;
    let each = |rules: &[&str], verdict| rules.iter().map(|id| (Some(id.to_string()), verdict)).collect::<Vec<_>>();
    let attributed: Vec<&str> = r.classified.attributed().iter().copied().filter(|id| judged(id, r.task)).collect();
    let attributed = attributed.as_slice();
    match r.outcome {
        Outcome::Withheld => if valid { vec![] } else { each(attributed, Verdict::NotImplemented) },
        Outcome::NotApplicable | Outcome::Error => if valid { vec![] } else { each(attributed, Verdict::NotRun) },
        Outcome::Reject => match r.classified.class {
            Class::Valid | Class::Result => vec![(r.named_known().map(str::to_owned), Verdict::Stricter)],
            // A refusal for another rule did not test this one, as for n/a.
            Class::Isolated if r.named_other().is_some() => each(attributed, Verdict::NotRun),
            Class::Isolated => each(attributed, Verdict::Match),
            // A confounded vector gives evidence only on the failing rule the
            // project names; attribution confirms that rule fails.
            Class::Confounded => match r.named_known() {
                Some(named) if attributed.contains(&named) => each(&[named], Verdict::Match),
                _ => vec![],
            },
            Class::None | Class::Undecided => vec![],
        },
        Outcome::Accept => match r.classified.class {
            Class::Valid => match &r.returned {
                Some(returned) => each(&returned.failed, Verdict::Looser),
                None if r.task == Task::Sign => {
                    let signer_results: Vec<&str> = rules()
                        .iter()
                        .filter(|(id, info)| Task::of_role_rule(id) == Some(Task::Sign) && info.phase == Some("Result"))
                        .map(|(id, _)| *id)
                        .collect();
                    each(&signer_results, Verdict::NotRun)
                }
                None => vec![],
            },
            Class::Isolated | Class::Confounded => each(attributed, Verdict::Looser),
            Class::Result => match &r.returned {
                Some(returned) if returned.failed.is_empty() => each(attributed, Verdict::Match),
                Some(returned) => each(&returned.failed, Verdict::Looser),
                None => vec![],
            },
            Class::None | Class::Undecided => vec![],
        },
    }
}

/// The tasks a rule's rows always appear under: `deserialize` for a General
/// rule with no `roles`, its owning roles' tasks for one with `roles`, and
/// the task of its role for a Role rule.
fn native_tasks(id: &str, general: bool) -> Vec<Task> {
    match (general, owning_tasks(id)) {
        (true, owning) if owning.is_empty() => vec![Task::Deserialize],
        (true, owning) => owning,
        (false, _) => vec![Task::of_role_rule(id).expect("Role rule ID names a role")],
    }
}

#[derive(Default)]
struct Row {
    evidence: Vec<(usize, Verdict)>,
    notes: Vec<String>,
}

/// The `stale` entries for a row: evidence links into a BIP the evidence
/// vectors exercise, at a bips commit other than the corpus's `bip_revision`.
fn stale(rule: &str, vectors: &BTreeSet<usize>, records: &[Record], corpora: &[Corpus]) -> Vec<Value> {
    let Some(info) = rule_infos().get(rule) else { return vec![] };
    let url = info.evidence_url;
    let (Some(blob), Some(bip)) = (url.split("/blob/").nth(1), url.split("/bip-").nth(1)) else { return vec![] };
    let commit = blob.split('/').next().unwrap_or_default();
    let Ok(bip) = bip.chars().take_while(char::is_ascii_digit).collect::<String>().parse::<u64>() else { return vec![] };
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for &i in vectors {
        let record = &records[i];
        let corpus = &corpora[record.file];
        let differs = !(commit.starts_with(&corpus.file.bip_revision) || corpus.file.bip_revision.starts_with(commit));
        if record.vector.bips.contains(&bip) && differs && seen.insert(record.file) {
            out.push(json!({"bip": bip, "evidence": commit, "corpus": corpus.file.bip_revision, "file": corpus.path}));
        }
    }
    out
}

fn timestamp(time: std::time::SystemTime) -> String {
    let secs = time.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64;
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Runs the evaluation and returns the report (report.schema.json).
pub fn run(corpora: &[Corpus], argv: &[String], timeout: Duration, pins: &Pins) -> Result<Value, String> {
    let started = timestamp(std::time::SystemTime::now());
    let (mut adapter, declared) = Adapter::start(argv, timeout)?;

    // Attribution comes before any adapter call. An invalid `deserialize`
    // vector that isolates a General rule with `roles` is also put to each
    // owning role's task in the contract, as a stage request, when it
    // isolates the same rule there; otherwise the owning row gets a note.
    let mut records: Vec<Record> = Vec::new();
    // Stage requests not sent, by (rule, task, why): their vector refs.
    let mut skipped: std::collections::BTreeMap<(String, Task, String), Vec<String>> = Default::default();
    for (file, corpus) in corpora.iter().enumerate() {
        for vector in &corpus.file.vectors {
            let reference = format!("{}#{}", corpus.path, vector.index);
            let failures = attribute(vector.task, &vector.request);
            let classified = classify(&vector.request, vector.valid, &failures);
            let isolated = (vector.task == Task::Deserialize && classified.class == Class::Isolated).then(|| classified.refusal[0]);
            let record = |task, stage, failures, classified| Record {
                file,
                reference: reference.clone(),
                vector,
                task,
                stage,
                failures,
                classified,
                outcome: Outcome::Withheld,
                reason: None,
                named: None,
                error: None,
                returned: None,
                evidence: vec![],
            };
            records.push(record(vector.task, false, failures, classified));
            let Some(rule) = isolated else { continue };
            for task in owning_tasks(rule).into_iter().filter(|t| TASKS.contains(&t.name())) {
                let failures = attribute(task, &vector.request);
                let classified = classify(&vector.request, false, &failures);
                // The entry points stop at a General failure, so the role's own
                // rules are checked apart: a Precondition failing there would be
                // a reason of its own to refuse.
                let bips = enabled_bips(&vector.request.bips).expect("corpus BIPs are known");
                let own = psbt_spec::failing_role_rules_ungated(task, vector.request.psbt.as_deref().unwrap(), &bips).failed;
                if classified.class == Class::Isolated && classified.refusal == [rule] && own.is_empty() {
                    records.push(record(task, true, failures, classified));
                } else {
                    let others: Vec<&str> = classified.refusal.iter().chain(&own).copied().filter(|r| *r != rule).collect();
                    let why = if others.is_empty() { "fails no refusal rule there".to_owned() } else { format!("also fails {} there", others.join(", ")) };
                    skipped.entry((rule.to_owned(), task, why)).or_default().push(reference.clone());
                }
            }
        }
    }

    let mut next_id = 1;
    let mut broken = false;
    for r in records.iter_mut() {
        if let Some(why) = withheld(r.task, r.vector, &declared) {
            r.reason = Some(why);
            continue;
        }
        if broken {
            (r.outcome, r.error, r.reason) = (Outcome::Error, Some("crashed"), Some("adapter could not be restarted".into()));
            continue;
        }
        let request = request_json(next_id, r.task, r.vector);
        next_id += 1;
        match adapter.ask(&request) {
            Ok(answer) => {
                r.reason = answer.reason;
                match answer.reply {
                    Reply::Accept { psbt } => {
                        r.outcome = Outcome::Accept;
                        if matches!(r.classified.class, Class::Valid | Class::Result) {
                            r.returned = psbt.map(|p| attribute_returned(r.task, r.vector, &p));
                        }
                    }
                    Reply::Reject { rule } => (r.outcome, r.named) = (Outcome::Reject, rule),
                    Reply::NotApplicable => r.outcome = Outcome::NotApplicable,
                    Reply::AdapterError => (r.outcome, r.error) = (Outcome::Error, Some("adapter")),
                }
            }
            Err((failure, reason)) => {
                (r.outcome, r.error, r.reason) = (Outcome::Error, Some(failure.name()), Some(reason));
                broken = !matches!(adapter.restart(), Ok(hello) if hello == declared);
            }
        }
    }
    adapter.finish();
    for r in records.iter_mut() {
        r.evidence = evidence(r);
    }

    // Rows: every General rule under deserialize, every Role rule under its
    // task, other (rule, task) pairs that evidence names, unattributed rows.
    let mut rows: std::collections::BTreeMap<(Option<String>, Task), Row> = Default::default();
    for ((rule, task, why), refs) in skipped {
        let text = format!("not put to {} (stage request), as each {why}: {}", task.name(), refs.join(", "));
        rows.entry((Some(rule), task)).or_default().notes.push(text);
    }
    // Parser answers on rules a parser is not judged on, by rule: the note
    // goes on each owning role's row.
    let mut informational: std::collections::BTreeMap<&str, Vec<(Outcome, &str)>> = Default::default();
    // MATCH evidence from refusals that named no rule (or an unknown one), by row.
    let mut unconfirmed: std::collections::BTreeMap<(Option<String>, Task), Vec<&str>> = Default::default();
    for (i, r) in records.iter().enumerate() {
        let task = r.task;
        if !r.vector.valid && matches!(r.outcome, Outcome::Accept | Outcome::Reject) {
            for rule in r.classified.attributed().iter().filter(|id| !judged(id, task)) {
                informational.entry(rule).or_default().push((r.outcome, &r.reference));
            }
        }
        for (rule, verdict) in &r.evidence {
            rows.entry((rule.clone(), task)).or_default().evidence.push((i, *verdict));
        }
        let mut note = |rule: &str, text: String| rows.entry((Some(rule.to_owned()), task)).or_default().notes.push(text);
        if r.outcome == Outcome::Reject && r.classified.class == Class::Confounded {
            let named = r.named_known().map(|n| format!(" naming {n}")).unwrap_or_default();
            for rule in r.classified.refusal.iter().filter(|id| judged(id, task) && r.named_known() != Some(**id)) {
                note(rule, format!("confounded vector {} rejected{named} (no evidence)", r.reference));
            }
        }
        if let Some(other) = r.named_other() {
            if r.classified.class == Class::Isolated {
                for rule in r.classified.refusal.iter().filter(|id| judged(id, task)) {
                    note(rule, format!("{} rejected naming {other}, not this rule (NOT RUN)", r.reference));
                }
            }
            let fails = r.classified.refusal.join(", ");
            note(other, format!("{}: project names {other} on rejecting it, but attribution finds {fails} failing there, not {other} (no evidence)", r.reference));
        }
        if !r.failures.incomplete.is_empty() && !r.vector.valid {
            for rule in r.classified.attributed().iter().filter(|id| judged(id, task)) {
                note(rule, format!("{} also incomplete on {}", r.reference, r.failures.incomplete.join(", ")));
            }
        }
        if let Some(unknown) = r.named_unknown() {
            for (rule, _) in &r.evidence {
                let text = format!("{}: project names {unknown}, not in rules.json (treated as no rule)", r.reference);
                rows.entry((rule.clone(), task)).or_default().notes.push(text);
            }
        }
        if r.outcome == Outcome::Reject && r.named_known().is_none() {
            for (rule, _) in r.evidence.iter().filter(|(_, v)| *v == Verdict::Match) {
                unconfirmed.entry((rule.clone(), task)).or_default().push(&r.reference);
            }
        }
        if r.outcome == Outcome::Reject {
            let reason = r.reason.as_deref().unwrap_or_default();
            for (rule, _) in r.evidence.iter().filter(|(_, v)| *v == Verdict::Stricter) {
                let said = if reason.is_empty() { String::new() } else { format!(" says \"{reason}\"") };
                let text = format!("{}: project{said}", r.reference);
                rows.entry((rule.clone(), task)).or_default().notes.push(text);
            }
        }
    }
    for (key, refs) in unconfirmed {
        let text = format!("unconfirmed MATCH (project named no rule in rules.json): {}", refs.join(", "));
        rows.entry(key).or_default().notes.push(text);
    }

    for (rule, answers) in &informational {
        let mut groups: Vec<(Outcome, Vec<&str>)> = Vec::new();
        for (outcome, reference) in answers {
            match groups.iter_mut().find(|(o, _)| o == outcome) {
                Some((_, list)) => list.push(reference),
                None => groups.push((*outcome, vec![reference])),
            }
        }
        let said = groups.iter().map(|(o, l)| format!("{} {}", if *o == Outcome::Accept { "accepted" } else { "rejected" }, l.join(", "))).collect::<Vec<_>>().join("; ");
        let roles = rule_infos()[rule].roles.join(", ");
        for task in owning_tasks(rule) {
            let text = format!("deserialize (informational, the BIP assigns this duty to {roles}): {said}");
            rows.entry((Some(rule.to_string()), task)).or_default().notes.push(text);
        }
    }

    let mut order: Vec<(Option<String>, Task)> = Vec::new();
    for (id, info) in rules() {
        let native = native_tasks(id, info.general);
        order.extend(native.iter().map(|t| (Some(id.to_string()), *t)));
        order.extend(rows.keys().filter(|(rule, task)| rule.as_deref() == Some(*id) && !native.contains(task)).cloned());
    }
    order.extend(rows.keys().filter(|(rule, _)| rule.is_none()).cloned());
    order.dedup();

    let in_contract = |t: Task| TASKS.contains(&t.name());
    let task_declared = |t: Task| declared.tasks.iter().any(|d| d == t.name());
    let mut row_values = Vec::new();
    let mut counts = [0usize; 5];
    for key in &order {
        let (rule, task) = (key.0.as_deref(), key.1);
        let row = rows.remove(key).unwrap_or_default();
        let has = |v: Verdict| row.evidence.iter().any(|(_, e)| *e == v);
        let mut task_note = None;
        let verdicts: Vec<Verdict> = if has(Verdict::Looser) || has(Verdict::Stricter) {
            [Verdict::Looser, Verdict::Stricter].into_iter().filter(|v| has(*v)).collect()
        } else if !in_contract(task) {
            task_note = Some(format!("adapter contract v1 has no {} task", task.name()));
            vec![Verdict::NotRun]
        } else if !task_declared(task) {
            task_note = Some(format!("adapter does not declare {}", task.name()));
            vec![Verdict::NotImplemented]
        } else if has(Verdict::Match) {
            vec![Verdict::Match]
        } else if has(Verdict::NotImplemented) {
            vec![Verdict::NotImplemented]
        } else {
            vec![Verdict::NotRun]
        };
        for v in &verdicts {
            counts[*v as usize] += 1;
        }
        let vectors: BTreeSet<usize> = row.evidence.iter().map(|(i, _)| *i).collect();
        let mut bips: Vec<u64> = vectors.iter().flat_map(|&i| records[i].vector.bips.iter().copied()).collect();
        bips.sort_unstable();
        bips.dedup();
        let mut notes: Vec<String> = task_note.into_iter().collect();
        if row.evidence.is_empty() && notes.is_empty() && row.notes.is_empty() {
            notes.push("no vector".into());
        }
        if rule.is_some_and(|r| rule_infos()[r].declared) {
            notes.push("coverage Declared: needs evidence outside the PSBT".into());
        }
        notes.extend(row.notes.iter().cloned());
        let mut value = json!({
            "rule": rule,
            "task": task.name(),
            "verdicts": verdicts.iter().map(|v| v.name()).collect::<Vec<_>>(),
            "bips": bips,
            "evidence": row.evidence.iter().map(|(i, v)| json!({"vector": records[*i].reference, "verdict": v.name()})).collect::<Vec<_>>(),
            "stale": rule.map(|r| stale(r, &vectors, &records, corpora)).unwrap_or_default(),
        });
        if !notes.is_empty() {
            value["notes"] = json!(notes.join("; "));
        }
        row_values.push(value);
    }

    let count = |stage: bool, o: Outcome| records.iter().filter(|r| r.stage == stage && r.outcome == o).count();
    let counts_of = |stage: bool| json!({
        "total": records.iter().filter(|r| r.stage == stage).count(),
        "withheld": count(stage, Outcome::Withheld),
        "not_run": count(stage, Outcome::NotApplicable) + count(stage, Outcome::Error),
        "accepted": count(stage, Outcome::Accept),
        "rejected": count(stage, Outcome::Reject),
    });
    let sent_valid: Vec<&Record> = records.iter().filter(|r| !r.stage && r.vector.valid && r.outcome != Outcome::Withheld).collect();
    let passed = sent_valid
        .iter()
        .filter(|r| r.outcome == Outcome::Accept && !r.evidence.iter().any(|(_, v)| *v == Verdict::Looser))
        .count();
    // Refusals, stage requests included, by whether the rule the project named
    // confirms their MATCH evidence.
    let gave_match = |r: &Record| r.outcome == Outcome::Reject && r.evidence.iter().any(|(_, v)| *v == Verdict::Match);
    let rejects = |pick: &dyn Fn(&Record) -> bool| records.iter().filter(|r| r.outcome == Outcome::Reject && pick(r)).count();
    let refs = |pick: &dyn Fn(&Record) -> bool| records.iter().filter(|r| !r.stage && pick(r)).map(|r| r.reference.clone()).collect::<Vec<_>>();
    // A record's attribution, answer and evidence; a vector adds its own
    // fields and its stage requests.
    let answer = |r: &Record| {
        let mut v = json!({
            "task": r.task.name(),
            "failed": r.failures.failed,
            "incomplete": r.failures.incomplete,
            "class": r.classified.class.name(),
            "outcome": r.outcome.name(),
            "evidence": r.evidence.iter().map(|(rule, verdict)| json!({"rule": rule, "verdict": verdict.name()})).collect::<Vec<_>>(),
        });
        if let Some(reason) = &r.reason {
            v["reason"] = json!(reason);
        }
        if let Some(rule) = &r.named {
            v["rule"] = json!(rule);
        }
        if let Some(kind) = r.error {
            v["error"] = json!(kind);
        }
        if let Some(returned) = &r.returned {
            v["returned"] = json!({"failed": returned.failed, "incomplete": returned.incomplete});
        }
        v
    };
    let mut vector_values: Vec<Value> = Vec::new();
    for r in &records {
        if r.stage {
            let last = vector_values.last_mut().expect("a stage request follows its vector");
            last.as_object_mut().unwrap().entry("stages").or_insert(json!([])).as_array_mut().unwrap().push(answer(r));
            continue;
        }
        let mut v = json!({
            "ref": r.reference,
            "description": r.vector.description,
            "valid": r.vector.valid,
            "bips": r.vector.bips,
        });
        if let Some(note) = &r.vector.note {
            v["note"] = json!(note);
        }
        v.as_object_mut().unwrap().extend(answer(r).as_object().unwrap().clone());
        vector_values.push(v);
    }

    Ok(json!({
        "format": FORMAT,
        "spec": {"revision": pins.revision, "dirty": pins.dirty, "status": pins.status},
        "project": {"name": declared.project[0], "version": declared.project[1], "revision": declared.project[2]},
        "adapter": {"name": declared.adapter[0], "version": declared.adapter[1], "protocol": PROTOCOL},
        "declared": {"tasks": declared.tasks, "bips": declared.bips},
        "corpus": corpora.iter().map(|c| json!({
            "file": c.path, "sha256": c.sha256, "bip_revision": c.file.bip_revision, "vectors": c.file.vectors.len(),
        })).collect::<Vec<_>>(),
        "started": started,
        "finished": timestamp(std::time::SystemTime::now()),
        "summary": {
            "vectors": counts_of(false),
            "stages": counts_of(true),
            "valid": {"total": sent_valid.len(), "passed": passed},
            "rows": {
                "MATCH": counts[Verdict::Match as usize],
                "STRICTER": counts[Verdict::Stricter as usize],
                "LOOSER": counts[Verdict::Looser as usize],
                "NOT IMPLEMENTED": counts[Verdict::NotImplemented as usize],
                "NOT RUN": counts[Verdict::NotRun as usize],
            },
            "rejects": {
                "confirmed": rejects(&|r| gave_match(r) && r.named_known().is_some()),
                "unconfirmed": rejects(&|r| gave_match(r) && r.named_known().is_none()),
                "other_rule": rejects(&|r| r.named_other().is_some()),
                "unknown_rule": rejects(&|r| r.named_unknown().is_some()),
            },
            "confounded": refs(&|r| r.outcome == Outcome::Reject && r.classified.class == Class::Confounded),
            "triage": refs(&|r| matches!(r.classified.class, Class::None | Class::Undecided)),
        },
        "rows": row_values,
        "vectors": vector_values,
    }))
}

/// Reads and pins one corpus file.
pub fn load(path: &str) -> Result<Corpus, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let text = String::from_utf8(bytes.clone()).map_err(|e| format!("{path}: {e}"))?;
    let file = corpus::parse(&text).map_err(|e| format!("{path}: {e}"))?;
    Ok(Corpus { path: path.to_owned(), sha256: pins::sha256_hex(&bytes), file })
}
