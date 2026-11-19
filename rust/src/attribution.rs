//! Attribution requests (docs/attribute.md) and the classes `evaluate` and
//! `vectors` give a vector (docs/report.md). A request names a task and its
//! PSBTs; `attribute` runs the matching all-failures entry point and `classify`
//! splits the result into refusal and Result rules.

use std::collections::HashMap;
use std::sync::OnceLock;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;

use crate::{spec, Bip, Failures};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Task {
    Deserialize,
    Create,
    Construct,
    Update,
    Sign,
    Finalize,
    Extract,
    Combine,
}

impl Task {
    pub fn name(self) -> &'static str {
        match self {
            Task::Deserialize => "deserialize",
            Task::Create => "create",
            Task::Construct => "construct",
            Task::Update => "update",
            Task::Sign => "sign",
            Task::Finalize => "finalize",
            Task::Extract => "extract",
            Task::Combine => "combine",
        }
    }

    pub fn from_name(name: &str) -> Option<Task> {
        [Task::Deserialize, Task::Create, Task::Construct, Task::Update, Task::Sign, Task::Finalize, Task::Extract, Task::Combine]
            .into_iter()
            .find(|t| t.name() == name)
    }

    /// The task a corpus vector's `task` field names; absent means validity.
    pub fn from_corpus(name: Option<&str>) -> Option<Task> {
        Some(match name.unwrap_or("validity") {
            "validity" => Task::Deserialize,
            "signing" => Task::Sign,
            "finalizing" => Task::Finalize,
            "extraction" => Task::Extract,
            "combining" => Task::Combine,
            _ => return None,
        })
    }

    /// The tasks of a role section, as General rules name it in `roles`.
    pub fn of_role(role: &str) -> &'static [Task] {
        match role {
            "Creator and Constructor" => &[Task::Create, Task::Construct],
            "Updater" => &[Task::Update],
            "Signer" => &[Task::Sign],
            "Input Finalizer" => &[Task::Finalize],
            "Transaction Extractor" => &[Task::Extract],
            "Combiner" => &[Task::Combine],
            _ => &[],
        }
    }

    /// The task whose entry point evaluates a Role rule, from its ID.
    pub fn of_role_rule(id: &str) -> Option<Task> {
        Some(match id {
            "ROLE-C-1" | "ROLE-C-2" => Task::Create,
            "ROLE-C-3" | "ROLE-C-4" | "ROLE-C-5" | "ROLE-C-6" => Task::Construct,
            _ => match id.split('-').nth(1)? {
                "U" => Task::Update,
                "S" => Task::Sign,
                "F" => Task::Finalize,
                "X" => Task::Extract,
                "B" => Task::Combine,
                _ => return None,
            },
        })
    }
}

/// An attribution request: the PSBTs are raw bytes.
#[derive(Debug, Clone, Default)]
pub struct Request {
    pub bips: Vec<u64>,
    pub psbt: Option<Vec<u8>>,
    pub sources: Option<Vec<Vec<u8>>>,
    pub returned: Option<Vec<u8>>,
    pub delegates_additions: Option<bool>,
    pub intended_timelocks: Vec<(usize, bool)>,
}

/// The BIPs `attribute` accepts: 174 and 370 gate nothing, 372, 375 and 376
/// enable their rules, 322, 353, 371 and 373 are always checked.
pub fn enabled_bips(numbers: &[u64]) -> Result<Vec<Bip>, String> {
    let mut bips = Vec::new();
    for &n in numbers {
        match n {
            174 | 370 | 322 | 353 | 371 | 373 => {}
            372 => bips.push(Bip::Bip372),
            375 => bips.push(Bip::Bip375),
            376 => bips.push(Bip::Bip376),
            other => return Err(format!("unknown BIP {other}")),
        }
    }
    Ok(bips)
}

fn decode(value: &Value, field: &str) -> Result<Vec<u8>, String> {
    let s = value.as_str().ok_or_else(|| format!("{field} must be a string"))?;
    STANDARD.decode(s).map_err(|e| format!("{field} is not base64: {e}"))
}

/// Parses and validates a request object against the table in attribute.md:
/// required fields, and fields the task does not list are an error.
pub fn parse_request(value: &Value) -> Result<(Task, Request), String> {
    let object = value.as_object().ok_or("request must be a JSON object")?;
    let task = object.get("task").and_then(Value::as_str).ok_or("task is required")?;
    let task = match Task::from_name(task) {
        Some(t) if t != Task::Update => t,
        _ => return Err(format!("unknown task {task}")),
    };
    let (required, optional): (&[&str], &[&str]) = match task {
        Task::Deserialize | Task::Extract => (&["psbt"], &[]),
        Task::Sign | Task::Finalize => (&["psbt"], &["returned"]),
        Task::Create => (&["returned", "delegates_additions"], &[]),
        Task::Construct => (&["psbt", "returned"], &["intended_timelocks"]),
        Task::Combine => (&["sources", "returned"], &[]),
        Task::Update => unreachable!(),
    };
    for key in object.keys() {
        if !["id", "task", "bips"].contains(&key.as_str()) && !required.contains(&key.as_str()) && !optional.contains(&key.as_str()) {
            return Err(format!("{key} is not allowed for {}", task.name()));
        }
    }
    for key in required {
        if !object.contains_key(*key) {
            return Err(format!("{} needs {key}", task.name()));
        }
    }
    let numbers = object.get("bips").and_then(Value::as_array).filter(|a| !a.is_empty()).ok_or("bips is required and must not be empty")?;
    let bips = numbers.iter().map(|n| n.as_u64().filter(|&n| n >= 1).ok_or("bips must be positive integers")).collect::<Result<Vec<_>, _>>()?;
    let mut request = Request { bips, ..Request::default() };
    if let Some(v) = object.get("psbt") {
        request.psbt = Some(decode(v, "psbt")?);
    }
    if let Some(v) = object.get("returned") {
        request.returned = Some(decode(v, "returned")?);
    }
    if let Some(v) = object.get("sources") {
        let list = v.as_array().filter(|a| !a.is_empty()).ok_or("sources must be a non-empty array")?;
        request.sources = Some(list.iter().map(|s| decode(s, "sources")).collect::<Result<_, _>>()?);
    }
    if let Some(v) = object.get("delegates_additions") {
        request.delegates_additions = Some(v.as_bool().ok_or("delegates_additions must be a boolean")?);
    }
    if let Some(v) = object.get("intended_timelocks") {
        for item in v.as_array().ok_or("intended_timelocks must be an array")? {
            let input = item.get("input").and_then(Value::as_u64).ok_or("intended_timelocks input must be an integer")?;
            let requires = item.get("requires_locktime").and_then(Value::as_bool).ok_or("intended_timelocks requires_locktime must be a boolean")?;
            request.intended_timelocks.push((input as usize, requires));
        }
    }
    enabled_bips(&request.bips)?;
    Ok((task, request))
}

/// Every rule the request's PSBTs fail, by the entry point the task names. A
/// request `parse_request` accepted always has the fields its task needs.
pub fn attribute(task: Task, request: &Request) -> Failures {
    let bips = enabled_bips(&request.bips).expect("parse_request validated the BIPs");
    let psbt = request.psbt.as_deref();
    let returned = request.returned.as_deref();
    match task {
        Task::Deserialize => crate::failing_rules(psbt.unwrap(), &bips),
        Task::Create => crate::failing_rules_creating(returned.unwrap(), request.delegates_additions.unwrap(), &bips),
        Task::Construct => crate::failing_rules_constructing(psbt.unwrap(), returned.unwrap(), &request.intended_timelocks, &bips),
        Task::Sign => match returned {
            Some(returned) => crate::failing_rules_signing(psbt.unwrap(), returned, &bips),
            None => crate::failing_rules_before_signing(psbt.unwrap(), &bips),
        },
        Task::Finalize => match returned {
            Some(returned) => crate::failing_rules_finalizing(psbt.unwrap(), returned, &bips),
            None => crate::failing_rules_for_finalizing(psbt.unwrap(), &bips),
        },
        Task::Extract => crate::failing_rules_extracting(psbt.unwrap(), &bips),
        Task::Combine => {
            let sources: Vec<&[u8]> = request.sources.as_ref().unwrap().iter().map(Vec::as_slice).collect();
            crate::failing_rules_combining(&sources, returned.unwrap(), &bips)
        }
        Task::Update => unreachable!("parse_request rejects update"),
    }
}

/// What a rule is for classification: from `rules.json` (the specification).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleInfo {
    pub general: bool,
    /// Role rules: Precondition or Result; None for a rule that has no phase.
    pub phase: Option<&'static str>,
    /// The rule's check cannot decide it from a PSBT (coverage Declared).
    pub declared: bool,
    /// The URL of the rule's BIP evidence link, empty when it has none.
    pub evidence_url: &'static str,
    /// General rules: the roles whose BIP text assigns the rule's duty.
    pub roles: &'static [&'static str],
}

/// Every General and Role rule of the specification, in specification order.
pub fn rules() -> &'static [(&'static str, RuleInfo)] {
    static RULES: OnceLock<Vec<(&'static str, RuleInfo)>> = OnceLock::new();
    RULES.get_or_init(|| {
        let sections = spec::specification().sections;
        ["general", "role"]
            .into_iter()
            .flat_map(|category| {
                sections.iter().filter(move |s| s.category == category).flat_map(move |s| {
                    s.entries.iter().filter(|e| e.coverage.is_some()).map(move |e| {
                        let info = RuleInfo {
                            general: category == "general",
                            phase: e.implementations.first().and_then(|i| i.phase),
                            declared: e.coverage == Some(crate::catalog::Coverage::Declared),
                            evidence_url: e.evidence.url,
                            roles: e.roles,
                        };
                        (e.id, info)
                    })
                })
            })
            .collect()
    })
}

/// The same rules by ID.
pub fn rule_infos() -> &'static HashMap<&'static str, RuleInfo> {
    static INFOS: OnceLock<HashMap<&'static str, RuleInfo>> = OnceLock::new();
    INFOS.get_or_init(|| rules().iter().copied().collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Valid,
    Isolated,
    Confounded,
    Result,
    None,
    Undecided,
}

impl Class {
    pub fn name(self) -> &'static str {
        match self {
            Class::Valid => "valid",
            Class::Isolated => "isolated",
            Class::Confounded => "confounded",
            Class::Result => "result",
            Class::None => "none",
            Class::Undecided => "undecided",
        }
    }
}

/// A vector's attribution, split by what the role should have done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    pub class: Class,
    /// Rules a role must refuse the given PSBT for: General rules failing on a
    /// PSBT the role is given, and Preconditions.
    pub refusal: Vec<&'static str>,
    /// Result rules, and General rules failing only on the returned PSBT.
    pub result: Vec<&'static str>,
}

impl Classified {
    /// The rules a verdict on the vector lands on: the refusal rules, or the
    /// Result rules for a result vector.
    pub fn attributed(&self) -> &[&'static str] {
        if self.class == Class::Result { &self.result } else { &self.refusal }
    }
}

/// Splits `failures` (the attribution of `request`) into refusal
/// and Result rules and gives the vector its class (docs/report.md). Rules the
/// specification has no phase for count as refusal rules.
pub fn classify(request: &Request, valid: bool, failures: &Failures) -> Classified {
    let infos = rule_infos();
    // General rules that fail on a PSBT the role is given.
    let mut given_general: Vec<&'static str> = Vec::new();
    if request.returned.is_some() {
        let bips = enabled_bips(&request.bips).expect("parse_request validated the BIPs");
        let given: Vec<&[u8]> = request.psbt.iter().map(Vec::as_slice).chain(request.sources.iter().flatten().map(Vec::as_slice)).collect();
        for psbt in given {
            given_general.extend(crate::failing_rules(psbt, &bips).failed);
        }
    }
    let mut refusal = Vec::new();
    let mut result = Vec::new();
    for &id in &failures.failed {
        let info = infos.get(id);
        let is_result = match info {
            Some(i) if i.general => request.returned.is_some() && !given_general.contains(&id),
            Some(i) => i.phase == Some("Result"),
            None => false,
        };
        if is_result { result.push(id) } else { refusal.push(id) }
    }
    let class = if valid {
        Class::Valid
    } else if refusal.len() == 1 {
        Class::Isolated
    } else if refusal.len() > 1 {
        Class::Confounded
    } else if !result.is_empty() {
        Class::Result
    } else if failures.incomplete.is_empty() {
        Class::None
    } else {
        Class::Undecided
    };
    Classified { class, refusal, result }
}
