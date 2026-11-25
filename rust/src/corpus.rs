//! Corpus files (vectors/corpus.schema.json) as the evaluator reads them: each
//! vector becomes an attribution request under its task.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;

use crate::attribution::{classify, Class, Request, Task};
use crate::{encoding, Failures};

/// The corpus files that follow the schema, by name, with their contents.
pub const FILES: [(&str, &str); 6] = [
    ("bip174", include_str!("../../vectors/bip174.json")),
    ("bip370", include_str!("../../vectors/bip370.json")),
    ("bip371", include_str!("../../vectors/bip371.json")),
    ("bip373", include_str!("../../vectors/bip373.json")),
    ("bip375", include_str!("../../vectors/bip375.json")),
    ("bip376", include_str!("../../vectors/bip376.json")),
];

pub struct File {
    pub bip_revision: String,
    /// The file-level `bips`.
    pub bips: Vec<u64>,
    pub vectors: Vec<Vector>,
}

pub struct Vector {
    pub index: usize,
    pub description: String,
    pub task: Task,
    pub valid: bool,
    /// The labeled rule (invalid vectors).
    pub rule: Option<String>,
    /// `incomplete` when the label is an Incomplete rule.
    pub incomplete_label: bool,
    pub note: Option<String>,
    /// Request BIPs: the PSBT version (174 or 370), the file's `bips` and the
    /// vector's own, ascending.
    pub bips: Vec<u64>,
    /// The attribution request for this vector's task.
    pub request: Request,
}

/// 370 when the PSBT has PSBT_GLOBAL_VERSION 2, otherwise 174 (version 0, no
/// version field, or bytes that cannot be read that far).
pub fn version_bip(psbt: &[u8]) -> u64 {
    let version = encoding::scan(psbt).ok().and_then(|p| {
        p.maps.first()?.iter().find(|r| r.key_type == 0xfb && r.key_data.is_empty()).and_then(|r| {
            <[u8; 4]>::try_from(r.value.as_slice()).ok().map(u32::from_le_bytes)
        })
    });
    if version == Some(2) { 370 } else { 174 }
}

fn decode(value: &Value) -> Result<Vec<u8>, String> {
    STANDARD.decode(value.as_str().ok_or("not a string")?).map_err(|e| e.to_string())
}

/// Reads a corpus file. Fails on a missing required key or an unreadable
/// PSBT; schema conformance beyond that is `tests/corpus.rs`.
pub fn parse(text: &str) -> Result<File, String> {
    let file: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let bip_revision = file["bip_revision"].as_str().ok_or("bip_revision is required")?.to_owned();
    let bips = file["bips"].as_array().ok_or("bips is required")?.iter().map(|b| b.as_u64().ok_or("bips must be integers")).collect::<Result<Vec<_>, _>>()?;
    let mut vectors = Vec::new();
    for (index, v) in file["vectors"].as_array().ok_or("vectors is required")?.iter().enumerate() {
        let at = |e: String| format!("vector {index}: {e}");
        let task = Task::from_corpus(v["task"].as_str()).ok_or_else(|| at("unknown task".into()))?;
        let psbt = decode(&v["psbt"]).map_err(|e| at(format!("psbt: {e}")))?;
        let mut request = Request::default();
        let first = if task == Task::Combine {
            let sources = v["combine"].as_array().ok_or_else(|| at("combining needs combine".into()))?;
            let sources: Vec<Vec<u8>> = sources.iter().map(decode).collect::<Result<_, _>>().map_err(|e| at(format!("combine: {e}")))?;
            let first = sources.first().cloned().ok_or_else(|| at("combine is empty".into()))?;
            request.sources = Some(sources);
            request.returned = Some(psbt);
            first
        } else {
            request.psbt = Some(psbt.clone());
            psbt
        };
        let mut bips_list: Vec<u64> = bips.clone();
        bips_list.extend(v["bips"].as_array().into_iter().flatten().filter_map(Value::as_u64));
        bips_list.push(version_bip(&first));
        bips_list.sort_unstable();
        bips_list.dedup();
        request.bips = bips_list.clone();
        vectors.push(Vector {
            index,
            description: v["description"].as_str().unwrap_or_default().to_owned(),
            task,
            valid: v["valid"].as_bool().ok_or_else(|| at("valid is required".into()))?,
            rule: v["rule"].as_str().map(str::to_owned),
            incomplete_label: v["outcome"].as_str() == Some("incomplete"),
            note: v["note"].as_str().map(str::to_owned),
            bips: bips_list,
            request,
        });
    }
    Ok(File { bip_revision, bips, vectors })
}

/// Whether invalid vector `v`, whose attribution is `failures`, isolates its
/// rule: it is the only refusal rule, or the only Result rule of a result
/// vector, or the only Incomplete rule of an `outcome: "incomplete"` vector.
pub fn isolates(v: &Vector, failures: &Failures) -> bool {
    let Some(rule) = v.rule.as_deref() else { return false };
    if v.incomplete_label {
        return failures.failed.is_empty() && failures.incomplete == [rule];
    }
    let classified = classify(&v.request, false, failures);
    matches!(classified.class, Class::Isolated | Class::Result) && classified.attributed() == [rule]
}
