//! psbt-spec adapter (docs/adapter.md) for spdk's `psbt` crate (BIP-375 roles on psbt-v2).
//!
//! Usage: psbt-spec-adapter-spdk --revision COMMIT [--psbt-v2-revision COMMIT] [--project-dir DIR]
//!
//! The mapping of each task to a library call is in README.md.

use std::io::{BufRead, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use psbt::extractor::{SpExtractorError, SpExtractorExt};
use psbt::signer::{SpSignerError, SpSignerExt};
use psbt_v2::bitcoin::base64::prelude::{Engine as _, BASE64_STANDARD};
use psbt_v2::bitcoin::secp256k1::Secp256k1;
use psbt_v2::{DeserializeError, Psbt, SilentPaymentSignerError};
use serde_json::{json, Value};

const PROTOCOL: &str = "psbt-spec.adapter/1";

/// Why an operation did not accept.
enum Stop {
    /// The project refused, with the reason it gave and, when the error means exactly one
    /// psbt-spec rule, that rule (see the mapping below).
    Refused(String, Option<&'static str>),
    /// The adapter cannot put this vector to the project.
    NotApplicable(&'static str),
}

fn refuse<E: std::fmt::Display>(what: &str, e: E) -> Stop {
    Stop::Refused(format!("{what}: {e}"), None)
}

fn refuse_as<E: std::fmt::Display>(what: &str, e: E, rule: Option<&'static str>) -> Stop {
    Stop::Refused(format!("{what}: {e}"), rule)
}

// The rule behind each refusal. This is the only place the adapter names a rule; README.md
// ("Rules named") tabulates it. A variant is mapped only when it means exactly that rule; a
// variant that is not listed names no rule.

fn decode_rule(e: &DeserializeError) -> Option<&'static str> {
    match e {
        DeserializeError::InvalidMagic(_) | DeserializeError::InvalidSeparator(_) => Some("GEN-F-1"),
        _ => map_decode_rule(e),
    }
}

/// The rule behind an error decoding the global, input or output maps.
///
/// psbt-v2 does not export its map error types (`map` is a private module), so the variant is
/// read from the error's Debug text: the first variant inside `DecodeGlobal(..)`, or inside
/// `Item(..)` for an input or output map.
fn map_decode_rule(e: &DeserializeError) -> Option<&'static str> {
    let debug = format!("{e:?}");
    let rest = debug
        .strip_prefix("DecodeGlobal(")
        .or_else(|| debug.strip_prefix("DecodeInputs(VecDecoderError(Item("))
        .or_else(|| debug.strip_prefix("DecodeOutputs(VecDecoderError(Item("))?;
    let ident = |s: &str| s.split(|c: char| !c.is_ascii_alphanumeric()).next().unwrap_or("").to_owned();
    let variant = ident(rest);
    let inner = ident(rest[variant.len()..].trim_start_matches(['(', ' ', '{']));
    match variant.as_str() {
        "DuplicateKey" => Some("GEN-F-4"),
        "KeyDecode" => match inner.as_str() {
            "Bytes" | "TypeValue" => Some("GEN-F-2"),
            "InvalidKeyData" => Some("GEN-F-5"),
            "ExcludedKey" => Some("GEN-ST-2"),
            _ => None,
        },
        "MissingVersion" | "MissingTxVersion" | "MissingInputCount" | "MissingOutputCount"
        | "MissingUnsignedTx" | "MissingPreviousTxid" | "MissingSpentOutputIndex"
        | "MissingAmount" | "MissingScriptPubkey" => Some("GEN-ST-2"),
        // The version a decoder for one PSBT version found; only a version other than 0 or 2
        // breaks a rule.
        "WrongVersion" => match inner.as_str() {
            "0" | "2" => None,
            _ => Some("GEN-ST-1"),
        },
        "SpFieldMismatch" => Some("GEN-SP-3"),
        "Validation" => (inner == "SpLabelWithoutInfo").then_some("GEN-SP-1"),
        // A value whose length prefix itself is malformed breaks the record, not the field.
        _ if rest.contains("LengthPrefix(") => Some("GEN-F-2"),
        "Version" if rest.contains("UnsupportedVersion") => Some("GEN-ST-1"),
        // A known field whose key data or value does not have the registry's format.
        "Version" | "Xpub" | "ModifiableFlags" | "Count" | "TxVersion" | "LockTime" | "UnsignedTx"
        | "InvalidHash" | "InvalidPublicKey" | "InvalidXOnlyPublicKey" | "PreviousTxid"
        | "OutputIndex" | "Sequence" | "MinTime" | "MinHeight" | "SighashType"
        | "TapInternalKey" | "TapMerkleRoot" | "NonWitnessUtxo" | "WitnessUtxo"
        | "FinalScriptWitness" | "RedeemScript" | "WitnessScript" | "FinalScriptSig"
        | "TapKeySig" | "PartialSig" | "Bip32Derivation" | "TapBip32Derivation"
        | "TapScriptSig" | "LeafScript" | "InvalidControlBlock" | "Amount" | "Script"
        | "TapTree" | "SpEcdh" | "SpDleq" | "SpTweak" | "SpV0Info" | "SpV0Label" =>
            Some("GEN-F-5"),
        // EarlyEnd, preimages, proprietary and unknown values, PorCommitment and
        // IncorrectNonWitnessUtxo name no rule.
        _ => None,
    }
}

/// psbt-v2's BIP-375 structure checks (spdk's `commit_sp_outputs` runs them first).
fn structure_rule(e: &SilentPaymentSignerError) -> Option<&'static str> {
    use SilentPaymentSignerError as E;
    match e {
        E::TransactionModifiable { .. } => Some("GEN-SP-2"),
        E::UnsupportedWitnessVersion { .. } | E::NonSighashAll { .. } => Some("GEN-SP-4"),
        E::RedeemScriptMismatch { .. } => Some("ROLE-S-2"),
        E::MissingEcdhShare { .. }
        | E::MismatchedShareAndProofKeys { .. }
        | E::MissingInputPublicKey { .. } => Some("GEN-SP-3"),
        // NoEligibleInputs: REF-9 has no "at least one eligible input" clause. FundingUtxo: no
        // rule covers a missing full previous transaction.
        _ => None,
    }
}

/// spdk's derivation. MissingInputPubkey is not mapped: spdk raises it while deriving, where the
/// missing key could equally be GEN-SP-5's "input public keys its derivation needs" (REF-10).
fn derive_rule(e: &SpSignerError) -> Option<&'static str> {
    match e {
        SpSignerError::MissingShare { .. } | SpSignerError::MissingDleqProof { .. } => {
            Some("GEN-SP-3")
        }
        _ => None,
    }
}

fn extract_rule(e: &SpExtractorError) -> Option<&'static str> {
    match e {
        SpExtractorError::OutputScriptMismatch { .. } => Some("GEN-SP-5"),
        SpExtractorError::Derive(e) => derive_rule(e),
        _ => None,
    }
}

/// Whether the PSBT carries any BIP-375 field.
fn has_silent_payment_fields(psbt: &Psbt) -> bool {
    !psbt.global.sp_ecdh_shares.is_empty()
        || !psbt.global.sp_dleq_proofs.is_empty()
        || psbt.inputs.iter().any(|i| !i.sp_ecdh_shares.is_empty() || !i.sp_dleq_proofs.is_empty())
        || psbt.outputs.iter().any(|o| o.sp_v0_info.is_some() || o.sp_v0_label.is_some())
}

/// Decodes a v2 PSBT. BIP-375 is compiled in and cannot be switched off, so a PSBT that carries
/// BIP-375 fields, in a request that does not enable BIP-375, is `n/a`.
fn decode(b64: &str, bip375: bool) -> Result<Psbt, Stop> {
    let bytes = BASE64_STANDARD.decode(b64).map_err(|e| refuse("base64", e))?;
    let psbt = Psbt::deserialize(&bytes).map_err(|e| refuse_as("decode", &e, decode_rule(&e)))?;
    if !bip375 && has_silent_payment_fields(&psbt) {
        return Err(Stop::NotApplicable(
            "BIP-375 is compiled in and cannot be disabled, so a PSBT with BIP-375 fields cannot be run as one without BIP-375",
        ));
    }
    Ok(psbt)
}

/// psbt-v2 decoding, then spdk's part of BIP-375, applied once every Silent Payment output has its
/// script (before that the PSBT is a valid work in progress):
/// - every input finalized: `verify_sp_output_scripts`, the check the Extractor runs;
/// - otherwise psbt-v2's BIP-375 structure checks (`silent_payment_signer_checks`, which spdk's
///   `commit_sp_outputs` runs first), then `derive_sp_output_scripts` compared with the scripts set.
fn deserialize(b64: &str, bip375: bool) -> Result<(), Stop> {
    let psbt = decode(b64, bip375)?;
    let secp = Secp256k1::new();
    let sp_outputs: Vec<_> = psbt.outputs.iter().filter(|o| o.sp_v0_info.is_some()).collect();
    if sp_outputs.is_empty() || sp_outputs.iter().any(|o| o.script_pubkey.is_empty()) {
        return Ok(());
    }
    if psbt.is_finalized() {
        return psbt.verify_sp_output_scripts(&secp)
            .map_err(|e| refuse_as("verify output scripts", &e, extract_rule(&e)));
    }
    psbt.silent_payment_signer_checks()
        .map_err(|e| refuse_as("silent payment signer checks", &e, structure_rule(&e)))?;
    let derived =
        psbt.derive_sp_output_scripts(&secp)
        .map_err(|e| refuse_as("derive output scripts", &e, derive_rule(&e)))?;
    for (index, script) in derived {
        if psbt.outputs[index].script_pubkey != script {
            return Err(Stop::Refused(
                format!("output {index}: script differs from the derived script"),
                Some("GEN-SP-5"),
            ));
        }
    }
    Ok(())
}

/// SpExtractorExt::extract_tx on the given (finalized) PSBT: verifies the Silent Payment output
/// scripts, then runs psbt-v2's Extractor.
fn extract(b64: &str, bip375: bool) -> Result<(), Stop> {
    let psbt = decode(b64, bip375)?;
    psbt.extract_tx(&Secp256k1::new()).map(|_| ()).map_err(|e| refuse_as("extract", &e, extract_rule(&e)))
}

fn answer(request: &Value) -> Value {
    let id = request["id"].clone();
    let task = request["task"].as_str().unwrap_or("");
    let psbt = request["psbt"].as_str().unwrap_or("");
    let bip375 = request["bips"].as_array().is_some_and(|a| a.iter().any(|b| b == 375));
    let run: fn(&str, bool) -> Result<(), Stop> = match task {
        "deserialize" => deserialize,
        "extract" => extract,
        _ => return json!({"id": id, "verdict": "error", "reason": format!("task {task} is not declared")}),
    };
    // A panic caused by the PSBT is a refusal by accident; the reason says so.
    match catch_unwind(AssertUnwindSafe(|| run(psbt, bip375))) {
        Ok(Ok(())) => json!({"id": id, "verdict": "accept"}),
        Ok(Err(Stop::Refused(reason, rule))) => {
            let mut r = json!({"id": id, "verdict": "reject", "reason": reason});
            if let Some(rule) = rule {
                r["rule"] = json!(rule);
            }
            r
        }
        Ok(Err(Stop::NotApplicable(reason))) => json!({"id": id, "verdict": "n/a", "reason": reason}),
        Err(_) => json!({"id": id, "verdict": "reject", "reason": "PANIC in the library"}),
    }
}

fn crate_version(dir: &PathBuf) -> String {
    std::fs::read_to_string(dir.join("psbt/Cargo.toml"))
        .ok()
        .and_then(|t| {
            t.lines().find_map(|l| {
                l.strip_prefix("version = \"").and_then(|v| v.strip_suffix('"')).map(String::from)
            })
        })
        .unwrap_or_else(|| "unknown".into())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1));
    let revision = flag("--revision").cloned().unwrap_or_else(|| {
        eprintln!("usage: psbt-spec-adapter-spdk --revision COMMIT [--psbt-v2-revision COMMIT] [--project-dir DIR]");
        std::process::exit(2)
    });
    let dir = flag("--project-dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spdk"));
    let mut version = format!("psbt {}", crate_version(&dir));
    if let Some(rev) = flag("--psbt-v2-revision") {
        version.push_str(&format!(" on psbt-v2 {rev}"));
    }
    let hello = json!({
        "protocol": PROTOCOL,
        "project": {"name": "spdk (psbt crate)", "version": version, "revision": revision},
        "adapter": {"name": "psbt-spec spdk adapter", "version": "0.1.0"},
        "tasks": ["deserialize", "extract"],
        "bips": [370, 375],
    });

    std::panic::set_hook(Box::new(|_| {}));
    let stdout = std::io::stdout();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let request: Value = serde_json::from_str(&line).expect("request is JSON");
        let mut response =
            if request["task"] == "hello" { hello.clone() } else { answer(&request) };
        response["id"] = request["id"].clone();
        let mut out = stdout.lock();
        writeln!(out, "{response}").unwrap();
        out.flush().unwrap();
    }
}
