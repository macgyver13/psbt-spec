//! psbt-spec adapter (docs/adapter.md) for rust-psbt (crate `psbt-v2`).
//!
//! Usage: psbt-spec-adapter-rust-psbt --revision COMMIT [--project-dir DIR]
//!
//! The mapping of each task to a library call is in README.md.

use std::io::{BufRead, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use psbt_v2::bitcoin::base64::prelude::{Engine as _, BASE64_STANDARD};
use psbt_v2::bitcoin::secp256k1::Secp256k1;
use psbt_v2::{
    DeserializeError, Extractor, Finalizer, ParsePsbtError, Psbt, PsbtV0, SignError, Signer, SilentPaymentSignerError,
};
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

type Outcome = Result<Option<String>, Stop>;

fn refuse<E: std::fmt::Display>(what: &str, e: E) -> Stop {
    Stop::Refused(format!("{what}: {e}"), None)
}

fn refuse_as<E: std::fmt::Display>(what: &str, e: E, rule: Option<&'static str>) -> Stop {
    Stop::Refused(format!("{what}: {e}"), rule)
}

// The rule behind each refusal. This is the only place the adapter names a rule; README.md
// ("Rules named") tabulates it. A variant is mapped only when it means exactly that rule; a
// variant that is not listed names no rule.

fn decode_rule(e: &ParsePsbtError) -> Option<&'static str> {
    match e {
        ParsePsbtError::PsbtEncoding(
            DeserializeError::InvalidMagic(_) | DeserializeError::InvalidSeparator(_),
        ) => Some("GEN-F-1"),
        ParsePsbtError::PsbtEncoding(e) => map_decode_rule(e),
        _ => None,
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

fn signer_check_rule(e: &SilentPaymentSignerError) -> Option<&'static str> {
    use SilentPaymentSignerError as E;
    match e {
        E::TransactionModifiable { .. } => Some("GEN-SP-2"),
        E::UnsupportedWitnessVersion { .. } | E::NonSighashAll { .. } => Some("GEN-SP-4"),
        E::RedeemScriptMismatch { .. } => Some("ROLE-S-2"),
        E::MissingEcdhShare { .. }
        | E::MismatchedShareAndProofKeys { .. }
        | E::MissingInputPublicKey { .. } => Some("GEN-SP-3"),
        // NoEligibleInputs: REF-9 has no "at least one eligible input" clause; REF-8 has one only
        // for a global share. FundingUtxo: no rule covers a missing full previous transaction.
        _ => None,
    }
}

fn sign_rule(e: &SignError) -> Option<&'static str> {
    match e {
        SignError::SilentPayment(e) => signer_check_rule(e),
        SignError::NonWitnessUtxoTxidMismatch => Some("ROLE-S-1"),
        SignError::RedeemScriptMismatch => Some("ROLE-S-2"),
        SignError::WitnessScriptMismatchWsh | SignError::WitnessScriptMismatchShWsh =>
            Some("ROLE-S-3"),
        SignError::NonWitnessSig => Some("ROLE-S-4"),
        // SilentPaymentIncomplete and "output scripts not yet set": the Signer cannot sign yet.
        // That is not GEN-SP-7, which forbids a signature already present while a script is
        // missing; the check looks at the scripts only.
        _ => None,
    }
}

/// The one rule every per-input error names, or none when they differ or any names none.
fn common_rule(errors: &std::collections::BTreeMap<usize, SignError>) -> Option<&'static str> {
    let mut rules = errors.values().map(sign_rule);
    let first = rules.next()??;
    rules.all(|r| r == Some(first)).then_some(first)
}

/// What the request says about the PSBT: its version, and whether BIP-375 is enabled.
#[derive(Clone, Copy)]
struct Ctx {
    v2: bool,
    bip375: bool,
}

/// Whether the PSBT carries any BIP-375 field.
fn has_silent_payment_fields(psbt: &Psbt) -> bool {
    !psbt.global.sp_ecdh_shares.is_empty()
        || !psbt.global.sp_dleq_proofs.is_empty()
        || psbt.inputs.iter().any(|i| !i.sp_ecdh_shares.is_empty() || !i.sp_dleq_proofs.is_empty())
        || psbt.outputs.iter().any(|o| o.sp_v0_info.is_some() || o.sp_v0_label.is_some())
}

/// Decodes a PSBT: v2 when the request lists BIP-370, otherwise v0.
///
/// BIP-375 is a compile-time feature of this build and cannot be switched off. A PSBT that carries
/// BIP-375 fields, in a request that does not enable BIP-375, cannot be put to the project as the
/// vector means it, so it is `n/a`.
fn decode(b64: &str, ctx: Ctx) -> Result<Psbt, Stop> {
    let psbt = if ctx.v2 {
        b64.parse::<Psbt>().map_err(|e| refuse_as("decode", &e, decode_rule(&e)))?
    } else {
        PsbtV0::deserialize_base64(b64)
            .map(PsbtV0::into_psbt)
            .map_err(|e| refuse_as("decode", &e, decode_rule(&e)))?
    };
    if !ctx.bip375 && has_silent_payment_fields(&psbt) {
        return Err(Stop::NotApplicable(
            "BIP-375 is compiled in and cannot be disabled, so a PSBT with BIP-375 fields cannot be run as one without BIP-375",
        ));
    }
    Ok(psbt)
}

/// Encodes a returned PSBT in the version it was given in.
fn encode(psbt: Psbt, ctx: Ctx) -> Result<String, Stop> {
    if ctx.v2 {
        Ok(BASE64_STANDARD.encode(psbt.serialize()))
    } else {
        PsbtV0::from_psbt(psbt).map(|p| p.serialize_base64()).map_err(|e| refuse("encode v0", e))
    }
}

fn deserialize(b64: &str, ctx: Ctx) -> Outcome {
    decode(b64, ctx)?;
    Ok(None)
}

/// Would the project sign: the Signer's strict checks for every input, then the BIP-375
/// Signer checks. No keys are involved.
fn sign(b64: &str, ctx: Ctx) -> Outcome {
    let psbt = decode(b64, ctx)?;
    let state = psbt
        .silent_payment_signer_checks()
        .map_err(|e| refuse_as("silent payment signer checks", &e, signer_check_rule(&e)))?;
    if !state.can_sign() {
        return Err(Stop::Refused("silent payment output scripts are not yet set".into(), None));
    }
    let mut signer = Signer::new(psbt).map_err(|e| refuse("signer", e))?;
    signer.session(|session| {
        session
            .signable_inputs()
            .map(|_| ())
            .map_err(|errors| {
                refuse_as("signable inputs", format!("{errors:?}"), common_rule(&errors))
            })
    })?;
    Ok(None)
}

fn finalize(b64: &str, ctx: Ctx) -> Outcome {
    let psbt = decode(b64, ctx)?;
    let finalizer = Finalizer::new(psbt).map_err(|e| refuse("finalizer", e))?;
    let finalized =
        finalizer.finalize(&Secp256k1::verification_only()).map_err(|e| refuse("finalize", e))?;
    encode(finalized, ctx).map(Some)
}

fn extract(b64: &str, ctx: Ctx) -> Outcome {
    let psbt = decode(b64, ctx)?;
    let extractor = Extractor::new(psbt).map_err(|e| refuse("extractor", e))?;
    extractor.extract_tx();
    Ok(None)
}

fn combine(sources: &[String], ctx: Ctx) -> Outcome {
    let mut sources = sources.iter();
    let first = sources.next().ok_or_else(|| Stop::Refused("no sources".into(), None))?;
    let mut combined = decode(first, ctx)?;
    for source in sources {
        combined = combined.combine_with(decode(source, ctx)?).map_err(|e| refuse("combine", e))?;
    }
    encode(combined, ctx).map(Some)
}

fn answer(request: &Value) -> Value {
    let id = request["id"].clone();
    let task = request["task"].as_str().unwrap_or("");
    let bips: Vec<u64> = request["bips"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_u64).collect())
        .unwrap_or_default();
    let ctx = Ctx { v2: bips.contains(&370), bip375: bips.contains(&375) };
    let psbt = request["psbt"].as_str().unwrap_or("");
    let sources: Vec<String> = request["sources"]
        .as_array()
        .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let run = || -> Outcome {
        match task {
            "deserialize" => deserialize(psbt, ctx),
            "sign" => sign(psbt, ctx),
            "finalize" => finalize(psbt, ctx),
            "extract" => extract(psbt, ctx),
            "combine" => combine(&sources, ctx),
            other => Err(Stop::Refused(format!("task {other} is not declared"), None)),
        }
    };
    if !["deserialize", "sign", "finalize", "extract", "combine"].contains(&task) {
        return json!({"id": id, "verdict": "error", "reason": format!("task {task} is not declared")});
    }
    // A panic caused by the PSBT is a refusal by accident; the reason says so.
    match catch_unwind(AssertUnwindSafe(run)) {
        Ok(Ok(Some(psbt))) => json!({"id": id, "verdict": "accept", "psbt": psbt}),
        Ok(Ok(None)) => json!({"id": id, "verdict": "accept"}),
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
    std::fs::read_to_string(dir.join("Cargo.toml"))
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
        eprintln!("usage: psbt-spec-adapter-rust-psbt --revision COMMIT [--project-dir DIR]");
        std::process::exit(2)
    });
    let dir = flag("--project-dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../rust-psbt"));
    // BIP-373 is not declared: the crate's "Supported BIPs" table does not list it and the
    // MuSig2 map fields are not parsed in this line of the crate.
    let hello = json!({
        "protocol": PROTOCOL,
        "project": {"name": "rust-psbt (psbt-v2)", "version": crate_version(&dir), "revision": revision},
        "adapter": {"name": "psbt-spec rust-psbt adapter", "version": "0.1.0"},
        "tasks": ["deserialize", "sign", "finalize", "extract", "combine"],
        "bips": [174, 370, 371, 375],
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
