//! Validation rules for BIP-353 DNS payment instruction proofs.

use crate::algebra::CheckOutcome;
use crate::context::OutputContext;
use crate::signature::{verify_dnssec_proof, Validity};

pub const OUT_DNSSEC_PROOF: u64 = 0x35;

/// GEN-DNS-1: When PSBT_OUT_DNSSEC_PROOF is present, the field value MUST begin with
/// a 1-byte length prefix specifying the ASCII human-readable name length.
pub fn validate_dnssec_proof_structure(output: &OutputContext) -> CheckOutcome {
    let Some(val) = output.value(OUT_DNSSEC_PROOF) else {
        return CheckOutcome::NotApplicable;
    };

    if val.is_empty() {
        return CheckOutcome::Failed(format!("output {} DNSSEC proof field is empty", output.index));
    }

    let name_len = val[0] as usize;
    if val.len() < 1 + name_len {
        return CheckOutcome::Failed(format!(
            "output {} DNSSEC name length {name_len} exceeds field length {}",
            output.index,
            val.len()
        ));
    }

    let Ok(name_str) = std::str::from_utf8(&val[1..1 + name_len]) else {
        return CheckOutcome::Failed(format!(
            "output {} DNSSEC human-readable name is not valid UTF-8/ASCII",
            output.index
        ));
    };

    if !name_str.contains('@') {
        return CheckOutcome::Failed(format!(
            "output {} DNSSEC human-readable name '{name_str}' is missing '@' domain separator",
            output.index
        ));
    }

    CheckOutcome::Verified
}

/// One output's proof as a Signer validates it: the verification time (Unix
/// seconds), if the caller supplies one, and whether the caller's use case has a
/// delay between PSBT construction and signing that permits an expiry up to an
/// hour in the past.
#[derive(Clone)]
pub struct DnssecProofContext {
    pub output: OutputContext,
    pub time: Option<u64>,
    pub allow_construction_delay: bool,
}

/// ROLE-S-6: A Signer that validates a PSBT_OUT_DNSSEC_PROOF MUST validate the DNSSEC
/// chain from the root to the name's TXT records, with each RRSIG's inception no
/// later than the current time and its expiry no earlier than it (or up to an hour
/// earlier when a construction delay is likely), ignore TXT records not beginning
/// with "bitcoin:", and refuse the proof if more than one does.
pub fn validate_dnssec_proof_validation(context: &DnssecProofContext) -> CheckOutcome {
    let output = &context.output;
    let Some(value) = output.value(OUT_DNSSEC_PROOF) else {
        return CheckOutcome::NotApplicable;
    };
    let Some(time) = context.time else {
        return CheckOutcome::Incomplete(format!("output {}: validating its DNSSEC proof needs the current time", output.index));
    };
    let name_len = value[0] as usize;
    let name = String::from_utf8_lossy(&value[1..1 + name_len]);
    let Some((user, domain)) = name.split_once('@') else {
        return CheckOutcome::Failed(format!("output {}: '{name}' is not user@domain", output.index));
    };
    let label = format!("{user}.user._bitcoin-payment.{domain}.");
    let allowance = if context.allow_construction_delay { 3600 } else { 0 };
    let (validity, txts) = verify_dnssec_proof(&label, &value[1 + name_len..], time, allowance);
    if validity != Validity::Valid {
        return CheckOutcome::Failed(format!("output {}: DNSSEC proof for {name} does not validate at time {time}", output.index));
    }
    let payment = txts.iter().filter(|t| t.len() >= 8 && t[..8].eq_ignore_ascii_case(b"bitcoin:")).count();
    match payment {
        1 => CheckOutcome::Verified,
        0 => CheckOutcome::Failed(format!("output {}: the proof has no bitcoin: TXT record for {name}", output.index)),
        n => CheckOutcome::Failed(format!("output {}: the proof has {n} bitcoin: TXT records for {name}", output.index)),
    }
}
