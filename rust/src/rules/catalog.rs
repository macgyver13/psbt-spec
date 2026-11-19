//! Compound bindings used by the new specification graph.
//! These reuse existing checks; documented enforcement gaps still apply.

use super::{combiner, signer};
use crate::algebra::CheckOutcome;
use crate::context::{
    SignatureKind, SigningInputContext, TransitionContext, IN_REDEEM_SCRIPT,
    IN_WITNESS_SCRIPT,
};
use crate::encoding::{is_p2sh, is_witness_program, p2sh_script, p2wsh_script, TxOut};

/// The selected input's spent output, once a supplied non-witness UTXO matches
/// its prevout and any witness UTXO. Missing data is Incomplete; a mismatch is
/// Failed.
fn signing_output(context: &SigningInputContext) -> Result<TxOut, CheckOutcome> {
    let input = context.input();
    signer::validate_non_witness_utxo(input).map_err(CheckOutcome::Failed)?;
    let spent = input.spent_output().ok_or_else(|| {
        CheckOutcome::Incomplete(format!("input {} has no supplied UTXO", input.index))
    })?;
    match input.witness_utxo() {
        Some(witness) if witness != spent => Err(CheckOutcome::Failed(
            "witness and non-witness UTXOs disagree on the spent output".into(),
        )),
        _ => Ok(spent),
    }
}

/// The script the spend commits to: a P2SH spend's matching redeemScript, or
/// the spent script itself.
fn signing_program(context: &SigningInputContext) -> Result<Vec<u8>, CheckOutcome> {
    let input = context.input();
    let spent = signing_output(context)?;
    if !is_p2sh(&spent.script_pubkey) {
        return Ok(spent.script_pubkey);
    }
    let Some(redeem_script) = input.value(IN_REDEEM_SCRIPT) else {
        return Err(CheckOutcome::Incomplete(format!("input {} needs its redeemScript", input.index)));
    };
    if p2sh_script(redeem_script) != spent.script_pubkey {
        return Err(CheckOutcome::Failed("redeemScript does not match the spent P2SH output".into()));
    }
    Ok(redeem_script.to_vec())
}

fn outcome<T>(result: Result<T, CheckOutcome>) -> CheckOutcome {
    result.map_or_else(|outcome| outcome, |_| CheckOutcome::Verified)
}

/// ROLE-S-1: a supplied non-witness UTXO hashes to the prevout's txid, has the
/// spent output, and agrees with any witness UTXO.
pub fn validate_signing_non_witness_utxo(context: &SigningInputContext) -> CheckOutcome {
    if context.input().non_witness_utxo().is_none() {
        return CheckOutcome::NotApplicable;
    }
    outcome(signing_output(context))
}

/// ROLE-S-2: a supplied PSBT_IN_REDEEM_SCRIPT is the script the spent output
/// commits to as P2SH. Not applicable when none is supplied.
pub fn validate_signing_redeem_script(context: &SigningInputContext) -> CheckOutcome {
    let Some(redeem_script) = context.input().value(IN_REDEEM_SCRIPT) else {
        return CheckOutcome::NotApplicable;
    };
    match signing_output(context) {
        Ok(spent) if p2sh_script(redeem_script) == spent.script_pubkey => CheckOutcome::Verified,
        Ok(_) => CheckOutcome::Failed("the spent output is not P2SH of the redeemScript".into()),
        Err(outcome) => outcome,
    }
}

/// ROLE-S-3: a supplied PSBT_IN_WITNESS_SCRIPT is the script the spent script,
/// or a P2SH spend's redeemScript, commits to as P2WSH. Not applicable when none
/// is supplied.
pub fn validate_signing_witness_script(context: &SigningInputContext) -> CheckOutcome {
    let Some(witness_script) = context.input().value(IN_WITNESS_SCRIPT) else {
        return CheckOutcome::NotApplicable;
    };
    match signing_program(context) {
        Ok(program) if p2wsh_script(witness_script) == program => CheckOutcome::Verified,
        Ok(_) => CheckOutcome::Failed("neither the spent script nor the redeemScript is P2WSH of the witnessScript".into()),
        Err(outcome) => outcome,
    }
}

/// ROLE-S-4: the selected signature kind suits the input: never non-witness
/// with a witness UTXO, and witness exactly when the spent script, or its
/// redeemScript, is a witness program.
pub fn validate_signing_signature_kind(context: &SigningInputContext) -> CheckOutcome {
    let witness = context.signature_kind() == SignatureKind::Witness;
    if !witness && context.input().witness_utxo().is_some() {
        return CheckOutcome::Failed("a witness UTXO forbids a non-witness signature".into());
    }
    match signing_program(context) {
        Ok(program) if witness == is_witness_program(&program) => CheckOutcome::Verified,
        Ok(_) => CheckOutcome::Failed("selected signature kind does not match the spent script".into()),
        Err(outcome) => outcome,
    }
}

/// ROLE-B-2: preserve source keys and choose only supplied key-value pairs.
/// Requires source/result identities and positional maps already checked by
/// ROLE-B-1. This binding does not establish comprehensive merge consistency.
pub fn validate_merge_preservation(transition: &TransitionContext) -> Result<(), String> {
    combiner::validate_combined_keeps_keys(transition)?;
    combiner::validate_combined_adds_nothing(transition)
}
