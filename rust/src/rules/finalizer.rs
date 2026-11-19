use super::input_output::signature_sighash;
use crate::context::{value_u32, InputContext, IN_PARTIAL_SIG, IN_SIGHASH_TYPE, IN_SP_TWEAK, IN_TAP_KEY_SIG};
use crate::ecdsa::check_input_signature;
use crate::encoding::{is_p2sh, is_p2wsh, is_witness_program, p2sh_script, p2wsh_script};
use crate::silent_payments::{final_witness, has_finalized_script_path, input_signatures, is_p2pkh, is_p2tr, is_p2wpkh, pushes, spent_script};
use bitcoin_hashes::{hash160, Hash};
use crate::algebra::CheckOutcome;
use crate::context::{
    records, IN_FINAL_SCRIPTSIG, IN_FINAL_SCRIPTWITNESS, IN_OUTPUT_INDEX, IN_PREVIOUS_TXID,
    IN_REQUIRED_HEIGHT_LOCKTIME, IN_REQUIRED_TIME_LOCKTIME, IN_SEQUENCE,
};

/// ROLE-F-6: For each input with enough data to pass validation, the Finalizer MUST
/// construct its finalized scriptSig and scriptWitness fields as applicable.
///
/// Checks the finalized input against its spent script's template: the fields
/// the spend uses, the public key a key-hash spend reveals, and the redeem or
/// witness script a script-hash spend reveals. A key-hash spend's signature is
/// verified with ECDSA. A script-hash or Taproot script-path spend
/// is Incomplete, since script satisfaction is not checked; a Taproot key-path
/// signature is verified by ROLE-F-10. A spent script of another type is
/// Incomplete.
pub fn validate_final_script_construction(input: &InputContext) -> CheckOutcome {
    let script_sig = input.value(IN_FINAL_SCRIPTSIG);
    let has_witness = input.value(IN_FINAL_SCRIPTWITNESS).is_some();
    if script_sig.is_none() && !has_witness {
        return CheckOutcome::Incomplete(format!("input {} lacks finalized scriptSig or scriptWitness", input.index));
    }
    let spk = match spent_script(input) {
        Ok(spk) => spk,
        Err(e) => return CheckOutcome::Incomplete(e),
    };
    let i = input.index;
    let sig_pushes = pushes(script_sig);
    let stack = final_witness(input);
    let fail = |what: &str| CheckOutcome::Failed(format!("input {i}: {what}"));
    let key_hash = |key: &[u8]| hash160::Hash::hash(key).to_byte_array();
    let unsatisfied = || CheckOutcome::Incomplete(format!("input {i}: final script satisfaction is not checked"));
    let ecdsa = |sig: &[u8], key: &[u8]| check_input_signature(input, sig, key);

    // The spent script, or the redeem script a P2SH scriptSig reveals.
    let (spk, wrapped) = if is_p2sh(&spk) {
        let Some(redeem) = sig_pushes.last() else { return fail("P2SH scriptSig does not end with a redeem script push") };
        if p2sh_script(redeem) != spk {
            return fail("redeem script does not match the P2SH hash");
        }
        if !is_witness_program(redeem) {
            return if has_witness { fail("legacy P2SH spend has a scriptWitness") } else { unsatisfied() };
        }
        if sig_pushes.len() != 1 {
            return fail("wrapped segwit scriptSig must be only the redeem script push");
        }
        (redeem.clone(), true)
    } else {
        (spk, false)
    };
    if !wrapped && is_witness_program(&spk) && script_sig.is_some() {
        return fail("native segwit spend has a scriptSig");
    }

    if is_p2pkh(&spk) {
        if has_witness {
            return fail("P2PKH spend has a scriptWitness");
        }
        match sig_pushes.as_slice() {
            [sig, key] if key_hash(key)[..] == spk[3..23] => ecdsa(sig, key),
            [_, _] => fail("scriptSig key does not match the P2PKH hash"),
            _ => fail("P2PKH scriptSig is not a signature and a public key"),
        }
    } else if is_p2wpkh(&spk) {
        match stack.as_slice() {
            [sig, key] if key_hash(key)[..] == spk[2..] => ecdsa(sig, key),
            [_, _] => fail("witness key does not match the P2WPKH hash"),
            _ => fail("P2WPKH witness is not a signature and a public key"),
        }
    } else if is_p2wsh(&spk) {
        match stack.last() {
            Some(script) if p2wsh_script(script) == spk => unsatisfied(),
            Some(_) => fail("witness script does not match the P2WSH hash"),
            None => fail("P2WSH spend has no witness script"),
        }
    } else if is_p2tr(&spk) {
        // ROLE-F-9 and ROLE-F-10 check the witness contents.
        if stack.is_empty() {
            fail("P2TR spend has an empty witness")
        } else if has_finalized_script_path(input) {
            unsatisfied()
        } else {
            CheckOutcome::Verified
        }
    } else {
        CheckOutcome::Incomplete(format!("input {i}: final fields for this spent script type are not checked"))
    }
}

/// ROLE-F-2: Before finalizing an input with PSBT_IN_SP_TWEAK, the Finalizer MUST
/// require PSBT_IN_TAP_KEY_SIG.
pub fn validate_sp_finalization_key_sig(input: &InputContext) -> CheckOutcome {
    if input.value(IN_SP_TWEAK).is_none() {
        return CheckOutcome::NotApplicable;
    }
    match input.value(IN_TAP_KEY_SIG) {
        Some(_) => CheckOutcome::Verified,
        None => CheckOutcome::Failed(format!("input {} has a tweak but no PSBT_IN_TAP_KEY_SIG", input.index)),
    }
}

/// A transition representing metadata cleanup by an Input Finalizer.
#[derive(Clone)]
pub struct FinalizerTransitionContext {
    pub before: InputContext,
    pub after: InputContext,
}

impl FinalizerTransitionContext {
    pub fn new(before: InputContext, after: InputContext) -> Self {
        Self { before, after }
    }
}

/// ROLE-F-7: When clearing finalized input metadata, the Finalizer MUST retain existing
/// PREVIOUS_TXID, OUTPUT_INDEX, SEQUENCE, REQUIRED_TIME_LOCKTIME and REQUIRED_HEIGHT_LOCKTIME fields.
pub fn validate_finalizer_field_retention(transition: &FinalizerTransitionContext) -> CheckOutcome {
    let before = &transition.before;
    let after = &transition.after;

    if after.value(IN_FINAL_SCRIPTSIG).is_none() && after.value(IN_FINAL_SCRIPTWITNESS).is_none() {
        return CheckOutcome::NotApplicable;
    }

    let preserved_types = [
        (IN_PREVIOUS_TXID, "PREVIOUS_TXID"),
        (IN_OUTPUT_INDEX, "OUTPUT_INDEX"),
        (IN_SEQUENCE, "SEQUENCE"),
        (IN_REQUIRED_TIME_LOCKTIME, "REQUIRED_TIME_LOCKTIME"),
        (IN_REQUIRED_HEIGHT_LOCKTIME, "REQUIRED_HEIGHT_LOCKTIME"),
    ];

    for (key_type, name) in preserved_types {
        if let Some(val) = before.value(key_type) {
            match after.value(key_type) {
                Some(after_val) if after_val == val => {},
                Some(_) => return CheckOutcome::Failed(format!("Finalizer modified existing {name} on input {}", before.index)),
                None => return CheckOutcome::Failed(format!("Finalizer dropped required {name} on input {}", before.index)),
            }
        }
    }

    CheckOutcome::Verified
}

/// Checks N01 and ROLE-F-1: discovered signatures match a present input sighash type.
///
/// Requires a validated input projection and field formats; supplied UTXOs and
/// scripts determine which finalized signatures can be discovered. Returns
/// `Err` for a discovered mismatch, otherwise `Ok(())`, including no sighash
/// field or no discovered signatures. A 64-byte Schnorr signature uses DEFAULT.
/// Discovery via `input_signatures` is incomplete for arbitrary finalized
/// scripts, including taproot script paths; success does not prove completeness
/// or cryptographic signature validity.
pub fn validate_signatures_match_sighash_type(input: &InputContext) -> Result<(), String> {
    let Some(expected) = value_u32(input.map(), IN_SIGHASH_TYPE) else { return Ok(()) };
    let matches = |sig: &(Vec<u8>, bool)| signature_sighash(sig).is_some_and(|t| u32::from(t) == expected);
    if !input_signatures(input).iter().all(matches) {
        return Err(format!("input {} has a signature without sighash type {expected}", input.index));
    }
    Ok(())
}

/// ROLE-F-8: For an input with PSBT_IN_SP_TWEAK, the Finalizer MUST construct a
/// single-element PSBT_IN_FINAL_SCRIPTWITNESS from its PSBT_IN_TAP_KEY_SIG, and remove
/// PSBT_IN_TAP_KEY_SIG. GEN-SP-6 checks the other SP fields are removed.
pub fn validate_sp_finalized_witness(transition: &FinalizerTransitionContext) -> CheckOutcome {
    let (before, after) = (&transition.before, &transition.after);
    let Some(witness) = after.value(IN_FINAL_SCRIPTWITNESS) else {
        return CheckOutcome::NotApplicable;
    };
    if before.value(IN_SP_TWEAK).is_none() {
        return CheckOutcome::NotApplicable;
    }
    if after.value(IN_TAP_KEY_SIG).is_some() {
        return CheckOutcome::Failed(format!("finalized input {} still has TAP_KEY_SIG", after.index));
    }
    let Ok(stack) = crate::encoding::decode_exact(witness, crate::encoding::read_witness) else {
        return CheckOutcome::Failed(format!("input {} final witness does not decode", after.index));
    };
    match (stack.as_slice(), before.value(IN_TAP_KEY_SIG)) {
        ([item], Some(sig)) if item == sig => CheckOutcome::Verified,
        ([_], Some(_)) => CheckOutcome::Failed(format!("input {} final witness is not its PSBT_IN_TAP_KEY_SIG", after.index)),
        ([_], None) => CheckOutcome::Failed(format!("input {} was finalized without PSBT_IN_TAP_KEY_SIG", after.index)),
        _ => CheckOutcome::Failed(format!("finalized SP input {} witness is not a single element", after.index)),
    }
}

/// ROLE-F-1: If PSBT_IN_SIGHASH_TYPE is present, the Finalizer MUST refuse to finalize
/// an input if any of its signatures uses a different sighash type. Not applicable
/// without the field or without a signature. An input already finalized with a
/// Taproot script path is Incomplete: its witness does not label its signatures.
pub fn validate_finalizer_sighash_type(input: &InputContext) -> CheckOutcome {
    if input.value(IN_SIGHASH_TYPE).is_none() {
        return CheckOutcome::NotApplicable;
    }
    let outcome = validate_signatures_match_sighash_type(input);
    if outcome.is_ok() && has_finalized_script_path(input) {
        return CheckOutcome::Incomplete(format!("input {}: signatures in a finalized script path witness are not identified", input.index));
    }
    if outcome.is_ok() && input_signatures(input).is_empty() {
        return CheckOutcome::NotApplicable;
    }
    outcome.into()
}

/// ROLE-F-4: Before finalizing an input, the Finalizer MUST verify each
/// PSBT_IN_PARTIAL_SIG it uses as an ECDSA signature over the input's legacy or
/// BIP143 signature message. Not applicable without a partial signature.
pub fn validate_finalizer_ecdsa_signatures(input: &InputContext) -> CheckOutcome {
    let mut outcome = CheckOutcome::NotApplicable;
    for r in records(input.map(), IN_PARTIAL_SIG) {
        match check_input_signature(input, &r.value, &r.key_data) {
            CheckOutcome::Verified => outcome = CheckOutcome::Verified,
            other => return other,
        }
    }
    outcome
}

