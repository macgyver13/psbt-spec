use crate::context::InputContext;
use crate::algebra::{Bip, CheckOutcome};
use crate::context::{
    records, value_u32, PsbtContext, GLOBAL_TX_MODIFIABLE, IN_P2C_TWEAK, IN_PARTIAL_SIG, IN_SIGHASH_TYPE,
    IN_SP_TWEAK, IN_TAP_KEY_SIG, IN_TAP_SCRIPT_SIG,
};
use crate::rules::input_output::signature_sighash;
use crate::taproot::check_input_signature;
use crate::silent_payments::{
    input_signatures, is_p2tr, spent_script,
};

/// The signatures input `index` carries after signing that it did not carry before.
pub fn added_signatures(transition: &SignerTransitionContext, index: usize) -> Vec<(Vec<u8>, bool)> {
    let mut before = input_signatures(&transition.before.inputs()[index]);
    input_signatures(&transition.after.inputs()[index])
        .into_iter()
        .filter(|sig| match before.iter().position(|b| b == sig) {
            Some(i) => {
                before.remove(i);
                false
            }
            None => true,
        })
        .collect()
}

/// A transition representing signatures added by a Signer.
#[derive(Clone)]
pub struct SignerTransitionContext {
    pub before: PsbtContext,
    pub after: PsbtContext,
}

impl SignerTransitionContext {
    pub fn new(before: PsbtContext, after: PsbtContext) -> Self {
        Self { before, after }
    }
}

/// BIP372 overrides "only add data" for one field: with BIP372 enabled, a Signer
/// may remove PSBT_IN_P2C_TWEAK from an input that has PSBT_IN_PARTIAL_SIG.
fn p2c_tweak_removed_after_signing(after: &PsbtContext, map: usize, key_type: u64) -> bool {
    let is_input = (1..=after.inputs).contains(&map);
    is_input
        && key_type == IN_P2C_TWEAK
        && after.psbt.bips.contains(&Bip::Bip372)
        && records(&after.psbt.maps[map], IN_PARTIAL_SIG).next().is_some()
}

/// ROLE-S-9: BIP174’s Signer MUST only add data to a PSBT. Signatures belong in the
/// appropriate input fields; version- and extension-specific writes follow the stated role requirements.
pub fn validate_signer_data_preservation(transition: &SignerTransitionContext) -> CheckOutcome {
    let before = &transition.before;
    let after = &transition.after;

    if after.inputs != before.inputs || after.outputs != before.outputs {
        return CheckOutcome::Failed("Signer cannot add or remove inputs or outputs".into());
    }

    for (m, before_map) in before.psbt.maps.iter().enumerate() {
        let after_map = &after.psbt.maps[m];
        for r in before_map {
            // In v2, TX_MODIFIABLE can be legitimately updated by Signer (clearing flags)
            if m == 0 && r.key_type == GLOBAL_TX_MODIFIABLE {
                continue;
            }
            let matching = after_map.iter().find(|ar| ar.key_type == r.key_type && ar.key_data == r.key_data);
            match matching {
                Some(ar) if ar.value == r.value => {},
                Some(_) => return CheckOutcome::Failed(format!("map {m} modified existing key {:#04x}", r.key_type)),
                None if p2c_tweak_removed_after_signing(after, m, r.key_type) => {},
                None => return CheckOutcome::Failed(format!("map {m} dropped existing key {:#04x}", r.key_type)),
            }
        }
    }

    CheckOutcome::Verified
}

/// ROLE-S-10: Every signature the Signer adds to an input with PSBT_IN_SIGHASH_TYPE
/// MUST use that sighash type.
pub fn validate_signer_sighash_type(transition: &SignerTransitionContext) -> CheckOutcome {
    let mut applicable = false;
    for input in transition.after.inputs() {
        let Some(expected) = value_u32(input.map(), IN_SIGHASH_TYPE) else { continue };
        let added = added_signatures(transition, input.index);
        applicable |= !added.is_empty();
        if added.iter().any(|sig| signature_sighash(sig).is_none_or(|t| u32::from(t) != expected)) {
            return CheckOutcome::Failed(format!("input {} has an added signature without sighash type {expected}", input.index));
        }
    }
    if applicable { CheckOutcome::Verified } else { CheckOutcome::NotApplicable }
}

/// ROLE-S-11: The Signer MUST write the BIP340 signature for an SP input to
/// PSBT_IN_TAP_KEY_SIG, as a key-path signature by the spent output key.
pub fn validate_sp_key_signature_written(transition: &SignerTransitionContext) -> CheckOutcome {
    let mut outcome = CheckOutcome::NotApplicable;
    for input in transition.after.inputs() {
        if input.value(IN_SP_TWEAK).is_none() || added_signatures(transition, input.index).is_empty() {
            continue;
        }
        let before = &transition.before.inputs()[input.index];
        let added = |key_type| {
            records(input.map(), key_type).any(|r| records(before.map(), key_type).all(|b| b != r))
        };
        if added(IN_PARTIAL_SIG) || added(IN_TAP_SCRIPT_SIG) {
            return CheckOutcome::Failed(format!("input {} has an SP signature outside PSBT_IN_TAP_KEY_SIG", input.index));
        }
        let Some(sig) = input.value(IN_TAP_KEY_SIG) else {
            return CheckOutcome::Failed(format!("input {} has no PSBT_IN_TAP_KEY_SIG", input.index));
        };
        let key = match spent_script(&input) {
            Ok(s) if is_p2tr(&s) => <[u8; 32]>::try_from(&s[2..]).unwrap(),
            Ok(_) => return CheckOutcome::Failed(format!("input {} has a tweak but spent script is not P2TR", input.index)),
            Err(e) => return CheckOutcome::Incomplete(e),
        };
        match check_input_signature(&input, sig, &key, None, None) {
            CheckOutcome::Verified => outcome = CheckOutcome::Verified,
            other => return other,
        }
    }
    outcome
}

// A non-witness UTXO MUST hash to the input's previous txid and contain the spent output index.
pub fn validate_non_witness_utxo(input: &InputContext) -> Result<(), String> {
    let Some(tx) = input.non_witness_utxo() else { return Ok(()) };
    let (txid, vout) = input.prevout();
    if tx.txid() != txid {
        return Err("non-witness UTXO does not match the previous txid".into());
    }
    if vout as usize >= tx.outputs.len() {
        return Err(format!("non-witness UTXO has no output {vout}"));
    }
    Ok(())
}

