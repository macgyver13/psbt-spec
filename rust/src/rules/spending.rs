use crate::context::{records, InputContext, IN_FINAL_SCRIPTWITNESS, IN_SP_SPEND_BIP32_DERIVATION, IN_SP_TWEAK};
use crate::silent_payments::{is_p2tr, tweaked_spend_key_matches};

// A finalized input MUST NOT keep PSBT_IN_SP_TWEAK or PSBT_IN_SP_SPEND_BIP32_DERIVATION.
pub fn validate_sp_finalized_cleared(input: &InputContext) -> Result<(), String> {
    let kept = input.value(IN_SP_TWEAK).is_some() || records(input.map(), IN_SP_SPEND_BIP32_DERIVATION).next().is_some();
    if input.value(IN_FINAL_SCRIPTWITNESS).is_some() && kept {
        return Err(format!("finalized input {} keeps silent payment spending fields", input.index));
    }
    Ok(())
}

// An input with PSBT_IN_SP_SPEND_BIP32_DERIVATION MUST have PSBT_IN_SP_TWEAK.
pub fn validate_sp_spend_key_has_tweak(input: &InputContext) -> Result<(), String> {
    if records(input.map(), IN_SP_SPEND_BIP32_DERIVATION).next().is_some() && input.value(IN_SP_TWEAK).is_none() {
        return Err(format!("input {} has a spend key but no tweak", input.index));
    }
    Ok(())
}

// An input with PSBT_IN_SP_TWEAK MUST have a PSBT_IN_WITNESS_UTXO whose scriptPubKey is P2TR.
pub fn validate_sp_tweak_spends_p2tr(input: &InputContext) -> Result<(), String> {
    if input.value(IN_SP_TWEAK).is_none() {
        return Ok(());
    }
    match input.witness_utxo() {
        Some(utxo) if is_p2tr(&utxo.script_pubkey) => Ok(()),
        Some(_) => Err(format!("input {} has a tweak but its witness UTXO is not P2TR", input.index)),
        None => Err(format!("input {} has a tweak but no witness UTXO", input.index)),
    }
}

// Every spend key in PSBT_IN_SP_SPEND_BIP32_DERIVATION, plus the tweak times G, MUST have the x-coordinate of the spent P2TR output key.
pub fn validate_sp_tweaked_spend_key(input: &InputContext) -> Result<(), String> {
    let Some(tweak) = input.value(IN_SP_TWEAK) else { return Ok(()) };
    let output_key = input.witness_utxo().unwrap().script_pubkey[2..].to_vec();
    for record in records(input.map(), IN_SP_SPEND_BIP32_DERIVATION) {
        if !tweaked_spend_key_matches(&record.key_data, tweak, &output_key) {
            return Err(format!("input {}: spend key plus tweak does not match the output key", input.index));
        }
    }
    Ok(())
}
