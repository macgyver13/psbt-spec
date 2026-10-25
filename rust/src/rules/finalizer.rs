use super::input_output::signature_sighash;
use crate::context::{value_u32, InputContext, IN_SIGHASH_TYPE, IN_SP_TWEAK, IN_TAP_KEY_SIG};
use crate::silent_payments::input_signatures;

// If an input has PSBT_IN_SIGHASH_TYPE, every signature it carries MUST use that sighash type.
pub fn validate_signatures_match_sighash_type(input: &InputContext) -> Result<(), String> {
    let Some(expected) = value_u32(input.map(), IN_SIGHASH_TYPE) else { return Ok(()) };
    let matches = |sig: &(Vec<u8>, bool)| signature_sighash(sig).is_some_and(|t| u32::from(t) == expected);
    if !input_signatures(input).iter().all(matches) {
        return Err(format!("input {} has a signature without sighash type {expected}", input.index));
    }
    Ok(())
}

// An input with PSBT_IN_SP_TWEAK MUST have PSBT_IN_TAP_KEY_SIG.
pub fn validate_sp_tweak_has_key_sig(input: &InputContext) -> Result<(), String> {
    if input.value(IN_SP_TWEAK).is_some() && input.value(IN_TAP_KEY_SIG).is_none() {
        return Err(format!("input {} has a tweak but no taproot key path signature", input.index));
    }
    Ok(())
}
