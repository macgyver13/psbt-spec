use crate::context::{
    keyed, value_u32, InputContext, OutputContext, PsbtContext, GLOBAL_SP_DLEQ, GLOBAL_SP_ECDH_SHARE,
    GLOBAL_TX_MODIFIABLE, IN_SIGHASH_TYPE, IN_SP_DLEQ, IN_SP_ECDH_SHARE, OUT_SCRIPT, OUT_SP_V0_INFO, OUT_SP_V0_LABEL,
};
use crate::silent_payments::{
    derived_scripts, dleq_verify, ecdh_and_pubkey_sum, input_pubkey, input_signatures, is_eligible, is_p2tr,
    is_segwit_v2_or_later, point, scan_key_has_script, scan_keys, sp_outputs, spent_script,
};

/// A scan key and the ECDH share for it.
type Share<'a> = (Vec<u8>, &'a [u8]);

/// The scan keys for which `input` has an ECDH share, when it is eligible.
fn eligible_shares(input: &InputContext) -> Result<Vec<Share<'_>>, String> {
    let mut shares = Vec::new();
    for scan_key in scan_keys(&input.psbt) {
        if let Some(share) = keyed(input.map(), IN_SP_ECDH_SHARE, &scan_key) {
            if is_eligible(input)? {
                shares.push((scan_key, share));
            }
        }
    }
    Ok(shares)
}

// An output with PSBT_OUT_SP_V0_LABEL MUST also have PSBT_OUT_SP_V0_INFO.
pub fn validate_sp_label_has_info(output: &OutputContext) -> Result<(), String> {
    if output.value(OUT_SP_V0_LABEL).is_some() && output.value(OUT_SP_V0_INFO).is_none() {
        return Err(format!("output {} has a label but no silent payment info", output.index));
    }
    Ok(())
}

// Once a silent payment output has PSBT_OUT_SCRIPT, its scan key MUST have a global ECDH share,
// or per-input ECDH shares on at least one input and on every eligible input.
pub fn validate_ecdh_coverage(psbt: &PsbtContext) -> Result<(), String> {
    for scan_key in scan_keys(psbt) {
        if !scan_key_has_script(psbt, &scan_key) || keyed(psbt.psbt.global(), GLOBAL_SP_ECDH_SHARE, &scan_key).is_some() {
            continue;
        }
        let inputs = psbt.inputs();
        let has_share = |i: &InputContext| keyed(i.map(), IN_SP_ECDH_SHARE, &scan_key).is_some();
        if !inputs.iter().any(has_share) {
            return Err("silent payment output script set but no ECDH share for its scan key".into());
        }
        for input in inputs.iter().filter(|i| !has_share(i)) {
            if is_eligible(input)? {
                return Err(format!("silent payment output script set but eligible input {} has no ECDH share", input.index));
            }
        }
    }
    Ok(())
}

// A global ECDH share for a silent payment output's scan key MUST have a global DLEQ proof.
pub fn validate_global_dleq_present(psbt: &PsbtContext) -> Result<(), String> {
    let global = psbt.psbt.global();
    for scan_key in scan_keys(psbt) {
        if keyed(global, GLOBAL_SP_ECDH_SHARE, &scan_key).is_some() && keyed(global, GLOBAL_SP_DLEQ, &scan_key).is_none() {
            return Err("global ECDH share has no DLEQ proof".into());
        }
    }
    Ok(())
}

// When a silent payment output's scan key has a global ECDH share, the PSBT MUST have an eligible
// input, and every eligible input MUST have a public key.
pub fn validate_global_share_pubkeys(psbt: &PsbtContext) -> Result<(), String> {
    if !scan_keys(psbt).iter().any(|k| keyed(psbt.psbt.global(), GLOBAL_SP_ECDH_SHARE, k).is_some()) {
        return Ok(());
    }
    let mut eligible = 0;
    for input in psbt.inputs() {
        if is_eligible(&input)? {
            eligible += 1;
            if input_pubkey(&input)?.is_none() {
                return Err(format!("global ECDH share set but eligible input {} has no public key", input.index));
            }
        }
    }
    if eligible == 0 {
        return Err("global ECDH share set but no input is eligible".into());
    }
    Ok(())
}

// A global DLEQ proof MUST verify for the sum of the eligible inputs' public keys, the scan key,
// and the global ECDH share.
pub fn validate_global_dleq_proof(psbt: &PsbtContext) -> Result<(), String> {
    let global = psbt.psbt.global();
    for scan_key in scan_keys(psbt) {
        if keyed(global, GLOBAL_SP_ECDH_SHARE, &scan_key).is_none() {
            continue;
        }
        let proof = keyed(global, GLOBAL_SP_DLEQ, &scan_key).unwrap();
        let (share, pubkey_sum) = ecdh_and_pubkey_sum(psbt, &scan_key)?.unwrap();
        if !dleq_verify(&pubkey_sum, &point(&scan_key).unwrap(), &share, proof) {
            return Err("global DLEQ proof does not verify".into());
        }
    }
    Ok(())
}

// An eligible input's ECDH share for a silent payment output's scan key MUST have a DLEQ proof.
pub fn validate_input_dleq_present(input: &InputContext) -> Result<(), String> {
    for (scan_key, _) in eligible_shares(input)? {
        if keyed(input.map(), IN_SP_DLEQ, &scan_key).is_none() {
            return Err(format!("input {} ECDH share has no DLEQ proof", input.index));
        }
    }
    Ok(())
}

// An eligible input with an ECDH share MUST have a public key.
pub fn validate_input_share_pubkey(input: &InputContext) -> Result<(), String> {
    if !eligible_shares(input)?.is_empty() && input_pubkey(input)?.is_none() {
        return Err(format!("input {} has an ECDH share but no public key", input.index));
    }
    Ok(())
}

// An input DLEQ proof MUST verify for the input's public key, the scan key, and the input's ECDH share.
pub fn validate_input_dleq_proof(input: &InputContext) -> Result<(), String> {
    for (scan_key, share) in eligible_shares(input)? {
        let pubkey = input_pubkey(input)?.unwrap();
        let proof = keyed(input.map(), IN_SP_DLEQ, &scan_key).unwrap();
        if !dleq_verify(&pubkey, &point(&scan_key).unwrap(), &point(share).unwrap(), proof) {
            return Err(format!("input {} DLEQ proof does not verify", input.index));
        }
    }
    Ok(())
}

// An input MUST NOT spend a segwit version 2 or later output.
pub fn validate_sp_segwit_version(input: &InputContext) -> Result<(), String> {
    match spent_script(input) {
        Ok(spk) if is_segwit_v2_or_later(&spk) => {
            Err(format!("input {} spends a segwit version 2 or later output", input.index))
        }
        _ => Ok(()),
    }
}

// PSBT_IN_SIGHASH_TYPE MUST be SIGHASH_ALL, or SIGHASH_DEFAULT on a P2TR input.
pub fn validate_sp_sighash_type(input: &InputContext) -> Result<(), String> {
    match value_u32(input.map(), IN_SIGHASH_TYPE) {
        None | Some(1) => Ok(()),
        Some(0) if spent_script(input).is_ok_and(|s| is_p2tr(&s)) => Ok(()),
        Some(t) => Err(format!("input {} has sighash type {t}", input.index)),
    }
}

// Every signature an input carries MUST use SIGHASH_ALL, or SIGHASH_DEFAULT for a 64-byte Schnorr signature.
pub fn validate_sp_signatures(input: &InputContext) -> Result<(), String> {
    let sighash_all = |(sig, schnorr): &(Vec<u8>, bool)| (*schnorr && sig.len() == 64) || sig.last() == Some(&1);
    if !input_signatures(input).iter().all(sighash_all) {
        return Err(format!("input {} has a signature without SIGHASH_ALL", input.index));
    }
    Ok(())
}

// Once a silent payment output has PSBT_OUT_SCRIPT, PSBT_GLOBAL_TX_MODIFIABLE MUST have its Inputs
// Modifiable and Outputs Modifiable flags cleared.
pub fn validate_sp_tx_unmodifiable(psbt: &PsbtContext) -> Result<(), String> {
    let flags = crate::context::value(psbt.psbt.global(), GLOBAL_TX_MODIFIABLE).map_or(0, |v| v[0]);
    let outputs = psbt.outputs();
    let has_script = sp_outputs(psbt).iter().any(|(i, ..)| outputs[*i].value(OUT_SCRIPT).is_some_and(|s| !s.is_empty()));
    if flags & 0x03 != 0 && has_script {
        return Err("silent payment output script set while inputs or outputs are modifiable".into());
    }
    Ok(())
}

// A silent payment output with PSBT_OUT_SCRIPT MUST have the ECDH shares and input public keys
// its derivation needs.
pub fn validate_sp_script_derivable(psbt: &PsbtContext) -> Result<(), String> {
    let outputs = psbt.outputs();
    for (index, script) in derived_scripts(psbt)? {
        if script.is_none() && outputs[index].value(OUT_SCRIPT).is_some() {
            return Err(format!("output {index} script set but its ECDH share or input public keys are missing"));
        }
    }
    Ok(())
}

// A silent payment output's PSBT_OUT_SCRIPT MUST equal its BIP-352 output script, with k counted per
// scan key over the silent payment outputs sorted by PSBT_OUT_SP_V0_INFO, then by index.
pub fn validate_sp_script(psbt: &PsbtContext) -> Result<(), String> {
    let outputs = psbt.outputs();
    for (index, script) in derived_scripts(psbt)? {
        if let (Some(expected), Some(actual)) = (script, outputs[index].value(OUT_SCRIPT)) {
            if expected != actual {
                return Err(format!("output {index} script does not match its silent payment derivation"));
            }
        }
    }
    Ok(())
}

// An input MUST NOT carry a signature while any output lacks PSBT_OUT_SCRIPT.
pub fn validate_sp_no_signature_before_scripts(psbt: &PsbtContext) -> Result<(), String> {
    let missing = psbt.outputs().iter().position(|o| o.value(OUT_SCRIPT).is_none_or(|s| s.is_empty()));
    let signed = psbt.inputs().iter().position(|i| !input_signatures(i).is_empty());
    if let (Some(o), Some(i)) = (missing, signed) {
        return Err(format!("input {i} is signed while output {o} has no PSBT_OUT_SCRIPT"));
    }
    Ok(())
}
