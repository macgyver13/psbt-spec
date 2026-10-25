use crate::context::{InputContext, IN_REDEEM_SCRIPT, IN_WITNESS_SCRIPT};
use crate::encoding::{is_p2sh, is_witness_program, p2sh_script, p2wsh_script};

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

// A witness UTXO's scriptPubKey MUST be a witness program, or P2SH of a redeemScript that is one.
pub fn validate_witness_utxo(input: &InputContext) -> Result<(), String> {
    let Some(utxo) = input.witness_utxo() else { return Ok(()) };
    let spk = &utxo.script_pubkey;
    let nested = is_p2sh(spk) && input.value(IN_REDEEM_SCRIPT).is_some_and(is_witness_program);
    if !is_witness_program(spk) && !nested {
        return Err("witness UTXO provided for a non-witness input".into());
    }
    Ok(())
}

// A redeemScript MUST hash to the spent output's P2SH scriptPubKey.
pub fn validate_redeem_script(input: &InputContext) -> Result<(), String> {
    let (Some(rs), Some(spent)) = (input.value(IN_REDEEM_SCRIPT), input.spent_output()) else { return Ok(()) };
    if spent.script_pubkey != p2sh_script(rs) {
        return Err("redeemScript does not match the scriptPubKey".into());
    }
    Ok(())
}

// A witnessScript MUST hash to the P2WSH program in the spent scriptPubKey, or in the redeemScript when nested.
pub fn validate_witness_script(input: &InputContext) -> Result<(), String> {
    let (Some(ws), Some(spent)) = (input.value(IN_WITNESS_SCRIPT), input.spent_output()) else { return Ok(()) };
    let program = match input.value(IN_REDEEM_SCRIPT) {
        Some(rs) if is_p2sh(&spent.script_pubkey) => rs.to_vec(),
        _ => spent.script_pubkey,
    };
    if program != p2wsh_script(ws) {
        return Err("witnessScript does not match the witness program".into());
    }
    Ok(())
}
