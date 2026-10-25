use super::{check_formats, check_versions};
use crate::context::{
    determine_locktime, value, value_u32, InputContext, OutputContext, PsbtContext, GLOBAL_TX_MODIFIABLE,
    IN_REQUIRED_HEIGHT_LOCKTIME, IN_REQUIRED_TIME_LOCKTIME,
};
use crate::registry::Scope;
use crate::silent_payments::input_signatures;

const LOCKTIME_THRESHOLD: u32 = 500_000_000;

// Every known input field MUST have the key data and value format its type defines. (Table 1)
pub fn validate_input_field_formats(input: &InputContext) -> Result<(), String> {
    check_formats(input.map(), Scope::Input, &input.psbt.psbt.bips)
}

// An input map MUST include every field its version requires and no field its version excludes. (Table 1)
pub fn validate_input_field_versions(input: &InputContext) -> Result<(), String> {
    check_versions(input.map(), Scope::Input, input.version(), &input.psbt.psbt.bips)
}

// A required time-based lock time MUST be at least 500,000,000.
pub fn validate_required_time_locktime(input: &InputContext) -> Result<(), String> {
    match value_u32(input.map(), IN_REQUIRED_TIME_LOCKTIME) {
        Some(t) if t < LOCKTIME_THRESHOLD => Err(format!("time lock time {t} is below the threshold")),
        _ => Ok(()),
    }
}

// A required height-based lock time MUST be greater than 0 and less than 500,000,000.
pub fn validate_required_height_locktime(input: &InputContext) -> Result<(), String> {
    match value_u32(input.map(), IN_REQUIRED_HEIGHT_LOCKTIME) {
        Some(h) if h == 0 || h >= LOCKTIME_THRESHOLD => Err(format!("height lock time {h} is out of range")),
        _ => Ok(()),
    }
}

// Every known output field MUST have the key data and value format its type defines. (Table 1)
pub fn validate_output_field_formats(output: &OutputContext) -> Result<(), String> {
    check_formats(output.map(), Scope::Output, &output.psbt.psbt.bips)
}

// An output map MUST include every field its version requires and no field its version excludes. (Table 1)
pub fn validate_output_field_versions(output: &OutputContext) -> Result<(), String> {
    check_versions(output.map(), Scope::Output, output.version(), &output.psbt.psbt.bips)
}

// The inputs' required lock times MUST share a lock time type, so the transaction lock time can be determined.
pub fn validate_locktime_determinable(psbt: &PsbtContext) -> Result<(), String> {
    match determine_locktime(psbt) {
        Some(_) => Ok(()),
        None => Err("inputs require incompatible lock time types".into()),
    }
}

const INPUTS_MODIFIABLE: u8 = 0x01;
const OUTPUTS_MODIFIABLE: u8 = 0x02;
const HAS_SIGHASH_SINGLE: u8 = 0x04;
const SIGHASH_NONE: u8 = 0x02;
const SIGHASH_SINGLE: u8 = 0x03;
const SIGHASH_ANYONECANPAY: u8 = 0x80;

/// The sighash type of a signature from `input_signatures`. A 64-byte Schnorr
/// signature uses SIGHASH_DEFAULT (0x00).
pub fn signature_sighash((sig, schnorr): &(Vec<u8>, bool)) -> Option<u8> {
    if *schnorr && sig.len() == 64 { Some(0) } else { sig.last().copied() }
}

/// The sighash type of every signature the inputs carry.
fn sighash_types(psbt: &PsbtContext) -> Vec<u8> {
    psbt.inputs().iter().flat_map(input_signatures).filter_map(|s| signature_sighash(&s)).collect()
}

fn modifiable_flags(psbt: &PsbtContext) -> Option<u8> {
    value(psbt.psbt.global(), GLOBAL_TX_MODIFIABLE).map(|v| v[0])
}

// If any signature lacks SIGHASH_ANYONECANPAY, the Inputs Modifiable flag MUST be cleared.
pub fn validate_inputs_modifiable_flag(psbt: &PsbtContext) -> Result<(), String> {
    let flags = modifiable_flags(psbt).unwrap_or(0);
    if flags & INPUTS_MODIFIABLE != 0 && sighash_types(psbt).iter().any(|h| h & SIGHASH_ANYONECANPAY == 0) {
        return Err("inputs are modifiable but a signature commits to all inputs".into());
    }
    Ok(())
}

// If any signature does not use SIGHASH_NONE, the Outputs Modifiable flag MUST be cleared.
pub fn validate_outputs_modifiable_flag(psbt: &PsbtContext) -> Result<(), String> {
    let flags = modifiable_flags(psbt).unwrap_or(0);
    if flags & OUTPUTS_MODIFIABLE != 0 && sighash_types(psbt).iter().any(|h| h & 0x1f != SIGHASH_NONE) {
        return Err("outputs are modifiable but a signature commits to outputs".into());
    }
    Ok(())
}

// If any signature uses SIGHASH_SINGLE, a present PSBT_GLOBAL_TX_MODIFIABLE MUST have its Has SIGHASH_SINGLE flag set.
pub fn validate_sighash_single_flag(psbt: &PsbtContext) -> Result<(), String> {
    let Some(flags) = modifiable_flags(psbt) else { return Ok(()) };
    if flags & HAS_SIGHASH_SINGLE == 0 && sighash_types(psbt).iter().any(|h| h & 0x1f == SIGHASH_SINGLE) {
        return Err("a signature uses SIGHASH_SINGLE but the Has SIGHASH_SINGLE flag is clear".into());
    }
    Ok(())
}
