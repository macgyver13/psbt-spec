use super::{check_formats, check_versions};
use crate::context::{
    determine_locktime, value, value_u32, InputContext, OutputContext, PsbtContext, GLOBAL_TX_MODIFIABLE,
    IN_REQUIRED_HEIGHT_LOCKTIME, IN_REQUIRED_TIME_LOCKTIME,
};
use crate::registry::Scope;
use crate::silent_payments::input_signatures;

const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// Checks the registry-backed part of GEN-F-5 for present input fields.
///
/// Requires an input projected after global and map-count checks. Returns `Err`
/// for a known field's invalid key data or value, otherwise `Ok(())`. Enabled
/// BIPs select known types; unknown types are ignored. Locktime ranges and
/// field presence/version restrictions are separate checks.
pub fn validate_input_field_formats(input: &InputContext) -> Result<(), String> {
    check_formats(input.map(), Scope::Input)
}

/// Checks GEN-ST-2: required input fields exist and excluded fields do not.
///
/// Requires a valid input projection, supported version, unique keys and valid
/// field formats. Returns `Err` for a missing required or present excluded
/// field, otherwise `Ok(())`, within the enabled BIPs' registry and registered
/// replacements. Cross-field semantics are checked separately.
pub fn validate_input_field_versions(input: &InputContext) -> Result<(), String> {
    check_versions(input.map(), Scope::Input, input.version(), &input.psbt.psbt.bips)
}

/// Checks the GEN-F-5 PSBTv2 time-locktime bound: at least 500,000,000.
///
/// The caller gates on v2 and establishes a valid input projection and field
/// formats. Returns `Err` for a present value below the bound, otherwise
/// `Ok(())`, including absence. Compatibility across inputs is separate.
pub fn validate_required_time_locktime(input: &InputContext) -> Result<(), String> {
    match value_u32(input.map(), IN_REQUIRED_TIME_LOCKTIME) {
        Some(t) if t < LOCKTIME_THRESHOLD => Err(format!("time lock time {t} is below the threshold")),
        _ => Ok(()),
    }
}

/// Checks the GEN-F-5 PSBTv2 height-locktime bound: strictly between zero
/// and 500,000,000.
///
/// The caller gates on v2 and establishes a valid input projection and field
/// formats. Returns `Err` for a present value outside that range, otherwise
/// `Ok(())`, including absence. Compatibility across inputs is separate.
pub fn validate_required_height_locktime(input: &InputContext) -> Result<(), String> {
    match value_u32(input.map(), IN_REQUIRED_HEIGHT_LOCKTIME) {
        Some(h) if h == 0 || h >= LOCKTIME_THRESHOLD => Err(format!("height lock time {h} is out of range")),
        _ => Ok(()),
    }
}

/// Checks GEN-F-5 for present output fields known to the enabled BIPs.
///
/// Requires an output projected after global and map-count checks. Returns
/// `Err` for a known field's invalid key data or value, otherwise `Ok(())`.
/// Unknown types are ignored; presence, version restrictions and silent-payment
/// relationships are separate checks. Coverage follows the field registry.
pub fn validate_output_field_formats(output: &OutputContext) -> Result<(), String> {
    check_formats(output.map(), Scope::Output)
}

/// Checks GEN-ST-2: required output fields exist and excluded fields do not.
///
/// Requires a valid output projection, supported version, unique keys and valid
/// field formats. Returns `Err` for a missing required or present excluded
/// field, otherwise `Ok(())`, within the enabled BIPs' registry. Registered
/// replacements can satisfy presence; their semantic relationships are separate.
pub fn validate_output_field_versions(output: &OutputContext) -> Result<(), String> {
    check_versions(output.map(), Scope::Output, output.version(), &output.psbt.psbt.bips)
}

/// Checks GEN-T-1: BIP370 can determine the transaction locktime.
///
/// The caller gates on PSBTv2 and establishes global, map-count and input-field
/// validity, including required-locktime ranges. Returns `Err` if constrained
/// inputs share no locktime type, otherwise `Ok(())`. Shared height wins over
/// time; no requirements use fallback or zero. This checks determinability,
/// not spend finality or whether existing signatures permit a locktime change.
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

/// GEN-T-2: if any signature lacks SIGHASH_ANYONECANPAY, Inputs Modifiable is clear.
pub fn validate_inputs_modifiable_flag(psbt: &PsbtContext) -> Result<(), String> {
    let flags = modifiable_flags(psbt).unwrap_or(0);
    if flags & INPUTS_MODIFIABLE != 0 && sighash_types(psbt).iter().any(|h| h & SIGHASH_ANYONECANPAY == 0) {
        return Err("inputs are modifiable but a signature commits to all inputs".into());
    }
    Ok(())
}

/// GEN-T-2: if any signature does not use SIGHASH_NONE, Outputs Modifiable is clear.
pub fn validate_outputs_modifiable_flag(psbt: &PsbtContext) -> Result<(), String> {
    let flags = modifiable_flags(psbt).unwrap_or(0);
    if flags & OUTPUTS_MODIFIABLE != 0 && sighash_types(psbt).iter().any(|h| h & 0x1f != SIGHASH_NONE) {
        return Err("outputs are modifiable but a signature commits to outputs".into());
    }
    Ok(())
}

/// GEN-T-2: if any signature uses SIGHASH_SINGLE, a present
/// PSBT_GLOBAL_TX_MODIFIABLE has Has SIGHASH_SINGLE set.
pub fn validate_sighash_single_flag(psbt: &PsbtContext) -> Result<(), String> {
    let Some(flags) = modifiable_flags(psbt) else { return Ok(()) };
    if flags & HAS_SIGHASH_SINGLE == 0 && sighash_types(psbt).iter().any(|h| h & 0x1f == SIGHASH_SINGLE) {
        return Err("a signature uses SIGHASH_SINGLE but the Has SIGHASH_SINGLE flag is clear".into());
    }
    Ok(())
}
