use std::collections::HashSet;

use super::{check_formats, check_versions};
use crate::encoding::{Map, Psbt};
use crate::registry::Scope;

/// Checks GEN-F-4: each decoded map has unique `(key_type, key_data)` keys.
///
/// Requires a decoded map; applies to every scope and version, including unknown
/// fields. Returns `Err` on a repeated key even if values differ, otherwise
/// `Ok(())`. Keys in different maps are independent.
pub fn validate_unique_keys(map: &Map) -> Result<(), String> {
    let mut seen = HashSet::new();
    for r in map {
        if !seen.insert((r.key_type, &r.key_data)) {
            return Err(format!("duplicate key of type {:#04x}", r.key_type));
        }
    }
    Ok(())
}

/// Checks the registry-backed part of GEN-F-5 for present global fields.
///
/// Requires a framed, decoded PSBT with a global map. Returns `Err` for a known
/// field's invalid key data or value, otherwise `Ok(())`. Enabled BIPs select
/// known fields; unknown types are ignored. Presence, version restrictions and
/// empty unsigned-transaction scriptSigs are separate checks.
pub fn validate_global_field_formats(psbt: &Psbt) -> Result<(), String> {
    check_formats(psbt.global(), Scope::Global)
}

/// Checks the specification's version scope: PSBTv0 or PSBTv2 only.
///
/// Requires a global map and validated global field formats. An absent version
/// means zero. Returns `Ok(())` for 0 or 2, otherwise `Err`; required and
/// excluded fields are checked separately.
pub fn validate_version(psbt: &Psbt) -> Result<(), String> {
    match psbt.version() {
        0 | 2 => Ok(()),
        v => Err(format!("unsupported version {v}")),
    }
}

/// Checks GEN-ST-2: required global fields exist and excluded fields do not.
///
/// Requires unique keys, valid global field formats and a supported version.
/// Returns `Err` for a missing required or present excluded field, otherwise
/// `Ok(())`, using the enabled BIPs' registry and registered replacements.
/// This does not establish map counts or transaction semantics.
pub fn validate_global_field_versions(psbt: &Psbt) -> Result<(), String> {
    check_versions(psbt.global(), Scope::Global, psbt.version(), &psbt.bips)
}

/// Checks the GEN-F-5 unsigned-transaction requirement of empty scriptSigs.
///
/// Applies when an unsigned transaction is present; requires its field format
/// to be valid. Returns `Err` for any nonempty scriptSig, otherwise `Ok(())`.
/// It does not check other transaction properties or field-version rules.
pub fn validate_unsigned_tx_unsigned(psbt: &Psbt) -> Result<(), String> {
    let tx = psbt.unsigned_tx().unwrap();
    match tx.inputs.iter().position(|i| !i.script_sig.is_empty()) {
        Some(i) => Err(format!("input {i} has a scriptSig")),
        None => Ok(()),
    }
}

/// Checks GEN-ST-3: exactly one map follows for each input and each output.
///
/// Requires a global map, valid global formats, a supported version and the
/// required version-specific count source. Returns `Err` when the remaining
/// map count differs from inputs plus outputs, otherwise `Ok(())`. Assignment
/// is positional; map contents are checked separately.
pub fn validate_map_count(psbt: &Psbt) -> Result<(), String> {
    let (inputs, outputs) = psbt.counts();
    let found = psbt.maps.len() - 1;
    if found != inputs + outputs {
        return Err(format!("{inputs} inputs and {outputs} outputs need {} maps, found {found}", inputs + outputs));
    }
    Ok(())
}
