use std::collections::HashSet;

use super::{check_formats, check_versions};
use crate::encoding::{Map, Psbt};
use crate::registry::Scope;

// Keys MUST be unique within a map.
pub fn validate_unique_keys(map: &Map) -> Result<(), String> {
    let mut seen = HashSet::new();
    for r in map {
        if !seen.insert((r.key_type, &r.key_data)) {
            return Err(format!("duplicate key of type {:#04x}", r.key_type));
        }
    }
    Ok(())
}

// Every known global field MUST have the key data and value format its type defines. (Table 1)
pub fn validate_global_field_formats(psbt: &Psbt) -> Result<(), String> {
    check_formats(psbt.global(), Scope::Global, &psbt.bips)
}

// The PSBT version MUST be 0 or 2.
pub fn validate_version(psbt: &Psbt) -> Result<(), String> {
    match psbt.version() {
        0 | 2 => Ok(()),
        v => Err(format!("unsupported version {v}")),
    }
}

// The global map MUST include every field its version requires and no field its version excludes. (Table 1)
pub fn validate_global_field_versions(psbt: &Psbt) -> Result<(), String> {
    check_versions(psbt.global(), Scope::Global, psbt.version(), &psbt.bips)
}

// Every scriptSig in the unsigned transaction MUST be empty.
pub fn validate_unsigned_tx_unsigned(psbt: &Psbt) -> Result<(), String> {
    let tx = psbt.unsigned_tx().unwrap();
    match tx.inputs.iter().position(|i| !i.script_sig.is_empty()) {
        Some(i) => Err(format!("input {i} has a scriptSig")),
        None => Ok(()),
    }
}

// After the global map, a PSBT MUST contain exactly one map per input followed by one map per output.
pub fn validate_map_count(psbt: &Psbt) -> Result<(), String> {
    let (inputs, outputs) = psbt.counts();
    let found = psbt.maps.len() - 1;
    if found != inputs + outputs {
        return Err(format!("{inputs} inputs and {outputs} outputs need {} maps, found {found}", inputs + outputs));
    }
    Ok(())
}
