pub mod constructor;
pub mod creator;
pub mod catalog;
pub mod combiner;
pub mod extractor;
pub mod finalizer;
pub mod framing;
pub mod global;
pub mod input_output;
pub mod sending;
pub mod signer;
pub mod spending;

use crate::algebra::Bip;
use crate::encoding::Map;
use crate::registry::{check_record, fields, lookup, Scope};

/// Every known field in `map` has the key data and value format its type defines.
fn check_formats(map: &Map, scope: Scope) -> Result<(), String> {
    for record in map {
        if let Some(field) = lookup(scope, record.key_type) {
            check_record(field, &record.key_data, &record.value)
                .map_err(|e| format!("{}: {e}", field.name))?;
        }
    }
    Ok(())
}

/// `map` holds every field `version` requires, or a known field that replaces
/// it, and none it excludes.
fn check_versions(map: &Map, scope: Scope, version: u32, bips: &[Bip]) -> Result<(), String> {
    let present = |key_type| map.iter().any(|r| r.key_type == key_type);
    for field in fields(scope) {
        if present(field.key_type) && field.excluded_in.contains(&version) {
            return Err(format!("{} is excluded in PSBTv{version}", field.name));
        }
        let replaced = field.replaced_by.iter().any(|&t| bips.contains(&Bip::Bip375) && lookup(scope, t).is_some() && present(t));
        if !present(field.key_type) && !replaced && field.required_in.contains(&version) {
            return Err(format!("{} is required in PSBTv{version}", field.name));
        }
    }
    Ok(())
}

pub mod taproot;

pub mod musig;

pub mod dnssec;

pub mod message;

pub mod p2c;
