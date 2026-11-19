use crate::context::{unique_id, TransitionContext};
use crate::encoding::{Map, Record};

fn has_key(map: &Map, record: &Record) -> bool {
    map.iter().any(|r| r.key_type == record.key_type && r.key_data == record.key_data)
}

/// Checks ROLE-B-1, a precondition: every PSBT the Combiner was given has the
/// same transaction identifier.
///
/// Requires individually validated PSBTs and enough context for `unique_id`:
/// v0 unsigned transactions, or v2 outpoints, amounts, scripts and determinable
/// locktime. Enabled BIP375 substitutes SP info for output scripts. Returns
/// `Err` for any differing identifier, otherwise `Ok(())`, including one or no
/// sources. That the result keeps the identifier follows from ROLE-B-2.
pub fn validate_shared_unique_id(t: &TransitionContext) -> Result<(), String> {
    let Some(first) = t.before.first() else { return Ok(()) };
    let id = unique_id(first);
    match t.before.iter().position(|p| unique_id(p) != id) {
        Some(i) => Err(format!("PSBT {i} has a different unique identifier")),
        None => Ok(()),
    }
}

// The combined PSBT MUST hold every key that a PSBT it combines holds, in the same map.
pub fn validate_combined_keeps_keys(t: &TransitionContext) -> Result<(), String> {
    for (i, psbt) in t.before.iter().enumerate() {
        for (m, map) in psbt.psbt.maps.iter().enumerate() {
            if let Some(r) = map.iter().find(|r| !has_key(&t.after.psbt.maps[m], r)) {
                return Err(format!("map {m} drops key type {:#04x} from PSBT {i}", r.key_type));
            }
        }
    }
    Ok(())
}

// Every key-value pair in the combined PSBT MUST come from the same map of a PSBT it combines.
pub fn validate_combined_adds_nothing(t: &TransitionContext) -> Result<(), String> {
    for (m, map) in t.after.psbt.maps.iter().enumerate() {
        if let Some(r) = map.iter().find(|r| !t.before.iter().any(|p| p.psbt.maps[m].contains(r))) {
            return Err(format!("map {m} has a key-value pair of type {:#04x} from no combined PSBT", r.key_type));
        }
    }
    Ok(())
}
