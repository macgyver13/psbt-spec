use crate::encoding::{scan, ScanError, MAGIC};

// A PSBT MUST begin with the magic bytes 0x70736274FF.
pub fn validate_magic(bytes: &[u8]) -> Result<(), String> {
    if !bytes.starts_with(&MAGIC) {
        return Err("missing magic bytes".into());
    }
    Ok(())
}

// Every record MUST be complete: each compact size, including the key type,
// minimally encoded, and each key and value exactly its stated length.
pub fn validate_records(bytes: &[u8]) -> Result<(), String> {
    match scan(bytes) {
        Err(ScanError::Record(detail)) => Err(detail),
        _ => Ok(()),
    }
}

// The serialization MUST end with a 0x00 separator closing its last map,
// and MUST contain at least the global map.
pub fn validate_maps_terminated(bytes: &[u8]) -> Result<(), String> {
    match scan(bytes) {
        Err(ScanError::Unterminated) => Err("last map is not terminated".into()),
        _ => Ok(()),
    }
}
