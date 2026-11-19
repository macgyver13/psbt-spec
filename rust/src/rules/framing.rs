use crate::encoding::{scan, ScanError, MAGIC};

/// Checks GEN-F-1: every serialization starts with `70 73 62 74 FF`.
///
/// Accepts arbitrary bytes without prerequisites. Returns `Ok(())` exactly when
/// that prefix is present, otherwise `Err`; trailing bytes are not checked.
pub fn validate_magic(bytes: &[u8]) -> Result<(), String> {
    if !bytes.starts_with(&MAGIC) {
        return Err("missing magic bytes".into());
    }
    Ok(())
}

/// Checks GEN-F-2: records have complete, minimally encoded CompactSizes
/// and exactly the declared key and value lengths.
///
/// Requires the magic check to have passed. Returns `Err` for record decoding
/// errors, otherwise `Ok(())`. Missing magic and unterminated maps are left to
/// the other framing checks; success alone does not permit parsing.
pub fn validate_records(bytes: &[u8]) -> Result<(), String> {
    match scan(bytes) {
        Err(ScanError::Record(detail)) => Err(detail),
        _ => Ok(()),
    }
}

/// Checks GEN-F-3: at least the global map exists and every map terminates.
///
/// Requires magic and record checks to have passed. Returns `Err` for a missing
/// map or final separator, otherwise `Ok(())`. Other scan failures are left to
/// the preceding checks; only all three framing checks establish parseability.
pub fn validate_maps_terminated(bytes: &[u8]) -> Result<(), String> {
    match scan(bytes) {
        Err(ScanError::Unterminated) => Err("last map is not terminated".into()),
        _ => Ok(()),
    }
}
