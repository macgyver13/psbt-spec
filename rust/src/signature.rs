//! Signature validity. Every rule that requires a valid signature calls one of
//! these functions, and each says whether the check was performed. BIP340 and
//! ECDSA are performed with `k256`. A scheme that would need cryptography this reference
//! does not carry is declared instead: its function names the check a
//! conforming implementation performs and returns `NotPerformed`, which rules
//! report as `Incomplete`.

use k256::ecdsa::{self, signature::hazmat::PrehashVerifier};
use k256::schnorr::{Signature, VerifyingKey};
use musig2::secp::{MaybeScalar, Point};
use musig2::{AggNonce, KeyAggContext, PubNonce};
use dnssec_prover::rr::{Name, RR};
use dnssec_prover::ser::parse_rr_stream;
use dnssec_prover::validation::verify_rr_stream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    Valid,
    Invalid,
    /// The check a conforming implementation performs, which this reference does not.
    NotPerformed(&'static str),
}

/// A BIP340 Schnorr signature over a 32-byte message by a 32-byte x-only public key.
pub fn verify_bip340(xonly_pubkey: &[u8; 32], msg: &[u8], sig_bytes: &[u8; 64]) -> Validity {
    let valid = VerifyingKey::from_bytes(xonly_pubkey)
        .ok()
        .zip(Signature::try_from(sig_bytes.as_slice()).ok())
        .is_some_and(|(key, sig)| key.verify_raw(msg, &sig).is_ok());
    if valid { Validity::Valid } else { Validity::Invalid }
}

/// A strict DER (BIP66) ECDSA signature by a SEC1 public key over a 32-byte
/// signature hash, checked with `k256`. A high-S signature is normalized
/// first, as consensus accepts it; low S is only a relay policy.
pub fn verify_ecdsa(pubkey: &[u8], msg: &[u8; 32], der: &[u8]) -> Validity {
    let valid = ecdsa::VerifyingKey::from_sec1_bytes(pubkey)
        .ok()
        .zip(ecdsa::Signature::from_der(der).ok())
        .is_some_and(|(key, sig)| key.verify_prehash(msg, &sig.normalize_s().unwrap_or(sig)).is_ok());
    if valid { Validity::Valid } else { Validity::Invalid }
}

/// A BIP327 partial signature by `participant`, checked with PartialSigVerify
/// (the `musig2` crate) against the session's key aggregation context, with its
/// tweaks applied, the aggregate nonce, the participant's public nonce, and the
/// 32-byte message. Inputs the registry has not validated are Invalid.
pub fn verify_musig2_partial(
    key_agg: &KeyAggContext,
    agg_nonce: &AggNonce,
    participant: &[u8],
    pubnonce: &[u8],
    msg: &[u8; 32],
    psig: &[u8],
) -> Validity {
    let decoded = Point::from_slice(participant)
        .ok()
        .zip(PubNonce::from_bytes(pubnonce).ok())
        .zip(MaybeScalar::from_slice(psig).ok());
    let valid = decoded.is_some_and(|((key, nonce), sig)| {
        musig2::verify_partial(key_agg, sig, agg_nonce, key, &nonce, msg).is_ok()
    });
    if valid { Validity::Valid } else { Validity::Invalid }
}

/// An RFC 9102 DNSSEC proof, checked with `dnssec-prover` from the root to the TXT
/// records at `label`, with every RRSIG's inception no later than `time` and its
/// expiry no earlier than `time - expiry_allowance` (Unix seconds). Returns the
/// verified TXT RDATA at `label`, CNAME and DNAME resolved, each with its
/// character-strings concatenated in RDATA order. Empty unless Valid.
pub fn verify_dnssec_proof(label: &str, proof: &[u8], time: u64, expiry_allowance: u64) -> (Validity, Vec<Vec<u8>>) {
    let Ok(rrs) = parse_rr_stream(proof) else { return (Validity::Invalid, Vec::new()) };
    let Ok(verified) = verify_rr_stream(&rrs) else { return (Validity::Invalid, Vec::new()) };
    if verified.valid_from > time || verified.expires.saturating_add(expiry_allowance) < time {
        return (Validity::Invalid, Vec::new());
    }
    let Ok(name) = Name::try_from(label) else { return (Validity::Invalid, Vec::new()) };
    let txts = verified
        .resolve_name(&name)
        .into_iter()
        .filter_map(|rr| match rr {
            RR::Txt(txt) => Some(txt.data.iter().collect()),
            _ => None,
        })
        .collect();
    (Validity::Valid, txts)
}
