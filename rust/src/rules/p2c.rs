//! Validation rules for BIP-372 Pay-to-Contract (P2C) PSBT fields.

use bitcoin_hashes::{hash160, Hash};
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, ProjectivePoint, Scalar};

use crate::algebra::CheckOutcome;
use crate::context::{records, InputContext, IN_P2C_TWEAK, IN_REDEEM_SCRIPT, IN_WITNESS_SCRIPT};
use crate::silent_payments::is_p2tr;

/// The compressed key P + tG, or None when P is not a point or t is not a scalar.
fn tweaked_key(original: &[u8], tweak: &[u8]) -> Option<[u8; 33]> {
    let p = AffinePoint::from_encoded_point(&k256::EncodedPoint::from_bytes(original).ok()?).into_option()?;
    let t = Scalar::from_repr(<[u8; 32]>::try_from(tweak).ok()?.into()).into_option()?;
    let q = (ProjectivePoint::from(p) + ProjectivePoint::GENERATOR * t).to_affine();
    q.to_encoded_point(true).as_bytes().try_into().ok()
}

/// Whether `script` commits to `key`: as a P2PKH or P2WPKH key hash, or as a
/// 33-byte push (P2PK, bare scripts, and redeem or witness scripts).
fn commits_to(script: &[u8], key: &[u8; 33]) -> bool {
    let hash = hash160::Hash::hash(key).to_byte_array();
    let p2pkh = script.len() == 25 && script[..3] == [0x76, 0xa9, 0x14] && script[3..23] == hash && script[23..] == [0x88, 0xac];
    let p2wpkh = script.len() == 22 && script[..2] == [0x00, 0x14] && script[2..] == hash;
    let push = script.windows(34).any(|w| w[0] == 0x21 && w[1..] == key[..]);
    p2pkh || p2wpkh || push
}

/// GEN-P2C-1: For each PSBT_IN_P2C_TWEAK, the original key plus the tweak times G
/// MUST be a key the input's spent script, redeem script, or witness script commits
/// to. Taproot spends are not covered: BIP372 leaves them unresolved.
pub fn validate_p2c_tweak_commitment(input: &InputContext) -> CheckOutcome {
    if records(input.map(), IN_P2C_TWEAK).next().is_none() {
        return CheckOutcome::NotApplicable;
    }
    let Some(spent) = input.spent_output() else {
        return CheckOutcome::Incomplete(format!("input {} has P2C tweaks but its spent output is unavailable", input.index));
    };
    if is_p2tr(&spent.script_pubkey) {
        // TODO: BIP372 (Draft) does not define Taproot P2C tweak application; revisit when upstream resolves it.
        return CheckOutcome::Incomplete(format!("input {} P2C tweak on a Taproot spend is unresolved in BIP372", input.index));
    }

    let mut scripts = vec![spent.script_pubkey];
    scripts.extend(input.value(IN_REDEEM_SCRIPT).map(<[u8]>::to_vec));
    scripts.extend(input.value(IN_WITNESS_SCRIPT).map(<[u8]>::to_vec));

    for record in records(input.map(), IN_P2C_TWEAK) {
        let Some(key) = tweaked_key(&record.key_data, &record.value) else {
            return CheckOutcome::Failed(format!("input {} P2C tweak is not a valid scalar", input.index));
        };
        if !scripts.iter().any(|s| commits_to(s, &key)) {
            return CheckOutcome::Failed(format!(
                "input {} tweaked P2C key is not committed to by its spent, redeem, or witness script",
                input.index
            ));
        }
    }
    CheckOutcome::Verified
}
