//! Validation rules for BIP-373 MuSig2 PSBT fields.

use crate::algebra::CheckOutcome;
use crate::context::{
    records, InputContext, PsbtContext, IN_MUSIG2_PARTIAL_SIG, IN_MUSIG2_PARTICIPANT_PUBKEYS, IN_MUSIG2_PUB_NONCE,
    IN_TAP_LEAF_SCRIPT, OUT_MUSIG2_PARTICIPANT_PUBKEYS,
};
use crate::encoding::Map;
use crate::context::{keyed, value, value_u32, IN_SIGHASH_TYPE, IN_TAP_BIP32_DERIVATION, IN_TAP_INTERNAL_KEY, IN_TAP_KEY_SIG, IN_TAP_MERKLE_ROOT, IN_TAP_SCRIPT_SIG};
use crate::signature::{verify_musig2_partial, Validity};
use crate::taproot::input_signature_message;
use musig2::secp::Point;
use musig2::{AggNonce, KeyAggContext, PubNonce};
use crate::encoding::put_compact_size;
use crate::silent_payments::is_p2tr;
use crate::taproot::tagged_hash;

/// The script of the PSBT_IN_TAP_LEAF_SCRIPT record whose tapleaf hash is `leaf_hash`.
fn leaf_script<'a>(input: &'a InputContext, leaf_hash: &[u8]) -> Option<&'a [u8]> {
    records(input.map(), IN_TAP_LEAF_SCRIPT).find_map(|r| {
        let (script, version) = r.value.split_at(r.value.len().checked_sub(1)?);
        let mut msg = version.to_vec();
        put_compact_size(&mut msg, script.len());
        msg.extend_from_slice(script);
        (tagged_hash("TapLeaf", &msg)[..] == *leaf_hash).then_some(script)
    })
}

/// GEN-MS-1: In PSBT_IN_MUSIG2_PUB_NONCE and PSBT_IN_MUSIG2_PARTIAL_SIG key data, the
/// plain public key MUST be the Taproot output key when the tapleaf hash is omitted,
/// and MUST be found in that leaf's script when it is present.
pub fn validate_musig2_plain_keys(input: &InputContext) -> CheckOutcome {
    let keys: Vec<_> = records(input.map(), IN_MUSIG2_PUB_NONCE)
        .chain(records(input.map(), IN_MUSIG2_PARTIAL_SIG))
        .map(|r| r.key_data.as_slice())
        .collect();
    if keys.is_empty() {
        return CheckOutcome::NotApplicable;
    }
    let Some(spent) = input.spent_output() else {
        return CheckOutcome::Incomplete(format!("input {} has MuSig2 nonces or partial signatures but its spent output is unavailable", input.index));
    };
    if !is_p2tr(&spent.script_pubkey) {
        return CheckOutcome::Failed(format!("input {} has MuSig2 nonces or partial signatures but its spent output is not P2TR", input.index));
    }
    let output_key = &spent.script_pubkey[2..];
    for key_data in keys {
        let plain = &key_data[34..66];
        match key_data.get(66..) {
            Some([]) | None if plain != output_key => {
                return CheckOutcome::Failed(format!("input {} MuSig2 plain key without a tapleaf hash is not the Taproot output key", input.index));
            }
            Some(leaf_hash) if !leaf_hash.is_empty() => match leaf_script(input, leaf_hash) {
                None => {
                    return CheckOutcome::Incomplete(format!("input {} MuSig2 tapleaf hash has no PSBT_IN_TAP_LEAF_SCRIPT", input.index));
                }
                Some(script) if !script.windows(32).any(|w| w == plain) => {
                    return CheckOutcome::Failed(format!("input {} MuSig2 plain key is not in the script of its tapleaf", input.index));
                }
                Some(_) => {}
            },
            _ => {}
        }
    }
    CheckOutcome::Verified
}

/// The BIP327 KeyAgg context of `participants`, in the listed order. The registry
/// has already checked that each is a compressed point.
pub fn key_agg_context(participants: &[u8]) -> Result<KeyAggContext, String> {
    let points: Vec<Point> = participants.chunks(33).map(|k| Point::from_slice(k).map_err(|e| e.to_string())).collect::<Result<_, _>>()?;
    KeyAggContext::new(points).map_err(|e| e.to_string())
}

/// Every PSBT_*_MUSIG2_PARTICIPANT_PUBKEYS record of `key_type` in `map` has the
/// KeyAgg result of its participant keys, in order, as its aggregate key.
fn key_aggregation(map: &Map, key_type: u64, what: &str) -> CheckOutcome {
    let mut outcome = CheckOutcome::NotApplicable;
    for record in records(map, key_type) {
        let aggregate: [u8; 33] = match key_agg_context(&record.value) {
            Ok(ctx) => ctx.aggregated_pubkey_untweaked::<Point>().serialize(),
            Err(e) => return CheckOutcome::Failed(format!("{what}: participant keys do not aggregate: {e}")),
        };
        if aggregate[..] != record.key_data[..] {
            return CheckOutcome::Failed(format!("{what}: KeyAgg of the participant keys is not the aggregate key"));
        }
        outcome = CheckOutcome::Verified;
    }
    outcome
}

/// GEN-MS-2: The key of each PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS and
/// PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS MUST be the BIP327 KeyAgg result of the
/// listed participant keys in the listed order.
pub fn validate_musig2_key_aggregation(psbt: &PsbtContext) -> CheckOutcome {
    let inputs = psbt.inputs().into_iter().map(|i| key_aggregation(i.map(), IN_MUSIG2_PARTICIPANT_PUBKEYS, &format!("input {}", i.index)));
    let outputs = psbt.outputs().into_iter().map(|o| key_aggregation(o.map(), OUT_MUSIG2_PARTICIPANT_PUBKEYS, &format!("output {}", o.index)));
    let mut outcome = CheckOutcome::NotApplicable;
    for check in inputs.chain(outputs) {
        match check {
            CheckOutcome::Failed(e) => return CheckOutcome::Failed(e),
            CheckOutcome::Verified => outcome = CheckOutcome::Verified,
            _ => {}
        }
    }
    outcome
}

/// BIP328's chain code for the synthetic xpub of a MuSig2 aggregate key:
/// SHA256("MuSig2MuSig2MuSig2").
const BIP328_CHAIN_CODE: [u8; 32] = [
    0x86, 0x80, 0x87, 0xca, 0x02, 0xa6, 0xf9, 0x74, 0xc4, 0x59, 0x89, 0x24, 0xc3, 0x6b, 0x57, 0x76, 0x2d, 0x32, 0xcb,
    0x45, 0x71, 0x71, 0x67, 0xe3, 0x00, 0x62, 0x2c, 0x71, 0x67, 0xe3, 0x89, 0x65,
];

/// Keys derived from `aggregate` through BIP328: for each PSBT_IN_TAP_BIP32_DERIVATION
/// whose origin fingerprint is the aggregate key's, unhardened BIP32 derivation of
/// the synthetic xpub (`bip32` crate) along its path. Returns each derived x-only
/// key that matches the record's key, with the per-step tweaks in order.
fn bip328_derivations(input: &InputContext, aggregate: &[u8]) -> Vec<([u8; 32], Vec<[u8; 32]>)> {
    use bip32::{ChildNumber, PublicKey};
    let Ok(parent) = k256::PublicKey::from_sec1_bytes(aggregate) else { return Vec::new() };
    let fingerprint = parent.fingerprint();
    let mut found = Vec::new();
    for record in records(input.map(), IN_TAP_BIP32_DERIVATION) {
        // compact-size leaf hash count, leaf hashes, fingerprint, path.
        let Ok((origin_fp, path)) = crate::encoding::decode_exact(&record.value, |r| {
            let n = r.compact_size()? as usize;
            r.take(32 * n)?;
            let fp: [u8; 4] = r.take(4)?.try_into().unwrap();
            let path: Vec<u32> = (0..r.remaining() / 4).map(|_| r.u32()).collect::<Result<_, _>>()?;
            Ok((fp, path))
        }) else { continue };
        if origin_fp != fingerprint {
            continue;
        }
        let (mut key, mut chain_code, mut tweaks) = (parent, BIP328_CHAIN_CODE, Vec::new());
        let derived = path.iter().all(|&index| {
            let Ok(child) = ChildNumber::new(index, false) else { return false };
            let Ok((tweak, next)) = key.derive_tweak(&chain_code, child) else { return false };
            let Ok(child_key) = key.derive_child(tweak) else { return false };
            (key, chain_code) = (child_key, next);
            tweaks.push(tweak);
            true
        });
        let xonly: [u8; 32] = key.to_bytes()[1..].try_into().unwrap();
        if derived && xonly[..] == record.key_data[..] {
            found.push((xonly, tweaks));
        }
    }
    found
}

/// The key aggregation context, with tweaks, of the session whose plain key is
/// `plain` (x-only) for `leaf`. The session's aggregate key is that of a
/// PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS record listing `participant`; the plain key is
/// that aggregate key, or a BIP328 derivation of it, used directly or, on the key
/// path, as the internal key under the Taproot tweak. Returns the context and the
/// participant keys.
fn session(input: &InputContext, participant: &[u8], plain: &[u8], leaf: Option<&[u8]>) -> Result<(KeyAggContext, Vec<u8>), CheckOutcome> {
    let index = input.index;
    let failed = |e: String| CheckOutcome::Failed(format!("input {index}: {e}"));
    let mut listed = false;
    for record in records(input.map(), IN_MUSIG2_PARTICIPANT_PUBKEYS) {
        if !record.value.chunks(33).any(|k| k == participant) {
            continue;
        }
        listed = true;
        let ctx = key_agg_context(&record.value).map_err(failed)?;
        // The untweaked aggregate key, then each BIP328 derivation with its plain tweaks.
        let mut candidates = vec![(record.key_data[1..].to_vec(), ctx.clone())];
        for (derived, tweaks) in bip328_derivations(input, &record.key_data) {
            let mut tweaked = ctx.clone();
            for tweak in tweaks {
                let scalar = musig2::secp::Scalar::from_slice(&tweak).map_err(|e| failed(e.to_string()))?;
                tweaked = tweaked.with_plain_tweak(scalar).map_err(|e| failed(e.to_string()))?;
            }
            candidates.push((derived.to_vec(), tweaked));
        }
        for (key, ctx) in candidates {
            if key == plain {
                return Ok((ctx, record.value.clone()));
            }
            if leaf.is_none() && value(input.map(), IN_TAP_INTERNAL_KEY) == Some(&key[..]) {
                let tweaked = match value(input.map(), IN_TAP_MERKLE_ROOT) {
                    Some(root) => ctx.with_taproot_tweak(root.try_into().unwrap()),
                    None => ctx.with_unspendable_taproot_tweak(),
                }
                .map_err(|e| failed(e.to_string()))?;
                if tweaked.aggregated_pubkey::<Point>().serialize_xonly()[..] == *plain {
                    return Ok((tweaked, record.value.clone()));
                }
            }
        }
    }
    Err(CheckOutcome::Incomplete(match listed {
        true => format!("input {index}: MuSig2 plain key is not the aggregate key, a BIP328 derivation of it, or their Taproot tweak"),
        false => format!("input {index}: no PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS lists the partial signature's participant"),
    }))
}

/// ROLE-F-5: the partial signatures of every MuSig2 session that has no aggregated signature
/// yet, checked with BIP327 PartialSigVerify. A session missing a participant's
/// nonce, or whose plain key cannot be related to a listed aggregate key, is
/// Incomplete. The message uses PSBT_IN_SIGHASH_TYPE, or SIGHASH_DEFAULT without it.
pub fn validate_musig2_partial_signatures(input: &InputContext) -> CheckOutcome {
    let index = input.index;
    let mut outcome = CheckOutcome::NotApplicable;
    for record in records(input.map(), IN_MUSIG2_PARTIAL_SIG) {
        let (participant, plain, leaf) = (&record.key_data[..33], &record.key_data[34..66], record.key_data.get(66..).filter(|l| !l.is_empty()));
        let aggregated = match leaf {
            None => value(input.map(), IN_TAP_KEY_SIG).is_some(),
            Some(leaf) => keyed(input.map(), IN_TAP_SCRIPT_SIG, &[plain, leaf].concat()).is_some(),
        };
        if aggregated {
            continue;
        }
        let check = (|| {
            let (ctx, participants) = session(input, participant, plain, leaf)?;
            let mut nonces = Vec::new();
            for p in participants.chunks(33) {
                let key = [p, &record.key_data[33..]].concat();
                let Some(nonce) = keyed(input.map(), IN_MUSIG2_PUB_NONCE, &key) else {
                    return Err(CheckOutcome::Incomplete(format!("input {index}: a MuSig2 participant has no PSBT_IN_MUSIG2_PUB_NONCE")));
                };
                nonces.push(PubNonce::from_bytes(nonce).map_err(|e| CheckOutcome::Failed(format!("input {index}: {e}")))?);
            }
            let agg_nonce = AggNonce::sum(&nonces);
            let hash_type = value_u32(input.map(), IN_SIGHASH_TYPE).map_or(0, |t| t as u8);
            let leaf: Option<[u8; 32]> = leaf.map(|l| l.try_into().unwrap());
            let msg = input_signature_message(input, hash_type, leaf.as_ref(), None)?;
            let own = keyed(input.map(), IN_MUSIG2_PUB_NONCE, &record.key_data).unwrap_or_default();
            Ok(match verify_musig2_partial(&ctx, &agg_nonce, participant, own, &msg, &record.value) {
                Validity::Valid => CheckOutcome::Verified,
                Validity::Invalid => CheckOutcome::Failed(format!("input {index}: MuSig2 partial signature does not verify")),
                Validity::NotPerformed(c) => CheckOutcome::Incomplete(format!("input {index}: {c}")),
            })
        })();
        match check.unwrap_or_else(|o| o) {
            CheckOutcome::Failed(e) => return CheckOutcome::Failed(e),
            CheckOutcome::Incomplete(e) => outcome = CheckOutcome::Incomplete(e),
            CheckOutcome::Verified if outcome == CheckOutcome::NotApplicable => outcome = CheckOutcome::Verified,
            _ => {}
        }
    }
    outcome
}
