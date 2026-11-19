//! Validation rules for BIP-322 generic signed message PSBTs.

use bitcoin_hashes::Hash;
use crate::algebra::CheckOutcome;
use crate::context::{records, value_u32, PsbtContext, GLOBAL_TX_VERSION, IN_TAP_LEAF_SCRIPT, OUT_AMOUNT, OUT_SCRIPT};
use crate::rules::input_output::signature_sighash;
use crate::silent_payments::{final_witness, input_signatures, is_p2tr, is_segwit_v2_or_later, spent_script};
use crate::taproot::tagged_hash;

pub const GLOBAL_GENERIC_SIGNED_MESSAGE: u64 = 0x09;

/// Computes the to_spend txid for a BIP-322 message and challenge scriptPubKey.
pub fn bip322_to_spend_txid(message: &[u8], challenge: &[u8]) -> [u8; 32] {
    let message_hash = tagged_hash("BIP0322-signed-message", message);
    let mut script_sig = vec![0x00, 0x20];
    script_sig.extend_from_slice(&message_hash);

    let mut raw_tx = Vec::new();
    // nVersion = 0
    raw_tx.extend_from_slice(&0u32.to_le_bytes());
    // vin count = 1
    raw_tx.push(0x01);
    // vin[0].prevout.hash = 000...000
    raw_tx.extend_from_slice(&[0u8; 32]);
    // vin[0].prevout.n = 0xFFFFFFFF
    raw_tx.extend_from_slice(&0xffffffffu32.to_le_bytes());
    // scriptSig
    crate::encoding::put_compact_size(&mut raw_tx, script_sig.len());
    raw_tx.extend_from_slice(&script_sig);
    // nSequence = 0
    raw_tx.extend_from_slice(&0u32.to_le_bytes());
    // vout count = 1
    raw_tx.push(0x01);
    // vout[0].nValue = 0
    raw_tx.extend_from_slice(&0i64.to_le_bytes());
    // vout[0].scriptPubKey = challenge
    crate::encoding::put_compact_size(&mut raw_tx, challenge.len());
    raw_tx.extend_from_slice(challenge);
    // nLockTime = 0
    raw_tx.extend_from_slice(&0u32.to_le_bytes());

    bitcoin_hashes::sha256d::Hash::hash(&raw_tx).to_byte_array()
}

/// The to_sign transaction's version and outputs, from the unsigned transaction
/// (v0) or the global and output fields (v2). None when an output has no script.
fn to_sign_shape(psbt: &PsbtContext) -> Option<(u32, Vec<(i64, Vec<u8>)>)> {
    if let Some(tx) = psbt.psbt.unsigned_tx() {
        return Some((tx.version, tx.outputs.into_iter().map(|o| (o.amount, o.script_pubkey)).collect()));
    }
    let version = value_u32(psbt.psbt.global(), GLOBAL_TX_VERSION)?;
    let outputs = psbt
        .outputs()
        .iter()
        .map(|o| {
            let amount = i64::from_le_bytes(o.value(OUT_AMOUNT)?.try_into().ok()?);
            Some((amount, o.value(OUT_SCRIPT)?.to_vec()))
        })
        .collect::<Option<_>>()?;
    Some((version, outputs))
}

/// Whether `psbt` is a BIP-322 message-signing PSBT: it has
/// PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE, its first input spends output 0 of to_spend
/// for that message and the input's spent script, and its only output has value 0
/// and script OP_RETURN. Err when recognition needs the first input's spent output.
pub fn is_bip322(psbt: &PsbtContext) -> Result<bool, String> {
    let Some(msg) = crate::context::value(psbt.psbt.global(), GLOBAL_GENERIC_SIGNED_MESSAGE) else {
        return Ok(false);
    };
    let Some(input0) = psbt.inputs().into_iter().next() else {
        return Ok(false);
    };
    let (prev_txid, prev_vout) = input0.prevout();
    let Some((_, outputs)) = to_sign_shape(psbt) else {
        return Ok(false);
    };
    if prev_vout != 0 || outputs != [(0, vec![0x6a])] {
        return Ok(false);
    }
    let Some(spent) = input0.spent_output() else {
        return Err("BIP-322 recognition needs the first input's spent output".into());
    };
    Ok(prev_txid == bip322_to_spend_txid(msg, &spent.script_pubkey))
}

/// Runs `check` on a recognized BIP-322 PSBT; an ordinary PSBT is not applicable.
fn when_bip322(psbt: &PsbtContext, check: impl FnOnce() -> CheckOutcome) -> CheckOutcome {
    match is_bip322(psbt) {
        Ok(true) => check(),
        Ok(false) => CheckOutcome::NotApplicable,
        Err(e) => CheckOutcome::Incomplete(e),
    }
}

/// GEN-MSG-1: In a BIP-322 PSBT, the first input's PSBT_IN_WITNESS_UTXO, when present,
/// MUST be output 0 of to_spend, whose amount is 0.
pub fn validate_bip322_challenge_utxo(psbt: &PsbtContext) -> CheckOutcome {
    when_bip322(psbt, || match psbt.inputs()[0].witness_utxo() {
        None => CheckOutcome::NotApplicable,
        Some(out) if out.amount == 0 => CheckOutcome::Verified,
        Some(out) => CheckOutcome::Failed(format!("BIP-322 first input's witness UTXO has amount {}, not 0", out.amount)),
    })
}

/// GEN-MSG-2: In a BIP-322 PSBT, every input after the first MUST have a
/// PSBT_IN_WITNESS_UTXO or PSBT_IN_NON_WITNESS_UTXO, except that the non-witness UTXO
/// may be omitted when an earlier input spending the same transaction has it.
pub fn validate_bip322_proof_of_funds_utxos(psbt: &PsbtContext) -> CheckOutcome {
    when_bip322(psbt, || {
        let inputs = psbt.inputs();
        if inputs.len() == 1 {
            return CheckOutcome::NotApplicable;
        }
        for input in &inputs[1..] {
            let shared = inputs[..input.index].iter().any(|e| e.prevout().0 == input.prevout().0 && e.non_witness_utxo().is_some());
            if input.witness_utxo().is_none() && input.non_witness_utxo().is_none() && !shared {
                return CheckOutcome::Failed(format!("BIP-322 proof-of-funds input {} has no UTXO", input.index));
            }
        }
        CheckOutcome::Verified
    })
}

/// GEN-MSG-3: In a BIP-322 PSBT, every signature MUST use SIGHASH_ALL, or SIGHASH_DEFAULT
/// on an input that spends a P2TR output.
pub fn validate_bip322_sighash(psbt: &PsbtContext) -> CheckOutcome {
    when_bip322(psbt, || {
        let mut outcome = CheckOutcome::NotApplicable;
        for input in psbt.inputs() {
            let p2tr = spent_script(&input).is_ok_and(|s| is_p2tr(&s));
            for sig in input_signatures(&input) {
                match signature_sighash(&sig) {
                    Some(1) => {}
                    Some(0) if p2tr => {}
                    t => return CheckOutcome::Failed(format!("BIP-322 input {} has a signature with sighash type {t:?}", input.index)),
                }
                outcome = CheckOutcome::Verified;
            }
        }
        outcome
    })
}

/// GEN-MSG-4: A BIP-322 PSBT that uses an upgradeable feature is inconclusive, reported
/// as Incomplete: a to_sign version other than 0 or 2, an input spending a Segwit
/// version above 1, an annex in a final witness, or a leaf version other than 0xc0.
pub fn validate_bip322_upgradeable_rules(psbt: &PsbtContext) -> CheckOutcome {
    when_bip322(psbt, || {
        let inconclusive = |what: String| CheckOutcome::Incomplete(format!("BIP-322 inconclusive: {what}"));
        if let Some((version, _)) = to_sign_shape(psbt) {
            if version != 0 && version != 2 {
                return inconclusive(format!("to_sign version {version} is not 0 or 2"));
            }
        }
        for input in psbt.inputs() {
            let i = input.index;
            if spent_script(&input).is_ok_and(|s| is_segwit_v2_or_later(&s)) {
                return inconclusive(format!("input {i} spends a Segwit version above 1"));
            }
            let stack = final_witness(&input);
            if spent_script(&input).is_ok_and(|s| is_p2tr(&s)) && stack.len() >= 2 && stack.last().unwrap().first() == Some(&0x50) {
                return inconclusive(format!("input {i} has an annex"));
            }
            let leaf_versions = records(input.map(), IN_TAP_LEAF_SCRIPT).filter_map(|r| r.value.last().copied());
            if leaf_versions.into_iter().any(|v| v != 0xc0) {
                return inconclusive(format!("input {i} has a leaf version other than 0xc0"));
            }
        }
        CheckOutcome::Verified
    })
}
