//! BIP-341 Taproot signature messages, tweaks and control blocks. Signature
//! validity goes through `crate::signature`.

use bitcoin_hashes::{sha256, Hash, HashEngine};
use k256::schnorr::VerifyingKey;
use crate::encoding::{put_compact_size, Transaction, TxOut};

pub const SIGHASH_DEFAULT: u8 = 0x00;
pub const SIGHASH_ALL: u8 = 0x01;
pub const SIGHASH_NONE: u8 = 0x02;
pub const SIGHASH_SINGLE: u8 = 0x03;
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;

/// Whether BIP-341 defines `hash_type`: 0x00 to 0x03 or 0x81 to 0x83.
pub fn valid_hash_type(hash_type: u8) -> bool {
    matches!(hash_type, 0x00..=0x03 | 0x81..=0x83)
}

/// The hash type of a 64- or 65-byte Taproot signature. A 65-byte signature must
/// carry a defined hash type other than SIGHASH_DEFAULT.
pub fn signature_hash_type(sig: &[u8]) -> Result<u8, String> {
    match (sig.len(), sig.last()) {
        (64, _) => Ok(SIGHASH_DEFAULT),
        (65, Some(&t)) if t != SIGHASH_DEFAULT && valid_hash_type(t) => Ok(t),
        (65, Some(t)) => Err(format!("hash type {t:#04x} is not valid in a 65-byte signature")),
        (n, _) => Err(format!("expected a 64 or 65 byte signature, got {n} bytes")),
    }
}

/// BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg).
pub fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut engine = sha256::Hash::engine();
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);
    engine.input(msg);
    *sha256::Hash::from_engine(engine).as_byte_array()
}

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    *sha256::Hash::hash(data).as_byte_array()
}

/// Computes the BIP-341 Taproot signature message (sigMsg) and sighash digest.
pub fn taproot_sigmsg(
    tx: &Transaction,
    input_index: usize,
    spent_utxos: &[TxOut],
    hash_type: u8,
    leaf_hash: Option<(&[u8; 32], u32)>,
    annex: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    if !valid_hash_type(hash_type) {
        return Err(format!("hash type {hash_type:#04x} is not defined by BIP-341"));
    }
    if input_index >= tx.inputs.len() {
        return Err(format!("input index {input_index} out of bounds"));
    }
    if spent_utxos.len() != tx.inputs.len() {
        return Err(format!(
            "spent_utxos length {} does not match tx inputs {}",
            spent_utxos.len(),
            tx.inputs.len()
        ));
    }

    let anyone_can_pay = (hash_type & SIGHASH_ANYONECANPAY) != 0;
    let mode = hash_type & 0x03;

    let mut msg = Vec::new();

    // 1. Epoch (0x00)
    msg.push(0x00);

    // 2. Control byte: hash_type
    msg.push(hash_type);

    // 3. Transaction version (4 bytes, little-endian)
    msg.extend_from_slice(&tx.version.to_le_bytes());

    // 4. nLockTime (4 bytes, little-endian)
    msg.extend_from_slice(&tx.locktime.to_le_bytes());

    // 5. If not ANYONECANPAY:
    if !anyone_can_pay {
        // sha_prevouts
        let mut prevouts = Vec::new();
        for input in &tx.inputs {
            prevouts.extend_from_slice(&input.txid);
            prevouts.extend_from_slice(&input.vout.to_le_bytes());
        }
        msg.extend_from_slice(&sha256_hash(&prevouts));

        // sha_amounts
        let mut amounts = Vec::new();
        for utxo in spent_utxos {
            amounts.extend_from_slice(&utxo.amount.to_le_bytes());
        }
        msg.extend_from_slice(&sha256_hash(&amounts));

        // sha_scriptpubkeys
        let mut spks = Vec::new();
        for utxo in spent_utxos {
            put_compact_size(&mut spks, utxo.script_pubkey.len());
            spks.extend_from_slice(&utxo.script_pubkey);
        }
        msg.extend_from_slice(&sha256_hash(&spks));

        // sha_sequences
        let mut sequences = Vec::new();
        for input in &tx.inputs {
            sequences.extend_from_slice(&input.sequence.to_le_bytes());
        }
        msg.extend_from_slice(&sha256_hash(&sequences));
    }

    // 6. Outputs commitment
    if mode != SIGHASH_NONE && mode != SIGHASH_SINGLE {
        let mut outputs = Vec::new();
        for out in &tx.outputs {
            outputs.extend_from_slice(&out.amount.to_le_bytes());
            put_compact_size(&mut outputs, out.script_pubkey.len());
            outputs.extend_from_slice(&out.script_pubkey);
        }
        msg.extend_from_slice(&sha256_hash(&outputs));
    }

    // 7. Spend type: (ext_flag * 2) + annex_present
    let annex_present = if annex.is_some() { 1u8 } else { 0u8 };
    let ext_flag = if leaf_hash.is_some() { 1u8 } else { 0u8 };
    let spend_type = (ext_flag << 1) | annex_present;
    msg.push(spend_type);

    // 8. Input specific data
    if anyone_can_pay {
        let input = &tx.inputs[input_index];
        msg.extend_from_slice(&input.txid);
        msg.extend_from_slice(&input.vout.to_le_bytes());
        msg.extend_from_slice(&spent_utxos[input_index].amount.to_le_bytes());
        put_compact_size(&mut msg, spent_utxos[input_index].script_pubkey.len());
        msg.extend_from_slice(&spent_utxos[input_index].script_pubkey);
        msg.extend_from_slice(&input.sequence.to_le_bytes());
    } else {
        msg.extend_from_slice(&(input_index as u32).to_le_bytes());
    }

    // 9. If annex present:
    if let Some(annex_bytes) = annex {
        let mut a = Vec::new();
        put_compact_size(&mut a, annex_bytes.len());
        a.extend_from_slice(annex_bytes);
        msg.extend_from_slice(&sha256_hash(&a));
    }

    // 10. If SINGLE:
    if mode == SIGHASH_SINGLE {
        if input_index >= tx.outputs.len() {
            return Err(format!("SIGHASH_SINGLE input {input_index} exceeds output count {}", tx.outputs.len()));
        }
        let out = &tx.outputs[input_index];
        let mut single_out = Vec::new();
        single_out.extend_from_slice(&out.amount.to_le_bytes());
        put_compact_size(&mut single_out, out.script_pubkey.len());
        single_out.extend_from_slice(&out.script_pubkey);
        msg.extend_from_slice(&sha256_hash(&single_out));
    }

    // 11. If script path:
    if let Some((l_hash, code_sep_pos)) = leaf_hash {
        msg.extend_from_slice(l_hash);
        msg.push(0x00); // key version for tapscript
        msg.extend_from_slice(&code_sep_pos.to_le_bytes());
    }

    Ok(msg)
}

/// Computes the BIP-341 TapSighash digest.
pub fn taproot_sighash(
    tx: &Transaction,
    input_index: usize,
    spent_utxos: &[TxOut],
    hash_type: u8,
    leaf_hash: Option<(&[u8; 32], u32)>,
    annex: Option<&[u8]>,
) -> Result<[u8; 32], String> {
    let sigmsg = taproot_sigmsg(tx, input_index, spent_utxos, hash_type, leaf_hash, annex)?;
    Ok(tagged_hash("TapSighash", &sigmsg))
}

use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, ProjectivePoint, Scalar};

/// Computes the TapTweak for an internal public key and optional Merkle root.
pub fn tap_tweak(internal_key: &[u8; 32], merkle_root: Option<&[u8; 32]>) -> [u8; 32] {
    let mut msg = Vec::with_capacity(64);
    msg.extend_from_slice(internal_key);
    if let Some(root) = merkle_root {
        msg.extend_from_slice(root);
    }
    tagged_hash("TapTweak", &msg)
}

/// Computes the tweaked Taproot output key Q = P + int(hash(P || m))G.
/// Returns (tweaked_xonly, parity).
pub fn taproot_output_key(internal_key: &[u8; 32], merkle_root: Option<&[u8; 32]>) -> Option<([u8; 32], bool)> {
    let mut sec1 = [0u8; 33];
    sec1[0] = 0x02;
    sec1[1..].copy_from_slice(internal_key);
    let p = AffinePoint::from_encoded_point(&k256::EncodedPoint::from_bytes(&sec1).ok()?).into_option()?;
    let tweak_bytes = tap_tweak(internal_key, merkle_root);
    let tweak = Scalar::from_repr(tweak_bytes.into()).into_option()?;
    let q = (ProjectivePoint::from(p) + ProjectivePoint::GENERATOR * tweak).to_affine();
    let q_encoded = q.to_encoded_point(false);
    let mut xonly = [0u8; 32];
    xonly.copy_from_slice(&q_encoded.as_bytes()[1..33]);
    let odd_y = q_encoded.as_bytes()[64] & 1 != 0;
    Some((xonly, odd_y))
}

/// Computes the output key for a leaf script and control block according to BIP-341.
pub fn verify_taproot_control_block(
    output_key: &[u8; 32],
    control_block: &[u8],
    leaf_script: &[u8],
    leaf_version: u8,
) -> bool {
    if control_block.len() < 33 || (control_block.len() - 33) % 32 != 0 {
        return false;
    }
    let internal_key: &[u8; 32] = control_block[1..33].try_into().unwrap();
    let mut leaf_msg = vec![leaf_version];
    put_compact_size(&mut leaf_msg, leaf_script.len());
    leaf_msg.extend_from_slice(leaf_script);
    let mut node = tagged_hash("TapLeaf", &leaf_msg);

    for sibling in control_block[33..].chunks_exact(32) {
        let (lo, hi) = if node[..] <= *sibling {
            (&node[..], sibling)
        } else {
            (sibling, &node[..])
        };
        let mut branch_msg = Vec::with_capacity(64);
        branch_msg.extend_from_slice(lo);
        branch_msg.extend_from_slice(hi);
        node = tagged_hash("TapBranch", &branch_msg);
    }

    if let Some((q, parity)) = taproot_output_key(internal_key, Some(&node)) {
        let expected_parity = (control_block[0] & 1) != 0;
        q == *output_key && parity == expected_parity
    } else {
        false
    }
}

/// The BIP-341 signature message digest an input's Taproot signature of
/// `hash_type` signs: key path when `leaf_hash` is None, otherwise script path for
/// that leaf (no code separator executed). Missing transaction data is
/// `Incomplete`; an undefined hash type or input is `Failed`.
pub fn input_signature_message(
    input: &crate::context::InputContext,
    hash_type: u8,
    leaf_hash: Option<&[u8; 32]>,
    annex: Option<&[u8]>,
) -> Result<[u8; 32], crate::algebra::CheckOutcome> {
    use crate::algebra::CheckOutcome;
    let Some(tx) = crate::context::signing_tx(&input.psbt) else {
        return Err(CheckOutcome::Incomplete(format!("input {} signature needs the complete unsigned transaction", input.index)));
    };
    let spent = if hash_type & SIGHASH_ANYONECANPAY != 0 {
        // Only this input's spent output is committed; the others are never read.
        let Some(own) = input.spent_output() else {
            return Err(CheckOutcome::Incomplete(format!("input {} signature needs its spent output", input.index)));
        };
        vec![own; tx.inputs.len()]
    } else {
        let Some(all) = crate::context::spent_outputs(&input.psbt) else {
            return Err(CheckOutcome::Incomplete(format!("input {} signature needs every input's spent output", input.index)));
        };
        all
    };
    taproot_sighash(&tx, input.index, &spent, hash_type, leaf_hash.map(|h| (h, u32::MAX)), annex)
        .map_err(|e| CheckOutcome::Failed(format!("input {}: {e}", input.index)))
}

/// Checks a Taproot signature from a PSBT input against the BIP-341 signature
/// message: key path when `leaf_hash` is None, otherwise script path for that leaf
/// (no code separator executed). `annex` is the final witness's annex, if any;
/// PSBT signature fields carry none. Missing transaction data returns `Incomplete`.
pub fn check_input_signature(
    input: &crate::context::InputContext,
    sig: &[u8],
    xonly_key: &[u8; 32],
    leaf_hash: Option<&[u8; 32]>,
    annex: Option<&[u8]>,
) -> crate::algebra::CheckOutcome {
    use crate::algebra::CheckOutcome;
    use crate::signature::Validity;
    let hash_type = match signature_hash_type(sig) {
        Ok(t) => t,
        Err(e) => return CheckOutcome::Failed(format!("input {}: {e}", input.index)),
    };
    let digest = match input_signature_message(input, hash_type, leaf_hash, annex) {
        Ok(d) => d,
        Err(outcome) => return outcome,
    };
    let sig64: &[u8; 64] = sig[..64].try_into().unwrap();
    match crate::signature::verify_bip340(xonly_key, &digest, sig64) {
        Validity::Valid => CheckOutcome::Verified,
        Validity::Invalid => CheckOutcome::Failed(format!("input {} Taproot signature does not verify", input.index)),
        Validity::NotPerformed(check) => CheckOutcome::Incomplete(format!("input {}: {check}", input.index)),
    }
}

/// Whether `version` can be a BIP-341 leaf version: even, since the control block's
/// low bit carries parity, and not 0x50, the annex tag.
pub fn valid_leaf_version(version: u8) -> bool {
    version & 1 == 0 && version != 0x50
}

/// Whether `bytes` is a BIP-340 x-only public key: 32 bytes that lift to the curve.
pub fn is_xonly_key(bytes: &[u8]) -> bool {
    bytes.len() == 32 && VerifyingKey::from_bytes(bytes).is_ok()
}

/// The BIP-341 TapLeaf hash of a leaf script.
pub fn leaf_hash(version: u8, script: &[u8]) -> [u8; 32] {
    let mut msg = vec![version];
    put_compact_size(&mut msg, script.len());
    msg.extend_from_slice(script);
    tagged_hash("TapLeaf", &msg)
}

/// A PSBT_OUT_TAP_TREE value rebuilt in depth-first order: its Merkle root and
/// leaf hashes. Fails unless the tuples form exactly one complete tree with no
/// depth above 128 and valid leaf versions.
pub fn tap_tree(value: &[u8]) -> Result<([u8; 32], Vec<[u8; 32]>), String> {
    let mut reader = crate::encoding::Reader::new(value);
    let mut leaves = Vec::new();
    let mut stack: Vec<(u8, [u8; 32])> = Vec::new();
    while !reader.is_empty() {
        if stack.len() == 1 && stack[0].0 == 0 {
            return Err("tuples follow a complete tree".into());
        }
        let depth = reader.u8()?;
        let version = reader.u8()?;
        let script = reader.var_bytes()?;
        if depth > 128 {
            return Err(format!("leaf depth {depth} exceeds 128"));
        }
        if !valid_leaf_version(version) {
            return Err(format!("leaf version {version:#04x} is not valid"));
        }
        let leaf = leaf_hash(version, script);
        leaves.push(leaf);
        stack.push((depth, leaf));
        while let [.., (d1, h1), (d2, h2)] = stack[..] {
            if d1 != d2 || d2 == 0 {
                break;
            }
            stack.truncate(stack.len() - 2);
            let (lo, hi) = if h1 <= h2 { (h1, h2) } else { (h2, h1) };
            stack.push((d2 - 1, tagged_hash("TapBranch", &[lo, hi].concat())));
        }
        if stack.windows(2).any(|w| w[1].0 < w[0].0) {
            return Err("tuples are not in depth-first order".into());
        }
    }
    match stack[..] {
        [(0, root)] => Ok((root, leaves)),
        [] => Err("tree has no leaves".into()),
        _ => Err("tuples do not form a complete tree".into()),
    }
}
