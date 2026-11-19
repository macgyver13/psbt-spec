//! Validation rules for BIP-371 Taproot fields and role obligations.

use crate::algebra::CheckOutcome;
use crate::context::{
    records, InputContext, OutputContext, IN_FINAL_SCRIPTWITNESS, IN_TAP_INTERNAL_KEY, IN_TAP_KEY_SIG,
    IN_TAP_LEAF_SCRIPT, IN_TAP_MERKLE_ROOT, IN_TAP_SCRIPT_SIG, OUT_SCRIPT, OUT_TAP_BIP32_DERIVATION,
    OUT_TAP_INTERNAL_KEY, OUT_TAP_TREE,
};
use crate::encoding::Reader;
use crate::silent_payments::is_p2tr;
use crate::taproot::{check_input_signature, tap_tree, taproot_output_key, verify_taproot_control_block};

/// GEN-TR-1: For each input with PSBT_IN_TAP_LEAF_SCRIPT, every control block
/// MUST reconstruct to the spent P2TR key.
pub fn validate_taproot_control_block_commitment(input: &InputContext) -> CheckOutcome {
    if records(input.map(), IN_TAP_LEAF_SCRIPT).next().is_none() {
        return CheckOutcome::NotApplicable;
    }
    let Some(utxo) = input.spent_output() else {
        return CheckOutcome::Incomplete(format!(
            "input {} has taproot leaf scripts but no spent output to verify commitments",
            input.index
        ));
    };

    if !is_p2tr(&utxo.script_pubkey) {
        return CheckOutcome::Failed(format!(
            "input {} has taproot leaf scripts but its spent output is not P2TR",
            input.index
        ));
    }

    let output_key: &[u8; 32] = utxo.script_pubkey[2..].try_into().unwrap();

    for record in records(input.map(), IN_TAP_LEAF_SCRIPT) {
        let control_block = &record.key_data;
        let leaf_val = &record.value;
        if leaf_val.is_empty() {
            return CheckOutcome::Failed(format!("input {} has empty leaf script value", input.index));
        }
        let leaf_version = leaf_val[leaf_val.len() - 1];
        let leaf_script = &leaf_val[..leaf_val.len() - 1];

        let cb_version = control_block.first().map(|b| b & 0xfe);
        if cb_version.is_some_and(|v| v != leaf_version) {
            return CheckOutcome::Failed(format!(
                "input {} control block leaf version {:#04x} differs from leaf script version {leaf_version:#04x}",
                input.index,
                cb_version.unwrap()
            ));
        }
        if !verify_taproot_control_block(output_key, control_block, leaf_script, leaf_version) {
            return CheckOutcome::Failed(format!(
                "input {} control block does not commit to the spent P2TR output key",
                input.index
            ));
        }
    }

    CheckOutcome::Verified
}

/// Whether `script` is the P2TR output for `internal` tweaked by `root`. Without a
/// root, a mismatch is inconclusive: the PSBT may simply omit the script tree.
fn check_commitment(subject: &str, internal: &[u8], root: Option<&[u8; 32]>, script: &[u8]) -> CheckOutcome {
    if !is_p2tr(script) {
        return CheckOutcome::Failed(format!("{subject} has a Taproot internal key but its script is not P2TR"));
    }
    let Some((key, _)) = internal.try_into().ok().and_then(|k| taproot_output_key(k, root)) else {
        return CheckOutcome::Failed(format!("{subject} internal key is not an x-only public key"));
    };
    match (key[..] == script[2..], root) {
        (true, _) => CheckOutcome::Verified,
        (false, Some(_)) => CheckOutcome::Failed(format!("{subject} internal key and script tree do not produce its output key")),
        (false, None) => CheckOutcome::Incomplete(format!(
            "{subject} internal key alone does not produce its output key, and the script tree is not supplied"
        )),
    }
}

/// GEN-TR-2: PSBT_IN_TAP_INTERNAL_KEY, tweaked by PSBT_IN_TAP_MERKLE_ROOT when present,
/// MUST produce the spent P2TR output key. Without a Merkle root, a key-only match is
/// verified and a mismatch is incomplete.
pub fn validate_taproot_key_commitments(input: &InputContext) -> CheckOutcome {
    let Some(internal) = input.value(IN_TAP_INTERNAL_KEY) else {
        return CheckOutcome::NotApplicable;
    };
    let Some(utxo) = input.spent_output() else {
        return CheckOutcome::Incomplete(format!("input {} has a Taproot internal key but no spent output", input.index));
    };
    let root = input.value(IN_TAP_MERKLE_ROOT).and_then(|r| <&[u8; 32]>::try_from(r).ok());
    check_commitment(&format!("input {}", input.index), internal, root, &utxo.script_pubkey)
}

/// The script of an output: PSBT_OUT_SCRIPT (v2) or the unsigned transaction's (v0).
fn output_script(output: &OutputContext) -> Option<Vec<u8>> {
    match &output.psbt.unsigned_tx {
        Some(tx) => tx.outputs.get(output.index).map(|o| o.script_pubkey.clone()),
        None => output.value(OUT_SCRIPT).map(<[u8]>::to_vec),
    }
}

/// GEN-TR-3: PSBT_OUT_TAP_INTERNAL_KEY, tweaked by the root of PSBT_OUT_TAP_TREE when
/// present, MUST produce the output's P2TR key. Without a tree, a key-only match is
/// verified and a mismatch is incomplete.
pub fn validate_taproot_output_commitment(output: &OutputContext) -> CheckOutcome {
    let Some(internal) = output.value(OUT_TAP_INTERNAL_KEY) else {
        return CheckOutcome::NotApplicable;
    };
    let Some(script) = output_script(output) else {
        return CheckOutcome::Incomplete(format!("output {} has a Taproot internal key but no script yet", output.index));
    };
    let root = output.value(OUT_TAP_TREE).and_then(|t| tap_tree(t).ok()).map(|(root, _)| root);
    check_commitment(&format!("output {}", output.index), internal, root.as_ref(), &script)
}

/// GEN-TR-4: Each leaf hash in PSBT_OUT_TAP_BIP32_DERIVATION MUST be a leaf of
/// PSBT_OUT_TAP_TREE. Without a tree the hashes cannot be checked.
pub fn validate_taproot_output_derivation_leaves(output: &OutputContext) -> CheckOutcome {
    let hashes: Vec<Vec<u8>> = records(output.map(), OUT_TAP_BIP32_DERIVATION)
        .flat_map(|r| {
            let mut reader = Reader::new(&r.value);
            let count = reader.compact_size().unwrap_or(0) as usize;
            (0..count).filter_map(|_| reader.take(32).ok().map(<[u8]>::to_vec)).collect::<Vec<_>>()
        })
        .collect();
    if hashes.is_empty() {
        return CheckOutcome::NotApplicable;
    }
    let Some((_, leaves)) = output.value(OUT_TAP_TREE).and_then(|t| tap_tree(t).ok()) else {
        return CheckOutcome::Incomplete(format!("output {} derivation names leaves but PSBT_OUT_TAP_TREE is absent", output.index));
    };
    match hashes.iter().all(|h| leaves.iter().any(|l| l[..] == h[..])) {
        true => CheckOutcome::Verified,
        false => CheckOutcome::Failed(format!("output {} derivation names a leaf that is not in PSBT_OUT_TAP_TREE", output.index)),
    }
}

/// ROLE-F-9: For an input finalized via script path, the final witness MUST consist of
/// the script inputs, followed by the leaf script and control block. After removing an
/// annex, a P2TR witness with two or more elements is a script-path spend whose control
/// block must commit to the spent output key. Field cleanup is BIP174 guidance and is
/// not checked here.
pub fn validate_taproot_script_path_finalization(input: &InputContext) -> CheckOutcome {
    let Some(witness_bytes) = input.value(IN_FINAL_SCRIPTWITNESS) else {
        return CheckOutcome::NotApplicable;
    };
    let Ok(mut stack) = crate::encoding::decode_exact(witness_bytes, crate::encoding::read_witness) else {
        return CheckOutcome::NotApplicable;
    };
    if stack.len() >= 2 && stack.last().unwrap().first() == Some(&0x50) {
        stack.pop();
    }
    if stack.len() < 2 {
        return CheckOutcome::NotApplicable;
    }
    let control_block = &stack[stack.len() - 1];
    let leaf_script = &stack[stack.len() - 2];
    let shaped = control_block.len() >= 33 && (control_block.len() - 33) % 32 == 0 && control_block.len() <= 33 + 128 * 32;

    let Some(utxo) = input.spent_output() else {
        if shaped {
            return CheckOutcome::Incomplete(format!(
                "input {} has a script-path-shaped witness but its spent output is unavailable",
                input.index
            ));
        }
        return CheckOutcome::NotApplicable;
    };
    if !is_p2tr(&utxo.script_pubkey) {
        return CheckOutcome::NotApplicable;
    }
    if !shaped {
        return CheckOutcome::Failed(format!(
            "finalized taproot input {} script-path witness has a malformed control block of {} bytes",
            input.index,
            control_block.len()
        ));
    }

    let output_key: &[u8; 32] = utxo.script_pubkey[2..].try_into().unwrap();
    if !verify_taproot_control_block(output_key, control_block, leaf_script, control_block[0] & 0xfe) {
        return CheckOutcome::Failed(format!(
            "finalized taproot input {} control block and leaf script do not commit to the spent output key",
            input.index
        ));
    }
    CheckOutcome::Verified
}

/// ROLE-F-3: each PSBT_IN_TAP_KEY_SIG and PSBT_IN_TAP_SCRIPT_SIG
/// is a BIP340 signature by the spent output key, or by its x-only key for its leaf,
/// under the BIP341 signature message for its hash type. A PSBT itself may carry
/// signatures that do not verify.
pub fn validate_taproot_signatures(input: &InputContext) -> CheckOutcome {
    let key_sig = input.value(IN_TAP_KEY_SIG);
    let script_sigs: Vec<_> = records(input.map(), IN_TAP_SCRIPT_SIG).collect();
    if key_sig.is_none() && script_sigs.is_empty() {
        return CheckOutcome::NotApplicable;
    }
    let Some(spent) = input.spent_output() else {
        return CheckOutcome::Incomplete(format!("input {} has Taproot signatures but its spent output is unavailable", input.index));
    };
    if !is_p2tr(&spent.script_pubkey) {
        return CheckOutcome::Failed(format!("input {} has Taproot signatures but its spent output is not P2TR", input.index));
    }
    let output_key: [u8; 32] = spent.script_pubkey[2..].try_into().unwrap();
    let checks = key_sig.map(|sig| check_input_signature(input, sig, &output_key, None, None)).into_iter().chain(
        script_sigs.iter().map(|r| {
            let key: [u8; 32] = r.key_data[..32].try_into().unwrap();
            let leaf: [u8; 32] = r.key_data[32..].try_into().unwrap();
            check_input_signature(input, &r.value, &key, Some(&leaf), None)
        }),
    );
    let mut outcome = CheckOutcome::Verified;
    for check in checks {
        match check {
            CheckOutcome::Failed(e) => return CheckOutcome::Failed(e),
            CheckOutcome::Incomplete(e) => outcome = CheckOutcome::Incomplete(e),
            _ => {}
        }
    }
    outcome
}

/// ROLE-F-10: For a P2TR input finalized via key path, the final witness MUST be a single
/// signature, followed by any annex, that verifies against the spent output key.
pub fn validate_taproot_key_path_finalization(input: &InputContext) -> CheckOutcome {
    let Some(witness_bytes) = input.value(IN_FINAL_SCRIPTWITNESS) else {
        return CheckOutcome::NotApplicable;
    };
    let Ok(mut stack) = crate::encoding::decode_exact(witness_bytes, crate::encoding::read_witness) else {
        return CheckOutcome::NotApplicable;
    };
    let annex = match stack.len() >= 2 && stack.last().unwrap().first() == Some(&0x50) {
        true => stack.pop(),
        false => None,
    };
    let [sig] = stack.as_slice() else {
        return CheckOutcome::NotApplicable;
    };
    let Some(utxo) = input.spent_output() else {
        if matches!(sig.len(), 64 | 65) {
            return CheckOutcome::Incomplete(format!("input {} has a key-path-shaped witness but its spent output is unavailable", input.index));
        }
        return CheckOutcome::NotApplicable;
    };
    if !is_p2tr(&utxo.script_pubkey) {
        return CheckOutcome::NotApplicable;
    }
    let output_key: [u8; 32] = utxo.script_pubkey[2..].try_into().unwrap();
    check_input_signature(input, sig, &output_key, None, annex.as_deref())
}
