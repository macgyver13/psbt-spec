//! Legacy and BIP-143 (segwit v0) signature messages for ECDSA signatures.
//! Signature validity goes through `crate::signature`.

use bitcoin_hashes::{sha256d, Hash};
use crate::algebra::CheckOutcome;
use crate::context::{signing_tx, InputContext, IN_WITNESS_SCRIPT};
use crate::encoding::{is_p2sh, is_p2wsh, is_witness_program, put_compact_size, Transaction};
use crate::signature::{verify_ecdsa, Validity};
use crate::silent_payments::{final_witness, is_p2wpkh, redeem_script, spent_script};
use crate::taproot::{SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE};

const OP_CODESEPARATOR: u8 = 0xab;

fn hash(data: &[u8]) -> [u8; 32] {
    sha256d::Hash::hash(data).to_byte_array()
}

fn put_script(out: &mut Vec<u8>, script: &[u8]) {
    put_compact_size(out, script.len());
    out.extend(script);
}

/// The legacy signature hash for input `index` with `script_code` in its place.
/// SIGHASH_SINGLE without a matching output signs the number one, as consensus
/// does. OP_CODESEPARATOR is not removed from `script_code`.
pub fn legacy_sighash(tx: &Transaction, index: usize, script_code: &[u8], hash_type: u32) -> [u8; 32] {
    let base = (hash_type & 0x1f) as u8;
    let anyone = hash_type & u32::from(SIGHASH_ANYONECANPAY) != 0;
    if base == SIGHASH_SINGLE && index >= tx.outputs.len() {
        let mut one = [0; 32];
        one[0] = 1;
        return one;
    }
    let mut out = tx.version.to_le_bytes().to_vec();
    let inputs: Vec<usize> = if anyone { vec![index] } else { (0..tx.inputs.len()).collect() };
    put_compact_size(&mut out, inputs.len());
    for i in inputs {
        let input = &tx.inputs[i];
        out.extend(input.txid);
        out.extend(input.vout.to_le_bytes());
        put_script(&mut out, if i == index { script_code } else { &[] });
        let zeroed = i != index && (base == SIGHASH_NONE || base == SIGHASH_SINGLE);
        out.extend(if zeroed { 0 } else { input.sequence }.to_le_bytes());
    }
    let outputs = match base {
        SIGHASH_NONE => 0,
        SIGHASH_SINGLE => index + 1,
        _ => tx.outputs.len(),
    };
    put_compact_size(&mut out, outputs);
    for (i, o) in tx.outputs[..outputs].iter().enumerate() {
        if base == SIGHASH_SINGLE && i != index {
            out.extend((-1i64).to_le_bytes());
            put_script(&mut out, &[]);
        } else {
            out.extend(o.amount.to_le_bytes());
            put_script(&mut out, &o.script_pubkey);
        }
    }
    out.extend(tx.locktime.to_le_bytes());
    out.extend(hash_type.to_le_bytes());
    hash(&out)
}

/// The BIP-143 signature hash for input `index`, spending `amount` with `script_code`.
pub fn segwit_v0_sighash(tx: &Transaction, index: usize, script_code: &[u8], amount: i64, hash_type: u32) -> [u8; 32] {
    let base = (hash_type & 0x1f) as u8;
    let anyone = hash_type & u32::from(SIGHASH_ANYONECANPAY) != 0;
    let single_or_none = base == SIGHASH_SINGLE || base == SIGHASH_NONE;
    let output = |o: &crate::encoding::TxOut| {
        let mut out = o.amount.to_le_bytes().to_vec();
        put_script(&mut out, &o.script_pubkey);
        out
    };
    let prevouts = if anyone {
        [0; 32]
    } else {
        hash(&tx.inputs.iter().flat_map(|i| [&i.txid[..], &i.vout.to_le_bytes()].concat()).collect::<Vec<_>>())
    };
    let sequences = if anyone || single_or_none {
        [0; 32]
    } else {
        hash(&tx.inputs.iter().flat_map(|i| i.sequence.to_le_bytes()).collect::<Vec<_>>())
    };
    let outputs = if !single_or_none {
        hash(&tx.outputs.iter().flat_map(output).collect::<Vec<_>>())
    } else if base == SIGHASH_SINGLE && index < tx.outputs.len() {
        hash(&output(&tx.outputs[index]))
    } else {
        [0; 32]
    };
    let input = &tx.inputs[index];
    let mut out = tx.version.to_le_bytes().to_vec();
    out.extend(prevouts);
    out.extend(sequences);
    out.extend(input.txid);
    out.extend(input.vout.to_le_bytes());
    put_script(&mut out, script_code);
    out.extend(amount.to_le_bytes());
    out.extend(input.sequence.to_le_bytes());
    out.extend(outputs);
    out.extend(tx.locktime.to_le_bytes());
    out.extend(hash_type.to_le_bytes());
    hash(&out)
}

/// Whether `script` executes OP_CODESEPARATOR, which changes the script code
/// this reference does not track. A truncated push ends the walk.
fn has_code_separator(script: &[u8]) -> bool {
    let mut i = 0;
    while let Some(&op) = script.get(i) {
        let width = match op {
            0x01..=0x4b => op as usize,
            0x4c => 1 + *script.get(i + 1).unwrap_or(&0) as usize,
            0x4d => 2 + script.get(i + 1..i + 3).map_or(0, |b| u16::from_le_bytes([b[0], b[1]]) as usize),
            0x4e => 4 + script.get(i + 1..i + 5).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()) as usize),
            OP_CODESEPARATOR => return true,
            _ => 0,
        };
        i += 1 + width;
    }
    false
}

/// The script code an ECDSA signature on `input` commits to, and whether the
/// spend is segwit v0: the P2WPKH template, the witness script (from
/// PSBT_IN_WITNESS_SCRIPT or the final witness), or for a legacy spend the
/// redeem script or the spent script.
fn script_code(input: &InputContext) -> Result<(Vec<u8>, bool), CheckOutcome> {
    let i = input.index;
    let spk = spent_script(input).map_err(CheckOutcome::Incomplete)?;
    let inner = if is_p2sh(&spk) {
        redeem_script(input).ok_or_else(|| CheckOutcome::Incomplete(format!("input {i} needs its redeem script")))?
    } else {
        spk
    };
    if is_p2wpkh(&inner) {
        return Ok(([&[0x76, 0xa9, 0x14][..], &inner[2..], &[0x88, 0xac]].concat(), true));
    }
    if is_p2wsh(&inner) {
        let script = match input.value(IN_WITNESS_SCRIPT) {
            Some(ws) => ws.to_vec(),
            None => final_witness(input).pop().ok_or_else(|| CheckOutcome::Incomplete(format!("input {i} needs its witness script")))?,
        };
        return Ok((script, true));
    }
    if is_witness_program(&inner) {
        return Err(CheckOutcome::Incomplete(format!("input {i}: an ECDSA signature on a witness version above 0 is not checked")));
    }
    Ok((inner, false))
}

/// Checks an ECDSA signature from a PSBT input (DER with its hash type byte
/// appended) by `pubkey` against the BIP-143 message for a segwit v0 spend, or
/// the legacy message otherwise. Missing transaction data, or a script code
/// with OP_CODESEPARATOR, returns `Incomplete`. The legacy message does not
/// remove the signature from the script code (FindAndDelete), which matters
/// only for a script that contains its own signature.
pub fn check_input_signature(input: &InputContext, sig: &[u8], pubkey: &[u8]) -> CheckOutcome {
    let i = input.index;
    let Some((&hash_type_byte, der)) = sig.split_last() else {
        return CheckOutcome::Failed(format!("input {i}: empty ECDSA signature"));
    };
    let (code, segwit) = match script_code(input) {
        Ok(found) => found,
        Err(outcome) => return outcome,
    };
    if has_code_separator(&code) {
        return CheckOutcome::Incomplete(format!("input {i}: a script code with OP_CODESEPARATOR is not checked"));
    }
    let Some(tx) = signing_tx(&input.psbt) else {
        return CheckOutcome::Incomplete(format!("input {i} signature needs the complete unsigned transaction"));
    };
    let hash_type = u32::from(hash_type_byte);
    let digest = if segwit {
        let Some(spent) = input.spent_output() else {
            return CheckOutcome::Incomplete(format!("input {i} signature needs its spent output"));
        };
        segwit_v0_sighash(&tx, i, &code, spent.amount, hash_type)
    } else {
        legacy_sighash(&tx, i, &code, hash_type)
    };
    match verify_ecdsa(pubkey, &digest, der) {
        Validity::Valid => CheckOutcome::Verified,
        Validity::Invalid => CheckOutcome::Failed(format!("input {i} ECDSA signature does not verify")),
        Validity::NotPerformed(check) => CheckOutcome::Incomplete(format!("input {i}: {check}")),
    }
}
