//! BIP-352 and BIP-374 primitives, and the input eligibility, public key
//! recovery and output derivation the BIP-375 sending rules share.

use bitcoin_hashes::{hash160, sha256, Hash};
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{FieldBytes, ProjectivePoint, PublicKey, Scalar, U256};

use crate::context::{
    keyed, records, InputContext, OutputContext, PsbtContext, GLOBAL_SP_ECDH_SHARE, IN_BIP32_DERIVATION,
    IN_FINAL_SCRIPTSIG, IN_FINAL_SCRIPTWITNESS, IN_PARTIAL_SIG, IN_REDEEM_SCRIPT, IN_SP_ECDH_SHARE, IN_TAP_INTERNAL_KEY,
    IN_TAP_KEY_SIG, IN_TAP_MERKLE_ROOT, IN_TAP_SCRIPT_SIG, OUT_SCRIPT, OUT_SP_V0_INFO,
};
use crate::encoding::{decode_exact, is_p2sh, p2sh_script, put_compact_size, read_witness, Reader};

/// The BIP-341 NUMS point H. A taproot output with this internal key has no key path.
const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a,
    0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag = sha256::Hash::hash(tag.as_bytes()).to_byte_array();
    sha256::Hash::hash(&[&tag[..], &tag, msg].concat()).to_byte_array()
}

fn scalar(bytes: [u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(bytes))
}

pub fn point(bytes: &[u8]) -> Option<ProjectivePoint> {
    PublicKey::from_sec1_bytes(bytes).ok().map(|k| k.to_projective())
}

pub fn compressed(p: &ProjectivePoint) -> Vec<u8> {
    p.to_affine().to_encoded_point(true).as_bytes().to_vec()
}

fn xonly(p: &ProjectivePoint) -> Vec<u8> {
    compressed(p)[1..].to_vec()
}

pub fn is_p2tr(spk: &[u8]) -> bool {
    spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20
}

pub fn is_p2wpkh(spk: &[u8]) -> bool {
    spk.len() == 22 && spk[0] == 0x00 && spk[1] == 0x14
}

pub fn is_p2pkh(spk: &[u8]) -> bool {
    spk.len() == 25 && spk[..3] == [0x76, 0xa9, 0x14] && spk[23..] == [0x88, 0xac]
}

/// A segwit version 2 through 16 witness program.
pub fn is_segwit_v2_or_later(spk: &[u8]) -> bool {
    (4..=42).contains(&spk.len()) && (0x52..=0x60).contains(&spk[0]) && spk[1] as usize + 2 == spk.len()
}

fn p2wpkh_script(pubkey: &[u8]) -> Vec<u8> {
    [&[0x00, 0x14][..], &hash160::Hash::hash(pubkey).to_byte_array()].concat()
}

/// True if a P2PKH, P2WPKH or P2SH-P2WPKH scriptPubKey commits to `pubkey`.
fn commits_to(spk: &[u8], pubkey: &[u8]) -> bool {
    let p2pkh = [&[0x76, 0xa9, 0x14][..], &hash160::Hash::hash(pubkey).to_byte_array(), &[0x88, 0xac]].concat();
    spk == p2pkh || spk == p2wpkh_script(pubkey) || spk == p2sh_script(&p2wpkh_script(pubkey))
}

/// The data pushes of a push-only script, or none if it is empty, truncated,
/// or has any opcode other than a push.
fn pushes(script: Option<&[u8]>) -> Vec<Vec<u8>> {
    let mut r = Reader::new(script.unwrap_or_default());
    let mut items = Vec::new();
    while !r.is_empty() {
        let len = match r.u8().unwrap() {
            n @ 0x00..=0x4b => Ok(n as usize),
            0x4c => r.u8().map(|n| n as usize),
            0x4d => r.take(2).map(|b| u16::from_le_bytes(b.try_into().unwrap()) as usize),
            0x4e => r.u32().map(|n| n as usize),
            _ => return Vec::new(),
        };
        match len.and_then(|n| r.take(n)) {
            Ok(data) => items.push(data.to_vec()),
            Err(_) => return Vec::new(),
        }
    }
    items
}

fn final_witness(input: &InputContext) -> Vec<Vec<u8>> {
    input.value(IN_FINAL_SCRIPTWITNESS).map(|w| decode_exact(w, read_witness).unwrap()).unwrap_or_default()
}

fn drop_annex(stack: &mut Vec<Vec<u8>>) {
    if stack.len() >= 2 && stack.last().unwrap().first() == Some(&0x50) {
        stack.pop();
    }
}

/// The scriptPubKey an input spends, from PSBT_IN_WITNESS_UTXO if present,
/// otherwise from PSBT_IN_NON_WITNESS_UTXO.
pub fn spent_script(input: &InputContext) -> Result<Vec<u8>, String> {
    match input.witness_utxo().or_else(|| input.spent_output()) {
        Some(out) => Ok(out.script_pubkey),
        None => Err(format!("input {} has no spent scriptPubKey", input.index)),
    }
}

/// The BIP-341 x-only output key for the NUMS internal key and a script tree merkle root.
fn nums_output_key(merkle_root: &[u8]) -> Vec<u8> {
    let internal = point(&[&[0x02][..], &NUMS_H].concat()).unwrap();
    let tweak = scalar(tagged_hash("TapTweak", &[&NUMS_H[..], merkle_root].concat()));
    xonly(&(internal + ProjectivePoint::GENERATOR * tweak))
}

/// True if a finalized script path witness spends from the NUMS internal key,
/// which the leaf script and merkle path must reproduce from the output key.
fn final_witness_nums_claim(input: &InputContext, output_key: &[u8]) -> bool {
    let mut stack = final_witness(input);
    drop_annex(&mut stack);
    let [.., leaf, control] = stack.as_slice() else { return false };
    if control.len() < 33 || (control.len() - 33) % 32 != 0 || control[1..33] != NUMS_H {
        return false;
    }
    let mut leaf_msg = vec![control[0] & 0xfe];
    put_compact_size(&mut leaf_msg, leaf.len());
    leaf_msg.extend(leaf);
    let mut node = tagged_hash("TapLeaf", &leaf_msg);
    for sibling in control[33..].chunks(32) {
        let (lo, hi) = if node[..] <= *sibling { (&node[..], sibling) } else { (sibling, &node[..]) };
        node = tagged_hash("TapBranch", &[lo, hi].concat());
    }
    nums_output_key(&node) == output_key
}

/// The redeemScript of a P2SH input, from PSBT_IN_REDEEM_SCRIPT or, once the
/// Input Finalizer has pruned it, the last push of the final scriptSig.
fn redeem_script(input: &InputContext) -> Option<Vec<u8>> {
    match input.value(IN_REDEEM_SCRIPT) {
        Some(rs) => Some(rs.to_vec()),
        None => pushes(input.value(IN_FINAL_SCRIPTSIG)).pop(),
    }
}

/// Whether an input contributes to the silent payment shared secret: a P2PKH,
/// P2WPKH, P2SH-P2WPKH or P2TR spend, except a P2TR output that proves it has
/// the NUMS internal key.
pub fn is_eligible(input: &InputContext) -> Result<bool, String> {
    let spk = spent_script(input)?;
    if is_p2tr(&spk) {
        let output_key = &spk[2..];
        let nums_fields = input.value(IN_TAP_INTERNAL_KEY) == Some(&NUMS_H[..])
            && input.value(IN_TAP_MERKLE_ROOT).is_some_and(|root| nums_output_key(root) == output_key);
        return Ok(!nums_fields && !final_witness_nums_claim(input, output_key));
    }
    if is_p2sh(&spk) {
        return match redeem_script(input) {
            Some(rs) => Ok(is_p2wpkh(&rs)),
            None => Err(format!("P2SH input {} has no redeemScript", input.index)),
        };
    }
    Ok(is_p2pkh(&spk) || is_p2wpkh(&spk))
}

/// The public key of an eligible input: the P2TR output key, or a key the
/// spent script commits to from a BIP32 derivation or the final scriptSig or
/// witness. `None` for an ineligible input or one with no such key.
pub fn input_pubkey(input: &InputContext) -> Result<Option<ProjectivePoint>, String> {
    if !is_eligible(input)? {
        return Ok(None);
    }
    let spk = spent_script(input)?;
    if is_p2tr(&spk) {
        return Ok(point(&[&[0x02], &spk[2..]].concat()));
    }
    let derived = records(input.map(), IN_BIP32_DERIVATION).map(|r| r.key_data.clone());
    let finalized = match final_witness(input).pop() {
        Some(item) => Some(item),
        None if input.value(IN_FINAL_SCRIPTWITNESS).is_some() => None,
        None => pushes(input.value(IN_FINAL_SCRIPTSIG)).pop(),
    };
    Ok(derived.chain(finalized).find(|k| k.len() == 33 && commits_to(&spk, k)).and_then(|k| point(&k)))
}

/// Every signature an input carries, as (signature, is_schnorr): partial and
/// taproot signatures, and those in the final scriptSig and witness of the
/// spends the Input Finalizer builds.
pub fn input_signatures(input: &InputContext) -> Vec<(Vec<u8>, bool)> {
    let map = input.map();
    let mut sigs: Vec<_> = records(map, IN_PARTIAL_SIG).map(|r| (r.value.clone(), false)).collect();
    sigs.extend(input.value(IN_TAP_KEY_SIG).map(|s| (s.to_vec(), true)));
    sigs.extend(records(map, IN_TAP_SCRIPT_SIG).map(|r| (r.value.clone(), true)));
    let Ok(spk) = spent_script(input) else { return sigs };
    let mut stack = final_witness(input);
    let pushes = pushes(input.value(IN_FINAL_SCRIPTSIG));
    if is_p2tr(&spk) {
        drop_annex(&mut stack);
        // TODO: a script path witness's signatures depend on its leaf script,
        // which is not interpreted here, so only a key path signature is checked.
        if stack.len() == 1 {
            sigs.push((stack.remove(0), true));
        }
    } else if is_p2wpkh(&spk) || (is_p2sh(&spk) && !stack.is_empty()) {
        if stack.len() == 2 {
            sigs.push((stack.remove(0), false));
        }
    } else if is_p2pkh(&spk) {
        if pushes.len() == 2 {
            sigs.push((pushes[0].clone(), false));
        }
    } else if is_p2sh(&spk) && pushes.len() > 2 {
        sigs.extend(pushes[1..pushes.len() - 1].iter().map(|s| (s.clone(), false)));
    }
    sigs
}

/// BIP-374 VerifyProof with the generator G and no message.
pub fn dleq_verify(a: &ProjectivePoint, b: &ProjectivePoint, c: &ProjectivePoint, proof: &[u8]) -> bool {
    let parse = |bytes: &[u8]| {
        let bytes: [u8; 32] = bytes.try_into().unwrap();
        Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(bytes)))
    };
    let (Some(e), Some(s)) = (parse(&proof[..32]), parse(&proof[32..])) else { return false };
    let g = ProjectivePoint::GENERATOR;
    let r1 = g * s - *a * e;
    let r2 = *b * s - *c * e;
    if bool::from(r1.is_identity()) || bool::from(r2.is_identity()) {
        return false;
    }
    let msg: Vec<u8> = [a, b, c, &g, &r1, &r2].into_iter().flat_map(compressed).collect();
    scalar(tagged_hash("BIP0374/challenge", &msg)) == e
}

/// The silent payment outputs, as (index, scan key, spend key).
pub fn sp_outputs(psbt: &PsbtContext) -> Vec<(usize, Vec<u8>, Vec<u8>)> {
    let info = |o: &OutputContext| o.value(OUT_SP_V0_INFO).map(|v| (o.index, v[..33].to_vec(), v[33..].to_vec()));
    psbt.outputs().iter().filter_map(info).collect()
}

/// The distinct scan keys of the silent payment outputs, sorted.
pub fn scan_keys(psbt: &PsbtContext) -> Vec<Vec<u8>> {
    let mut keys: Vec<_> = sp_outputs(psbt).into_iter().map(|(_, scan, _)| scan).collect();
    keys.sort();
    keys.dedup();
    keys
}

pub fn has_sp_outputs(psbt: &PsbtContext) -> bool {
    !sp_outputs(psbt).is_empty()
}

/// Whether some silent payment output for `scan_key` already has PSBT_OUT_SCRIPT.
pub fn scan_key_has_script(psbt: &PsbtContext, scan_key: &[u8]) -> bool {
    let outputs = psbt.outputs();
    sp_outputs(psbt).iter().any(|(i, scan, _)| scan == scan_key && outputs[*i].value(OUT_SCRIPT).is_some())
}

/// The ECDH share for `scan_key` and the sum of the public keys it covers: the
/// global share with every eligible input's key, or else the sum of the
/// eligible inputs' shares with their keys. `None` when either is unavailable.
pub fn ecdh_and_pubkey_sum(
    psbt: &PsbtContext,
    scan_key: &[u8],
) -> Result<Option<(ProjectivePoint, ProjectivePoint)>, String> {
    let mut shares = None;
    let mut pubkeys = None;
    let add = |sum: &mut Option<ProjectivePoint>, p: ProjectivePoint| *sum = Some(sum.map_or(p, |s| s + p));
    if let Some(global) = keyed(psbt.psbt.global(), GLOBAL_SP_ECDH_SHARE, scan_key) {
        for input in psbt.inputs() {
            if !is_eligible(&input)? {
                continue;
            }
            match input_pubkey(&input)? {
                Some(p) => add(&mut pubkeys, p),
                None => return Ok(None),
            }
        }
        return Ok(pubkeys.map(|p| (point(global).unwrap(), p)));
    }
    for input in psbt.inputs() {
        let Some(share) = keyed(input.map(), IN_SP_ECDH_SHARE, scan_key) else { continue };
        if !is_eligible(&input)? {
            continue;
        }
        add(&mut shares, point(share).unwrap());
        if let Some(p) = input_pubkey(&input)? {
            add(&mut pubkeys, p);
        }
    }
    Ok(shares.zip(pubkeys))
}

/// A silent payment output's index and its derived script.
pub type DerivedScript = (usize, Option<Vec<u8>>);

/// The BIP-352 output script of every silent payment output, or `None` where
/// the ECDH share or input public keys are unavailable. k counts per scan key
/// over the outputs sorted by PSBT_OUT_SP_V0_INFO, then by index.
pub fn derived_scripts(psbt: &PsbtContext) -> Result<Vec<DerivedScript>, String> {
    let lowest_outpoint = psbt
        .inputs()
        .iter()
        .map(|i| {
            let (txid, vout) = i.prevout();
            [&txid[..], &vout.to_le_bytes()].concat()
        })
        .min();
    let mut outputs = sp_outputs(psbt);
    outputs.sort_by(|(i, scan, spend), (j, scan2, spend2)| (scan, spend, i).cmp(&(scan2, spend2, j)));
    let mut k_values: Vec<(Vec<u8>, u32)> = Vec::new();
    let mut scripts = Vec::new();
    for (index, scan, spend) in outputs {
        let (Some((ecdh, pubkey_sum)), Some(outpoint)) = (ecdh_and_pubkey_sum(psbt, &scan)?, &lowest_outpoint) else {
            scripts.push((index, None));
            continue;
        };
        let k = match k_values.iter_mut().find(|(s, _)| *s == scan) {
            Some((_, k)) => {
                *k += 1;
                *k - 1
            }
            None => {
                k_values.push((scan, 1));
                0
            }
        };
        let input_hash = scalar(tagged_hash("BIP0352/Inputs", &[&outpoint[..], &compressed(&pubkey_sum)].concat()));
        let shared_secret = compressed(&(ecdh * input_hash));
        let t_k = scalar(tagged_hash("BIP0352/SharedSecret", &[&shared_secret[..], &k.to_be_bytes()].concat()));
        let p_k = point(&spend).unwrap() + ProjectivePoint::GENERATOR * t_k;
        scripts.push((index, Some([&[0x51, 0x20][..], &xonly(&p_k)].concat())));
    }
    Ok(scripts)
}

/// BIP-376: whether the spend key tweaked by `tweak`, B + tweak·G, has the
/// x-only output key `output_key`. Negating d for an odd y does not change x.
pub fn tweaked_spend_key_matches(spend_key: &[u8], tweak: &[u8], output_key: &[u8]) -> bool {
    let Some(b) = point(spend_key) else { return false };
    let q = b + ProjectivePoint::GENERATOR * scalar(tweak.try_into().unwrap());
    !bool::from(q.is_identity()) && xonly(&q) == output_key
}
