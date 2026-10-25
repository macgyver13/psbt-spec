//! PSBT VALIDITY SPECIFICATION
//!
//! This declarative graph is the executable specification of the invariants
//! that make a PSBT valid under BIP-174 (version 0) and BIP-370 (version 2).
//! Each Rule node names a validation function that fails, with the rule's ID
//! as its error code, if and only if that property does not hold.
//! `render` walks this same graph to produce spec.html.

use crate::algebra::{all, each, from, section, when, with, Bip, BoxNode};
use crate::context::{InputContext, OutputContext, PsbtContext, TransitionContext};
use crate::encoding::{scan, Map, Psbt};
use crate::rule;
use crate::rules::{combiner::*, extractor::*, finalizer::*, framing::*, global::*, input_output::*, sending::*, signer::*, spending::*};
use crate::silent_payments::has_sp_outputs;

/// Splits a PSBT the framing rules accept into maps, noting the enabled BIPs.
pub fn parse(bytes: &[u8], bips: &[Bip]) -> Psbt {
    Psbt { bips: bips.to_vec(), ..scan(bytes).ok().unwrap() }
}
fn maps(psbt: &Psbt) -> Vec<Map> {
    psbt.maps.clone()
}
fn has_unsigned_tx(psbt: &Psbt) -> bool {
    psbt.unsigned_tx().is_some()
}
fn inputs(psbt: &PsbtContext) -> Vec<InputContext> {
    psbt.inputs()
}
fn outputs(psbt: &PsbtContext) -> Vec<OutputContext> {
    psbt.outputs()
}

#[rustfmt::skip]
pub fn validity_rules(bips: &[Bip]) -> BoxNode<[u8]> {
  all(vec![
    section("Framing Rules", all(vec![
      rule!("F01", validate_magic,             "A PSBT MUST begin with the magic bytes 0x70736274FF."),
      rule!("F02", validate_records,           "Every record MUST be complete: each compact size, including the key type, minimally encoded, and each key and value exactly its stated length."),
      rule!("F03", validate_maps_terminated,   "The serialization MUST end with a 0x00 separator closing its last map, and MUST contain at least the global map."),
    ])),
    with({ let bips = bips.to_vec(); move |bytes: &[u8]| parse(bytes, &bips) }, all(vec![
      section("Map Rules", each(maps,
        rule!("M01", validate_unique_keys,     "Keys MUST be unique within a map."))),
      section("Global Rules", all(vec![
        rule!("G01", validate_global_field_formats,  "Every known global field MUST have the key data and value format its type defines. (Table 1)"),
        rule!("G02", validate_version,               "The PSBT version MUST be 0 or 2, where an absent PSBT_GLOBAL_VERSION means 0."),
        rule!("G03", validate_global_field_versions, "The global map MUST include every field its version requires and no field its version excludes. (Table 1)"),
        when("PSBTv0", has_unsigned_tx,
          rule!("G04", validate_unsigned_tx_unsigned, "Every scriptSig in the unsigned transaction MUST be empty.")),
        rule!("G05", validate_map_count,             "After the global map, a PSBT MUST contain exactly one map per input followed by one map per output."),
      ])),
      with(PsbtContext::new, all(vec![
        section("Input Rules", each(inputs, all(vec![
          rule!("I01", validate_input_field_formats,  "Every known input field MUST have the key data and value format its type defines. (Table 1)"),
          rule!("I02", validate_input_field_versions, "An input map MUST include every field its version requires and no field its version excludes. (Table 1)"),
          when("PSBTv2", |i: &InputContext| i.version() == 2, all(vec![
            rule!("I03", validate_required_time_locktime,   "A required time-based lock time MUST be at least 500,000,000."),
            rule!("I04", validate_required_height_locktime, "A required height-based lock time MUST be greater than 0 and less than 500,000,000."),
          ])),
        ]))),
        section("Output Rules", each(outputs, all(vec![
          rule!("O01", validate_output_field_formats,  "Every known output field MUST have the key data and value format its type defines. (Table 1)"),
          rule!("O02", validate_output_field_versions, "An output map MUST include every field its version requires and no field its version excludes. (Table 1)"),
        ]))),
        section("Transaction Rules", when("PSBTv2", |p: &PsbtContext| p.version == 2, all(vec![
          rule!("T01", validate_locktime_determinable,  "The inputs' required lock times MUST share a lock time type, so the transaction lock time can be determined."),
          rule!("T02", validate_inputs_modifiable_flag, "If any signature lacks SIGHASH_ANYONECANPAY, PSBT_GLOBAL_TX_MODIFIABLE MUST have its Inputs Modifiable flag cleared."),
          rule!("T03", validate_outputs_modifiable_flag, "If any signature does not use SIGHASH_NONE, PSBT_GLOBAL_TX_MODIFIABLE MUST have its Outputs Modifiable flag cleared."),
          rule!("T04", validate_sighash_single_flag,    "If any signature uses SIGHASH_SINGLE, a present PSBT_GLOBAL_TX_MODIFIABLE MUST have its Has SIGHASH_SINGLE flag set."),
        ]))),
        section("Silent Payment Sending Rules (BIP-375)", from(Bip::Bip375, bips, all(vec![
          each(outputs,
            rule!("P01", validate_sp_label_has_info,    "An output with PSBT_OUT_SP_V0_LABEL MUST also have PSBT_OUT_SP_V0_INFO.")),
          when("Silent payment outputs", has_sp_outputs, all(vec![
            rule!("P02", validate_ecdh_coverage,        "Once a silent payment output has PSBT_OUT_SCRIPT, its scan key MUST have a global ECDH share, or per-input ECDH shares on at least one input and on every eligible input."),
            rule!("P03", validate_global_dleq_present,  "A global ECDH share for a silent payment output's scan key MUST have a global DLEQ proof."),
            rule!("P04", validate_global_share_pubkeys, "When a silent payment output's scan key has a global ECDH share, the PSBT MUST have an eligible input, and every eligible input MUST have a public key."),
            rule!("P05", validate_global_dleq_proof,    "A global DLEQ proof MUST verify for the sum of the eligible inputs' public keys, the scan key, and the global ECDH share."),
            each(inputs, all(vec![
              rule!("P06", validate_input_dleq_present, "An eligible input's ECDH share for a silent payment output's scan key MUST have a DLEQ proof."),
              rule!("P07", validate_input_share_pubkey, "An eligible input with an ECDH share MUST have a public key."),
              rule!("P08", validate_input_dleq_proof,   "An input DLEQ proof MUST verify for the input's public key, the scan key, and the input's ECDH share."),
              rule!("P09", validate_sp_segwit_version,  "An input MUST NOT spend a segwit version 2 or later output."),
              rule!("P10", validate_sp_sighash_type,    "PSBT_IN_SIGHASH_TYPE MUST be SIGHASH_ALL, or SIGHASH_DEFAULT on a P2TR input."),
              rule!("P11", validate_sp_signatures,      "Every signature an input carries MUST use SIGHASH_ALL, or SIGHASH_DEFAULT for a 64-byte Schnorr signature."),
            ])),
            rule!("P12", validate_sp_tx_unmodifiable,   "Once a silent payment output has PSBT_OUT_SCRIPT, PSBT_GLOBAL_TX_MODIFIABLE MUST have its Inputs Modifiable and Outputs Modifiable flags cleared."),
            rule!("P13", validate_sp_script_derivable,  "A silent payment output with PSBT_OUT_SCRIPT MUST have the ECDH shares and input public keys its derivation needs."),
            rule!("P14", validate_sp_script,            "A silent payment output's PSBT_OUT_SCRIPT MUST equal its BIP-352 output script, with k counted per scan key over the silent payment outputs sorted by PSBT_OUT_SP_V0_INFO, then by index."),
            rule!("P15", validate_sp_no_signature_before_scripts, "An input MUST NOT carry a signature while any output lacks PSBT_OUT_SCRIPT."),
          ])),
        ]))),
        section("Silent Payment Spending Rules (BIP-376)", from(Bip::Bip376, bips, each(inputs, all(vec![
          rule!("R01", validate_sp_finalized_cleared,   "A finalized input MUST NOT keep PSBT_IN_SP_TWEAK or PSBT_IN_SP_SPEND_BIP32_DERIVATION."),
          rule!("R02", validate_sp_spend_key_has_tweak, "An input with PSBT_IN_SP_SPEND_BIP32_DERIVATION MUST have PSBT_IN_SP_TWEAK."),
          rule!("R03", validate_sp_tweak_spends_p2tr,   "An input with PSBT_IN_SP_TWEAK MUST have a PSBT_IN_WITNESS_UTXO whose scriptPubKey is P2TR."),
          rule!("R04", validate_sp_tweaked_spend_key,   "Every spend key in PSBT_IN_SP_SPEND_BIP32_DERIVATION, plus the tweak times G, MUST have the x-coordinate of the spent P2TR output key."),
        ])))),
      ])),
    ])),
  ])
}

/// Checks a Signer makes before signing. They assume `validity_rules` hold.
#[rustfmt::skip]
pub fn signer_rules(_bips: &[Bip]) -> BoxNode<PsbtContext> {
  section("Signer Rules", each(inputs, all(vec![
    rule!("S01", validate_non_witness_utxo, "A non-witness UTXO MUST hash to the input's previous txid and contain the spent output index."),
    rule!("S02", validate_witness_utxo,     "A witness UTXO's scriptPubKey MUST be a witness program, or P2SH of a redeemScript that is one."),
    rule!("S03", validate_redeem_script,    "A redeemScript MUST hash to the spent output's P2SH scriptPubKey."),
    rule!("S04", validate_witness_script,   "A witnessScript MUST hash to the P2WSH program in the spent scriptPubKey, or in the redeemScript when nested."),
  ])))
}

/// Preconditions a Transaction Extractor checks. They assume `validity_rules` hold.
#[rustfmt::skip]
pub fn extractor_rules(_bips: &[Bip]) -> BoxNode<PsbtContext> {
  section("Extractor Rules", all(vec![
    each(inputs,
      rule!("X01", validate_input_finalized,   "Every input MUST have PSBT_IN_FINAL_SCRIPTSIG or PSBT_IN_FINAL_SCRIPTWITNESS.")),
    when("PSBTv2", |p: &PsbtContext| p.version == 2, each(outputs,
      rule!("X02", validate_output_has_script, "Every output MUST have a non-empty PSBT_OUT_SCRIPT."))),
  ]))
}

/// Preconditions an Input Finalizer checks before finalizing. They assume `validity_rules` hold.
#[rustfmt::skip]
pub fn finalizer_rules(bips: &[Bip]) -> BoxNode<PsbtContext> {
  section("Input Finalizer Rules", each(inputs, all(vec![
    rule!("N01", validate_signatures_match_sighash_type, "If an input has PSBT_IN_SIGHASH_TYPE, every signature it carries MUST use that sighash type."),
    from(Bip::Bip376, bips,
      rule!("N02", validate_sp_tweak_has_key_sig, "An input with PSBT_IN_SP_TWEAK MUST have PSBT_IN_TAP_KEY_SIG.")),
  ])))
}

/// Transition rules for a Combiner, comparing the PSBTs it combined with the
/// PSBT it produced. They assume `validity_rules` hold for each.
#[rustfmt::skip]
pub fn combiner_rules(_bips: &[Bip]) -> BoxNode<TransitionContext> {
  section("Combiner Rules", all(vec![
    rule!("C01", validate_shared_unique_id,     "Every PSBT a Combiner combines, and the PSBT it produces, MUST share a unique identifier: the unsigned transaction's txid (v0), or the BIP-370 unique identifier (v2), with BIP-375 outputs identified by PSBT_OUT_SP_V0_INFO."),
    rule!("C02", validate_combined_keeps_keys,  "The combined PSBT MUST hold every key that a PSBT it combines holds, in the same map."),
    rule!("C03", validate_combined_adds_nothing, "Every key-value pair in the combined PSBT MUST come from the same map of a PSBT it combines."),
  ]))
}
