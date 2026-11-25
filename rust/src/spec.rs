//! PSBT CONFORMANCE SPECIFICATION
//!
//! A PSBT is well formed iff the General rules hold for it. A role conforms iff
//! its rules hold on the PSBT it received and the PSBT it returned.
//!
//! Each `rule!(id, check, wording)` names the function that decides its
//! statement, and its ID is the error code that function reports. A check
//! returns one of four outcomes: Verified (the property holds), Failed (it does
//! not), NotApplicable (the statement does not apply to this PSBT), or
//! Incomplete (the PSBT lacks the context to decide). Each rule's coverage in
//! catalog.rs says how much of its statement the check decides: Full, Partial,
//! Declared or Pending. Definitions, references and guidance are text
//! definitions, never placeholder checks.

use crate::algebra::{all, each, from, precondition, result, section, seq, when, with, Bip, BoxNode, Doc};
use crate::catalog::{build, text, Declaration, DeclaredSection, Text, NO_EVIDENCE};
use crate::catalog::Coverage::{Declared, Full, Partial};
use crate::catalog::Strength::{May, Must, MustNot, Should};
use crate::context::{InputContext, OutputContext, PsbtContext, SigningInputContext, TransitionContext};
use crate::rules::creator::CreatorContext;
use crate::rules::constructor::ConstructorTransitionContext;
use crate::rules::signer::SignerTransitionContext;
use crate::rules::finalizer::FinalizerTransitionContext;
use crate::encoding::{Map, Psbt};
use crate::check;
use crate::silent_payments::has_sp_outputs;

pub use crate::catalog::{Basis, Coverage, Evidence, Specification, Statement, Strength};

/// Evidence: a section of a BIP at the pinned bitcoin/bips revision.
macro_rules! bip {
    ($label:literal, $path:literal) => {
        crate::catalog::Evidence {
            label: $label,
            url: concat!("https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/", $path),
        }
    };
}

/// Evidence: a section of BIP375 at its own pinned revision, tag psbt-spec-bip375-21e48c11 on
/// macgyver13/bips (bips change vwyyuntk). bitcoin/bips does not serve the commit.
macro_rules! bip375 {
    ($label:literal, $path:literal) => {
        crate::catalog::Evidence {
            label: $label,
            url: concat!("https://github.com/macgyver13/bips/blob/21e48c1175b966eb2919965692759e0a0f7a2fb1/", $path),
        }
    };
}

// Declarations, in display order. The graphs below bind checks to them with
// check!, in evaluation order.

#[rustfmt::skip]
pub const FRAMING: DeclaredSection = DeclaredSection { category: "general", title: "Framing", entries: &[
    Declaration::rule("GEN-F-1", Must, Full, bip!("BIP174 - Specification", "bip-0174.mediawiki#specification"),
        "A PSBT MUST begin with the five-byte header 70 73 62 74 FF: ASCII psbt followed by the FF separator."),
    Declaration::rule("GEN-F-2", Must, Full, bip!("BIP174 - Specification", "bip-0174.mediawiki#specification"),
        "Each key-value record MUST be complete and use its declared lengths; the key type MUST be minimally encoded.")
        .note("The linked parser also requires minimally encoded outer CompactSize lengths."),
    Declaration::rule("GEN-F-3", Must, Full, bip!("BIP174 - Specification", "bip-0174.mediawiki#specification"),
        "A PSBT MUST contain a global map, and each map MUST end with 00."),
    Declaration::rule("GEN-F-4", Must, Full, bip!("BIP174 - Handling Duplicated Keys", "bip-0174.mediawiki#handling-duplicated-keys"),
        "Keys MUST be unique within each map."),
    Declaration::rule("GEN-F-5", Must, Full, bip!("BIP174 - Specification", "bip-0174.mediawiki#specification"),
        "Every present known field MUST conform to the key-data and value format the field registry gives it.")
        .note("Bound three times: the global map first, then each input map and each output map once the map count assigns them. The field registry below is the table it enforces, including the unsigned transaction's empty scriptSigs and the required-locktime ranges. It checks structure and the relations the field tables state, not every property a value may need, such as xpub version bytes or ECDSA signature validity."),
]};

#[rustfmt::skip]
pub const STRUCTURE: DeclaredSection = DeclaredSection { category: "general", title: "Structure", entries: &[
    Declaration::rule("GEN-ST-1", Must, Full, bip!("BIP174 - Version Numbers", "bip-0174.mediawiki#version-numbers"),
        "The PSBT version MUST be 0 or 2."),
    Declaration::rule("GEN-ST-2", Must, Full, bip!("BIP370 - Specification", "bip-0370.mediawiki#specification"),
        "Each map MUST include the fields its PSBT version requires and exclude the fields it forbids.")
        .note("Bound three times: the global map before the map count is known, then each input map and each output map. The field registry's Required and Excluded columns are the table it enforces."),
    Declaration::rule("GEN-ST-3", Must, Full, bip!("BIP174 - Specification", "bip-0174.mediawiki#specification"),
        "Input maps MUST follow the global map, followed by output maps, with one map for each transaction input and output."),
]};

#[rustfmt::skip]
pub const TRANSACTION: DeclaredSection = DeclaredSection { category: "general", title: "Transaction", entries: &[
    Declaration::rule("GEN-T-1", Must, Full, bip!("BIP370 - Determining Lock Time", "bip-0370.mediawiki#determining-lock-time"),
        "The inputs’ required locktimes MUST permit nLockTime to be determined by the BIP370 procedure."),
    Declaration::rule("GEN-T-2", Must, Full, bip!("BIP370 - Signer", "bip-0370.mediawiki#signer"),
        "A PSBT's signatures MUST agree with PSBT_GLOBAL_TX_MODIFIABLE: Inputs Modifiable is clear if any signature lacks SIGHASH_ANYONECANPAY, Outputs Modifiable is clear if any does not use SIGHASH_NONE, and Has SIGHASH_SINGLE is set if any uses SIGHASH_SINGLE.")
        .note("Bound three times, one per flag. It also covers the Signer's BIP370 flag duties: a Signer that leaves a flag wrong returns a PSBT that fails this rule. Signatures are found as input_signatures finds them, including those in finalized key-path and legacy fields.")
        .roles(&["Signer"]),
]};

#[rustfmt::skip]
pub const TAPROOT: DeclaredSection = DeclaredSection { category: "general", title: "Taproot", entries: &[
    Declaration::rule("GEN-TR-1", Must, Full, bip!("BIP371 - PSBT_IN_TAP_LEAF_SCRIPT", "bip-0371.mediawiki#specification"),
        "For each input with PSBT_IN_TAP_LEAF_SCRIPT, every control block MUST reconstruct to the spent P2TR key.")
        .cite(&[bip!("BIP341 - Script validation rules", "bip-0341.mediawiki#script-validation-rules")])
        .derived("BIP371 describes the control block only as specified in BIP341. A control block that does not reconstruct to the spent output key fails BIP341 script path validation.")
        .note("Applies only to inputs with PSBT_IN_TAP_LEAF_SCRIPT. Takes the spent output from either UTXO field; a missing spent output returns Incomplete. The control block leaf version must equal the leaf script version."),
    Declaration::rule("GEN-TR-2", Must, Full, bip!("BIP371 - PSBT_IN_TAP_INTERNAL_KEY and PSBT_IN_TAP_MERKLE_ROOT", "bip-0371.mediawiki#specification"),
        "PSBT_IN_TAP_INTERNAL_KEY, tweaked by PSBT_IN_TAP_MERKLE_ROOT or, without it, by some script tree, MUST produce the spent P2TR output key.")
        .cite(&[bip!("BIP341 - Constructing and spending Taproot outputs", "bip-0341.mediawiki#constructing-and-spending-taproot-outputs")])
        .derived("BIP371 gives the internal key and merkle root of the spent output. BIP341 defines the output key as the internal key tweaked by that root, so fields that do not produce it do not describe the output.")
        .note("Without PSBT_IN_TAP_MERKLE_ROOT, a key-only tweak that matches is Verified and a mismatch is Incomplete. The PSBT may omit the script tree. A missing spent output returns Incomplete."),
    Declaration::rule("GEN-TR-3", Must, Full, bip!("BIP371 - PSBT_OUT_TAP_INTERNAL_KEY and PSBT_OUT_TAP_TREE", "bip-0371.mediawiki#specification"),
        "PSBT_OUT_TAP_INTERNAL_KEY, tweaked by the root of PSBT_OUT_TAP_TREE or, without it, by some script tree, MUST produce the output's P2TR key.")
        .cite(&[bip!("BIP341 - Constructing and spending Taproot outputs", "bip-0341.mediawiki#constructing-and-spending-taproot-outputs")])
        .derived("BIP371 gives the internal key and script tree of the output. BIP341 defines the output key as the internal key tweaked by the tree's root, so fields that do not produce it do not describe the output.")
        .note("Uses PSBT_OUT_SCRIPT (v2) or the unsigned transaction's output (v0). Without PSBT_OUT_TAP_TREE, a key-only match is Verified and a mismatch is Incomplete. An output with no script yet returns Incomplete."),
    Declaration::rule("GEN-TR-4", Must, Full, bip!("BIP371 - PSBT_OUT_TAP_BIP32_DERIVATION", "bip-0371.mediawiki#specification"),
        "Each leaf hash in PSBT_OUT_TAP_BIP32_DERIVATION MUST be a leaf of PSBT_OUT_TAP_TREE.")
        .derived("BIP371 says the leaf hashes are of the leaves which involve this public key. Read as a requirement, each one is a leaf of the output's tree.")
        .note("Without PSBT_OUT_TAP_TREE, leaf hashes cannot be checked and the rule returns Incomplete. Input derivation leaf hashes are not checked, because inputs list only the leaves signers can sign."),
]};

#[rustfmt::skip]
pub const MUSIG2: DeclaredSection = DeclaredSection { category: "general", title: "MuSig2", entries: &[
    Declaration::rule("GEN-MS-1", Must, Full, bip!("BIP373 - Specification", "bip-0373.mediawiki#specification"),
        "In PSBT_IN_MUSIG2_PUB_NONCE and PSBT_IN_MUSIG2_PARTIAL_SIG key data, the plain public key MUST be the Taproot output key when the tapleaf hash is omitted, and MUST be found in that leaf's script when it is present.")
        .note("Applies to inputs with PSBT_IN_MUSIG2_PUB_NONCE or PSBT_IN_MUSIG2_PARTIAL_SIG. A missing spent output, or a tapleaf hash without a matching PSBT_IN_TAP_LEAF_SCRIPT, returns Incomplete."),
    Declaration::rule("GEN-MS-2", Must, Full, bip!("BIP373 - Specification", "bip-0373.mediawiki#specification"),
        "The key of each PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS and PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS MUST be the BIP327 KeyAgg result of its participant keys in the listed order.")
        .cite(&[bip!("BIP327 - Key Aggregation", "bip-0327.mediawiki#key-aggregation")])
        .note("Runs BIP327 KeyAgg with the musig2 crate over the listed keys in order and compares the untweaked aggregate key. Keys listed in a different order produce a different key and fail."),
]};

#[rustfmt::skip]
pub const DNS: DeclaredSection = DeclaredSection { category: "general", title: "DNS payment instructions", entries: &[
    Declaration::rule("GEN-DNS-1", Must, Full, bip!("BIP353 - Specification", "bip-0353.mediawiki#psbt-types"),
        "When PSBT_OUT_DNSSEC_PROOF is present, the field value MUST begin with a valid length-prefixed human-readable name.")
        .note("Checks the one-byte length prefix and that the name is UTF-8 and contains an @ separator."),
]};

#[rustfmt::skip]
pub const SIGNED_MESSAGES: DeclaredSection = DeclaredSection { category: "general", title: "Generic signed messages", entries: &[
    Declaration::rule("GEN-MSG-1", Must, Full, bip!("BIP322 - PSBT creator; Full", "bip-0322.mediawiki#psbt-creator"),
        "In a BIP322 PSBT, the first input's PSBT_IN_WITNESS_UTXO, when present, MUST be output 0 of to_spend, whose amount is 0.")
        .derived("Merges BIP322's PSBT creator section with its Full format, which makes to_spend's output 0 the spent output at amount 0.")
        .note("Not applicable without PSBT_IN_WITNESS_UTXO; a non-witness UTXO is checked against the prevout by ROLE-S-1 and recognition.")
        .roles(&["Creator and Constructor"]),
    Declaration::rule("GEN-MSG-2", Must, Full, bip!("BIP322 - Full (Proof of Funds); PSBT creator", "bip-0322.mediawiki#full-proof-of-funds"),
        "In a BIP322 PSBT, every input after the first MUST have PSBT_IN_WITNESS_UTXO or PSBT_IN_NON_WITNESS_UTXO; the non-witness UTXO may be omitted when an earlier input spending the same transaction has it.")
        .derived("Merges the inputs of BIP322's Full (Proof of Funds) format with its PSBT creator section.")
        .note("Not applicable to a PSBT with one input.")
        .roles(&["Creator and Constructor"]),
    Declaration::rule("GEN-MSG-3", Must, Partial, bip!("BIP322 - Verification Process (required rules)", "bip-0322.mediawiki#verification-process"),
        "In a BIP322 PSBT, every signature MUST use SIGHASH_ALL, or SIGHASH_DEFAULT on an input spending P2TR.")
        .note("Uses discovered signatures; a 64-byte Schnorr signature is SIGHASH_DEFAULT.")
        .gap("Signature discovery does not cover finalized P2WSH spends or finalized Taproot script paths."),
    Declaration::rule("GEN-MSG-4", Must, Full, bip!("BIP322 - Verification Process (upgradeable rules)", "bip-0322.mediawiki#verification-process"),
        "A BIP322 PSBT whose to_sign version is not 0 or 2, or that spends a Segwit version above 1, uses an annex, or uses a leaf version other than 0xc0, MUST be reported as inconclusive, not invalid.")
        .note("Never Failed: an upgradeable feature makes the proof inconclusive, not invalid."),
]};

#[rustfmt::skip]
pub const PAY_TO_CONTRACT: DeclaredSection = DeclaredSection { category: "general", title: "Pay-to-contract", entries: &[
    Declaration::rule("GEN-P2C-1", Must, Partial, bip!("BIP372 - Specification", "bip-0372.mediawiki#specification"),
        "For each PSBT_IN_P2C_TWEAK, the original key plus the tweak times G MUST be a key committed to by the input's spent, redeem, or witness script.")
        .note("Matches P + tG as a P2PKH or P2WPKH key hash or a 33-byte push in the spent, redeem, or witness script. Taproot spends return Incomplete because BIP372 leaves them unresolved.")
        .gap("Does not check that redeem or witness scripts match the spent script, or verify signatures."),
]};

#[rustfmt::skip]
pub const SILENT_PAYMENTS: DeclaredSection = DeclaredSection { category: "general", title: "Silent payments", entries: &[
    Declaration::rule("GEN-SP-1", Must, Full, bip375!("BIP375 - Invalid Psbts", "bip-0375.mediawiki#invalid-psbts"),
        "An output with PSBT_OUT_SP_V0_LABEL MUST also have PSBT_OUT_SP_V0_INFO."),
    Declaration::rule("GEN-SP-2", Must, Full, bip375!("BIP375 - Invalid Psbts (Input Eligibility); Signer", "bip-0375.mediawiki#invalid-psbts"),
        "Once a silent-payment output has PSBT_OUT_SCRIPT, PSBT_GLOBAL_TX_MODIFIABLE MUST have Inputs Modifiable and Outputs Modifiable clear.")
        .derived("Merges the BIP375 Input Eligibility invalid case with the Signer's duty to clear both flags when it sets the output scripts.")
        .note("BIP375 publishes this as an Input Eligibility failure. It also covers the Signer's duty to clear both flags when it sets the scripts.")
        .roles(&["Signer"]),
    Declaration::rule("GEN-SP-3", Must, Full, bip375!("BIP375 - Invalid Psbts (ECDH Coverage)", "bip-0375.mediawiki#invalid-psbts"),
        "A PSBT with silent-payment outputs MUST pass the ECDH coverage check REF-8 describes.")
        .note("Bound once per subcheck, in REF-8's order; the failure detail names the subcheck. DLEQ proofs are verified with BIP374 VerifyProof.")
        .roles(&["Signer", "Transaction Extractor"]),
    Declaration::rule("GEN-SP-4", Must, Full, bip375!("BIP375 - Signer (sighash type); Invalid Psbts (Input Eligibility); Constructor", "bip-0375.mediawiki#signer"),
        "A PSBT with silent-payment outputs MUST pass the input eligibility check REF-9 describes.")
        .derived("Merges the BIP375 Signer's sighash check, the Input Eligibility invalid cases and the Constructor's eligibility check into one check, REF-9.")
        .note("Bound once per subcheck. The Signer fails if PSBT_IN_SIGHASH_TYPE is not SIGHASH_ALL, and without it signs using SIGHASH_ALL. \"For a taproot input, SIGHASH_DEFAULT is accepted in place of SIGHASH_ALL in both cases.\"")
        .roles(&["Creator and Constructor", "Signer"]),
    Declaration::rule("GEN-SP-5", Must, Full, bip375!("BIP375 - Invalid Psbts (Output Scripts); Signer; Transaction Extractor", "bip-0375.mediawiki#invalid-psbts"),
        "A PSBT with silent-payment outputs MUST pass the output script check REF-10 describes.")
        .derived("Merges the BIP375 Output Scripts invalid cases with the Signer's and Transaction Extractor's output script checks into one check, REF-10.")
        .note("Bound twice: the derivation context first, then the scripts. With GEN-SP-3 the shares a set script needs are present. That lets the check decide rather than report missing context.")
        .roles(&["Signer", "Transaction Extractor"]),
    Declaration::rule("GEN-SP-6", Must, Full, bip!("BIP376 - Specification; Updater; Signer; Input Finalizer", "bip-0376.mediawiki#specification"),
        "Every input MUST pass the BIP376 spend-field check REF-11 describes.")
        .derived("Merges the BIP376 field rules of its Specification, Updater, Signer and Input Finalizer sections into one check, REF-11.")
        .note("Bound once per subcheck, in REF-11's order, when BIP376 is enabled.")
        .roles(&["Updater", "Signer", "Input Finalizer"]),
    Declaration::rule("GEN-SP-7", MustNot, Full, bip375!("BIP375 - Signer", "bip-0375.mediawiki#signer"),
        "A PSBT with silent-payment outputs MUST NOT carry a signature while any output lacks PSBT_OUT_SCRIPT.")
        .note("Restates the Signer's duty \"If any output does not have PSBT_OUT_SCRIPT set, the Signer must not yet add a signature\" as a property of the PSBT: no conforming Signer produces it, and a Signer that receives it refuses. A present empty script counts as set.")
        .roles(&["Signer"]),
]};

#[rustfmt::skip]
pub const CREATOR_AND_CONSTRUCTOR: DeclaredSection = DeclaredSection { category: "role", title: "Creator and Constructor", entries: &[
    Declaration::rule("ROLE-C-1", Must, Partial, bip!("BIP370 - Creator", "bip-0370.mediawiki#creator"),
        "A v0 Creator MUST create the unsigned transaction with empty input and output maps; a v2 Creator MUST create a version 2 PSBT with no inputs or outputs.")
        .note("The linked v0 check currently requires zero transaction inputs and outputs; it does not check empty maps for an unsigned transaction with inputs or outputs.")
        .gap("The v0 check requires zero inputs and outputs; it does not check empty maps for an unsigned transaction that has inputs or outputs."),
    Declaration::rule("ROLE-C-2", Must, Partial, bip!("BIP370 - Creator", "bip-0370.mediawiki#creator"),
        "If the Creator is not also a Constructor and delegates additions, PSBT_GLOBAL_TX_MODIFIABLE MUST be present with flags set appropriately, and transaction nVersion MUST be at least 2.")
        .note("Supply delegation intent explicitly. The linked check verifies flag-field presence and length, but does not verify that its bits permit the intended additions.")
        .gap("Checks the flag field's presence and length, not that its bits permit the intended additions."),
    Declaration::rule("ROLE-C-3", Must, Partial, bip!("BIP370 - Constructor", "bip-0370.mediawiki#constructor"),
        "Before adding inputs or outputs, the Constructor MUST check the corresponding modification flag and add only what it permits.")
        .note("evaluate_constructing runs the General rules on both PSBTs first. The linked check compares input and output counts with the modification flags of the PSBT the Constructor received.")
        .gap("Assumes new maps are appended. An inserted map is read as a changed one."),
    Declaration::rule("ROLE-C-4", Must, Partial, bip!("BIP370 - Constructor", "bip-0370.mediawiki#constructor"),
        "For an input with a required spend-branch locktime, the Constructor MUST set the corresponding required time- or height-based locktime field.")
        .note("The linked context records only whether each listed input needs a locktime, not the required type or value. Success confirms field presence for listed requirements; it does not establish that all added inputs or their chosen spend branches were covered.")
        .gap("Knows only whether each listed input needs a locktime, not the required type or value."),
    Declaration::rule("ROLE-C-5", MustNot, Partial, bip!("BIP370 - Constructor", "bip-0370.mediawiki#constructor"),
        "When adding an input with a required locktime, the Constructor MUST NOT change the determined transaction locktime if any existing input has a signature.")
        .note("Preservation is checked using discoverable signatures. Signature discovery does not cover arbitrary finalized scripts or all Taproot script paths.")
        .gap("Sees only the signatures signature discovery reaches, not those in arbitrary finalized scripts or every Taproot script path."),
    Declaration::rule("ROLE-C-6", Must, Partial, bip!("BIP370 - Constructor", "bip-0370.mediawiki#constructor"),
        "If Has SIGHASH_SINGLE is true, the Constructor MUST identify the signed SINGLE input/output pairs and insert equal numbers of inputs and outputs before each affected pair.")
        .note("The linked check locates the signed input but does not compare its paired output. A Verified result does not establish preservation of the SINGLE pair.")
        .gap("Locates the signed SINGLE input but does not compare its paired output."),
]};

#[rustfmt::skip]
pub const UPDATER: DeclaredSection = DeclaredSection { category: "role", title: "Updater", entries: &[
    Declaration::rule("ROLE-U-1", Must, Declared, bip!("BIP376 - Updater", "bip-0376.mediawiki#updater"),
        "When an input spends a Silent Payment output, the Updater MUST add PSBT_IN_SP_TWEAK.")
        .note("Not observable in the PSBT: only the Updater knows that an input spends a silent-payment output. GEN-SP-6 rejects a spend-key derivation without the tweak."),
]};

#[rustfmt::skip]
pub const SIGNER: DeclaredSection = DeclaredSection { category: "role", title: "Signer", entries: &[
    Declaration::rule("ROLE-S-1", Must, Full, bip!("BIP174 - Data Signers Check For", "bip-0174.mediawiki#data-signers-check-for"),
        "Before signing an input with PSBT_IN_NON_WITNESS_UTXO, the Signer MUST verify that it hashes to the input's previous txid and agrees with any PSBT_IN_WITNESS_UTXO.")
        .note("Not applicable without PSBT_IN_NON_WITNESS_UTXO. Also fails when the transaction lacks the prevout's output, or when a PSBT_IN_WITNESS_UTXO names a different spent output."),
    Declaration::rule("ROLE-S-2", Must, Full, bip!("BIP174 - Data Signers Check For", "bip-0174.mediawiki#data-signers-check-for"),
        "Before signing an input with PSBT_IN_REDEEM_SCRIPT, the Signer MUST verify that the spent output is P2SH of that script.")
        .note("Not applicable without PSBT_IN_REDEEM_SCRIPT. A P2SH spend missing it passes this rule; ROLE-S-3 and ROLE-S-4 are then Incomplete. Takes the spent output from either UTXO field; without one it is Incomplete."),
    Declaration::rule("ROLE-S-3", Must, Full, bip!("BIP174 - Data Signers Check For", "bip-0174.mediawiki#data-signers-check-for"),
        "Before signing an input with PSBT_IN_WITNESS_SCRIPT, the Signer MUST verify that the spent script, or its redeemScript, is P2WSH of that script.")
        .note("Not applicable without PSBT_IN_WITNESS_SCRIPT. A P2WSH spend missing it passes this rule. A P2SH spend without its redeemScript, or an input without a spent output, is Incomplete."),
    Declaration::rule("ROLE-S-4", Must, Full, bip!("BIP174 - Data Signers Check For", "bip-0174.mediawiki#data-signers-check-for"),
        "The Signer MUST NOT create a non-witness signature for an input with PSBT_IN_WITNESS_UTXO, nor a signature of a kind the spent script does not take.")
        .note("Run by evaluate_for_signing with the input and signature kind the caller selects; evaluate_signing infers the kind from the spent script. Without a spent output, or a P2SH spend without its redeemScript, it is Incomplete."),
    Declaration::rule("ROLE-S-5", Must, Declared, bip!("BIP376 - Signer", "bip-0376.mediawiki#signer"),
        "Before signing an SP input, the Signer MUST fail unless its spend private key, tweaked as REF-7 describes, gives the spent P2TR output key.")
        .note("Not observable in the PSBT: the check uses the Signer's private key. GEN-SP-6 checks a supplied spend public key the same way."),
    Declaration::rule("ROLE-S-6", Must, Full, bip!("BIP353 - PSBT types; Resolution", "bip-0353.mediawiki#psbt-types"),
        "A Signer that validates a PSBT_OUT_DNSSEC_PROOF MUST validate it as REF-6 describes.")
        .derived("Merges BIP353's PSBT types and Resolution sections into one procedure, REF-6.")
        .note("Run by evaluate_dnssec_proofs with a supplied time; without one it is Incomplete. Uses dnssec-prover. It enforces the DNSSEC algorithm policy and resolves CNAME and DNAME. TXT character-strings are concatenated in RDATA order."),
    Declaration::rule("ROLE-S-7", Must, Declared, bip!("BIP353 - Resolution", "bip-0353.mediawiki#resolution"),
        "A Signer that displays a BIP353 name without homograph precautions MUST display non-ASCII user and domain identifiers as raw punycode.")
        .note("Not observable in the PSBT: the rule needs evidence of what the wallet displayed."),
    Declaration::rule("ROLE-S-8", Must, Declared, bip!("BIP322 - PSBT signer", "bip-0322.mediawiki#psbt-signer"),
        "A Signer that recognizes a BIP322 PSBT MUST inform the user of the message and the address it signs for, and MUST sign only on the user's approval.")
        .note("Not observable in the PSBT: the rule needs evidence of what the Signer showed and that the user approved."),
    Declaration::rule("ROLE-S-9", Must, Partial, bip!("BIP174 - Signer", "bip-0174.mediawiki#signer"),
        "The Signer MUST only add data: every key-value pair it received, including unknown types, MUST be in the PSBT it returns.")
        .note("The linked transition check preserves existing records but exempts TX_MODIFIABLE from comparison. It does not restrict newly added fields or verify that flag changes are permitted.")
        .gap("Exempts PSBT_GLOBAL_TX_MODIFIABLE from comparison and does not restrict which fields the Signer adds."),
    Declaration::rule("ROLE-S-10", Must, Full, bip!("BIP174 - Specification (PSBT_IN_SIGHASH_TYPE)", "bip-0174.mediawiki#specification"),
        "Every signature the Signer adds to an input with PSBT_IN_SIGHASH_TYPE MUST use that sighash type.")
        .note("Compares the PSBT the Signer received with the one it returned. Applies to inputs with PSBT_IN_SIGHASH_TYPE that gained a signature; a 64-byte Schnorr signature uses SIGHASH_DEFAULT."),
    Declaration::rule("ROLE-S-11", Must, Full, bip!("BIP376 - Signer", "bip-0376.mediawiki#signer"),
        "The Signer MUST write the BIP340 signature for an SP input to PSBT_IN_TAP_KEY_SIG.")
        .note("Compares the PSBT the Signer received with the one it returned. For an SP input that gained a signature, the signature must be in PSBT_IN_TAP_KEY_SIG rather than a partial or script-path signature. It must verify as a key-path signature by the spent output key. Missing transaction data returns Incomplete."),
]};

#[rustfmt::skip]
pub const INPUT_FINALIZER: DeclaredSection = DeclaredSection { category: "role", title: "Input Finalizer", entries: &[
    Declaration::rule("ROLE-F-1", Must, Partial, bip!("BIP174 - Input Finalizer", "bip-0174.mediawiki#input-finalizer"),
        "If PSBT_IN_SIGHASH_TYPE is present, the Finalizer MUST refuse to finalize an input if any of its signatures uses a different sighash type.")
        .note("Compares the sighash types of the input's signatures: partial and Taproot signature fields, and those in a finalized key-path or legacy witness. evaluate_finalizing applies it to the input the Finalizer received, where every signature is in a labeled field. Not applicable without PSBT_IN_SIGHASH_TYPE or without a signature.")
        .gap("An input already finalized with a Taproot script path is Incomplete, because its witness does not say which items are signatures. Finalized P2WSH spends are not searched."),
    Declaration::rule("ROLE-F-2", Must, Full, bip!("BIP376 - Input Finalizer", "bip-0376.mediawiki#input-finalizer"),
        "Before finalizing an input with PSBT_IN_SP_TWEAK, the Finalizer MUST require PSBT_IN_TAP_KEY_SIG.")
        .note("Checks the input the Finalizer receives: one with PSBT_IN_SP_TWEAK must have PSBT_IN_TAP_KEY_SIG."),
    Declaration::rule("ROLE-F-3", Must, Full, bip!("BIP174 - Input Finalizer", "bip-0174.mediawiki#input-finalizer"),
        "Before finalizing an input, the Finalizer MUST verify each PSBT_IN_TAP_KEY_SIG and PSBT_IN_TAP_SCRIPT_SIG it uses as REF-5 describes.")
        .cite(&[bip!("BIP371 - Specification", "bip-0371.mediawiki#specification"), bip!("BIP341 - Signature validation rules", "bip-0341.mediawiki#signature-validation-rules")])
        .derived("BIP174 finalizes an input only when it has enough data to pass validation. A Taproot signature that does not verify under BIP341 cannot pass validation.")
        .note("Performed with BIP340 through crate::signature. The BIP341 signature message is computed from the unsigned transaction and every input's spent output (only this input's for ANYONECANPAY); missing data returns Incomplete."),
    Declaration::rule("ROLE-F-4", Must, Full, bip!("BIP174 - Input Finalizer", "bip-0174.mediawiki#input-finalizer"),
        "Before finalizing an input, the Finalizer MUST verify each PSBT_IN_PARTIAL_SIG it uses as REF-5 describes.")
        .derived("BIP174 finalizes an input only when it has enough data to pass validation. An ECDSA signature that does not verify cannot pass validation.")
        .note("Performed with ECDSA (k256) over the BIP143 signature message for a P2WPKH or P2WSH spend, bare or inside P2SH, and the legacy message otherwise. The signature must be strict DER; a high S is accepted, as consensus does. A missing UTXO, redeem script or witness script returns Incomplete. So does a script code with OP_CODESEPARATOR or a witness version above 0. Runs after ROLE-F-3 and ROLE-F-5."),
    Declaration::rule("ROLE-F-5", Must, Partial, bip!("BIP373 - Finalizer", "bip-0373.mediawiki#finalizer"),
        "A signature the Finalizer produces with PartialSigAgg MUST verify as REF-5 describes for PSBT_IN_TAP_KEY_SIG or PSBT_IN_TAP_SCRIPT_SIG.")
        .cite(&[bip!("BIP174 - Input Finalizer", "bip-0174.mediawiki#input-finalizer"), bip!("BIP327 - Identifying Disruptive Signers", "bip-0327.mediawiki#identifying-disruptive-signers")])
        .derived("BIP373 lets a Finalizer run PartialSigAgg and says to treat the result as a BIP340 signature, and BIP174 finalizes an input only when it can pass validation. BIP327 makes PartialSigVerify optional, so a Finalizer may check the aggregate signature instead of each partial signature.")
        .note("Performed with BIP327 PartialSigVerify (the musig2 crate) on the PSBT the Finalizer received, for every session with no aggregated signature: if a partial signature fails, the aggregate signature cannot verify. A session missing a participant's nonce, or whose plain key cannot be related to a listed aggregate key, is Incomplete.")
        .gap("A BIP328 derivation is found only through a PSBT_IN_TAP_BIP32_DERIVATION with the aggregate key's fingerprint, not a synthetic PSBT_GLOBAL_XPUB."),
    Declaration::rule("ROLE-F-6", Must, Partial, bip!("BIP174 - Input Finalizer", "bip-0174.mediawiki#input-finalizer"),
        "For each input with enough data to pass validation, the Finalizer MUST construct its finalized scriptSig and scriptWitness fields as applicable.")
        .note("Checks a finalized input against its spent script. P2PKH and P2WPKH must reveal a key that hashes to the committed hash; P2SH and P2WSH must reveal a script that hashes to the commitment; wrapped segwit uses a scriptSig of only the redeem script push; native segwit has no scriptSig; P2TR has a witness and no scriptSig. A matching template is not Verified on its own. A P2PKH or P2WPKH signature (bare or inside P2SH) is verified with ECDSA as ROLE-F-4 does. P2SH, P2WSH and Taproot script-path spends are Incomplete because script satisfaction is not checked. A Taproot key-path spend is Verified here; ROLE-F-10 verifies its signature. Other spent scripts and a missing UTXO return Incomplete. evaluate_finalizing applies it to every input whose final fields the Finalizer set or changed, and fails an input whose final fields it removed. Whether every input with enough data was finalized is not checked.")
        .gap("Does not execute scripts. Script-hash and Taproot script-path spends are Incomplete rather than Verified. Does not determine which inputs had enough data to finalize."),
    Declaration::rule("ROLE-F-7", Must, Full, bip!("BIP370 - Input Finalizer", "bip-0370.mediawiki#input-finalizer"),
        "When clearing finalized input metadata, the Finalizer MUST retain existing PREVIOUS_TXID, OUTPUT_INDEX, SEQUENCE, REQUIRED_TIME_LOCKTIME and REQUIRED_HEIGHT_LOCKTIME fields.")
        .note("Supply before and after contexts for the same input. Only fields present before finalization are required to be retained; optional fields do not become mandatory."),
    Declaration::rule("ROLE-F-8", Must, Full, bip!("BIP376 - Input Finalizer", "bip-0376.mediawiki#input-finalizer"),
        "For an input with PSBT_IN_SP_TWEAK, the Finalizer MUST construct a single-element PSBT_IN_FINAL_SCRIPTWITNESS from its PSBT_IN_TAP_KEY_SIG, and remove PSBT_IN_TAP_KEY_SIG.")
        .note("Compares the input before and after finalizing. The final witness must be exactly one element equal to the PSBT_IN_TAP_KEY_SIG it had, with no annex, and that field must be gone. GEN-SP-6 rejects a finalized input that keeps PSBT_IN_SP_TWEAK or PSBT_IN_SP_SPEND_BIP32_DERIVATION."),
    Declaration::rule("ROLE-F-9", Must, Full, bip!("BIP341 - Constructing and spending Taproot outputs", "bip-0341.mediawiki#constructing-and-spending-taproot-outputs"),
        "For an input finalized via script path, the final witness MUST consist of the script inputs, followed by the leaf script and control block.")
        .cite(&[bip!("BIP341 - Script validation rules", "bip-0341.mediawiki#script-validation-rules")])
        .derived("BIP371 does not describe the final witness. BIP341 gives the script path witness: the script's inputs, then the leaf script, then the control block.")
        .note("After removing an annex, a P2TR final witness with two or more elements must end with a leaf script and a control block that commit to the spent output key. Field cleanup is BIP174 guidance and is not checked here."),
    Declaration::rule("ROLE-F-10", Must, Full, bip!("BIP341 - Script validation rules", "bip-0341.mediawiki#script-validation-rules"),
        "For a P2TR input finalized via key path, the final witness MUST be a single signature, followed by any annex, that verifies against the spent output key.")
        .cite(&[bip!("BIP174 - Input Finalizer", "bip-0174.mediawiki#input-finalizer")])
        .derived("BIP174 asks for a final witness that passes validation, and BIP341 defines a key path witness as one signature, followed by any annex, valid for the output key.")
        .note("Applies to a P2TR final witness with one element after removing any annex. The signature is checked against the spent output key with the annex committed; missing transaction data returns Incomplete."),
]};

#[rustfmt::skip]
pub const TRANSACTION_EXTRACTOR: DeclaredSection = DeclaredSection { category: "role", title: "Transaction Extractor", entries: &[
    Declaration::rule("ROLE-X-1", Must, Partial, bip!("BIP174 - Transaction Extractor", "bip-0174.mediawiki#transaction-extractor"),
        "The Extractor MUST extract only when every input has the final fields its spend needs and the version-specific fields can build the transaction.")
        .note("The linked check tests final-field presence and some v2 transaction fields, without constructing the transaction or establishing spend satisfaction. It currently rejects present empty output scripts.")
        .gap("Tests final-field presence and some version 2 fields; it does not build the transaction or establish that each spend is satisfied."),
]};

#[rustfmt::skip]
pub const COMBINER: DeclaredSection = DeclaredSection { category: "role", title: "Combiner", entries: &[
    Declaration::rule("ROLE-B-1", MustNot, Full, bip!("BIP174 - Combiner", "bip-0174.mediawiki#combiner"),
        "A Combiner MUST NOT combine PSBTs whose transaction identifiers differ.")
        .note("Validate each source and result before comparing identifiers. Equal identifiers do not establish a consistent metadata merge; apply ROLE-B-2 separately."),
    Declaration::rule("ROLE-B-2", Must, Partial, bip!("BIP174 - Combiner", "bip-0174.mediawiki#combiner"),
        "A successful combination MUST preserve source key-value data in the corresponding maps. For conflicting duplicate keys, choose a supplied value or fail. Fail where a consistent merge cannot be produced.")
        .note("The linked check preserves source keys and selects supplied values after identity comparison. It does not establish comprehensive consistency between merged metadata fields.")
        .gap("Key preservation and supplied-value selection exist; comprehensive merge consistency is not established."),
]};

#[rustfmt::skip]
pub const DEFINITIONS: DeclaredSection = DeclaredSection { category: "definition", title: "Definitions", entries: &[
    Declaration::term("PSBT version", bip!("BIP174 - Version Numbers", "bip-0174.mediawiki#version-numbers"),
        "The value of PSBT_GLOBAL_VERSION, or 0 when the field is absent."),
    Declaration::term("Known field", bip!("BIP174 - Specification", "bip-0174.mediawiki#specification"),
        "A field whose key type the field registry below lists for its map. Other key types are unknown fields."),
    Declaration::term("Spent output", bip!("BIP174 - Specification", "bip-0174.mediawiki#specification"),
        "The output an input spends: its PSBT_IN_WITNESS_UTXO, or else the output of its PSBT_IN_NON_WITNESS_UTXO at the input's output index."),
    Declaration::term("Finalized input", bip!("BIP174 - Input Finalizer", "bip-0174.mediawiki#input-finalizer"),
        "An input with PSBT_IN_FINAL_SCRIPTSIG or PSBT_IN_FINAL_SCRIPTWITNESS."),
    Declaration::term("Added signature", NO_EVIDENCE,
        "A signature in an input of the PSBT a role returned that the same input of the PSBT it received did not have."),
    Declaration::term("Modification flags", bip!("BIP370 - Specification", "bip-0370.mediawiki#specification"),
        "Inputs Modifiable, Outputs Modifiable and Has SIGHASH_SINGLE are bits 0, 1 and 2 of PSBT_GLOBAL_TX_MODIFIABLE."),
    Declaration::term("Transaction identifier", bip!("BIP370 - Unique Identification; BIP375 - Unique Identification", "bip-0370.mediawiki#unique-identification"),
        "For version 0, the txid of PSBT_GLOBAL_UNSIGNED_TX. For version 2, the txid of the unsigned transaction BIP370 builds for unique identification. Under BIP375, an output's PSBT_OUT_SP_V0_INFO is used in place of its PSBT_OUT_SCRIPT when building that transaction."),
    Declaration::term("BIP322 PSBT", bip!("BIP322 - PSBT signer", "bip-0322.mediawiki#psbt-signer"),
        "A PSBT with PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE whose first input spends output 0 of the to_spend transaction for that message and the input's spent script, and whose only output is a zero-value OP_RETURN. Recognition needs the first input's spent output; without it, the rules about BIP322 PSBTs are Incomplete."),
    Declaration::term("Silent-payment output", bip375!("BIP375 - Specification", "bip-0375.mediawiki#specification"),
        "An output with PSBT_OUT_SP_V0_INFO."),
    Declaration::term("Scan key and spend key", bip!("BIP352 - Overview", "bip-0352.mediawiki#overview"),
        "The two public keys of a silent payment address. The sender combines the scan key with its inputs' keys to derive a shared secret; the output pays the spend key tweaked by that secret."),
    Declaration::term("Silent payment code", bip!("BIP352 - Address encoding", "bip-0352.mediawiki#address-encoding"),
        "The address a recipient publishes, encoding its scan key and spend key. A PSBT carries the two keys in PSBT_OUT_SP_V0_INFO."),
    Declaration::term("Label", bip!("BIP352 - Overview", "bip-0352.mediawiki#overview"),
        "An integer m the recipient uses to tweak its spend key, so payments to one scan key can be told apart. Label 0 is reserved for change; PSBT_OUT_SP_V0_LABEL carries it."),
    Declaration::term("ECDH share", bip375!("BIP375 - Specification", "bip-0375.mediawiki#specification"),
        "A scan key multiplied by an input's private key (PSBT_IN_SP_ECDH_SHARE) or by the sum of the eligible inputs' private keys (PSBT_GLOBAL_SP_ECDH_SHARE). Shares let the output script be computed without revealing private keys to whoever computes it."),
    Declaration::term("DLEQ proof", bip!("BIP374 - Specification", "bip-0374.mediawiki#specification"),
        "A proof that an ECDH share was made with the same private key as a public key, without revealing that key (PSBT_IN_SP_DLEQ, PSBT_GLOBAL_SP_DLEQ). It lets other parties check a share they did not make."),
    Declaration::term("Eligible input", bip!("BIP352 - Inputs For Shared Secret Derivation", "bip-0352.mediawiki#inputs-for-shared-secret-derivation"),
        "An input whose key contributes to the BIP352 shared secret: a P2PKH, P2WPKH, P2SH-P2WPKH or P2TR spend, except a P2TR spend that shows its internal key is the BIP341 NUMS point."),
]};

#[rustfmt::skip]
pub const REFERENCE: DeclaredSection = DeclaredSection { category: "reference", title: "Procedures", entries: &[
    Declaration::reference("REF-1", "Locktime determination", bip!("BIP370 - Determining Lock Time", "bip-0370.mediawiki#determining-lock-time"),
        "Use the shared locktime type supported by all constrained inputs and take its maximum. Prefer height when both types work. With no input requirement, use fallback locktime, or zero if absent."),
    Declaration::reference("REF-2", "SP derivation context", bip375!("BIP375 - Computing The Output Scripts", "bip-0375.mediawiki#computing-the-output-scripts"),
        "For output derivation, select at least one eligible input. Use the scan key’s global ECDH share, or sum the matching shares from all eligible inputs. Public keys and eligibility must be established for the inputs included in the computation.")
        .note("Derivation requires complete eligible-input context. Missing public keys or shares cannot count as successful derivation."),
    Declaration::reference("REF-3", "DLEQ verification", bip375!("BIP375 - Verifying The Dleq Proof", "bip-0375.mediawiki#verifying-the-dleq-proof"),
        "Global verification uses the sum of all eligible-input public keys; per-input verification uses that input’s key. Use the matching scan key, share and proof with BIP374 VerifyProof.")
        .note("A proof check requires the matching proof and complete verification inputs. Summing only recoverable public keys or trusting unrelated derivation keys does not establish the required aggregate key."),
    Declaration::reference("REF-4", "SP output ordering", bip375!("BIP375 - Computing The Output Scripts", "bip-0375.mediawiki#computing-the-output-scripts"),
        "Assign k per scan key after sorting silent-payment codes lexicographically. Break identical-code ties by ascending output index, then derive the BIP352 script using the selected shared secret."),
    Declaration::reference("REF-5", "Signature verification", bip!("BIP174 - Specification; BIP341; BIP327", "bip-0174.mediawiki#specification"),
        "PSBT_IN_PARTIAL_SIG: an ECDSA signature by its public key under the BIP143 signature message for a segwit v0 spend, or the legacy message otherwise. PSBT_IN_TAP_KEY_SIG: a BIP340 signature by the spent output key under the BIP341 key-path message for its hash type. PSBT_IN_TAP_SCRIPT_SIG: a BIP340 signature by its x-only key under the BIP341 script-path message for its leaf. PSBT_IN_MUSIG2_PARTIAL_SIG: BIP327 PartialSigVerify under its session's aggregate key, tweaks and nonces."),
    Declaration::reference("REF-6", "DNSSEC proof validation", bip!("BIP353 - Resolution", "bip-0353.mediawiki#resolution"),
        "Validate the RFC 9102 chain from the DNS root to the name's TXT records. Each RRSIG's inception is no later than the current time and its expiry no earlier than it, or up to an hour earlier only when a delay between construction and signing is likely. Ignore TXT records not beginning with \"bitcoin:\", and refuse the proof if more than one does."),
    Declaration::reference("REF-7", "SP spend key", bip!("BIP376 - Signer", "bip-0376.mediawiki#signer"),
        "Take P from the input's P2TR PSBT_IN_WITNESS_UTXO. Compute d = (b_spend + tweak) mod n, and negate d when dG has odd y. The key matches when x(dG) equals P."),
    Declaration::reference("REF-8", "ECDH coverage", bip375!("BIP375 - Test Vectors", "bip-0375.mediawiki#test-vectors"),
        "For each silent-payment output's scan key: once the output has PSBT_OUT_SCRIPT, there is a global ECDH share, or per-input shares on at least one input and every eligible input. A global share has a global DLEQ proof, the PSBT has an eligible input, every eligible input has a public key, and the proof verifies for the sum of those keys, the scan key and the share. An eligible input's share has a DLEQ proof, the input has a public key, and the proof verifies for that key, the scan key and the share."),
    Declaration::reference("REF-9", "Input eligibility", bip375!("BIP375 - Test Vectors", "bip-0375.mediawiki#test-vectors"),
        "With silent-payment outputs, no input spends a SegWit version 2 or later output, PSBT_IN_SIGHASH_TYPE is SIGHASH_ALL (or SIGHASH_DEFAULT on a P2TR input), and every signature uses SIGHASH_ALL (or SIGHASH_DEFAULT for a 64-byte Schnorr signature)."),
    Declaration::reference("REF-10", "Output scripts", bip375!("BIP375 - Test Vectors", "bip-0375.mediawiki#test-vectors"),
        "A silent-payment output with PSBT_OUT_SCRIPT has the ECDH shares and input public keys its derivation needs (REF-2), and its script is the BIP352 output script, with k assigned as REF-4 describes."),
    Declaration::reference("REF-11", "BIP376 spend fields", bip!("BIP376 - Specification", "bip-0376.mediawiki#specification"),
        "A finalized input keeps neither PSBT_IN_SP_TWEAK nor PSBT_IN_SP_SPEND_BIP32_DERIVATION. An input with PSBT_IN_SP_SPEND_BIP32_DERIVATION has PSBT_IN_SP_TWEAK. An input with PSBT_IN_SP_TWEAK has a PSBT_IN_WITNESS_UTXO whose script is P2TR. Every spend key, plus the tweak times G, has the x-coordinate of the spent P2TR output key."),
]};

#[rustfmt::skip]
pub const GUIDANCE: DeclaredSection = DeclaredSection { category: "guidance", title: "Guidance", entries: &[
    Declaration::guidance("GUIDE-1", Should, "Creator fallback", bip!("BIP370 - Creator", "bip-0370.mediawiki#creator"),
        "The Creator SHOULD set fallback locktime. Its absence means zero when no input requires a locktime.")
        .role("Creator and Constructor"),
    Declaration::guidance("GUIDE-2", May, "Self-contained construction", bip!("BIP370 - Creator", "bip-0370.mediawiki#creator"),
        "A Creator that is also the Constructor may omit TX_MODIFIABLE if no other entity will add inputs or outputs.")
        .role("Creator and Constructor"),
    Declaration::guidance("GUIDE-3", May, "Branch alternatives", bip!("BIP370 - Constructor", "bip-0370.mediawiki#constructor"),
        "Both required locktime types may be set. If the chosen spend branch uses one type, that field can be the only one set.")
        .role("Creator and Constructor"),
    Declaration::guidance("GUIDE-4", May, "Close construction", bip!("BIP370 - Constructor", "bip-0370.mediawiki#constructor"),
        "A Constructor may close additions by clearing the appropriate modification flags or removing TX_MODIFIABLE.")
        .role("Creator and Constructor"),
    Declaration::guidance("GUIDE-5", Should, "Known metadata", bip!("BIP174 - Updater; Specification", "bip-0174.mediawiki#updater"),
        "Updaters SHOULD add available input UTXOs and known scripts and BIP32 origins at the applicable input/output scopes. PSBT_IN_NON_WITNESS_UTXO SHOULD be present for inputs spending non-segwit outputs and can be present for segwit ones; PSBT_IN_WITNESS_UTXO SHOULD only be present for inputs spending segwit outputs.")
        .role("Updater"),
    Declaration::guidance("GUIDE-6", Should, "Version and sequence", bip!("BIP174 - Version Numbers", "bip-0174.mediawiki#version-numbers"),
        "When adding a PSBT format version, use the highest required version as recommended by BIP174. A v2 Updater can set sequence.")
        .note("Sequence-setting permission does not authorize arbitrary PSBT format conversion.")
        .role("Updater"),
    Declaration::guidance("GUIDE-7", Should, "SP sending metadata", bip375!("BIP375 - Updater", "bip-0375.mediawiki#updater"),
        "Updaters SHOULD supply BIP32 derivation fields for P2PKH, P2WPKH and P2SH-P2WPKH inputs so public keys are available. BIP375 permits setting the derivation value to zero to withhold origin information.")
        .note("BIP375 describes a privacy alternative as setting the value to zero. Do not assume this uses BIP376’s separate four-byte-fingerprint encoding.")
        .role("Updater"),
    Declaration::guidance("GUIDE-8", May, "SP change annotations", bip375!("BIP375 - Change Detection", "bip-0375.mediawiki#change-detection"),
        "Updaters may supply scan/spend derivation information and a label for change detection.")
        .role("Updater"),
    Declaration::guidance("GUIDE-9", Should, "SP spending derivation", bip!("BIP376 - Updater", "bip-0376.mediawiki#updater"),
        "For an SP spend using BIP32, the Updater SHOULD add SP_SPEND_BIP32_DERIVATION. To hide origin information, it can use a four-byte zero fingerprint and no derivation paths.")
        .role("Updater"),
    Declaration::guidance("GUIDE-10", Should, "SP share generation", bip375!("BIP375 - Signer", "bip-0375.mediawiki#signer"),
        "The Signer SHOULD generate per-input shares and proofs for eligible inputs whose private keys it has, or a global share and proof when it has all eligible private keys, and compute missing scripts when share coverage is complete.")
        .role("Signer"),
    Declaration::guidance("GUIDE-11", Should, "General finalization cleanup", bip!("BIP174 - Input Finalizer", "bip-0174.mediawiki#input-finalizer"),
        "Empty scriptSig and nonexistent scriptWitness final fields SHOULD remain unset. Other input metadata SHOULD be cleared except UTXOs, unknown fields and fields retained by the version or extension rules.")
        .note("This general cleanup recommendation does not weaken the mandatory three-field SP cleanup in ROLE-F-8.")
        .role("Input Finalizer"),
    Declaration::guidance("GUIDE-12", Should, "Taproot finalization cleanup", bip!("BIP371 - Specification", "bip-0371.mediawiki#specification"),
        "BIP371: after constructing PSBT_IN_FINAL_SCRIPTWITNESS, Finalizers SHOULD remove PSBT_IN_TAP_KEY_SIG, PSBT_IN_TAP_SCRIPT_SIG, PSBT_IN_TAP_LEAF_SCRIPT, PSBT_IN_TAP_BIP32_DERIVATION, PSBT_IN_TAP_INTERNAL_KEY and PSBT_IN_TAP_MERKLE_ROOT.")
        .note("A recommendation; no validator fails a PSBT that keeps these fields.")
        .role("Input Finalizer"),
    Declaration::guidance("GUIDE-13", Should, "Taproot leaf scripts", bip!("BIP371 - Specification", "bip-0371.mediawiki#specification"),
        "BIP371: the leaves in PSBT_IN_TAP_LEAF_SCRIPT SHOULD be those the signers of the input are expected to be able to sign for.")
        .note("Because inputs may omit leaves, input derivation leaf hashes are not checked against PSBT_IN_TAP_LEAF_SCRIPT.")
        .role("Updater"),
    Declaration::guidance("GUIDE-14", May, "Taproot UTXO types", bip!("BIP371 - UTXO Types", "bip-0371.mediawiki#utxo-types"),
        "BIP371: a Taproot input may carry only PSBT_IN_WITNESS_UTXO, since a Taproot signature commits to every spent amount and script.")
        .note("Taproot rules take the spent output from either UTXO field.")
        .role("Updater"),
    Declaration::guidance("GUIDE-15", Should, "Global xpub depth", bip!("BIP174 - Specification (PSBT_GLOBAL_XPUB)", "bip-0174.mediawiki#specification"),
        "A PSBT_GLOBAL_XPUB SHOULD be the public key at the highest hardened derivation index, so the unhardened child keys in the transaction can be derived from it.")
        .role("Updater"),
    Declaration::guidance("GUIDE-16", May, "Signer UTXO policy", bip!("BIP174 - Signer", "bip-0174.mediawiki#signer"),
        "A Signer may refuse to sign a segwit input that has no PSBT_IN_NON_WITNESS_UTXO.")
        .role("Signer"),
    Declaration::guidance("GUIDE-17", Should, "Default sighash type", bip!("BIP174 - Data Signers Check For", "bip-0174.mediawiki#data-signers-check-for"),
        "Without PSBT_IN_SIGHASH_TYPE, a Signer SHOULD sign using SIGHASH_ALL, but may use any sighash type.")
        .role("Signer"),
    Declaration::guidance("GUIDE-18", Should, "Partial signature validity", bip!("BIP174 - Specification (PSBT_IN_PARTIAL_SIG)", "bip-0174.mediawiki#specification"),
        "A PSBT_IN_PARTIAL_SIG value SHOULD be a valid ECDSA signature for its public key, as it would be pushed to the stack.")
        .note("General validation does not check PSBT_IN_PARTIAL_SIG signatures; ROLE-F-4 does before finalizing.")
        .role("Signer"),
    Declaration::guidance("GUIDE-19", Should, "MuSig2 input metadata", bip!("BIP373 - Updater", "bip-0373.mediawiki#updater"),
        "BIP373: an Updater that knows a MuSig2 aggregate key in a Taproot output may add PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS, SHOULD add PSBT_IN_TAP_BIP32_DERIVATION for the participant keys, and for a key derived from the aggregate key SHOULD add that derivation, which follows BIP328 unless a PSBT_GLOBAL_XPUB gives the synthetic xpub.")
        .role("Updater"),
    Declaration::guidance("GUIDE-20", Should, "MuSig2 output metadata", bip!("BIP373 - Updater", "bip-0373.mediawiki#updater"),
        "BIP373: Updaters SHOULD add PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS and PSBT_OUT_TAP_BIP32_DERIVATION to outputs, as for inputs, to aid change detection.")
        .role("Updater"),
    Declaration::guidance("GUIDE-21", Should, "MuSig2 participation and nonces", bip!("BIP373 - Signer", "bip-0373.mediawiki#signer"),
        "BIP373: a Signer SHOULD find its participation through PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS and its PSBT_IN_TAP_BIP32_DERIVATION keys, and SHOULD add a PSBT_IN_MUSIG2_PUB_NONCE when it has none. Improper nonce use can compromise private keys; see BIP327.")
        .role("Signer"),
    Declaration::guidance("GUIDE-22", Should, "BIP353 proof inclusion", bip!("BIP353 - PSBT types", "bip-0353.mediawiki#psbt-types"),
        "BIP353: wallets creating PSBTs with recipient information from a human-readable name SHOULD include PSBT_OUT_DNSSEC_PROOF. Wallets accepting payment information from external devices MAY examine it.")
        .role("Creator and Constructor"),
    Declaration::guidance("GUIDE-23", Should, "BIP353 recipient display", bip!("BIP353 - Display; Resolution", "bip-0353.mediawiki#display"),
        "BIP353: when a proof validates, a Signer SHOULD display the recipient as ₿user@domain.")
        .role("Signer"),
    Declaration::guidance("GUIDE-24", Should, "BIP322 signing presentation", bip!("BIP322 - PSBT signer; PSBT creator", "bip-0322.mediawiki#psbt-signer"),
        "BIP322: the Signer's presentation SHOULD resemble signing a message rather than a transaction. Creators should keep the message to a few kilobytes and commit to very large messages by hash.")
        .role("Signer"),
    Declaration::guidance("GUIDE-25", Should, "P2C tweak cleanup", bip!("BIP372 - Specification", "bip-0372.mediawiki#specification"),
        "BIP372: Signers SHOULD remove PSBT_IN_P2C_TWEAK after PSBT_IN_PARTIAL_SIG is constructed.")
        .role("Signer"),
    Declaration::guidance("GUIDE-26", Should, "SP DLEQ verification", bip375!("BIP375 - Signer", "bip-0375.mediawiki#signer"),
        "BIP375: at minimum, the Signer SHOULD verify the DLEQ proofs of eligible inputs it has no private keys for, or the global DLEQ proof if it is set, as REF-3 describes. Verifying the proofs of inputs it has the private keys for as well is acceptable.")
        .resolution("BIP375's Signer section limits per-input verification to inputs the Signer has no private keys for, while the reference validator and the ECDH coverage vectors verify every eligible input's proof. The BIP's scope is read as the minimum, so a Signer that also verifies its own inputs, as GEN-SP-3 requires of the PSBT it receives, conforms.")
        .role("Signer"),
]};

const DECLARED: &[DeclaredSection] = &[FRAMING, STRUCTURE, TRANSACTION, TAPROOT, MUSIG2, DNS, SIGNED_MESSAGES, PAY_TO_CONTRACT, SILENT_PAYMENTS, CREATOR_AND_CONSTRUCTOR, UPDATER, SIGNER, INPUT_FINALIZER, TRANSACTION_EXTRACTOR, COMBINER, DEFINITIONS, REFERENCE, GUIDANCE];

/// Splits a PSBT the framing rules accept into maps, noting the enabled BIPs.
pub fn parse(bytes: &[u8], bips: &[Bip]) -> Psbt {
    Psbt { bips: bips.to_vec(), ..crate::encoding::scan(bytes).ok().unwrap() }
}

fn maps(psbt: &Psbt) -> Vec<Map> { psbt.maps.clone() }
fn inputs(psbt: &PsbtContext) -> Vec<InputContext> { psbt.inputs() }
fn outputs(psbt: &PsbtContext) -> Vec<OutputContext> { psbt.outputs() }

/// GEN-F-1 through GEN-F-3 establish the byte-level prerequisites for parse().
/// These checks fail before any map decoding or positional context projection.
#[rustfmt::skip]
pub fn framing_rules() -> BoxNode<[u8]> {
  section("Framing", seq(vec![
      check!("GEN-F-1", crate::rules::framing::validate_magic),
      check!("GEN-F-2", crate::rules::framing::validate_records),
      check!("GEN-F-3", crate::rules::framing::validate_maps_terminated),
    ]))
}


/// General rule bindings used by evaluate().
#[rustfmt::skip]
pub fn general_rules(bips: &[Bip]) -> BoxNode<[u8]> {
  // Framing, field formats and structure are ordered: each step reads what
  // the earlier ones accepted. The extension sections are independent.
  seq(vec![
    framing_rules(),
    with({ let bips = bips.to_vec(); move |bytes: &[u8]| parse(bytes, &bips) }, seq(vec![
      each(maps,
        check!("GEN-F-4", crate::rules::global::validate_unique_keys)),
      check!("GEN-F-5", crate::rules::global::validate_global_field_formats),
      section("Structure", seq(vec![
        check!("GEN-ST-1", crate::rules::global::validate_version),
        check!("GEN-ST-2", crate::rules::global::validate_global_field_versions),
        check!("GEN-ST-3", crate::rules::global::validate_map_count),
      ])),
      // GEN-F-5 and GEN-ST-2 again, for each input and output map once
      // GEN-ST-3 has assigned them.
      with(PsbtContext::new, seq(vec![
       all(vec![
        each(inputs, all(vec![
          check!("GEN-F-5", crate::rules::input_output::validate_input_field_formats),
          check!("GEN-ST-2", crate::rules::input_output::validate_input_field_versions),
        ])),
        each(outputs, all(vec![
          check!("GEN-F-5", crate::rules::input_output::validate_output_field_formats),
          check!("GEN-ST-2", crate::rules::input_output::validate_output_field_versions),
        ])),
       ]),
       // The semantic sections read fields GEN-F-5 accepted; they are
       // independent of each other.
       all(vec![
        section("Transaction", when("PSBTv2", |p: &PsbtContext| p.version == 2, all(vec![
          check!("GEN-T-1", crate::rules::input_output::validate_locktime_determinable),
          check!("GEN-T-2", crate::rules::input_output::validate_inputs_modifiable_flag),
          check!("GEN-T-2", crate::rules::input_output::validate_outputs_modifiable_flag),
          check!("GEN-T-2", crate::rules::input_output::validate_sighash_single_flag),
        ]))),
        section("Taproot", all(vec![
          each(inputs,
            check!("GEN-TR-1", crate::rules::taproot::validate_taproot_control_block_commitment)),
          each(inputs,
            check!("GEN-TR-2", crate::rules::taproot::validate_taproot_key_commitments)),
          each(outputs,
            check!("GEN-TR-3", crate::rules::taproot::validate_taproot_output_commitment)),
          each(outputs,
            check!("GEN-TR-4", crate::rules::taproot::validate_taproot_output_derivation_leaves)),
        ])),
        section("MuSig2", all(vec![
          each(inputs,
            check!("GEN-MS-1", crate::rules::musig::validate_musig2_plain_keys)),
          check!("GEN-MS-2", crate::rules::musig::validate_musig2_key_aggregation),
        ])),
        section("DNS payment instructions", all(vec![
          each(outputs,
            check!("GEN-DNS-1", crate::rules::dnssec::validate_dnssec_proof_structure)),
        ])),
        section("Generic signed messages", all(vec![
          check!("GEN-MSG-1", crate::rules::message::validate_bip322_challenge_utxo),
          check!("GEN-MSG-2", crate::rules::message::validate_bip322_proof_of_funds_utxos),
          check!("GEN-MSG-3", crate::rules::message::validate_bip322_sighash),
          check!("GEN-MSG-4", crate::rules::message::validate_bip322_upgradeable_rules),
        ])),
        section("Pay-to-contract", all(vec![
          each(inputs,
            check!("GEN-P2C-1", crate::rules::p2c::validate_p2c_tweak_commitment)),
        ])),
        section("Silent payments", from(Bip::Bip375, bips, all(vec![
          each(outputs,
            check!("GEN-SP-1", crate::rules::sending::validate_sp_label_has_info)),
          when("Silent payment outputs", has_sp_outputs,
            check!("GEN-SP-7", crate::rules::sending::validate_sp_unsigned_until_scripts)),
          // BIP375's checks in its order; later subchecks read what earlier ones accepted.
          when("Silent payment outputs", has_sp_outputs, seq(vec![
            check!("GEN-SP-2", crate::rules::sending::validate_sp_tx_unmodifiable),
            check!("GEN-SP-3", crate::rules::sending::validate_ecdh_coverage),
            check!("GEN-SP-3", crate::rules::sending::validate_global_dleq_present),
            check!("GEN-SP-3", crate::rules::sending::validate_global_share_pubkeys),
            check!("GEN-SP-3", crate::rules::sending::validate_global_dleq_proof),
            each(inputs, seq(vec![
              check!("GEN-SP-3", crate::rules::sending::validate_input_dleq_present),
              check!("GEN-SP-3", crate::rules::sending::validate_input_share_pubkey),
              check!("GEN-SP-3", crate::rules::sending::validate_input_dleq_proof),
            ])),
            each(inputs, all(vec![
              check!("GEN-SP-4", crate::rules::sending::validate_sp_segwit_version),
              check!("GEN-SP-4", crate::rules::sending::validate_sp_sighash_type),
              check!("GEN-SP-4", crate::rules::sending::validate_sp_signatures),
            ])),
            check!("GEN-SP-5", crate::rules::sending::validate_sp_script_derivable),
            check!("GEN-SP-5", crate::rules::sending::validate_sp_script),
          ])),
        ]))),
        section("Silent payments", from(Bip::Bip376, bips, each(inputs, seq(vec![
          check!("GEN-SP-6", crate::rules::spending::validate_sp_finalized_cleared),
          check!("GEN-SP-6", crate::rules::spending::validate_sp_spend_key_has_tweak),
          check!("GEN-SP-6", crate::rules::spending::validate_sp_tweak_spends_p2tr),
          check!("GEN-SP-6", crate::rules::spending::validate_sp_tweaked_spend_key),
        ])))),
       ]),
      ])),
    ])),
  ])
}

/// Updater obligations.
#[rustfmt::skip]

/// Signer, before and after: the signatures and fields the Signer added.
#[rustfmt::skip]
pub fn signer_transition_obligations() -> BoxNode<SignerTransitionContext> {
  section("Signer", result(all(vec![
    check!("ROLE-S-9", crate::rules::signer::validate_signer_data_preservation),
    check!("ROLE-S-10", crate::rules::signer::validate_signer_sighash_type),
    check!("ROLE-S-11", crate::rules::signer::validate_sp_key_signature_written),
  ])))
}

// The Input Finalizer's rules are split by when they apply, because each phase
// sees a different context: the input it is given (before), the finalized
// input (after), and the pair (across). All three render as one Input
// Finalizer section in the catalog.

/// Input Finalizer, before finalizing: preconditions on the input it is given.
/// ROLE-F-1 is Incomplete for an input already finalized with a Taproot script path.
#[rustfmt::skip]
pub fn finalizer_obligations() -> BoxNode<InputContext> {
  section("Input Finalizer", precondition(all(vec![
    check!("ROLE-F-1", crate::rules::finalizer::validate_finalizer_sighash_type),
    check!("ROLE-F-2", crate::rules::finalizer::validate_sp_finalization_key_sig),
    check!("ROLE-F-3", crate::rules::taproot::validate_taproot_signatures),
    check!("ROLE-F-5", crate::rules::musig::validate_musig2_partial_signatures),
    // Last: what it cannot check is Incomplete, which would otherwise hide
    // a failure of the rules before it.
    check!("ROLE-F-4", crate::rules::finalizer::validate_finalizer_ecdsa_signatures),
  ])))
}

/// Input Finalizer, after finalizing: properties of each finalized input.
/// ROLE-F-6 runs last: it is Incomplete wherever script satisfaction is not
/// checked, which would otherwise hide a ROLE-F-9 or ROLE-F-10 failure.
#[rustfmt::skip]
pub fn finalizer_role_obligations() -> BoxNode<InputContext> {
  section("Input Finalizer", result(all(vec![
    check!("ROLE-F-9", crate::rules::taproot::validate_taproot_script_path_finalization),
    check!("ROLE-F-10", crate::rules::taproot::validate_taproot_key_path_finalization),
    check!("ROLE-F-6", crate::rules::finalizer::validate_final_script_construction),
  ])))
}

/// Input Finalizer, across finalizing: the input before and after.
#[rustfmt::skip]
pub fn finalizer_transition_obligations() -> BoxNode<FinalizerTransitionContext> {
  section("Input Finalizer", result(all(vec![
    check!("ROLE-F-7", crate::rules::finalizer::validate_finalizer_field_retention),
    check!("ROLE-F-8", crate::rules::finalizer::validate_sp_finalized_witness),
  ])))
}

/// Extractor obligations.
#[rustfmt::skip]
pub fn extractor_role_obligations() -> BoxNode<PsbtContext> {
  section("Transaction Extractor", precondition(all(vec![
    check!("ROLE-X-1", crate::rules::extractor::validate_extraction_readiness),
  ])))
}

/// Signer, before signing: prerequisites for the selected input and signature kind.
#[rustfmt::skip]
pub fn signer_obligations() -> BoxNode<SigningInputContext> {
  section("Signer", precondition(all(vec![
    check!("ROLE-S-1", crate::rules::catalog::validate_signing_non_witness_utxo),
    check!("ROLE-S-2", crate::rules::catalog::validate_signing_redeem_script),
    check!("ROLE-S-3", crate::rules::catalog::validate_signing_witness_script),
    check!("ROLE-S-4", crate::rules::catalog::validate_signing_signature_kind),
  ])))
}

/// Signer, before signing: a BIP353 DNSSEC proof the Signer validates, with the
/// verification time the caller supplies.
#[rustfmt::skip]
pub fn signer_proof_obligations() -> BoxNode<crate::rules::dnssec::DnssecProofContext> {
  section("Signer",
    precondition(check!("ROLE-S-6", crate::rules::dnssec::validate_dnssec_proof_validation)))
}

/// Reusable Combiner transition checks, with their documented coverage limits.
#[rustfmt::skip]
pub fn combiner_obligations() -> BoxNode<TransitionContext> {
  section("Combiner", all(vec![
    precondition(check!("ROLE-B-1", crate::rules::combiner::validate_shared_unique_id)),
    result(check!("ROLE-B-2", crate::rules::catalog::validate_merge_preservation)),
  ]))
}

/// Creator obligations.
#[rustfmt::skip]
pub fn creator_obligations() -> BoxNode<CreatorContext> {
  section("Creator", result(all(vec![
    check!("ROLE-C-1", crate::rules::creator::validate_creator_initialization),
    check!("ROLE-C-2", crate::rules::creator::validate_delegated_construction),
  ])))
}

/// Constructor obligations.
#[rustfmt::skip]
pub fn constructor_obligations() -> BoxNode<ConstructorTransitionContext> {
  section("Constructor", result(all(vec![
    check!("ROLE-C-3", crate::rules::constructor::validate_permitted_additions),
    check!("ROLE-C-4", crate::rules::constructor::validate_spend_branch_locktime),
    check!("ROLE-C-5", crate::rules::constructor::validate_preserve_signed_locktime),
    check!("ROLE-C-6", crate::rules::constructor::validate_preserve_single_pairing),
  ])))
}

/// Describes the new bindings without invoking their checks or reading JSON.
pub fn describe() -> Doc {
    let mut doc = Doc::default();
    general_rules(&[Bip::Bip375, Bip::Bip376]).describe(&mut doc);
    creator_obligations().describe(&mut doc);
    constructor_obligations().describe(&mut doc);
    signer_obligations().describe(&mut doc);
    signer_proof_obligations().describe(&mut doc);
    signer_transition_obligations().describe(&mut doc);
    finalizer_obligations().describe(&mut doc);
    finalizer_role_obligations().describe(&mut doc);
    finalizer_transition_obligations().describe(&mut doc);
    extractor_role_obligations().describe(&mut doc);
    combiner_obligations().describe(&mut doc);
    doc
}

/// Builds the reading catalog from rule descriptions and explicit documentation.
pub fn specification() -> Specification {
    build(&describe(), DESCRIPTIONS, DECLARED)
}

// These entries do not implement Node and cannot masquerade as successful checks.
// TODO: implement pending role obligations when their operation contexts exist.
#[rustfmt::skip]
const DESCRIPTIONS: &[Text] = &[
    // Preamble
    text("Scope", "This specification covers PSBT versions 0 and 2 (GEN-ST-1), with the extensions of BIP371, BIP372, BIP373, BIP353, BIP322, BIP375 and BIP376."),
    text("Applicability", "BIP375 and BIP376 provisions apply when the corresponding extension is supported. General rules describe PSBT properties. Role obligations describe the operation being performed."),
    text("Validation context", "A check needs enough authenticated context to evaluate its property. Missing context is an incomplete check, not a verified match. Signers use only UTXOs provided in the PSBT."),
];
