//! Every rule with a check is observed by its ID through an entry point: a
//! case it decides as Verified, and one it reports as Failed (Incomplete for
//! a rule that never fails). Evidence comes from the vector corpus, whose
//! expectations tests/vectors.rs asserts, and from the cases below, mostly
//! small edits of published PSBTs.
//!
//! A Verified case is one its entry point accepts while the rule's trace in
//! that entry point's graph reports Passed. One rule cannot be observed that
//! way: ROLE-F-6 is Incomplete on every script-path spend, so ROLE-F-9's
//! Verified case is an evaluation stopped only by ROLE-F-6.
//!
//! A role rule whose breach a General rule would already report has no case
//! here: by principle 4 (PRINCIPLES.md) such a rule does not exist.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::STANDARD, Engine};
use common::{encode, field, graph_statuses, hex, outcome, psbt, status, txout, vectors};
use psbt_spec::algebra::{Trace, TraceStatus};
use psbt_spec::context::*;
use psbt_spec::encoding::{scan, Psbt, Record, MAGIC};
use psbt_spec::rules::dnssec::OUT_DNSSEC_PROOF;
use psbt_spec::rules::message::{bip322_to_spend_txid, GLOBAL_GENERIC_SIGNED_MESSAGE};
use psbt_spec::algebra::each;
use psbt_spec::context::{signing_tx, spent_outputs, TransitionContext};
use psbt_spec::taproot::{leaf_hash, taproot_output_key, taproot_sighash};
use psbt_spec::rules::dnssec::DnssecProofContext;
use psbt_spec::{
    evaluate, evaluate_combining, evaluate_constructing, evaluate_creating, evaluate_dnssec_proofs, evaluate_extracting,
    evaluate_finalizing, evaluate_for_finalizing, evaluate_for_signing, evaluate_signing, spec, Bip,
    ConstructorTransitionContext, CreatorContext, Evaluation, SignatureKind, SignerTransitionContext, SigningInputContext,
};
use serde_json::Value;

const CORPORA: [(&str, &[Bip]); 7] = [
    ("bip174", &[]),
    ("bip370", &[]),
    ("bip370_locktime", &[]),
    ("bip371", &[]),
    ("bip373", &[]),
    ("bip375", &[Bip::Bip375]),
    ("derived/bip376", &[Bip::Bip376]),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Seen {
    Verified,
    Failed,
    Incomplete,
}

/// The rules each outcome was observed for, from the vector corpus.
fn vector_evidence() -> BTreeMap<&'static str, BTreeSet<Seen>> {
    let mut seen: BTreeMap<&'static str, BTreeSet<Seen>> = BTreeMap::new();
    for (corpus, bips) in CORPORA {
        for v in vectors(corpus) {
            match outcome(&v, bips) {
                Evaluation::Failed(x) => {
                    seen.entry(x.rule).or_default().insert(Seen::Failed);
                }
                Evaluation::Incomplete(x) => {
                    seen.entry(x.rule).or_default().insert(Seen::Incomplete);
                }
                _ => {}
            }
            for id in general_passed(&psbt(&v), bips) {
                seen.entry(id).or_default().insert(Seen::Verified);
            }
        }
    }
    for case in cases() {
        seen.entry(case.rule).or_default().insert(case.seen);
    }
    seen
}

/// The General rules whose trace reports Passed on a PSBT `evaluate` accepts.
fn general_passed(bytes: &[u8], bips: &[Bip]) -> Vec<&'static str> {
    if evaluate(bytes, bips) != Evaluation::Verified {
        return Vec::new();
    }
    let mut trace = Trace::default();
    spec::general_rules(bips).evaluate_traced(bytes, &mut trace);
    trace.observations.into_iter().filter(|o| o.status == TraceStatus::Passed).map(|o| o.id).collect()
}

/// The rules.json entries in scope: General and Role rules with a check.
fn checked_rules() -> Vec<Value> {
    let rules: Value = serde_json::from_str(include_str!("../../rules.json")).unwrap();
    rules["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["checks"].as_array().is_some_and(|c| !c.is_empty()))
        .filter(|r| matches!(r["category"].as_str(), Some("general" | "role")))
        .cloned()
        .collect()
}

#[test]
fn every_checked_rule_is_observed_verified_and_failing() {
    let seen = vector_evidence();
    let mut missing = Vec::new();
    for rule in checked_rules() {
        let id = rule["id"].as_str().unwrap();
        let got = seen.get(id).cloned().unwrap_or_default();
        let never_fails = rule["note"].as_str().unwrap().starts_with("Never Failed");
        let negative = if never_fails { Seen::Incomplete } else { Seen::Failed };
        for want in [Seen::Verified, negative] {
            if !got.contains(&want) {
                missing.push(format!("{id} {want:?}"));
            }
        }
    }
    assert!(missing.is_empty(), "{} missing:\n{}", missing.len(), missing.join("\n"));
}

#[test]
fn every_case_reports_its_rule() {
    let wrong: Vec<String> = cases()
        .into_iter()
        .filter(|case| {
            !match (&case.got, case.seen) {
                (Evaluation::Verified, Seen::Verified) => true,
                (Evaluation::Failed(v), Seen::Failed) | (Evaluation::Incomplete(v), Seen::Incomplete) => v.rule == case.rule,
                _ => false,
            }
        })
        .map(|case| format!("{} {:?} ({}): got {:?}", case.rule, case.seen, case.what, case.got))
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// One observation of `rule` through an entry point.
struct Case {
    rule: &'static str,
    seen: Seen,
    what: &'static str,
    got: Evaluation,
}

fn case(rule: &'static str, seen: Seen, what: &'static str, got: Evaluation) -> Case {
    Case { rule, seen, what, got }
}

fn cases() -> Vec<Case> {
    let mut all = general_cases();
    all.extend(finalizer_cases());
    all.extend(extractor_and_combiner_cases());
    all.extend(signer_cases());
    all.extend(construction_cases());
    all
}

// Fixtures.

/// The vector in `corpus` whose description starts with or contains `needle`.
fn fixture(corpus: &str, needle: &str) -> Psbt {
    let v = vectors(corpus)
        .into_iter()
        .find(|v| v["description"].as_str().unwrap().contains(needle))
        .unwrap_or_else(|| panic!("no {corpus} vector {needle}"));
    let Ok(psbt) = scan(&STANDARD.decode(v["psbt"].as_str().unwrap()).unwrap()) else { panic!("{needle}") };
    psbt
}

fn edited(mut psbt: Psbt, edit: impl FnOnce(&mut Psbt)) -> Vec<u8> {
    edit(&mut psbt);
    encode(&psbt)
}

fn find(map: &mut [Record], key_type: u64) -> &mut Record {
    map.iter_mut().find(|r| r.key_type == key_type).unwrap_or_else(|| panic!("no field {key_type:#x}"))
}

fn u32le(n: u32) -> Vec<u8> {
    n.to_le_bytes().to_vec()
}

/// A PSBTv2 with the given extra global fields, inputs (after their previous
/// txid and output index) and outputs.
fn v2(global: Vec<Record>, inputs: Vec<Vec<Record>>, outputs: Vec<Vec<Record>>) -> Psbt {
    let mut g = vec![
        field(GLOBAL_VERSION, vec![], u32le(2)),
        field(GLOBAL_TX_VERSION, vec![], u32le(2)),
        field(GLOBAL_INPUT_COUNT, vec![], vec![inputs.len() as u8]),
        field(GLOBAL_OUTPUT_COUNT, vec![], vec![outputs.len() as u8]),
    ];
    g.extend(global);
    let mut maps = vec![g];
    for (n, input) in inputs.into_iter().enumerate() {
        let mut map = vec![field(IN_PREVIOUS_TXID, vec![], vec![n as u8 + 1; 32]), field(IN_OUTPUT_INDEX, vec![], u32le(0))];
        map.extend(input);
        maps.push(map);
    }
    maps.extend(outputs);
    Psbt { maps, bips: vec![] }
}

fn output(script: &[u8]) -> Vec<Record> {
    vec![field(OUT_AMOUNT, vec![], 9_000i64.to_le_bytes().to_vec()), field(OUT_SCRIPT, vec![], script.to_vec())]
}

const P2WPKH: [u8; 22] = [0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

/// A v2 BIP322 PSBT with one to_sign input spending to_spend, whose first
/// input's PSBT_IN_WITNESS_UTXO has `amount`, plus `extra` inputs.
fn message(amount: i64, extra: Vec<Vec<Record>>, signature_hash: Option<u8>) -> Psbt {
    let msg = b"Hello World".to_vec();
    let challenge = P2WPKH.to_vec();
    let mut first = vec![field(IN_WITNESS_UTXO, vec![], txout(amount, &challenge))];
    first.extend(signature_hash.map(|t| field(IN_PARTIAL_SIG, hex(KEY), vec![0x30, 0x01, t])));
    let mut inputs = vec![first];
    inputs.extend(extra);
    let mut psbt = v2(vec![field(GLOBAL_GENERIC_SIGNED_MESSAGE, vec![], msg.clone())], inputs, vec![output(&[0x6a])]);
    find(&mut psbt.maps[1], IN_PREVIOUS_TXID).value = bip322_to_spend_txid(&msg, &challenge).to_vec();
    find(&mut psbt.maps[0], GLOBAL_OUTPUT_COUNT).value = vec![1];
    if let Some(r) = psbt.maps.last_mut().unwrap().iter_mut().find(|r| r.key_type == OUT_AMOUNT) {
        r.value = 0i64.to_le_bytes().to_vec();
    }
    psbt
}

const KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const OTHER_KEY: &str = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

/// A General case through `evaluate`. A Verified one also needs the rule's
/// trace to report Passed, or it is recorded as NotApplicable.
fn general(rule: &'static str, seen: Seen, what: &'static str, bytes: &[u8]) -> Case {
    let got = match evaluate(bytes, &[]) {
        Evaluation::Verified if status(bytes, rule) != TraceStatus::Passed => Evaluation::NotApplicable,
        got => got,
    };
    case(rule, seen, what, got)
}

/// General rules no vector fails.
fn general_cases() -> Vec<Case> {
    use Seen::*;
    let valid = encode(&fixture("bip370", "1 input, 2 output PSBTv2, required fields only."));
    // Key 0xfb with a value length of 4 and only two bytes left.
    let truncated = [&MAGIC[..], &[1, 0xfb, 4, 2, 0]].concat();
    let mut non_minimal = MAGIC.to_vec();
    // Key length 3 holding key type 0xfb as the non-minimal fd fb 00.
    non_minimal.extend([3, 0xfd, 0xfb, 0x00, 4, 2, 0, 0, 0, 0]);
    let unterminated = valid[..valid.len() - 1].to_vec();
    let version_3 = edited(fixture("bip370", "1 input, 2 output PSBTv2, required fields only."), |p| {
        find(&mut p.maps[0], GLOBAL_VERSION).value = u32le(3)
    });

    let script_input = || fixture("bip371", "script path only input with dummy internal key, scripts, script key derivation paths, merkle root, and script path signatures");
    let script_output = || fixture("bip371", "script path only output with dummy internal key");
    let musig = |stage: &str| fixture("bip373", &format!("output key is a MuSig2 Aggregate Pubkey (With {stage}"));

    let proof: Vec<Value> = serde_json::from_str(include_str!("../../vectors/bip353_proofs.json")).unwrap();
    let mut proof = hex(proof[0]["proof_hex"].as_str().unwrap());
    let with_proof = |value: Vec<u8>| encode(&v2(vec![], vec![], vec![[output(&[0x51]), vec![field(OUT_DNSSEC_PROOF, vec![], value)]].concat()]));
    let dns_ok = with_proof(proof.clone());
    let at = proof.iter().position(|&b| b == b'@').unwrap();
    proof[at] = b'.';

    // P2C: original key G and tweak 1 commit to 2G.
    let p2c = |spent_script: Vec<u8>| {
        let mut tweak = [0u8; 32];
        tweak[31] = 1;
        let input = vec![field(IN_WITNESS_UTXO, vec![], txout(10_000, &spent_script)), field(IN_P2C_TWEAK, hex(KEY), tweak.to_vec())];
        encode(&v2(vec![], vec![input], vec![output(&[0x51])]))
    };
    let two_g = hex("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
    use bitcoin_hashes::{hash160, Hash};
    let p2wpkh_2g = [&[0x00, 0x14][..], &hash160::Hash::hash(&two_g).to_byte_array()].concat();
    let utxo = |script: &[u8]| field(IN_WITNESS_UTXO, vec![], txout(1_000, script));
    let mut v3_message = message(0, vec![], None);
    find(&mut v3_message.maps[0], GLOBAL_TX_VERSION).value = u32le(3);

    let modifiable_signed = edited(fixture("bip375", "can finalize: one P2WPKH input with PSBT_GLOBAL_TX_MODIFIABLE omitted"), |p| {
        p.maps[0].push(field(GLOBAL_TX_MODIFIABLE, vec![], vec![0x01]));
    });

    vec![
        general("GEN-F-2", Failed, "value length past the end", &truncated),
        general("GEN-F-2", Failed, "non-minimal key type", &non_minimal),
        general("GEN-F-3", Failed, "last map unterminated", &unterminated),
        general("GEN-ST-1", Failed, "version 3", &version_3),
        general("GEN-T-2", Failed, "SIGHASH_ALL signature with Inputs Modifiable set", &modifiable_signed),
        general("GEN-TR-1", Failed, "control block for another key", &edited(script_input(), |p| {
            find(&mut p.maps[1], IN_TAP_LEAF_SCRIPT).key_data[1..33].copy_from_slice(&hex(OTHER_KEY))
        })),
        general("GEN-TR-2", Incomplete, "key-only mismatch", &edited(fixture("bip371", "P2TR key only input with internal key and its derivation path"), |p| {
            find(&mut p.maps[1], IN_TAP_INTERNAL_KEY).value = hex(OTHER_KEY)
        })),
        general("GEN-TR-3", Failed, "wrong internal key with a tree", &edited(script_output(), |p| {
            find(p.maps.last_mut().unwrap(), OUT_TAP_INTERNAL_KEY).value = hex(OTHER_KEY)
        })),
        general("GEN-TR-3", Incomplete, "key-only mismatch", &edited(fixture("bip371", "P2TR key only output with internal key"), |p| {
            find(p.maps.last_mut().unwrap(), OUT_TAP_INTERNAL_KEY).value = hex(OTHER_KEY)
        })),
        general("GEN-TR-4", Failed, "derivation leaf not in the tree", &edited(script_output(), |p| {
            let d = p.maps.last_mut().unwrap().iter_mut().find(|r| r.key_type == OUT_TAP_BIP32_DERIVATION && r.value[0] > 0).unwrap();
            d.value[1] ^= 1;
        })),
        general("GEN-TR-4", Incomplete, "no tree", &edited(script_output(), |p| {
            p.maps.last_mut().unwrap().retain(|r| r.key_type != OUT_TAP_TREE && r.key_type != OUT_TAP_INTERNAL_KEY)
        })),
        general("GEN-MS-1", Failed, "plain key is not the output key", &edited(musig("all pubnonces"), |p| {
            let r = p.maps.iter_mut().flatten().find(|r| r.key_type == IN_MUSIG2_PUB_NONCE).unwrap();
            let participant = r.key_data[..33].to_vec();
            r.key_data[33..66].copy_from_slice(&participant);
        })),
        general("GEN-MS-2", Failed, "participants swapped", &edited(musig("participant pubkeys only"), |p| {
            let list = &mut find(&mut p.maps[1], IN_MUSIG2_PARTICIPANT_PUBKEYS).value;
            let first = list[..33].to_vec();
            list.copy_within(33..66, 0);
            list[33..66].copy_from_slice(&first);
        })),
        general("GEN-DNS-1", Verified, "published proof", &dns_ok),
        general("GEN-DNS-1", Failed, "name without @", &with_proof(proof)),
        general("GEN-MSG-1", Verified, "to_spend output of amount 0", &encode(&message(0, vec![], None))),
        general("GEN-MSG-1", Failed, "to_spend output of amount 1", &encode(&message(1, vec![], None))),
        general("GEN-MSG-2", Verified, "second input has a UTXO", &encode(&message(0, vec![vec![utxo(&P2WPKH)]], None))),
        general("GEN-MSG-2", Failed, "second input has no UTXO", &encode(&message(0, vec![vec![]], None))),
        general("GEN-MSG-3", Verified, "SIGHASH_ALL", &encode(&message(0, vec![], Some(0x01)))),
        general("GEN-MSG-3", Failed, "SIGHASH_NONE", &encode(&message(0, vec![], Some(0x02)))),
        general("GEN-MSG-4", Verified, "to_sign version 2", &encode(&message(0, vec![], None))),
        general("GEN-MSG-4", Incomplete, "to_sign version 3", &encode(&v3_message)),
        general("GEN-MSG-4", Incomplete, "spends segwit v2", &encode(&message(0, vec![vec![utxo(&[0x52, 0x02, 1, 2])]], None))),
        general("GEN-P2C-1", Verified, "P2WPKH of the tweaked key", &p2c(p2wpkh_2g)),
        general("GEN-P2C-1", Failed, "script commits to another key", &p2c(P2WPKH.to_vec())),
    ]
}

// Role rules.

fn ctx(bytes: &[u8], bips: &[Bip]) -> PsbtContext {
    PsbtContext::new(&spec::parse(bytes, bips))
}

/// A role case: `got` from the role's entry point, and the rule's statuses in
/// that role's graph. A Verified outcome counts only where the rule Passed.
fn role(rule: &'static str, seen: Seen, what: &'static str, got: Evaluation, trace: Vec<(TraceStatus, String)>) -> Case {
    let passed = trace.iter().any(|(s, _)| *s == TraceStatus::Passed);
    let got = match got {
        Evaluation::Verified if !passed => Evaluation::NotApplicable,
        got => got,
    };
    case(rule, seen, what, got)
}

/// Every status of `id` in the Finalizer's graphs for `received` and, when
/// given, the input pairs and finalized inputs of `returned`.
fn finalizer_trace(id: &str, received: &[u8], returned: Option<&[u8]>, bips: &[Bip]) -> Vec<(TraceStatus, String)> {
    let before = ctx(received, bips);
    let mut all = graph_statuses(each(|p: &PsbtContext| p.inputs(), spec::finalizer_obligations()), &before, id);
    if let Some(returned) = returned {
        let after = ctx(returned, bips);
        let pairs: Vec<psbt_spec::FinalizerTransitionContext> = before
            .inputs()
            .into_iter()
            .zip(after.inputs())
            .map(|(b, a)| psbt_spec::FinalizerTransitionContext::new(b, a))
            .collect();
        all.extend(graph_statuses(each(|p: &Vec<_>| Vec::clone(p), spec::finalizer_transition_obligations()), &pairs, id));
        all.extend(graph_statuses(each(|p: &PsbtContext| p.inputs(), spec::finalizer_role_obligations()), &after, id));
    }
    all
}

fn for_finalizing(rule: &'static str, seen: Seen, what: &'static str, psbt: &[u8], bips: &[Bip]) -> Case {
    role(rule, seen, what, evaluate_for_finalizing(psbt, bips), finalizer_trace(rule, psbt, None, bips))
}

fn finalizing(rule: &'static str, seen: Seen, what: &'static str, received: &[u8], returned: &[u8], bips: &[Bip]) -> Case {
    role(rule, seen, what, evaluate_finalizing(received, returned, bips), finalizer_trace(rule, received, Some(returned), bips))
}

const WORKFLOW: &str = "Single-input P2WPKH to silent payment workflow (global-share): ";

fn workflow(step: &str) -> Psbt {
    fixture("bip375", &format!("{WORKFLOW}{step}"))
}

/// A v2 PSBT spending the P2TR output of key [7; 32], with PSBT_IN_SP_TWEAK
/// and `extra` input records, and a valid key-path signature for it.
fn sp_input(extra: Vec<Record>) -> (Psbt, Vec<u8>) {
    use k256::schnorr::SigningKey;
    let signer = SigningKey::from_bytes(&[7; 32]).unwrap();
    let key: [u8; 32] = signer.verifying_key().to_bytes().into();
    let spk = [&[0x51, 0x20][..], &key].concat();
    let mut input = vec![field(IN_WITNESS_UTXO, vec![], txout(10_000, &spk)), field(IN_SP_TWEAK, vec![], vec![1; 32])];
    input.extend(extra);
    let psbt = v2(vec![], vec![input], vec![output(&[0x51])]);
    let c = PsbtContext::new(&psbt);
    let digest = taproot_sighash(&signing_tx(&c).unwrap(), 0, &spent_outputs(&c).unwrap(), 0x00, None, None).unwrap();
    let sig = signer.sign_raw(&digest, &[0; 32]).unwrap().to_bytes().to_vec();
    (psbt, sig)
}

fn witness(items: &[&[u8]]) -> Vec<u8> {
    let mut w = vec![items.len() as u8];
    for item in items {
        w.push(item.len() as u8);
        w.extend(*item);
    }
    w
}

/// A one-leaf P2TR script-path spend by key [3; 32], signed with
/// SIGHASH_DEFAULT: the input a Finalizer receives and its final witness items.
fn script_path() -> (Psbt, Vec<Vec<u8>>) {
    use k256::schnorr::SigningKey;
    let signer = SigningKey::from_bytes(&[3; 32]).unwrap();
    let key: [u8; 32] = signer.verifying_key().to_bytes().into();
    let script = [&[0x20][..], &key, &[0xac]].concat();
    let leaf = leaf_hash(0xc0, &script);
    let internal: [u8; 32] = hex(&KEY[2..]).try_into().unwrap();
    let (output_key, odd) = taproot_output_key(&internal, Some(&leaf)).unwrap();
    let spk = [&[0x51, 0x20][..], &output_key].concat();
    let control_block = [&[0xc0 | u8::from(odd)][..], &internal].concat();
    let input = vec![
        field(IN_WITNESS_UTXO, vec![], txout(10_000, &spk)),
        field(IN_TAP_LEAF_SCRIPT, control_block.clone(), [&script[..], &[0xc0]].concat()),
        field(IN_TAP_INTERNAL_KEY, vec![], internal.to_vec()),
        field(IN_TAP_MERKLE_ROOT, vec![], leaf.to_vec()),
    ];
    let mut psbt = v2(vec![], vec![input], vec![output(&[0x51])]);
    let c = PsbtContext::new(&psbt);
    let digest = taproot_sighash(&signing_tx(&c).unwrap(), 0, &spent_outputs(&c).unwrap(), 0x00, Some((&leaf, u32::MAX)), None).unwrap();
    let sig = signer.sign_raw(&digest, &[0; 32]).unwrap().to_bytes().to_vec();
    psbt.maps[1].push(field(IN_TAP_SCRIPT_SIG, [&key[..], &leaf].concat(), sig.clone()));
    (psbt, vec![sig, script, control_block])
}

/// `psbt` with input map 1 finalized by `final_witness`: its signing, key and
/// script fields replaced by PSBT_IN_FINAL_SCRIPTWITNESS.
fn finalized(psbt: &Psbt, final_witness: Vec<u8>) -> Psbt {
    let mut p = psbt.clone();
    let keep = [IN_PREVIOUS_TXID, IN_OUTPUT_INDEX, IN_SEQUENCE, IN_WITNESS_UTXO, IN_NON_WITNESS_UTXO];
    p.maps[1].retain(|r| keep.contains(&r.key_type));
    p.maps[1].push(field(IN_FINAL_SCRIPTWITNESS, vec![], final_witness));
    p
}

fn finalizer_cases() -> Vec<Case> {
    use Seen::*;
    let sp = [Bip::Bip375];
    let combined_psbt = fixture("bip174", "BIP-174 combiner result, whose signatures use its SIGHASH_ALL sighash types");
    let combined = encode(&combined_psbt);
    let sighash_mismatch = edited(combined_psbt.clone(), |p| {
        find(&mut p.maps[1], IN_SIGHASH_TYPE).value = u32le(0x81);
    });
    let forged_partial = edited(combined_psbt, |p| {
        find(&mut p.maps[1], IN_PARTIAL_SIG).value[10] ^= 1;
    });
    let signed = workflow("Signer");
    let workflow_finalized = workflow("Input Finalizer");

    // The workflow's P2WPKH final witness with the last byte of S changed.
    let forged = {
        let mut p = workflow_finalized.clone();
        let w = &mut find(&mut p.maps[1], IN_FINAL_SCRIPTWITNESS).value;
        let sig_len = w[1] as usize;
        w[sig_len] ^= 1;
        p
    };

    let (sp_unsigned, sp_sig) = sp_input(vec![field(IN_SEQUENCE, vec![], u32le(1))]);
    let mut sp_signed = sp_unsigned.clone();
    sp_signed.maps[1].push(field(IN_TAP_KEY_SIG, vec![], sp_sig.clone()));
    let sp_final = finalized(&sp_signed, witness(&[&sp_sig]));
    let mut sp_sequence_changed = sp_final.clone();
    find(&mut sp_sequence_changed.maps[1], IN_SEQUENCE).value = u32le(0);
    let mut sp_key_sig_kept = sp_final.clone();
    sp_key_sig_kept.maps[1].push(field(IN_TAP_KEY_SIG, vec![], sp_sig.clone()));

    let key_path = fixture("bip371", "key only input with internal key, its derivation path, and signature");
    let key_sig = key_path.maps[1].iter().find(|r| r.key_type == IN_TAP_KEY_SIG).unwrap().value.clone();
    let key_path_bad_sig = edited(key_path.clone(), |p| {
        find(&mut p.maps[1], IN_TAP_KEY_SIG).value[0] ^= 1;
    });
    let key_path_final = finalized(&key_path, witness(&[&key_sig]));
    let mut bad_key_sig = key_sig.clone();
    bad_key_sig[0] ^= 1;
    let key_path_forged = finalized(&key_path, witness(&[&bad_key_sig]));

    let (script_signed, items) = script_path();
    let items: Vec<&[u8]> = items.iter().map(Vec::as_slice).collect();
    let script_final = finalized(&script_signed, witness(&items));
    let mut other_control = items[2].to_vec();
    other_control[1..33].copy_from_slice(&hex(OTHER_KEY));
    let script_wrong_control = finalized(&script_signed, witness(&[items[0], items[1], &other_control]));

    let musig = || {
        let mut p = fixture("bip373", "output key is a MuSig2 Aggregate Pubkey (With all partial signatures)");
        p.maps[1].retain(|r| r.key_type != IN_TAP_KEY_SIG && r.key_type != IN_TAP_SCRIPT_SIG);
        p
    };
    let mut musig_forged = musig();
    find(&mut musig_forged.maps[1], IN_MUSIG2_PARTIAL_SIG).value[31] ^= 1;

    // ROLE-F-6 is Incomplete on every script-path spend, so a script-path
    // finalization stops there. ROLE-F-9 is Verified where only ROLE-F-6 stops it.
    let f9 = {
        let got = evaluate_finalizing(&encode(&script_signed), &encode(&script_final), &[]);
        let stops_at_f6 = matches!(&got, Evaluation::Incomplete(v) if v.rule == "ROLE-F-6" && v.detail.contains("satisfaction is not checked"));
        let trace = finalizer_trace("ROLE-F-9", &encode(&script_signed), Some(&encode(&script_final)), &[]);
        role("ROLE-F-9", Verified, "script path, stopped only by ROLE-F-6", if stops_at_f6 { Evaluation::Verified } else { got }, trace)
    };

    vec![
        for_finalizing("ROLE-F-1", Verified, "BIP174 SIGHASH_ALL signatures", &combined, &[]),
        for_finalizing("ROLE-F-1", Failed, "signature sighash disagrees with PSBT_IN_SIGHASH_TYPE", &sighash_mismatch, &[]),
        for_finalizing("ROLE-F-2", Verified, "SP input with a key signature", &encode(&sp_signed), &[]),
        for_finalizing("ROLE-F-2", Failed, "SP tweak without taproot key signature", &encode(&sp_unsigned), &[]),
        for_finalizing("ROLE-F-3", Verified, "BIP371 key-path signature", &encode(&key_path), &[]),
        for_finalizing("ROLE-F-3", Failed, "changed key-path signature", &key_path_bad_sig, &[]),
        for_finalizing("ROLE-F-4", Verified, "BIP174 legacy and BIP143 partial signatures", &combined, &[]),
        for_finalizing("ROLE-F-4", Failed, "changed partial signature", &forged_partial, &[]),
        for_finalizing("ROLE-F-5", Verified, "BIP373 partial signatures", &encode(&musig()), &[]),
        for_finalizing("ROLE-F-5", Failed, "changed partial signature", &encode(&musig_forged), &[]),
        finalizing("ROLE-F-6", Verified, "BIP375 workflow P2WPKH", &encode(&signed), &encode(&workflow_finalized), &sp),
        finalizing("ROLE-F-6", Failed, "final signature does not verify", &encode(&signed), &encode(&forged), &sp),
        finalizing("ROLE-F-6", Incomplete, "script path satisfaction", &encode(&script_signed), &encode(&script_final), &[]),
        finalizing("ROLE-F-7", Verified, "sequence kept", &encode(&sp_signed), &encode(&sp_final), &[]),
        finalizing("ROLE-F-7", Failed, "sequence changed", &encode(&sp_signed), &encode(&sp_sequence_changed), &[]),
        finalizing("ROLE-F-8", Verified, "SP key signature as the witness", &encode(&sp_signed), &encode(&sp_final), &[]),
        finalizing("ROLE-F-8", Failed, "PSBT_IN_TAP_KEY_SIG kept", &encode(&sp_signed), &encode(&sp_key_sig_kept), &[]),
        f9,
        finalizing("ROLE-F-9", Failed, "control block for another key", &encode(&script_signed), &encode(&script_wrong_control), &[]),
        finalizing("ROLE-F-10", Verified, "BIP371 key-path signature", &encode(&key_path), &encode(&key_path_final), &[]),
        finalizing("ROLE-F-10", Failed, "key-path witness does not verify", &encode(&key_path), &encode(&key_path_forged), &[]),
    ]
}

fn extractor_and_combiner_cases() -> Vec<Case> {
    use Seen::*;
    let extracting = |rule, seen, what, bytes: &[u8], bips: &[Bip]| {
        let trace = graph_statuses(spec::extractor_role_obligations(), &ctx(bytes, bips), rule);
        role(rule, seen, what, evaluate_extracting(bytes, bips), trace)
    };
    let combining = |rule, seen, what, sources: &[&[u8]], combined: &[u8]| {
        let transition = TransitionContext { before: sources.iter().map(|p| ctx(p, &[])).collect(), after: ctx(combined, &[]) };
        let trace = graph_statuses(spec::combiner_obligations(), &transition, rule);
        role(rule, seen, what, evaluate_combining(sources, combined, &[]), trace)
    };
    let finalizer_result = encode(&fixture("bip174", "BIP-174 input finalizer result"));
    let sp_final = fixture("bip375", "can finalize: two inputs single-signer using per-input ECDH shares (finalized result)");
    let mut sp_wrong_script = sp_final.clone();
    let sp_output = sp_wrong_script.maps.iter_mut().rev().find(|m| m.iter().any(|r| r.key_type == OUT_SP_V0_INFO)).unwrap();
    find(sp_output, OUT_SCRIPT).value[5] ^= 1;

    let bip174 = vectors("bip174");
    let v = bip174.iter().find(|v| v["description"] == "BIP-174 combiner test vector").unwrap();
    let sources: Vec<Vec<u8>> = v["combine"].as_array().unwrap().iter().map(|p| STANDARD.decode(p.as_str().unwrap()).unwrap()).collect();
    let sources: Vec<&[u8]> = sources.iter().map(Vec::as_slice).collect();
    let combined = psbt(v);
    let other_v = bip174.iter().find(|v| v["description"] == "BIP-174 unknown key-value pairs combiner test vector").unwrap();
    let other_source = STANDARD.decode(other_v["combine"][0].as_str().unwrap()).unwrap();

    vec![
        extracting("ROLE-X-1", Verified, "BIP174 finalizer result", &finalizer_result, &[]),
        extracting("ROLE-X-1", Failed, "BIP174 combiner result, not finalized", &combined, &[]),
        combining("ROLE-B-1", Verified, "BIP174 combiner vector", &sources, &combined),
        combining("ROLE-B-1", Failed, "PSBTs for different transactions", &[sources[0], &other_source], &combined),
        combining("ROLE-B-2", Verified, "BIP174 combiner vector", &sources, &combined),
        combining("ROLE-B-2", Failed, "combined drops second signer partial signatures", &sources, sources[0]),
    ]
}

fn for_signing(rule: &'static str, seen: Seen, what: &'static str, psbt: &[u8], bips: &[Bip], kind: SignatureKind) -> Case {
    let input = ctx(psbt, bips).inputs().remove(0);
    let trace = graph_statuses(spec::signer_obligations(), &SigningInputContext::new(input, kind), rule);
    role(rule, seen, what, evaluate_for_signing(psbt, bips, 0, kind), trace)
}

fn signer_trace(rule: &str, received: &[u8], returned: &[u8], bips: &[Bip]) -> Vec<(TraceStatus, String)> {
    let transition = SignerTransitionContext::new(ctx(received, bips), ctx(returned, bips));
    graph_statuses(spec::signer_transition_obligations(), &transition, rule)
}

fn signing(rule: &'static str, seen: Seen, what: &'static str, received: &[u8], returned: &[u8], bips: &[Bip]) -> Case {
    role(rule, seen, what, evaluate_signing(received, returned, bips), signer_trace(rule, received, returned, bips))
}

/// A v2 PSBT with one P2WPKH input carrying `input` and one output, with
/// PSBT_GLOBAL_TX_MODIFIABLE `flags` when given.
fn single_input(flags: Option<u8>, input: Vec<Record>) -> Psbt {
    let global = flags.map(|f| field(GLOBAL_TX_MODIFIABLE, vec![], vec![f])).into_iter().collect();
    v2(global, vec![[vec![field(IN_WITNESS_UTXO, vec![], txout(10_000, &P2WPKH))], input].concat()], vec![output(&[0x51])])
}

/// A placeholder ECDSA partial signature with `hash_type`; Signer rules do not
/// verify signatures.
fn partial_sig(hash_type: u8) -> Record {
    field(IN_PARTIAL_SIG, hex(KEY), vec![0x30, 0x01, hash_type])
}

fn signer_cases() -> Vec<Case> {
    use Seen::*;
    use SignatureKind::*;
    let sp = [Bip::Bip375];
    let sp_spend = [Bip::Bip375, Bip::Bip376];

    let p2pkh = fixture("bip174", "PSBT with one P2PKH input. Outputs are empty");
    let mut p2pkh_wrong_utxo = p2pkh.clone();
    find(&mut p2pkh_wrong_utxo.maps[1], IN_NON_WITNESS_UTXO).value[0] ^= 1;
    let p2sh_p2wsh = encode(&fixture("bip174", "PSBT with one P2SH-P2WSH input of a 2-of-2 multisig"));

    let updated = workflow("Updater");
    let signed = workflow("Signer");
    let mut signed_without_script = updated.clone();
    signed_without_script.maps[1].push(partial_sig(0x01));
    find(&mut signed_without_script.maps[0], GLOBAL_TX_MODIFIABLE).value = vec![0x00];

    // sp_input's output key is key [7; 32] and its tweak [1; 32], so the
    // spend key is key [6; 32].
    let spend_key = {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        k256::SecretKey::from_slice(&[6; 32]).unwrap().public_key().to_encoded_point(true).as_bytes().to_vec()
    };
    let (sp_key_unsigned, sp_sig) = sp_input(vec![field(IN_SP_SPEND_BIP32_DERIVATION, spend_key, vec![0; 4])]);
    let key_signed = |sig: &[u8]| {
        let mut p = sp_key_unsigned.clone();
        p.maps[1].push(field(IN_TAP_KEY_SIG, vec![], sig.to_vec()));
        p
    };
    let sp_key_signed = key_signed(&sp_sig);
    let mut bad_sig = sp_sig.clone();
    bad_sig[0] ^= 1;
    let sp_key_forged = key_signed(&bad_sig);

    let unknown = fixture("bip174", "PSBT with unknown types in the inputs.");
    let mut unknown_dropped = unknown.clone();
    unknown_dropped.maps[1].retain(|r| r.key_type < 0x0f);

    let typed = |t: u8, sig: Option<u8>| encode(&single_input(None, [vec![field(IN_SIGHASH_TYPE, vec![], u32le(t.into()))], sig.map(partial_sig).into_iter().collect()].concat()));

    let proofs: Vec<Value> = serde_json::from_str(include_str!("../../vectors/bip353_proofs.json")).unwrap();
    let proof = encode(&v2(vec![], vec![], vec![[output(&[0x51]), vec![field(OUT_DNSSEC_PROOF, vec![], hex(proofs[0]["proof_hex"].as_str().unwrap()))]].concat()]));
    // Noon UTC on 7 August 2025, a date BIP353 gives for its proofs.
    let aug_7 = 1_754_568_000;
    let dnssec = |seen, what, time| {
        let proofs: Vec<DnssecProofContext> = ctx(&proof, &[]).outputs().into_iter().map(|output| DnssecProofContext { output, time: Some(time), allow_construction_delay: false }).collect();
        let trace = graph_statuses(each(|p: &Vec<_>| Vec::clone(p), spec::signer_proof_obligations()), &proofs, "ROLE-S-6");
        role("ROLE-S-6", seen, what, evaluate_dnssec_proofs(&proof, &[], time, false), trace)
    };

    vec![
        for_signing("ROLE-S-1", Verified, "BIP174 P2PKH non-witness UTXO", &encode(&p2pkh), &[], NonWitness),
        for_signing("ROLE-S-1", Failed, "non-witness UTXO with another txid", &encode(&p2pkh_wrong_utxo), &[], NonWitness),
        for_signing("ROLE-S-2", Verified, "BIP174 P2SH-P2WSH", &p2sh_p2wsh, &[], Witness),
        for_signing("ROLE-S-3", Verified, "BIP174 P2SH-P2WSH", &p2sh_p2wsh, &[], Witness),
        for_signing("ROLE-S-4", Verified, "BIP174 P2SH-P2WSH", &p2sh_p2wsh, &[], Witness),
        dnssec(Verified, "published proof on its date", aug_7),
        dnssec(Failed, "a year after expiry", aug_7 + 365 * 86_400),
        signing("ROLE-S-9", Verified, "BIP375 workflow", &encode(&updated), &encode(&signed), &sp),
        signing("ROLE-S-9", Failed, "unknown field dropped", &encode(&unknown), &encode(&unknown_dropped), &[]),
        signing("ROLE-S-10", Verified, "signature uses PSBT_IN_SIGHASH_TYPE", &typed(1, None), &typed(1, Some(0x01)), &[]),
        signing("ROLE-S-10", Failed, "SIGHASH_NONE under SIGHASH_ALL", &typed(1, None), &typed(1, Some(0x02)), &[]),
        // GEN-SP-7 is General; a Signer that signs too early returns a PSBT that fails it.
        case("GEN-SP-7", Failed, "signed while an output has no script", evaluate_signing(&encode(&updated), &encode(&signed_without_script), &sp)),
        signing("ROLE-S-11", Verified, "SP key-path signature", &encode(&sp_key_unsigned), &encode(&sp_key_signed), &sp_spend),
        signing("ROLE-S-11", Failed, "key signature does not verify", &encode(&sp_key_unsigned), &encode(&sp_key_forged), &sp_spend),
    ]
}

fn construction_cases() -> Vec<Case> {
    use Seen::*;
    let creating = |rule, seen, what, psbt: &Psbt, delegates: bool| {
        let bytes = encode(psbt);
        let trace = graph_statuses(spec::creator_obligations(), &CreatorContext::new(ctx(&bytes, &[]), delegates), rule);
        role(rule, seen, what, evaluate_creating(&bytes, delegates, &[]), trace)
    };
    let constructing = |rule, seen, what, received: &Psbt, returned: &Psbt, timelocks: &[(usize, bool)]| {
        let (r, a) = (encode(received), encode(returned));
        let transition = ConstructorTransitionContext::with_intended_timelocks(ctx(&r, &[]), ctx(&a, &[]), timelocks.to_vec());
        let trace = graph_statuses(spec::constructor_obligations(), &transition, rule);
        role(rule, seen, what, evaluate_constructing(&r, &a, timelocks, &[]), trace)
    };

    let empty = v2(vec![], vec![], vec![]);
    let delegating = v2(vec![field(GLOBAL_TX_MODIFIABLE, vec![], vec![0x03])], vec![], vec![]);
    let populated = v2(vec![], vec![vec![]], vec![output(&[0x51])]);

    let utxo = |script: &[u8]| field(IN_WITNESS_UTXO, vec![], txout(10_000, script));
    let height = |h: u32| field(IN_REQUIRED_HEIGHT_LOCKTIME, vec![], u32le(h));
    // `received` with one more input carrying `extra`.
    let add_input = |received: &Psbt, extra: Vec<Record>| {
        let mut p = received.clone();
        let n = p.maps.iter().skip(1).take_while(|m| m.iter().any(|r| r.key_type == IN_PREVIOUS_TXID)).count();
        let mut map = vec![field(IN_PREVIOUS_TXID, vec![], vec![0x40 + n as u8; 32]), field(IN_OUTPUT_INDEX, vec![], u32le(0)), utxo(&P2WPKH)];
        map.extend(extra);
        p.maps.insert(1 + n, map);
        find(&mut p.maps[0], GLOBAL_INPUT_COUNT).value = vec![n as u8 + 1];
        p
    };
    let open = |flags: u8, inputs: Vec<Vec<Record>>, outputs: usize| {
        let inputs = inputs.into_iter().map(|i| [vec![utxo(&P2WPKH)], i].concat()).collect();
        v2(vec![field(GLOBAL_TX_MODIFIABLE, vec![], vec![flags])], inputs, (0..outputs).map(|_| output(&[0x51])).collect())
    };
    let plain = open(0x03, vec![vec![]], 1);
    let closed_inputs = open(0x02, vec![vec![]], 1);
    let signed_acp = open(0x01, vec![vec![partial_sig(0x81)]], 1);
    let signed_acp_locked = open(0x01, vec![vec![partial_sig(0x81), height(100)]], 1);
    let single = open(0x05, vec![vec![partial_sig(0x83)]], 1);
    let unpaired_single = open(0x05, vec![vec![], vec![partial_sig(0x83)]], 1);


    vec![
        creating("ROLE-C-1", Verified, "v2 with no inputs or outputs", &empty, false),
        creating("ROLE-C-1", Failed, "v2 with an input and an output", &populated, false),
        creating("ROLE-C-2", Verified, "delegating with flags", &delegating, true),
        creating("ROLE-C-2", Failed, "delegating without flags", &empty, true),
        constructing("ROLE-C-3", Verified, "input added, Inputs Modifiable", &plain, &add_input(&plain, vec![]), &[(1, false)]),
        constructing("ROLE-C-3", Failed, "input added, Inputs Modifiable clear", &closed_inputs, &add_input(&closed_inputs, vec![]), &[(1, false)]),
        constructing("ROLE-C-4", Verified, "required height set", &plain, &add_input(&plain, vec![height(100)]), &[(1, true)]),
        constructing("ROLE-C-4", Failed, "required locktime missing", &plain, &add_input(&plain, vec![]), &[(1, true)]),
        constructing("ROLE-C-4", Incomplete, "no intended locktimes", &plain, &add_input(&plain, vec![]), &[]),
        constructing("ROLE-C-5", Verified, "lower height keeps the locktime", &signed_acp_locked, &add_input(&signed_acp_locked, vec![height(50)]), &[(1, true)]),
        constructing("ROLE-C-5", Failed, "height changes a signed locktime", &signed_acp, &add_input(&signed_acp, vec![height(100)]), &[(1, true)]),
        constructing("ROLE-C-6", Verified, "input added after a SINGLE pair", &single, &add_input(&single, vec![]), &[(1, false)]),
        // FIXME: validate_preserve_single_pairing never compares the paired
        // output, so this missing pair is the only failure it reports.
        constructing("ROLE-C-6", Failed, "SINGLE input without an output", &unpaired_single, &add_input(&unpaired_single, vec![]), &[(2, false)]),
    ]
}
