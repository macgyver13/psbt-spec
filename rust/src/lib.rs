//! PSBT conformance specification and its validator. `evaluate` checks the
//! General rules; one entry point per role checks that role's rules.

pub mod algebra;
pub mod attribution;
mod catalog;
pub mod corpus;
pub mod context;
pub mod ecdsa;
pub mod encoding;
pub mod registry;
pub mod rules;
pub mod signature;
pub mod silent_payments;
pub mod taproot;
pub mod spec;

pub use algebra::{Bip, CheckOutcome, Evaluation, Verdict, Violation};
pub use context::{SignatureKind, SigningInputContext};
pub use rules::creator::CreatorContext;
pub use rules::constructor::ConstructorTransitionContext;
pub use rules::signer::SignerTransitionContext;
pub use rules::finalizer::FinalizerTransitionContext;

/// Evaluate the implemented General rule graph using catalog IDs and explicit
/// incomplete outcomes. Verified covers these bindings, not every pending role,
/// field schema or open acceptance question in the specification.
pub fn evaluate(psbt: &[u8], bips: &[Bip]) -> Evaluation {
    spec::general_rules(bips).evaluate(psbt)
}

/// The first General-rule outcome over `psbts` that is neither Verified nor
/// NotApplicable; a role's rules run only when there is none.
fn general_outcome(psbts: &[&[u8]], bips: &[Bip]) -> Option<Evaluation> {
    psbts
        .iter()
        .map(|psbt| evaluate(psbt, bips))
        .find(|outcome| !matches!(outcome, Evaluation::Verified | Evaluation::NotApplicable))
}

fn psbt_context(psbt: &[u8], bips: &[Bip]) -> context::PsbtContext {
    context::PsbtContext::new(&spec::parse(psbt, bips))
}

/// Evaluate a Creator's work: General rules on the PSBT it created, then the
/// Creator rules. `delegates_additions` says whether the Creator hands the
/// PSBT to others to add inputs or outputs (ROLE-C-2).
pub fn evaluate_creating(created: &[u8], delegates_additions: bool, bips: &[Bip]) -> Evaluation {
    if let Some(outcome) = general_outcome(&[created], bips) {
        return outcome;
    }
    spec::creator_obligations().evaluate(&CreatorContext::new(psbt_context(created, bips), delegates_additions))
}

/// Evaluate a Constructor's work: General rules on the PSBT it received and the
/// PSBT it returned, then the Constructor rules comparing the two.
/// `intended_timelocks` lists, for added inputs by index, whether the chosen
/// spend branch requires a locktime (ROLE-C-4).
pub fn evaluate_constructing(received: &[u8], returned: &[u8], intended_timelocks: &[(usize, bool)], bips: &[Bip]) -> Evaluation {
    if let Some(outcome) = general_outcome(&[received, returned], bips) {
        return outcome;
    }
    let transition = ConstructorTransitionContext::with_intended_timelocks(
        psbt_context(received, bips),
        psbt_context(returned, bips),
        intended_timelocks.to_vec(),
    );
    spec::constructor_obligations().evaluate(&transition)
}

/// Evaluate a PSBT an Input Finalizer is given: General rules, then the
/// Finalizer's preconditions on every input that is not yet finalized.
pub fn evaluate_for_finalizing(psbt: &[u8], bips: &[Bip]) -> Evaluation {
    if let Some(outcome) = general_outcome(&[psbt], bips) {
        return outcome;
    }
    algebra::each(unfinalized_inputs, spec::finalizer_obligations()).evaluate(&psbt_context(psbt, bips))
}

/// Evaluate a PSBT a Transaction Extractor is given: General rules, then the
/// Extractor's preconditions.
pub fn evaluate_extracting(psbt: &[u8], bips: &[Bip]) -> Evaluation {
    if let Some(outcome) = general_outcome(&[psbt], bips) {
        return outcome;
    }
    spec::extractor_role_obligations().evaluate(&psbt_context(psbt, bips))
}

/// Evaluate a Combiner's work: General rules on every PSBT it was given and the
/// PSBT it produced, then the Combiner rules.
pub fn evaluate_combining(sources: &[&[u8]], combined: &[u8], bips: &[Bip]) -> Evaluation {
    let all: Vec<&[u8]> = sources.iter().copied().chain([combined]).collect();
    if let Some(outcome) = general_outcome(&all, bips) {
        return outcome;
    }
    let transition = context::TransitionContext {
        before: sources.iter().map(|p| psbt_context(p, bips)).collect(),
        after: psbt_context(combined, bips),
    };
    spec::combiner_obligations().evaluate(&transition)
}

/// Evaluate General rules, then ROLE-S-1 for the selected input and intended
/// signature kind. Context projection occurs only after General checks succeed.
/// This checks supplied data and operation intent; it does not create a signature.
pub fn evaluate_for_signing(
    psbt: &[u8], bips: &[Bip], input_index: usize, signature_kind: SignatureKind,
) -> Evaluation {
    match evaluate(psbt, bips) {
        Evaluation::Verified | Evaluation::NotApplicable => {}
        outcome => return outcome,
    }
    let context = context::PsbtContext::new(&spec::parse(psbt, bips));
    let Some(input) = context.inputs().into_iter().nth(input_index) else {
        return Evaluation::Failed(Violation {
            rule: "ROLE-S-1",
            detail: format!("signing input {input_index} does not exist"),
        });
    };
    spec::signer_obligations().evaluate(&SigningInputContext::new(input, signature_kind))
}

/// Evaluate a Signer's work: General rules on the PSBT it received and the
/// PSBT it returned, the before-signing rules for each input it added a
/// signature to, then the rules comparing the two PSBTs.
///
/// The signature kind for each signed input is inferred from its spent script:
/// a witness program, or P2SH wrapping one, is a witness signature; any other
/// script is a non-witness signature; with no spent output it is taken as a
/// witness signature, and ROLE-S-1 then reports the missing UTXO as Incomplete.
pub fn evaluate_signing(received: &[u8], returned: &[u8], bips: &[Bip]) -> Evaluation {
    for psbt in [received, returned] {
        match evaluate(psbt, bips) {
            Evaluation::Verified | Evaluation::NotApplicable => {}
            outcome => return outcome,
        }
    }
    let context = |p: &[u8]| context::PsbtContext::new(&spec::parse(p, bips));
    let transition = SignerTransitionContext::new(context(received), context(returned));
    let (before, after) = (&transition.before, &transition.after);
    if before.inputs != after.inputs || before.outputs != after.outputs {
        return Evaluation::Failed(Violation {
            rule: "ROLE-S-9",
            detail: "Signer cannot add or remove inputs or outputs".into(),
        });
    }
    algebra::all(vec![
        algebra::each(signed_inputs, spec::signer_obligations()),
        spec::signer_transition_obligations(),
    ])
    .evaluate(&transition)
}

/// The inputs the Signer added a signature to, as the Signer received them.
fn signed_inputs(transition: &SignerTransitionContext) -> Vec<SigningInputContext> {
    transition
        .before
        .inputs()
        .into_iter()
        .filter(|input| !rules::signer::added_signatures(transition, input.index).is_empty())
        .map(|input| {
            let kind = inferred_kind(&input);
            SigningInputContext::new(input, kind)
        })
        .collect()
}

/// Evaluate an Input Finalizer's work: General rules on the PSBT it received
/// and the PSBT it returned, then, for each input whose final fields it set or
/// changed, the before-finalizing rules on the input it received, the rules
/// comparing the two, and the finalized-input rules on the input it returned.
/// An input whose final fields it removed fails ROLE-F-6.
pub fn evaluate_finalizing(received: &[u8], returned: &[u8], bips: &[Bip]) -> Evaluation {
    for psbt in [received, returned] {
        match evaluate(psbt, bips) {
            Evaluation::Verified | Evaluation::NotApplicable => {}
            outcome => return outcome,
        }
    }
    match finalizer_transitions(received, returned, bips) {
        Err(violation) => Evaluation::Failed(violation),
        Ok(transitions) => finalizer_graph().evaluate(&transitions),
    }
}

/// The input pairs whose final fields the Finalizer set or changed, or the
/// ROLE-F-6 violation when it added or removed inputs or removed final fields.
fn finalizer_transitions(received: &[u8], returned: &[u8], bips: &[Bip]) -> Result<Vec<FinalizerTransitionContext>, Violation> {
    let before = context::PsbtContext::new(&spec::parse(received, bips));
    let after = context::PsbtContext::new(&spec::parse(returned, bips));
    if before.inputs != after.inputs {
        return Err(Violation {
            rule: "ROLE-F-6",
            detail: "Finalizer cannot add or remove inputs".into(),
        });
    }
    let final_fields = |input: &context::InputContext| {
        [context::IN_FINAL_SCRIPTSIG, context::IN_FINAL_SCRIPTWITNESS].map(|t| input.value(t).map(<[u8]>::to_vec))
    };
    let mut transitions = Vec::new();
    for (b, a) in before.inputs().into_iter().zip(after.inputs()) {
        let (was, is) = (final_fields(&b), final_fields(&a));
        if was == is {
            continue;
        }
        if is == [None, None] {
            return Err(Violation {
                rule: "ROLE-F-6",
                detail: format!("Finalizer removed the final fields of input {}", b.index),
            });
        }
        transitions.push(FinalizerTransitionContext::new(b, a));
    }
    Ok(transitions)
}

/// The Finalizer rules over each input it finalized.
fn finalizer_graph() -> algebra::BoxNode<Vec<FinalizerTransitionContext>> {
    algebra::each(
        |t: &Vec<FinalizerTransitionContext>| t.clone(),
        algebra::all(vec![
            algebra::with(|t: &FinalizerTransitionContext| t.before.clone(), spec::finalizer_obligations()),
            spec::finalizer_transition_obligations(),
            algebra::with(|t: &FinalizerTransitionContext| t.after.clone(), spec::finalizer_role_obligations()),
        ]),
    )
}

/// Evaluate General rules, then ROLE-S-6 for every output with a BIP353 DNSSEC
/// proof, validated at `time` (Unix seconds). `allow_construction_delay` permits
/// an RRSIG expiry up to an hour before `time`, which BIP353 allows only when a
/// delay between construction and signing is likely.
pub fn evaluate_dnssec_proofs(psbt: &[u8], bips: &[Bip], time: u64, allow_construction_delay: bool) -> Evaluation {
    match evaluate(psbt, bips) {
        Evaluation::Verified | Evaluation::NotApplicable => {}
        outcome => return outcome,
    }
    let context = context::PsbtContext::new(&spec::parse(psbt, bips));
    let proofs: Vec<rules::dnssec::DnssecProofContext> = context
        .outputs()
        .into_iter()
        .map(|output| rules::dnssec::DnssecProofContext { output, time: Some(time), allow_construction_delay })
        .collect();
    algebra::each(|p: &Vec<rules::dnssec::DnssecProofContext>| p.clone(), spec::signer_proof_obligations()).evaluate(&proofs)
}

// All-failures evaluation. Each function runs the entry point's graph under an
// exhaustive trace (see `algebra::Trace::exhaustive`) and returns every rule ID
// that was Failed, and apart from them every rule that was Incomplete and
// Failed nowhere, each in evaluation order without repeats. Like the
// first-failure entry points, a role's rules run only when the General rules
// on every PSBT it is given pass (neither Failed nor Incomplete). A rule
// behind a failed prerequisite that its graph orders first (`seq`, or a `with`
// projection) is Blocked, not listed.

/// The rules an all-failures evaluation reports. `failed` is evidence of a
/// violation; `incomplete` lacks the context to decide and is never one
/// (PRINCIPLES.md, principle 14). A rule Failed anywhere is only in `failed`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Failures {
    pub failed: Vec<&'static str>,
    pub incomplete: Vec<&'static str>,
    /// Rules observed Passed and neither Failed nor Incomplete anywhere: the
    /// rules a valid vector exercises (per-rule corpus coverage in `render`).
    pub passed: Vec<&'static str>,
}

impl Failures {
    pub fn is_empty(&self) -> bool {
        self.failed.is_empty() && self.incomplete.is_empty()
    }

    fn only_failed(id: &'static str) -> Self {
        Self { failed: vec![id], ..Self::default() }
    }

    fn from_trace(trace: algebra::Trace) -> Self {
        use algebra::TraceStatus::{Failed, Incomplete, Passed};
        let mut all = Self::default();
        for o in &trace.observations {
            match o.status {
                Failed => all.failed.push(o.id),
                Incomplete => all.incomplete.push(o.id),
                Passed => all.passed.push(o.id),
                _ => {}
            }
        }
        all.normalize()
    }

    /// Drops repeats, any Incomplete rule that is Failed somewhere, and any
    /// Passed rule that is Failed or Incomplete somewhere.
    fn normalize(self) -> Self {
        let mut failed: Vec<&'static str> = Vec::new();
        for id in self.failed {
            if !failed.contains(&id) {
                failed.push(id);
            }
        }
        let mut incomplete: Vec<&'static str> = Vec::new();
        for id in self.incomplete {
            if !failed.contains(&id) && !incomplete.contains(&id) {
                incomplete.push(id);
            }
        }
        let mut passed: Vec<&'static str> = Vec::new();
        for id in self.passed {
            if !failed.contains(&id) && !incomplete.contains(&id) && !passed.contains(&id) {
                passed.push(id);
            }
        }
        Self { failed, incomplete, passed }
    }

    /// `self` followed by `other`, as for several PSBTs or inputs.
    pub fn merge(mut self, other: Self) -> Self {
        self.failed.extend(other.failed);
        self.incomplete.extend(other.incomplete);
        self.passed.extend(other.passed);
        self.normalize()
    }
}

fn failing_in<C: ?Sized>(node: algebra::BoxNode<C>, ctx: &C) -> Failures {
    let mut trace = algebra::Trace::exhaustive();
    node.evaluate_traced(ctx, &mut trace);
    Failures::from_trace(trace)
}

/// Every General rule that fails `psbt`; the all-failures form of `evaluate`.
pub fn failing_rules(psbt: &[u8], bips: &[Bip]) -> Failures {
    failing_in(spec::general_rules(bips), psbt)
}

/// The General failures over `psbts`; a role's rules run only when there are none.
fn general_failures(psbts: &[&[u8]], bips: &[Bip]) -> Failures {
    psbts.iter().fold(Failures::default(), |all, psbt| all.merge(failing_rules(psbt, bips)))
}

/// All-failures form of `evaluate_creating`.
pub fn failing_rules_creating(created: &[u8], delegates_additions: bool, bips: &[Bip]) -> Failures {
    let general = general_failures(&[created], bips);
    if !general.is_empty() {
        return general;
    }
    failing_in(spec::creator_obligations(), &CreatorContext::new(psbt_context(created, bips), delegates_additions))
}

/// All-failures form of `evaluate_constructing`.
pub fn failing_rules_constructing(
    received: &[u8], returned: &[u8], intended_timelocks: &[(usize, bool)], bips: &[Bip],
) -> Failures {
    let general = general_failures(&[received, returned], bips);
    if !general.is_empty() {
        return general;
    }
    let transition = ConstructorTransitionContext::with_intended_timelocks(
        psbt_context(received, bips),
        psbt_context(returned, bips),
        intended_timelocks.to_vec(),
    );
    failing_in(spec::constructor_obligations(), &transition)
}

/// The inputs of `p` that carry no final scriptSig or witness.
fn unfinalized_inputs(p: &context::PsbtContext) -> Vec<context::InputContext> {
    p.inputs()
        .into_iter()
        .filter(|i| i.value(context::IN_FINAL_SCRIPTSIG).is_none() && i.value(context::IN_FINAL_SCRIPTWITNESS).is_none())
        .collect()
}

/// All-failures form of `evaluate_for_finalizing`.
pub fn failing_rules_for_finalizing(psbt: &[u8], bips: &[Bip]) -> Failures {
    let general = general_failures(&[psbt], bips);
    if !general.is_empty() {
        return general;
    }
    failing_in(algebra::each(unfinalized_inputs, spec::finalizer_obligations()), &psbt_context(psbt, bips))
}

/// All-failures form of `evaluate_extracting`.
pub fn failing_rules_extracting(psbt: &[u8], bips: &[Bip]) -> Failures {
    let general = general_failures(&[psbt], bips);
    if !general.is_empty() {
        return general;
    }
    failing_in(spec::extractor_role_obligations(), &psbt_context(psbt, bips))
}

/// All-failures form of `evaluate_combining`.
pub fn failing_rules_combining(sources: &[&[u8]], combined: &[u8], bips: &[Bip]) -> Failures {
    let all: Vec<&[u8]> = sources.iter().copied().chain([combined]).collect();
    let general = general_failures(&all, bips);
    if !general.is_empty() {
        return general;
    }
    let transition = context::TransitionContext {
        before: sources.iter().map(|p| psbt_context(p, bips)).collect(),
        after: psbt_context(combined, bips),
    };
    failing_in(spec::combiner_obligations(), &transition)
}

/// All-failures form of `evaluate_for_signing`.
pub fn failing_rules_for_signing(
    psbt: &[u8], bips: &[Bip], input_index: usize, signature_kind: SignatureKind,
) -> Failures {
    let general = general_failures(&[psbt], bips);
    if !general.is_empty() {
        return general;
    }
    let Some(input) = psbt_context(psbt, bips).inputs().into_iter().nth(input_index) else {
        return Failures::only_failed("ROLE-S-1");
    };
    failing_in(spec::signer_obligations(), &SigningInputContext::new(input, signature_kind))
}

/// The rules of `task`'s role that fail on `psbt`, without the General gate
/// the other entry points apply: what the role would refuse the PSBT for even
/// if it passed every General rule. `evaluate` uses it to check that a stage
/// request leaves the role no reason of its own to refuse (docs/report.md).
/// Empty for a task with no role rules on a lone PSBT.
pub fn failing_role_rules_ungated(task: attribution::Task, psbt: &[u8], bips: &[Bip]) -> Failures {
    let p = psbt_context(psbt, bips);
    match task {
        attribution::Task::Sign => p.inputs().into_iter().fold(Failures::default(), |all, input| {
            let kind = inferred_kind(&input);
            all.merge(failing_in(spec::signer_obligations(), &SigningInputContext::new(input, kind)))
        }),
        attribution::Task::Finalize => failing_in(algebra::each(unfinalized_inputs, spec::finalizer_obligations()), &p),
        attribution::Task::Extract => failing_in(spec::extractor_role_obligations(), &p),
        _ => Failures::default(),
    }
}

/// The signature kind a Signer would use for `input`, inferred from its spent
/// script as `evaluate_signing` does.
fn inferred_kind(input: &context::InputContext) -> SignatureKind {
    use encoding::{is_p2sh, is_witness_program};
    let witness = match input.spent_output() {
        None => true,
        Some(out) if is_p2sh(&out.script_pubkey) => input.value(context::IN_REDEEM_SCRIPT).is_some_and(is_witness_program),
        Some(out) => is_witness_program(&out.script_pubkey),
    };
    if witness { SignatureKind::Witness } else { SignatureKind::NonWitness }
}

/// The before-signing rules over a PSBT a Signer is given, for every input,
/// the signature kind inferred from the spent script. This is the all-failures
/// form of the corpus's `signing` vectors (a PSBT with no returned PSBT).
pub fn failing_rules_before_signing(psbt: &[u8], bips: &[Bip]) -> Failures {
    let general = general_failures(&[psbt], bips);
    if !general.is_empty() {
        return general;
    }
    psbt_context(psbt, bips).inputs().iter().fold(Failures::default(), |all, input| {
        all.merge(failing_rules_for_signing(psbt, bips, input.index, inferred_kind(input)))
    })
}

/// All-failures form of `evaluate_signing`. Like it, a Signer that added or
/// removed an input or output fails ROLE-S-9 alone.
pub fn failing_rules_signing(received: &[u8], returned: &[u8], bips: &[Bip]) -> Failures {
    let general = general_failures(&[received, returned], bips);
    if !general.is_empty() {
        return general;
    }
    let transition = SignerTransitionContext::new(psbt_context(received, bips), psbt_context(returned, bips));
    if transition.before.inputs != transition.after.inputs || transition.before.outputs != transition.after.outputs {
        return Failures::only_failed("ROLE-S-9");
    }
    failing_in(
        algebra::all(vec![
            algebra::each(signed_inputs, spec::signer_obligations()),
            spec::signer_transition_obligations(),
        ]),
        &transition,
    )
}

/// All-failures form of `evaluate_finalizing`. Like it, a Finalizer that added
/// or removed an input, or removed an input's final fields, fails ROLE-F-6 alone.
pub fn failing_rules_finalizing(received: &[u8], returned: &[u8], bips: &[Bip]) -> Failures {
    let general = general_failures(&[received, returned], bips);
    if !general.is_empty() {
        return general;
    }
    match finalizer_transitions(received, returned, bips) {
        Err(_) => Failures::only_failed("ROLE-F-6"),
        Ok(transitions) => failing_in(finalizer_graph(), &transitions),
    }
}
