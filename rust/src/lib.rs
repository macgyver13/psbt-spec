//! An executable, declarative specification of PSBT validity.
//! See `spec.rs` for the rule graph and `algebra.rs` for its combinators.

pub mod algebra;
pub mod context;
pub mod encoding;
pub mod registry;
pub mod rules;
pub mod silent_payments;
pub mod spec;

pub use algebra::{Bip, Verdict, Violation};

/// Validates a serialized PSBT against every validity rule.
pub fn validate(psbt: &[u8], bips: &[Bip]) -> Verdict {
    spec::validity_rules(bips).validate(psbt)
}

/// Validates a serialized PSBT, then runs the Signer checks on it.
pub fn validate_for_signing(psbt: &[u8], bips: &[Bip]) -> Verdict {
    validate(psbt, bips)?;
    let ctx = context::PsbtContext::new(&spec::parse(psbt, bips));
    spec::signer_rules(bips).validate(&ctx)
}

/// Validates a serialized PSBT, then runs the Transaction Extractor checks on it.
pub fn validate_for_extraction(psbt: &[u8], bips: &[Bip]) -> Verdict {
    validate(psbt, bips)?;
    let ctx = context::PsbtContext::new(&spec::parse(psbt, bips));
    spec::extractor_rules(bips).validate(&ctx)
}

/// Validates a serialized PSBT, then runs the Input Finalizer checks on it.
pub fn validate_for_finalizing(psbt: &[u8], bips: &[Bip]) -> Verdict {
    validate(psbt, bips)?;
    let ctx = context::PsbtContext::new(&spec::parse(psbt, bips));
    spec::finalizer_rules(bips).validate(&ctx)
}

/// Validates the PSBTs a Combiner was given and the PSBT it produced, then
/// runs the Combiner transition checks on them.
pub fn validate_combination(psbts: &[&[u8]], combined: &[u8], bips: &[Bip]) -> Verdict {
    psbts.iter().try_for_each(|p| validate(p, bips))?;
    validate(combined, bips)?;
    let ctx = |p: &[u8]| context::PsbtContext::new(&spec::parse(p, bips));
    let transition = context::TransitionContext { before: psbts.iter().map(|p| ctx(p)).collect(), after: ctx(combined) };
    spec::combiner_rules(bips).validate(&transition)
}
