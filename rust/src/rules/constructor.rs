//! Constructor role validation rules (BIP-370 and BIP-375).

use crate::algebra::CheckOutcome;
use crate::context::{
    determine_locktime, value, PsbtContext, GLOBAL_TX_MODIFIABLE,
    IN_REQUIRED_HEIGHT_LOCKTIME, IN_REQUIRED_TIME_LOCKTIME,
};
use crate::silent_payments::input_signatures;

const INPUTS_MODIFIABLE: u8 = 0x01;
const OUTPUTS_MODIFIABLE: u8 = 0x02;
const HAS_SIGHASH_SINGLE: u8 = 0x04;
const SIGHASH_SINGLE: u8 = 0x03;

/// A transition representing additions performed by a Constructor.
///
/// Compares the PSBT state before additions (`before`) and after additions (`after`).
/// If `intended_timelocks` are specified for newly added inputs, each entry is
/// `(added_input_index, requires_timelock)` to verify ROLE-C-4.
#[derive(Clone)]
pub struct ConstructorTransitionContext {
    pub before: PsbtContext,
    pub after: PsbtContext,
    pub intended_timelocks: Vec<(usize, bool)>,
}

impl ConstructorTransitionContext {
    pub fn new(before: PsbtContext, after: PsbtContext) -> Self {
        Self {
            before,
            after,
            intended_timelocks: Vec::new(),
        }
    }

    pub fn with_intended_timelocks(
        before: PsbtContext,
        after: PsbtContext,
        intended_timelocks: Vec<(usize, bool)>,
    ) -> Self {
        Self {
            before,
            after,
            intended_timelocks,
        }
    }
}

fn modifiable_flags(psbt: &PsbtContext) -> Option<u8> {
    value(psbt.psbt.global(), GLOBAL_TX_MODIFIABLE).map(|v| v[0])
}

/// Returns indices of inputs in `psbt` that carry a signature committing to SIGHASH_SINGLE.
fn single_signed_inputs(psbt: &PsbtContext) -> Vec<usize> {
    psbt.inputs()
        .iter()
        .filter(|input| {
            input_signatures(input).iter().any(|(sig, schnorr)| {
                let sighash = if *schnorr && sig.len() == 64 {
                    0
                } else {
                    sig.last().copied().unwrap_or(0)
                };
                (sighash & 0x1f) == SIGHASH_SINGLE
            })
        })
        .map(|input| input.index)
        .collect()
}

/// ROLE-C-3: Before adding inputs or outputs, the Constructor MUST check the corresponding
/// modification flag and add only what it permits. The result MUST satisfy the applicable general rules.
pub fn validate_permitted_additions(transition: &ConstructorTransitionContext) -> CheckOutcome {
    let before = &transition.before;
    let after = &transition.after;

    if after.inputs < before.inputs || after.outputs < before.outputs {
        return CheckOutcome::Failed("Constructor cannot remove existing inputs or outputs".into());
    }

    let inputs_added = after.inputs > before.inputs;
    let outputs_added = after.outputs > before.outputs;

    if !inputs_added && !outputs_added {
        return CheckOutcome::NotApplicable;
    }

    let flags = modifiable_flags(before).unwrap_or(0);

    if inputs_added && (flags & INPUTS_MODIFIABLE == 0) {
        return CheckOutcome::Failed("inputs added while Inputs Modifiable flag is clear".into());
    }
    if outputs_added && (flags & OUTPUTS_MODIFIABLE == 0) {
        return CheckOutcome::Failed("outputs added while Outputs Modifiable flag is clear".into());
    }

    CheckOutcome::Verified
}

/// ROLE-C-4: For an input with a required spend-branch locktime, the Constructor MUST
/// set the corresponding required time- or height-based locktime field.
pub fn validate_spend_branch_locktime(transition: &ConstructorTransitionContext) -> CheckOutcome {
    if transition.after.inputs <= transition.before.inputs {
        return CheckOutcome::NotApplicable;
    }
    if transition.intended_timelocks.is_empty() {
        return CheckOutcome::Incomplete("intended spend-branch locktime requirements not provided".into());
    }

    let after = &transition.after;
    for &(input_index, requires_timelock) in &transition.intended_timelocks {
        if input_index >= after.inputs {
            return CheckOutcome::Failed(format!("input index {input_index} out of bounds"));
        }
        if requires_timelock {
            let input = &after.inputs()[input_index];
            let has_time = input.value(IN_REQUIRED_TIME_LOCKTIME).is_some();
            let has_height = input.value(IN_REQUIRED_HEIGHT_LOCKTIME).is_some();
            if !has_time && !has_height {
                return CheckOutcome::Failed(format!(
                    "input {input_index} requires a spend-branch locktime, but none was set"
                ));
            }
        }
    }

    CheckOutcome::Verified
}

/// ROLE-C-5: When adding an input with a required locktime, the Constructor MUST NOT
/// change the determined transaction locktime if any existing input has a signature.
pub fn validate_preserve_signed_locktime(transition: &ConstructorTransitionContext) -> CheckOutcome {
    let before = &transition.before;
    let after = &transition.after;

    if after.inputs <= before.inputs {
        return CheckOutcome::NotApplicable;
    }

    // Check if any existing input in `before` carried a signature
    let has_signatures = before.inputs().iter().any(|i| !input_signatures(i).is_empty());
    if !has_signatures {
        return CheckOutcome::NotApplicable;
    }

    let before_locktime = match determine_locktime(before) {
        Some(lt) => lt,
        None => return CheckOutcome::Incomplete("could not determine locktime of prior PSBT state".into()),
    };

    let after_locktime = match determine_locktime(after) {
        Some(lt) => lt,
        None => return CheckOutcome::Failed("added inputs made transaction locktime indeterminable".into()),
    };

    if before_locktime != after_locktime {
        return CheckOutcome::Failed(format!(
            "adding input changed determined locktime from {before_locktime} to {after_locktime} when signatures exist"
        ));
    }

    CheckOutcome::Verified
}

/// ROLE-C-6: If Has SIGHASH_SINGLE is true, the Constructor MUST identify the signed SINGLE
/// input/output pairs and insert equal numbers of inputs and outputs before each affected pair.
pub fn validate_preserve_single_pairing(transition: &ConstructorTransitionContext) -> CheckOutcome {
    let before = &transition.before;
    let after = &transition.after;

    let flags = modifiable_flags(before).unwrap_or(0);
    let single_inputs = single_signed_inputs(before);

    if flags & HAS_SIGHASH_SINGLE == 0 && single_inputs.is_empty() {
        return CheckOutcome::NotApplicable;
    }

    if after.inputs < before.inputs || after.outputs < before.outputs {
        return CheckOutcome::Failed("Constructor cannot remove existing inputs or outputs".into());
    }

    // For each SIGHASH_SINGLE input in before (which pairs with output at the same index):
    // verify that in `after`, its new input index equals its new output index.
    for orig_idx in single_inputs {
        if orig_idx >= before.inputs || orig_idx >= before.outputs {
            return CheckOutcome::Failed(format!("SIGHASH_SINGLE input {orig_idx} has no matching output pair"));
        }

        let orig_in = &before.inputs()[orig_idx];
        let orig_prevout = orig_in.prevout();

        // Find this input in `after`
        let new_in_pos = after.inputs().iter().position(|i| i.prevout() == orig_prevout);
        let Some(new_in_idx) = new_in_pos else {
            return CheckOutcome::Failed(format!("SIGHASH_SINGLE input {orig_idx} not found in resulting PSBT"));
        };

        // The number of inputs added before this pair is (new_in_idx - orig_idx).
        // The number of outputs added before this pair must be identical, meaning
        // the paired output must now sit at `new_in_idx`.
        let num_inputs_before = new_in_idx.saturating_sub(orig_idx);
        let expected_output_idx = orig_idx + num_inputs_before;
        if expected_output_idx != new_in_idx {
            return CheckOutcome::Failed(format!(
                "SIGHASH_SINGLE pair {orig_idx} index mismatch: input shifted to {new_in_idx} but output expected at {expected_output_idx}"
            ));
        }
    }

    CheckOutcome::Verified
}
