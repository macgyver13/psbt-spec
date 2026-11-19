//! Creator role validation rules (BIP-174 and BIP-370).

use crate::algebra::CheckOutcome;
use crate::context::{
    value, value_u32, PsbtContext, GLOBAL_TX_MODIFIABLE, GLOBAL_TX_VERSION, GLOBAL_UNSIGNED_TX,
    GLOBAL_VERSION,
};

/// Context representing a newly initialized PSBT from a Creator.
///
/// In addition to the PSBT itself, it carries whether the Creator is delegating
/// additions to other entities (which requires modifiable flags and nVersion >= 2).
#[derive(Clone)]
pub struct CreatorContext {
    pub psbt: PsbtContext,
    pub delegates_additions: bool,
}

impl CreatorContext {
    pub fn new(psbt: PsbtContext, delegates_additions: bool) -> Self {
        Self {
            psbt,
            delegates_additions,
        }
    }
}

/// ROLE-C-1: A v0 Creator constructs the unsigned transaction and initially empty
/// input/output maps. A v2 Creator initializes version 2 with zero inputs and zero outputs.
pub fn validate_creator_initialization(context: &CreatorContext) -> CheckOutcome {
    let psbt = &context.psbt;
    match psbt.version {
        0 => {
            if psbt.unsigned_tx.is_none() {
                return CheckOutcome::Failed("v0 Creator must construct the unsigned transaction".into());
            }
            if psbt.inputs != 0 || psbt.outputs != 0 {
                return CheckOutcome::Failed("v0 Creator must initialize with empty input/output maps".into());
            }
            CheckOutcome::Verified
        }
        2 => {
            if value_u32(psbt.psbt.global(), GLOBAL_VERSION) != Some(2) {
                return CheckOutcome::Failed("v2 Creator must set PSBT_GLOBAL_VERSION to 2".into());
            }
            if psbt.inputs != 0 || psbt.outputs != 0 {
                return CheckOutcome::Failed("v2 Creator must initialize with zero inputs and zero outputs".into());
            }
            if value(psbt.psbt.global(), GLOBAL_UNSIGNED_TX).is_some() {
                return CheckOutcome::Failed("v2 Creator must not include PSBT_GLOBAL_UNSIGNED_TX".into());
            }
            CheckOutcome::Verified
        }
        v => CheckOutcome::Failed(format!("unsupported PSBT version {v} for Creator initialization")),
    }
}

/// ROLE-C-2: If the Creator is not also a Constructor and delegates additions,
/// PSBT_GLOBAL_TX_MODIFIABLE MUST be present with flags set appropriately,
/// and transaction nVersion MUST be at least 2.
pub fn validate_delegated_construction(context: &CreatorContext) -> CheckOutcome {
    let psbt = &context.psbt;
    if psbt.version != 2 {
        return CheckOutcome::NotApplicable;
    }

    if !context.delegates_additions {
        // Self-contained construction: omitting TX_MODIFIABLE is permitted.
        return CheckOutcome::NotApplicable;
    }

    let Some(flags) = value(psbt.psbt.global(), GLOBAL_TX_MODIFIABLE) else {
        return CheckOutcome::Failed("delegated construction requires PSBT_GLOBAL_TX_MODIFIABLE".into());
    };
    if flags.len() != 1 {
        return CheckOutcome::Failed("PSBT_GLOBAL_TX_MODIFIABLE must be 1 byte".into());
    }

    let Some(tx_version) = value_u32(psbt.psbt.global(), GLOBAL_TX_VERSION) else {
        return CheckOutcome::Failed("delegated construction requires PSBT_GLOBAL_TX_VERSION".into());
    };
    if tx_version < 2 {
        return CheckOutcome::Failed("delegated construction requires transaction nVersion >= 2".into());
    }

    CheckOutcome::Verified
}
