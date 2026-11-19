use crate::context::{IN_FINAL_SCRIPTSIG, IN_FINAL_SCRIPTWITNESS, OUT_SCRIPT};
use crate::algebra::CheckOutcome;
use crate::context::{value_u32, PsbtContext, GLOBAL_TX_VERSION, IN_OUTPUT_INDEX, IN_PREVIOUS_TXID};

/// ROLE-X-1: Extract only when every input has the final script fields needed to represent its
/// completed spend, and the transaction can be constructed from the version-specific fields.
pub fn validate_extraction_readiness(psbt: &PsbtContext) -> CheckOutcome {
    for input in psbt.inputs() {
        if input.value(IN_FINAL_SCRIPTSIG).is_none() && input.value(IN_FINAL_SCRIPTWITNESS).is_none() {
            return CheckOutcome::Failed(format!("input {} lacks final script fields", input.index));
        }
        if psbt.version == 2 {
            if input.value(IN_PREVIOUS_TXID).is_none() || value_u32(input.map(), IN_OUTPUT_INDEX).is_none() {
                return CheckOutcome::Failed(format!("v2 input {} lacks prevout information for extraction", input.index));
            }
        }
    }

    if psbt.version == 2 {
        if value_u32(psbt.psbt.global(), GLOBAL_TX_VERSION).is_none() {
            return CheckOutcome::Failed("v2 extraction requires PSBT_GLOBAL_TX_VERSION".into());
        }
        for output in psbt.outputs() {
            if output.value(OUT_SCRIPT).is_none_or(|s| s.is_empty()) {
                return CheckOutcome::Failed(format!("output {} lacks scriptPubKey for extraction", output.index));
            }
        }
    }

    CheckOutcome::Verified
}

