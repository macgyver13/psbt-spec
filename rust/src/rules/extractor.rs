use crate::context::{InputContext, OutputContext, IN_FINAL_SCRIPTSIG, IN_FINAL_SCRIPTWITNESS, OUT_SCRIPT};

// Every input MUST have PSBT_IN_FINAL_SCRIPTSIG or PSBT_IN_FINAL_SCRIPTWITNESS.
pub fn validate_input_finalized(input: &InputContext) -> Result<(), String> {
    if input.value(IN_FINAL_SCRIPTSIG).is_none() && input.value(IN_FINAL_SCRIPTWITNESS).is_none() {
        return Err(format!("input {} is not finalized", input.index));
    }
    Ok(())
}

// Every output MUST have a non-empty PSBT_OUT_SCRIPT.
pub fn validate_output_has_script(output: &OutputContext) -> Result<(), String> {
    if output.value(OUT_SCRIPT).is_none_or(|s| s.is_empty()) {
        return Err(format!("output {} has no PSBT_OUT_SCRIPT", output.index));
    }
    Ok(())
}
