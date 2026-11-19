mod common;

use psbt_spec::algebra::{CheckOutcome, Evaluation};
use psbt_spec::{evaluate_constructing, Bip};
use psbt_spec::context::*;
use psbt_spec::encoding::{Map, Psbt, Record, Transaction};
use psbt_spec::rules::constructor::*;
use psbt_spec::rules::creator::*;

fn field(key_type: u64, value: impl Into<Vec<u8>>) -> Record {
    Record {
        key_type,
        key_data: Vec::new(),
        value: value.into(),
    }
}

fn psbt_ctx(global: Map, inputs: Vec<Map>, outputs: Vec<Map>) -> PsbtContext {
    let mut maps = vec![global];
    maps.extend(inputs);
    maps.extend(outputs);
    let psbt = Psbt {
        maps,
        bips: Vec::new(),
    };
    PsbtContext::new(&psbt)
}

#[test]
fn test_role_c_1_creator_initialization() {
    // v0: valid initialization with unsigned tx and 0 inputs, 0 outputs
    let unsigned_tx = Transaction {
        version: 1,
        inputs: vec![],
        outputs: vec![],
        locktime: 0,
    };
    let v0_global = vec![field(GLOBAL_UNSIGNED_TX, unsigned_tx.serialize_without_witness())];
    let ctx0 = psbt_ctx(v0_global, vec![], vec![]);
    let creator_ctx0 = CreatorContext::new(ctx0, false);
    assert_eq!(validate_creator_initialization(&creator_ctx0), CheckOutcome::Verified);

    // v2: valid initialization with 0 inputs, 0 outputs
    let v2_global = vec![
        field(GLOBAL_VERSION, 2u32.to_le_bytes()),
        field(GLOBAL_TX_VERSION, 2u32.to_le_bytes()),
        field(GLOBAL_INPUT_COUNT, vec![0]),
        field(GLOBAL_OUTPUT_COUNT, vec![0]),
    ];
    let ctx2 = psbt_ctx(v2_global, vec![], vec![]);
    let creator_ctx2 = CreatorContext::new(ctx2, false);
    assert_eq!(validate_creator_initialization(&creator_ctx2), CheckOutcome::Verified);

    // v2 with non-zero inputs fails
    let bad_v2_global = vec![
        field(GLOBAL_VERSION, 2u32.to_le_bytes()),
        field(GLOBAL_TX_VERSION, 2u32.to_le_bytes()),
        field(GLOBAL_INPUT_COUNT, vec![1]),
        field(GLOBAL_OUTPUT_COUNT, vec![0]),
    ];
    let bad_ctx2 = psbt_ctx(bad_v2_global, vec![vec![]], vec![]);
    let bad_creator_ctx2 = CreatorContext::new(bad_ctx2, false);
    assert!(matches!(validate_creator_initialization(&bad_creator_ctx2), CheckOutcome::Failed(_)));
}

#[test]
fn test_role_c_2_delegated_construction() {
    // When delegation is false, it's NotApplicable
    let v2_global = vec![
        field(GLOBAL_VERSION, 2u32.to_le_bytes()),
        field(GLOBAL_TX_VERSION, 2u32.to_le_bytes()),
        field(GLOBAL_INPUT_COUNT, vec![0]),
        field(GLOBAL_OUTPUT_COUNT, vec![0]),
    ];
    let ctx = psbt_ctx(v2_global.clone(), vec![], vec![]);
    assert_eq!(validate_delegated_construction(&CreatorContext::new(ctx, false)), CheckOutcome::NotApplicable);

    // When delegation is true, requires TX_MODIFIABLE and nVersion >= 2
    let ctx_missing_mod = psbt_ctx(v2_global, vec![], vec![]);
    assert!(matches!(validate_delegated_construction(&CreatorContext::new(ctx_missing_mod, true)), CheckOutcome::Failed(_)));

    let mut v2_delegated = vec![
        field(GLOBAL_VERSION, 2u32.to_le_bytes()),
        field(GLOBAL_TX_VERSION, 2u32.to_le_bytes()),
        field(GLOBAL_INPUT_COUNT, vec![0]),
        field(GLOBAL_OUTPUT_COUNT, vec![0]),
        field(GLOBAL_TX_MODIFIABLE, vec![0x03]), // inputs & outputs modifiable
    ];
    let ctx_delegated = psbt_ctx(v2_delegated.clone(), vec![], vec![]);
    assert_eq!(validate_delegated_construction(&CreatorContext::new(ctx_delegated, true)), CheckOutcome::Verified);

    // nVersion = 1 fails when delegating
    v2_delegated[1] = field(GLOBAL_TX_VERSION, 1u32.to_le_bytes());
    let ctx_bad_version = psbt_ctx(v2_delegated, vec![], vec![]);
    assert!(matches!(validate_delegated_construction(&CreatorContext::new(ctx_bad_version, true)), CheckOutcome::Failed(_)));
}

#[test]
fn test_role_c_3_permitted_additions() {
    let v2_before = vec![
        field(GLOBAL_VERSION, 2u32.to_le_bytes()),
        field(GLOBAL_TX_VERSION, 2u32.to_le_bytes()),
        field(GLOBAL_INPUT_COUNT, vec![0]),
        field(GLOBAL_OUTPUT_COUNT, vec![0]),
        field(GLOBAL_TX_MODIFIABLE, vec![0x01]), // only inputs modifiable
    ];
    let before = psbt_ctx(v2_before, vec![], vec![]);

    // Adding an input when inputs are modifiable is permitted
    let v2_after_in = vec![
        field(GLOBAL_VERSION, 2u32.to_le_bytes()),
        field(GLOBAL_TX_VERSION, 2u32.to_le_bytes()),
        field(GLOBAL_INPUT_COUNT, vec![1]),
        field(GLOBAL_OUTPUT_COUNT, vec![0]),
        field(GLOBAL_TX_MODIFIABLE, vec![0x01]),
    ];
    let input0 = vec![field(IN_PREVIOUS_TXID, [1u8; 32]), field(IN_OUTPUT_INDEX, 0u32.to_le_bytes())];
    let after_in = psbt_ctx(v2_after_in, vec![input0.clone()], vec![]);
    let trans_in = ConstructorTransitionContext::new(before.clone(), after_in);
    assert_eq!(validate_permitted_additions(&trans_in), CheckOutcome::Verified);

    // Adding an output when outputs modifiable is 0 fails
    let v2_after_out = vec![
        field(GLOBAL_VERSION, 2u32.to_le_bytes()),
        field(GLOBAL_TX_VERSION, 2u32.to_le_bytes()),
        field(GLOBAL_INPUT_COUNT, vec![0]),
        field(GLOBAL_OUTPUT_COUNT, vec![1]),
        field(GLOBAL_TX_MODIFIABLE, vec![0x01]),
    ];
    let out0 = vec![field(OUT_AMOUNT, 1000i64.to_le_bytes()), field(OUT_SCRIPT, vec![0x51])];
    let after_out = psbt_ctx(v2_after_out, vec![], vec![out0]);
    let trans_out = ConstructorTransitionContext::new(before, after_out);
    assert!(matches!(validate_permitted_additions(&trans_out), CheckOutcome::Failed(_)));
}

#[test]
fn test_role_c_3_sp_info_stands_in_for_script_only_with_bip375() {
    // evaluate_constructing runs the General rules on what the Constructor
    // returned, so GEN-ST-2 decides whether PSBT_OUT_SP_V0_INFO may stand in
    // for PSBT_OUT_SCRIPT.
    let g = common::hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    let global = |outputs: u8| vec![
        field(GLOBAL_VERSION, 2u32.to_le_bytes()),
        field(GLOBAL_TX_VERSION, 2u32.to_le_bytes()),
        field(GLOBAL_INPUT_COUNT, vec![0]),
        field(GLOBAL_OUTPUT_COUNT, vec![outputs]),
        field(GLOBAL_TX_MODIFIABLE, vec![0x02]),
    ];
    let sp_output = vec![field(OUT_AMOUNT, 1000i64.to_le_bytes()), field(OUT_SP_V0_INFO, [g.clone(), g].concat())];
    let received = common::encode(&Psbt { maps: vec![global(0)], bips: vec![] });
    let returned = common::encode(&Psbt { maps: vec![global(1), sp_output], bips: vec![] });
    assert!(matches!(
        evaluate_constructing(&received, &returned, &[], &[]),
        Evaluation::Failed(v) if v.rule == "GEN-ST-2"
    ));
    assert_eq!(evaluate_constructing(&received, &returned, &[], &[Bip::Bip375]), Evaluation::Verified);
}
