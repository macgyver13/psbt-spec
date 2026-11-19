use base64::{engine::general_purpose::STANDARD, Engine};
use psbt_spec::algebra::{Doc, Entry};
use psbt_spec::context::{
    determine_locktime, PsbtContext, GLOBAL_FALLBACK_LOCKTIME, GLOBAL_INPUT_COUNT, GLOBAL_OUTPUT_COUNT,
    GLOBAL_TX_VERSION, GLOBAL_UNSIGNED_TX, GLOBAL_VERSION, IN_OUTPUT_INDEX, IN_PREVIOUS_TXID,
    IN_REQUIRED_HEIGHT_LOCKTIME, IN_REQUIRED_TIME_LOCKTIME,
};
use psbt_spec::encoding::{put_compact_size, Map, Psbt, Record, Transaction, TxIn, MAGIC};
use psbt_spec::rules::{framing::*, global::*, input_output::*};
use psbt_spec::spec;
use serde_json::Value;

fn field(key_type: u64, value: impl Into<Vec<u8>>) -> Record {
    Record {
        key_type,
        key_data: Vec::new(),
        value: value.into(),
    }
}

fn serialize(psbt: &Psbt) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    for map in &psbt.maps {
        for record in map {
            let mut key = Vec::new();
            put_compact_size(&mut key, usize::try_from(record.key_type).unwrap());
            key.extend(&record.key_data);
            put_compact_size(&mut bytes, key.len());
            bytes.extend(key);
            put_compact_size(&mut bytes, record.value.len());
            bytes.extend(&record.value);
        }
        bytes.push(0);
    }
    bytes
}

fn input(time: Option<u32>, height: Option<u32>) -> Map {
    let mut map = vec![
        field(IN_PREVIOUS_TXID, [0; 32]),
        field(IN_OUTPUT_INDEX, 0u32.to_le_bytes()),
    ];
    if let Some(time) = time {
        map.push(field(IN_REQUIRED_TIME_LOCKTIME, time.to_le_bytes()));
    }
    if let Some(height) = height {
        map.push(field(IN_REQUIRED_HEIGHT_LOCKTIME, height.to_le_bytes()));
    }
    map
}

fn v2(inputs: Vec<Map>, fallback: Option<u32>) -> Psbt {
    let mut count = Vec::new();
    put_compact_size(&mut count, inputs.len());
    let mut global = vec![
        field(GLOBAL_VERSION, 2u32.to_le_bytes()),
        field(GLOBAL_TX_VERSION, 2u32.to_le_bytes()),
        field(GLOBAL_INPUT_COUNT, count),
        field(GLOBAL_OUTPUT_COUNT, [0]),
    ];
    if let Some(fallback) = fallback {
        global.push(field(GLOBAL_FALLBACK_LOCKTIME, fallback.to_le_bytes()));
    }
    Psbt {
        maps: std::iter::once(global).chain(inputs).collect(),
        bips: Vec::new(),
    }
}

// Establish projection prerequisites without requiring GEN-T-1 itself to pass.
fn checked_context(bytes: &[u8]) -> PsbtContext {
    validate_magic(bytes).unwrap();
    validate_records(bytes).unwrap();
    validate_maps_terminated(bytes).unwrap();
    let psbt = spec::parse(bytes, &[]);
    for map in &psbt.maps {
        validate_unique_keys(map).unwrap();
    }
    validate_global_field_formats(&psbt).unwrap();
    validate_version(&psbt).unwrap();
    validate_global_field_versions(&psbt).unwrap();
    if psbt.unsigned_tx().is_some() {
        validate_unsigned_tx_unsigned(&psbt).unwrap();
    }
    validate_map_count(&psbt).unwrap();
    let ctx = PsbtContext::new(&psbt);
    for input in ctx.inputs() {
        validate_input_field_formats(&input).unwrap();
        validate_input_field_versions(&input).unwrap();
        if ctx.version == 2 {
            validate_required_time_locktime(&input).unwrap();
            validate_required_height_locktime(&input).unwrap();
        }
    }
    for output in ctx.outputs() {
        validate_output_field_formats(&output).unwrap();
        validate_output_field_versions(&output).unwrap();
    }
    ctx
}

#[test]
fn magic_is_exact_and_checks_only_the_prefix() {
    assert_eq!(validate_magic(&MAGIC), Ok(()));
    assert_eq!(validate_magic(&[MAGIC.as_slice(), &[0xff, 0xfd]].concat()), Ok(()));
    for length in 0..MAGIC.len() {
        let bytes = &MAGIC[..length];
        assert!(validate_magic(bytes).is_err());
        assert_eq!(spec::general_rules(&[]).validate(bytes).unwrap_err().rule, "GEN-F-1");
    }
    for index in 0..MAGIC.len() {
        let mut bytes = serialize(&v2(Vec::new(), None));
        bytes[index] ^= 1;
        assert!(validate_magic(&bytes).is_err());
        assert_eq!(spec::general_rules(&[]).validate(&bytes).unwrap_err().rule, "GEN-F-1");
    }
}

#[test]
fn malformed_framing_is_rejected_before_parse_projection() {
    let graph = spec::general_rules(&[]);
    let bytes = serialize(&v2(Vec::new(), None));
    assert_eq!(graph.validate(&bytes), Ok(()));
    for length in 0..bytes.len() {
        // A panic in the infallible parse projection would fail this test.
        let error = graph.validate(&bytes[..length]).unwrap_err();
        assert!(
            matches!(error.rule, "GEN-F-1" | "GEN-F-2" | "GEN-F-3"),
            "prefix {length}: {error:?}"
        );
    }
    for record in [
        vec![1, 2, 4, 0],          // Truncated four-byte value.
        vec![3, 0xfd, 1, 0, 0, 0], // Nonminimal key type.
        vec![0xfd, 1, 0, 2, 0, 0], // Nonminimal key length.
    ] {
        let malformed = [MAGIC.as_slice(), &record].concat();
        assert_eq!(graph.validate(&malformed).unwrap_err().rule, "GEN-F-2");
    }
    assert_eq!(graph.validate(&MAGIC).unwrap_err().rule, "GEN-F-3");
}

#[test]
fn malformed_globals_fail_before_psbt_context_projection() {
    let graph = spec::general_rules(&[]);
    let mut malformed = v2(Vec::new(), None);
    malformed.maps[0][0].value = vec![2];
    assert_eq!(graph.validate(&serialize(&malformed)).unwrap_err().rule, "GEN-F-5");

    let mut missing_count = v2(Vec::new(), None);
    missing_count.maps[0].retain(|r| r.key_type != GLOBAL_INPUT_COUNT);
    assert_eq!(graph.validate(&serialize(&missing_count)).unwrap_err().rule, "GEN-ST-2");

    let mut missing_input_map = v2(vec![input(None, None)], None);
    missing_input_map.maps.pop();
    assert_eq!(
        graph.validate(&serialize(&missing_input_map)).unwrap_err().rule,
        "GEN-ST-3"
    );
}

#[test]
fn published_locktimes_agree_with_direct_check_and_general_graph() {
    let vectors: Vec<Value> = serde_json::from_str(include_str!("../../vectors/bip370_locktime.json")).unwrap();
    let graph = spec::general_rules(&[]);
    for vector in vectors {
        let bytes = STANDARD.decode(vector["psbt"].as_str().unwrap()).unwrap();
        let ctx = checked_context(&bytes);
        let expected = vector["locktime"].as_u64().map(|n| u32::try_from(n).unwrap());
        assert_eq!(determine_locktime(&ctx), expected, "{}", vector["description"]);
        assert_eq!(
            validate_locktime_determinable(&ctx).is_ok(),
            expected.is_some(),
            "{}",
            vector["description"]
        );
        assert_eq!(
            graph.validate(&bytes).err().map(|e| e.rule),
            expected.is_none().then_some("GEN-T-1"),
            "{}",
            vector["description"]
        );
    }
}

#[test]
fn empty_and_unconstrained_inputs_use_fallback_or_zero() {
    for inputs in [Vec::new(), vec![input(None, None)]] {
        for fallback in [None, Some(0), Some(499_999_999), Some(500_000_000), Some(u32::MAX)] {
            let bytes = serialize(&v2(inputs.clone(), fallback));
            let ctx = checked_context(&bytes);
            assert_eq!(determine_locktime(&ctx), Some(fallback.unwrap_or(0)));
            assert_eq!(validate_locktime_determinable(&ctx), Ok(()));
            assert_eq!(spec::general_rules(&[]).validate(&bytes), Ok(()));
        }
    }
}

#[test]
fn locktime_field_boundaries_are_checked_before_determination() {
    for (key_type, value, valid) in [
        (IN_REQUIRED_HEIGHT_LOCKTIME, 0, false),
        (IN_REQUIRED_HEIGHT_LOCKTIME, 1, true),
        (IN_REQUIRED_HEIGHT_LOCKTIME, 499_999_999, true),
        (IN_REQUIRED_HEIGHT_LOCKTIME, 500_000_000, false),
        (IN_REQUIRED_TIME_LOCKTIME, 499_999_999, false),
        (IN_REQUIRED_TIME_LOCKTIME, 500_000_000, true),
        (IN_REQUIRED_TIME_LOCKTIME, u32::MAX, true),
    ] {
        let mut map = input(None, None);
        map.push(field(key_type, value.to_le_bytes()));
        let bytes = serialize(&v2(vec![map], None));
        let result = spec::general_rules(&[]).validate(&bytes);
        assert_eq!(
            result.err().map(|e| e.rule),
            (!valid).then_some("GEN-F-5"),
            "type {key_type:#x}, value {value}"
        );
        if valid {
            assert_eq!(determine_locktime(&checked_context(&bytes)), Some(value));
        }
    }
}

#[test]
fn shared_type_beats_fallback_and_incompatible_types_fail_gen_t1() {
    let cases = [
        (
            vec![input(None, Some(1)), input(None, Some(499_999_999))],
            Some(499_999_999),
        ),
        (
            vec![input(Some(500_000_000), None), input(Some(u32::MAX), None)],
            Some(u32::MAX),
        ),
        (
            vec![
                input(Some(u32::MAX), Some(1)),
                input(Some(500_000_000), Some(499_999_999)),
            ],
            Some(499_999_999),
        ),
        (
            vec![input(None, Some(499_999_999)), input(Some(500_000_000), None)],
            None,
        ),
    ];
    for (inputs, expected) in cases {
        let bytes = serialize(&v2(inputs, Some(42)));
        let ctx = checked_context(&bytes);
        assert_eq!(determine_locktime(&ctx), expected);
        assert_eq!(validate_locktime_determinable(&ctx).is_ok(), expected.is_some());
        assert_eq!(
            spec::general_rules(&[]).validate(&bytes).err().map(|e| e.rule),
            expected.is_none().then_some("GEN-T-1")
        );
    }
}

#[test]
fn gen_t1_is_gated_on_v2_and_v0_uses_its_unsigned_transaction() {
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            txid: [0; 32],
            vout: 0,
            script_sig: Vec::new(),
            sequence: u32::MAX,
            witness: Vec::new(),
        }],
        outputs: Vec::new(),
        locktime: 500_000_000,
    };
    let mut psbt = Psbt {
        maps: vec![
            vec![field(GLOBAL_UNSIGNED_TX, tx.serialize_without_witness())],
            Vec::new(),
        ],
        bips: Vec::new(),
    };
    let bytes = serialize(&psbt);
    let ctx = checked_context(&bytes);
    assert_eq!(ctx.version, 0);
    assert_eq!(ctx.unsigned_tx.as_ref().unwrap().locktime, 500_000_000);
    assert_eq!(spec::general_rules(&[]).validate(&bytes), Ok(()));

    let mut doc = Doc::default();
    spec::general_rules(&[]).describe(&mut doc);
    let gates = doc
        .entries
        .iter()
        .find_map(|entry| match entry {
            Entry::Rule {
                id: "GEN-T-1", gates, ..
            } => Some(gates),
            _ => None,
        })
        .unwrap();
    assert_eq!(gates, &["PSBTv2"]);

    psbt.maps[1].push(field(IN_REQUIRED_HEIGHT_LOCKTIME, 1u32.to_le_bytes()));
    assert_eq!(
        spec::general_rules(&[]).validate(&serialize(&psbt)).unwrap_err().rule,
        "GEN-ST-2"
    );
}
