//! The field registry: every PSBT field these rules know, with its key data
//! format, value format, and the PSBT versions that require or exclude it.
//! Fields not listed here are unknown and pass through unchecked.

use crate::algebra::Bip;
use crate::encoding::{decode_exact, read_tx, read_txout, read_witness};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Global,
    Input,
    Output,
}

#[derive(Debug, Clone, Copy)]
pub enum KeyFormat {
    None,
    PubKey,
    /// A 33-byte compressed public key.
    CompressedPubKey,
    XPub,
    Hash20,
    Hash32,
}

#[derive(Debug, Clone, Copy)]
pub enum ValueFormat {
    /// A transaction in non-witness serialization.
    UnsignedTx,
    /// A transaction in either serialization.
    Tx,
    TxOut,
    /// A 4-byte fingerprint followed by zero or more 4-byte path elements.
    KeyOrigin,
    Witness,
    U8,
    U32,
    I64,
    CompactSize,
    Bytes32,
    Bytes64,
    /// A 33-byte compressed public key.
    CompressedPubKey,
    /// Two 33-byte compressed public keys.
    CompressedPubKeyPair,
    Bytes,
}

pub struct Field {
    pub scope: Scope,
    pub key_type: u64,
    pub name: &'static str,
    pub key: KeyFormat,
    pub value: ValueFormat,
    pub required_in: &'static [u32],
    pub excluded_in: &'static [u32],
    pub bip: u32,
    /// Known fields any of which satisfies this field's requirement in its place.
    pub replaced_by: &'static [u64],
}

impl Field {
    /// Whether a validator that enables `bips` knows this field.
    pub fn known(&self, bips: &[Bip]) -> bool {
        match self.bip {
            375 => bips.contains(&Bip::Bip375),
            376 => bips.contains(&Bip::Bip376),
            _ => true,
        }
    }
}

macro_rules! field {
    ($scope:ident, $type:literal, $name:literal, $key:ident, $value:ident, $req:expr, $excl:expr, $bip:literal $(, or $alt:literal)?) => {
        Field {
            scope: Scope::$scope,
            key_type: $type,
            name: $name,
            key: KeyFormat::$key,
            value: ValueFormat::$value,
            required_in: &$req,
            excluded_in: &$excl,
            bip: $bip,
            replaced_by: &[$($alt),*],
        }
    };
}

#[rustfmt::skip]
pub static FIELDS: &[Field] = &[
    field!(Global, 0x00, "PSBT_GLOBAL_UNSIGNED_TX",          None,             UnsignedTx,           [0], [2], 174),
    field!(Global, 0x01, "PSBT_GLOBAL_XPUB",                 XPub,             KeyOrigin,            [],  [],  174),
    field!(Global, 0x02, "PSBT_GLOBAL_TX_VERSION",           None,             U32,                  [2], [0], 370),
    field!(Global, 0x03, "PSBT_GLOBAL_FALLBACK_LOCKTIME",    None,             U32,                  [],  [0], 370),
    field!(Global, 0x04, "PSBT_GLOBAL_INPUT_COUNT",          None,             CompactSize,          [2], [0], 370),
    field!(Global, 0x05, "PSBT_GLOBAL_OUTPUT_COUNT",         None,             CompactSize,          [2], [0], 370),
    field!(Global, 0x06, "PSBT_GLOBAL_TX_MODIFIABLE",        None,             U8,                   [],  [0], 370),
    field!(Global, 0x07, "PSBT_GLOBAL_SP_ECDH_SHARE",        CompressedPubKey, CompressedPubKey,     [],  [0], 375),
    field!(Global, 0x08, "PSBT_GLOBAL_SP_DLEQ",              CompressedPubKey, Bytes64,              [],  [0], 375),
    field!(Global, 0xfb, "PSBT_GLOBAL_VERSION",              None,             U32,                  [2], [],  174),
    field!(Input,  0x00, "PSBT_IN_NON_WITNESS_UTXO",        None,             Tx,                   [],  [],  174),
    field!(Input,  0x01, "PSBT_IN_WITNESS_UTXO",            None,             TxOut,                [],  [],  174),
    field!(Input,  0x02, "PSBT_IN_PARTIAL_SIG",             PubKey,           Bytes,                [],  [],  174),
    field!(Input,  0x03, "PSBT_IN_SIGHASH_TYPE",            None,             U32,                  [],  [],  174),
    field!(Input,  0x04, "PSBT_IN_REDEEM_SCRIPT",           None,             Bytes,                [],  [],  174),
    field!(Input,  0x05, "PSBT_IN_WITNESS_SCRIPT",          None,             Bytes,                [],  [],  174),
    field!(Input,  0x06, "PSBT_IN_BIP32_DERIVATION",        PubKey,           KeyOrigin,            [],  [],  174),
    field!(Input,  0x07, "PSBT_IN_FINAL_SCRIPTSIG",         None,             Bytes,                [],  [],  174),
    field!(Input,  0x08, "PSBT_IN_FINAL_SCRIPTWITNESS",     None,             Witness,              [],  [],  174),
    field!(Input,  0x0a, "PSBT_IN_RIPEMD160",               Hash20,           Bytes,                [],  [],  174),
    field!(Input,  0x0b, "PSBT_IN_SHA256",                  Hash32,           Bytes,                [],  [],  174),
    field!(Input,  0x0c, "PSBT_IN_HASH160",                 Hash20,           Bytes,                [],  [],  174),
    field!(Input,  0x0d, "PSBT_IN_HASH256",                 Hash32,           Bytes,                [],  [],  174),
    field!(Input,  0x0e, "PSBT_IN_PREVIOUS_TXID",           None,             Bytes32,              [2], [0], 370),
    field!(Input,  0x0f, "PSBT_IN_OUTPUT_INDEX",            None,             U32,                  [2], [0], 370),
    field!(Input,  0x10, "PSBT_IN_SEQUENCE",                None,             U32,                  [],  [0], 370),
    field!(Input,  0x11, "PSBT_IN_REQUIRED_TIME_LOCKTIME",  None,             U32,                  [],  [0], 370),
    field!(Input,  0x12, "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME", None,             U32,                  [],  [0], 370),
    field!(Input,  0x1d, "PSBT_IN_SP_ECDH_SHARE",           CompressedPubKey, CompressedPubKey,     [],  [0], 375),
    field!(Input,  0x1e, "PSBT_IN_SP_DLEQ",                 CompressedPubKey, Bytes64,              [],  [0], 375),
    field!(Input,  0x1f, "PSBT_IN_SP_SPEND_BIP32_DERIVATION", CompressedPubKey, KeyOrigin,          [],  [0], 376),
    field!(Input,  0x20, "PSBT_IN_SP_TWEAK",                None,             Bytes32,              [],  [0], 376),
    field!(Output, 0x00, "PSBT_OUT_REDEEM_SCRIPT",           None,             Bytes,                [],  [],  174),
    field!(Output, 0x01, "PSBT_OUT_WITNESS_SCRIPT",          None,             Bytes,                [],  [],  174),
    field!(Output, 0x02, "PSBT_OUT_BIP32_DERIVATION",        PubKey,           KeyOrigin,            [],  [],  174),
    field!(Output, 0x03, "PSBT_OUT_AMOUNT",                  None,             I64,                  [2], [0], 370),
    // A validator that enables BIP-375 knows PSBT_OUT_SP_V0_INFO, which then
    // stands in for PSBT_OUT_SCRIPT on an output whose script is not yet computed.
    field!(Output, 0x04, "PSBT_OUT_SCRIPT",                  None,             Bytes,                [2], [0], 370, or 0x09),
    field!(Output, 0x09, "PSBT_OUT_SP_V0_INFO",              None,             CompressedPubKeyPair, [],  [0], 375),
    field!(Output, 0x0a, "PSBT_OUT_SP_V0_LABEL",             None,             U32,                  [],  [0], 375),
];

/// The fields of `scope` a validator that enables `bips` knows.
pub fn fields(scope: Scope, bips: &[Bip]) -> impl Iterator<Item = &'static Field> + '_ {
    FIELDS.iter().filter(move |f| f.scope == scope && f.known(bips))
}

pub fn lookup(scope: Scope, key_type: u64, bips: &[Bip]) -> Option<&'static Field> {
    fields(scope, bips).find(|f| f.key_type == key_type)
}

fn is_compressed_pubkey(data: &[u8]) -> bool {
    data.len() == 33 && k256::PublicKey::from_sec1_bytes(data).is_ok()
}

pub fn check_key(format: KeyFormat, data: &[u8]) -> Result<(), String> {
    let ok = match format {
        KeyFormat::None => data.is_empty(),
        KeyFormat::PubKey => {
            matches!(data.len(), 33 | 65) && k256::PublicKey::from_sec1_bytes(data).is_ok()
        }
        KeyFormat::CompressedPubKey => is_compressed_pubkey(data),
        KeyFormat::XPub => data.len() == 78,
        KeyFormat::Hash20 => data.len() == 20,
        KeyFormat::Hash32 => data.len() == 32,
    };
    if ok {
        Ok(())
    } else {
        Err(format!("key data is not {format:?}"))
    }
}

pub fn check_value(format: ValueFormat, value: &[u8]) -> Result<(), String> {
    let fixed = |n: usize| match value.len() == n {
        true => Ok(()),
        false => Err(format!("expected {n} bytes, got {}", value.len())),
    };
    match format {
        ValueFormat::UnsignedTx => decode_exact(value, |r| read_tx(r, false)).map(drop),
        ValueFormat::Tx => decode_exact(value, |r| read_tx(r, true)).map(drop),
        ValueFormat::TxOut => decode_exact(value, read_txout).map(drop),
        ValueFormat::Witness => decode_exact(value, read_witness).map(drop),
        ValueFormat::CompactSize => decode_exact(value, |r| r.compact_size()).map(drop),
        ValueFormat::KeyOrigin if value.len() >= 4 && value.len().is_multiple_of(4) => Ok(()),
        ValueFormat::KeyOrigin => Err(format!("key origin of {} bytes", value.len())),
        ValueFormat::U8 => fixed(1),
        ValueFormat::U32 => fixed(4),
        ValueFormat::I64 => fixed(8),
        ValueFormat::Bytes32 => fixed(32),
        ValueFormat::Bytes64 => fixed(64),
        ValueFormat::CompressedPubKey if is_compressed_pubkey(value) => Ok(()),
        ValueFormat::CompressedPubKeyPair if value.len() == 66 && value.chunks(33).all(is_compressed_pubkey) => Ok(()),
        ValueFormat::CompressedPubKey | ValueFormat::CompressedPubKeyPair => {
            Err(format!("{} bytes are not {format:?}", value.len()))
        }
        ValueFormat::Bytes => Ok(()),
    }
}
