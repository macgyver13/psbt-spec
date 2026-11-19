//! The field registry: every PSBT field these rules know, with its key data
//! format, value format, and the PSBT versions that require or exclude it.
//! Every listed field is known whatever BIPs a validator enables; fields not
//! listed here are unknown and pass through unchecked.

use bitcoin_hashes::{hash160, ripemd160, sha256, sha256d, Hash};

use crate::encoding::{decode_exact, read_tx, read_txout, read_witness, Reader};
use k256::elliptic_curve::PrimeField;

use crate::taproot::{is_xonly_key, valid_leaf_version};

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
    /// A 32-byte BIP-340 x-only public key.
    XOnlyPubKey,
    /// A 32-byte x-only public key followed by a 32-byte leaf hash.
    XOnlyPubKeyAndLeafHash,
    /// A BIP-341 Taproot control block (33 + 32*m bytes, where 0 <= m <= 128).
    TapControlBlock,
    /// A 33-byte participant compressed pubkey + 33-byte aggregate compressed pubkey + optional 32-byte leaf hash (66 or 98 bytes).
    MuSig2Session,
    XPub,
    Hash20,
    Hash32,
    /// A compact-size identifier length, the identifier, a compact-size subtype, then any key data.
    Proprietary,
}

#[derive(Debug, Clone, Copy)]
pub enum ValueFormat {
    /// A transaction in non-witness serialization with empty scriptSigs.
    UnsignedTx,
    /// A transaction in either serialization.
    Tx,
    TxOut,
    /// A 4-byte fingerprint followed by zero or more 4-byte path elements.
    KeyOrigin,
    /// A key origin with one path element per level of the xpub in the key data.
    XPubOrigin,
    /// Preimages whose hash under the named function is the key data.
    Ripemd160Preimage,
    Sha256Preimage,
    Hash160Preimage,
    Hash256Preimage,
    Witness,
    U8,
    U32,
    /// A 4-byte time-based locktime of at least 500,000,000.
    TimeLocktime,
    /// A 4-byte height-based locktime above 0 and below 500,000,000.
    HeightLocktime,
    I64,
    CompactSize,
    Bytes32,
    Bytes64,
    /// A 33-byte compressed public key.
    CompressedPubKey,
    /// Two 33-byte compressed public keys.
    CompressedPubKeyPair,
    /// A 32-byte BIP-340 x-only public key.
    XOnlyPubKey,
    /// A 64- or 65-byte Taproot Schnorr signature.
    TapSignature,
    /// A script followed by a 1-byte leaf version.
    TapLeafScript,
    /// CompactSize leaf hashes count + leaf hashes + BIP32 derivation path.
    TapBip32Derivation,
    /// One or more tuples of (depth, leaf version, script) in DFS order.
    TapTree,
    /// A BIP327 public nonce: two 33-byte compressed points.
    MuSig2PubNonce,
    /// A BIP327 partial signature: a 32-byte scalar below the curve order.
    MuSig2PartialSig,
    /// List of 33-byte compressed participant public keys.
    CompressedPubKeyList,
    /// 1-byte length prefix + human-readable name string + RFC 9102 DNSSEC proof.
    DnssecProof,
    /// UTF-8 encoded string.
    Utf8String,
    Bytes,
}

impl KeyFormat {
    /// The constraint GEN-F-5 enforces on key data in this format.
    pub fn constraint(self) -> &'static str {
        match self {
            KeyFormat::None => "empty",
            KeyFormat::PubKey => "33- or 65-byte public key on the curve",
            KeyFormat::CompressedPubKey => "33-byte compressed public key on the curve",
            KeyFormat::XOnlyPubKey => "32-byte BIP340 x-only key that lifts to the curve",
            KeyFormat::XOnlyPubKeyAndLeafHash => "32-byte x-only key on the curve, then a 32-byte leaf hash",
            KeyFormat::TapControlBlock => "BIP341 control block: 33 + 32m bytes (m at most 128), valid leaf version, internal key on the curve",
            KeyFormat::MuSig2Session => "33-byte participant key and 33-byte plain key on the curve, then an optional 32-byte leaf hash",
            KeyFormat::XPub => "78-byte serialized extended public key whose key is on the curve",
            KeyFormat::Hash20 => "20-byte hash",
            KeyFormat::Hash32 => "32-byte hash",
            KeyFormat::Proprietary => "compact-size identifier length, identifier, compact-size subtype, then any key data",
        }
    }
}

impl ValueFormat {
    /// The constraint GEN-F-5 enforces on values in this format.
    pub fn constraint(self) -> &'static str {
        match self {
            ValueFormat::UnsignedTx => "transaction in non-witness serialization with empty scriptSigs",
            ValueFormat::TimeLocktime => "4 bytes, at least 500,000,000",
            ValueFormat::HeightLocktime => "4 bytes, above 0 and below 500,000,000",
            ValueFormat::Tx => "transaction in either serialization",
            ValueFormat::TxOut => "8-byte amount and compact-size script",
            ValueFormat::KeyOrigin => "4-byte fingerprint, then 4-byte path elements",
            ValueFormat::XPubOrigin => "4-byte fingerprint, then one 4-byte path element per level of the xpub's depth",
            ValueFormat::Ripemd160Preimage => "bytes whose RIPEMD160 is the key data",
            ValueFormat::Sha256Preimage => "bytes whose SHA256 is the key data",
            ValueFormat::Hash160Preimage => "bytes whose HASH160 is the key data",
            ValueFormat::Hash256Preimage => "bytes whose HASH256 is the key data",
            ValueFormat::Witness => "compact-size count of compact-size stack items",
            ValueFormat::U8 => "1 byte",
            ValueFormat::U32 => "4 bytes",
            ValueFormat::I64 => "8 bytes",
            ValueFormat::CompactSize => "one compact-size integer",
            ValueFormat::Bytes32 => "32 bytes",
            ValueFormat::Bytes64 => "64 bytes",
            ValueFormat::CompressedPubKey => "33-byte compressed public key on the curve",
            ValueFormat::CompressedPubKeyPair => "two 33-byte compressed public keys on the curve",
            ValueFormat::XOnlyPubKey => "32-byte BIP340 x-only key that lifts to the curve",
            ValueFormat::TapSignature => "64-byte signature, or 65 bytes ending in a BIP341 hash type other than 0x00",
            ValueFormat::TapLeafScript => "script, then a leaf version that is even and not 0x50",
            ValueFormat::TapBip32Derivation => "compact-size count of 32-byte leaf hashes, then a key origin",
            ValueFormat::TapTree => "(depth, leaf version, script) tuples in depth-first order forming one complete tree; depth at most 128; leaf versions even and not 0x50",
            ValueFormat::MuSig2PubNonce => "two 33-byte compressed points on the curve",
            ValueFormat::MuSig2PartialSig => "32-byte scalar below the curve order",
            ValueFormat::CompressedPubKeyList => "one or more 33-byte compressed public keys on the curve",
            ValueFormat::DnssecProof => "1-byte name length and name; the RFC9102 proof after it is not parsed",
            ValueFormat::Utf8String => "UTF-8 text",
            ValueFormat::Bytes => "any bytes",
        }
    }
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
    field!(Global, 0x01, "PSBT_GLOBAL_XPUB",                 XPub,             XPubOrigin,           [],  [],  174),
    field!(Global, 0x02, "PSBT_GLOBAL_TX_VERSION",           None,             U32,                  [2], [0], 370),
    field!(Global, 0x03, "PSBT_GLOBAL_FALLBACK_LOCKTIME",    None,             U32,                  [],  [0], 370),
    field!(Global, 0x04, "PSBT_GLOBAL_INPUT_COUNT",          None,             CompactSize,          [2], [0], 370),
    field!(Global, 0x05, "PSBT_GLOBAL_OUTPUT_COUNT",         None,             CompactSize,          [2], [0], 370),
    field!(Global, 0x06, "PSBT_GLOBAL_TX_MODIFIABLE",        None,             U8,                   [],  [0], 370),
    field!(Global, 0x07, "PSBT_GLOBAL_SP_ECDH_SHARE",        CompressedPubKey, CompressedPubKey,     [],  [0], 375),
    field!(Global, 0x08, "PSBT_GLOBAL_SP_DLEQ",              CompressedPubKey, Bytes64,              [],  [0], 375),
    field!(Global, 0x09, "PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE", None,           Utf8String,           [],  [],  322),
    field!(Global, 0xfb, "PSBT_GLOBAL_VERSION",              None,             U32,                  [2], [],  174),
    field!(Global, 0xfc, "PSBT_GLOBAL_PROPRIETARY",          Proprietary,      Bytes,                [],  [],  174),
    field!(Input,  0x00, "PSBT_IN_NON_WITNESS_UTXO",        None,             Tx,                   [],  [],  174),
    field!(Input,  0x01, "PSBT_IN_WITNESS_UTXO",            None,             TxOut,                [],  [],  174),
    field!(Input,  0x02, "PSBT_IN_PARTIAL_SIG",             PubKey,           Bytes,                [],  [],  174),
    field!(Input,  0x03, "PSBT_IN_SIGHASH_TYPE",            None,             U32,                  [],  [],  174),
    field!(Input,  0x04, "PSBT_IN_REDEEM_SCRIPT",           None,             Bytes,                [],  [],  174),
    field!(Input,  0x05, "PSBT_IN_WITNESS_SCRIPT",          None,             Bytes,                [],  [],  174),
    field!(Input,  0x06, "PSBT_IN_BIP32_DERIVATION",        PubKey,           KeyOrigin,            [],  [],  174),
    field!(Input,  0x07, "PSBT_IN_FINAL_SCRIPTSIG",         None,             Bytes,                [],  [],  174),
    field!(Input,  0x08, "PSBT_IN_FINAL_SCRIPTWITNESS",     None,             Witness,              [],  [],  174),
    field!(Input,  0x09, "PSBT_IN_POR_COMMITMENT",          None,             Utf8String,           [],  [],  174),
    field!(Input,  0x0a, "PSBT_IN_RIPEMD160",               Hash20,           Ripemd160Preimage,    [],  [],  174),
    field!(Input,  0x0b, "PSBT_IN_SHA256",                  Hash32,           Sha256Preimage,       [],  [],  174),
    field!(Input,  0x0c, "PSBT_IN_HASH160",                 Hash20,           Hash160Preimage,      [],  [],  174),
    field!(Input,  0x0d, "PSBT_IN_HASH256",                 Hash32,           Hash256Preimage,      [],  [],  174),
    field!(Input,  0x0e, "PSBT_IN_PREVIOUS_TXID",           None,             Bytes32,              [2], [0], 370),
    field!(Input,  0x0f, "PSBT_IN_OUTPUT_INDEX",            None,             U32,                  [2], [0], 370),
    field!(Input,  0x10, "PSBT_IN_SEQUENCE",                None,             U32,                  [],  [0], 370),
    field!(Input,  0x11, "PSBT_IN_REQUIRED_TIME_LOCKTIME",  None,             TimeLocktime,         [],  [0], 370),
    field!(Input,  0x12, "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME", None,             HeightLocktime,       [],  [0], 370),
    field!(Input,  0x13, "PSBT_IN_TAP_KEY_SIG",              None,             TapSignature,         [],  [],  371),
    field!(Input,  0x14, "PSBT_IN_TAP_SCRIPT_SIG",           XOnlyPubKeyAndLeafHash, TapSignature,  [],  [],  371),
    field!(Input,  0x15, "PSBT_IN_TAP_LEAF_SCRIPT",          TapControlBlock,  TapLeafScript,        [],  [],  371),
    field!(Input,  0x16, "PSBT_IN_TAP_BIP32_DERIVATION",     XOnlyPubKey,      TapBip32Derivation,   [],  [],  371),
    field!(Input,  0x17, "PSBT_IN_TAP_INTERNAL_KEY",         None,             XOnlyPubKey,          [],  [],  371),
    field!(Input,  0x18, "PSBT_IN_TAP_MERKLE_ROOT",          None,             Bytes32,              [],  [],  371),
    field!(Input,  0x19, "PSBT_IN_P2C_TWEAK",                CompressedPubKey, Bytes32,              [],  [],  372),
    field!(Input,  0x1a, "PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS", CompressedPubKey, CompressedPubKeyList, [],  [],  373),
    field!(Input,  0x1b, "PSBT_IN_MUSIG2_PUB_NONCE",         MuSig2Session,    MuSig2PubNonce,              [],  [],  373),
    field!(Input,  0x1c, "PSBT_IN_MUSIG2_PARTIAL_SIG",       MuSig2Session,    MuSig2PartialSig,     [],  [],  373),
    field!(Input,  0x1d, "PSBT_IN_SP_ECDH_SHARE",           CompressedPubKey, CompressedPubKey,     [],  [0], 375),
    field!(Input,  0x1e, "PSBT_IN_SP_DLEQ",                 CompressedPubKey, Bytes64,              [],  [0], 375),
    field!(Input,  0x1f, "PSBT_IN_SP_SPEND_BIP32_DERIVATION", CompressedPubKey, KeyOrigin,          [],  [0], 376),
    field!(Input,  0x20, "PSBT_IN_SP_TWEAK",                None,             Bytes32,              [],  [0], 376),
    field!(Input,  0xfc, "PSBT_IN_PROPRIETARY",             Proprietary,      Bytes,                [],  [],  174),
    field!(Output, 0x00, "PSBT_OUT_REDEEM_SCRIPT",           None,             Bytes,                [],  [],  174),
    field!(Output, 0x01, "PSBT_OUT_WITNESS_SCRIPT",          None,             Bytes,                [],  [],  174),
    field!(Output, 0x02, "PSBT_OUT_BIP32_DERIVATION",        PubKey,           KeyOrigin,            [],  [],  174),
    field!(Output, 0x03, "PSBT_OUT_AMOUNT",                  None,             I64,                  [2], [0], 370),
    // A validator that enables BIP-375 knows PSBT_OUT_SP_V0_INFO, which then
    // stands in for PSBT_OUT_SCRIPT on an output whose script is not yet computed.
    field!(Output, 0x04, "PSBT_OUT_SCRIPT",                  None,             Bytes,                [2], [0], 370, or 0x09),
    field!(Output, 0x05, "PSBT_OUT_TAP_INTERNAL_KEY",        None,             XOnlyPubKey,          [],  [],  371),
    field!(Output, 0x06, "PSBT_OUT_TAP_TREE",                None,             TapTree,              [],  [],  371),
    field!(Output, 0x07, "PSBT_OUT_TAP_BIP32_DERIVATION",    XOnlyPubKey,      TapBip32Derivation,   [],  [],  371),
    field!(Output, 0x08, "PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS", CompressedPubKey, CompressedPubKeyList, [],  [],  373),
    field!(Output, 0x09, "PSBT_OUT_SP_V0_INFO",              None,             CompressedPubKeyPair, [],  [0], 375),
    field!(Output, 0x0a, "PSBT_OUT_SP_V0_LABEL",             None,             U32,                  [],  [0], 375),
    field!(Output, 0x35, "PSBT_OUT_DNSSEC_PROOF",            None,             DnssecProof,          [],  [],  353),
    field!(Output, 0xfc, "PSBT_OUT_PROPRIETARY",             Proprietary,      Bytes,                [],  [],  174),
];

/// The registered fields of `scope`.
pub fn fields(scope: Scope) -> impl Iterator<Item = &'static Field> {
    FIELDS.iter().filter(move |f| f.scope == scope)
}

pub fn lookup(scope: Scope, key_type: u64) -> Option<&'static Field> {
    fields(scope).find(|f| f.key_type == key_type)
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
        KeyFormat::XOnlyPubKey => is_xonly_key(data),
        KeyFormat::XOnlyPubKeyAndLeafHash => data.len() == 64 && is_xonly_key(&data[..32]),
        KeyFormat::TapControlBlock => {
            data.len() >= 33
                && (data.len() - 33) % 32 == 0
                && data.len() <= 33 + 128 * 32
                && valid_leaf_version(data[0] & 0xfe)
                && is_xonly_key(&data[1..33])
        }
        KeyFormat::MuSig2Session => {
            (data.len() == 66 || data.len() == 98)
                && is_compressed_pubkey(&data[..33])
                && is_compressed_pubkey(&data[33..66])
        }
        KeyFormat::XPub => data.len() == 78 && is_compressed_pubkey(&data[45..]),
        KeyFormat::Hash20 => data.len() == 20,
        KeyFormat::Hash32 => data.len() == 32,
        KeyFormat::Proprietary => {
            let mut r = Reader::new(data);
            r.var_bytes().and_then(|_| r.compact_size()).is_ok()
        }
    };
    if ok {
        Ok(())
    } else {
        Err(format!("key data is not {format:?}"))
    }
}

fn u32_value(value: &[u8]) -> Result<u32, String> {
    <[u8; 4]>::try_from(value)
        .map(u32::from_le_bytes)
        .map_err(|_| format!("expected 4 bytes, got {}", value.len()))
}

pub fn check_value(format: ValueFormat, value: &[u8]) -> Result<(), String> {
    let fixed = |n: usize| match value.len() == n {
        true => Ok(()),
        false => Err(format!("expected {n} bytes, got {}", value.len())),
    };
    match format {
        ValueFormat::UnsignedTx => match decode_exact(value, |r| read_tx(r, false))?.inputs.iter().position(|i| !i.script_sig.is_empty()) {
            Some(i) => Err(format!("unsigned transaction input {i} has a scriptSig")),
            None => Ok(()),
        },
        ValueFormat::TimeLocktime => match u32_value(value)? {
            t if t < 500_000_000 => Err(format!("time locktime {t} is below 500,000,000")),
            _ => Ok(()),
        },
        ValueFormat::HeightLocktime => match u32_value(value)? {
            h if h == 0 || h >= 500_000_000 => Err(format!("height locktime {h} is not above 0 and below 500,000,000")),
            _ => Ok(()),
        },
        ValueFormat::Tx => decode_exact(value, |r| read_tx(r, true)).map(drop),
        ValueFormat::TxOut => decode_exact(value, read_txout).map(drop),
        ValueFormat::Witness => decode_exact(value, read_witness).map(drop),
        ValueFormat::CompactSize => decode_exact(value, |r| r.compact_size()).map(drop),
        ValueFormat::KeyOrigin | ValueFormat::XPubOrigin if value.len() >= 4 && value.len().is_multiple_of(4) => Ok(()),
        ValueFormat::KeyOrigin | ValueFormat::XPubOrigin => Err(format!("key origin of {} bytes", value.len())),
        ValueFormat::U8 => fixed(1),
        ValueFormat::U32 => fixed(4),
        ValueFormat::I64 => fixed(8),
        ValueFormat::Bytes32 => fixed(32),
        ValueFormat::Bytes64 => fixed(64),
        ValueFormat::MuSig2PubNonce if value.len() == 66 && value.chunks(33).all(is_compressed_pubkey) => Ok(()),
        ValueFormat::MuSig2PubNonce => Err(format!("{} bytes are not two compressed points", value.len())),
        ValueFormat::MuSig2PartialSig => {
            fixed(32)?;
            let bytes: [u8; 32] = value.try_into().unwrap();
            match bool::from(k256::Scalar::from_repr(bytes.into()).is_some()) {
                true => Ok(()),
                false => Err("partial signature is not below the curve order".into()),
            }
        }
        ValueFormat::CompressedPubKey if is_compressed_pubkey(value) => Ok(()),
        ValueFormat::CompressedPubKeyPair if value.len() == 66 && value.chunks(33).all(is_compressed_pubkey) => Ok(()),
        ValueFormat::CompressedPubKey | ValueFormat::CompressedPubKeyPair => {
            Err(format!("{} bytes are not {format:?}", value.len()))
        }
        ValueFormat::TapSignature => crate::taproot::signature_hash_type(value).map(drop),
        ValueFormat::TapLeafScript => match value.last() {
            Some(&v) if valid_leaf_version(v) => Ok(()),
            Some(v) => Err(format!("leaf version {v:#04x} is not valid")),
            None => Err("TapLeafScript requires a leaf version byte".into()),
        },
        ValueFormat::XOnlyPubKey if is_xonly_key(value) => Ok(()),
        ValueFormat::XOnlyPubKey => Err(format!("{} bytes are not an x-only public key", value.len())),
        ValueFormat::TapBip32Derivation => decode_exact(value, |r| {
            let num_hashes = r.compact_size()?;
            for _ in 0..num_hashes {
                r.take(32)?;
            }
            let rem = r.remaining();
            if rem < 4 || rem % 4 != 0 {
                return Err(format!("derivation path length {rem} is not a valid BIP32 origin"));
            }
            r.take(rem)?;
            Ok(())
        }),
        ValueFormat::TapTree => crate::taproot::tap_tree(value).map(drop),
        ValueFormat::CompressedPubKeyList => {
            if value.is_empty() || value.len() % 33 != 0 || !value.chunks(33).all(is_compressed_pubkey) {
                return Err(format!("{} bytes are not a valid list of compressed public keys", value.len()));
            }
            Ok(())
        },
        ValueFormat::DnssecProof => {
            if value.is_empty() {
                return Err("DNSSEC proof field cannot be empty".into());
            }
            let name_len = value[0] as usize;
            if value.len() < 1 + name_len {
                return Err(format!("name length {name_len} exceeds field length {}", value.len()));
            }
            Ok(())
        },
        ValueFormat::Utf8String => match std::str::from_utf8(value) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("value is not valid UTF-8: {e}")),
        },
        ValueFormat::Bytes
        | ValueFormat::Ripemd160Preimage
        | ValueFormat::Sha256Preimage
        | ValueFormat::Hash160Preimage
        | ValueFormat::Hash256Preimage => Ok(()),
    }
}

/// Checks a record's key data and value against `field`, including the
/// constraints that relate the two: preimages hash to the key data, and an
/// xpub's origin has one path element per level of its depth.
pub fn check_record(field: &Field, key: &[u8], value: &[u8]) -> Result<(), String> {
    check_key(field.key, key)?;
    check_value(field.value, value)?;
    let hash: Option<Vec<u8>> = match field.value {
        ValueFormat::Ripemd160Preimage => Some(ripemd160::Hash::hash(value).to_byte_array().to_vec()),
        ValueFormat::Sha256Preimage => Some(sha256::Hash::hash(value).to_byte_array().to_vec()),
        ValueFormat::Hash160Preimage => Some(hash160::Hash::hash(value).to_byte_array().to_vec()),
        ValueFormat::Hash256Preimage => Some(sha256d::Hash::hash(value).to_byte_array().to_vec()),
        _ => None,
    };
    if hash.is_some_and(|h| h != key) {
        return Err("preimage does not hash to the key data".into());
    }
    if matches!(field.value, ValueFormat::XPubOrigin) && (value.len() - 4) / 4 != key[4] as usize {
        return Err(format!("{} path elements for an xpub of depth {}", (value.len() - 4) / 4, key[4]));
    }
    Ok(())
}
