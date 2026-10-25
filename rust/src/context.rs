//! Validation contexts. Each is projected from the one above it once the rules
//! that precede the projection have established what it relies on.

use std::rc::Rc;

use crate::algebra::Bip;
use crate::encoding::{decode_exact, read_tx, read_txout, Map, Psbt, Record, Transaction, TxIn, TxOut};

pub const GLOBAL_UNSIGNED_TX: u64 = 0x00;
pub const GLOBAL_TX_VERSION: u64 = 0x02;
pub const GLOBAL_INPUT_COUNT: u64 = 0x04;
pub const GLOBAL_OUTPUT_COUNT: u64 = 0x05;
pub const GLOBAL_FALLBACK_LOCKTIME: u64 = 0x03;
pub const GLOBAL_TX_MODIFIABLE: u64 = 0x06;
pub const GLOBAL_SP_ECDH_SHARE: u64 = 0x07;
pub const GLOBAL_SP_DLEQ: u64 = 0x08;
pub const GLOBAL_VERSION: u64 = 0xfb;
pub const IN_NON_WITNESS_UTXO: u64 = 0x00;
pub const IN_WITNESS_UTXO: u64 = 0x01;
pub const IN_PARTIAL_SIG: u64 = 0x02;
pub const IN_SIGHASH_TYPE: u64 = 0x03;
pub const IN_REDEEM_SCRIPT: u64 = 0x04;
pub const IN_WITNESS_SCRIPT: u64 = 0x05;
pub const IN_BIP32_DERIVATION: u64 = 0x06;
pub const IN_FINAL_SCRIPTSIG: u64 = 0x07;
pub const IN_FINAL_SCRIPTWITNESS: u64 = 0x08;
pub const IN_PREVIOUS_TXID: u64 = 0x0e;
pub const IN_OUTPUT_INDEX: u64 = 0x0f;
pub const IN_REQUIRED_TIME_LOCKTIME: u64 = 0x11;
pub const IN_REQUIRED_HEIGHT_LOCKTIME: u64 = 0x12;
pub const IN_TAP_KEY_SIG: u64 = 0x13;
pub const IN_TAP_SCRIPT_SIG: u64 = 0x14;
pub const IN_TAP_INTERNAL_KEY: u64 = 0x17;
pub const IN_TAP_MERKLE_ROOT: u64 = 0x18;
pub const IN_SP_ECDH_SHARE: u64 = 0x1d;
pub const IN_SP_DLEQ: u64 = 0x1e;
pub const IN_SP_SPEND_BIP32_DERIVATION: u64 = 0x1f;
pub const IN_SP_TWEAK: u64 = 0x20;
pub const OUT_AMOUNT: u64 = 0x03;
pub const OUT_SCRIPT: u64 = 0x04;
pub const OUT_SP_V0_INFO: u64 = 0x09;
pub const OUT_SP_V0_LABEL: u64 = 0x0a;

/// The value of the key-data-free field `key_type`, if the map has one.
pub fn value(map: &Map, key_type: u64) -> Option<&[u8]> {
    map.iter().find(|r| r.key_type == key_type && r.key_data.is_empty()).map(|r| r.value.as_slice())
}

/// The value of field `key_type` with key data `key_data`, if the map has one.
pub fn keyed<'a>(map: &'a Map, key_type: u64, key_data: &[u8]) -> Option<&'a [u8]> {
    map.iter().find(|r| r.key_type == key_type && r.key_data == key_data).map(|r| r.value.as_slice())
}

/// Every record of type `key_type`, whatever its key data.
pub fn records(map: &Map, key_type: u64) -> impl Iterator<Item = &Record> {
    map.iter().filter(move |r| r.key_type == key_type)
}

pub fn value_u32(map: &Map, key_type: u64) -> Option<u32> {
    value(map, key_type).map(|v| u32::from_le_bytes(v.try_into().unwrap()))
}

impl Psbt {
    pub fn global(&self) -> &Map {
        &self.maps[0]
    }

    /// The PSBT version. An absent PSBT_GLOBAL_VERSION means version 0.
    pub fn version(&self) -> u32 {
        value_u32(self.global(), GLOBAL_VERSION).unwrap_or(0)
    }

    pub fn unsigned_tx(&self) -> Option<Transaction> {
        value(self.global(), GLOBAL_UNSIGNED_TX).map(|v| decode_exact(v, |r| read_tx(r, false)).unwrap())
    }

    /// Input and output counts, from the unsigned transaction (v0) or the
    /// count fields (v2).
    pub fn counts(&self) -> (usize, usize) {
        if let Some(tx) = self.unsigned_tx() {
            return (tx.inputs.len(), tx.outputs.len());
        }
        let count = |t| decode_exact(value(self.global(), t).unwrap(), |r| r.compact_size()).unwrap() as usize;
        (count(GLOBAL_INPUT_COUNT), count(GLOBAL_OUTPUT_COUNT))
    }
}

pub struct PsbtData {
    pub psbt: Psbt,
    pub version: u32,
    pub unsigned_tx: Option<Transaction>,
    pub inputs: usize,
    pub outputs: usize,
}

/// A PSBT whose global rules hold, with its maps assigned to inputs and outputs.
#[derive(Clone)]
pub struct PsbtContext(pub Rc<PsbtData>);

impl std::ops::Deref for PsbtContext {
    type Target = PsbtData;
    fn deref(&self) -> &PsbtData {
        &self.0
    }
}

impl PsbtContext {
    pub fn new(psbt: &Psbt) -> Self {
        let (inputs, outputs) = psbt.counts();
        PsbtContext(Rc::new(PsbtData {
            version: psbt.version(),
            unsigned_tx: psbt.unsigned_tx(),
            psbt: psbt.clone(),
            inputs,
            outputs,
        }))
    }

    pub fn input_map(&self, index: usize) -> &Map {
        &self.psbt.maps[1 + index]
    }

    pub fn output_map(&self, index: usize) -> &Map {
        &self.psbt.maps[1 + self.inputs + index]
    }

    pub fn inputs(&self) -> Vec<InputContext> {
        (0..self.inputs).map(|index| InputContext { psbt: self.clone(), index }).collect()
    }

    pub fn outputs(&self) -> Vec<OutputContext> {
        (0..self.outputs).map(|index| OutputContext { psbt: self.clone(), index }).collect()
    }
}

#[derive(Clone)]
pub struct InputContext {
    pub psbt: PsbtContext,
    pub index: usize,
}

impl InputContext {
    pub fn map(&self) -> &Map {
        self.psbt.input_map(self.index)
    }

    pub fn version(&self) -> u32 {
        self.psbt.version
    }

    pub fn value(&self, key_type: u64) -> Option<&[u8]> {
        value(self.map(), key_type)
    }

    /// The spent outpoint: txid in internal byte order and output index.
    pub fn prevout(&self) -> ([u8; 32], u32) {
        match &self.psbt.unsigned_tx {
            Some(tx) => (tx.inputs[self.index].txid, tx.inputs[self.index].vout),
            None => (
                self.value(IN_PREVIOUS_TXID).unwrap().try_into().unwrap(),
                value_u32(self.map(), IN_OUTPUT_INDEX).unwrap(),
            ),
        }
    }

    pub fn non_witness_utxo(&self) -> Option<Transaction> {
        self.value(IN_NON_WITNESS_UTXO).map(|v| decode_exact(v, |r| read_tx(r, true)).unwrap())
    }

    pub fn witness_utxo(&self) -> Option<TxOut> {
        self.value(IN_WITNESS_UTXO).map(|v| decode_exact(v, read_txout).unwrap())
    }

    /// The output this input spends, from whichever UTXO field is present.
    pub fn spent_output(&self) -> Option<TxOut> {
        let (_, vout) = self.prevout();
        match self.non_witness_utxo() {
            Some(tx) => tx.outputs.get(vout as usize).cloned(),
            None => self.witness_utxo(),
        }
    }
}

#[derive(Clone)]
pub struct OutputContext {
    pub psbt: PsbtContext,
    pub index: usize,
}

impl OutputContext {
    pub fn map(&self) -> &Map {
        self.psbt.output_map(self.index)
    }

    pub fn version(&self) -> u32 {
        self.psbt.version
    }

    pub fn value(&self, key_type: u64) -> Option<&[u8]> {
        value(self.map(), key_type)
    }
}

/// BIP-370 lock time determination. `None` when the inputs' required lock
/// times share no lock time type.
pub fn determine_locktime(ctx: &PsbtContext) -> Option<u32> {
    let inputs = ctx.inputs();
    let required = |i: &InputContext| {
        (value_u32(i.map(), IN_REQUIRED_TIME_LOCKTIME), value_u32(i.map(), IN_REQUIRED_HEIGHT_LOCKTIME))
    };
    let constrained: Vec<_> =
        inputs.iter().map(required).filter(|(t, h)| t.is_some() || h.is_some()).collect();
    if constrained.is_empty() {
        return Some(value_u32(ctx.psbt.global(), GLOBAL_FALLBACK_LOCKTIME).unwrap_or(0));
    }
    // Height wins a tie, so it is tried first.
    if constrained.iter().all(|(_, h)| h.is_some()) {
        return constrained.iter().filter_map(|(_, h)| *h).max();
    }
    if constrained.iter().all(|(t, _)| t.is_some()) {
        return constrained.iter().filter_map(|(t, _)| *t).max();
    }
    None
}

/// The PSBT's unique identifier: the unsigned transaction's txid (v0), or the
/// BIP-370 txid of the transaction built with every sequence set to 0 (v2).
/// From BIP-375, an output with PSBT_OUT_SP_V0_INFO uses a 0x00 version byte
/// followed by that field as its script, whether or not PSBT_OUT_SCRIPT is set.
pub fn unique_id(ctx: &PsbtContext) -> [u8; 32] {
    if let Some(tx) = &ctx.unsigned_tx {
        return tx.txid();
    }
    let global = ctx.psbt.global();
    let inputs = ctx.inputs().into_iter().map(|i| {
        let (txid, vout) = i.prevout();
        TxIn { txid, vout, script_sig: Vec::new(), sequence: 0, witness: Vec::new() }
    });
    let sp = ctx.psbt.bips.contains(&Bip::Bip375);
    let outputs = ctx.outputs().into_iter().map(|o| TxOut {
        amount: i64::from_le_bytes(o.value(OUT_AMOUNT).unwrap().try_into().unwrap()),
        script_pubkey: match o.value(OUT_SP_V0_INFO).filter(|_| sp) {
            Some(info) => [&[0x00], info].concat(),
            None => o.value(OUT_SCRIPT).unwrap().to_vec(),
        },
    });
    Transaction {
        version: value_u32(global, GLOBAL_TX_VERSION).unwrap(),
        inputs: inputs.collect(),
        outputs: outputs.collect(),
        locktime: determine_locktime(ctx).unwrap(),
    }
    .txid()
}

/// A role's transition: the PSBTs it was given and the PSBT it produced, each
/// of which the validity rules accept.
pub struct TransitionContext {
    pub before: Vec<PsbtContext>,
    pub after: PsbtContext,
}

impl TransitionContext {
    /// Every PSBT in the transition, the produced one last.
    pub fn psbts(&self) -> impl Iterator<Item = &PsbtContext> {
        self.before.iter().chain(std::iter::once(&self.after))
    }
}
