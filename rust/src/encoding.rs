//! Byte-level decoding: PSBT key-value maps and Bitcoin transactions.

use bitcoin_hashes::{hash160, sha256, sha256d, Hash};

use crate::algebra::Bip;

pub const MAGIC: [u8; 5] = *b"psbt\xff";

pub struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, pos: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.pos == self.bytes.len()
    }

    pub fn peek(&self, offset: usize) -> Option<u8> {
        self.bytes.get(self.pos + offset).copied()
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.bytes.len() - self.pos < n {
            return Err(format!("needs {n} bytes, {} remain", self.bytes.len() - self.pos));
        }
        self.pos += n;
        Ok(&self.bytes[self.pos - n..self.pos])
    }

    pub fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn i64(&mut self) -> Result<i64, String> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    /// Reads a compact size unsigned integer, rejecting non-minimal encodings.
    pub fn compact_size(&mut self) -> Result<u64, String> {
        let (value, min) = match self.u8()? {
            0xfd => (u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as u64, 0xfd),
            0xfe => (u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as u64, 0x1_0000),
            0xff => (u64::from_le_bytes(self.take(8)?.try_into().unwrap()), 0x1_0000_0000),
            n => return Ok(n as u64),
        };
        if value < min {
            return Err(format!("compact size {value} is not minimally encoded"));
        }
        Ok(value)
    }

    pub fn var_bytes(&mut self) -> Result<&'a [u8], String> {
        let n = self.compact_size()?;
        self.take(usize::try_from(n).map_err(|_| "length overflows".to_string())?)
    }

    pub fn finish(&self) -> Result<(), String> {
        if !self.is_empty() {
            return Err(format!("{} trailing bytes", self.bytes.len() - self.pos));
        }
        Ok(())
    }
}

/// Decodes `bytes` with `f` and requires that it consume all of them.
pub fn decode_exact<T>(bytes: &[u8], f: impl FnOnce(&mut Reader) -> Result<T, String>) -> Result<T, String> {
    let mut r = Reader::new(bytes);
    let value = f(&mut r)?;
    r.finish()?;
    Ok(value)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub key_type: u64,
    pub key_data: Vec<u8>,
    pub value: Vec<u8>,
}

pub type Map = Vec<Record>;

/// A PSBT split into its maps: the global map first, then every per-input and
/// per-output map in serialization order.
#[derive(Debug, Clone)]
pub struct Psbt {
    pub maps: Vec<Map>,
    /// The BIPs the validator enables, which decide the fields it knows.
    pub bips: Vec<Bip>,
}

pub enum ScanError {
    Magic,
    Record(String),
    Unterminated,
}

fn read_record(r: &mut Reader) -> Result<Option<Record>, String> {
    let key = r.var_bytes()?;
    if key.is_empty() {
        return Ok(None);
    }
    let mut kr = Reader::new(key);
    let key_type = kr.compact_size().map_err(|e| format!("key type: {e}"))?;
    let key_data = kr.take(key.len() - kr.pos)?.to_vec();
    let value = r.var_bytes().map_err(|e| format!("value: {e}"))?.to_vec();
    Ok(Some(Record { key_type, key_data, value }))
}

/// Splits a serialized PSBT into maps. Each map ends at a 0x00 separator.
pub fn scan(bytes: &[u8]) -> Result<Psbt, ScanError> {
    if !bytes.starts_with(&MAGIC) {
        return Err(ScanError::Magic);
    }
    let mut r = Reader::new(&bytes[MAGIC.len()..]);
    let mut maps = Vec::new();
    let mut map = Map::new();
    while !r.is_empty() {
        match read_record(&mut r).map_err(ScanError::Record)? {
            Some(record) => map.push(record),
            None => maps.push(std::mem::take(&mut map)),
        }
    }
    if maps.is_empty() || !map.is_empty() {
        return Err(ScanError::Unterminated);
    }
    Ok(Psbt { maps, bips: Vec::new() })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    /// Previous txid in internal (little-endian) byte order.
    pub txid: [u8; 32],
    pub vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    pub amount: i64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub locktime: u32,
}

pub fn read_txout(r: &mut Reader) -> Result<TxOut, String> {
    Ok(TxOut { amount: r.i64()?, script_pubkey: r.var_bytes()?.to_vec() })
}

pub fn read_witness(r: &mut Reader) -> Result<Vec<Vec<u8>>, String> {
    (0..r.compact_size()?).map(|_| Ok(r.var_bytes()?.to_vec())).collect()
}

/// Reads a transaction. With `allow_witness`, the BIP-144 serialization is
/// accepted when the marker byte is followed by a non-zero flag.
pub fn read_tx(r: &mut Reader, allow_witness: bool) -> Result<Transaction, String> {
    let version = r.u32()?;
    let segwit = allow_witness && r.peek(0) == Some(0) && r.peek(1).is_some_and(|f| f != 0);
    if segwit {
        r.take(1)?;
        if r.u8()? != 1 {
            return Err("unknown witness flag".into());
        }
    }
    let mut inputs = (0..r.compact_size()?)
        .map(|_| {
            Ok(TxIn {
                txid: r.take(32)?.try_into().unwrap(),
                vout: r.u32()?,
                script_sig: r.var_bytes()?.to_vec(),
                sequence: r.u32()?,
                witness: Vec::new(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let outputs = (0..r.compact_size()?).map(|_| read_txout(r)).collect::<Result<Vec<_>, _>>()?;
    if segwit {
        for input in &mut inputs {
            input.witness = read_witness(r)?;
        }
    }
    Ok(Transaction { version, inputs, outputs, locktime: r.u32()? })
}

pub fn put_compact_size(out: &mut Vec<u8>, n: usize) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend((n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend((n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend((n as u64).to_le_bytes());
        }
    }
}

impl Transaction {
    /// The non-witness serialization, which the txid commits to.
    pub fn serialize_without_witness(&self) -> Vec<u8> {
        let mut out = self.version.to_le_bytes().to_vec();
        put_compact_size(&mut out, self.inputs.len());
        for i in &self.inputs {
            out.extend(i.txid);
            out.extend(i.vout.to_le_bytes());
            put_compact_size(&mut out, i.script_sig.len());
            out.extend(&i.script_sig);
            out.extend(i.sequence.to_le_bytes());
        }
        put_compact_size(&mut out, self.outputs.len());
        for o in &self.outputs {
            out.extend(o.amount.to_le_bytes());
            put_compact_size(&mut out, o.script_pubkey.len());
            out.extend(&o.script_pubkey);
        }
        out.extend(self.locktime.to_le_bytes());
        out
    }

    /// The txid in internal byte order.
    pub fn txid(&self) -> [u8; 32] {
        sha256d::Hash::hash(&self.serialize_without_witness()).to_byte_array()
    }
}

pub fn p2sh_script(redeem_script: &[u8]) -> Vec<u8> {
    let mut s = vec![0xa9, 0x14];
    s.extend(hash160::Hash::hash(redeem_script).to_byte_array());
    s.push(0x87);
    s
}

pub fn p2wsh_script(witness_script: &[u8]) -> Vec<u8> {
    let mut s = vec![0x00, 0x20];
    s.extend(sha256::Hash::hash(witness_script).to_byte_array());
    s
}

pub fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87
}

/// A BIP-141 witness program: a version opcode followed by one 2 to 40 byte push.
pub fn is_witness_program(script: &[u8]) -> bool {
    (4..=42).contains(&script.len())
        && (script[0] == 0x00 || (0x51..=0x60).contains(&script[0]))
        && script[1] as usize + 2 == script.len()
}
