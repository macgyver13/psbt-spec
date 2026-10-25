#!/usr/bin/env python3
"""Generates vectors/bip376.json. BIP-376 publishes no test vectors yet.

Usage: PYTHONPATH=<secp256k1lab>/src python3 gen_bip376.py > ../bip376.json

Each vector is a PSBT with one input spending a silent payment P2TR output and
one P2WPKH output. Keys are fixed, so the output is deterministic.
"""

import base64
import hashlib
import json
import struct

from secp256k1lab.secp256k1 import G, GE, Scalar


def compact(n):
    assert n < 0xfd
    return bytes([n])


def record(key_type, key_data, value):
    key = compact(key_type) + key_data
    return compact(len(key)) + key + compact(len(value)) + value


def map_bytes(records):
    return b"".join(records) + b"\x00"


def txout(amount, script):
    return struct.pack("<q", amount) + compact(len(script)) + script


def witness(items):
    return compact(len(items)) + b"".join(compact(len(i)) + i for i in items)


PREV_TXID = hashlib.sha256(b"bip376 prev").digest()
CHANGE_SCRIPT = b"\x00\x14" + hashlib.sha256(b"bip376 change").digest()[:20]
ORIGIN = bytes.fromhex("deadbeef") + struct.pack("<III", 352 | 0x80000000, 0x80000000, 0x80000000)


def keys(spend_seed, tweak_seed, want_odd_y):
    """A spend key B and tweak t whose tweaked key B + t·G has the requested y parity."""
    b = Scalar.from_bytes_wrapping(hashlib.sha256(spend_seed).digest())
    for i in range(256):
        t = Scalar.from_bytes_wrapping(hashlib.sha256(tweak_seed + bytes([i])).digest())
        q = (b + t) * G
        if q.has_even_y() != want_odd_y:
            return (b * G).to_bytes_compressed(), t.to_bytes(), q.to_bytes_xonly()
    raise AssertionError("no tweak found")


def v2_psbt(inputs_records):
    glob = [
        record(0x02, b"", struct.pack("<I", 2)),
        record(0x04, b"", compact(1)),
        record(0x05, b"", compact(1)),
        record(0xFB, b"", struct.pack("<I", 2)),
    ]
    out = [record(0x03, b"", struct.pack("<q", 90_000)), record(0x04, b"", CHANGE_SCRIPT)]
    base = [record(0x0E, b"", PREV_TXID), record(0x0F, b"", struct.pack("<I", 0))]
    return b"psbt\xff" + map_bytes(glob) + map_bytes(base + inputs_records) + map_bytes(out)


def v0_psbt(inputs_records):
    tx = (struct.pack("<I", 2) + compact(1) + PREV_TXID + struct.pack("<I", 0) + compact(0)
          + struct.pack("<I", 0xFFFFFFFD) + compact(1) + txout(90_000, CHANGE_SCRIPT) + struct.pack("<I", 0))
    return b"psbt\xff" + map_bytes([record(0x00, b"", tx)]) + map_bytes(inputs_records) + map_bytes([])


def main():
    spend_key, tweak, output_key = keys(b"bip376 spend", b"bip376 tweak", want_odd_y=False)
    odd_spend, odd_tweak, odd_output = keys(b"bip376 spend odd", b"bip376 tweak odd", want_odd_y=True)
    p2tr = lambda xonly: b"\x51\x20" + xonly
    utxo = record(0x01, b"", txout(100_000, p2tr(output_key)))
    deriv = record(0x1F, spend_key, ORIGIN)
    tw = record(0x20, b"", tweak)
    sig = bytes(range(64))
    wrong_tweak = (Scalar.from_bytes_checked(tweak) + 1).to_bytes()

    cases = [
        ("Tweak and spend key derivation that match the P2TR output key", v2_psbt([utxo, deriv, tw]), None),
        ("Tweaked spend key with an odd y-coordinate, matched on x only",
         v2_psbt([record(0x01, b"", txout(100_000, p2tr(odd_output))), record(0x1F, odd_spend, ORIGIN),
                  record(0x20, b"", odd_tweak)]), None),
        ("Tweak without a spend key derivation", v2_psbt([utxo, tw]), None),
        ("Spend key derivation with a zero fingerprint and no path",
         v2_psbt([utxo, record(0x1F, spend_key, bytes(4)), tw]), None),
        ("Signed input with a tap key signature, not yet finalized",
         v2_psbt([utxo, deriv, tw, record(0x13, b"", sig)]), None),
        ("Finalized input with the spending fields removed",
         v2_psbt([utxo, record(0x08, b"", witness([sig]))]), None),
        ("Finalized input that keeps PSBT_IN_SP_TWEAK",
         v2_psbt([utxo, tw, record(0x08, b"", witness([sig]))]), "R01"),
        ("Finalized input that keeps PSBT_IN_SP_SPEND_BIP32_DERIVATION",
         v2_psbt([utxo, deriv, record(0x08, b"", witness([sig]))]), "R01"),
        ("Spend key derivation without a tweak", v2_psbt([utxo, deriv]), "R02"),
        ("Tweak without a witness UTXO", v2_psbt([tw]), "R03"),
        ("Tweak on an input whose witness UTXO is P2WPKH",
         v2_psbt([record(0x01, b"", txout(100_000, CHANGE_SCRIPT)), tw]), "R03"),
        ("Tweak that does not produce the output key",
         v2_psbt([utxo, deriv, record(0x20, b"", wrong_tweak)]), "R04"),
        ("Spend key that does not produce the output key",
         v2_psbt([utxo, record(0x1F, odd_spend, ORIGIN), tw]), "R04"),
        ("Tweak of 31 bytes", v2_psbt([utxo, record(0x20, b"", tweak[:31])]), "I01"),
        ("Spend key derivation with a 32-byte x-only key", v2_psbt([utxo, record(0x1F, spend_key[1:], ORIGIN), tw]), "I01"),
        ("Spend key derivation with an uncompressed key",
         v2_psbt([utxo, record(0x1F, GE.from_bytes_compressed(spend_key).to_bytes_uncompressed(), ORIGIN), tw]), "I01"),
        ("Spend key derivation with a partial path element", v2_psbt([utxo, record(0x1F, spend_key, ORIGIN[:6]), tw]), "I01"),
        ("PSBTv0 with PSBT_IN_SP_TWEAK", v0_psbt([utxo, tw]), "I02"),
        ("PSBTv0 with PSBT_IN_SP_SPEND_BIP32_DERIVATION", v0_psbt([utxo, deriv, tw]), "I02"),
    ]
    vectors = [{"description": d, "psbt": base64.b64encode(p).decode(), "error": e} for d, p, e in cases]
    print(json.dumps(vectors, indent=2))


if __name__ == "__main__":
    main()
