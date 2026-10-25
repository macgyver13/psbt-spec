#!/usr/bin/env python3
"""Generates vectors/roles.json: vectors for the Signer snapshot rules (T02 to
T04, P15), the Input Finalizer rules (N01, N02), the Transaction Extractor
rules (X01, X02), and the Combiner transition rules (C01 to C03).

Usage: PYTHONPATH=<secp256k1lab>/src python3 gen_roles.py <bips repo> > ../roles.json

Each vector names the check it runs ("validity", "finalizing", "extraction" or
"combining"), the BIPs the validator enables, and the rule it must fail at (or
null). A "combining" vector also lists the PSBTs combined under "combine", and
"psbt" is the PSBT the Combiner produced. Vectors built from BIP-375's
workflows also give the produced PSBT's "unique_id", as the reference
computes it, in the txid's display byte order. Signatures are placeholders: no rule
here verifies them, only their sighash types. The v0 vectors come from
BIP-174's signer, combiner and input finalizer test vectors.
"""

import base64
import hashlib
import json
import re
import struct
import sys

from secp256k1lab.secp256k1 import G, Scalar


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


def hash160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def pubkey(seed):
    return (Scalar.from_bytes_wrapping(hashlib.sha256(seed).digest()) * G).to_bytes_compressed()


KEY = pubkey(b"roles input")
P2WPKH = b"\x00\x14" + hash160(KEY)
P2TR = b"\x51\x20" + pubkey(b"roles taproot")[1:]
P2WSH = b"\x00\x20" + hashlib.sha256(b"\x51").digest()  # witness script OP_TRUE
DEST = b"\x00\x14" + hash160(pubkey(b"roles dest"))
SP_INFO = pubkey(b"roles scan") + pubkey(b"roles spend")


def ecdsa_sig(sighash):
    """A placeholder DER-shaped signature with the given sighash byte."""
    return bytes.fromhex("3044") + b"\x02\x20" + bytes(range(1, 33)) + b"\x02\x20" + bytes(range(33, 65)) + bytes([sighash])


def psbt_v2(inputs, outputs, flags=None):
    glob = [
        record(0x02, b"", struct.pack("<I", 2)),
        record(0x04, b"", compact(1)),
        record(0x05, b"", compact(len(outputs))),
        record(0xFB, b"", struct.pack("<I", 2)),
    ]
    if flags is not None:
        glob.append(record(0x06, b"", bytes([flags])))
    base = [record(0x0E, b"", hashlib.sha256(b"roles prev").digest()), record(0x0F, b"", struct.pack("<I", 0))]
    return b"psbt\xff" + map_bytes(glob) + map_bytes(base + inputs) + b"".join(map_bytes(o) for o in outputs)


def utxo(script):
    return record(0x01, b"", txout(100_000, script))


def partial_sig(sighash):
    return record(0x02, KEY, ecdsa_sig(sighash))


OUT = [record(0x03, b"", struct.pack("<q", 90_000)), record(0x04, b"", DEST)]
SP_OUT = [record(0x03, b"", struct.pack("<q", 90_000)), record(0x09, b"", SP_INFO)]


def bip174_vector(bips_repo, heading, n=0):
    """The n-th Base64 PSBT after `heading` in BIP-174."""
    text = open(f"{bips_repo}/bip-0174.mediawiki").read()
    section = text[text.index(heading):]
    return base64.b64decode(re.findall(r"Base64 String: <pre>(.*?)</pre>", section)[n])


def bip375_workflow_combines(bips_repo):
    """Each BIP-375 workflow's Updater PSBT, whose silent payment outputs have
    no PSBT_OUT_SCRIPT yet, combined with its Signer PSBT, which has them."""
    steps = json.load(open(f"{bips_repo}/bip-0375/bip375_test_vectors.json"))["workflows"]
    vectors = []
    for update in (s for s in steps if s["supplementary"]["task"] == "update"):
        workflow = update["description"].split(":")[0]
        sign = next(s for s in steps if s["supplementary"]["task"] == "sign" and s["description"].startswith(workflow))
        psbts = [update["expected"]["psbt"], sign["expected"]["psbt"]]
        for bips, error in (([375], None), ([], "O02")):
            vectors.append({
                "description": f"BIP-375 {workflow}: Updater and Signer PSBTs" + ("" if bips else ", BIP-375 not enabled"),
                "check": "combining", "bips": bips, "combine": psbts, "psbt": psbts[1], "error": error,
                "unique_id": sign["expected"]["transaction_id"] if bips else None,
            })
    return vectors


def main():
    bips_repo = sys.argv[1]
    finalized = [utxo(P2WPKH), record(0x08, b"", witness([ecdsa_sig(0x01), KEY]))]
    sighash_type = lambda t: record(0x03, b"", struct.pack("<I", t))
    tweak = record(0x20, b"", hashlib.sha256(b"roles tweak").digest())
    sequence = lambda n: record(0x10, b"", struct.pack("<I", n))
    signer1 = bip174_vector(bips_repo, "a signer that supports SIGHASH_ALL for P2PKH")
    signer2 = bip174_vector(bips_repo, "Given the above updated PSBT, a signer with the following keys")
    combined = bip174_vector(bips_repo, "Given both of the above PSBTs, a combiner must create this PSBT")
    unknown1 = bip174_vector(bips_repo, "Given these two PSBTs with unknown key-value pairs", 0)
    unknown2 = bip174_vector(bips_repo, "Given these two PSBTs with unknown key-value pairs", 1)
    unknown_combined = bip174_vector(bips_repo, "A combiner which orders keys lexicographically")
    sighash1 = bip174_vector(bips_repo, "Given these two PSBTs:", 0)
    sighash2 = bip174_vector(bips_repo, "Given these two PSBTs:", 1)
    sighash_combined = bip174_vector(bips_repo, "Given these two PSBTs:", 2)
    cases = [
        # BIP-370 Signer: PSBT_GLOBAL_TX_MODIFIABLE agrees with the signatures present.
        ("SIGHASH_ALL signature without PSBT_GLOBAL_TX_MODIFIABLE", "validity", [],
         psbt_v2([utxo(P2WPKH), partial_sig(0x01)], [OUT]), None),
        ("SIGHASH_ALL signature with every flag cleared", "validity", [],
         psbt_v2([utxo(P2WPKH), partial_sig(0x01)], [OUT], flags=0x00), None),
        ("SIGHASH_ALL|ANYONECANPAY signature with Inputs Modifiable set", "validity", [],
         psbt_v2([utxo(P2WPKH), partial_sig(0x81)], [OUT], flags=0x01), None),
        ("SIGHASH_NONE signature with Outputs Modifiable set", "validity", [],
         psbt_v2([utxo(P2WPKH), partial_sig(0x02)], [OUT], flags=0x02), None),
        ("SIGHASH_SINGLE signature with Has SIGHASH_SINGLE set", "validity", [],
         psbt_v2([utxo(P2WPKH), partial_sig(0x03)], [OUT], flags=0x04), None),
        ("No signatures with every flag set", "validity", [],
         psbt_v2([utxo(P2WPKH)], [OUT], flags=0x07), None),
        ("SIGHASH_ALL signature with Inputs Modifiable set", "validity", [],
         psbt_v2([utxo(P2WPKH), partial_sig(0x01)], [OUT], flags=0x01), "T02"),
        ("SIGHASH_DEFAULT taproot key path signature with Inputs Modifiable set", "validity", [],
         psbt_v2([utxo(P2TR), record(0x13, b"", bytes(64))], [OUT], flags=0x01), "T02"),
        ("Finalized P2WPKH input signed with SIGHASH_ALL with Inputs Modifiable set", "validity", [],
         psbt_v2(finalized, [OUT], flags=0x01), "T02"),
        ("SIGHASH_ALL|ANYONECANPAY signature with Outputs Modifiable set", "validity", [],
         psbt_v2([utxo(P2WPKH), partial_sig(0x81)], [OUT], flags=0x03), "T03"),
        ("SIGHASH_SINGLE|ANYONECANPAY signature with Has SIGHASH_SINGLE clear", "validity", [],
         psbt_v2([utxo(P2WPKH), partial_sig(0x83)], [OUT], flags=0x00), "T04"),
        # BIP-375 Signer: no signature while a silent payment output script is missing.
        ("Silent payment output without a script and no signatures", "validity", [375],
         psbt_v2([utxo(P2WPKH)], [SP_OUT]), None),
        ("Signed input while a silent payment output has no script", "validity", [375],
         psbt_v2([utxo(P2WPKH), partial_sig(0x01)], [SP_OUT]), "P15"),
        ("Signed input while a silent payment output has no script, BIP-375 not enabled", "validity", [],
         psbt_v2([utxo(P2WPKH), partial_sig(0x01)], [SP_OUT]), "O02"),
        # Transaction Extractor preconditions.
        ("PSBTv2 with a finalized input and an output script", "extraction", [],
         psbt_v2(finalized, [OUT]), None),
        ("PSBTv2 with an input that is signed but not finalized", "extraction", [],
         psbt_v2([utxo(P2WPKH), partial_sig(0x01)], [OUT]), "X01"),
        ("PSBTv2 with an empty PSBT_OUT_SCRIPT", "extraction", [],
         psbt_v2(finalized, [[OUT[0], record(0x04, b"", b"")]]), "X02"),
        ("PSBTv2 with a finalized unsigned input and a silent payment output without a script", "extraction", [375],
         psbt_v2([utxo(P2WSH), record(0x08, b"", witness([b"\x51"]))], [SP_OUT]), "X02"),
        ("BIP-174 input finalizer result", "extraction", [],
         bip174_vector(bips_repo, "Given the above PSBT, an input finalizer must create this PSBT"), None),
        ("BIP-174 combiner result, not finalized", "extraction", [], combined, "X01"),
        # Input Finalizer preconditions.
        ("BIP-174 combiner result, whose signatures use its SIGHASH_ALL sighash types", "finalizing", [], combined, None),
        ("SIGHASH_ALL signature with PSBT_IN_SIGHASH_TYPE SIGHASH_ALL", "finalizing", [],
         psbt_v2([utxo(P2WPKH), sighash_type(0x01), partial_sig(0x01)], [OUT]), None),
        ("SIGHASH_SINGLE signature without PSBT_IN_SIGHASH_TYPE", "finalizing", [],
         psbt_v2([utxo(P2WPKH), partial_sig(0x03)], [OUT]), None),
        ("64-byte taproot key path signature with PSBT_IN_SIGHASH_TYPE SIGHASH_DEFAULT", "finalizing", [],
         psbt_v2([utxo(P2TR), sighash_type(0x00), record(0x13, b"", bytes(64))], [OUT]), None),
        ("65-byte taproot key path signature with PSBT_IN_SIGHASH_TYPE SIGHASH_ALL", "finalizing", [],
         psbt_v2([utxo(P2TR), sighash_type(0x01), record(0x13, b"", bytes(64) + b"\x01")], [OUT]), None),
        ("SIGHASH_ALL signature with PSBT_IN_SIGHASH_TYPE SIGHASH_ALL|ANYONECANPAY", "finalizing", [],
         psbt_v2([utxo(P2WPKH), sighash_type(0x81), partial_sig(0x01)], [OUT]), "N01"),
        ("64-byte taproot key path signature with PSBT_IN_SIGHASH_TYPE SIGHASH_ALL", "finalizing", [],
         psbt_v2([utxo(P2TR), sighash_type(0x01), record(0x13, b"", bytes(64))], [OUT]), "N01"),
        ("Final witness signed with SIGHASH_NONE while PSBT_IN_SIGHASH_TYPE is SIGHASH_ALL", "finalizing", [],
         psbt_v2([utxo(P2WPKH), sighash_type(0x01), record(0x08, b"", witness([ecdsa_sig(0x02), KEY]))], [OUT]), "N01"),
        ("Silent payment tweak with a taproot key path signature", "finalizing", [376],
         psbt_v2([utxo(P2TR), tweak, record(0x13, b"", bytes(64))], [OUT]), None),
        ("Silent payment tweak without a taproot key path signature", "finalizing", [376],
         psbt_v2([utxo(P2TR), tweak], [OUT]), "N02"),
        ("Silent payment tweak without a taproot key path signature, BIP-376 not enabled", "finalizing", [],
         psbt_v2([utxo(P2TR), tweak], [OUT]), None),
    ]
    vectors = [
        {"description": d, "check": c, "bips": b, "psbt": base64.b64encode(p).decode(), "error": e}
        for d, c, b, p, e in cases
    ]
    # Combiner transitions: the PSBTs combined, then the PSBT produced.
    v2_seq = lambda n: psbt_v2([utxo(P2WPKH), sequence(n)], [OUT])
    combines = [
        ("BIP-174 combiner test vector", [signer1, signer2], combined, None),
        ("BIP-174 combiner test vector, inputs reversed", [signer2, signer1], combined, None),
        ("BIP-174 unknown key-value pairs combiner test vector", [unknown1, unknown2], unknown_combined, None),
        ("BIP-174 unknown key-value pairs combiner test vector, inputs reversed", [unknown2, unknown1], unknown_combined, None),
        ("BIP-174 PSBT_IN_SIGHASH_TYPE combiner test vector", [sighash1, sighash2], sighash_combined, None),
        ("A single PSBT combined into itself", [signer1], signer1, None),
        ("PSBTv2s whose PSBT_IN_SEQUENCE conflicts, combined to one of the sequences", [v2_seq(1), v2_seq(2)], v2_seq(2), None),
        ("PSBTs for different transactions", [signer1, unknown1], combined, "C01"),
        ("PSBTv2s with different required lock times", [v2_seq(1), psbt_v2([utxo(P2WPKH), record(0x12, b"", struct.pack("<I", 100))], [OUT])],
         v2_seq(1), "C01"),
        ("Combined PSBT drops the second signer's partial signatures", [signer1, signer2], signer1, "C02"),
        ("Combined PSBT adds partial signatures neither PSBT holds", [signer1, signer1], combined, "C03"),
        ("PSBTv2s whose PSBT_IN_SEQUENCE conflicts, combined to a third sequence", [v2_seq(1), v2_seq(2)], v2_seq(3), "C03"),
    ]
    vectors += [
        {"description": d, "check": "combining", "bips": [], "combine": [base64.b64encode(p).decode() for p in ps],
         "psbt": base64.b64encode(r).decode(), "error": e}
        for d, ps, r, e in combines
    ]
    vectors += bip375_workflow_combines(bips_repo)
    print(json.dumps(vectors, indent=2))


if __name__ == "__main__":
    main()
