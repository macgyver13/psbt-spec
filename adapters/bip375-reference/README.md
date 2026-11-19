# bips BIP-375 reference validator adapter

A psbt-spec adapter ([`docs/adapter.md`](../../docs/adapter.md)) for the
reference validator in `bip-0375/` of bitcoin/bips. It wraps
`validate_bip375_psbt` from `bip-0375/test_runner.py` and does not modify the
bips tree. It needs only Python 3 and the tree (the validator vendors its own
dependencies).

It answers the `deserialize` task only, for BIPs 174, 370 and 375, because
the validator checks a PSBT and drives no role. A request without BIP 375
gets `n/a`. It names the rule behind a rejection when the check and message mean exactly
one ("Rules named" below). Details are in the docstring of `adapter.py`.

## Run

Export the bips commit the vectors are pinned to (a checkout works too, and
then `--revision` is optional):

```bash
mkdir /tmp/bips-9c5b825 && git -C ~/src/bips archive 9c5b825e4b bip-0375 | tar -x -C /tmp/bips-9c5b825
```

Evaluate the BIP-375 corpus (from the repository root):

```bash
cargo run --release --manifest-path rust/Cargo.toml --bin psbt-spec -- evaluate --out /tmp/bip375-report --corpus vectors/bip375.json -- python3 adapters/bip375-reference/adapter.py /tmp/bips-9c5b825 --revision 9c5b825e4ba43fab0431fa042ddb00afdf251a95
```

`/tmp/bip375-report/report.json` and `report.md` are the result.

## Rules named

On reject the adapter names the rule from the validator's failing check and message
(`RULES` in `adapter.py`: the first row whose check matches and whose pattern matches
the message). No match names no rule.

| Check | Message pattern | Rule |
|---|---|---|
| `psbt_structure` | `duplicate PSBT key` | GEN-F-4 |
| `psbt_structure` | `bad PSBT magic bytes` | GEN-F-1 |
| `psbt_structure` | `has PSBT_OUT_SP_V0_LABEL but missing PSBT_OUT_SP_V0_INFO` | GEN-SP-1 |
| `psbt_structure`, `input_eligibility` | `wrong length` | GEN-F-5 |
| `ecdh_coverage` | any | GEN-SP-3 |
| `input_eligibility` | `uses segwit version > 1`, `uses non-SIGHASH_ALL`, `has a non-SIGHASH_ALL signature` | GEN-SP-4 |
| `input_eligibility` | `is signed before every silent payment output has PSBT_OUT_SCRIPT` | GEN-SP-7 |
| `input_eligibility` | `flags not cleared` | GEN-SP-2 |
| `output_scripts` | any | GEN-SP-5 |

`ecdh_coverage` is REF-8 itself and `output_scripts` is REF-10 (which includes "has the
ECDH shares and input public keys its derivation needs"), so every message of those
checks is that rule. `input_eligibility` mixes rules, hence the message patterns.
Unnamed: `psbt_structure` "must have either PSBT_OUT_SCRIPT or PSBT_OUT_SP_V0_INFO",
"trailing bytes", "unsupported PSBT version" and the other parse errors.
