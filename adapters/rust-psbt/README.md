# rust-psbt adapter

A psbt-spec adapter ([`docs/adapter.md`](../../docs/adapter.md)) for rust-psbt
(crate `psbt-v2`, built with features `silent-payments`, `miniscript` and
`base64`). It is a small Rust binary that path-depends on the sibling checkout
and calls the crate's public API.

## Build and run

The layout is `~/src/psbt-spec` next to `~/src/rust-psbt`.

```bash
cargo build --release --manifest-path adapters/rust-psbt/Cargo.toml
```

Evaluate (from the repository root; the binary is in `target/release/` of the
adapter, or in `$CARGO_TARGET_DIR/release/` when that is set). `--revision` is
required: the adapter does not read version control, so pass the commit under
evaluation (`jj log -r @ -T commit_id --no-graph`, or `git rev-parse HEAD`).

```bash
cargo build --release --manifest-path rust/Cargo.toml --bin psbt-spec
rust/target/release/psbt-spec evaluate --out audits/rust-psbt --corpus vectors/bip174.json --corpus vectors/bip370.json --corpus vectors/bip371.json --corpus vectors/bip373.json --corpus vectors/bip375.json --corpus vectors/bip376.json --corpus vectors/roles.json -- adapters/rust-psbt/target/release/psbt-spec-adapter-rust-psbt --revision COMMIT
```

To evaluate another checkout, change the `path` of `psbt-v2` in `Cargo.toml`
and rebuild; pass `--project-dir DIR` too if the crate version in the hello
should come from that checkout (default `../../../rust-psbt`). The adapter
reports a dirty working copy only through the revision you pass: say so in the
report if it was dirty.

## What it declares

- BIPs 174, 370, 371, 375. 174 is PSBT v0 and 370 is v2, as in the crate's
  "Supported BIPs" table. 371 is listed there as Full, 375 as Experimental
  (feature `silent-payments`). Not declared: 373 (the table does not list it
  and the MuSig2 map fields are not parsed in this line of the crate) and 376
  (no spending-side support in this checkout). Those vectors are withheld,
  so their rules are NOT IMPLEMENTED.
- Tasks `deserialize`, `sign`, `finalize`, `extract`, `combine`. Not
  declared: `create`, `construct`, `update` (not in contract v1).

## Task mapping

A request with BIP 370 is decoded as v2 (`str::parse::<Psbt>()`), otherwise as
v0 (`PsbtV0::deserialize_base64` then `into_psbt`). A decode failure is a
`reject` for every task. A panic inside the library is a `reject` with reason
`PANIC in the library` (the library has no business panicking on input).

| Task | Library call | accept means |
|---|---|---|
| `deserialize` | decode as above | decoding succeeded |
| `sign` | `Psbt::silent_payment_signer_checks()` (reject on error, or when the state `can_sign()` is false), then `Signer::new` and `SigningSession::signable_inputs()` for every input | the Signer's strict checks pass for every input |
| `finalize` | `Finalizer::new`, `Finalizer::finalize(&Secp256k1::verification_only())` | the library finalized; returned PSBT is re-encoded in the version it was given in |
| `extract` | `Extractor::new`, `Extractor::extract_tx()` | a transaction was extracted |
| `combine` | `Psbt::combine_with` folded over the sources | the sources combined; returned PSBT re-encoded as for `finalize` |

Judgments, in order of how much they decide:

- `deserialize` is decode only. rust-psbt enforces most BIP-375 General rules
  at the Signer (`silent_payment_signer_checks`), not at decode, so those
  rules read LOOSER at `deserialize`. The report cannot say DIFFERENT STAGE;
  `audits/rust-psbt/FINDINGS.md` records, for each such vector, whether the
  Signer check rejects it.
- `sign` has no keys: it asks whether the Signer would accept the PSBT. The
  library has no `would_sign` call, so this composes the two checks the Signer
  itself runs (`SignableInput::check_silent_payments` plus the strict
  per-input checks). `signable_inputs()` is the whole-set check the Signer
  needs for taproot; `signable_input(i)` would refuse every non-ANYONECANPAY
  taproot input.
- `finalize` is all or nothing in the library: one input that cannot be
  finalized rejects the whole PSBT. The contract says "finalized the inputs it
  could"; that cannot be asked of this API.
- `extract` uses the unchecked fee rate variant because a fee rate is not a
  PSBT rule.
- BIP-375 is a compile-time feature and cannot be switched off. A request
  without BIP 375 whose PSBT carries any BIP-375 field is answered `n/a`
  (such a vector asks how a project without BIP-375 treats the field).

## Rules named

A `reject` carries `rule` when the library's error means exactly one psbt-spec rule
([`docs/adapter.md`](../../docs/adapter.md), "Naming the rule"). The mapping is the
`*_rule` functions at the top of `src/main.rs`. Errors not listed name no rule.

| Library error | Rule | Why |
|---|---|---|
| `DeserializeError::InvalidMagic`, `InvalidSeparator` (v0 or v2 decode) | GEN-F-1 | the five-byte header is wrong |
| `SilentPaymentSignerError::TransactionModifiable` | GEN-SP-2 | output scripts set, Inputs or Outputs Modifiable not clear |
| `SilentPaymentSignerError::UnsupportedWitnessVersion`, `NonSighashAll` | GEN-SP-4 | REF-9: no segwit v2+ input, SIGHASH_ALL only |
| `SilentPaymentSignerError::MissingEcdhShare`, `MismatchedShareAndProofKeys` | GEN-SP-3 | REF-8: share coverage, a share has its DLEQ proof |
| `SilentPaymentSignerError::MissingInputPublicKey` | GEN-SP-3 | REF-8: "the input has a public key" for a proof (judgment call 2) |
| `SilentPaymentSignerError::RedeemScriptMismatch`, `SignError::RedeemScriptMismatch` | ROLE-S-2 | the spent output is not P2SH of the redeem script |
| `SignError::NonWitnessUtxoTxidMismatch` | ROLE-S-1 | previous transaction does not hash to the prevout txid |
| `SignError::WitnessScriptMismatchWsh`, `WitnessScriptMismatchShWsh` | ROLE-S-3 | the spent script is not P2WSH of the witness script |
| `SignError::NonWitnessSig` | ROLE-S-4 | a witness UTXO input would get a non-witness signature |
| `SignError::SilentPayment(e)` | as `e` | wraps the signer check error |

`sign` collects one error per input from `signable_inputs`; it names a rule only when
every input's error maps to the same rule, so a mix with an unmapped error names none.

Deliberately unnamed:

- `FundingUtxo(UnverifiableUtxo)`: no psbt-spec rule covers needing the full previous
  transaction.
- "silent payment output scripts are not yet set" (state `Incomplete`, and
  `SignError::SilentPaymentIncomplete`): not GEN-SP-7 (judgment call 1).
- `NoEligibleInputs`: REF-9 has no "an eligible input exists" clause, and REF-8 has one
  only for a global share, while the error is raised whatever shares exist.
- `ExtractError::SilentPaymentOutputScriptNotComputed`: a missing script, where GEN-SP-5
  is about a script that is set and wrong. `PsbtNotFinalized`, fee and lock time errors,
  `SighashMismatch`, finalizer and combine errors: no rule.
- Map decode errors not in the table below.

Judgment calls:

1. "Output scripts not yet set" is not GEN-SP-7. GEN-SP-7 forbids a signature that
   is already present while a script is missing. The library check looks at the scripts
   only, and refuses a PSBT with no signature at all; that is a Signer that cannot yet
   derive scripts, which rust-psbt delegates elsewhere.
2. "has a Silent Payment proof without public-key information" is GEN-SP-3. It is raised
   only when a DLEQ proof is present and no `PSBT_IN_BIP32_DERIVATION` key is committed to
   by the prevout script, which is REF-8's "the input has a public key" clause for a proof.

### Map decode errors

psbt-v2 does not export its global, input and output map error types (`map` is a
private module), so `map_decode_rule` reads the variant from the error's Debug text: the
first variant inside `DecodeGlobal(..)`, or inside `Item(..)` for an input or output map.

| Map error variant | Rule | Why |
|---|---|---|
| `DuplicateKey` | GEN-F-4 | a key repeats within a map |
| `KeyDecode(Bytes)`, `KeyDecode(TypeValue)`, any `LengthPrefix` value error | GEN-F-2 | the record's lengths or key type encoding are broken |
| `KeyDecode(InvalidKeyData)` | GEN-F-5 | key data is wrong for a known key type |
| `KeyDecode(ExcludedKey)`, `MissingVersion`, `MissingTxVersion`, `MissingInputCount`, `MissingOutputCount`, `MissingUnsignedTx`, `MissingPreviousTxid`, `MissingSpentOutputIndex`, `MissingAmount`, `MissingScriptPubkey` | GEN-ST-2 | a field the version forbids, or one it requires is missing |
| `WrongVersion(v)` with v not 0 or 2, `Version` with `UnsupportedVersion` | GEN-ST-1 | the PSBT version is not 0 or 2 |
| `SpFieldMismatch` | GEN-SP-3 | ECDH shares and DLEQ proofs are not both present |
| `Validation(SpLabelWithoutInfo)` | GEN-SP-1 | a label without PSBT_OUT_SP_V0_INFO |
| a value error for a known field (`Version`, `Xpub`, `ModifiableFlags`, `Count`, `TxVersion`, `LockTime`, `UnsignedTx`, keys, txids, scripts, signatures, derivations, Taproot fields, `SpEcdh`, `SpDleq`, `SpTweak`, `SpV0Info`, `SpV0Label`) | GEN-F-5 | the value does not have the registry's format (for `UnsignedTx`, including non-empty scriptSigs) |

Unnamed: `WrongVersion` with 0 or 2 (a decoder for the other version), `EarlyEnd`,
preimages, proprietary and unknown values, `PorCommitment`, `IncorrectNonWitnessUtxo`
(ROLE-S-1 is the Signer's), and the top-level `EarlyEnd` and `Unconsumed`.
