# spdk adapter

A psbt-spec adapter ([`docs/adapter.md`](../../docs/adapter.md)) for spdk's
`psbt` crate: the BIP-375 Signer and Extractor extensions on top of `psbt-v2`.
It is a small Rust binary that path-depends on the sibling checkout
(`../../../spdk/psbt`) and calls the crate's public API.

## Build and run

The layout is `~/src/psbt-spec` next to `~/src/spdk` and `~/src/rust-psbt`.

```bash
cargo build --release --manifest-path adapters/spdk/Cargo.toml
```

`psbt` depends on `psbt-v2` from a git rev, and spdk's checkout ends with a
`[patch]` that points it at `../rust-psbt`. A patch in a dependency's
workspace does not apply to another workspace, so `Cargo.toml` here repeats
it (path `../../../rust-psbt`). To use another psbt-v2, edit that path; to use
the pinned rev, delete the `[patch]` block. Cargo can also override it per
build, without editing: `--config "patch.'https://gitea.bitcoin.ninja/macgyver/rust-psbt.git'.psbt-v2.path='DIR'"`.

Evaluate (from the repository root). `--revision` is the spdk commit under
evaluation; `--psbt-v2-revision` records which psbt-v2 it was built against
(it goes into the report's project version).

```bash
rust/target/release/psbt-spec evaluate --out audits/spdk --corpus vectors/bip174.json --corpus vectors/bip370.json --corpus vectors/bip371.json --corpus vectors/bip373.json --corpus vectors/bip375.json --corpus vectors/bip376.json --corpus vectors/roles.json -- adapters/spdk/target/release/psbt-spec-adapter-spdk --revision COMMIT --psbt-v2-revision COMMIT
```

## What it declares

- BIPs 370 and 375. spdk's `psbt` crate is BIP-375 on PSBT v2; it has no v0
  path and no spending side (BIP-376) in its public API. Vectors that need 174
  or 376 are withheld, so their rules are NOT IMPLEMENTED.
- Tasks `deserialize` and `extract`. Not declared: `sign` (spdk's signing
  entry points, `add_ecdh_shares` and `sign_silent_payment_inputs`, need keys,
  and the only readiness checks are psbt-v2's), `finalize` and `combine`
  (psbt-v2's `Finalizer` and combine, not spdk; its own docs say a combiner is
  not implemented).

## Task mapping

| Task | Library call | accept means |
|---|---|---|
| `deserialize` | `Psbt::deserialize` (psbt-v2), then the Silent Payment checks below | the PSBT decodes and passes them |
| `extract` | `SpExtractorExt::extract_tx` | spdk verified the output scripts and extracted a transaction |

`deserialize` is a judgment. spdk has no decode entry point of its own: its
vector test calls psbt-v2 and treats it as the parse boundary. So this task
composes what spdk's own code can say about a PSBT at rest, and only once
every Silent Payment output has its script (before that a PSBT is a valid work
in progress, as the corpus holds):

- every input finalized: `SpExtractorExt::verify_sp_output_scripts`, the check
  the Extractor runs;
- otherwise `Psbt::silent_payment_signer_checks` (psbt-v2's BIP-375 structure
  checks, which spdk's `commit_sp_outputs` runs first), then
  `SpSignerExt::derive_sp_output_scripts` compared with the scripts set.

So the rules spdk enforces when it derives scripts (ECDH coverage, DLEQ
proofs, derivation) read MATCH, and anything it only checks at a Signer entry
before scripts exist reads LOOSER here. The first version of this adapter ran
the signer checks on every PSBT and rejected 21 valid vectors (finalized
PSBTs, which no longer name the input public keys, and workflow snapshots
with no UTXO yet); that is a property of the composition, not of spdk, which
is why the gating above exists.

As with the rust-psbt adapter, BIP-375 is compiled in: a request without BIP
375 whose PSBT carries a BIP-375 field is answered `n/a`, and a panic is a
`reject` with reason `PANIC in the library`.

## Rules named

A `reject` carries `rule` when the library's error means exactly one psbt-spec rule
([`docs/adapter.md`](../../docs/adapter.md), "Naming the rule"). The mapping is the
`*_rule` functions at the top of `src/main.rs`. Errors not listed name no rule.

| Library error | Rule | Why |
|---|---|---|
| `DeserializeError::InvalidMagic`, `InvalidSeparator` | GEN-F-1 | the five-byte header is wrong |
| psbt-v2 `SilentPaymentSignerError::TransactionModifiable` | GEN-SP-2 | output scripts set, Inputs or Outputs Modifiable not clear |
| `UnsupportedWitnessVersion`, `NonSighashAll` | GEN-SP-4 | REF-9 |
| `MissingEcdhShare`, `MismatchedShareAndProofKeys`, `MissingInputPublicKey` | GEN-SP-3 | REF-8 |
| `RedeemScriptMismatch` | ROLE-S-2 | the spent output is not P2SH of the redeem script |
| `SpSignerError::MissingShare`, `MissingDleqProof` (derivation) | GEN-SP-3 | REF-8: share coverage, a share has its DLEQ proof |
| `SpExtractorError::OutputScriptMismatch`, and the adapter's own "script differs from the derived script" | GEN-SP-5 | the set script is not the BIP-352 script |
| `SpExtractorError::Derive(e)` | as `e` | wraps the derivation error |

Deliberately unnamed:

- `SpSignerError::MissingInputPubkey` (spdk, derivation): spdk raises it while deriving,
  where the missing key is as likely GEN-SP-5's "input public keys its derivation needs"
  (REF-10) as GEN-SP-3's. psbt-v2's check of the same name, in the structure checks,
  is named GEN-SP-3.
- `SpSignerError::SilentPayments(..)` (an invalid DLEQ proof arrives as a string-typed
  `silentpayments::Error`, not a variant), `FundingUtxo`, `NoEligibleInputs`,
  `SpExtractorError::InputPubkey`, `Extractor`, `ExtractTx`.
- Map decode errors not in the table below.

Only rules without `roles` are scored from `deserialize`; a refusal for a rule with
`roles` (GEN-SP-2 to GEN-SP-5) is informational here, since `sign` is not declared.

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
