# PSBT Conformance Specification

Status: Draft. Rule IDs may change until version 1.0.
Revision: 0.1.0

Generated from `rust/src/spec.rs`, like `spec.html` and `rules.json`. A PSBT is well formed if it satisfies the General rules. A role conforms if its rules hold on the PSBT it received and the PSBT it returned. Every role receives a PSBT that satisfies the General rules. Vector numbers count from 0 within each corpus file.

## General rules

### Framing

#### GEN-F-1 (MUST)

A PSBT MUST begin with the five-byte header 70 73 62 74 FF: ASCII psbt followed by the FF separator.

- Coverage: Full
- Vectors: corpus
  - isolates: vectors/bip174.json #0: Network transaction, not PSBT format
  - passes: vectors/bip174.json #20 #21 #22 #23 #24 #25 #26 #27 #28 #29
  - passes: vectors/bip370.json #24 #25 #26 #27 #28 #29 #30 #31 #32 #33 #34 #35 #36 #37
  - passes: vectors/bip371.json #11 #12 #13 #14 #15 #16
  - passes: vectors/bip373.json #0 #1 #2 #3 #4 #5 #6 #7 #8 #9 #10 #11 #12 #13
  - passes: vectors/bip375.json #37 #38 #39 #40 #41 #42 #43 #44 #45 #46 #47 #48 #49 #50 #51 #52 #53 #54 #55 #56 #57 #58 #59 #60 #61 #62 #63 #64 #65 #66 #67 #68 #69 #70 #71 #72 #73 #74 #75 #76 #77 #78 #80 #81 #82 #83 #84 #85 #86 #87 #88 #89 #90 #91 #92 #93
  - passes: vectors/bip376.json #0 #1 #2 #3 #4 #5
  - passes: vectors/roles.json #0 #1 #2 #3 #4 #5 #11
- From: [BIP174 - Specification](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#specification)

#### GEN-F-2 (MUST)

Each key-value record MUST be complete and use its declared lengths; the key type MUST be minimally encoded.

- Coverage: Full
- Vectors: tests only
  - passes: vectors/bip174.json #20 #21 #22 #23 #24 #25 #26 #27 #28 #29
  - passes: vectors/bip370.json #24 #25 #26 #27 #28 #29 #30 #31 #32 #33 #34 #35 #36 #37
  - passes: vectors/bip371.json #11 #12 #13 #14 #15 #16
  - passes: vectors/bip373.json #0 #1 #2 #3 #4 #5 #6 #7 #8 #9 #10 #11 #12 #13
  - passes: vectors/bip375.json #37 #38 #39 #40 #41 #42 #43 #44 #45 #46 #47 #48 #49 #50 #51 #52 #53 #54 #55 #56 #57 #58 #59 #60 #61 #62 #63 #64 #65 #66 #67 #68 #69 #70 #71 #72 #73 #74 #75 #76 #77 #78 #80 #81 #82 #83 #84 #85 #86 #87 #88 #89 #90 #91 #92 #93
  - passes: vectors/bip376.json #0 #1 #2 #3 #4 #5
  - passes: vectors/roles.json #0 #1 #2 #3 #4 #5 #11
- From: [BIP174 - Specification](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#specification)
- Note: The linked parser also requires minimally encoded outer CompactSize lengths.

#### GEN-F-3 (MUST)

A PSBT MUST contain a global map, and each map MUST end with 00.

- Coverage: Full
- Vectors: tests only
  - passes: vectors/bip174.json #20 #21 #22 #23 #24 #25 #26 #27 #28 #29
  - passes: vectors/bip370.json #24 #25 #26 #27 #28 #29 #30 #31 #32 #33 #34 #35 #36 #37
  - passes: vectors/bip371.json #11 #12 #13 #14 #15 #16
  - passes: vectors/bip373.json #0 #1 #2 #3 #4 #5 #6 #7 #8 #9 #10 #11 #12 #13
  - passes: vectors/bip375.json #37 #38 #39 #40 #41 #42 #43 #44 #45 #46 #47 #48 #49 #50 #51 #52 #53 #54 #55 #56 #57 #58 #59 #60 #61 #62 #63 #64 #65 #66 #67 #68 #69 #70 #71 #72 #73 #74 #75 #76 #77 #78 #80 #81 #82 #83 #84 #85 #86 #87 #88 #89 #90 #91 #92 #93
  - passes: vectors/bip376.json #0 #1 #2 #3 #4 #5
  - passes: vectors/roles.json #0 #1 #2 #3 #4 #5 #11
- From: [BIP174 - Specification](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#specification)

#### GEN-F-4 (MUST)

Keys MUST be unique within each map.

- Coverage: Full
- Vectors: corpus
  - isolates: vectors/bip174.json #4: PSBT with duplicate keys in an input
  - passes: vectors/bip174.json #20 #21 #22 #23 #24 #25 #26 #27 #28 #29
  - passes: vectors/bip370.json #24 #25 #26 #27 #28 #29 #30 #31 #32 #33 #34 #35 #36 #37
  - passes: vectors/bip371.json #11 #12 #13 #14 #15 #16
  - passes: vectors/bip373.json #0 #1 #2 #3 #4 #5 #6 #7 #8 #9 #10 #11 #12 #13
  - passes: vectors/bip375.json #37 #38 #39 #40 #41 #42 #43 #44 #45 #46 #47 #48 #49 #50 #51 #52 #53 #54 #55 #56 #57 #58 #59 #60 #61 #62 #63 #64 #65 #66 #67 #68 #69 #70 #71 #72 #73 #74 #75 #76 #77 #78 #80 #81 #82 #83 #84 #85 #86 #87 #88 #89 #90 #91 #92 #93
  - passes: vectors/bip376.json #0 #1 #2 #3 #4 #5
  - passes: vectors/roles.json #0 #1 #2 #3 #4 #5 #11
- From: [BIP174 - Handling Duplicated Keys](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#handling-duplicated-keys)

#### GEN-F-5 (MUST)

Every present known field MUST conform to the key-data and value format the field registry gives it.

- Coverage: Full
- Vectors: corpus
  - isolates: vectors/bip174.json #2: PSBT where one input has a filled scriptSig in the unsigned tx
  - isolates: vectors/bip174.json #5: PSBT with invalid global transaction typed key
  - isolates: vectors/bip174.json #6: PSBT with invalid input witness utxo typed key
  - isolates: vectors/bip174.json #7: PSBT with invalid pubkey length for input partial signature typed key
  - isolates: vectors/bip174.json #8: PSBT with invalid redeemscript typed key
  - isolates: vectors/bip174.json #9: PSBT with invalid witnessscript typed key
  - isolates: vectors/bip174.json #10: PSBT with invalid pubkey in input BIP 32 derivation paths typed key
  - isolates: vectors/bip174.json #11: PSBT with invalid non-witness utxo typed key
  - isolates: vectors/bip174.json #12: PSBT with invalid final scriptsig typed key
  - isolates: vectors/bip174.json #13: PSBT with invalid final script witness typed key
  - isolates: vectors/bip174.json #14: PSBT with invalid pubkey in output BIP 32 derivation paths typed key
  - isolates: vectors/bip174.json #16: PSBT with invalid output redeemScript typed key
  - isolates: vectors/bip174.json #17: PSBT with invalid output witnessScript typed key
  - isolates: vectors/bip174.json #18: PSBT with unsigned tx serialized with witness serialization format
  - isolates: vectors/bip174.json #19: PSBT with an invalid value data due to its size being not the stated size
  - isolates: vectors/bip370.json #21: PSBTv2 with PSBT_IN_REQUIRED_TIME_LOCKTIME less than 500000000.
  - isolates: vectors/bip370.json #22: PSBTv2 with PSBT_IN_REQUIRED_HEIGHT_LOCKTIME greater than or equal to 500000000.
  - isolates: vectors/bip370.json #23: PSBTv2 with PSBT_IN_REQUIRED_HEIGHT_LOCKTIME of 0.
  - isolates: vectors/bip371.json #0: PSBT With PSBT_IN_TAP_INTERNAL_KEY key that is too long (incorrectly serialized as compressed DER)
  - isolates: vectors/bip371.json #1: PSBT With PSBT_IN_TAP_KEY_SIG signature that is too short
  - isolates: vectors/bip371.json #2: PSBT With PSBT_IN_TAP_KEY_SIG signature that is too long
  - isolates: vectors/bip371.json #3: PSBT With PSBT_IN_TAP_BIP32_DERIVATION key that is too long (incorrectly serialized as compressed DER)
  - isolates: vectors/bip371.json #4: PSBT With PSBT_OUT_TAP_INTERNAL_KEY key that is too long (incorrectly serialized as compressed DER)
  - isolates: vectors/bip371.json #5: PSBT With PSBT_OUT_TAP_BIP32_DERIVATION key that is too long (incorrectly serialized as compressed DER)
  - isolates: vectors/bip371.json #6: PSBT With PSBT_IN_TAP_SCRIPT_SIG key that is too long (incorrectly serialized as compressed DER)
  - isolates: vectors/bip371.json #7: PSBT With PSBT_IN_TAP_SCRIPT_SIG signature that is too long
  - isolates: vectors/bip371.json #8: PSBT With PSBT_IN_TAP_SCRIPT_SIG signature that is too short
  - isolates: vectors/bip371.json #9: PSBT With PSBT_IN_TAP_LEAF_SCRIPT Control block that is too long
  - isolates: vectors/bip371.json #10: PSBT With PSBT_IN_TAP_LEAF_SCRIPT Control block that is too short
  - isolates: vectors/bip373.json #14: PSBT with x-only aggregate pubkey in input participant pubkeys keydata
  - isolates: vectors/bip373.json #15: PSBT with an x-only input participant pubkey
  - isolates: vectors/bip373.json #16: PSBT with x-only aggregate pubkey in output participant pubkeys keydata
  - isolates: vectors/bip373.json #17: PSBT with an x-only output participant pubkey
  - isolates: vectors/bip373.json #18: PSBT with x-only aggregate pubkey in public nonce keydata
  - isolates: vectors/bip373.json #19: PSBT with an x-only participant pubkey in public nonce keydata
  - isolates: vectors/bip373.json #20: PSBT with invalid public nonce valuedata length
  - isolates: vectors/bip373.json #21: PSBT with x-only aggregate pubkey in partial sig keydata
  - isolates: vectors/bip373.json #22: PSBT with an x-only participant pubkey in partial sig keydata
  - isolates: vectors/bip373.json #23: PSBT with invalid partial sig valuedata length
  - isolates: vectors/bip375.json #1: psbt structure: incorrect byte length for PSBT_OUT_SP_V0_LABEL field
  - isolates: vectors/bip375.json #2: psbt structure: incorrect byte length for PSBT_OUT_SP_V0_INFO field
  - isolates: vectors/bip375.json #3: psbt structure: incorrect byte length for PSBT_IN_SP_ECDH_SHARE field
  - isolates: vectors/bip375.json #4: psbt structure: incorrect byte length for PSBT_IN_SP_DLEQ field
  - isolates: vectors/bip376.json #13: Tweak of 31 bytes
  - isolates: vectors/bip376.json #14: Spend key derivation with a 32-byte x-only key
  - isolates: vectors/bip376.json #15: Spend key derivation with an uncompressed key
  - isolates: vectors/bip376.json #16: Spend key derivation with a partial path element
  - passes: vectors/bip174.json #20 #21 #22 #23 #24 #25 #26 #27 #28 #29
  - passes: vectors/bip370.json #24 #25 #26 #27 #28 #29 #30 #31 #32 #33 #34 #35 #36 #37
  - passes: vectors/bip371.json #11 #12 #13 #14 #15 #16
  - passes: vectors/bip373.json #0 #1 #2 #3 #4 #5 #6 #7 #8 #9 #10 #11 #12 #13
  - passes: vectors/bip375.json #37 #38 #39 #40 #41 #42 #43 #44 #45 #46 #47 #48 #49 #50 #51 #52 #53 #54 #55 #56 #57 #58 #59 #60 #61 #62 #63 #64 #65 #66 #67 #68 #69 #70 #71 #72 #73 #74 #75 #76 #77 #78 #80 #81 #82 #83 #84 #85 #86 #87 #88 #89 #90 #91 #92 #93
  - passes: vectors/bip376.json #0 #1 #2 #3 #4 #5
  - passes: vectors/roles.json #0 #1 #2 #3 #4 #5 #11
- From: [BIP174 - Specification](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#specification)
- Note: Bound three times: the global map first, then each input map and each output map once the map count assigns them. The field registry below is the table it enforces, including the unsigned transaction's empty scriptSigs and the required-locktime ranges. It checks structure and the relations the field tables state, not every property a value may need, such as xpub version bytes or ECDSA signature validity.

### Structure

#### GEN-ST-1 (MUST)

The PSBT version MUST be 0 or 2.

- Coverage: Full
- Vectors: tests only
  - passes: vectors/bip174.json #20 #21 #22 #23 #24 #25 #26 #27 #28 #29
  - passes: vectors/bip370.json #24 #25 #26 #27 #28 #29 #30 #31 #32 #33 #34 #35 #36 #37
  - passes: vectors/bip371.json #11 #12 #13 #14 #15 #16
  - passes: vectors/bip373.json #0 #1 #2 #3 #4 #5 #6 #7 #8 #9 #10 #11 #12 #13
  - passes: vectors/bip375.json #37 #38 #39 #40 #41 #42 #43 #44 #45 #46 #47 #48 #49 #50 #51 #52 #53 #54 #55 #56 #57 #58 #59 #60 #61 #62 #63 #64 #65 #66 #67 #68 #69 #70 #71 #72 #73 #74 #75 #76 #77 #78 #80 #81 #82 #83 #84 #85 #86 #87 #88 #89 #90 #91 #92 #93
  - passes: vectors/bip376.json #0 #1 #2 #3 #4 #5
  - passes: vectors/roles.json #0 #1 #2 #3 #4 #5 #11
- From: [BIP174 - Version Numbers](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#version-numbers)

#### GEN-ST-2 (MUST)

Each map MUST include the fields its PSBT version requires and exclude the fields it forbids.

- Coverage: Full
- Vectors: corpus
  - isolates: vectors/bip174.json #3: PSBT where inputs and outputs are provided but without an unsigned tx
  - isolates: vectors/bip370.json #0: PSBTv0 but with PSBT_GLOBAL_VERSION set to 2.
  - isolates: vectors/bip370.json #1: PSBTv0 but with PSBT_GLOBAL_TX_VERSION.
  - isolates: vectors/bip370.json #2: PSBTv0 but with PSBT_GLOBAL_FALLBACK_LOCKTIME.
  - isolates: vectors/bip370.json #3: PSBTv0 but with PSBT_GLOBAL_INPUT_COUNT.
  - isolates: vectors/bip370.json #4: PSBTv0 but with PSBT_GLOBAL_OUTPUT_COUNT.
  - isolates: vectors/bip370.json #5: PSBTv0 but with PSBT_GLOBAL_TX_MODIFIABLE.
  - isolates: vectors/bip370.json #6: PSBTv0 but with PSBT_IN_PREVIOUS_TXID.
  - isolates: vectors/bip370.json #7: PSBTv0 but with PSBT_IN_OUTPUT_INDEX.
  - isolates: vectors/bip370.json #8: PSBTv0 but with PSBT_IN_SEQUENCE.
  - isolates: vectors/bip370.json #9: PSBTv0 but with PSBT_IN_REQUIRED_TIME_LOCKTIME.
  - isolates: vectors/bip370.json #10: PSBTv0 but with PSBT_IN_REQUIRED_HEIGHT_LOCKTIME.
  - isolates: vectors/bip370.json #11: PSBTv0 but with PSBT_OUT_AMOUNT.
  - isolates: vectors/bip370.json #12: PSBTv0 but with PSBT_OUT_SCRIPT.
  - isolates: vectors/bip370.json #13: PSBTv2 but with PSBT_GLOBAL_UNSIGNED_TX.
  - isolates: vectors/bip370.json #14: PSBTv2 missing PSBT_GLOBAL_INPUT_COUNT.
  - isolates: vectors/bip370.json #15: PSBTv2 missing PSBT_GLOBAL_OUTPUT_COUNT.
  - isolates: vectors/bip370.json #16: PSBTv2 missing PSBT_GLOBAL_TX_VERSION.
  - isolates: vectors/bip370.json #17: PSBTv2 missing PSBT_IN_PREVIOUS_TXID.
  - isolates: vectors/bip370.json #18: PSBTv2 missing PSBT_IN_OUTPUT_INDEX.
  - isolates: vectors/bip370.json #19: PSBTv2 missing PSBT_OUT_AMOUNT.
  - isolates: vectors/bip370.json #20: PSBTv2 missing PSBT_OUT_SCRIPT.
  - isolates: vectors/bip375.json #6: psbt structure: missing PSBT_OUT_SCRIPT field when sending to non-sp output
  - isolates: vectors/bip376.json #17: PSBTv0 with PSBT_IN_SP_TWEAK
  - isolates: vectors/bip376.json #18: PSBTv0 with PSBT_IN_SP_SPEND_BIP32_DERIVATION
  - isolates: vectors/roles.json #13: Signed input while a silent payment output has no script, BIP-375 not enabled
  - isolates: vectors/roles.json #44: BIP-375 Single-input P2WPKH to silent payment workflow (global-share): Updater and Signer PSBTs, BIP-375 not enabled
  - isolates: vectors/roles.json #46: BIP-375 Two-input P2WPKH to silent payment workflow (global-share): Updater and Signer PSBTs, BIP-375 not enabled
  - isolates: vectors/roles.json #48: BIP-375 Two-input P2WPKH to silent payment workflow (per-input-share): Updater and Signer PSBTs, BIP-375 not enabled
  - passes: vectors/bip174.json #20 #21 #22 #23 #24 #25 #26 #27 #28 #29
  - passes: vectors/bip370.json #24 #25 #26 #27 #28 #29 #30 #31 #32 #33 #34 #35 #36 #37
  - passes: vectors/bip371.json #11 #12 #13 #14 #15 #16
  - passes: vectors/bip373.json #0 #1 #2 #3 #4 #5 #6 #7 #8 #9 #10 #11 #12 #13
  - passes: vectors/bip375.json #37 #38 #39 #40 #41 #42 #43 #44 #45 #46 #47 #48 #49 #50 #51 #52 #53 #54 #55 #56 #57 #58 #59 #60 #61 #62 #63 #64 #65 #66 #67 #68 #69 #70 #71 #72 #73 #74 #75 #76 #77 #78 #80 #81 #82 #83 #84 #85 #86 #87 #88 #89 #90 #91 #92 #93
  - passes: vectors/bip376.json #0 #1 #2 #3 #4 #5
  - passes: vectors/roles.json #0 #1 #2 #3 #4 #5 #11
- From: [BIP370 - Specification](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0370.mediawiki#specification)
- Note: Bound three times: the global map before the map count is known, then each input map and each output map. The field registry's Required and Excluded columns are the table it enforces.

#### GEN-ST-3 (MUST)

Input maps MUST follow the global map, followed by output maps, with one map for each transaction input and output.

- Coverage: Full
- Vectors: corpus
  - isolates: vectors/bip174.json #1: PSBT missing outputs
  - isolates: vectors/bip174.json #15: PSBT with invalid input sighash type typed key
  - passes: vectors/bip174.json #20 #21 #22 #23 #24 #25 #26 #27 #28 #29
  - passes: vectors/bip370.json #24 #25 #26 #27 #28 #29 #30 #31 #32 #33 #34 #35 #36 #37
  - passes: vectors/bip371.json #11 #12 #13 #14 #15 #16
  - passes: vectors/bip373.json #0 #1 #2 #3 #4 #5 #6 #7 #8 #9 #10 #11 #12 #13
  - passes: vectors/bip375.json #37 #38 #39 #40 #41 #42 #43 #44 #45 #46 #47 #48 #49 #50 #51 #52 #53 #54 #55 #56 #57 #58 #59 #60 #61 #62 #63 #64 #65 #66 #67 #68 #69 #70 #71 #72 #73 #74 #75 #76 #77 #78 #80 #81 #82 #83 #84 #85 #86 #87 #88 #89 #90 #91 #92 #93
  - passes: vectors/bip376.json #0 #1 #2 #3 #4 #5
  - passes: vectors/roles.json #0 #1 #2 #3 #4 #5 #11
- From: [BIP174 - Specification](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#specification)

### Transaction

#### GEN-T-1 (MUST)

The inputs’ required locktimes MUST permit nLockTime to be determined by the BIP370 procedure.

- Applies when: PSBTv2
- Coverage: Full
- Vectors: tests only
  - passes: vectors/bip370.json #24 #25 #26 #27 #28 #29 #30 #31 #32 #33 #34 #35 #36 #37
  - passes: vectors/bip375.json #37 #38 #39 #40 #41 #42 #43 #44 #45 #46 #47 #48 #49 #50 #51 #52 #53 #54 #55 #56 #57 #58 #59 #60 #61 #62 #63 #64 #65 #66 #67 #68 #69 #70 #71 #72 #73 #74 #75 #76 #77 #78 #80 #81 #82 #83 #84 #85 #86 #87 #88 #89 #90 #91 #92 #93
  - passes: vectors/bip376.json #0 #1 #2 #3 #4 #5
  - passes: vectors/roles.json #0 #1 #2 #3 #4 #5 #11
- From: [BIP370 - Determining Lock Time](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0370.mediawiki#determining-lock-time)

#### GEN-T-2 (MUST)

A PSBT's signatures MUST agree with PSBT_GLOBAL_TX_MODIFIABLE: Inputs Modifiable is clear if any signature lacks SIGHASH_ANYONECANPAY, Outputs Modifiable is clear if any does not use SIGHASH_NONE, and Has SIGHASH_SINGLE is set if any uses SIGHASH_SINGLE.

- Applies when: PSBTv2
- Coverage: Full
- Vectors: corpus
  - isolates: vectors/roles.json #6: SIGHASH_ALL signature with Inputs Modifiable set
  - isolates: vectors/roles.json #7: SIGHASH_DEFAULT taproot key path signature with Inputs Modifiable set
  - isolates: vectors/roles.json #8: Finalized P2WPKH input signed with SIGHASH_ALL with Inputs Modifiable set
  - isolates: vectors/roles.json #9: SIGHASH_ALL|ANYONECANPAY signature with Outputs Modifiable set
  - isolates: vectors/roles.json #10: SIGHASH_SINGLE|ANYONECANPAY signature with Has SIGHASH_SINGLE clear
  - passes: vectors/bip370.json #24 #25 #26 #27 #28 #29 #30 #31 #32 #33 #34 #35 #36 #37
  - passes: vectors/bip375.json #37 #38 #39 #40 #41 #42 #43 #44 #45 #46 #47 #48 #49 #50 #51 #52 #53 #54 #55 #56 #57 #58 #59 #60 #61 #62 #63 #64 #65 #66 #67 #68 #69 #70 #71 #72 #73 #74 #75 #76 #77 #78 #80 #81 #82 #83 #84 #85 #86 #87 #88 #89 #90 #91 #92 #93
  - passes: vectors/bip376.json #0 #1 #2 #3 #4 #5
  - passes: vectors/roles.json #0 #1 #2 #3 #4 #5 #11
- Enforced by: Signer
- From: [BIP370 - Signer](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0370.mediawiki#signer)
- Note: Bound three times, one per flag. It also covers the Signer's BIP370 flag duties: a Signer that leaves a flag wrong returns a PSBT that fails this rule. Signatures are found as input_signatures finds them, including those in finalized key-path and legacy fields.

### Taproot

#### GEN-TR-1 (MUST)

For each input with PSBT_IN_TAP_LEAF_SCRIPT, every control block MUST reconstruct to the spent P2TR key.

- Coverage: Full
- Vectors: tests only
  - passes: vectors/bip371.json #14 #16
  - passes: vectors/bip373.json #6 #7 #8
- From: [BIP371 - Specification](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0371.mediawiki#specification)
- Note: Applies only to inputs with PSBT_IN_TAP_LEAF_SCRIPT. Takes the spent output from either UTXO field; a missing spent output returns Incomplete. The control block leaf version must equal the leaf script version.

#### GEN-TR-2 (MUST)

PSBT_IN_TAP_INTERNAL_KEY, tweaked by PSBT_IN_TAP_MERKLE_ROOT or, without it, by some script tree, MUST produce the spent P2TR output key.

- Coverage: Full
- Vectors: tests only
  - passes: vectors/bip371.json #11 #12 #13 #14 #15 #16
  - passes: vectors/bip373.json #3 #4 #5 #6 #7 #8 #9 #10 #11
  - passes: vectors/bip375.json #49 #61 #68 #69 #70 #74 #75
- From: [BIP371 - Specification](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0371.mediawiki#specification)
- Note: Without PSBT_IN_TAP_MERKLE_ROOT, a key-only tweak that matches is Verified and a mismatch is Incomplete, since the PSBT may omit the script tree. A missing spent output returns Incomplete.

#### GEN-TR-3 (MUST)

PSBT_OUT_TAP_INTERNAL_KEY, tweaked by the root of PSBT_OUT_TAP_TREE or, without it, by some script tree, MUST produce the output's P2TR key.

- Coverage: Full
- Vectors: tests only
  - passes: vectors/bip371.json #13 #14 #15 #16
  - passes: vectors/bip373.json #12 #13
- From: [BIP371 - Specification](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0371.mediawiki#specification)
- Note: Uses PSBT_OUT_SCRIPT (v2) or the unsigned transaction's output (v0). Without PSBT_OUT_TAP_TREE, a key-only match is Verified and a mismatch is Incomplete. An output with no script yet returns Incomplete.

#### GEN-TR-4 (MUST)

Each leaf hash in PSBT_OUT_TAP_BIP32_DERIVATION MUST be a leaf of PSBT_OUT_TAP_TREE.

- Coverage: Full
- Vectors: tests only
  - passes: vectors/bip371.json #15
- From: [BIP371 - Specification](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0371.mediawiki#specification)
- Note: Without PSBT_OUT_TAP_TREE, leaf hashes cannot be checked and the rule returns Incomplete. Input derivation leaf hashes are not checked, because inputs list only the leaves signers can sign.

### MuSig2

#### GEN-MS-1 (MUST)

In PSBT_IN_MUSIG2_PUB_NONCE and PSBT_IN_MUSIG2_PARTIAL_SIG key data, the plain public key MUST be the Taproot output key when the tapleaf hash is omitted, and MUST be found in that leaf's script when it is present.

- Coverage: Full
- Vectors: tests only
  - passes: vectors/bip373.json #1 #2 #4 #5 #7 #8 #10 #11
- From: [BIP373 - Specification](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0373.mediawiki#specification)
- Note: Applies to inputs with PSBT_IN_MUSIG2_PUB_NONCE or PSBT_IN_MUSIG2_PARTIAL_SIG. A missing spent output, or a tapleaf hash without a matching PSBT_IN_TAP_LEAF_SCRIPT, returns Incomplete.

#### GEN-MS-2 (MUST)

The key of each PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS and PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS MUST be the BIP327 KeyAgg result of its participant keys in the listed order.

- Coverage: Full
- Vectors: tests only
  - passes: vectors/bip373.json #0 #1 #2 #3 #4 #5 #6 #7 #8 #9 #10 #11 #12 #13
- From: [BIP373 - Specification; BIP327 - Key Aggregation](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0373.mediawiki#specification)
- Note: Runs BIP327 KeyAgg with the musig2 crate over the listed keys in order and compares the untweaked aggregate key. Keys listed in a different order produce a different key and fail.

### DNS payment instructions

#### GEN-DNS-1 (MUST)

When PSBT_OUT_DNSSEC_PROOF is present, the field value MUST begin with a valid length-prefixed human-readable name.

- Coverage: Full
- Vectors: tests only
- From: [BIP353 - Specification](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0353.mediawiki#psbt-types)
- Note: Checks the one-byte length prefix and that the name is UTF-8 and contains an @ separator.

### Generic signed messages

#### GEN-MSG-1 (MUST)

In a BIP322 PSBT, the first input's PSBT_IN_WITNESS_UTXO, when present, MUST be output 0 of to_spend, whose amount is 0.

- Coverage: Full
- Vectors: tests only
- Enforced by: Creator and Constructor
- From: [BIP322 - PSBT creator; Full](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0322.mediawiki#psbt-creator)
- Note: Not applicable without PSBT_IN_WITNESS_UTXO; a non-witness UTXO is checked against the prevout by ROLE-S-1 and recognition.

#### GEN-MSG-2 (MUST)

In a BIP322 PSBT, every input after the first MUST have PSBT_IN_WITNESS_UTXO or PSBT_IN_NON_WITNESS_UTXO; the non-witness UTXO may be omitted when an earlier input spending the same transaction has it.

- Coverage: Full
- Vectors: tests only
- Enforced by: Creator and Constructor
- From: [BIP322 - Full (Proof of Funds); PSBT creator](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0322.mediawiki#full-proof-of-funds)
- Note: Not applicable to a PSBT with one input.

#### GEN-MSG-3 (MUST)

In a BIP322 PSBT, every signature MUST use SIGHASH_ALL, or SIGHASH_DEFAULT on an input spending P2TR.

- Coverage: Partial
- Vectors: tests only
- From: [BIP322 - Verification Process (required rules)](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0322.mediawiki#verification-process)
- Note: Uses discovered signatures; a 64-byte Schnorr signature is SIGHASH_DEFAULT.
- Not decided: Signature discovery does not cover finalized P2WSH spends or finalized Taproot script paths.

#### GEN-MSG-4 (MUST)

A BIP322 PSBT whose to_sign version is not 0 or 2, or that spends a Segwit version above 1, uses an annex, or uses a leaf version other than 0xc0, MUST be reported as inconclusive, not invalid.

- Coverage: Full
- Vectors: tests only
- From: [BIP322 - Verification Process (upgradeable rules)](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0322.mediawiki#verification-process)
- Note: Never Failed: an upgradeable feature makes the proof inconclusive, not invalid.

### Pay-to-contract

#### GEN-P2C-1 (MUST)

For each PSBT_IN_P2C_TWEAK, the original key plus the tweak times G MUST be a key committed to by the input's spent, redeem, or witness script.

- Coverage: Partial
- Vectors: tests only
- From: [BIP372 - Specification (Draft)](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0372.mediawiki#specification)
- Note: Matches P + tG as a P2PKH or P2WPKH key hash or a 33-byte push in the spent, redeem, or witness script. Taproot spends return Incomplete because BIP372 leaves them unresolved.
- Not decided: Does not check that redeem or witness scripts match the spent script, or verify signatures.

### Silent payments

#### GEN-SP-1 (MUST)

An output with PSBT_OUT_SP_V0_LABEL MUST also have PSBT_OUT_SP_V0_INFO.

- Applies when: From BIP-375
- Coverage: Full
- Vectors: corpus
  - isolates: vectors/bip375.json #0: psbt structure: missing PSBT_OUT_SP_V0_INFO field when PSBT_OUT_SP_V0_LABEL set
  - passes: vectors/bip375.json #37 #38 #39 #40 #41 #42 #43 #44 #45 #46 #47 #48 #49 #50 #51 #52 #53 #54 #55 #56 #57 #58 #59 #60 #61 #62 #63 #64 #65 #66 #67 #68 #69 #70 #71 #72 #73 #74 #75 #76 #77 #78 #80 #81 #82 #83 #84 #85 #86 #87 #88 #89 #90 #91 #92 #93
  - passes: vectors/bip376.json #0 #1 #2 #3 #4 #5
  - passes: vectors/roles.json #11
- From: [BIP375 - Invalid Psbts](https://github.com/bitcoin/bips/blob/9c5b825e4ba43fab0431fa042ddb00afdf251a95/bip-0375.mediawiki#invalid-psbts)

#### GEN-SP-2 (MUST)

Once a silent-payment output has PSBT_OUT_SCRIPT, PSBT_GLOBAL_TX_MODIFIABLE MUST have Inputs Modifiable and Outputs Modifiable clear.

- Applies when: From BIP-375; Silent payment outputs
- Coverage: Full
- Vectors: corpus
  - isolates: vectors/bip375.json #5: psbt structure: PSBT_GLOBAL_TX_MODIFIABLE field is non-zero when PSBT_OUT_SCRIPT set for sp output
  - passes: vectors/bip375.json #37 #38 #39 #40 #41 #42 #43 #44 #45 #46 #47 #48 #49 #50 #51 #52 #53 #54 #55 #56 #57 #58 #59 #60 #61 #62 #63 #64 #65 #66 #67 #68 #69 #70 #71 #72 #73 #74 #75 #76 #77 #78 #80 #81 #82 #83 #84 #85 #86 #87 #88 #89 #90 #91 #92 #93
  - passes: vectors/roles.json #11
- Enforced by: Signer
- From: [BIP375 - Invalid Psbts (PSBT Structure); Signer](https://github.com/bitcoin/bips/blob/9c5b825e4ba43fab0431fa042ddb00afdf251a95/bip-0375.mediawiki#invalid-psbts)
- Note: BIP375 publishes this as a PSBT Structure failure. It also covers the Signer's duty to clear both flags when it sets the scripts.

#### GEN-SP-3 (MUST)

A PSBT with silent-payment outputs MUST pass the ECDH coverage check REF-8 describes.

- Applies when: From BIP-375; Silent payment outputs
- Coverage: Full
- Vectors: corpus
  - isolates: vectors/bip375.json #7: ecdh coverage: only one ineligible P2SH multisig input when PSBT_OUT_SCRIPT set for sp output
  - isolates: vectors/bip375.json #8: ecdh coverage: missing PSBT_IN_SP_ECDH_SHARE field for input 0 when PSBT_OUT_SCRIPT set for sp output
  - isolates: vectors/bip375.json #9: ecdh coverage: missing PSBT_IN_SP_DLEQ field for input when PSBT_IN_SP_ECDH_SHARE set
  - isolates: vectors/bip375.json #10: ecdh coverage: missing PSBT_GLOBAL_SP_DLEQ field when PSBT_GLOBAL_SP_ECDH_SHARE set
  - isolates: vectors/bip375.json #11: ecdh coverage: invalid proof in PSBT_IN_SP_DLEQ field
  - isolates: vectors/bip375.json #12: ecdh coverage: invalid proof in PSBT_GLOBAL_SP_DLEQ field
  - isolates: vectors/bip375.json #13: ecdh coverage: missing PSBT_IN_BIP32_DERIVATION field for input when PSBT_IN_SP_DLEQ set
  - isolates: vectors/bip375.json #15: ecdh coverage: invalid proof in PSBT_IN_SP_DLEQ field when PSBT_OUT_SCRIPT not set
  - isolates: vectors/bip375.json #16: ecdh coverage: global ECDH share proven over a subset of eligible inputs
  - isolates: vectors/bip375.json #17: ecdh coverage: output 1 missing ECDH share for scan key with one input / three sp outputs (different scan keys)
  - isolates: vectors/bip375.json #18: ecdh coverage: input 1 missing ECDH share for output 1 with two inputs / two sp outputs (different scan keys)
  - isolates: vectors/bip375.json #19: ecdh coverage: input 1 missing ECDH share for scan key with two inputs / one sp output
  - isolates: vectors/bip375.json #33: input derivation: P2WPKH BIP32_DERIVATION pubkey does not match prevout script
  - isolates: vectors/bip375.json #34: input derivation: P2PKH BIP32_DERIVATION pubkey does not match prevout script
  - isolates: vectors/bip375.json #35: input derivation: P2SH-P2WPKH BIP32_DERIVATION pubkey does not match prevout script
  - isolates: vectors/bip375.json #36: input pubkey mismatch: global ECDH share computed from decoy pubkey not matching prevout script
  - passes: vectors/bip375.json #37 #38 #39 #40 #41 #42 #43 #44 #45 #46 #47 #48 #49 #50 #51 #52 #53 #54 #55 #56 #57 #58 #59 #60 #61 #62 #63 #64 #65 #66 #67 #68 #69 #70 #71 #72 #73 #74 #75 #76 #77 #78 #80 #81 #82 #83 #84 #85 #86 #87 #88 #89 #90 #91 #92 #93
  - passes: vectors/roles.json #11
- Enforced by: Signer, Transaction Extractor
- From: [BIP375 - Invalid Psbts (ECDH Coverage)](https://github.com/bitcoin/bips/blob/9c5b825e4ba43fab0431fa042ddb00afdf251a95/bip-0375.mediawiki#invalid-psbts)
- Note: Bound once per subcheck, in REF-8's order; the failure detail names the subcheck. DLEQ proofs are verified with BIP374 VerifyProof.

#### GEN-SP-4 (MUST)

A PSBT with silent-payment outputs MUST pass the input eligibility check REF-9 describes.

- Applies when: From BIP-375; Silent payment outputs
- Coverage: Full
- Vectors: corpus
  - isolates: vectors/bip375.json #20: input eligibility: segwit version greater than 1 in transaction inputs with sp output
  - isolates: vectors/bip375.json #21: input eligibility: segwit version greater than 1 supplied via PSBT_IN_NON_WITNESS_UTXO with sp output
  - isolates: vectors/bip375.json #22: input eligibility: non-SIGHASH_ALL signature on input with sp output
  - isolates: vectors/bip375.json #23: input eligibility: non-SIGHASH_ALL signature on input with sp output and PSBT_IN_SIGHASH_TYPE omitted
  - isolates: vectors/bip375.json #24: input eligibility: non-SIGHASH_ALL signature on ineligible input with sp output
  - isolates: vectors/bip375.json #25: input eligibility: non-SIGHASH_ALL signature on ineligible input with sp output and PSBT_IN_SIGHASH_TYPE omitted
  - isolates: vectors/bip375.json #26: input eligibility: SIGHASH_ALL|ANYONECANPAY sighash type on input with sp output
  - isolates: vectors/bip375.json #27: input eligibility: non-SIGHASH_ALL signature on taproot input with sp output
  - isolates: vectors/bip375.json #28: input eligibility: SIGHASH_DEFAULT sighash type on non-taproot input with sp output
  - passes: vectors/bip375.json #37 #38 #39 #40 #41 #42 #43 #44 #45 #46 #47 #48 #49 #50 #51 #52 #53 #54 #55 #56 #57 #58 #59 #60 #61 #62 #63 #64 #65 #66 #67 #68 #69 #70 #71 #72 #73 #74 #75 #76 #77 #78 #80 #81 #82 #83 #84 #85 #86 #87 #88 #89 #90 #91 #92 #93
  - passes: vectors/roles.json #11
- Enforced by: Creator and Constructor, Signer
- From: [BIP375 - Signer (sighash type); Invalid Psbts (Input Eligibility); Constructor](https://github.com/bitcoin/bips/blob/9c5b825e4ba43fab0431fa042ddb00afdf251a95/bip-0375.mediawiki#signer)
- Note: Bound once per subcheck. The Signer section allows SIGHASH_DEFAULT on a taproot input in both sighash sentences: it fails if a provided sighash type is not "SIGHASH_ALL, or SIGHASH_DEFAULT for a taproot input", and signs using "SIGHASH_ALL, or SIGHASH_DEFAULT for a taproot input" when none is provided.

#### GEN-SP-5 (MUST)

A PSBT with silent-payment outputs MUST pass the output script check REF-10 describes.

- Applies when: From BIP-375; Silent payment outputs
- Coverage: Full
- Vectors: corpus
  - isolates: vectors/bip375.json #29: output scripts: P2TR input with NUMS internal key cannot derive sp output
  - isolates: vectors/bip375.json #30: output scripts: PSBT_OUT_SCRIPT does not match derived sp output
  - isolates: vectors/bip375.json #31: output scripts: two sp outputs (same scan / different spend keys) not sorted lexicographically by spend key
  - isolates: vectors/bip375.json #32: output scripts: k values assigned to wrong output indices with three sp outputs (same scan / spend keys)
  - isolates: vectors/bip375.json #79: input eligibility: bare OP_2 script is not a segwit v2 witness program
  - passes: vectors/bip375.json #37 #38 #39 #40 #41 #42 #43 #44 #45 #46 #47 #48 #49 #50 #51 #52 #53 #54 #55 #56 #57 #58 #59 #60 #61 #62 #63 #64 #65 #66 #67 #68 #69 #70 #71 #72 #73 #74 #75 #76 #77 #78 #80 #81 #82 #83 #84 #85 #86 #87 #88 #89 #90 #91 #92 #93
  - passes: vectors/roles.json #11
- Enforced by: Signer, Transaction Extractor
- From: [BIP375 - Invalid Psbts (Output Scripts); Signer; Transaction Extractor](https://github.com/bitcoin/bips/blob/9c5b825e4ba43fab0431fa042ddb00afdf251a95/bip-0375.mediawiki#invalid-psbts)
- Note: Bound twice: the derivation context first, then the scripts. With GEN-SP-3 the shares a set script needs are present, so the check decides rather than reporting missing context.

#### GEN-SP-6 (MUST)

Every input MUST pass the BIP376 spend-field check REF-11 describes.

- Applies when: From BIP-376
- Coverage: Full
- Vectors: corpus
  - isolates: vectors/bip376.json #6: Finalized input that keeps PSBT_IN_SP_TWEAK
  - isolates: vectors/bip376.json #7: Finalized input that keeps PSBT_IN_SP_SPEND_BIP32_DERIVATION
  - isolates: vectors/bip376.json #8: Spend key derivation without a tweak
  - isolates: vectors/bip376.json #9: Tweak without a witness UTXO
  - isolates: vectors/bip376.json #10: Tweak on an input whose witness UTXO is P2WPKH
  - isolates: vectors/bip376.json #11: Tweak that does not produce the output key
  - isolates: vectors/bip376.json #12: Spend key that does not produce the output key
  - passes: vectors/bip376.json #0 #1 #2 #3 #4 #5
- Enforced by: Updater, Signer, Input Finalizer
- From: [BIP376 - Specification; Updater; Signer; Input Finalizer](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0376.mediawiki#specification)
- Note: Bound once per subcheck, in REF-11's order, when BIP376 is enabled.

#### GEN-SP-7 (MUST NOT)

A PSBT with silent-payment outputs MUST NOT carry a signature while any output lacks PSBT_OUT_SCRIPT.

- Applies when: From BIP-375; Silent payment outputs
- Coverage: Full
- Vectors: corpus
  - isolates: vectors/roles.json #12: Signed input while a silent payment output has no script
  - passes: vectors/bip375.json #37 #38 #39 #40 #41 #42 #43 #44 #45 #46 #47 #48 #49 #50 #51 #52 #53 #54 #55 #56 #57 #58 #59 #60 #61 #62 #63 #64 #65 #66 #67 #68 #69 #70 #71 #72 #73 #74 #75 #76 #77 #78 #80 #81 #82 #83 #84 #85 #86 #87 #88 #89 #90 #91 #92 #93
  - passes: vectors/roles.json #11
- Enforced by: Signer
- From: [BIP375 - Signer](https://github.com/bitcoin/bips/blob/9c5b825e4ba43fab0431fa042ddb00afdf251a95/bip-0375.mediawiki#signer)
- Note: Restates the Signer's duty "If any output does not have PSBT_OUT_SCRIPT set, the Signer must not yet add a signature" as a property of the PSBT: no conforming Signer produces it, and a Signer that receives it refuses. A present empty script counts as set.

## Creator and Constructor

General rules this role must enforce: GEN-MSG-1, GEN-MSG-2, GEN-SP-4.

### Result

#### ROLE-C-1 (MUST)

A v0 Creator MUST create the unsigned transaction with empty input and output maps; a v2 Creator MUST create a version 2 PSBT with no inputs or outputs.

- Phase: Result
- Coverage: Partial
- Vectors: tests only
- From: [BIP370 - Creator](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0370.mediawiki#creator)
- Note: The linked v0 check currently requires zero transaction inputs and outputs; it does not check empty maps for an unsigned transaction with inputs or outputs.
- Not decided: The v0 check requires zero inputs and outputs; it does not check empty maps for an unsigned transaction that has inputs or outputs.

#### ROLE-C-2 (MUST)

If the Creator is not also a Constructor and delegates additions, PSBT_GLOBAL_TX_MODIFIABLE MUST be present with flags set appropriately, and transaction nVersion MUST be at least 2.

- Phase: Result
- Coverage: Partial
- Vectors: tests only
- From: [BIP370 - Creator](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0370.mediawiki#creator)
- Note: Supply delegation intent explicitly. The linked check verifies flag-field presence and length, but does not verify that its bits permit the intended additions.
- Not decided: Checks the flag field's presence and length, not that its bits permit the intended additions.

#### ROLE-C-3 (MUST)

Before adding inputs or outputs, the Constructor MUST check the corresponding modification flag and add only what it permits.

- Phase: Result
- Coverage: Partial
- Vectors: tests only
- From: [BIP370 - Constructor](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0370.mediawiki#constructor)
- Note: evaluate_constructing runs the General rules on both PSBTs first. The linked check compares input and output counts with the modification flags of the PSBT the Constructor received.
- Not decided: Assumes new maps are appended, so an inserted map is read as a changed one.

#### ROLE-C-4 (MUST)

For an input with a required spend-branch locktime, the Constructor MUST set the corresponding required time- or height-based locktime field.

- Phase: Result
- Coverage: Partial
- Vectors: tests only
- From: [BIP370 - Constructor](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0370.mediawiki#constructor)
- Note: The linked context records only whether each listed input needs a locktime, not the required type or value. Success confirms field presence for listed requirements; it does not establish that all added inputs or their chosen spend branches were covered.
- Not decided: Knows only whether each listed input needs a locktime, not the required type or value.

#### ROLE-C-5 (MUST NOT)

When adding an input with a required locktime, the Constructor MUST NOT change the determined transaction locktime if any existing input has a signature.

- Phase: Result
- Coverage: Partial
- Vectors: tests only
- From: [BIP370 - Constructor](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0370.mediawiki#constructor)
- Note: Preservation is checked using discoverable signatures. Signature discovery does not cover arbitrary finalized scripts or all Taproot script paths.
- Not decided: Sees only the signatures signature discovery reaches, not those in arbitrary finalized scripts or every Taproot script path.

#### ROLE-C-6 (MUST)

If Has SIGHASH_SINGLE is true, the Constructor MUST identify the signed SINGLE input/output pairs and insert equal numbers of inputs and outputs before each affected pair.

- Phase: Result
- Coverage: Partial
- Vectors: tests only
- From: [BIP370 - Constructor](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0370.mediawiki#constructor)
- Note: The linked check locates the signed input but does not compare its paired output. A Verified result does not establish preservation of the SINGLE pair.
- Not decided: Locates the signed SINGLE input but does not compare its paired output.

### Guidance

#### GUIDE-1 (SHOULD) Creator fallback

The Creator SHOULD set fallback locktime. Its absence means zero when no input requires a locktime.

- From: [BIP370 - Creator](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0370.mediawiki#creator)

#### GUIDE-2 (MAY) Self-contained construction

A Creator that is also the Constructor may omit TX_MODIFIABLE if no other entity will add inputs or outputs.

- From: [BIP370 - Creator](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0370.mediawiki#creator)

#### GUIDE-3 (MAY) Branch alternatives

Both required locktime types may be set. If the chosen spend branch uses one type, that field can be the only one set.

- From: [BIP370 - Constructor](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0370.mediawiki#constructor)

#### GUIDE-4 (MAY) Close construction

A Constructor may close additions by clearing the appropriate modification flags or removing TX_MODIFIABLE.

- From: [BIP370 - Constructor](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0370.mediawiki#constructor)

#### GUIDE-22 (SHOULD) BIP353 proof inclusion

BIP353: wallets creating PSBTs with recipient information from a human-readable name SHOULD include PSBT_OUT_DNSSEC_PROOF. Wallets accepting payment information from external devices MAY examine it.

- From: [BIP353 - PSBT types](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0353.mediawiki#psbt-types)

## Updater

General rules this role must enforce: GEN-SP-6.

### Not shown in the PSBT

#### ROLE-U-1 (MUST)

When an input spends a Silent Payment output, the Updater MUST add PSBT_IN_SP_TWEAK.

- Coverage: Declared
- Vectors: none
- From: [BIP376 - Updater](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0376.mediawiki#updater)
- Note: Not observable in the PSBT: only the Updater knows that an input spends a silent-payment output. GEN-SP-6 rejects a spend-key derivation without the tweak.

### Guidance

#### GUIDE-5 (SHOULD) Known metadata

Updaters SHOULD add available input UTXOs and known scripts and BIP32 origins at the applicable input/output scopes. PSBT_IN_NON_WITNESS_UTXO SHOULD be present for inputs spending non-segwit outputs and can be present for segwit ones; PSBT_IN_WITNESS_UTXO SHOULD only be present for inputs spending segwit outputs.

- From: [BIP174 - Updater; Specification](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#updater)

#### GUIDE-6 (SHOULD) Version and sequence

When adding a PSBT format version, use the highest required version as recommended by BIP174. A v2 Updater can set sequence.

- From: [BIP174 - Version Numbers](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#version-numbers)
- Note: Sequence-setting permission does not authorize arbitrary PSBT format conversion.

#### GUIDE-7 (SHOULD) SP sending metadata

Updaters SHOULD supply BIP32 derivation fields for P2PKH, P2WPKH and P2SH-P2WPKH inputs so public keys are available. BIP375 permits setting the derivation value to zero to withhold origin information.

- From: [BIP375 - Updater](https://github.com/bitcoin/bips/blob/9c5b825e4ba43fab0431fa042ddb00afdf251a95/bip-0375.mediawiki#updater)
- Note: BIP375 describes a privacy alternative as setting the value to zero. Do not assume this uses BIP376’s separate four-byte-fingerprint encoding.

#### GUIDE-8 (MAY) SP change annotations

Updaters may supply scan/spend derivation information and a label for change detection.

- From: [BIP375 - Change Detection](https://github.com/bitcoin/bips/blob/9c5b825e4ba43fab0431fa042ddb00afdf251a95/bip-0375.mediawiki#change-detection)

#### GUIDE-9 (SHOULD) SP spending derivation

For an SP spend using BIP32, the Updater SHOULD add SP_SPEND_BIP32_DERIVATION. To hide origin information, it can use a four-byte zero fingerprint and no derivation paths.

- From: [BIP376 - Updater](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0376.mediawiki#updater)

#### GUIDE-13 (SHOULD) Taproot leaf scripts

BIP371: the leaves in PSBT_IN_TAP_LEAF_SCRIPT SHOULD be those the signers of the input are expected to be able to sign for.

- From: [BIP371 - Specification](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0371.mediawiki#specification)
- Note: Because inputs may omit leaves, input derivation leaf hashes are not checked against PSBT_IN_TAP_LEAF_SCRIPT.

#### GUIDE-14 (MAY) Taproot UTXO types

BIP371: a Taproot input may carry only PSBT_IN_WITNESS_UTXO, since a Taproot signature commits to every spent amount and script.

- From: [BIP371 - UTXO Types](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0371.mediawiki#utxo-types)
- Note: Taproot rules take the spent output from either UTXO field.

#### GUIDE-15 (SHOULD) Global xpub depth

A PSBT_GLOBAL_XPUB SHOULD be the public key at the highest hardened derivation index, so the unhardened child keys in the transaction can be derived from it.

- From: [BIP174 - Specification (PSBT_GLOBAL_XPUB)](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#specification)

#### GUIDE-19 (SHOULD) MuSig2 input metadata

BIP373: an Updater that knows a MuSig2 aggregate key in a Taproot output may add PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS, SHOULD add PSBT_IN_TAP_BIP32_DERIVATION for the participant keys, and for a key derived from the aggregate key SHOULD add that derivation, which follows BIP328 unless a PSBT_GLOBAL_XPUB gives the synthetic xpub.

- From: [BIP373 - Updater](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0373.mediawiki#updater)

#### GUIDE-20 (SHOULD) MuSig2 output metadata

BIP373: Updaters SHOULD add PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS and PSBT_OUT_TAP_BIP32_DERIVATION to outputs, as for inputs, to aid change detection.

- From: [BIP373 - Updater](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0373.mediawiki#updater)

## Signer

General rules this role must enforce: GEN-T-2, GEN-SP-2, GEN-SP-3, GEN-SP-4, GEN-SP-5, GEN-SP-6, GEN-SP-7.

### Precondition

#### ROLE-S-1 (MUST)

Before signing an input with PSBT_IN_NON_WITNESS_UTXO, the Signer MUST verify that it hashes to the input's previous txid and agrees with any PSBT_IN_WITNESS_UTXO.

- Phase: Precondition
- Coverage: Full
- Vectors: tests only
- From: [BIP174 - Data Signers Check For](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#data-signers-check-for)
- Note: Not applicable without PSBT_IN_NON_WITNESS_UTXO. Also fails when the transaction lacks the prevout's output, or when a PSBT_IN_WITNESS_UTXO names a different spent output.

#### ROLE-S-2 (MUST)

Before signing an input with PSBT_IN_REDEEM_SCRIPT, the Signer MUST verify that the spent output is P2SH of that script.

- Phase: Precondition
- Coverage: Full
- Vectors: tests only
- From: [BIP174 - Data Signers Check For](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#data-signers-check-for)
- Note: Not applicable without PSBT_IN_REDEEM_SCRIPT, so a P2SH spend missing it passes this rule; ROLE-S-3 and ROLE-S-4 are then Incomplete. Takes the spent output from either UTXO field; without one it is Incomplete.

#### ROLE-S-3 (MUST)

Before signing an input with PSBT_IN_WITNESS_SCRIPT, the Signer MUST verify that the spent script, or its redeemScript, is P2WSH of that script.

- Phase: Precondition
- Coverage: Full
- Vectors: corpus
  - isolates: vectors/bip174.json #33: witnessScript with witness UTXO does not match the redeemScript
- From: [BIP174 - Data Signers Check For](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#data-signers-check-for)
- Note: Not applicable without PSBT_IN_WITNESS_SCRIPT, so a P2WSH spend missing it passes this rule. A P2SH spend without its redeemScript, or an input without a spent output, is Incomplete.

#### ROLE-S-4 (MUST)

The Signer MUST NOT create a non-witness signature for an input with PSBT_IN_WITNESS_UTXO, nor a signature of a kind the spent script does not take.

- Phase: Precondition
- Coverage: Full
- Vectors: corpus
  - isolates: vectors/bip174.json #30: A Witness UTXO is provided for a non-witness input
- From: [BIP174 - Data Signers Check For](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#data-signers-check-for)
- Note: Run by evaluate_for_signing with the input and signature kind the caller selects; evaluate_signing infers the kind from the spent script. Without a spent output, or a P2SH spend without its redeemScript, it is Incomplete.

#### ROLE-S-6 (MUST)

A Signer that validates a PSBT_OUT_DNSSEC_PROOF MUST validate it as REF-6 describes.

- Phase: Precondition
- Coverage: Full
- Vectors: tests only
- From: [BIP353 - PSBT types; Resolution](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0353.mediawiki#psbt-types)
- Note: Run by evaluate_dnssec_proofs with a supplied time; without one it is Incomplete. Uses dnssec-prover, which enforces the DNSSEC algorithm policy and resolves CNAME and DNAME. TXT character-strings are concatenated in RDATA order.

### Not shown in the PSBT

#### ROLE-S-5 (MUST)

Before signing an SP input, the Signer MUST fail unless its spend private key, tweaked as REF-7 describes, gives the spent P2TR output key.

- Coverage: Declared
- Vectors: none
- From: [BIP376 - Signer](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0376.mediawiki#signer)
- Note: Not observable in the PSBT: the check uses the Signer's private key. GEN-SP-6 checks a supplied spend public key the same way.

#### ROLE-S-7 (MUST)

A Signer that displays a BIP353 name without homograph precautions MUST display non-ASCII user and domain identifiers as raw punycode.

- Coverage: Declared
- Vectors: none
- From: [BIP353 - Resolution](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0353.mediawiki#resolution)
- Note: Not observable in the PSBT: the rule needs evidence of what the wallet displayed.

#### ROLE-S-8 (MUST)

A Signer that recognizes a BIP322 PSBT MUST inform the user of the message and the address it signs for, and MUST sign only on the user's approval.

- Coverage: Declared
- Vectors: none
- From: [BIP322 - PSBT signer](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0322.mediawiki#psbt-signer)
- Note: Not observable in the PSBT: the rule needs evidence of what the Signer showed and that the user approved.

### Result

#### ROLE-S-9 (MUST)

The Signer MUST only add data: every key-value pair it received, including unknown types, MUST be in the PSBT it returns.

- Phase: Result
- Coverage: Partial
- Vectors: tests only
- From: [BIP174 - Signer](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#signer)
- Note: The linked transition check preserves existing records but exempts TX_MODIFIABLE from comparison. It does not restrict newly added fields or verify that flag changes are permitted.
- Not decided: Exempts PSBT_GLOBAL_TX_MODIFIABLE from comparison and does not restrict which fields the Signer adds.

#### ROLE-S-10 (MUST)

Every signature the Signer adds to an input with PSBT_IN_SIGHASH_TYPE MUST use that sighash type.

- Phase: Result
- Coverage: Full
- Vectors: tests only
- From: [BIP174 - Specification (PSBT_IN_SIGHASH_TYPE)](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#specification)
- Note: Compares the PSBT the Signer received with the one it returned. Applies to inputs with PSBT_IN_SIGHASH_TYPE that gained a signature; a 64-byte Schnorr signature uses SIGHASH_DEFAULT.

#### ROLE-S-11 (MUST)

The Signer MUST write the BIP340 signature for an SP input to PSBT_IN_TAP_KEY_SIG.

- Phase: Result
- Coverage: Full
- Vectors: tests only
- From: [BIP376 - Signer](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0376.mediawiki#signer)
- Note: Compares the PSBT the Signer received with the one it returned. For an SP input that gained a signature, it must be in PSBT_IN_TAP_KEY_SIG, not a partial or script-path signature, and verify as a key-path signature by the spent output key. Missing transaction data returns Incomplete.

### Guidance

#### GUIDE-10 (SHOULD) SP share generation

The Signer SHOULD generate per-input shares and proofs for eligible inputs whose private keys it has, or a global share and proof when it has all eligible private keys, and compute missing scripts when share coverage is complete.

- From: [BIP375 - Signer](https://github.com/bitcoin/bips/blob/9c5b825e4ba43fab0431fa042ddb00afdf251a95/bip-0375.mediawiki#signer)

#### GUIDE-16 (MAY) Signer UTXO policy

A Signer may refuse to sign a segwit input that has no PSBT_IN_NON_WITNESS_UTXO.

- From: [BIP174 - Signer](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#signer)

#### GUIDE-17 (SHOULD) Default sighash type

Without PSBT_IN_SIGHASH_TYPE, a Signer SHOULD sign using SIGHASH_ALL, but may use any sighash type.

- From: [BIP174 - Data Signers Check For](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#data-signers-check-for)

#### GUIDE-18 (SHOULD) Partial signature validity

A PSBT_IN_PARTIAL_SIG value SHOULD be a valid ECDSA signature for its public key, as it would be pushed to the stack.

- From: [BIP174 - Specification (PSBT_IN_PARTIAL_SIG)](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#specification)
- Note: General validation does not check PSBT_IN_PARTIAL_SIG signatures; ROLE-F-4 does before finalizing.

#### GUIDE-21 (SHOULD) MuSig2 participation and nonces

BIP373: a Signer SHOULD find its participation through PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS and its PSBT_IN_TAP_BIP32_DERIVATION keys, and SHOULD add a PSBT_IN_MUSIG2_PUB_NONCE when it has none. Improper nonce use can compromise private keys; see BIP327.

- From: [BIP373 - Signer](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0373.mediawiki#signer)

#### GUIDE-23 (SHOULD) BIP353 recipient display

BIP353: when a proof validates, a Signer SHOULD display the recipient as ₿user@domain.

- From: [BIP353 - Display; Resolution](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0353.mediawiki#display)

#### GUIDE-24 (SHOULD) BIP322 signing presentation

BIP322: the Signer's presentation SHOULD resemble signing a message rather than a transaction. Creators should keep the message to a few kilobytes and commit to very large messages by hash.

- From: [BIP322 - PSBT signer; PSBT creator](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0322.mediawiki#psbt-signer)

#### GUIDE-25 (SHOULD) P2C tweak cleanup

BIP372 (Draft): Signers SHOULD remove PSBT_IN_P2C_TWEAK after PSBT_IN_PARTIAL_SIG is constructed.

- From: [BIP372 - Specification (Draft)](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0372.mediawiki#specification)

#### GUIDE-26 (SHOULD) SP DLEQ verification

BIP375: the Signer SHOULD verify the DLEQ proofs of eligible inputs it has no private keys for, or the global DLEQ proof if it is set, as REF-3 describes.

- From: [BIP375 - Signer](https://github.com/bitcoin/bips/blob/9c5b825e4ba43fab0431fa042ddb00afdf251a95/bip-0375.mediawiki#signer)

## Input Finalizer

General rules this role must enforce: GEN-SP-6.

### Precondition

#### ROLE-F-1 (MUST)

If PSBT_IN_SIGHASH_TYPE is present, the Finalizer MUST refuse to finalize an input if any of its signatures uses a different sighash type.

- Phase: Precondition
- Coverage: Partial
- Vectors: tests only
  - passes: vectors/roles.json #20
- From: [BIP174 - Input Finalizer](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#input-finalizer)
- Note: Compares the sighash types of the input's signatures: partial and Taproot signature fields, and those in a finalized key-path or legacy witness. evaluate_finalizing applies it to the input the Finalizer received, where every signature is in a labeled field. Not applicable without PSBT_IN_SIGHASH_TYPE or without a signature.
- Not decided: An input already finalized with a Taproot script path is Incomplete, because its witness does not say which items are signatures. Finalized P2WSH spends are not searched.

#### ROLE-F-2 (MUST)

Before finalizing an input with PSBT_IN_SP_TWEAK, the Finalizer MUST require PSBT_IN_TAP_KEY_SIG.

- Phase: Precondition
- Coverage: Full
- Vectors: corpus
  - isolates: vectors/roles.json #29: Silent payment tweak without a taproot key path signature
  - isolates: vectors/roles.json #30: Silent payment tweak without a taproot key path signature, BIP-376 not enabled
- From: [BIP376 - Input Finalizer](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0376.mediawiki#input-finalizer)
- Note: Checks the input the Finalizer receives: one with PSBT_IN_SP_TWEAK must have PSBT_IN_TAP_KEY_SIG.

#### ROLE-F-3 (MUST)

Before finalizing an input, the Finalizer MUST verify each PSBT_IN_TAP_KEY_SIG and PSBT_IN_TAP_SCRIPT_SIG it uses as REF-5 describes.

- Phase: Precondition
- Coverage: Full
- Vectors: corpus
  - isolates: vectors/roles.json #23: 64-byte taproot key path signature with PSBT_IN_SIGHASH_TYPE SIGHASH_DEFAULT
  - isolates: vectors/roles.json #24: 65-byte taproot key path signature with PSBT_IN_SIGHASH_TYPE SIGHASH_ALL
  - isolates: vectors/roles.json #28: Silent payment tweak with a taproot key path signature
- From: [BIP174 - Input Finalizer; BIP371](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#input-finalizer)
- Note: Performed with BIP340 through crate::signature. The BIP341 signature message is computed from the unsigned transaction and every input's spent output (only this input's for ANYONECANPAY); missing data returns Incomplete.

#### ROLE-F-4 (MUST)

Before finalizing an input, the Finalizer MUST verify each PSBT_IN_PARTIAL_SIG it uses as REF-5 describes.

- Phase: Precondition
- Coverage: Full
- Vectors: corpus
  - isolates: vectors/roles.json #21: SIGHASH_ALL signature with PSBT_IN_SIGHASH_TYPE SIGHASH_ALL
  - isolates: vectors/roles.json #22: SIGHASH_SINGLE signature without PSBT_IN_SIGHASH_TYPE
  - passes: vectors/roles.json #20
- From: [BIP174 - Input Finalizer](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#input-finalizer)
- Note: Performed with ECDSA (k256) over the BIP143 signature message for a P2WPKH or P2WSH spend, bare or inside P2SH, and the legacy message otherwise. The signature must be strict DER; a high S is accepted, as consensus does. A missing UTXO, redeem script or witness script, a script code with OP_CODESEPARATOR, or a witness version above 0 returns Incomplete. Runs after ROLE-F-3 and ROLE-F-5.

#### ROLE-F-5 (MUST)

Before finalizing an input, the Finalizer MUST verify each PSBT_IN_MUSIG2_PARTIAL_SIG it would aggregate as REF-5 describes.

- Phase: Precondition
- Coverage: Partial
- Vectors: tests only
- From: [BIP373 - Finalizer; BIP327](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0373.mediawiki#finalizer)
- Note: Performed with BIP327 PartialSigVerify (the musig2 crate) for every session with no aggregated signature. A session missing a participant's nonce, or whose plain key cannot be related to a listed aggregate key, is Incomplete.
- Not decided: A BIP328 derivation is found only through a PSBT_IN_TAP_BIP32_DERIVATION with the aggregate key's fingerprint, not a synthetic PSBT_GLOBAL_XPUB.

### Result

#### ROLE-F-6 (MUST)

For each input with enough data to pass validation, the Finalizer MUST construct its finalized scriptSig and scriptWitness fields as applicable.

- Phase: Result
- Coverage: Partial
- Vectors: tests only
- From: [BIP174 - Input Finalizer](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#input-finalizer)
- Note: Checks a finalized input against its spent script. P2PKH and P2WPKH must reveal a key that hashes to the committed hash; P2SH and P2WSH must reveal a script that hashes to the commitment; wrapped segwit uses a scriptSig of only the redeem script push; native segwit has no scriptSig; P2TR has a witness and no scriptSig. A matching template is not Verified on its own: a P2PKH or P2WPKH signature, bare or inside P2SH, is verified with ECDSA as ROLE-F-4 does, and P2SH, P2WSH and Taproot script-path spends are Incomplete because script satisfaction is not checked. A Taproot key-path spend is Verified here; ROLE-F-10 verifies its signature. Other spent scripts, or a missing UTXO, return Incomplete. evaluate_finalizing applies it to every input whose final fields the Finalizer set or changed, and fails an input whose final fields it removed. Whether every input with enough data was finalized is not checked.
- Not decided: Does not execute scripts, so script-hash and Taproot script-path spends are Incomplete rather than Verified; does not determine which inputs had enough data to finalize.

#### ROLE-F-7 (MUST)

When clearing finalized input metadata, the Finalizer MUST retain existing PREVIOUS_TXID, OUTPUT_INDEX, SEQUENCE, REQUIRED_TIME_LOCKTIME and REQUIRED_HEIGHT_LOCKTIME fields.

- Phase: Result
- Coverage: Full
- Vectors: tests only
- From: [BIP370 - Input Finalizer](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0370.mediawiki#input-finalizer)
- Note: Supply before and after contexts for the same input. Only fields present before finalization are required to be retained; optional fields do not become mandatory.

#### ROLE-F-8 (MUST)

For an input with PSBT_IN_SP_TWEAK, the Finalizer MUST construct a single-element PSBT_IN_FINAL_SCRIPTWITNESS from its PSBT_IN_TAP_KEY_SIG, and remove PSBT_IN_TAP_KEY_SIG.

- Phase: Result
- Coverage: Full
- Vectors: tests only
- From: [BIP376 - Input Finalizer](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0376.mediawiki#input-finalizer)
- Note: Compares the input before and after finalizing. The final witness must be exactly one element equal to the PSBT_IN_TAP_KEY_SIG it had, with no annex, and that field must be gone. GEN-SP-6 rejects a finalized input that keeps PSBT_IN_SP_TWEAK or PSBT_IN_SP_SPEND_BIP32_DERIVATION.

#### ROLE-F-9 (MUST)

For an input finalized via script path, the final witness MUST consist of the script inputs, followed by the leaf script and control block.

- Phase: Result
- Coverage: Full
- Vectors: tests only
- From: [BIP371 - Specification](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0371.mediawiki#specification)
- Note: After removing an annex, a P2TR final witness with two or more elements must end with a leaf script and a control block that commit to the spent output key. Field cleanup is BIP174 guidance and is not checked here.

#### ROLE-F-10 (MUST)

For a P2TR input finalized via key path, the final witness MUST be a single signature, followed by any annex, that verifies against the spent output key.

- Phase: Result
- Coverage: Full
- Vectors: tests only
- From: [BIP341 - Script validation rules; BIP174 - Input Finalizer](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0341.mediawiki#script-validation-rules)
- Note: Applies to a P2TR final witness with one element after removing any annex. The signature is checked against the spent output key with the annex committed; missing transaction data returns Incomplete.

### Guidance

#### GUIDE-11 (SHOULD) General finalization cleanup

Empty scriptSig and nonexistent scriptWitness final fields SHOULD remain unset. Other input metadata SHOULD be cleared except UTXOs, unknown fields and fields retained by the version or extension rules.

- From: [BIP174 - Input Finalizer](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#input-finalizer)
- Note: This general cleanup recommendation does not weaken the mandatory three-field SP cleanup in ROLE-F-8.

#### GUIDE-12 (SHOULD) Taproot finalization cleanup

BIP371: after constructing PSBT_IN_FINAL_SCRIPTWITNESS, Finalizers SHOULD remove PSBT_IN_TAP_KEY_SIG, PSBT_IN_TAP_SCRIPT_SIG, PSBT_IN_TAP_LEAF_SCRIPT, PSBT_IN_TAP_BIP32_DERIVATION, PSBT_IN_TAP_INTERNAL_KEY and PSBT_IN_TAP_MERKLE_ROOT.

- From: [BIP371 - Specification](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0371.mediawiki#specification)
- Note: A recommendation; no validator fails a PSBT that keeps these fields.

## Transaction Extractor

General rules this role must enforce: GEN-SP-3, GEN-SP-5.

### Precondition

#### ROLE-X-1 (MUST)

The Extractor MUST extract only when every input has the final fields its spend needs and the version-specific fields can build the transaction.

- Phase: Precondition
- Coverage: Partial
- Vectors: corpus
  - isolates: vectors/roles.json #15: PSBTv2 with an input that is signed but not finalized
  - isolates: vectors/roles.json #16: PSBTv2 with an empty PSBT_OUT_SCRIPT
  - isolates: vectors/roles.json #17: PSBTv2 with a finalized unsigned input and a silent payment output without a script
  - isolates: vectors/roles.json #19: BIP-174 combiner result, not finalized
  - passes: vectors/roles.json #14 #18
- From: [BIP174 - Transaction Extractor](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#transaction-extractor)
- Note: The linked check tests final-field presence and some v2 transaction fields, without constructing the transaction or establishing spend satisfaction. It currently rejects present empty output scripts.
- Not decided: Tests final-field presence and some version 2 fields; it does not build the transaction or establish that each spend is satisfied.

## Combiner

### Precondition

#### ROLE-B-1 (MUST NOT)

A Combiner MUST NOT combine PSBTs whose transaction identifiers differ.

- Phase: Precondition
- Coverage: Full
- Vectors: corpus
  - isolates: vectors/roles.json #38: PSBTs for different transactions
  - isolates: vectors/roles.json #39: PSBTv2s with different required lock times
  - passes: vectors/roles.json #31 #32 #33 #34 #35 #36 #37 #43 #45 #47
- From: [BIP174 - Combiner](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#combiner)
- Note: Validate each source and result before comparing identifiers. Equal identifiers do not establish a consistent metadata merge; apply ROLE-B-2 separately.

### Result

#### ROLE-B-2 (MUST)

A successful combination MUST preserve source key-value data in the corresponding maps. For conflicting duplicate keys, choose a supplied value or fail. Fail where a consistent merge cannot be produced.

- Phase: Result
- Coverage: Partial
- Vectors: corpus
  - isolates: vectors/roles.json #40: Combined PSBT drops the second signer's partial signatures
  - isolates: vectors/roles.json #41: Combined PSBT adds partial signatures neither PSBT holds
  - isolates: vectors/roles.json #42: PSBTv2s whose PSBT_IN_SEQUENCE conflicts, combined to a third sequence
  - passes: vectors/roles.json #31 #32 #33 #34 #35 #36 #37 #43 #45 #47
- From: [BIP174 - Combiner](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#combiner)
- Note: The linked check preserves source keys and selects supplied values after identity comparison. It does not establish comprehensive consistency between merged metadata fields.
- Not decided: Key preservation and supplied-value selection exist; comprehensive merge consistency is not established.

## Definitions

### PSBT version

The value of PSBT_GLOBAL_VERSION, or 0 when the field is absent.

- From: [BIP174 - Version Numbers](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#version-numbers)

### Known field

A field whose key type the field registry below lists for its map. Other key types are unknown fields.

- From: [BIP174 - Specification](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#specification)

### Spent output

The output an input spends: its PSBT_IN_WITNESS_UTXO, or else the output of its PSBT_IN_NON_WITNESS_UTXO at the input's output index.

- From: [BIP174 - Specification](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#specification)

### Finalized input

An input with PSBT_IN_FINAL_SCRIPTSIG or PSBT_IN_FINAL_SCRIPTWITNESS.

- From: [BIP174 - Input Finalizer](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#input-finalizer)

### Added signature

A signature in an input of the PSBT a role returned that the same input of the PSBT it received did not have.


### Modification flags

Inputs Modifiable, Outputs Modifiable and Has SIGHASH_SINGLE are bits 0, 1 and 2 of PSBT_GLOBAL_TX_MODIFIABLE.

- From: [BIP370 - Specification](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0370.mediawiki#specification)

### Transaction identifier

For version 0, the txid of PSBT_GLOBAL_UNSIGNED_TX. For version 2, the txid of the unsigned transaction BIP370 builds for unique identification. Under BIP375, an output's PSBT_OUT_SP_V0_INFO is used in place of its PSBT_OUT_SCRIPT when building that transaction.

- From: [BIP370 - Unique Identification; BIP375 - Unique Identification](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0370.mediawiki#unique-identification)

### BIP322 PSBT

A PSBT with PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE whose first input spends output 0 of the to_spend transaction for that message and the input's spent script, and whose only output is a zero-value OP_RETURN. Recognition needs the first input's spent output; without it, the rules about BIP322 PSBTs are Incomplete.

- From: [BIP322 - PSBT signer](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0322.mediawiki#psbt-signer)

### Silent-payment output

An output with PSBT_OUT_SP_V0_INFO.

- From: [BIP375 - Specification](https://github.com/bitcoin/bips/blob/9c5b825e4ba43fab0431fa042ddb00afdf251a95/bip-0375.mediawiki#specification)

### Scan key and spend key

The two public keys of a silent payment address. The sender combines the scan key with its inputs' keys to derive a shared secret; the output pays the spend key tweaked by that secret.

- From: [BIP352 - Overview](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0352.mediawiki#overview)

### Silent payment code

The address a recipient publishes, encoding its scan key and spend key. A PSBT carries the two keys in PSBT_OUT_SP_V0_INFO.

- From: [BIP352 - Address encoding](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0352.mediawiki#address-encoding)

### Label

An integer m the recipient uses to tweak its spend key, so payments to one scan key can be told apart. Label 0 is reserved for change; PSBT_OUT_SP_V0_LABEL carries it.

- From: [BIP352 - Overview](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0352.mediawiki#overview)

### ECDH share

A scan key multiplied by an input's private key (PSBT_IN_SP_ECDH_SHARE) or by the sum of the eligible inputs' private keys (PSBT_GLOBAL_SP_ECDH_SHARE). Shares let the output script be computed without revealing private keys to whoever computes it.

- From: [BIP375 - Specification](https://github.com/bitcoin/bips/blob/9c5b825e4ba43fab0431fa042ddb00afdf251a95/bip-0375.mediawiki#specification)

### DLEQ proof

A proof that an ECDH share was made with the same private key as a public key, without revealing that key (PSBT_IN_SP_DLEQ, PSBT_GLOBAL_SP_DLEQ). It lets other parties check a share they did not make.

- From: [BIP374 - Specification](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0374.mediawiki#specification)

### Eligible input

An input whose key contributes to the BIP352 shared secret: a P2PKH, P2WPKH, P2SH-P2WPKH or P2TR spend, except a P2TR spend that shows its internal key is the BIP341 NUMS point.

- From: [BIP352 - Inputs For Shared Secret Derivation](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0352.mediawiki#inputs-for-shared-secret-derivation)

## Procedures

### REF-1 Locktime determination

Use the shared locktime type supported by all constrained inputs and take its maximum. Prefer height when both types work. With no input requirement, use fallback locktime, or zero if absent.

- From: [BIP370 - Determining Lock Time](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0370.mediawiki#determining-lock-time)

### REF-2 SP derivation context

For output derivation, select at least one eligible input. Use the scan key’s global ECDH share, or sum the matching shares from all eligible inputs. Public keys and eligibility must be established for the inputs included in the computation.

- From: [BIP375 - Computing The Output Scripts](https://github.com/bitcoin/bips/blob/9c5b825e4ba43fab0431fa042ddb00afdf251a95/bip-0375.mediawiki#computing-the-output-scripts)
- Note: Derivation requires complete eligible-input context. Missing public keys or shares cannot count as successful derivation.

### REF-3 DLEQ verification

Global verification uses the sum of all eligible-input public keys; per-input verification uses that input’s key. Use the matching scan key, share and proof with BIP374 VerifyProof.

- From: [BIP375 - Verifying The Dleq Proof](https://github.com/bitcoin/bips/blob/9c5b825e4ba43fab0431fa042ddb00afdf251a95/bip-0375.mediawiki#verifying-the-dleq-proof)
- Note: A proof check requires the matching proof and complete verification inputs. Summing only recoverable public keys or trusting unrelated derivation keys does not establish the required aggregate key.

### REF-4 SP output ordering

Assign k per scan key after sorting silent-payment codes lexicographically. Break identical-code ties by ascending output index, then derive the BIP352 script using the selected shared secret.

- From: [BIP375 - Computing The Output Scripts](https://github.com/bitcoin/bips/blob/9c5b825e4ba43fab0431fa042ddb00afdf251a95/bip-0375.mediawiki#computing-the-output-scripts)
- Note: The ordering stated here follows BIP375 prose. The published helper uses output-map ordering, which can produce different results.

### REF-5 Signature verification

PSBT_IN_PARTIAL_SIG: an ECDSA signature by its public key under the BIP143 signature message for a segwit v0 spend, or the legacy message otherwise. PSBT_IN_TAP_KEY_SIG: a BIP340 signature by the spent output key under the BIP341 key-path message for its hash type. PSBT_IN_TAP_SCRIPT_SIG: a BIP340 signature by its x-only key under the BIP341 script-path message for its leaf. PSBT_IN_MUSIG2_PARTIAL_SIG: BIP327 PartialSigVerify under its session's aggregate key, tweaks and nonces.

- From: [BIP174 - Specification; BIP341; BIP327](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0174.mediawiki#specification)

### REF-6 DNSSEC proof validation

Validate the RFC 9102 chain from the DNS root to the name's TXT records. Each RRSIG's inception is no later than the current time and its expiry no earlier than it, or up to an hour earlier only when a delay between construction and signing is likely. Ignore TXT records not beginning with "bitcoin:", and refuse the proof if more than one does.

- From: [BIP353 - Resolution](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0353.mediawiki#resolution)

### REF-7 SP spend key

Take P from the input's P2TR PSBT_IN_WITNESS_UTXO. Compute d = (b_spend + tweak) mod n, and negate d when dG has odd y. The key matches when x(dG) equals P.

- From: [BIP376 - Signer](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0376.mediawiki#signer)

### REF-8 ECDH coverage

For each silent-payment output's scan key: once the output has PSBT_OUT_SCRIPT, there is a global ECDH share, or per-input shares on at least one input and every eligible input. A global share has a global DLEQ proof, the PSBT has an eligible input, every eligible input has a public key, and the proof verifies for the sum of those keys, the scan key and the share. An eligible input's share has a DLEQ proof, the input has a public key, and the proof verifies for that key, the scan key and the share.

- From: [BIP375 - Test Vectors](https://github.com/bitcoin/bips/blob/9c5b825e4ba43fab0431fa042ddb00afdf251a95/bip-0375.mediawiki#test-vectors)

### REF-9 Input eligibility

With silent-payment outputs, no input spends a SegWit version 2 or later output, PSBT_IN_SIGHASH_TYPE is SIGHASH_ALL (or SIGHASH_DEFAULT on a P2TR input), and every signature uses SIGHASH_ALL (or SIGHASH_DEFAULT for a 64-byte Schnorr signature).

- From: [BIP375 - Test Vectors](https://github.com/bitcoin/bips/blob/9c5b825e4ba43fab0431fa042ddb00afdf251a95/bip-0375.mediawiki#test-vectors)

### REF-10 Output scripts

A silent-payment output with PSBT_OUT_SCRIPT has the ECDH shares and input public keys its derivation needs (REF-2), and its script is the BIP352 output script, with k assigned as REF-4 describes.

- From: [BIP375 - Test Vectors](https://github.com/bitcoin/bips/blob/9c5b825e4ba43fab0431fa042ddb00afdf251a95/bip-0375.mediawiki#test-vectors)

### REF-11 BIP376 spend fields

A finalized input keeps neither PSBT_IN_SP_TWEAK nor PSBT_IN_SP_SPEND_BIP32_DERIVATION. An input with PSBT_IN_SP_SPEND_BIP32_DERIVATION has PSBT_IN_SP_TWEAK. An input with PSBT_IN_SP_TWEAK has a PSBT_IN_WITNESS_UTXO whose script is P2TR. Every spend key, plus the tweak times G, has the x-coordinate of the spent P2TR output key.

- From: [BIP376 - Specification](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0376.mediawiki#specification)
