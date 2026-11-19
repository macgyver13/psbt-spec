# Roadmap

Planned work that is not in the current release. Each item says what it adds
and what it depends on.

## Check a PSBT in the browser

The reference checks compile to WebAssembly, so the published `spec.html`
can take a pasted PSBT, with the role and task that produced it, and list the
rules it fails, each linked to its rule. This is what `psbt-spec attribute`
does on the command line, made available to anyone reading the page and to
agents working from it, with nothing to install. The page stays static, so
it fits the same hosting as the specification.

Depends on: the checks building for `wasm32-unknown-unknown` (signature and
DNSSEC verification included), and a small page around them.

## Builder tasks in the adapter contract

Only if a side-by-side comparison of PSBT builders is wanted. The Creator,
Constructor and Updater rules are already checked on PSBTs a builder
produces (`psbt-spec attribute` with task `create` or `construct`) and on
each hop of an interoperability workflow. What builder tasks would add is the
corpus driving the builder: request shapes for `create`, `construct` and
`update` that take a description of the transaction to build, and vectors for
them, so different builders face the same cases.

## Test keys in vectors

Corpus vectors carry no private keys, so a `sign` request asks whether
signing may proceed under the rules; it cannot ask for the signature. Keys
for a published test wallet would let projects return signed PSBTs, giving
the Signer's Result rules evidence from every project.

## More implementations

An adapter for psbt-interop-lab's containerized adapters (Bitcoin Core,
rust-bitcoin, btcsuite, bitcoinjs-lib, BDK, rust-psbt, libwally and others)
would put the PSBT version 0 corpora (BIP-174, BIP-371, BIP-373) in front of
those libraries.

## 1.0

Rule IDs become append-only: never reused or redefined. Until then rules may
still be renumbered, merged or removed.
