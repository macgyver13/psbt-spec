# psbt-spec

An evaluation tool for the PSBT BIPs. Projects such as wallets, libraries and
vector generators use it to judge their own compliance with the BIPs by rule
ID: each rule has a stable ID, its BIP evidence, a strength and a coverage
value, so a report can say which rules a project matches, over-enforces or
misses. It specifies PSBT versions 0 and 2, including silent payments under
BIP-375 and BIP-376. Extension rules cover
Taproot (BIP-371), MuSig2 (BIP-373), DNS payment proofs (BIP-353), message
signing (BIP-322), and pay-to-contract (BIP-372).

The `evaluate`, `vectors` and `attribute` commands run a project against the
vectors through an adapter ([`docs/adapter.md`](docs/adapter.md)) and write a
per-rule report ([`docs/report.md`](docs/report.md)). The rulebook
(`spec.html`, `rules.json`), the vectors and these commands are the product.
The Rust reference checks described below prove that each vector isolates the
rule it claims and trace which rules a PSBT fails. They are not a public
checking API. [`ROADMAP.md`](ROADMAP.md) lists what is next.

[`PRINCIPLES.md`](PRINCIPLES.md) states how the specification decides what a
rule is and how it is worded, checked, tested and audited.

[`rust/src/spec.rs`](rust/src/spec.rs) is the source of truth. It declares
every rule, definition, reference and guidance entry once, in display order,
with its normative strength (MUST, MUST NOT, SHOULD, MAY), each rule's coverage
(Full, Partial, Declared, Pending), its BIP evidence, its wording and an
optional reader note. The graphs below the declarations bind checks to rules
with `check!(id, validator)` inside `section`, `all`, `each`, `with`, `when`,
and BIP gates, in evaluation order. A rule may be bound at several points, as
GEN-F-5 is for the global, input and output maps; an unknown or undeclared ID
fails the build.

[`rust/src/catalog.rs`](rust/src/catalog.rs) holds the declaration types, the
preamble, the open questions and the import history, and joins declarations
with the graph bindings. `spec::specification()` joins that metadata with
the rule descriptions to generate [`spec.html`](spec.html). Neither the
specification nor the renderer parses JSON.

The HTML's Validation column links each rule binding beside its statement and
shows its coverage. Reader-facing implementation notes describe material
prerequisites and coverage limits.
Coverage, not the presence of a binding, says how much of a statement its check
decides.

## New rule set

| Designation | Meaning | Examples |
|---|---|---|
| `GEN-<section>-<number>` | Properties of a PSBT under the applicable version and extensions | `GEN-F-5`, `GEN-ST-1`, `GEN-SP-1`, `GEN-TR-1` |
| `ROLE-<role>-<number>` | Duties or prerequisites at the named operation | `ROLE-C-3`, `ROLE-S-1`, `ROLE-F-7` |
| `REF-<number>` | Procedures the rules cite | `REF-1`, `REF-5` |
| `GUIDE-<number>` | Recommendations and permitted actions | `GUIDE-1`, `GUIDE-2` |

Definitions have no ID; the page lists them by term. The General sections are
Framing (`F`, bytes, records and field formats), Structure (`ST`, version,
version fields and map count), Transaction (`T`), and the extensions.

Extension sections use short names: `SP` (BIP-375/376), `TR` (BIP-371), `MS`
(BIP-373), `DNS` (BIP-353), `MSG` (BIP-322), and `P2C` (BIP-372). Role statements
continue the `ROLE-<role>-<number>` sequence.

Published normative strengths are preserved. Guidance IDs identify entries without
changing their SHOULD or MAY wording. Display order is not the order the reference checks run. The scope covers versions
0 and 2, with an absent `PSBT_GLOBAL_VERSION` meaning version 0.

Open questions, when there are any, are listed at the top of `spec.html`. Creator, Constructor, Updater, private-key signing, script construction,
and missing-context outcomes require implementation work beyond the current APIs.

## Implementation

The combinators follow [Hornet's consensus specification](https://hornetnode.org/spec.html).
A rule's ID is the error code its check reports. BIP-375 and BIP-376 semantics are
explicitly enabled through `Bip`.

The catalog graphs are evaluated with explicit `Incomplete` and `NotApplicable`
outcomes by `evaluate` (General rules), `evaluate_for_signing` (one selected
input), `evaluate_for_finalizing` (the Finalizer's preconditions on a lone
PSBT), and one entry point per role with executable rules: `evaluate_creating`,
`evaluate_constructing`, `evaluate_signing`, `evaluate_finalizing`,
`evaluate_extracting` and `evaluate_combining`. Each runs the General rules on
every PSBT involved, then the role's Precondition rules on what it received and
its Result rules on what it returned. The Updater's only rule (ROLE-U-1) is
not observable in a PSBT, so an Updater's output is checked with `evaluate`.

Every registered field is known and syntax-checked whatever `Bip` list the caller
passes; `Bip` enables extension semantics only. A check run with no BIP enabled
therefore rejects malformed BIP-375/376 fields, and without BIP-375 an output's
`PSBT_OUT_SP_V0_INFO` does not stand in for `PSBT_OUT_SCRIPT`.

## Build and verify

```bash
cd rust
cargo run --bin render > ../spec.html
cargo run --bin render -- --json > ../rules.json
cargo run --bin render -- --markdown > ../rules.md
cargo test
```

`spec.html` lists the General rules, then each role's Precondition rules,
Result rules and guidance, with filters by strength, BIP and text. Field
names in rule text link to the field registry, whose rows list the rules
naming each field. `rules.json` holds every declared entry (ID, wording,
strength, coverage, phase, gates, checks, evidence, note, gap, corpus) for
machine audits; [`docs/rules.md`](docs/rules.md) and its JSON Schema describe
it. `rules.md` is the same catalog as Markdown, grouped General first and then
by role, and [`llms.txt`](llms.txt) points agents at these files. Each rule's
corpus coverage (the vectors that isolate it, the valid vectors that pass it,
and a status) is computed by the certifier at render time. Function links are relative to the repository; set
`PSBT_SPEC_SOURCE_BASE` to a blob URL at a pinned commit (ending in `/`) when
rendering a copy to publish.

Tests verify catalog ID and migration integrity, rendered catalog and
validation rules, and agreement with checked-in HTML. Each vector names the
rule ID its entry point stops at. `tests/rule_ids.rs` requires every rule with
a check to be observed by ID through its entry point, both Verified and Failed.

When changing a rule, edit its declaration in `spec.rs` and regenerate the HTML.

## Publish the site

The public copy is a static site on GitHub Pages at
https://macgyver13.github.io/psbt-spec/. `.github/workflows/pages.yml` runs
the tests, renders the site at the pushed commit and deploys it on every push
to `main` (or by hand from the Actions tab). `render --site DIR` writes it: the page as
`index.html` and `spec.html`, `rules.json`, `rules.md`, `llms.txt`,
`PRINCIPLES.md`, `docs/` and the corpus files under `vectors/`. The site has
no `rust/` or `adapters/` directory, so it needs `PSBT_SPEC_SOURCE_BASE` for
the source links; set it to the published commit:

```bash
cd rust
PSBT_SPEC_SOURCE_BASE=https://github.com/macgyver13/psbt-spec/blob/$(git rev-parse HEAD)/ PSBT_SPEC_REVISION=$(git rev-parse --short HEAD) cargo run --release --bin render -- --site ../site
```

`site/` is built, not committed (`.gitignore`). A rebuild overwrites files but
does not remove ones an earlier build wrote, so start from an empty `site/`
when the file list changes. Preview it locally at http://localhost:8000:

```bash
python3 -m http.server -d site 8000
```

Pages must use GitHub Actions as its source (Settings, Pages, Build and
deployment). `tests/render.rs` builds the site and checks that every relative link in it
resolves.

## Rule and vector report

Generate a self-contained HTML report of the checked-in JSON fixtures:

```bash
cd rust
cargo run --bin coverage > ../coverage.html
```

Open the generated `coverage.html` at the repository root directly in a browser
(no web server required). `rust/src/bin/coverage.template.html` is the source
template and contains no vector data. The report filters by corpus, rule, operation scope,
status, or the Silent payments lens. Select a cell for rule wording, recorded
outcomes, prerequisite blockers, iteration indices, and documented enforcement
gaps. The lens selects rules by their source evidence; it does not disable base
validation. Vector details compare General evaluation with and without the
fixture's enabled extensions.

This report observes execution in exhaustive mode (`Trace::exhaustive`): after
a failure, independent rules and later items still run, so one fixture shows
every rule it breaks; rules in an ordered group (`seq`) or behind a context
projection stay Blocked. Outcomes are the same as without it. A successful
check can be vacuous. Each fixture's expectation names the rule its entry
point stops at; other rules' outcomes are observed, not asserted. Missing role intent or transition data is shown explicitly. Cases
constructed or mutated inside Rust tests are outside the report. Regenerate it
after changing rules or vectors; the HTML is a local artifact, not checked in.

## Evaluate a project

`psbt-spec` (`rust/src/bin/psbt-spec/`) has three commands. The contract an
adapter speaks is in [`docs/adapter.md`](docs/adapter.md), the report in
[`docs/report.md`](docs/report.md) and `attribute` in
[`docs/attribute.md`](docs/attribute.md).

```bash
cd rust
cargo run --release --bin psbt-spec -- evaluate --out DIR --corpus ../vectors/bip375.json -- ADAPTER [ARGS ...]
cargo run --release --bin psbt-spec -- vectors ../vectors/bip375.json
echo '{"task": "deserialize", "bips": [370], "psbt": "..."}' | cargo run --release --bin psbt-spec -- attribute
```

`evaluate` puts every vector of the corpus files to the adapter and writes
`DIR/report.json` and `DIR/report.md`, one verdict per (rule, operation).
`vectors` audits corpus files: the rules each vector fails against its label,
and whether it isolates its rule; it exits 1 for a vector that neither isolates
its label nor carries a triage note. `attribute` reads JSON lines and answers
which rules a PSBT fails. [`adapters/bip375-reference/`](adapters/bip375-reference)
is an adapter for the bips BIP-375 reference validator.

## Layout

- [`rust/src/spec.rs`](rust/src/spec.rs): authoritative rule graph and explicit documentation definitions.
- [`rust/src/catalog.rs`](rust/src/catalog.rs): supporting metadata and catalog assembly.
- [`rust/src/bin/render.rs`](rust/src/bin/render.rs): renders the Rust catalog, executable validation rules, and field registry.
- [`rust/src/algebra.rs`](rust/src/algebra.rs): existing validation graph combinators.
- [`rust/src/registry.rs`](rust/src/registry.rs): the field inventory: every field of the BIPs in scope, with the format GEN-F-5 enforces.
- [`rust/src/rules/`](rust/src/rules): existing validation functions.
- [`rust/src/silent_payments.rs`](rust/src/silent_payments.rs): silent-payment primitives and context recovery.
- [`vectors/`](vectors): vector corpus; the PSBT vector files follow [`corpus.schema.json`](vectors/corpus.schema.json) (schema v1): a `bip_revision`, the file's `bips` and a `vectors` array, each vector with `description`, `psbt`, `valid`, the rule ID its entry point stops at (`rule`, when invalid), whether that outcome is Incomplete (`outcome`), and a non-default entry point (`task`).
- [`vectors/bitcoin_core_sighash.json`](vectors/bitcoin_core_sighash.json): Bitcoin Core's `src/test/data/sighash.json` (`43cb41859e`), the legacy signature hash cases ECDSA verification is tested against.

## Vector generators

`vectors/derived/` holds vectors written for psbt-spec rather than published by
a BIP. The BIP-376 corpus there is generated from fixed keys.

FIXME: `gen_bip376.py` still writes the pre-schema-v1 shape (`error`, no
`valid`, no `bip_revision` wrapper); convert its output before regenerating.

```bash
PYTHONPATH=<secp256k1lab>/src python3 vectors/tools/gen_bip376.py > vectors/derived/bip376.json
```

The BIP-375 corpus follows the BIP's `bip375_test_vectors.json`. When the
BIP375 pin moves, `import_bip375.py` takes the vector file at the corpus's
current `bip_revision` and at the new revision. It replaces each vector's PSBT
and description by position, keeping its `rule`, `task` and `note`, and refuses
to write unless the old file reproduces the current corpus exactly. Run
`psbt-spec vectors ../vectors/bip375.json` afterwards to confirm every vector
still isolates its rule.

```bash
python3 vectors/tools/import_bip375.py OLD.json NEW.json vectors/bip375.json <short revision>
```

Published vectors are pinned to `bitcoin/bips` revision
`5aadddb511a5dcfe4599531bd8ae5e5b96d0f793` and are byte-identical to it:
`bip340_vectors.csv` (`bip-0340/test-vectors.csv`), `bip341_wallet_vectors.json`
(`bip-0341/wallet-test-vectors.json`), `bip322_basic.json`
(`bip-0322/basic-test-vectors.json`), and the PSBTs or proofs in `bip371.json`,
`bip373.json`, and `bip353_proofs.json` (from the BIP texts). The error codes
on invalid BIP-371 and BIP-373 vectors (`GEN-F-5`) are local assignments.

Regeneration should use an identified source revision. Preserve published,
development, and generated vector origins; matching descriptions do not establish
identical PSBT bytes.
