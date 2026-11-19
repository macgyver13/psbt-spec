# The attribute command

Protocol string: `psbt-spec.attribute/1`. Schema:
[`attribute.schema.json`](attribute.schema.json).

`psbt-spec attribute` answers one question: given a PSBT (or what a role was
given and what it returned) and a task, which rules does it fail? It is what
bip375-interop calls so that judge splits and findings cite rule IDs,
and what `evaluate` and `vectors` use internally. It runs the
reference checks' all-failures entry points; it judges nothing about a project.

## Invocation

```
psbt-spec attribute
```

JSON lines on stdin, one result line per request on stdout, in order, the
same framing as the adapter contract. One call can be a single line
(`echo '{...}' | psbt-spec attribute`), or a caller can keep the process
open and stream requests, as interop does with providers. The command exits
0 at end of input. A request that cannot be attributed gets an error line;
it never stops the stream.

## Hello

Optional. It gives the caller the revision to record with each attribution:

```json
{"id": 0, "task": "hello"}
{"id": 0, "protocol": "psbt-spec.attribute/1", "spec": {"revision": "e536919afd9605fa2ff2b54f05d4b5ef0061d6c7", "dirty": false, "status": "Draft. Rule IDs may change until version 1.0."}}
```

## Requests

Every request has `task` and `bips`, and may have `id` (string or integer,
echoed). The PSBT fields follow the adapter contract: `psbt` is what the
role was given, `sources` what a Combiner was given, and `returned` what the
role gave back.

| Task | Fields | Certifier entry point | Rules evaluated |
|---|---|---|---|
| `deserialize` | `psbt` | `failing_rules` | General |
| `create` | `returned`, `delegates_additions` | `failing_rules_creating` | General on `returned`, then Creator |
| `construct` | `psbt`, `returned`, optional `intended_timelocks` | `failing_rules_constructing` | General on both, then Constructor |
| `sign` | `psbt` | `failing_rules_for_signing`, once per input, signature kind inferred from the spent script | General, then Signer Preconditions |
| `sign` | `psbt`, `returned` | `failing_rules_signing` | General on both, Signer Preconditions on each input it signed, Signer Results |
| `finalize` | `psbt` | `failing_rules_for_finalizing` | General, then Finalizer Preconditions on each unfinalized input |
| `finalize` | `psbt`, `returned` | `failing_rules_finalizing` | General on both, then the Finalizer rules on each input it finalized |
| `extract` | `psbt` | `failing_rules_extracting` | General, then Extractor Preconditions |
| `combine` | `sources`, `returned` | `failing_rules_combining` | General on every source and on `returned`, then Combiner |

As in the first-failure entry points, a role's own rules run only when the
General rules pass on every PSBT it is given and returned. A rule behind a
failed prerequisite is not listed.

- `bips`: the adapter contract's numbers. 174 and 370 are accepted and do
  not gate anything (the reference checks read the version from the PSBT). 372, 375
  and 376 enable their rules. 322, 353, 371 and 373 are always checked. Any
  other number is an error, so a caller cannot mistake "psbt-spec has no
  rules for this BIP" for "no failures".
- `delegates_additions` (`create`, required): the Creator hands the PSBT to
  others to add inputs or outputs (ROLE-C-2).
- `intended_timelocks` (`construct`, optional): `[{"input": 2,
  "requires_locktime": true}]`, by input index in `returned`, for the inputs
  the Constructor added. Absent, ROLE-C-4 is Incomplete.

Fields a task does not list are an error, not ignored, so a caller learns
when it sent a pair to a task that only reads one PSBT.

## Results

```json
{"id": 1, "failed": ["GEN-T-2", "GEN-SP-2"], "incomplete": []}
{"id": 5, "error": "create needs delegates_additions"}
```

- `failed`: rule IDs reported Failed, in evaluation order, without repeats.
- `incomplete`: rule IDs reported Incomplete and Failed nowhere, in
  evaluation order. A rule Failed on one input and Incomplete on another is
  in `failed` only.
- `error`: the request could not be attributed (not JSON, schema violation,
  bad base64, unknown BIP). Bytes that are valid base64 but not a PSBT are
  not an error: they fail GEN-F rules.

The caller decides what a rule means for it with `rules.json` (category,
phase, strength). `report.md` shows how `evaluate` splits refusal rules from
Result rules.

## Incomplete versus Failed

Decision: attribution keeps the two apart. The `failing_rules*` functions
return a struct with both lists, `failed` and `incomplete`.

Why: principle 14 says missing context is never a violation, and Incomplete
is exactly missing context (a script's satisfaction, a Constructor's
intended locktimes). Merging the two would let a vector "isolate" a rule the
reference checks could not decide, and would let `evaluate` call a project LOOSER
for accepting a PSBT that may be fine.

What it means:

- Isolation uses `failed` only. A vector isolates rule R when R is its only
  refusal rule (or, for a result vector, its only Result rule). Incomplete
  rules beside it are listed in the report row notes.
- A vector whose `failed` is empty but `incomplete` is not is class
  `undecided`: a triage item with no rule evidence, like a vector that fails
  nothing. The corpus field `outcome: "incomplete"` labels such a vector.
- `corpus.rs` compares the labeled `rule` with `failed`, or with
  `incomplete` when the vector has `outcome: "incomplete"`.
- A project's returned PSBT gets LOOSER only for `failed` rules.

Checked against today's corpus (2026-11-11, at `e536919`, with a throwaway
probe that ran the same graphs as `failing_rules*` and kept the trace
statuses apart): no vector in the seven schema v1 files, valid or invalid,
has any Incomplete rule. None of the eight `confounded:` notes rests on an
Incomplete rule; every rule they name is Failed. So the split changes no
current result. Separately, the refusal and Result split in `report.md`
shows that two of the eight notes (`roles.json#38` and `#39`, ROLE-B-1 with
ROLE-B-2) are not confounded for evaluation: both isolate ROLE-B-1.

## Interop use

A hop in an interop case maps to a request like this (E4 item 18 settles
the details):

| Interop | attribute request |
|---|---|
| `create` hop | `deserialize` on the hop's PSBT. The coordinator creates and constructs in one step, with no received PSBT for `construct`. |
| `contribute`, `resolve`, `sign`, `spend` hops | `sign` with the PSBT before the hop as `psbt` and after it as `returned` |
| `finalize` hop | `finalize` with `psbt` and `returned` |
| `extract` hop | `extract` with the PSBT it was given |
| a judge split on a snapshot | `deserialize` on the snapshot |

BIP-375 has the Signer add ECDH shares and then the output scripts, which
also clears TX_MODIFIABLE bits. Whether ROLE-S-9 ("the Signer MUST only
add data") reads that correctly over a `resolve` hop needs a check in E4
before interop relies on it.

## Worked example

From [`examples/attribute-session.jsonl`](examples/attribute-session.jsonl),
which holds the full lines; the results are the reference checks' real output at
`e536919` (computed with the probe described above). PSBTs are shortened
here.

```
> {"id": 0, "task": "hello"}
< {"id": 0, "protocol": "psbt-spec.attribute/1", "spec": {"revision": "e536919afd9605fa2ff2b54f05d4b5ef0061d6c7", "dirty": false, "status": "Draft. Rule IDs may change until version 1.0."}}
> {"id": 1, "task": "deserialize", "bips": [370, 375], "psbt": "cHNidP8BAgQCAAAA..."}
< {"id": 1, "failed": ["GEN-T-2", "GEN-SP-2"], "incomplete": []}
> {"id": 2, "task": "combine", "bips": [174], "sources": ["cHNidP8BAJoCAAAA...", "cHNidP8BAD8CAAAA..."], "returned": "cHNidP8BAJoCAAAA..."}
< {"id": 2, "failed": ["ROLE-B-1", "ROLE-B-2"], "incomplete": []}
> {"id": 3, "task": "combine", "bips": [370], "sources": ["cHNidP8BAgQCAAAA...", "cHNidP8BAgQCAAAA..."], "returned": "cHNidP8BAgQCAAAA..."}
< {"id": 3, "failed": [], "incomplete": []}
> {"id": 4, "task": "finalize", "bips": [370], "psbt": "cHNidP8BAgQCAAAA..."}
< {"id": 4, "failed": ["ROLE-F-1", "ROLE-F-4"], "incomplete": []}
> {"id": 5, "task": "create", "bips": [370], "returned": "cHNidP8BAgQCAAAA..."}
< {"id": 5, "error": "create needs delegates_additions"}
```

1. `bip375.json#5`, TX_MODIFIABLE non-zero once PSBT_OUT_SCRIPT is set: two
   General rules fail (its corpus note says "confounded: also fails
   GEN-SP-2").
2. `roles.json#38`, PSBTs for different transactions, with the corpus's
   combined PSBT: ROLE-B-1 (Precondition) and ROLE-B-2 (Result).
3. `roles.json#42`'s sources with `roles.json#37`'s combined PSBT as
   `returned`: a correct combination of the same sources fails nothing.
   With `#42`'s own PSBT it fails ROLE-B-2, which is how the report example
   finds the LOOSER.
4. `roles.json#25`, SIGHASH_ALL signature with PSBT_IN_SIGHASH_TYPE
   SIGHASH_ALL|ANYONECANPAY, Preconditions only: two Finalizer rules.
5. A `create` request without `delegates_additions` (the PSBT is
   `roles.json#5`): an error line. The schema rejects this request too.
