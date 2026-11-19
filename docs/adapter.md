# Adapter contract v1

Protocol string: `psbt-spec.adapter/1`. Schema:
[`adapter.schema.json`](adapter.schema.json).

An adapter lets `psbt-spec evaluate` put corpus vectors to a project: a
wallet, a library, a vector generator's reference code, or a hardware wallet
through its host software. The adapter is a program that receives one vector
at a time, asks the project to perform one role operation on it, and says
whether the project performed it or refused. psbt-spec owns this contract;
it names role operations and BIP numbers only, so it fits any PSBT
BIP, extensions included.

## Transport

- The evaluator starts the adapter as a child process from the argv the user
  gives it, in the evaluator's working directory, with the evaluator's
  environment. One process serves the whole run.
- stdin and stdout carry UTF-8 JSON, one object per line, each line ending
  in `\n`. A line never contains a raw newline.
- The evaluator sends one line and waits for exactly one line back before it
  sends the next. There is no pipelining.
- stderr is the adapter's own. The evaluator passes it through to its own
  stderr and never parses it. Nothing but response lines may go to stdout.
- To finish, the evaluator closes stdin. The adapter exits; after 5 seconds
  the evaluator kills it.
- Requests are independent. A verdict must not depend on earlier requests.
  Keys, seeds and other project setup come from the adapter's own argv,
  environment or files, never from the contract.

## Handshake

The first request is always:

```json
{"id": 0, "task": "hello", "protocol": "psbt-spec.adapter/1"}
```

The adapter answers with what it is and what it supports:

```json
{"id": 0, "protocol": "psbt-spec.adapter/1",
 "project": {"name": "...", "version": "...", "revision": "..."},
 "adapter": {"name": "...", "version": "..."},
 "tasks": ["deserialize", "finalize"], "bips": [174, 370, 371]}
```

- `protocol`: the protocol the adapter speaks. Any other value stops the run
  (setup failure).
- `project`: the implementation under evaluation. `revision` is its source
  commit, or the firmware build when there is no commit. These go into the
  report's pins (principle 24).
- `adapter`: the adapter program, which may live in another repository than
  the project (for example a shim in psbt-spec or in bip375-interop).
- `tasks`: the tasks the adapter answers. Vectors of any other task are not
  sent; their rules are NOT IMPLEMENTED.
- `bips`: the BIPs the project supports. 174 stands for PSBT version 0 and
  370 for version 2, so a v2-only project omits 174. Every other number is an
  extension (371, 372, 373, 375, 376, ...). A vector that needs a BIP not in
  this list is not sent; it counts as NOT IMPLEMENTED evidence for its rules.
  Numbers psbt-spec has no rules for are ignored.

## Tasks

A task is one role operation. Contract v1 has the five that the corpus
exercises today.

| Task | Corpus `task` | Request carries | `accept` means | Response `psbt` on accept |
|---|---|---|---|---|
| `deserialize` | absent or `validity` | `psbt` | the project decodes the PSBT and accepts it as valid at its load or decode entry point | none |
| `sign` | `signing` | `psbt` | the project would sign this PSBT (or signed it) | optional: the signed PSBT, when the project produced one |
| `finalize` | `finalizing` | `psbt` | the project finalized the inputs it could | required: the finalized PSBT |
| `extract` | `extraction` | `psbt` | the project extracted a network transaction | none |
| `combine` | `combining` | `sources` | the project combined the sources | required: the combined PSBT |

`reject` means the project refused: it raised an error, returned a failure
code, or declined the operation. An adapter for a library that throws on bad
input maps every throw caused by the PSBT to `reject`.

For a `combining` vector the evaluator sends the vector's `combine` array as
`sources`. The vector's own `psbt` is the combined PSBT the corpus expects
(or, for an invalid vector, a wrong one); it is never sent. The project's
returned PSBT is judged by attribution instead (see `report.md`).

`sign` asks whether signing can occur under the rules: `accept` means the
project would sign, `reject` that it refuses. That verdict is judged against
the Signer's refusal rules (General rules and Signer Preconditions), as the
four `signing` vectors in `vectors/bip174.json` expect. The contract carries
no keys, so the project need not produce a signature. An adapter that does
return a signed PSBT has the Signer Result rules attributed on it; without
one, those rules are NOT RUN for the vector. Test keys in vectors, so that
libraries can produce signatures, are planned ([roadmap](../ROADMAP.md)).

Not in v1, and why:

- `create`, `construct` and `update` take a description of the transaction to
  build, not a PSBT. No corpus vector exercises them yet, and the request
  shape for them is a design of its own. Their rules (ROLE-C-1 to ROLE-C-6,
  ROLE-U-1) are NOT RUN with the note "adapter contract v1 has no create
  task". The `attribute` command does take `create` and `construct`, since
  there the caller already holds the PSBTs (see `attribute.md`).
- `extract` returns no transaction. psbt-spec has no rule that judges the
  extracted transaction, so the contract does not ask for it.

## Requests

```json
{"id": 7, "task": "finalize", "bips": [370], "psbt": "cHNidP8BAgQC..."}
{"id": 8, "task": "combine", "bips": [174], "sources": ["cHNidP8BAJoC...", "cHNidP8BAD8C..."]}
```

- `id`: 1, 2, 3, ... in order. The adapter echoes it. A response with another
  id is a protocol error.
- `task`: one of the declared tasks.
- `bips`: every BIP the vector exercises, built by the evaluator as: 174 if
  the given PSBT (the first source for `combine`) has PSBT_GLOBAL_VERSION 0,
  no version field, or cannot be read that far; 370 if it has version 2; plus
  the corpus file's `bips` and the vector's own `bips`. The adapter enables
  exactly these extensions. The evaluator sends a vector only when every
  number is in the hello `bips`.
- `psbt`: every task except `combine`. `sources`: `combine` only.

A vector can be sent more than once. An invalid `validity` vector that
isolates a General rule whose `roles` name a Signer, Input Finalizer or
Transaction Extractor is also sent as `sign`, `finalize` or `extract` (a
stage request, `report.md`), with the same `bips` and `psbt`. The request
looks like any other of that task; the adapter answers it on its own, as
every request is independent.

Encoding: PSBTs are standard base64 (RFC 4648 section 4) with `=` padding.
Invalid vectors may hold bytes that are not a PSBT at all (bad magic,
truncated maps); they are still valid base64.

## Responses

```json
{"id": 7, "verdict": "accept", "psbt": "cHNidP8BAgQC..."}
{"id": 8, "verdict": "reject", "reason": "unique ids differ", "rule": "ROLE-B-1"}
{"id": 9, "verdict": "n/a", "reason": "input type not supported"}
{"id": 10, "verdict": "error", "reason": "unexpected exception: KeyError"}
```

- `verdict`:
  - `accept` and `reject`: the project's answer.
  - `n/a`: the adapter cannot put this vector to the project although it
    declared the task and BIPs (an input type the project cannot handle at
    all, a device that needs a confirmation the emulator cannot
    give). NOT RUN for the vector.
  - `error`: the adapter itself failed. NOT RUN for the vector.
- `reason`: free text, copied into the report. Required for `n/a` and
  `error`.
- `rule`: `reject` only, optional. The psbt-spec rule ID whose property
  made the project refuse (see "Naming the rule" below). It decides whether
  the refusal is MATCH evidence and which rule a STRICTER verdict lands on.
- `psbt`: `accept` only; required for `finalize` and `combine`, optional
  for `sign`.

### Naming the rule

An adapter sets `rule` on a `reject` when, and only when, it knows which
psbt-spec rule the project refused for:

1. Take the rule from the project's own error: its error type, code or
   message, as the project reports it for this request. Do not take it from
   the vector, its description or the corpus, and do not guess it from the
   PSBT.
2. Name the rule ID whose property the project found broken: the one whose
   wording in `rules.json` states what the error says is wrong. A General
   rule keeps its General ID when a role enforces it: a Signer refusing a
   PSBT whose DLEQ proof does not verify names GEN-SP-3 (the ECDH coverage
   check, which verifies the DLEQ proofs), not a ROLE-S rule.
3. Name it only when the mapping is certain: the error is raised for that
   property and no other. When an error covers several properties, or the
   project refused for a reason psbt-spec has no rule for (a missing key, an
   input type it cannot handle, a policy of its own such as requiring the
   full previous transaction), omit `rule`. Keep the error text in `reason`
   either way.
4. Use an ID from `rules.json` at the psbt-spec revision being evaluated.

What the evaluator does with it (`report.md`, "Named rules"):

- It names the rule the vector isolates (for a confounded vector, one of the
  rules it fails): MATCH, counted as confirmed.
- It names another rule: no MATCH. The vector's rule gets NOT RUN for that
  vector, since the project refused before it was tested, and both rows get
  a note.
- It is omitted: MATCH as before, counted and noted as unconfirmed, so a
  report shows how much of its MATCH evidence the adapter confirmed.
- It is not in `rules.json`: treated as omitted, with a warning in the report.

So a wrong `rule` costs the project MATCH evidence, and a missing one only
leaves it unconfirmed. When in doubt, omit it.

Responses are judged against the schema and the task. A line that is not
JSON, does not match the schema, carries the wrong id, or omits a required
`psbt` is a protocol error.

## A minimal adapter

A deserialize-only adapter in Python. Replace `decode` with a call into your
project; everything else is the contract.

```python
import base64, json, sys

def decode(psbt: bytes) -> None:
    """Call your project's PSBT decoder here; raise if it refuses."""
    raise NotImplementedError

def answer(request):
    if request["task"] == "hello":
        return {"protocol": "psbt-spec.adapter/1",
                "project": {"name": "my-wallet", "version": "1.0", "revision": "abc123"},
                "adapter": {"name": "my-wallet-adapter", "version": "0.1"},
                "tasks": ["deserialize"], "bips": [174, 370]}
    try:
        decode(base64.b64decode(request["psbt"]))
    except Exception as error:
        return {"verdict": "reject", "reason": str(error)}
    return {"verdict": "accept"}

for line in sys.stdin:
    request = json.loads(line)
    print(json.dumps({"id": request["id"], **answer(request)}), flush=True)
```

Run it with `psbt-spec evaluate --out DIR --corpus ../vectors/roles.json --
python3 adapter.py`. To add a task, declare it in `tasks`, return the
resulting PSBT on accept where the task table requires one, and set `rule` on
a refusal when the project's error names one. The example adapters in
`adapters/` do this for a Python reference implementation (138 lines) and two
Rust libraries (265 and 325 lines).

## Errors and timeouts

| What happens | Vector outcome | Then |
|---|---|---|
| Adapter answers `error` | `error`, kind `adapter` | continue |
| No response within the timeout (default 180 s, `--timeout SECONDS`) | `error`, kind `timeout` | restart |
| stdout closes or the process exits | `error`, kind `crashed` | restart |
| Protocol error | `error`, kind `protocol` | restart |

Restart: the evaluator kills the process group, starts the adapter again and
repeats the hello. If the hello fails or declares different tasks, BIPs or
project, every remaining vector is `error` (kind `crashed`) and the report is
still written. A failed first hello is a setup failure: no report, exit
code 2.

## Versioning

- The protocol string changes major version (`psbt-spec.adapter/2`) for any
  change that a v1 peer would misread: a new required field, a changed
  meaning, a removed field or task.
- A new optional field, task or verdict a v1 peer can ignore keeps `/1`.
  Both sides ignore fields they do not know. The schema describes exactly
  what a v1 sender writes.
- psbt-spec ships one protocol version at a time until 1.0.

## Running interop providers

bip375-interop's provider protocol (`sp-interop.provider/0.1`) is also JSON
lines over stdio, so a shim is a loop that rewrites each line:

| psbt-spec | interop provider |
|---|---|
| `hello` | `hello`. `operations` gives the tasks: `judge` gives `deserialize`, `finalize` and `extract` give themselves, `sp-sign` gives `sign`. `psbtVersions` gives 174 (0) and 370 (2); 375 always, 376 when `features` has `bip376`. `implementation` `{name, version, sourceRevision}` gives `project` `{name, version, revision}`. |
| `deserialize` | `judge` with `{"psbt", "stage"}`; its verdict and reason pass through. The shim chooses the stage. |
| `finalize`, `extract` | the operation of the same name |
| `sign` | `sp-sign`, after `reset` with the shim's configured mnemonic; the shim computes `commitment` |
| status `ok` / `rejected` / `unsupported` / `crashed` or `timeout` | `accept` (with `output.psbt`) / `reject` (`error.message` as reason) / `n/a` / `error` |

Interop has no combine operation, so the shim does not declare `combine`.
The judge stage to use for `deserialize`, and whether `sp-sign` fits a vector that
was not produced by an interop case, are not settled yet.

## Worked example

From [`examples/adapter-session.jsonl`](examples/adapter-session.jsonl),
which holds the full lines and validates against the schema. PSBTs are
shortened here. The vectors are real (`vectors/roles.json`); the project is
the illustrative `example-wallet` of the report example.

```
> {"id": 0, "task": "hello", "protocol": "psbt-spec.adapter/1"}
< {"id": 0, "protocol": "psbt-spec.adapter/1", "project": {"name": "example-wallet", "version": "0.1.0", "revision": "0000000000000000000000000000000000000000"}, "adapter": {"name": "example-wallet-adapter", "version": "0.1.0"}, "tasks": ["deserialize", "finalize", "extract", "combine"], "bips": [174, 370, 371]}
> {"id": 1, "task": "deserialize", "bips": [370], "psbt": "cHNidP8BAgQCAAAA..."}
< {"id": 1, "verdict": "reject", "reason": "refused"}
> {"id": 2, "task": "deserialize", "bips": [370], "psbt": "cHNidP8BAgQCAAAA..."}
< {"id": 2, "verdict": "accept"}
> {"id": 3, "task": "finalize", "bips": [370], "psbt": "cHNidP8BAgQCAAAA..."}
< {"id": 3, "verdict": "reject", "reason": "partial signature does not verify", "rule": "ROLE-F-4"}
> {"id": 4, "task": "finalize", "bips": [174], "psbt": "cHNidP8BAF4CAAAA..."}
< {"id": 4, "verdict": "n/a", "reason": "script path finalizing not supported"}
> {"id": 5, "task": "combine", "bips": [370], "sources": ["cHNidP8BAgQCAAAA...", "cHNidP8BAgQCAAAA..."]}
< {"id": 5, "verdict": "accept", "psbt": "cHNidP8BAgQCAAAA..."}
```

| Request | Vector | Its attribution | What the evaluator records |
|---|---|---|---|
| 1 | `roles.json#6` SIGHASH_ALL signature with Inputs Modifiable set | isolates GEN-T-2 | no evidence: GEN-T-2 names the Signer in `roles`, so the parser's refusal is a note on the row GEN-T-2 / sign |
| 2 | `roles.json#9` SIGHASH_ALL\|ANYONECANPAY signature with Outputs Modifiable set | isolates GEN-T-2 | no evidence, a note as for request 1; its stage request under `sign` is withheld (the example does not declare `sign`), so NOT IMPLEMENTED for GEN-T-2 / sign |
| 3 | `roles.json#21` SIGHASH_ALL signature with PSBT_IN_SIGHASH_TYPE SIGHASH_ALL | isolates ROLE-F-4 | MATCH for ROLE-F-4, confirmed: the project named the same rule |
| 4 | `roles.json#49` Finalized taproot script path input | valid | NOT RUN |
| 5 | `roles.json#42` sources whose PSBT_IN_SEQUENCE conflicts; the project returned the vector's own combined PSBT | result vector: ROLE-B-2 | the returned PSBT fails ROLE-B-2: LOOSER for ROLE-B-2 (combine) |

Request 1 has `bips: [370]` because the vector is PSBTv2 and `roles.json`
enables no extension for it.
