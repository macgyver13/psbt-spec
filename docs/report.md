# Evaluation report v1

Format string: `psbt-spec.report/2`. Schema:
[`report.schema.json`](report.schema.json).

`psbt-spec evaluate` runs one project, through one adapter
([`adapter.md`](adapter.md)), over one or more corpus files, and writes a
report keyed by rule ID: `report.json`, and `report.md` rendered from it.

```
psbt-spec evaluate --out DIR [--timeout SECONDS] --corpus FILE [--corpus FILE ...] -- ADAPTER [ARGS ...]
```

Exit code 0 when the report is written, 2 on setup failure (unreadable or
invalid corpus file, first hello failed, protocol mismatch). Verdicts never
change the exit code: the report is the answer.

## Attribution of a vector

Before any adapter call, the reference checks attribute every vector of the
corpus under its task, with the all-failures entry points (`attribute.md`
lists them). Attribution has two lists:

- `failed`: rules reported Failed.
- `incomplete`: rules reported Incomplete and not Failed anywhere. The PSBT
  lacks the context to decide them. They are listed, never used as evidence
  (principle 14).

`failed` is then split by what the role should have done about each rule:

- Refusal rules: General rules that fail on a PSBT the role is given (for
  `combine`, on a source), and Precondition rules. A role must refuse a PSBT
  that fails one.
- Result rules: Result rules, and General rules that fail only on the
  returned PSBT. They judge what a role returned, so they only occur when the
  corpus carries a returned PSBT (today, `combining` vectors).

The phase comes from `rules.json`. The vector's class:

| Class | Condition |
|---|---|
| valid | `valid: true` |
| isolated | exactly one refusal rule |
| confounded | two or more refusal rules |
| result | no refusal rule, one or more Result rules |
| none | invalid, `failed` and `incomplete` empty |
| undecided | invalid, `failed` empty, `incomplete` not empty |

The split matters: `roles.json#38` and `#39` (Combiner sources for different
transactions) fail ROLE-B-1 (Precondition) and ROLE-B-2 (Result). The
Combiner should refuse because of ROLE-B-1; ROLE-B-2 only says the corpus's
combined PSBT is wrong too. Both vectors are isolated on ROLE-B-1, not
confounded.

## Stage requests

A General rule is a property of a lone PSBT (principle 2), but its duty
belongs to the roles its BIP text names: `roles` in `rules.json` (principle
9). GEN-SP-3 names the Signer and the Transaction Extractor; GEN-F-1 names
none. `deserialize` is not a role, so a parser that accepts a PSBT failing
GEN-SP-3 breaks no duty, while a Signer that would sign it does. So:

- A General rule with no `roles` (framing, structure and the other parser
  level rules) is judged at `deserialize`, as any rule is at its vector's
  task.
- A General rule with `roles` is judged at the tasks of those roles:
  Signer at `sign`, Input Finalizer at `finalize`, Transaction Extractor at
  `extract`. Creator and Constructor (`create`, `construct`) and Updater
  (`update`) have no task in contract v1, so those rows are NOT RUN.

The corpus asks most of these rules only as `validity` vectors. So for each
invalid `deserialize` vector isolated on a rule R with `roles`, the evaluator
also sends the vector's PSBT as the task T of each owning role in the
contract: a stage request. It is attributed under T first, and sent only when
there it is still isolated on R and the role's own rules, checked without
the General gate, fail nothing. Otherwise the role would have a reason of its
own to refuse (an Extractor given an unfinalized PSBT fails ROLE-X-1) and a
refusal would say nothing about R; the row (R, T) notes the vectors not sent
and why. A stage request is withheld like any request when T or a BIP is not
declared.

A project's answer at `deserialize` on a rule with `roles` is informational
either way. Accepting is not LOOSER, since no BIP asks a parser to refuse.
Refusing is not MATCH either, for the same reason: the parser was not asked,
and counting its refusal would let a strict parser stand in for a Signer it
may not have. It is not STRICTER, since the PSBT is invalid. Each owning
role's row carries the answers as a note ("deserialize (informational, ...):
accepted #5; rejected #6"), so a reader still sees the stage at which the
project enforces the rule. A confounded `deserialize` vector gives evidence
only on its rules with no `roles`.

Stage requests apply only to `deserialize` vectors. A vector whose own task
is a role's (a `signing` or `combining` vector failing a General rule) is
judged at that task, as before. Valid vectors get no stage request.

## Verdicts

Each row of a report gives one verdict for a rule at one task:

- MATCH: the project accepts and rejects what the rule does, at the task the
  rule names.
- STRICTER: the project rejects something the rule accepts.
- LOOSER: the project accepts something the rule rejects, or has no check.
- NOT IMPLEMENTED: the project does not declare the task or BIP the vectors
  need, so they were withheld.
- NOT RUN: no vector gave evidence for the rule. Either the corpus has no
  vector for it, or the project answered `n/a` or failed. NOT RUN is not a
  pass.

A MATCH from a refusal that named no rule is unconfirmed (see Named rules):
the project refused, but nothing shows it refused for this rule.

## Verdict rules

Per vector, from its class and the project's response:

| Vector | Project | Evidence |
|---|---|---|
| valid | accepts | LOOSER for each rule the returned PSBT fails, when the project returned one; otherwise none (counts toward the valid pass total). A `sign` accept without a returned PSBT gives NOT RUN for the Signer Result rules |
| valid | rejects | STRICTER on the rule the project names; unattributed STRICTER if it names none |
| isolated on R | rejects naming R, or no rule | MATCH for R (unconfirmed when no rule is named) |
| isolated on R | rejects naming another rule X | NOT RUN for R; a note on R and on X |
| isolated on R | accepts | LOOSER for R |
| isolated on R with `roles`, at `deserialize` | either | none; a note on each owning row (R, T) |
| stage request: isolated on R under owning task T | rejects naming R, or no rule | MATCH for (R, T) (unconfirmed when no rule is named) |
| stage request: isolated on R under owning task T | rejects naming another rule X | NOT RUN for (R, T); a note on (R, T) and (X, T) |
| stage request: isolated on R under owning task T | accepts | LOOSER for (R, T) |
| confounded on R1..Rn | accepts | LOOSER for each of R1..Rn (at `deserialize`, only those with no `roles`) |
| confounded on R1..Rn | rejects naming one of them, Ri | MATCH for Ri only (at `deserialize`, only when Ri has no `roles`); listed as confounded |
| confounded | rejects naming no rule or another rule | none for any single rule; listed as confounded |
| result, rules R1..Rn | accepts | if the returned PSBT fails nothing: MATCH for each Ri; otherwise LOOSER for each rule it fails |
| result | rejects | as for valid: STRICTER on the named rule, or unattributed |
| none or undecided | either | triage item, no rule evidence |
| any | `n/a` or `error` | NOT RUN for its attributed rules |
| any, task or a BIP not declared | not sent (withheld) | NOT IMPLEMENTED for its attributed rules |

"Naming" is the response's `rule` (`adapter.md`); an ID not in `rules.json`
counts as no rule. "Attributed rules" are the refusal rules, or the Result rules for a result
vector. "The returned PSBT fails" means the reference checks attribute the
project's returned PSBT under the vector's task, with the given PSBT (or
sources) as received, and takes the `failed` list. Its `incomplete` list is
recorded but gives no evidence. For a result vector with a returned PSBT
that has only Incomplete rules, there is no evidence either way.

`sign` is judged on refusal: the project says whether it would sign, and
that answer meets the refusal rules like any other task. The returned PSBT
is optional for `sign` only (`adapter.md`), because the contract carries no
keys. When it is absent, the vector gives NOT RUN evidence for each Signer
Result rule (ROLE-S-9, ROLE-S-10, ROLE-S-11 at `e536919`; the
evaluator takes them from `rules.json`), so the row lists the vector without
a verdict on what a signature would have looked like.

## Named rules

A refusal is MATCH evidence only if it is a refusal for the vector's rule.
Before format 2, any refusal of an isolated vector was MATCH, so a project
that refused for an unrelated reason (rust-psbt refusing BIP-375 vectors at
`sign` because it lacks the full previous transaction, `UnverifiableUtxo`)
read MATCH on the rule the vector isolates (GEN-SP-3, GEN-T-2) without ever
checking it. The adapter's `rule` (`adapter.md`, "Naming the rule") now
decides:

- **Same rule.** The project names the rule the vector isolates, or for a
  confounded vector one of the rules it fails: MATCH for that rule, counted
  as confirmed. Attribution and the project agree, so the evidence is
  checked from both sides (principle 27). A confounded vector gave no
  evidence before; a named rule that attribution confirms failing now
  gives MATCH for that rule alone.
- **Another rule X.** The vector's rule R gets NOT RUN for the vector: the
  project refused for a property the vector does not isolate, so R was not
  tested, which is what NOT RUN means for `n/a` too. NOT RUN rather than no
  evidence keeps the vector on R's row, so a row with only such vectors
  reads NOT RUN with the vectors listed, not "no vector". R's row notes
  "rejected naming X, not this rule". X gets no evidence, only a note on
  (X, T) that the project named it where attribution finds R failing.
  Not STRICTER on X: STRICTER means refusing a PSBT the rules accept, and
  this PSBT fails R, so the refusal was owed. Nor can attribution confirm
  that X holds there: the entry points stop at the first General failure,
  so a role's own rules are not evaluated on a PSBT that fails a General
  rule. Whether the project or the adapter's mapping is wrong is a
  disagreement for triage (principles 27 and 28), and the note is where a
  reader finds it.
- **No rule.** MATCH, as before, but counted as unconfirmed and noted on
  the row ("unconfirmed MATCH (project named no rule in rules.json): ...").
  Adapters opt in by naming rules; a stricter verdict would punish projects
  whose errors carry no rule-level detail.
- **A rule ID not in `rules.json`.** Treated as no rule (unconfirmed MATCH),
  with a warning note on the rows its evidence lands on ("project names
  X-9, not in rules.json (treated as no rule)") and the `unknown_rule`
  count. The ID may come from a newer or older psbt-spec revision or a typo;
  either way the evaluator cannot check it, and dropping the MATCH would
  make a typo cost more than omitting the rule.

On a valid or result vector, a named rule picks the row of the STRICTER
verdict, as before; an unknown one leaves the STRICTER unattributed, with
the same warning. A `deserialize` refusal of a vector isolated on a rule
with `roles` is informational whatever it names.

`summary.rejects` counts refusals, stage requests included: `confirmed` and
`unconfirmed` split those that gave MATCH evidence, `other_rule` counts
those of an isolated or confounded vector that named another rule in
`rules.json`, and `unknown_rule` those that named an ID not in it.

Evidence lands on the row (rule, task) of the request's task (the vector's
own, or a stage request's), so a Combiner
that accepts a source failing GEN-ST-2 is LOOSER on the row GEN-ST-2 /
combine (principle 25).

## Rows

One row per (rule, task), for these pairs:

- every General rule with no `roles`, under `deserialize`;
- every General rule with `roles`, under each task of those roles (Creator
  and Constructor gives both `create` and `construct`);
- every Role rule, under the task whose entry point evaluates it (ROLE-B
  combine, ROLE-C-1 and ROLE-C-2 create, ROLE-C-3 to ROLE-C-6 construct,
  ROLE-F finalize, ROLE-S sign, ROLE-U update, ROLE-X extract);
- every other (rule, task) that a vector's evidence names, or that a
  project named for a vector failing another rule (a row with a note only);
- one unattributed row (rule `null`) per task that has unattributed STRICTER
  evidence.

Guidance, Reference and Definition entries carry no verdict and get no row.

A row's verdict, in order:

1. LOOSER if any evidence is LOOSER, STRICTER if any is STRICTER; both
   together when both occur (as `bitcoin-core.md` does for GEN-F-5).
2. Otherwise NOT RUN, with a note, when the task is not in the adapter
   contract (create, construct, update in v1).
3. Otherwise NOT IMPLEMENTED when the adapter did not declare the task.
4. Otherwise MATCH if any evidence is MATCH.
5. Otherwise NOT IMPLEMENTED if any evidence is NOT IMPLEMENTED (vectors
   withheld for a BIP).
6. Otherwise NOT RUN.

The evaluator never gives DIFFERENT STAGE; a reader sees it by comparing a
rule's rows across tasks, and for a rule with `roles` by the informational
`deserialize` note on its owning rows.

Notes on a row record what the verdict does not show: confounded vectors the
project rejected, the reason the project gave for a STRICTER, a rule the
project named that differs from the vector's, unconfirmed MATCH evidence, a
named rule ID not in `rules.json`, Incomplete rules on its vectors,
coverage Declared, the informational `deserialize` answers on a rule with
`roles`, and stage requests not sent.

`stale` (principle 29) lists each evidence link of the row's rule into a BIP
that the row's evidence vectors exercise (their request `bips`, ignoring 174
and 370), when the link's bips commit differs from that corpus file's
`bip_revision`. The evaluator cannot tell which commit is older offline, so
it reports the difference and leaves the order to the reader.

## Pins

Per run (principle 24):

- `spec`: psbt-spec commit (40 hex), whether tracked files were modified,
  and the `rules.json` status line.
- `project`: name, version and revision from the adapter's hello.
- `adapter`: name and version from the hello, and the protocol.
- `declared`: the tasks and BIPs from the hello.
- `started`, `finished`: RFC 3339 UTC.

Per corpus file: the path as given, its SHA-256, its `bip_revision` and its
vector count. Per vector: `ref` is `<path>#<zero-based index>`.

## JSON

The schema is normative; in brief:

- `summary`: vector counts (total, withheld, not_run, accepted, rejected),
  the same counts for stage requests, valid vectors sent and passed, row counts per verdict (a two-verdict row
  counts under both), refusals by the rule they named (`rejects`, "Named
  rules"), and the refs of confounded and triage vectors.
- `rows`: rule, task, verdicts, bips, evidence (vector ref and verdict),
  stale, notes.
- `vectors`: every vector in file order: ref, description, task, valid,
  request bips, `failed`, `incomplete`, class, the corpus note, outcome
  (`accept`, `reject`, `n/a`, `error`, `withheld`), reason, the rule the
  project named, error kind, the attribution of the returned PSBT, the
  evidence it gave, and its stage requests (`stages`: task, attribution
  under that task, outcome, reason, rule, error kind and evidence), when it
  has any.

## Markdown rendering

`report.md` has these parts:

- Title: `# <project name> PSBT behavior vs. psbt-spec <short revision>`.
- Record: the pins, as bullets. Rules in scope: every General
  and Role rule at the revision. Method: executed, with the corpus files.
  Auditor: `psbt-spec evaluate` and the run times.
- Summary: the `summary` counts, stage requests on a line of their own and
  the `rejects` counts on two lines.
- Rows: the template's eight columns. Operation is the task. Versions /
  extensions is the row's `bips`. Verdict joins two verdicts with "and".
  Project location is "not located" (a source review fills it in). Test
  evidence lists the vector refs. Observed outcome groups them by the
  outcome under the row's task, a stage request's for a stage row
  ("rejected #6, #7; accepted #9"). Notes holds the row notes and any stale
  entries.
- Then sections the template's Unverified list points to: Confounded
  vectors, Triage, Not run (with each adapter reason, stage requests
  marked), and Unverified, which
  states that verdicts rest on the vectors run and on psbt-spec's
  attribution at the pinned revision, and that a rule with no vector is NOT
  RUN, not MATCH.

## Versioning

- The format string changes major version (`psbt-spec.report/3`) for any
  change a reader of the previous version would misread: a new required
  field, a removed or renamed field, or a changed meaning of a field or a
  verdict.
- A new optional field keeps the version.
- `psbt-spec.report/2` (E2e): a refusal naming another rule is no longer
  MATCH, a confounded refusal naming one of its rules is, and
  `summary.rejects` is required. Rows, vectors and the other fields keep
  their v1 shape; the row and vector `evidence` may now carry NOT RUN for a
  vector the project answered.

## Worked example

[`examples/report.json`](examples/report.json) and
[`examples/report.md`](examples/report.md): the illustrative `example-wallet`
over `vectors/roles.json` (50 vectors, `bip_revision` 5aadddb). The vectors,
their attribution and the rule IDs are real: the attribution was computed by
the reference checks at `e536919`, with `failed` and `incomplete` kept apart. The
project's answers are invented to reach every verdict row. It declares tasks
deserialize, finalize, extract and combine, and BIPs 174, 370 and 371.

Selected rows:

| Rule ID | Operation | Verdict | Evidence | Why |
|---|---|---|---|---|
| GEN-T-2 | sign | NOT IMPLEMENTED | #6 to #10 NOT IMPLEMENTED | GEN-T-2 names the Signer; the stage requests under `sign` are withheld, as `sign` is not declared. The parser's answers (rejected #6, #7, #8, #10; accepted #9) are an informational note |
| GEN-ST-2 | combine | MATCH | #44, #46, #48 | a source fails GEN-ST-2 (BIP-375 not enabled); the project refused |
| ROLE-B-1 | combine | MATCH | #38, #39 | isolated on ROLE-B-1 once ROLE-B-2 counts as a Result rule |
| ROLE-B-2 | combine | LOOSER | #40 MATCH, #42 LOOSER, #41 NOT RUN | result vectors: for #40 it returned a PSBT that fails nothing; for #42 it returned one that fails ROLE-B-2; #41 crashed |
| ROLE-F-1 | finalize | LOOSER | #25 MATCH, #26 LOOSER | accepted confounded #26 (ROLE-F-1, ROLE-F-3); rejected confounded #25 (ROLE-F-1, ROLE-F-4) naming ROLE-F-1, confirmed |
| ROLE-F-4 | finalize | MATCH | #21 MATCH, #22 NOT RUN | #21 named ROLE-F-4 (confirmed); #22 named ROLE-F-3, which it does not fail, so NOT RUN and a note on ROLE-F-3 |
| ROLE-X-1 | extract | MATCH | #15, #16, #19 MATCH, #17 NOT IMPLEMENTED | unconfirmed: #16 named ROLE-X-99, not in `rules.json`, noted as a warning |
| ROLE-F-2 | finalize | MATCH | #30 MATCH, #29 NOT IMPLEMENTED | #29 needs BIP 376, which it does not declare |
| ROLE-S-1 | sign | NOT IMPLEMENTED | none | sign not declared |
| ROLE-C-1 | create | NOT RUN | none | no create task in contract v1 |
| (none) | finalize | STRICTER | #27 | rejected a valid vector and named no rule |

Totals: 50 vectors, 18 accepted, 20 rejected, 4 not run, 8 withheld; 6
stage requests (GEN-T-2 #6 to #10 and GEN-SP-7 #12 under `sign`), all
withheld; 14 of 18 valid vectors sent passed; rows 6 MATCH, 1 STRICTER, 3
LOOSER, 18 NOT IMPLEMENTED, 42 NOT RUN; refusals 2 confirmed (#21, #25), 12
unconfirmed, 1 naming another rule (#22), 1 naming an unknown ID (#16); 1
confounded vector rejected (#25); no triage items.

The example does not declare `sign`, so it reaches no stage MATCH or LOOSER.
`rust/tests/evaluate_command.rs` covers both with
`rust/tests/fixtures/stage_adapter.py`: a project that accepts #6 to #10 and
#12 at `deserialize` and refuses them at `sign` is MATCH on GEN-T-2 / sign
and GEN-SP-7 / sign; one that accepts them at both is LOOSER there. Its
mode `named` covers "Named rules": the same rule, another rule, no rule and
an unknown ID, at `deserialize` (`vectors/bip174.json`), at `sign` stage
requests (`vectors/roles.json` #6 to #10, #12) and on confounded `sign`
vectors (`vectors/bip174.json` #31, #32).
