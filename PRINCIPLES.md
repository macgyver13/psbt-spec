# Principles

psbt-spec is an evaluation tool: projects use it to judge their own compliance
with the PSBT BIPs, by rule ID. These principles state how the
specification decides what a rule is, how it is worded, checked and tested,
and how it changes. This file is the reference: when a principle changes,
change it here.

## What the specification states

1. **Two predicates.** A PSBT is well formed when every General rule passes.
   A role conforms when its rules pass on the PSBT it received and the PSBT
   it returned.
2. **General rules are properties of a lone PSBT.** Anyone holding the file
   can check them: a parser, `decodepsbt`, an agent. No actor is involved.
3. **Role rules are duties of one actor.** Creator, Constructor, Updater,
   Signer, Input Finalizer, Transaction Extractor or Combiner. Each role
   section starts from the implicit precondition "receives a PSBT that
   satisfies the General rules".
4. **Two phases.** A Precondition is checked on the PSBT the role received;
   failing it means the role refuses. A Result is checked on the PSBT the
   role returned, alone or compared with what it received.

## What counts as a rule

5. **One rule per property.** BIP sentences that restate the same property,
   in one BIP or several, become one rule. The rule lists every source
   sentence as evidence and is marked as derived wording. A rule bound to
   several checks names, in its failure detail, the part that failed.
6. **Separate actors stay separate.** When two roles share a property, the
   property goes in Definitions and each role's rule cites it.
7. **Separate strengths stay separate.** A MUST and a SHOULD are never one
   rule.
8. **Related extensions may share a rule.** BIPs that build on each other,
   such as BIP375 (sending) and BIP376 (spending) on silent payments, can
   share a rule. Each binding keeps its own BIP gate, so a project
   supporting one BIP is audited on that part.
9. **A role rule exists only for what General rules cannot decide.** Every
   role entry point runs the General rules first, and failing a
   precondition is the same as refusing. So a duty to refuse, or to avoid
   returning, a PSBT that a General rule rejects is that General rule. A
   role rule covers what no General rule can see: a comparison between the
   received and returned PSBTs, a signature, a value only the actor knows.
   The General rule keeps the actor visible: it names the roles whose BIP
   text assigns the duty, and each of those role sections lists it as a
   rule that role must enforce, so an implementer reads one checklist per
   role.
10. **Not observable is still a rule.** A duty that needs evidence outside the
    PSBT (what a wallet displayed, a private key, where an input came from)
    is a role rule with coverage Declared and a note saying what evidence an
    audit needs.

## Wording and interpretation

11. **Keep the BIP's wording.** A rule restates its source sentence. Where
    the check decides less than the sentence, the coverage value and the
    gap say so; the sentence is not narrowed to fit the check.
12. **Say where wording comes from.** A rule is a direct BIP requirement, a
    derived reading, or a project resolution, and is marked as such.
13. **Decide, then record the basis.** When BIP text is ambiguous, the
    project decides and states the reading and its basis in the rule's note
    (another BIP, consensus behavior, Bitcoin Core's practice). An open
    question is only for what the project has not decided. A wording fix
    goes upstream as a BIP pull request; the note can cite it.
    Example: a Taproot SIGHASH_DEFAULT signature counts as SIGHASH_ALL for
    BIP375, because BIP341 defines it to commit to the same data and
    Bitcoin Core signs Taproot inputs with it by default.

## Checks and outcomes

14. **Four outcomes.** Verified, Failed, Incomplete (the PSBT lacks the
    context to decide) and NotApplicable. Missing context is Incomplete,
    never Verified.
15. **Four coverage values.** Full (the check decides the sentence), Partial
    (it decides part; the gap states what it does not), Declared (no check;
    the note states the evidence an audit needs) and Pending (not yet
    written).
16. **Order only where a check depends on another.** Framing before parsing,
    formats before structure, a check whose Incomplete would hide another's
    failure last. Independent checks are unordered, and the exhaustive trace
    for coverage never changes an outcome.
17. **Verify what can be verified.** Signatures (BIP340, ECDSA, BIP327) and
    DNSSEC proofs are verified with real cryptography. What the reference
    cannot compute, such as a script's satisfaction, is Incomplete, never
    assumed.

## Identifiers and declarations

18. **One ID per rule, bound as often as needed.** A rule checked in the
    global map, each input and each output keeps one ID and one error code.
19. **IDs are free until 1.0, then append-only.** Before 1.0 rules may be
    renumbered, merged or removed; from 1.0 an ID is never reused or
    redefined.
20. **One declaration per rule.** A rule's ID, strength, coverage, evidence,
    wording, note and gap are declared once in `spec.rs`; the graph only
    binds IDs to checks and panics on an unknown ID. `spec.html` and
    `rules.json` are generated from the declarations, and tests fail when
    the checked-in copies are stale.

## Tests and vectors

21. **Every vector names its entry point, rule ID and outcome.**
22. **Every checked rule is observed by its ID.** For each rule with a
    check, a test reaches it through its entry point once Verified (with the
    rule's trace reporting Passed) and once Failed (Incomplete for a rule
    that never fails). Binding a rule to the wrong check fails a test.
    (`rust/tests/rule_ids.rs`)
23. **Known answers over self-consistency.** Cryptography and signature
    hashes are tested against published vectors (BIP, Bitcoin Core), not
    only against values the reference produced itself.

## Audits

24. **An audit is against one pinned revision.** It records the
    specification revision and status, the project and its revision, the
    versions and extensions in scope, the method, and whether evidence was
    read or run.
25. **An audit cites rule IDs with the project's operation.** A Signer's
    handling of a General property is a row for the General rule with
    operation "sign".

## Evaluation

26. **The rulebook and corpus are the product; the checks serve the corpus.**
    The reference checks are internal tooling, used to prove that a
    vector isolates its rule and to attribute failures, not offered as a
    public checking API.
27. **Attribution is checked, not trusted.** An invalid vector that fails no
    rule, or a producer label that disagrees with attribution, is a triage
    item; neither side wins by default.
28. **Every disagreement gets a class:** confounded vector, psbt-spec lagging
    the BIP, ambiguous BIP, or project defect. The class goes in the vector
    note or the report row. (evaluation, Proposed principles)
29. **A corpus pins its BIP revision.** A rule whose evidence cites a BIP the
    corpus exercises at a revision that differs from the corpus's is flagged
    stale. (evaluation, Proposed principles)
