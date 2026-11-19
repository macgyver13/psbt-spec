# rules.json

`rules.json` holds every declared entry of the specification for tools and
agents. It is generated with `spec.html` and `rules.md` from
`rust/src/spec.rs` (`cargo run --bin render -- --json`), and a test fails when
the checked-in copy is stale. Schema: [`rules.schema.json`](rules.schema.json).

Top level:

- `title`, `status`: the specification and its release status. Before 1.0,
  rule IDs may be renumbered, merged or removed; from 1.0 they are
  append-only.
- `revision`: the package version, with the source commit when rendered for
  publication.
- `corpora`: each corpus file, the bitcoin/bips revision it pins, its BIPs and
  its vector count.
- `entries`: rules, guidance, definitions and procedures, in display order.

Each entry:

| Key | Meaning |
|---|---|
| `id` | `GEN-<section>-<n>`, `ROLE-<role>-<n>`, `REF-<n>` or `GUIDE-<n>`; empty for a definition. The page anchor is `spec.html#<id>`, or `#term-<slug>` for a definition. |
| `category` | `general`, `role`, `guidance`, `definition` or `reference` (a procedure). |
| `section` | The General section (Framing, Structure, ...) or role. |
| `text` | The wording, keeping the BIP's strength. |
| `strength` | MUST, MUST NOT, SHOULD, MAY, or null. |
| `coverage` | Rules only: Full, Partial, Declared or Pending. |
| `phase` | Role rules: Precondition or Result. |
| `gates` | When the rule applies, such as "From BIP-375". |
| `checks` | Reference functions bound to the rule. |
| `basis` | Rules only: `direct` (restates one BIP sentence), `derived` (merges sentences, or reads a requirement from a field description or another BIP) or `resolution` (the project decided where the BIP is ambiguous or silent). Null for other entries. |
| `reading` | For a derived or resolution rule, the project's reading and its basis; otherwise empty. |
| `evidence` | The sources it comes from, first the main one: a list of `{label, url}`. |
| `note`, `gap` | Reader note; for a Partial rule, what the check leaves undecided. |
| `role`, `roles` | The role a guidance entry belongs to; the roles that enforce a General rule. |
| `corpus` | Rules only: `status` (`corpus`, `tests only`, `none`), the invalid vectors that isolate the rule and the valid vectors that pass it, each as `{file, index}` in `vectors/<file>.json`. |

A rule's ID is the error code its check reports, so `psbt-spec attribute`
output (`failed`, `incomplete`) can be joined to `entries` by `id`.
