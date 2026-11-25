#!/usr/bin/env python3
"""Re-imports vectors/bip375.json from a new revision of BIP-375's test vectors.

Usage: python3 import_bip375.py OLD.json NEW.json ../bip375.json REVISION

OLD.json and NEW.json are bip-0375/bip375_test_vectors.json at the corpus's
current bip_revision and at REVISION. The corpus lists, in order: the invalid
cases; each valid case followed by its expected PSBT when that differs; each
workflow step's expected PSBT; then the finalize and extract workflow inputs
again. The script first checks that OLD.json flattens to exactly the current
corpus, then replaces each vector's description and PSBT by position. The
corpus's own fields (valid, rule, task, note) are kept, so run
`psbt-spec vectors` afterwards to confirm every vector still isolates its rule.
"""

import json
import sys

SUFFIX = {"create": " (created result)", "update": " (updated result)", "sign": " (signed result)", "finalize": " (finalized result)"}
REPEATED_INPUTS = {"finalize", "extract"}


def flatten(bip):
    out = [(v["description"], v["psbt"]) for v in bip["invalid"]]
    for v in bip["valid"]:
        out.append((v["description"], v["psbt"]))
        expected = (v.get("expected") or {}).get("psbt")
        if expected and expected != v["psbt"]:
            out.append((v["description"] + SUFFIX[v["task"]], expected))
    for w in bip["workflows"]:
        expected = (w.get("expected") or {}).get("psbt")
        if expected and expected != w["psbt"]:
            out.append((w["description"] + SUFFIX[w["task"]], expected))
    for w in bip["workflows"]:
        if w["task"] in REPEATED_INPUTS:
            out.append((w["description"], w["psbt"]))
    return out


def load(path):
    with open(path) as f:
        return json.load(f)


def main(old_path, new_path, corpus_path, revision):
    with open(corpus_path) as f:
        text = f.read()
    corpus = json.loads(text)
    if json.dumps(corpus, indent=2) + "\n" != text:
        sys.exit(f"{corpus_path} is not in the expected JSON format")

    have = [(v["description"], v["psbt"]) for v in corpus["vectors"]]
    old = flatten(load(old_path))
    if old != have:
        if len(old) != len(have):
            sys.exit(f"{old_path} flattens to {len(old)} vectors, the corpus has {len(have)}")
        n = next(i for i, (a, b) in enumerate(zip(old, have), 1) if a != b)
        field = "description" if old[n - 1][0] != have[n - 1][0] else "PSBT"
        sys.exit(f"{old_path} does not reproduce the corpus: #{n} ({have[n - 1][0]}) has a different {field}")

    new = flatten(load(new_path))
    if len(new) != len(old):
        sys.exit(f"{new_path} flattens to {len(new)} vectors, the corpus has {len(old)}")

    for v, (description, psbt) in zip(corpus["vectors"], new):
        v["description"], v["psbt"] = description, psbt
    corpus["bip_revision"] = revision
    with open(corpus_path, "w") as f:
        f.write(json.dumps(corpus, indent=2) + "\n")
    print(f"rewrote {len(new)} vectors at {revision}")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    main(*sys.argv[1:])
