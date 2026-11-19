#!/usr/bin/env python3
"""psbt-spec adapter (docs/adapter.md) for the bips BIP-375 reference validator.

Usage: adapter.py BIPS_TREE [--revision COMMIT]

BIPS_TREE is a bitcoin/bips checkout, or an export of its bip-0375 directory,
holding bip-0375/test_runner.py. The adapter is read-only on that tree. It
wraps validate_bip375_psbt from test_runner.py, so a PSBT is accepted exactly
when the runner's four checks (psbt_structure, ecdh_coverage,
input_eligibility, output_scripts) all pass.

What it answers, and why:
- Task deserialize only. The validator checks a PSBT; it signs, finalizes,
  extracts and combines nothing (the runner's own `task` tags for valid vectors
  only name the vector's snapshot, and "no role is driven yet"). Other tasks
  are not declared, so psbt-spec reports their rules as NOT IMPLEMENTED.
- BIPs 174, 370 and 375: the PSBT classes it deserializes are versions 0 and 2,
  and its checks are BIP-375's.
- A request whose bips lack 375 gets n/a: the validator cannot be run without
  the BIP-375 rules, so it cannot answer for a PSBT with BIP-375 not enabled.
- On reject it names the rule when the check name and message mean exactly one
  (RULES below; README.md tabulates it), and no rule otherwise.
"""
import contextlib
import json
import re
import subprocess
import sys
from pathlib import Path

PROTOCOL = "psbt-spec.adapter/1"


# The rule behind a refusal: the first row whose check is the failing check and whose pattern
# matches the message. This is the only place the adapter names a rule. A refusal that matches no
# row names no rule.
RULES = [
    ("psbt_structure", r"^duplicate PSBT key", "GEN-F-4"),
    ("psbt_structure", r"^bad PSBT magic bytes", "GEN-F-1"),
    ("psbt_structure", r"has PSBT_OUT_SP_V0_LABEL but missing PSBT_OUT_SP_V0_INFO", "GEN-SP-1"),
    ("psbt_structure", r"wrong length", "GEN-F-5"),
    ("ecdh_coverage", r"", "GEN-SP-3"),
    ("input_eligibility", r"wrong length", "GEN-F-5"),
    ("input_eligibility", r"uses segwit version > 1", "GEN-SP-4"),
    ("input_eligibility", r"uses non-SIGHASH_ALL", "GEN-SP-4"),
    ("input_eligibility", r"has a non-SIGHASH_ALL signature", "GEN-SP-4"),
    ("input_eligibility", r"is signed before every silent payment output has PSBT_OUT_SCRIPT", "GEN-SP-7"),
    ("input_eligibility", r"flags not cleared", "GEN-SP-2"),
    ("output_scripts", r"", "GEN-SP-5"),
]


def rule_of(check, message):
    for row_check, pattern, rule in RULES:
        if row_check == check and re.search(pattern, message or ""):
            return rule
    return None


def load_runner(tree):
    directory = Path(tree) / "bip-0375"
    if not (directory / "test_runner.py").is_file():
        sys.exit(f"{directory}/test_runner.py not found")
    sys.path.insert(0, str(directory))
    import test_runner  # runs nothing: its main is guarded

    return test_runner


def revision(tree, given):
    if given:
        return given
    try:
        out = subprocess.run(["git", "-C", str(tree), "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        sys.exit("BIPS_TREE is not a git checkout: pass --revision COMMIT")


def vectors_version(tree):
    with open(Path(tree) / "bip-0375" / "bip375_test_vectors.json") as f:
        return str(json.load(f).get("version", "unknown"))


def reply(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def answer(runner, request):
    rid = request["id"]
    if request["task"] != "deserialize":
        return {"id": rid, "verdict": "error", "reason": f"task {request['task']} is not declared"}
    if 375 not in request["bips"]:
        return {"id": rid, "verdict": "n/a", "reason": "the validator applies BIP-375 rules and cannot run without BIP-375 enabled"}
    try:
        # The validator and its dependencies should print nothing; keep stdout clean regardless.
        with contextlib.redirect_stdout(sys.stderr):
            valid, message, check = runner.validate_bip375_psbt(request["psbt"], None)
    except Exception as e:  # a throw caused by the PSBT is a refusal (adapter.md)
        return {"id": rid, "verdict": "reject", "reason": f"exception: {type(e).__name__}: {e}"}
    if valid:
        return {"id": rid, "verdict": "accept"}
    response = {"id": rid, "verdict": "reject", "reason": f"{check}: {message}"}
    rule = rule_of(check, message)
    if rule:
        response["rule"] = rule
    return response


def main(argv):
    args = argv[1:]
    given = None
    if "--revision" in args:
        i = args.index("--revision")
        given = args[i + 1]
        del args[i : i + 2]
    if len(args) != 1:
        sys.exit(__doc__)
    tree = args[0]
    runner = load_runner(tree)
    hello = {
        "protocol": PROTOCOL,
        "project": {"name": "bips bip-0375 reference validator", "version": f"vectors {vectors_version(tree)}", "revision": revision(tree, given)},
        "adapter": {"name": "psbt-spec bip375-reference adapter", "version": "0.1.0"},
        "tasks": ["deserialize"],
        "bips": [174, 370, 375],
    }
    for line in sys.stdin:
        request = json.loads(line)
        if request["task"] == "hello":
            reply({"id": request["id"], **hello})
        else:
            reply(answer(runner, request))


if __name__ == "__main__":
    main(sys.argv)
