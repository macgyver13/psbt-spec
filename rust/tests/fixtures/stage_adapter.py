#!/usr/bin/env python3
"""Test-only adapter for stage requests and named rules (docs/report.md).

Usage: stage_adapter.py MODE [CORPUS ...]

It declares deserialize and sign for BIPs 174, 370 and 375, accepts every
deserialize request, and answers every sign request with reject (MODE
refuse-sign: a project that enforces at the Signer) or accept (MODE
accept-all: a project that enforces nowhere).

MODE named reads the CORPUS files and rejects the vectors in NAMED, at the
task given there, with the rule given there (None: no rule), keyed by
"<file>#<index>". It finds a request's vector by its PSBT, so it relies on
those PSBTs being unique in the corpus files. Everything else is accepted.
"""
import json
import sys

mode = sys.argv[1]
assert mode in ("refuse-sign", "accept-all", "named"), mode

NAMED = {
    # deserialize: same rule, another rule, no rule, an unknown rule.
    ("deserialize", "vectors/bip174.json#0"): "GEN-F-1",
    ("deserialize", "vectors/bip174.json#1"): "GEN-F-1",
    ("deserialize", "vectors/bip174.json#15"): "GEN-F-1",
    ("deserialize", "vectors/bip174.json#4"): None,
    ("deserialize", "vectors/bip174.json#3"): "GEN-ST-99",
    # sign stage requests on GEN-T-2 and GEN-SP-7: the same four cases.
    ("sign", "vectors/roles.json#6"): "GEN-T-2",
    ("sign", "vectors/roles.json#7"): "GEN-SP-7",
    ("sign", "vectors/roles.json#10"): "GEN-SP-7",
    ("sign", "vectors/roles.json#8"): None,
    ("sign", "vectors/roles.json#9"): "GEN-T-99",
    ("sign", "vectors/roles.json#12"): "GEN-SP-7",
    # sign vectors confounded on ROLE-S-2 and ROLE-S-4 (and ROLE-S-3).
    ("sign", "vectors/bip174.json#31"): "ROLE-S-4",
    ("sign", "vectors/bip174.json#32"): "ROLE-S-1",
}

by_psbt = {}
for path in sys.argv[2:]:
    for index, vector in enumerate(json.load(open(path))["vectors"]):
        reference = f"{path}#{index}"
        if any(ref == reference for _, ref in NAMED):
            assert vector["psbt"] not in by_psbt, reference
            by_psbt[vector["psbt"]] = reference

for line in sys.stdin:
    request = json.loads(line)
    task = request["task"]
    if task == "hello":
        response = {
            "id": 0, "protocol": "psbt-spec.adapter/1",
            "project": {"name": "stage-test", "version": "0", "revision": "0"},
            "adapter": {"name": "stage-adapter", "version": "0"},
            "tasks": ["deserialize", "sign"], "bips": [174, 370, 375],
        }
    elif mode == "named" and (task, by_psbt.get(request["psbt"])) in NAMED:
        rule = NAMED[(task, by_psbt[request["psbt"]])]
        response = {"id": request["id"], "verdict": "reject", "reason": "refused"}
        if rule is not None:
            response["rule"] = rule
    elif task == "sign" and mode == "refuse-sign":
        response = {"id": request["id"], "verdict": "reject", "reason": "signer refuses"}
    else:
        response = {"id": request["id"], "verdict": "accept"}
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()
