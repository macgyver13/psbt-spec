#!/usr/bin/env python3
"""Test-only adapter: replays the invented example-wallet of docs/examples.

Usage: example_adapter.py REPORT.json CORPUS.json

It answers request N with what REPORT.json records for the Nth vector that
was not withheld, so it relies on request ids (it is not a real adapter, which
must not depend on earlier requests). A vector recorded as "error" with kind
"crashed" makes it exit with status 101 instead of answering.
"""
import base64
import json
import sys

report = json.load(open(sys.argv[1]))
corpus = json.load(open(sys.argv[2]))["vectors"]
sent = [(i, v) for i, v in enumerate(report["vectors"]) if v["outcome"] != "withheld"]

print_line = lambda obj: (sys.stdout.write(json.dumps(obj) + "\n"), sys.stdout.flush())


def good_combination(sources):
    for v in corpus:
        if v["valid"] and v.get("combine") == sources:
            return v["psbt"]
    return None


for line in sys.stdin:
    request = json.loads(line)
    if request["task"] == "hello":
        h = report
        print_line({
            "id": 0, "protocol": "psbt-spec.adapter/1",
            "project": h["project"],
            "adapter": {"name": h["adapter"]["name"], "version": h["adapter"]["version"]},
            "tasks": h["declared"]["tasks"], "bips": h["declared"]["bips"],
        })
        continue
    index, recorded = sent[request["id"] - 1]
    vector = corpus[index]
    assert recorded["task"] == request["task"], (recorded["ref"], request["task"])
    outcome = recorded["outcome"]
    if outcome == "error" and recorded["error"] == "crashed":
        sys.exit(101)
    if outcome == "accept":
        response = {"id": request["id"], "verdict": "accept"}
        if request["task"] == "combine":
            returned = recorded.get("returned")
            if returned is not None and returned["failed"] == [] and not vector["valid"]:
                response["psbt"] = good_combination(vector["combine"])
            else:
                response["psbt"] = vector["psbt"]
        elif request["task"] in ("finalize", "sign"):
            response["psbt"] = request["psbt"]
        print_line(response)
    elif outcome == "reject":
        response = {"id": request["id"], "verdict": "reject", "reason": recorded.get("reason", "refused")}
        if "rule" in recorded:
            response["rule"] = recorded["rule"]
        print_line(response)
    else:
        print_line({"id": request["id"], "verdict": outcome, "reason": recorded["reason"]})
