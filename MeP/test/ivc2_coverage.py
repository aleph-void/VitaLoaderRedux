#!/usr/bin/env python3
"""Every-entry decode test for the generated IVC2 constructors: every form of
tools/ivc2_spec.json.gz must appear in Ghidra's decoding of the corpora (CoverageCheck.java cannot
reach the slot tables, which match context that the bundle constructors compute from the bytes).

  ivc2_coverage.py <ivc2_spec.json.gz> <ghidra C3 dump>... --vliw <ghidra VLIW dump>...
Prints "unreached <slot> <form>" lines and a summary.
"""
import gzip
import json
import re
import sys


def kind(op):
    op = op.strip()
    if re.fullmatch(r"c\d+", op):
        return "c"
    if re.fullmatch(r"(r\d+|tp|gp|sp)", op):
        return "r"
    if re.fullmatch(r"-?(0x[0-9a-f]+|\d+)", op):
        return "i"
    return "x"


def form(t):
    m, _, ops = t.strip().partition(" ")
    ops = [o for o in ops.split(",")] if ops else []
    return m.lower() + "/" + "".join(kind(o) for o in ops)


spec = json.load(gzip.open(sys.argv[1], "rt"))
i = sys.argv.index("--vliw")
seen = {"C3": set(), "P0S": set(), "P0": set(), "P1": set()}
for path in sys.argv[2:i]:
    for line in open(path):
        p = line.rstrip("\n").split(" ", 2)
        if len(p) == 3 and p[1] != "0":
            seen["C3"].add(form(p[2]))
for path in sys.argv[i + 1:]:
    for line in open(path):
        p = line.rstrip("\n").split(" ", 2)
        if len(p) < 3 or p[1] == "0":
            continue
        parts = p[2].split(" + ")
        if len(parts) == 3:
            seen["P0S"].add(form(parts[1]))
        if len(parts) == 2:
            seen["P0"].add(form(parts[0]))   # P0 + P1, or core32 + P1 (core forms never match)
        seen["P1"].add(form(parts[-1]))
total = reached = 0
for slot in ("C3", "P0S", "P0", "P1"):
    forms = sorted({e["form"] for e in spec[slot]})
    for f in forms:
        total += 1
        if f in seen[slot]:
            reached += 1
        else:
            print("unreached %s %s" % (slot, f))
print("ivc2 coverage: %d forms, %d reached, %d unreached" % (total, reached, total - reached))
