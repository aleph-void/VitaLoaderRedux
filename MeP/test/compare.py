#!/usr/bin/env python3
"""Compare Ghidra slot disassembly (DumpSlots.java) with GNU objdump slot disassembly (slotdis)
for MeP.

  compare.py <ghidra.txt> <objdump.txt> [examples-per-class]

exact:    same length and text after lower-casing, removing blanks in the operands, writing GPRs
          as rN ($13/$tp, $14/$gp, $15/$sp), dropping '$' and writing every number as signed hex
semantic: additionally addresses and immediates modulo 2^32 (objdump prints backward branch
          targets near 0 as 64-bit addresses), reserved control registers (objdump: ???) and the
          simulator system call (Ghidra: SIM_SYSCALL n, objdump: --syscall--)
"""
import re
import sys
from collections import Counter, defaultdict

NUM = re.compile(r"(?<![\w.$])(-?)(0x[0-9a-f]+|\d+)(?![\w])")
GPR = {"tp": "r13", "gp": "r14", "sp": "r15"}

def load(path):
    d = {}
    for line in open(path):
        p = line.rstrip("\n").split(" ", 2)
        if len(p) < 2:
            continue
        d[int(p[0], 16)] = (int(p[1]), p[2] if len(p) > 2 else "")
    return d


def canon(m):
    v = int(m.group(2), 0)
    return ("-" if m.group(1) else "") + hex(v)


def regs(t):
    t = re.sub(r"\$(\d+)(?![\w])", r"r\1", t)
    t = re.sub(r"\$([a-z_][\w]*)", r"\1", t)
    t = re.sub(r"(?<![\w])(tp|gp|sp)(?![\w])", lambda x: GPR[x.group(1)], t)
    return t


def exact_norm(t):
    t = t.lower().replace("\t", " ").strip()
    t = re.sub(r"\s*<[^>]*>", "", t)
    m, _, ops = t.partition(" ")
    t = m + " " + regs(ops.replace(" ", ""))
    return NUM.sub(canon, t).strip()


def sem_norm(t):
    t = exact_norm(t)
    m, _, ops = t.partition(" ")
    if m in ("stcb", "ldcb"):
        ops = re.sub(r",\((0x[0-9a-f]+)\)$", r",\1", ops)
    ops = NUM.sub(lambda x: hex((-int(x.group(2), 0) if x.group(1) else int(x.group(2), 0)) & 0xffffffff), ops)
    return (m + " " + ops).strip()


def bundle_parts(t):
    return [p.strip() for p in t.split(" + ")]


def sem_equal(g, o):
    if " + " in g or " + " in o:
        gp, op = bundle_parts(g), bundle_parts(o)
        return len(gp) == len(op) and all(sem_equal1(a, b) for a, b in zip(gp, op))
    return sem_equal1(g, o)


def sem_equal1(g, o):
    """objdump prints reserved control registers (3, 9-11, 29-31) as ???; Ghidra names them
    csrN"""
    g, o = sem_norm(g), sem_norm(o)
    if g == o:
        return True
    g = re.sub(r"(?<![\w])ivc2_ccr_reserved(?![\w])", "???", g)
    if g == o:
        return True
    # the simulator system call: objdump prints no operand
    if g.startswith("sim_syscall ") and o == "--syscall--":
        return True
    g = re.sub(r"(?<![\w])ivc2_ccr_reserved(?![\w])", "???", g)
    return g == o or re.sub(r",csr\d+$", ",???", g) == o


def mnem(t):
    return t.split(" ")[0].lower() if t else "-"


def main():
    g = load(sys.argv[1])
    o = load(sys.argv[2])
    nex = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    cnt = Counter()
    classes = defaultdict(list)
    for off in sorted(o):
        gl, gt = g.get(off, (0, "BAD"))
        ol, ot = o[off]
        gbad = gl == 0
        obad = (ol == 0 or ot.startswith("(bad)") or "unknown" in ot or "--reserved--" in ot
                or any(not p for p in bundle_parts(ot)))
        cnt["total"] += 1
        if gbad and obad:
            cnt["both_reject"] += 1
            continue
        if gbad:
            cnt["ref_only"] += 1
            classes["ref only: " + mnem(ot)].append((off, gt, ot, ol))
            continue
        if obad:
            cnt["ghidra_only"] += 1
            classes["ghidra only: " + mnem(gt)].append((off, gt, ot, gl))
            continue
        cnt["both_decode"] += 1
        if gl == ol and [exact_norm(p) for p in bundle_parts(gt)] == [exact_norm(p) for p in bundle_parts(ot)]:
            cnt["exact"] += 1
            cnt["semantic"] += 1
        elif gl == ol and sem_equal(gt, ot):
            cnt["semantic"] += 1
            classes["~ " + mnem(ot)].append((off, gt, ot, gl))
        else:
            key = ("LEN " if gl != ol else "DIFF ") + mnem(ot) + " / " + mnem(gt)
            classes[key].append((off, gt, ot, "%d/%d" % (gl, ol)))
    bd = cnt["both_decode"] or 1
    print("compared %d slots: both decode %d, exact %d (%.2f%%), semantic %d (%.2f%%), "
          "ghidra-only %d, ref-only %d, both reject %d"
          % (cnt["total"], cnt["both_decode"], cnt["exact"], 100.0 * cnt["exact"] / bd,
             cnt["semantic"], 100.0 * cnt["semantic"] / bd, cnt["ghidra_only"], cnt["ref_only"],
             cnt["both_reject"]))
    for k in sorted(classes, key=lambda k: (k.startswith("~"), -len(classes[k]))):
        v = classes[k]
        print("  [%d] %s" % (len(v), k))
        for off, gt, ot, ln in v[:nex]:
            print("      %08x len %s  ghidra: %-36s objdump: %s" % (off, ln, gt, ot))


if __name__ == "__main__":
    main()
