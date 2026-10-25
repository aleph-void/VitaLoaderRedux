#!/usr/bin/env python3
"""Generate data/languages/ivc2.sinc (IVC2 coprocessor: core-mode C3 instructions, VLIW-mode
bundles with P0S/P0/P1 slots) from the spec ivc2_learn.py learned from GNU objdump.

  gen_ivc2.py ivc2_spec.json.gz <languages dir>
     -> ivc2.sinc (tables and constructors), ivc2_ctx.sinc (context fields), ivc2_instr.sinc and
        ivc2_instr2.sinc (fields of the instr/instr2 tokens), included by MeP-c5.sinc

Slot values live in context while a bundle is decoded: the bundle constructor copies the P0S or
P0 slot to IVA and the P1 slot to IVB, and the slot tables match on fields of those.
Semantics: CMOV/CMOVH/CMOVC (core <-> coprocessor moves) and CPMOV are p-code; every other
IVC2 operation is a user operation named after its mnemonic, writing its "o" operand (and the
first operand of the move-immediate forms) and reading the others. No public specification of
the IVC2 operations exists; see GHIDRA-RARE.md.
"""
import gzip
import json
import re
import sys

spec = json.load(gzip.open(sys.argv[1], "rt") if sys.argv[1].endswith(".gz") else open(sys.argv[1]))

# context positions (contextreg bits numbered from the most significant bit)
IVA_END, IVB_END = 91, 123   # slot bit j lives at END - j
fields = {}                  # name -> definition line
out = []


def runs(bits):
    """sorted bit list -> list of (lo, hi) contiguous runs"""
    r = []
    for b in sorted(bits):
        if r and r[-1][1] == b - 1:
            r[-1][1] = b
        else:
            r.append([b, b])
    return [tuple(x) for x in r]


def field(slot, lo, hi, tag="", signed=False):
    """field name for slot bits lo..hi (C3: split at the halfword boundary by the caller)"""
    sg = "s" if signed else ""
    if slot == "C3":
        if lo >= 16:
            name = "c3h%s%s_%d_%d" % (tag, sg, lo, hi)
            fields[name] = ("instr", "%s=(%d,%d)%s" % (name, lo - 16, hi - 16, " signed" if signed else ""))
        else:
            name = "c3l%s%s_%d_%d" % (tag, sg, lo, hi)
            fields[name] = ("instr2", "%s=(%d,%d)%s" % (name, lo, hi, " signed" if signed else ""))
        return name
    end = IVA_END if slot in ("P0S", "P0") else IVB_END
    pre = "iva" if slot in ("P0S", "P0") else "ivb"
    name = "%s%s%s_%d_%d" % (pre, tag, sg, lo, hi)
    fields[name] = ("ctx", "%s=(%d,%d)%s noflow" % (name, end - hi, end - lo, " signed" if signed else ""))
    return name


def join_c3(pieces):
    """C3 pattern pieces (field=value) -> 'H ; L' pattern over the two halfwords"""
    h = [p for p in pieces if fields[p.split("=")[0]][0] == "instr"]
    l = [p for p in pieces if fields[p.split("=")[0]][0] == "instr2"]
    if not l:
        return " & ".join(h)
    return "%s; %s" % (" & ".join(h) if h else "major", " & ".join(l))


def split_c3(slot, lo, hi):
    if slot == "C3" and lo < 16 <= hi:
        return [(lo, 15), (16, hi)]
    return [(lo, hi)]


def constraint(slot, mask, value):
    parts = []
    nb = 32 if slot == "C3" else 28
    bits = [b for b in range(nb) if mask >> b & 1]
    for lo, hi in runs(bits):
        for a, b in split_c3(slot, lo, hi):
            f = field(slot, a, b)
            parts.append((f, (value >> a) & ((1 << (b - a + 1)) - 1), a))
    return parts


CREGS = ["c%d" % i for i in range(32)]
GREGS = ["r%d" % i for i in range(13)] + ["tp", "gp", "sp"]
tables = {}       # subtable name -> list of constructor lines
attached = {}     # field -> register list


def operand(slot, op, idx):
    """-> (display piece, pattern piece, action piece, export expression)"""
    bits, kind = op["bits"], op["kind"]
    if "names" in op:
        tname = "IVX_%s_%s" % (slot, "_".join(map(str, bits)))
        if tname not in tables:
            lines = []
            for v in range(1 << len(bits)):
                n = op["names"].get(str(v))
                n = n[1:] if n and n.startswith("$") else "???"
                reg = n if n != "???" else "ivc2_ccr_reserved"
                pat = []
                for lo, hi in runs(bits):
                    for a, b in split_c3(slot, lo, hi):
                        val = 0
                        for i, bit in enumerate(bits):
                            if a <= bit <= b and (v >> i) & 1:
                                val |= 1 << (bit - a)
                        pat.append("%s=%d" % (field(slot, a, b), val))
                disp = reg
                pp = join_c3(pat) if slot == "C3" else " & ".join(pat)
                pp = pp.replace(";", " & %s;" % reg, 1) if ";" in pp else pp + " & " + reg
                lines.append('%s: %s is %s { export %s; }' % (tname, disp, pp, reg))
                CCR_NAMES.add(reg)
            tables[tname] = lines
        return tname, tname, None, tname
    w, off = op["weights"], op["offset"]
    simple = (off == 0 and len(runs(bits)) == 1 and w == [1 << i for i in range(len(bits) - 1)] + [w[-1]]
              and abs(w[-1]) == 1 << (len(bits) - 1))
    if kind in ("c", "r"):
        regs = CREGS if kind == "c" else GREGS
        if simple and w[-1] > 0 and (slot != "C3" or len(split_c3(slot, bits[0], bits[-1])) == 1):
            f = field(slot, bits[0], bits[-1], tag="r" if kind == "r" else "c")
            attached[f] = regs[:1 << len(bits)]
            return f, f, None, f
        tname = "IV%s_%s_%s" % (kind.upper(), slot, "_".join(map(str, bits)))
        if tname not in tables:
            lines = []
            for v in range(1 << len(bits)):
                idx2 = off + sum(wt for i, wt in enumerate(w) if (v >> i) & 1)
                pat = []
                for lo, hi in runs(bits):
                    for a, b in split_c3(slot, lo, hi):
                        val = 0
                        for i, bit in enumerate(bits):
                            if a <= bit <= b and (v >> i) & 1:
                                val |= 1 << (bit - a)
                        pat.append("%s=%d" % (field(slot, a, b), val))
                pp = join_c3(pat) if slot == "C3" else " & ".join(pat)
                pp = pp.replace(";", " & %s;" % regs[idx2], 1) if ";" in pp else pp + " & " + regs[idx2]
                lines.append("%s: %s is %s { export %s; }" % (tname, regs[idx2], pp, regs[idx2]))
            tables[tname] = lines
        return tname, tname, None, tname
    # immediate: off + sum(run value * weight of its low bit); a negative top weight makes the
    # run containing it signed
    terms, pats = [], []
    for lo, hi in runs(bits):
        for a, b in split_c3(slot, lo, hi):
            wl = w[bits.index(a)]
            neg = any(w[bits.index(x)] < 0 for x in range(a, b + 1))
            f = field(slot, a, b, signed=neg)
            pats.append(f)
            terms.append("(%s * %d)" % (f, wl))
    name = "imm%d" % idx
    expr = " + ".join(terms) + (" + %d" % off if off else "")
    return name, " & ".join(pats), "%s = %s;" % (name, expr), name


CCR_NAMES = set()


def outputs(syntax, mnem, n):
    """indices of written operands, from the opcode table's operand names"""
    names = syntax.split(" ", 1)[1].split(",") if " " in syntax else []
    outs = set()
    for i, nm in enumerate(names):
        if re.match(r"\$cro[cp]$", nm):
            outs.add(i)
    if (mnem.startswith("cpmovi") or mnem.startswith("cdmovi") or mnem in ("cmov", "cmovh", "cmovc")) and n:
        outs.add(0)
    return outs


def pcodeop_name(m):
    return "ivc2_" + m.replace(".", "_")


def constructor(slot, e, table):
    text = e["text"]
    m = text.partition(" ")[0]
    disp, pats, acts, exps = [], [], [], []
    for i, op in enumerate(e.get("operands", [])):
        d, p, a, x = operand(slot, op, i)
        disp.append(d)
        pats.append(p)
        if a:
            acts.append(a)
        exps.append(x)
    cons = ["%s=%d" % (f, v) for f, v, _ in constraint(slot, e["mask"], e["value"])]
    if slot == "C3":
        pieces, subs = list(cons), []
        for p in pats:
            for piece in p.split(" & "):
                (pieces if piece in fields else subs).append(piece)
        h = [p for p in pieces if fields[p.split("=")[0]][0] == "instr" and not p.startswith(("c3h_16_19=", "c3h_28_31="))]
        l = [p for p in pieces if fields[p.split("=")[0]][0] == "instr2"]
        pat = "(OM=0 & INVLIW=0 & major=15 & sub=7%s; %s)%s" % (
            "".join(" & " + c for c in h), " & ".join(l) or "wimm16", "".join(" & " + x for x in subs))
    else:
        pat = " & ".join(cons + pats) if cons + pats else "epsilon"
    mn = m.upper()
    if table == "instruction":
        head = ":%s %s" % (mn, ",".join(disp)) if disp else ":" + mn
    elif disp:
        head = '%s: "%s "^%s' % (table, mn, '^","^'.join(disp))
    else:
        head = '%s: "%s"' % (table, mn)
    act = (" [ " + " ".join(acts) + " ]") if acts else ""
    # semantics
    outs = outputs(e["syntax"] or text, m, len(exps))
    sem = semantics(m, exps, outs, e)
    return "%s is %s%s {\n%s\n}" % (head, pat, act, sem)


def semantics(m, exps, outs, e):
    if m in ("cmov", "cmovh") and len(exps) == 2:
        k0 = e["operands"][0]["kind"]
        if k0 == "c":   # cmov CRn,Rm
            if m == "cmov":
                return "\t%s = (%s & 0xffffffff00000000) | zext(%s);" % (exps[0], exps[0], exps[1])
            return "\t%s = (%s & 0xffffffff) | (zext(%s) << 32);" % (exps[0], exps[0], exps[1])
        return ("\t%s = %s:4;" if m == "cmov" else "\t%s = %s(4);") % (exps[0], exps[1])
    if m == "cmovc" and len(exps) == 2:
        return "\t%s = %s;" % (exps[0], exps[1])
    if m in ("c0nop", "c1nop"):
        return ""
    if m == "cpmov" and len(exps) == 2:
        return "\t%s = %s;" % (exps[0], exps[1])
    pre = "".join("\tlocal %s_v:4 = %s;\n" % (x, x) for x in exps if re.fullmatch(r"imm\d+", x))
    ins = [x + "_v" if re.fullmatch(r"imm\d+", x) else x for i, x in enumerate(exps) if i not in outs]
    call = "%s(%s)" % (pcodeop_name(m), ", ".join(ins))
    PCODEOPS.add(pcodeop_name(m))
    if outs:
        o = sorted(outs)[0]
        return pre + "\t%s = %s;" % (exps[o], call)
    return pre + "\t%s;" % call


PCODEOPS = set()
body = {"C3": [], "P0S": [], "P0": [], "P1": []}
TABLE = {"C3": "instruction", "P0S": "IVSlotP0S", "P0": "IVSlotP0", "P1": "IVSlotP1"}
for slot in ("C3", "P0S", "P0", "P1"):
    for e in sorted(spec[slot], key=lambda e: (e["text"].split(" ")[0], e["mask"], e["value"])):
        body[slot].append(constructor(slot, e, TABLE[slot]))

import os
D = sys.argv[2]
HDR = "# GENERATED by tools/gen_ivc2.py from tools/ivc2_spec.json.gz -- do not edit.\n"
with open(os.path.join(D, "ivc2_ctx.sinc"), "w") as f:
    f.write(HDR + "\n".join("\t" + d for t, d in sorted(fields.values()) if t == "ctx") + "\n")
for tok in ("instr", "instr2"):
    with open(os.path.join(D, "ivc2_%s.sinc" % tok), "w") as f:
        f.write(HDR + "\n".join("\t" + d for t, d in sorted(fields.values()) if t == tok) + "\n")
o = open(os.path.join(D, "ivc2.sinc"), "w")
w = lambda *a: o.write(" ".join(a) + "\n")
w(HDR + "# IVC2 coprocessor: core-mode (C3) instructions and VLIW bundles. See tools/gen_ivc2.py.")
w()
w("#IVC2 accumulators (CMOVC); the other IVC2 control registers are the ccr registers of")
w("#MeP-c5.sinc under their IVC2 names")
w("define register offset=0x18400 size=4 [ %s ];" % " ".join(
    sorted(n for n in CCR_NAMES if n.startswith("acc") or n == "ivc2_ccr_reserved")))
w()
for f, regs in sorted(attached.items()):
    w("attach variables [ %s ] [ %s ];" % (f, " ".join(regs)))
w()
for p in sorted(PCODEOPS):
    w("define pcodeop %s;" % p)
w()
for t in sorted(tables):
    w("\n".join(tables[t]))
    w()
for slot in ("P0S", "P0", "P1"):
    w("# ---- %s slot" % slot)
    w("\n".join(body[slot]))
    w()
w("# ---- core-mode coprocessor instructions (C3)")
w("\n".join(body["C3"]))
o.close()
