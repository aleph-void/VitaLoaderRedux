#!/usr/bin/env python3
"""Learn the IVC2 coprocessor instruction encodings from GNU objdump (black box) and write a
compact spec for gen_ivc2.py.

  ivc2_learn.py <slotdis-mep> <template.o> <binutils-src>/opcodes/mep-opc.c > ivc2_spec.json

slotdis-mep is test/slotdis.c built against a mep-elf binutils; template.o an IVC2 object
assembled by mep-elf-as -mconfig=default with a VLIW section (see run-tests.sh).

Method (as the SASS and C7x modules of Ghidra-Rare): the opcode table only seeds the search
with one encoding per entry and gives each operand's role (o = output); every encoding fact is
learned by asking the disassembler:
  1. decode seeds and random words in each slot (C3, P0S, P0, P1) and group the results into
     forms: mnemonic plus operand kinds (c = coprocessor register, r = general register,
     i = immediate, x = coprocessor control register name);
  2. for a few samples of each form, flip every bit: a bit that changes operand k in any sample
     belongs to operand k; otherwise one that changes the form is an opcode bit, and one that
     changes nothing is ignored;
  3. split forms whose samples disagree on opcode bits, and keep the opcode bits' values;
  4. learn each operand's value as offset + sum(bit * weight) from single-bit flips and check
     it on random operand values (names of control registers are tabulated per value).
Deterministic (fixed seeds, sorted output).
"""
import json
import random
import re
import sys

from ivc2_oracle import Oracle

NBITS = {"C3": 32, "P0S": 20, "P0": 28, "P1": 28}
GPR = {"tp": 13, "gp": 14, "sp": 15}


def kind(op):
    op = op.strip()
    if re.fullmatch(r"\$c\d+", op):
        return "c"
    if re.fullmatch(r"\$(\d+|tp|gp|sp)", op):
        return "r"
    if re.fullmatch(r"-?(0x[0-9a-f]+|\d+)", op):
        return "i"
    return "x"


def parse(t):
    m, _, ops = t.partition(" ")
    ops = [o.strip() for o in ops.split(",")] if ops else []
    return m, ops


def form_of(t):
    m, ops = parse(t)
    return m + "/" + "".join(kind(o) for o in ops)


def opval(op):
    op = op.strip()
    k = kind(op)
    if k == "c":
        return int(op[2:])
    if k == "r":
        n = op[1:]
        return GPR.get(n, None) if not n.isdigit() else int(n)
    if k == "i":
        return int(op, 0)
    return op


def seeds(opc_path):
    text = open(opc_path).read()
    fmts = {m.group(1): int(m.group(4), 16) for m in re.finditer(
        r"static const CGEN_IFMT (ifmt_\w+) ATTRIBUTE_UNUSED = \{\s*(\d+), (\d+), (0x[0-9a-f]+)", text)}
    tab = text[text.index("mep_cgen_insn_opcode_table[MAX_INSNS]"):]
    out = []
    for m in re.finditer(r"/\* (.*?) \*/\s*\{\s*\{[^}]*\},\s*\{.*?\},\s*& (ifmt_\w+), \{ (0x[0-9a-f]+) \}",
                         tab, re.S):
        out.append((m.group(1), fmts[m.group(2)], int(m.group(3), 16)))
    return out


def slot_value(slot, w):
    if slot == "C3":
        return w if (w >> 28) == 0xf and ((w >> 16) & 0xf) == 7 else None
    if slot == "P0S":
        return None if w & 0xff00000f else (w >> 4) & 0xfffff
    return None if w & 0xf else w >> 4


def main():
    o = Oracle(sys.argv[1], sys.argv[2])
    ents = seeds(sys.argv[3])
    rnd = random.Random(11)
    spec = {}
    for slot in ("C3", "P0S", "P0", "P1"):
        nb = NBITS[slot]
        vals, roles = [], []
        for syn, mask, val in ents:
            for _ in range(12):
                v = slot_value(slot, (val & mask) | (rnd.getrandbits(32) & ~mask & 0xffffffff))
                if v is not None:
                    vals.append(v)
                    roles.append(syn)
        for _ in range(30000):
            v = rnd.getrandbits(nb)
            if slot == "C3":
                v = (v & 0x0ff0ffff) | 0xf0070000
            vals.append(v)
            roles.append(None)
        txt = o.decode(slot, vals)
        forms = {}
        for v, t, syn in zip(vals, txt, roles):
            if not t:
                continue
            f = forms.setdefault(form_of(t), {"samples": {}, "syntax": None})
            f["samples"][v] = t
            if syn and syn.split(" ")[0] == t.split(" ")[0] and f["syntax"] is None:
                f["syntax"] = syn
        # bit-flip classification
        queries = []
        plan = []
        for fk in sorted(forms):
            smp = sorted(forms[fk]["samples"])
            rnd.shuffle(smp)
            # prefer samples whose operands are all printable (control registers without a
            # name print as ???, and flipping between two unnamed ones changes nothing)
            smp.sort(key=lambda s: "???" in forms[fk]["samples"][s])
            smp = sorted(smp[:10])
            plan.append((fk, smp))
            for s in smp:
                for b in range(nb):
                    queries.append(s ^ (1 << b))
        res = o.decode(slot, queries)
        qi = 0
        entries = []
        for fk, smp in plan:
            nops = len(parse(forms[fk]["samples"][smp[0]])[1])
            votes = [dict(op=0, ign=0, **{"o%d" % k: 0 for k in range(nops)}) for _ in range(nb)]
            for s in smp:
                base = parse(forms[fk]["samples"][s])
                for b in range(nb):
                    t = res[qi]
                    qi += 1
                    if not t or form_of(t) != fk:
                        votes[b]["op"] += 1
                        continue
                    _, ops = parse(t)
                    ch = [k for k in range(nops) if ops[k] != base[1][k]]
                    if not ch:
                        votes[b]["ign"] += 1
                    for k in ch:
                        votes[b]["o%d" % k] += 1
            cls = []
            for b in range(nb):
                v = votes[b]
                ops = {k: n for k, n in v.items() if k.startswith("o") and k != "op" and n}
                if ops:
                    cls.append(max(sorted(ops), key=lambda k: ops[k]))
                else:
                    cls.append("op" if v["op"] else "ign")
            opmask = sum(1 << b for b in range(nb) if cls[b] == "op")
            # split by opcode-bit values
            groups = {}
            for s in forms[fk]["samples"]:
                groups.setdefault(s & opmask, []).append(s)
            for ov in sorted(groups):
                entries.append({"form": fk, "mask": opmask, "value": ov, "cls": cls,
                                "samples": sorted(groups[ov])[:8], "syntax": forms[fk]["syntax"],
                                "text": forms[fk]["samples"][groups[ov][0]]})
        # operand value models
        queries, plan = [], []
        for e in entries:
            nops = len(parse(e["text"])[1])
            base = e["samples"][0]
            for k in range(nops):
                bits = [b for b in range(nb) if e["cls"][b] == "o%d" % k]
                z = base & ~sum(1 << b for b in bits)
                qs = [z] + [z | (1 << b) for b in bits]
                combos = [z | sum((1 << b) for b in bits if rnd.getrandbits(1)) for _ in range(12)]
                full = []
                if len(bits) <= 6:
                    full = [z | sum(((r >> i) & 1) << b for i, b in enumerate(bits)) for r in range(1 << len(bits))]
                plan.append((e, k, bits, z, qs, combos, full))
                queries += qs + combos + full
        res = o.decode(slot, queries)
        qi = 0
        for e, k, bits, z, qs, combos, full in plan:
            r = res[qi:qi + len(qs) + len(combos) + len(full)]
            qi += len(qs) + len(combos) + len(full)
            vals = [opval(parse(t)[1][k]) if t and form_of(t) == e["form"] else None for t in r]
            op = {"bits": bits}
            kd = kind(parse(e["text"])[1][k])
            op["kind"] = kd
            if kd == "x" or vals[0] is None or any(isinstance(v, str) for v in vals if v is not None):
                names = {}
                for (rv, t) in zip(range(1 << len(bits)), vals[len(qs) + len(combos):]):
                    names[rv] = t
                op["names"] = names
            else:
                off = vals[0]
                w = [(vals[1 + i] - off) if vals[1 + i] is not None else None for i in range(len(bits))]
                op["offset"], op["weights"] = off, w
                ok = all(v is None or v == off + sum(wt for b, wt in zip(bits, w) if q >> b & 1)
                         for q, v in zip(combos, vals[len(qs):len(qs) + len(combos)]))
                op["checked"] = ok
            e.setdefault("operands", []).append(op)
        for e in entries:
            del e["samples"]
        spec[slot] = entries
        print("%s: %d forms, %d encodings" % (slot, len(forms), len(entries)), file=sys.stderr)
    json.dump(spec, sys.stdout, indent=0, sort_keys=True)


if __name__ == "__main__":
    main()
