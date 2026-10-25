#!/usr/bin/env python3
"""MeP decode corpora, 4-byte slots (core instructions are 16 or 32 bits).

  gen_corpus.py <binutils-src>/opcodes/mep-opc.c <outdir>
     -> table_{le,be}.bin (+ table.txt: slot -> opcode-table entry), first_{le,be}.bin,
        fuzz_{le,be}.bin

table: 32 encodings of every mep_cgen_insn_opcode_table[] entry (core and IVC2 coprocessor),
       opcode bits fixed, other bits random
first: every first halfword with three random second halfwords
fuzz:  100,000 random slots
vliw:  64-bit IVC2 VLIW bundles (8-byte slots): every opcode-table entry that fits a coprocessor
       slot (P0S, P0, P1) placed in it with random other slots, then 50,000 random bundles
The big-endian files hold the same instruction halfwords as the little-endian ones, byte-swapped
per halfword. Fixed seeds; output is deterministic.
"""
import os
import random
import re
import struct
import sys

src, out = sys.argv[1], sys.argv[2]
text = open(src).read()
fmts = {}
for m in re.finditer(r"static const CGEN_IFMT (ifmt_\w+) ATTRIBUTE_UNUSED = \{\s*(\d+), (\d+), (0x[0-9a-f]+)", text):
    fmts[m.group(1)] = (int(m.group(2)), int(m.group(4), 16))
tab = text[text.index("mep_cgen_insn_opcode_table[MAX_INSNS]"):]
entries = []
for m in re.finditer(r"/\* (.*?) \*/\s*\{\s*\{[^}]*\},\s*\{.*?\},\s*& (ifmt_\w+), \{ (0x[0-9a-f]+) \}", tab, re.S):
    ln, mask = fmts[m.group(2)]
    if ln not in (16, 32):
        continue
    entries.append((m.group(1), ln, int(m.group(3), 16), mask))


def halves(w, ln):
    return [w] if ln == 16 else [w >> 16, w & 0xffff]


def emit(hws, le):
    return b"".join(struct.pack("<H" if le else ">H", h) for h in hws)


rnd = random.Random(7)
slots, lines = [], []
for name, ln, val, mask in entries:
    for _ in range(32):
        w = (val & mask) | (rnd.getrandbits(ln) & ~mask & ((1 << ln) - 1))
        hw = halves(w, ln)
        if ln == 16:
            hw.append(rnd.getrandbits(16))
        lines.append("%08x %s" % (4 * len(slots), name))
        slots.append(hw)
first = [[h, rnd.getrandbits(16)] for h in range(0x10000) for _ in range(3)]
rz = random.Random(1)
fuzz = [[rz.getrandbits(16), rz.getrandbits(16)] for _ in range(100000)]

def bundle(core, p0s=None, p0=None, p1=0):
    """bundle halfwords: V1 (core16 + P0S + P1), V3 (P0 + P1) or V2 (core32 + P1)"""
    if p0 is not None:
        return [0xf007 | ((p0 >> 24) << 8) | (((p0 >> 20) & 0xf) << 4), (p0 >> 4) & 0xffff,
                ((p0 & 0xf) << 12) | ((p1 >> 16) & 0xfff), p1 & 0xffff]
    if p0s is not None:
        return [core, p0s >> 4, ((p0s & 0xf) << 12) | ((p1 >> 16) & 0xfff), p1 & 0xffff]
    return [core >> 16, core & 0xffff, (rnd.getrandbits(4) << 12) | ((p1 >> 16) & 0xfff), p1 & 0xffff]


def core16():
    return (rnd.randrange(12) << 12) | rnd.getrandbits(12)


vliw = []
p0s_pool, p28_pool = [0], [0]
for name, ln, val, mask in entries:
    for _ in range(8):
        w = (val & mask) | (rnd.getrandbits(32) & ~mask & 0xffffffff)
        if ln == 32 and not w & 0xff00000f:
            p0s_pool.append((w >> 4) & 0xfffff)
        if ln == 32 and not w & 0xf:
            p28_pool.append(w >> 4)
other28 = lambda: rnd.choice(p28_pool) if rnd.getrandbits(1) else 0
for v in p0s_pool[1:]:
    vliw.append(bundle(core16(), p0s=v, p1=other28()))
for v in p28_pool[1:]:
    vliw.append(bundle(0, p0=v, p1=other28()))
    vliw.append(bundle(core16(), p0s=rnd.choice(p0s_pool), p1=v))
    vliw.append(bundle(0xc0000000 | rnd.getrandbits(28), p1=v))
rv = random.Random(3)
for _ in range(50000):
    vliw.append([rv.getrandbits(16) for _ in range(4)])
for nm, s in (("vliw", vliw),):
    for le in (True, False):
        open(os.path.join(out, "%s_%s.bin" % (nm, "le" if le else "be")), "wb").write(
            b"".join(emit(h, le) for h in s))
for nm, s in (("table", slots), ("first", first), ("fuzz", fuzz)):
    for le in (True, False):
        open(os.path.join(out, "%s_%s.bin" % (nm, "le" if le else "be")), "wb").write(
            b"".join(emit(h, le) for h in s))
open(os.path.join(out, "table.txt"), "w").write("\n".join(lines) + "\n")
print("%d opcode-table entries; table %d, first %d, fuzz %d slots; vliw %d bundles"
      % (len(entries), len(slots), len(first), len(fuzz), len(vliw)))
