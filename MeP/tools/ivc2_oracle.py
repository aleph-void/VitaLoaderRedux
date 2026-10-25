#!/usr/bin/env python3
"""Drive GNU objdump's MeP disassembler (slotdis built against a mep-elf binutils) on IVC2
coprocessor slot encodings. Used by ivc2_learn.py.

Slots (binutils terms): C3 = 32-bit coprocessor instruction in core mode (major 15, sub 7);
P0S = 20-bit slot after a 16-bit core instruction in a 64-bit VLIW bundle; P0 = 28-bit slot of
a bundle without a core instruction; P1 = the last 28 bits of every bundle.
Bundle layout, as halfwords H0..H3 (L0..L7 the big-endian bytes of H0..H3):
  V1 (L0 < 0xc0):              core16 = H0, P0S = L2:L3:L4[7:4], P1 = L4[3:0]:L5:L6:L7
  V3 (L0 = 0xf?, L1 = 0x?7):   P0 = L0[3:0]:L1[7:4]:L2:L3:L4[7:4], P1 as above
  V2 (otherwise):              core32 = H0:H1, L4[7:4] ignored, P1 as above
"""
import os
import struct
import subprocess
import tempfile


class Oracle:
    def __init__(self, slotdis, tmpl):
        self.slotdis, self.tmpl = slotdis, tmpl

    def _run(self, words, slot, section):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            for hw in words:
                f.write(b"".join(struct.pack("<H", h) for h in hw))
            name = f.name
        try:
            out = subprocess.run([self.slotdis, "c5", str(slot), name, "-s", self.tmpl, section],
                                 capture_output=True, text=True, check=True).stdout
        finally:
            os.unlink(name)
        res = []
        for line in out.splitlines():
            p = line.split(" ", 2)
            res.append((int(p[1]), p[2] if len(p) > 2 else ""))
        return res

    @staticmethod
    def bundle(slot, v, core=0):
        if slot == "P0S":
            return [core, v >> 4, (v & 0xf) << 12, 0]
        if slot == "P1":
            return [core, 0, (v >> 16) & 0xfff, v & 0xffff]
        if slot == "P0":
            l0 = 0xf0 | (v >> 24)
            l1 = (((v >> 20) & 0xf) << 4) | 7
            return [(l0 << 8) | l1, (v >> 4) & 0xffff, (v & 0xf) << 12, 0]
        raise ValueError(slot)

    def decode(self, slot, values):
        """-> list of slot texts ('' when the disassembler rejects the slot)"""
        if slot == "C3":
            r = self._run([[v >> 16, v & 0xffff] for v in values], 4, ".text")
            return [t if n == 4 and "unknown" not in t else "" for n, t in r]
        r = self._run([self.bundle(slot, v) for v in values], 8, ".vtext")
        out = []
        for n, t in r:
            parts = [p.strip() for p in t.split(" + ")]
            idx = {"P0S": 1, "P1": -1, "P0": 0}[slot]
            s = parts[idx] if len(parts) >= 2 else ""
            out.append("" if "unknown" in s or not s else s)
        return out
