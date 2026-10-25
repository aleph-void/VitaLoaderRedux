#!/usr/bin/env python3
"""Write the executable PROGBITS sections of a 32-bit ELF (either byte order) as one raw image.
  elf_exec_image.py <elf> <out.bin> [sections.txt]
    -> prints the base address (hex) and the byte order; sections.txt gets one line per
       executable section: <name> <start-hex> <end-hex>"""
import struct
import sys

d = open(sys.argv[1], "rb").read()
assert d[:4] == b"\x7fELF" and d[4] == 1, "ELF32 only"
e = "<" if d[5] == 1 else ">"
shoff, = struct.unpack_from(e + "I", d, 0x20)
shentsize, shnum = struct.unpack_from(e + "HH", d, 0x2e)
secs = []
for i in range(shnum):
    name, typ, flags, addr, off, size = struct.unpack_from(e + "IIIIII", d, shoff + i * shentsize)
    if typ == 1 and flags & 0x2 and flags & 0x4 and size:
        secs.append((addr, off, size, name))
lo = min(s[0] for s in secs)
hi = max(s[0] + s[2] for s in secs)
img = bytearray(hi - lo)
for a, o, s, _ in secs:
    img[a - lo:a - lo + s] = d[o:o + s]
open(sys.argv[2], "wb").write(img)
if len(sys.argv) > 3:
    shstrndx, = struct.unpack_from(e + "H", d, 0x32)
    stroff = struct.unpack_from(e + "IIIIII", d, shoff + shstrndx * shentsize)[4]
    with open(sys.argv[3], "w") as f:
        for a, o, s, n in secs:
            name = d[stroff + n:d.index(b"\0", stroff + n)].decode()
            f.write("%s %x %x\n" % (name, a, a + s))
print("%x %s" % (lo, "little" if e == "<" else "big"))
