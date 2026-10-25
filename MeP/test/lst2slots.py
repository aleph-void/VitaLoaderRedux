#!/usr/bin/env python3
"""RealCheck listing ("<addr> <bytes-hex> <text>") -> slot format ("<addr> <len> <text>")."""
import sys
for line in open(sys.argv[1]):
    p = line.rstrip("\n").split(" ", 2)
    print("%s %d %s" % (p[0], len(p[1]) // 2, p[2] if len(p) > 2 else ""))
