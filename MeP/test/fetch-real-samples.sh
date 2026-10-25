#!/usr/bin/env bash
# Fetch public C sources (pinned, SHA-256 checked) and build them with mep-elf-gcc 6.5
# (build-toolchain.sh) into <outdir>/*.elf: little-endian (GCC's default configuration: every
# optional instruction, repeat loops), big-endian (-meb) and little-endian core-only (-mno-opts).
# Nothing fetched or built here is committed.
#   test/fetch-real-samples.sh <outdir>
# Sources and licences: Lua 5.4.7 (MIT), zlib 1.3.1 (zlib licence); newlib (BSD-style) and
# libgcc (GPL with the runtime exception) come from the toolchain.
# Links pass --noinhibit-exec: binutils 2.45 ld reports a bogus "relocation truncated to fit:
# R_MEP_UIMM24" for crtstuff's complex relocation (__CTOR_END__ - 4); the value written is right.
set -euo pipefail
O=$(mkdir -p "$1" && cd "$1" && pwd)
S=$O/src
mkdir -p "$S"
fetch() { # url sha256 file
	[[ -f $S/$3 ]] || curl -fsSL -o "$S/$3" "$1"
	echo "$2  $S/$3" | sha256sum -c --quiet
}
fetch https://www.lua.org/ftp/lua-5.4.7.tar.gz 9fbf5e28ef86c69858f6d3d34eccc32e911c1a28b4120ff3e84aaa70cfbf1e30 lua-5.4.7.tar.gz
fetch https://zlib.net/fossils/zlib-1.3.1.tar.gz 9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23 zlib-1.3.1.tar.gz
(cd "$S" && rm -rf lua-5.4.7 zlib-1.3.1 && tar xzf lua-5.4.7.tar.gz && tar xzf zlib-1.3.1.tar.gz)
mep-elf-gcc --version | head -1
Z="adler32.c compress.c crc32.c deflate.c gzclose.c gzlib.c gzread.c gzwrite.c infback.c inffast.c inflate.c inftrees.c trees.c uncompr.c zutil.c"
cc() { mep-elf-gcc "$@" -msimnovec -Wl,--noinhibit-exec 2>&1 | { grep -E "error" | grep -v "relocation truncated|collect2|ld returned" || true; }; }
for v in "le:-mel" "be:-meb" "le_noopts:-mel -mno-opts"; do
	n=${v%%:*} F="-O2 -g ${v#*:}"
	(cd "$S/lua-5.4.7/src" && cc $F -std=gnu99 -DLUA_USE_C89 -o "$O/${n}_lua.elf" \
		$(ls ./*.c | grep -v luac.c) -lm)
	for p in example minigzip; do
		(cd "$S/zlib-1.3.1" && cc $F -include unistd.h -I. -o "$O/${n}_zlib_$p.elf" test/$p.c $Z)
	done
done
# The same programs with the coprocessor field of e_flags cleared (EF_MEP_COP_NONE): the opinion
# then picks MeP-c5:LE:32:CMeP (little-endian) and MeP-c5:BE:32:default (big-endian), so every
# language is tested on real code (GCC marks everything IVC2 in its default configuration).
for f in "$O"/le_noopts_*.elf "$O"/be_*.elf; do
	n=$(basename "$f")
	n=${n/le_noopts_/le_nocop_}
	n=${n/be_/be_nocop_}
	python3 - "$f" "$O/$n" <<'PY'
import struct, sys
d = bytearray(open(sys.argv[1], "rb").read())
e = "<" if d[5] == 1 else ">"
flags, = struct.unpack_from(e + "I", d, 0x24)
struct.pack_into(e + "I", d, 0x24, flags & ~0x00ff0000)
open(sys.argv[2], "wb").write(d)
PY
done
"$(dirname "$0")/ivc2/build-ivc2-sample.sh" "$O"
ls -l "$O"/*.elf
