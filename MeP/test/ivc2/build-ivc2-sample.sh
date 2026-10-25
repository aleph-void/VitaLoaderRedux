#!/usr/bin/env bash
# Build the IVC2 test program (VLIW-mode functions and hand-written bundles) with mep-elf-gcc:
#   test/ivc2/build-ivc2-sample.sh <outdir>   -> ivc2_le.elf, ivc2_be.elf
set -euo pipefail
H=$(cd "$(dirname "$0")" && pwd)
O=$(mkdir -p "$1" && cd "$1" && pwd)
for e in le be; do
	F="-O2 -g -mivc2 -m${e/le/el}"
	F=${F/-mbe/-meb}
	mep-elf-gcc $F -msimnovec -Wl,--noinhibit-exec -o "$O/ivc2_$e.elf" "$H/ivc2_sample.c" "$H/ivc2_vliw.S" 2>&1 |
		{ grep -E "error" | grep -v "relocation truncated|collect2|ld returned" || true; }
done
ls -l "$O"/ivc2_*.elf
