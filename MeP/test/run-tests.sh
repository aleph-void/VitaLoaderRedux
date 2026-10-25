#!/usr/bin/env bash
# MeP processor module tests.
#
#   test/run-tests.sh [workdir]
#
# 1. compile every SLEIGH spec, build the Java loader extension into lib/ (Ghidra's gradle wrapper)
#    and link the module into $GHIDRA_INSTALL_DIR/Ghidra/Processors/MeP
# 2. decode corpora (gen_corpus.py): 32 encodings of every entry of binutils' MeP opcode table,
#    every first halfword with three second halfwords, 100,000 random words (4-byte slots), and
#    IVC2 VLIW bundles (8-byte slots); Ghidra (DumpSlots.java) vs GNU objdump's disassembler
#    (slotdis, binutils 2.45 libopcodes) as follows, scored by compare.py:
#      MeP-c5:LE:32:default, MeP-c5:BE:32:default, MeP-c5:LE:32:CMeP vs objdump -m c5 (core)
#      MeP-c5:LE/BE:32:IVC2 vs objdump on an IVC2 object (core mode, and VLIW mode for bundles)
# 3. every-entry decode tests: CoverageCheck.java (core languages) and ivc2_coverage.py
#    (every generated IVC2 slot form appears in the decodings)
# 4. the IVC2 spec and generated SLEIGH are reproducible: ivc2_learn.py re-learns the spec from
#    objdump and gen_ivc2.py regenerates data/languages/ivc2*.sinc; both must be unchanged
# 5. p-code emulator tests (emu_tests.py, EmuCheck.java); needs mep-elf-as/ld
# 6. if REAL_SAMPLES is set (fetch-real-samples.sh output): real-binaries.sh
#
# Environment: GHIDRA_INSTALL_DIR; BU_SRC (binutils 2.45 source: opcodes/mep-opc.c seeds the
# corpora and the IVC2 learning); SLOTDIS, or BU_BUILD (a binutils build tree configured
# --target=mep-elf, see build-toolchain.sh) to build it from slotdis.c; mep-elf-* on PATH.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(cd "$HERE/.." && pwd)
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}" "${BU_SRC:?set BU_SRC}"
W=$(mkdir -p "${1:-$PWD/mep-test-work}" && cd "${1:-$PWD/mep-test-work}" && pwd)
cd "$W"

echo "== compiling SLEIGH and the loader extension"
for s in "$MOD"/data/languages/*.slaspec; do
	"$GHIDRA_INSTALL_DIR/support/sleigh" "$s" 2>&1 | grep -E "^ERROR|^Error" || true
done
ls -l "$MOD"/data/languages/*.sla | awk '{print "   " $5, $9}'
if [[ ! -f $MOD/lib/MeP.jar || -n $(find "$MOD/src" -newer "$MOD/lib/MeP.jar" -name '*.java') ]]; then
	# Ghidra's bundled Gradle wrapper refuses non-PUBLIC/DEV installs; then use gradle on PATH
	GRADLE=$GHIDRA_INSTALL_DIR/support/gradle/gradlew
	grep -qE '^application.release.name=(PUBLIC|DEV)$' "$GHIDRA_INSTALL_DIR/Ghidra/application.properties" ||
		GRADLE=gradle
	(cd "$MOD" && GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR "$GRADLE" --no-daemon -q buildExtension \
		>"$W/gradle.log" 2>&1 && mkdir -p lib &&
		unzip -o -q -j dist/*.zip '*/lib/MeP.jar' -d lib && touch lib/MeP.jar && rm -rf dist build .gradle) ||
		{ tail -20 "$W/gradle.log" >&2; echo "building lib/MeP.jar failed" >&2; exit 1; }
fi
P="$GHIDRA_INSTALL_DIR/Ghidra/Processors/MeP"
if [[ ! -e $P ]]; then ln -s "$MOD" "$P"; elif [[ $(readlink -f "$P") != "$MOD" ]]; then
	echo "warning: $P exists and is not this module" >&2; fi

if [[ -z ${SLOTDIS:-} ]]; then
	: "${BU_BUILD:?set SLOTDIS, or BU_BUILD to build it}"
	SLOTDIS=$W/slotdis
	gcc -O2 -DPACKAGE=1 -DPACKAGE_VERSION=1 -include "$BU_BUILD/bfd/config.h" -o "$SLOTDIS" \
		"$HERE/slotdis.c" -I"$BU_BUILD/bfd" -I"$BU_SRC/include" -I"$BU_SRC/bfd" \
		"$BU_BUILD/opcodes/.libs/libopcodes.a" "$BU_BUILD/bfd/.libs/libbfd.a" \
		"$BU_BUILD/libiberty/libiberty.a" "$BU_BUILD/libsframe/.libs/libsframe.a" \
		"$BU_BUILD/zlib/libz.a" -lzstd 2>/dev/null
fi
export SLOTDIS
# IVC2 template objects: the disassembler takes the coprocessor from e_flags and the operation
# mode from the section (.vtext is a VLIW section)
printf '\t.text\n\tnop\n\t.section .vtext,"axv"\n\t.vliw\n\tnop\n\tnop\n' >tmpl.s
mep-elf-as -EL tmpl.s -o tmpl_le.o
mep-elf-as -EB tmpl.s -o tmpl_be.o

echo "== decode corpora vs GNU objdump"
python3 "$HERE/gen_corpus.py" "$BU_SRC/opcodes/mep-opc.c" .
run() { # tag language corpus slot oracle-file [ctx...]
	local tag=$1 lang=$2 c=$3 slot=$4 ref=$5
	shift 5
	"$HERE/ghidra-slots.sh" "$lang" "$c.bin" "$slot" "g_${tag}_$c.txt" "$@"
	echo "-- $c: $lang vs $ref"
	python3 "$HERE/compare.py" "g_${tag}_$c.txt" "$ref" 3 | tee "cmp_${tag}_$c.txt" | grep -v '^      ' | grep -v '\] ~' | head -12
}
for e in le be; do
	big=(); [[ $e == be ]] && big=(-e big)
	E=$(tr a-z A-Z <<<"$e")
	for c in table first fuzz; do
		"$SLOTDIS" c5 4 "${c}_$e.bin" "${big[@]}" >"o_${c}_c5_$e.txt"
		"$SLOTDIS" c5 4 "${c}_$e.bin" "${big[@]}" -s "tmpl_$e.o" .text >"o_${c}_ivc2_$e.txt"
		run "$e" "MeP-c5:$E:32:default" "${c}_$e" 4 "o_${c}_c5_$e.txt"
		run "ivc2$e" "MeP-c5:$E:32:IVC2" "${c}_$e" 4 "o_${c}_ivc2_$e.txt"
		[[ $e == le ]] && run cmep MeP-c5:LE:32:CMeP "${c}_le" 4 "o_${c}_c5_le.txt"
	done
	"$SLOTDIS" c5 8 "vliw_$e.bin" "${big[@]}" -s "tmpl_$e.o" .vtext >"o_vliw_ivc2_$e.txt"
	run "ivc2$e" "MeP-c5:$E:32:IVC2" "vliw_$e" 8 "o_vliw_ivc2_$e.txt" OM=1
done

echo "== every-entry decode tests"
head -c 64 /dev/zero >zero.bin
# IVC2 slot forms have their own targeted coverage check below. The generic constructor
# search is useful for the core languages but expands to hundreds of millions of attempts
# on IVC2's large subtables without improving the slot-form result.
for l in LE:32:default BE:32:default LE:32:CMeP; do
	f=cov_${l//:/_}.txt
	"$HERE/ghidra-script.sh" raw "MeP-c5:$l" zero.bin CoverageCheck.java "$W/$f" 256
	echo "-- MeP-c5:$l: $(tail -1 "$f")"
	grep '^unreached' "$f" | grep -v ' IVSlot\| IV[CXR]_' | head -20 || true
done
python3 "$HERE/ivc2_coverage.py" "$MOD/tools/ivc2_spec.json.gz" g_ivc2le_table_le.txt g_ivc2le_first_le.txt \
	g_ivc2le_fuzz_le.txt --vliw g_ivc2le_vliw_le.txt | tee ivc2_cov.txt | tail -5

echo "== IVC2 spec and generated SLEIGH are reproducible"
(cd "$MOD/tools" && python3 ivc2_learn.py "$SLOTDIS" "$W/tmpl_le.o" "$BU_SRC/opcodes/mep-opc.c" 2>/dev/null) >spec.json
python3 -c "import gzip,json,sys; a=json.load(open('spec.json')); b=json.load(gzip.open(sys.argv[1],'rt')); print('spec: ' + ('same' if a == b else 'DIFFERENT'))" "$MOD/tools/ivc2_spec.json.gz"
mkdir -p gen && (cd "$MOD/tools" && python3 gen_ivc2.py ivc2_spec.json.gz "$W/gen")
for f in gen/*.sinc; do cmp -s "$f" "$MOD/data/languages/$(basename "$f")" && echo "   $(basename "$f"): same" ||
	echo "   $(basename "$f"): DIFFERENT"; done

echo "== p-code emulator tests"
python3 "$HERE/emu_tests.py" .
for e in le be; do
	E=$(tr a-z A-Z <<<"$e")
	"$HERE/ghidra-script.sh" raw "MeP-c5:$E:32:default" "emu_$e.bin" EmuCheck.java "$W/emu_$e.txt" "$W/emu_${e}_out.txt"
	"$HERE/ghidra-script.sh" raw "MeP-c5:$E:32:IVC2" "emu_ivc2_$e.bin" EmuCheck.java "$W/emu_ivc2_$e.txt" \
		"$W/emu_ivc2_${e}_out.txt" 20000 2ffff
	grep -v '^PASS' "emu_${e}_out.txt" "emu_ivc2_${e}_out.txt" || true
done

if [[ -n ${REAL_SAMPLES:-} ]]; then
	echo "== real binaries"
	"$HERE/real-binaries.sh" "$REAL_SAMPLES" "$W/real"
fi

echo "== summary"
grep -H "^compared" cmp_*.txt | sed 's/^cmp_//; s/\.txt:/: /'
grep -H "^coverage" cov_*.txt | sed 's/\.txt:/: /'
tail -1 ivc2_cov.txt
tail -qn1 emu_*_out.txt
