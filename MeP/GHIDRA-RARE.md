# Ghidra-Rare notes: Toshiba MeP (Media embedded Processor)

Ghidra processor module for the Toshiba MeP-c4/MeP-c5 cores (and MeP-h1 code, which uses the
same core encodings), with the IVC2 coprocessor ("Venezia") and its VLIW operation mode. It is a
community module: the MeP-c5 language of [CreepNT/VitaLoaderRedux](https://github.com/CreepNT/VitaLoaderRedux)
(Clear BSD License), moved into this standalone module, completed, tested against GNU binutils
and fixed. See [CREDITS.md](CREDITS.md) for provenance and the list of changes.

| Language ID | Use |
|---|---|
| `MeP-c5:LE:32:CMeP` | upstream's language: PlayStation Vita CMeP (MeP-c5 core options, no coprocessor, UCI or DSP). The ELF opinion picks it for little-endian files without a coprocessor in `e_flags` |
| `MeP-c5:LE:32:default`, `MeP-c5:BE:32:default` | every core option, UCI, DSP, coprocessor loads/stores, BCPxx, JSRV/BSRV (big-endian is GCC's `-meb`) |
| `MeP-c5:LE:32:IVC2`, `MeP-c5:BE:32:IVC2` | the default set plus the IVC2 coprocessor: core-mode IVC2 instructions and 64-bit VLIW bundles. Picked for `EF_MEP_COP_IVC2`, which GCC's default configuration sets on every file |

Installation: the module's release zip (this fork's Releases page) or `gradle buildExtension`
with `GHIDRA_INSTALL_DIR` set; it contains a small Java part (the ELF loader extension and the
relocation handler), so the module must be built, not just copied.

## Results

Reference: GNU binutils 2.45 (`objdump -m c5` and an IVC2 object for coprocessor/VLIW
decoding), via `test/slotdis.c`. Semantic agreement where both decode; "objdump-only" = encodings
objdump decodes and the module rejects, "Ghidra-only" the reverse.

| Test | Result |
|---|---|
| Decode, MeP-c5:LE/BE:32:default vs objdump c5 core | opcode table (29,632): 100.00%, 0 objdump-only, 0 Ghidra-only; every first halfword x 3 (196,608): 100.00%, 0/0; 100,000 random words: 100.00%, 0/0. Exact text 98.8-99.3% (the rest: objdump prints negative branch targets as 64-bit addresses, `???` for reserved control registers, `--syscall--`) |
| Decode, MeP-c5:LE:32:CMeP | 100.00% where both decode, 0 Ghidra-only; objdump-only are only the coprocessor, UCI and DSP instructions this configuration leaves out |
| Decode, MeP-c5:LE/BE:32:IVC2 vs objdump on an IVC2 object | core mode: 100.00% on all three corpora (27,507 / 155,968 / 79,241 decoded), 0/0; VLIW bundles (62,155 slots, 11,505 valid bundles): 100.00%, 0/0 |
| Every-entry decode test | `CoverageCheck.java`: every constructor reached in CMeP (194), default (248) and the core part of IVC2; `ivc2_coverage.py`: all 881 IVC2 forms (293 C3, 135 P0S, 131 P0, 322 P1) appear in Ghidra's decodings |
| Reproducibility | `ivc2_learn.py` re-learns the identical IVC2 spec from objdump; `gen_ivc2.py` regenerates identical SLEIGH |
| p-code emulator (`EmuCheck.java`) | 49/49 (LE) and 49/49 (BE): moves, ALU, overflow checks, shifts/FSFT/SSARB (byte-order dependent), extensions, multiply/MADD, DIV special cases, min/max/abs/ave/clip/saturation, LDZ, loads/stores in every addressing mode, bit ops/TAS, CAS, branches, calls/returns, GCC's `jmp $11` return, REPEAT/EREPEAT, control registers incl. write masks, DI/EI/RETI/HALT, control bus, coprocessor loads/stores incl. post-increment and modulo addressing, BCP. IVC2: 6/6 (LE and BE): CMOV/CMOVH/CMOVC/CPMOV, core->VLIW calls (BSRV), a VLIW repeat loop, a bundle whose core slot branches, GCC's mode-switching sibling call. A deliberately wrong expectation fails |
| Real binaries | 15 GCC 6.5 ELFs from public source plus the VLIW test program in both byte orders (below), imported without forcing the language: the opinion picks CMeP, default (BE) and IVC2 as intended; 9,117 functions, 790,111 instructions; 0 bad-instruction bookmarks; every function decompiles (0 failures, 0 timeouts); disassembly 100% semantic (99.9-99.98% exact) vs objdump at the same addresses, VLIW sections included; 0 relocation, loader or DWARF-map errors |
| Relocatable objects | zlib `.o` files (LE and BE): every relocation applied (85/95/29 per file), every call resolves to its callee |
| Builds | `.sla` 20 KB (CMeP), 25 KB (default), 92 KB (IVC2); builds with Ghidra 12.1.3, 12.1.4 and 12.2 |

Real-binary samples (`test/fetch-real-samples.sh`: pinned, SHA-256 checked, built with
`test/build-toolchain.sh`, GCC 6.5.0 + newlib 4.5.0 + binutils 2.45; never committed): Lua 5.4.7
(MIT) and the zlib 1.3.1 (zlib licence) example and minigzip programs, little-endian (GCC's
default: every option, repeat loops), big-endian and core-only (`-mno-opts`), and copies with
the coprocessor field of `e_flags` cleared (so the opinion picks CMeP and the big-endian default
language). `test/ivc2/` is a small own program with VLIW-mode C functions (`.vtext`), calls in
both directions between core and VLIW mode and hand-written IVC2 bundles.

What upstream got wrong, as imported (same corpora): 2,638 opcode-table encodings and 15,555
first halfwords that objdump decodes did not decode (MeP-c5 and coprocessor instructions);
NEG, SSARB, SADD/SSUB, DIV, REPEAT and the 32-bit coprocessor transfers computed wrong
results; every GCC function that saves LP returned through an unrecovered jump (`jmp $11`);
and every switch table using `$1` became a return. `xyzz/ghidra-mep` scores 85-93% and
`guedou/ghidra-processor-mep` 63-66% on the same corpora (see CREDITS.md).

## Upstream's known limitations

| Source | Limitation | State |
|---|---|---|
| README | "Implements most of the MeP-c4 instruction set" | Fixed: every core instruction binutils knows (MeP-c4, c5, h1) |
| README | "Coprocessor-modulo instructions are not implemented" | Fixed: A/M0/M1 forms with modulo addressing (emulator test `cop_modulo`) |
| README | "MeP-c5 instructions are not implemented (except PREF)" | Fixed |
| README, Future plans | "IVC2 coprocessor (i.e. Venezia core) is not implemented"; "Venezia (MeP + IVC2) support" | Fixed for decoding (100% vs objdump) and data flow; IVC2 operations other than the moves are user operations (below) |
| README, Future plans | "Full MeP-c5 implementation" | Fixed |
| `MeP-c5.sinc` TODO | "MeP-c5 instructions" | Fixed |
| `MeP-c5.sinc` TODOs | SBVCK3/ADVCK3, BCPxx "is this correct?" | Checked: decode vs objdump, semantics by emulator tests `overflow_check`, `bcp` |
| `MeP-c5.sinc` TODO | RETI "NMI handling etc" | Fixed: NMI returns to NPC; IEC/UMC restored (test `reti`) |
| `MeP-c5.sinc` TODO | SSUB underflow "Is this OK?" | Fixed (it was wrong: SSUB overflows towards the sign of Rn) |
| `MeP-c5.sinc` TODO | "when is CACHE enabled?" | CACHE decodes unconditionally, as in binutils |
| `STCLDC.sinc` TODOs | "SOME BITS ARE SUPPOSED TO BE READ-ONLY", "should we really clear the bits that are unwriteable?" | Fixed: STC writes only the writable bits (test `stc_masks`) |
| `MeP-c5.sinc` | "Emitting a write to CBusReg breaks the pcodeop disassembly" | Fixed: the control bus is a memory space (`cbus`) |
| `MeP-c5.sinc` | "BUG: Ghidra assumes contextreg to be 64-bit" | Not a limitation in Ghidra 12: the IVC2 languages use a 128-bit context register |
| `Options.sinc` | PTO_OPT/HWE_OPT "Useless?" | They are core options without instructions (program trace, hardware engine); kept as unused macros |
| `MeP-c5.sinc` | DSP/DSP0/DSP1 share one encoding | Decoded in binutils' form `DSP Rn,Rm,code16`; the operation is a user operation (below) |
| README "Known bugs" and issues #8, #20, #21, #23 (all on the ELF-PRX loader) | Demangler breaks import thunks; NID analyzer; scewebkit import; SDK types; PyGhidra | Out of scope: they concern the Vita ARM loader at the repository root, which is not part of this module and is unchanged |
| xyzz/ghidra-mep issue #1 (open) | 31 instructions not implemented | All decode here (ADVCK3 ... TAS) |

## Confirmed reference-tool behaviour

- objdump prints backward branch targets near address 0 as 64-bit addresses
  (`0xffffffffffff8ff4`); compared modulo 2^32.
- objdump prints reserved control registers as `???` and the GNU/SID simulator call as
  `--syscall--`.
- binutils 2.45 `ld` reports "relocation truncated to fit: R_MEP_UIMM24" for crtstuff's complex
  relocation (`__CTOR_END__ - 4`) although the value written is correct; the sample builds pass
  `--noinhibit-exec`.
- binutils 2.45 `as`: a REPEAT to a numeric local label (`9f`) inside a `.vliw` section gets the
  wrong displacement (the label resolves before bundling); named labels (as GCC emits) are right.
- GCC 6.5's MeP back end ICEs on libgcc's `unwind-dw2.c`; `test/build-toolchain.sh` builds
  libgcc without the DWARF unwinder (C only).

## Known gaps

- IVC2 operations (vector arithmetic, accumulators, shifts, compares, packing ...; 875 forms)
  other than CMOV/CMOVH/CMOVC/CPMOV are user operations: they write their output register and
  read their inputs, but their arithmetic and their implicit accumulator/condition state are
  not modelled. No public specification of the IVC2 operations exists; the only description,
  binutils/GCC's CGEN files, is GPL and cannot be copied into this Clear-BSD module, and no IVC2
  hardware or simulator is available to learn the semantics from.
- UCI and DSP instructions are user operations: their operation is defined by the custom logic a
  given chip was built with.
- CACHE, PREF, SYNCM, SYNCCP, BREAK, DBREAK, SWI and SLEEP keep user operations for the
  hardware effect (cache, pipeline, exceptions) besides the register updates that are modelled;
  divide by zero calls `DivideByZero()` (the exception) and leaves HI/LO unchanged.
- VLIW mode is entered from ELF section flags (`.vtext`), BSRV targets and the returns
  of VLIW calls; a JSRV or `jmp` to a computed VLIW address does not switch the target to VLIW
  mode (Ghidra cannot derive a context from a register value). VLIW32 coprocessors (other than
  IVC2) are not decoded: binutils knows none.
- The coprocessor slots of a bundle execute before its core slot in p-code (the hardware runs
  them in parallel).
- GCC returns with `jmp $11`; the module treats every `jmp $11` as a return except GCC's
  mode-switching sibling call (`stc $12,$lp` just before). Hand-written code that uses `jmp $11`
  for another purpose would be misread. Upstream treated `jmp $1` as a return as well; GCC uses
  `$1` for switch tables, so that was dropped (no CMeP binary with a free licence was available
  to check Vita code).
- newlib's `vfprintf` family (4 functions per image): the switch guard compares two registers,
  so the decompiler cannot bound the table ("Too many branches") — a decompiler limit.
- About 200 DWARF line-table error bookmarks per image: Ghidra's importer rejects the negative
  line numbers GCC 6's line programs produce (objdump shows the same entries).
- REPEAT blocks need the REPEAT instruction disassembled first (its target is marked by context).

Unverified: CMeP code from Sony's toolchain (PlayStation Vita firmware is not freely licensed;
not used) and IVC2 code from Toshiba's toolchain.

## Testing

```
test/build-toolchain.sh <workdir> <prefix>      # mep-elf binutils/gcc/newlib (once)
export PATH=<prefix>/bin:$PATH GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC
test/fetch-real-samples.sh <samples>            # optional: build the real-binary samples
BU_SRC=<binutils-2.45 source> BU_BUILD=<workdir>/build-binutils \
  REAL_SAMPLES=<samples> test/run-tests.sh <testdir>
```

`tools/ivc2_learn.py` relearns the IVC2 spec from objdump (`tools/ivc2_spec.json.gz`);
`tools/gen_ivc2.py` regenerates `data/languages/ivc2*.sinc` from it.
