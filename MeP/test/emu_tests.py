#!/usr/bin/env python3
"""P-code semantic tests for the MeP module, run in Ghidra's emulator by EmuCheck.java.

  emu_tests.py <outdir> [--break NAME]
      -> emu_{le,be}.s/.bin/.txt (MeP-c5:xx:32:default) and emu_ivc2_{le,be}.s/.bin/.txt
         (MeP-c5:xx:32:IVC2; VLIW code at 0x20000), assembled by mep-elf-as/ld (binutils)

Each test is a short instruction sequence at its own label. emu_*.txt has one line per test:
  <name> <start-hex> <stop-hex> <init: key=val,...|-> <expect: key=val,...>
Keys are register names ($0-$15 as r0-r12, tp, gp, sp; control registers; c0-c15), or
m1:/m2:/m4:/m8:<addr> for memory in the program's byte order. Values are hex. Before every test
r0-r12, tp, gp, hi, lo, sar, psw and the repeat registers are 0 and sp is 0x8000.
Expected values were worked out by hand from the MeP instruction definitions.
--break NAME makes that test's first expectation wrong, to show the harness can fail.
"""
import os
import subprocess
import sys

M = 0xffffffff


def tests(big):
    t = [
        ("mov_imm", ["mov $1,5", "mov $2,-2", "movu $3,0x123456", "movh $4,0x1234", "mov $5,-30000",
                     "movu $6,0xbeef"], {},
         {"r1": 5, "r2": 0xfffffffe, "r3": 0x123456, "r4": 0x12340000, "r5": (-30000) & M, "r6": 0xbeef}),
        ("add", ["add3 $3,$1,$2", "add $1,-1", "add3 $4,$2,-100", "add3 $5,$sp,8"], {"r1": 7, "r2": 10},
         {"r3": 17, "r1": 6, "r4": (-90) & M, "r5": 0x8008}),
        ("neg_sub", ["neg $3,$1", "sub $2,$1"], {"r1": 5, "r2": 3}, {"r3": (-5) & M, "r2": (-2) & M}),
        ("slt", ["slt3 $0,$1,$2", "mov $5,$0", "sltu3 $0,$1,$2", "mov $6,$0", "slt3 $0,$2,3", "mov $7,$0",
                 "slt3 $8,$1,-2", "sltu3 $9,$2,0x8000"],
         {"r1": M, "r2": 1}, {"r5": 1, "r6": 0, "r7": 1, "r8": 0, "r9": 1}),
        ("overflow_check", ["advck3 $0,$1,$2", "mov $5,$0", "sbvck3 $0,$3,$2", "mov $6,$0",
                            "advck3 $0,$2,$2", "mov $7,$0"],
         {"r1": 0x7fffffff, "r2": 1, "r3": 0x80000000}, {"r5": 1, "r6": 1, "r7": 0}),
        ("logic", ["or $1,$2", "and $3,$2", "xor $4,$2", "nor $5,$2", "or3 $6,$2,0x8000", "and3 $7,$1,0xff00",
                   "xor3 $8,$2,0xffff"],
         {"r1": 0xf0, "r2": 0x0f0f, "r3": 0xff, "r4": 0xffff, "r5": 0x1},
         {"r1": 0x0fff, "r3": 0x0f, "r4": 0xf0f0, "r5": 0xfffff0f0, "r6": 0x8f0f, "r7": 0x0f00, "r8": 0xf0f0}),
        ("shifts", ["sll $1,4", "srl $2,4", "sra $3,4", "sll3 $0,$4,8", "sra $5,$6", "srl $7,$6", "sll $8,$6"],
         {"r1": 0x10000001, "r2": 0x80000010, "r3": 0x80000010, "r4": 0xab, "r5": 0x80000000, "r6": 0x21,
          "r7": 0x80000000, "r8": 3},
         {"r1": 0x00000010, "r2": 0x08000001, "r3": 0xf8000001, "r0": 0xab00, "r5": 0xc0000000,
          "r7": 0x40000000, "r8": 6}),
        ("sladd", ["sl1ad3 $0,$1,$2", "mov $3,$0", "sl2ad3 $0,$1,$2"], {"r1": 3, "r2": 100},
         {"r3": 106, "r0": 112}),
        ("fsft", ["mov $3,8", "stc $3,$sar", "fsft $1,$2"], {"r1": 0x11223344, "r2": 0xaabbccdd},
         {"r1": 0x223344aa, "sar": 8}),
        # SAR = byte offset * 8 (big-endian) or 32 - offset * 8 (little-endian)
        ("ssarb", ["ssarb 1($2)", "ldc $3,$sar"], {"r2": 0x1001}, {"r3": 16 if big else 16}),
        ("ssarb2", ["ssarb 3($2)", "ldc $3,$sar"], {"r2": 0x1000}, {"r3": 24 if big else 8}),
        ("ext", ["extb $1", "exth $2", "extub $3", "extuh $4"], {"r1": 0x80, "r2": 0x8000, "r3": 0xfff1, "r4": M},
         {"r1": 0xffffff80, "r2": 0xffff8000, "r3": 0xf1, "r4": 0xffff}),
        ("mul", ["mul $1,$2", "ldc $3,$hi", "ldc $4,$lo", "mulu $1,$2", "ldc $5,$hi", "mulr $6,$2"],
         {"r1": 0xfffffffe, "r2": 3, "r6": 7},
         {"r3": M, "r4": 0xfffffffa, "r5": 2, "r6": 21, "hi": 0, "lo": 21}),
        ("madd", ["mov $3,1", "stc $3,$lo", "stc $0,$hi", "madd $1,$2", "maddr $1,$2", "ldc $4,$hi"],
         {"r1": 0x10000, "r2": 0x10000}, {"r1": 1, "lo": 1, "r4": 2}),
        ("maddu", ["maddu $1,$2", "ldc $3,$lo", "ldc $4,$hi", "maddru $1,$2"], {"r1": M, "r2": 2},
         {"r3": 0xfffffffe, "r4": 1, "r1": 0xfffffffc, "hi": 3}),
        ("div", ["div $1,$2", "ldc $3,$lo", "ldc $4,$hi", "divu $5,$2", "ldc $6,$lo", "ldc $7,$hi"],
         {"r1": (-7) & M, "r2": 2, "r5": 9}, {"r3": (-3) & M, "r4": M, "r6": 4, "r7": 1}),
        ("div_special", ["div $1,$2"], {"r1": 0x80000000, "r2": M}, {"lo": 0x80000000, "hi": 0}),
        ("minmax", ["min $1,$2", "max $3,$2", "minu $4,$2", "maxu $5,$2"],
         {"r1": 5, "r2": M, "r3": 5, "r4": 5, "r5": 5}, {"r1": M, "r3": 5, "r4": 5, "r5": M}),
        ("abs_ave", ["abs $1,$2", "ave $3,$4", "ave $5,$6"], {"r1": 3, "r2": 10, "r3": 5, "r4": 8, "r5": (-5) & M, "r6": 2},
         {"r1": 7, "r3": 7, "r5": (-1) & M}),
        ("clip", ["clip $1,5", "clip $2,5", "clip $3,5", "clipu $4,4", "clipu $5,4", "clip $6,0"],
         {"r1": 100, "r2": (-100) & M, "r3": 7, "r4": (-3) & M, "r5": 40, "r6": 9},
         {"r1": 15, "r2": (-16) & M, "r3": 7, "r4": 0, "r5": 15, "r6": 0}),
        ("saturate", ["sadd $1,$2", "sadd $3,$2", "ssub $4,$2", "saddu $5,$2", "ssubu $6,$7"],
         {"r1": 0x7ffffff0, "r2": 0x20, "r3": 1, "r4": 0x80000010, "r5": 0xfffffff0, "r6": 3, "r7": 5},
         {"r1": 0x7fffffff, "r3": 0x21, "r4": 0x80000000, "r5": M, "r6": 0}),
        ("sadd_neg", ["sadd $1,$2"], {"r1": 0x80000000, "r2": M}, {"r1": 0x80000000}),
        ("ldz", ["ldz $1,$2", "ldz $3,$4"], {"r2": 0x00010000, "r4": 0}, {"r1": 15, "r3": 32}),
        ("load_reg", ["lb $1,($5)", "lbu $2,($5)", "lh $3,($5)", "lhu $4,($5)", "lw $6,($5)"],
         {"r5": 0x4000, "m4:4000": 0x8081ff80 if not big else 0x80ff8180},
         {"r1": 0xffffff80, "r2": 0x80, "r3": 0xffff80ff if big else 0xffffff80, "r4": 0x80ff if big else 0xff80,
          "r6": 0x8081ff80 if not big else 0x80ff8180}),
        ("store_reg", ["sb $1,($5)", "sh $1,2($5)", "sw $1,4($5)"], {"r1": 0x11223344, "r5": 0x4000},
         {"m1:4000": 0x44, "m2:4002": 0x3344, "m4:4004": 0x11223344}),
        ("disp16", ["lw $1,-4($5)", "sw $1,0x100($5)", "lb $2,-1($5)", "lhu $3,-2($5)", "sb $3,0x110($5)"],
         {"r5": 0x4004, "m4:4000": 0xcafe8001},
         {"r1": 0xcafe8001, "m4:4104": 0xcafe8001, "r2": (0xffffffca if big else 0xffffffca) if not big else 0x01,
          "r3": 0x8001 if big else 0xcafe, "m1:4114": 0x01 if big else 0xfe}),
        ("sp_tp", ["sw $1,8($sp)", "lw $2,8($sp)", "sw $1,4($tp)", "sh $1,2($tp)", "sb $1,1($tp)",
                   "lbu $3,1($tp)", "lh $4,2($tp)", "lhu $5,2($tp)", "lw $6,4($tp)", "lb $7,1($tp)"],
         {"r1": 0x1234fe80, "tp": 0x5000},
         {"r2": 0x1234fe80, "m4:8008": 0x1234fe80, "r3": 0x80, "r4": 0xfffffe80, "r5": 0xfe80, "r6": 0x1234fe80,
          "r7": 0xffffff80}),
        ("abs24", ["sw $1,(0x4010)", "lw $2,(0x4010)"], {"r1": 0x55aa}, {"r2": 0x55aa, "m4:4010": 0x55aa}),
        ("bitops", ["bsetm ($5),3", "bclrm ($6),0", "bnotm ($7),7", "btstm $0,($5),3", "mov $1,$0",
                    "btstm $0,($6),0", "tas $2,($8)"],
         {"r5": 0x4000, "r6": 0x4001, "r7": 0x4002, "r8": 0x4003,
          "m1:4000": 0, "m1:4001": 0xff, "m1:4002": 0x80, "m1:4003": 0x5a},
         {"m1:4000": 8, "m1:4001": 0xfe, "m1:4002": 0, "r1": 8, "r0": 0, "r2": 0x5a, "m1:4003": 1}),
        ("cas_hit", ["casw3 $3,$4,($5)"], {"r3": 7, "r4": 9, "r5": 0x4000, "m4:4000": 7}, {"r3": 7, "m4:4000": 9}),
        ("cas_miss", ["casb3 $3,$4,($5)"], {"r3": 7, "r4": 9, "r5": 0x4000, "m1:4000": 8}, {"r3": 8, "m1:4000": 8}),
        ("branches", ["beqz $1,1f", "mov $9,1", "1: bnez $2,2f", "mov $9,2", "2: beqi $3,5,3f", "mov $9,3",
                      "3: bnei $3,4,4f", "mov $9,4", "4: blti $4,0,5f", "mov $9,5", "5: bgei $3,5,6f",
                      "mov $9,6", "6: beq $3,$5,7f", "mov $9,7", "7: bne $3,$4,8f", "mov $9,8", "8: bra 9f",
                      "mov $9,9", "9: nop"],
         {"r2": 1, "r3": 5, "r4": M, "r5": 5}, {"r9": 0}),
        ("branch_not_taken", ["beqz $2,1f", "add $9,1", "1: bgei $4,0,2f", "add $9,1", "2: blti $3,5,3f",
                              "add $9,1", "3: nop"], {"r2": 1, "r3": 5, "r4": M}, {"r9": 3}),
        ("call_ret", ["bsr sub_add", "mov $5,$0", "movu $6,sub_add", "jsr $6", "add3 $7,$0,0"],
         {"r1": 2, "r2": 3}, {"r5": 5, "r7": 5}),
        ("call24_jmp", ["bsr sub_far", "jmp 1f", "mov $9,1", "1: mov $10,2"], {}, {"r0": 0x77, "r9": 0, "r10": 2}),
        ("jmp_reg", ["movu $6,1f", "jmp $6", "mov $9,1", "1: nop"], {}, {"r9": 0}),
        # repeat: RPC = $1 = 3, the block (3 instructions) runs 4 times
        ("repeat", ["mov $1,3", "repeat $1,9f", "add $2,1", "9: add $3,1", "add $4,1", "mov $5,1"], {},
         {"r2": 4, "r3": 4, "r4": 4, "r5": 1, "rpc": 0}),
        ("erepeat", ["erepeat 9f", "beqi $2,5,8f", "9: add $2,1", "nop", "8: nop"], {}, {"r2": 5}),
        ("control_regs", ["stc $1,$rpb", "ldc $2,$rpb", "stc $1,$lp", "ldc $3,$lp", "stc $1,$mb1", "ldc $4,$mb1",
                          "ldc $5,$pc"], {"r1": 0x1234}, {"r2": 0x1234, "r3": 0x1234, "r4": 0x1234}),
        ("di_ei", ["ei", "ldc $1,$psw", "di", "ldc $2,$psw"], {}, {"r1": 1, "r2": 0}),
        # RETI: PSW.IEP (bit 1) -> IEC (bit 0), UMP (bit 3) -> UMC (bit 2); returns to EPC
        ("reti", ["movu $1,1f", "stc $1,$epc", "mov $2,0xa", "stc $2,$psw", "reti", "mov $9,1", "1: ldc $3,$psw"],
         {}, {"r9": 0, "r3": 0xf}),
        ("halt", ["halt", "ldc $1,$psw"], {}, {"r1": 0x800}),
        # STC writes only the writable bits: SAR 6 bits, PSW 10 bits, MB0 16 bits; ID is read-only
        ("stc_masks", ["stc $1,$sar", "ldc $2,$sar", "stc $1,$psw", "ldc $3,$psw", "stc $1,$mb0", "ldc $4,$mb0",
                       "stc $1,$id", "ldc $5,$id"], {"r1": M}, {"r2": 0x3f, "r3": 0x3ff, "r4": 0xffff, "r5": 0}),
        # GCC epilogue: the saved LP is reloaded into $11 and the function returns with jmp $11
        ("jmp11_return", ["bsr sub_gcc", "mov $5,$0"], {}, {"r5": 0x99}),
        ("control_bus", ["stcb $1,0x10", "ldcb $2,0x10", "mov $3,0x10", "ldcb $4,($3)", "stcb $1,($5)",
                         "ldcb $6,0x20"],
         {"r1": 0xabcd, "r5": 0x10020}, {"r2": 0xabcd, "r4": 0xabcd, "r6": 0xabcd}),
        ("cop_load_store", ["lwcp $c1,($5)", "swcp $c1,4($5)", "lmcp $c2,8($5)", "smcp $c2,16($5)",
                            "lwcpi $c3,($6+)", "smcpi $c2,($7+)"],
         {"r5": 0x4000, "r6": 0x4000, "r7": 0x4100, "m4:4000": 0x11223344, "m8:4008": 0x0102030405060708},
         {"m4:4004": 0x11223344, "m8:4010": 0x0102030405060708, "c1": 0x11223344, "r6": 0x4004, "r7": 0x4108,
          "m8:4100": 0x0102030405060708}),
        ("cop_post_inc", ["lbcpa $c1,($5+),-1", "lbucpa $c2,($5+),2", "shcpa $c1,($6+),6", "lhucp $c3,2($7)"],
         {"r5": 0x4001, "r6": 0x4100, "r7": 0x4000, "m4:4000": 0x8081ff80 if not big else 0x80ff8180},
         {"c1": 0xffffffff, "r5": 0x4002, "c2": 0x80, "m2:4100": 0xffff, "r6": 0x4106,
          "c3": 0x8081 if not big else 0x8180}),
        # modulo 0: MB0 = 0x1000, ME0 = 0x1008: mask = 0x1fff; at ME0 the pointer wraps to MB0
        ("cop_modulo", ["mov $1,0x1000", "stc $1,$mb0", "mov $1,0x1008", "stc $1,$me0", "swcpm0 $c1,($5+),4",
                        "swcpm0 $c1,($5+),4", "swcpm0 $c1,($5+),4"],
         {"r5": 0x1004, "c1": 0x77}, {"r5": 0x1004, "m4:1004": 0x77, "m4:1008": 0x77, "m4:1000": 0x77}),
        ("bcp", ["bcpeq 0,1f", "mov $9,1", "1: nop"], {"ccr1": 0}, {"r9": 0}),
    ]
    return t


# IVC2 language (MeP-c5:xx:32:IVC2): core-mode coprocessor moves and VLIW-mode code. VLIW
# functions live in .vtext at 0x20000 (EmuCheck sets OM=1 there); bundles are written with gas's
# "+" continuation lines.
IVC2_TESTS = [
    ("ivc2_cmov", ["cmov $c1,$1", "cmovh $c1,$2", "cpmov $c2,$c1", "cmov $3,$c2", "cmovh $4,$c2"],
     {"r1": 0x11223344, "r2": 0x55667788}, {"r3": 0x11223344, "r4": 0x55667788, "c1": 0x5566778811223344}),
    ("ivc2_cmovc", ["cmovc $csar0,$1", "cmovc $2,$csar0"], {"r1": 0x1f}, {"r2": 0x1f}),
    ("vliw_call", ["bsrv vadd", "mov $5,$0"], {"r1": 20, "r2": 22}, {"r5": 42}),
    ("vliw_repeat", ["movu $1,0x4000", "mov $2,4", "bsrv vsum"],
     {"m4:4000": 1, "m4:4004": 2, "m4:4008": 3, "m4:400c": 4}, {"r0": 10}),
    ("vliw_slots", ["mov $1,5", "bsrv vslots", "mov $6,$0"], {}, {"r6": 5, "r3": 5}),
    # GCC's mode-switching sibling call: "stc $12,$lp; jmp $11" into a VLIW function
    ("vliw_sibcall", ["bsr core_sib", "mov $6,$0"], {"r1": 1, "r2": 2}, {"r6": 3}),
]

IVC2_SUBS = """
core_sib:
	ldc $12,$lp
	movh $11,%hi(vadd)
	xor3 $12,$12,1
	add3 $11,$11,%lo(vadd+1)
	stc $12,$lp
	jmp $11
	.section .vtext,"axv"
	.vliw
vadd:
	add3 $0,$1,$2
	ret
vsum:
	mov $0,0
	add $2,-1
	repeat $2,.Lvs_end
	lw $3,($1)
.Lvs_end:
	add3 $0,$0,$3
	add $1,4
	sll $0,0
	ret
vslots:
	cmov $c1,$1
	bra 1f
	+cpmov $c2,$c1
	mov $0,99
1:	cmov $3,$c2
	mov $0,$3
	ret
"""

SUBS = """
sub_add:
	add3 $0,$1,$2
	ret
sub_gcc:
	add $sp,-8
	ldc $11,$lp
	sw $11,4($sp)
	mov $0,0x99
	lw $11,4($sp)
	add $sp,8
	jmp $11
	.org 0x10000
sub_far:
	mov $0,0x77
	ret
"""


def main():
    out = sys.argv[1]
    brk = sys.argv[sys.argv.index("--break") + 1] if "--break" in sys.argv else None
    bindir = os.environ.get("MEP_BIN", "")
    tool = lambda t: os.path.join(bindir, "mep-elf-" + t) if bindir else "mep-elf-" + t
    for big, ivc2 in ((False, False), (True, False), (False, True), (True, True)):
        e = ("ivc2_" if ivc2 else "") + ("be" if big else "le")
        T = IVC2_TESTS if ivc2 else tests(big)
        s = ["\t.text", "\t.org 0x100"]
        for i, (name, asm, init, exp) in enumerate(T):
            s.append("t%d:" % i)
            for a in asm:
                if a[:1].isdigit() and a[1:3] == ": ":
                    s.append(a[:2])
                    s.append("\t" + a[3:])
                else:
                    s.append("\t" + a)
            s.append("t%d_end:" % i)
            s.append("\tbra t%d_end" % i)
        s.append(IVC2_SUBS if ivc2 else SUBS)
        src = os.path.join(out, "emu_%s.s" % e)
        open(src, "w").write("\n".join(s) + "\n")
        obj, elf, binf = (os.path.join(out, "emu_%s%s" % (e, x)) for x in (".o", ".elf", ".bin"))
        flag = "-EB" if big else "-EL"
        subprocess.check_call([tool("as"), flag, src, "-o", obj])
        subprocess.check_call([tool("ld"), flag, "-Ttext=0", "--section-start=.vtext=0x20000", "-e", "0",
                               obj, "-o", elf])
        subprocess.check_call([tool("objcopy"), "-O", "binary", "-j", ".text", "-j", ".vtext", elf, binf])
        syms = {}
        for line in subprocess.check_output([tool("nm"), elf], text=True).splitlines():
            p = line.split()
            if len(p) == 3:
                syms[p[2]] = int(p[0], 16)
        with open(os.path.join(out, "emu_%s.txt" % e), "w") as f:
            for i, (name, asm, init, exp) in enumerate(T):
                exp = dict(exp)
                if name == brk:
                    k = next(iter(exp))
                    exp[k] = exp[k] ^ 1
                kv = lambda d: ",".join("%s=%x" % (k, v) for k, v in d.items()) or "-"
                f.write("%s %x %x %s %s\n" % (name, syms["t%d" % i], syms["t%d_end" % i], kv(init), kv(exp)))
        print("%d emulator tests -> %s" % (len(T), os.path.join(out, "emu_%s.txt" % e)))


if __name__ == "__main__":
    main()
