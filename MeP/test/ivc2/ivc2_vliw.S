/* Ghidra-Rare MeP test code: hand-written IVC2 VLIW bundles (core + P0S + P1, P0 + P1 and
 * core32 + P1 forms) and core-mode IVC2 instructions. */
	.section .vtext,"axv"
	.vliw
	.globl vasm
vasm:
	add3 $0,$1,$2
	+cpadd3.b $c1,$c2,$c3
	+cpsub3.h $c4,$c5,$c6
	cpmovi.b $c1,5
	+cpmov $c2,$c1
	cmov $c3,$1
	+cpor3 $c4,$c3,$c2
	movu $3,0x123456
	+cpsrli3.w $c5,$c4,3
	cpmovi.h $c6,-2
	+cpadd3.w $c7,$c6,$c5
	add $0,1
	ret

	.globl vcop
vcop:
	lmcp $c1,($1)
	+cpmovi.w $c2,1
	cpadd3.w $c3,$c1,$c2
	cpsll3.w $c4,$c3,$c2
	smcp $c4,($1)
	mov $0,$1
	ret

	.text
	.core
	.globl core_ivc2
core_ivc2:
	cmov $c1,$1
	cmovh $c1,$2
	cpadd3.b $c2,$c1,$c1
	cpmov $c3,$c2
	cmov $0,$c3
	cmovh $1,$c3
	cmovc $csar0,$3
	ret
