/* Ghidra-Rare MeP test program for the IVC2 language: VLIW-mode functions (.vtext), calls
 * between core and VLIW mode (bsrv/jsrv, mode-switching sibling calls), repeat loops, and
 * coprocessor moves. Built by build-ivc2-sample.sh with mep-elf-gcc -mivc2. */
#include <intrinsics.h>

extern int vasm(int a, int b);         /* hand-written VLIW bundles, ivc2_vliw.S */
extern cp_v2si vcop(cp_v2si a);        /* VLIW function using IVC2 operations */

int table[64];
cp_v2si gvec;

int __attribute__((vliw)) vsum(const int *p, int n)
{
	int s = 0;
	for (int i = 0; i < n; i++)
		s += p[i] * 3;
	return s;
}

int __attribute__((vliw)) vfill(int *p, int n, int v)
{
	for (int i = 0; i < n; i++)
		p[i] = v + i;
	return vsum(p, n);
}

int __attribute__((vliw)) vtail(int n)
{
	return vfill(table, n, 7);
}

static int core_helper(int x)
{
	return x * x + 1;
}

int __attribute__((vliw)) vcall_core(int x)
{
	return core_helper(x) + 2;
}

int main(void)
{
	int r = vtail(16);
	r += vcall_core(r & 7);
	r += vasm(r, 3);
	gvec = vcop(gvec);
	int (*fp)(int) = vcall_core;
	r += fp(5);
	return r;
}
