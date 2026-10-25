/* Ghidra-Rare MeP module (Clear BSD License, see LICENSE) */
package ghidra.app.util.bin.format.elf.relocation;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;

/**
 * ELF relocation handler for Toshiba MeP (EM_CYGNUS_MEP = 0xF00D), for relocatable objects
 * (linked executables carry no relocations). Instructions are sequences of 16-bit halfwords in
 * the file's byte order; the fields patched are those of the instruction encodings:
 * <ul>
 * <li>8/16/32: data. PCREL8A2/12A2: BEQZ/BNEZ and BRA/BSR displacements; PCREL17A2: 16-bit
 * branch displacement in the second halfword; PCREL24A2 (BSR/BSRV) and PCABS24A2 (JMP):
 * bits 7..1 in halfword 0 bits 10..4, bits 23..8 in halfword 1.</li>
 * <li>LOW16, HI16U, HI16S (rounded): the 16-bit immediate in halfword 1. UIMM24 (MOVU):
 * bits 7..0 in halfword 0, 23..8 in halfword 1. ADDR24A4 (SW/LW abs24): bits 7..2 in
 * halfword 0 bits 7..2.</li>
 * <li>GPREL and TPREL: relative to {@code __sdabase} and {@code __tpbase}; TPREL7/7A2/7A4:
 * the 7-bit $tp displacements of the 16-bit loads and stores.</li>
 * </ul>
 */
public class MeP_ElfRelocationHandler
		extends AbstractElfRelocationHandler<MeP_ElfRelocationType, ElfRelocationContext<?>> {

	public static final short EM_CYGNUS_MEP = (short) 0xF00D;

	public MeP_ElfRelocationHandler() {
		super(MeP_ElfRelocationType.class);
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == EM_CYGNUS_MEP;
	}

	private static int hw(Memory mem, Address a, int i) throws MemoryAccessException {
		return mem.getShort(a.add(2 * i)) & 0xffff;
	}

	private static void setHw(Memory mem, Address a, int i, int mask, long v)
			throws MemoryAccessException {
		int old = hw(mem, a, i);
		mem.setShort(a.add(2 * i), (short) ((old & ~mask) | ((int) v & mask)));
	}

	private static Long base(Program program, String name) {
		Symbol s = SymbolUtilities.getLabelOrFunctionSymbol(program, name, err -> {
		});
		return s == null ? null : s.getAddress().getOffset();
	}

	@Override
	protected RelocationResult relocate(ElfRelocationContext<?> ctx, ElfRelocation relocation,
			MeP_ElfRelocationType type, Address relocationAddress, ElfSymbol elfSymbol,
			Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		Program program = ctx.getProgram();
		Memory mem = program.getMemory();
		int symIndex = relocation.getSymbolIndex();

		switch (type) {
			case R_MEP_NONE:
			case R_MEP_GNU_VTINHERIT:
			case R_MEP_GNU_VTENTRY:
				return RelocationResult.SKIPPED;
			default:
				break;
		}
		if (handleUnresolvedSymbol(ctx, relocation, relocationAddress)) {
			return RelocationResult.FAILURE;
		}
		long v = symbolValue + relocation.getAddend();
		long P = relocationAddress.getOffset();
		Address a = relocationAddress;

		switch (type) {
			case R_MEP_8:
				mem.setByte(a, (byte) v);
				return new RelocationResult(Status.APPLIED, 1);
			case R_MEP_16:
				mem.setShort(a, (short) v);
				return new RelocationResult(Status.APPLIED, 2);
			case R_MEP_32:
				mem.setInt(a, (int) v);
				return new RelocationResult(Status.APPLIED, 4);
			case R_MEP_PCREL8A2:
				setHw(mem, a, 0, 0x00fe, v - P);
				return new RelocationResult(Status.APPLIED, 2);
			case R_MEP_PCREL12A2:
				setHw(mem, a, 0, 0x0ffe, v - P);
				return new RelocationResult(Status.APPLIED, 2);
			case R_MEP_PCREL17A2:
				setHw(mem, a, 1, 0xffff, (v - P) >> 1);
				return new RelocationResult(Status.APPLIED, 4);
			case R_MEP_PCREL24A2:
			case R_MEP_PCABS24A2: {
				long u = type == MeP_ElfRelocationType.R_MEP_PCREL24A2 ? v - P : v;
				setHw(mem, a, 0, 0x07f0, (u & 0xfe) << 3);
				setHw(mem, a, 1, 0xffff, u >> 8);
				return new RelocationResult(Status.APPLIED, 4);
			}
			case R_MEP_LOW16:
				setHw(mem, a, 1, 0xffff, v);
				return new RelocationResult(Status.APPLIED, 4);
			case R_MEP_HI16U:
				setHw(mem, a, 1, 0xffff, v >> 16);
				return new RelocationResult(Status.APPLIED, 4);
			case R_MEP_HI16S:
				setHw(mem, a, 1, 0xffff, (v + 0x8000) >> 16);
				return new RelocationResult(Status.APPLIED, 4);
			case R_MEP_UIMM24:
				setHw(mem, a, 0, 0x00ff, v);
				setHw(mem, a, 1, 0xffff, v >> 8);
				return new RelocationResult(Status.APPLIED, 4);
			case R_MEP_ADDR24A4:
				setHw(mem, a, 0, 0x00fc, v);
				setHw(mem, a, 1, 0xffff, v >> 8);
				return new RelocationResult(Status.APPLIED, 4);
			case R_MEP_GPREL:
			case R_MEP_TPREL:
			case R_MEP_TPREL7:
			case R_MEP_TPREL7A2:
			case R_MEP_TPREL7A4: {
				String bname = type == MeP_ElfRelocationType.R_MEP_GPREL ? "__sdabase" : "__tpbase";
				Long b = base(program, bname);
				if (b == null) {
					markAsError(program, relocationAddress, type, symbolName, symIndex,
						bname + " is not defined", ctx.getLog());
					return RelocationResult.FAILURE;
				}
				long u = v - b;
				switch (type) {
					case R_MEP_TPREL7:
						setHw(mem, a, 0, 0x007f, u);
						return new RelocationResult(Status.APPLIED, 2);
					case R_MEP_TPREL7A2:
						setHw(mem, a, 0, 0x007e, u);
						return new RelocationResult(Status.APPLIED, 2);
					case R_MEP_TPREL7A4:
						setHw(mem, a, 0, 0x007c, u);
						return new RelocationResult(Status.APPLIED, 2);
					default:
						setHw(mem, a, 1, 0xffff, u);
						return new RelocationResult(Status.APPLIED, 4);
				}
			}
			default:
				markAsUnhandled(program, relocationAddress, type, symIndex, symbolName,
					ctx.getLog());
				return RelocationResult.UNSUPPORTED;
		}
	}
}
