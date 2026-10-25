/* Ghidra-Rare MeP module (Clear BSD License, see LICENSE) */
package ghidra.app.util.bin.format.elf.relocation;

/**
 * Toshiba MeP ELF relocation types (binutils include/elf/mep.h).
 */
public enum MeP_ElfRelocationType implements ElfRelocationType {

	R_MEP_NONE(0),
	R_MEP_8(2),
	R_MEP_16(3),
	R_MEP_32(4),
	R_MEP_PCREL8A2(5),
	R_MEP_PCREL12A2(6),
	R_MEP_PCREL17A2(7),
	R_MEP_PCREL24A2(8),
	R_MEP_PCABS24A2(9),
	R_MEP_LOW16(10),
	R_MEP_HI16U(11),
	R_MEP_HI16S(12),
	R_MEP_GPREL(13),
	R_MEP_TPREL(14),
	R_MEP_TPREL7(15),
	R_MEP_TPREL7A2(16),
	R_MEP_TPREL7A4(17),
	R_MEP_UIMM24(18),
	R_MEP_ADDR24A4(19),
	R_MEP_GNU_VTINHERIT(20),
	R_MEP_GNU_VTENTRY(21);

	public final int typeId;

	private MeP_ElfRelocationType(int typeId) {
		this.typeId = typeId;
	}

	@Override
	public int typeId() {
		return typeId;
	}
}
