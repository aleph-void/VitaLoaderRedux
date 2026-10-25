/* Ghidra-Rare MeP module (Clear BSD License, see LICENSE) */
package ghidra.app.util.bin.format.elf.extend;

import java.math.BigInteger;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * ELF load tweaks for Toshiba MeP (EM_CYGNUS_MEP = 0xF00D).
 * <p>
 * Sections flagged {@code SHF_MEP_VLIW} (GCC puts {@code __attribute__((vliw))} functions in
 * {@code .vtext}) hold 64-bit VLIW bundles. Their code is disassembled with the operation-mode
 * context {@code OM = 1} when the language decodes VLIW bundles (MeP-c5:xx:32:IVC2).
 */
public class MeP_ElfExtension extends ElfExtension {

	public static final short EM_CYGNUS_MEP = (short) 0xF00D;
	public static final long SHF_MEP_VLIW = 0x10000000L;

	@Override
	public boolean canHandle(ElfHeader elf) {
		return elf.e_machine() == EM_CYGNUS_MEP && elf.is32Bit();
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		return canHandle(elfLoadHelper.getElfHeader()) &&
			"MeP-c5".equals(elfLoadHelper.getProgram().getLanguage().getProcessor().toString());
	}

	@Override
	public String getDataTypeSuffix() {
		return "_MeP";
	}

	@Override
	public void processElf(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {
		Program program = elfLoadHelper.getProgram();
		Register om = program.getRegister("OM");
		if (om == null || !"IVC2".equals(program.getLanguage().getLanguageDescription()
				.getVariant())) {
			return;
		}
		for (ElfSectionHeader sh : elfLoadHelper.getElfHeader().getSections()) {
			monitor.checkCancelled();
			if ((sh.getFlags() & SHF_MEP_VLIW) == 0 || !sh.isExecutable() || sh.getSize() == 0) {
				continue;
			}
			Address start = elfLoadHelper.findLoadAddress(sh, 0);
			if (start == null) {
				continue;
			}
			try {
				program.getProgramContext()
						.setValue(om, start, start.add(sh.getSize() - 1), BigInteger.ONE);
				elfLoadHelper.log(String.format("MeP: VLIW mode for %s (%s, 0x%x bytes)",
					sh.getNameAsString(), start, sh.getSize()));
			}
			catch (Exception e) {
				elfLoadHelper.log("MeP: could not set VLIW mode for " + sh.getNameAsString() +
					": " + e.getMessage());
			}
		}
	}
}
