// Runs the MeP p-code semantic tests produced by emu_tests.py in Ghidra's p-code emulator.
// The program must be emu_le.bin / emu_be.bin imported raw at address 0.
// Script args: <tests.txt> <outfile> [vliw-start-hex vliw-end-hex]  (sets OM=1 there)
//   tests.txt lines: <name> <start-hex> <stop-hex> <init key=val,...|-> <expect key=val,...>
//   keys: register names, or m1:/m2:/m4:/m8:<hex address> for memory in the program's byte order
//@category Testing

import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emulate.EmulateExecutionState;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;

public class EmuCheck extends GhidraScript {

	private static final String[] REGS = { "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8",
		"r9", "r10", "r11", "r12", "tp", "gp", "lp", "hi", "lo", "sar", "psw", "rpb", "rpe", "rpc",
		"epc", "npc", "exc", "mb0", "me0", "mb1", "me1" };

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[1]);
		if (args.length > 3) {
			currentProgram.getProgramContext()
					.setValue(currentProgram.getRegister("OM"), toAddr(Long.parseLong(args[2], 16)),
						toAddr(Long.parseLong(args[3], 16)), BigInteger.ONE);
		}
		int pass = 0, fail = 0;
		for (String line : Files.readAllLines(Path.of(args[0]))) {
			line = line.trim();
			if (line.isEmpty() || line.startsWith("#")) {
				continue;
			}
			String[] f = line.split("\\s+");
			String err = runOne(f);
			if (err == null) {
				pass++;
				out.println("PASS " + f[0]);
			}
			else {
				fail++;
				out.println("FAIL " + f[0] + ": " + err);
			}
		}
		out.printf("emulator tests: %d passed, %d failed%n", pass, fail);
		out.close();
	}

	private void put(EmulatorHelper emu, String k, BigInteger v) throws Exception {
		if (k.startsWith("m")) {
			int n = k.charAt(1) - '0';
			long a = Long.parseLong(k.substring(3), 16);
			byte[] b = new byte[n];
			boolean be = currentProgram.getLanguage().isBigEndian();
			for (int i = 0; i < n; i++) {
				b[be ? n - 1 - i : i] = v.shiftRight(8 * i).byteValue();
			}
			emu.writeMemory(toAddr(a), b);
		}
		else {
			emu.writeRegister(k, v);
		}
	}

	private BigInteger get(EmulatorHelper emu, String k) throws Exception {
		if (k.startsWith("m")) {
			int n = k.charAt(1) - '0';
			long a = Long.parseLong(k.substring(3), 16);
			byte[] b = emu.readMemory(toAddr(a), n);
			BigInteger v = BigInteger.ZERO;
			boolean be = currentProgram.getLanguage().isBigEndian();
			for (int i = n - 1; i >= 0; i--) {
				v = v.shiftLeft(8).or(BigInteger.valueOf(b[be ? n - 1 - i : i] & 0xff));
			}
			return v;
		}
		Register r = currentProgram.getRegister(k);
		BigInteger mask = BigInteger.ONE.shiftLeft(r.getBitLength()).subtract(BigInteger.ONE);
		return emu.readRegister(r).and(mask);
	}

	private String runOne(String[] f) throws Exception {
		Address start = toAddr(Long.parseUnsignedLong(f[1], 16));
		Address stop = toAddr(Long.parseUnsignedLong(f[2], 16));
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		try {
			for (String r : REGS) {
				emu.writeRegister(r, 0);
			}
			for (int i = 0; i < 16; i++) {
				emu.writeRegister("c" + i, 0);
			}
			emu.writeRegister(currentProgram.getRegister("ccr1") != null ? "ccr1" : "cc", 0);
			emu.writeRegister("sp", 0x8000);
			if (!f[3].equals("-")) {
				for (String kv : f[3].split(",")) {
					String[] p = kv.split("=");
					put(emu, p[0], new BigInteger(p[1], 16));
				}
			}
			emu.writeRegister(emu.getPCRegister(), start.getOffset());
			emu.setBreakpoint(stop);
			emu.run(start, null, monitor);
			if (emu.getEmulateExecutionState() != EmulateExecutionState.BREAKPOINT ||
				!emu.getExecutionAddress().equals(stop)) {
				return "did not reach " + stop + " (state " + emu.getEmulateExecutionState() +
					" at " + emu.getExecutionAddress() + ", " + emu.getLastError() + ")";
			}
			StringBuilder bad = new StringBuilder();
			for (String kv : f[4].split(",")) {
				String[] p = kv.split("=");
				BigInteger want = new BigInteger(p[1], 16);
				BigInteger got = get(emu, p[0]);
				if (!want.equals(got)) {
					bad.append(String.format(" %s=%x (want %x)", p[0], got, want));
				}
			}
			return bad.length() == 0 ? null : bad.toString().trim();
		}
		finally {
			emu.dispose();
		}
	}
}
