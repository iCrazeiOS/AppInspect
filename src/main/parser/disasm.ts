/**
 * Disassembler — ARM/ARM64/x86/x86_64 code disassembly using Capstone WASM
 *
 * Provides chunked disassembly of __text sections from Mach-O binaries.
 * Supports all common iOS/macOS CPU types.
 */

import { Capstone, Const, type Insn, loadCapstone } from "capstone-wasm";
import { CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_X86, CPU_TYPE_X86_64 } from "./macho";

// ── Types ─────────────────────────────────────────────────────────────

export type DisasmArch = "arm" | "arm64" | "x86" | "x86_64";

export interface DisasmInstruction {
	/** Virtual memory address */
	address: bigint;
	/** File offset (for hex view linking) */
	offset: number;
	/** Raw machine code bytes */
	bytes: number[];
	/** Instruction mnemonic (e.g., "mov", "bl") */
	mnemonic: string;
	/** Instruction operands (e.g., "x0, x1") */
	operands: string;
	/** Instruction size in bytes */
	size: number;
	/** Symbol label if this address matches a symbol */
	label?: string;
}

// ── Capstone Initialization ───────────────────────────────────────────

let initialized = false;

/**
 * Initialize the Capstone WASM module. Must be called once before disassembly.
 * Safe to call multiple times — subsequent calls are no-ops.
 */
export async function initCapstone(): Promise<void> {
	if (initialized) return;
	await loadCapstone();
	initialized = true;
}

/**
 * Check if Capstone has been initialized.
 */
export function isCapstoneReady(): boolean {
	return initialized;
}

// ── Architecture Mapping ──────────────────────────────────────────────

/**
 * Map Mach-O CPU type to disasm architecture string.
 */
export function cpuTypeToArch(cputype: number): DisasmArch | null {
	switch (cputype) {
		case CPU_TYPE_ARM64:
			return "arm64";
		case CPU_TYPE_ARM:
			return "arm";
		case CPU_TYPE_X86_64:
			return "x86_64";
		case CPU_TYPE_X86:
			return "x86";
		default:
			return null;
	}
}

/**
 * Get Capstone arch and mode for a given architecture.
 */
function getCapstoneConfig(arch: DisasmArch): { csArch: number; csMode: number } {
	switch (arch) {
		case "arm64":
			return { csArch: Const.CS_ARCH_ARM64, csMode: Const.CS_MODE_LITTLE_ENDIAN };
		case "arm":
			return { csArch: Const.CS_ARCH_ARM, csMode: Const.CS_MODE_ARM };
		case "x86_64":
			return { csArch: Const.CS_ARCH_X86, csMode: Const.CS_MODE_64 };
		case "x86":
			return { csArch: Const.CS_ARCH_X86, csMode: Const.CS_MODE_32 };
	}
}

// ── Disassembly ───────────────────────────────────────────────────────

/**
 * Disassemble a chunk of bytes.
 *
 * @param bytes - Raw machine code bytes
 * @param baseAddr - Virtual address of the first byte
 * @param arch - Target architecture
 * @param baseOffset - File offset of the first byte (for offset calculation)
 * @returns Array of disassembled instructions
 */
export function disassembleChunk(
	bytes: Uint8Array,
	baseAddr: bigint,
	arch: DisasmArch,
	baseOffset: number
): DisasmInstruction[] {
	if (!initialized) {
		throw new Error("Capstone not initialized. Call initCapstone() first.");
	}

	if (bytes.length === 0) {
		return [];
	}

	const { csArch, csMode } = getCapstoneConfig(arch);
	const cs = new Capstone(csArch, csMode);

	try {
		const insns: Insn[] = cs.disasm(bytes, { address: baseAddr });
		const results: DisasmInstruction[] = [];

		for (const insn of insns) {
			const addr = typeof insn.address === "bigint" ? insn.address : BigInt(insn.address);
			const offsetInChunk = Number(addr - baseAddr);

			results.push({
				address: addr,
				offset: baseOffset + offsetInChunk,
				bytes: Array.from(insn.bytes),
				mnemonic: insn.mnemonic,
				operands: insn.opStr,
				size: insn.size
			});
		}

		return results;
	} finally {
		cs.close();
	}
}

/**
 * Get the average instruction size for an architecture.
 * Used for estimating total instruction count in virtual scrolling.
 */
export function getAvgInstructionSize(arch: DisasmArch): number {
	switch (arch) {
		case "arm64":
			return 4; // Fixed 4-byte instructions
		case "arm":
			return 4; // ARM mode is 4 bytes (Thumb would be 2-4)
		case "x86_64":
		case "x86":
			return 5; // Variable, but ~5 is a reasonable average
	}
}

/**
 * Classify an instruction mnemonic for syntax highlighting.
 */
export function classifyMnemonic(
	mnemonic: string
): "branch" | "call" | "ret" | "load" | "store" | "other" {
	const m = mnemonic.toLowerCase();

	// Return instructions
	if (m === "ret" || m === "retaa" || m === "retab" || m === "eret") {
		return "ret";
	}

	// Call instructions
	if (
		m === "bl" ||
		m === "blr" ||
		m === "blx" ||
		m === "call" ||
		m === "blraa" ||
		m === "blrab"
	) {
		return "call";
	}

	// Branch instructions
	if (
		m.startsWith("b.") ||
		m === "b" ||
		m === "br" ||
		m === "bx" ||
		m === "jmp" ||
		m.startsWith("j") ||
		m === "cbz" ||
		m === "cbnz" ||
		m === "tbz" ||
		m === "tbnz"
	) {
		return "branch";
	}

	// Load instructions
	if (
		m.startsWith("ld") ||
		m.startsWith("ldr") ||
		m === "mov" ||
		m === "movz" ||
		m === "movk" ||
		m === "movn" ||
		m === "adrp" ||
		m === "adr" ||
		m === "lea"
	) {
		return "load";
	}

	// Store instructions
	if (m.startsWith("st") || m.startsWith("str") || m === "push") {
		return "store";
	}

	return "other";
}
