/**
 * Test fixtures: helpers to build minimal Mach-O byte arrays in memory.
 * All values are known constants for easy assertion.
 */

import {
	CPU_TYPE_ARM,
	CPU_TYPE_ARM64,
	CPU_TYPE_X86,
	CPU_TYPE_X86_64,
	FAT_MAGIC,
	MH_DYLIB,
	MH_EXECUTE,
	MH_MAGIC,
	MH_MAGIC_64,
	MH_PIE
} from "../macho";

// ── mach_header_64 builder ─────────────────────────────────────────────

export interface MachHeader64Options {
	magic?: number;
	cputype?: number;
	cpusubtype?: number;
	filetype?: number;
	ncmds?: number;
	sizeofcmds?: number;
	flags?: number;
	reserved?: number;
	littleEndian?: boolean;
}

/**
 * Build a 32-byte mach_header_64 buffer with configurable fields.
 * Defaults to a valid ARM64 executable header in little-endian.
 */
export function buildMachHeader64(opts: MachHeader64Options = {}): ArrayBuffer {
	const le = opts.littleEndian ?? true;
	const buf = new ArrayBuffer(32);
	const view = new DataView(buf);

	view.setUint32(0, opts.magic ?? MH_MAGIC_64, le);
	view.setUint32(4, opts.cputype ?? CPU_TYPE_ARM64, le);
	view.setUint32(8, opts.cpusubtype ?? 0x00000000, le);
	view.setUint32(12, opts.filetype ?? MH_EXECUTE, le);
	view.setUint32(16, opts.ncmds ?? 15, le);
	view.setUint32(20, opts.sizeofcmds ?? 1200, le);
	view.setUint32(24, opts.flags ?? MH_PIE, le);
	view.setUint32(28, opts.reserved ?? 0, le);

	return buf;
}

// ── 32-bit mach_header builder ─────────────────────────────────────────

export interface MachHeader32Options {
	magic?: number;
	cputype?: number;
	cpusubtype?: number;
	filetype?: number;
	ncmds?: number;
	sizeofcmds?: number;
	flags?: number;
	littleEndian?: boolean;
}

/**
 * Build a 28-byte mach_header (32-bit) buffer with configurable fields.
 * Defaults to a valid ARM32 executable header in little-endian.
 */
export function buildMachHeader32(opts: MachHeader32Options | boolean = {}): ArrayBuffer {
	// Backward compatibility: if a boolean is passed, treat it as littleEndian
	const options: MachHeader32Options = typeof opts === "boolean" ? { littleEndian: opts } : opts;
	const le = options.littleEndian ?? true;
	const buf = new ArrayBuffer(28);
	const view = new DataView(buf);

	view.setUint32(0, options.magic ?? MH_MAGIC, le);
	view.setUint32(4, options.cputype ?? CPU_TYPE_ARM, le);
	view.setUint32(8, options.cpusubtype ?? 0x00000000, le);
	view.setUint32(12, options.filetype ?? MH_EXECUTE, le);
	view.setUint32(16, options.ncmds ?? 5, le);
	view.setUint32(20, options.sizeofcmds ?? 400, le);
	view.setUint32(24, options.flags ?? 0, le);

	return buf;
}

// ── Fat binary builder ─────────────────────────────────────────────────

export interface FatArchEntry {
	cputype: number;
	cpusubtype: number;
	offset: number;
	size: number;
	align: number;
}

/**
 * Build a fat header with the given arch entries.
 * Fat headers are ALWAYS big-endian.
 * Returns buffer containing fat_header + fat_arch entries (no actual slice data).
 */
export function buildFatHeader(arches: FatArchEntry[]): ArrayBuffer {
	const headerSize = 8 + arches.length * 20;
	const buf = new ArrayBuffer(headerSize);
	const view = new DataView(buf);

	// fat_header: always big-endian
	view.setUint32(0, FAT_MAGIC, false);
	view.setUint32(4, arches.length, false);

	for (let i = 0; i < arches.length; i++) {
		const base = 8 + i * 20;
		const arch = arches[i]!;
		view.setUint32(base, arch.cputype, false);
		view.setUint32(base + 4, arch.cpusubtype, false);
		view.setUint32(base + 8, arch.offset, false);
		view.setUint32(base + 12, arch.size, false);
		view.setUint32(base + 16, arch.align, false);
	}

	return buf;
}

// ── Pre-built fixtures with known values ───────────────────────────────

/** A standard ARM64 executable header (little-endian) */
export const ARM64_EXEC_HEADER = buildMachHeader64({
	cputype: CPU_TYPE_ARM64,
	filetype: MH_EXECUTE,
	ncmds: 15,
	sizeofcmds: 1200,
	flags: MH_PIE,
	littleEndian: true
});

/** An x86_64 dylib header (little-endian) */
export const X86_64_DYLIB_HEADER = buildMachHeader64({
	cputype: CPU_TYPE_X86_64,
	filetype: MH_DYLIB,
	ncmds: 22,
	sizeofcmds: 2048,
	flags: 0x00000085,
	littleEndian: true
});

/** A big-endian ARM64 header (unusual but valid) */
export const BE_ARM64_HEADER = buildMachHeader64({
	cputype: CPU_TYPE_ARM64,
	filetype: MH_EXECUTE,
	ncmds: 10,
	sizeofcmds: 800,
	flags: MH_PIE,
	littleEndian: false
});

/** A fat binary with ARM64 + x86_64 slices */
export const FAT_DUAL_ARCH = buildFatHeader([
	{ cputype: CPU_TYPE_ARM64, cpusubtype: 0, offset: 16384, size: 50000, align: 14 },
	{ cputype: CPU_TYPE_X86_64, cpusubtype: 3, offset: 70000, size: 45000, align: 14 }
]);

// ── 32-bit pre-built fixtures ─────────────────────────────────────────

/** A standard ARM32 executable header (little-endian) */
export const ARM32_EXEC_HEADER = buildMachHeader32({
	cputype: CPU_TYPE_ARM,
	filetype: MH_EXECUTE,
	ncmds: 10,
	sizeofcmds: 600,
	flags: 0,
	littleEndian: true
});

/** An x86 (32-bit) executable header (little-endian) */
export const X86_EXEC_HEADER = buildMachHeader32({
	cputype: CPU_TYPE_X86,
	filetype: MH_EXECUTE,
	ncmds: 12,
	sizeofcmds: 700,
	flags: 0,
	littleEndian: true
});

// ── Relocatable object (MH_OBJECT) builder ─────────────────────────────

export interface ObjectRelocSpec {
	/** Offset of the fixup within its section */
	address: number;
	/** Symbol table index (extern) or 1-based section ordinal */
	symbolnum: number;
	type: number;
	/** log2 of the fixup width: 2 = 32-bit, 3 = 64-bit */
	length: number;
	pcrel?: boolean;
	/** Defaults to true */
	extern?: boolean;
}

export interface ObjectSectionSpec {
	segname: string;
	sectname: string;
	data: Uint8Array;
	flags?: number;
	/** Relocations in file order (an arm64 ADDEND precedes the entry it applies to) */
	relocs?: ObjectRelocSpec[];
}

export interface ObjectSymbolSpec {
	name: string;
	/** 1-based section ordinal; 0 for an undefined (imported) symbol */
	sect: number;
	/** Offset within the section, for defined symbols */
	offset?: number;
	external?: boolean;
}

export const N_EXT = 0x01;
export const N_SECT = 0x0e;

/**
 * Build a little-endian 64-bit relocatable object: one LC_SEGMENT_64 holding every
 * section (laid out back to back from address 0, 16-byte aligned) plus LC_SYMTAB.
 * Section file offsets track their addresses linearly, as an assembler lays them out.
 * Returns the buffer and each section's address so tests can compute expectations.
 */
export function buildObjectFile(opts: {
	cputype?: number;
	cpusubtype?: number;
	sections: ObjectSectionSpec[];
	symbols?: ObjectSymbolSpec[];
}): { buffer: ArrayBuffer; sectionAddrs: number[] } {
	const sections = opts.sections;
	const symbols = opts.symbols ?? [];
	const segCmdSize = 72 + 80 * sections.length;
	const symtabCmdSize = 24;
	const dataStart = 32 + segCmdSize + symtabCmdSize;
	const align = (n: number) => Math.ceil(n / 16) * 16;

	const sectionAddrs: number[] = [];
	let addr = 0;
	for (const s of sections) {
		sectionAddrs.push(addr);
		addr = align(addr + s.data.length);
	}
	const dataSize = addr;
	const relocStart = align(dataStart + dataSize);
	const relocOffsets: number[] = [];
	let cursor = relocStart;
	for (const s of sections) {
		relocOffsets.push(cursor);
		cursor += (s.relocs?.length ?? 0) * 8;
	}
	const symoff = align(cursor);
	let strtab = "\0";
	const strx = symbols.map((sym) => {
		const index = strtab.length;
		strtab += `${sym.name}\0`;
		return index;
	});
	const stroff = symoff + symbols.length * 16;
	const total = stroff + strtab.length;

	const buffer = new ArrayBuffer(total);
	const view = new DataView(buffer);
	const bytes = new Uint8Array(buffer);
	const le = true;

	view.setUint32(0, MH_MAGIC_64, le);
	view.setUint32(4, opts.cputype ?? CPU_TYPE_ARM64, le);
	view.setUint32(8, opts.cpusubtype ?? 0, le);
	view.setUint32(12, 1, le); // MH_OBJECT
	view.setUint32(16, 2, le);
	view.setUint32(20, segCmdSize + symtabCmdSize, le);
	view.setUint32(24, 0x2000, le); // MH_SUBSECTIONS_VIA_SYMBOLS

	// LC_SEGMENT_64 (unnamed, as in every object file)
	let lc = 32;
	view.setUint32(lc, 0x19, le);
	view.setUint32(lc + 4, segCmdSize, le);
	view.setBigUint64(lc + 24, 0n, le);
	view.setBigUint64(lc + 32, BigInt(dataSize), le);
	view.setBigUint64(lc + 40, BigInt(dataStart), le);
	view.setBigUint64(lc + 48, BigInt(dataSize), le);
	view.setUint32(lc + 56, 7, le);
	view.setUint32(lc + 60, 7, le);
	view.setUint32(lc + 64, sections.length, le);
	sections.forEach((s, i) => {
		const base = lc + 72 + i * 80;
		const writeName = (offset: number, name: string) => {
			for (let c = 0; c < name.length; c++) bytes[offset + c] = name.charCodeAt(c);
		};
		writeName(base, s.sectname);
		writeName(base + 16, s.segname);
		view.setBigUint64(base + 32, BigInt(sectionAddrs[i]!), le);
		view.setBigUint64(base + 40, BigInt(s.data.length), le);
		view.setUint32(base + 48, dataStart + sectionAddrs[i]!, le);
		view.setUint32(base + 52, 4, le);
		view.setUint32(base + 56, s.relocs?.length ? relocOffsets[i]! : 0, le);
		view.setUint32(base + 60, s.relocs?.length ?? 0, le);
		view.setUint32(base + 64, s.flags ?? 0, le);
		bytes.set(s.data, dataStart + sectionAddrs[i]!);

		(s.relocs ?? []).forEach((r, j) => {
			const at = relocOffsets[i]! + j * 8;
			view.setUint32(at, r.address, le);
			const info =
				(r.symbolnum & 0xffffff) |
				((r.pcrel ? 1 : 0) << 24) |
				((r.length & 3) << 25) |
				((r.extern === false ? 0 : 1) << 27) |
				(r.type << 28);
			view.setUint32(at + 4, info >>> 0, le);
		});
	});

	// LC_SYMTAB
	lc += segCmdSize;
	view.setUint32(lc, 0x2, le);
	view.setUint32(lc + 4, symtabCmdSize, le);
	view.setUint32(lc + 8, symoff, le);
	view.setUint32(lc + 12, symbols.length, le);
	view.setUint32(lc + 16, stroff, le);
	view.setUint32(lc + 20, strtab.length, le);

	symbols.forEach((sym, i) => {
		const base = symoff + i * 16;
		const defined = sym.sect > 0;
		view.setUint32(base, strx[i]!, le);
		view.setUint8(base + 4, (defined ? N_SECT : 0) | (sym.external || !defined ? N_EXT : 0));
		view.setUint8(base + 5, sym.sect);
		const value = defined ? sectionAddrs[sym.sect - 1]! + (sym.offset ?? 0) : 0;
		view.setBigUint64(base + 8, BigInt(value), le);
	});
	for (let c = 0; c < strtab.length; c++) bytes[stroff + c] = strtab.charCodeAt(c);

	return { buffer, sectionAddrs };
}
