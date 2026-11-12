/**
 * Relocatable object (MH_OBJECT) resolver.
 *
 * A `.o` file — and so every member of a static library — is not yet linked: its
 * pointers, relative offsets and PC-relative instructions hold placeholders (usually
 * zero or an addend) and the real targets live in per-section relocation entries. The
 * parsers in this directory read pointers straight out of the buffer and consult the
 * rebase/bind maps a linked image provides, so this module acts as a minimal static
 * linker for a single object:
 *
 *  - Relocations against symbols defined in the object are applied in place on a copy
 *    of the buffer — absolute pointers, `A - B` relative offsets (Swift metadata),
 *    arm64 ADRP/ADD/LDR/BL immediates and x86_64 RIP-relative displacements — and
 *    absolute pointers are also recorded in the rebase map.
 *  - Pointers to undefined symbols (imports) are recorded in the bind map, keyed by
 *    file offset like the chained-fixup and classic-bind maps.
 *  - GOT references (`sym@GOTPAGE`, `sym@GOTPCREL`, Swift's indirect symbolic
 *    references) get a synthesised GOT: one pointer slot per symbol, appended past the
 *    end of the file and mapped by an extra `__got` segment.
 *
 * An object has a single unnamed segment holding every section, so the returned
 * segment list instead groups sections by their own segment name (`__TEXT`, `__DATA`,
 * …). Readers that look for the `__TEXT` segment then find `__text` as they would in a
 * linked image. File offsets of existing data are unchanged — only the GOT is appended —
 * so string offsets and hex locations still match the file on disk.
 *
 * arm64 (including arm64e and arm64_32) and x86_64 relocations are applied. For i386
 * and armv7 objects, whose assemblers precompute most values in the object's layout,
 * symbol pointers are resolved and absolute pointers recorded. Other architectures
 * only get the regrouped segments.
 *
 * Reference: <mach-o/reloc.h>, <mach-o/arm64/reloc.h>, <mach-o/x86_64/reloc.h>.
 */

import { CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_X86, CPU_TYPE_X86_64 } from "../../shared/arch";
import type { BindEntry } from "./classic-fixups";
import type { LoadCommandsResult, Section64, Segment64 } from "./load-commands";
import { readCString } from "./load-commands";

/** CPU_TYPE_ARM64_32 (watchOS): arm64 instructions and relocations, 32-bit pointers. */
const CPU_TYPE_ARM64_32 = 0x0200000c;

// Generic relocation_info layout (little-endian bitfields)
const RELOC_SIZE = 8;
const R_SCATTERED = 0x80000000;

// Classic 32-bit relocation types (GENERIC_* for i386, ARM_* share the values)
const GENERIC_RELOC_VANILLA = 0;
const RELOC_PAIR = 1;

// arm64 relocation types
const ARM64_RELOC_UNSIGNED = 0;
const ARM64_RELOC_SUBTRACTOR = 1;
const ARM64_RELOC_BRANCH26 = 2;
const ARM64_RELOC_PAGE21 = 3;
const ARM64_RELOC_PAGEOFF12 = 4;
const ARM64_RELOC_GOT_LOAD_PAGE21 = 5;
const ARM64_RELOC_GOT_LOAD_PAGEOFF12 = 6;
const ARM64_RELOC_POINTER_TO_GOT = 7;
const ARM64_RELOC_TLVP_LOAD_PAGE21 = 8;
const ARM64_RELOC_TLVP_LOAD_PAGEOFF12 = 9;
const ARM64_RELOC_ADDEND = 10;
const ARM64_RELOC_AUTHENTICATED_POINTER = 11;

// x86_64 relocation types
const X86_64_RELOC_UNSIGNED = 0;
const X86_64_RELOC_SIGNED = 1;
const X86_64_RELOC_BRANCH = 2;
const X86_64_RELOC_GOT_LOAD = 3;
const X86_64_RELOC_GOT = 4;
const X86_64_RELOC_SUBTRACTOR = 5;
const X86_64_RELOC_SIGNED_1 = 6;
const X86_64_RELOC_SIGNED_2 = 7;
const X86_64_RELOC_SIGNED_4 = 8;
const X86_64_RELOC_TLV = 9;

// nlist n_type bits
const N_STAB = 0xe0;
const N_TYPE = 0x0e;
const N_ABS = 0x02;
const N_SECT = 0x0e;

// Section attributes and types
const SECTION_TYPE = 0xff;
const S_ZEROFILL = 0x1;
const S_GB_ZEROFILL = 0xc;
const S_THREAD_LOCAL_ZEROFILL = 0x12;
const S_ATTR_DEBUG = 0x02000000;

/** Binds in an object are resolved by the static linker, not a dylib ordinal. */
const BIND_SPECIAL_DYLIB_FLAT_LOOKUP = -2;

/** Synthesised GOT: segment/section names and page alignment of its address. */
const GOT_SEGNAME = "__DATA_CONST";
const GOT_SECTNAME = "__got";
const GOT_VM_ALIGN = 0x4000n;

const MASK64 = (1n << 64n) - 1n;

export interface ObjectImage {
	/** Copy of the input with relocations applied and the synthesised GOT appended. */
	buffer: ArrayBuffer;
	/** Sections grouped by segment name, plus the GOT segment when one was needed. */
	segments: Segment64[];
	/** The grouped sections alone, without the synthesised GOT. */
	sectionSegments: Segment64[];
	/** File offset → target vmaddr for every absolute pointer resolved in the object. */
	rebaseMap: Map<number, bigint>;
	/** File offset → imported symbol for every pointer to an undefined symbol. */
	bindMap: Map<number, BindEntry>;
}

interface ObjectSymbol {
	name: string;
	/** Address for symbols defined in the object; null for undefined (and common) ones. */
	address: bigint | null;
}

interface RelocationEntry {
	address: number;
	symbolnum: number;
	pcrel: boolean;
	length: number;
	extern: boolean;
	type: number;
	scattered?: boolean;
}

/** A resolved relocation target: an address inside the object, or an imported symbol. */
type Target = { address: bigint } | { name: string };

function isZerofill(section: Section64): boolean {
	const type = section.flags & SECTION_TYPE;
	return type === S_ZEROFILL || type === S_GB_ZEROFILL || type === S_THREAD_LOCAL_ZEROFILL;
}

function signExtend(value: number, bits: number): number {
	const shift = 32 - bits;
	return (value << shift) >> shift;
}

function readSymbols(
	view: DataView,
	lc: LoadCommandsResult,
	le: boolean,
	is64Bit: boolean
): ObjectSymbol[] {
	const symtab = lc.symtabInfo;
	if (!symtab) return [];
	const entrySize = is64Bit ? 16 : 12;
	const symbols: ObjectSymbol[] = [];
	for (let i = 0; i < symtab.nsyms; i++) {
		const offset = symtab.symoff + i * entrySize;
		if (offset + entrySize > view.byteLength) break;
		const strx = view.getUint32(offset, le);
		const type = view.getUint8(offset + 4);
		const value = is64Bit
			? view.getBigUint64(offset + 8, le)
			: BigInt(view.getUint32(offset + 8, le));
		const nameOffset = symtab.stroff + strx;
		const name =
			strx !== 0 && nameOffset < view.byteLength && strx < symtab.strsize
				? readCString(
						view,
						nameOffset,
						Math.min(symtab.strsize - strx, view.byteLength - nameOffset)
					)
				: "";
		const kind = type & N_TYPE;
		const defined = (type & N_STAB) === 0 && (kind === N_SECT || kind === N_ABS);
		symbols.push({ name, address: defined ? value : null });
	}
	return symbols;
}

function readRelocations(view: DataView, section: Section64, le: boolean): RelocationEntry[] {
	const entries: RelocationEntry[] = [];
	for (let i = 0; i < section.nreloc; i++) {
		const offset = section.reloff + i * RELOC_SIZE;
		if (offset + RELOC_SIZE > view.byteLength) break;
		const address = view.getUint32(offset, le);
		const info = view.getUint32(offset + 4, le);
		// Scattered (32-bit only): r_address and the bitfields share the first word;
		// the second holds the target's address in the object's layout.
		if ((address & R_SCATTERED) !== 0) {
			entries.push({
				address: address & 0x00ffffff,
				symbolnum: 0,
				pcrel: ((address >>> 30) & 1) === 1,
				length: (address >>> 28) & 3,
				extern: false,
				type: (address >>> 24) & 0xf,
				scattered: true
			});
			continue;
		}
		entries.push({
			address,
			symbolnum: info & 0x00ffffff,
			pcrel: ((info >>> 24) & 1) === 1,
			length: (info >>> 25) & 3,
			extern: ((info >>> 27) & 1) === 1,
			type: info >>> 28
		});
	}
	return entries;
}

/**
 * Group the object's sections by segment name. A group becomes one segment when its
 * sections share a single vmaddr→file-offset delta (as assemblers lay them out);
 * otherwise each section becomes a segment of its own so translation stays exact.
 */
function groupSegments(lc: LoadCommandsResult): Segment64[] {
	const template = lc.segments[0];
	const groups = new Map<string, Section64[]>();
	for (const section of lc.segments.flatMap((seg) => seg.sections)) {
		const name = section.segname.trim();
		const group = groups.get(name);
		if (group) group.push(section);
		else groups.set(name, [section]);
	}

	const makeSegment = (segname: string, sections: Section64[]): Segment64 => {
		let vmStart: bigint | null = null;
		let vmEnd = 0n;
		let fileStart: bigint | null = null;
		let fileEnd = 0n;
		for (const s of sections) {
			if (vmStart === null || s.addr < vmStart) vmStart = s.addr;
			if (s.addr + s.size > vmEnd) vmEnd = s.addr + s.size;
		}
		const base = vmStart ?? 0n;
		for (const s of sections) {
			if (isZerofill(s) || s.size === 0n) continue;
			// File position of the group's base address under this section's delta
			const start = BigInt(s.offset) - (s.addr - base);
			if (fileStart === null) fileStart = start;
			if (s.addr + s.size - base > fileEnd) fileEnd = s.addr + s.size - base;
		}
		return {
			cmd: template?.cmd ?? 0,
			cmdsize: 0,
			segname,
			vmaddr: base,
			vmsize: vmEnd - base,
			fileoff: fileStart ?? 0n,
			filesize: fileStart === null ? 0n : fileEnd,
			maxprot: template?.maxprot ?? 0,
			initprot: template?.initprot ?? 0,
			nsects: sections.length,
			flags: 0,
			sections
		};
	};

	const segments: Segment64[] = [];
	for (const [segname, sections] of groups) {
		const filed = sections.filter((s) => !isZerofill(s) && s.size > 0n);
		const delta = filed[0] ? BigInt(filed[0].offset) - filed[0].addr : 0n;
		if (filed.every((s) => BigInt(s.offset) - s.addr === delta)) {
			segments.push(makeSegment(segname, sections));
		} else {
			for (const section of sections) segments.push(makeSegment(segname, [section]));
		}
	}
	return segments;
}

function needsGot(cputype: number, type: number): boolean {
	if (cputype === CPU_TYPE_X86_64) {
		return (
			type === X86_64_RELOC_GOT_LOAD || type === X86_64_RELOC_GOT || type === X86_64_RELOC_TLV
		);
	}
	return (
		type === ARM64_RELOC_GOT_LOAD_PAGE21 ||
		type === ARM64_RELOC_GOT_LOAD_PAGEOFF12 ||
		type === ARM64_RELOC_POINTER_TO_GOT ||
		type === ARM64_RELOC_TLVP_LOAD_PAGE21 ||
		type === ARM64_RELOC_TLVP_LOAD_PAGEOFF12
	);
}

/** Patch the 21-bit page delta of an arm64 ADRP instruction. */
function patchAdrp(view: DataView, offset: number, pc: bigint, target: bigint): void {
	const insn = view.getUint32(offset, true);
	if ((insn & 0x9f000000) >>> 0 !== 0x90000000) return;
	const delta = Number(((target & ~0xfffn) - (pc & ~0xfffn)) >> 12n);
	if (delta < -(1 << 20) || delta >= 1 << 20) return;
	const immlo = delta & 0x3;
	const immhi = (delta >> 2) & 0x7ffff;
	view.setUint32(offset, ((insn & 0x9f00001f) | (immlo << 29) | (immhi << 5)) >>> 0, true);
}

/** Patch the low 12 bits of a target into an arm64 ADD (immediate) or load/store. */
function patchPageOffset(view: DataView, offset: number, target: bigint): void {
	const insn = view.getUint32(offset, true);
	const low = Number(target & 0xfffn);
	let imm: number;
	if ((insn & 0x1f000000) === 0x11000000) {
		// ADD/SUB (immediate): unscaled
		imm = low;
	} else if ((insn & 0x3b000000) === 0x39000000) {
		// Load/store (unsigned immediate): scaled by the access size
		let scale = insn >>> 30;
		if ((insn & 0x04800000) === 0x04800000 && scale === 0) scale = 4; // 128-bit SIMD
		if (low % (1 << scale) !== 0) return;
		imm = low >> scale;
	} else {
		return;
	}
	view.setUint32(offset, ((insn & ~(0xfff << 10)) | (imm << 10)) >>> 0, true);
}

/** Patch the 26-bit word offset of an arm64 B/BL instruction. */
function patchBranch26(view: DataView, offset: number, pc: bigint, target: bigint): void {
	const insn = view.getUint32(offset, true);
	if ((insn & 0x7c000000) !== 0x14000000) return;
	const delta = target - pc;
	if (delta % 4n !== 0n || delta < -(1n << 27n) || delta >= 1n << 27n) return;
	const imm = Number(delta >> 2n) & 0x3ffffff;
	view.setUint32(offset, ((insn & 0xfc000000) | imm) >>> 0, true);
}

/**
 * Apply an object file's relocations and return a buffer, segment list and fixup maps
 * the regular parsers can consume. Never throws for malformed relocation data: entries
 * that point outside their section or at unknown symbols are skipped.
 */
export function buildObjectImage(
	buffer: ArrayBuffer,
	lc: LoadCommandsResult,
	cputype: number,
	littleEndian: boolean,
	is64Bit: boolean
): ObjectImage {
	const sectionSegments = groupSegments(lc);
	const segments = [...sectionSegments];
	const rebaseMap = new Map<number, bigint>();
	const bindMap = new Map<number, BindEntry>();

	const isArm64 = cputype === CPU_TYPE_ARM64 || cputype === CPU_TYPE_ARM64_32;
	const isClassic32 = !is64Bit && (cputype === CPU_TYPE_ARM || cputype === CPU_TYPE_X86);
	if ((!isArm64 && !isClassic32 && cputype !== CPU_TYPE_X86_64) || !littleEndian) {
		return { buffer, segments, sectionSegments, rebaseMap, bindMap };
	}

	const inputView = new DataView(buffer);
	const symbols = readSymbols(inputView, lc, littleEndian, is64Bit);
	const sections = lc.segments.flatMap((seg) => seg.sections);
	const relocSections = sections
		.filter((s) => s.nreloc > 0 && (s.flags & S_ATTR_DEBUG) === 0 && !isZerofill(s))
		.map((section) => ({
			section,
			entries: readRelocations(inputView, section, littleEndian)
		}));

	// Pass 1: one GOT slot per symbol referenced through the GOT
	const gotSlots = new Map<number, number>(); // symbol index → slot index
	for (const { entries } of relocSections) {
		for (const r of entries) {
			if (isClassic32) break; // classic 32-bit objects reference imports without a GOT
			if (r.extern && needsGot(cputype, r.type) && !gotSlots.has(r.symbolnum)) {
				if (symbols[r.symbolnum]) gotSlots.set(r.symbolnum, gotSlots.size);
			}
		}
	}

	const pointerSize = is64Bit ? 8 : 4;
	const gotFileOffset = Math.ceil(buffer.byteLength / 8) * 8;
	let vmEnd = 0n;
	for (const s of sections) if (s.addr + s.size > vmEnd) vmEnd = s.addr + s.size;
	const gotVmaddr = ((vmEnd + GOT_VM_ALIGN - 1n) / GOT_VM_ALIGN) * GOT_VM_ALIGN;
	const gotSize = gotSlots.size * pointerSize;

	const out = new ArrayBuffer(gotFileOffset + gotSize);
	new Uint8Array(out).set(new Uint8Array(buffer));
	const view = new DataView(out);

	const writePointer = (offset: number, value: bigint): void => {
		if (is64Bit) view.setBigUint64(offset, value & MASK64, true);
		else view.setUint32(offset, Number(value & 0xffffffffn), true);
	};

	// Fill the GOT: defined symbols are rebased, undefined ones bound
	for (const [symbolIndex, slot] of gotSlots) {
		const symbol = symbols[symbolIndex]!;
		const slotOffset = gotFileOffset + slot * pointerSize;
		if (symbol.address !== null) {
			writePointer(slotOffset, symbol.address);
			rebaseMap.set(slotOffset, symbol.address);
		} else if (symbol.name) {
			bindMap.set(slotOffset, {
				ordinal: BIND_SPECIAL_DYLIB_FLAT_LOOKUP,
				symbolName: symbol.name,
				addend: 0n
			});
		}
	}
	const slotAddress = (symbolIndex: number): bigint | null => {
		const slot = gotSlots.get(symbolIndex);
		return slot === undefined ? null : gotVmaddr + BigInt(slot * pointerSize);
	};

	const sectionByOrdinal = (ordinal: number): Section64 | undefined => sections[ordinal - 1];

	const resolve = (r: RelocationEntry): Target | null => {
		if (!r.extern) {
			const section = sectionByOrdinal(r.symbolnum);
			return section ? { address: section.addr } : null;
		}
		const symbol = symbols[r.symbolnum];
		if (!symbol) return null;
		if (symbol.address !== null) return { address: symbol.address };
		return symbol.name ? { name: symbol.name } : null;
	};

	const readContent = (offset: number, length: number): bigint =>
		length === 3
			? view.getBigInt64(offset, true)
			: length === 2
				? BigInt(view.getInt32(offset, true))
				: 0n;

	const writeContent = (offset: number, length: number, value: bigint): void => {
		if (length === 3) view.setBigUint64(offset, value & MASK64, true);
		else if (length === 2) view.setUint32(offset, Number(value & 0xffffffffn), true);
	};

	/**
	 * Absolute pointer (UNSIGNED / arm64e authenticated). `content` is the addend for
	 * a symbol target; a section-relative entry already holds the target's address.
	 */
	const applyPointer = (r: RelocationEntry, offset: number, length: number, content: bigint) => {
		if (length !== 3 && length !== 2) return;
		const isPointer = length === (is64Bit ? 3 : 2);
		let value = content;
		if (r.extern) {
			const target = resolve(r);
			if (!target) return;
			if ("name" in target) {
				writeContent(offset, length, 0n);
				if (isPointer) {
					bindMap.set(offset, {
						ordinal: BIND_SPECIAL_DYLIB_FLAT_LOOKUP,
						symbolName: target.name,
						addend: content
					});
				}
				return;
			}
			value = target.address + content;
		}
		writeContent(offset, length, value);
		if (isPointer) rebaseMap.set(offset, value & (is64Bit ? MASK64 : 0xffffffffn));
	};

	for (const { section, entries } of relocSections) {
		const sectionEnd = Number(section.size);
		let pendingAddend = 0n;

		for (let i = 0; i < entries.length; i++) {
			const r = entries[i]!;
			const width = r.length === 3 ? 8 : r.length === 2 ? 4 : r.length === 1 ? 2 : 1;
			if (r.type < 0 || r.address < 0 || r.address + width > sectionEnd) {
				pendingAddend = 0n;
				continue;
			}
			const offset = section.offset + r.address;
			const pc = section.addr + BigInt(r.address);

			if (isClassic32) {
				// i386 and armv7 assemblers store values already computed in the object's
				// layout (differences, branches, section-relative pointers), so only
				// symbol pointers need resolving; absolute pointers feed the rebase map.
				if (r.type === GENERIC_RELOC_VANILLA && r.length === 2 && !r.pcrel) {
					if (r.scattered) rebaseMap.set(offset, BigInt(view.getUint32(offset, true)));
					else {
						const content = r.extern
							? BigInt(view.getInt32(offset, true))
							: BigInt(view.getUint32(offset, true));
						applyPointer(r, offset, 2, content);
					}
				}
				// Difference and half-word relocations are followed by their PAIR entry
				if (r.type !== RELOC_PAIR && entries[i + 1]?.type === RELOC_PAIR) i++;
				continue;
			}

			const isSubtractor = isArm64
				? r.type === ARM64_RELOC_SUBTRACTOR
				: r.type === X86_64_RELOC_SUBTRACTOR;
			if (isSubtractor) {
				// A - B + addend: this entry names B, the next (UNSIGNED, same address) names A
				pendingAddend = 0n;
				const next = entries[i + 1];
				i++;
				if (!next || next.address !== r.address || next.type !== 0) continue;
				const subtrahend = resolve(r);
				if (!subtrahend || !("address" in subtrahend)) continue;
				let minuend = 0n;
				if (next.extern) {
					const target = resolve(next);
					if (!target || !("address" in target)) continue;
					minuend = target.address;
				}
				const value = minuend - subtrahend.address + readContent(offset, r.length);
				writeContent(offset, r.length, value);
				continue;
			}

			if (isArm64) {
				const addend = pendingAddend;
				pendingAddend = 0n;
				switch (r.type) {
					case ARM64_RELOC_ADDEND:
						pendingAddend = BigInt(signExtend(r.symbolnum, 24));
						break;
					case ARM64_RELOC_UNSIGNED:
						applyPointer(r, offset, r.length, readContent(offset, r.length));
						break;
					case ARM64_RELOC_AUTHENTICATED_POINTER: {
						// Low 32 bits carry the addend; the rest is pointer-auth metadata
						if (r.length !== 3) break;
						const raw = view.getBigUint64(offset, true);
						applyPointer(r, offset, 3, BigInt.asIntN(32, raw & 0xffffffffn));
						break;
					}
					case ARM64_RELOC_BRANCH26: {
						const target = resolve(r);
						if (target && "address" in target) {
							patchBranch26(view, offset, pc, target.address + addend);
						}
						break;
					}
					case ARM64_RELOC_PAGE21:
					case ARM64_RELOC_PAGEOFF12: {
						const target = resolve(r);
						if (!target || !("address" in target)) break;
						if (r.type === ARM64_RELOC_PAGE21) {
							patchAdrp(view, offset, pc, target.address + addend);
						} else {
							patchPageOffset(view, offset, target.address + addend);
						}
						break;
					}
					case ARM64_RELOC_GOT_LOAD_PAGE21:
					case ARM64_RELOC_TLVP_LOAD_PAGE21: {
						const slot = r.extern ? slotAddress(r.symbolnum) : null;
						if (slot !== null) patchAdrp(view, offset, pc, slot);
						break;
					}
					case ARM64_RELOC_GOT_LOAD_PAGEOFF12:
					case ARM64_RELOC_TLVP_LOAD_PAGEOFF12: {
						const slot = r.extern ? slotAddress(r.symbolnum) : null;
						if (slot !== null) patchPageOffset(view, offset, slot);
						break;
					}
					case ARM64_RELOC_POINTER_TO_GOT: {
						const slot = r.extern ? slotAddress(r.symbolnum) : null;
						if (slot === null) break;
						// No addend: the assembler leaves a placeholder the linker ignores
						writeContent(offset, r.length, r.pcrel ? slot - pc : slot);
						if (!r.pcrel && r.length === (is64Bit ? 3 : 2)) rebaseMap.set(offset, slot);
						break;
					}
				}
				continue;
			}

			// x86_64
			switch (r.type) {
				case X86_64_RELOC_UNSIGNED:
					applyPointer(r, offset, r.length, readContent(offset, r.length));
					break;
				case X86_64_RELOC_SIGNED:
				case X86_64_RELOC_SIGNED_1:
				case X86_64_RELOC_SIGNED_2:
				case X86_64_RELOC_SIGNED_4:
				case X86_64_RELOC_BRANCH: {
					// Section-relative displacements are already final in the object's layout
					if (!r.extern || r.length !== 2) break;
					const target = resolve(r);
					if (!target || !("address" in target)) break;
					const content = readContent(offset, 2);
					writeContent(offset, 2, target.address + content - (pc + 4n));
					break;
				}
				case X86_64_RELOC_GOT_LOAD:
				case X86_64_RELOC_GOT:
				case X86_64_RELOC_TLV: {
					const slot = r.extern ? slotAddress(r.symbolnum) : null;
					if (slot === null || r.length !== 2 || !r.pcrel) break;
					const content = readContent(offset, 2);
					writeContent(offset, 2, slot + content - (pc + 4n));
					break;
				}
			}
		}
	}

	if (gotSlots.size > 0) {
		const gotSection: Section64 = {
			sectname: GOT_SECTNAME,
			segname: GOT_SEGNAME,
			addr: gotVmaddr,
			size: BigInt(gotSize),
			offset: gotFileOffset,
			align: 3,
			reloff: 0,
			nreloc: 0,
			flags: 0,
			reserved1: 0,
			reserved2: 0,
			reserved3: 0
		};
		segments.push({
			cmd: segments[0]?.cmd ?? 0,
			cmdsize: 0,
			segname: GOT_SEGNAME,
			vmaddr: gotVmaddr,
			vmsize: BigInt(gotSize),
			fileoff: BigInt(gotFileOffset),
			filesize: BigInt(gotSize),
			maxprot: 3,
			initprot: 3,
			nsects: 1,
			flags: 0,
			sections: [gotSection]
		});
	}

	return { buffer: out, segments, sectionSegments, rebaseMap, bindMap };
}

/**
 * Segments describing where an object file's bytes go, for size views. The grouped
 * section segments interleave in the file, so each is sized by its own sections
 * (`__TEXT` also takes the header and load commands ahead of the first section),
 * and a pseudo `__LINKEDIT` segment spans the trailing relocation entries, symbol
 * and string tables the way it would in a linked image.
 */
export function objectSizeSegments(
	lc: LoadCommandsResult,
	sectionSegments: Segment64[],
	fileSize: number
): Segment64[] {
	const filed = (s: Section64) => (isZerofill(s) ? 0 : Number(s.size));
	const firstSection = Math.min(
		...sectionSegments.flatMap((seg) => seg.sections.filter(filed).map((s) => s.offset))
	);
	const segments = sectionSegments.map((seg) => {
		let filesize = seg.sections.reduce((sum, s) => sum + filed(s), 0);
		if (seg.segname === "__TEXT" && Number.isFinite(firstSection)) filesize += firstSection;
		return { ...seg, filesize: BigInt(filesize) };
	});

	const starts: number[] = [];
	if (lc.symtabInfo) starts.push(lc.symtabInfo.symoff, lc.symtabInfo.stroff);
	for (const seg of lc.segments) {
		for (const s of seg.sections) if (s.nreloc > 0) starts.push(s.reloff);
	}
	const start = Math.min(...starts.filter((o) => o > 0 && o < fileSize));
	if (Number.isFinite(start)) {
		segments.push({
			cmd: lc.segments[0]?.cmd ?? 0,
			cmdsize: 0,
			segname: "__LINKEDIT",
			vmaddr: 0n,
			vmsize: 0n,
			fileoff: BigInt(start),
			filesize: BigInt(fileSize - start),
			maxprot: 1,
			initprot: 1,
			nsects: 0,
			flags: 0,
			sections: []
		});
	}
	return segments;
}
