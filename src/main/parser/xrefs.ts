/**
 * Cross-reference analysis for Mach-O binaries
 *
 * Parses LC_FUNCTION_STARTS to build function address ranges, then scans
 * arm64 code (__TEXT.__text) for ADRP+ADD instruction pairs that reference
 * addresses in string sections. This maps string file offsets to the
 * function(s) that reference them.
 */

import type { Section64, Segment64 } from "./load-commands";
import { CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_X86, CPU_TYPE_X86_64 } from "./macho";
import { vmaddrToFileOffset } from "./strings";
import type { SymbolEntry } from "./symbols";

// ── Function starts parsing ──────────────────────────────────────────

/**
 * Decode the ULEB128-encoded function start deltas from LC_FUNCTION_STARTS.
 * Returns an array of virtual memory addresses for each function entry point.
 */
export function parseFunctionStarts(
	buffer: ArrayBuffer,
	dataoff: number,
	datasize: number,
	textSegmentVmaddr: bigint
): bigint[] {
	const bytes = new Uint8Array(buffer);
	const end = dataoff + datasize;
	const addrs: bigint[] = [];
	let addr = textSegmentVmaddr;

	let pos = dataoff;
	while (pos < end) {
		// Read ULEB128 delta
		let delta = 0n;
		let shift = 0n;
		let byte: number;
		do {
			if (pos >= end) break;
			byte = bytes[pos++]!;
			delta |= BigInt(byte & 0x7f) << shift;
			shift += 7n;
		} while (byte & 0x80);

		if (delta === 0n) break; // terminator
		addr += delta;
		addrs.push(addr);
	}

	return addrs;
}

// ── Function range building ──────────────────────────────────────────

interface FunctionRange {
	start: bigint; // vmaddr
	end: bigint; // vmaddr of next function (exclusive)
	name: string;
}

/**
 * Build named function ranges from function starts and symbol table.
 * If functionStarts is empty, falls back to deriving ranges from symbol
 * addresses in the __text section (common for stripped frameworks that
 * lack LC_FUNCTION_STARTS).
 */
function buildFunctionRanges(
	functionStarts: bigint[],
	symbols: SymbolEntry[],
	textSectionStart: bigint,
	textSectionEnd: bigint
): FunctionRange[] {
	// Build address → name map from non-imported symbols
	const addrToName = new Map<bigint, string>();
	for (const sym of symbols) {
		if (sym.type === "imported") continue;
		const existing = addrToName.get(sym.address);
		if (!existing || (existing.startsWith("sub_") && !sym.name.startsWith("sub_"))) {
			addrToName.set(sym.address, sym.name);
		}
	}

	// Use function starts if available; otherwise derive from symbol addresses
	let sortedAddrs: bigint[];
	if (functionStarts.length > 0) {
		sortedAddrs = functionStarts;
	} else {
		// Collect symbol addresses that fall within the __text section
		const textSymAddrs = new Set<bigint>();
		for (const sym of symbols) {
			if (sym.type === "imported") continue;
			if (sym.address >= textSectionStart && sym.address < textSectionEnd) {
				textSymAddrs.add(sym.address);
			}
		}
		if (textSymAddrs.size === 0) return [];
		sortedAddrs = [...textSymAddrs].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
	}

	const ranges: FunctionRange[] = [];
	for (let i = 0; i < sortedAddrs.length; i++) {
		const start = sortedAddrs[i]!;
		const end = i + 1 < sortedAddrs.length ? sortedAddrs[i + 1]! : textSectionEnd;
		const name = addrToName.get(start) ?? `sub_${start.toString(16)}`;
		ranges.push({ start, end, name });
	}

	return ranges;
}

/**
 * Find the function containing a given vmaddr using binary search.
 */
function findContainingFunction(vmaddr: bigint, ranges: FunctionRange[]): string | null {
	let lo = 0;
	let hi = ranges.length - 1;
	while (lo <= hi) {
		const mid = (lo + hi) >>> 1;
		const r = ranges[mid]!;
		if (vmaddr < r.start) {
			hi = mid - 1;
		} else if (vmaddr >= r.end) {
			lo = mid + 1;
		} else {
			return r.name;
		}
	}
	return null;
}

// ── ARM64 instruction decoding ───────────────────────────────────────

/**
 * Decode an ADRP instruction.
 * Returns { rd, targetPage } or null if not ADRP.
 *
 * ADRP: bit[31]=1, bits[28:24]=10000
 *   immlo = bits[30:29], immhi = bits[23:5]
 *   immediate = SignExtend(immhi:immlo, 21) << 12
 *   result = (PC & ~0xFFF) + immediate
 */
function decodeADRP(insn: number, pc: bigint): { rd: number; target: bigint } | null {
	// Check opcode: bit31=1, bits[28:24]=10000
	// Use >>> 0 to force unsigned comparison (JS bitwise ops return signed Int32)
	if ((insn & 0x9f000000) >>> 0 !== 0x90000000) return null;

	const rd = insn & 0x1f;
	const immlo = (insn >>> 29) & 0x3;
	const immhi = (insn >>> 5) & 0x7ffff;
	// Combine: 21-bit value = immhi:immlo
	let imm21 = (immhi << 2) | immlo;
	// Sign-extend from 21 bits
	if (imm21 & (1 << 20)) {
		imm21 |= ~((1 << 21) - 1); // sign extend to 32 bits
	}
	const immediate = BigInt(imm21) << 12n;
	const pageBase = pc & ~0xfffn;
	return { rd, target: pageBase + immediate };
}

/**
 * Decode an ADD immediate instruction.
 * Returns { rd, rn, imm } or null if not ADD imm.
 *
 * ADD (imm): sf=1, bits[30:24]=0010001, sh, imm12, Rn, Rd
 */
function decodeADDImm(insn: number): { rd: number; rn: number; imm: number } | null {
	// Check: bit31=1 (64-bit), bits[30:24]=0010001
	if ((insn & 0xff000000) >>> 0 !== 0x91000000) return null;

	const rd = insn & 0x1f;
	const rn = (insn >>> 5) & 0x1f;
	const imm12 = (insn >>> 10) & 0xfff;
	const sh = (insn >>> 22) & 0x1;
	const imm = sh ? imm12 << 12 : imm12;

	return { rd, rn, imm };
}

/**
 * Decode an ADR instruction (PC-relative address within +/-1MB).
 * Returns { rd, target } or null if not ADR.
 *
 * ADR: bit[31]=0, bits[28:24]=10000
 *   immlo = bits[30:29], immhi = bits[23:5]
 *   immediate = SignExtend(immhi:immlo, 21)
 *   result = PC + immediate
 */
function decodeADR(insn: number, pc: bigint): { rd: number; target: bigint } | null {
	// Check opcode: bit31=0, bits[28:24]=10000
	if ((insn & 0x9f000000) >>> 0 !== 0x10000000) return null;

	const rd = insn & 0x1f;
	const immlo = (insn >>> 29) & 0x3;
	const immhi = (insn >>> 5) & 0x7ffff;
	let imm21 = (immhi << 2) | immlo;
	// Sign-extend from 21 bits
	if (imm21 & (1 << 20)) {
		imm21 |= ~((1 << 21) - 1);
	}
	return { rd, target: pc + BigInt(imm21) };
}

/**
 * Decode an LDR (unsigned offset, 64-bit) instruction.
 * Returns { rt, rn, offset } or null.
 *
 * LDR Xt, [Xn, #imm]: size=11, V=0, opc=01
 * Encoding: 1111 1001 01 [imm12] [Rn] [Rt]
 * offset = imm12 << 3
 */
function decodeLDR64(insn: number): { rt: number; rn: number; offset: number } | null {
	if ((insn & 0xffc00000) >>> 0 !== 0xf9400000) return null;
	const rt = insn & 0x1f;
	const rn = (insn >>> 5) & 0x1f;
	const imm12 = (insn >>> 10) & 0xfff;
	return { rt, rn, offset: imm12 << 3 };
}

// ── ARM32 / THUMB-2 instruction decoding ─────────────────────────────

/**
 * Decode ARM32 LDR Rd, [PC, #imm] - PC-relative literal load.
 * This is the most common pattern for loading string addresses.
 * Note: ARM32 PC is instruction address + 8 (pipeline).
 */
function decodeARM32_LDR_PC(insn: number, pc: bigint): { rd: number; target: bigint } | null {
	// Pattern: cond 01 0 P U 0 W 1 1111 Rd [imm12]
	// For LDR with PC base (Rn=15): bits[19:16] = 1111
	// cond=AL (1110), P=1, W=0, L=1
	// Check: 1110 01 0 1 U 0 0 1 1111 Rd [imm12]
	if ((insn & 0x0f7f0000) !== 0x051f0000) return null;

	const rd = (insn >>> 12) & 0xf;
	const imm12 = insn & 0xfff;
	const isAdd = (insn >>> 23) & 1;

	// ARM32 PC is instruction address + 8
	const effectivePC = pc + 8n;
	const offset = isAdd ? BigInt(imm12) : -BigInt(imm12);

	return { rd, target: effectivePC + offset };
}

/**
 * Decode ARM32 ADR (ADD/SUB Rd, PC, #imm).
 * Used for PC-relative address calculation.
 */
function decodeARM32_ADR(insn: number, pc: bigint): { rd: number; target: bigint } | null {
	// ADD Rd, PC, #imm: 1110 00 1 0100 0 1111 Rd [rotate][imm8]
	// SUB Rd, PC, #imm: 1110 00 1 0010 0 1111 Rd [rotate][imm8]
	const isADD = (insn & 0x0fef0000) === 0x028f0000;
	const isSUB = (insn & 0x0fef0000) === 0x024f0000;
	if (!isADD && !isSUB) return null;

	const rd = (insn >>> 12) & 0xf;
	const rotate = (insn >>> 8) & 0xf;
	const imm8 = insn & 0xff;

	// ARM32 rotated immediate: imm8 ROR (rotate * 2)
	const rotateAmount = rotate * 2;
	const immediate =
		rotateAmount === 0 ? imm8 : ((imm8 >>> rotateAmount) | (imm8 << (32 - rotateAmount))) >>> 0;

	const effectivePC = pc + 8n;
	const offset = isADD ? BigInt(immediate) : -BigInt(immediate);

	return { rd, target: effectivePC + offset };
}

/**
 * Decode ARM32 MOVW Rd, #imm16 (load low 16 bits).
 */
function decodeARM32_MOVW(insn: number): { rd: number; imm16: number } | null {
	// Encoding: 1110 0011 0000 [imm4] [Rd] [imm12]
	if ((insn & 0x0ff00000) !== 0x03000000) return null;

	const rd = (insn >>> 12) & 0xf;
	const imm4 = (insn >>> 16) & 0xf;
	const imm12 = insn & 0xfff;
	const imm16 = (imm4 << 12) | imm12;

	return { rd, imm16 };
}

/**
 * Decode ARM32 MOVT Rd, #imm16 (load high 16 bits).
 */
function decodeARM32_MOVT(insn: number): { rd: number; imm16: number } | null {
	// Encoding: 1110 0011 0100 [imm4] [Rd] [imm12]
	if ((insn & 0x0ff00000) !== 0x03400000) return null;

	const rd = (insn >>> 12) & 0xf;
	const imm4 = (insn >>> 16) & 0xf;
	const imm12 = insn & 0xfff;
	const imm16 = (imm4 << 12) | imm12;

	return { rd, imm16 };
}

/**
 * Decode THUMB-2 LDR.W Rt, [PC, #imm] - 32-bit PC-relative load.
 * This is the common pattern in THUMB-2 code.
 * Note: THUMB PC is instruction address + 4, aligned to 4.
 */
function decodeThumb2_LDR_PC(
	hw1: number,
	hw2: number,
	pc: bigint
): { rd: number; target: bigint } | null {
	// LDR.W Rt, [PC, #imm12] or LDR.W Rt, [PC, #-imm12]
	// Encoding: 1111 1000 U 101 1111 | Rt [imm12]
	// hw1: F8DF (add) or F85F (subtract)
	if ((hw1 & 0xff7f) !== 0xf85f && (hw1 & 0xff7f) !== 0xf8df) return null;

	const isAdd = (hw1 & 0x0080) !== 0;
	const rt = (hw2 >>> 12) & 0xf;
	const imm12 = hw2 & 0xfff;

	// THUMB PC is (instruction address + 4) aligned down to 4
	const effectivePC = (pc + 4n) & ~3n;
	const offset = isAdd ? BigInt(imm12) : -BigInt(imm12);

	return { rd: rt, target: effectivePC + offset };
}

/**
 * Decode THUMB-2 MOVW Rd, #imm16 (load low 16 bits).
 */
function decodeThumb2_MOVW(hw1: number, hw2: number): { rd: number; imm16: number } | null {
	// Encoding: 1111 0 i 10 0 1 0 0 [imm4] | 0 [imm3] [Rd] [imm8]
	// hw1: F240-F24F or F2C0-F2CF (with i bit)
	if ((hw1 & 0xfbf0) !== 0xf240) return null;

	const imm4 = hw1 & 0xf;
	const i = (hw1 >>> 10) & 1;
	const imm3 = (hw2 >>> 12) & 0x7;
	const rd = (hw2 >>> 8) & 0xf;
	const imm8 = hw2 & 0xff;

	const imm16 = (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8;

	return { rd, imm16 };
}

/**
 * Decode THUMB-2 MOVT Rd, #imm16 (load high 16 bits).
 */
function decodeThumb2_MOVT(hw1: number, hw2: number): { rd: number; imm16: number } | null {
	// Encoding: 1111 0 i 10 1 1 0 0 [imm4] | 0 [imm3] [Rd] [imm8]
	if ((hw1 & 0xfbf0) !== 0xf2c0) return null;

	const imm4 = hw1 & 0xf;
	const i = (hw1 >>> 10) & 1;
	const imm3 = (hw2 >>> 12) & 0x7;
	const rd = (hw2 >>> 8) & 0xf;
	const imm8 = hw2 & 0xff;

	const imm16 = (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8;

	return { rd, imm16 };
}

/**
 * Decode 16-bit THUMB LDR Rt, [PC, #imm8] - short PC-relative load.
 */
function decodeThumb16_LDR_PC(hw: number, pc: bigint): { rd: number; target: bigint } | null {
	// Encoding: 0100 1 [Rt:3] [imm8]
	if ((hw & 0xf800) !== 0x4800) return null;

	const rt = (hw >>> 8) & 0x7;
	const imm8 = hw & 0xff;

	// PC is (instruction address + 4) aligned to 4, offset is imm8 << 2
	const effectivePC = (pc + 4n) & ~3n;
	const offset = BigInt(imm8 << 2);

	return { rd: rt, target: effectivePC + offset };
}

// ── x86 32-bit instruction decoding ──────────────────────────────────

/**
 * Decode x86 MOV EAX, [addr] - direct load to EAX.
 * Opcode: A1 [addr32]
 */
function decodeX86_MOV_EAX_mem(
	bytes: Uint8Array,
	offset: number
): { address: number; length: number } | null {
	if (offset >= bytes.length) return null;
	if (bytes[offset] !== 0xa1) return null;
	if (offset + 5 > bytes.length) return null;

	const view = new DataView(bytes.buffer, bytes.byteOffset + offset);
	const address = view.getUint32(1, true); // little-endian

	return { address, length: 5 };
}

/**
 * Decode x86 MOV reg, [addr] or LEA reg, [addr] with ModR/M absolute addressing.
 * Opcode: 8B /r (MOV) or 8D /r (LEA)
 * ModR/M with mod=00, r/m=101 means disp32 (no base register).
 */
function decodeX86_MOV_LEA_mem(
	bytes: Uint8Array,
	offset: number
): { reg: number; address: number; length: number } | null {
	if (offset + 1 >= bytes.length) return null;

	const opcode = bytes[offset]!;
	if (opcode !== 0x8b && opcode !== 0x8d) return null;

	const modrm = bytes[offset + 1]!;
	const mod = (modrm >>> 6) & 0x3;
	const reg = (modrm >>> 3) & 0x7;
	const rm = modrm & 0x7;

	// mod=00, rm=101 means 32-bit displacement only (no SIB, no base)
	if (mod !== 0 || rm !== 5) return null;
	if (offset + 6 > bytes.length) return null;

	const view = new DataView(bytes.buffer, bytes.byteOffset + offset);
	const address = view.getUint32(2, true);

	return { reg, address, length: 6 };
}

// ── String section range helpers ─────────────────────────────────────

interface VmRange {
	vmStart: bigint;
	vmEnd: bigint;
	fileStart: number;
	isCFString: boolean;
}

function buildStringSectionRanges(segments: Segment64[]): VmRange[] {
	const STRING_SECTIONS = [
		"__cstring",
		"__objc_methname",
		"__objc_classname",
		"__objc_methtype",
		"__swift5_reflstr",
		"__oslogstring",
		"__ustring"
	];

	const ranges: VmRange[] = [];
	for (const seg of segments) {
		for (const sect of seg.sections) {
			const name = sect.sectname.trim();
			if (STRING_SECTIONS.includes(name)) {
				ranges.push({
					vmStart: sect.addr,
					vmEnd: sect.addr + sect.size,
					fileStart: sect.offset,
					isCFString: false
				});
			} else if (name === "__cfstring") {
				ranges.push({
					vmStart: sect.addr,
					vmEnd: sect.addr + sect.size,
					fileStart: sect.offset,
					isCFString: true
				});
			}
		}
	}
	return ranges;
}

/**
 * Check if a vmaddr falls in a string section and return the file offset.
 * Also indicates whether the hit is in a CFString section.
 */
function vmaddrToStringFileOffset(
	vmaddr: bigint,
	strRanges: VmRange[]
): { fileOffset: number; isCFString: boolean } | null {
	for (const r of strRanges) {
		if (vmaddr >= r.vmStart && vmaddr < r.vmEnd) {
			return {
				fileOffset: r.fileStart + Number(vmaddr - r.vmStart),
				isCFString: r.isCFString
			};
		}
	}
	return null;
}

// CFString struct sizes:
// 64-bit: isa(8) + flags(8) + data_ptr(8) + length(8) = 32 bytes
// 32-bit: isa(4) + flags(4) + data_ptr(4) + length(4) = 16 bytes
const CFSTRING_STRUCT_SIZE_64 = 32;
const CFSTRING_STRUCT_SIZE_32 = 16;
const CFSTRING_DATA_OFFSET_64 = 16;
const CFSTRING_DATA_OFFSET_32 = 8;

/**
 * For a CFString struct at a given file offset, resolve the data_ptr field
 * to get the file offset of the actual string character data.
 * This handles the deduplication mismatch: code references the CFString struct,
 * but the StringEntry may use the __cstring data offset.
 */
function resolveCFStringDataOffset(
	structFileOffset: number,
	buffer: ArrayBuffer,
	segments: Segment64[],
	rebaseMap: Map<number, bigint>,
	littleEndian: boolean,
	is64Bit: boolean
): number | null {
	const view = new DataView(buffer);
	const dataPtrOffset = is64Bit ? CFSTRING_DATA_OFFSET_64 : CFSTRING_DATA_OFFSET_32;
	const ptrSize = is64Bit ? 8 : 4;
	const dataPtrFieldOffset = structFileOffset + dataPtrOffset;

	if (dataPtrFieldOffset + ptrSize > buffer.byteLength) return null;

	// Try rebaseMap first (chained fixups)
	const rebasedVmaddr = rebaseMap.get(dataPtrFieldOffset);
	if (rebasedVmaddr !== undefined) {
		return vmaddrToFileOffset(rebasedVmaddr, segments);
	}

	// Fallback: raw pointer value
	const rawPtr = is64Bit
		? view.getBigUint64(dataPtrFieldOffset, littleEndian)
		: BigInt(view.getUint32(dataPtrFieldOffset, littleEndian));
	if (rawPtr > 0n) {
		return vmaddrToFileOffset(rawPtr, segments);
	}

	return null;
}

// ── Xref context (shared state for all scanners) ─────────────────────

interface XrefContext {
	buffer: ArrayBuffer;
	view: DataView;
	segments: Segment64[];
	funcRanges: FunctionRange[];
	strRanges: VmRange[];
	indirectVmaddrMap: Map<bigint, number>;
	xrefMap: Map<number, string[]>;
	rebaseMap: Map<number, bigint>;
	littleEndian: boolean;
	is64Bit: boolean;
	textSection: Section64;
}

function createXrefContext(
	buffer: ArrayBuffer,
	segments: Segment64[],
	functionStarts: bigint[],
	symbols: SymbolEntry[],
	littleEndian: boolean,
	rebaseMap: Map<number, bigint>,
	is64Bit: boolean
): XrefContext | null {
	// Find __TEXT.__text section
	let textSection: Section64 | null = null;
	for (const seg of segments) {
		if (seg.segname.trim() === "__TEXT") {
			for (const sect of seg.sections) {
				if (sect.sectname.trim() === "__text") {
					textSection = sect;
					break;
				}
			}
			break;
		}
	}

	if (!textSection) return null;

	// Build function ranges (uses function starts if available, else symbol addresses)
	const textStart = textSection.addr;
	const textEnd = textSection.addr + textSection.size;
	const funcRanges = buildFunctionRanges(functionStarts, symbols, textStart, textEnd);
	if (funcRanges.length === 0) return null;

	// Build string section vmaddr ranges (includes __cstring, __cfstring, etc.)
	const strRanges = buildStringSectionRanges(segments);
	if (strRanges.length === 0) return null;

	// Build indirect pointer map: for strings referenced through data tables
	const indirectPtrMap = new Map<number, number>();
	for (const [ptrFileOff, targetVmaddr] of rebaseMap) {
		for (const r of strRanges) {
			if (targetVmaddr >= r.vmStart && targetVmaddr < r.vmEnd) {
				const strFileOff = r.fileStart + Number(targetVmaddr - r.vmStart);
				indirectPtrMap.set(ptrFileOff, strFileOff);
				break;
			}
		}
	}

	// Convert indirect pointer file offsets → vmaddrs for matching against code targets
	const indirectVmaddrMap = new Map<bigint, number>();
	for (const [ptrFileOff, strFileOff] of indirectPtrMap) {
		for (const seg of segments) {
			const segFileOff = Number(seg.fileoff);
			const segFileEnd = segFileOff + Number(seg.filesize);
			if (ptrFileOff >= segFileOff && ptrFileOff < segFileEnd) {
				const vmaddr = seg.vmaddr + BigInt(ptrFileOff - segFileOff);
				indirectVmaddrMap.set(vmaddr, strFileOff);
				break;
			}
		}
	}

	return {
		buffer,
		view: new DataView(buffer),
		segments,
		funcRanges,
		strRanges,
		indirectVmaddrMap,
		xrefMap: new Map(),
		rebaseMap,
		littleEndian,
		is64Bit,
		textSection
	};
}

function addXref(ctx: XrefContext, fileOffset: number, funcName: string): void {
	const existing = ctx.xrefMap.get(fileOffset);
	if (existing) {
		if (!existing.includes(funcName)) existing.push(funcName);
	} else {
		ctx.xrefMap.set(fileOffset, [funcName]);
	}
}

/**
 * Record a xref for a resolved target vmaddr.
 * Checks: direct string section hit, CFString data_ptr resolution,
 * and indirect pointers through data tables.
 */
function recordXrefForTarget(ctx: XrefContext, targetVmaddr: bigint, pc: bigint): void {
	const ptrSize = ctx.is64Bit ? 8n : 4n;

	// 1. Direct hit in a string/CFString section
	const directHit = vmaddrToStringFileOffset(targetVmaddr, ctx.strRanges);
	if (directHit) {
		const funcName = findContainingFunction(pc, ctx.funcRanges);
		if (!funcName) return;

		addXref(ctx, directHit.fileOffset, funcName);

		// For CFString, also resolve data_ptr to the actual __cstring offset
		if (directHit.isCFString) {
			const dataOffset = resolveCFStringDataOffset(
				directHit.fileOffset,
				ctx.buffer,
				ctx.segments,
				ctx.rebaseMap,
				ctx.littleEndian,
				ctx.is64Bit
			);
			if (dataOffset !== null && dataOffset !== directHit.fileOffset) {
				addXref(ctx, dataOffset, funcName);
			}
		}
		return;
	}

	// 2. Indirect: target is a data location that holds a pointer to a string
	const indirectStrOff = ctx.indirectVmaddrMap.get(targetVmaddr);
	if (indirectStrOff !== undefined) {
		const funcName = findContainingFunction(pc, ctx.funcRanges);
		if (funcName) addXref(ctx, indirectStrOff, funcName);
		return;
	}

	// 3. Check nearby aligned addresses for indirect pointers (array access patterns)
	for (let delta = 0n; delta < 256n; delta += ptrSize) {
		const nearby = ctx.indirectVmaddrMap.get(targetVmaddr + delta);
		if (nearby !== undefined) {
			const funcName = findContainingFunction(pc, ctx.funcRanges);
			if (funcName) addXref(ctx, nearby, funcName);
			return;
		}
	}
}

// ── ARM64 scanner ────────────────────────────────────────────────────

function scanARM64(ctx: XrefContext): void {
	const { view, littleEndian, textSection, buffer } = ctx;
	const sectionOffset = textSection.offset;
	const sectionSize = Number(textSection.size);
	const sectionVmaddr = textSection.addr;

	// Limit scan to avoid excessive time on very large binaries
	const MAX_INSTRUCTIONS = 20_000_000; // ~80MB of arm64 code
	const instrCount = Math.min(sectionSize >>> 2, MAX_INSTRUCTIONS);

	// Track register values: register → { computed address, instruction index }
	const regCache = new Map<number, { addr: bigint; instrIdx: number }>();
	const MAX_GAP = 8;

	for (let i = 0; i < instrCount; i++) {
		const off = sectionOffset + (i << 2);
		if (off + 4 > buffer.byteLength) break;

		const insn = view.getUint32(off, littleEndian);
		const pc = sectionVmaddr + BigInt(i << 2);

		// ── Try ADRP ──
		const adrp = decodeADRP(insn, pc);
		if (adrp) {
			regCache.set(adrp.rd, { addr: adrp.target, instrIdx: i });
			continue;
		}

		// ── Try ADR (single-instruction PC-relative) ──
		const adr = decodeADR(insn, pc);
		if (adr) {
			regCache.set(adr.rd, { addr: adr.target, instrIdx: i });
			recordXrefForTarget(ctx, adr.target, pc);
			continue;
		}

		// ── Try ADD immediate (ADRP + ADD pattern) ──
		const add = decodeADDImm(insn);
		if (add) {
			const cached = regCache.get(add.rn);
			if (cached && i - cached.instrIdx <= MAX_GAP) {
				const target = cached.addr + BigInt(add.imm);
				recordXrefForTarget(ctx, target, pc);
				regCache.set(add.rd, { addr: target, instrIdx: i });
			} else if (add.rd !== add.rn) {
				regCache.delete(add.rd);
			}
			continue;
		}

		// ── Try LDR 64-bit unsigned offset (ADRP+LDR or ADRP+ADD+LDR) ──
		const ldr = decodeLDR64(insn);
		if (ldr) {
			const cached = regCache.get(ldr.rn);
			if (cached && i - cached.instrIdx <= MAX_GAP) {
				const target = cached.addr + BigInt(ldr.offset);
				recordXrefForTarget(ctx, target, pc);
			}
		}
	}
}

// ── ARM32 / THUMB-2 scanner ──────────────────────────────────────────

/**
 * Scan ARM32 / THUMB-2 code for string references.
 * Most iOS 32-bit binaries use THUMB-2, so we primarily scan for THUMB patterns.
 * The function start addresses have bit 0 set for THUMB code (Thumb interworking).
 */
function scanARM32(ctx: XrefContext): void {
	const { view, littleEndian, textSection, buffer } = ctx;
	const sectionOffset = textSection.offset;
	const sectionSize = Number(textSection.size);
	const sectionVmaddr = textSection.addr;

	// Limit scan to avoid excessive time on very large binaries
	const MAX_BYTES = 80_000_000; // ~80MB
	const scanSize = Math.min(sectionSize, MAX_BYTES);

	// Track register values for MOVW+MOVT pairs
	const movwCache = new Map<number, { lo16: number; byteIdx: number }>();
	const regCache = new Map<number, { addr: bigint; byteIdx: number }>();
	const MAX_GAP_BYTES = 32; // Allow up to 32 bytes between related instructions

	// THUMB-2 uses 16-bit and 32-bit instructions mixed
	// We scan 2 bytes at a time, checking for 32-bit instruction prefixes
	let pos = 0;
	while (pos < scanSize) {
		const off = sectionOffset + pos;
		if (off + 2 > buffer.byteLength) break;

		const pc = sectionVmaddr + BigInt(pos);
		const hw1 = view.getUint16(off, littleEndian);

		// Check if this is a 32-bit THUMB-2 instruction
		// 32-bit instructions have first halfword in range 0xE800-0xFFFF
		// or 0xE000-0xE7FF for BL/BLX
		const is32Bit = (hw1 & 0xe000) === 0xe000 && (hw1 & 0x1800) !== 0x0000;

		if (is32Bit && pos + 4 <= scanSize) {
			if (off + 4 > buffer.byteLength) break;
			const hw2 = view.getUint16(off + 2, littleEndian);

			// Try THUMB-2 LDR.W [PC, #imm]
			const ldrPC = decodeThumb2_LDR_PC(hw1, hw2, pc);
			if (ldrPC) {
				regCache.set(ldrPC.rd, { addr: ldrPC.target, byteIdx: pos });
				recordXrefForTarget(ctx, ldrPC.target, pc);
				pos += 4;
				continue;
			}

			// Try THUMB-2 MOVW (low 16 bits)
			const movw = decodeThumb2_MOVW(hw1, hw2);
			if (movw) {
				movwCache.set(movw.rd, { lo16: movw.imm16, byteIdx: pos });
				pos += 4;
				continue;
			}

			// Try THUMB-2 MOVT (high 16 bits) - combine with MOVW
			const movt = decodeThumb2_MOVT(hw1, hw2);
			if (movt) {
				const cached = movwCache.get(movt.rd);
				if (cached && pos - cached.byteIdx <= MAX_GAP_BYTES) {
					const fullAddr = BigInt((movt.imm16 << 16) | cached.lo16);
					regCache.set(movt.rd, { addr: fullAddr, byteIdx: pos });
					recordXrefForTarget(ctx, fullAddr, pc);
				}
				pos += 4;
				continue;
			}

			// Unknown 32-bit instruction, skip it
			pos += 4;
			continue;
		}

		// 16-bit THUMB instruction
		// Try THUMB-16 LDR Rt, [PC, #imm8]
		const ldr16 = decodeThumb16_LDR_PC(hw1, pc);
		if (ldr16) {
			regCache.set(ldr16.rd, { addr: ldr16.target, byteIdx: pos });
			recordXrefForTarget(ctx, ldr16.target, pc);
			pos += 2;
			continue;
		}

		// Unknown 16-bit instruction, skip it
		pos += 2;
	}
}

// ── x86 32-bit scanner ───────────────────────────────────────────────

/**
 * Scan x86 32-bit code for string references.
 * x86 uses variable-length instructions, so we scan byte-by-byte looking for
 * known patterns that load absolute addresses.
 */
function scanX86(ctx: XrefContext): void {
	const { textSection, buffer } = ctx;
	const sectionOffset = textSection.offset;
	const sectionSize = Number(textSection.size);
	const sectionVmaddr = textSection.addr;
	const bytes = new Uint8Array(buffer);

	// Limit scan to avoid excessive time on very large binaries
	const MAX_BYTES = 80_000_000; // ~80MB
	const scanSize = Math.min(sectionSize, MAX_BYTES);

	let pos = 0;
	while (pos < scanSize) {
		const off = sectionOffset + pos;
		if (off >= buffer.byteLength) break;

		const pc = sectionVmaddr + BigInt(pos);

		// Try MOV EAX, [addr] (opcode A1)
		const movEax = decodeX86_MOV_EAX_mem(bytes, off);
		if (movEax) {
			const vmaddr = BigInt(movEax.address);
			recordXrefForTarget(ctx, vmaddr, pc);
			pos += movEax.length;
			continue;
		}

		// Try MOV/LEA reg, [addr] with ModR/M absolute addressing
		const movLea = decodeX86_MOV_LEA_mem(bytes, off);
		if (movLea) {
			const vmaddr = BigInt(movLea.address);
			recordXrefForTarget(ctx, vmaddr, pc);
			pos += movLea.length;
			continue;
		}

		// Unknown byte, skip it
		pos++;
	}
}

// ── Main xref builder ────────────────────────────────────────────────

/**
 * Build a map from string file offset to the function name(s) that reference it.
 *
 * Dispatches to architecture-specific scanners based on CPU type:
 *   - ARM64: ADRP+ADD, ADRP+LDR, ADR patterns
 *   - ARM32/THUMB: LDR [PC], MOVW+MOVT patterns
 *   - x86_64: Same as ARM64 (RIP-relative addressing is similar)
 *   - x86: Absolute addressing patterns
 */
export function buildStringXrefMap(
	buffer: ArrayBuffer,
	segments: Segment64[],
	functionStarts: bigint[],
	symbols: SymbolEntry[],
	littleEndian: boolean,
	rebaseMap: Map<number, bigint>,
	cputype: number = CPU_TYPE_ARM64,
	is64Bit: boolean = true
): Map<number, string[]> {
	const ctx = createXrefContext(
		buffer,
		segments,
		functionStarts,
		symbols,
		littleEndian,
		rebaseMap,
		is64Bit
	);
	if (!ctx) return new Map();

	// Dispatch to architecture-specific scanner
	switch (cputype) {
		case CPU_TYPE_ARM64:
		case CPU_TYPE_X86_64:
			// ARM64 and x86_64 both use PC-relative addressing that our ARM64 scanner handles
			scanARM64(ctx);
			break;
		case CPU_TYPE_ARM:
			scanARM32(ctx);
			break;
		case CPU_TYPE_X86:
			scanX86(ctx);
			break;
		default:
			// Unknown architecture, return empty map
			break;
	}

	return ctx.xrefMap;
}

// ── Convenience: format function name for display ────────────────────

/**
 * Clean up a raw symbol name for display.
 * ObjC methods like "-[ClassName method:]" are already readable.
 * C functions start with "_" which we strip.
 */
export function formatFunctionName(raw: string): string {
	// ObjC method: already in nice form
	if (raw.startsWith("-[") || raw.startsWith("+[")) {
		return raw;
	}
	// Strip leading underscore from C symbols
	if (raw.startsWith("_")) {
		return raw.slice(1);
	}
	return raw;
}
