/**
 * Swift small-string extraction
 *
 * Swift stores strings of up to 15 UTF-8 code units inline in the 16-byte
 * `String` value (tag byte 15: `(tag & 0xb0) === 0xa0`, count in the low nibble).
 * These values never appear in `__cstring`, `__swift5_reflstr` or the other
 * sections the regular string extractor reads, so they are scanned separately:
 *
 * 1. Constant data in `__const` and `__data` sections.
 * 2. Instruction immediates in `__TEXT.__text` (ARM64 MOVZ/MOVN/MOVK pairs,
 *    x86_64 movabs / mov imm32 pairs).
 *
 * Decoding is best-effort and strict: the tag, zero padding, valid UTF-8 and a
 * nonzero count are all required. The module does not deduplicate; callers merge
 * the hits into their own value map.
 */

import { vmaddrToFileOffset } from "./address";
import type { Section64, Segment64 } from "./load-commands";
import { CPU_TYPE_ARM64, CPU_TYPE_X86_64 } from "./macho";

export const SMALL_STRING_SOURCE = "__swift_small";
export const SMALL_STRING_CODE_SOURCE = "__swift_small_code";

const SIZE = 16;
const TAG_MASK = 0xb0;
const TAG_VALUE = 0xa0;
const MAX_COUNT = 15;
const utf8 = new TextDecoder("utf-8", { fatal: true });

export interface SmallStringHit {
	value: string;
	/** File offset of the 16-byte value (data) or its first materialising
	 *  instruction (code). */
	offset: number;
	source: string;
}

/** Decode a 64-bit small string at `offset`. Returns null when the bytes are
 *  not a valid small-string value. */
export function decodeSmallString64(bytes: Uint8Array, offset: number): string | null {
	if (offset < 0 || offset + SIZE > bytes.length) return null;
	const tag = bytes[offset + 15]!;
	if ((tag & TAG_MASK) !== TAG_VALUE) return null;
	const count = tag & 0x0f;
	if (count < 1 || count > MAX_COUNT) return null;
	for (let i = count; i < SIZE - 1; i++) {
		if (bytes[offset + i] !== 0) return null;
	}
	let value: string;
	try {
		value = utf8.decode(bytes.subarray(offset, offset + count));
	} catch {
		return null;
	}
	if (value.length === 0 || value.includes("\0")) return null;
	return value;
}

/** Scan constant sections and (optionally) code immediates. */
export function scanSwiftSmallStrings(
	buffer: ArrayBuffer,
	segments: Segment64[],
	cputype: number,
	is64Bit: boolean,
	scanCode: boolean
): SmallStringHit[] {
	if (!is64Bit) return [];
	const bytes = new Uint8Array(buffer);
	const hits: SmallStringHit[] = [];

	scanConstantSections(bytes, segments, hits);

	if (scanCode) {
		const text = findTextSection(segments);
		if (text) {
			const start = vmaddrToFileOffset(text.addr, segments) ?? text.offset;
			const end = Math.min(start + Number(text.size), bytes.length);
			if (start >= 0 && start < end) {
				const view = new DataView(buffer);
				if (cputype === CPU_TYPE_ARM64) {
					scanArm64(view, start, end, hits);
				} else if (cputype === CPU_TYPE_X86_64) {
					scanX86_64(view, bytes, start, end, hits);
				}
			}
		}
	}

	return hits;
}

function findTextSection(segments: Segment64[]): Section64 | null {
	for (const seg of segments) {
		if (seg.segname.trim() !== "__TEXT") continue;
		for (const sect of seg.sections) {
			if (sect.sectname.trim() === "__text") return sect;
		}
	}
	return null;
}

function scanConstantSections(
	bytes: Uint8Array,
	segments: Segment64[],
	hits: SmallStringHit[]
): void {
	for (const seg of segments) {
		for (const sect of seg.sections) {
			const sectname = sect.sectname.trim();
			if (sectname !== "__const" && sectname !== "__data") continue;
			const size = Number(sect.size);
			if (size < SIZE) continue;
			const start = vmaddrToFileOffset(sect.addr, segments) ?? sect.offset;
			const end = Math.min(start + size, bytes.length);
			for (let off = start; off + SIZE <= end; off += 8) {
				const value = decodeSmallString64(bytes, off);
				if (value !== null) {
					hits.push({ value, offset: off, source: SMALL_STRING_SOURCE });
				}
			}
		}
	}
}

// ── ARM64 immediate scanner ──────────────────────────────────────────

const WIDE_MOVN = 1;
const WIDE_MOVZ = 2;
const WIDE_MOVK = 3;
const WIDE_MASK = 0x7f800000;

interface RegState {
	value: bigint;
	firstOff: number;
}

interface Word {
	value: bigint;
	firstOff: number;
	endOff: number;
}

function wideMoveKind(insn: number): number {
	switch (insn & WIDE_MASK) {
		case 0x12800000:
			return WIDE_MOVN;
		case 0x52800000:
			return WIDE_MOVZ;
		case 0x72800000:
			return WIDE_MOVK;
		default:
			return 0;
	}
}

function scanArm64(view: DataView, start: number, end: number, hits: SmallStringHit[]): void {
	const regs = new Map<number, RegState>();
	const scratch = new Uint8Array(SIZE);
	let prev: Word | null = null;

	for (let off = start; off + 4 <= end; off += 4) {
		const insn = view.getUint32(off, true);

		// BL, RET and unconditional B end the current basic block.
		if (
			(insn & 0xfc000000) === 0x94000000 ||
			insn === 0xd65f03c0 ||
			(insn & 0x7c000000) === 0x14000000
		) {
			regs.clear();
			prev = null;
			continue;
		}

		const kind = wideMoveKind(insn);
		if (kind === 0) continue;

		const rd = insn & 31;
		const hw = (insn >>> 21) & 3;
		const imm = (insn >>> 5) & 0xffff;
		const shift = hw * 16;
		const sf = (insn >>> 31) & 1;
		const widthMask = sf ? 0xffffffffffffffffn : 0xffffffffn;
		const shifted = (BigInt(imm) << BigInt(shift)) & widthMask;

		let state: RegState;
		if (kind === WIDE_MOVZ) {
			state = { value: shifted, firstOff: off };
		} else if (kind === WIDE_MOVN) {
			state = { value: ~shifted & widthMask, firstOff: off };
		} else {
			const existing = regs.get(rd);
			state = existing
				? {
						value: (existing.value & ~(0xffffn << BigInt(shift))) | shifted,
						firstOff: existing.firstOff
					}
				: { value: shifted, firstOff: off };
		}
		regs.set(rd, state);

		// Keep accumulating while the next instruction extends the same register.
		if (off + 8 <= end) {
			const next = view.getUint32(off + 4, true);
			if (wideMoveKind(next) !== 0 && (next & 31) === rd) continue;
		}

		regs.delete(rd);
		const word: Word = { value: state.value, firstOff: state.firstOff, endOff: off };
		if (prev && word.firstOff - prev.endOff <= 8) {
			const value = pairValue(prev.value, word.value, scratch);
			if (value !== null) {
				hits.push({
					value,
					offset: prev.firstOff,
					source: SMALL_STRING_CODE_SOURCE
				});
			}
		}
		prev = word;
	}
}

// ── x86_64 immediate scanner ─────────────────────────────────────────

const X86_PAIR_WINDOW = 16;

function scanX86_64(
	view: DataView,
	bytes: Uint8Array,
	start: number,
	end: number,
	hits: SmallStringHit[]
): void {
	const scratch = new Uint8Array(SIZE);
	let prev: Word | null = null;

	let off = start;
	while (off < end) {
		// 48 B8+rd imm64 — movabs r64, imm64
		if (off + 10 <= end && bytes[off] === 0x48 && (bytes[off + 1]! & 0xf8) === 0xb8) {
			const word: Word = {
				value: view.getBigUint64(off + 2, true),
				firstOff: off,
				endOff: off + 9
			};
			prev = emitX86Pair(prev, word, scratch, hits);
			off += 10;
			continue;
		}

		// B8+rd imm32 — mov r32, imm32 (zero-extends)
		if (off + 5 <= end && (bytes[off]! & 0xf8) === 0xb8) {
			const word: Word = {
				value: BigInt(view.getUint32(off + 1, true)),
				firstOff: off,
				endOff: off + 4
			};
			prev = emitX86Pair(prev, word, scratch, hits);
			off += 5;
			continue;
		}

		const b = bytes[off]!;
		let controlFlow = b === 0xe8 || b === 0xe9 || b === 0xc3 || b === 0xeb;
		if (b === 0xff && off + 1 < end) {
			const reg = (bytes[off + 1]! >>> 3) & 7;
			if (reg === 2 || reg === 4) {
				controlFlow = true;
				off += 2;
				prev = null;
				continue;
			}
		}
		if (controlFlow) prev = null;
		off++;
	}
}

function emitX86Pair(
	prev: Word | null,
	word: Word,
	scratch: Uint8Array,
	hits: SmallStringHit[]
): Word {
	if (prev && word.firstOff - prev.endOff <= X86_PAIR_WINDOW) {
		const value = pairValue(prev.value, word.value, scratch);
		if (value !== null) {
			hits.push({ value, offset: prev.firstOff, source: SMALL_STRING_CODE_SOURCE });
		}
	}
	return word;
}

// ── Pair validation ──────────────────────────────────────────────────

function writeWord(out: Uint8Array, offset: number, value: bigint): void {
	for (let i = 0; i < 8; i++) {
		out[offset + i] = Number((value >> BigInt(i * 8)) & 0xffn);
	}
}

/**
 * Try both word orders and accept the pair only when exactly one decodes as a
 * small string. Register allocation may materialise the tag half first.
 */
function pairValue(low: bigint, high: bigint, scratch: Uint8Array): string | null {
	writeWord(scratch, 0, low);
	writeWord(scratch, 8, high);
	const direct = decodeSmallString64(scratch, 0);

	writeWord(scratch, 0, high);
	writeWord(scratch, 8, low);
	const reversed = decodeSmallString64(scratch, 0);

	if (direct !== null && reversed !== null) return null;
	return direct ?? reversed;
}
