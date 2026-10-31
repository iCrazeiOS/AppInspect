/**
 * Classic dyld bind opcodes (LC_DYLD_INFO / LC_DYLD_INFO_ONLY).
 *
 * Binaries that predate chained fixups (older toolchains, and the non-arm64e slice of
 * many dual-arch tweaks) describe their external pointer fixups with a bytecode stream
 * instead of the chain walked in `chained-fixups.ts`. External pointers — an ObjC class's
 * imported superclass (`_OBJC_CLASS_$_UIView`), a category's external target, imported
 * functions — sit at zero in the file and are filled by these binds at load.
 *
 * This interpreter replays the bind / weak-bind / lazy-bind streams and records, per bound
 * file offset, the symbol bound there, producing the same bind map the chained-fixups path
 * yields so the ObjC parser can resolve the same references either way. Internal pointers
 * need no bind: a classic image stores their preferred vmaddr inline, which the readers in
 * `objc.ts` already pick up.
 */

import type { Segment64 } from "./load-commands";

export interface ClassicBindInfo {
	bindOff: number;
	bindSize: number;
	weakBindOff: number;
	weakBindSize: number;
	lazyBindOff: number;
	lazyBindSize: number;
}

export interface BindEntry {
	ordinal: number;
	symbolName: string;
	addend: bigint;
}

// Bind opcodes: high nibble is the opcode, low nibble an immediate operand.
const BIND_OPCODE_MASK = 0xf0;
const BIND_IMMEDIATE_MASK = 0x0f;
const BIND_OPCODE_DONE = 0x00;
const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10;
const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20;
const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 0x30;
const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40;
const BIND_OPCODE_SET_TYPE_IMM = 0x50;
const BIND_OPCODE_SET_ADDEND_SLEB = 0x60;
const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x70;
const BIND_OPCODE_ADD_ADDR_ULEB = 0x80;
const BIND_OPCODE_DO_BIND = 0x90;
const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xa0;
const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xb0;
const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xc0;

/** 64-bit wraparound mask: dyld address arithmetic is modulo 2^64. */
const MASK64 = (1n << 64n) - 1n;

/** Read an unsigned LEB128 at `offset` as a BigInt, returning the value and the end offset. */
function readULEB(view: DataView, offset: number, end: number): { value: bigint; next: number } {
	let value = 0n;
	let shift = 0n;
	let i = offset;
	while (i < end) {
		const byte = view.getUint8(i);
		i++;
		value |= BigInt(byte & 0x7f) << shift;
		if ((byte & 0x80) === 0) break;
		shift += 7n;
	}
	return { value, next: i };
}

/** Read a signed LEB128 at `offset`, returning the value and the end offset. */
function readSLEB(view: DataView, offset: number, end: number): { value: bigint; next: number } {
	let value = 0n;
	let shift = 0n;
	let i = offset;
	let byte = 0;
	do {
		if (i >= end) break;
		byte = view.getUint8(i);
		i++;
		value |= BigInt(byte & 0x7f) << shift;
		shift += 7n;
	} while ((byte & 0x80) !== 0);
	// Sign-extend if the sign bit of the last byte is set.
	if ((byte & 0x40) !== 0) value |= -1n << shift;
	return { value, next: i };
}

/**
 * Replay a single bind opcode stream, recording each bound file offset → symbol.
 * `pointerSize` advances the cursor after a bind (8 for 64-bit, 4 for 32-bit).
 */
function runBindStream(
	view: DataView,
	start: number,
	size: number,
	segments: Segment64[],
	pointerSize: number,
	out: Map<number, BindEntry>
): void {
	const end = Math.min(start + size, view.byteLength);
	const ptr = BigInt(pointerSize);
	let i = start;

	let segIndex = 0;
	let segOffset = 0n; // offset within the segment, tracked mod 2^64 like dyld
	let symbolName = "";
	let ordinal = 0;
	let addend = 0n;

	const record = (): void => {
		const seg = segments[segIndex];
		if (!seg || !symbolName) return;
		const fileOffset = Number((BigInt(seg.fileoff) + segOffset) & MASK64);
		out.set(fileOffset, { ordinal, symbolName, addend });
	};

	while (i < end) {
		const byte = view.getUint8(i);
		i++;
		const opcode = byte & BIND_OPCODE_MASK;
		const immediate = byte & BIND_IMMEDIATE_MASK;

		switch (opcode) {
			case BIND_OPCODE_DONE:
				// Ends the regular/weak stream; in the lazy stream it just ends one entry.
				break;
			case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
				ordinal = immediate;
				break;
			case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: {
				const r = readULEB(view, i, end);
				ordinal = Number(r.value);
				i = r.next;
				break;
			}
			case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
				// Special ordinals (self/main/flat-lookup) are encoded as small negatives.
				ordinal = immediate === 0 ? 0 : (0xf0 | immediate) - 0x100;
				break;
			case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
				let s = "";
				while (i < end) {
					const c = view.getUint8(i);
					i++;
					if (c === 0) break;
					s += String.fromCharCode(c);
				}
				symbolName = s;
				break;
			}
			case BIND_OPCODE_SET_TYPE_IMM:
				break;
			case BIND_OPCODE_SET_ADDEND_SLEB: {
				const r = readSLEB(view, i, end);
				addend = r.value;
				i = r.next;
				break;
			}
			case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: {
				segIndex = immediate;
				const r = readULEB(view, i, end);
				segOffset = r.value & MASK64;
				i = r.next;
				break;
			}
			case BIND_OPCODE_ADD_ADDR_ULEB: {
				const r = readULEB(view, i, end);
				segOffset = (segOffset + r.value) & MASK64;
				i = r.next;
				break;
			}
			case BIND_OPCODE_DO_BIND:
				record();
				segOffset = (segOffset + ptr) & MASK64;
				break;
			case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: {
				record();
				const r = readULEB(view, i, end);
				segOffset = (segOffset + ptr + r.value) & MASK64;
				i = r.next;
				break;
			}
			case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
				record();
				segOffset = (segOffset + ptr + BigInt(immediate) * ptr) & MASK64;
				break;
			case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
				const countR = readULEB(view, i, end);
				i = countR.next;
				const skipR = readULEB(view, i, end);
				i = skipR.next;
				const count = Number(countR.value);
				for (let n = 0; n < count; n++) {
					record();
					segOffset = (segOffset + ptr + skipR.value) & MASK64;
				}
				break;
			}
			default:
				// Unknown opcode: stop rather than risk desynchronised reads.
				return;
		}
	}
}

/**
 * Build the bind map from the classic bind / weak-bind / lazy-bind streams. Returns an
 * empty map when there is no bind info. The map is keyed by file offset, matching the
 * chained-fixups bind map so either fixup scheme feeds the same consumers.
 */
export function buildClassicBindMap(
	buffer: ArrayBuffer,
	bindInfo: ClassicBindInfo | null,
	segments: Segment64[],
	is64Bit = true
): Map<number, BindEntry> {
	const out = new Map<number, BindEntry>();
	if (!bindInfo) return out;

	const view = new DataView(buffer);
	const pointerSize = is64Bit ? 8 : 4;

	const streams: Array<[number, number]> = [
		[bindInfo.bindOff, bindInfo.bindSize],
		[bindInfo.weakBindOff, bindInfo.weakBindSize],
		[bindInfo.lazyBindOff, bindInfo.lazyBindSize]
	];
	for (const [off, size] of streams) {
		if (size > 0) runBindStream(view, off, size, segments, pointerSize, out);
	}

	return out;
}
