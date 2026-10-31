import { describe, expect, it } from "bun:test";
import { buildClassicBindMap } from "../classic-fixups";
import type { Segment64 } from "../load-commands";

// Bind opcodes (high nibble opcode | low nibble immediate).
const SET_DYLIB_ORDINAL_IMM = 0x10;
const SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40;
const SET_TYPE_IMM = 0x50;
const SET_SEGMENT_AND_OFFSET_ULEB = 0x70;
const DO_BIND = 0x90;
const DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xc0;
const DONE = 0x00;

function seg(fileoff: number): Segment64 {
	return {
		cmd: 0x19,
		cmdsize: 72,
		segname: "__DATA",
		vmaddr: BigInt(fileoff),
		vmsize: 0x1000n,
		fileoff: BigInt(fileoff),
		filesize: 0x1000n,
		maxprot: 7,
		initprot: 3,
		nsects: 0,
		flags: 0,
		sections: []
	};
}

/** Encode a symbol name as its trailing-flags opcode + null-terminated bytes. */
function symbol(name: string): number[] {
	return [SET_SYMBOL_TRAILING_FLAGS_IMM, ...[...name].map((c) => c.charCodeAt(0)), 0];
}

function bufferFrom(bytes: number[]): ArrayBuffer {
	return new Uint8Array(bytes).buffer;
}

describe("buildClassicBindMap", () => {
	it("binds a symbol at segment offset", () => {
		const bytes = [
			SET_DYLIB_ORDINAL_IMM | 1,
			...symbol("_OBJC_CLASS_$_UIView"),
			SET_TYPE_IMM | 1,
			SET_SEGMENT_AND_OFFSET_ULEB | 0,
			0x10, // ULEB offset
			DO_BIND,
			DONE
		];
		const map = buildClassicBindMap(
			bufferFrom(bytes),
			{
				bindOff: 0,
				bindSize: bytes.length,
				weakBindOff: 0,
				weakBindSize: 0,
				lazyBindOff: 0,
				lazyBindSize: 0
			},
			[seg(0x4000)],
			true
		);
		// fileOffset = segment.fileoff (0x4000) + segOffset (0x10)
		expect(map.get(0x4010)?.symbolName).toBe("_OBJC_CLASS_$_UIView");
	});

	it("advances by a pointer after each DO_BIND and handles the times/skip loop", () => {
		const bytes = [
			SET_DYLIB_ORDINAL_IMM | 1,
			...symbol("_sym"),
			SET_SEGMENT_AND_OFFSET_ULEB | 0,
			0x00,
			// Three binds, each pointer-sized (8) + skip 0 apart → 0x0, 0x8, 0x10
			DO_BIND_ULEB_TIMES_SKIPPING_ULEB,
			0x03, // count
			0x00, // skip
			DONE
		];
		const map = buildClassicBindMap(
			bufferFrom(bytes),
			{
				bindOff: 0,
				bindSize: bytes.length,
				weakBindOff: 0,
				weakBindSize: 0,
				lazyBindOff: 0,
				lazyBindSize: 0
			},
			[seg(0)],
			true
		);
		expect([...map.keys()].sort((a, b) => a - b)).toEqual([0x0, 0x8, 0x10]);
		expect(map.get(0x8)?.symbolName).toBe("_sym");
	});

	it("returns an empty map when there is no bind info", () => {
		expect(buildClassicBindMap(new ArrayBuffer(0), null, [], true).size).toBe(0);
	});
});
