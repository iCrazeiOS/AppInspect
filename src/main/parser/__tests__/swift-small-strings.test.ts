/**
 * Tests for Swift inline small-string extraction (swift-small-strings.ts).
 */

import { describe, expect, it } from "bun:test";
import type { Section64, Segment64 } from "../load-commands";
import { CPU_TYPE_ARM64, CPU_TYPE_X86_64 } from "../macho";
import { extractStrings } from "../strings";
import {
	decodeSmallString64,
	SMALL_STRING_CODE_SOURCE,
	SMALL_STRING_SOURCE,
	scanSwiftSmallStrings
} from "../swift-small-strings";

// ── Fixture Helpers ──────────────────────────────────────────────────

const BASE = 0x100000000n;

function makeSection(segname: string, sectname: string, offset: number, size: number): Section64 {
	return {
		sectname,
		segname,
		addr: BASE + BigInt(offset),
		size: BigInt(size),
		offset,
		align: 0,
		reloff: 0,
		nreloc: 0,
		flags: 0,
		reserved1: 0,
		reserved2: 0,
		reserved3: 0
	};
}

function makeSegment(
	segname: string,
	vmaddr: bigint,
	vmsize: bigint,
	fileoff: bigint,
	filesize: bigint,
	sections: Section64[] = []
): Segment64 {
	return {
		cmd: 0x19,
		cmdsize: 72 + sections.length * 80,
		segname,
		vmaddr,
		vmsize,
		fileoff,
		filesize,
		maxprot: 7,
		initprot: 5,
		nsects: sections.length,
		flags: 0,
		sections
	};
}

function textSegment(bufSize: number, sections: Section64[]): Segment64 {
	return makeSegment("__TEXT", BASE, BigInt(bufSize), 0n, BigInt(bufSize), sections);
}

function encodeSmallString(value: string): Uint8Array {
	const encoded = new TextEncoder().encode(value);
	const bytes = new Uint8Array(16);
	bytes.set(encoded);
	const ascii = encoded.every((b) => b < 0x80);
	bytes[15] = (ascii ? 0xe0 : 0xa0) | encoded.length;
	return bytes;
}

function wordFromBytes(bytes: Uint8Array): bigint {
	let value = 0n;
	for (let i = 0; i < 8; i++) {
		value |= BigInt(bytes[i] ?? 0) << BigInt(i * 8);
	}
	return value;
}

function wordsFor(value: string): [bigint, bigint] {
	const bytes = encodeSmallString(value);
	return [wordFromBytes(bytes.subarray(0, 8)), wordFromBytes(bytes.subarray(8, 16))];
}

function movz(rd: number, imm: number, shift = 0, sf = 1): number {
	return ((sf & 1) << 31) | 0x52800000 | ((shift / 16) << 21) | ((imm & 0xffff) << 5) | rd;
}

function movk(rd: number, imm: number, shift = 0, sf = 1): number {
	return ((sf & 1) << 31) | 0x72800000 | ((shift / 16) << 21) | ((imm & 0xffff) << 5) | rd;
}

function movn(rd: number, imm: number, shift = 0, sf = 1): number {
	return ((sf & 1) << 31) | 0x12800000 | ((shift / 16) << 21) | ((imm & 0xffff) << 5) | rd;
}

function materialize(rd: number, value: bigint): number[] {
	const insns: number[] = [];
	for (let lane = 0; lane < 4; lane++) {
		const imm = Number((value >> BigInt(lane * 16)) & 0xffffn);
		insns.push(lane === 0 ? movz(rd, imm, lane * 16) : movk(rd, imm, lane * 16));
	}
	return insns;
}

function buildArm64Fixture(
	insns: number[],
	extraBytes = 0
): { buf: ArrayBuffer; segments: Segment64[]; textOffset: number } {
	const textOffset = 64;
	const textSize = insns.length * 4;
	const bufSize = textOffset + textSize + extraBytes + 64;
	const buf = new ArrayBuffer(bufSize);
	const view = new DataView(buf);
	for (let i = 0; i < insns.length; i++) {
		view.setUint32(textOffset + i * 4, insns[i]! >>> 0, true);
	}
	const text = makeSection("__TEXT", "__text", textOffset, textSize);
	const segments = [textSegment(bufSize, [text])];
	return { buf, segments, textOffset };
}

function buildX86Fixture(write: (view: DataView, bytes: Uint8Array, offset: number) => number): {
	buf: ArrayBuffer;
	segments: Segment64[];
	textOffset: number;
	size: number;
} {
	const textOffset = 64;
	const bufSize = 512;
	const buf = new ArrayBuffer(bufSize);
	const view = new DataView(buf);
	const bytes = new Uint8Array(buf);
	const size = write(view, bytes, textOffset);
	const text = makeSection("__TEXT", "__text", textOffset, size);
	const segments = [textSegment(bufSize, [text])];
	return { buf, segments, textOffset, size };
}

function pushMovabs(view: DataView, bytes: Uint8Array, offset: number, reg: number, value: bigint) {
	bytes[offset] = 0x48;
	bytes[offset + 1] = 0xb8 + reg;
	view.setBigUint64(offset + 2, value, true);
	return offset + 10;
}

function pushMov32(view: DataView, bytes: Uint8Array, offset: number, reg: number, value: number) {
	bytes[offset] = 0xb8 + reg;
	view.setUint32(offset + 1, value, true);
	return offset + 5;
}

// ── Decoder ──────────────────────────────────────────────────────────

describe("decodeSmallString64", () => {
	it("decodes the verified values", () => {
		expect(decodeSmallString64(encodeSmallString("abcd"), 0)).toBe("abcd");
		expect(decodeSmallString64(encodeSmallString("syntheticName"), 0)).toBe("syntheticName");
	});

	it("decodes 1-byte and 15-byte values", () => {
		expect(decodeSmallString64(encodeSmallString(","), 0)).toBe(",");
		expect(decodeSmallString64(encodeSmallString("abcdefghijklmno"), 0)).toBe(
			"abcdefghijklmno"
		);
	});

	it("decodes non-ASCII values with the 0xA_ tag", () => {
		expect(decodeSmallString64(encodeSmallString("éàü"), 0)).toBe("éàü");
		expect(decodeSmallString64(encodeSmallString("ñø"), 0)).toBe("ñø");
	});

	it("rejects invalid values", () => {
		const noTag = new Uint8Array(16);
		noTag.set(new TextEncoder().encode("hello"));
		expect(decodeSmallString64(noTag, 0)).toBeNull();

		const empty = encodeSmallString("");
		expect(decodeSmallString64(empty, 0)).toBeNull();

		const tooLong = new Uint8Array(16);
		tooLong.set(new TextEncoder().encode("abcdefghijklmnop"));
		tooLong[15] = 0xf0;
		expect(decodeSmallString64(tooLong, 0)).toBeNull();

		const badPadding = encodeSmallString("abcd");
		badPadding[4] = 1;
		expect(decodeSmallString64(badPadding, 0)).toBeNull();

		const invalidUtf8 = new Uint8Array(16);
		invalidUtf8[0] = 0xff;
		invalidUtf8[15] = 0xe1;
		expect(decodeSmallString64(invalidUtf8, 0)).toBeNull();

		const embeddedNul = new Uint8Array(16);
		embeddedNul[0] = 0;
		embeddedNul[15] = 0xe1;
		expect(decodeSmallString64(embeddedNul, 0)).toBeNull();

		expect(decodeSmallString64(new Uint8Array(15), 0)).toBeNull();
	});
});

// ── Constant sections ────────────────────────────────────────────────

describe("scanSwiftSmallStrings constant sections", () => {
	it("scans __TEXT.__const", () => {
		const bufSize = 512;
		const buf = new ArrayBuffer(bufSize);
		new Uint8Array(buf).set(encodeSmallString("synthValue"), 64);
		const sect = makeSection("__TEXT", "__const", 64, 64);
		const segments = [textSegment(bufSize, [sect])];

		const hits = scanSwiftSmallStrings(buf, segments, CPU_TYPE_ARM64, true, false);
		expect(hits).toHaveLength(1);
		expect(hits[0]!.value).toBe("synthValue");
		expect(hits[0]!.offset).toBe(64);
		expect(hits[0]!.source).toBe(SMALL_STRING_SOURCE);
	});

	it("scans __DATA_CONST.__const and __DATA.__data but not string sections", () => {
		const bufSize = 1024;
		const buf = new ArrayBuffer(bufSize);
		const bytes = new Uint8Array(buf);
		bytes.set(encodeSmallString("dataValue"), 64);
		bytes.set(encodeSmallString("anotherItem"), 128);
		bytes.set(encodeSmallString("skipThis"), 192);
		bytes.set(encodeSmallString("skipThat"), 256);

		const dataConst = makeSection("__DATA_CONST", "__const", 64, 64);
		const data = makeSection("__DATA", "__data", 128, 64);
		const cstring = makeSection("__TEXT", "__cstring", 192, 64);
		const reflstr = makeSection("__TEXT", "__swift5_reflstr", 256, 64);
		const segments = [
			textSegment(bufSize, [cstring, reflstr]),
			makeSegment("__DATA_CONST", BASE + 64n, 64n, 64n, 64n, [dataConst]),
			makeSegment("__DATA", BASE + 128n, 64n, 128n, 64n, [data])
		];

		const values = scanSwiftSmallStrings(buf, segments, CPU_TYPE_ARM64, true, false).map(
			(h) => h.value
		);
		expect(values).toContain("dataValue");
		expect(values).toContain("anotherItem");
		expect(values).not.toContain("skipThis");
		expect(values).not.toContain("skipThat");
	});

	it("resolves a stale section offset through the segment vmaddr", () => {
		const bufSize = 512;
		const buf = new ArrayBuffer(bufSize);
		new Uint8Array(buf).set(encodeSmallString("constVal"), 64);
		const sect: Section64 = {
			...makeSection("__TEXT", "__const", 64, 64),
			offset: bufSize + 5_000_000
		};
		const segments = [textSegment(bufSize, [sect])];

		const values = scanSwiftSmallStrings(buf, segments, CPU_TYPE_ARM64, true, false).map(
			(h) => h.value
		);
		expect(values).toContain("constVal");
	});

	it("returns nothing for 32-bit slices", () => {
		const bufSize = 512;
		const buf = new ArrayBuffer(bufSize);
		new Uint8Array(buf).set(encodeSmallString("nope"), 64);
		const sect = makeSection("__TEXT", "__const", 64, 64);
		const segments = [textSegment(bufSize, [sect])];

		expect(scanSwiftSmallStrings(buf, segments, CPU_TYPE_ARM64, false, true)).toHaveLength(0);
	});
});

// ── ARM64 code ───────────────────────────────────────────────────────

describe("scanSwiftSmallStrings ARM64", () => {
	it("decodes a 4-byte value assembled from w-register moves", () => {
		const insns = [movz(0, 0x6261, 0, 0), movk(0, 0x6463, 16, 0), movz(1, 0xe400, 48, 1)];
		const { buf, segments, textOffset } = buildArm64Fixture(insns);

		const hits = scanSwiftSmallStrings(buf, segments, CPU_TYPE_ARM64, true, true);
		expect(hits).toHaveLength(1);
		expect(hits[0]!.value).toBe("abcd");
		expect(hits[0]!.offset).toBe(textOffset);
		expect(hits[0]!.source).toBe(SMALL_STRING_CODE_SOURCE);
	});

	it("decodes a 13-byte value assembled from MOVZ/MOVK chains", () => {
		const [low, high] = wordsFor("syntheticName");
		const insns = [...materialize(0, low), ...materialize(1, high)];
		const { buf, segments } = buildArm64Fixture(insns);

		const hits = scanSwiftSmallStrings(buf, segments, CPU_TYPE_ARM64, true, true);
		expect(hits).toHaveLength(1);
		expect(hits[0]!.value).toBe("syntheticName");
	});

	it("does not pair across a BL", () => {
		const [low, high] = wordsFor("syntheticName");
		const insns = [...materialize(0, low), 0x94000000, ...materialize(1, high)];
		const { buf, segments } = buildArm64Fixture(insns);

		expect(scanSwiftSmallStrings(buf, segments, CPU_TYPE_ARM64, true, true)).toHaveLength(0);
	});

	it("rejects pairs with nonzero padding or bad UTF-8", () => {
		const padded = encodeSmallString("abcd");
		padded[5] = 1;
		const badLow = wordFromBytes(padded.subarray(0, 8));
		const badHigh = wordFromBytes(padded.subarray(8, 16));

		const paddedFixture = buildArm64Fixture([
			...materialize(0, badLow),
			...materialize(1, badHigh)
		]);
		expect(
			scanSwiftSmallStrings(
				paddedFixture.buf,
				paddedFixture.segments,
				CPU_TYPE_ARM64,
				true,
				true
			)
		).toHaveLength(0);

		const invalid = new Uint8Array(16);
		invalid[0] = 0xff;
		invalid[15] = 0xe1;
		const badUtf8Fixture = buildArm64Fixture([
			...materialize(0, wordFromBytes(invalid.subarray(0, 8))),
			...materialize(1, wordFromBytes(invalid.subarray(8, 16)))
		]);
		expect(
			scanSwiftSmallStrings(
				badUtf8Fixture.buf,
				badUtf8Fixture.segments,
				CPU_TYPE_ARM64,
				true,
				true
			)
		).toHaveLength(0);
	});

	it("does not emit a lone tag half", () => {
		const [, high] = wordsFor("abcd");
		const { buf, segments } = buildArm64Fixture(materialize(0, high));

		expect(scanSwiftSmallStrings(buf, segments, CPU_TYPE_ARM64, true, true)).toHaveLength(0);
	});

	it("decodes a non-ASCII sequence", () => {
		const [low, high] = wordsFor("éàü");
		const { buf, segments } = buildArm64Fixture([
			...materialize(0, low),
			...materialize(1, high)
		]);

		const hits = scanSwiftSmallStrings(buf, segments, CPU_TYPE_ARM64, true, true);
		expect(hits).toHaveLength(1);
		expect(hits[0]!.value).toBe("éàü");
	});

	it("accepts a tag half materialised first", () => {
		const [low, high] = wordsFor("abcd");
		const { buf, segments } = buildArm64Fixture([
			...materialize(0, high),
			...materialize(1, low)
		]);

		const hits = scanSwiftSmallStrings(buf, segments, CPU_TYPE_ARM64, true, true);
		expect(hits).toHaveLength(1);
		expect(hits[0]!.value).toBe("abcd");
	});

	it("understand MOVN (sanity check for opcode decoding)", () => {
		// A MOVN with all-zero immediate yields all ones; it must not decode as text.
		const { buf, segments } = buildArm64Fixture([movn(0, 0), movn(1, 0)]);
		expect(scanSwiftSmallStrings(buf, segments, CPU_TYPE_ARM64, true, true)).toHaveLength(0);
	});
});

// ── x86_64 code ──────────────────────────────────────────────────────

describe("scanSwiftSmallStrings x86_64", () => {
	it("pairs two movabs instructions", () => {
		const [low, high] = wordsFor("abcd");
		const { buf, segments, textOffset } = buildX86Fixture((view, bytes, offset) => {
			offset = pushMovabs(view, bytes, offset, 0, low);
			return pushMovabs(view, bytes, offset, 1, high);
		});

		const hits = scanSwiftSmallStrings(buf, segments, CPU_TYPE_X86_64, true, true);
		expect(hits).toHaveLength(1);
		expect(hits[0]!.value).toBe("abcd");
		expect(hits[0]!.offset).toBe(textOffset);
		expect(hits[0]!.source).toBe(SMALL_STRING_CODE_SOURCE);
	});

	it("pairs a mov imm32 with a movabs", () => {
		const [low, high] = wordsFor("abcd");
		const { buf, segments } = buildX86Fixture((view, bytes, offset) => {
			offset = pushMov32(view, bytes, offset, 0, Number(low & 0xffffffffn));
			return pushMovabs(view, bytes, offset, 1, high);
		});

		const hits = scanSwiftSmallStrings(buf, segments, CPU_TYPE_X86_64, true, true);
		expect(hits).toHaveLength(1);
		expect(hits[0]!.value).toBe("abcd");
	});

	it("does not pair across control flow", () => {
		const [low, high] = wordsFor("abcd");
		const { buf, segments } = buildX86Fixture((view, bytes, offset) => {
			offset = pushMovabs(view, bytes, offset, 0, low);
			bytes[offset++] = 0xc3;
			return pushMovabs(view, bytes, offset, 1, high);
		});

		expect(scanSwiftSmallStrings(buf, segments, CPU_TYPE_X86_64, true, true)).toHaveLength(0);
	});
});

// ── Integration with extractStrings ──────────────────────────────────

describe("extractStrings with Swift small strings", () => {
	it("adds small strings without disturbing C strings", () => {
		const bufSize = 1024;
		const buf = new ArrayBuffer(bufSize);
		const bytes = new Uint8Array(buf);
		const encoder = new TextEncoder();
		encoder.encodeInto("cstringValue", bytes.subarray(64));
		bytes[64 + "cstringValue".length] = 0;
		bytes.set(encodeSmallString("inlineValue"), 128);

		const cstring = makeSection("__TEXT", "__cstring", 64, 32);
		const constSection = makeSection("__TEXT", "__const", 128, 32);
		const segments = [textSegment(bufSize, [cstring, constSection])];

		const entries = extractStrings(buf, [cstring, constSection], segments, new Map(), true);
		const byValue = new Map(entries.map((e) => [e.value, e]));

		expect(byValue.get("cstringValue")?.sources).toEqual(["__cstring"]);
		expect(byValue.get("inlineValue")?.sources).toEqual([SMALL_STRING_SOURCE]);
	});

	it("deduplicates a value found in __cstring and __const", () => {
		const bufSize = 1024;
		const buf = new ArrayBuffer(bufSize);
		const bytes = new Uint8Array(buf);
		const encoder = new TextEncoder();
		encoder.encodeInto("sharedValue", bytes.subarray(64));
		bytes[64 + "sharedValue".length] = 0;
		bytes.set(encodeSmallString("sharedValue"), 128);

		const cstring = makeSection("__TEXT", "__cstring", 64, 32);
		const constSection = makeSection("__TEXT", "__const", 128, 32);
		const segments = [textSegment(bufSize, [cstring, constSection])];

		const entries = extractStrings(buf, [cstring, constSection], segments, new Map(), true);
		const matches = entries.filter((e) => e.value === "sharedValue");

		expect(matches).toHaveLength(1);
		expect(matches[0]!.offset).toBe(64);
		expect(matches[0]!.sources).toContain("__cstring");
		expect(matches[0]!.sources).toContain(SMALL_STRING_SOURCE);
	});

	it("skips small strings for 32-bit files and encrypted images", () => {
		const bufSize = 512;
		const buf = new ArrayBuffer(bufSize);
		new Uint8Array(buf).set(encodeSmallString("hidden"), 64);
		const constSection = makeSection("__TEXT", "__const", 64, 32);
		const segments = [textSegment(bufSize, [constSection])];

		const thirtyTwo = extractStrings(buf, [constSection], segments, new Map(), true, false, {
			cputype: CPU_TYPE_ARM64
		});
		expect(thirtyTwo.map((e) => e.value)).not.toContain("hidden");

		const encrypted = extractStrings(buf, [constSection], segments, new Map(), true, true, {
			cputype: CPU_TYPE_ARM64,
			skipSmallStrings: true
		});
		expect(encrypted.map((e) => e.value)).not.toContain("hidden");
	});
});
