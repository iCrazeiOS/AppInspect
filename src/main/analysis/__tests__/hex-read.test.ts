import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { AnalysisSession, formatHexdump } from "../orchestrator";

const TMP_DIR = path.join(import.meta.dir, ".tmp-hex-test");
const TEST_FILE = path.join(TMP_DIR, "test.bin");
const BIG_FILE = path.join(TMP_DIR, "big.bin");

/** Size chosen to sit above the 64 KiB read cap by a wide margin. */
const BIG_FILE_SIZE = 100_000;

// Known bytes for the test file — a valid-ish Mach-O header followed by recognizable data
const TEST_BYTES = new Uint8Array(512);

// Fill with a recognizable pattern
for (let i = 0; i < TEST_BYTES.length; i++) {
	TEST_BYTES[i] = i & 0xff;
}

// Write a minimal Mach-O 64 header (little-endian ARM64 executable)
const view = new DataView(TEST_BYTES.buffer);
view.setUint32(0, 0xfeedfacf, true); // MH_MAGIC_64
view.setUint32(4, 0x0100000c, true); // CPU_TYPE_ARM64
view.setUint32(8, 0x00000000, true); // cpusubtype
view.setUint32(12, 0x00000002, true); // MH_EXECUTE
view.setUint32(16, 0, true); // ncmds = 0
view.setUint32(20, 0, true); // sizeofcmds = 0
view.setUint32(24, 0x00200000, true); // MH_PIE
view.setUint32(28, 0, true); // reserved

// Also embed a known text pattern for search testing
const textPattern = "HELLO_HEX";
for (let i = 0; i < textPattern.length; i++) {
	TEST_BYTES[256 + i] = textPattern.charCodeAt(i);
}

let session: AnalysisSession;

beforeAll(async () => {
	mkdirSync(TMP_DIR, { recursive: true });
	writeFileSync(TEST_FILE, TEST_BYTES);
	writeFileSync(BIG_FILE, new Uint8Array(BIG_FILE_SIZE));

	// analyseMachO sets filePath and binaries even if parsing is minimal
	session = new AnalysisSession();
	await session.analyseMachO(TEST_FILE, () => {});
});

afterAll(() => {
	rmSync(TMP_DIR, { recursive: true, force: true });
});

describe("AnalysisSession.readHex", () => {
	it("reads bytes at offset 0", () => {
		const result = session.readHex(0, 16);
		expect(result).not.toBeNull();
		expect(result!.offset).toBe(0);
		expect(result!.length).toBe(16);
		expect(result!.data.length).toBe(16);
		// First 4 bytes should be MH_MAGIC_64 in little-endian
		expect(result!.data[0]).toBe(0xcf);
		expect(result!.data[1]).toBe(0xfa);
		expect(result!.data[2]).toBe(0xed);
		expect(result!.data[3]).toBe(0xfe);
	});

	it("reads bytes at a specific offset", () => {
		const result = session.readHex(256, 9);
		expect(result).not.toBeNull();
		expect(result!.offset).toBe(256);
		expect(result!.length).toBe(9);
		// Should read the "HELLO_HEX" text pattern
		const text = String.fromCharCode(...result!.data);
		expect(text).toBe("HELLO_HEX");
	});

	it("returns empty data for offset beyond file size", () => {
		const result = session.readHex(100000, 16);
		expect(result).not.toBeNull();
		expect(result!.length).toBe(0);
		expect(result!.data).toEqual([]);
	});

	it("returns fileSize", () => {
		const result = session.readHex(0, 1);
		expect(result).not.toBeNull();
		expect(result!.fileSize).toBe(512);
	});
});

describe("AnalysisSession.readHex length clamping", () => {
	let bigSession: AnalysisSession;

	beforeAll(async () => {
		bigSession = new AnalysisSession();
		await bigSession.analyseMachO(BIG_FILE, () => {});
	});

	// The cap is a DoS guard: without it a single IPC call could ask for and
	// materialise an arbitrary number of bytes. Assert the exact clamped length
	// against a file larger than the cap so the file-size limit cannot mask it.
	it("clamps a read to the 65536-byte cap on a file larger than the cap", () => {
		const result = bigSession.readHex(0, 100000);
		expect(result).not.toBeNull();
		expect(result!.length).toBe(65536);
		expect(result!.data).toHaveLength(65536);
		expect(result!.fileSize).toBe(BIG_FILE_SIZE);
	});

	it("reads the whole file when the request is under the cap", () => {
		const result = bigSession.readHex(0, 1024);
		expect(result!.length).toBe(1024);
	});

	it("clamps a negative length to zero instead of throwing", () => {
		const result = bigSession.readHex(0, -100);
		expect(result).not.toBeNull();
		expect(result!.length).toBe(0);
		expect(result!.data).toEqual([]);
	});
});

describe("AnalysisSession.resolveBinary", () => {
	it("resolves the active binary without recomputing", async () => {
		const { result, path: binPath } = await session.resolveBinary(0);
		expect(session.getResult()).toBe(result);
		expect(binPath).toBe(TEST_FILE);
	});

	it("reads hex from a specific binary index", async () => {
		const result = await session.readHexForBinary(0, 0, 4);
		expect(result).not.toBeNull();
		expect(result!.data).toEqual([0xcf, 0xfa, 0xed, 0xfe]);
	});

	it("throws for an out-of-range binary index", async () => {
		await expect(session.resolveBinary(5)).rejects.toThrow("out of range");
	});
});

describe("AnalysisSession.searchHex", () => {
	it("finds a known byte pattern", () => {
		// Search for MH_MAGIC_64 bytes: CF FA ED FE
		const result = session.searchHex(0, 512, [0xcf, 0xfa, 0xed, 0xfe]);
		expect(result).not.toBeNull();
		expect(result!.matches.length).toBeGreaterThanOrEqual(1);
		expect(result!.matches).toContain(0);
	});

	it("finds text pattern as bytes", () => {
		const pattern = Array.from(new TextEncoder().encode("HELLO_HEX"));
		const result = session.searchHex(0, 512, pattern);
		expect(result).not.toBeNull();
		expect(result!.matches.length).toBe(1);
		expect(result!.matches[0]).toBe(256);
	});

	it("returns empty matches for non-existent pattern", () => {
		const result = session.searchHex(0, 512, [0xde, 0xad, 0xbe, 0xef]);
		expect(result).not.toBeNull();
		expect(result!.matches).toEqual([]);
	});

	it("returns null for empty pattern", () => {
		const result = session.searchHex(0, 512, []);
		expect(result).toBeNull();
	});

	it("respects region bounds", () => {
		// Search only in first 32 bytes — should not find "HELLO_HEX" at offset 256
		const pattern = Array.from(new TextEncoder().encode("HELLO_HEX"));
		const result = session.searchHex(0, 32, pattern);
		expect(result).not.toBeNull();
		expect(result!.matches).toEqual([]);
	});
});

describe("formatHexdump", () => {
	it("formats a full 16-byte row", () => {
		const data = [
			0x48, 0x45, 0x4c, 0x4c, 0x4f, 0x5f, 0x48, 0x45, 0x58, 0x00, 0x01, 0x02, 0xff, 0x7e,
			0x20, 0x7f
		];
		const result = formatHexdump(data, 0x100);
		expect(result).toBe(
			"00000100  48 45 4C 4C 4F 5F 48 45  58 00 01 02 FF 7E 20 7F  |HELLO_HEX....~ .|"
		);
	});

	it("pads a partial last row", () => {
		const data = [0x41, 0x42, 0x43];
		const result = formatHexdump(data, 0);
		// 3 bytes + 13 empty slots
		expect(result).toBe("00000000  41 42 43                                          |ABC|");
	});

	it("formats multiple rows", () => {
		const data = new Array(32).fill(0).map((_, i) => i);
		const lines = formatHexdump(data, 0).split("\n");
		expect(lines.length).toBe(2);
		expect(lines[0]!.startsWith("00000000")).toBe(true);
		expect(lines[1]!.startsWith("00000010")).toBe(true);
	});

	it("replaces non-printable bytes with dots in ASCII column", () => {
		const data = [0x00, 0x1f, 0x20, 0x7e, 0x7f, 0x80, 0xff];
		const result = formatHexdump(data, 0);
		// 0x00=. 0x1f=. 0x20=space 0x7e=~ 0x7f=. 0x80=. 0xff=.
		expect(result).toContain("|.. ~...|");
	});

	it("returns empty string for empty data", () => {
		expect(formatHexdump([], 0)).toBe("");
	});
});

describe("AnalysisSession.searchHexForBinary", () => {
	const pattern = Array.from(new TextEncoder().encode("HELLO_HEX"));

	it("finds a pattern and reports the effective region", async () => {
		const r = await session.searchHexForBinary(0, 0, undefined, pattern);
		expect(r?.matches).toEqual([256]);
		expect(r?.regionSize).toBe(512);
	});

	it("clamps an oversized region and handles an offset past the end", async () => {
		expect((await session.searchHexForBinary(0, 0, 1e9, pattern))?.regionSize).toBe(512);
		const past = await session.searchHexForBinary(0, 10_000, 100, pattern);
		expect(past?.matches).toEqual([]);
		expect(past?.regionSize).toBe(0);
	});

	it("supports case-insensitive matching", async () => {
		const lower = Array.from(new TextEncoder().encode("hello_hex"));
		expect((await session.searchHexForBinary(0, 0, undefined, lower))?.matches).toEqual([]);
		expect((await session.searchHexForBinary(0, 0, undefined, lower, true))?.matches).toEqual([
			256
		]);
	});
});
