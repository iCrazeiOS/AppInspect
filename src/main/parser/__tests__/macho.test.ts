import { describe, expect, it } from "bun:test";
import {
	CPU_TYPE_ARM,
	CPU_TYPE_ARM64,
	CPU_TYPE_X86_64,
	FAT_MAGIC,
	MH_CIGAM_64,
	MH_DYLIB,
	MH_EXECUTE,
	MH_MAGIC,
	MH_MAGIC_64,
	MH_PIE,
	parseFatHeader,
	parseMachOHeader
} from "../macho";
import {
	ARM64_EXEC_HEADER,
	BE_ARM64_HEADER,
	buildFatHeader,
	buildMachHeader32,
	buildMachHeader64,
	FAT_DUAL_ARCH,
	X86_64_DYLIB_HEADER
} from "./fixtures";

// ── Fat binary detection ───────────────────────────────────────────────

describe("parseFatHeader", () => {
	it("should detect a fat binary and return arch entries", () => {
		const result = parseFatHeader(FAT_DUAL_ARCH);
		expect(result.ok).toBe(true);
		if (!result.ok) return;

		expect(result.data).toHaveLength(2);

		expect(result.data[0]!.cputype).toBe(CPU_TYPE_ARM64);
		expect(result.data[0]!.cpusubtype).toBe(0);
		expect(result.data[0]!.offset).toBe(16384);
		expect(result.data[0]!.size).toBe(50000);
		expect(result.data[0]!.align).toBe(14);

		expect(result.data[1]!.cputype).toBe(CPU_TYPE_X86_64);
		expect(result.data[1]!.cpusubtype).toBe(3);
		expect(result.data[1]!.offset).toBe(70000);
		expect(result.data[1]!.size).toBe(45000);
		expect(result.data[1]!.align).toBe(14);
	});

	it("should return single slice for non-fat Mach-O", () => {
		const result = parseFatHeader(ARM64_EXEC_HEADER);
		expect(result.ok).toBe(true);
		if (!result.ok) return;

		expect(result.data).toHaveLength(1);
		expect(result.data[0]!.offset).toBe(0);
		expect(result.data[0]!.size).toBe(32);
		expect(result.data[0]!.cputype).toBe(0);
	});

	it("should handle fat header with single arch", () => {
		const buf = buildFatHeader([
			{ cputype: CPU_TYPE_ARM64, cpusubtype: 2, offset: 4096, size: 10000, align: 12 }
		]);
		const result = parseFatHeader(buf);
		expect(result.ok).toBe(true);
		if (!result.ok) return;

		expect(result.data).toHaveLength(1);
		expect(result.data[0]!.cputype).toBe(CPU_TYPE_ARM64);
		expect(result.data[0]!.offset).toBe(4096);
	});

	it("should error on buffer too small for magic", () => {
		const buf = new ArrayBuffer(2);
		const result = parseFatHeader(buf);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error).toContain("too small");
	});

	it("should error on buffer too small for fat_arch entries", () => {
		// Build a fat header claiming 5 arches but only provide space for header
		const buf = new ArrayBuffer(8);
		const view = new DataView(buf);
		view.setUint32(0, FAT_MAGIC, false);
		view.setUint32(4, 5, false); // claims 5 arches
		const result = parseFatHeader(buf);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error).toContain("too small");
	});
});

// ── Mach-O header parsing ──────────────────────────────────────────────

describe("parseMachOHeader", () => {
	it("should parse a little-endian ARM64 executable header", () => {
		const result = parseMachOHeader(ARM64_EXEC_HEADER, 0);
		expect(result.ok).toBe(true);
		if (!result.ok) return;

		const { header, offset, littleEndian } = result.data;
		expect(littleEndian).toBe(true);
		expect(offset).toBe(0);
		expect(header.magic).toBe(MH_MAGIC_64);
		expect(header.cputype).toBe(CPU_TYPE_ARM64);
		expect(header.cpusubtype).toBe(0);
		expect(header.filetype).toBe(MH_EXECUTE);
		expect(header.ncmds).toBe(15);
		expect(header.sizeofcmds).toBe(1200);
		expect(header.flags).toBe(MH_PIE);
		expect(header.reserved).toBe(0);
	});

	it("should parse a little-endian x86_64 dylib header", () => {
		const result = parseMachOHeader(X86_64_DYLIB_HEADER, 0);
		expect(result.ok).toBe(true);
		if (!result.ok) return;

		const { header, littleEndian } = result.data;
		expect(littleEndian).toBe(true);
		expect(header.cputype).toBe(CPU_TYPE_X86_64);
		expect(header.filetype).toBe(MH_DYLIB);
		expect(header.ncmds).toBe(22);
		expect(header.sizeofcmds).toBe(2048);
		expect(header.flags).toBe(0x00000085);
	});

	it("should parse a big-endian header", () => {
		const result = parseMachOHeader(BE_ARM64_HEADER, 0);
		expect(result.ok).toBe(true);
		if (!result.ok) return;

		const { header, littleEndian } = result.data;
		expect(littleEndian).toBe(false);
		expect(header.magic).toBe(MH_MAGIC_64);
		expect(header.cputype).toBe(CPU_TYPE_ARM64);
		expect(header.filetype).toBe(MH_EXECUTE);
		expect(header.ncmds).toBe(10);
		expect(header.sizeofcmds).toBe(800);
		expect(header.flags).toBe(MH_PIE);
	});

	it("should handle header at non-zero offset", () => {
		// Pad 64 bytes before the header
		const padding = 64;
		const headerBuf = ARM64_EXEC_HEADER;
		const combined = new ArrayBuffer(padding + headerBuf.byteLength);
		new Uint8Array(combined).set(new Uint8Array(headerBuf), padding);

		const result = parseMachOHeader(combined, padding);
		expect(result.ok).toBe(true);
		if (!result.ok) return;

		expect(result.data.offset).toBe(padding);
		expect(result.data.header.magic).toBe(MH_MAGIC_64);
		expect(result.data.header.cputype).toBe(CPU_TYPE_ARM64);
	});

	it("should parse 32-bit Mach-O (little-endian)", () => {
		const buf = buildMachHeader32(true);
		const result = parseMachOHeader(buf, 0);
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.data.header.magic).toBe(MH_MAGIC);
		expect(result.data.header.cputype).toBe(CPU_TYPE_ARM);
		expect(result.data.header.filetype).toBe(MH_EXECUTE);
		expect(result.data.littleEndian).toBe(true);
		expect(result.data.is64Bit).toBe(false);
	});

	it("should parse 32-bit Mach-O (big-endian)", () => {
		const buf = buildMachHeader32(false);
		const result = parseMachOHeader(buf, 0);
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.data.header.magic).toBe(MH_MAGIC);
		expect(result.data.header.cputype).toBe(CPU_TYPE_ARM);
		expect(result.data.header.filetype).toBe(MH_EXECUTE);
		expect(result.data.littleEndian).toBe(false);
		expect(result.data.is64Bit).toBe(false);
	});

	it("should return error for invalid magic", () => {
		const buf = new ArrayBuffer(32);
		const view = new DataView(buf);
		view.setUint32(0, 0xdeadbeef, false);
		const result = parseMachOHeader(buf, 0);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error).toContain("Invalid Mach-O magic");
		expect(result.error).toContain("deadbeef");
	});

	it("should return error for buffer too small to read magic", () => {
		const buf = new ArrayBuffer(2);
		const result = parseMachOHeader(buf, 0);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error).toContain("too small");
	});

	it("should return error for buffer too small for full header", () => {
		// 20 bytes: enough for magic but not full 32-byte header
		const buf = buildMachHeader64({ littleEndian: true });
		const truncated = buf.slice(0, 20);
		const result = parseMachOHeader(truncated, 0);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error).toContain("too small");
	});

	it("should return error when offset puts header past end of buffer", () => {
		const buf = new ArrayBuffer(32);
		const result = parseMachOHeader(buf, 100);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error).toContain("too small");
	});

	it("should not crash on zero-length buffer", () => {
		const buf = new ArrayBuffer(0);
		const result = parseMachOHeader(buf, 0);
		expect(result.ok).toBe(false);
	});
});
