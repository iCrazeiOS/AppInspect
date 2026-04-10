/**
 * Tests for load command parser and segment/section enumeration.
 */

import { describe, expect, it } from "bun:test";
import {
	type BuildVersionCommand,
	type DylibCommand,
	type EncryptionInfo64,
	LC_BUILD_VERSION,
	LC_CODE_SIGNATURE,
	LC_DYLD_CHAINED_FIXUPS,
	LC_ENCRYPTION_INFO,
	LC_ENCRYPTION_INFO_64,
	LC_LOAD_DYLIB,
	LC_LOAD_WEAK_DYLIB,
	LC_MAIN,
	LC_RPATH,
	LC_SEGMENT,
	LC_SEGMENT_64,
	LC_SYMTAB,
	LC_UUID,
	type LinkeditDataCommand,
	type MainCommand,
	parseLoadCommands,
	type RpathCommand,
	readCString,
	readVersion,
	type Segment64,
	type SymtabCommand,
	type UUIDCommand
} from "../load-commands";

// ── Fixture Helpers ───────────────────────────────────────────────────

/** Write a null-terminated string into a DataView at the given offset (max maxLen bytes). */
function writeCString(view: DataView, offset: number, str: string, maxLen: number): void {
	for (let i = 0; i < maxLen; i++) {
		view.setUint8(offset + i, i < str.length ? str.charCodeAt(i) : 0);
	}
}

/** Build a single LC_SEGMENT (32-bit) with N sections, returning its byte array. */
function buildSegment32(opts: {
	segname: string;
	vmaddr: number;
	vmsize: number;
	fileoff: number;
	filesize: number;
	maxprot: number;
	initprot: number;
	flags: number;
	sections: Array<{
		sectname: string;
		segname: string;
		addr: number;
		size: number;
		offset: number;
		align: number;
		reloff: number;
		nreloc: number;
		flags: number;
		reserved1: number;
		reserved2: number;
	}>;
}): ArrayBuffer {
	const nsects = opts.sections.length;
	// LC_SEGMENT: 56 bytes header + 68 bytes per section
	const cmdsize = 56 + nsects * 68;
	const buf = new ArrayBuffer(cmdsize);
	const view = new DataView(buf);
	const le = true;

	view.setUint32(0, LC_SEGMENT, le);
	view.setUint32(4, cmdsize, le);
	writeCString(view, 8, opts.segname, 16);
	view.setUint32(24, opts.vmaddr, le);
	view.setUint32(28, opts.vmsize, le);
	view.setUint32(32, opts.fileoff, le);
	view.setUint32(36, opts.filesize, le);
	view.setInt32(40, opts.maxprot, le);
	view.setInt32(44, opts.initprot, le);
	view.setUint32(48, nsects, le);
	view.setUint32(52, opts.flags, le);

	let off = 56;
	for (const sec of opts.sections) {
		writeCString(view, off, sec.sectname, 16);
		writeCString(view, off + 16, sec.segname, 16);
		view.setUint32(off + 32, sec.addr, le);
		view.setUint32(off + 36, sec.size, le);
		view.setUint32(off + 40, sec.offset, le);
		view.setUint32(off + 44, sec.align, le);
		view.setUint32(off + 48, sec.reloff, le);
		view.setUint32(off + 52, sec.nreloc, le);
		view.setUint32(off + 56, sec.flags, le);
		view.setUint32(off + 60, sec.reserved1, le);
		view.setUint32(off + 64, sec.reserved2, le);
		// Note: section_32 has no reserved3 field (68 bytes total, not 80)
		off += 68;
	}

	return buf;
}

/** Build a single LC_SEGMENT_64 with N sections, returning its byte array. */
function buildSegment64(opts: {
	segname: string;
	vmaddr: bigint;
	vmsize: bigint;
	fileoff: bigint;
	filesize: bigint;
	maxprot: number;
	initprot: number;
	flags: number;
	sections: Array<{
		sectname: string;
		segname: string;
		addr: bigint;
		size: bigint;
		offset: number;
		align: number;
		reloff: number;
		nreloc: number;
		flags: number;
		reserved1: number;
		reserved2: number;
		reserved3: number;
	}>;
}): ArrayBuffer {
	const nsects = opts.sections.length;
	const cmdsize = 72 + nsects * 80;
	const buf = new ArrayBuffer(cmdsize);
	const view = new DataView(buf);
	const le = true;

	view.setUint32(0, LC_SEGMENT_64, le);
	view.setUint32(4, cmdsize, le);
	writeCString(view, 8, opts.segname, 16);
	view.setBigUint64(24, opts.vmaddr, le);
	view.setBigUint64(32, opts.vmsize, le);
	view.setBigUint64(40, opts.fileoff, le);
	view.setBigUint64(48, opts.filesize, le);
	view.setInt32(56, opts.maxprot, le);
	view.setInt32(60, opts.initprot, le);
	view.setUint32(64, nsects, le);
	view.setUint32(68, opts.flags, le);

	let off = 72;
	for (const sec of opts.sections) {
		writeCString(view, off, sec.sectname, 16);
		writeCString(view, off + 16, sec.segname, 16);
		view.setBigUint64(off + 32, sec.addr, le);
		view.setBigUint64(off + 40, sec.size, le);
		view.setUint32(off + 48, sec.offset, le);
		view.setUint32(off + 52, sec.align, le);
		view.setUint32(off + 56, sec.reloff, le);
		view.setUint32(off + 60, sec.nreloc, le);
		view.setUint32(off + 64, sec.flags, le);
		view.setUint32(off + 68, sec.reserved1, le);
		view.setUint32(off + 72, sec.reserved2, le);
		view.setUint32(off + 76, sec.reserved3, le);
		off += 80;
	}

	return buf;
}

/** Build LC_LOAD_DYLIB or LC_LOAD_WEAK_DYLIB command. */
function buildDylibCommand(opts: {
	cmd?: number;
	name: string;
	currentVersion: number;
	compatVersion: number;
}): ArrayBuffer {
	const cmd = opts.cmd ?? LC_LOAD_DYLIB;
	const nameBytes = opts.name.length + 1; // +1 for null terminator
	// Header is 24 bytes, then string data; pad to multiple of 8
	const cmdsize = Math.ceil((24 + nameBytes) / 8) * 8;
	const buf = new ArrayBuffer(cmdsize);
	const view = new DataView(buf);
	const le = true;

	view.setUint32(0, cmd, le);
	view.setUint32(4, cmdsize, le);
	view.setUint32(8, 24, le); // name offset (relative to start of load command)
	view.setUint32(12, 0, le); // timestamp
	view.setUint32(16, opts.currentVersion, le);
	view.setUint32(20, opts.compatVersion, le);
	writeCString(view, 24, opts.name, cmdsize - 24);

	return buf;
}

/** Build LC_ENCRYPTION_INFO_64. */
function buildEncryptionInfo64(cryptoff: number, cryptsize: number, cryptid: number): ArrayBuffer {
	const cmdsize = 24; // cmd(4) + cmdsize(4) + cryptoff(4) + cryptsize(4) + cryptid(4) + pad(4)
	const buf = new ArrayBuffer(cmdsize);
	const view = new DataView(buf);
	const le = true;

	view.setUint32(0, LC_ENCRYPTION_INFO_64, le);
	view.setUint32(4, cmdsize, le);
	view.setUint32(8, cryptoff, le);
	view.setUint32(12, cryptsize, le);
	view.setUint32(16, cryptid, le);

	return buf;
}

/** Build LC_ENCRYPTION_INFO (32-bit). */
function buildEncryptionInfo32(cryptoff: number, cryptsize: number, cryptid: number): ArrayBuffer {
	const cmdsize = 20; // cmd(4) + cmdsize(4) + cryptoff(4) + cryptsize(4) + cryptid(4)
	const buf = new ArrayBuffer(cmdsize);
	const view = new DataView(buf);
	const le = true;

	view.setUint32(0, LC_ENCRYPTION_INFO, le);
	view.setUint32(4, cmdsize, le);
	view.setUint32(8, cryptoff, le);
	view.setUint32(12, cryptsize, le);
	view.setUint32(16, cryptid, le);

	return buf;
}

/** Build LC_UUID. */
function buildUUID(uuidBytes: number[]): ArrayBuffer {
	const cmdsize = 24; // cmd(4) + cmdsize(4) + uuid(16)
	const buf = new ArrayBuffer(cmdsize);
	const view = new DataView(buf);
	const le = true;

	view.setUint32(0, LC_UUID, le);
	view.setUint32(4, cmdsize, le);
	for (let i = 0; i < 16; i++) {
		view.setUint8(8 + i, uuidBytes[i]!);
	}

	return buf;
}

/** Build LC_SYMTAB. */
function buildSymtab(symoff: number, nsyms: number, stroff: number, strsize: number): ArrayBuffer {
	const cmdsize = 24;
	const buf = new ArrayBuffer(cmdsize);
	const view = new DataView(buf);
	const le = true;

	view.setUint32(0, LC_SYMTAB, le);
	view.setUint32(4, cmdsize, le);
	view.setUint32(8, symoff, le);
	view.setUint32(12, nsyms, le);
	view.setUint32(16, stroff, le);
	view.setUint32(20, strsize, le);

	return buf;
}

/** Build a linkedit_data_command (LC_CODE_SIGNATURE, LC_DYLD_CHAINED_FIXUPS, etc). */
function buildLinkeditData(cmd: number, dataoff: number, datasize: number): ArrayBuffer {
	const cmdsize = 16;
	const buf = new ArrayBuffer(cmdsize);
	const view = new DataView(buf);
	const le = true;

	view.setUint32(0, cmd, le);
	view.setUint32(4, cmdsize, le);
	view.setUint32(8, dataoff, le);
	view.setUint32(12, datasize, le);

	return buf;
}

/** Build an unknown/generic load command with optional extra padding. */
function buildGenericCommand(cmd: number, cmdsize: number): ArrayBuffer {
	const buf = new ArrayBuffer(cmdsize);
	const view = new DataView(buf);
	view.setUint32(0, cmd, true);
	view.setUint32(4, cmdsize, true);
	return buf;
}

/** Concatenate multiple ArrayBuffers. */
function concat(...buffers: ArrayBuffer[]): ArrayBuffer {
	const totalLen = buffers.reduce((sum, b) => sum + b.byteLength, 0);
	const out = new ArrayBuffer(totalLen);
	const u8 = new Uint8Array(out);
	let offset = 0;
	for (const b of buffers) {
		u8.set(new Uint8Array(b), offset);
		offset += b.byteLength;
	}
	return out;
}

/** Run parseLoadCommands on a concatenated buffer of load commands (64-bit). */
function parse(buffers: ArrayBuffer[]) {
	const combined = concat(...buffers);
	const ncmds = buffers.length;
	return parseLoadCommands(combined, 0, ncmds, combined.byteLength, true, true);
}

/** Run parseLoadCommands on a concatenated buffer of load commands (32-bit). */
function parse32(buffers: ArrayBuffer[]) {
	const combined = concat(...buffers);
	const ncmds = buffers.length;
	return parseLoadCommands(combined, 0, ncmds, combined.byteLength, true, false);
}

// ── Tests ─────────────────────────────────────────────────────────────

describe("readCString", () => {
	it("reads a null-terminated string", () => {
		const buf = new ArrayBuffer(16);
		const view = new DataView(buf);
		writeCString(view, 0, "hello", 16);
		expect(readCString(view, 0, 16)).toBe("hello");
	});

	it("respects maxLen", () => {
		const buf = new ArrayBuffer(16);
		const view = new DataView(buf);
		writeCString(view, 0, "hello world", 16);
		expect(readCString(view, 0, 5)).toBe("hello");
	});
});

describe("readVersion", () => {
	it("decodes version 1.2.3", () => {
		const packed = (1 << 16) | (2 << 8) | 3;
		expect(readVersion(packed)).toBe("1.2.3");
	});

	it("decodes version 15.0.0", () => {
		const packed = (15 << 16) | (0 << 8) | 0;
		expect(readVersion(packed)).toBe("15.0.0");
	});
});

describe("parseLoadCommands", () => {
	it("parses LC_SEGMENT_64 with 2 sections", () => {
		const seg = buildSegment64({
			segname: "__TEXT",
			vmaddr: 0x100000000n,
			vmsize: 0x4000n,
			fileoff: 0n,
			filesize: 0x4000n,
			maxprot: 5,
			initprot: 5,
			flags: 0,
			sections: [
				{
					sectname: "__text",
					segname: "__TEXT",
					addr: 0x100001000n,
					size: 0x1000n,
					offset: 0x1000,
					align: 4,
					reloff: 0,
					nreloc: 0,
					flags: 0x80000400,
					reserved1: 0,
					reserved2: 0,
					reserved3: 0
				},
				{
					sectname: "__stubs",
					segname: "__TEXT",
					addr: 0x100002000n,
					size: 0x60n,
					offset: 0x2000,
					align: 2,
					reloff: 0,
					nreloc: 0,
					flags: 0x80000408,
					reserved1: 0,
					reserved2: 6,
					reserved3: 0
				}
			]
		});

		const result = parse([seg]);

		expect(result.segments).toHaveLength(1);
		const s = result.segments[0]!;
		expect(s.segname).toBe("__TEXT");
		expect(s.vmaddr).toBe(0x100000000n);
		expect(s.vmsize).toBe(0x4000n);
		expect(s.fileoff).toBe(0n);
		expect(s.filesize).toBe(0x4000n);
		expect(s.maxprot).toBe(5);
		expect(s.initprot).toBe(5);
		expect(s.nsects).toBe(2);
		expect(s.sections).toHaveLength(2);

		// First section
		expect(s.sections[0]!.sectname).toBe("__text");
		expect(s.sections[0]!.segname).toBe("__TEXT");
		expect(s.sections[0]!.addr).toBe(0x100001000n);
		expect(s.sections[0]!.size).toBe(0x1000n);
		expect(s.sections[0]!.offset).toBe(0x1000);
		expect(s.sections[0]!.flags).toBe(0x80000400);

		// Second section
		expect(s.sections[1]!.sectname).toBe("__stubs");
		expect(s.sections[1]!.addr).toBe(0x100002000n);
		expect(s.sections[1]!.size).toBe(0x60n);
		expect(s.sections[1]!.reserved2).toBe(6);
	});

	it("parses LC_SEGMENT_64 with 3 sections", () => {
		const seg = buildSegment64({
			segname: "__DATA",
			vmaddr: 0x200000000n,
			vmsize: 0x8000n,
			fileoff: 0x4000n,
			filesize: 0x8000n,
			maxprot: 3,
			initprot: 3,
			flags: 0,
			sections: [
				{
					sectname: "__data",
					segname: "__DATA",
					addr: 0x200001000n,
					size: 0x500n,
					offset: 0x5000,
					align: 3,
					reloff: 0,
					nreloc: 0,
					flags: 0,
					reserved1: 0,
					reserved2: 0,
					reserved3: 0
				},
				{
					sectname: "__bss",
					segname: "__DATA",
					addr: 0x200002000n,
					size: 0x200n,
					offset: 0,
					align: 3,
					reloff: 0,
					nreloc: 0,
					flags: 1,
					reserved1: 0,
					reserved2: 0,
					reserved3: 0
				},
				{
					sectname: "__objc_classlist",
					segname: "__DATA",
					addr: 0x200003000n,
					size: 0x80n,
					offset: 0x6000,
					align: 3,
					reloff: 0,
					nreloc: 0,
					flags: 0x10000000,
					reserved1: 0,
					reserved2: 0,
					reserved3: 0
				}
			]
		});

		const result = parse([seg]);
		expect(result.segments[0]!.sections).toHaveLength(3);
		expect(result.segments[0]!.sections[2]!.sectname).toBe("__objc_classlist");
		expect(result.segments[0]!.sections[2]!.flags).toBe(0x10000000);
	});

	it("parses LC_LOAD_DYLIB with name string extraction", () => {
		const dylib = buildDylibCommand({
			name: "/usr/lib/libSystem.B.dylib",
			currentVersion: (1 << 16) | (300 << 8) | 0,
			compatVersion: (1 << 16) | (0 << 8) | 0
		});

		const result = parse([dylib]);

		expect(result.libraries).toHaveLength(1);
		const lib = result.libraries[0]!;
		expect(lib.name).toBe("/usr/lib/libSystem.B.dylib");
		expect(lib.currentVersion).toBe("1.44.0"); // 300 = 0x12C → (0x12C >> 8)=1, remainder
		expect(lib.weak).toBe(false);
	});

	it("parses LC_LOAD_WEAK_DYLIB with weak flag set", () => {
		const dylib = buildDylibCommand({
			cmd: LC_LOAD_WEAK_DYLIB,
			name: "/usr/lib/swift/libswiftCore.dylib",
			currentVersion: (5 << 16) | (9 << 8) | 0,
			compatVersion: (1 << 16) | (0 << 8) | 0
		});

		const result = parse([dylib]);

		expect(result.libraries).toHaveLength(1);
		expect(result.libraries[0]!.name).toBe("/usr/lib/swift/libswiftCore.dylib");
		expect(result.libraries[0]!.weak).toBe(true);
		expect(result.libraries[0]!.currentVersion).toBe("5.9.0");
		expect(result.libraries[0]!.compatVersion).toBe("1.0.0");
	});

	it("parses LC_ENCRYPTION_INFO_64", () => {
		const enc = buildEncryptionInfo64(0x4000, 0x10000, 1);
		const result = parse([enc]);

		expect(result.encryption).not.toBeNull();
		expect(result.encryption!.cryptoff).toBe(0x4000);
		expect(result.encryption!.cryptsize).toBe(0x10000);
		expect(result.encryption!.cryptid).toBe(1);
	});

	it("parses LC_UUID into formatted hex string", () => {
		const uuidBytes = [
			0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
			0x32, 0x10
		];
		const uuid = buildUUID(uuidBytes);
		const result = parse([uuid]);

		expect(result.uuid).toBe("ABCDEF01-2345-6789-FEDC-BA9876543210");
	});

	it("parses LC_SYMTAB", () => {
		const sym = buildSymtab(0x8000, 500, 0xc000, 4096);
		const result = parse([sym]);

		expect(result.symtabInfo).not.toBeNull();
		expect(result.symtabInfo!.symoff).toBe(0x8000);
		expect(result.symtabInfo!.nsyms).toBe(500);
		expect(result.symtabInfo!.stroff).toBe(0xc000);
		expect(result.symtabInfo!.strsize).toBe(4096);
	});

	it("parses LC_CODE_SIGNATURE", () => {
		const cs = buildLinkeditData(LC_CODE_SIGNATURE, 0x20000, 0x1000);
		const result = parse([cs]);

		expect(result.codeSignatureInfo).not.toBeNull();
		expect(result.codeSignatureInfo!.offset).toBe(0x20000);
		expect(result.codeSignatureInfo!.size).toBe(0x1000);
	});

	it("parses LC_DYLD_CHAINED_FIXUPS", () => {
		const cf = buildLinkeditData(LC_DYLD_CHAINED_FIXUPS, 0x18000, 0x800);
		const result = parse([cf]);

		expect(result.chainedFixupsInfo).not.toBeNull();
		expect(result.chainedFixupsInfo!.offset).toBe(0x18000);
		expect(result.chainedFixupsInfo!.size).toBe(0x800);
	});

	it("handles unknown command types gracefully", () => {
		const unknown = buildGenericCommand(0xdeadbeef, 16);
		const result = parse([unknown]);

		expect(result.loadCommands).toHaveLength(1);
		expect(result.loadCommands[0]!.cmd).toBe(0xdeadbeef);
		expect(result.loadCommands[0]!.cmdsize).toBe(16);
	});

	it("always advances by cmdsize, finding next command correctly", () => {
		// Build a generic command with cmdsize much larger than its 8-byte header
		// to verify the parser skips ahead by cmdsize, not struct size
		const paddedCmd = buildGenericCommand(0x99, 64); // 64 bytes, but only 8 used

		// Place a UUID command right after the 64-byte padded command
		const uuidBytes = [
			0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
			0xff, 0x00
		];
		const uuid = buildUUID(uuidBytes);

		const result = parse([paddedCmd, uuid]);

		expect(result.loadCommands).toHaveLength(2);
		// The second command should be the UUID, not garbage
		expect(result.uuid).toBe("11223344-5566-7788-99AA-BBCCDDEEFF00");
	});

	it("parses multiple load commands in sequence", () => {
		const seg = buildSegment64({
			segname: "__TEXT",
			vmaddr: 0x100000000n,
			vmsize: 0x4000n,
			fileoff: 0n,
			filesize: 0x4000n,
			maxprot: 5,
			initprot: 5,
			flags: 0,
			sections: []
		});
		const dylib = buildDylibCommand({
			name: "/usr/lib/libc.dylib",
			currentVersion: (1 << 16) | (0 << 8) | 0,
			compatVersion: (1 << 16) | (0 << 8) | 0
		});
		const uuid = buildUUID([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
		const cs = buildLinkeditData(LC_CODE_SIGNATURE, 0x30000, 0x2000);

		const result = parse([seg, dylib, uuid, cs]);

		expect(result.loadCommands).toHaveLength(4);
		expect(result.segments).toHaveLength(1);
		expect(result.libraries).toHaveLength(1);
		expect(result.uuid).not.toBeNull();
		expect(result.codeSignatureInfo).not.toBeNull();
	});

	// ── 32-bit Load Command Tests ───────────────────────────────────────

	it("parses LC_SEGMENT (32-bit) with 2 sections", () => {
		const seg = buildSegment32({
			segname: "__TEXT",
			vmaddr: 0x1000,
			vmsize: 0x4000,
			fileoff: 0,
			filesize: 0x4000,
			maxprot: 5,
			initprot: 5,
			flags: 0,
			sections: [
				{
					sectname: "__text",
					segname: "__TEXT",
					addr: 0x2000,
					size: 0x1000,
					offset: 0x1000,
					align: 4,
					reloff: 0,
					nreloc: 0,
					flags: 0x80000400,
					reserved1: 0,
					reserved2: 0
				},
				{
					sectname: "__stubs",
					segname: "__TEXT",
					addr: 0x3000,
					size: 0x60,
					offset: 0x2000,
					align: 2,
					reloff: 0,
					nreloc: 0,
					flags: 0x80000408,
					reserved1: 0,
					reserved2: 6
				}
			]
		});

		const result = parse32([seg]);

		expect(result.segments).toHaveLength(1);
		const s = result.segments[0]!;
		expect(s.segname).toBe("__TEXT");
		expect(s.vmaddr).toBe(0x1000n);
		expect(s.vmsize).toBe(0x4000n);
		expect(s.fileoff).toBe(0n);
		expect(s.filesize).toBe(0x4000n);
		expect(s.maxprot).toBe(5);
		expect(s.initprot).toBe(5);
		expect(s.nsects).toBe(2);
		expect(s.sections).toHaveLength(2);

		// First section
		expect(s.sections[0]!.sectname).toBe("__text");
		expect(s.sections[0]!.segname).toBe("__TEXT");
		expect(s.sections[0]!.addr).toBe(0x2000n);
		expect(s.sections[0]!.size).toBe(0x1000n);
		expect(s.sections[0]!.offset).toBe(0x1000);
		expect(s.sections[0]!.flags).toBe(0x80000400);
		// 32-bit sections don't have reserved3
		expect(s.sections[0]!.reserved3).toBe(0);

		// Second section
		expect(s.sections[1]!.sectname).toBe("__stubs");
		expect(s.sections[1]!.addr).toBe(0x3000n);
		expect(s.sections[1]!.size).toBe(0x60n);
		expect(s.sections[1]!.reserved2).toBe(6);
	});

	it("parses LC_ENCRYPTION_INFO (32-bit)", () => {
		const enc = buildEncryptionInfo32(0x4000, 0x10000, 1);
		const result = parse32([enc]);

		expect(result.encryption).not.toBeNull();
		expect(result.encryption!.cryptoff).toBe(0x4000);
		expect(result.encryption!.cryptsize).toBe(0x10000);
		expect(result.encryption!.cryptid).toBe(1);
	});

	it("parses mixed 32-bit load commands in sequence", () => {
		const seg = buildSegment32({
			segname: "__TEXT",
			vmaddr: 0x1000,
			vmsize: 0x4000,
			fileoff: 0,
			filesize: 0x4000,
			maxprot: 5,
			initprot: 5,
			flags: 0,
			sections: []
		});
		const dylib = buildDylibCommand({
			name: "/usr/lib/libc.dylib",
			currentVersion: (1 << 16) | (0 << 8) | 0,
			compatVersion: (1 << 16) | (0 << 8) | 0
		});
		const uuid = buildUUID([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
		const enc = buildEncryptionInfo32(0x4000, 0x8000, 0);

		const result = parse32([seg, dylib, uuid, enc]);

		expect(result.loadCommands).toHaveLength(4);
		expect(result.segments).toHaveLength(1);
		expect(result.segments[0]!.vmaddr).toBe(0x1000n);
		expect(result.libraries).toHaveLength(1);
		expect(result.uuid).not.toBeNull();
		expect(result.encryption).not.toBeNull();
		expect(result.encryption!.cryptid).toBe(0);
	});
});
