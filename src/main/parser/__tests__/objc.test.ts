/**
 * Tests for ObjC class + method name extraction.
 */

import { describe, expect, it } from "bun:test";
import type { Section64, Segment64 } from "../load-commands";
import { extractObjCMetadata, resolvePointer, vmaddrToFileOffset } from "../objc";

// ── Fixture Helpers ──────────────────────────────────────────────────

/** Write a null-terminated C string into a DataView. */
function writeCString(view: DataView, offset: number, str: string): void {
	for (let i = 0; i < str.length; i++) {
		view.setUint8(offset + i, str.charCodeAt(i));
	}
	view.setUint8(offset + str.length, 0);
}

/** Create a minimal Segment64 for testing. */
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
		initprot: 3,
		nsects: sections.length,
		flags: 0,
		sections
	};
}

/** Create a minimal Section64. */
function makeSection(
	segname: string,
	sectname: string,
	addr: bigint,
	size: bigint,
	offset: number
): Section64 {
	return {
		sectname,
		segname,
		addr,
		size,
		offset,
		align: 3,
		reloff: 0,
		nreloc: 0,
		flags: 0,
		reserved1: 0,
		reserved2: 0,
		reserved3: 0
	};
}

// ── Tests ────────────────────────────────────────────────────────────

describe("objc", () => {
	describe("vmaddrToFileOffset", () => {
		const segments = [
			makeSegment("__TEXT", 0x100000000n, 0x4000n, 0n, 0x4000n),
			makeSegment("__DATA", 0x100004000n, 0x4000n, 0x4000n, 0x4000n)
		];

		it("converts a vmaddr within __TEXT to file offset", () => {
			const result = vmaddrToFileOffset(0x100000100n, segments);
			expect(result).toBe(0x100);
		});

		it("converts a vmaddr within __DATA to file offset", () => {
			const result = vmaddrToFileOffset(0x100004010n, segments);
			expect(result).toBe(0x4010);
		});

		it("returns null for vmaddr outside all segments", () => {
			const result = vmaddrToFileOffset(0x200000000n, segments);
			expect(result).toBeNull();
		});

		it("returns null for empty segments array", () => {
			const result = vmaddrToFileOffset(0x100000000n, []);
			expect(result).toBeNull();
		});
	});

	describe("resolvePointer", () => {
		it("returns rebaseMap value when present", () => {
			const buf = new ArrayBuffer(64);
			const view = new DataView(buf);
			view.setBigUint64(8, 0xdeadbeefn, true);

			const rebaseMap = new Map<number, bigint>([[8, 0x100004000n]]);
			const result = resolvePointer(view, 8, rebaseMap, true);
			expect(result).toBe(0x100004000n);
		});

		it("reads raw value when not in rebaseMap", () => {
			const buf = new ArrayBuffer(64);
			const view = new DataView(buf);
			view.setBigUint64(16, 0xcafebaben, true);

			const rebaseMap = new Map<number, bigint>();
			const result = resolvePointer(view, 16, rebaseMap, true);
			expect(result).toBe(0xcafebaben);
		});

		it("returns 0n when file offset is beyond buffer", () => {
			const buf = new ArrayBuffer(16);
			const view = new DataView(buf);

			const rebaseMap = new Map<number, bigint>();
			const result = resolvePointer(view, 100, rebaseMap, true);
			expect(result).toBe(0n);
		});
	});

	describe("extractObjCMetadata", () => {
		it("returns empty result when __objc_classlist section is missing", () => {
			const buf = new ArrayBuffer(256);
			const segments = [makeSegment("__TEXT", 0n, 0x100n, 0n, 0x100n)];
			const sections: Section64[] = [];
			const rebaseMap = new Map<number, bigint>();

			const result = extractObjCMetadata(buf, sections, segments, rebaseMap, true);
			expect(result.classes).toEqual([]);
			expect(result.protocols).toEqual([]);
		});

		it("returns empty classes for zero-size __objc_classlist", () => {
			const buf = new ArrayBuffer(256);
			const classlistSection = makeSection(
				"__DATA",
				"__objc_classlist",
				0x100n,
				0n, // zero size
				0x100
			);
			const segments = [makeSegment("__DATA", 0n, 0x1000n, 0n, 0x1000n)];
			const rebaseMap = new Map<number, bigint>();

			const result = extractObjCMetadata(buf, [classlistSection], segments, rebaseMap, true);
			expect(result.classes).toEqual([]);
		});

		it("extracts a class name from a crafted class_t + class_ro_t", () => {
			// Layout:
			//   0x0000 - 0x0008: __objc_classlist (1 pointer at file offset 0)
			//   0x1000 - 0x1028: class_t (40 bytes)
			//   0x2000 - 0x2040: class_ro_t
			//   0x3000 - 0x300F: class name string "MyClass\0"
			//
			// Segments: single __DATA covering vmaddr 0x100000000, fileoff 0

			const buf = new ArrayBuffer(0x4000);
			const view = new DataView(buf);
			const le = true;

			const baseVmaddr = 0x100000000n;

			// class_t at file offset 0x1000
			// isa(8) + superclass(8) + cache(8) + vtable(8) + data(8)
			const classFileOff = 0x1000;
			const roVmaddr = baseVmaddr + 0x2000n;
			// data pointer at offset 32
			view.setBigUint64(classFileOff + 32, roVmaddr, le);

			// class_ro_t at file offset 0x2000
			// flags(4) + instanceStart(4) + instanceSize(4) + reserved(4) + ivarLayout(8) + name(8) + baseMethods(8)
			const roFileOff = 0x2000;
			const nameVmaddr = baseVmaddr + 0x3000n;
			// name pointer at offset 24
			view.setBigUint64(roFileOff + 24, nameVmaddr, le);
			// baseMethods = 0 (no methods)
			view.setBigUint64(roFileOff + 32, 0n, le);

			// Class name string at file offset 0x3000
			writeCString(view, 0x3000, "MyClass");

			// __objc_classlist at file offset 0 — one pointer to class_t vmaddr
			const classVmaddr = baseVmaddr + BigInt(classFileOff);
			view.setBigUint64(0, classVmaddr, le);

			const classlistSection = makeSection(
				"__DATA",
				"__objc_classlist",
				baseVmaddr, // addr
				8n, // size (1 pointer)
				0 // file offset
			);

			const segments = [makeSegment("__DATA", baseVmaddr, 0x4000n, 0n, 0x4000n)];

			const rebaseMap = new Map<number, bigint>();
			const result = extractObjCMetadata(buf, [classlistSection], segments, rebaseMap, le);

			expect(result.classes.length).toBe(1);
			expect(result.classes[0]!.name).toBe("MyClass");
			expect(result.classes[0]!.methods).toEqual([]);
		});

		it("extracts a class with absolute method list", () => {
			const buf = new ArrayBuffer(0x5000);
			const view = new DataView(buf);
			const le = true;
			const baseVmaddr = 0x100000000n;

			// Classlist at file offset 0x0000
			const classVmaddr = baseVmaddr + 0x1000n;
			view.setBigUint64(0, classVmaddr, le);

			// class_t at file offset 0x1000
			const classFileOff = 0x1000;
			const roVmaddr = baseVmaddr + 0x2000n;
			view.setBigUint64(classFileOff + 32, roVmaddr, le);

			// class_ro_t at file offset 0x2000
			const roFileOff = 0x2000;
			const nameVmaddr = baseVmaddr + 0x3000n;
			const methodsVmaddr = baseVmaddr + 0x3100n;
			view.setBigUint64(roFileOff + 24, nameVmaddr, le);
			view.setBigUint64(roFileOff + 32, methodsVmaddr, le);

			// Class name at 0x3000
			writeCString(view, 0x3000, "AppDelegate");

			// method_list_t at 0x3100
			// entsizeAndFlags = 24 (absolute, no relative flag)
			// count = 2
			const mlFileOff = 0x3100;
			view.setUint32(mlFileOff, 24, le); // entsizeAndFlags (entsize=24, no flags)
			view.setUint32(mlFileOff + 4, 2, le); // count = 2

			// Method entries (absolute): name_ptr(8) + types_ptr(8) + imp_ptr(8)
			// Method 1 name at 0x3200
			const method1NameVmaddr = baseVmaddr + 0x3200n;
			view.setBigUint64(mlFileOff + 8, method1NameVmaddr, le); // name_ptr
			writeCString(view, 0x3200, "viewDidLoad");

			// Method 2 name at 0x3220
			const method2NameVmaddr = baseVmaddr + 0x3220n;
			view.setBigUint64(mlFileOff + 8 + 24, method2NameVmaddr, le); // name_ptr
			writeCString(view, 0x3220, "applicationDidFinishLaunching:");

			const classlistSection = makeSection("__DATA", "__objc_classlist", baseVmaddr, 8n, 0);

			const segments = [makeSegment("__DATA", baseVmaddr, 0x5000n, 0n, 0x5000n)];

			const rebaseMap = new Map<number, bigint>();
			const result = extractObjCMetadata(buf, [classlistSection], segments, rebaseMap, le);

			expect(result.classes.length).toBe(1);
			expect(result.classes[0]!.name).toBe("AppDelegate");
			expect(result.classes[0]!.methods.map((m: any) => m.selector)).toEqual([
				"viewDidLoad",
				"applicationDidFinishLaunching:"
			]);
		});

		it("uses rebaseMap to resolve class pointer in classlist", () => {
			const buf = new ArrayBuffer(0x5000);
			const view = new DataView(buf);
			const le = true;
			const baseVmaddr = 0x100000000n;

			// Classlist at file offset 0x0000
			// The raw value in the buffer is garbage — rebaseMap provides the real pointer
			view.setBigUint64(0, 0xffffffffffffffffn, le); // garbage raw value

			// class_t at file offset 0x1000
			const classFileOff = 0x1000;
			const roVmaddr = baseVmaddr + 0x2000n;
			view.setBigUint64(classFileOff + 32, roVmaddr, le);

			// class_ro_t at 0x2000
			const roFileOff = 0x2000;
			const nameVmaddr = baseVmaddr + 0x3000n;
			view.setBigUint64(roFileOff + 24, nameVmaddr, le);
			view.setBigUint64(roFileOff + 32, 0n, le); // no methods

			// Class name at 0x3000
			writeCString(view, 0x3000, "RebasedClass");

			const classlistSection = makeSection("__DATA", "__objc_classlist", baseVmaddr, 8n, 0);

			const segments = [makeSegment("__DATA", baseVmaddr, 0x5000n, 0n, 0x5000n)];

			// rebaseMap resolves file offset 0 to the correct class_t vmaddr
			const classVmaddr = baseVmaddr + 0x1000n;
			const rebaseMap = new Map<number, bigint>([[0, classVmaddr]]);

			const result = extractObjCMetadata(buf, [classlistSection], segments, rebaseMap, le);

			expect(result.classes.length).toBe(1);
			expect(result.classes[0]!.name).toBe("RebasedClass");
		});

		it("finds __objc_classlist in __DATA_CONST segment", () => {
			const buf = new ArrayBuffer(0x5000);
			const view = new DataView(buf);
			const le = true;
			const baseVmaddr = 0x100000000n;

			// class_t at file offset 0x1000
			const classVmaddr = baseVmaddr + 0x1000n;
			view.setBigUint64(0x0, classVmaddr, le);

			const classFileOff = 0x1000;
			const roVmaddr = baseVmaddr + 0x2000n;
			view.setBigUint64(classFileOff + 32, roVmaddr, le);

			// class_ro_t
			const nameVmaddr = baseVmaddr + 0x3000n;
			view.setBigUint64(0x2000 + 24, nameVmaddr, le);
			view.setBigUint64(0x2000 + 32, 0n, le);

			writeCString(view, 0x3000, "ConstClass");

			// Section in __DATA_CONST
			const classlistSection = makeSection(
				"__DATA_CONST",
				"__objc_classlist",
				baseVmaddr,
				8n,
				0
			);

			const segments = [makeSegment("__DATA_CONST", baseVmaddr, 0x5000n, 0n, 0x5000n)];

			const rebaseMap = new Map<number, bigint>();
			const result = extractObjCMetadata(buf, [classlistSection], segments, rebaseMap, le);

			expect(result.classes.length).toBe(1);
			expect(result.classes[0]!.name).toBe("ConstClass");
		});

		it("extracts protocol names from __objc_protolist", () => {
			const buf = new ArrayBuffer(0x5000);
			const view = new DataView(buf);
			const le = true;
			const baseVmaddr = 0x100000000n;

			// protocol_t at file offset 0x1000
			// isa(8) + mangledName(8)
			const protoVmaddr = baseVmaddr + 0x1000n;
			const protoNameVmaddr = baseVmaddr + 0x2000n;
			view.setBigUint64(0x1000 + 8, protoNameVmaddr, le); // mangledName
			writeCString(view, 0x2000, "NSCoding");

			// __objc_protolist at file offset 0x0000 — one pointer
			view.setBigUint64(0, protoVmaddr, le);

			const protolistSection = makeSection("__DATA", "__objc_protolist", baseVmaddr, 8n, 0);

			// No classlist section — we just want to test protocol extraction
			const segments = [makeSegment("__DATA", baseVmaddr, 0x5000n, 0n, 0x5000n)];

			const rebaseMap = new Map<number, bigint>();
			const result = extractObjCMetadata(buf, [protolistSection], segments, rebaseMap, le);

			expect(result.classes).toEqual([]);
			expect(result.protocols.length).toBe(1);
			expect(result.protocols[0]).toBe("NSCoding");
		});

		it("strips low 3 bits from class pointer (flag bits)", () => {
			const buf = new ArrayBuffer(0x5000);
			const view = new DataView(buf);
			const le = true;
			const baseVmaddr = 0x100000000n;

			// class_t at file offset 0x1000
			const classVmaddrClean = baseVmaddr + 0x1000n;
			// Set low bits (flags) on the pointer in classlist
			const classVmaddrWithFlags = classVmaddrClean | 0x5n;
			view.setBigUint64(0, classVmaddrWithFlags, le);

			const classFileOff = 0x1000;
			const roVmaddr = baseVmaddr + 0x2000n;
			// Also set flags on data pointer
			view.setBigUint64(classFileOff + 32, roVmaddr | 0x3n, le);

			const nameVmaddr = baseVmaddr + 0x3000n;
			view.setBigUint64(0x2000 + 24, nameVmaddr, le);
			view.setBigUint64(0x2000 + 32, 0n, le);

			writeCString(view, 0x3000, "FlaggedClass");

			const classlistSection = makeSection("__DATA", "__objc_classlist", baseVmaddr, 8n, 0);

			const segments = [makeSegment("__DATA", baseVmaddr, 0x5000n, 0n, 0x5000n)];

			const rebaseMap = new Map<number, bigint>();
			const result = extractObjCMetadata(buf, [classlistSection], segments, rebaseMap, le);

			expect(result.classes.length).toBe(1);
			expect(result.classes[0]!.name).toBe("FlaggedClass");
		});

		it("handles relative method lists", () => {
			const buf = new ArrayBuffer(0x6000);
			const view = new DataView(buf);
			const le = true;
			const baseVmaddr = 0x100000000n;

			// Classlist at 0x0000
			const classVmaddr = baseVmaddr + 0x1000n;
			view.setBigUint64(0, classVmaddr, le);

			// class_t at 0x1000
			const roVmaddr = baseVmaddr + 0x2000n;
			view.setBigUint64(0x1000 + 32, roVmaddr, le);

			// class_ro_t at 0x2000
			const nameVmaddr = baseVmaddr + 0x3000n;
			const methodsVmaddr = baseVmaddr + 0x4000n;
			view.setBigUint64(0x2000 + 24, nameVmaddr, le);
			view.setBigUint64(0x2000 + 32, methodsVmaddr, le);

			writeCString(view, 0x3000, "RelativeClass");

			// method_list_t at 0x4000 (relative methods)
			const mlOff = 0x4000;
			// entsizeAndFlags: bit 31 set (relative), entsize=12
			view.setUint32(mlOff, 0x80000000 | 12, le);
			view.setUint32(mlOff + 4, 1, le); // count = 1

			// Relative method entry at mlOff + 8:
			// name_offset(int32) + types_offset(int32) + imp_offset(int32)
			const entryOffset = mlOff + 8;

			// The name_offset is relative to its own position.
			// It points to a selector reference (a pointer to the actual string).
			// Put the selector ref at file offset 0x5000.
			const selectorRefFileOffset = 0x5000;
			const nameRelOff = selectorRefFileOffset - entryOffset; // relative offset
			view.setInt32(entryOffset, nameRelOff, le);

			// The selector reference at 0x5000 is a pointer to the actual string
			const selectorStringVmaddr = baseVmaddr + 0x5100n;
			view.setBigUint64(selectorRefFileOffset, selectorStringVmaddr, le);

			writeCString(view, 0x5100, "initWithFrame:");

			const classlistSection = makeSection("__DATA", "__objc_classlist", baseVmaddr, 8n, 0);

			const segments = [makeSegment("__DATA", baseVmaddr, 0x6000n, 0n, 0x6000n)];

			const rebaseMap = new Map<number, bigint>();
			const result = extractObjCMetadata(buf, [classlistSection], segments, rebaseMap, le);

			expect(result.classes.length).toBe(1);
			expect(result.classes[0]!.name).toBe("RelativeClass");
			expect(result.classes[0]!.methods.map((m: any) => m.selector)).toEqual([
				"initWithFrame:"
			]);
		});

		it("extracts class protocol conformances from baseProtocols", () => {
			// Layout:
			//   0x0000 - 0x0008: __objc_classlist (1 pointer)
			//   0x1000 - 0x1028: class_t (40 bytes)
			//   0x2000 - 0x2040: class_ro_t (with baseProtocols at offset 40)
			//   0x3000 - 0x300F: class name string "MyViewController\0"
			//   0x4000 - 0x4018: protocol_list_t (count + 2 protocol pointers)
			//   0x5000 - 0x5010: protocol_t #1 (isa + mangledName)
			//   0x5100 - 0x5110: protocol_t #2 (isa + mangledName)
			//   0x6000 - 0x600F: protocol name #1 "UITableViewDelegate\0"
			//   0x6100 - 0x610F: protocol name #2 "UITableViewDataSource\0"

			const buf = new ArrayBuffer(0x7000);
			const view = new DataView(buf);
			const le = true;
			const baseVmaddr = 0x100000000n;

			// __objc_classlist at file offset 0 — one pointer to class_t vmaddr
			const classVmaddr = baseVmaddr + 0x1000n;
			view.setBigUint64(0, classVmaddr, le);

			// class_t at file offset 0x1000
			// data pointer at offset 32
			const roVmaddr = baseVmaddr + 0x2000n;
			view.setBigUint64(0x1000 + 32, roVmaddr, le);

			// class_ro_t at file offset 0x2000
			// name pointer at offset 24
			const nameVmaddr = baseVmaddr + 0x3000n;
			view.setBigUint64(0x2000 + 24, nameVmaddr, le);
			// baseMethods = 0 (no methods)
			view.setBigUint64(0x2000 + 32, 0n, le);
			// baseProtocols at offset 40
			const protocolsVmaddr = baseVmaddr + 0x4000n;
			view.setBigUint64(0x2000 + 40, protocolsVmaddr, le);

			// Class name string at file offset 0x3000
			writeCString(view, 0x3000, "MyViewController");

			// protocol_list_t at file offset 0x4000
			// count (8 bytes) + protocol_t* array
			view.setBigUint64(0x4000, 2n, le); // count = 2

			// Protocol pointers at 0x4008 and 0x4010
			const proto1Vmaddr = baseVmaddr + 0x5000n;
			const proto2Vmaddr = baseVmaddr + 0x5100n;
			view.setBigUint64(0x4000 + 8, proto1Vmaddr, le);
			view.setBigUint64(0x4000 + 16, proto2Vmaddr, le);

			// protocol_t #1 at 0x5000: isa(8) + mangledName(8)
			const proto1NameVmaddr = baseVmaddr + 0x6000n;
			view.setBigUint64(0x5000 + 8, proto1NameVmaddr, le);

			// protocol_t #2 at 0x5100: isa(8) + mangledName(8)
			const proto2NameVmaddr = baseVmaddr + 0x6100n;
			view.setBigUint64(0x5100 + 8, proto2NameVmaddr, le);

			// Protocol name strings
			writeCString(view, 0x6000, "UITableViewDelegate");
			writeCString(view, 0x6100, "UITableViewDataSource");

			const classlistSection = makeSection("__DATA", "__objc_classlist", baseVmaddr, 8n, 0);

			const segments = [makeSegment("__DATA", baseVmaddr, 0x7000n, 0n, 0x7000n)];

			const rebaseMap = new Map<number, bigint>();
			const result = extractObjCMetadata(buf, [classlistSection], segments, rebaseMap, le);

			expect(result.classes.length).toBe(1);
			expect(result.classes[0]!.name).toBe("MyViewController");
			expect(result.classes[0]!.protocols).toEqual([
				"UITableViewDelegate",
				"UITableViewDataSource"
			]);
		});

		it("extracts protocol details with instance and class methods", () => {
			// Layout:
			//   0x0000 - 0x0008: __objc_protolist (1 pointer)
			//   0x1000 - 0x1040: protocol_t (full structure with method lists)
			//   0x2000 - 0x200F: protocol name "MyProtocol\0"
			//   0x3000 - 0x3020: instance method_list_t (1 method)
			//   0x3100 - 0x3120: class method_list_t (1 method)
			//   0x4000 - 0x400F: selector "doSomething:\0"
			//   0x4100 - 0x410F: selector "sharedInstance\0"
			//   0x5000 - 0x500F: type encoding "v@:\0"
			//   0x5100 - 0x510F: type encoding "@:\0"

			const buf = new ArrayBuffer(0x6000);
			const view = new DataView(buf);
			const le = true;
			const baseVmaddr = 0x100000000n;

			// __objc_protolist at file offset 0
			const protoVmaddr = baseVmaddr + 0x1000n;
			view.setBigUint64(0, protoVmaddr, le);

			// protocol_t at 0x1000:
			// isa(8) + mangledName(8) + protocols(8) + instanceMethods(8) + classMethods(8) + ...
			const nameVmaddr = baseVmaddr + 0x2000n;
			const instMethodsVmaddr = baseVmaddr + 0x3000n;
			const classMethodsVmaddr = baseVmaddr + 0x3100n;

			view.setBigUint64(0x1000 + 0, 0n, le); // isa
			view.setBigUint64(0x1000 + 8, nameVmaddr, le); // mangledName
			view.setBigUint64(0x1000 + 16, 0n, le); // protocols (none)
			view.setBigUint64(0x1000 + 24, instMethodsVmaddr, le); // instanceMethods
			view.setBigUint64(0x1000 + 32, classMethodsVmaddr, le); // classMethods
			view.setBigUint64(0x1000 + 40, 0n, le); // optionalInstanceMethods
			view.setBigUint64(0x1000 + 48, 0n, le); // optionalClassMethods

			// Protocol name
			writeCString(view, 0x2000, "MyProtocol");

			// Instance method_list_t at 0x3000 (absolute format):
			// entsize_and_flags(4) + count(4) + [method entries]
			// method entry: name_ptr(8) + types_ptr(8) + imp_ptr(8) = 24 bytes
			view.setUint32(0x3000, 24, le); // entsize (24 bytes per entry)
			view.setUint32(0x3004, 1, le); // count = 1

			const instSelVmaddr = baseVmaddr + 0x4000n;
			const instTypesVmaddr = baseVmaddr + 0x5000n;
			view.setBigUint64(0x3000 + 8, instSelVmaddr, le); // selector
			view.setBigUint64(0x3000 + 16, instTypesVmaddr, le); // types
			view.setBigUint64(0x3000 + 24, 0n, le); // imp (not needed)

			// Class method_list_t at 0x3100
			view.setUint32(0x3100, 24, le); // entsize
			view.setUint32(0x3104, 1, le); // count = 1

			const classSelVmaddr = baseVmaddr + 0x4100n;
			const classTypesVmaddr = baseVmaddr + 0x5100n;
			view.setBigUint64(0x3100 + 8, classSelVmaddr, le);
			view.setBigUint64(0x3100 + 16, classTypesVmaddr, le);
			view.setBigUint64(0x3100 + 24, 0n, le);

			// Selector strings
			writeCString(view, 0x4000, "doSomething:");
			writeCString(view, 0x4100, "sharedInstance");

			// Type encodings
			writeCString(view, 0x5000, "v@:");
			writeCString(view, 0x5100, "@:");

			const protolistSection = makeSection("__DATA", "__objc_protolist", baseVmaddr, 8n, 0);

			const segments = [makeSegment("__DATA", baseVmaddr, 0x6000n, 0n, 0x6000n)];

			const rebaseMap = new Map<number, bigint>();
			const result = extractObjCMetadata(buf, [protolistSection], segments, rebaseMap, le);

			expect(result.protocols).toEqual(["MyProtocol"]);
			expect(result.protocolDetails.length).toBe(1);

			const proto = result.protocolDetails[0]!;
			expect(proto.name).toBe("MyProtocol");
			expect(proto.instanceMethods.length).toBe(1);
			expect(proto.instanceMethods[0]!.selector).toBe("doSomething:");
			expect(proto.classMethods.length).toBe(1);
			expect(proto.classMethods[0]!.selector).toBe("sharedInstance");
			expect(proto.optionalInstanceMethods).toEqual([]);
			expect(proto.optionalClassMethods).toEqual([]);
		});
	});
});
