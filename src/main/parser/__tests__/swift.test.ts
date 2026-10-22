/**
 * Tests for Swift 5 runtime metadata extraction.
 */

import { describe, expect, it } from "bun:test";
import type { Section64, Segment64 } from "../load-commands";
import { extractSwiftMetadata } from "../swift";
import { initSwiftDemangler } from "../swift-demangle";

const BASE = 0x100000000n;
const MODULE_DESC = 0x100;
const PERSON_DESC = 0x120;
const ADDRESS_DESC = 0x180;
const EXTENSION_DESC = 0x1a0;
const NESTED_DESC = 0x1c0;
const NAMED_PROTO = 0x200;
const PERSON_FIELDS = 0x300;
const ADDRESS_FIELDS = 0x340;
const NESTED_FIELDS = 0x380;
const PERSON_CONFORMANCE = 0x400;
const SYMBOLIC_DESC = 0x1e0;
const ENV_DESC = 0x220;
const COLOR_DESC = 0x240;
const SYMBOLIC_FIELDS = 0x430;
const SYMBOLIC_COPY_DESC = 0x7c0;
const SYMBOLIC_TYPES_ENTRY = 0x1018;
const SLOT_ENV = 0x800;
const SLOT_COLOR = 0x808;
const SLOT_URL = 0x810;
const SLOT_INT8 = 0x818;
const SLOT_REBASE = 0x828;
const SLOT_PROTOCOL = 0x830;

function makeSection(segname: string, sectname: string, offset: number, size: number): Section64 {
	return {
		sectname,
		segname,
		addr: BASE + BigInt(offset),
		size: BigInt(size),
		offset,
		align: 2,
		reloff: 0,
		nreloc: 0,
		flags: 0,
		reserved1: 0,
		reserved2: 0,
		reserved3: 0
	};
}

function makeSegment(sections: Section64[]): Segment64 {
	return {
		cmd: 0x19,
		cmdsize: 72 + sections.length * 80,
		segname: "__TEXT",
		vmaddr: BASE,
		vmsize: 0x2000n,
		fileoff: 0n,
		filesize: 0x2000n,
		maxprot: 7,
		initprot: 5,
		nsects: sections.length,
		flags: 0,
		sections
	};
}

function writeCString(buffer: ArrayBuffer, offset: number, value: string): void {
	const bytes = new Uint8Array(buffer);
	for (let i = 0; i < value.length; i++) bytes[offset + i] = value.charCodeAt(i);
	bytes[offset + value.length] = 0;
}

/** Write a relative pointer stored at `fieldOffset` targeting `targetOffset`. */
function writeRelative(buffer: ArrayBuffer, fieldOffset: number, targetOffset: number): void {
	new DataView(buffer).setInt32(fieldOffset, targetOffset - fieldOffset, true);
}

function writeSymbolicRef(
	buffer: ArrayBuffer,
	kindOffset: number,
	kind: number,
	targetOffset: number
): void {
	new DataView(buffer).setUint8(kindOffset, kind);
	writeRelative(buffer, kindOffset + 1, targetOffset);
}

function buildFixture(withSymbolic = false): { buffer: ArrayBuffer; segments: Segment64[] } {
	const buffer = new ArrayBuffer(0x2000);
	const view = new DataView(buffer);

	// Strings
	writeCString(buffer, 0x500, "Test");
	writeCString(buffer, 0x510, "Person");
	writeCString(buffer, 0x520, "Address");
	writeCString(buffer, 0x530, "Named");
	writeCString(buffer, 0x540, "So8NSObjectC");
	writeCString(buffer, 0x550, "SS");
	writeCString(buffer, 0x554, "Si");
	writeCString(buffer, 0x560, "name");
	writeCString(buffer, 0x568, "age");
	writeCString(buffer, 0x570, "street");
	writeCString(buffer, 0x580, "MyObjCClass");
	writeCString(buffer, 0x590, "4Test6PersonC");
	writeCString(buffer, 0x5a0, "Inner");

	// Module descriptor
	view.setUint32(MODULE_DESC, 0, true); // kind = module
	view.setInt32(MODULE_DESC + 4, 0, true);
	writeRelative(buffer, MODULE_DESC + 8, 0x500);

	// Class descriptor: Test.Person (generic)
	view.setUint32(PERSON_DESC, 16 | 0x80, true); // kind = class, generic
	writeRelative(buffer, PERSON_DESC + 4, MODULE_DESC);
	writeRelative(buffer, PERSON_DESC + 8, 0x510);
	view.setInt32(PERSON_DESC + 12, 0, true);
	writeRelative(buffer, PERSON_DESC + 16, PERSON_FIELDS);
	writeRelative(buffer, PERSON_DESC + 20, 0x540); // superclass mangled name

	// Struct descriptor: Test.Address
	view.setUint32(ADDRESS_DESC, 17, true); // kind = struct
	writeRelative(buffer, ADDRESS_DESC + 4, MODULE_DESC);
	writeRelative(buffer, ADDRESS_DESC + 8, 0x520);
	view.setInt32(ADDRESS_DESC + 12, 0, true);
	writeRelative(buffer, ADDRESS_DESC + 16, ADDRESS_FIELDS);

	// Extension of Test.Person, containing Test.Person.Inner.
	view.setUint32(EXTENSION_DESC, 1, true); // kind = extension
	writeRelative(buffer, EXTENSION_DESC + 4, MODULE_DESC);
	writeRelative(buffer, EXTENSION_DESC + 8, 0x590); // mangled extended type

	view.setUint32(NESTED_DESC, 17, true); // kind = struct
	writeRelative(buffer, NESTED_DESC + 4, EXTENSION_DESC);
	writeRelative(buffer, NESTED_DESC + 8, 0x5a0);
	view.setInt32(NESTED_DESC + 12, 0, true);
	writeRelative(buffer, NESTED_DESC + 16, NESTED_FIELDS);

	// Protocol descriptor: Test.Named
	view.setUint32(NAMED_PROTO, 3, true); // kind = protocol
	writeRelative(buffer, NAMED_PROTO + 4, MODULE_DESC);
	writeRelative(buffer, NAMED_PROTO + 8, 0x530);
	view.setUint32(NAMED_PROTO + 12, 1, true); // requirements in signature
	view.setUint32(NAMED_PROTO + 16, 1, true); // requirements

	// Person fields: name: String, age: Int
	view.setUint16(PERSON_FIELDS + 8, 1, true); // kind
	view.setUint16(PERSON_FIELDS + 10, 12, true); // record size
	view.setUint32(PERSON_FIELDS + 12, 2, true); // field count
	writeRelative(buffer, PERSON_FIELDS + 16 + 4, 0x550); // SS
	writeRelative(buffer, PERSON_FIELDS + 16 + 8, 0x560); // name
	writeRelative(buffer, PERSON_FIELDS + 28 + 4, 0x554); // Si
	writeRelative(buffer, PERSON_FIELDS + 28 + 8, 0x568); // age

	// Address fields: street: String
	view.setUint16(ADDRESS_FIELDS + 8, 1, true);
	view.setUint16(ADDRESS_FIELDS + 10, 12, true);
	view.setUint32(ADDRESS_FIELDS + 12, 1, true);
	writeRelative(buffer, ADDRESS_FIELDS + 16 + 4, 0x550); // SS
	writeRelative(buffer, ADDRESS_FIELDS + 16 + 8, 0x570); // street

	// Inner has no stored properties.
	view.setUint16(NESTED_FIELDS + 10, 12, true);
	view.setUint32(NESTED_FIELDS + 12, 0, true);

	if (withSymbolic) {
		writeCString(buffer, 0x5b0, "Symbolic");
		writeCString(buffer, 0x5c0, "Environment");
		writeCString(buffer, 0x5d0, "ColorScheme");
		writeCString(buffer, 0x5e0, "environment");
		writeCString(buffer, 0x5f0, "url");
		writeCString(buffer, 0x600, "pointer");
		writeCString(buffer, 0x610, "direct");
		writeCString(buffer, 0x620, "rebased");
		writeCString(buffer, 0x630, "padded");
		writeCString(buffer, 0x640, "negative");
		writeCString(buffer, 0x650, "case");
		writeCString(buffer, 0x660, "protocol");
		writeCString(buffer, 0x670, "extended");

		view.setUint32(SYMBOLIC_DESC, 17, true);
		writeRelative(buffer, SYMBOLIC_DESC + 4, MODULE_DESC);
		writeRelative(buffer, SYMBOLIC_DESC + 8, 0x5b0);
		view.setInt32(SYMBOLIC_DESC + 12, 0, true);
		writeRelative(buffer, SYMBOLIC_DESC + 16, SYMBOLIC_FIELDS);

		view.setUint32(ENV_DESC, 17, true);
		writeRelative(buffer, ENV_DESC + 4, MODULE_DESC);
		writeRelative(buffer, ENV_DESC + 8, 0x5c0);

		view.setUint32(COLOR_DESC, 18, true);
		writeRelative(buffer, COLOR_DESC + 4, MODULE_DESC);
		writeRelative(buffer, COLOR_DESC + 8, 0x5d0);

		view.setUint32(SYMBOLIC_COPY_DESC, 17, true);
		writeRelative(buffer, SYMBOLIC_COPY_DESC + 4, MODULE_DESC);
		writeRelative(buffer, SYMBOLIC_COPY_DESC + 8, 0x5c0);

		view.setUint16(SYMBOLIC_FIELDS + 8, 1, true);
		view.setUint16(SYMBOLIC_FIELDS + 10, 12, true);
		view.setUint32(SYMBOLIC_FIELDS + 12, 10, true);

		const fieldNames = [0x5e0, 0x5f0, 0x600, 0x610, 0x620, 0x630, 0x640, 0x660, 0x670, 0x650];
		const fieldTypes = [0x700, 0x720, 0x740, 0x760, 0x770, 0x790, 0x7a0, 0x7b0, 0x7b8, 0];
		for (let i = 0; i < fieldNames.length; i++) {
			const record = SYMBOLIC_FIELDS + 16 + i * 12;
			const typeOffset = fieldTypes[i]!;
			if (typeOffset === 0) view.setInt32(record + 4, 0, true);
			else writeRelative(buffer, record + 4, typeOffset);
			writeRelative(buffer, record + 8, fieldNames[i]!);
		}

		writeSymbolicRef(buffer, 0x700, 0x02, SLOT_ENV);
		view.setUint8(0x705, 0x79);
		writeSymbolicRef(buffer, 0x706, 0x02, SLOT_COLOR);
		view.setUint8(0x70b, 0x47);

		writeSymbolicRef(buffer, 0x720, 0x02, SLOT_URL);
		writeCString(buffer, 0x725, "Sg");

		writeCString(buffer, 0x740, "Spy");
		writeSymbolicRef(buffer, 0x743, 0x02, SLOT_INT8);
		writeCString(buffer, 0x748, "GSg");

		writeSymbolicRef(buffer, 0x760, 0x01, PERSON_DESC);
		writeSymbolicRef(buffer, 0x770, 0x02, SLOT_REBASE);

		view.setUint8(0x790, 0xff);
		view.setUint8(0x791, 0xff);
		writeSymbolicRef(buffer, 0x792, 0x01, PERSON_DESC);

		writeSymbolicRef(buffer, 0x7a0, 0x01, SYMBOLIC_COPY_DESC);
		writeSymbolicRef(buffer, 0x7b0, 0x02, SLOT_PROTOCOL);
		writeSymbolicRef(buffer, 0x7b8, 0x01, EXTENSION_DESC);

		writeRelative(buffer, SYMBOLIC_TYPES_ENTRY, SYMBOLIC_DESC);
	}

	// Person : Named conformance
	writeRelative(buffer, PERSON_CONFORMANCE, NAMED_PROTO);
	writeRelative(buffer, PERSON_CONFORMANCE + 4, PERSON_DESC);
	view.setInt32(PERSON_CONFORMANCE + 8, 0, true);
	view.setUint32(PERSON_CONFORMANCE + 12, 0, true); // typeReferenceKind = 0

	// Section entry tables
	writeRelative(buffer, 0x1000, PERSON_DESC);
	writeRelative(buffer, 0x1004, ADDRESS_DESC);
	writeRelative(buffer, 0x1008, EXTENSION_DESC);
	writeRelative(buffer, 0x100c, NESTED_DESC);
	writeRelative(buffer, 0x1010, NAMED_PROTO);
	writeRelative(buffer, 0x1020, PERSON_CONFORMANCE);

	const sections = [
		makeSection("__TEXT", "__swift5_fieldmd", 0x300, 0x100),
		makeSection("__TEXT", "__swift5_types", 0x1000, 16),
		makeSection("__TEXT", "__swift5_protos", 0x1010, 4),
		makeSection("__TEXT", "__swift5_proto", 0x1020, 4)
	];
	if (withSymbolic) {
		sections.push(makeSection("__TEXT", "__swift5_types2", SYMBOLIC_TYPES_ENTRY, 4));
	}

	return { buffer, segments: [makeSegment(sections)] };
}

describe("extractSwiftMetadata", () => {
	it("returns an empty result when Swift sections are missing", () => {
		const result = extractSwiftMetadata(new ArrayBuffer(0x100), [makeSegment([])], true, true);
		expect(result.present).toBe(false);
		expect(result.types).toEqual([]);
		expect(result.protocols).toEqual([]);
		expect(result.conformances).toEqual([]);
	});

	it("extracts nominal types, stored properties, and superclasses", async () => {
		await initSwiftDemangler();
		const { buffer, segments } = buildFixture();
		const result = extractSwiftMetadata(buffer, segments, true, true);

		expect(result.present).toBe(true);
		expect(result.types).toHaveLength(3);

		const person = result.types.find((t) => t.fullName === "Test.Person");
		expect(person).toBeDefined();
		expect(person?.kind).toBe("class");
		expect(person?.module).toBe("Test");
		expect(person?.generic).toBe(true);
		expect(person?.superclass).toBe("__C.NSObject");
		expect(person?.fields).toEqual([
			{ name: "name", type: "Swift.String" },
			{ name: "age", type: "Swift.Int" }
		]);

		const address = result.types.find((t) => t.fullName === "Test.Address");
		expect(address?.kind).toBe("struct");
		expect(address?.fields).toEqual([{ name: "street", type: "Swift.String" }]);
	});

	it("keeps nesting for a type declared inside an extension", async () => {
		await initSwiftDemangler();
		const { buffer, segments } = buildFixture();
		const result = extractSwiftMetadata(buffer, segments, true, true);

		const nested = result.types.find((t) => t.fullName === "Test.Person.Inner");
		expect(nested).toBeDefined();
		expect(nested?.module).toBe("Test");
		expect(nested?.name).toBe("Inner");
	});

	it("resolves symbolic field type manglings", async () => {
		await initSwiftDemangler();
		const { buffer, segments } = buildFixture(true);
		const bindMap = new Map([
			[SLOT_ENV, { ordinal: 0, symbolName: "_$s4Test11EnvironmentVMn", addend: 0n }],
			[SLOT_COLOR, { ordinal: 1, symbolName: "_$s4Test11ColorSchemeOMn", addend: 0n }],
			[SLOT_URL, { ordinal: 2, symbolName: "_$s10Foundation3URLVMn", addend: 0n }],
			[SLOT_INT8, { ordinal: 3, symbolName: "_$ss4Int8VMn", addend: 0n }],
			[SLOT_PROTOCOL, { ordinal: 4, symbolName: "_$s4Test5NamedMp", addend: 0n }]
		]);
		const rebaseMap = new Map([[SLOT_REBASE, BASE + BigInt(ADDRESS_DESC)]]);

		const result = extractSwiftMetadata(buffer, segments, true, true, bindMap, rebaseMap);
		const symbolic = result.types.find((t) => t.fullName === "Test.Symbolic");

		expect(symbolic).toBeDefined();
		expect(symbolic?.fields).toEqual([
			{ name: "environment", type: "Test.Environment<Test.ColorScheme>" },
			{ name: "url", type: "Swift.Optional<Foundation.URL>" },
			{ name: "pointer", type: "Swift.Optional<Swift.UnsafeMutablePointer<Swift.Int8>>" },
			{ name: "direct", type: "Test.Person" },
			{ name: "rebased", type: "Test.Address" },
			{ name: "padded", type: "Test.Person" },
			{ name: "negative", type: "Test.Environment" },
			{ name: "protocol", type: "Test.Named" },
			{ name: "extended", type: "Test.Person" },
			{ name: "case" }
		]);
	});

	it("resolves an indirect parent through the chained-fixup rebase map", async () => {
		await initSwiftDemangler();
		const { buffer, segments } = buildFixture();
		const view = new DataView(buffer);

		// Address's parent is an indirect pointer into a chained-fixup slot.
		// The raw slot value is an encoded rebase, not a usable pointer.
		view.setInt32(ADDRESS_DESC + 4, (0x700 - (ADDRESS_DESC + 4)) | 1, true);
		view.setBigUint64(0x700, 0xdeadbeefn, true);

		const rebaseMap = new Map([[0x700, BASE + BigInt(MODULE_DESC)]]);
		const result = extractSwiftMetadata(buffer, segments, true, true, new Map(), rebaseMap);

		const address = result.types.find((t) => t.fullName === "Test.Address");
		expect(address).toBeDefined();
		expect(address?.module).toBe("Test");
	});

	it("extracts protocols and attaches resolved conformances", async () => {
		await initSwiftDemangler();
		const { buffer, segments } = buildFixture();
		const result = extractSwiftMetadata(buffer, segments, true, true);

		const protocol = result.protocols.find((p) => p.fullName === "Test.Named");
		expect(protocol).toBeDefined();
		expect(protocol?.requirementCount).toBe(1);
		expect(protocol?.conformingTypes).toEqual(["Test.Person"]);

		expect(result.conformances).toEqual([
			{ typeName: "Test.Person", protocolName: "Test.Named" }
		]);

		const person = result.types.find((t) => t.fullName === "Test.Person");
		expect(person?.protocols).toEqual(["Test.Named"]);
		expect(result.unresolvedConformances).toBe(0);
	});

	it("resolves an indirect protocol through the chained-fixup rebase map", async () => {
		await initSwiftDemangler();
		const { buffer, segments } = buildFixture();
		const view = new DataView(buffer);

		view.setInt32(PERSON_CONFORMANCE, (0x700 - PERSON_CONFORMANCE) | 1, true);
		view.setBigUint64(0x700, 0xdeadbeefn, true);

		const rebaseMap = new Map([[0x700, BASE + BigInt(NAMED_PROTO)]]);
		const result = extractSwiftMetadata(buffer, segments, true, true, new Map(), rebaseMap);

		expect(result.conformances).toContainEqual({
			typeName: "Test.Person",
			protocolName: "Test.Named"
		});
	});

	it("resolves external protocols through the chained-fixup bind map", async () => {
		await initSwiftDemangler();
		const { buffer, segments } = buildFixture();
		const view = new DataView(buffer);

		// Person : Swift.RawRepresentable, with an indirect protocol pointer bound
		// at load time (the pointer value itself is not present in the file).
		view.setInt32(PERSON_CONFORMANCE + 0x20, (0x600 - (PERSON_CONFORMANCE + 0x20)) | 1, true);
		writeRelative(buffer, PERSON_CONFORMANCE + 0x24, PERSON_DESC);
		view.setUint32(PERSON_CONFORMANCE + 0x2c, 0, true);

		const protoSection = segments[0]!.sections.find((s) => s.sectname === "__swift5_proto")!;
		protoSection.size = 8n;
		writeRelative(buffer, 0x1024, PERSON_CONFORMANCE + 0x20);

		const bindMap = new Map([[0x600, { ordinal: 0, symbolName: "_$sSYMp", addend: 0n }]]);

		const result = extractSwiftMetadata(buffer, segments, true, true, bindMap);
		expect(result.conformances).toContainEqual({
			typeName: "Test.Person",
			protocolName: "Swift.RawRepresentable"
		});
		expect(result.unresolvedConformances).toBe(0);
	});

	it("resolves ObjC class-name conformances (typeReferenceKind 2)", async () => {
		await initSwiftDemangler();
		const { buffer, segments } = buildFixture();
		const view = new DataView(buffer);

		writeRelative(buffer, PERSON_CONFORMANCE + 4, 0x580);
		view.setUint32(PERSON_CONFORMANCE + 12, 2 << 3, true); // DirectObjCClassName

		const result = extractSwiftMetadata(buffer, segments, true, true);
		expect(result.conformances).toContainEqual({
			typeName: "MyObjCClass",
			protocolName: "Test.Named"
		});
		expect(result.unresolvedConformances).toBe(0);
	});

	it("does not treat an indirect ObjC class object as a class name", () => {
		const { buffer, segments } = buildFixture();
		const view = new DataView(buffer);

		// TypeRef points at a location holding the class object pointer. The
		// bytes at that pointer happen to look like a valid C string, but that
		// name is not the class name.
		writeRelative(buffer, PERSON_CONFORMANCE + 4, 0x600);
		view.setBigUint64(0x600, BASE + 0x580n, true);
		view.setUint32(PERSON_CONFORMANCE + 12, 3 << 3, true); // IndirectObjCClass

		const result = extractSwiftMetadata(buffer, segments, true, true);
		expect(result.conformances).toEqual([]);
		expect(result.unresolvedConformances).toBe(1);
	});

	it("reports present when only protocol sections exist", () => {
		const { buffer, segments } = buildFixture();
		const typesSection = segments[0]!.sections.find((s) => s.sectname === "__swift5_types")!;
		typesSection.size = 0n;

		const result = extractSwiftMetadata(buffer, segments, true, true);
		expect(result.present).toBe(true);
		expect(result.types).toEqual([]);
		expect(result.protocols).toHaveLength(1);
	});

	it("skips a truncated protocol descriptor without throwing", () => {
		const { buffer, segments } = buildFixture();
		const view = new DataView(buffer);
		const descriptorOffset = buffer.byteLength - 18;

		view.setUint32(descriptorOffset, 3, true); // kind = protocol
		writeRelative(buffer, descriptorOffset + 4, MODULE_DESC);
		writeRelative(buffer, descriptorOffset + 8, 0x530);
		writeRelative(buffer, 0x1010, descriptorOffset);

		const result = extractSwiftMetadata(buffer, segments, true, true);
		expect(result.protocols).toEqual([]);
	});

	it("skips malformed type entries without throwing", () => {
		const { buffer, segments } = buildFixture();
		new DataView(buffer).setInt32(0x1000, 0x7fffffff, true);

		const result = extractSwiftMetadata(buffer, segments, true, true);
		expect(result.types.some((t) => t.fullName === "Test.Address")).toBe(true);
	});
});
