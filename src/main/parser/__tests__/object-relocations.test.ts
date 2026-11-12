import { describe, expect, it } from "bun:test";
import { CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_X86_64 } from "../../../shared/arch";
import { vmaddrToFileOffset } from "../address";
import { parseLoadCommands } from "../load-commands";
import { parseMachOHeader } from "../macho";
import { buildObjectImage, objectSizeSegments } from "../object-relocations";
import { parseSymbolTable } from "../symbols";
import { buildStringXrefMap } from "../xrefs";
import { buildObjectFile, type ObjectSectionSpec, type ObjectSymbolSpec } from "./fixtures";

// arm64 relocation types
const UNSIGNED = 0;
const SUBTRACTOR = 1;
const BRANCH26 = 2;
const PAGE21 = 3;
const PAGEOFF12 = 4;
const GOT_LOAD_PAGE21 = 5;
const GOT_LOAD_PAGEOFF12 = 6;
const POINTER_TO_GOT = 7;
const ADDEND = 10;

// x86_64 relocation types
const X86_SIGNED = 1;
const X86_BRANCH = 2;
const X86_GOT_LOAD = 3;
const X86_GOT = 4;
const X86_SUBTRACTOR = 5;
const X86_SIGNED_1 = 6;

const S_ATTR_CODE = 0x80000400;

function words(...values: number[]): Uint8Array {
	const out = new Uint8Array(values.length * 4);
	const view = new DataView(out.buffer);
	values.forEach((v, i) => {
		view.setUint32(i * 4, v >>> 0, true);
	});
	return out;
}

function build(spec: {
	cputype: number;
	bits32?: boolean;
	sections: ObjectSectionSpec[];
	symbols: ObjectSymbolSpec[];
}) {
	const { buffer, sectionAddrs } = buildObjectFile(spec);
	const header = parseMachOHeader(buffer, 0);
	if (!header.ok) throw new Error(header.error);
	const is64 = !spec.bits32;
	const lc = parseLoadCommands(
		buffer,
		is64 ? 32 : 28,
		header.data.header.ncmds,
		header.data.header.sizeofcmds,
		true,
		is64
	);
	const image = buildObjectImage(buffer, lc, spec.cputype, true, is64);
	const sections = lc.segments.flatMap((s) => s.sections);
	return { buffer, lc, image, sections, sectionAddrs, view: new DataView(image.buffer) };
}

function adrpTarget(insn: number, pc: number): number {
	const immlo = (insn >>> 29) & 0x3;
	const immhi = (insn >>> 5) & 0x7ffff;
	const imm = ((((immhi << 2) | immlo) << 11) >> 11) * 0x1000;
	return (pc & ~0xfff) + imm;
}

const imm12 = (insn: number) => (insn >>> 10) & 0xfff;

describe("buildObjectImage (arm64)", () => {
	const symbols: ObjectSymbolSpec[] = [
		{ name: "l_.str", sect: 3 },
		{ name: "_helper", sect: 1, offset: 0x20, external: true },
		{ name: "_ext", sect: 0 },
		{ name: "_value", sect: 4, external: true },
		{ name: "_anchor", sect: 2, offset: 0x10 },
		{ name: "_OBJC_CLASS_$_NSObject", sect: 0 }
	];
	const constData = new Uint8Array(0x2000);
	const constView = new DataView(constData.buffer);
	constView.setInt32(0x10, 4, true); // addend of the A - B pair
	constView.setInt32(0x20, -0x20, true); // assembler placeholder the linker ignores
	const data = new Uint8Array(0x18);
	const dataView = new DataView(data.buffer);
	dataView.setBigUint64(0, 2n, true); // addend: l_.str + 2

	const sections: ObjectSectionSpec[] = [
		{
			segname: "__TEXT",
			sectname: "__text",
			flags: S_ATTR_CODE,
			data: words(
				0x90000000, // adrp x0, l_.str@PAGE
				0x91000000, // add x0, x0, l_.str@PAGEOFF
				0x94000000, // bl _helper
				0x90000001, // adrp x1, _ext@GOTPAGE
				0xf9400021, // ldr x1, [x1, _ext@GOTPAGEOFF]
				0x90000002, // adrp x2, (_value + 8)@PAGE
				0xf9400042, // ldr x2, [x2, (_value + 8)@PAGEOFF]
				0xd503201f, // nop
				0xd65f03c0 // _helper: ret
			),
			relocs: [
				{ address: 0x0, symbolnum: 0, type: PAGE21, length: 2, pcrel: true },
				{ address: 0x4, symbolnum: 0, type: PAGEOFF12, length: 2 },
				{ address: 0x8, symbolnum: 1, type: BRANCH26, length: 2, pcrel: true },
				{ address: 0xc, symbolnum: 2, type: GOT_LOAD_PAGE21, length: 2, pcrel: true },
				{ address: 0x10, symbolnum: 2, type: GOT_LOAD_PAGEOFF12, length: 2 },
				{ address: 0x14, symbolnum: 8, type: ADDEND, length: 2, extern: false },
				{ address: 0x14, symbolnum: 3, type: PAGE21, length: 2, pcrel: true },
				{ address: 0x18, symbolnum: 8, type: ADDEND, length: 2, extern: false },
				{ address: 0x18, symbolnum: 3, type: PAGEOFF12, length: 2 }
			]
		},
		{
			segname: "__TEXT",
			sectname: "__const",
			data: constData,
			relocs: [
				{ address: 0x10, symbolnum: 4, type: SUBTRACTOR, length: 2 },
				{ address: 0x10, symbolnum: 0, type: UNSIGNED, length: 2 },
				{ address: 0x20, symbolnum: 2, type: POINTER_TO_GOT, length: 2, pcrel: true }
			]
		},
		{ segname: "__TEXT", sectname: "__cstring", data: new TextEncoder().encode("hello\0") },
		{
			segname: "__DATA",
			sectname: "__data",
			data,
			relocs: [
				{ address: 0x0, symbolnum: 0, type: UNSIGNED, length: 3 },
				{ address: 0x8, symbolnum: 5, type: UNSIGNED, length: 3 },
				// Section-relative: the content already holds the target's address
				{ address: 0x10, symbolnum: 3, type: UNSIGNED, length: 3, extern: false }
			]
		}
	];

	const fixture = (() => {
		const sections2 = sections.map((s) => ({ ...s, data: s.data.slice() }));
		// The section-relative pointer holds __cstring + 1, known only after layout
		const probe = buildObjectFile({ cputype: CPU_TYPE_ARM64, sections: sections2, symbols });
		new DataView(sections2[3]!.data.buffer).setBigUint64(
			0x10,
			BigInt(probe.sectionAddrs[2]! + 1),
			true
		);
		return build({ cputype: CPU_TYPE_ARM64, sections: sections2, symbols });
	})();
	const { image, view, sections: parsed, sectionAddrs } = fixture;
	const [textAddr, constAddr, cstrAddr, dataAddr] = sectionAddrs as [
		number,
		number,
		number,
		number
	];
	const text = parsed[0]!;
	const constSect = parsed[1]!;
	const dataSect = parsed[3]!;
	const got = image.segments.find((s) => s.sections[0]?.sectname === "__got")!;
	const slotVm = Number(got.vmaddr);
	const slotOffset = Number(got.fileoff);

	it("groups sections by their segment name and appends the GOT", () => {
		expect(image.segments.map((s) => s.segname)).toEqual(["__TEXT", "__DATA", "__DATA_CONST"]);
		expect(image.segments[0]!.sections.map((s) => s.sectname)).toEqual([
			"__text",
			"__const",
			"__cstring"
		]);
		expect(image.sectionSegments.map((s) => s.segname)).toEqual(["__TEXT", "__DATA"]);
		expect(got.sections[0]!.size).toBe(8n);
		// File offsets of existing data are unchanged
		expect(vmaddrToFileOffset(BigInt(cstrAddr), image.segments)).toBe(parsed[2]!.offset);
		expect(slotOffset).toBeGreaterThanOrEqual(fixture.buffer.byteLength);
	});

	it("patches ADRP/ADD to a local string", () => {
		const adrp = view.getUint32(text.offset, true);
		const add = view.getUint32(text.offset + 4, true);
		expect(adrpTarget(adrp, textAddr) + imm12(add)).toBe(cstrAddr);
		// Destination register is preserved
		expect(adrp & 0x1f).toBe(0);
	});

	it("patches BL to a local function", () => {
		const bl = view.getUint32(text.offset + 8, true);
		expect(bl & 0x3ffffff).toBe((0x20 - 0x8) / 4);
	});

	it("routes GOT loads through a synthesised slot bound to the import", () => {
		const adrp = view.getUint32(text.offset + 0xc, true);
		const ldr = view.getUint32(text.offset + 0x10, true);
		expect(adrpTarget(adrp, textAddr + 0xc) + imm12(ldr) * 8).toBe(slotVm);
		expect(image.bindMap.get(slotOffset)?.symbolName).toBe("_ext");
	});

	it("applies an ADDEND to the following page relocations, scaling LDR offsets", () => {
		const adrp = view.getUint32(text.offset + 0x14, true);
		const ldr = view.getUint32(text.offset + 0x18, true);
		expect(adrpTarget(adrp, textAddr + 0x14) + imm12(ldr) * 8).toBe(dataAddr + 8);
	});

	it("resolves A - B relative offsets", () => {
		const value = view.getInt32(constSect.offset + 0x10, true);
		expect(value).toBe(cstrAddr - (constAddr + 0x10) + 4);
	});

	it("points POINTER_TO_GOT at the slot, ignoring the placeholder", () => {
		const value = view.getInt32(constSect.offset + 0x20, true);
		expect(constAddr + 0x20 + value).toBe(slotVm);
	});

	it("rebases pointers to defined symbols and binds pointers to imports", () => {
		expect(image.rebaseMap.get(dataSect.offset)).toBe(BigInt(cstrAddr + 2));
		expect(view.getBigUint64(dataSect.offset, true)).toBe(BigInt(cstrAddr + 2));

		const bind = image.bindMap.get(dataSect.offset + 8);
		expect(bind?.symbolName).toBe("_OBJC_CLASS_$_NSObject");
		expect(view.getBigUint64(dataSect.offset + 8, true)).toBe(0n);

		expect(image.rebaseMap.get(dataSect.offset + 0x10)).toBe(BigInt(cstrAddr + 1));
	});

	it("sizes segments by their own sections plus trailing link-edit data", () => {
		const sized = objectSizeSegments(
			fixture.lc,
			image.sectionSegments,
			fixture.buffer.byteLength
		);
		expect(sized.map((s) => s.segname)).toEqual(["__TEXT", "__DATA", "__LINKEDIT"]);
		const textSize = parsed.slice(0, 3).reduce((n, s) => n + Number(s.size), 0);
		expect(Number(sized[0]!.filesize)).toBe(textSize + text.offset);
		expect(Number(sized[1]!.filesize)).toBe(Number(dataSect.size));
		const linkEdit = sized[2]!;
		expect(Number(linkEdit.fileoff + linkEdit.filesize)).toBe(fixture.buffer.byteLength);
	});
});

describe("buildObjectImage (x86_64)", () => {
	const symbols: ObjectSymbolSpec[] = [
		{ name: "l_.str", sect: 3 },
		{ name: "_helper", sect: 1, offset: 0x20, external: true },
		{ name: "_ext", sect: 0 },
		{ name: "_anchor", sect: 2 }
	];
	const code = new Uint8Array(0x24);
	code.set([0x48, 0x8d, 0x05], 0); // lea rax, [rip + l_.str]
	code.set([0x48, 0x8b, 0x05], 7); // mov rax, [rip + _ext@GOTPCREL]
	code.set([0xc6, 0x05], 14); // movb [rip + l_.str], 1
	const codeView = new DataView(code.buffer);
	codeView.setInt32(16, -1, true); // SIGNED_1 addend
	code[20] = 0x01;
	code[21] = 0xe8; // call _helper
	codeView.setInt32(26, 0x1234, true); // section-relative displacement, already final
	const constData = new Uint8Array(0x10);
	const constView = new DataView(constData.buffer);
	constView.setInt32(0, 5, true); // _ext@GOTPCREL + 1 (pc-relative bias of 4 included)
	constView.setInt32(4, 0, true);

	const { image, view, sections, sectionAddrs } = build({
		cputype: CPU_TYPE_X86_64,
		symbols,
		sections: [
			{
				segname: "__TEXT",
				sectname: "__text",
				flags: S_ATTR_CODE,
				data: code,
				relocs: [
					{ address: 3, symbolnum: 0, type: X86_SIGNED, length: 2, pcrel: true },
					{ address: 10, symbolnum: 2, type: X86_GOT_LOAD, length: 2, pcrel: true },
					{ address: 16, symbolnum: 0, type: X86_SIGNED_1, length: 2, pcrel: true },
					{ address: 22, symbolnum: 1, type: X86_BRANCH, length: 2, pcrel: true },
					{
						address: 26,
						symbolnum: 3,
						type: X86_SIGNED,
						length: 2,
						pcrel: true,
						extern: false
					}
				]
			},
			{
				segname: "__TEXT",
				sectname: "__const",
				data: constData,
				relocs: [
					{ address: 0, symbolnum: 2, type: X86_GOT, length: 2, pcrel: true },
					{ address: 4, symbolnum: 3, type: X86_SUBTRACTOR, length: 2 },
					{ address: 4, symbolnum: 0, type: 0, length: 2 }
				]
			},
			{ segname: "__TEXT", sectname: "__cstring", data: new TextEncoder().encode("hi\0") }
		]
	});
	const [textAddr, constAddr, cstrAddr] = sectionAddrs as [number, number, number];
	const text = sections[0]!;
	const got = image.segments.find((s) => s.sections[0]?.sectname === "__got")!;
	const disp = (at: number) => view.getInt32(text.offset + at, true);

	it("resolves RIP-relative displacements, including the SIGNED_1 bias", () => {
		expect(textAddr + 3 + 4 + disp(3)).toBe(cstrAddr);
		// movb has a trailing imm8, so RIP is one byte further on
		expect(textAddr + 16 + 5 + disp(16)).toBe(cstrAddr);
		expect(textAddr + 22 + 4 + disp(22)).toBe(textAddr + 0x20);
	});

	it("leaves section-relative displacements untouched", () => {
		expect(disp(26)).toBe(0x1234);
	});

	it("routes GOT references through a bound slot", () => {
		expect(textAddr + 10 + 4 + disp(10)).toBe(Number(got.vmaddr));
		const constValue = view.getInt32(sections[1]!.offset, true);
		expect(constAddr + constValue).toBe(Number(got.vmaddr) + 1);
		expect(image.bindMap.get(Number(got.fileoff))?.symbolName).toBe("_ext");
	});

	it("resolves A - B relative offsets", () => {
		expect(view.getInt32(sections[1]!.offset + 4, true)).toBe(cstrAddr - constAddr);
	});
});

describe("buildObjectImage (armv7 / i386)", () => {
	it("resolves symbol pointers and records absolute ones, leaving precomputed values", () => {
		const data = new Uint8Array(0x18);
		const dv = new DataView(data.buffer);
		dv.setUint32(0, 2, true); // addend: l_.str + 2
		dv.setUint32(0x10, 0x1234, true); // section difference, already final
		// Section-relative and scattered pointers hold the target address; the string
		// section sits at 0x20 once laid out after this 0x18-byte section
		dv.setUint32(0x8, 0x20, true);
		dv.setUint32(0xc, 0x21, true);
		const { image, view, sections, sectionAddrs } = build({
			cputype: CPU_TYPE_ARM,
			bits32: true,
			symbols: [
				{ name: "l_.str", sect: 2 },
				{ name: "_OBJC_CLASS_$_NSObject", sect: 0 }
			],
			sections: [
				{
					segname: "__DATA",
					sectname: "__data",
					data,
					relocs: [
						{ address: 0, symbolnum: 0, type: 0, length: 2 },
						{ address: 4, symbolnum: 1, type: 0, length: 2 },
						{ address: 8, symbolnum: 2, type: 0, length: 2, extern: false },
						{
							address: 0xc,
							symbolnum: 0,
							type: 0,
							length: 2,
							scattered: true,
							value: 0x20
						},
						{
							address: 0x10,
							symbolnum: 0,
							type: 2,
							length: 2,
							scattered: true,
							value: 0x20
						},
						{ address: 0, symbolnum: 0, type: 1, length: 2, scattered: true, value: 0 }
					]
				},
				{ segname: "__TEXT", sectname: "__cstring", data: new TextEncoder().encode("hi\0") }
			]
		});
		const base = sections[0]!.offset;
		const str = sectionAddrs[1]!;
		expect(str).toBe(0x20);
		expect(image.rebaseMap.get(base)).toBe(BigInt(str + 2));
		expect(view.getUint32(base, true)).toBe(str + 2);
		expect(image.bindMap.get(base + 4)?.symbolName).toBe("_OBJC_CLASS_$_NSObject");
		expect(image.rebaseMap.get(base + 8)).toBe(BigInt(str));
		expect(image.rebaseMap.get(base + 0xc)).toBe(BigInt(str + 1));
		expect(view.getUint32(base + 0x10, true)).toBe(0x1234);
		expect(image.rebaseMap.has(base + 0x10)).toBe(false);
	});
});

describe("buildObjectImage (edge cases)", () => {
	it("only regroups segments for architectures it cannot relocate", () => {
		const { buffer, image } = build({
			cputype: CPU_TYPE_ARM,
			symbols: [{ name: "_x", sect: 1 }],
			sections: [
				{
					segname: "__DATA",
					sectname: "__data",
					data: new Uint8Array(8),
					relocs: [{ address: 0, symbolnum: 0, type: UNSIGNED, length: 3 }]
				}
			]
		});
		expect(image.buffer).toBe(buffer);
		expect(image.rebaseMap.size).toBe(0);
		expect(image.segments.map((s) => s.segname)).toEqual(["__DATA"]);
	});

	it("skips relocations outside their section and unknown symbols", () => {
		const { image, view, sections } = build({
			cputype: CPU_TYPE_ARM64,
			symbols: [{ name: "_x", sect: 1 }],
			sections: [
				{
					segname: "__DATA",
					sectname: "__data",
					data: new Uint8Array(8),
					relocs: [
						{ address: 4, symbolnum: 0, type: UNSIGNED, length: 3 },
						{ address: 0, symbolnum: 99, type: UNSIGNED, length: 3 },
						{ address: 0, symbolnum: 99, type: SUBTRACTOR, length: 2 }
					]
				}
			]
		});
		expect(image.rebaseMap.size).toBe(0);
		expect(image.bindMap.size).toBe(0);
		expect(view.getBigUint64(sections[0]!.offset, true)).toBe(0n);
	});
});

describe("object files through the readers", () => {
	it("attributes string references to the real function, not the section label", () => {
		const { image, lc } = build({
			cputype: CPU_TYPE_ARM64,
			symbols: [
				{ name: "ltmp0", sect: 1 },
				{ name: "_main", sect: 1, external: true },
				{ name: "l_.str", sect: 2 }
			],
			sections: [
				{
					segname: "__TEXT",
					sectname: "__text",
					flags: S_ATTR_CODE,
					data: words(0x90000000, 0x91000000, 0xd65f03c0),
					relocs: [
						{ address: 0, symbolnum: 2, type: PAGE21, length: 2, pcrel: true },
						{ address: 4, symbolnum: 2, type: PAGEOFF12, length: 2 }
					]
				},
				{
					segname: "__TEXT",
					sectname: "__cstring",
					data: new TextEncoder().encode("secret\0")
				}
			]
		});
		const symbols = parseSymbolTable(image.buffer, lc.symtabInfo, true, true);
		const cstring = image.segments[0]!.sections[1]!;
		const xrefs = buildStringXrefMap(
			image.buffer,
			image.segments,
			[],
			symbols,
			true,
			image.rebaseMap,
			CPU_TYPE_ARM64,
			true
		);
		expect(xrefs.get(cstring.offset)).toEqual(["_main"]);
	});

	it("attributes x86_64 RIP-relative loads, including Swift's biased literals", () => {
		const code = new Uint8Array(0x20);
		code.set([0x48, 0x8d, 0x05], 0); // _c: lea rax, [rip + l_.str]
		code.set([0xc3], 7);
		code.set([0x48, 0x8d, 0x05], 0x10); // _$sSwift: lea rax, [rip + l_.str.1 - 32]
		new DataView(code.buffer).setInt32(0x13, -32, true);
		const { image, lc } = build({
			cputype: CPU_TYPE_X86_64,
			symbols: [
				{ name: "_c", sect: 1, external: true },
				{ name: "_$s4Demo5swiftyyF", sect: 1, offset: 0x10, external: true },
				{ name: "l_.str", sect: 2 },
				{ name: "l_.str.1", sect: 2, offset: 0x20 }
			],
			sections: [
				{
					segname: "__TEXT",
					sectname: "__text",
					flags: S_ATTR_CODE,
					data: code,
					relocs: [
						{ address: 3, symbolnum: 2, type: X86_SIGNED, length: 2, pcrel: true },
						{ address: 0x13, symbolnum: 3, type: X86_SIGNED, length: 2, pcrel: true }
					]
				},
				{
					segname: "__TEXT",
					sectname: "__cstring",
					data: new TextEncoder().encode(
						`${"c string".padEnd(31, "\0")}\0swift literal\0`
					)
				}
			]
		});
		const symbols = parseSymbolTable(image.buffer, lc.symtabInfo, true, true);
		const cstring = image.segments[0]!.sections[1]!;
		const xrefs = buildStringXrefMap(
			image.buffer,
			image.segments,
			[],
			symbols,
			true,
			image.rebaseMap,
			CPU_TYPE_X86_64,
			true
		);
		expect(xrefs.get(cstring.offset)).toEqual(["_c"]);
		expect(xrefs.get(cstring.offset + 0x20)).toEqual(["_$s4Demo5swiftyyF"]);
	});
});
