import { describe, expect, it } from "bun:test";
import type { LoadCommandsResult, Section64, Segment64 } from "../../parser/load-commands";
import type { SymbolEntry } from "../../parser/symbols";
import { buildSizeBreakdown, classifySymbol } from "../size-breakdown";

// ── Helpers ──

const S_ATTR_PURE_INSTRUCTIONS = 0x80000000;
const S_ZEROFILL = 0x1;

function section(sectname: string, addr: number, size: number, flags = 0): Section64 {
	return {
		sectname,
		segname: "",
		addr: BigInt(addr),
		size: BigInt(size),
		offset: 0,
		align: 0,
		reloff: 0,
		nreloc: 0,
		flags,
		reserved1: 0,
		reserved2: 0,
		reserved3: 0
	};
}

function segment(
	segname: string,
	vmaddr: number,
	filesize: number,
	sections: Section64[]
): Segment64 {
	return {
		cmd: 0x19,
		cmdsize: 0,
		segname,
		vmaddr: BigInt(vmaddr),
		vmsize: BigInt(filesize),
		fileoff: 0n,
		filesize: BigInt(filesize),
		maxprot: 0,
		initprot: 0,
		nsects: sections.length,
		flags: 0,
		sections
	};
}

function loadCommands(
	segments: Segment64[],
	extra: Partial<LoadCommandsResult> = {}
): LoadCommandsResult {
	return {
		segments,
		loadCommands: [],
		libraries: [],
		encryption: null,
		uuid: null,
		buildVersion: null,
		symtabInfo: null,
		codeSignatureInfo: null,
		chainedFixupsInfo: null,
		functionStartsInfo: null,
		exportTrieInfo: null,
		...extra
	};
}

function sym(name: string, address: number, type: SymbolEntry["type"] = "local"): SymbolEntry {
	return { name, address: BigInt(address), type, sectionIndex: 0 };
}

// ── classifySymbol ──

describe("classifySymbol", () => {
	it("groups Swift symbols by module", () => {
		expect(classifySymbol("_$s9ReadID_UI10CornerViewC4drawyySo6CGRectVF")).toEqual({
			name: "ReadID_UI",
			kind: "swift"
		});
		expect(classifySymbol("_$sSa6appendyyxnF")?.name).toBe("Swift stdlib (specialised)");
		expect(classifySymbol("_symbolic _____ 9ReadID_UI8DocumentV")?.name).toBe("ReadID_UI");
	});

	it("maps Swift classes exposed to ObjC back to their module", () => {
		expect(classifySymbol("-[_TtC8Proxyman10FilterView drawRect:]")?.name).toBe("Proxyman");
		expect(classifySymbol("_OBJC_CLASS_$__TtC9ReadID_UI14VIZCaptureView")?.name).toBe(
			"ReadID_UI"
		);
	});

	it("groups ObjC classes, metadata and categories by prefix", () => {
		expect(classifySymbol("+[FIRApp configure]")).toEqual({ name: "FIR*", kind: "objc" });
		expect(classifySymbol("-[SDWebImageManager loadImage]")?.name).toBe("SD*");
		expect(classifySymbol("-[UIView(SDWebImage) sd_setImage]")?.name).toBe("SD*");
		expect(classifySymbol("__OBJC_$_INSTANCE_METHODS_GTMSessionFetcher")?.name).toBe("GTM*");
		expect(classifySymbol("-[ReportPageController load]")?.name).toBe(
			"ObjC (unprefixed classes)"
		);
	});

	it("groups C++ by namespace", () => {
		expect(classifySymbol("__ZN4absl7Mutex4LockEv")).toEqual({ name: "absl", kind: "cpp" });
		expect(classifySymbol("__ZNSt3__16vectorIiE9push_backEv")?.name).toBe("std");
		expect(classifySymbol("__ZTVN6google8protobuf7MessageE")?.name).toBe("google");
		expect(classifySymbol("__Z3foov")?.name).toBe("C++ (global)");
	});

	it("groups Kotlin/Native declarations by package", () => {
		expect(classifySymbol("_kfun:com.iproov.palms.ui.Foo#bar(){}")).toEqual({
			name: "com.iproov.palms",
			kind: "kotlin"
		});
		expect(classifySymbol("_objc2kotlin_virtual_kfun:kotlinx.coroutines.Job#x")?.name).toBe(
			"kotlinx.coroutines"
		);
		expect(classifySymbol("_kfun:kotlin.text.Regex#find")?.name).toBe("kotlin (stdlib)");
		// Block bridges hex-encode their source file: "sdk:/src/iosMain/kotlin/com/iproov/palms/ui/GhostHandView.kt"
		expect(
			classifySymbol(
				"____73646b3a2f7372632f696f734d61696e2f6b6f746c696e2f636f6d2f6970726f6f762f70616c6d732f75692f47686f737448616e64566965772e6b74_13_knbridge1_block_invoke"
			)?.name
		).toBe("com.iproov.palms");
		expect(
			classifySymbol(
				"____68616e64732e70616c6d733a47686f737448616e64566965772e6b74_2_knbridge1"
			)?.name
		).toBe("hands.palms");
	});

	it("recognises well-known C libraries and falls back to the name prefix", () => {
		expect(classifySymbol("_EVP_PKEY_new")?.name).toBe("OpenSSL / BoringSSL");
		expect(classifySymbol("_ecp_nistz256_mul")?.name).toBe("OpenSSL / BoringSSL");
		expect(classifySymbol("_sqlite3_open")?.name).toBe("SQLite");
		expect(classifySymbol("_mylib_init")).toEqual({ name: "mylib_*", kind: "c" });
		expect(classifySymbol("_main")?.name).toBe("C (other)");
	});

	it("classifies blocks by their enclosing function", () => {
		expect(classifySymbol("___45-[FIRApp configure]_block_invoke")?.name).toBe("FIR*");
	});

	it("treats names without module information as unnamed", () => {
		for (const name of [
			"<redacted>",
			"ltmp0",
			"_OUTLINED_FUNCTION_12",
			"GCC_except_table4",
			"___unnamed_126",
			""
		]) {
			expect(classifySymbol(name)).toBeNull();
		}
	});
});

// ── buildSizeBreakdown ──

describe("buildSizeBreakdown", () => {
	const text = section("__text", 0x1000, 0x100, S_ATTR_PURE_INSTRUCTIONS);
	const lc = loadCommands([segment("__TEXT", 0x0, 0x2000, [text])]);

	it("sizes each symbol up to the next range start and reports the remainder", () => {
		const result = buildSizeBreakdown(
			lc,
			[
				sym("_$s5AlphaA1fyyF", 0x1010),
				sym("_EVP_new", 0x1040),
				sym("_imported", 0, "imported")
			],
			[],
			0x2000,
			true
		);
		const byName = Object.fromEntries(result.modules.map((m) => [m.name, m]));
		expect(byName.Alpha!.size).toBe(0x30);
		expect(byName.Alpha!.codeSize).toBe(0x30);
		expect(byName["OpenSSL / BoringSSL"]!.size).toBe(0xc0);
		// The 0x10 bytes before the first symbol are unattributed
		expect(byName.Unattributed!.size).toBe(0x10);
		expect(result.attributedSize).toBe(0xf0);
		expect(result.sectionSize).toBe(0x100);
		expect(result.modules[0]!.name).toBe("OpenSSL / BoringSSL");
	});

	it("infers unnamed code sandwiched between ranges of the same module", () => {
		const result = buildSizeBreakdown(
			lc,
			[
				sym("_$s5AlphaA1fyyF", 0x1000),
				sym("_$s5AlphaA1gyyF", 0x1080),
				sym("_EVP_new", 0x10c0)
			],
			// Function starts with no symbols: two stripped functions between Alpha's,
			// one between Alpha and OpenSSL (ambiguous, left unattributed)
			[0x1000n, 0x1020n, 0x1050n, 0x1080n, 0x10a0n, 0x10c0n],
			0x2000,
			true
		);
		const alpha = result.modules.find((m) => m.name === "Alpha")!;
		expect(alpha.size).toBe(0x20 + 0x60 + 0x20);
		expect(alpha.inferredSize).toBe(0x60);
		expect(alpha.symbolCount).toBe(2);
		expect(result.modules.find((m) => m.name === "Unattributed")!.size).toBe(0x20);
	});

	it("places symbols by address, ignoring zero-fill sections", () => {
		const data = section("__data", 0x3000, 0x40);
		const bss = section("__bss", 0x3040, 0x1000, S_ZEROFILL);
		const result = buildSizeBreakdown(
			loadCommands([segment("__DATA", 0x3000, 0x40, [data, bss])]),
			[sym("_sqlite3_config", 0x3000), sym("_sqlite3_state", 0x3040)],
			[],
			0x40,
			true
		);
		expect(result.sectionSize).toBe(0x40);
		expect(result.modules).toEqual([
			expect.objectContaining({ name: "SQLite", size: 0x40, codeSize: 0, symbolCount: 1 })
		]);
		// Data symbol extents are unknown, so they never appear as largest functions
		expect(result.modules[0]!.topFunctions).toEqual([]);
	});

	it("splits __LINKEDIT into the blobs its load commands describe", () => {
		const result = buildSizeBreakdown(
			loadCommands(
				[segment("__TEXT", 0, 0x200, [text]), segment("__LINKEDIT", 0x4000, 0x1000, [])],
				{
					symtabInfo: {
						cmd: 2,
						cmdsize: 24,
						symoff: 0,
						nsyms: 10,
						stroff: 0,
						strsize: 0x100
					},
					codeSignatureInfo: { offset: 0, size: 0x400 }
				}
			),
			[],
			[],
			0x1200,
			true
		);
		const linkedit = result.segments.find((s) => s.name === "__LINKEDIT")!;
		expect(linkedit.sections).toEqual([
			{ name: "Other link-edit data", size: 0x1000 - 0x400 - 0x100 - 160 },
			{ name: "Code signature", size: 0x400 },
			{ name: "String table", size: 0x100 },
			{ name: "Symbol table", size: 160 }
		]);
		const textSegment = result.segments.find((s) => s.name === "__TEXT")!;
		expect(textSegment.sections).toContainEqual({
			name: "Header, load commands & padding",
			size: 0x100
		});
	});

	it("keeps the largest functions per module, demangled", () => {
		const result = buildSizeBreakdown(
			lc,
			[sym("-[FIRApp small]", 0x1000), sym("-[FIRApp big]", 0x1010)],
			[],
			0x2000,
			true
		);
		expect(result.modules[0]!.topFunctions).toEqual([
			{ name: "-[FIRApp big]", size: 0xf0 },
			{ name: "-[FIRApp small]", size: 0x10 }
		]);
	});
});
