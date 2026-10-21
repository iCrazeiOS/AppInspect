/**
 * Binary size breakdown.
 *
 * Splits a Mach-O slice into segments and sections, then attributes section
 * bytes to modules. Every defined symbol (plus every LC_FUNCTION_STARTS entry
 * in code sections) opens a range that runs to the next one, and the range's
 * symbol name decides its module: Swift module, C++ namespace, ObjC class
 * prefix, or C library prefix.
 *
 * Release builds strip most local names. The linker lays each object file out
 * contiguously, so an unnamed run sandwiched between two ranges of the same
 * module is assigned to that module and counted as "inferred".
 */

import type { SizeBreakdown, SizeModule, SizeModuleKind, SizeSegment } from "../../shared/types";
import type { LoadCommandsResult, Section64 } from "../parser/load-commands";
import { demangleSwiftSymbol } from "../parser/swift-demangle";
import type { SymbolEntry } from "../parser/symbols";
import { formatFunctionName } from "../parser/xrefs";

const SECTION_TYPE_MASK = 0xff;
/** S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL — occupy no file bytes */
const ZEROFILL_TYPES = new Set([0x1, 0xc, 0x12]);
const S_ATTR_PURE_INSTRUCTIONS = 0x80000000;
const S_ATTR_SOME_INSTRUCTIONS = 0x400;
const TOP_SYMBOL_COUNT = 10;
const UNATTRIBUTED = "Unattributed";

/** Symbol prefixes (text before the first "_", lowercased) of commonly statically-linked C libraries. */
const C_LIBRARY_PREFIXES = new Map<string, string>([
	["sqlite3", "SQLite"],
	["png", "libpng"],
	["jpeg", "libjpeg"],
	["webp", "libwebp"],
	["curl", "libcurl"],
	["ffi", "libffi"],
	["mbedtls", "Mbed TLS"],
	["swift", "Swift runtime"],
	["kotlin", "Kotlin/Native runtime"]
]);
for (const prefix of [
	"a2d",
	"a2i",
	"aes",
	"armv7",
	"armv8",
	"asn1",
	"async",
	"b2i",
	"bf",
	"bignum",
	"bio",
	"blake2",
	"bn",
	"buf",
	"camellia",
	"cast",
	"chacha20",
	"cmac",
	"cms",
	"comp",
	"conf",
	"crl",
	"crypto",
	"ct",
	"ctlog",
	"d2i",
	"des",
	"dh",
	"dhparams",
	"dsa",
	"dsaparams",
	"dso",
	"dtls",
	"dtls1",
	"ec",
	"ecdh",
	"ecdsa",
	"ecp",
	"ecparameters",
	"ecpkparameters",
	"ecx",
	"ed25519",
	"ed448",
	"engine",
	"err",
	"ess",
	"evp",
	"gcm",
	"gf",
	"hmac",
	"i2a",
	"i2b",
	"i2d",
	"i2o",
	"i2s",
	"i2t",
	"i2v",
	"idea",
	"md4",
	"md5",
	"mdc2",
	"nconf",
	"o2i",
	"obj",
	"ocsp",
	"openssl",
	"ossl",
	"pem",
	"pkcs1",
	"pkcs12",
	"pkcs5",
	"pkcs7",
	"pkcs8",
	"poly1305",
	"rand",
	"rc2",
	"rc4",
	"rc5",
	"ripemd160",
	"rsa",
	"s2i",
	"scrypt",
	"sct",
	"seed",
	"sha1",
	"sha224",
	"sha256",
	"sha3",
	"sha384",
	"sha512",
	"siphash",
	"sm2",
	"sm3",
	"sm4",
	"smime",
	"srp",
	"ssl",
	"ssl3",
	"sxnet",
	"tls",
	"tls1",
	"ui",
	"v2i",
	"vpaes",
	"whirlpool",
	"wpacket",
	"x25519",
	"x448",
	"x509",
	"x509at",
	"x509v3",
	"x9"
]) {
	C_LIBRARY_PREFIXES.set(prefix, "OpenSSL / BoringSSL");
}

/** Top-level domains that start reverse-DNS Kotlin packages (group by 3 segments). */
const REVERSE_DNS_ROOTS = new Set([
	"com",
	"org",
	"io",
	"net",
	"dev",
	"app",
	"me",
	"co",
	"uk",
	"de"
]);

/** ObjC metadata symbol infixes between "$_" and the class/protocol name. */
const OBJC_METADATA_INFIX =
	/^(?:PROTOCOL_(?:INSTANCE|CLASS)_METHODS_(?:OPT_)?|PROTOCOL_METHOD_TYPES_|PROTOCOL_REFS_|PROTOCOL_PROP_LIST_|CATEGORY_(?:INSTANCE_METHODS_|CLASS_METHODS_|PROP_LIST_)?|INSTANCE_METHODS_|CLASS_METHODS_|INSTANCE_VARIABLES_|CLASS_PROP_LIST_|PROP_LIST_|CLASS_PROTOCOLS_|PROTOCOL_)/;

/** Raw names that carry no module information: assembler temporaries, local labels, tables. */
const UNNAMED_SYMBOL = /^(?:<redacted|l?tmp\d|l_|L_|lCPI|LCPI|Lloh|GCC_except_table)/;

interface ModuleKey {
	name: string;
	kind: SizeModuleKind;
}

/** Read a Swift/Itanium length-prefixed identifier ("9ReadID_UI..." → "ReadID_UI"). */
function readIdentifier(s: string): string | null {
	const digits = /^[1-9]\d*/.exec(s)?.[0];
	if (!digits) return null;
	const len = Number(digits);
	const id = s.slice(digits.length, digits.length + len);
	return id.length === len ? id : null;
}

/** Module of a Swift mangled name, given the text after the "$s" / "_T0" prefix. */
function swiftModule(mangled: string): ModuleKey {
	const id = readIdentifier(mangled);
	if (id) return { name: id, kind: "swift" };
	if (mangled.startsWith("So") || mangled.startsWith("SC")) {
		return { name: "Swift (ObjC/C interop)", kind: "swift" };
	}
	// "s" is the Swift module; "S<x>" are stdlib type substitutions (Array, String, ...)
	if (mangled.startsWith("s") || mangled.startsWith("S")) {
		return { name: "Swift stdlib (specialised)", kind: "swift" };
	}
	return { name: "Swift (other)", kind: "swift" };
}

/** Group an Objective-C class by its leading uppercase prefix ("FIRApp" → "FIR*"). */
function objcModule(className: string): ModuleKey {
	// Swift classes exposed to ObjC: _TtC9ReadID_UI10CornerView, _TtGC..., or Module.Class
	if (className.startsWith("_Tt")) {
		const rest = className.slice(3).replace(/^[A-Z]+/, "");
		return rest.startsWith("s") ? { name: "Swift", kind: "swift" } : swiftModule(rest);
	}
	const dot = className.indexOf(".");
	if (dot > 0) return { name: className.slice(0, dot), kind: "swift" };

	// The last capital of the run starts the next word: "FIRApp" → "FIR", "SDWebImage" → "SD"
	const run = /^[A-Z]+/.exec(className)?.[0] ?? "";
	if (run.length < 2) return { name: "ObjC (unprefixed classes)", kind: "objc" };
	const prefix = run.length === 2 ? run : run.slice(0, Math.min(run.length - 1, 3));
	return { name: `${prefix}*`, kind: "objc" };
}

/** Group a Kotlin/Native declaration path ("com.squareup.wire.ProtoAdapter") by package. */
function kotlinModule(declaration: string): ModuleKey {
	const segments = declaration.split(".");
	const packages: string[] = [];
	for (const segment of segments) {
		if (!/^[a-z]/.test(segment)) break;
		packages.push(segment);
	}
	const root = packages[0];
	if (!root) return { name: "Kotlin (other)", kind: "kotlin" };
	if (root === "kotlin") return { name: "kotlin (stdlib)", kind: "kotlin" };
	const depth = REVERSE_DNS_ROOTS.has(root) ? 3 : root === "kotlinx" ? 2 : 1;
	return { name: packages.slice(0, depth).join("."), kind: "kotlin" };
}

/** Namespace (or class) of an Itanium-mangled C++ name, given the text after "_Z". */
function cppModule(mangled: string): ModuleKey {
	let rest = mangled;
	let nested = false;
	// vtable / typeinfo / typeinfo name are followed by the type's name
	if (/^T[VIS]/.test(rest)) {
		rest = rest.slice(2);
		nested = true;
	}
	if (rest.startsWith("N")) {
		rest = rest.slice(1).replace(/^[rVKRO]+/, "");
		nested = true;
	}
	if (rest.startsWith("S")) return { name: "std", kind: "cpp" };
	const id = nested ? readIdentifier(rest) : null;
	if (!id) return { name: "C++ (global)", kind: "cpp" };
	if (id.startsWith("_GLOBAL__N")) return { name: "C++ (anonymous namespace)", kind: "cpp" };
	if (id === "kotlin") return { name: "Kotlin/Native runtime", kind: "kotlin" };
	return { name: id, kind: "cpp" };
}

function classifyName(name: string): ModuleKey {
	if (name.startsWith("-[") || name.startsWith("+[")) {
		// Categories count towards the category's prefix: -[UIView(SDWebImage) sd_setImage]
		const body = name.slice(2);
		const category = /^[^ (]+\(([^)]+)\)/.exec(body)?.[1];
		const target = category && /^[A-Z]{2}/.test(category) ? category : body.split(/[ (]/)[0]!;
		return objcModule(target);
	}
	if (name.startsWith("$s") || name.startsWith("$S") || name.startsWith("$e")) {
		return swiftModule(name.slice(2));
	}
	if (name.startsWith("_T0")) return swiftModule(name.slice(3));
	if (name.startsWith("_Z")) return cppModule(name.slice(2));

	// Swift metadata references: "symbolic _____ 9ReadID_UI8DocumentV"
	const symbolic =
		/^(?:symbolic|associated conformance|get_type_metadata|get_witness_table) [_ ]*/.exec(name);
	if (symbolic) return swiftModule(name.slice(symbolic[0].length));

	// Kotlin/Native: kfun:com.example.Foo#bar(){}, kclass:..., plus ObjC bridges
	const kotlin = /^(?:objc2kotlin_|kotlin2objc_)?(?:virtual_)?k[a-z]*:([^#(]+)/.exec(name);
	if (kotlin) return kotlinModule(kotlin[1]!);

	// ObjC metadata: OBJC_CLASS_$_Foo, _OBJC_$_INSTANCE_METHODS_Foo, OBJC_IVAR_$_Foo.bar
	const objcMetadata = /^_?OBJC_[A-Z_]*\$_(.+)$/.exec(name);
	if (objcMetadata) {
		const [target, category] = objcMetadata[1]!.replace(OBJC_METADATA_INFIX, "").split("_$_");
		const owner = category && /^[A-Z]{2}/.test(category) ? category : target!;
		return objcModule(owner.split(".")[0]!);
	}

	const cName = name.replace(/^_+/, "");
	const underscore = cName.indexOf("_", 1);
	if (underscore > 0) {
		const prefix = cName.slice(0, underscore);
		const library = C_LIBRARY_PREFIXES.get(prefix.toLowerCase());
		if (library) {
			return { name: library, kind: library.startsWith("Kotlin") ? "kotlin" : "c" };
		}
		if (prefix.length >= 2) return { name: `${prefix}_*`, kind: "c" };
	}
	return { name: "C (other)", kind: "c" };
}

/**
 * Module a raw Mach-O symbol belongs to, or null when the name carries no
 * information (redacted, assembler temporaries, outlined fragments).
 */
export function classifySymbol(raw: string): ModuleKey | null {
	if (raw.length === 0 || UNNAMED_SYMBOL.test(raw) || raw.includes("OUTLINED_FUNCTION")) {
		return null;
	}

	// Drop the C-level underscore Mach-O prepends to every symbol
	const name = raw.startsWith("_") ? raw.slice(1) : raw;
	if (/^_*unnamed_\d/.test(name)) return null;

	// Kotlin/Native block bridges and C-function stubs hex-encode "module:/path/to/kotlin/com/example/File.kt":
	// ____<hex>_13_knbridge1_block_invoke
	const knBridge = /^_*((?:[0-9a-f]{2})+)_\d+_kn(?:bridge|cfun)/.exec(name);
	if (knBridge) {
		const source = Buffer.from(knBridge[1]!, "hex").toString("latin1");
		const kotlinDir = source.indexOf("/kotlin/");
		if (kotlinDir >= 0) {
			return kotlinModule(
				source
					.slice(kotlinDir + "/kotlin/".length)
					.split("/")
					.join(".")
			);
		}
		const colon = source.indexOf(":");
		return { name: colon > 0 ? source.slice(0, colon) : "Kotlin (other)", kind: "kotlin" };
	}

	// Blocks are named after their enclosing function: ___45-[Foo bar]_block_invoke
	if (name.includes("_block_invoke")) {
		const inner = /[-+]\[[^\]]+\]|\$s\w+|_Z\w+/.exec(name)?.[0];
		return inner ? classifyName(inner) : { name: "C (other)", kind: "c" };
	}
	return classifyName(name);
}

function fileBytes(section: Section64): number {
	return ZEROFILL_TYPES.has(section.flags & SECTION_TYPE_MASK) ? 0 : Number(section.size);
}

function isCodeSection(section: Section64): boolean {
	return (section.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)) !== 0;
}

function buildSegments(lc: LoadCommandsResult, is64Bit: boolean): SizeSegment[] {
	return lc.segments.map((seg) => {
		const name = seg.segname.trim();
		const fileSize = Number(seg.filesize);
		const sections = seg.sections.map((sec) => ({
			name: sec.sectname.trim(),
			size: fileBytes(sec)
		}));

		// __LINKEDIT has no sections; split it into the blobs the load commands describe
		if (name === "__LINKEDIT") {
			const symtab = lc.symtabInfo;
			const blobs: [string, number][] = [
				["Symbol table", symtab ? symtab.nsyms * (is64Bit ? 16 : 12) : 0],
				["String table", symtab?.strsize ?? 0],
				["Code signature", lc.codeSignatureInfo?.size ?? 0],
				["Chained fixups", lc.chainedFixupsInfo?.size ?? 0],
				["Function starts", lc.functionStartsInfo?.size ?? 0],
				["Export trie", lc.exportTrieInfo?.size ?? 0]
			];
			for (const [blob, size] of blobs) {
				if (size > 0) sections.push({ name: blob, size });
			}
		}

		const remainder = fileSize - sections.reduce((sum, s) => sum + s.size, 0);
		if (remainder > 0) {
			const label =
				name === "__TEXT"
					? "Header, load commands & padding"
					: name === "__LINKEDIT"
						? "Other link-edit data"
						: "Padding";
			sections.push({ name: label, size: remainder });
		}
		sections.sort((a, b) => b.size - a.size);
		return { name, fileSize, vmSize: Number(seg.vmsize), sections };
	});
}

interface ModuleAccumulator {
	key: ModuleKey;
	size: number;
	codeSize: number;
	inferredSize: number;
	symbolCount: number;
	functions: { raw: string; size: number }[];
}

export function buildSizeBreakdown(
	lc: LoadCommandsResult,
	symbols: SymbolEntry[],
	functionStarts: bigint[],
	binarySize: number,
	is64Bit: boolean
): SizeBreakdown {
	const sections = lc.segments
		.flatMap((seg) => seg.sections)
		.filter((sec) => sec.size > 0n)
		.sort((a, b) => (a.addr < b.addr ? -1 : a.addr > b.addr ? 1 : 0));

	// Section containing an address (binary search). Export-trie entries carry
	// no section index, so every symbol is placed by address.
	const sectionAt = (addr: bigint): number => {
		let lo = 0;
		let hi = sections.length - 1;
		while (lo <= hi) {
			const mid = (lo + hi) >>> 1;
			const sec = sections[mid]!;
			if (addr < sec.addr) hi = mid - 1;
			else if (addr >= sec.addr + sec.size) lo = mid + 1;
			else return mid;
		}
		return -1;
	};

	// Range starts per section, preferring informative names when several
	// symbols share an address
	const startsBySection = new Map<number, Map<bigint, string>>();
	for (const sym of symbols) {
		if (sym.type === "imported") continue;
		const index = sectionAt(sym.address);
		if (index < 0) continue;
		let starts = startsBySection.get(index);
		if (!starts) {
			starts = new Map();
			startsBySection.set(index, starts);
		}
		const existing = starts.get(sym.address);
		if (existing === undefined || (!classifySymbol(existing) && classifySymbol(sym.name))) {
			starts.set(sym.address, sym.name);
		}
	}

	const modules = new Map<string, ModuleAccumulator>();
	const moduleFor = (key: ModuleKey): ModuleAccumulator => {
		let acc = modules.get(key.name);
		if (!acc) {
			acc = { key, size: 0, codeSize: 0, inferredSize: 0, symbolCount: 0, functions: [] };
			modules.set(key.name, acc);
		}
		return acc;
	};

	let sectionSize = 0;
	let codeSectionSize = 0;
	let attributedSize = 0;
	let attributedCode = 0;

	for (let i = 0; i < sections.length; i++) {
		const section = sections[i]!;
		const size = fileBytes(section);
		if (size === 0) continue;
		const isCode = isCodeSection(section);
		sectionSize += size;
		if (isCode) codeSectionSize += size;

		const start = section.addr;
		const end = section.addr + section.size;
		const starts = new Map(startsBySection.get(i));
		if (isCode) {
			for (const addr of functionStarts) {
				if (addr >= start && addr < end && !starts.has(addr)) starts.set(addr, "");
			}
		}
		const addrs = [...starts.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

		const attribute = (acc: ModuleAccumulator, bytes: number) => {
			acc.size += bytes;
			attributedSize += bytes;
			if (isCode) {
				acc.codeSize += bytes;
				attributedCode += bytes;
			}
		};

		let previous: ModuleAccumulator | null = null;
		let pendingUnnamed = 0;
		for (let j = 0; j < addrs.length; j++) {
			const addr = addrs[j]!;
			const bytes = Number((addrs[j + 1] ?? end) - addr);
			const raw = starts.get(addr)!;
			const key = classifySymbol(raw);
			if (!key) {
				pendingUnnamed += bytes;
				continue;
			}
			const acc = moduleFor(key);
			if (previous === acc && pendingUnnamed > 0) {
				attribute(acc, pendingUnnamed);
				acc.inferredSize += pendingUnnamed;
			}
			pendingUnnamed = 0;
			previous = acc;
			attribute(acc, bytes);
			acc.symbolCount++;
			// Only code ranges are bounded by function starts; a data symbol's
			// range runs over whatever unnamed data follows it, so it isn't listed
			if (isCode) acc.functions.push({ raw, size: bytes });
		}
	}

	const result: SizeModule[] = [...modules.values()].map((acc) => ({
		name: acc.key.name,
		kind: acc.key.kind,
		size: acc.size,
		codeSize: acc.codeSize,
		inferredSize: acc.inferredSize,
		symbolCount: acc.symbolCount,
		topFunctions: acc.functions
			.sort((a, b) => b.size - a.size)
			.slice(0, TOP_SYMBOL_COUNT)
			.map((s) => ({
				name: demangleSwiftSymbol(s.raw) ?? formatFunctionName(s.raw),
				size: s.size
			}))
	}));

	const unattributed = sectionSize - attributedSize;
	if (unattributed > 0) {
		result.push({
			name: UNATTRIBUTED,
			kind: "unattributed",
			size: unattributed,
			codeSize: codeSectionSize - attributedCode,
			inferredSize: 0,
			symbolCount: 0,
			topFunctions: []
		});
	}
	result.sort((a, b) => b.size - a.size);

	return {
		binarySize,
		segments: buildSegments(lc, is64Bit),
		modules: result,
		attributedSize,
		sectionSize
	};
}

export const EMPTY_SIZE_BREAKDOWN: SizeBreakdown = {
	binarySize: 0,
	segments: [],
	modules: [],
	attributedSize: 0,
	sectionSize: 0
};
