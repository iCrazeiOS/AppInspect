import { afterEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { detectFileType } from "../../analysis/file-type";
import { buildFatHeader, buildMachHeader64 } from "../../parser/__tests__/fixtures";
import { CPU_TYPE_ARM64, CPU_TYPE_X86_64, MH_DYLIB } from "../../parser/macho";
import { discoverXCFramework, findXCFramework } from "../discovery";

const tempDirs: string[] = [];

function makeTempDir(): string {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "appinspect-test-xcf-"));
	tempDirs.push(dir);
	return dir;
}

afterEach(() => {
	for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

const DYLIB = Buffer.from(buildMachHeader64({ filetype: MH_DYLIB }));
const STATIC_LIB = Buffer.from(
	"!<arch>\n#1/20           0           0     0     644     8         `\n"
);

/** A universal static library: fat header whose slices are ar archives. */
function fatStaticLib(): Buffer {
	const fat = Buffer.from(
		buildFatHeader([
			{ cputype: CPU_TYPE_X86_64, cpusubtype: 3, offset: 64, size: 64, align: 3 },
			{ cputype: CPU_TYPE_ARM64, cpusubtype: 0, offset: 128, size: 64, align: 3 }
		])
	);
	const out = Buffer.alloc(192);
	fat.copy(out, 0);
	STATIC_LIB.copy(out, 64);
	STATIC_LIB.copy(out, 128);
	return out;
}

interface Lib {
	LibraryIdentifier: string;
	LibraryPath: string;
	BinaryPath?: string;
	SupportedPlatform: string;
	SupportedPlatformVariant?: string;
	SupportedArchitectures: string[];
}

function plistValue(value: unknown): string {
	if (Array.isArray(value)) return `<array>${value.map(plistValue).join("")}</array>`;
	if (typeof value === "object" && value !== null) {
		return `<dict>${Object.entries(value)
			.map(([k, v]) => `<key>${k}</key>${plistValue(v)}`)
			.join("")}</dict>`;
	}
	return `<string>${value}</string>`;
}

/** Write an .xcframework with the given libraries and binary contents. */
function buildXCFramework(root: string, libs: Lib[], files: Record<string, Buffer>): string {
	const xcf = path.join(root, "Kit.xcframework");
	fs.mkdirSync(xcf, { recursive: true });
	fs.writeFileSync(
		path.join(xcf, "Info.plist"),
		`<?xml version="1.0"?><plist version="1.0">${plistValue({ AvailableLibraries: libs })}</plist>`
	);
	for (const [rel, data] of Object.entries(files)) {
		const full = path.join(xcf, rel);
		fs.mkdirSync(path.dirname(full), { recursive: true });
		fs.writeFileSync(full, data);
	}
	return xcf;
}

const SIM: Lib = {
	LibraryIdentifier: "ios-arm64_x86_64-simulator",
	LibraryPath: "Kit.framework",
	BinaryPath: "Kit.framework/Kit",
	SupportedPlatform: "ios",
	SupportedPlatformVariant: "simulator",
	SupportedArchitectures: ["arm64", "x86_64"]
};
const DEVICE: Lib = {
	LibraryIdentifier: "ios-arm64",
	LibraryPath: "Kit.framework",
	BinaryPath: "Kit.framework/Kit",
	SupportedPlatform: "ios",
	SupportedArchitectures: ["arm64"]
};

describe("discoverXCFramework", () => {
	it("lists dynamic slices with device builds first and unique names", () => {
		const xcf = buildXCFramework(makeTempDir(), [SIM, DEVICE], {
			"ios-arm64_x86_64-simulator/Kit.framework/Kit": DYLIB,
			"ios-arm64/Kit.framework/Kit": DYLIB
		});
		const { slices, binaries } = discoverXCFramework(xcf);

		expect(binaries.map((b) => b.name)).toEqual([
			"Kit (ios-arm64)",
			"Kit (ios-arm64_x86_64-simulator)"
		]);
		expect(binaries[0]!.path).toBe(path.join(xcf, "ios-arm64", "Kit.framework", "Kit"));
		expect(slices.find((s) => s.identifier === SIM.LibraryIdentifier)).toMatchObject({
			platform: "ios",
			platformVariant: "simulator",
			architectures: ["arm64", "x86_64"],
			analysable: true
		});
	});

	it("resolves the framework binary when BinaryPath is omitted", () => {
		const { BinaryPath: _, ...noBinaryPath } = DEVICE;
		const xcf = buildXCFramework(makeTempDir(), [noBinaryPath], {
			"ios-arm64/Kit.framework/Kit": DYLIB
		});
		expect(discoverXCFramework(xcf).binaries).toHaveLength(1);
	});

	it("lists static libraries (thin and universal) but does not offer them for analysis", () => {
		const xcf = buildXCFramework(
			makeTempDir(),
			[
				{ ...DEVICE, LibraryPath: "libKit.a", BinaryPath: "libKit.a" },
				{ ...SIM, LibraryPath: "libKit.a", BinaryPath: "libKit.a" }
			],
			{
				"ios-arm64/libKit.a": STATIC_LIB,
				"ios-arm64_x86_64-simulator/libKit.a": fatStaticLib()
			}
		);
		const { slices, binaries } = discoverXCFramework(xcf);
		expect(slices).toHaveLength(2);
		expect(slices.every((s) => !s.analysable)).toBe(true);
		expect(binaries).toEqual([]);
	});

	it("skips slices whose paths escape the xcframework", () => {
		const root = makeTempDir();
		fs.writeFileSync(path.join(root, "outside"), DYLIB);
		const xcf = buildXCFramework(
			root,
			[
				{ ...DEVICE, BinaryPath: "../../outside" },
				{ ...SIM, LibraryIdentifier: "../.." }
			],
			{}
		);
		const { slices, binaries } = discoverXCFramework(xcf);
		expect(slices).toEqual([]);
		expect(binaries).toEqual([]);
	});

	it("throws when Info.plist is missing", () => {
		const xcf = path.join(makeTempDir(), "Empty.xcframework");
		fs.mkdirSync(xcf);
		expect(() => discoverXCFramework(xcf)).toThrow("missing Info.plist");
	});
});

describe("findXCFramework", () => {
	it("finds an xcframework nested below the extraction root", () => {
		const root = makeTempDir();
		const nested = path.join(root, "Users", "dev", "build", "Kit.xcframework");
		fs.mkdirSync(nested, { recursive: true });
		fs.mkdirSync(path.join(root, "__MACOSX", "Other.xcframework"), { recursive: true });
		expect(findXCFramework(root)).toBe(nested);
	});

	it("returns null when there is none", () => {
		const root = makeTempDir();
		fs.mkdirSync(path.join(root, "Payload"));
		expect(findXCFramework(root)).toBeNull();
	});
});

describe("detectFileType", () => {
	it("routes .xcframework directories", () => {
		const xcf = path.join(makeTempDir(), "Kit.xcframework");
		fs.mkdirSync(xcf);
		expect(detectFileType(xcf)).toBe("xcframework");
	});
});
