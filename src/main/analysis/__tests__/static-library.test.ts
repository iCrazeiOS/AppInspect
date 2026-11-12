import { afterAll, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { CPU_TYPE_ARM64, CPU_TYPE_X86_64 } from "../../../shared/arch";
import { arArchive, buildObjectFile } from "../../parser/__tests__/fixtures";
import { getCacheDir } from "../cache";
import { AnalysisSession } from "../session";

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "appinspect-staticlib-session-"));
const cacheDirs: string[] = [];
afterAll(() => {
	fs.rmSync(dir, { recursive: true, force: true });
	for (const cache of cacheDirs) fs.rmSync(cache, { recursive: true, force: true });
});

/** An object with one C string, so each member has something to report. */
function object(cputype: number, text: string): Uint8Array {
	const { buffer } = buildObjectFile({
		cputype,
		cpusubtype: cputype === CPU_TYPE_X86_64 ? 3 : 0,
		sections: [
			{ segname: "__TEXT", sectname: "__text", flags: 0x80000400, data: new Uint8Array(4) },
			{
				segname: "__TEXT",
				sectname: "__cstring",
				data: new TextEncoder().encode(`${text}\0`)
			}
		],
		symbols: [{ name: "_fn", sect: 1, external: true }]
	});
	return new Uint8Array(buffer);
}

/** A universal static library with an arm64 and an x86_64 archive. */
function universalLibrary(): Buffer {
	const arm = arArchive([
		{ name: "Beta.o", data: object(CPU_TYPE_ARM64, "beta arm64") },
		{ name: "Alpha.o", data: object(CPU_TYPE_ARM64, "alpha arm64") }
	]);
	const x86 = arArchive([
		{ name: "Beta.o", data: object(CPU_TYPE_X86_64, "beta x86_64") },
		{ name: "Alpha.o", data: object(CPU_TYPE_X86_64, "alpha x86_64") }
	]);
	const out = Buffer.alloc(0x1000 + Math.ceil(arm.length / 0x1000) * 0x1000 + x86.length);
	const x86Offset = 0x1000 + Math.ceil(arm.length / 0x1000) * 0x1000;
	out.writeUInt32BE(0xcafebabe, 0);
	out.writeUInt32BE(2, 4);
	for (const [i, cputype, offset, data] of [
		[0, CPU_TYPE_ARM64, 0x1000, arm],
		[1, CPU_TYPE_X86_64, x86Offset, x86]
	] as const) {
		out.writeUInt32BE(cputype, 8 + i * 20);
		out.writeUInt32BE(offset, 16 + i * 20);
		out.writeUInt32BE(data.length, 20 + i * 20);
		out.writeUInt32BE(12, 24 + i * 20);
		out.set(data, offset);
	}
	return out;
}

function writeLibrary(): string {
	const file = path.join(dir, "libDemo.a");
	fs.writeFileSync(file, universalLibrary());
	cacheDirs.push(getCacheDir(file));
	return file;
}

/** An .xcframework with a thin device static library and a universal simulator one. */
function writeXCFramework(): string {
	const xcf = path.join(dir, "Demo.xcframework");
	const slice = (id: string, archs: string[], variant?: string) =>
		`<dict><key>LibraryIdentifier</key><string>${id}</string>` +
		"<key>LibraryPath</key><string>libDemo.a</string>" +
		"<key>SupportedPlatform</key><string>ios</string>" +
		(variant ? `<key>SupportedPlatformVariant</key><string>${variant}</string>` : "") +
		`<key>SupportedArchitectures</key><array>${archs.map((a) => `<string>${a}</string>`).join("")}</array></dict>`;
	fs.mkdirSync(path.join(xcf, "ios-arm64"), { recursive: true });
	fs.mkdirSync(path.join(xcf, "ios-arm64_x86_64-simulator"), { recursive: true });
	fs.writeFileSync(
		path.join(xcf, "Info.plist"),
		'<?xml version="1.0"?><plist version="1.0"><dict><key>AvailableLibraries</key><array>' +
			slice("ios-arm64_x86_64-simulator", ["arm64", "x86_64"], "simulator") +
			slice("ios-arm64", ["arm64"]) +
			"</array></dict></plist>"
	);
	const device = path.join(xcf, "ios-arm64", "libDemo.a");
	fs.writeFileSync(
		device,
		arArchive([{ name: "Device.o", data: object(CPU_TYPE_ARM64, "device arm64") }])
	);
	const simulator = path.join(xcf, "ios-arm64_x86_64-simulator", "libDemo.a");
	fs.writeFileSync(simulator, universalLibrary());
	cacheDirs.push(getCacheDir(device), getCacheDir(simulator));
	return xcf;
}

describe("AnalysisSession static libraries", () => {
	const libPath = writeLibrary();

	it("lists each object file as a binary and analyses the first", async () => {
		const session = new AnalysisSession();
		const result = await session.analyseFile(libPath, () => {});
		expect(result.overview.sourceType).toBe("staticlib");
		expect(result.overview.ipa.appName).toBe("libDemo.a");
		expect(result.overview.ipa.binaries.map((b) => [b.name, b.type])).toEqual([
			["Alpha.o", "object"],
			["Beta.o", "object"]
		]);
		expect(result.overview.staticLibraryArchitectures).toEqual(["arm64", "x86_64"]);
		expect(result.overview.header.filetype).toBe(1);
		expect(result.overview.header.cputype).toBe(CPU_TYPE_ARM64);
		expect(result.strings.map((s) => s.value)).toEqual(["alpha arm64"]);
		expect(result.files.map((f) => f.name).sort()).toEqual(["Alpha.o", "Beta.o"]);

		const tree = session.getSizeTree();
		expect(tree.name).toBe("libDemo.a");
		expect(tree.children?.map((c) => c.name).sort()).toEqual(["Alpha.o", "Beta.o"]);
	});

	it("switches members and architecture slices", async () => {
		const session = new AnalysisSession();
		await session.analyseFile(libPath, () => {});
		const beta = await session.analyseBinary(1, () => {}, CPU_TYPE_X86_64);
		expect(beta.overview.header.cputype).toBe(CPU_TYPE_X86_64);
		expect(beta.strings.map((s) => s.value)).toEqual(["beta x86_64"]);
	});

	it("reuses the cached extraction", async () => {
		const session = new AnalysisSession();
		const result = await session.analyseFile(libPath, () => {});
		expect(result.overview.ipa.binaries).toHaveLength(2);
		expect(session.getCacheDirs()).toContain(getCacheDir(libPath));
	});
});

describe("AnalysisSession XCFramework static slices", () => {
	it("expands each static slice into its object files, device slice first", async () => {
		const session = new AnalysisSession();
		const result = await session.analyseFile(writeXCFramework(), () => {});
		expect(result.overview.sourceType).toBe("xcframework");
		expect(result.overview.ipa.binaries.map((b) => [b.name, b.type])).toEqual([
			["Device.o (ios-arm64)", "object"],
			["Alpha.o (ios-arm64_x86_64-simulator)", "object"],
			["Beta.o (ios-arm64_x86_64-simulator)", "object"]
		]);
		expect(result.strings.map((s) => s.value)).toEqual(["device arm64"]);
		expect(
			result.overview.xcframeworkLibraries?.map((l) => [l.analysable, l.isStatic])
		).toEqual([
			[true, true],
			[true, true]
		]);

		const beta = await session.analyseBinary(2, () => {});
		expect(beta.strings.map((s) => s.value)).toEqual(["beta arm64"]);
	});
});
