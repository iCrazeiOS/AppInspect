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
function writeLibrary(): string {
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
	const file = path.join(dir, "libDemo.a");
	fs.writeFileSync(file, out);
	cacheDirs.push(getCacheDir(file));
	return file;
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
