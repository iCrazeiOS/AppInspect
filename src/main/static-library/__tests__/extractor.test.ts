import { afterAll, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { CPU_TYPE_ARM64, CPU_TYPE_X86_64 } from "../../../shared/arch";
import { arArchive, buildObjectFile } from "../../parser/__tests__/fixtures";
import { parseFatHeader, parseMachOHeader } from "../../parser/macho";
import {
	extractStaticLibrary,
	isStaticLibraryFile,
	listStaticLibraryMembers,
	memberArchitectures
} from "../extractor";

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "appinspect-staticlib-"));
afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

function object(cputype: number): Uint8Array {
	const { buffer } = buildObjectFile({
		cputype,
		sections: [{ segname: "__TEXT", sectname: "__text", data: new Uint8Array(4) }]
	});
	return new Uint8Array(buffer);
}

/** A universal file whose slices are the given (cputype, archive) pairs. */
function fatLibrary(slices: [number, Uint8Array][]): Uint8Array {
	const align = 0x1000;
	let offset = align;
	const placed = slices.map(([cputype, data]) => {
		const at = offset;
		offset = Math.ceil((at + data.length) / align) * align;
		return { cputype, data, at };
	});
	const out = Buffer.alloc(offset);
	out.writeUInt32BE(0xcafebabe, 0);
	out.writeUInt32BE(placed.length, 4);
	placed.forEach((s, i) => {
		const base = 8 + i * 20;
		out.writeUInt32BE(s.cputype, base);
		out.writeUInt32BE(0, base + 4);
		out.writeUInt32BE(s.at, base + 8);
		out.writeUInt32BE(s.data.length, base + 12);
		out.writeUInt32BE(12, base + 16);
		out.set(s.data, s.at);
	});
	return out;
}

function write(name: string, bytes: Uint8Array): string {
	const file = path.join(dir, name);
	fs.writeFileSync(file, bytes);
	return file;
}

describe("isStaticLibraryFile", () => {
	it("accepts thin and universal static libraries", () => {
		const thin = arArchive([{ name: "a.o", data: object(CPU_TYPE_ARM64) }]);
		expect(isStaticLibraryFile(write("thin.a", thin))).toBe(true);
		const fat = fatLibrary([
			[CPU_TYPE_ARM64, thin],
			[CPU_TYPE_X86_64, arArchive([{ name: "a.o", data: object(CPU_TYPE_X86_64) }])]
		]);
		expect(isStaticLibraryFile(write("fat.a", fat))).toBe(true);
	});

	it("rejects Debian packages, Mach-O images and other files", () => {
		const deb = arArchive([{ name: "debian-binary", data: "2.0\n" }]);
		expect(isStaticLibraryFile(write("pkg.deb", deb))).toBe(false);
		expect(isStaticLibraryFile(write("obj.o", object(CPU_TYPE_ARM64)))).toBe(false);
		expect(isStaticLibraryFile(write("junk.a", new Uint8Array(64)))).toBe(false);
	});
});

describe("extractStaticLibrary", () => {
	it("writes each Mach-O member, skipping the symbol table and bitcode", async () => {
		const lib = write(
			"members.a",
			arArchive([
				{ name: "__.SYMDEF SORTED", data: "symbols", style: "bsd" },
				{ name: "Zeta.o", data: object(CPU_TYPE_ARM64) },
				{ name: "a-long-member-name.o", data: object(CPU_TYPE_ARM64), style: "bsd" },
				{ name: "Zeta.o", data: object(CPU_TYPE_ARM64) },
				{ name: "zeta.o", data: object(CPU_TYPE_ARM64) },
				{ name: "bitcode.o", data: new Uint8Array([0x42, 0x43, 0xc0, 0xde]) }
			])
		);
		const dest = path.join(dir, "members");
		expect(await extractStaticLibrary(lib, dest)).toEqual({ success: true });
		const members = listStaticLibraryMembers(dest);
		// Duplicates are numbered, case-insensitively so no file overwrites another
		expect(members.map((m) => m.name)).toEqual([
			"a-long-member-name.o",
			"Zeta (2).o",
			"zeta (3).o",
			"Zeta.o"
		]);
		const header = parseMachOHeader(new Uint8Array(fs.readFileSync(members[0]!.path)).buffer);
		expect(header.ok && header.data.header.filetype).toBe(1);
	});

	it("keeps member files inside the destination", async () => {
		const lib = write(
			"evil.a",
			arArchive([{ name: "../../escape.o", data: object(CPU_TYPE_ARM64), style: "bsd" }])
		);
		const dest = path.join(dir, "evil");
		expect(await extractStaticLibrary(lib, dest)).toEqual({ success: true });
		const [member] = listStaticLibraryMembers(dest);
		expect(path.dirname(member!.path)).toBe(dest);
		expect(member!.name).not.toContain("/");
	});

	it("joins a member's architecture slices into one universal object", async () => {
		const lib = write(
			"universal.a",
			fatLibrary([
				[
					CPU_TYPE_ARM64,
					arArchive([
						{ name: "Shared.o", data: object(CPU_TYPE_ARM64) },
						{ name: "ArmOnly.o", data: object(CPU_TYPE_ARM64) }
					])
				],
				[CPU_TYPE_X86_64, arArchive([{ name: "Shared.o", data: object(CPU_TYPE_X86_64) }])]
			])
		);
		const dest = path.join(dir, "universal");
		expect(await extractStaticLibrary(lib, dest)).toEqual({ success: true });
		const members = listStaticLibraryMembers(dest);
		expect(members.map((m) => m.name)).toEqual(["ArmOnly.o", "Shared.o"]);

		const shared = new Uint8Array(fs.readFileSync(members[1]!.path)).buffer;
		const fat = parseFatHeader(shared);
		if (!fat.ok) throw new Error(fat.error);
		expect(fat.data.map((a) => a.cputype)).toEqual([CPU_TYPE_ARM64, CPU_TYPE_X86_64]);
		for (const slice of fat.data) {
			const header = parseMachOHeader(shared.slice(slice.offset, slice.offset + slice.size));
			expect(header.ok && header.data.header.cputype).toBe(slice.cputype);
		}
		expect(memberArchitectures(members)).toEqual(["arm64", "x86_64"]);
	});

	it("fails when no member is a Mach-O object", async () => {
		const lib = write("empty.a", arArchive([{ name: "notes.txt", data: "hello" }]));
		const result = await extractStaticLibrary(lib, path.join(dir, "empty"));
		expect(result.success).toBe(false);
		expect(fs.existsSync(path.join(dir, "empty"))).toBe(false);
	});
});
