import { afterEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { zipSync } from "fflate";
import { buildMachHeader64 } from "../../parser/__tests__/fixtures";
import { getCacheDir } from "../cache";
import { detectFileType } from "../file-type";
import { discoverFolderBinaries } from "../folder";

const tempDirs: string[] = [];
const cacheDirs: string[] = [];

function makeTempDir(): string {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "appinspect-folder-"));
	tempDirs.push(dir);
	return dir;
}

afterEach(() => {
	for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
	for (const dir of cacheDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

const MACHO = Buffer.from(buildMachHeader64());

function write(root: string, relPath: string, data: Buffer = MACHO): string {
	const full = path.join(root, relPath);
	fs.mkdirSync(path.dirname(full), { recursive: true });
	fs.writeFileSync(full, data);
	return full;
}

const noop = () => {};

function arHeader(name: string, size: number): Buffer {
	return Buffer.from(
		name.padEnd(16, " ") +
			"0".padEnd(12, " ") +
			"0".padEnd(6, " ") +
			"0".padEnd(6, " ") +
			"100644".padEnd(8, " ") +
			String(size).padEnd(10, " ") +
			"`\n",
		"ascii"
	);
}

function buildDeb(files: Array<{ name: string; data: Buffer }>): Buffer {
	const parts: Buffer[] = [];
	for (const file of files) {
		parts.push(arHeader(file.name, file.data.length), file.data);
		if (file.data.length % 2 !== 0) parts.push(Buffer.from("\n"));
	}
	return Buffer.concat([Buffer.from("!<arch>\n", "ascii"), ...parts]);
}

describe("discoverFolderBinaries", () => {
	it("finds extensionless executables, dylibs and framework binaries", async () => {
		const root = makeTempDir();
		write(root, "MyApp.app/MyApp");
		write(root, "MyApp.app/Frameworks/Kit.framework/Kit");
		write(root, "MyApp.app/Frameworks/libfoo.dylib");
		write(root, "notes.txt", Buffer.from("not a binary"));
		write(root, "readme", Buffer.from("not a binary"));
		write(root, ".git/hidden", MACHO);

		const binaries = await discoverFolderBinaries(root, noop);
		const names = binaries.map((b) => b.name);

		expect(names).toEqual([
			"MyApp.app/MyApp",
			"MyApp.app/Frameworks/Kit.framework/Kit",
			"MyApp.app/Frameworks/libfoo.dylib"
		]);
		expect(binaries.map((b) => b.type)).toEqual(["main", "framework", "framework"]);
	});

	it("extracts .deb packages and names their binaries relative to the package", async () => {
		const root = makeTempDir();
		const debPath = write(root, "Tweak.deb", buildDeb([]));
		const tar = buildTar([
			{ name: "./Library/MobileSubstrate/DynamicLibraries/Tweak.dylib", data: MACHO }
		]);
		fs.writeFileSync(
			debPath,
			buildDeb([
				{ name: "debian-binary", data: Buffer.from("2.0\n", "ascii") },
				{ name: "data.tar", data: tar }
			])
		);
		cacheDirs.push(getCacheDir(debPath));

		const binaries = await discoverFolderBinaries(root, noop);

		expect(binaries).toHaveLength(1);
		expect(binaries[0]!.name).toBe(
			"Tweak.deb/Library/MobileSubstrate/DynamicLibraries/Tweak.dylib"
		);
		expect(binaries[0]!.type).toBe("main");
	});

	it("extracts .ipa archives and names their binaries relative to the archive", async () => {
		const root = makeTempDir();
		const infoPlist = Buffer.from(
			'<?xml version="1.0"?><plist version="1.0"><dict>' +
				"<key>CFBundleExecutable</key><string>TestApp</string>" +
				"</dict></plist>"
		);
		const ipaData = zipSync({
			"Payload/TestApp.app/Info.plist": new Uint8Array(infoPlist),
			"Payload/TestApp.app/TestApp": new Uint8Array(MACHO),
			"Payload/TestApp.app/Frameworks/Kit.framework/Kit": new Uint8Array(MACHO)
		});
		const ipaPath = write(root, "Sample.ipa", Buffer.from(ipaData));
		cacheDirs.push(getCacheDir(ipaPath));

		const binaries = await discoverFolderBinaries(root, noop);
		const names = binaries.map((b) => b.name);

		expect(names).toContain("Sample.ipa/TestApp");
		expect(names).toContain("Sample.ipa/Kit");
	});

	it("returns an empty list when the folder has no binaries", async () => {
		const root = makeTempDir();
		write(root, "notes.txt", Buffer.from("nothing here"));

		expect(await discoverFolderBinaries(root, noop)).toEqual([]);
	});
});

describe("detectFileType", () => {
	it("reports a plain directory as a folder", () => {
		expect(detectFileType(makeTempDir())).toBe("folder");
	});
});

// ── Minimal ustar helper (uncompressed data.tar) ───────────────────────

function tarHeader(name: string, size: number): Buffer {
	const header = Buffer.alloc(512);
	header.write(name, 0, 100, "utf-8");
	header.write("0000644\0", 100, 8, "ascii");
	header.write("0000000\0", 108, 8, "ascii");
	header.write("0000000\0", 116, 8, "ascii");
	header.write(`${size.toString(8).padStart(11, "0")}\0`, 124, 12, "ascii");
	header.write("00000000000\0", 136, 12, "ascii");
	header.write("        ", 148, 8, "ascii");
	header.write("0", 156, 1, "ascii");
	header.write("ustar\0", 257, 6, "ascii");
	header.write("00", 263, 2, "ascii");

	let sum = 0;
	for (const byte of header) sum += byte;
	header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
	return header;
}

function buildTar(files: Array<{ name: string; data: Buffer }>): Buffer {
	const parts: Buffer[] = [];
	for (const file of files) {
		parts.push(tarHeader(file.name, file.data.length), file.data);
		parts.push(Buffer.alloc((512 - (file.data.length % 512)) % 512));
	}
	parts.push(Buffer.alloc(1024));
	return Buffer.concat(parts);
}
