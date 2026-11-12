import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { arArchive } from "../../parser/__tests__/fixtures";
import { detectFileType } from "../file-type";

const TMP_DIR = path.join(import.meta.dir, ".tmp-file-type-test");

beforeAll(() => mkdirSync(TMP_DIR, { recursive: true }));
afterAll(() => rmSync(TMP_DIR, { recursive: true, force: true }));

describe("detectFileType", () => {
	it("treats a ZIP-magic .tipa like an .ipa", () => {
		const file = path.join(TMP_DIR, "App.tipa");
		writeFileSync(file, Buffer.from([0x50, 0x4b, 0x03, 0x04, 0, 0, 0, 0]));
		expect(detectFileType(file)).toBe("ipa");
	});

	it("falls back to the .tipa extension when the magic is unrecognised", () => {
		const file = path.join(TMP_DIR, "Odd.tipa");
		writeFileSync(file, Buffer.alloc(8));
		expect(detectFileType(file)).toBe("ipa");
	});

	it("tells static libraries apart from Debian packages", () => {
		const lib = path.join(TMP_DIR, "libFoo.a");
		writeFileSync(lib, arArchive([{ name: "foo.o", data: "x" }]));
		expect(detectFileType(lib)).toBe("staticlib");

		const deb = path.join(TMP_DIR, "pkg.deb");
		writeFileSync(deb, arArchive([{ name: "debian-binary", data: "2.0\n" }]));
		expect(detectFileType(deb)).toBe("deb");
	});

	it("falls back to the .a extension", () => {
		const file = path.join(TMP_DIR, "libOdd.a");
		writeFileSync(file, Buffer.alloc(8));
		expect(detectFileType(file)).toBe("staticlib");
	});
});
