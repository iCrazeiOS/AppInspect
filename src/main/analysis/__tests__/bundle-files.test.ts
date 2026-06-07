import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";

import { extractLocalisationStrings } from "../bundle-files";

const TMP_DIR = path.join(import.meta.dir, ".tmp-bundle-files");

function writeFile(filePath: string, content: string | Buffer): void {
	mkdirSync(path.dirname(filePath), { recursive: true });
	writeFileSync(filePath, content);
}

describe("extractLocalisationStrings", () => {
	beforeAll(() => {
		rmSync(TMP_DIR, { recursive: true, force: true });
		mkdirSync(TMP_DIR, { recursive: true });
	});

	afterAll(() => {
		rmSync(TMP_DIR, { recursive: true, force: true });
	});

	it("extracts .strings from nested paths inside .lproj (macOS storyboardc layout)", () => {
		const appPath = path.join(TMP_DIR, "Test.app");
		const contentsPath = path.join(appPath, "Contents");
		const enStringsPath = path.join(
			contentsPath,
			"Resources",
			"en.lproj",
			"Main.storyboardc",
			"Localizable.strings"
		);
		const frStringsPath = path.join(
			contentsPath,
			"Resources",
			"fr.lproj",
			"Main.storyboardc",
			"Localizable.strings"
		);

		writeFile(enStringsPath, '"HELLO" = "Hello";\n');
		writeFile(frStringsPath, '"HELLO" = "Bonjour";\n');

		const results = extractLocalisationStrings(contentsPath);

		expect(
			results.some(
				(r) =>
					r.language === "en" &&
					r.key === "HELLO" &&
					r.value === "Hello" &&
					r.file === "Resources/en.lproj/Main.storyboardc/Localizable.strings"
			)
		).toBe(true);

		expect(
			results.some(
				(r) =>
					r.language === "fr" &&
					r.key === "HELLO" &&
					r.value === "Bonjour" &&
					r.file === "Resources/fr.lproj/Main.storyboardc/Localizable.strings"
			)
		).toBe(true);
	});

	it("parses old-style UTF-16LE .strings files (common on macOS)", () => {
		const appPath = path.join(TMP_DIR, "TestUtf16.app");
		const contentsPath = path.join(appPath, "Contents");
		const stringsPath = path.join(contentsPath, "Resources", "en.lproj", "DFLocalizable.strings");

		const body = Buffer.from('"HELLO" = "Hello";\n', "utf16le");
		const withBom = Buffer.concat([Buffer.from([0xff, 0xfe]), body]);
		writeFile(stringsPath, withBom);

		const results = extractLocalisationStrings(contentsPath);
		expect(results.some((r) => r.language === "en" && r.key === "HELLO" && r.value === "Hello")).toBe(
			true
		);
	});
});
