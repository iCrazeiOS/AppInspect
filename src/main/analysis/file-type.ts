/**
 * File type detection.
 *
 * Sniffs magic bytes (falling back to the extension) to route a selected file
 * to the correct container driver.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import type { SourceType } from "../../shared/types";
import { MACHO_MAGICS } from "../parser/macho";
import { isStaticLibraryFile } from "../static-library/extractor";
import { isXCFrameworkPath } from "../xcframework/discovery";

/** Extensions accepted regardless of the bytes they contain. */
const KNOWN_EXTENSIONS = new Set([
	".ipa",
	".tipa",
	".deb",
	".dylib",
	".a",
	".zip",
	".app",
	".xcframework"
]);

/** Read the leading 8 bytes (never the whole file) and identify the container. */
function sniffMagic(filePath: string): SourceType | null {
	const fd = fs.openSync(filePath, "r");
	try {
		const buf = Buffer.alloc(8);
		fs.readSync(fd, buf, 0, 8, 0);

		// ar archive magic "!<arch>\n": a static library unless it is a Debian package
		if (buf.toString("ascii", 0, 8) === "!<arch>\n") {
			return isStaticLibraryFile(filePath) ? "staticlib" : "deb";
		}

		// Mach-O: check 4-byte magic in both byte orders. A universal static
		// library shares the fat magic, but its slices are ar archives.
		const magic = buf.readUInt32BE(0);
		const magicLE = buf.readUInt32LE(0);
		if (MACHO_MAGICS.has(magic) || MACHO_MAGICS.has(magicLE)) {
			return isStaticLibraryFile(filePath) ? "staticlib" : "macho";
		}

		// IPA: ZIP file (PK\x03\x04)
		if (buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04) {
			return "ipa";
		}

		return null;
	} finally {
		fs.closeSync(fd);
	}
}

/**
 * Whether a dropped or picked path looks like something the analysis pipeline
 * can open. Directories are always accepted; files are accepted when their
 * magic bytes match a supported container or they carry a known extension.
 * Rare names such as `Foo.iOS_16.3.1` therefore still work.
 */
export function isSupportedFile(filePath: string): boolean {
	try {
		if (fs.statSync(filePath).isDirectory()) return true;
		if (sniffMagic(filePath) !== null) return true;
		return KNOWN_EXTENSIONS.has(path.extname(filePath).toLowerCase());
	} catch {
		return false;
	}
}

export function detectFileType(filePath: string): SourceType {
	if (fs.statSync(filePath).isDirectory()) {
		if (filePath.endsWith(".app")) return "ipa";
		if (isXCFrameworkPath(filePath)) return "xcframework";
		return "folder";
	}

	const sniffed = sniffMagic(filePath);
	if (sniffed) return sniffed;

	// Fallback: check extension
	const ext = path.extname(filePath).toLowerCase();
	if (ext === ".ipa" || ext === ".tipa") return "ipa";
	if (ext === ".deb") return "deb";
	if (ext === ".a") return "staticlib";
	if (ext === ".dylib") return "macho";

	// Default to macho for extensionless files (common for executables)
	return "macho";
}
