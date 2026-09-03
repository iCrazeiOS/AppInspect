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

export function detectFileType(filePath: string): SourceType {
	// Handle directories: .app bundles are valid, anything else is not
	if (fs.statSync(filePath).isDirectory()) {
		if (filePath.endsWith(".app")) return "ipa";
		throw new Error("The selected folder is not a valid .app bundle or supported file.");
	}

	const fd = fs.openSync(filePath, "r");
	const buf = Buffer.alloc(8);
	fs.readSync(fd, buf, 0, 8, 0);
	fs.closeSync(fd);

	// DEB: ar archive magic "!<arch>\n"
	if (buf.toString("ascii", 0, 8) === "!<arch>\n") {
		return "deb";
	}

	// Mach-O: check 4-byte magic
	const magic = buf.readUInt32BE(0);
	const magicLE = buf.readUInt32LE(0);
	if (MACHO_MAGICS.has(magic) || MACHO_MAGICS.has(magicLE)) {
		return "macho";
	}

	// IPA: ZIP file (PK\x03\x04) or assume IPA by extension
	if (buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04) {
		return "ipa";
	}

	// Fallback: check extension
	const ext = path.extname(filePath).toLowerCase();
	if (ext === ".ipa") return "ipa";
	if (ext === ".deb") return "deb";
	if (ext === ".dylib" || ext === ".a") return "macho";

	// Default to macho for extensionless files (common for executables)
	return "macho";
}
