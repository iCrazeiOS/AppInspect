/**
 * Bundle file reading and localisation string extraction.
 *
 * Walks an app bundle to read text-based files for security scanning
 * and extracts localisation strings from .lproj directories.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import type { LocalisationString } from "../../shared/types";
import { parsePlistBuffer } from "../parser/plist";
import { loadSettings } from "../settings";
import type { BundleFileEntry } from "./security";
import { isScannableExtension } from "./security";

function getBundleSizeLimits(): { maxTotal: number; maxSingle: number } {
	const settings = loadSettings();
	return {
		maxTotal: settings.maxBundleSizeMB * 1024 * 1024,
		maxSingle: settings.maxFileSizeMB * 1024 * 1024
	};
}

/**
 * Try to parse a plist (binary or XML) into a JSON text representation
 * so it can be scanned for secrets. Returns null if parsing fails.
 */
function tryParsePlistToJson(buf: Buffer): string | null {
	try {
		const parsed = parsePlistBuffer(buf);
		return JSON.stringify(parsed, null, 2);
	} catch {
		return null;
	}
}

/**
 * Check if a file appears to be binary (has null bytes in the first 512 bytes).
 * Plists are handled separately via tryParsePlistToJson.
 */
function hasBinaryContent(buf: Buffer): boolean {
	const checkLen = Math.min(buf.length, 512);
	for (let i = 0; i < checkLen; i++) {
		if (buf[i] === 0) return true;
	}
	return false;
}

export function readBundleFiles(appBundlePath: string): BundleFileEntry[] {
	const files: BundleFileEntry[] = [];
	let totalSize = 0;
	const { maxTotal, maxSingle } = getBundleSizeLimits();

	function walk(dir: string): void {
		if (totalSize >= maxTotal) return;

		let entries: fs.Dirent[];
		try {
			entries = fs.readdirSync(dir, { withFileTypes: true });
		} catch {
			return;
		}

		for (const entry of entries) {
			if (totalSize >= maxTotal) break;
			const fullPath = path.join(dir, entry.name);

			if (entry.isDirectory()) {
				// Skip known binary-only directories
				if (
					entry.name === "Frameworks" ||
					entry.name === "PlugIns" ||
					entry.name === "_CodeSignature"
				) {
					continue;
				}
				walk(fullPath);
				continue;
			}

			if (!entry.isFile()) continue;

			const ext = path.extname(entry.name);
			if (!isScannableExtension(ext)) continue;

			try {
				const stat = fs.statSync(fullPath);
				if (stat.size === 0 || stat.size > maxSingle) continue;

				const rawBuf = fs.readFileSync(fullPath);
				let content: string;

				// Try parsing plists (.plist, .strings can be binary or XML plist format)
				const plistText = tryParsePlistToJson(rawBuf);
				if (plistText !== null) {
					content = plistText;
				} else if (hasBinaryContent(rawBuf)) {
					// Skip other binary files (compiled nibs embedded with wrong extension, etc.)
					continue;
				} else {
					content = rawBuf.toString("utf-8");
				}

				const relativePath = path.relative(appBundlePath, fullPath).replace(/\\/g, "/");
				files.push({ relativePath, content });
				totalSize += stat.size;
			} catch {
				// Skip unreadable files
			}
		}
	}

	walk(appBundlePath);
	return files;
}

// ── Localisation string extraction ──────────────────────────────────

/**
 * Parse a .strings file content (binary plist, XML plist, or old-style format)
 * into key-value pairs.
 */
function parseStringsFile(buf: Buffer): Record<string, string> {
	const result: Record<string, string> = {};

	// Try binary or XML plist first
	try {
		const parsed = parsePlistBuffer(buf);
		for (const [k, v] of Object.entries(parsed)) {
			if (typeof v === "string") result[k] = v;
		}
		return result;
	} catch {
		// Fall through to old-style format
	}

	function decodeText(b: Buffer): string {
		// UTF-8 BOM
		if (b.length >= 3 && b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) {
			return b.subarray(3).toString("utf-8");
		}

		// UTF-16 BOMs
		if (b.length >= 2 && b[0] === 0xff && b[1] === 0xfe) {
			return b.subarray(2).toString("utf16le");
		}
		if (b.length >= 2 && b[0] === 0xfe && b[1] === 0xff) {
			// Convert BE -> LE by swapping byte pairs
			const body = b.subarray(2);
			const swapped = Buffer.alloc(body.length);
			for (let i = 0; i + 1 < body.length; i += 2) {
				swapped[i] = body[i + 1]!;
				swapped[i + 1] = body[i]!;
			}
			return swapped.toString("utf16le");
		}

		// Heuristic: old-style .strings are often UTF-16 (with or without BOM)
		if (hasBinaryContent(b)) {
			return b.toString("utf16le");
		}

		return b.toString("utf-8");
	}

	function unescapeStringsText(s: string): string {
		// Apple .strings sometimes uses \UXXXX sequences.
		return s
			.replace(/\\U([0-9a-fA-F]{4})/g, (_m, hex: string) =>
				String.fromCharCode(Number.parseInt(hex, 16))
			)
			.replace(/\\u([0-9a-fA-F]{4})/g, (_m, hex: string) =>
				String.fromCharCode(Number.parseInt(hex, 16))
			)
			.replace(/\\"/g, '"')
			.replace(/\\n/g, "\n")
			.replace(/\\r/g, "\r")
			.replace(/\\t/g, "\t")
			.replace(/\\\\/g, "\\");
	}

	const text = decodeText(buf);

	// Old-style .strings format: "key" = "value";
	const regex = /"((?:[^"\\]|\\.)*)"\s*=\s*"((?:[^"\\]|\\.)*)"\s*;/g;
	for (const match of text.matchAll(regex)) {
		const key = unescapeStringsText(match[1]!);
		const value = unescapeStringsText(match[2]!);
		result[key] = value;
	}

	return result;
}

/**
 * Walk the app bundle for .lproj directories and extract localisation strings
 * from all .strings files within them.
 */
export function extractLocalisationStrings(rootPath: string): LocalisationString[] {
	const results: LocalisationString[] = [];
	const { maxTotal, maxSingle } = getBundleSizeLimits();
	let totalSize = 0;

	function readStringsFile(fullPath: string, language: string): void {
		try {
			const stat = fs.statSync(fullPath);
			if (stat.size === 0 || stat.size > maxSingle) return;

			const buf = fs.readFileSync(fullPath);
			totalSize += stat.size;

			const pairs = parseStringsFile(buf);
			const relativePath = path.relative(rootPath, fullPath).replace(/\\/g, "/");

			for (const [key, value] of Object.entries(pairs)) {
				results.push({ key, value, file: relativePath, language });
			}
		} catch {
			// Skip unreadable files
		}
	}

	function walkLproj(dir: string, language: string): void {
		if (totalSize >= maxTotal) return;

		let entries: fs.Dirent[];
		try {
			entries = fs.readdirSync(dir, { withFileTypes: true });
		} catch {
			return;
		}

		for (const entry of entries) {
			if (totalSize >= maxTotal) break;
			const fullPath = path.join(dir, entry.name);

			if (entry.isDirectory()) {
				walkLproj(fullPath, language);
				continue;
			}

			if (entry.isFile() && entry.name.endsWith(".strings")) {
				readStringsFile(fullPath, language);
			}
		}
	}

	function walk(dir: string): void {
		if (totalSize >= maxTotal) return;

		let entries: fs.Dirent[];
		try {
			entries = fs.readdirSync(dir, { withFileTypes: true });
		} catch {
			return;
		}

		for (const entry of entries) {
			if (totalSize >= maxTotal) break;
			const fullPath = path.join(dir, entry.name);

			if (entry.isDirectory()) {
				// Skip heavy binary-only dirs
				if (entry.name === "_CodeSignature") continue;

				if (entry.name.endsWith(".lproj")) {
					// Process all .strings files anywhere within this lproj (e.g. storyboardc)
					const language = entry.name.replace(/\.lproj$/, "");
					walkLproj(fullPath, language);
				} else {
					walk(fullPath);
				}
				continue;
			}

			// Standalone .strings files outside .lproj (no language)
			if (entry.isFile() && entry.name.endsWith(".strings")) {
				readStringsFile(fullPath, "");
			}
		}
	}

	walk(rootPath);
	return results;
}
