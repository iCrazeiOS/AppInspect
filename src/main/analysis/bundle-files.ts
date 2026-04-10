/**
 * Bundle file reading and localisation string extraction.
 *
 * Walks an app bundle to read text-based files for security scanning
 * and extracts localisation strings from .lproj directories.
 */

import * as fs from "fs";
import * as path from "path";

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

	const text = buf.toString("utf-8");

	// Old-style .strings format: "key" = "value";
	const regex = /"((?:[^"\\]|\\.)*)"\s*=\s*"((?:[^"\\]|\\.)*)"\s*;/g;
	for (const match of text.matchAll(regex)) {
		const key = match[1]!.replace(/\\"/g, '"').replace(/\\n/g, "\n").replace(/\\\\/g, "\\");
		const value = match[2]!.replace(/\\"/g, '"').replace(/\\n/g, "\n").replace(/\\\\/g, "\\");
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
					// Process all .strings files in this lproj
					const language = entry.name.replace(/\.lproj$/, "");
					let files: fs.Dirent[];
					try {
						files = fs.readdirSync(fullPath, { withFileTypes: true });
					} catch {
						continue;
					}
					for (const file of files) {
						if (file.isFile() && file.name.endsWith(".strings")) {
							readStringsFile(path.join(fullPath, file.name), language);
						}
					}
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
