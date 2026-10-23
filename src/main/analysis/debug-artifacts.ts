/**
 * Debug artifact detection.
 *
 * Flags development artifacts leaked into a shipped build: DWARF debug info,
 * retained STABS symbols, developer source paths baked into strings, and source
 * maps / module interfaces / symbol maps shipped inside the app bundle.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { formatCount } from "../../shared/format";
import type { SecurityFinding, StringEntry } from "../../shared/types";

export interface DebugArtifactParams {
	segmentNames: string[];
	sectionNames: string[];
	strings: StringEntry[];
	/** Count of N_STAB (debug) symbols retained in the symbol table. */
	debugSymbolCount: number;
}

const DWARF_SEGMENT = "__DWARF";
const DWARF_SECTIONS = new Set([
	"__debug_info",
	"__debug_str",
	"__debug_line",
	"__debug_abbrev",
	"__debug_aranges"
]);

// Bounded to user/build roots (never system roots) plus path-like tokens ending
// in a source extension.
const DEV_PATH_RE =
	/(?<![\w.])(?:\/Users\/|\/home\/|\/private\/var\/folders\/|\/var\/folders\/|\/Volumes\/|C:\\Users\\)[^\s"'<>|]{0,300}|[^\s"'<>|]{0,300}\/[^\s"'<>|]{0,300}\.(?:swiftinterface|swiftmodule|swift|mm|cpp|cc|hpp|m|c|h)(?=$|[\s"'<>|,)])/g;
const SYSTEM_PATH_RE = /^(?:\/usr\/|\/System\/|\/Library\/)/;
const MAX_SOURCE_PATH_FINDINGS = 10;

export function checkDebugArtifacts(params: DebugArtifactParams): SecurityFinding[] {
	const findings: SecurityFinding[] = [];

	// DWARF debug info left in the binary
	const dwarfMatches = [
		...params.segmentNames.filter((n) => n === DWARF_SEGMENT),
		...params.sectionNames.filter((n) => DWARF_SECTIONS.has(n))
	];
	if (dwarfMatches.length > 0) {
		findings.push({
			severity: "warning",
			category: "debug-artifacts",
			message: "Binary contains DWARF debug information (not stripped)",
			evidence: [...new Set(dwarfMatches)].join(", ")
		});
	}

	// Retained STABS debug symbols
	if (params.debugSymbolCount > 0) {
		findings.push({
			severity: "info",
			category: "debug-artifacts",
			message: `Symbol table retains ${formatCount(params.debugSymbolCount, "debug (STABS) symbol")}`,
			evidence: `stabs=${params.debugSymbolCount}`
		});
	}

	// Developer source paths embedded in strings
	const seenPaths = new Set<string>();
	for (const entry of params.strings) {
		if (seenPaths.size >= MAX_SOURCE_PATH_FINDINGS) break;

		for (const match of entry.value.match(DEV_PATH_RE) ?? []) {
			if (seenPaths.size >= MAX_SOURCE_PATH_FINDINGS) break;

			const candidate = match.replace(/[.,;:)\]]+$/, "");
			if (candidate.length < 6 || candidate.length > 300) continue;
			if (SYSTEM_PATH_RE.test(candidate)) continue;
			if (seenPaths.has(candidate)) continue;

			seenPaths.add(candidate);
			findings.push({
				severity: "info",
				category: "leaked-source-path",
				message: "Developer source/build path embedded in binary",
				evidence: candidate,
				location: `offset=0x${entry.offset.toString(16)}`
			});
		}
	}

	return findings;
}

// ── Bundle-level artifacts ──────────────────────────────────────────

const MAX_BUNDLE_ENTRIES = 20000;
const MAX_BUNDLE_FINDINGS = 25;
const MAX_VENDOR_SOURCE_MAPS = 5;
const DECLARATION_MAP_RE = /\.d\.(?:ts|mts|cts)\.map$/;
const VENDOR_SEGMENT = /(^|\/)(?:node_modules|vendor|third_party|3rdparty)(\/|$)/i;

/**
 * Runtime source maps are the only ones worth a warning: declaration maps
 * (`.d.ts.map`) are build metadata, and CSS maps are not JavaScript.
 */
function classifySourceMap(fileName: string): {
	message: string;
	severity: SecurityFinding["severity"];
} | null {
	const lower = fileName.toLowerCase();
	if (DECLARATION_MAP_RE.test(lower)) return null;
	if (lower.endsWith(".css.map")) {
		return { message: "CSS source map shipped in bundle", severity: "warning" };
	}
	if (/\.(?:js|mjs|cjs|jsx|ts|tsx)\.map$/.test(lower)) {
		return { message: "JavaScript source map shipped in bundle", severity: "warning" };
	}
	return { message: "Source map shipped in bundle", severity: "info" };
}

function isVendorPath(relativePath: string): boolean {
	return VENDOR_SEGMENT.test(relativePath);
}

export function findBundleDebugArtifacts(rootPath: string): SecurityFinding[] {
	const findings: SecurityFinding[] = [];
	const seen = new Set<string>();
	let visited = 0;
	let vendorSourceMaps = 0;

	function add(
		category: string,
		severity: SecurityFinding["severity"],
		message: string,
		relativePath: string,
		evidence: string,
		options: { vendor?: boolean } = {}
	): void {
		if (findings.length >= MAX_BUNDLE_FINDINGS) return;
		const key = `${category}|${relativePath}`;
		if (seen.has(key)) return;
		seen.add(key);
		const finding: SecurityFinding = {
			severity,
			category,
			message,
			evidence,
			source: relativePath
		};
		if (options.vendor) finding.vendor = true;
		findings.push(finding);
	}

	function walk(dir: string): void {
		if (visited >= MAX_BUNDLE_ENTRIES || findings.length >= MAX_BUNDLE_FINDINGS) return;

		let entries: fs.Dirent[];
		try {
			entries = fs.readdirSync(dir, { withFileTypes: true });
		} catch {
			return;
		}

		// App-owned artifacts first: a deep vendor tree must not consume the
		// bundle finding cap before the app's own files are reached.
		entries.sort((a, b) => {
			const vendorA = VENDOR_SEGMENT.test(a.name) ? 1 : 0;
			const vendorB = VENDOR_SEGMENT.test(b.name) ? 1 : 0;
			return vendorA - vendorB || a.name.localeCompare(b.name);
		});

		for (const entry of entries) {
			if (visited >= MAX_BUNDLE_ENTRIES || findings.length >= MAX_BUNDLE_FINDINGS) break;
			visited++;

			if (entry.name === "_CodeSignature") continue;
			const fullPath = path.join(dir, entry.name);
			const relativePath = path.relative(rootPath, fullPath).replace(/\\/g, "/");
			const lower = entry.name.toLowerCase();

			if (entry.isDirectory()) {
				if (lower.endsWith(".dsym")) {
					add(
						"debug-artifacts",
						"warning",
						"Debug symbol bundle (dSYM) shipped in bundle",
						relativePath,
						entry.name
					);
					continue;
				}
				if (entry.name === "BCSymbolMaps") {
					add(
						"debug-artifacts",
						"info",
						"Bitcode symbol map shipped in bundle",
						relativePath,
						entry.name
					);
					continue;
				}
				walk(fullPath);
				continue;
			}

			if (!entry.isFile()) continue;

			if (lower.endsWith(".map")) {
				const classified = classifySourceMap(entry.name);
				if (!classified) continue;
				const vendor = isVendorPath(relativePath);
				if (vendor) {
					if (vendorSourceMaps >= MAX_VENDOR_SOURCE_MAPS) continue;
					vendorSourceMaps++;
				}
				add(
					"source-map",
					classified.severity,
					classified.message,
					relativePath,
					entry.name,
					{ vendor }
				);
			} else if (lower.endsWith(".swiftmodule") || lower.endsWith(".swiftinterface")) {
				add(
					"debug-artifacts",
					"info",
					"Swift module interface shipped in bundle",
					relativePath,
					entry.name
				);
			} else if (lower.endsWith(".bcsymbolmap")) {
				add(
					"debug-artifacts",
					"info",
					"Bitcode symbol map shipped in bundle",
					relativePath,
					entry.name
				);
			}
		}
	}

	walk(rootPath);
	return findings;
}
