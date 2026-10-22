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

export function findBundleDebugArtifacts(rootPath: string): SecurityFinding[] {
	const findings: SecurityFinding[] = [];
	const seen = new Set<string>();
	let visited = 0;

	function add(
		category: string,
		severity: SecurityFinding["severity"],
		message: string,
		relativePath: string,
		evidence: string
	): void {
		if (findings.length >= MAX_BUNDLE_FINDINGS) return;
		const key = `${category}|${relativePath}`;
		if (seen.has(key)) return;
		seen.add(key);
		findings.push({ severity, category, message, evidence, source: relativePath });
	}

	function walk(dir: string): void {
		if (visited >= MAX_BUNDLE_ENTRIES || findings.length >= MAX_BUNDLE_FINDINGS) return;

		let entries: fs.Dirent[];
		try {
			entries = fs.readdirSync(dir, { withFileTypes: true });
		} catch {
			return;
		}

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
				add(
					"source-map",
					"warning",
					"JavaScript source map shipped in bundle",
					relativePath,
					entry.name
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
