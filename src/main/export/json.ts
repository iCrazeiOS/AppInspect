/**
 * JSON Export
 *
 * Serializes analysis data as JSON with metadata wrapper.
 * Supports full export or export filtered to chosen sections.
 */

import type { SectionName } from "../../shared/ipc-types";
import type { AnalysisResult } from "../../shared/types";

/** Map of section names to their key in AnalysisResult */
const SECTION_KEY_MAP: Record<SectionName, keyof AnalysisResult> = {
	overview: "overview",
	strings: "strings",
	headers: "headers",
	libraries: "libraries",
	symbols: "symbols",
	objc: "objc",
	swift: "swift",
	entitlements: "entitlements",
	infoPlist: "infoPlist",
	hooks: "hooks",
	security: "security",
	files: "files",
	size: "size",
	electron: "electron"
};

/**
 * JSON replacer that converts BigInt values to strings.
 */
function bigintReplacer(_key: string, value: unknown): unknown {
	if (typeof value === "bigint") {
		if (value <= BigInt(Number.MAX_SAFE_INTEGER) && value >= BigInt(Number.MIN_SAFE_INTEGER)) {
			return Number(value);
		}
		return value.toString();
	}
	return value;
}

/**
 * App version for the export wrapper: the bundle's short version string, then
 * its build number, then a DEB package version.
 */
function appVersion(result: AnalysisResult): string {
	const candidates = [
		result.infoPlist?.CFBundleShortVersionString,
		result.infoPlist?.CFBundleVersion,
		result.overview?.debControl?.version
	];
	for (const candidate of candidates) {
		if (typeof candidate === "string" && candidate.trim() !== "") return candidate;
	}
	return "Unknown";
}

/**
 * Serialize analysis data as JSON.
 *
 * @param result - The full analysis result
 * @param sections - If specified, include only these sections' data. If omitted, export everything.
 * @returns JSON string with metadata wrapper
 */
export function exportAnalysis(result: AnalysisResult, sections?: SectionName[]): string {
	const appName = result.overview?.ipa?.appName ?? "Unknown";

	let data: Record<string, unknown>;

	if (!sections || sections.length === 0) {
		// Export everything
		data = { ...result } as Record<string, unknown>;
	} else {
		// Export only requested sections
		data = {};
		for (const section of sections) {
			const key = SECTION_KEY_MAP[section];
			if (key && key in result) {
				data[key] = result[key];
			}
		}
	}

	const wrapper = {
		exportedAt: new Date().toISOString(),
		appName,
		version: appVersion(result),
		data
	};

	return JSON.stringify(wrapper, bigintReplacer, 2);
}
