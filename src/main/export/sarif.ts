/**
 * SARIF Export
 *
 * Serialises security findings as a SARIF 2.1.0 log for CI and code-scanning
 * tooling. Pure and deterministic — no filesystem access.
 */

import { basename, dirname } from "node:path";
import { pathToFileURL } from "node:url";

import type { AnalysisResult, SecurityFinding } from "../../shared/types";

const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
const SARIF_VERSION = "2.1.0";
const TOOL_NAME = "AppInspect";
const TOOL_VERSION = "0.1.0";
const TOOL_INFO_URI = "https://github.com/iCrazeiOS/AppInspect";
const MAX_MESSAGE_LENGTH = 2000;
const MAX_SNIPPET_LENGTH = 120;
const OFFSET_RE = /offset=0x([0-9a-f]+)/i;

const CATEGORY_LABELS: Record<string, string> = {
	"credential-leak": "Hardcoded credential or secret",
	"binary-hardening": "Binary hardening issue",
	"unsafe-api": "Memory-unsafe function used",
	"weak-crypto": "Weak cryptographic algorithm used",
	"dangerous-api": "Dangerous system call used",
	"jailbreak-detection": "Jailbreak detection string",
	"debug-artifacts": "Leaked debug artifact",
	"leaked-source-path": "Leaked developer source path",
	"source-map": "Shipped source map",
	"electron-fuses": "Electron fuse weakens the runtime",
	"electron-renderer": "Unsafe Electron renderer preference",
	"electron-csp": "Electron Content-Security-Policy weakness",
	"electron-integrity": "Electron bundle integrity issue",
	"electron-runtime": "Electron runtime API misuse",
	"electron-version": "Unsupported Electron version"
};

const LEVELS: Record<SecurityFinding["severity"], "error" | "warning" | "note"> = {
	critical: "error",
	warning: "warning",
	info: "note"
};

const SEVERITY_RANK: Record<SecurityFinding["severity"], number> = {
	critical: 3,
	warning: 2,
	info: 1
};

interface SarifRegion {
	byteOffset?: number;
	snippet?: { text: string };
}

interface SarifLocation {
	physicalLocation: {
		artifactLocation: { uri: string; uriBaseId: string };
		region?: SarifRegion;
	};
	logicalLocations?: Array<{ name: string }>;
}

interface SarifRule {
	id: string;
	name: string;
	shortDescription: { text: string };
	defaultConfiguration: { level: "error" | "warning" | "note" };
}

interface SarifResult {
	ruleId: string;
	ruleIndex: number;
	level: "error" | "warning" | "note";
	message: { text: string };
	locations: SarifLocation[];
	properties: { category: string; evidence: string; severity: string };
}

/** Rule identifier for a finding category, e.g. `appinspect/credential-leak`. */
function ruleId(category: string): string {
	return `appinspect/${category}`;
}

function pascalCase(value: string): string {
	return value
		.split(/[^a-zA-Z0-9]+/)
		.filter(Boolean)
		.map((part) => part.charAt(0).toUpperCase() + part.slice(1))
		.join("");
}

function truncate(value: string, max: number): string {
	return value.length > max ? `${value.slice(0, max - 3)}...` : value;
}

function buildLocation(finding: SecurityFinding, filePath: string): SarifLocation {
	const physicalLocation: SarifLocation["physicalLocation"] = {
		artifactLocation: {
			uri: finding.source ?? basename(filePath),
			uriBaseId: "SRCROOT"
		}
	};

	const match = finding.location?.match(OFFSET_RE);
	if (match) {
		const region: SarifRegion = { byteOffset: Number.parseInt(match[1]!, 16) };
		if (finding.evidence && finding.evidence.length <= MAX_SNIPPET_LENGTH) {
			region.snippet = { text: finding.evidence };
		}
		physicalLocation.region = region;
	}

	const location: SarifLocation = { physicalLocation };
	if (finding.functionName) {
		location.logicalLocations = [{ name: finding.functionName }];
	}
	return location;
}

/**
 * Count findings at or above a severity threshold.
 *
 * @param findings - Security findings to test
 * @param level - Minimum severity to count (`critical` > `warning` > `info`)
 */
export function findingsAtOrAbove(
	findings: SecurityFinding[],
	level: "critical" | "warning" | "info"
): number {
	const threshold = SEVERITY_RANK[level];
	return findings.filter((f) => SEVERITY_RANK[f.severity] >= threshold).length;
}

/**
 * Serialise the security findings of an analysis as a SARIF 2.1.0 log.
 *
 * @param result - The full analysis result
 * @returns SARIF JSON string (pretty-printed)
 */
export function exportSarif(result: AnalysisResult): string {
	const findings = result.security?.findings ?? [];
	const filePath = result.overview.filePath;

	const categories = [...new Set(findings.map((f) => f.category))].sort();
	const rules: SarifRule[] = categories.map((category) => {
		let highest: SecurityFinding["severity"] = "info";
		for (const finding of findings) {
			if (
				finding.category === category &&
				SEVERITY_RANK[finding.severity] > SEVERITY_RANK[highest]
			) {
				highest = finding.severity;
			}
		}
		return {
			id: ruleId(category),
			name: pascalCase(category),
			shortDescription: { text: CATEGORY_LABELS[category] ?? category },
			defaultConfiguration: { level: LEVELS[highest] }
		};
	});
	const ruleIndex = new Map(categories.map((category, index) => [category, index]));

	const results: SarifResult[] = findings.map((finding) => ({
		ruleId: ruleId(finding.category),
		ruleIndex: ruleIndex.get(finding.category) ?? 0,
		level: LEVELS[finding.severity],
		message: {
			text: truncate(
				finding.evidence ? `${finding.message} — ${finding.evidence}` : finding.message,
				MAX_MESSAGE_LENGTH
			)
		},
		locations: [buildLocation(finding, filePath)],
		properties: {
			category: finding.category,
			evidence: finding.evidence,
			severity: finding.severity
		}
	}));

	const baseUri = pathToFileURL(dirname(filePath)).href;
	const log = {
		$schema: SARIF_SCHEMA,
		version: SARIF_VERSION,
		runs: [
			{
				tool: {
					driver: {
						name: TOOL_NAME,
						informationUri: TOOL_INFO_URI,
						version: TOOL_VERSION,
						rules
					}
				},
				results,
				originalUriBaseIds: {
					SRCROOT: { uri: baseUri.endsWith("/") ? baseUri : `${baseUri}/` }
				}
			}
		]
	};

	return JSON.stringify(log, null, 2);
}
