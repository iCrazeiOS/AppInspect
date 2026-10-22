/**
 * Electron `app.asar` scanning.
 *
 * Extracts scannable text files from an archive for the existing secret
 * scanner, and derives Electron-specific findings (fuse wire, ASAR integrity,
 * shipped source maps, dangerous `webPreferences`). Archive data is untrusted,
 * so every read is bounded by the bundle size settings.
 */

import * as path from "node:path";

import type { ElectronInfo, SecurityFinding } from "../../shared/types";
import type { BundleFileEntry } from "../analysis/security";
import { isScannableExtension } from "../analysis/security";
import { loadSettings } from "../settings";
import type { AsarArchive } from "./asar";
import { readAsarFile } from "./asar";

const MAX_FINDINGS_PER_CATEGORY = 20;

/** Fuse states that weaken the Electron runtime sandbox. */
const RISKY_FUSES: Array<{ name: string; message: string }> = [
	{
		name: "RunAsNode",
		message: "RunAsNode is enabled — ELECTRON_RUN_AS_NODE runs the binary as plain Node"
	},
	{
		name: "EnableNodeOptionsEnvironmentVariable",
		message: "NODE_OPTIONS is honoured — environment variables can inject Node flags"
	},
	{
		name: "EnableNodeCliInspectArguments",
		message: "Node CLI inspect arguments are honoured — the debugger can attach"
	}
];

/** `webPreferences` settings that weaken an Electron renderer. */
const WEB_PREFERENCE_PATTERNS: Array<{
	severity: SecurityFinding["severity"];
	name: string;
	pattern: RegExp;
}> = [
	{
		severity: "warning",
		name: "nodeIntegration",
		pattern: /["']?nodeIntegration["']?\s*:\s*true/
	},
	{
		severity: "warning",
		name: "contextIsolation",
		pattern: /["']?contextIsolation["']?\s*:\s*false/
	},
	{
		severity: "warning",
		name: "webSecurity",
		pattern: /["']?webSecurity["']?\s*:\s*false/
	},
	{
		severity: "warning",
		name: "allowRunningInsecureContent",
		pattern: /["']?allowRunningInsecureContent["']?\s*:\s*true/
	},
	{
		severity: "info",
		name: "sandbox",
		pattern: /["']?sandbox["']?\s*:\s*false/
	},
	{
		severity: "info",
		name: "webviewTag",
		pattern: /["']?webviewTag["']?\s*:\s*true/
	}
];

export interface AsarScanLimits {
	/** Largest single file to read, in bytes. Defaults to `maxFileSizeMB`. */
	maxFileSize: number;
	/** Total bytes to read across the archive. Defaults to `maxBundleSizeMB`. */
	maxBundleSize: number;
}

/** Read scannable text files from the archive, bounded by the bundle size settings. */
export function readAsarTextFiles(
	archive: AsarArchive,
	limits?: AsarScanLimits
): BundleFileEntry[] {
	const settings = loadSettings();
	const maxFileSize = limits?.maxFileSize ?? settings.maxFileSizeMB * 1024 * 1024;
	const maxBundleSize = limits?.maxBundleSize ?? settings.maxBundleSizeMB * 1024 * 1024;

	const files: BundleFileEntry[] = [];
	let totalSize = 0;

	for (const record of archive.files.values()) {
		if (totalSize >= maxBundleSize) break;
		// Links have no contents of their own; the target is scanned instead
		if (record.link !== undefined) continue;
		// Unpacked files live beside the archive and are scanned from disk
		if (record.unpacked) continue;
		if (record.size === 0 || record.size > maxFileSize) continue;
		// Source maps are huge and already reported as shipped source maps
		if (record.path.toLowerCase().endsWith(".map")) continue;
		if (!isScannableExtension(path.extname(record.path))) continue;

		const result = readAsarFile(archive, record.path, maxFileSize);
		if (!result.ok) continue;
		const data = result.data.data;
		if (data.includes(0)) continue;

		files.push({
			relativePath: `app.asar/${record.path}`,
			content: data.toString("utf8")
		});
		totalSize += record.size;
	}

	return files;
}

/** Derive Electron findings from the bundle metadata and archive text files. */
export function scanElectron(info: ElectronInfo, files: BundleFileEntry[]): SecurityFinding[] {
	const findings: SecurityFinding[] = [];
	const seen = new Set<string>();
	const counts = new Map<string, number>();

	const push = (finding: SecurityFinding): void => {
		const key = `${finding.category}|${finding.source ?? ""}|${finding.evidence ?? ""}`;
		if (seen.has(key)) return;
		const count = counts.get(finding.category) ?? 0;
		if (count >= MAX_FINDINGS_PER_CATEGORY) return;
		seen.add(key);
		counts.set(finding.category, count + 1);
		findings.push(finding);
	};

	const fuseStates = new Map(info.fuses.map((fuse) => [fuse.name, fuse.state]));

	for (const { name, message } of RISKY_FUSES) {
		if (fuseStates.get(name) !== "enabled") continue;
		push({
			severity: "warning",
			category: "Electron",
			message,
			evidence: `${name}=enabled`
		});
	}

	if (fuseStates.get("OnlyLoadAppFromAsar") === "disabled") {
		push({
			severity: "info",
			category: "Electron",
			message: "OnlyLoadAppFromAsar is disabled — the app can load unpacked app code",
			evidence: "OnlyLoadAppFromAsar=disabled"
		});
	}

	if (fuseStates.get("EnableEmbeddedAsarIntegrityValidation") === "disabled") {
		push({
			severity: "info",
			category: "Electron",
			message:
				"EnableEmbeddedAsarIntegrityValidation is disabled — app.asar can be modified without detection",
			evidence: "EnableEmbeddedAsarIntegrityValidation=disabled"
		});
	}

	const integrity = info.integrity;
	if (integrity && !integrity.valid) {
		push({
			severity: "critical",
			category: "Electron",
			message: "app.asar header does not match the ElectronAsarIntegrity hash",
			evidence: `expected ${integrity.expected}, actual ${integrity.actual}`,
			source: "app.asar"
		});
	}

	if (info.sourceMaps.length > 0) {
		push({
			severity: "info",
			category: "Electron",
			message: `Shipped source maps (${info.sourceMaps.length}) expose original source`,
			evidence: info.sourceMaps.slice(0, 3).join(", "),
			source: "app.asar"
		});
	}

	for (const file of files) {
		for (const { severity, name, pattern } of WEB_PREFERENCE_PATTERNS) {
			const match = pattern.exec(file.content);
			if (!match) continue;
			push({
				severity,
				category: "Electron",
				message: `webPreferences weakens the renderer: ${name}`,
				evidence: match[0],
				source: file.relativePath
			});
		}
	}

	return findings;
}
