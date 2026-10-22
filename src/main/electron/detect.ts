/**
 * Electron bundle detection.
 *
 * Locates `app.asar`, the Electron Framework version and fuse wire, and the
 * archive integrity entry in the app's Info.plist. The archive is parsed once;
 * all reads are best-effort, so a malformed `app.asar` yields info without an
 * `asarPath` instead of failing the analysis.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import type { ElectronAsarIntegrity, ElectronInfo, PlistValue } from "../../shared/types";
import { parsePlistBuffer } from "../parser/plist";
import { type AsarArchive, readAsarFile, readAsarHeader } from "./asar";
import { readFuses } from "./fuses";

const FRAMEWORK_NAME = "Electron Framework";
const FRAMEWORK_DIR = `${FRAMEWORK_NAME}.framework`;
const PACKAGE_JSON_MAX = 1024 * 1024;

function readPlist(filePath: string): Record<string, unknown> | null {
	try {
		return parsePlistBuffer(fs.readFileSync(filePath));
	} catch {
		return null;
	}
}

function frameworkRoots(appRoot: string): string[] {
	const bases = [path.join(appRoot, "Contents", "Frameworks"), path.join(appRoot, "Frameworks")];
	const roots: string[] = [];
	for (const base of bases) {
		const frameworkDir = path.join(base, FRAMEWORK_DIR);
		roots.push(path.join(frameworkDir, "Versions", "A"), frameworkDir);
	}
	return roots;
}

/** `app.asar` locations for a `.app`, its `Contents`, or an unpacked app root. */
function resourcesDirs(appRoot: string): string[] {
	return [
		path.join(appRoot, "Contents", "Resources"),
		path.join(appRoot, "Resources"),
		path.join(appRoot, "resources")
	];
}

function readPackageJson(archive: AsarArchive): { [key: string]: PlistValue } | null {
	const result = readAsarFile(archive, "package.json", PACKAGE_JSON_MAX);
	if (!result.ok) return null;
	try {
		const parsed: unknown = JSON.parse(result.data.data.toString("utf8"));
		if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
		return parsed as { [key: string]: PlistValue };
	} catch {
		return null;
	}
}

function readIntegrity(appRoot: string, archive: AsarArchive): ElectronAsarIntegrity | null {
	const plistPaths = [
		path.join(appRoot, "Contents", "Info.plist"),
		path.join(appRoot, "Info.plist")
	];
	for (const plistPath of plistPaths) {
		const plist = readPlist(plistPath);
		const table = plist?.ElectronAsarIntegrity;
		if (typeof table !== "object" || table === null || Array.isArray(table)) continue;

		for (const [key, value] of Object.entries(table)) {
			if (!key.endsWith("app.asar")) continue;
			if (typeof value !== "object" || value === null || Array.isArray(value)) continue;
			const record = value as Record<string, unknown>;
			const algorithm = record.algorithm;
			const expected = record.hash;
			if (typeof algorithm !== "string" || typeof expected !== "string") continue;

			// Electron only writes SHA-256 here. An unknown algorithm cannot be
			// verified, so leave integrity unreported instead of calling it a mismatch.
			if (algorithm.toLowerCase() !== "sha256") continue;

			const actual = archive.headerHash;
			return { algorithm, expected, actual, valid: expected.toLowerCase() === actual };
		}
	}
	return null;
}

export function detectElectron(appRoot: string, isMacOS: boolean): ElectronInfo | null {
	const candidates = resourcesDirs(appRoot);
	if (!isMacOS) candidates.reverse();
	const asarPath = candidates
		.map((dir) => path.join(dir, "app.asar"))
		.find((candidate) => fs.existsSync(candidate));
	const hasFramework = frameworkRoots(appRoot).some((root) =>
		fs.existsSync(path.join(root, FRAMEWORK_NAME))
	);
	if (!asarPath && !hasFramework) return null;

	const info: ElectronInfo = {
		fileCount: 0,
		unpackedCount: 0,
		fuses: [],
		sourceMaps: [],
		nativeAddons: []
	};

	for (const root of frameworkRoots(appRoot)) {
		if (info.electronVersion === undefined) {
			const plist = readPlist(path.join(root, "Resources", "Info.plist"));
			const version = plist?.CFBundleVersion;
			if (typeof version === "string" && version.length > 0) {
				info.electronVersion = version;
			}
		}
		if (info.fuses.length === 0) {
			const binaryPath = path.join(root, FRAMEWORK_NAME);
			if (fs.existsSync(binaryPath)) {
				info.fuses = readFuses(binaryPath);
			}
		}
	}

	if (asarPath) {
		const parsed = readAsarHeader(asarPath);
		if (parsed.ok) {
			const archive = parsed.data;
			info.asarPath = asarPath;
			info.asarSize = archive.size;
			info.fileCount = archive.fileCount;
			info.unpackedCount = archive.unpackedCount;

			const packageJson = readPackageJson(archive);
			if (packageJson) info.packageJson = packageJson;

			const integrity = readIntegrity(appRoot, archive);
			if (integrity) info.integrity = integrity;

			for (const record of archive.files.values()) {
				if (record.link !== undefined) continue;
				const lower = record.path.toLowerCase();
				if (lower.endsWith(".map")) info.sourceMaps.push(record.path);
				else if (lower.endsWith(".node")) info.nativeAddons.push(record.path);
			}
		}
	}

	info.sourceMaps.sort((a, b) => a.localeCompare(b));
	info.nativeAddons.sort((a, b) => a.localeCompare(b));
	return info;
}
