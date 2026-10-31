/**
 * Folder discovery.
 *
 * Walks a plain directory and collects every Mach-O binary it contains. App
 * and framework bundles are traversed as ordinary directories, so their main
 * executables, embedded dylibs and frameworks all surface. `.deb` and `.ipa`
 * archives are extracted to the cache first, then their binaries are added too.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { extractDEB } from "../deb/extractor";
import type { BinaryInfo } from "../ipa/extractor";
import { discoverAppBundle, discoverBinaries, extractIPA } from "../ipa/extractor";
import { isMachOFile } from "../parser/macho";
import { yieldToEventLoop } from "./binary-pipeline";
import { extractToCache, getCacheDir } from "./cache";

/** Directories that never contain useful Mach-O binaries. */
const SKIPPED_DIRS = new Set([".git", ".hg", ".svn", "node_modules", "_CodeSignature", "__MACOSX"]);

const TYPE_PRIORITY: Record<BinaryInfo["type"], number> = {
	main: 0,
	framework: 1,
	extension: 2
};

/** Relative path with forward slashes — stable across platforms and unique. */
function relativeName(root: string, fullPath: string): string {
	return path.relative(root, fullPath).split(path.sep).join("/");
}

function classify(root: string, fullPath: string): BinaryInfo["type"] {
	const rel = relativeName(root, fullPath);
	if (rel.endsWith(".dylib")) return "framework";
	if (rel.includes(".appex/") || rel.includes(".bundle/") || rel.includes("/PlugIns/")) {
		return "extension";
	}
	if (rel.includes(".framework/") || root.toLowerCase().endsWith(".framework"))
		return "framework";
	return "main";
}

function addBinary(
	binaries: BinaryInfo[],
	seenRealPaths: Set<string>,
	name: string,
	binaryPath: string,
	type: BinaryInfo["type"]
): void {
	let realPath: string;
	try {
		realPath = fs.realpathSync(binaryPath);
	} catch {
		return;
	}
	if (seenRealPaths.has(realPath)) return;
	seenRealPaths.add(realPath);
	binaries.push({ name, path: binaryPath, type });
}

/** Extract a DEB and return its binaries named relative to the package. */
async function discoverDebBinaries(debPath: string, root: string): Promise<BinaryInfo[]> {
	const cacheDir = getCacheDir(debPath);
	const extraction = await extractToCache(cacheDir, (dest) => extractDEB(debPath, dest));
	if (!extraction.cached && !extraction.result.success) return [];

	// Re-read from the stable cache directory (also supplies dataDir on a hit).
	const result = await extractDEB(debPath, cacheDir);
	if (!result.success) return [];

	const debName = relativeName(root, debPath);
	return result.binaries.map((b) => ({
		name: `${debName}/${relativeName(result.dataDir, b.path)}`,
		path: b.path,
		type: b.type === "tweak" ? "main" : "framework"
	}));
}

/** Extract an IPA and return its app-bundle binaries named relative to the archive. */
async function discoverIpaBinaries(ipaPath: string, root: string): Promise<BinaryInfo[]> {
	const cacheDir = getCacheDir(ipaPath);
	const extraction = await extractToCache(cacheDir, (dest) => extractIPA(ipaPath, dest));
	if (!extraction.cached && !extraction.result.success) return [];

	const appBundlePath = discoverAppBundle(cacheDir);
	if (!appBundlePath) return [];

	const ipaName = relativeName(root, ipaPath);
	return discoverBinaries(appBundlePath).map((b) => ({
		name: `${ipaName}/${b.name}`,
		path: b.path,
		type: b.type
	}));
}

/**
 * Find every analysable Mach-O binary under `rootPath`, including binaries
 * inside `.deb` and `.ipa` archives. Names are paths relative to the folder, so
 * binaries with the same basename remain distinguishable in the selector.
 */
export async function discoverFolderBinaries(
	rootPath: string,
	progressCallback: (phase: string, percent: number) => void
): Promise<BinaryInfo[]> {
	const binaries: BinaryInfo[] = [];
	const seenRealPaths = new Set<string>();
	const debPaths: string[] = [];
	const ipaPaths: string[] = [];

	async function walk(dir: string): Promise<void> {
		let entries: fs.Dirent[];
		try {
			entries = await fs.promises.readdir(dir, { withFileTypes: true });
		} catch {
			return;
		}
		entries.sort((a, b) => a.name.localeCompare(b.name));

		for (const entry of entries) {
			if (entry.name.startsWith(".")) continue;
			const fullPath = path.join(dir, entry.name);

			if (entry.isSymbolicLink()) continue;
			if (entry.isDirectory()) {
				if (!SKIPPED_DIRS.has(entry.name)) await walk(fullPath);
				continue;
			}
			if (!entry.isFile()) continue;

			const ext = path.extname(entry.name).toLowerCase();
			if (ext === ".deb") {
				debPaths.push(fullPath);
				continue;
			}
			if (ext === ".ipa" || ext === ".tipa") {
				ipaPaths.push(fullPath);
				continue;
			}
			// Mach-O executables are often extensionless; .dylib is the other
			// common shipped form. Anything else is a resource, not code.
			if ((ext === "" || ext === ".dylib") && isMachOFile(fullPath)) {
				addBinary(
					binaries,
					seenRealPaths,
					relativeName(rootPath, fullPath),
					fullPath,
					classify(rootPath, fullPath)
				);
			}
		}
	}

	progressCallback("Scanning folder...", 0);
	await walk(rootPath);

	for (let i = 0; i < debPaths.length; i++) {
		const debPath = debPaths[i]!;
		progressCallback(
			`Extracting ${path.basename(debPath)}...`,
			Math.round((i / debPaths.length) * 10)
		);
		await yieldToEventLoop();
		for (const binary of await discoverDebBinaries(debPath, rootPath)) {
			addBinary(binaries, seenRealPaths, binary.name, binary.path, binary.type);
		}
	}

	for (let i = 0; i < ipaPaths.length; i++) {
		const ipaPath = ipaPaths[i]!;
		progressCallback(
			`Extracting ${path.basename(ipaPath)}...`,
			10 + Math.round((i / ipaPaths.length) * 10)
		);
		await yieldToEventLoop();
		for (const binary of await discoverIpaBinaries(ipaPath, rootPath)) {
			addBinary(binaries, seenRealPaths, binary.name, binary.path, binary.type);
		}
	}

	return binaries.sort(
		(a, b) => TYPE_PRIORITY[a.type] - TYPE_PRIORITY[b.type] || a.name.localeCompare(b.name)
	);
}
