/**
 * XCFramework discovery.
 *
 * Reads an .xcframework's Info.plist (AvailableLibraries) to enumerate its
 * platform slices and resolve each slice's binary. Dynamic slices become
 * selectable binaries; static libraries (ar archives) are listed but skipped,
 * since the analysis pipeline only parses Mach-O.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import type { XCFrameworkLibrary } from "../../shared/types";
import type { BinaryInfo } from "../ipa/extractor";
import { isMachOFile, parseFatHeader } from "../parser/macho";
import { parsePlistBuffer } from "../parser/plist";
import { safeJoin } from "../util/safe-path";

export interface XCFrameworkSlice extends XCFrameworkLibrary {
	/** Absolute path to the slice's library (.framework dir, .dylib or .a) */
	libraryPath: string;
	/** Absolute path to the slice binary, or null if it doesn't exist */
	absoluteBinaryPath: string | null;
}

export interface XCFrameworkContents {
	slices: XCFrameworkSlice[];
	/** Analysable slices, device builds first, named "<library> (<identifier>)" */
	binaries: BinaryInfo[];
}

/** True when `dirPath` is an .xcframework directory (extension match, case-insensitive). */
export function isXCFrameworkPath(dirPath: string): boolean {
	return dirPath
		.replace(/[\\/]+$/, "")
		.toLowerCase()
		.endsWith(".xcframework");
}

/** Directory levels searched for an .xcframework inside an extracted ZIP. */
const MAX_ZIP_SEARCH_DEPTH = 8;

/**
 * Find the shallowest .xcframework inside an extracted archive (e.g. a SwiftPM
 * binary target zip). Searches breadth-first, since some zips nest the
 * framework under the directory path it was built in.
 */
export function findXCFramework(extractedDir: string): string | null {
	let level = [extractedDir];
	for (let depth = 0; depth < MAX_ZIP_SEARCH_DEPTH && level.length > 0; depth++) {
		const next: string[] = [];
		for (const dir of level) {
			let entries: fs.Dirent[];
			try {
				entries = fs.readdirSync(dir, { withFileTypes: true });
			} catch {
				continue;
			}
			for (const entry of entries) {
				if (!entry.isDirectory() || entry.name === "__MACOSX") continue;
				const fullPath = path.join(dir, entry.name);
				if (isXCFrameworkPath(entry.name)) return fullPath;
				next.push(fullPath);
			}
		}
		level = next;
	}
	return null;
}

/**
 * True when the binary is a Mach-O image the pipeline can parse. Universal
 * static libraries carry a fat header too, but each slice is an ar archive.
 */
function isAnalysableBinary(filePath: string): boolean {
	if (!isMachOFile(filePath)) return false;
	let fd: number | null = null;
	try {
		fd = fs.openSync(filePath, "r");
		const head = Buffer.alloc(4096);
		const bytesRead = fs.readSync(fd, head, 0, head.length, 0);
		const fat = parseFatHeader(head.buffer.slice(0, bytesRead));
		const firstSlice = fat.ok ? fat.data[0] : undefined;
		if (!firstSlice) return false;
		if (firstSlice.offset === 0) return true; // thin Mach-O

		const magic = Buffer.alloc(4);
		fs.readSync(fd, magic, 0, 4, firstSlice.offset);
		return magic.toString("ascii") !== "!<ar";
	} catch {
		return false;
	} finally {
		if (fd !== null) fs.closeSync(fd);
	}
}

/** Resolve a slice binary when Info.plist omits BinaryPath. */
function defaultBinaryPath(libraryPath: string): string {
	if (!libraryPath.endsWith(".framework")) return libraryPath;
	const name = path.basename(libraryPath, ".framework");
	return path.join(libraryPath, name);
}

/** Enumerate the slices of an .xcframework and the binaries that can be analysed. */
export function discoverXCFramework(xcframeworkPath: string): XCFrameworkContents {
	const plistPath = path.join(xcframeworkPath, "Info.plist");
	if (!fs.existsSync(plistPath)) {
		throw new Error("XCFramework is missing Info.plist");
	}
	const plist = parsePlistBuffer(fs.readFileSync(plistPath));
	const available = plist.AvailableLibraries;
	if (!Array.isArray(available)) {
		throw new Error("XCFramework Info.plist has no AvailableLibraries");
	}

	const slices: XCFrameworkSlice[] = [];
	for (const raw of available as Record<string, unknown>[]) {
		const identifier = raw.LibraryIdentifier;
		const libraryPath = raw.LibraryPath;
		if (typeof identifier !== "string" || typeof libraryPath !== "string") continue;

		const binaryPath =
			typeof raw.BinaryPath === "string" ? raw.BinaryPath : defaultBinaryPath(libraryPath);
		const sliceDir = safeJoin(xcframeworkPath, identifier);
		const libAbs = sliceDir && safeJoin(sliceDir, libraryPath);
		const binAbs = sliceDir && safeJoin(sliceDir, binaryPath);
		if (!libAbs || !binAbs) continue;

		const exists = fs.existsSync(binAbs) && fs.statSync(binAbs).isFile();
		slices.push({
			identifier,
			platform: typeof raw.SupportedPlatform === "string" ? raw.SupportedPlatform : "",
			platformVariant:
				typeof raw.SupportedPlatformVariant === "string"
					? raw.SupportedPlatformVariant
					: undefined,
			architectures: Array.isArray(raw.SupportedArchitectures)
				? raw.SupportedArchitectures.filter((a): a is string => typeof a === "string")
				: [],
			binaryPath,
			analysable: exists && isAnalysableBinary(binAbs),
			libraryPath: libAbs,
			absoluteBinaryPath: exists ? binAbs : null
		});
	}

	// Device slices first so the default binary is the one that ships in apps
	const ordered = [
		...slices.filter((s) => !s.platformVariant),
		...slices.filter((s) => s.platformVariant)
	];
	const binaries: BinaryInfo[] = ordered
		.filter((s) => s.analysable)
		.map((s) => ({
			name: `${path.basename(s.libraryPath, path.extname(s.libraryPath))} (${s.identifier})`,
			path: s.absoluteBinaryPath!,
			type: "framework"
		}));

	return { slices, binaries };
}
