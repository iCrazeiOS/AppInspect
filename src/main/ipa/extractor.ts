import { execFile } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { isMachOFile } from "../parser/macho";
import { parsePlistBuffer } from "../parser/plist";

export interface BinaryInfo {
	name: string;
	path: string;
	type: "main" | "framework" | "extension";
}

export interface ExtractionResult {
	success: true;
	extractedDir: string;
}

export interface ExtractionError {
	success: false;
	error: string;
}

/**
 * Extract an IPA file (ZIP archive) to a destination directory.
 * Uses async system tools so the main thread stays responsive.
 */
export async function extractIPA(
	ipaPath: string,
	destDir: string
): Promise<ExtractionResult | ExtractionError> {
	try {
		// Ensure destDir exists
		fs.mkdirSync(destDir, { recursive: true });

		return await extractWithSystem(ipaPath, destDir);
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		return { success: false, error: `Failed to extract IPA: ${message}` };
	}
}

function extractWithSystem(
	ipaPath: string,
	destDir: string
): Promise<ExtractionResult | ExtractionError> {
	return new Promise((resolve) => {
		const args: string[] = [];
		let cmd: string;

		if (process.platform === "win32") {
			cmd = "powershell.exe";
			args.push(
				"-NoProfile",
				"-Command",
				`Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::ExtractToDirectory('${ipaPath.replace(/'/g, "''")}', '${destDir.replace(/'/g, "''")}')`
			);
		} else {
			cmd = "unzip";
			args.push("-o", "-q", ipaPath, "-d", destDir);
		}

		execFile(cmd, args, { timeout: 120000 }, (err) => {
			if (err) {
				const message = err instanceof Error ? err.message : String(err);
				resolve({ success: false, error: `Failed to extract IPA: ${message}` });
			} else {
				resolve({ success: true, extractedDir: destDir });
			}
		});
	});
}

/**
 * Discover the .app bundle inside an extracted IPA's Payload directory.
 * Returns the absolute path to the .app directory, or null if not found.
 */
export function discoverAppBundle(extractedDir: string): string | null {
	const payloadDir = path.join(extractedDir, "Payload");

	if (!fs.existsSync(payloadDir)) {
		return null;
	}

	try {
		const entries = fs.readdirSync(payloadDir, { withFileTypes: true });
		for (const entry of entries) {
			if (entry.isDirectory() && entry.name.endsWith(".app")) {
				return path.join(payloadDir, entry.name);
			}
		}
	} catch {
		return null;
	}

	return null;
}

/** Add binary only if its real path hasn't been seen (skips symlink duplicates). */
function addBinary(info: BinaryInfo, binaries: BinaryInfo[], seenRealPaths: Set<string>): void {
	try {
		const realPath = fs.realpathSync(info.path);
		if (seenRealPaths.has(realPath)) return;
		seenRealPaths.add(realPath);
	} catch {
		/* add anyway if resolve fails */
	}
	binaries.push(info);
}

function resolveBundleExecutable(bundlePath: string, fallbackName: string): string | null {
	const execName = readCFBundleExecutable(path.join(bundlePath, "Info.plist")) ?? fallbackName;
	const binaryPath = path.join(bundlePath, execName);
	if (fs.existsSync(binaryPath) && isMachOFile(binaryPath)) {
		return binaryPath;
	}
	return null;
}

/**
 * Discover binaries in an app bundle: the main executable,
 * frameworks in Frameworks/, and app extensions in PlugIns/.
 */
export function discoverBinaries(appBundlePath: string): BinaryInfo[] {
	const binaries: BinaryInfo[] = [];
	const seenRealPaths = new Set<string>();

	// Determine main executable name from the .app folder name
	const appName = path.basename(appBundlePath, ".app");
	const mainBinaryPath = path.join(appBundlePath, appName);

	if (fs.existsSync(mainBinaryPath)) {
		addBinary(
			{
				name: appName,
				path: mainBinaryPath,
				type: "main"
			},
			binaries,
			seenRealPaths
		);
	}

	// Discover frameworks and dylibs in Frameworks/
	const frameworksDir = path.join(appBundlePath, "Frameworks");
	if (fs.existsSync(frameworksDir)) {
		try {
			const entries = fs.readdirSync(frameworksDir, { withFileTypes: true });
			for (const entry of entries) {
				if (entry.isDirectory() && entry.name.endsWith(".framework")) {
					const frameworkName = path.basename(entry.name, ".framework");
					const frameworkBinaryPath = path.join(frameworksDir, entry.name, frameworkName);
					addBinary(
						{
							name: frameworkName,
							path: frameworkBinaryPath,
							type: "framework"
						},
						binaries,
						seenRealPaths
					);
				} else if (entry.isFile() && entry.name.endsWith(".dylib")) {
					const dylibPath = path.join(frameworksDir, entry.name);
					addBinary(
						{
							name: entry.name,
							path: dylibPath,
							type: "framework"
						},
						binaries,
						seenRealPaths
					);
				}
			}
		} catch {
			// Ignore errors reading frameworks directory
		}
	}

	// Discover app extensions in PlugIns/
	const plugInsDir = path.join(appBundlePath, "PlugIns");
	if (fs.existsSync(plugInsDir)) {
		try {
			const entries = fs.readdirSync(plugInsDir, { withFileTypes: true });
			for (const entry of entries) {
				if (entry.isDirectory() && entry.name.endsWith(".appex")) {
					const extensionName = path.basename(entry.name, ".appex");
					const extensionPath = path.join(plugInsDir, entry.name);
					const extensionBinaryPath = resolveBundleExecutable(
						extensionPath,
						extensionName
					);
					if (!extensionBinaryPath) continue;
					addBinary(
						{
							name: extensionName,
							path: extensionBinaryPath,
							type: "extension"
						},
						binaries,
						seenRealPaths
					);
				}
			}
		} catch {
			// Ignore errors reading plugins directory
		}
	}

	return binaries;
}

/**
 * Detect whether a .app bundle uses macOS layout (Contents/MacOS/)
 * or iOS layout (flat, binary at root of .app).
 */
export function isMacOSAppBundle(appBundlePath: string): boolean {
	return fs.existsSync(path.join(appBundlePath, "Contents", "MacOS"));
}

/**
 * Read CFBundleExecutable from an Info.plist (handles both binary and XML format).
 */
function readCFBundleExecutable(plistPath: string): string | null {
	try {
		const buf = fs.readFileSync(plistPath);
		const parsed = parsePlistBuffer(buf);
		if (typeof parsed.CFBundleExecutable === "string") {
			return parsed.CFBundleExecutable;
		}
	} catch {
		// ignore
	}
	return null;
}

/**
 * Discover binaries in a macOS .app bundle.
 * macOS layout: Contents/MacOS/<binary>, Contents/Frameworks/, Contents/PlugIns/
 */
export function discoverMacOSBinaries(appBundlePath: string): BinaryInfo[] {
	const binaries: BinaryInfo[] = [];
	const seenRealPaths = new Set<string>();

	const contentsDir = path.join(appBundlePath, "Contents");
	const macosDir = path.join(contentsDir, "MacOS");

	// Get executable name from Info.plist (supports binary and XML plists)
	const plistPath = path.join(contentsDir, "Info.plist");
	const execName = readCFBundleExecutable(plistPath) ?? path.basename(appBundlePath, ".app");

	// All Mach-O files in Contents/MacOS/ — the main executable plus helpers
	if (fs.existsSync(macosDir)) {
		try {
			const entries = fs.readdirSync(macosDir, { withFileTypes: true });
			for (const entry of entries) {
				if (!entry.isFile()) continue;
				const fullPath = path.join(macosDir, entry.name);
				if (!isMachOFile(fullPath)) continue;

				addBinary(
					{
						name: entry.name,
						path: fullPath,
						type: entry.name === execName ? "main" : "framework"
					},
					binaries,
					seenRealPaths
				);
			}
		} catch {
			/* ignore */
		}

		// Ensure the main binary is first in the list
		const mainIdx = binaries.findIndex((b) => b.type === "main");
		if (mainIdx > 0) {
			const [main] = binaries.splice(mainIdx, 1);
			binaries.unshift(main!);
		}
	}

	// Frameworks in Contents/Frameworks/
	const frameworksDir = path.join(contentsDir, "Frameworks");
	if (fs.existsSync(frameworksDir)) {
		try {
			const entries = fs.readdirSync(frameworksDir, { withFileTypes: true });
			for (const entry of entries) {
				const fullEntryPath = path.join(frameworksDir, entry.name);

				if (entry.isDirectory() && entry.name.endsWith(".framework")) {
					const fwName = path.basename(entry.name, ".framework");
					// macOS frameworks: Versions/Current/<name>, Versions/A/<name>, or flat <name>
					const candidates = [
						path.join(fullEntryPath, "Versions", "Current", fwName),
						path.join(fullEntryPath, fwName)
					];
					// Also check Versions/<letter>/<name> for versioned frameworks
					try {
						const versionsDir = path.join(fullEntryPath, "Versions");
						if (fs.existsSync(versionsDir)) {
							const vEntries = fs.readdirSync(versionsDir);
							for (const v of vEntries) {
								if (v !== "Current") {
									candidates.push(path.join(versionsDir, v, fwName));
								}
							}
						}
					} catch {
						/* ignore */
					}

					for (const candidate of candidates) {
						try {
							if (
								fs.existsSync(candidate) &&
								fs.statSync(candidate).isFile() &&
								isMachOFile(candidate)
							) {
								addBinary(
									{ name: fwName, path: candidate, type: "framework" },
									binaries,
									seenRealPaths
								);
								break;
							}
						} catch {
							/* ignore */
						}
					}
				} else if (entry.isFile() && entry.name.endsWith(".dylib")) {
					// Loose dylibs in Frameworks/
					if (isMachOFile(fullEntryPath)) {
						addBinary(
							{ name: entry.name, path: fullEntryPath, type: "framework" },
							binaries,
							seenRealPaths
						);
					}
				}
			}
		} catch {
			/* ignore */
		}
	}

	// PlugIns in Contents/PlugIns/
	const plugInsDir = path.join(contentsDir, "PlugIns");
	if (fs.existsSync(plugInsDir)) {
		try {
			const entries = fs.readdirSync(plugInsDir, { withFileTypes: true });
			for (const entry of entries) {
				if (
					entry.isDirectory() &&
					(entry.name.endsWith(".appex") || entry.name.endsWith(".bundle"))
				) {
					const ext = path.extname(entry.name);
					const extName = path.basename(entry.name, ext);
					// Read the plugin's own CFBundleExecutable, or fall back to folder name
					const pluginPlist = path.join(plugInsDir, entry.name, "Contents", "Info.plist");
					const pluginExec = readCFBundleExecutable(pluginPlist) ?? extName;
					// Extension binary may be in Contents/MacOS/ or flat
					const nestedPath = path.join(
						plugInsDir,
						entry.name,
						"Contents",
						"MacOS",
						pluginExec
					);
					const flatPath = path.join(plugInsDir, entry.name, pluginExec);
					const extBinaryPath = fs.existsSync(nestedPath) ? nestedPath : flatPath;
					if (fs.existsSync(extBinaryPath) && isMachOFile(extBinaryPath)) {
						addBinary(
							{ name: extName, path: extBinaryPath, type: "extension" },
							binaries,
							seenRealPaths
						);
					}
				}
			}
		} catch {
			/* ignore */
		}
	}

	return binaries;
}

/**
 * Remove the temporary extraction directory recursively.
 */
export function cleanupExtracted(destDir: string): void {
	if (fs.existsSync(destDir)) {
		fs.rmSync(destDir, { recursive: true, force: true });
	}
}
