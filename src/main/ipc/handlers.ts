/**
 * IPC Handlers
 *
 * Registers all Electron IPC handlers for the main process.
 * Bridges renderer requests to the analysis orchestrator.
 */

import { statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { type BrowserWindow, dialog, ipcMain, shell } from "electron";
import { FILE_PREVIEW_BYTES } from "../../shared/file-preview";
import { formatCount, formatSize } from "../../shared/format";
import type { TabName } from "../../shared/ipc-types";
import type { AppSettings } from "../../shared/types";
import { clearCache, getCacheInfo } from "../analysis/cache";
import type { SearchableTab } from "../analysis/orchestrator";
import { AnalysisSession } from "../analysis/orchestrator";
import { buildHeaders } from "../export/headers";
import { exportAnalysis } from "../export/json";
import { loadSettings, saveSettings } from "../settings";
import { isInsideAny } from "../util/safe-path";

/**
 * Custom replacer for JSON.stringify that converts BigInt values to numbers.
 */
function bigintReplacer(_key: string, value: unknown): unknown {
	if (typeof value === "bigint") {
		// If it fits in a safe integer, return number; otherwise string
		if (value <= BigInt(Number.MAX_SAFE_INTEGER) && value >= BigInt(Number.MIN_SAFE_INTEGER)) {
			return Number(value);
		}
		return value.toString();
	}
	return value;
}

/**
 * Deep-clone an object, converting all BigInt values to numbers.
 * This is necessary because Electron's structured clone for IPC
 * does not support BigInt.
 */
function sanitizeBigInts<T>(obj: T): T {
	return JSON.parse(JSON.stringify(obj, bigintReplacer)) as T;
}

const sessions = new Map<string, AnalysisSession>();

function getSession(sessionId: string): AnalysisSession {
	const session = sessions.get(sessionId);
	if (!session) throw new Error(`No session for ${sessionId}. Analyse a file first.`);
	return session;
}

/** True when the path belongs to one of the loaded sessions. */
function isKnownPath(candidate: string): boolean {
	for (const session of sessions.values()) {
		if (isInsideAny(session.getAllowedOpenRoots(), candidate)) return true;
	}
	return false;
}

/** Cache directories read by any open session. Never clear these. */
function inUseCacheDirs(): Set<string> {
	const dirs = new Set<string>();
	for (const session of sessions.values()) {
		for (const dir of session.getCacheDirs()) dirs.add(path.resolve(dir));
	}
	return dirs;
}

/** First eight bytes of every PNG file. */
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

export function registerIPCHandlers(win: BrowserWindow): void {
	// ── analyse-ipa ──
	ipcMain.handle("analyse-ipa", async (_event, args: { path: string }) => {
		const sessionId = args.path;
		try {
			const session = new AnalysisSession();
			sessions.set(sessionId, session);
			const result = await session.analyseIPA(args.path, (phase, percent) => {
				win.webContents.send("update-progress", {
					sessionId,
					phase,
					percent,
					message: phase
				});
			});

			const sanitized = sanitizeBigInts(result);
			win.webContents.send("analysis-complete", { sessionId });
			return { sessionId, result: sanitized };
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			win.webContents.send("analysis-error", { sessionId, message });
			return null;
		}
	});

	// ── analyse-file (unified: IPA, Mach-O, or DEB) ──
	ipcMain.handle("analyse-file", async (_event, args: { path: string }) => {
		const sessionId = args.path;
		try {
			const session = new AnalysisSession();
			sessions.set(sessionId, session);
			const result = await session.analyseFile(args.path, (phase, percent) => {
				win.webContents.send("update-progress", {
					sessionId,
					phase,
					percent,
					message: phase
				});
			});

			const sanitized = sanitizeBigInts(result);
			win.webContents.send("analysis-complete", { sessionId });
			return { sessionId, result: sanitized };
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			win.webContents.send("analysis-error", { sessionId, message });
			return null;
		}
	});

	// ── analyse-binary ──
	ipcMain.handle(
		"analyse-binary",
		async (
			_event,
			args: { sessionId: string; binaryIndex: number; cpuType?: number; cpuSubtype?: number }
		) => {
			const { sessionId } = args;
			try {
				const session = getSession(sessionId);
				const result = await session.analyseBinary(
					args.binaryIndex,
					(phase, percent) => {
						win.webContents.send("update-progress", {
							sessionId,
							phase,
							percent,
							message: phase
						});
					},
					args.cpuType,
					args.cpuSubtype
				);

				const sanitized = sanitizeBigInts(result);
				win.webContents.send("analysis-complete", { sessionId });
				return sanitized;
			} catch (err) {
				const message = err instanceof Error ? err.message : String(err);
				win.webContents.send("analysis-error", { sessionId, message });
				return null;
			}
		}
	);

	// ── get-tab-data ──
	ipcMain.handle("get-tab-data", async (_event, args: { sessionId: string; tab: TabName }) => {
		const { sessionId } = args;
		try {
			const session = getSession(sessionId);
			const cached = session.getResult();
			if (!cached) {
				throw new Error("No analysis result available");
			}

			const { tab } = args;

			switch (tab) {
				case "overview":
					return sanitizeBigInts({
						tab: "overview",
						data: { ...cached.overview, hooks: cached.hooks, electron: cached.electron }
					});
				case "strings":
					return sanitizeBigInts({
						tab: "strings",
						data: {
							binary: cached.strings,
							localisation: cached.localisationStrings ?? []
						}
					});
				case "headers":
					return sanitizeBigInts({ tab: "headers", data: cached.headers });
				case "libraries":
					return sanitizeBigInts({ tab: "libraries", data: cached.libraries });
				case "symbols":
					return sanitizeBigInts({ tab: "symbols", data: cached.symbols });
				case "swift":
					return sanitizeBigInts({ tab: "swift", data: cached.swift });
				case "classes":
					return sanitizeBigInts({
						tab: "classes",
						data: {
							classes: cached.classes,
							protocols: cached.protocols ?? [],
							protocolDetails: cached.protocolDetails ?? []
						}
					});
				case "entitlements": {
					// Null prototype: keys come from an untrusted plist inside the
					// analysed binary, so "__proto__" must not be the setter.
					const entObj: Record<string, unknown> = Object.create(null);
					if (Array.isArray(cached.entitlements)) {
						for (const e of cached.entitlements) entObj[e.key] = e.value;
					}
					return sanitizeBigInts({ tab: "entitlements", data: entObj });
				}
				case "infoPlist":
					return sanitizeBigInts({ tab: "infoPlist", data: cached.infoPlist });
				case "electron":
					if (!cached.electron) throw new Error("No Electron bundle in this analysis");
					return sanitizeBigInts({
						tab: "electron",
						data: { info: cached.electron, files: session.getAsarTree() }
					});
				case "security":
					return sanitizeBigInts({ tab: "security", data: cached.security });
				case "files":
					return sanitizeBigInts({ tab: "files", data: cached.files });
				case "hooks":
					return sanitizeBigInts({ tab: "hooks", data: cached.hooks });
				case "size":
					return sanitizeBigInts({ tab: "size", data: cached.size });
				default:
					throw new Error(`Unknown tab: ${tab}`);
			}
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			win.webContents.send("analysis-error", { sessionId, message });
			return null;
		}
	});

	// ── search-all-binaries ──
	ipcMain.handle(
		"search-all-binaries",
		async (
			_event,
			args: {
				sessionId: string;
				query: string;
				tab: SearchableTab;
				isRegex?: boolean;
				caseSensitive?: boolean;
			}
		) => {
			const { sessionId } = args;
			try {
				const session = getSession(sessionId);
				const results = await session.searchAllBinaries(
					args.query,
					args.tab,
					(phase, percent) => {
						win.webContents.send("update-progress", {
							sessionId,
							phase,
							percent,
							message: phase
						});
					},
					args.isRegex,
					args.caseSensitive
				);
				// Clears the tab's loading state set by the indexing progress events
				win.webContents.send("analysis-complete", { sessionId });
				return results;
			} catch (err) {
				const message = err instanceof Error ? err.message : String(err);
				win.webContents.send("analysis-error", { sessionId, message });
				return [];
			}
		}
	);

	// ── get-library-graph ──
	ipcMain.handle("get-library-graph", async (_event, args: { sessionId: string }) => {
		const session = getSession(args.sessionId);
		return sanitizeBigInts(await session.getLibraryGraph());
	});

	// ── get-size-tree ──
	ipcMain.handle("get-size-tree", (_event, args: { sessionId: string }) => {
		return getSession(args.sessionId).getSizeTree();
	});

	// ── read-hex ──
	ipcMain.handle(
		"read-hex",
		(_event, args: { sessionId: string; offset: number; length: number }) => {
			try {
				const session = getSession(args.sessionId);
				return session.readHex(args.offset, args.length);
			} catch (err) {
				const message = err instanceof Error ? err.message : String(err);
				win.webContents.send("analysis-error", { sessionId: args.sessionId, message });
				return null;
			}
		}
	);

	// ── read-asar-file ──
	ipcMain.handle(
		"read-asar-file",
		(
			_event,
			args: { sessionId: string; path: string; maxBytes?: number; includeImage?: boolean }
		) => {
			try {
				const session = getSession(args.sessionId);
				return session.readAsarFile(
					args.path,
					args.maxBytes ?? FILE_PREVIEW_BYTES,
					args.includeImage === true
				);
			} catch (err) {
				const message = err instanceof Error ? err.message : String(err);
				win.webContents.send("analysis-error", { sessionId: args.sessionId, message });
				return null;
			}
		}
	);

	// ── open-asar-file ──
	ipcMain.handle("open-asar-file", async (_event, args: { sessionId: string; path: string }) => {
		try {
			const target = getSession(args.sessionId).extractAsarFile(args.path);
			if (target) await shell.openPath(target);
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			win.webContents.send("analysis-error", { sessionId: args.sessionId, message });
		}
	});

	// ── read-file-preview ──
	ipcMain.handle(
		"read-file-preview",
		(
			_event,
			args: { sessionId: string; path: string; maxBytes?: number; includeImage?: boolean }
		) => {
			try {
				const session = getSession(args.sessionId);
				return session.readWorkspaceFile(
					args.path,
					args.maxBytes ?? FILE_PREVIEW_BYTES,
					args.includeImage === true
				);
			} catch (err) {
				const message = err instanceof Error ? err.message : String(err);
				win.webContents.send("analysis-error", { sessionId: args.sessionId, message });
				return null;
			}
		}
	);

	// ── search-hex ──
	ipcMain.handle(
		"search-hex",
		(
			_event,
			args: {
				sessionId: string;
				regionOffset: number;
				regionSize: number;
				pattern: number[];
				caseInsensitive?: boolean;
			}
		) => {
			try {
				const session = getSession(args.sessionId);
				return session.searchHex(
					args.regionOffset,
					args.regionSize,
					args.pattern,
					args.caseInsensitive
				);
			} catch (err) {
				const message = err instanceof Error ? err.message : String(err);
				win.webContents.send("analysis-error", { sessionId: args.sessionId, message });
				return null;
			}
		}
	);

	// ── export-json ──
	ipcMain.handle("export-json", async (_event, args: { sessionId: string; tabs?: TabName[] }) => {
		const { sessionId } = args;
		try {
			const session = getSession(sessionId);
			const cached = session.getResult();
			if (!cached) {
				throw new Error("No analysis result available");
			}

			const jsonString = exportAnalysis(cached, args.tabs);

			// Build filename from app/input name + active binary
			const appName = cached.overview?.ipa?.appName;
			const inputFile = cached.overview?.filePath;
			const inputName =
				appName ??
				(inputFile ? path.basename(inputFile, path.extname(inputFile)) : null) ??
				"appinspect";
			const binaryName = session.getActiveBinaryName();
			const needsBinarySuffix =
				binaryName && binaryName !== appName && binaryName !== inputName;
			const defaultPath = needsBinarySuffix
				? `${inputName}-${binaryName}-export.json`
				: `${inputName}-export.json`;

			const { canceled, filePath } = await dialog.showSaveDialog(win, {
				defaultPath,
				filters: [{ name: "JSON", extensions: ["json"] }]
			});

			if (canceled || !filePath) {
				return { success: false };
			}

			writeFileSync(filePath, jsonString, "utf-8");
			return { success: true, path: filePath };
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			win.webContents.send("analysis-error", { sessionId, message });
			return { success: false };
		}
	});

	// ── export-headers ──
	ipcMain.handle("export-headers", async (_event, args: { sessionId: string }) => {
		const { sessionId } = args;
		try {
			const session = getSession(sessionId);
			const cached = session.getResult();
			if (!cached) {
				throw new Error("No analysis result available");
			}

			const { canceled, filePaths } = await dialog.showOpenDialog(win, {
				title: "Export Headers",
				message:
					"Choose a folder for the generated header files. Existing files with the same names are overwritten.",
				buttonLabel: "Export",
				properties: ["openDirectory", "createDirectory", "promptToCreate"]
			});

			const outputDir = filePaths[0];
			if (canceled || !outputDir) {
				return { success: false };
			}

			const files = buildHeaders({
				classes: cached.classes ?? [],
				protocols: cached.protocols ?? [],
				protocolDetails: cached.protocolDetails ?? [],
				binaryName: session.getActiveBinaryName()
			});

			for (const file of files) {
				writeFileSync(path.join(outputDir, file.name), file.content, "utf-8");
			}

			return { success: true, path: outputDir, files: files.length };
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			win.webContents.send("analysis-error", { sessionId, message });
			return { success: false };
		}
	});

	// ── export-asar ──
	ipcMain.handle("export-asar", async (_event, args: { sessionId: string }) => {
		const { sessionId } = args;
		try {
			const session = getSession(sessionId);
			if (!session.hasAsarArchive()) {
				throw new Error("No readable app.asar archive available");
			}

			const { canceled, filePaths } = await dialog.showOpenDialog(win, {
				title: "Export app.asar",
				message:
					"Choose a folder to extract app.asar into. Files with the same paths are overwritten.",
				buttonLabel: "Export",
				properties: ["openDirectory", "createDirectory", "promptToCreate"]
			});

			const outputDir = filePaths[0];
			if (canceled || !outputDir) {
				return { success: false };
			}

			const { files, skipped } = session.exportAsar(outputDir);
			return { success: true, path: outputDir, files, skipped };
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			win.webContents.send("analysis-error", { sessionId, message });
			return { success: false };
		}
	});

	// ── save-png ──
	ipcMain.handle("save-png", async (_event, args: { defaultName: string; data: Uint8Array }) => {
		const data = Buffer.from(args.data);
		if (!data.subarray(0, PNG_SIGNATURE.length).equals(PNG_SIGNATURE)) {
			throw new Error("Refusing to save: data is not a PNG");
		}
		// The renderer only suggests a name; never let it pick the directory
		const defaultPath = `${path.basename(args.defaultName).replace(/\.png$/i, "")}.png`;
		const { canceled, filePath } = await dialog.showSaveDialog(win, {
			defaultPath,
			filters: [{ name: "PNG image", extensions: ["png"] }]
		});
		if (canceled || !filePath) return { success: false };
		writeFileSync(filePath, data);
		return { success: true, path: filePath };
	});

	// ── close-session ──
	ipcMain.handle("close-session", (_event, args: { sessionId: string }) => {
		sessions.delete(args.sessionId);
	});

	// ── get-settings ──
	ipcMain.handle("get-settings", () => {
		return loadSettings();
	});

	// ── set-settings ──
	ipcMain.handle("set-settings", (_event, settings: AppSettings) => {
		saveSettings(settings);
	});

	// ── get-cache-info ──
	ipcMain.handle("get-cache-info", async () => {
		const info = await getCacheInfo();
		const { removedEntries, keptInUse } = await clearCache({
			inUse: inUseCacheDirs,
			dryRun: true
		});
		return { ...info, clearableEntries: removedEntries, keptInUse };
	});

	// ── clear-cache ──
	ipcMain.handle("clear-cache", async () => {
		const none = {
			cleared: false,
			entryCount: 0,
			removedEntries: 0,
			removedBytes: 0,
			keptInUse: 0,
			keptRecentTemp: 0,
			failed: 0
		};
		try {
			const { entryCount } = await getCacheInfo();
			if (entryCount === 0) return none;

			// Re-read the in-use set on every removal: a file may be opened while the dialog is up.
			const options = { inUse: inUseCacheDirs };
			const preview = await clearCache({ ...options, dryRun: true });
			if (preview.removedEntries === 0)
				return { ...none, entryCount, keptInUse: preview.keptInUse };

			const { response } = await dialog.showMessageBox(win, {
				type: "warning",
				title: "Clear cache",
				message: `Clear ${formatSize(preview.removedBytes)} of cached extractions?`,
				detail:
					`${formatCount(preview.removedEntries, "entry", "entries")} will be removed.` +
					(preview.keptInUse
						? ` ${formatCount(preview.keptInUse, "entry", "entries")} used by open files will be kept.`
						: "") +
					"\n\nFiles are extracted again the next time you open them.",
				buttons: ["Cancel", "Clear cache"],
				defaultId: 1,
				cancelId: 0,
				noLink: true
			});
			if (response !== 1) return { ...none, entryCount };

			return { cleared: true, entryCount, ...(await clearCache(options)) };
		} catch (err) {
			console.error("[AppInspect] Failed to clear cache:", err);
			return { ...none, failed: 1 };
		}
	});

	// ── show-item-in-folder ──
	ipcMain.handle("show-item-in-folder", (_event, args: { path: string }) => {
		if (!isKnownPath(args.path)) return;
		shell.showItemInFolder(args.path);
	});

	// ── open-file ──
	ipcMain.handle("open-file", async (_event, args: { path: string }) => {
		if (!isKnownPath(args.path)) return;
		await shell.openPath(args.path);
	});

	// ── get-platform ──
	ipcMain.handle("get-platform", () => process.platform);

	// ── open-file-picker ──
	ipcMain.handle("open-file-picker", async (_event, args?: { mode?: "file" | "folder" }) => {
		try {
			if (args?.mode === "folder") {
				const result = await dialog.showOpenDialog(win, {
					properties: ["openDirectory"]
				});
				return result.canceled ? null : (result.filePaths[0] ?? null);
			}

			// On macOS, .app bundles and .xcframeworks are directories that appear as files in
			// Finder, so we need both openFile and openDirectory. On Windows
			// and Linux, combining the two flags results in a folder-only
			// picker, so we only allow openFile (folders can still be dropped).
			const props: Electron.OpenDialogOptions["properties"] =
				process.platform === "darwin" ? ["openFile", "openDirectory"] : ["openFile"];

			const isMac = process.platform === "darwin";

			const filters: Electron.FileFilter[] = [
				{
					name: "Supported Files",
					extensions: isMac
						? ["ipa", "tipa", "deb", "dylib", "app", "xcframework", "zip"]
						: ["ipa", "tipa", "deb", "dylib", "zip"]
				},
				...(isMac ? [{ name: "App Bundles", extensions: ["app"] }] : []),
				...(isMac ? [{ name: "XCFrameworks", extensions: ["xcframework"] }] : []),
				{ name: "Zipped XCFrameworks", extensions: ["zip"] },
				{ name: "IPA Files", extensions: ["ipa", "tipa"] },
				{ name: "DEB Packages", extensions: ["deb"] },
				{ name: "Mach-O Binaries", extensions: ["dylib"] },
				{ name: "All Files", extensions: ["*"] }
			];

			const result = await dialog.showOpenDialog(win, {
				filters,
				properties: props
			});

			if (result.canceled || result.filePaths.length === 0) {
				return null;
			}

			return result.filePaths[0] ?? null;
		} catch {
			return null;
		}
	});

	// ── is-directory ──
	ipcMain.handle("is-directory", (_event, args: { path: string }) => {
		try {
			return statSync(args.path).isDirectory();
		} catch {
			return false;
		}
	});
}
