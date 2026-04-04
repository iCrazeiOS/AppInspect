/**
 * IPC Handlers
 *
 * Registers all Electron IPC handlers for the main process.
 * Bridges renderer requests to the analysis orchestrator.
 */

import { ipcMain, dialog, BrowserWindow, shell } from "electron";
import { writeFileSync } from "fs";
import path from "path";
import type { TabName } from "../../shared/ipc-types";
import {
  analyseIPA,
  analyseFile,
  analyseBinary,
  getCachedResult,
  getActiveBinaryName,
  searchAllBinaries,
} from "../analysis/orchestrator";
import type { SearchableTab } from "../analysis/orchestrator";
import { exportAnalysis } from "../export/json";
import { loadSettings, saveSettings } from "../settings";
import type { AppSettings } from "../../shared/types";

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

export function registerIPCHandlers(win: BrowserWindow): void {
  // ── analyse-ipa ──
  ipcMain.handle("analyse-ipa", async (_event, args: { path: string }) => {
    try {
      const result = await analyseIPA(args.path, (phase, percent) => {
        win.webContents.send("update-progress", {
          phase,
          percent,
          message: phase,
        });
      });

      const sanitized = sanitizeBigInts(result);
      win.webContents.send("analysis-complete");
      return sanitized;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      win.webContents.send("analysis-error", { message });
      return null;
    }
  });

  // ── analyse-file (unified: IPA, Mach-O, or DEB) ──
  ipcMain.handle("analyse-file", async (_event, args: { path: string }) => {
    try {
      const result = await analyseFile(args.path, (phase, percent) => {
        win.webContents.send("update-progress", {
          phase,
          percent,
          message: phase,
        });
      });

      const sanitized = sanitizeBigInts(result);
      win.webContents.send("analysis-complete");
      return sanitized;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      win.webContents.send("analysis-error", { message });
      return null;
    }
  });

  // ── analyse-binary ──
  ipcMain.handle("analyse-binary", async (_event, args: { binaryIndex: number; cpuType?: number; cpuSubtype?: number }) => {
    try {
      const result = await analyseBinary(args.binaryIndex, (phase, percent) => {
        win.webContents.send("update-progress", { phase, percent, message: phase });
      }, args.cpuType, args.cpuSubtype);

      const sanitized = sanitizeBigInts(result);
      win.webContents.send("analysis-complete");
      return sanitized;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      win.webContents.send("analysis-error", { message });
      return null;
    }
  });

  // ── get-tab-data ──
  ipcMain.handle("get-tab-data", async (_event, args: { tab: TabName; binaryIndex?: number }) => {
    try {
      const cached = getCachedResult();
      if (!cached) {
        throw new Error("No analysis result available");
      }

      const { tab } = args;

      switch (tab) {
        case "overview":
          return sanitizeBigInts({ tab: "overview", data: { ...cached.overview, hooks: cached.hooks } });
        case "strings":
          return sanitizeBigInts({ tab: "strings", data: {
            binary: cached.strings,
            localisation: cached.localisationStrings ?? [],
          } });
        case "headers":
          return sanitizeBigInts({ tab: "headers", data: cached.headers });
        case "libraries":
          return sanitizeBigInts({ tab: "libraries", data: cached.libraries });
        case "symbols":
          return sanitizeBigInts({ tab: "symbols", data: cached.symbols });
        case "classes":
          return sanitizeBigInts({ tab: "classes", data: { classes: cached.classes, protocols: cached.protocols ?? [] } });
        case "entitlements": {
          // Convert Entitlement[] to flat object for the renderer
          const entObj: Record<string, unknown> = {};
          if (Array.isArray(cached.entitlements)) {
            for (const e of cached.entitlements) entObj[e.key] = e.value;
          }
          return sanitizeBigInts({ tab: "entitlements", data: entObj });
        }
        case "infoPlist":
        case "infoplist" as any:
          return sanitizeBigInts({ tab: "infoPlist", data: cached.infoPlist });
        case "security":
          return sanitizeBigInts({ tab: "security", data: cached.security });
        case "files":
          return sanitizeBigInts({ tab: "files", data: cached.files });
        case "hooks":
          return sanitizeBigInts({ tab: "hooks", data: cached.hooks });
        default:
          throw new Error(`Unknown tab: ${tab}`);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      win.webContents.send("analysis-error", { message });
      return null;
    }
  });

  // ── search-all-binaries ──
  ipcMain.handle("search-all-binaries", async (_event, args: { query: string; tab: SearchableTab; isRegex?: boolean; caseSensitive?: boolean }) => {
    try {
      return await searchAllBinaries(
        args.query,
        args.tab,
        (phase, percent) => {
          win.webContents.send("update-progress", { phase, percent, message: phase });
        },
        args.isRegex,
        args.caseSensitive,
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      win.webContents.send("analysis-error", { message });
      return [];
    }
  });

  // ── export-json ──
  ipcMain.handle("export-json", async (_event, args: { tabs?: TabName[] }) => {
    try {
      const cached = getCachedResult();
      if (!cached) {
        throw new Error("No analysis result available");
      }

      const jsonString = exportAnalysis(cached, args.tabs);

      // Build filename from app/input name + active binary
      const appName = cached.overview?.ipa?.appName;
      const inputFile = cached.overview?.filePath;
      const inputName = appName
        ?? (inputFile ? path.basename(inputFile, path.extname(inputFile)) : null)
        ?? "appinspect";
      const binaryName = getActiveBinaryName();
      const needsBinarySuffix = binaryName && binaryName !== appName && binaryName !== inputName;
      const defaultPath = needsBinarySuffix
        ? `${inputName}-${binaryName}-export.json`
        : `${inputName}-export.json`;

      const { canceled, filePath } = await dialog.showSaveDialog(win, {
        defaultPath,
        filters: [{ name: "JSON", extensions: ["json"] }],
      });

      if (canceled || !filePath) {
        return { success: false };
      }

      writeFileSync(filePath, jsonString, "utf-8");
      return { success: true, path: filePath };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      win.webContents.send("analysis-error", { message });
      return { success: false };
    }
  });

  // ── get-settings ──
  ipcMain.handle("get-settings", () => {
    return loadSettings();
  });

  // ── set-settings ──
  ipcMain.handle("set-settings", (_event, settings: AppSettings) => {
    saveSettings(settings);
  });

  // ── show-item-in-folder ──
  ipcMain.handle("show-item-in-folder", (_event, args: { path: string }) => {
    shell.showItemInFolder(args.path);
  });

  // ── open-file ──
  ipcMain.handle("open-file", async (_event, args: { path: string }) => {
    await shell.openPath(args.path);
  });

  // ── get-platform ──
  ipcMain.handle("get-platform", () => process.platform);

  // ── open-file-picker ──
  ipcMain.handle("open-file-picker", async () => {
    try {
      // On macOS, .app bundles are directories that appear as files in
      // Finder, so we need both openFile and openDirectory. On Windows
      // and Linux, combining the two flags results in a folder-only
      // picker, so we only allow openFile (folders can still be dropped).
      const props: Electron.OpenDialogOptions["properties"] =
        process.platform === "darwin"
          ? ["openFile", "openDirectory"]
          : ["openFile"];

      const isMac = process.platform === "darwin";

      const filters: Electron.FileFilter[] = [
        { name: "Supported Files", extensions: isMac ? ["ipa", "deb", "dylib", "app"] : ["ipa", "deb", "dylib"] },
        ...(isMac ? [{ name: "App Bundles", extensions: ["app"] }] : []),
        { name: "IPA Files", extensions: ["ipa"] },
        { name: "DEB Packages", extensions: ["deb"] },
        { name: "Mach-O Binaries", extensions: ["dylib"] },
        { name: "All Files", extensions: ["*"] },
      ];

      const result = await dialog.showOpenDialog(win, {
        filters,
        properties: props,
      });

      if (result.canceled || result.filePaths.length === 0) {
        return null;
      }

      return result.filePaths[0] ?? null;
    } catch {
      return null;
    }
  });
}
