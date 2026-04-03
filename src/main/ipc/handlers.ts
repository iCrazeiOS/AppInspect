/**
 * IPC Handlers
 *
 * Registers all Electron IPC handlers for the main process.
 * Bridges renderer requests to the analysis orchestrator.
 */

import { ipcMain, dialog, BrowserWindow } from "electron";
import { writeFileSync } from "fs";
import type { TabName } from "../../shared/ipc-types";
import {
  analyzeIPA,
  analyzeBinary,
  getCachedResult,
} from "../analysis/orchestrator";
import { exportAnalysis } from "../export/json";

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
  // ── analyze-ipa ──
  ipcMain.handle("analyze-ipa", async (_event, args: { path: string }) => {
    try {
      const result = await analyzeIPA(args.path, (phase, percent) => {
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
      throw err;
    }
  });

  // ── analyze-binary ──
  ipcMain.handle("analyze-binary", async (_event, args: { binaryIndex: number; cpuType?: number; cpuSubtype?: number }) => {
    try {
      const result = await analyzeBinary(args.binaryIndex, (phase, percent) => {
        win.webContents.send("update-progress", { phase, percent, message: phase });
      }, args.cpuType, args.cpuSubtype);

      const sanitized = sanitizeBigInts(result);
      win.webContents.send("analysis-complete");
      return sanitized;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      win.webContents.send("analysis-error", { message });
      throw err;
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
          return sanitizeBigInts({ tab: "overview", data: cached.overview });
        case "strings":
          return sanitizeBigInts({ tab: "strings", data: cached.strings });
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
        default:
          throw new Error(`Unknown tab: ${tab}`);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      win.webContents.send("analysis-error", { message });
      throw err;
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

      const { canceled, filePath } = await dialog.showSaveDialog(win, {
        defaultPath: "disect-export.json",
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
      throw err;
    }
  });

  // ── open-file-picker ──
  ipcMain.handle("open-file-picker", async () => {
    try {
      const result = await dialog.showOpenDialog(win, {
        filters: [{ name: "IPA Files", extensions: ["ipa"] }],
        properties: ["openFile"],
      });

      if (result.canceled || result.filePaths.length === 0) {
        return null;
      }

      return result.filePaths[0] ?? null;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      win.webContents.send("analysis-error", { message });
      return null;
    }
  });
}
