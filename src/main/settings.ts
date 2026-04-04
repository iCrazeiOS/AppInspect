/**
 * App Settings — persistent JSON file in userData directory.
 */

import { app } from "electron";
import * as fs from "fs";
import * as path from "path";
import type { AppSettings } from "../shared/types";

const DEFAULT_SETTINGS: AppSettings = {
  scanAllBinaries: false,
  maxBundleSizeMB: 200,
  maxFileSizeMB: 50,
};

function getSettingsPath(): string {
  return path.join(app.getPath("userData"), "appinspect-settings.json");
}

export function loadSettings(): AppSettings {
  try {
    const raw = fs.readFileSync(getSettingsPath(), "utf-8");
    return { ...DEFAULT_SETTINGS, ...JSON.parse(raw) };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

export function saveSettings(settings: AppSettings): void {
  const settingsPath = getSettingsPath();
  fs.mkdirSync(path.dirname(settingsPath), { recursive: true });
  fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2), "utf-8");
}
