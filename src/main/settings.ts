/**
 * App Settings — persistent JSON file in userData directory.
 *
 * Uses Electron's userData path when running inside the desktop app,
 * falls back to ~/.appinspect when running standalone (e.g. MCP server).
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import type { AppSettings } from "../shared/types";

const DEFAULT_SETTINGS: AppSettings = {
	scanAllBinaries: false,
	maxBundleSizeMB: 200,
	maxFileSizeMB: 50
};

let userDataDir: string;
try {
	userDataDir = require("electron").app.getPath("userData");
} catch {
	userDataDir = path.join(os.homedir(), ".appinspect");
}

function getSettingsPath(): string {
	return path.join(userDataDir, "appinspect-settings.json");
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

	// Merge on top of current disk state to avoid clobbering
	// another instance's concurrent writes
	const current = loadSettings();
	const merged = { ...current, ...settings };
	fs.writeFileSync(settingsPath, JSON.stringify(merged, null, 2), "utf-8");
}
