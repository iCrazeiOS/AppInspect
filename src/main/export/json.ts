/**
 * JSON Export
 *
 * Serializes analysis data as JSON with metadata wrapper.
 * Supports full export or per-tab filtered export.
 */

import type { AnalysisResult } from "../../shared/types";
import type { TabName } from "../../shared/ipc-types";

/** Map of tab names to their keys in AnalysisResult */
const TAB_KEY_MAP: Record<TabName, keyof AnalysisResult> = {
  overview: "overview",
  strings: "strings",
  headers: "headers",
  libraries: "libraries",
  symbols: "symbols",
  classes: "classes",
  entitlements: "entitlements",
  infoPlist: "infoPlist",
  hooks: "hooks",
  security: "security",
  files: "files",
};

/**
 * JSON replacer that converts BigInt values to strings.
 */
function bigintReplacer(_key: string, value: unknown): unknown {
  if (typeof value === "bigint") {
    if (
      value <= BigInt(Number.MAX_SAFE_INTEGER) &&
      value >= BigInt(Number.MIN_SAFE_INTEGER)
    ) {
      return Number(value);
    }
    return value.toString();
  }
  return value;
}

/**
 * Serialize analysis data as JSON.
 *
 * @param result - The full analysis result
 * @param tabs - If specified, include only these tabs' data. If omitted, export everything.
 * @returns JSON string with metadata wrapper
 */
export function exportAnalysis(result: AnalysisResult, tabs?: TabName[]): string {
  const appName = result.overview?.ipa?.appName ?? "Unknown";

  let data: Record<string, unknown>;

  if (!tabs || tabs.length === 0) {
    // Export everything
    data = { ...result } as Record<string, unknown>;
  } else {
    // Export only requested tabs
    data = {};
    for (const tab of tabs) {
      const key = TAB_KEY_MAP[tab];
      if (key && key in result) {
        data[key] = result[key];
      }
    }
  }

  const wrapper = {
    exportedAt: new Date().toISOString(),
    appName,
    version: "1.0.0",
    data,
  };

  return JSON.stringify(wrapper, bigintReplacer, 2);
}
