/**
 * File tab state management for multi-file sessions.
 *
 * Each open file gets a FileTabState that holds its analysis result
 * and all per-file UI state. Keyed by file path (sessionId).
 */

import type { AnalysisResult } from "../shared/types";

export type FileAppState = "loading" | "content" | "error";

export interface FileTabState {
  sessionId: string;
  displayName: string;
  analysisResult: AnalysisResult | null;
  currentSectionTab: string;
  currentBinaryIndex: number;
  currentArchIndex: number;
  loadedSectionTabs: Set<string>;
  isEncrypted: boolean;
  encryptionBannerDismissed: boolean;
  appState: FileAppState;
}

export const fileTabs = new Map<string, FileTabState>();
export let activeFileTabId: string | null = null;

export function getActiveFileTab(): FileTabState | null {
  if (!activeFileTabId) return null;
  return fileTabs.get(activeFileTabId) ?? null;
}

export function getFileTab(sessionId: string): FileTabState | null {
  return fileTabs.get(sessionId) ?? null;
}

export function createFileTab(sessionId: string, displayName: string): FileTabState {
  const state: FileTabState = {
    sessionId,
    displayName,
    analysisResult: null,
    currentSectionTab: "overview",
    currentBinaryIndex: 0,
    currentArchIndex: 0,
    loadedSectionTabs: new Set(),
    isEncrypted: false,
    encryptionBannerDismissed: false,
    appState: "loading",
  };
  fileTabs.set(sessionId, state);
  return state;
}

export function removeFileTab(sessionId: string): void {
  fileTabs.delete(sessionId);
  if (activeFileTabId === sessionId) {
    activeFileTabId = null;
  }
}

export function setActiveFileTabId(sessionId: string | null): void {
  activeFileTabId = sessionId;
}

export function getOpenFileTabs(): FileTabState[] {
  return Array.from(fileTabs.values());
}
