// Renderer entry point
/// <reference path="./global.d.ts" />

import type { AnalysisResult } from "../shared/types";

// ── Types ──
type AppState = "empty" | "loading" | "content" | "error";

// ── DOM references ──
const $ = <T extends HTMLElement>(sel: string): T =>
  document.querySelector(sel) as T;

const dropOverlay = $<HTMLDivElement>("#drop-overlay");
const emptyState = $<HTMLDivElement>("#empty-state");
const loadingBar = $<HTMLDivElement>("#loading-bar");
const loadingText = $<HTMLDivElement>("#loading-text");
const tabContent = $<HTMLDivElement>("#tab-content");
const binarySelector = $<HTMLDivElement>("#binary-selector");

const tabButtons = document.querySelectorAll<HTMLButtonElement>(".tab-btn");
const tabPanels = document.querySelectorAll<HTMLDivElement>(".tab-panel");

// ── State ──
let currentTab = "overview";
let appState: AppState = "empty";
let analysisResult: AnalysisResult | null = null;
const loadedTabs = new Set<string>();

// ── App state transitions ──
function setState(state: AppState): void {
  appState = state;

  emptyState.classList.toggle("hidden", state !== "empty");
  loadingBar.classList.toggle("hidden", state !== "loading");
  tabContent.classList.toggle("hidden", state !== "content");
}

function setLoadingPhase(phase: string, percent?: number): void {
  loadingText.textContent = percent != null
    ? `${phase} (${Math.round(percent)}%)`
    : phase;
}

function showError(message: string): void {
  setState("empty");
  // Show error in the empty state area
  const errorDiv = document.createElement("div");
  errorDiv.className = "error-message";
  errorDiv.textContent = `Error: ${message}`;
  errorDiv.style.cssText = "color: #f85149; padding: 1rem; text-align: center;";
  emptyState.appendChild(errorDiv);
  // Auto-remove after 5 seconds
  setTimeout(() => errorDiv.remove(), 5000);
}

// ── Tab switching ──
function switchTab(tabId: string): void {
  currentTab = tabId;

  tabButtons.forEach((btn) => {
    btn.classList.toggle("active", btn.dataset["tab"] === tabId);
  });

  tabPanels.forEach((panel) => {
    const isTarget = panel.id === `tab-${tabId}`;
    panel.classList.toggle("hidden", !isTarget);
  });

  // Lazy-load tab data if we have an analysis result and haven't loaded this tab yet
  if (analysisResult && !loadedTabs.has(tabId)) {
    loadTabData(tabId);
  }
}

async function loadTabData(tabId: string): Promise<void> {
  try {
    const tabData = await window.api.getTabData(tabId);
    loadedTabs.add(tabId);
    // Tab data is now available for rendering
    // (Future tasks will add tab-specific rendering here)
    console.log(`[Disect] Tab data loaded for: ${tabId}`, tabData);
  } catch (err) {
    console.error(`[Disect] Failed to load tab data for ${tabId}:`, err);
  }
}

tabButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    const tabId = btn.dataset["tab"];
    if (tabId) {
      switchTab(tabId);
    }
  });
});

// ── IPA Analysis ──
async function startAnalysis(filePath: string): Promise<void> {
  setState("loading");
  setLoadingPhase("Starting analysis...", 0);
  loadedTabs.clear();
  analysisResult = null;

  try {
    const result = await window.api.analyzeIPA(filePath);
    analysisResult = result;
    loadedTabs.add("overview"); // Overview is included in the full result
    setState("content");
    switchTab("overview");
    console.log("[Disect] Analysis complete:", result);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    showError(message);
    console.error("[Disect] Analysis failed:", err);
  }
}

// ── Open IPA button ──
async function handleOpenIPA(): Promise<void> {
  try {
    const filePath = await window.api.openFilePicker();
    if (filePath) {
      await startAnalysis(filePath);
    }
  } catch (err) {
    console.error("[Disect] File picker error:", err);
  }
}

$<HTMLButtonElement>("#btn-open-ipa").addEventListener("click", handleOpenIPA);
$<HTMLButtonElement>("#btn-open-ipa-empty").addEventListener("click", handleOpenIPA);

// ── Drag and drop ──
let dragCounter = 0;

document.addEventListener("dragenter", (e: DragEvent) => {
  e.preventDefault();
  e.stopPropagation();
  dragCounter++;
  if (dragCounter === 1) {
    dropOverlay.classList.remove("hidden");
  }
});

document.addEventListener("dragover", (e: DragEvent) => {
  e.preventDefault();
  e.stopPropagation();
});

document.addEventListener("dragleave", (e: DragEvent) => {
  e.preventDefault();
  e.stopPropagation();
  dragCounter--;
  if (dragCounter <= 0) {
    dragCounter = 0;
    dropOverlay.classList.add("hidden");
  }
});

document.addEventListener("drop", (e: DragEvent) => {
  e.preventDefault();
  e.stopPropagation();
  dragCounter = 0;
  dropOverlay.classList.add("hidden");

  const files = e.dataTransfer?.files;
  if (!files || files.length === 0) return;

  const file = files[0];
  // Electron provides .path on File objects
  const filePath = (file as File & { path?: string }).path;

  if (!filePath) {
    console.warn("[Disect] No file path available from drop");
    return;
  }

  if (!filePath.toLowerCase().endsWith(".ipa")) {
    console.warn("[Disect] Dropped file is not an IPA:", filePath);
    return;
  }

  console.log("[Disect] Dropped IPA:", filePath);
  startAnalysis(filePath);
});

// ── IPC listeners ──
window.api.onProgress((data) => {
  setLoadingPhase(data.phase, data.percent);
});

window.api.onComplete(() => {
  console.log("[Disect] Analysis complete signal received");
});

window.api.onError((data) => {
  showError(data.message);
});

// ── Exports for future use ──
export { setState, setLoadingPhase, switchTab };

// ── Init ──
console.log("[Disect] Renderer loaded");
setState("empty");
switchTab("overview");
