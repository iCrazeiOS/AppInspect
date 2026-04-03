// Renderer entry point
/// <reference path="./global.d.ts" />

import type { AnalysisResult, BinaryInfo } from "../shared/types";
import { renderOverview } from "./tabs/overview";
import { renderLibraries } from "./tabs/libraries";
import { renderHeaders } from "./tabs/headers";
import { renderStrings } from "./tabs/strings";
import { renderSymbols } from "./tabs/symbols";
import { renderSecurity } from "./tabs/security";
import { renderFiles } from "./tabs/files";
import { renderClasses } from "./tabs/classes";
import { renderEntitlements } from "./tabs/entitlements";
import { renderPlist } from "./tabs/plist";
import { showToast } from "./components/toast";

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
const binaryDropdown = $<HTMLSelectElement>("#binary-dropdown");
const archSelector = $<HTMLDivElement>("#arch-selector");
const archDropdown = $<HTMLSelectElement>("#arch-dropdown");
const sidebarFooter = $<HTMLDivElement>("#sidebar-footer");
const exportTabBtns = document.querySelectorAll<HTMLButtonElement>(".export-tab-btn");

const tabButtons = document.querySelectorAll<HTMLButtonElement>(".tab-btn");
const tabPanels = document.querySelectorAll<HTMLDivElement>(".tab-panel");

console.log("[Disect] Renderer loaded. window.api =", typeof window.api, window.api);

// ── Search state (imported from dedicated module to avoid circular deps) ──
import { clearSearchStates, getSearchBar } from "./search-state";

// ── Keyboard shortcut: Ctrl/Cmd+F to focus active tab's search bar ──
document.addEventListener("keydown", (e: KeyboardEvent) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "f") {
    e.preventDefault();
    const bar = getSearchBar(currentTab);
    if (bar) {
      bar.focus();
    }
  }
});

// ── State ──
let currentTab = "overview";
let appState: AppState = "empty";
let analysisResult: AnalysisResult | null = null;
let currentBinaryIndex = 0;
let isSwitchingBinary = false;
let isEncrypted = false;
let encryptionBannerDismissed = false;
const loadedTabs = new Set<string>();

// ── App state transitions ──
function setTabsDisabled(disabled: boolean): void {
  tabButtons.forEach((btn) => {
    btn.classList.toggle("tab-btn--disabled", disabled);
  });
}

function setState(state: AppState): void {
  appState = state;

  emptyState.classList.toggle("hidden", state !== "empty");
  loadingBar.classList.toggle("hidden", state !== "loading");
  tabContent.classList.toggle("hidden", state !== "content");
  setTabsDisabled(state !== "content");
}

function setLoadingPhase(phase: string, percent?: number): void {
  loadingText.textContent = percent != null
    ? `${phase} (${Math.round(percent)}%)`
    : phase;
}

function showError(message: string): void {
  setState("empty");
  showToast(message, "error");
}

// ── Encryption warning banner ──
function checkEncryptionBanner(result: AnalysisResult): void {
  const encrypted =
    result.overview?.hardening?.encrypted === true ||
    (result.overview?.encryptionInfo?.cryptid != null &&
      result.overview.encryptionInfo.cryptid !== 0);

  isEncrypted = encrypted;
  encryptionBannerDismissed = false;
  updateEncryptionBanner();
}

function updateEncryptionBanner(): void {
  let banner = document.getElementById("encryption-banner");
  if (isEncrypted && !encryptionBannerDismissed) {
    if (!banner) {
      banner = document.createElement("div");
      banner.id = "encryption-banner";
      banner.className = "encryption-banner";
      banner.innerHTML =
        '<span class="encryption-banner-icon">\u26A0</span>' +
        '<span class="encryption-banner-text">This binary is FairPlay encrypted. Strings, classes, and symbols data may be incomplete. Use a decrypted IPA for full analysis.</span>' +
        '<button class="encryption-banner-close">\u00D7</button>';
      // Insert before tab-content inside main-content
      const mainContent = document.getElementById("main-content");
      if (mainContent && tabContent) {
        mainContent.insertBefore(banner, tabContent);
      }
      banner.querySelector(".encryption-banner-close")!.addEventListener("click", () => {
        encryptionBannerDismissed = true;
        updateEncryptionBanner();
      });
    }
    banner.classList.remove("hidden");
  } else if (banner) {
    banner.classList.add("hidden");
  }
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

  // Re-show encryption banner on tab switch as a reminder
  if (isEncrypted) {
    encryptionBannerDismissed = false;
    updateEncryptionBanner();
  }

  // Lazy-load tab data if we have an analysis result and haven't loaded this tab yet
  if (analysisResult && !loadedTabs.has(tabId)) {
    loadTabData(tabId);
  }
}

async function loadTabData(tabId: string): Promise<void> {
  try {
    const tabData = await window.api.getTabData(tabId);
    loadedTabs.add(tabId);

    const panel = document.getElementById(`tab-${tabId}`);
    if (panel && tabData != null) {
      switch (tabId) {
        case "overview":
          renderOverview(panel, (tabData as any)?.data ?? tabData);
          break;
        case "libraries":
          renderLibraries(panel, (tabData as any)?.data ?? tabData);
          break;
        case "headers":
          renderHeaders(panel, (tabData as any)?.data ?? tabData);
          break;
        case "strings":
          renderStrings(panel, (tabData as any)?.data ?? tabData);
          break;
        case "symbols":
          renderSymbols(panel, (tabData as any)?.data ?? tabData);
          break;
        case "security":
          renderSecurity(panel, (tabData as any)?.data ?? tabData);
          break;
        case "files":
          renderFiles(panel, (tabData as any)?.data ?? tabData);
          break;
        case "classes":
          renderClasses(panel, (tabData as any)?.data ?? tabData);
          break;
        case "entitlements":
          renderEntitlements(panel, (tabData as any)?.data ?? tabData);
          break;
        case "infoplist": {
          const plistData = (tabData as any)?.data ?? tabData;
          renderPlist(panel, plistData);
          break;
        }
        default:
          break;
      }
    }

    console.log(`[Disect] Tab data loaded for: ${tabId}`, tabData);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    showToast(`Failed to load ${tabId} tab: ${message}`, "error");
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

// ── Binary selector ──

/** Badge label for binary type */
function binaryTypeBadge(type: BinaryInfo["type"]): string {
  switch (type) {
    case "main":
      return "Main";
    case "framework":
      return "Framework";
    case "extension":
      return "Extension";
    default:
      return String(type);
  }
}

/** Populate the binary dropdown from discovered binaries */
function populateBinarySelector(binaries: BinaryInfo[]): void {
  binaryDropdown.innerHTML = "";

  if (!binaries || binaries.length <= 1) {
    binarySelector.classList.add("hidden");
    return;
  }

  for (let i = 0; i < binaries.length; i++) {
    const bin = binaries[i];
    const opt = document.createElement("option");
    opt.value = String(i);
    opt.textContent = `${bin.name}  [${binaryTypeBadge(bin.type)}]`;
    opt.dataset["binType"] = bin.type;
    binaryDropdown.appendChild(opt);
  }

  binaryDropdown.value = String(currentBinaryIndex);
  binarySelector.classList.remove("hidden");
}

/** Clear all tab content and mark tabs as needing reload */
function clearAllTabContent(): void {
  loadedTabs.clear();
  tabPanels.forEach((panel) => {
    panel.innerHTML = "";
  });
}

/** Show/hide the binary-switch loading overlay */
function setBinarySwitchLoading(show: boolean): void {
  let overlay = document.getElementById("binary-loading-overlay");
  if (show) {
    if (!overlay) {
      overlay = document.createElement("div");
      overlay.id = "binary-loading-overlay";
      overlay.className = "binary-loading-overlay";
      overlay.innerHTML =
        '<div class="binary-loading-inner"><div class="ld-spinner"></div><span class="binary-loading-text">Switching binary...</span></div>';
      tabContent.style.position = "relative";
      tabContent.appendChild(overlay);
    }
    overlay.classList.remove("hidden");
  } else if (overlay) {
    overlay.classList.add("hidden");
  }
}

/** Handle binary dropdown change */
async function handleBinaryChange(): Promise<void> {
  const selectedIndex = parseInt(binaryDropdown.value, 10);
  if (isNaN(selectedIndex) || selectedIndex === currentBinaryIndex || isSwitchingBinary) {
    return;
  }

  isSwitchingBinary = true;
  currentBinaryIndex = selectedIndex;
  binaryDropdown.disabled = true;
  setBinarySwitchLoading(true);

  try {
    const result = await window.api.analyzeBinary(selectedIndex);
    analysisResult = result;

    // Clear all cached tab renders so they re-render with new data
    clearAllTabContent();

    // Render the currently active tab immediately
    loadedTabs.add(currentTab);
    await loadTabData(currentTab);

    // Repopulate arch selector for the new binary
    currentArchIndex = 0;
    if (result.overview?.fatArchs) {
      populateArchSelector(result.overview.fatArchs as FatArchInfo[]);
    } else {
      archSelector.classList.add("hidden");
    }

    // Check encryption for the new binary
    checkEncryptionBanner(result);

    console.log(`[Disect] Switched to binary index ${selectedIndex}:`, result);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    showToast(`Binary switch failed: ${message}`, "error");
    console.error("[Disect] Binary switch failed:", err);
  } finally {
    isSwitchingBinary = false;
    binaryDropdown.disabled = false;
    setBinarySwitchLoading(false);
  }
}

binaryDropdown.addEventListener("change", handleBinaryChange);

// ── Architecture selector ──

const CPU_TYPE_NAMES: Record<number, string> = {
  7: "x86",
  12: "ARM",
  0x01000007: "x86_64",
  0x0100000c: "ARM64",
};

function cpuLabel(cputype: number, cpusubtype: number): string {
  const base = CPU_TYPE_NAMES[cputype] ?? `CPU(0x${cputype.toString(16)})`;
  // Mask off CPU_SUBTYPE_LIB64 (bit 31) to get the real subtype
  const sub = cpusubtype & 0x00ffffff;
  if (cputype === 0x0100000c && sub === 2) return "ARM64e";
  if (sub !== 0) return `${base} (sub ${sub})`;
  return base;
}

interface FatArchInfo {
  cputype: number;
  cpusubtype: number;
  offset: number;
  size: number;
  align: number;
}

let currentArchIndex = 0;

function populateArchSelector(fatArchs: FatArchInfo[]): void {
  archDropdown.innerHTML = "";

  if (!fatArchs || fatArchs.length <= 1) {
    archSelector.classList.add("hidden");
    return;
  }

  for (let i = 0; i < fatArchs.length; i++) {
    const arch = fatArchs[i];
    const opt = document.createElement("option");
    opt.value = String(i);
    opt.textContent = `${cpuLabel(arch.cputype, arch.cpusubtype)}  (${(arch.size / 1024).toFixed(0)} KB)`;
    archDropdown.appendChild(opt);
  }

  archDropdown.value = String(currentArchIndex);
  archSelector.classList.remove("hidden");
}

async function handleArchChange(): Promise<void> {
  const idx = parseInt(archDropdown.value, 10);
  if (isNaN(idx) || idx === currentArchIndex || isSwitchingBinary) return;
  const fatArchs = analysisResult?.overview?.fatArchs as FatArchInfo[] | undefined;
  if (!fatArchs || !fatArchs[idx]) return;

  isSwitchingBinary = true;
  currentArchIndex = idx;
  const cpuType = fatArchs[idx].cputype;
  const cpuSubtype = fatArchs[idx].cpusubtype;
  archDropdown.disabled = true;
  binaryDropdown.disabled = true;
  setBinarySwitchLoading(true);

  try {
    const result = await window.api.analyzeBinary(currentBinaryIndex, cpuType, cpuSubtype);
    analysisResult = result;
    clearAllTabContent();
    loadedTabs.add(currentTab);
    await loadTabData(currentTab);
    checkEncryptionBanner(result);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    showToast(`Architecture switch failed: ${message}`, "error");
  } finally {
    isSwitchingBinary = false;
    archDropdown.disabled = false;
    binaryDropdown.disabled = false;
    setBinarySwitchLoading(false);
  }
}

archDropdown.addEventListener("change", handleArchChange);

// ── IPA Analysis ──
async function startAnalysis(filePath: string): Promise<void> {
  setState("loading");
  setLoadingPhase("Starting analysis...", 0);
  loadedTabs.clear();
  clearSearchStates();
  analysisResult = null;
  currentBinaryIndex = 0;

  // Hide selectors during analysis
  binarySelector.classList.add("hidden");
  archSelector.classList.add("hidden");
  currentArchIndex = 0;

  try {
    const result = await window.api.analyzeIPA(filePath);
    analysisResult = result;
    loadedTabs.add("overview"); // Overview is included in the full result
    setState("content");

    // Populate binary selector if multiple binaries discovered
    if (result.overview?.ipa?.binaries) {
      populateBinarySelector(result.overview.ipa.binaries);
    }

    // Populate arch selector if fat binary
    if (result.overview?.fatArchs) {
      currentArchCpuType = result.overview.header.cputype;
      populateArchSelector(result.overview.fatArchs as FatArchInfo[]);
    }

    // Render overview immediately from the full result
    const overviewPanel = document.getElementById("tab-overview");
    if (overviewPanel) {
      renderOverview(overviewPanel, result.overview);
    }

    // Check for encryption and show banner
    checkEncryptionBanner(result);

    // Show export buttons now that analysis is loaded
    updateExportVisibility(true);

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
  console.log("[Disect] handleOpenIPA called, window.api =", window.api);
  try {
    const filePath = await window.api.openFilePicker();
    console.log("[Disect] openFilePicker returned:", filePath);
    if (filePath) {
      await startAnalysis(filePath);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    showToast(`File picker error: ${message}`, "error");
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
  console.log("[Disect] Drop event, files:", files?.length, "file[0]:", files?.[0]);
  if (!files || files.length === 0) return;

  const file = files[0];
  // Electron provides .path on File objects
  const filePath = (file as File & { path?: string }).path;
  console.log("[Disect] Dropped file path:", filePath);

  if (!filePath) {
    showToast("No file path available from drop", "warning");
    return;
  }

  if (!filePath.toLowerCase().endsWith(".ipa")) {
    showToast("Not a valid IPA file", "warning");
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
  showToast(data.message, "error");
});

// ── JSON Export ──

/** Show or hide export buttons based on whether analysis is loaded */
function updateExportVisibility(visible: boolean): void {
  sidebarFooter.classList.toggle("hidden", !visible);
  exportTabBtns.forEach((btn) => btn.classList.toggle("export-active", visible));
}

/** Export all analysis data */
async function handleExportAll(): Promise<void> {
  try {
    const result = await window.api.exportJSON();
    if (result.success) {
      showToast(`Exported to ${result.path}`, "success");
    }
  } catch (err) {
    console.error("[Disect] Export failed:", err);
    showToast("Export failed", "error");
  }
}

/** Export a single tab's data */
async function handleExportTab(tabName: string): Promise<void> {
  try {
    const result = await window.api.exportJSON([tabName as any]);
    if (result.success) {
      showToast(`Exported ${tabName} to ${result.path}`, "success");
    }
  } catch (err) {
    console.error(`[Disect] Export of ${tabName} failed:`, err);
    showToast("Export failed", "error");
  }
}

$<HTMLButtonElement>("#btn-export-all").addEventListener("click", handleExportAll);

exportTabBtns.forEach((btn) => {
  btn.addEventListener("click", (e) => {
    e.stopPropagation(); // Prevent tab switch
    const tabName = btn.dataset["exportTab"];
    if (tabName) {
      handleExportTab(tabName);
    }
  });
});

// ── Global error handlers ──
window.onerror = (msg) => {
  showToast(String(msg), "error");
};

window.onunhandledrejection = (e: PromiseRejectionEvent) => {
  showToast(e.reason?.message || "Unexpected error", "error");
};


// ── Init ──
console.log("[Disect] Renderer loaded");
setState("empty");
switchTab("overview");
