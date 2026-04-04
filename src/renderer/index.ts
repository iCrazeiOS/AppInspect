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
import { renderHooks } from "./tabs/hooks";
import { showToast } from "./components/toast";
import { CPU_TYPE_NAMES } from "./utils/macho";
import type { AppSettings } from "../shared/types";

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
const tabBtnInfoPlist = $<HTMLButtonElement>("#tab-btn-infoplist");
const tabBtnHooks = $<HTMLButtonElement>("#tab-btn-hooks");
const exportTabBtns = document.querySelectorAll<HTMLButtonElement>(".export-tab-btn");

const tabButtons = document.querySelectorAll<HTMLButtonElement>(".tab-btn");
const tabPanels = document.querySelectorAll<HTMLDivElement>(".tab-panel");

const btnSettings = $<HTMLButtonElement>("#btn-settings");
const settingsPanel = $<HTMLDivElement>("#settings-panel");
const optScanAllBinaries = $<HTMLInputElement>("#opt-scan-all-binaries");
const optMaxBundleSize = $<HTMLInputElement>("#opt-max-bundle-size");
const optMaxFileSize = $<HTMLInputElement>("#opt-max-file-size");

console.log("[AppInspect] Renderer loaded. window.api =", typeof window.api, window.api);

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
  loadingText.textContent = percent != null && percent > 0
    ? `${phase} (${Math.round(percent)}%)`
    : phase;
}

function showError(message: string): void {
  setState("empty");
  showToast(message, "error");
}

// ── Tab visibility based on source type ──
function updateTabsForSourceType(sourceType: string): void {
  const isTweak = sourceType === "deb" || sourceType === "macho";
  // Show Hooks tab for tweaks/binaries, Info.plist for IPAs and macOS apps
  tabBtnInfoPlist.classList.toggle("hidden", isTweak);
  tabBtnHooks.classList.toggle("hidden", !isTweak);
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
        case "libraries": {
          const libBinCount = analysisResult?.overview?.ipa?.binaries?.length ?? 1;
          renderLibraries(panel, (tabData as any)?.data ?? tabData, libBinCount);
          break;
        }
        case "headers":
          renderHeaders(panel, (tabData as any)?.data ?? tabData);
          break;
        case "strings": {
          const strBinCount = analysisResult?.overview?.ipa?.binaries?.length ?? 1;
          renderStrings(panel, (tabData as any)?.data ?? tabData, strBinCount);
          break;
        }
        case "symbols": {
          const symBinCount = analysisResult?.overview?.ipa?.binaries?.length ?? 1;
          renderSymbols(panel, (tabData as any)?.data ?? tabData, symBinCount);
          break;
        }
        case "security":
          renderSecurity(panel, (tabData as any)?.data ?? tabData);
          break;
        case "files":
          renderFiles(panel, (tabData as any)?.data ?? tabData);
          break;
        case "classes": {
          const binaryCount = analysisResult?.overview?.ipa?.binaries?.length ?? 1;
          renderClasses(panel, (tabData as any)?.data ?? tabData, binaryCount);
          break;
        }
        case "entitlements":
          renderEntitlements(panel, (tabData as any)?.data ?? tabData);
          break;
        case "infoplist": {
          const plistData = (tabData as any)?.data ?? tabData;
          renderPlist(panel, plistData);
          break;
        }
        case "hooks":
          renderHooks(panel, (tabData as any)?.data ?? tabData);
          break;
        default:
          break;
      }
    }

    console.log(`[AppInspect] Tab data loaded for: ${tabId}`, tabData);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    showToast(`Failed to load ${tabId} tab: ${message}`, "error");
    console.error(`[AppInspect] Failed to load tab data for ${tabId}:`, err);
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
    // Remember the current arch so we can try to preserve it
    const prevArchs = analysisResult?.overview?.fatArchs as FatArchInfo[] | undefined;
    const prevArch = prevArchs?.[currentArchIndex];

    const result = await window.api.analyseBinary(selectedIndex);
    if (!result) throw new Error("Binary analysis returned no result");
    analysisResult = result;

    // Clear all cached tab renders so they re-render with new data
    clearAllTabContent();

    // Render the currently active tab immediately
    loadedTabs.add(currentTab);
    await loadTabData(currentTab);

    // Repopulate arch selector for the new binary, preserving arch if available
    const newArchs = result.overview?.fatArchs as FatArchInfo[] | undefined;
    let matchedIdx = 0;
    if (prevArch && newArchs) {
      const found = newArchs.findIndex(
        (a) => a.cputype === prevArch.cputype && a.cpusubtype === prevArch.cpusubtype
      );
      if (found >= 0) matchedIdx = found;
    }
    currentArchIndex = matchedIdx;

    if (newArchs) {
      populateArchSelector(newArchs);
    } else {
      archSelector.classList.add("hidden");
    }

    // If we matched a non-default arch, re-analyse with that arch
    if (matchedIdx > 0 && newArchs?.[matchedIdx]) {
      const arch = newArchs[matchedIdx];
      const archResult = await window.api.analyseBinary(selectedIndex, arch.cputype, arch.cpusubtype);
      analysisResult = archResult;
      clearAllTabContent();
      loadedTabs.add(currentTab);
      await loadTabData(currentTab);
    }

    // Check encryption for the new binary
    checkEncryptionBanner(result);

    console.log(`[AppInspect] Switched to binary index ${selectedIndex}:`, result);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    showToast(`Binary switch failed: ${message}`, "error");
    console.error("[AppInspect] Binary switch failed:", err);
  } finally {
    isSwitchingBinary = false;
    binaryDropdown.disabled = false;
    setBinarySwitchLoading(false);
  }
}

binaryDropdown.addEventListener("change", handleBinaryChange);

// ── Architecture selector ──

function cpuLabel(cputype: number, cpusubtype: number): string {
  const base = CPU_TYPE_NAMES[cputype] ?? `CPU(0x${cputype.toString(16)})`;
  // Mask off CPU_SUBTYPE_LIB64 (bit 31) to get the real subtype
  const sub = cpusubtype & 0x00ffffff;

  // Known "all/default" subtypes — don't append anything
  // x86/x86_64: CPU_SUBTYPE_X86_ALL = 3, CPU_SUBTYPE_X86_64_ALL = 3
  // ARM: CPU_SUBTYPE_ARM_ALL = 0
  // ARM64: CPU_SUBTYPE_ARM64_ALL = 0
  if (sub === 0) return base;
  if ((cputype === 7 || cputype === 0x01000007) && sub === 3) return base;

  // Named subtypes
  if (cputype === 0x0100000c && sub === 2) return "ARM64e";
  if (cputype === 0x01000007 && sub === 8) return "x86_64 (Haswell)";

  return `${base} (sub ${sub})`;
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
    const result = await window.api.analyseBinary(currentBinaryIndex, cpuType, cpuSubtype);
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
    const result = await window.api.analyseFile(filePath);
    if (!result) {
      // Error already shown via analysis-error event
      setState("empty");
      return;
    }
    analysisResult = result;
    loadedTabs.add("overview"); // Overview is included in the full result
    setState("content");

    // Populate binary selector if multiple binaries discovered
    if (result.overview?.ipa?.binaries) {
      populateBinarySelector(result.overview.ipa.binaries);
    }

    // Populate arch selector if fat binary
    if (result.overview?.fatArchs) {
      populateArchSelector(result.overview.fatArchs as FatArchInfo[]);
    }

    // Render overview immediately from the full result
    const overviewPanel = document.getElementById("tab-overview");
    if (overviewPanel) {
      renderOverview(overviewPanel, Object.assign({}, result.overview, { hooks: (result as any).hooks }) as any);
    }

    // Check for encryption and show banner
    checkEncryptionBanner(result);

    // Show/hide tabs based on file type
    updateTabsForSourceType(result.overview?.sourceType ?? "ipa");

    // Show export buttons now that analysis is loaded
    updateExportVisibility(true);

    switchTab("overview");
    console.log("[AppInspect] Analysis complete:", result);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    showError(message);
    console.error("[AppInspect] Analysis failed:", err);
  }
}

// ── Open IPA button ──
async function handleOpenIPA(): Promise<void> {
  console.log("[AppInspect] handleOpenIPA called, window.api =", window.api);
  try {
    const filePath = await window.api.openFilePicker();
    console.log("[AppInspect] openFilePicker returned:", filePath);
    if (filePath) {
      await startAnalysis(filePath);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    showToast(`File picker error: ${message}`, "error");
    console.error("[AppInspect] File picker error:", err);
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
  console.log("[AppInspect] Drop event, files:", files?.length, "file[0]:", files?.[0]);
  if (!files || files.length === 0) return;

  const file = files[0];
  const filePath = window.api.getPathForFile(file);
  console.log("[AppInspect] Dropped file path:", filePath);

  if (!filePath) {
    showToast("No file path available from drop", "warning");
    return;
  }

  const lowerPath = filePath.toLowerCase();
  const supported = lowerPath.endsWith(".ipa") || lowerPath.endsWith(".deb") || lowerPath.endsWith(".dylib") || lowerPath.endsWith(".app");
  if (!supported) {
    // Allow extensionless files (bare Mach-O executables) — they'll be detected by magic bytes
    const fileName = filePath.split(/[\\/]/).pop() ?? "";
    const hasExtension = fileName.includes(".");
    if (hasExtension) {
      showToast("Unsupported file type. Supported: IPA, .app, DEB, dylib, Mach-O", "warning");
      return;
    }
  }

  console.log("[AppInspect] Dropped file:", filePath);
  startAnalysis(filePath);
});

// ── IPC listeners ──
window.api.onProgress((data) => {
  setLoadingPhase(data.phase, data.percent);
});

window.api.onComplete(() => {
  console.log("[AppInspect] Analysis complete signal received");
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
    console.error("[AppInspect] Export failed:", err);
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
    console.error(`[AppInspect] Export of ${tabName} failed:`, err);
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


// ── Settings ──
btnSettings.addEventListener("click", () => {
  const isHidden = settingsPanel.classList.contains("hidden");
  settingsPanel.classList.toggle("hidden", !isHidden);
  btnSettings.classList.toggle("btn-settings--active", isHidden);
});

optScanAllBinaries.addEventListener("change", async () => {
  try {
    const current = await window.api.getSettings();
    current.scanAllBinaries = optScanAllBinaries.checked;
    await window.api.setSettings(current);
  } catch (err) {
    console.error("[AppInspect] Failed to save settings:", err);
  }
});

async function saveNumberSetting(key: "maxBundleSizeMB" | "maxFileSizeMB", el: HTMLInputElement): Promise<void> {
  const val = parseInt(el.value, 10);
  if (isNaN(val) || val < 1) return;
  try {
    const current = await window.api.getSettings();
    current[key] = val;
    await window.api.setSettings(current);
  } catch (err) {
    console.error("[AppInspect] Failed to save settings:", err);
  }
}

optMaxBundleSize.addEventListener("change", () => saveNumberSetting("maxBundleSizeMB", optMaxBundleSize));
optMaxFileSize.addEventListener("change", () => saveNumberSetting("maxFileSizeMB", optMaxFileSize));

// Load settings on startup
(async () => {
  try {
    const settings = await window.api.getSettings();
    optScanAllBinaries.checked = settings.scanAllBinaries;
    optMaxBundleSize.value = String(settings.maxBundleSizeMB);
    optMaxFileSize.value = String(settings.maxFileSizeMB);
  } catch {
    // Settings not available yet — use defaults
  }
})();

// ── Init ──
console.log("[AppInspect] Renderer loaded");
setState("empty");
switchTab("overview");
