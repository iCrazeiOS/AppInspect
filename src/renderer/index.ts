// Renderer entry point
/// <reference path="./global.d.ts" />

import type { AnalysisResult, BinaryInfo } from "../shared/types";
import { renderOverview } from "./tabs/overview";
import { renderLibraries, cleanupLibrariesSession } from "./tabs/libraries";
import { renderHeaders } from "./tabs/headers";
import { renderHex } from "./tabs/hex";
import { renderStrings } from "./tabs/strings";
import { renderSymbols } from "./tabs/symbols";
import { renderSecurity } from "./tabs/security";
import { renderFiles } from "./tabs/files";
import { renderClasses } from "./tabs/classes";
import { renderEntitlements } from "./tabs/entitlements";
import { renderPlist } from "./tabs/plist";
import { renderHooks } from "./tabs/hooks";
import { showToast } from "./components/toast";
import { CPU_TYPE_NAMES, cpuSubtypeName } from "./utils/macho";
import type { AppSettings } from "../shared/types";

// ── File tab state ──
import {
  fileTabs,
  activeFileTabId,
  getActiveFileTab,
  getFileTab,
  createFileTab,
  removeFileTab,
  setActiveFileTabId,
  getOpenFileTabs,
} from "./file-tabs";
import type { FileTabState } from "./file-tabs";
import {
  addFileTab as addFileTabToBar,
  removeFileTab as removeFileTabFromBar,
  setActiveTab as setActiveTabInBar,
  setTabLoading,
  getAdjacentTabId,
  setFileTabCallbacks,
} from "./file-tab-bar";

// ── Search state ──
import { clearSearchStatesForSession, getSearchBar } from "./search-state";

// ── Types ──
type AppState = "empty" | "loading" | "content" | "error";

// ── DOM references ──
const $ = <T extends HTMLElement>(sel: string): T =>
  document.querySelector(sel) as T;

const dropOverlay = $<HTMLDivElement>("#drop-overlay");
const emptyState = $<HTMLDivElement>("#empty-state");
const loadingBar = $<HTMLDivElement>("#loading-bar");
const titlebarStatus = $<HTMLSpanElement>("#titlebar-status");
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

// ── Keyboard shortcuts ──
document.addEventListener("keydown", (e: KeyboardEvent) => {
  const mod = e.metaKey || e.ctrlKey;

  if (mod && e.key === "f") {
    e.preventDefault();
    const tab = getActiveFileTab();
    if (tab) {
      const bar = getSearchBar(tab.sessionId, tab.currentSectionTab);
      if (bar) bar.focus();
    }
  }

  if (mod && e.key === "w") {
    e.preventDefault();
    if (activeFileTabId) closeFileTab(activeFileTabId);
  }

  // Ctrl/Cmd+O: open file
  if (mod && e.key === "o") {
    e.preventDefault();
    handleOpenIPA();
  }

  // Ctrl+Tab / Ctrl+Shift+Tab: cycle file tabs
  if (e.ctrlKey && e.key === "Tab") {
    e.preventDefault();
    cycleFileTab(e.shiftKey ? -1 : 1);
  }

  // Ctrl/Cmd+1-9: jump to file tab by position
  if (mod && !e.shiftKey && !e.altKey && e.key >= "1" && e.key <= "9") {
    e.preventDefault();
    jumpToFileTab(parseInt(e.key, 10) - 1);
  }

  // Alt+1-9: jump to section tab by position
  if (e.altKey && !e.ctrlKey && !e.metaKey && !e.shiftKey && e.key >= "1" && e.key <= "9") {
    e.preventDefault();
    jumpToSectionTab(parseInt(e.key, 10) - 1);
  }


});

// ── Tab cycling helpers ──

function cycleFileTab(direction: number): void {
  const tabs = getOpenFileTabs();
  if (tabs.length <= 1) return;
  const currentIdx = tabs.findIndex((t) => t.sessionId === activeFileTabId);
  let nextIdx = currentIdx + direction;
  if (nextIdx < 0) nextIdx = tabs.length - 1;
  if (nextIdx >= tabs.length) nextIdx = 0;
  const next = tabs[nextIdx];
  if (next) switchFileTab(next.sessionId);
}

function jumpToFileTab(index: number): void {
  const tabs = getOpenFileTabs();
  const tab = tabs[index];
  if (tab) switchFileTab(tab.sessionId);
}

function jumpToSectionTab(index: number): void {
  const visibleBtns = Array.from(tabButtons).filter(
    (btn) => !btn.classList.contains("hidden"),
  );
  const btn = visibleBtns[index];
  if (btn) {
    const tabId = btn.dataset["tab"];
    if (tabId) switchSectionTab(tabId);
  }
}

// ── Focus tab content ──

/** When true, the next tab render should auto-focus the main interactive element. */
let pendingContentFocus = false;

/** Try to focus the primary interactive element in a tab panel. Returns true if found. */
function focusTabContent(tabId: string): boolean {
  const panel = document.getElementById(`tab-${tabId}`);
  if (!panel) return false;

  const dt = panel.querySelector<HTMLElement>(".dt-scroll");
  if (dt) { dt.focus(); return true; }

  const cls = panel.querySelector<HTMLElement>(".cls-scroll");
  if (cls) { cls.focus(); return true; }

  return false;
}

// ── Sidebar keyboard navigation ──

/** Build ordered list of focusable sidebar elements (selectors, tabs, export). */
function getSidebarFocusables(): HTMLElement[] {
  const items: HTMLElement[] = [];
  if (!binarySelector.classList.contains("hidden")) items.push(binaryDropdown);
  if (!archSelector.classList.contains("hidden")) items.push(archDropdown);
  tabButtons.forEach((btn) => {
    if (!btn.classList.contains("hidden")) items.push(btn);
  });
  if (!sidebarFooter.classList.contains("hidden")) {
    items.push($<HTMLElement>("#btn-export-all"));
  }
  return items;
}

$<HTMLElement>("#sidebar").addEventListener("keydown", (e: KeyboardEvent) => {
  const target = e.target as HTMLElement;

  // Enter on a tab button → focus the tab's main content
  if (e.key === "Enter" && target.classList.contains("tab-btn")) {
    e.preventDefault();
    const tabId = (target as HTMLButtonElement).dataset["tab"];
    if (!tabId) return;
    switchSectionTab(tabId);
    // Try focusing immediately (already-loaded tab); if not ready, set pending flag
    requestAnimationFrame(() => {
      if (!focusTabContent(tabId)) {
        pendingContentFocus = true;
      }
    });
    return;
  }

  if (e.key !== "ArrowUp" && e.key !== "ArrowDown") return;

  // Don't intercept arrows on <select> — they need native dropdown behavior
  if (target.tagName === "SELECT") return;

  const items = getSidebarFocusables();
  const currentIdx = items.indexOf(target);
  if (currentIdx === -1) return;

  e.preventDefault();
  const nextIdx = e.key === "ArrowDown"
    ? Math.min(currentIdx + 1, items.length - 1)
    : Math.max(currentIdx - 1, 0);

  const next = items[nextIdx];
  if (next) {
    next.focus();
    // If it's a section tab button, also activate it
    if (next.classList.contains("tab-btn")) {
      const tabId = (next as HTMLButtonElement).dataset["tab"];
      if (tabId) switchSectionTab(tabId);
    }
  }
});

// ── App state transitions ──
function setTabsDisabled(disabled: boolean): void {
  tabButtons.forEach((btn) => {
    btn.classList.toggle("tab-btn--disabled", disabled);
  });
}

function setGlobalState(state: AppState): void {
  emptyState.classList.toggle("hidden", state !== "empty");
  loadingBar.classList.toggle("hidden", state !== "loading");
  tabContent.classList.toggle("hidden", state !== "content");
  setTabsDisabled(state !== "content");
  if (state !== "loading") {
    titlebarStatus.classList.add("hidden");
  }
}

function setLoadingPhase(phase: string, percent?: number): void {
  titlebarStatus.textContent = percent != null && percent > 0
    ? `${phase} (${Math.round(percent)}%)`
    : phase;
  titlebarStatus.classList.remove("hidden");
}

function showError(message: string): void {
  setGlobalState("empty");
  showToast(message, "error");
}

// ── Tab visibility based on source type ──
function updateTabsForSourceType(sourceType: string): void {
  const isTweak = sourceType === "deb" || sourceType === "macho";
  tabBtnInfoPlist.classList.toggle("hidden", isTweak);
  tabBtnHooks.classList.toggle("hidden", !isTweak);
}

// ── Encryption warning banner ──
function checkEncryptionBanner(tab: FileTabState, result: AnalysisResult): void {
  const encrypted =
    result.overview?.hardening?.encrypted === true ||
    (result.overview?.encryptionInfo?.cryptid != null &&
      result.overview.encryptionInfo.cryptid !== 0);

  tab.isEncrypted = encrypted;
  tab.encryptionBannerDismissed = false;
  updateEncryptionBanner();
}

function updateEncryptionBanner(): void {
  const tab = getActiveFileTab();
  let banner = document.getElementById("encryption-banner");
  if (tab && tab.isEncrypted && !tab.encryptionBannerDismissed) {
    if (!banner) {
      banner = document.createElement("div");
      banner.id = "encryption-banner";
      banner.className = "encryption-banner";
      banner.innerHTML =
        '<span class="encryption-banner-icon">\u26A0</span>' +
        '<span class="encryption-banner-text">This binary is FairPlay encrypted. Strings, classes, and symbols data may be incomplete. Use a decrypted IPA for full analysis.</span>' +
        '<button class="encryption-banner-close">\u00D7</button>';
      const mainContent = document.getElementById("main-content");
      if (mainContent && tabContent) {
        mainContent.insertBefore(banner, tabContent);
      }
      banner.querySelector(".encryption-banner-close")!.addEventListener("click", () => {
        const activeTab = getActiveFileTab();
        if (activeTab) activeTab.encryptionBannerDismissed = true;
        updateEncryptionBanner();
      });
    }
    banner.classList.remove("hidden");
  } else if (banner) {
    banner.classList.add("hidden");
  }
}

// ── Section tab switching ──
function switchSectionTab(tabId: string): void {
  const tab = getActiveFileTab();
  if (tab) tab.currentSectionTab = tabId;

  tabButtons.forEach((btn) => {
    btn.classList.toggle("active", btn.dataset["tab"] === tabId);
  });

  tabPanels.forEach((panel) => {
    const isTarget = panel.id === `tab-${tabId}`;
    panel.classList.toggle("hidden", !isTarget);
  });

  // Re-show encryption banner on tab switch
  if (tab?.isEncrypted) {
    tab.encryptionBannerDismissed = false;
    updateEncryptionBanner();
  }

  // Lazy-load tab data
  if (tab && tab.analysisResult && !tab.loadedSectionTabs.has(tabId)) {
    loadTabData(tabId);
  }
}

async function loadTabData(tabId: string): Promise<void> {
  const tab = getActiveFileTab();
  if (!tab) return;

  // Hex tab uses analysis result directly — no IPC round-trip needed
  if (tabId === "hex") {
    tab.loadedSectionTabs.add(tabId);
    const panel = document.getElementById("tab-hex");
    if (panel && tab.analysisResult) {
      renderHex(panel, { loadCommands: tab.analysisResult.headers.loadCommands }, tab.sessionId);
    }
    return;
  }

  try {
    const tabData = await window.api.getTabData(tab.sessionId, tabId as import("../shared/ipc-types").TabName);
    tab.loadedSectionTabs.add(tabId);

    const panel = document.getElementById(`tab-${tabId}`);
    if (panel && tabData != null) {
      const sid = tab.sessionId;
      const binCount = tab.analysisResult?.overview?.ipa?.binaries?.length ?? 1;
      switch (tabId) {
        case "overview":
          renderOverview(panel, (tabData as any)?.data ?? tabData);
          break;
        case "libraries":
          renderLibraries(panel, (tabData as any)?.data ?? tabData, binCount, sid);
          break;
        case "headers":
          renderHeaders(panel, (tabData as any)?.data ?? tabData);
          break;
        case "strings":
          renderStrings(panel, (tabData as any)?.data ?? tabData, binCount, sid);
          break;
        case "symbols":
          renderSymbols(panel, (tabData as any)?.data ?? tabData, binCount, sid);
          break;
        case "security":
          renderSecurity(panel, (tabData as any)?.data ?? tabData, sid);
          break;
        case "files":
          renderFiles(panel, (tabData as any)?.data ?? tabData, sid);
          break;
        case "classes":
          renderClasses(panel, (tabData as any)?.data ?? tabData, binCount, sid);
          break;
        case "entitlements":
          renderEntitlements(panel, (tabData as any)?.data ?? tabData);
          break;
        case "infoplist":
          renderPlist(panel, (tabData as any)?.data ?? tabData, sid);
          break;
        case "hooks":
          renderHooks(panel, (tabData as any)?.data ?? tabData);
          break;
        default:
          break;
      }
    }

    // Auto-focus content if Enter was pressed on the sidebar tab
    if (pendingContentFocus) {
      pendingContentFocus = false;
      focusTabContent(tabId);
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
    if (tabId) switchSectionTab(tabId);
    btn.blur();
  });
});

// ── Binary selector ──

function binaryTypeBadge(type: BinaryInfo["type"]): string {
  switch (type) {
    case "main": return "Main";
    case "framework": return "Framework";
    case "extension": return "Extension";
    default: return String(type);
  }
}

function populateBinarySelector(binaries: BinaryInfo[]): void {
  const tab = getActiveFileTab();
  binaryDropdown.innerHTML = "";

  if (!binaries || binaries.length <= 1) {
    binarySelector.classList.add("hidden");
    return;
  }

  for (let i = 0; i < binaries.length; i++) {
    const bin = binaries[i]!;
    const opt = document.createElement("option");
    opt.value = String(i);
    opt.textContent = `${bin.name}  [${binaryTypeBadge(bin.type)}]`;
    opt.dataset["binType"] = bin.type;
    binaryDropdown.appendChild(opt);
  }

  binaryDropdown.value = String(tab?.currentBinaryIndex ?? 0);
  binarySelector.classList.remove("hidden");
}

function clearAllTabContent(): void {
  const tab = getActiveFileTab();
  if (tab) tab.loadedSectionTabs.clear();
  tabPanels.forEach((panel) => {
    panel.innerHTML = "";
  });
}

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

async function handleBinaryChange(): Promise<void> {
  const tab = getActiveFileTab();
  if (!tab) return;

  const selectedIndex = parseInt(binaryDropdown.value, 10);
  if (isNaN(selectedIndex) || selectedIndex === tab.currentBinaryIndex) return;

  tab.currentBinaryIndex = selectedIndex;
  binaryDropdown.disabled = true;
  setBinarySwitchLoading(true);

  try {
    const prevArchs = tab.analysisResult?.overview?.fatArchs as FatArchInfo[] | undefined;
    const prevArch = prevArchs?.[tab.currentArchIndex];

    const result = await window.api.analyseBinary(tab.sessionId, selectedIndex);
    if (!result) throw new Error("Binary analysis returned no result");
    tab.analysisResult = result;

    clearAllTabContent();
    tab.loadedSectionTabs.add(tab.currentSectionTab);
    await loadTabData(tab.currentSectionTab);

    const newArchs = result.overview?.fatArchs as FatArchInfo[] | undefined;
    let matchedIdx = 0;
    if (prevArch && newArchs) {
      const found = newArchs.findIndex(
        (a) => a.cputype === prevArch.cputype && a.cpusubtype === prevArch.cpusubtype
      );
      if (found >= 0) matchedIdx = found;
    }
    tab.currentArchIndex = matchedIdx;

    if (newArchs) {
      populateArchSelector(newArchs);
    } else {
      archSelector.classList.add("hidden");
    }

    if (matchedIdx > 0 && newArchs?.[matchedIdx]) {
      const arch = newArchs[matchedIdx]!;
      const archResult = await window.api.analyseBinary(tab.sessionId, selectedIndex, arch.cputype, arch.cpusubtype);
      tab.analysisResult = archResult;
      clearAllTabContent();
      tab.loadedSectionTabs.add(tab.currentSectionTab);
      await loadTabData(tab.currentSectionTab);
    }

    checkEncryptionBanner(tab, result);
    console.log(`[AppInspect] Switched to binary index ${selectedIndex}:`, result);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    showToast(`Binary switch failed: ${message}`, "error");
    console.error("[AppInspect] Binary switch failed:", err);
  } finally {
    binaryDropdown.disabled = false;
    setBinarySwitchLoading(false);
  }
}

binaryDropdown.addEventListener("change", handleBinaryChange);

// ── Architecture selector ──

function cpuLabel(cputype: number, cpusubtype: number): string {
  const base = CPU_TYPE_NAMES[cputype] ?? `CPU(0x${cputype.toString(16)})`;
  const sub = cpusubtype & 0x00ffffff;
  if (sub === 0) return base;
  if ((cputype === 7 || cputype === 0x01000007) && sub === 3) return base;
  const name = cpuSubtypeName(cputype, cpusubtype);
  if (name) return name;
  return `${base} (sub ${sub})`;
}

interface FatArchInfo {
  cputype: number;
  cpusubtype: number;
  offset: number;
  size: number;
  align: number;
}

function populateArchSelector(fatArchs: FatArchInfo[]): void {
  const tab = getActiveFileTab();
  archDropdown.innerHTML = "";

  if (!fatArchs || fatArchs.length <= 1) {
    archSelector.classList.add("hidden");
    return;
  }

  for (let i = 0; i < fatArchs.length; i++) {
    const arch = fatArchs[i]!;
    const opt = document.createElement("option");
    opt.value = String(i);
    opt.textContent = `${cpuLabel(arch.cputype, arch.cpusubtype)}  (${(arch.size / 1024).toFixed(0)} KB)`;
    archDropdown.appendChild(opt);
  }

  archDropdown.value = String(tab?.currentArchIndex ?? 0);
  archSelector.classList.remove("hidden");
}

async function handleArchChange(): Promise<void> {
  const tab = getActiveFileTab();
  if (!tab) return;

  const idx = parseInt(archDropdown.value, 10);
  if (isNaN(idx) || idx === tab.currentArchIndex) return;
  const fatArchs = tab.analysisResult?.overview?.fatArchs as FatArchInfo[] | undefined;
  if (!fatArchs || !fatArchs[idx]) return;

  tab.currentArchIndex = idx;
  const cpuType = fatArchs[idx].cputype;
  const cpuSubtype = fatArchs[idx].cpusubtype;
  archDropdown.disabled = true;
  binaryDropdown.disabled = true;
  setBinarySwitchLoading(true);

  try {
    const result = await window.api.analyseBinary(tab.sessionId, tab.currentBinaryIndex, cpuType, cpuSubtype);
    tab.analysisResult = result;
    clearAllTabContent();
    tab.loadedSectionTabs.add(tab.currentSectionTab);
    await loadTabData(tab.currentSectionTab);
    checkEncryptionBanner(tab, result);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    showToast(`Architecture switch failed: ${message}`, "error");
  } finally {
    archDropdown.disabled = false;
    binaryDropdown.disabled = false;
    setBinarySwitchLoading(false);
  }
}

archDropdown.addEventListener("change", handleArchChange);

// ── File tab management ──

function switchFileTab(sessionId: string): void {
  if (sessionId === activeFileTabId) return;

  setActiveFileTabId(sessionId);
  setActiveTabInBar(sessionId);

  const tab = getFileTab(sessionId);
  if (!tab) return;

  // Clear all panel content for fresh render
  tabPanels.forEach((panel) => { panel.innerHTML = ""; });

  if (tab.appState === "loading") {
    setGlobalState("loading");
  } else if (tab.appState === "content" && tab.analysisResult) {
    setGlobalState("content");

    // Restore selectors
    if (tab.analysisResult.overview?.ipa?.binaries) {
      populateBinarySelector(tab.analysisResult.overview.ipa.binaries);
    } else {
      binarySelector.classList.add("hidden");
    }
    if (tab.analysisResult.overview?.fatArchs) {
      populateArchSelector(tab.analysisResult.overview.fatArchs as FatArchInfo[]);
    } else {
      archSelector.classList.add("hidden");
    }

    // Restore tab visibility
    updateTabsForSourceType(tab.analysisResult.overview?.sourceType ?? "ipa");
    updateExportVisibility(true);
    updateEncryptionBanner();

    // Re-render the active section tab (clears loadedSectionTabs since panels were wiped)
    tab.loadedSectionTabs.clear();
    switchSectionTab(tab.currentSectionTab);
  } else {
    setGlobalState("empty");
    binarySelector.classList.add("hidden");
    archSelector.classList.add("hidden");
    updateExportVisibility(false);
  }
}

function closeFileTab(sessionId: string): void {
  const adjacent = getAdjacentTabId(sessionId);

  // Clean up
  window.api.closeSession(sessionId);
  removeFileTab(sessionId);
  removeFileTabFromBar(sessionId);
  clearSearchStatesForSession(sessionId);
  cleanupLibrariesSession(sessionId);

  if (activeFileTabId === null || activeFileTabId === sessionId) {
    if (adjacent) {
      switchFileTab(adjacent);
    } else {
      setActiveFileTabId(null);
      setActiveTabInBar(null);
      tabPanels.forEach((panel) => { panel.innerHTML = ""; });
      binarySelector.classList.add("hidden");
      archSelector.classList.add("hidden");
      updateExportVisibility(false);
      setGlobalState("empty");
      updateEncryptionBanner();
    }
  }
}

// Wire up file tab bar callbacks
setFileTabCallbacks(switchFileTab, closeFileTab);

// Handle menu events from app menu
window.api.onCloseActiveTab(() => {
  if (activeFileTabId) closeFileTab(activeFileTabId);
});
window.api.onOpenFile(() => handleOpenIPA());

// ── Analysis ──
async function startAnalysis(filePath: string): Promise<void> {
  // If already open, just switch to it
  if (fileTabs.has(filePath)) {
    switchFileTab(filePath);
    return;
  }

  // Create file tab
  const fileName = filePath.split(/[\\/]/).pop() ?? filePath;
  const tab = createFileTab(filePath, fileName);
  addFileTabToBar(filePath, fileName);
  setActiveFileTabId(filePath);
  setActiveTabInBar(filePath);
  setTabLoading(filePath, true);

  setGlobalState("loading");
  setLoadingPhase("Starting analysis...", 0);

  // Hide selectors during analysis
  binarySelector.classList.add("hidden");
  archSelector.classList.add("hidden");
  updateExportVisibility(false);

  try {
    const response = await window.api.analyseFile(filePath);
    if (!response) {
      tab.appState = "error";
      setTabLoading(filePath, false);
      if (activeFileTabId === filePath) setGlobalState("empty");
      return;
    }
    const result = response.result;
    tab.analysisResult = result;
    tab.appState = "content";
    tab.loadedSectionTabs.add("overview");
    setTabLoading(filePath, false);

    // Only update UI if this tab is still active
    if (activeFileTabId === filePath) {
      setGlobalState("content");

      if (result.overview?.ipa?.binaries) {
        populateBinarySelector(result.overview.ipa.binaries);
      }
      if (result.overview?.fatArchs) {
        populateArchSelector(result.overview.fatArchs as FatArchInfo[]);
      }

      const overviewPanel = document.getElementById("tab-overview");
      if (overviewPanel) {
        renderOverview(overviewPanel, Object.assign({}, result.overview, { hooks: (result as any).hooks }) as any);
      }

      checkEncryptionBanner(tab, result);
      updateTabsForSourceType(result.overview?.sourceType ?? "ipa");
      updateExportVisibility(true);
      switchSectionTab("overview");
    }

    console.log("[AppInspect] Analysis complete:", result);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    tab.appState = "error";
    setTabLoading(filePath, false);
    if (activeFileTabId === filePath) showError(message);
    console.error("[AppInspect] Analysis failed:", err);
  }
}

// ── Open file button ──
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
$<HTMLButtonElement>("#file-tab-add").addEventListener("click", handleOpenIPA);

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

  const file = files[0]!;
  const filePath = window.api.getPathForFile(file);
  console.log("[AppInspect] Dropped file path:", filePath);

  if (!filePath) {
    showToast("No file path available from drop", "warning");
    return;
  }

  const lowerPath = filePath.toLowerCase();
  const supported = lowerPath.endsWith(".ipa") || lowerPath.endsWith(".deb") || lowerPath.endsWith(".dylib") || lowerPath.endsWith(".app");
  if (!supported) {
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
  setTabLoading(data.sessionId, true);
  if (data.sessionId === activeFileTabId) {
    setLoadingPhase(data.phase, data.percent);
  }
});

window.api.onComplete((data) => {
  setTabLoading(data.sessionId, false);
  if (data.sessionId === activeFileTabId) {
    titlebarStatus.classList.add("hidden");
  }
  console.log("[AppInspect] Analysis complete signal received for", data.sessionId);
});

window.api.onError((data) => {
  setTabLoading(data.sessionId, false);
  if (data.sessionId === activeFileTabId) {
    showToast(data.message, "error");
  }
});

// ── JSON Export ──

function updateExportVisibility(visible: boolean): void {
  sidebarFooter.classList.toggle("hidden", !visible);
  exportTabBtns.forEach((btn) => btn.classList.toggle("export-active", visible));
}

async function handleExportAll(): Promise<void> {
  const tab = getActiveFileTab();
  if (!tab) return;
  try {
    const result = await window.api.exportJSON(tab.sessionId);
    if (result.success) {
      showToast(`Exported to ${result.path}`, "success");
    }
  } catch (err) {
    console.error("[AppInspect] Export failed:", err);
    showToast("Export failed", "error");
  }
}

async function handleExportTab(tabName: string): Promise<void> {
  const tab = getActiveFileTab();
  if (!tab) return;
  try {
    const result = await window.api.exportJSON(tab.sessionId, [tabName as any]);
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
    e.stopPropagation();
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
setGlobalState("empty");
switchSectionTab("overview");
