// Renderer entry point

// ── Types ──
type AppState = "empty" | "loading" | "content";

interface WindowApi {
  analyzeIPA?: (filePath: string) => void;
  openFilePicker?: () => void;
  onProgress?: (callback: (phase: string) => void) => void;
}

declare global {
  interface Window {
    api?: WindowApi;
  }
}

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

// ── App state transitions ──
function setState(state: AppState): void {
  appState = state;

  emptyState.classList.toggle("hidden", state !== "empty");
  loadingBar.classList.toggle("hidden", state !== "loading");
  tabContent.classList.toggle("hidden", state !== "content");
}

function setLoadingPhase(phase: string): void {
  loadingText.textContent = phase;
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
}

tabButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    const tabId = btn.dataset["tab"];
    if (tabId) {
      switchTab(tabId);
    }
  });
});

// ── Open IPA button ──
function handleOpenIPA(): void {
  if (window.api?.openFilePicker) {
    window.api.openFilePicker();
  } else {
    console.log("[Disect] openFilePicker not yet wired");
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

  if (window.api?.analyzeIPA) {
    window.api.analyzeIPA(filePath);
  } else {
    console.log("[Disect] analyzeIPA not yet wired — would analyze:", filePath);
  }
});

// ── Progress listener stub ──
if (window.api?.onProgress) {
  window.api.onProgress((phase: string) => {
    setLoadingPhase(phase);
  });
}

// ── Exports for future use ──
export { setState, setLoadingPhase, switchTab };

// ── Init ──
console.log("[Disect] Renderer loaded");
setState("empty");
switchTab("overview");
