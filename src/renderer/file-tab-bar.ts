/**
 * File tab bar DOM module.
 *
 * Renders and manages the browser-style tab strip for open files.
 * Pure DOM — state lives in file-tabs.ts.
 */

const fileTabBar = document.getElementById("file-tab-bar")!;
const fileTabList = document.getElementById("file-tab-list")!;

/** Callbacks set by the renderer to handle tab interactions. */
let onSwitch: ((sessionId: string) => void) | null = null;
let onClose: ((sessionId: string) => void) | null = null;

export function setFileTabCallbacks(
  switchCb: (sessionId: string) => void,
  closeCb: (sessionId: string) => void,
): void {
  onSwitch = switchCb;
  onClose = closeCb;
}

export function addFileTab(sessionId: string, displayName: string): void {
  const tab = document.createElement("div");
  tab.className = "file-tab";
  tab.dataset.sessionId = sessionId;
  tab.title = sessionId;

  const loading = document.createElement("span");
  loading.className = "file-tab-loading";
  loading.style.display = "none";

  const name = document.createElement("span");
  name.className = "file-tab-name";
  name.textContent = displayName;

  const close = document.createElement("button");
  close.className = "file-tab-close";
  close.innerHTML = "&times;";
  close.addEventListener("click", (e) => {
    e.stopPropagation();
    onClose?.(sessionId);
  });

  tab.appendChild(loading);
  tab.appendChild(name);
  tab.appendChild(close);

  tab.addEventListener("click", () => onSwitch?.(sessionId));
  tab.addEventListener("auxclick", (e) => {
    if (e.button === 1) onClose?.(sessionId);
  });

  fileTabList.appendChild(tab);
  updateVisibility();
}

export function removeFileTab(sessionId: string): void {
  const el = fileTabList.querySelector(`[data-session-id="${CSS.escape(sessionId)}"]`);
  el?.remove();
  updateVisibility();
}

export function setActiveTab(sessionId: string | null): void {
  const tabs = Array.from(fileTabList.children) as HTMLElement[];
  for (const tab of tabs) {
    tab.classList.toggle("file-tab--active", tab.dataset.sessionId === sessionId);
  }
}

export function setTabLoading(sessionId: string, loading: boolean): void {
  const el = fileTabList.querySelector(`[data-session-id="${CSS.escape(sessionId)}"]`);
  if (!el) return;
  const dot = el.querySelector(".file-tab-loading") as HTMLElement | null;
  if (dot) dot.style.display = loading ? "" : "none";
}

export function updateVisibility(): void {
  fileTabBar.classList.toggle("hidden", fileTabList.children.length === 0);
}

/** Get the sessionId of the tab adjacent to the given one (for close-and-switch). */
export function getAdjacentTabId(sessionId: string): string | null {
  const tabs = Array.from(fileTabList.children) as HTMLElement[];
  const idx = tabs.findIndex((t) => t.dataset.sessionId === sessionId);
  if (idx === -1) return null;
  const next = tabs[idx + 1] ?? tabs[idx - 1];
  return next?.dataset.sessionId ?? null;
}
