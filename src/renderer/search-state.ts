/**
 * Centralized search state management for per-tab search persistence
 * and Ctrl/Cmd+F keyboard shortcut support.
 *
 * Keys are composite: `${sessionId}:${sectionTabId}` to isolate
 * search state across multiple open files.
 */

// ── Search state per tab ──
interface TabSearchState {
  term: string;
  isRegex: boolean;
}

const tabSearchStates = new Map<string, TabSearchState>();

function key(sessionId: string, tabId: string): string {
  return `${sessionId}:${tabId}`;
}

/** Save search state for a tab. Called by tab renderers on input change. */
export function saveSearchState(sessionId: string, tabId: string, term: string, isRegex: boolean): void {
  tabSearchStates.set(key(sessionId, tabId), { term, isRegex });
}

/** Get saved search state for a tab. */
export function getSearchState(sessionId: string, tabId: string): TabSearchState | null {
  return tabSearchStates.get(key(sessionId, tabId)) ?? null;
}

/** Clear all saved search states for a specific session. */
export function clearSearchStatesForSession(sessionId: string): void {
  const prefix = `${sessionId}:`;
  for (const k of tabSearchStates.keys()) {
    if (k.startsWith(prefix)) tabSearchStates.delete(k);
  }
  for (const k of activeSearchBars.keys()) {
    if (k.startsWith(prefix)) activeSearchBars.delete(k);
  }
}

/** Clear all saved search states (e.g. on new analysis). */
export function clearSearchStates(): void {
  tabSearchStates.clear();
  activeSearchBars.clear();
}

// ── Active search bar registry (for Ctrl/Cmd+F focus) ──
const activeSearchBars = new Map<string, { focus: () => void }>();

/** Register a tab's SearchBar instance so Ctrl/Cmd+F can focus it. */
export function registerSearchBar(sessionId: string, tabId: string, bar: { focus: () => void }): void {
  activeSearchBars.set(key(sessionId, tabId), bar);
}

/** Get the registered search bar for a given tab. */
export function getSearchBar(sessionId: string, tabId: string): { focus: () => void } | undefined {
  return activeSearchBars.get(key(sessionId, tabId));
}
