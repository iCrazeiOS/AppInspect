/**
 * Centralized search state management for per-tab search persistence
 * and Ctrl/Cmd+F keyboard shortcut support.
 *
 * Extracted to its own module to avoid circular dependencies
 * between index.ts and tab renderers.
 */

// ── Search state per tab ──
interface TabSearchState {
  term: string;
  isRegex: boolean;
}

const tabSearchStates = new Map<string, TabSearchState>();

/** Save search state for a tab. Called by tab renderers on input change. */
export function saveSearchState(tabId: string, term: string, isRegex: boolean): void {
  tabSearchStates.set(tabId, { term, isRegex });
}

/** Get saved search state for a tab. */
export function getSearchState(tabId: string): TabSearchState | null {
  return tabSearchStates.get(tabId) ?? null;
}

/** Clear all saved search states (e.g. on new analysis). */
export function clearSearchStates(): void {
  tabSearchStates.clear();
  activeSearchBars.clear();
}

// ── Active search bar registry (for Ctrl/Cmd+F focus) ──
const activeSearchBars = new Map<string, { focus: () => void }>();

/** Register a tab's SearchBar instance so Ctrl/Cmd+F can focus it. */
export function registerSearchBar(tabId: string, bar: { focus: () => void }): void {
  activeSearchBars.set(tabId, bar);
}

/** Get the registered search bar for a given tab. */
export function getSearchBar(tabId: string): { focus: () => void } | undefined {
  return activeSearchBars.get(tabId);
}
