/**
 * Shared cross-binary search helpers for the "All" toggle in
 * classes, strings, and symbols tabs.
 */

import type { SearchableTab, CrossBinarySearchResult } from "../../shared/ipc-types";
import type { SearchBar } from "../components";

export interface CrossBinaryState {
  active: boolean;
  results: CrossBinarySearchResult[];
  loading: boolean;
  debounce: ReturnType<typeof setTimeout> | null;
  /** @internal generation counter to discard stale results */
  _gen: number;
}

export function createCrossBinaryState(): CrossBinaryState {
  return { active: false, results: [], loading: false, debounce: null, _gen: 0 };
}

/**
 * Add the "All" toggle button inside a SearchBar.
 * Returns a cleanup-free toggle; call the returned function to
 * programmatically set the active state.
 */
export function addAllBinariesToggle(
  searchBar: SearchBar,
  binaryCount: number,
  state: CrossBinaryState,
  onToggle: (active: boolean) => void,
): void {
  if (binaryCount <= 1) return;

  const btn = document.createElement("button");
  btn.textContent = "All";
  btn.title = "Search across all binaries and frameworks";
  btn.addEventListener("click", () => {
    state.active = !state.active;
    btn.classList.toggle("sb-extra-toggle--active", state.active);
    onToggle(state.active);
  });
  searchBar.addToggle(btn);
}

/**
 * Perform a debounced cross-binary search via IPC.
 * Calls `onResults` when done (only if not cancelled by a newer search).
 */
export function doCrossBinarySearch(
  term: string,
  tab: SearchableTab,
  state: CrossBinaryState,
  onResults: () => void,
  isRegex?: boolean,
  caseSensitive?: boolean,
): void {
  if (state.debounce) clearTimeout(state.debounce);

  if (!term) {
    state.results = [];
    state.loading = false;
    onResults();
    return;
  }

  // Track search generation to discard stale results
  const gen = ++state._gen;
  state.debounce = setTimeout(async () => {
    state.loading = true;
    onResults();
    try {
      state.results = await window.api.searchAllBinaries(term, tab, isRegex, caseSensitive);
    } catch {
      state.results = [];
    }
    // Only apply if this is still the latest search
    if (state._gen !== gen) return;
    state.loading = false;
    onResults();
  }, 400);
}

/** Format a binary type as a badge label. */
export function binaryTypeBadge(type: string): string {
  return type === "main" ? "Main"
    : type === "framework" ? "Framework"
    : "Extension";
}
