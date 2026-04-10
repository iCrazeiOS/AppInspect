/**
 * Shared cross-binary search helpers for the "All" toggle in
 * classes, strings, symbols, and libraries tabs.
 */

import type { CrossBinarySearchResult, SearchableTab } from "../../shared/ipc-types";
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
	onToggle: (active: boolean) => void
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
	sessionId: string,
	term: string,
	tab: SearchableTab,
	state: CrossBinaryState,
	onResults: () => void,
	isRegex?: boolean,
	caseSensitive?: boolean
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
			state.results = await window.api.searchAllBinaries(
				sessionId,
				term,
				tab,
				isRegex,
				caseSensitive
			);
		} catch {
			state.results = [];
		}
		// Only apply if this is still the latest search
		if (state._gen !== gen) return;
		state.loading = false;
		onResults();
	}, 400);
}

/**
 * Build a "Show all <label>" link that triggers a wildcard cross-binary search.
 * Used by both the custom Classes renderer and the DataTable-based hint overlay.
 */
export function buildShowAllLink(
	sessionId: string,
	label: string,
	tab: SearchableTab,
	state: CrossBinaryState,
	onResults: () => void
): HTMLAnchorElement {
	const link = document.createElement("a");
	link.className = "cls-cross-show-all";
	link.textContent = `Show all ${label}`;
	link.href = "#";
	link.addEventListener("click", (e) => {
		e.preventDefault();
		doCrossBinarySearch(sessionId, ".", tab, state, onResults, true, false);
	});
	return link;
}

/** Format a binary type as a badge label. */
export function binaryTypeBadge(type: string): string {
	return type === "main" ? "Main" : type === "framework" ? "Framework" : "Extension";
}

/**
 * Create or update a "show all" hint element for cross-binary mode.
 * Shows a prompt with a "Show all <label>" link when xbin is active,
 * no search term is entered, and there are no results.
 * Returns the hint container element.
 */
export function createCrossBinaryHint(parent: HTMLElement): HTMLDivElement {
	parent.style.position = "relative";
	const hint = document.createElement("div");
	hint.className = "xbin-show-all-hint";
	hint.style.display = "none";
	parent.appendChild(hint);
	return hint;
}

/**
 * Update visibility/content of a cross-binary "show all" hint.
 * @param hint - The hint element from createCrossBinaryHint
 * @param state - Cross-binary state
 * @param searchValue - Current search bar value
 * @param tab - The SearchableTab to search
 * @param label - Display label (e.g. "symbols", "strings", "libraries")
 * @param onResults - Callback when results arrive from "Show all"
 */
export function updateCrossBinaryHint(
	sessionId: string,
	hint: HTMLDivElement,
	state: CrossBinaryState,
	searchValue: string,
	tab: SearchableTab,
	label: string,
	onResults: () => void
): void {
	if (state.active && !searchValue && state.results.length === 0 && !state.loading) {
		hint.innerHTML = "";
		const singular = label.endsWith("ies") ? label.slice(0, -3) + "y" : label.slice(0, -1);
		const text = document.createElement("span");
		text.textContent = `Type a ${singular} name to search across all binaries.`;
		hint.appendChild(text);
		hint.appendChild(buildShowAllLink(sessionId, label, tab, state, onResults));
		hint.style.display = "flex";
	} else {
		hint.style.display = "none";
	}
}
