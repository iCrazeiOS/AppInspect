/**
 * Strings tab: displays extracted string entries with virtual scrolling,
 * search filtering (with regex toggle), and section filter chips.
 * Supports toggling between binary strings and localisation strings.
 */

import type { Column } from "../components";
import { DataTable, SearchBar } from "../components";
import { announce, navigateTo, takePendingTarget } from "../navigation";
import { getSearchState, registerSearchBar, saveSearchState } from "../search-state";
import { getTabState, setTabState } from "../tab-state";
import {
	addAllBinariesToggle,
	binaryTypeBadge,
	createCrossBinaryHint,
	createCrossBinaryState,
	doCrossBinarySearch,
	updateCrossBinaryHint
} from "../utils/cross-binary-search";
import { plural } from "../utils/format";

interface StringEntry {
	value: string;
	sectionSource: string;
	offset: number;
}

interface LocalisationString {
	key: string;
	value: string;
	file: string;
	language: string;
}

interface StringsData {
	binary: StringEntry[];
	localisation: LocalisationString[];
}

const BINARY_COLUMNS: Column[] = [
	{ key: "value", label: "String Value" },
	{ key: "source", label: "Source Section", width: "160px" },
	{ key: "offsetHex", label: "Offset", width: "120px" }
];

const LOCALISATION_COLUMNS: Column[] = [
	{ key: "key", label: "Key", width: "25%" },
	{ key: "value", label: "Value" },
	{ key: "language", label: "Language", width: "100px" },
	{ key: "file", label: "File", width: "30%" }
];

const CROSS_BINARY_COLUMNS: Column[] = [
	{ key: "value", label: "String Value" },
	{ key: "binary", label: "Binary", width: "280px" }
];

export function renderStrings(
	container: HTMLElement,
	data: unknown,
	binaryCount: number = 1,
	sessionId: string = ""
): void {
	container.innerHTML = "";

	// Handle both old format (array) and new format ({ binary, localisation })
	let binaryEntries: StringEntry[] = [];
	let localisationEntries: LocalisationString[] = [];

	if (Array.isArray(data)) {
		// Legacy format: plain array of StringEntry
		binaryEntries = data as StringEntry[];
	} else if (data && typeof data === "object") {
		const d = data as StringsData;
		binaryEntries = Array.isArray(d.binary) ? d.binary : [];
		localisationEntries = Array.isArray(d.localisation) ? d.localisation : [];
	}

	// Collect individual section names for binary filter chips
	const sectionCounts = new Map<string, number>();
	for (const e of binaryEntries) {
		for (const s of (e.sectionSource ?? "").split(", ")) {
			if (s) sectionCounts.set(s, (sectionCounts.get(s) ?? 0) + 1);
		}
	}
	const sections = [...sectionCounts.entries()]
		.sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
		.map(([name]) => name);
	const sectionIndex = new Map(sections.map((s, i) => [s, i]));

	// Convert raw entries to table row format
	const binaryRows = binaryEntries.map((e) => {
		const source = e.sectionSource ?? "";
		let sourceMask = 0;
		for (const s of source.split(", ")) {
			const idx = sectionIndex.get(s);
			if (idx !== undefined) sourceMask |= 1 << idx;
		}
		return {
			value: e.value,
			source,
			offsetHex: `0x${(e.offset >>> 0).toString(16).padStart(4, "0")}`,
			_offset: typeof e.offset === "number" ? e.offset : 0,
			_sourceMask: sourceMask
		};
	});

	const localisationRows = localisationEntries.map((e) => ({
		key: e.key,
		value: e.value,
		language: e.language,
		file: e.file
	}));

	// ── State ──
	const savedMode = getTabState<"binary" | "localisation">(sessionId, "strings", "mode");
	let mode: "binary" | "localisation" = savedMode ?? "binary";

	const savedSections = getTabState<string[]>(sessionId, "strings", "sections");
	const knownSections = savedSections?.filter((s) => sectionCounts.has(s));
	const activeSections = new Set<string>(
		knownSections && (knownSections.length > 0 || savedSections?.length === 0)
			? knownSections
			: sections
	);

	// Collect unique languages for localisation filter chips
	const langSet = new Set<string>();
	for (const r of localisationRows) {
		if (r.language) langSet.add(r.language);
	}
	const languages = [...langSet].sort();
	// Default to English if available, otherwise show all
	const englishLang = languages.find((l) => /^(en|en[-_]|english|base)$/i.test(l));
	const savedLanguages = getTabState<string[]>(sessionId, "strings", "languages");
	const activeLanguages = new Set<string>(
		savedLanguages ?? (englishLang ? [englishLang] : languages)
	);

	// ── Wrapper ──
	const wrapper = document.createElement("div");
	wrapper.className = "strings-tab";
	wrapper.style.cssText = "display:flex;flex-direction:column;height:100%;min-height:0;";

	// ── Mode toggle (only show if there are localisation strings) ──
	let toggleBar: HTMLElement | null = null;
	let binaryBtn: HTMLButtonElement | null = null;
	let localisationBtn: HTMLButtonElement | null = null;

	if (localisationEntries.length > 0) {
		toggleBar = document.createElement("div");
		toggleBar.className = "strings-mode-toggle";

		binaryBtn = document.createElement("button");
		binaryBtn.className = `strings-mode-btn${mode === "binary" ? " strings-mode-btn--active" : ""}`;
		binaryBtn.textContent = "Binary";
		binaryBtn.addEventListener("click", () => switchMode("binary"));

		localisationBtn = document.createElement("button");
		localisationBtn.className = `strings-mode-btn${mode === "localisation" ? " strings-mode-btn--active" : ""}`;
		localisationBtn.textContent = "Localisations";
		localisationBtn.addEventListener("click", () => switchMode("localisation"));

		toggleBar.appendChild(binaryBtn);
		toggleBar.appendChild(localisationBtn);
		wrapper.appendChild(toggleBar);
	}

	// ── Cross-binary state ──
	const xbin = createCrossBinaryState();

	// ── Search bar ──
	let searchTerm = "";
	let searchRegex = false;

	const searchBar = new SearchBar((term, isRegex, caseSensitive) => {
		if (xbin.active) {
			doCrossBinarySearch(
				sessionId,
				term,
				"strings",
				xbin,
				applyCrossBinaryResults,
				isRegex,
				caseSensitive
			);
			return;
		}
		searchTerm = term;
		searchRegex = isRegex;
		saveSearchState(sessionId, "strings", term, isRegex);
		applyFilters();
	});
	searchBar.mount(wrapper);
	registerSearchBar(sessionId, "strings", searchBar);
	searchBar.onEscape = () => table.focus();

	addAllBinariesToggle(searchBar, binaryCount, xbin, () => {
		if (!xbin.active) {
			// Switching back to local mode — restore original data
			table.setColumns(mode === "binary" ? BINARY_COLUMNS : LOCALISATION_COLUMNS);
			table.setStorageKey(
				mode === "binary" ? "cols:strings:binary" : "cols:strings:localisation"
			);
			table.setData(mode === "binary" ? binaryRows : localisationRows);
			applyFilters();
		}
		// Hide filter chips in cross-binary mode (they don't apply)
		chipBar.classList.toggle("hidden", xbin.active);
		const t = searchBar.getValue();
		searchBar.setValue(t, searchBar.isRegexMode(), searchBar.isCaseSensitive());
	});

	// ── Section/language filter chips ──
	const chipBar = document.createElement("div");
	chipBar.className = "filter-chip-bar";
	wrapper.appendChild(chipBar);

	// ── Data table ──
	const tableWrap = document.createElement("div");
	tableWrap.style.cssText = "flex:1;min-height:0;overflow:hidden;";
	wrapper.appendChild(tableWrap);

	const table = new DataTable(BINARY_COLUMNS, 28);
	table.setStorageKey("cols:strings:binary");
	table.mount(tableWrap);

	// ── Cross-binary "show all" hint ──
	const xbinHint = createCrossBinaryHint(tableWrap);

	function applyCrossBinaryResults(): void {
		const xrows = xbin.results.map((r) => ({
			value: r.match,
			binary: `${r.binaryName}  [${binaryTypeBadge(r.binaryType)}]`
		}));
		table.setColumns(CROSS_BINARY_COLUMNS);
		table.setStorageKey("cols:strings:xbin");
		table.setData(xrows);
		table.setFilter(null);
		updateCount();
	}

	function updateCount(): void {
		const shown = table.filteredCount;
		const total = table.totalCount;
		searchBar.updateCount(shown, total, plural(total, "string"));
		updateCrossBinaryHint(
			sessionId,
			xbinHint,
			xbin,
			searchBar.getValue(),
			"strings",
			"strings",
			applyCrossBinaryResults
		);
	}

	function buildChips(): void {
		chipBar.innerHTML = "";

		if (mode === "binary") {
			for (const section of sections) {
				const chip = document.createElement("button");
				chip.className = `filter-chip${activeSections.has(section) ? " filter-chip--active" : ""}`;
				chip.textContent = section;
				chip.addEventListener("click", () => {
					if (activeSections.has(section)) {
						activeSections.delete(section);
						chip.classList.remove("filter-chip--active");
					} else {
						activeSections.add(section);
						chip.classList.add("filter-chip--active");
					}
					setTabState(sessionId, "strings", "sections", [...activeSections]);
					applyFilters();
				});
				chipBar.appendChild(chip);
			}
		} else {
			for (const lang of languages) {
				const chip = document.createElement("button");
				chip.className = `filter-chip${activeLanguages.has(lang) ? " filter-chip--active" : ""}`;
				chip.textContent = lang;
				chip.addEventListener("click", () => {
					if (activeLanguages.has(lang)) {
						activeLanguages.delete(lang);
						chip.classList.remove("filter-chip--active");
					} else {
						activeLanguages.add(lang);
						chip.classList.add("filter-chip--active");
					}
					setTabState(sessionId, "strings", "languages", [...activeLanguages]);
					applyFilters();
				});
				chipBar.appendChild(chip);
			}
		}

		chipBar.classList.toggle(
			"hidden",
			xbin.active ||
				(mode === "binary" && sections.length === 0) ||
				(mode === "localisation" && languages.length === 0)
		);
	}

	function matchesSearch(text: string): boolean {
		if (!searchTerm) return true;
		if (searchRegex) {
			try {
				return new RegExp(searchTerm, "i").test(text);
			} catch {
				return true;
			}
		}
		return text.toLowerCase().includes(searchTerm.toLowerCase());
	}

	function applyFilters(): void {
		if (mode === "binary") {
			let activeMask = 0;
			for (const s of activeSections) {
				const idx = sectionIndex.get(s);
				if (idx !== undefined) activeMask |= 1 << idx;
			}
			table.setFilter((row) => {
				const mask = Number(row._sourceMask ?? 0);
				if (mask !== 0 && (mask & activeMask) === 0) return false;
				return matchesSearch(String(row.value ?? ""));
			});
		} else {
			table.setFilter((row) => {
				const lang = String(row.language ?? "");
				if (lang && !activeLanguages.has(lang)) return false;
				const key = String(row.key ?? "");
				const val = String(row.value ?? "");
				return matchesSearch(key) || matchesSearch(val);
			});
		}
		updateCount();
	}

	function switchMode(newMode: "binary" | "localisation"): void {
		if (newMode === mode) return;
		mode = newMode;
		setTabState(sessionId, "strings", "mode", mode);

		if (binaryBtn && localisationBtn) {
			binaryBtn.classList.toggle("strings-mode-btn--active", mode === "binary");
			localisationBtn.classList.toggle("strings-mode-btn--active", mode === "localisation");
		}

		// Swap columns and data
		table.unmount();
		table.setColumns(mode === "binary" ? BINARY_COLUMNS : LOCALISATION_COLUMNS);
		table.setStorageKey(
			mode === "binary" ? "cols:strings:binary" : "cols:strings:localisation"
		);
		table.mount(tableWrap);

		buildChips();
		table.setData(mode === "binary" ? binaryRows : localisationRows);
		applyFilters();
	}

	// Append to DOM first so the table has real dimensions for virtual scrolling
	container.appendChild(wrapper);
	if (mode === "localisation") {
		table.setColumns(LOCALISATION_COLUMNS);
		table.setStorageKey("cols:strings:localisation");
	}
	buildChips();
	table.setData(mode === "binary" ? binaryRows : localisationRows);

	// Restore saved search state (must happen after table is created)
	const savedState = getSearchState(sessionId, "strings");
	if (savedState?.term) {
		searchBar.setValue(savedState.term, savedState.isRegex);
	}

	if (savedSections !== undefined || savedLanguages !== undefined) {
		applyFilters();
	} else {
		updateCount();
	}

	// ── Cross-tab jump from a Security finding ──
	const target = takePendingTarget(sessionId, "strings");
	if (target?.kind === "string") {
		const offset = target.offset;
		const value = target.value;

		// Localisation mode renders a different table; switch back to binary rows.
		if (mode !== "binary") switchMode("binary");

		// The saved term/chips may hide the row.
		searchBar.setValue("", false);
		saveSearchState(sessionId, "strings", "", false);

		const row =
			offset !== undefined
				? binaryRows.find((r) => r._offset === offset)
				: value !== undefined
					? binaryRows.find((r) => r.value === value)
					: undefined;

		if (!row) {
			if (offset !== undefined) {
				navigateTo(sessionId, { sectionTab: "hex", kind: "hex", offset });
			} else {
				announce("String not found in this binary");
			}
			return;
		}

		if (row.source && !row.source.split(", ").some((s) => activeSections.has(s))) {
			for (const s of row.source.split(", ")) activeSections.add(s);
			setTabState(sessionId, "strings", "sections", [...activeSections]);
			buildChips();
		}
		applyFilters();
		// Defer so the tab's stored scroll restore cannot clobber the jump.
		requestAnimationFrame(() => {
			const found = table.selectRowWhere((r) =>
				offset !== undefined ? r._offset === offset : r.value === value
			);
			if (found) {
				table.focus();
				announce("Opened string in Strings");
			}
		});
	}
}
