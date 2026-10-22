/**
 * Symbols tab: displays symbol table entries with virtual scrolling,
 * search filtering (with regex toggle), and type filter buttons.
 */

import type { Column } from "../components";
import { DataTable, SearchBar } from "../components";
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

interface SymbolEntry {
	name: string;
	demangled?: string;
	type: "exported" | "imported" | "local";
	address: string | number;
}

const COLUMNS: Column[] = [
	{ key: "name", label: "Symbol Name" },
	{ key: "type", label: "Type", width: "120px" },
	{ key: "addressHex", label: "Address", width: "140px" }
];

type TypeFilter = "all" | "exported" | "imported" | "local";

const CROSS_BINARY_COLUMNS: Column[] = [
	{ key: "name", label: "Symbol Name" },
	{ key: "type", label: "Type", width: "120px" },
	{ key: "binary", label: "Binary", width: "280px" }
];

export function renderSymbols(
	container: HTMLElement,
	data: unknown,
	binaryCount: number = 1,
	sessionId: string = ""
): void {
	container.innerHTML = "";

	const entries = (Array.isArray(data) ? data : []) as SymbolEntry[];

	// Convert raw entries to table row format
	const rows = entries.map((e) => {
		const addr =
			typeof e.address === "number"
				? `0x${(e.address >>> 0).toString(16).padStart(8, "0")}`
				: typeof e.address === "string" && !e.address.startsWith("0x")
					? `0x${e.address}`
					: String(e.address ?? "0x0");
		return {
			name: e.demangled ?? e.name ?? "",
			nameRaw: e.name ?? "",
			type: e.type ?? "local",
			addressHex: addr
		};
	});

	// ── Wrapper ──
	const wrapper = document.createElement("div");
	wrapper.className = "symbols-tab";
	wrapper.style.cssText = "display:flex;flex-direction:column;height:100%;min-height:0;";

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
				"symbols",
				xbin,
				applyCrossBinaryResults,
				isRegex,
				caseSensitive
			);
			return;
		}
		searchTerm = term;
		searchRegex = isRegex;
		saveSearchState(sessionId, "symbols", term, isRegex);
		applyFilters();
	});
	searchBar.mount(wrapper);
	registerSearchBar(sessionId, "symbols", searchBar);
	searchBar.onEscape = () => table.focus();

	addAllBinariesToggle(searchBar, binaryCount, xbin, () => {
		if (!xbin.active) {
			// Switching back to local mode — restore original columns/data
			table.setColumns(COLUMNS);
			table.setStorageKey("cols:symbols");
			table.setData(rows);
			applyFilters();
		}
		const t = searchBar.getValue();
		searchBar.setValue(t, searchBar.isRegexMode(), searchBar.isCaseSensitive());
	});

	// ── Type filter buttons ──
	const savedType = getTabState<TypeFilter>(sessionId, "symbols", "type");
	let activeType: TypeFilter = savedType ?? "all";

	const filterBar = document.createElement("div");
	filterBar.className = "filter-chip-bar";

	const typeOptions: { label: string; value: TypeFilter }[] = [
		{ label: "All", value: "all" },
		{ label: "Exported", value: "exported" },
		{ label: "Imported", value: "imported" },
		{ label: "Local", value: "local" }
	];

	const typeButtons = new Map<TypeFilter, HTMLButtonElement>();

	for (const opt of typeOptions) {
		const btn = document.createElement("button");
		btn.className = `filter-chip${opt.value === activeType ? " filter-chip--active" : ""}`;
		btn.textContent = opt.label;

		// Add badge color indicator
		if (opt.value !== "all") {
			const dot = document.createElement("span");
			dot.className = `sym-badge sym-badge--${opt.value}`;
			btn.prepend(dot);
		}

		btn.addEventListener("click", () => {
			activeType = opt.value;
			setTabState(sessionId, "symbols", "type", activeType);
			for (const [val, b] of typeButtons) {
				b.classList.toggle("filter-chip--active", val === activeType);
			}
			if (xbin.active) {
				table.setFilter(activeType === "all" ? null : (row) => row.type === activeType);
				updateCount();
			} else {
				applyFilters();
			}
		});

		typeButtons.set(opt.value, btn);
		filterBar.appendChild(btn);
	}

	wrapper.appendChild(filterBar);

	// ── Row count ──
	const rowCount = document.createElement("div");
	rowCount.className = "tab-row-count";
	wrapper.appendChild(rowCount);

	// ── Data table ──
	const tableWrap = document.createElement("div");
	tableWrap.style.cssText = "flex:1;min-height:0;overflow:hidden;";
	wrapper.appendChild(tableWrap);

	const table = new DataTable(COLUMNS, 28);
	table.setStorageKey("cols:symbols");
	table.setInitialCap(200);
	table.mount(tableWrap);
	table.onCapChange(() => updateCount());

	// ── Cross-binary "show all" hint ──
	const xbinHint = createCrossBinaryHint(tableWrap);

	function applyCrossBinaryResults(): void {
		const xrows = xbin.results.map((r) => ({
			name: r.match,
			type: r.symbolType ?? "local",
			binary: `${r.binaryName}  [${binaryTypeBadge(r.binaryType)}]`
		}));
		table.setColumns(CROSS_BINARY_COLUMNS);
		table.setStorageKey("cols:symbols:xbin");
		table.setData(xrows);
		table.setFilter(activeType === "all" ? null : (row) => row.type === activeType);
		updateCount();
	}

	function updateCount(): void {
		const shown = table.filteredCount;
		const total = table.totalCount;
		rowCount.textContent = `Showing ${shown.toLocaleString()} of ${total.toLocaleString()} ${plural(total, "symbol")}`;
		searchBar.updateCount(shown, total);
		updateCrossBinaryHint(
			sessionId,
			xbinHint,
			xbin,
			searchBar.getValue(),
			"symbols",
			"symbols",
			applyCrossBinaryResults
		);
	}

	function applyFilters(): void {
		table.setFilter((row) => {
			// Type filter
			if (activeType !== "all" && row.type !== activeType) return false;

			// Text/regex filter — match the displayed and raw name
			if (!searchTerm) return true;
			const name = String(row.name ?? "");
			const nameRaw = String(row.nameRaw ?? "");
			if (searchRegex) {
				try {
					const re = new RegExp(searchTerm, "i");
					return re.test(name) || re.test(nameRaw);
				} catch {
					return true;
				}
			}
			const lower = searchTerm.toLowerCase();
			return name.toLowerCase().includes(lower) || nameRaw.toLowerCase().includes(lower);
		});
		updateCount();
	}

	// Append to DOM first so the table has real dimensions for virtual scrolling
	container.appendChild(wrapper);
	table.setData(rows);

	// Restore saved search state (must happen after table is created)
	const savedState = getSearchState(sessionId, "symbols");
	if (savedState?.term) {
		searchBar.setValue(savedState.term, savedState.isRegex);
	}

	if (activeType !== "all") applyFilters();

	updateCount();
}
