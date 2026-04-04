/**
 * Symbols tab: displays symbol table entries with virtual scrolling,
 * search filtering (with regex toggle), and type filter buttons.
 */

import { DataTable, SearchBar } from "../components";
import type { Column } from "../components";
import { saveSearchState, getSearchState, registerSearchBar } from "../search-state";

interface SymbolEntry {
  name: string;
  type: "exported" | "imported" | "local";
  address: string | number;
}

const COLUMNS: Column[] = [
  { key: "name", label: "Symbol Name" },
  { key: "type", label: "Type", width: "120px" },
  { key: "addressHex", label: "Address", width: "140px" },
];

type TypeFilter = "all" | "exported" | "imported" | "local";

export function renderSymbols(container: HTMLElement, data: unknown): void {
  container.innerHTML = "";

  const entries = (Array.isArray(data) ? data : []) as SymbolEntry[];

  // Convert raw entries to table row format
  const rows = entries.map((e) => {
    const addr =
      typeof e.address === "number"
        ? "0x" + (e.address >>> 0).toString(16).padStart(8, "0")
        : typeof e.address === "string" && !e.address.startsWith("0x")
          ? "0x" + e.address
          : String(e.address ?? "0x0");
    return {
      name: e.name ?? "",
      type: e.type ?? "local",
      addressHex: addr,
    };
  });

  // ── Wrapper ──
  const wrapper = document.createElement("div");
  wrapper.className = "symbols-tab";
  wrapper.style.cssText = "display:flex;flex-direction:column;height:100%;min-height:0;";

  // ── Search bar ──
  let searchTerm = "";
  let searchRegex = false;

  const searchBar = new SearchBar((term, isRegex, _caseSensitive) => {
    searchTerm = term;
    searchRegex = isRegex;
    saveSearchState("symbols", term, isRegex);
    applyFilters();
  });
  searchBar.mount(wrapper);
  registerSearchBar("symbols", searchBar);

  // ── Type filter buttons ──
  let activeType: TypeFilter = "all";

  const filterBar = document.createElement("div");
  filterBar.className = "filter-chip-bar";

  const typeOptions: { label: string; value: TypeFilter }[] = [
    { label: "All", value: "all" },
    { label: "Exported", value: "exported" },
    { label: "Imported", value: "imported" },
    { label: "Local", value: "local" },
  ];

  const typeButtons = new Map<TypeFilter, HTMLButtonElement>();

  for (const opt of typeOptions) {
    const btn = document.createElement("button");
    btn.className =
      "filter-chip" + (opt.value === "all" ? " filter-chip--active" : "");
    btn.textContent = opt.label;

    // Add badge color indicator
    if (opt.value !== "all") {
      const dot = document.createElement("span");
      dot.className = `sym-badge sym-badge--${opt.value}`;
      btn.prepend(dot);
    }

    btn.addEventListener("click", () => {
      activeType = opt.value;
      for (const [val, b] of typeButtons) {
        b.classList.toggle("filter-chip--active", val === activeType);
      }
      applyFilters();
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
  table.setInitialCap(200);
  table.mount(tableWrap);
  table.onCapChange(() => updateCount());

  function updateCount(): void {
    const shown = table.filteredCount;
    const total = table.totalCount;
    rowCount.textContent = `Showing ${shown.toLocaleString()} of ${total.toLocaleString()} symbols`;
    searchBar.updateCount(shown, total);
  }

  function applyFilters(): void {
    table.setFilter((row) => {
      // Type filter
      if (activeType !== "all" && row["type"] !== activeType) return false;

      // Text/regex filter
      if (!searchTerm) return true;
      const name = String(row["name"] ?? "");
      if (searchRegex) {
        try {
          return new RegExp(searchTerm, "i").test(name);
        } catch {
          return true;
        }
      }
      return name.toLowerCase().includes(searchTerm.toLowerCase());
    });
    updateCount();
  }

  // Append to DOM first so the table has real dimensions for virtual scrolling
  container.appendChild(wrapper);
  table.setData(rows);

  // Restore saved search state (must happen after table is created)
  const savedState = getSearchState("symbols");
  if (savedState && savedState.term) {
    searchBar.setValue(savedState.term, savedState.isRegex);
  }

  updateCount();
}
