/**
 * Strings tab: displays extracted string entries with virtual scrolling,
 * search filtering (with regex toggle), and section filter chips.
 */

import { DataTable, SearchBar } from "../components";
import type { Column } from "../components";
import { saveSearchState, getSearchState, registerSearchBar } from "../search-state";

interface StringEntry {
  value: string;
  source: string;
  offset: number;
}

const COLUMNS: Column[] = [
  { key: "value", label: "String Value" },
  { key: "source", label: "Source Section", width: "160px" },
  { key: "offsetHex", label: "Offset", width: "120px" },
];

export function renderStrings(container: HTMLElement, data: unknown): void {
  container.innerHTML = "";

  const entries = (Array.isArray(data) ? data : []) as StringEntry[];

  // Convert raw entries to table row format
  const rows = entries.map((e) => ({
    value: e.value,
    source: e.source ?? "",
    offsetHex: "0x" + (e.offset >>> 0).toString(16).padStart(4, "0"),
    _offset: typeof e.offset === "number" ? e.offset : 0,
  }));

  // Collect unique sections for filter chips
  const sectionSet = new Set<string>();
  for (const r of rows) {
    if (r.source) sectionSet.add(r.source);
  }
  const sections = [...sectionSet].sort();

  // Track active section filters (all on by default)
  const activeSections = new Set<string>(sections);

  // ── Wrapper ──
  const wrapper = document.createElement("div");
  wrapper.className = "strings-tab";
  wrapper.style.cssText = "display:flex;flex-direction:column;height:100%;min-height:0;";

  // ── Search bar ──
  let searchTerm = "";
  let searchRegex = false;

  const searchBar = new SearchBar((term, isRegex) => {
    searchTerm = term;
    searchRegex = isRegex;
    saveSearchState("strings", term, isRegex);
    applyFilters();
  });
  searchBar.mount(wrapper);
  registerSearchBar("strings", searchBar);

  // ── Section filter chips ──
  const chipBar = document.createElement("div");
  chipBar.className = "filter-chip-bar";

  const chipElements = new Map<string, HTMLButtonElement>();

  for (const section of sections) {
    const chip = document.createElement("button");
    chip.className = "filter-chip filter-chip--active";
    chip.textContent = section;
    chip.addEventListener("click", () => {
      if (activeSections.has(section)) {
        activeSections.delete(section);
        chip.classList.remove("filter-chip--active");
      } else {
        activeSections.add(section);
        chip.classList.add("filter-chip--active");
      }
      applyFilters();
    });
    chipElements.set(section, chip);
    chipBar.appendChild(chip);
  }

  if (sections.length > 0) {
    wrapper.appendChild(chipBar);
  }

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
    rowCount.textContent = `Showing ${shown.toLocaleString()} of ${total.toLocaleString()} strings`;
    searchBar.updateCount(shown, total);
  }

  function applyFilters(): void {
    table.setFilter((row) => {
      // Section filter
      const src = String(row["source"] ?? "");
      if (src && !activeSections.has(src)) return false;

      // Text/regex filter
      if (!searchTerm) return true;
      const val = String(row["value"] ?? "");
      if (searchRegex) {
        try {
          return new RegExp(searchTerm, "i").test(val);
        } catch {
          return true;
        }
      }
      return val.toLowerCase().includes(searchTerm.toLowerCase());
    });
    updateCount();
  }

  // Append to DOM first so the table has real dimensions for virtual scrolling
  container.appendChild(wrapper);
  table.setData(rows);

  // Restore saved search state (must happen after table is created)
  const savedState = getSearchState("strings");
  if (savedState && savedState.term) {
    searchBar.setValue(savedState.term, savedState.isRegex);
  }

  updateCount();
}
