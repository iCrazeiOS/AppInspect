/**
 * Strings tab: displays extracted string entries with virtual scrolling,
 * search filtering (with regex toggle), and section filter chips.
 * Supports toggling between binary strings and localisation strings.
 */

import { DataTable, SearchBar } from "../components";
import type { Column } from "../components";
import { saveSearchState, getSearchState, registerSearchBar } from "../search-state";
import {
  createCrossBinaryState,
  addAllBinariesToggle,
  doCrossBinarySearch,
  binaryTypeBadge,
} from "../utils/cross-binary-search";

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
  { key: "offsetHex", label: "Offset", width: "120px" },
];

const LOCALISATION_COLUMNS: Column[] = [
  { key: "key", label: "Key", width: "25%" },
  { key: "value", label: "Value" },
  { key: "language", label: "Language", width: "100px" },
  { key: "file", label: "File", width: "30%" },
];

const CROSS_BINARY_COLUMNS: Column[] = [
  { key: "value", label: "String Value" },
  { key: "binary", label: "Binary", width: "280px" },
];

export function renderStrings(container: HTMLElement, data: unknown, binaryCount: number = 1): void {
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

  // Convert raw entries to table row format
  const binaryRows = binaryEntries.map((e) => ({
    value: e.value,
    source: e.sectionSource ?? "",
    offsetHex: "0x" + (e.offset >>> 0).toString(16).padStart(4, "0"),
    _offset: typeof e.offset === "number" ? e.offset : 0,
  }));

  const localisationRows = localisationEntries.map((e) => ({
    key: e.key,
    value: e.value,
    language: e.language,
    file: e.file,
  }));

  // ── State ──
  let mode: "binary" | "localisation" = "binary";

  // Collect unique sections for binary filter chips
  const sectionSet = new Set<string>();
  for (const r of binaryRows) {
    if (r.source) sectionSet.add(r.source);
  }
  const sections = [...sectionSet].sort();
  const activeSections = new Set<string>(sections);

  // Collect unique languages for localisation filter chips
  const langSet = new Set<string>();
  for (const r of localisationRows) {
    if (r.language) langSet.add(r.language);
  }
  const languages = [...langSet].sort();
  // Default to English if available, otherwise show all
  const englishLang = languages.find((l) => /^(en|en[-_]|english|base)$/i.test(l));
  const activeLanguages = new Set<string>(englishLang ? [englishLang] : languages);

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
    binaryBtn.className = "strings-mode-btn strings-mode-btn--active";
    binaryBtn.textContent = "Binary";
    binaryBtn.addEventListener("click", () => switchMode("binary"));

    localisationBtn = document.createElement("button");
    localisationBtn.className = "strings-mode-btn";
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
      doCrossBinarySearch(term, "strings", xbin, () => {
        const rows = xbin.results.map((r) => ({
          value: r.match,
          binary: `${r.binaryName}  [${binaryTypeBadge(r.binaryType)}]`,
        }));
        table.setColumns(CROSS_BINARY_COLUMNS);
        table.setStorageKey("cols:strings:xbin");
        table.setData(rows);
        table.setFilter(null);
        updateCount();
      }, isRegex, caseSensitive);
      return;
    }
    searchTerm = term;
    searchRegex = isRegex;
    saveSearchState("strings", term, isRegex);
    applyFilters();
  });
  searchBar.mount(wrapper);
  registerSearchBar("strings", searchBar);

  addAllBinariesToggle(searchBar, binaryCount, xbin, () => {
    if (!xbin.active) {
      // Switching back to local mode — restore original data
      table.setColumns(mode === "binary" ? BINARY_COLUMNS : LOCALISATION_COLUMNS);
      table.setStorageKey(mode === "binary" ? "cols:strings:binary" : "cols:strings:localisation");
      table.setData(mode === "binary" ? binaryRows : localisationRows);
      applyFilters();
    }
    const t = searchBar.getValue();
    searchBar.setValue(t, searchBar.isRegexMode(), searchBar.isCaseSensitive());
  });

  // ── Section/language filter chips ──
  const chipBar = document.createElement("div");
  chipBar.className = "filter-chip-bar";
  wrapper.appendChild(chipBar);

  // ── Row count ──
  const rowCount = document.createElement("div");
  rowCount.className = "tab-row-count";
  wrapper.appendChild(rowCount);

  // ── Data table ──
  const tableWrap = document.createElement("div");
  tableWrap.style.cssText = "flex:1;min-height:0;overflow:hidden;";
  wrapper.appendChild(tableWrap);

  const table = new DataTable(BINARY_COLUMNS, 28);
  table.setStorageKey("cols:strings:binary");
  table.setInitialCap(200);
  table.mount(tableWrap);
  table.onCapChange(() => updateCount());

  function updateCount(): void {
    const shown = table.filteredCount;
    const total = table.totalCount;
    rowCount.textContent = `Showing ${shown.toLocaleString()} of ${total.toLocaleString()} strings`;
    searchBar.updateCount(shown, total);
  }

  function buildChips(): void {
    chipBar.innerHTML = "";

    if (mode === "binary") {
      for (const section of sections) {
        const chip = document.createElement("button");
        chip.className = "filter-chip" + (activeSections.has(section) ? " filter-chip--active" : "");
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
        chipBar.appendChild(chip);
      }
    } else {
      for (const lang of languages) {
        const chip = document.createElement("button");
        chip.className = "filter-chip" + (activeLanguages.has(lang) ? " filter-chip--active" : "");
        chip.textContent = lang;
        chip.addEventListener("click", () => {
          if (activeLanguages.has(lang)) {
            activeLanguages.delete(lang);
            chip.classList.remove("filter-chip--active");
          } else {
            activeLanguages.add(lang);
            chip.classList.add("filter-chip--active");
          }
          applyFilters();
        });
        chipBar.appendChild(chip);
      }
    }

    chipBar.classList.toggle("hidden",
      (mode === "binary" && sections.length === 0) ||
      (mode === "localisation" && languages.length === 0));
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
      table.setFilter((row) => {
        const src = String(row["source"] ?? "");
        if (src && !activeSections.has(src)) return false;
        return matchesSearch(String(row["value"] ?? ""));
      });
    } else {
      table.setFilter((row) => {
        const lang = String(row["language"] ?? "");
        if (lang && !activeLanguages.has(lang)) return false;
        const key = String(row["key"] ?? "");
        const val = String(row["value"] ?? "");
        return matchesSearch(key) || matchesSearch(val);
      });
    }
    updateCount();
  }

  function switchMode(newMode: "binary" | "localisation"): void {
    if (newMode === mode) return;
    mode = newMode;

    if (binaryBtn && localisationBtn) {
      binaryBtn.classList.toggle("strings-mode-btn--active", mode === "binary");
      localisationBtn.classList.toggle("strings-mode-btn--active", mode === "localisation");
    }

    // Swap columns and data
    table.unmount();
    table.setColumns(mode === "binary" ? BINARY_COLUMNS : LOCALISATION_COLUMNS);
    table.setStorageKey(mode === "binary" ? "cols:strings:binary" : "cols:strings:localisation");
    table.mount(tableWrap);

    buildChips();
    table.setData(mode === "binary" ? binaryRows : localisationRows);
    applyFilters();
  }

  // Append to DOM first so the table has real dimensions for virtual scrolling
  container.appendChild(wrapper);
  buildChips();
  table.setData(binaryRows);

  // Restore saved search state (must happen after table is created)
  const savedState = getSearchState("strings");
  if (savedState && savedState.term) {
    searchBar.setValue(savedState.term, savedState.isRegex);
  }

  updateCount();
}
