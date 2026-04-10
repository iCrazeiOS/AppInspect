/**
 * Libraries tab renderer — DataTable with search, grouping summary,
 * and a list/graph view toggle.
 */

import type { LinkedLibrary } from "../../shared/types";
import { DataTable, SearchBar, EmptyState } from "../components";
import type { Column } from "../components";
import { saveSearchState, getSearchState, registerSearchBar } from "../search-state";
import { el } from "../utils/dom";
import {
  createCrossBinaryState,
  addAllBinariesToggle,
  doCrossBinarySearch,
  binaryTypeBadge,
  createCrossBinaryHint,
  updateCrossBinaryHint,
} from "../utils/cross-binary-search";
import { mountGraphView } from "./graph";

// ── Helpers ──

function classifyLibrary(name: string): "system" | "swift" | "embedded" {
  if (name.startsWith("/usr/lib/swift") || name.includes("libswift")) return "swift";
  if (name.startsWith("/") || name.startsWith("@rpath/libswift")) return "system";
  return "embedded";
}

const COLUMNS: Column[] = [
  { key: "name", label: "Name" },
  { key: "currentVersion", label: "Version", width: "120px" },
  { key: "type", label: "Type", width: "80px" },
];

const CROSS_BINARY_COLUMNS: Column[] = [
  { key: "name", label: "Library Name" },
  { key: "binary", label: "Binary", width: "280px" },
];

// ── Main render ──

export function renderLibraries(container: HTMLElement, data: LinkedLibrary[] | null, binaryCount: number = 1, sessionId: string = ""): void {
  container.innerHTML = "";

  if (!data || data.length === 0) {
    const empty = new EmptyState({
      icon: "\u{1F4DA}",
      message: "No linked libraries found.",
    });
    empty.mount(container);
    return;
  }

  // ── Outer wrapper with view toggle ──
  const outerWrapper = el("div", "lib-outer-wrapper");

  // ── View toggle row ──
  const toggleRow = el("div", "lib-view-toggle");

  const listBtn = document.createElement("button");
  listBtn.className = "lib-toggle-btn lib-toggle-btn--active";
  listBtn.textContent = "List";

  const graphBtn = document.createElement("button");
  graphBtn.className = "lib-toggle-btn";
  graphBtn.textContent = "Graph";

  toggleRow.appendChild(listBtn);
  toggleRow.appendChild(graphBtn);
  outerWrapper.appendChild(toggleRow);

  // ── Content area (swapped between list and graph) ──
  const contentArea = el("div", "lib-content-area");
  outerWrapper.appendChild(contentArea);
  container.appendChild(outerWrapper);

  // Track current view and graph cleanup
  let currentView: "list" | "graph" = "list";
  let graphCleanup: (() => void) | null = null;

  function showListView(): void {
    if (currentView === "list") return;
    currentView = "list";
    listBtn.classList.add("lib-toggle-btn--active");
    graphBtn.classList.remove("lib-toggle-btn--active");
    if (graphCleanup) { graphCleanup(); graphCleanup = null; }
    contentArea.innerHTML = "";
    buildListView(contentArea);
  }

  function showGraphView(): void {
    if (currentView === "graph") return;
    currentView = "graph";
    graphBtn.classList.add("lib-toggle-btn--active");
    listBtn.classList.remove("lib-toggle-btn--active");
    contentArea.innerHTML = "";
    graphCleanup = mountGraphView(contentArea, sessionId);
  }

  listBtn.addEventListener("click", showListView);
  graphBtn.addEventListener("click", showGraphView);

  // ── Build list view (default) ──

  function buildListView(target: HTMLElement): void {
    const wrapper = el("div", "lib-wrapper");

    // ── Group summary ──
    let systemCount = 0;
    let swiftCount = 0;
    let embeddedCount = 0;
    for (const lib of data!) {
      const cat = classifyLibrary(lib.name);
      if (cat === "system") systemCount++;
      else if (cat === "swift") swiftCount++;
      else embeddedCount++;
    }

    const summary = el("div", "lib-summary");
    summary.appendChild(buildCountBadge("System Frameworks", systemCount));
    summary.appendChild(buildCountBadge("Swift Runtime", swiftCount));
    summary.appendChild(buildCountBadge("Embedded", embeddedCount));
    wrapper.appendChild(summary);

    // ── Cross-binary state ──
    const xbin = createCrossBinaryState();

    // ── Search bar ──
    const searchContainer = el("div", "lib-search");
    wrapper.appendChild(searchContainer);

    let searchTerm = "";
    let searchRegex = false;

    const searchBar = new SearchBar((term, isRegex, caseSensitive) => {
      if (xbin.active) {
        doCrossBinarySearch(sessionId, term, "libraries", xbin, applyCrossBinaryResults, isRegex, caseSensitive);
        return;
      }
      searchTerm = term;
      searchRegex = isRegex;
      if (!term) {
        table.setFilter(null);
      } else if (isRegex) {
        try {
          const re = new RegExp(term, "i");
          table.setFilter((row) => re.test(String(row["name"] ?? "")));
        } catch {
          // invalid regex — ignore
        }
      } else {
        const lc = term.toLowerCase();
        table.setFilter((row) => String(row["name"] ?? "").toLowerCase().includes(lc));
      }
      saveSearchState(sessionId, "libraries", term, isRegex);
      updateCount();
    });
    searchBar.mount(searchContainer);
    registerSearchBar(sessionId, "libraries", searchBar);
    searchBar.onEscape = () => table.focus();

    addAllBinariesToggle(searchBar, binaryCount, xbin, () => {
      if (!xbin.active) {
        // Switching back to local mode — restore original columns/data
        table.setColumns(COLUMNS);
        table.setStorageKey("cols:libraries");
        table.setData(rows as any);
        applyLocalFilter();
      }
      const t = searchBar.getValue();
      searchBar.setValue(t, searchBar.isRegexMode(), searchBar.isCaseSensitive());
    });

    // ── Row count ──
    const rowCount = el("div", "tab-row-count");
    wrapper.appendChild(rowCount);

    // ── Data Table ──
    const tableContainer = el("div", "lib-table");
    wrapper.appendChild(tableContainer);
    target.appendChild(wrapper);

    const table = new DataTable(COLUMNS);
    table.setStorageKey("cols:libraries");
    table.mount(tableContainer);

    // ── Cross-binary "show all" hint ──
    const xbinHint = createCrossBinaryHint(tableContainer);

    function applyCrossBinaryResults(): void {
      const xrows = xbin.results.map((r) => ({
        name: r.match,
        binary: `${r.binaryName}  [${binaryTypeBadge(r.binaryType)}]`,
      }));
      table.setColumns(CROSS_BINARY_COLUMNS);
      table.setStorageKey("cols:libraries:xbin");
      table.setData(xrows);
      table.setFilter(null);
      updateCount();
    }

    // Convert to table rows
    const rows = data!.map((lib) => ({
      name: lib.name.includes("@rpath") ? "\u26A0 " + lib.name : lib.name,
      currentVersion: lib.currentVersion ?? "",
      type: lib.weak ? "weak" : "strong",
      _rawName: lib.name,
    }));

    table.setData(rows as any);

    function updateCount(): void {
      const shown = table.filteredCount;
      const total = table.totalCount;
      rowCount.textContent = `Showing ${shown.toLocaleString()} of ${total.toLocaleString()} libraries`;
      searchBar.updateCount(shown, total);
      updateCrossBinaryHint(sessionId, xbinHint, xbin, searchBar.getValue(), "libraries", "libraries", applyCrossBinaryResults);
    }

    function applyLocalFilter(): void {
      if (!searchTerm) {
        table.setFilter(null);
      } else if (searchRegex) {
        try {
          const re = new RegExp(searchTerm, "i");
          table.setFilter((row) => re.test(String(row["name"] ?? "")));
        } catch {
          // invalid regex — ignore
        }
      } else {
        const lc = searchTerm.toLowerCase();
        table.setFilter((row) => String(row["name"] ?? "").toLowerCase().includes(lc));
      }
      updateCount();
    }

    updateCount();

    // Restore saved search state
    const savedState = getSearchState(sessionId, "libraries");
    if (savedState && savedState.term) {
      searchBar.setValue(savedState.term, savedState.isRegex);
    }
  }

  // Start with list view
  buildListView(contentArea);
}

function buildCountBadge(label: string, count: number): HTMLElement {
  const badge = el("div", "lib-count-badge");
  badge.appendChild(el("span", "lib-count-num", String(count)));
  badge.appendChild(el("span", "lib-count-label", label));
  return badge;
}
