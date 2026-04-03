/**
 * Libraries tab renderer — DataTable with search, grouping summary.
 */

import type { LinkedLibrary } from "../../shared/types";
import { DataTable, SearchBar, EmptyState } from "../components";
import type { Column } from "../components";
import { saveSearchState, getSearchState, registerSearchBar } from "../search-state";
import { el } from "../utils/dom";

// ── Helpers ──

function classifyLibrary(name: string): "system" | "swift" | "embedded" {
  if (name.startsWith("/usr/lib/swift") || name.includes("libswift")) return "swift";
  if (name.startsWith("/") || name.startsWith("@rpath/libswift")) return "system";
  return "embedded";
}

// ── Main render ──

export function renderLibraries(container: HTMLElement, data: LinkedLibrary[] | null): void {
  container.innerHTML = "";

  if (!data || data.length === 0) {
    const empty = new EmptyState({
      icon: "\u{1F4DA}",
      message: "No linked libraries found.",
    });
    empty.mount(container);
    return;
  }

  const wrapper = el("div", "lib-wrapper");

  // ── Group summary ──
  let systemCount = 0;
  let swiftCount = 0;
  let embeddedCount = 0;
  for (const lib of data) {
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

  // ── Search bar ──
  const searchContainer = el("div", "lib-search");
  wrapper.appendChild(searchContainer);

  // ── Data Table ──
  const tableContainer = el("div", "lib-table");
  wrapper.appendChild(tableContainer);
  container.appendChild(wrapper);

  const columns: Column[] = [
    { key: "name", label: "Name" },
    { key: "currentVersion", label: "Version", width: "120px" },
    { key: "type", label: "Type", width: "80px" },
  ];

  const table = new DataTable(columns);
  table.mount(tableContainer);

  // Convert to table rows
  const rows = data.map((lib) => ({
    name: lib.name.includes("@rpath") ? "\u26A0 " + lib.name : lib.name,
    currentVersion: lib.currentVersion ?? "",
    type: lib.weak ? "weak" : "strong",
    _rawName: lib.name,
  }));

  table.setData(rows as any);

  // ── Wire up search ──
  const searchBar = new SearchBar((term, isRegex) => {
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
    saveSearchState("libraries", term, isRegex);
    searchBar.updateCount(table.filteredCount, table.totalCount);
  });
  searchBar.mount(searchContainer);
  registerSearchBar("libraries", searchBar);
  searchBar.updateCount(table.filteredCount, table.totalCount);

  // Restore saved search state
  const savedState = getSearchState("libraries");
  if (savedState && savedState.term) {
    searchBar.setValue(savedState.term, savedState.isRegex);
  }
}

function buildCountBadge(label: string, count: number): HTMLElement {
  const badge = el("div", "lib-count-badge");
  badge.appendChild(el("span", "lib-count-num", String(count)));
  badge.appendChild(el("span", "lib-count-label", label));
  return badge;
}
