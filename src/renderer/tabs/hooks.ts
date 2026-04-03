/**
 * Hooks tab: displays detected hook information for jailbreak tweaks.
 * Shows hook framework, target bundles, and hooked class/method pairs.
 */

import { DataTable, SearchBar, EmptyState } from "../components";
import type { Column } from "../components";
import { saveSearchState, getSearchState, registerSearchBar } from "../search-state";

interface HookMethod {
  className: string;
  selector: string;
  source: "logos" | "inferred";
}

interface HookInfo {
  frameworks: string[];
  targetBundles: string[];
  hookedClasses: string[];
  hookSymbols: string[];
  methods: HookMethod[];
}

const COLUMNS: Column[] = [
  { key: "className", label: "Class" },
  { key: "selector", label: "Method" },
  { key: "source", label: "Source", width: "100px" },
];

export function renderHooks(container: HTMLElement, data: unknown): void {
  container.innerHTML = "";

  const hooks = data as HookInfo | null;

  if (
    !hooks ||
    (!hooks.frameworks?.length &&
      !hooks.methods?.length &&
      !hooks.hookedClasses?.length)
  ) {
    const empty = new EmptyState({
      icon: "\u{1F517}",
      message: "No hooks detected in this binary.",
    });
    empty.mount(container);
    return;
  }

  const wrapper = document.createElement("div");
  wrapper.className = "hooks-tab";
  wrapper.style.cssText =
    "display:flex;flex-direction:column;height:100%;min-height:0;";

  // ── Summary bar ──
  const summary = document.createElement("div");
  summary.className = "hooks-summary";

  if (hooks.frameworks.length) {
    const chip = document.createElement("span");
    chip.className = "hooks-chip hooks-chip--framework";
    chip.textContent = hooks.frameworks.join(", ");
    summary.appendChild(chip);
  }

  if (hooks.targetBundles.length) {
    for (const bundle of hooks.targetBundles) {
      const chip = document.createElement("span");
      chip.className = "hooks-chip hooks-chip--bundle";
      chip.textContent = bundle;
      summary.appendChild(chip);
    }
  }

  if (hooks.hookedClasses.length) {
    const info = document.createElement("span");
    info.className = "hooks-stat";
    info.textContent = `${hooks.hookedClasses.length} hooked class${hooks.hookedClasses.length !== 1 ? "es" : ""}`;
    summary.appendChild(info);
  }

  if (hooks.methods.length) {
    const info = document.createElement("span");
    info.className = "hooks-stat";
    info.textContent = `${hooks.methods.length} hooked method${hooks.methods.length !== 1 ? "s" : ""}`;
    summary.appendChild(info);
  }

  wrapper.appendChild(summary);

  // ── Accuracy note ──
  const note = document.createElement("p");
  note.className = "hooks-note";
  note.textContent = "Hook details may be inaccurate. Accurate resolution requires disassembly.";
  wrapper.appendChild(note);

  // ── Methods table ──
  if (hooks.methods.length > 0) {
    // Search bar
    let searchTerm = "";
    let searchRegex = false;

    const searchBar = new SearchBar((term, isRegex) => {
      searchTerm = term;
      searchRegex = isRegex;
      saveSearchState("hooks", term, isRegex);
      applyFilters();
    });
    searchBar.mount(wrapper);
    registerSearchBar("hooks", searchBar);

    // Row count
    const rowCount = document.createElement("div");
    rowCount.className = "tab-row-count";
    wrapper.appendChild(rowCount);

    // Data table
    const tableWrap = document.createElement("div");
    tableWrap.style.cssText = "flex:1;min-height:0;overflow:hidden;";
    wrapper.appendChild(tableWrap);

    const rows = hooks.methods.map((m) => ({
      className: m.className,
      selector: m.selector,
      source: m.source,
    }));

    const table = new DataTable(COLUMNS, 28);
    table.mount(tableWrap);

    function updateCount(): void {
      const shown = table.filteredCount;
      const total = table.totalCount;
      rowCount.textContent = `Showing ${shown.toLocaleString()} of ${total.toLocaleString()} hooked methods`;
      searchBar.updateCount(shown, total);
    }

    function applyFilters(): void {
      table.setFilter((row) => {
        if (!searchTerm) return true;
        const text =
          String(row["className"] ?? "") + " " + String(row["selector"] ?? "");
        if (searchRegex) {
          try {
            return new RegExp(searchTerm, "i").test(text);
          } catch {
            return true;
          }
        }
        return text.toLowerCase().includes(searchTerm.toLowerCase());
      });
      updateCount();
    }

    container.appendChild(wrapper);
    table.setData(rows);

    // Restore saved search state
    const savedState = getSearchState("hooks");
    if (savedState && savedState.term) {
      searchBar.setValue(savedState.term, savedState.isRegex);
    }

    updateCount();
  } else if (hooks.hookedClasses.length > 0) {
    // No methods detected but we have hooked classes — show them as a list
    const classSection = document.createElement("div");
    classSection.className = "hooks-class-list";

    const title = document.createElement("h3");
    title.className = "hooks-section-title";
    title.textContent = "Hooked Classes";
    classSection.appendChild(title);

    const grid = document.createElement("div");
    grid.className = "hooks-class-grid";
    for (const cls of hooks.hookedClasses) {
      const tag = document.createElement("span");
      tag.className = "ov-hook-class-tag";
      tag.textContent = cls;
      grid.appendChild(tag);
    }
    classSection.appendChild(grid);
    wrapper.appendChild(classSection);
    container.appendChild(wrapper);
  } else {
    container.appendChild(wrapper);
  }
}
