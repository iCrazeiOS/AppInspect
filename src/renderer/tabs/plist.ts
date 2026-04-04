/**
 * Info.plist tab: quick-info chips + full collapsible JSON tree with search.
 */

import { SearchBar, JsonTree, EmptyState } from "../components";
import { saveSearchState, getSearchState, registerSearchBar } from "../search-state";

/** Extract quick-info fields from a raw plist object. */
function extractQuickInfo(plist: Record<string, unknown>): {
  urlSchemes: string[];
  backgroundModes: string[];
  privacyStrings: { key: string; value: string }[];
  atsExceptions: string[];
} {
  // URL schemes
  const urlSchemes: string[] = [];
  const urlTypes = plist["CFBundleURLTypes"];
  if (Array.isArray(urlTypes)) {
    for (const entry of urlTypes) {
      const schemes = (entry as Record<string, unknown>)?.["CFBundleURLSchemes"];
      if (Array.isArray(schemes)) {
        for (const s of schemes) {
          if (typeof s === "string") urlSchemes.push(s);
        }
      }
    }
  }

  // Background modes
  const backgroundModes: string[] = [];
  const bgModes = plist["UIBackgroundModes"];
  if (Array.isArray(bgModes)) {
    for (const m of bgModes) {
      if (typeof m === "string") backgroundModes.push(m);
    }
  }

  // Privacy usage strings (NS*UsageDescription)
  const privacyStrings: { key: string; value: string }[] = [];
  for (const [key, val] of Object.entries(plist)) {
    if (key.startsWith("NS") && key.endsWith("UsageDescription") && typeof val === "string") {
      privacyStrings.push({ key, value: val });
    }
  }

  // ATS exceptions
  const atsExceptions: string[] = [];
  const ats = plist["NSAppTransportSecurity"] as Record<string, unknown> | undefined;
  if (ats) {
    if (ats["NSAllowsArbitraryLoads"] === true) {
      atsExceptions.push("AllowsArbitraryLoads");
    }
    if (ats["NSAllowsArbitraryLoadsInWebContent"] === true) {
      atsExceptions.push("ArbitraryLoadsInWebContent");
    }
    if (ats["NSAllowsLocalNetworking"] === true) {
      atsExceptions.push("AllowsLocalNetworking");
    }
    const domains = ats["NSExceptionDomains"] as Record<string, unknown> | undefined;
    if (domains) {
      for (const domain of Object.keys(domains)) {
        atsExceptions.push(domain);
      }
    }
  }

  return { urlSchemes, backgroundModes, privacyStrings, atsExceptions };
}

export function renderPlist(container: HTMLElement, data: any): void {
  container.innerHTML = "";

  // data may be the raw plist object directly, or { raw: {...}, extracted: {...} }
  const plist: Record<string, unknown> | null =
    data?.raw ?? data?.plist ??
    (data && typeof data === "object" && !Array.isArray(data) ? data : null);

  if (!plist || Object.keys(plist).length === 0) {
    const empty = new EmptyState({
      icon: "\u2699",
      message: "No Info.plist data available.",
    });
    empty.mount(container);
    return;
  }

  // Quick-info section
  const info = extractQuickInfo(plist);
  const hasQuickInfo =
    info.urlSchemes.length > 0 ||
    info.backgroundModes.length > 0 ||
    info.privacyStrings.length > 0 ||
    info.atsExceptions.length > 0;

  if (hasQuickInfo) {
    const quickSection = document.createElement("div");
    quickSection.className = "plist-quick";

    const renderChipGroup = (label: string, items: string[]): void => {
      if (items.length === 0) return;
      const group = document.createElement("div");
      group.className = "plist-chip-group";

      const groupLabel = document.createElement("span");
      groupLabel.className = "plist-chip-label";
      groupLabel.textContent = label;
      group.appendChild(groupLabel);

      for (const item of items) {
        const chip = document.createElement("span");
        chip.className = "plist-chip";
        chip.textContent = item;
        chip.title = item;
        group.appendChild(chip);
      }

      quickSection.appendChild(group);
    };

    renderChipGroup("URL Schemes", info.urlSchemes);
    renderChipGroup("Background Modes", info.backgroundModes);
    renderChipGroup(
      "Privacy Strings",
      info.privacyStrings.map((p) => p.key.replace("NS", "").replace("UsageDescription", ""))
    );
    renderChipGroup("ATS Exceptions", info.atsExceptions);

    container.appendChild(quickSection);
  }

  // Search bar
  const searchWrap = document.createElement("div");
  searchWrap.className = "plist-search";
  container.appendChild(searchWrap);

  const treeContainer = document.createElement("div");
  treeContainer.className = "plist-tree";
  container.appendChild(treeContainer);

  const tree = new JsonTree();
  tree.mount(treeContainer);
  tree.setData(plist);

  const totalKeys = Object.keys(plist).length;
  const searchBar = new SearchBar((term, isRegex, _caseSensitive) => {
    saveSearchState("plist", term, isRegex);
    tree.filter(term);
    // Update count based on visible nodes
    const visibleCount = treeContainer.querySelectorAll(".jt-node:not(.jt-hidden)").length;
    searchBar.updateCount(term ? visibleCount : totalKeys, totalKeys);
  });
  searchBar.mount(searchWrap);
  registerSearchBar("plist", searchBar);

  // Restore saved search state
  const savedState = getSearchState("plist");
  if (savedState && savedState.term) {
    searchBar.setValue(savedState.term, savedState.isRegex);
  }
}
