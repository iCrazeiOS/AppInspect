/**
 * Classes tab: three-panel layout — class list, method list, method detail sidebar.
 */

import { SearchBar, EmptyState } from "../components";
import { saveSearchState, getSearchState, registerSearchBar } from "../search-state";
import { saveWidths, loadWidths } from "../utils/layout-store";
import {
  createCrossBinaryState,
  addAllBinariesToggle,
  doCrossBinarySearch,
  binaryTypeBadge,
  buildShowAllLink,
} from "../utils/cross-binary-search";
import { parseMethodSignature, generateLogosHook } from "../utils/logos-hook";

interface ObjCMethod {
  selector: string;
  signature: string;
}

interface ObjCClass {
  name: string;
  methods: ObjCMethod[];
}

interface ClassesData {
  classes: ObjCClass[];
  protocols: string[];
}

const ROW_HEIGHT = 28;
const BUFFER = 20;

/** Set externally (e.g. by cross-binary click) to auto-select a class after render. */
let pendingClassSelect: string | null = null;

// ── Copy-to-clipboard helper with feedback ──

function copyWithFeedback(btn: HTMLButtonElement, text: string): void {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = "Copied!";
    btn.classList.add("cls-sb-btn--copied");
    setTimeout(() => {
      btn.textContent = orig;
      btn.classList.remove("cls-sb-btn--copied");
    }, 1200);
  });
}

// ── Main render ──

export function renderClasses(container: HTMLElement, data: any, binaryCount: number = 1, sessionId: string = ""): void {
  container.innerHTML = "";

  const classesData = data as ClassesData | null;
  if (
    !classesData ||
    (!classesData.classes?.length && !classesData.protocols?.length)
  ) {
    const empty = new EmptyState({
      icon: "\u{1F3D7}",
      message: "No Objective-C classes found in this binary.",
    });
    empty.mount(container);
    return;
  }

  const allClasses = classesData.classes ?? [];
  const allProtocols = classesData.protocols ?? [];
  let filteredClasses = allClasses;
  let selectedClass: ObjCClass | null = null;
  let selectedMethod: ObjCMethod | null = null;
  let selectedClassIndex = -1;

  // ── Cross-binary search state ──
  const xbin = createCrossBinaryState();

  // Stats bar
  const stats = document.createElement("div");
  stats.className = "cls-stats";
  const totalMethods = allClasses.reduce((s, c) => s + c.methods.length, 0);
  stats.textContent = `${allClasses.length.toLocaleString()} classes \u00B7 ${totalMethods.toLocaleString()} methods \u00B7 ${allProtocols.length.toLocaleString()} protocols`;
  container.appendChild(stats);

  // Three-panel layout wrapper
  const wrapper = document.createElement("div");
  wrapper.className = "cls-panels";
  container.appendChild(wrapper);

  // ── Left panel ──
  const leftPanel = document.createElement("div");
  leftPanel.className = "cls-left";
  wrapper.appendChild(leftPanel);

  // ── Resize handle: left ↔ middle ──
  const leftHandle = document.createElement("div");
  leftHandle.className = "cls-resize-handle";
  wrapper.appendChild(leftHandle);

  // Search bar
  const searchBar = new SearchBar((term, isRegex, caseSensitive) => {
    if (xbin.active) {
      doCrossBinarySearch(sessionId, term, "classes", xbin, () => {
        searchBar.updateCount(xbin.results.length, xbin.results.length);
        renderList();
      }, isRegex, caseSensitive);
      return;
    }

    selectedClassIndex = -1;
    if (!term) {
      filteredClasses = allClasses;
    } else {
      try {
        const flags = caseSensitive ? "" : "i";
        const re = isRegex ? new RegExp(term, flags) : null;
        if (caseSensitive) {
          filteredClasses = allClasses.filter((c) =>
            re ? re.test(c.name) : c.name.includes(term)
          );
        } else {
          const lower = term.toLowerCase();
          filteredClasses = allClasses.filter((c) =>
            re ? re.test(c.name) : c.name.toLowerCase().includes(lower)
          );
        }
      } catch {
        return;
      }
    }
    saveSearchState(sessionId, "classes", term, isRegex);
    searchBar.updateCount(filteredClasses.length, allClasses.length);
    renderList();
  });
  searchBar.mount(leftPanel);
  registerSearchBar(sessionId, "classes", searchBar);
  searchBar.updateCount(filteredClasses.length, allClasses.length);

  addAllBinariesToggle(searchBar, binaryCount, xbin, () => {
    const t = searchBar.getValue();
    searchBar.setValue(t, searchBar.isRegexMode(), searchBar.isCaseSensitive());
  });

  // Virtual scroll container for class list
  const scrollContainer = document.createElement("div");
  scrollContainer.className = "cls-scroll";
  scrollContainer.tabIndex = 0;
  leftPanel.appendChild(scrollContainer);

  const spacer = document.createElement("div");
  spacer.className = "cls-spacer";
  scrollContainer.appendChild(spacer);

  const rowContainer = document.createElement("div");
  rowContainer.className = "cls-rows";
  scrollContainer.appendChild(rowContainer);

  const CROSS_ROW_HEIGHT = 44; // taller rows for cross-binary results

  function renderList(): void {
    if (xbin.active) {
      const rh = CROSS_ROW_HEIGHT;
      spacer.style.height = `${xbin.results.length * rh}px`;
    } else {
      spacer.style.height = `${filteredClasses.length * ROW_HEIGHT}px`;
    }
    renderVisibleRows();
  }

  function renderVisibleRows(): void {
    if (xbin.active) {
      renderCrossBinaryRows();
      return;
    }

    const scrollTop = scrollContainer.scrollTop;
    const viewportHeight = scrollContainer.clientHeight;
    const total = filteredClasses.length;

    const startIndex = Math.max(
      0,
      Math.floor(scrollTop / ROW_HEIGHT) - BUFFER
    );
    const visibleCount = Math.ceil(viewportHeight / ROW_HEIGHT);
    const endIndex = Math.min(total, startIndex + visibleCount + BUFFER * 2);

    rowContainer.style.transform = `translateY(${startIndex * ROW_HEIGHT}px)`;

    const fragment = document.createDocumentFragment();
    for (let i = startIndex; i < endIndex; i++) {
      const cls = filteredClasses[i];
      if (!cls) continue;
      const row = document.createElement("div");
      row.className = "cls-row";
      if (selectedClass && selectedClass.name === cls.name) {
        row.classList.add("cls-row-active");
      }
      row.style.height = `${ROW_HEIGHT}px`;
      row.textContent = cls.name;
      row.title = cls.name;
      row.addEventListener("click", () => {
        selectedClassIndex = i;
        selectedClass = cls;
        selectedMethod = null;
        scrollContainer.focus();
        renderVisibleRows();
        renderDetail();
        renderSidebar();
      });
      fragment.appendChild(row);
    }
    rowContainer.innerHTML = "";
    rowContainer.appendChild(fragment);
  }

  function renderCrossBinaryRows(): void {
    if (xbin.loading) {
      rowContainer.innerHTML = "";
      rowContainer.style.transform = "";
      const loading = document.createElement("div");
      loading.className = "cls-cross-loading";
      loading.textContent = "Indexing binaries\u2026";
      rowContainer.appendChild(loading);
      return;
    }

    if (xbin.results.length === 0) {
      rowContainer.innerHTML = "";
      rowContainer.style.transform = "";
      const hint = document.createElement("div");
      hint.className = "cls-cross-loading";
      if (searchBar.getValue()) {
        hint.textContent = "No classes found across binaries.";
      } else {
        hint.textContent = "Type a class name to search across all binaries.";
        const showAll = buildShowAllLink(sessionId, "classes", "classes", xbin, () => {
          searchBar.updateCount(xbin.results.length, xbin.results.length);
          renderList();
        });
        hint.appendChild(document.createElement("br"));
        hint.appendChild(showAll);
      }
      rowContainer.appendChild(hint);
      return;
    }

    const rh = CROSS_ROW_HEIGHT;
    const scrollTop = scrollContainer.scrollTop;
    const viewportHeight = scrollContainer.clientHeight;
    const total = xbin.results.length;

    const startIndex = Math.max(0, Math.floor(scrollTop / rh) - BUFFER);
    const visibleCount = Math.ceil(viewportHeight / rh);
    const endIndex = Math.min(total, startIndex + visibleCount + BUFFER * 2);

    rowContainer.style.transform = `translateY(${startIndex * rh}px)`;

    const fragment = document.createDocumentFragment();
    for (let i = startIndex; i < endIndex; i++) {
      const result = xbin.results[i];
      if (!result) continue;

      const row = document.createElement("div");
      row.className = "cls-row cls-cross-row";
      row.style.height = `${rh}px`;
      row.title = `${result.match} in ${result.binaryName}`;

      const nameSpan = document.createElement("span");
      nameSpan.className = "cls-cross-name";
      nameSpan.textContent = result.match;
      row.appendChild(nameSpan);

      const binSpan = document.createElement("span");
      binSpan.className = "cls-cross-binary";
      binSpan.textContent = `${result.binaryName}  [${binaryTypeBadge(result.binaryType)}]`;
      row.appendChild(binSpan);

      row.addEventListener("click", () => {
        const dropdown = document.getElementById("binary-dropdown") as HTMLSelectElement | null;
        const sameBinary = !dropdown || dropdown.value === String(result.binaryIndex);

        if (sameBinary) {
          // Same binary — find the class locally, disable xbin mode, select it
          const cls = allClasses.find((c) => c.name === result.match);
          if (cls) {
            xbin.active = false;
            // Visually deactivate the "All" toggle button
            const toggleBtn = leftPanel.querySelector(".sb-extra-toggle--active");
            if (toggleBtn) toggleBtn.classList.remove("sb-extra-toggle--active");
            searchBar.setValue("", false);
            selectedClass = cls;
            selectedMethod = null;
            filteredClasses = allClasses;
            searchBar.updateCount(filteredClasses.length, allClasses.length);
            renderList();
            renderDetail();
            renderSidebar();
            // Scroll the selected class into view
            const idx = filteredClasses.indexOf(cls);
            if (idx >= 0) scrollContainer.scrollTop = idx * ROW_HEIGHT;
          }
        } else if (dropdown) {
          // Different binary — queue the class name, then switch
          pendingClassSelect = result.match;
          dropdown.value = String(result.binaryIndex);
          dropdown.dispatchEvent(new Event("change", { bubbles: true }));
        }
      });

      fragment.appendChild(row);
    }
    rowContainer.innerHTML = "";
    rowContainer.appendChild(fragment);
  }

  let rafId = 0;
  scrollContainer.addEventListener(
    "scroll",
    () => {
      if (rafId) return;
      rafId = requestAnimationFrame(() => {
        rafId = 0;
        renderVisibleRows();
      });
    },
    { passive: true }
  );

  // ── Class list keyboard navigation ──

  function moveClassSelection(delta: number): void {
    const total = xbin.active ? xbin.results.length : filteredClasses.length;
    if (total === 0) return;
    let next = selectedClassIndex + delta;
    if (selectedClassIndex === -1) next = delta > 0 ? 0 : total - 1;
    if (next < 0) next = total - 1;
    if (next >= total) next = 0;
    setClassSelection(next);
  }

  function setClassSelection(index: number): void {
    if (index === selectedClassIndex) return;
    selectedClassIndex = index;

    // Scroll into view
    const rh = xbin.active ? CROSS_ROW_HEIGHT : ROW_HEIGHT;
    const rowTop = index * rh;
    const rowBottom = rowTop + rh;
    const viewTop = scrollContainer.scrollTop;
    const viewBottom = viewTop + scrollContainer.clientHeight;
    if (rowTop < viewTop) {
      scrollContainer.scrollTop = rowTop;
    } else if (rowBottom > viewBottom) {
      scrollContainer.scrollTop = rowBottom - scrollContainer.clientHeight;
    }

    // Auto-select the class on navigation
    if (!xbin.active) {
      const cls = filteredClasses[index];
      if (cls) {
        selectedClass = cls;
        selectedMethod = null;
        renderDetail();
        renderSidebar();
      }
    }

    if (rafId) { cancelAnimationFrame(rafId); rafId = 0; }
    renderVisibleRows();
  }

  scrollContainer.addEventListener("keydown", (e: KeyboardEvent) => {
    const target = e.target as HTMLElement;
    if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.tagName === "SELECT") return;
    const total = xbin.active ? xbin.results.length : filteredClasses.length;
    if (total === 0) return;

    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        moveClassSelection(1);
        break;
      case "ArrowUp":
        e.preventDefault();
        moveClassSelection(-1);
        break;
      case "Home":
        e.preventDefault();
        setClassSelection(0);
        break;
      case "End":
        e.preventDefault();
        setClassSelection(total - 1);
        break;
      case "PageDown": {
        e.preventDefault();
        const rh = xbin.active ? CROSS_ROW_HEIGHT : ROW_HEIGHT;
        const page = Math.floor(scrollContainer.clientHeight / rh);
        moveClassSelection(page);
        break;
      }
      case "PageUp": {
        e.preventDefault();
        const rh = xbin.active ? CROSS_ROW_HEIGHT : ROW_HEIGHT;
        const page = Math.floor(scrollContainer.clientHeight / rh);
        moveClassSelection(-page);
        break;
      }
      case "Enter":
        if (selectedClassIndex >= 0 && !xbin.active) {
          const cls = filteredClasses[selectedClassIndex];
          if (cls) {
            selectedClass = cls;
            selectedMethod = null;
            renderVisibleRows();
            renderDetail();
            renderSidebar();
          }
        }
        break;
    }
  });

  searchBar.onEscape = () => scrollContainer.focus();

  // Restore saved search state (must happen after spacer/rowContainer are created)
  const savedState = getSearchState(sessionId, "classes");
  if (savedState && savedState.term) {
    searchBar.setValue(savedState.term, savedState.isRegex);
  }

  // Protocols collapsible section
  if (allProtocols.length > 0) {
    const protoSection = document.createElement("div");
    protoSection.className = "cls-proto-section";

    const protoHeader = document.createElement("button");
    protoHeader.className = "cls-proto-header";
    protoHeader.textContent = `\u25B6 Protocols (${allProtocols.length})`;
    let protoExpanded = false;

    const protoList = document.createElement("div");
    protoList.className = "cls-proto-list";
    protoList.style.display = "none";

    for (const p of allProtocols) {
      const item = document.createElement("div");
      item.className = "cls-proto-item";
      item.textContent = p;
      protoList.appendChild(item);
    }

    protoHeader.addEventListener("click", () => {
      protoExpanded = !protoExpanded;
      protoHeader.textContent = `${protoExpanded ? "\u25BC" : "\u25B6"} Protocols (${allProtocols.length})`;
      protoList.style.display = protoExpanded ? "block" : "none";
    });

    protoSection.appendChild(protoHeader);
    protoSection.appendChild(protoList);
    leftPanel.appendChild(protoSection);
  }

  // ── Middle panel (method list) ──
  const rightPanel = document.createElement("div");
  rightPanel.className = "cls-right";
  wrapper.appendChild(rightPanel);

  // Method search bar + scope toggle (persistent across re-renders)
  const methodSearchWrap = document.createElement("div");
  methodSearchWrap.className = "cls-method-search-wrap";
  rightPanel.appendChild(methodSearchWrap);

  let methodSearchTerm = "";
  let methodSearchRegex = false;
  let methodSearchCaseSensitive = true;
  let searchAllClasses = false;

  const methodSearchBar = new SearchBar((term, isRegex, caseSensitive) => {
    methodSearchTerm = term;
    methodSearchRegex = isRegex;
    methodSearchCaseSensitive = caseSensitive;
    renderMethodList();
  });
  methodSearchBar.mount(methodSearchWrap);

  const scopeToggle = document.createElement("button");
  scopeToggle.className = "cls-scope-toggle";
  scopeToggle.textContent = "All Classes";
  scopeToggle.title = "Search across all classes";
  scopeToggle.addEventListener("click", () => {
    searchAllClasses = !searchAllClasses;
    scopeToggle.classList.toggle("cls-scope-toggle--active", searchAllClasses);
    scopeToggle.textContent = searchAllClasses ? "All Classes" : "All Classes";
    renderMethodList();
  });
  methodSearchWrap.appendChild(scopeToggle);

  // Header area (class name + method count) — re-rendered
  const detailHeader = document.createElement("div");
  detailHeader.className = "cls-detail-header";
  rightPanel.appendChild(detailHeader);

  // Scrollable method list area
  const methodListContainer = document.createElement("div");
  methodListContainer.className = "cls-method-scroll";
  rightPanel.appendChild(methodListContainer);

  // ── Resize handle: middle ↔ sidebar ──
  const rightHandle = document.createElement("div");
  rightHandle.className = "cls-resize-handle cls-resize-handle-right";
  rightHandle.style.display = "none"; // hidden until sidebar opens
  wrapper.appendChild(rightHandle);

  // ── Right sidebar (method detail) ──
  const sidebar = document.createElement("div");
  sidebar.className = "cls-sidebar";
  wrapper.appendChild(sidebar);

  // ── Panel resize drag logic ──
  /** Minimum width the middle (methods) panel is allowed to shrink to. */
  const MIN_MIDDLE = 360;

  /**
   * Compute the maximum width a side panel may occupy right now,
   * ensuring the methods pane always keeps at least MIN_MIDDLE px.
   */
  function panelMax(side: "left" | "right"): number {
    const containerW = wrapper.getBoundingClientRect().width;
    const sidebarOpen = sidebar.classList.contains("cls-sidebar--open");
    const siblingW = side === "left"
      ? (sidebarOpen ? sidebar.getBoundingClientRect().width : 0)
      : leftPanel.getBoundingClientRect().width;
    // ~10px accounts for the resize handles
    return Math.max(180, containerW - siblingW - MIN_MIDDLE - 10);
  }

  function initPanelResize(
    handle: HTMLElement,
    getTargetEl: () => HTMLElement,
    options: { side: "left" | "right"; min?: number; storageKey: string },
  ): void {
    const min = options.min ?? 180;

    // Restore saved width (skip sidebar — restored on open in renderSidebar)
    if (options.side === "left") {
      const saved = loadWidths(options.storageKey);
      if (saved?.width) {
        getTargetEl().style.width = saved.width;
      }
    }

    handle.addEventListener("mousedown", (e) => {
      e.preventDefault();
      const el = getTargetEl();
      const startX = e.clientX;
      const startW = el.getBoundingClientRect().width;
      const max = panelMax(options.side);
      const prevSelect = document.body.style.userSelect;
      document.body.style.userSelect = "none";
      handle.classList.add("cls-resize-handle--active");

      const onMove = (ev: MouseEvent): void => {
        const delta = ev.clientX - startX;
        const raw = options.side === "left" ? startW + delta : startW - delta;
        const newW = Math.max(min, Math.min(max, raw));
        el.style.width = `${newW}px`;
        if (options.side === "right") el.style.minWidth = `${newW}px`;
      };

      const onUp = (ev: MouseEvent): void => {
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
        document.body.style.userSelect = prevSelect;
        handle.classList.remove("cls-resize-handle--active");
        saveWidths(options.storageKey, { width: el.style.width });
      };

      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
  }

  initPanelResize(leftHandle, () => leftPanel, { side: "left", storageKey: "panels:classes:left" });
  initPanelResize(rightHandle, () => sidebar, { side: "right", storageKey: "panels:classes:sidebar" });

  // Re-clamp panels when the container resizes (e.g. window resize)
  new ResizeObserver(() => {
    const leftMax = panelMax("left");
    const leftW = leftPanel.getBoundingClientRect().width;
    if (leftW > leftMax) {
      leftPanel.style.width = `${leftMax}px`;
    }

    if (sidebar.classList.contains("cls-sidebar--open")) {
      const rightMax = panelMax("right");
      const sidebarW = sidebar.getBoundingClientRect().width;
      if (sidebarW > rightMax) {
        const w = `${rightMax}px`;
        sidebar.style.width = w;
        sidebar.style.minWidth = w;
      }
    }
  }).observe(wrapper);

  /** Get filtered methods for the current view */
  function getFilteredMethods(): { className: string; method: ObjCMethod }[] {
    let matcher: ((s: string) => boolean) | null = null;
    if (methodSearchTerm) {
      try {
        if (methodSearchRegex) {
          const flags = methodSearchCaseSensitive ? "" : "i";
          const re = new RegExp(methodSearchTerm, flags);
          matcher = (s) => re.test(s);
        } else if (methodSearchCaseSensitive) {
          matcher = (s) => s.includes(methodSearchTerm);
        } else {
          const lower = methodSearchTerm.toLowerCase();
          matcher = (s) => s.toLowerCase().includes(lower);
        }
      } catch {
        return [];
      }
    }

    if (searchAllClasses && methodSearchTerm) {
      // Search across all classes
      const results: { className: string; method: ObjCMethod }[] = [];
      for (const cls of allClasses) {
        for (const m of cls.methods) {
          const sig = typeof m === "string" ? m : m.signature;
          if (!matcher || matcher(sig)) {
            results.push({ className: cls.name, method: m });
          }
        }
      }
      return results;
    }

    if (!selectedClass) return [];

    const clsName = selectedClass.name;
    return selectedClass.methods
      .filter((m) => {
        if (!matcher) return true;
        const sig = typeof m === "string" ? m : m.signature;
        return matcher(sig);
      })
      .map((m) => ({ className: clsName, method: m }));
  }

  function renderDetail(): void {
    detailHeader.innerHTML = "";
    if (!selectedClass && !(searchAllClasses && methodSearchTerm)) {
      detailHeader.innerHTML = "";
      // clear method list too
      methodListContainer.innerHTML = "";
      const hint = document.createElement("div");
      hint.className = "cls-detail-hint";
      hint.textContent = "Select a class to view its methods";
      methodListContainer.appendChild(hint);
      return;
    }
    renderMethodList();
  }

  function renderMethodList(): void {
    detailHeader.innerHTML = "";
    methodListContainer.innerHTML = "";

    const filtered = getFilteredMethods();

    if (searchAllClasses && methodSearchTerm) {
      // Show global search results header
      const heading = document.createElement("h3");
      heading.className = "cls-detail-name";
      heading.textContent = "Method Search";
      detailHeader.appendChild(heading);

      const countEl = document.createElement("div");
      countEl.className = "cls-detail-count";
      countEl.textContent = `${filtered.length.toLocaleString()} result${filtered.length !== 1 ? "s" : ""} across all classes`;
      detailHeader.appendChild(countEl);

      methodSearchBar.updateCount(filtered.length, totalMethods);
    } else if (selectedClass) {
      const heading = document.createElement("h3");
      heading.className = "cls-detail-name";
      heading.textContent = selectedClass.name;
      detailHeader.appendChild(heading);

      const countEl = document.createElement("div");
      countEl.className = "cls-detail-count";
      const total = selectedClass.methods.length;
      if (methodSearchTerm) {
        countEl.textContent = `${filtered.length} of ${total} method${total !== 1 ? "s" : ""}`;
      } else {
        countEl.textContent = `${total} method${total !== 1 ? "s" : ""}`;
      }
      detailHeader.appendChild(countEl);

      methodSearchBar.updateCount(filtered.length, total);
    } else {
      const hint = document.createElement("div");
      hint.className = "cls-detail-hint";
      hint.textContent = "Select a class to view its methods";
      methodListContainer.appendChild(hint);
      methodSearchBar.updateCount(0, 0);
      return;
    }

    if (filtered.length === 0) {
      const noMethods = document.createElement("div");
      noMethods.className = "cls-detail-hint";
      noMethods.textContent = methodSearchTerm ? "No matching methods." : "No methods found for this class.";
      methodListContainer.appendChild(noMethods);
      return;
    }

    const methodList = document.createElement("ul");
    methodList.className = "cls-method-list";

    let lastClassName = "";
    for (const { className: clsName, method: m } of filtered) {
      // In global search, show class name group headers
      if (searchAllClasses && methodSearchTerm && clsName !== lastClassName) {
        lastClassName = clsName;
        const groupHeader = document.createElement("li");
        groupHeader.className = "cls-method-group";
        groupHeader.textContent = clsName;
        groupHeader.addEventListener("click", () => {
          // Click class header to select that class
          const cls = allClasses.find((c) => c.name === clsName);
          if (cls) {
            selectedClass = cls;
            searchAllClasses = false;
            scopeToggle.classList.remove("cls-scope-toggle--active");
            methodSearchTerm = "";
            methodSearchBar.setValue("", false);
            renderVisibleRows();
            renderDetail();
            renderSidebar();
          }
        });
        methodList.appendChild(groupHeader);
      }

      const sig = typeof m === "string" ? m : m.signature;
      const li = document.createElement("li");
      li.className = "cls-method-item";
      if (selectedMethod && selectedMethod === m) {
        li.classList.add("cls-method-active");
      }
      li.textContent = sig;
      li.title = "Click to inspect";
      li.addEventListener("click", () => {
        // In global search, also select the parent class
        if (searchAllClasses) {
          const cls = allClasses.find((c) => c.name === clsName);
          if (cls) selectedClass = cls;
        }
        selectedMethod = m;
        renderMethodList();
        renderSidebar();
      });
      methodList.appendChild(li);
    }
    methodListContainer.appendChild(methodList);
  }

  function renderSidebar(): void {
    sidebar.innerHTML = "";

    if (!selectedMethod || !selectedClass) {
      sidebar.classList.remove("cls-sidebar--open");
      sidebar.style.width = "";
      sidebar.style.minWidth = "";
      rightHandle.style.display = "none";
      return;
    }

    sidebar.classList.add("cls-sidebar--open");
    // Restore persisted width when opening, clamped to available space
    const saved = loadWidths("panels:classes:sidebar");
    if (saved?.width) {
      const max = panelMax("right");
      const parsed = parseInt(saved.width, 10);
      const clamped = Number.isFinite(parsed) ? Math.min(parsed, max) : parsed;
      const w = `${clamped}px`;
      sidebar.style.width = w;
      sidebar.style.minWidth = w;
    }
    rightHandle.style.display = "";

    const inner = document.createElement("div");
    inner.className = "cls-sb-inner";
    sidebar.appendChild(inner);

    const sig = typeof selectedMethod === "string" ? selectedMethod : selectedMethod.signature;
    const className = selectedClass.name;
    const parsed = parseMethodSignature(sig);

    // Close button
    const closeBtn = document.createElement("button");
    closeBtn.className = "cls-sb-close";
    closeBtn.textContent = "\u00D7";
    closeBtn.title = "Close";
    closeBtn.addEventListener("click", () => {
      selectedMethod = null;
      sidebar.classList.remove("cls-sidebar--open");
      sidebar.style.width = "";
      sidebar.style.minWidth = "";
      sidebar.innerHTML = "";
      rightHandle.style.display = "none";
      renderDetail();
    });
    inner.appendChild(closeBtn);

    // Full method signature (wrapping)
    const sigBlock = document.createElement("div");
    sigBlock.className = "cls-sb-sig";
    sigBlock.textContent = sig;
    inner.appendChild(sigBlock);

    // Class name
    const classLabel = document.createElement("div");
    classLabel.className = "cls-sb-class";
    classLabel.textContent = className;
    inner.appendChild(classLabel);

    // ── Copy buttons section ──
    const actions = document.createElement("div");
    actions.className = "cls-sb-actions";
    inner.appendChild(actions);

    // Copy class name
    const copyClassBtn = document.createElement("button");
    copyClassBtn.className = "cls-sb-btn";
    copyClassBtn.textContent = "Copy Class Name";
    copyClassBtn.addEventListener("click", () => copyWithFeedback(copyClassBtn, className));
    actions.appendChild(copyClassBtn);

    if (parsed) {
      // Copy selector (e.g. "doA:withB:")
      const copySelectorBtn = document.createElement("button");
      copySelectorBtn.className = "cls-sb-btn";
      copySelectorBtn.textContent = "Copy Selector";
      copySelectorBtn.addEventListener("click", () =>
        copyWithFeedback(copySelectorBtn, parsed.selector)
      );
      actions.appendChild(copySelectorBtn);

      // Copy full signature
      const copySigBtn = document.createElement("button");
      copySigBtn.className = "cls-sb-btn";
      copySigBtn.textContent = "Copy Signature";
      copySigBtn.addEventListener("click", () => copyWithFeedback(copySigBtn, sig));
      actions.appendChild(copySigBtn);

      // ── Logos Hook section ──
      const hookSection = document.createElement("div");
      hookSection.className = "cls-sb-hook-section";
      inner.appendChild(hookSection);

      const hookLabel = document.createElement("div");
      hookLabel.className = "cls-sb-section-title";
      hookLabel.textContent = "Logos Hook";
      hookSection.appendChild(hookLabel);

      const hookCode = generateLogosHook(className, parsed);

      const codeBlock = document.createElement("pre");
      codeBlock.className = "cls-sb-code";
      codeBlock.textContent = hookCode;
      hookSection.appendChild(codeBlock);

      const copyHookBtn = document.createElement("button");
      copyHookBtn.className = "cls-sb-btn cls-sb-btn--accent";
      copyHookBtn.textContent = "Copy Logos Hook";
      copyHookBtn.addEventListener("click", () => copyWithFeedback(copyHookBtn, hookCode));
      hookSection.appendChild(copyHookBtn);
    } else {
      // Fallback: just copy the raw signature
      const copySigBtn = document.createElement("button");
      copySigBtn.className = "cls-sb-btn";
      copySigBtn.textContent = "Copy Signature";
      copySigBtn.addEventListener("click", () => copyWithFeedback(copySigBtn, sig));
      actions.appendChild(copySigBtn);
    }
  }

  // Check for pending class selection (from cross-binary click on a different binary)
  if (pendingClassSelect) {
    const cls = allClasses.find((c) => c.name === pendingClassSelect);
    pendingClassSelect = null;
    if (cls) {
      selectedClass = cls;
      selectedMethod = null;
      renderList();
      renderDetail();
      renderSidebar();
      const idx = filteredClasses.indexOf(cls);
      if (idx >= 0) scrollContainer.scrollTop = idx * ROW_HEIGHT;
      return;
    }
  }

  // Initial render
  renderList();
  renderDetail();
  renderSidebar();
}
