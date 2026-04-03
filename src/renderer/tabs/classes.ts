/**
 * Classes tab: two-panel layout with searchable class list and method details.
 */

import { SearchBar, EmptyState } from "../components";
import { saveSearchState, getSearchState, registerSearchBar } from "../search-state";

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

export function renderClasses(container: HTMLElement, data: any): void {
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

  // Stats bar
  const stats = document.createElement("div");
  stats.className = "cls-stats";
  const totalMethods = allClasses.reduce((s, c) => s + c.methods.length, 0);
  stats.textContent = `${allClasses.length.toLocaleString()} classes \u00B7 ${totalMethods.toLocaleString()} methods \u00B7 ${allProtocols.length.toLocaleString()} protocols`;
  container.appendChild(stats);

  // Two-panel layout wrapper
  const wrapper = document.createElement("div");
  wrapper.className = "cls-panels";
  container.appendChild(wrapper);

  // ── Left panel ──
  const leftPanel = document.createElement("div");
  leftPanel.className = "cls-left";
  wrapper.appendChild(leftPanel);

  // Search bar
  const searchBar = new SearchBar((term, isRegex) => {
    if (!term) {
      filteredClasses = allClasses;
    } else {
      try {
        const re = isRegex ? new RegExp(term, "i") : null;
        const lower = term.toLowerCase();
        filteredClasses = allClasses.filter((c) =>
          re ? re.test(c.name) : c.name.toLowerCase().includes(lower)
        );
      } catch {
        return;
      }
    }
    saveSearchState("classes", term, isRegex);
    searchBar.updateCount(filteredClasses.length, allClasses.length);
    renderList();
  });
  searchBar.mount(leftPanel);
  registerSearchBar("classes", searchBar);
  searchBar.updateCount(filteredClasses.length, allClasses.length);

  // Restore saved search state
  const savedState = getSearchState("classes");
  if (savedState && savedState.term) {
    searchBar.setValue(savedState.term, savedState.isRegex);
  }

  // Virtual scroll container for class list
  const scrollContainer = document.createElement("div");
  scrollContainer.className = "cls-scroll";
  leftPanel.appendChild(scrollContainer);

  const spacer = document.createElement("div");
  spacer.className = "cls-spacer";
  scrollContainer.appendChild(spacer);

  const rowContainer = document.createElement("div");
  rowContainer.className = "cls-rows";
  scrollContainer.appendChild(rowContainer);

  function renderList(): void {
    spacer.style.height = `${filteredClasses.length * ROW_HEIGHT}px`;
    renderVisibleRows();
  }

  function renderVisibleRows(): void {
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
        selectedClass = cls;
        renderVisibleRows();
        renderDetail();
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

  // ── Right panel ──
  const rightPanel = document.createElement("div");
  rightPanel.className = "cls-right";
  wrapper.appendChild(rightPanel);

  function renderDetail(): void {
    rightPanel.innerHTML = "";
    if (!selectedClass) {
      const hint = document.createElement("div");
      hint.className = "cls-detail-hint";
      hint.textContent = "Select a class to view its methods";
      rightPanel.appendChild(hint);
      return;
    }

    const heading = document.createElement("h3");
    heading.className = "cls-detail-name";
    heading.textContent = selectedClass.name;
    rightPanel.appendChild(heading);

    const methodCount = document.createElement("div");
    methodCount.className = "cls-detail-count";
    methodCount.textContent = `${selectedClass.methods.length} method${selectedClass.methods.length !== 1 ? "s" : ""}`;
    rightPanel.appendChild(methodCount);

    if (selectedClass.methods.length === 0) {
      const noMethods = document.createElement("div");
      noMethods.className = "cls-detail-hint";
      noMethods.textContent = "No methods found for this class.";
      rightPanel.appendChild(noMethods);
      return;
    }

    const methodList = document.createElement("ul");
    methodList.className = "cls-method-list";
    for (const m of selectedClass.methods) {
      const sig = typeof m === "string" ? m : m.signature;
      const li = document.createElement("li");
      li.className = "cls-method-item";
      li.textContent = sig;
      li.title = "Click to copy";
      li.style.cursor = "pointer";
      li.addEventListener("click", () => {
        navigator.clipboard.writeText(sig).then(() => {
          li.classList.add("cls-method-copied");
          setTimeout(() => li.classList.remove("cls-method-copied"), 800);
        });
      });
      methodList.appendChild(li);
    }
    rightPanel.appendChild(methodList);
  }

  // Initial render
  renderList();
  renderDetail();
}
