/**
 * Virtualized data table component for large datasets.
 * Uses fixed row height and simple virtual scrolling.
 */

import { showToast } from "./toast";
import { saveWidths, loadWidths } from "../utils/layout-store";

export interface Column {
  key: string;
  label: string;
  width?: string;
}

export class DataTable {
  private columns: Column[];
  private rowHeight: number;
  private storageKey: string | null = null;
  private container: HTMLElement | null = null;
  private root: HTMLElement | null = null;
  private headerRow: HTMLElement | null = null;
  private scrollContainer: HTMLElement | null = null;
  private spacer: HTMLElement | null = null;
  private rowContainer: HTMLElement | null = null;

  private allData: Record<string, string | number>[] = [];
  private filteredData: Record<string, string | number>[] = [];
  private filterFn: ((row: Record<string, string | number>) => boolean) | null = null;

  private sortKey: string | null = null;
  private sortAsc = true;

  private rafId = 0;
  private boundOnScroll: () => void;
  private resizing = false;

  /** Optional initial row cap — when set and no filter is active, only show this many rows */
  private initialCap: number | null = null;
  private isCapped = false;
  private showMoreEl: HTMLElement | null = null;

  onRowClick?: (row: Record<string, string | number>, index: number) => void;

  private static BUFFER = 20;

  constructor(columns: Column[], rowHeight = 28) {
    this.columns = columns;
    this.rowHeight = rowHeight;
    this.boundOnScroll = this.onScroll.bind(this);
  }

  /** Enable localStorage persistence of column widths under the given key. Restores any saved widths. */
  setStorageKey(key: string): void {
    this.storageKey = key;
    const saved = loadWidths(key);
    if (saved) {
      for (const col of this.columns) {
        if (saved[col.key] != null) col.width = saved[col.key];
      }
    }
  }

  /** Persist current column widths to localStorage. */
  private persistWidths(): void {
    if (!this.storageKey) return;
    const widths: Record<string, string> = {};
    for (const col of this.columns) {
      if (col.width) widths[col.key] = col.width;
    }
    saveWidths(this.storageKey, widths);
  }

  /** Set an initial row limit. When no filter is active, only this many rows are shown with a "Show all" button. */
  setInitialCap(cap: number): void {
    this.initialCap = cap;
  }

  mount(container: HTMLElement): void {
    this.container = container;

    // Root wrapper
    const root = document.createElement("div");
    root.className = "dt-root";
    this.root = root;

    // Header
    const header = document.createElement("div");
    header.className = "dt-header";
    this.headerRow = header;
    this.renderHeader();
    root.appendChild(header);

    // Scroll container
    const scroll = document.createElement("div");
    scroll.className = "dt-scroll";
    this.scrollContainer = scroll;

    // Spacer (sets total height for scrollbar)
    const spacer = document.createElement("div");
    spacer.className = "dt-spacer";
    this.spacer = spacer;
    scroll.appendChild(spacer);

    // Row container (positioned inside spacer)
    const rowContainer = document.createElement("div");
    rowContainer.className = "dt-rows";
    this.rowContainer = rowContainer;
    scroll.appendChild(rowContainer);

    scroll.addEventListener("scroll", this.boundOnScroll, { passive: true });
    root.appendChild(scroll);

    container.appendChild(root);
  }

  private renderHeader(): void {
    if (!this.headerRow) return;
    this.headerRow.innerHTML = "";

    for (let ci = 0; ci < this.columns.length; ci++) {
      const col = this.columns[ci]!;
      const cell = document.createElement("div");
      cell.className = "dt-hcell";
      if (col.width) cell.style.width = col.width;
      else cell.style.flex = "1";

      const label = document.createElement("span");
      label.textContent = col.label;
      cell.appendChild(label);

      // Sort indicator
      const indicator = document.createElement("span");
      indicator.className = "dt-sort-indicator";
      if (this.sortKey === col.key) {
        indicator.textContent = this.sortAsc ? " \u25B2" : " \u25BC";
      }
      cell.appendChild(indicator);

      cell.addEventListener("click", () => this.handleSort(col.key));

      // Resize handle (not on the last column)
      if (ci < this.columns.length - 1) {
        const handle = document.createElement("div");
        handle.className = "dt-resize-handle";
        handle.addEventListener("mousedown", (e) => {
          e.stopPropagation(); // prevent sort
          e.preventDefault();
          this.startResize(ci, cell, e);
        });
        cell.appendChild(handle);
      }

      this.headerRow.appendChild(cell);
    }
  }

  private startResize(colIndex: number, headerCell: HTMLElement, e: MouseEvent): void {
    this.resizing = true;
    const startX = e.clientX;
    const startWidth = headerCell.getBoundingClientRect().width;

    // Freeze all non-last columns to their current pixel widths so that
    // resizing one column doesn't cause flex/% neighbours to reflow.
    const headerCells = this.headerRow ? Array.from(this.headerRow.children) as HTMLElement[] : [];
    const lastCol = this.columns.length - 1;
    for (let i = 0; i < this.columns.length; i++) {
      if (i === lastCol) continue; // last column stays flex
      const hc = headerCells[i];
      if (hc && !this.columns[i]!.width?.endsWith("px")) {
        const px = `${Math.round(hc.getBoundingClientRect().width)}px`;
        this.columns[i]!.width = px;
        hc.style.width = px;
        hc.style.flex = "";
      }
    }
    // Ensure last column is flex
    const lastHc = headerCells[lastCol];
    if (lastHc) {
      this.columns[lastCol]!.width = undefined;
      lastHc.style.width = "";
      lastHc.style.flex = "1";
    }
    // Apply frozen widths to visible data rows too
    this.renderVisibleRows();

    // Compute max width: total header width minus 50px per other column
    const totalWidth = this.headerRow?.getBoundingClientRect().width ?? Infinity;
    let otherColumnsMin = 0;
    for (let i = 0; i < this.columns.length; i++) {
      if (i !== colIndex) otherColumnsMin += 50;
    }
    const maxWidth = totalWidth - otherColumnsMin;

    const handle = headerCell.querySelector(".dt-resize-handle") as HTMLElement | null;
    handle?.classList.add("dt-resizing");

    const prevSelect = document.body.style.userSelect;
    document.body.style.userSelect = "none";

    const clampWidth = (delta: number): number =>
      Math.max(50, Math.min(maxWidth, startWidth + delta));

    const onMouseMove = (ev: MouseEvent): void => {
      const newWidth = clampWidth(ev.clientX - startX);
      const widthStr = `${Math.round(newWidth)}px`;

      headerCell.style.width = widthStr;
      headerCell.style.flex = "";

      if (this.rowContainer) {
        const rows = this.rowContainer.children;
        for (let r = 0; r < rows.length; r++) {
          const cell = rows[r]!.children[colIndex] as HTMLElement | undefined;
          if (cell) {
            cell.style.width = widthStr;
            cell.style.flex = "";
          }
        }
      }
    };

    const onMouseUp = (ev: MouseEvent): void => {
      document.removeEventListener("mousemove", onMouseMove);
      document.removeEventListener("mouseup", onMouseUp);
      document.body.style.userSelect = prevSelect;
      handle?.classList.remove("dt-resizing");

      const newWidth = clampWidth(ev.clientX - startX);
      this.columns[colIndex]!.width = `${Math.round(newWidth)}px`;
      this.persistWidths();
      this.renderVisibleRows();

      // Suppress the click event that fires after mouseup on the header cell
      setTimeout(() => { this.resizing = false; }, 0);
    };

    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
  }

  private handleSort(key: string): void {
    if (this.resizing) return;
    if (this.sortKey === key) {
      this.sortAsc = !this.sortAsc;
    } else {
      this.sortKey = key;
      this.sortAsc = true;
    }
    this.applySort();
    this.renderHeader();
    this.renderVisibleRows();
  }

  private applySort(): void {
    if (!this.sortKey) return;
    const key = this.sortKey;
    const asc = this.sortAsc;
    this.filteredData.sort((a, b) => {
      const va = a[key];
      const vb = b[key];
      if (va == null && vb == null) return 0;
      if (va == null) return asc ? -1 : 1;
      if (vb == null) return asc ? 1 : -1;
      if (typeof va === "number" && typeof vb === "number") {
        return asc ? va - vb : vb - va;
      }
      const sa = String(va);
      const sb = String(vb);
      return asc ? sa.localeCompare(sb) : sb.localeCompare(sa);
    });
  }

  setData(data: Record<string, string | number>[]): void {
    this.allData = data;
    this.applyFilter();
    this.applySort();
    this.updateSpacer();
    this.renderVisibleRows();
  }

  setFilter(filterFn: ((row: Record<string, string | number>) => boolean) | null): void {
    this.filterFn = filterFn;
    this.applyFilter();
    this.applySort();
    this.updateSpacer();
    if (this.scrollContainer) this.scrollContainer.scrollTop = 0;
    this.renderVisibleRows();
  }

  /** Returns current filtered count */
  get filteredCount(): number {
    return this.filteredData.length;
  }

  get totalCount(): number {
    return this.allData.length;
  }

  /** Listen for when the user clicks "Show all" to uncap results */
  onCapChange(cb: () => void): void {
    this.root?.addEventListener("dt-cap-change", () => cb());
  }

  private applyFilter(): void {
    if (this.filterFn) {
      this.filteredData = this.allData.filter(this.filterFn);
      // When a filter is active, always show all matching results (uncap)
      this.isCapped = false;
    } else if (this.initialCap !== null && this.allData.length > this.initialCap) {
      // No filter active and data exceeds cap — apply cap
      this.isCapped = true;
      this.filteredData = this.allData.slice(0, this.initialCap);
    } else {
      this.isCapped = false;
      this.filteredData = this.allData.slice();
    }
    this.updateShowMore();
  }

  private updateShowMore(): void {
    if (!this.root) return;

    if (this.isCapped && this.initialCap !== null) {
      if (!this.showMoreEl) {
        const btn = document.createElement("button");
        btn.className = "dt-show-more";
        btn.addEventListener("click", () => {
          this.isCapped = false;
          this.filteredData = this.filterFn
            ? this.allData.filter(this.filterFn)
            : this.allData.slice();
          this.applySort();
          this.updateSpacer();
          this.renderVisibleRows();
          this.updateShowMore();
          // Notify external count listeners via a custom event
          this.root?.dispatchEvent(new CustomEvent("dt-cap-change"));
        });
        this.showMoreEl = btn;
        // Insert before the scroll container
        if (this.scrollContainer) {
          this.root.insertBefore(btn, this.scrollContainer);
        } else {
          this.root.appendChild(btn);
        }
      }
      this.showMoreEl.textContent = `Showing first ${this.initialCap!.toLocaleString()} rows — click to show all ${this.allData.length.toLocaleString()}`;
      this.showMoreEl.style.display = "";
    } else if (this.showMoreEl) {
      this.showMoreEl.style.display = "none";
    }
  }

  private updateSpacer(): void {
    if (this.spacer) {
      this.spacer.style.height = `${this.filteredData.length * this.rowHeight}px`;
    }
  }

  private onScroll(): void {
    if (this.rafId) return;
    this.rafId = requestAnimationFrame(() => {
      this.rafId = 0;
      this.renderVisibleRows();
    });
  }

  private renderVisibleRows(): void {
    if (!this.scrollContainer || !this.rowContainer) return;

    const scrollTop = this.scrollContainer.scrollTop;
    const viewportHeight = this.scrollContainer.clientHeight;
    const totalRows = this.filteredData.length;

    const startIndex = Math.max(0, Math.floor(scrollTop / this.rowHeight) - DataTable.BUFFER);
    const visibleCount = Math.ceil(viewportHeight / this.rowHeight);
    const endIndex = Math.min(totalRows, startIndex + visibleCount + DataTable.BUFFER * 2);

    // Position the row container
    this.rowContainer.style.transform = `translateY(${startIndex * this.rowHeight}px)`;

    // Build rows
    const fragment = document.createDocumentFragment();
    for (let i = startIndex; i < endIndex; i++) {
      const row = this.filteredData[i];
      if (!row) continue;
      const rowEl = document.createElement("div");
      rowEl.className = "dt-row";
      rowEl.style.height = `${this.rowHeight}px`;

      for (const col of this.columns) {
        const cell = document.createElement("div");
        cell.className = "dt-cell";
        if (col.width) cell.style.width = col.width;
        else cell.style.flex = "1";
        const val = row[col.key];
        cell.textContent = val != null ? String(val) : "";
        cell.title = val != null ? String(val) : "";
        cell.addEventListener("dblclick", (e) => {
          e.stopPropagation();
          const text = cell.textContent ?? "";
          navigator.clipboard.writeText(text).then(() => showToast("Copied to clipboard", "info"));
        });
        rowEl.appendChild(cell);
      }

      if (this.onRowClick) {
        rowEl.style.cursor = "pointer";
        const idx = i;
        rowEl.addEventListener("click", () => {
          this.onRowClick?.(row, idx);
        });
      }

      fragment.appendChild(rowEl);
    }

    this.rowContainer.innerHTML = "";
    this.rowContainer.appendChild(fragment);
  }

  /** Change the column definitions (re-renders header on next mount/setData). */
  setColumns(columns: Column[]): void {
    this.columns = columns;
    this.sortKey = null;
    this.sortAsc = true;
    if (this.headerRow) this.renderHeader();
  }

  /** Remove the table from the DOM without fully destroying internal state. */
  unmount(): void {
    if (this.rafId) cancelAnimationFrame(this.rafId);
    if (this.scrollContainer) {
      this.scrollContainer.removeEventListener("scroll", this.boundOnScroll);
    }
    if (this.root && this.container) {
      this.container.removeChild(this.root);
    }
    this.root = null;
    this.container = null;
    this.scrollContainer = null;
    this.spacer = null;
    this.rowContainer = null;
    this.headerRow = null;
    this.showMoreEl = null;
  }

  destroy(): void {
    if (this.rafId) cancelAnimationFrame(this.rafId);
    if (this.scrollContainer) {
      this.scrollContainer.removeEventListener("scroll", this.boundOnScroll);
    }
    if (this.root && this.container) {
      this.container.removeChild(this.root);
    }
    this.root = null;
    this.container = null;
    this.scrollContainer = null;
    this.spacer = null;
    this.rowContainer = null;
    this.headerRow = null;
  }
}
