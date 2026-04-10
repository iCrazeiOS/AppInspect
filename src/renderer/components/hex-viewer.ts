/**
 * Hex viewer component — displays raw binary data as hex + ASCII dump
 * with virtual scrolling, offset navigation, and hex/text search.
 */

import { el } from "../utils/dom";

export interface HexRegion {
  label: string;
  offset: number;
  size: number;
}

export interface HexViewerOptions {
  sessionId: string;
  /** File offset of the region (segment fileoff or section offset) */
  regionOffset: number;
  /** Size of the region in bytes */
  regionSize: number;
  /** Display label (e.g. segment/section name) */
  label: string;
  /** Named sub-regions to show in the label as the user scrolls (e.g. segments) */
  regions?: HexRegion[];
  /** Called when the viewer is closed */
  onClose?: () => void;
}

const DEFAULT_BYTES_PER_ROW = 16;
const ROW_HEIGHT = 20;
const CHUNK_SIZE = 65536; // 64 KB per IPC fetch
const BUFFER_ROWS = 30;  // extra rows rendered above/below viewport
const MAX_SPACER_PX = 30_000_000; // browsers cap scrollHeight around 33M

// Row width in `ch` units for a given bytesPerRow:
//   offset(9) + hex(N*3) + gaps(floor((N-1)/8)*1.5) + ascii_margin(2) + ascii(N) + padding(~4)
function rowWidthCh(n: number): number {
  const gaps = Math.floor((n - 1) / 8) * 1.5;
  return 9 + n * 3 + gaps + 2 + n + 4;
}

function humanSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function hexOffset(n: number): string {
  return n.toString(16).toUpperCase().padStart(8, "0");
}

function hexByte(b: number): string {
  return b.toString(16).toUpperCase().padStart(2, "0");
}

function isPrintable(b: number): boolean {
  return b >= 0x20 && b <= 0x7e;
}

/** Parse a hex search string like "CF FA ED FE" into byte array, or an error string. */
function parseHexPattern(input: string): number[] | string {
  const cleaned = input.replace(/\s+/g, "");
  if (cleaned.length === 0) return "Enter hex bytes";
  if (!/^[0-9a-fA-F]+$/.test(cleaned)) return "Non-hex character";
  if (cleaned.length % 2 !== 0) return "Must enter full bytes";
  const bytes: number[] = [];
  for (let i = 0; i < cleaned.length; i += 2) {
    bytes.push(parseInt(cleaned.substring(i, i + 2), 16));
  }
  return bytes;
}

/** Convert a text string to byte array (UTF-8) */
function textToBytes(input: string): number[] {
  return Array.from(new TextEncoder().encode(input));
}

export class HexViewer {
  private root: HTMLElement | null = null;
  private scrollContainer: HTMLElement | null = null;
  private spacer: HTMLElement | null = null;
  private rowContainer: HTMLElement | null = null;
  private headerWrap: HTMLElement | null = null;
  private matchInfoEl: HTMLElement | null = null;
  private labelEl: HTMLElement | null = null;
  private opts: HexViewerOptions;

  private bytesPerRow = DEFAULT_BYTES_PER_ROW;
  private totalRows: number;
  private spacerHeight = 0; // actual pixel height of spacer (may be scaled)
  private rafId = 0;
  private boundOnScroll: () => void;
  private boundOnResize: () => void;
  private boundOnWheel: (e: WheelEvent) => void;
  private resizeRaf = 0;

  // Data cache: chunkIndex -> byte array
  private chunks = new Map<number, number[]>();
  private pendingChunks = new Set<number>();

  // Display state
  private offsetMode: "hex" | "dec" = "hex";

  // Search state
  private searchMode: "hex" | "text" = "hex";
  private matches: number[] = [];
  private currentMatchIndex = -1;
  private matchPositions = new Set<number>(); // byte positions within region to highlight
  private patternLength = 0;
  private searchDebounceTimer: ReturnType<typeof setTimeout> | null = null;

  // Track rendered range to avoid unnecessary re-renders
  private renderedStart = -1;
  private renderedEnd = -1;

  constructor(opts: HexViewerOptions) {
    this.opts = opts;
    this.totalRows = Math.ceil(opts.regionSize / DEFAULT_BYTES_PER_ROW);
    this.boundOnScroll = this.onScroll.bind(this);
    this.boundOnResize = this.onResize.bind(this);
    this.boundOnWheel = this.onWheel.bind(this);
  }

  mount(container: HTMLElement): void {
    this.root = el("div", "hv-root");
    this.root.appendChild(this.buildToolbar());
    this.root.appendChild(this.buildSearchBar());

    // Header wrap — rebuilt when bytesPerRow changes
    this.headerWrap = el("div", "hv-header-wrap");
    this.headerWrap.appendChild(this.buildHeader());
    this.root.appendChild(this.headerWrap);

    // Virtual scroll container
    this.scrollContainer = el("div", "hv-content");
    this.spacer = el("div", "hv-spacer");
    this.updateSpacerHeight();
    this.rowContainer = el("div", "hv-rows");
    this.scrollContainer.appendChild(this.spacer);
    this.scrollContainer.appendChild(this.rowContainer);
    this.scrollContainer.addEventListener("scroll", this.boundOnScroll);
    this.scrollContainer.addEventListener("wheel", this.boundOnWheel, { passive: false });
    this.root.appendChild(this.scrollContainer);

    container.innerHTML = "";
    container.appendChild(this.root);

    // Measure available width and pick optimal bytes per row
    this.measureAndResize();
    window.addEventListener("resize", this.boundOnResize);

    // Initial render
    this.renderVisibleRows();
  }

  unmount(): void {
    if (this.searchDebounceTimer) clearTimeout(this.searchDebounceTimer);
    if (this.rafId) cancelAnimationFrame(this.rafId);
    if (this.resizeRaf) cancelAnimationFrame(this.resizeRaf);
    window.removeEventListener("resize", this.boundOnResize);
    this.scrollContainer?.removeEventListener("scroll", this.boundOnScroll);
    this.scrollContainer?.removeEventListener("wheel", this.boundOnWheel);
    if (this.root) {
      this.root.remove();
      this.root = null;
    }
    this.scrollContainer = null;
    this.spacer = null;
    this.rowContainer = null;
    this.headerWrap = null;
    this.matchInfoEl = null;
    this.chunks.clear();
    this.pendingChunks.clear();
  }

  /** Focus the search input and select its text. */
  focusSearch(): void {
    const input = this.root?.querySelector(".hv-search-input") as HTMLInputElement | null;
    if (input) {
      input.focus();
      input.select();
    }
  }

  // ── Scroll scaling ──

  /** Compute and apply the spacer height, capping at MAX_SPACER_PX for large regions. */
  private updateSpacerHeight(): void {
    const natural = this.totalRows * ROW_HEIGHT;
    this.spacerHeight = Math.min(natural, MAX_SPACER_PX);
    if (this.spacer) this.spacer.style.height = `${this.spacerHeight}px`;
  }

  /** Map scrollTop → first visible row, accounting for scaling. */
  private scrollTopToRow(scrollTop: number): number {
    const natural = this.totalRows * ROW_HEIGHT;
    if (natural <= MAX_SPACER_PX) {
      return Math.floor(scrollTop / ROW_HEIGHT);
    }
    // Scaled: scrollTop / spacerHeight gives a 0..1 fraction
    const frac = this.spacerHeight > 0 ? scrollTop / this.spacerHeight : 0;
    return Math.floor(frac * this.totalRows);
  }

  /** Map a row index → pixel position within the spacer. */
  private rowToScrollTop(row: number): number {
    const natural = this.totalRows * ROW_HEIGHT;
    if (natural <= MAX_SPACER_PX) {
      return row * ROW_HEIGHT;
    }
    const frac = this.totalRows > 0 ? row / this.totalRows : 0;
    return Math.floor(frac * this.spacerHeight);
  }

  // ── Dynamic width ──

  private onResize(): void {
    if (this.resizeRaf) cancelAnimationFrame(this.resizeRaf);
    this.resizeRaf = requestAnimationFrame(() => this.measureAndResize());
  }

  /** Measure container width in ch units and pick the best bytesPerRow. */
  private measureAndResize(): void {
    if (!this.scrollContainer) return;

    // Measure 1ch in pixels using a probe element
    const probe = document.createElement("span");
    probe.style.cssText =
      "position:absolute;visibility:hidden;font-family:'SF Mono','Cascadia Code','Consolas',monospace;font-size:12px;";
    probe.textContent = "0";
    this.scrollContainer.appendChild(probe);
    const chPx = probe.offsetWidth || 7.2;
    probe.remove();

    const availableWidth = this.scrollContainer.clientWidth;
    const availableCh = availableWidth / chPx;

    // Pick largest multiple of 8 that fits (16, 24, or 32)
    let best = DEFAULT_BYTES_PER_ROW;
    for (const candidate of [32, 24, 16]) {
      if (rowWidthCh(candidate) <= availableCh) {
        best = candidate;
        break;
      }
    }

    if (best === this.bytesPerRow) return;

    const oldBytesPerRow = this.bytesPerRow;
    this.bytesPerRow = best;
    this.totalRows = Math.ceil(this.opts.regionSize / this.bytesPerRow);

    this.updateSpacerHeight();

    // Rebuild column header
    if (this.headerWrap) {
      this.headerWrap.innerHTML = "";
      this.headerWrap.appendChild(this.buildHeader());
    }

    // Adjust scroll position to keep roughly the same data in view
    if (this.scrollContainer && oldBytesPerRow !== best) {
      const topByte = Math.floor(this.scrollContainer.scrollTop / ROW_HEIGHT) * oldBytesPerRow;
      const newRow = Math.floor(topByte / this.bytesPerRow);
      this.scrollContainer.scrollTop = newRow * ROW_HEIGHT;
    }

    this.forceRerender();
  }

  // ── Toolbar ──

  private buildToolbar(): HTMLElement {
    const toolbar = el("div", "hv-toolbar");

    this.labelEl = el("span", "hv-label");
    this.updateLabel();
    toolbar.appendChild(this.labelEl);
    toolbar.appendChild(el("span", "hv-spacer"));

    // Go-to offset
    const gotoWrap = el("span", "hv-goto");
    gotoWrap.appendChild(el("span", "hv-goto-label", "Go to:"));
    const gotoInput = el("input", "hv-offset-input") as HTMLInputElement;
    gotoInput.type = "text";
    gotoInput.placeholder = "0x560 or 1376...";
    gotoInput.spellcheck = false;
    gotoInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        const raw = gotoInput.value.trim();
        const offset = raw.startsWith("0x") || raw.startsWith("0X")
          ? parseInt(raw, 16)
          : parseInt(raw, 10);
        if (!isNaN(offset)) this.scrollToOffset(offset);
      }
    });
    gotoWrap.appendChild(gotoInput);
    toolbar.appendChild(gotoWrap);

    // Close
    const close = el("button", "hv-close-btn", "\u2715");
    close.title = "Close hex viewer";
    close.addEventListener("click", () => {
      this.unmount();
      this.opts.onClose?.();
    });
    toolbar.appendChild(close);

    return toolbar;
  }

  // ── Column header ──

  private buildHeader(): HTMLElement {
    const header = el("div", "hv-row hv-header-row");
    const modeLabel = this.offsetMode === "hex" ? "(H)" : "(D)";
    const offsetLabel = el("span", "hv-offset hv-offset-toggle", `Offset ${modeLabel}`);
    offsetLabel.title = "Click to toggle hex/decimal offsets";
    offsetLabel.addEventListener("click", () => {
      this.offsetMode = this.offsetMode === "hex" ? "dec" : "hex";
      // Rebuild header and re-render rows
      if (this.headerWrap) {
        this.headerWrap.innerHTML = "";
        this.headerWrap.appendChild(this.buildHeader());
      }
      this.forceRerender();
    });
    header.appendChild(offsetLabel);
    const hexH = el("span", "hv-hex");
    for (let i = 0; i < this.bytesPerRow; i++) {
      if (i > 0 && i % 8 === 0) hexH.appendChild(el("span", "hv-hex-gap", " "));
      hexH.appendChild(el("span", "hv-hex-byte hv-hex-header-byte", hexByte(i)));
    }
    header.appendChild(hexH);
    header.appendChild(el("span", "hv-ascii", "ASCII"));
    return header;
  }

  // ── Search bar ──

  private buildSearchBar(): HTMLElement {
    const bar = el("div", "hv-search");

    const input = el("input", "hv-search-input") as HTMLInputElement;
    input.type = "text";
    input.placeholder = "Search hex bytes (e.g. CF FA ED FE)";
    input.spellcheck = false;
    input.addEventListener("input", () => {
      if (this.searchMode === "hex") {
        const pos = input.selectionStart ?? input.value.length;
        const before = input.value;
        const stripped = before.replace(/[^0-9a-fA-F]/g, "");
        if (stripped !== before) {
          const removed = before.length - stripped.length;
          input.value = stripped;
          input.selectionStart = input.selectionEnd = Math.max(0, pos - removed);
        }
      }
      if (this.searchDebounceTimer) clearTimeout(this.searchDebounceTimer);
      this.searchDebounceTimer = setTimeout(() => this.executeSearch(input.value), 300);
    });
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        if (e.shiftKey) this.goToMatch(this.currentMatchIndex - 1);
        else this.goToMatch(this.currentMatchIndex + 1);
      }
    });
    bar.appendChild(input);

    // Mode toggle
    const modeBtn = el("button", "hv-search-mode", "Hex");
    modeBtn.title = "Toggle hex/text search mode";
    modeBtn.addEventListener("click", () => {
      this.searchMode = this.searchMode === "hex" ? "text" : "hex";
      modeBtn.textContent = this.searchMode === "hex" ? "Hex" : "Text";
      input.placeholder = this.searchMode === "hex"
        ? "Search hex bytes (e.g. CF FA ED FE)"
        : "Search text (e.g. dyld)";
      if (input.value.trim()) this.executeSearch(input.value);
    });
    bar.appendChild(modeBtn);

    // Match nav
    const matchPrev = el("button", "hv-nav-btn hv-match-nav", "\u2039");
    matchPrev.title = "Previous match (Shift+Enter)";
    matchPrev.addEventListener("click", () => this.goToMatch(this.currentMatchIndex - 1));
    bar.appendChild(matchPrev);

    this.matchInfoEl = el("span", "hv-match-count");
    bar.appendChild(this.matchInfoEl);

    const matchNext = el("button", "hv-nav-btn hv-match-nav", "\u203A");
    matchNext.title = "Next match (Enter)";
    matchNext.addEventListener("click", () => this.goToMatch(this.currentMatchIndex + 1));
    bar.appendChild(matchNext);

    return bar;
  }

  // ── Search logic ──

  private async executeSearch(query: string): Promise<void> {
    const trimmed = query.trim();
    if (!trimmed) {
      this.matches = [];
      this.currentMatchIndex = -1;
      this.patternLength = 0;
      this.matchPositions.clear();

      this.updateMatchInfo();
      this.forceRerender();
      return;
    }

    let pattern: number[] | null;
    if (this.searchMode === "hex") {
      const parsed = parseHexPattern(trimmed);
      if (typeof parsed === "string") {
        this.matches = [];
        this.currentMatchIndex = -1;
        this.patternLength = 0;
        this.matchPositions.clear();
        this.updateMatchInfo(parsed);
        return;
      }
      pattern = parsed;
    } else {
      pattern = textToBytes(trimmed);
      if (pattern.length === 0) return;
    }

    this.patternLength = pattern.length;

    const result = await window.api.searchHex(
      this.opts.sessionId,
      this.opts.regionOffset,
      this.opts.regionSize,
      pattern,
    );

    if (!result) {
      this.matches = [];
      this.currentMatchIndex = -1;
      this.matchPositions.clear();
      this.updateMatchInfo();
      return;
    }

    this.matches = result.matches;
    this.currentMatchIndex = this.matches.length > 0 ? 0 : -1;

    // Build position set for highlighting
    this.matchPositions.clear();
    for (const off of this.matches) {
      const rel = off - this.opts.regionOffset;
      for (let i = 0; i < this.patternLength; i++) {
        this.matchPositions.add(rel + i);
      }
    }
    this.updateMatchInfo();
    if (this.currentMatchIndex >= 0) {
      this.goToMatch(0);
    } else {
      this.forceRerender();
    }
  }

  private goToMatch(index: number): void {
    if (this.matches.length === 0) return;
    if (index < 0) index = this.matches.length - 1;
    if (index >= this.matches.length) index = 0;
    this.currentMatchIndex = index;
    this.updateMatchInfo();

    const matchOffset = this.matches[index]!;
    const relOffset = matchOffset - this.opts.regionOffset;
    const targetRow = Math.floor(relOffset / this.bytesPerRow);
    this.scrollToRow(targetRow);
    // Force re-render so highlights appear even if scroll position didn't change
    this.forceRerender();
  }

  // ── Virtual scrolling ──

  private isScaled(): boolean {
    return this.totalRows * ROW_HEIGHT > MAX_SPACER_PX;
  }

  private onWheel(e: WheelEvent): void {
    if (!this.isScaled() || !this.scrollContainer) return;
    // When scaled, override native scroll to move rows proportional to delta
    e.preventDefault();
    const delta = e.deltaMode === WheelEvent.DOM_DELTA_LINE ? e.deltaY * ROW_HEIGHT : e.deltaY;
    const rows = Math.sign(delta) * Math.max(1, Math.round(Math.abs(delta) / ROW_HEIGHT));
    const currentRow = this.scrollTopToRow(this.scrollContainer.scrollTop);
    const targetRow = Math.max(0, Math.min(this.totalRows - 1, currentRow + rows));
    this.scrollContainer.scrollTop = this.rowToScrollTop(targetRow);
  }

  private onScroll(): void {
    if (this.rafId) cancelAnimationFrame(this.rafId);
    this.rafId = requestAnimationFrame(() => this.renderVisibleRows());
  }

  private renderVisibleRows(): void {
    const sc = this.scrollContainer;
    const rc = this.rowContainer;
    if (!sc || !rc) return;

    const scrollTop = sc.scrollTop;
    const viewHeight = sc.clientHeight;

    const firstVisible = this.scrollTopToRow(scrollTop);
    const visibleCount = Math.ceil(viewHeight / ROW_HEIGHT);

    const start = Math.max(0, firstVisible - BUFFER_ROWS);
    const end = Math.min(this.totalRows, firstVisible + visibleCount + BUFFER_ROWS);

    this.updateLabel();

    // Skip re-render if the visible window hasn't changed
    if (start === this.renderedStart && end === this.renderedEnd) return;
    this.renderedStart = start;
    this.renderedEnd = end;

    // Ensure data for visible rows is loaded
    this.ensureChunksLoaded(start, end);

    // Position row container at the pixel offset for the start row
    rc.style.top = `${this.rowToScrollTop(start)}px`;
    rc.innerHTML = "";

    for (let row = start; row < end; row++) {
      const byteOffset = row * this.bytesPerRow;
      const remaining = this.opts.regionSize - byteOffset;
      if (remaining <= 0) break;
      const rowLen = Math.min(this.bytesPerRow, remaining);
      const bytes = this.getBytesAt(byteOffset, rowLen);
      const fileOffset = this.opts.regionOffset + byteOffset;
      rc.appendChild(this.buildRow(fileOffset, bytes, byteOffset));
    }
  }

  private buildRow(
    fileOffset: number,
    bytes: (number | undefined)[],
    regionByteOffset: number,
  ): HTMLElement {
    const row = el("div", "hv-row");
    row.style.height = `${ROW_HEIGHT}px`;

    // Offset column
    const offsetText = this.offsetMode === "hex"
      ? "0x" + hexOffset(fileOffset)
      : String(fileOffset).padStart(10, "0");
    row.appendChild(el("span", "hv-offset", offsetText));

    // Hex column
    const hexCol = el("span", "hv-hex");
    for (let i = 0; i < this.bytesPerRow; i++) {
      if (i > 0 && i % 8 === 0) hexCol.appendChild(el("span", "hv-hex-gap", " "));
      if (i < bytes.length) {
        const b = bytes[i];
        if (b === undefined) {
          hexCol.appendChild(el("span", "hv-hex-byte hv-byte--loading", ".."));
        } else {
          const isMatch = this.matchPositions.has(regionByteOffset + i);
          const isNull = b === 0;
          let cls = "hv-hex-byte";
          if (isMatch) cls += " hv-byte--match";
          else if (isNull) cls += " hv-byte--null";
          hexCol.appendChild(el("span", cls, hexByte(b)));
        }
      } else {
        hexCol.appendChild(el("span", "hv-hex-byte", "  "));
      }
    }
    row.appendChild(hexCol);

    // ASCII column
    const asciiCol = el("span", "hv-ascii");
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (b === undefined) {
        asciiCol.appendChild(el("span", "hv-ascii-char hv-ascii--nonprint", "."));
      } else {
        const ch = isPrintable(b) ? String.fromCharCode(b) : ".";
        const isMatch = this.matchPositions.has(regionByteOffset + i);
        let cls = "hv-ascii-char";
        if (isMatch) cls += " hv-byte--match";
        else if (!isPrintable(b)) cls += " hv-ascii--nonprint";
        asciiCol.appendChild(el("span", cls, ch));
      }
    }
    row.appendChild(asciiCol);

    return row;
  }

  // ── Data loading ──

  private getBytesAt(regionOffset: number, length: number): (number | undefined)[] {
    const result: (number | undefined)[] = [];
    for (let i = 0; i < length; i++) {
      const absOffset = regionOffset + i;
      const chunkIdx = Math.floor(absOffset / CHUNK_SIZE);
      const chunk = this.chunks.get(chunkIdx);
      if (chunk) {
        const inChunk = absOffset - chunkIdx * CHUNK_SIZE;
        result.push(chunk[inChunk]);
      } else {
        result.push(undefined);
      }
    }
    return result;
  }

  private ensureChunksLoaded(startRow: number, endRow: number): void {
    const startByte = startRow * this.bytesPerRow;
    const endByte = Math.min(endRow * this.bytesPerRow, this.opts.regionSize);
    const firstChunk = Math.floor(startByte / CHUNK_SIZE);
    const lastChunk = Math.floor(Math.max(0, endByte - 1) / CHUNK_SIZE);

    for (let ci = firstChunk; ci <= lastChunk; ci++) {
      if (!this.chunks.has(ci) && !this.pendingChunks.has(ci)) {
        this.loadChunk(ci);
      }
    }
  }

  private async loadChunk(chunkIndex: number): Promise<void> {
    this.pendingChunks.add(chunkIndex);

    const offset = this.opts.regionOffset + chunkIndex * CHUNK_SIZE;
    const length = Math.min(CHUNK_SIZE, this.opts.regionSize - chunkIndex * CHUNK_SIZE);
    if (length <= 0) {
      this.pendingChunks.delete(chunkIndex);
      return;
    }

    const result = await window.api.readHex(this.opts.sessionId, offset, length);
    this.pendingChunks.delete(chunkIndex);

    if (result && result.data.length > 0) {
      this.chunks.set(chunkIndex, result.data);

      // Re-render so the loaded data appears
      this.forceRerender();
    }
  }

  // ── Navigation ──

  private scrollToOffset(offset: number): void {
    const clamped = Math.max(0, Math.min(offset, this.opts.regionSize - 1));
    const row = Math.floor(clamped / this.bytesPerRow);
    this.scrollToRow(row);
  }

  private scrollToRow(row: number): void {
    if (!this.scrollContainer) return;
    const viewHeight = this.scrollContainer.clientHeight;
    const visibleRows = Math.ceil(viewHeight / ROW_HEIGHT);
    // Center in row-space, then convert to scroll position
    const topRow = Math.max(0, row - Math.floor(visibleRows / 2));
    this.scrollContainer.scrollTop = this.rowToScrollTop(topRow);
  }

  private forceRerender(): void {
    this.renderedStart = -1;
    this.renderedEnd = -1;
    this.renderVisibleRows();
  }

  // ── Helpers ──

  private updateLabel(): void {
    if (!this.labelEl) return;
    const base = `${this.opts.label} (${humanSize(this.opts.regionSize)})`;
    const regions = this.opts.regions;
    const sc = this.scrollContainer;
    if (!regions || regions.length === 0 || !sc || sc.clientHeight === 0) {
      this.labelEl.textContent = base;
      return;
    }
    // Find which region the top visible row falls in
    const firstRow = this.scrollTopToRow(sc.scrollTop);
    const visibleFileOffset = this.opts.regionOffset + firstRow * this.bytesPerRow;
    let current: HexRegion | undefined;
    for (const r of regions) {
      if (visibleFileOffset >= r.offset && visibleFileOffset < r.offset + r.size) {
        current = r;
        break;
      }
    }
    this.labelEl.textContent = current
      ? `${base}  |  ${current.label}`
      : base;
  }

  private updateMatchInfo(error?: string): void {
    if (!this.matchInfoEl) return;
    if (error) {
      this.matchInfoEl.textContent = error;
      this.matchInfoEl.classList.add("hv-match-count--error");
    } else {
      this.matchInfoEl.classList.remove("hv-match-count--error");
      if (this.matches.length === 0) {
        const input = this.root?.querySelector(".hv-search-input") as HTMLInputElement | null;
        this.matchInfoEl.textContent = input?.value.trim() ? "No results" : "";
      } else {
        this.matchInfoEl.textContent = `${this.currentMatchIndex + 1} / ${this.matches.length}`;
      }
    }
  }
}
