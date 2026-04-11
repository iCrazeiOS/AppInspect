/**
 * Disassembly Viewer — virtual scrolling disassembly display
 *
 * Displays disassembled instructions with:
 * - Virtual scrolling for large code sections
 * - Symbol labels at function boundaries
 * - Mnemonic type coloring
 * - Address click-to-copy
 * - Index-based row-to-byte mapping for accurate scrolling
 */

import type { DisasmInstruction, DisasmSection } from "../../shared/types";
import { el } from "../utils/dom";

export interface DisasmViewerOptions {
	sessionId: string;
	section: DisasmSection;
	sectionIndex: number;
	onAddressClick?: (address: bigint, offset: number) => void;
	onBranchClick?: (targetAddress: bigint) => void;
}

const ROW_HEIGHT = 28;
const CHUNK_SIZE = 65536; // 64KB per fetch
const BUFFER_ROWS = 30;
const MAX_SPACER_PX = 30_000_000; // browsers cap scrollHeight around 33M

interface RowIndexEntry {
	byteOffset: number;
	cumulativeRow: number;
}

export class DisasmViewer {
	private root: HTMLElement | null = null;
	private content: HTMLElement | null = null;
	private spacer: HTMLElement | null = null;
	private rowContainer: HTMLElement | null = null;
	private statsEl: HTMLElement | null = null;

	private opts: DisasmViewerOptions;
	private totalRows: number;
	private spacerHeight: number;

	// Row index: maps visual rows to byte offsets via function boundaries
	private rowIndex: RowIndexEntry[] = [];

	// Cache: byteOffset -> instructions
	private chunks = new Map<number, DisasmInstruction[]>();
	private pendingChunks = new Set<number>();
	private loadedBytes = 0;

	private rafId = 0;
	private boundOnScroll: () => void;

	// Track rendered range
	private renderedStart = -1;
	private renderedEnd = -1;

	constructor(opts: DisasmViewerOptions) {
		this.opts = opts;
		// Initial estimate; replaced by exact count when row index arrives
		this.totalRows = Math.ceil(opts.section.size / 4);
		this.spacerHeight = this.calcSpacerHeight();
		this.boundOnScroll = this.onScroll.bind(this);

		// Fetch row index in the background (provides exact total + byte mapping)
		window.api
			.getDisasmRowIndex(opts.sessionId, opts.sectionIndex)
			.then((index) => {
				if (index && index.totalVisualRows > 0) {
					this.rowIndex = index.entries;
					this.totalRows = index.totalVisualRows;
					this.spacerHeight = this.calcSpacerHeight();
					if (this.spacer) {
						this.spacer.style.height = `${this.spacerHeight}px`;
					}
					// Re-render with correct mapping
					this.renderedStart = -1;
					this.renderedEnd = -1;
					this.renderVisibleRows();
				}
			})
			.catch(() => {});
	}

	/** Calculate spacer height, capping at MAX_SPACER_PX for large sections. */
	private calcSpacerHeight(): number {
		const natural = this.totalRows * ROW_HEIGHT;
		return Math.min(natural, MAX_SPACER_PX);
	}

	/** Map scrollTop → row index, accounting for scaling. */
	private scrollTopToRow(scrollTop: number): number {
		const natural = this.totalRows * ROW_HEIGHT;
		if (natural <= MAX_SPACER_PX) {
			return Math.floor(scrollTop / ROW_HEIGHT);
		}
		const frac = this.spacerHeight > 0 ? scrollTop / this.spacerHeight : 0;
		return Math.floor(frac * this.totalRows);
	}

	/** Map row index → pixel position within the spacer. */
	private rowToScrollTop(row: number): number {
		const natural = this.totalRows * ROW_HEIGHT;
		if (natural <= MAX_SPACER_PX) {
			return row * ROW_HEIGHT;
		}
		const frac = this.totalRows > 0 ? row / this.totalRows : 0;
		return Math.floor(frac * this.spacerHeight);
	}

	/**
	 * Map a visual row number to a section-relative byte offset using the index.
	 * Binary searches the index entries to find which function contains this row.
	 */
	private rowToByteOffset(row: number): number {
		if (this.rowIndex.length === 0) {
			// Fallback before index arrives: proportional
			return Math.floor((row / Math.max(1, this.totalRows)) * this.opts.section.size);
		}
		// Binary search: find the last entry where cumulativeRow <= row
		const entries = this.rowIndex;
		let lo = 0;
		let hi = entries.length - 1;
		while (lo < hi) {
			const mid = (lo + hi + 1) >> 1;
			if (entries[mid]!.cumulativeRow <= row) {
				lo = mid;
			} else {
				hi = mid - 1;
			}
		}
		return entries[lo]!.byteOffset;
	}

	/**
	 * Map a section-relative byte offset to a visual row using the index.
	 * Used by goToAddress for precise positioning.
	 */
	private byteOffsetToRow(byteOffset: number): number {
		if (this.rowIndex.length === 0) {
			return Math.floor((byteOffset / Math.max(1, this.opts.section.size)) * this.totalRows);
		}
		const entries = this.rowIndex;
		let lo = 0;
		let hi = entries.length - 1;
		while (lo < hi) {
			const mid = (lo + hi + 1) >> 1;
			if (entries[mid]!.byteOffset <= byteOffset) {
				lo = mid;
			} else {
				hi = mid - 1;
			}
		}
		return entries[lo]!.cumulativeRow;
	}

	mount(container: HTMLElement): void {
		this.root = el("div", "da-root");

		// Header row
		const header = el("div", "da-header");
		header.innerHTML = `
			<span class="da-col-address">Address</span>
			<span class="da-col-bytes">Bytes</span>
			<span class="da-col-mnemonic">Mnemonic</span>
			<span class="da-col-operands">Operands</span>
		`;
		this.root.appendChild(header);

		// Content with virtual scroll
		this.content = el("div", "da-content");
		this.spacer = el("div", "da-spacer");
		this.spacer.style.height = `${this.spacerHeight}px`;
		this.rowContainer = el("div", "da-rows");

		this.content.appendChild(this.spacer);
		this.content.appendChild(this.rowContainer);
		this.root.appendChild(this.content);

		// Stats bar
		this.statsEl = el("div", "da-stats");
		this.updateStats();
		this.root.appendChild(this.statsEl);

		container.appendChild(this.root);

		this.content.addEventListener("scroll", this.boundOnScroll, { passive: true });

		// Initial render
		this.renderVisibleRows();
	}

	unmount(): void {
		if (this.rafId) cancelAnimationFrame(this.rafId);
		if (this.content) {
			this.content.removeEventListener("scroll", this.boundOnScroll);
		}
		if (this.root?.parentElement) {
			this.root.parentElement.removeChild(this.root);
		}
		this.root = null;
		this.content = null;
		this.chunks.clear();
		this.pendingChunks.clear();
	}

	private onScroll(): void {
		if (this.rafId) return;
		this.rafId = requestAnimationFrame(() => {
			this.rafId = 0;
			this.renderVisibleRows();
		});
	}

	private async renderVisibleRows(): Promise<void> {
		if (!this.content || !this.rowContainer || !this.spacer) return;

		const scrollTop = this.content.scrollTop;
		const viewportHeight = this.content.clientHeight;

		// Calculate visible row range
		const visibleRows = Math.ceil(viewportHeight / ROW_HEIGHT);
		const firstVisibleRow = this.scrollTopToRow(scrollTop);
		const startRow = Math.max(0, firstVisibleRow - BUFFER_ROWS);
		const endRow = Math.min(this.totalRows, firstVisibleRow + visibleRows + BUFFER_ROWS);

		// Skip if range hasn't changed
		if (startRow === this.renderedStart && endRow === this.renderedEnd) {
			return;
		}
		this.renderedStart = startRow;
		this.renderedEnd = endRow;

		// Use the row index to map visual rows to byte offsets
		const startByte = this.rowToByteOffset(startRow);
		const endByte = Math.min(
			this.opts.section.size,
			this.rowToByteOffset(Math.min(endRow + BUFFER_ROWS, this.totalRows)) + CHUNK_SIZE
		);

		// Load chunks that cover this byte range
		const chunkStart = Math.floor(startByte / CHUNK_SIZE) * CHUNK_SIZE;
		const chunkEnd = Math.ceil(endByte / CHUNK_SIZE) * CHUNK_SIZE;

		const loadPromises: Promise<void>[] = [];
		for (
			let offset = chunkStart;
			offset < chunkEnd && offset < this.opts.section.size;
			offset += CHUNK_SIZE
		) {
			if (!this.chunks.has(offset) && !this.pendingChunks.has(offset)) {
				loadPromises.push(this.loadChunk(offset));
			}
		}

		if (loadPromises.length > 0) {
			await Promise.all(loadPromises);
		}

		// Collect ALL instructions from loaded chunks, sorted by offset
		const allInsns: DisasmInstruction[] = [];
		const sortedOffsets = Array.from(this.chunks.keys()).sort((a, b) => a - b);
		for (const offset of sortedOffsets) {
			const chunk = this.chunks.get(offset);
			if (!chunk) continue;
			for (const insn of chunk) {
				allInsns.push(insn);
			}
		}

		// Build visual rows from instructions, count rows to find the window
		// Each instruction is 1 row; instructions with labels add 1 extra row
		let visualRow = 0;
		let renderStartIdx = -1;
		let renderEndIdx = allInsns.length;

		// Find the first loaded instruction's visual row from the index
		if (allInsns.length > 0) {
			const firstInsnByteOffset = allInsns[0]!.offset - this.opts.section.fileOffset;
			visualRow = this.byteOffsetToRow(firstInsnByteOffset);
		}

		const rowsToRender: Array<{ insn: DisasmInstruction; visualRow: number }> = [];
		let currentVisualRow = visualRow;

		for (let idx = 0; idx < allInsns.length; idx++) {
			const insn = allInsns[idx]!;
			const insnStartRow = currentVisualRow;

			if (insn.label) currentVisualRow++; // label row
			currentVisualRow++; // instruction row

			// Check if this instruction's rows overlap with our visible window
			if (currentVisualRow > startRow && insnStartRow < endRow) {
				if (renderStartIdx === -1) renderStartIdx = idx;
				renderEndIdx = idx + 1;
				rowsToRender.push({ insn, visualRow: insnStartRow });
			}

			// Stop if we're past the visible range
			if (insnStartRow >= endRow) break;
		}

		// Render rows
		this.rowContainer.innerHTML = "";

		// Position container: align first visible row with scroll position
		const currentY = scrollTop - (firstVisibleRow - startRow) * ROW_HEIGHT;
		this.rowContainer.style.transform = `translateY(${currentY}px)`;

		for (const { insn } of rowsToRender) {
			if (insn.label) {
				const labelRow = el("div", "da-label-row");
				labelRow.textContent = `${insn.label}:`;
				this.rowContainer.appendChild(labelRow);
			}

			const row = this.createInstructionRow(insn);
			this.rowContainer.appendChild(row);
		}

		this.updateStats();
	}

	private createInstructionRow(insn: DisasmInstruction): HTMLElement {
		const row = el("div", "da-row");

		// Address
		const addrStr = insn.address.toString(16).toUpperCase().padStart(12, "0");
		const addrEl = el("span", "da-col-address", addrStr);
		addrEl.addEventListener("click", () => {
			navigator.clipboard.writeText(`0x${addrStr}`);
			if (this.opts.onAddressClick) {
				this.opts.onAddressClick(insn.address, insn.offset);
			}
		});
		row.appendChild(addrEl);

		// Bytes (show first 8 bytes max)
		const bytesStr = insn.bytes
			.slice(0, 8)
			.map((b) => b.toString(16).toUpperCase().padStart(2, "0"))
			.join(" ");
		const bytesEl = el("span", "da-col-bytes", bytesStr);
		row.appendChild(bytesEl);

		// Mnemonic with type coloring
		const mnemonicEl = el("span", "da-col-mnemonic", insn.mnemonic);
		mnemonicEl.classList.add(`da-mnemonic--${this.classifyMnemonic(insn.mnemonic)}`);
		row.appendChild(mnemonicEl);

		// Operands — make branch targets clickable
		const operandsEl = el("span", "da-col-operands");
		const branchTarget = this.parseBranchTarget(insn);
		if (branchTarget !== null && this.opts.onBranchClick) {
			const targetAddr = branchTarget;
			const targetHex = `0x${targetAddr.toString(16)}`;
			const labelMatch = insn.operands.match(/(#?0x[0-9a-fA-F]+)/);
			if (labelMatch) {
				const before = insn.operands.slice(0, labelMatch.index);
				const after = insn.operands.slice(labelMatch.index! + labelMatch[0].length);
				if (before) operandsEl.appendChild(document.createTextNode(before));
				const link = el("span", "da-branch-target", labelMatch[0]);
				link.title = `Jump to ${targetHex}`;
				link.addEventListener("click", () => {
					this.opts.onBranchClick!(targetAddr);
				});
				operandsEl.appendChild(link);
				if (after) operandsEl.appendChild(document.createTextNode(after));
			} else {
				operandsEl.textContent = insn.operands;
			}
		} else {
			operandsEl.textContent = insn.operands;
		}
		row.appendChild(operandsEl);

		return row;
	}

	private classifyMnemonic(mnemonic: string): string {
		const m = mnemonic.toLowerCase();

		if (m === "ret" || m === "retaa" || m === "retab" || m === "eret") {
			return "ret";
		}
		if (
			m === "bl" ||
			m === "blr" ||
			m === "blx" ||
			m === "call" ||
			m === "blraa" ||
			m === "blrab"
		) {
			return "call";
		}
		if (
			m.startsWith("b.") ||
			m === "b" ||
			m === "br" ||
			m === "bx" ||
			m === "jmp" ||
			m.startsWith("j") ||
			m === "cbz" ||
			m === "cbnz" ||
			m === "tbz" ||
			m === "tbnz"
		) {
			return "branch";
		}
		if (
			m.startsWith("ld") ||
			m.startsWith("ldr") ||
			m === "mov" ||
			m === "movz" ||
			m === "movk" ||
			m === "movn" ||
			m === "adrp" ||
			m === "adr" ||
			m === "lea"
		) {
			return "load";
		}
		if (m.startsWith("st") || m.startsWith("str") || m === "push") {
			return "store";
		}

		return "other";
	}

	/** Extract branch target address from a branch/call instruction. */
	private parseBranchTarget(insn: DisasmInstruction): bigint | null {
		const m = insn.mnemonic.toLowerCase();
		const isBranch =
			m === "b" ||
			m === "bl" ||
			m === "blr" ||
			m === "blx" ||
			m === "bx" ||
			m === "br" ||
			m === "cbz" ||
			m === "cbnz" ||
			m === "tbz" ||
			m === "tbnz" ||
			m.startsWith("b.") ||
			m === "jmp" ||
			m === "call" ||
			m.startsWith("j");

		if (!isBranch) return null;

		const match = insn.operands.match(/#?0x([0-9a-fA-F]+)/);
		if (!match?.[1]) return null;

		try {
			return BigInt(`0x${match[1]}`);
		} catch {
			return null;
		}
	}

	private async loadChunk(byteOffset: number): Promise<void> {
		if (this.pendingChunks.has(byteOffset)) return;
		this.pendingChunks.add(byteOffset);

		try {
			const result = await window.api.readDisasm(
				this.opts.sessionId,
				this.opts.sectionIndex,
				byteOffset,
				CHUNK_SIZE
			);

			if (result && result.instructions.length > 0) {
				this.chunks.set(byteOffset, result.instructions);
				this.loadedBytes += result.bytesConsumed;
			}
		} finally {
			this.pendingChunks.delete(byteOffset);
		}
	}

	private updateStats(): void {
		if (!this.statsEl) return;

		const section = this.opts.section;
		const sizeKB = (section.size / 1024).toFixed(1);
		const loadedKB = (this.loadedBytes / 1024).toFixed(1);
		const addrStart = section.virtualAddr.toString(16).toUpperCase();

		this.statsEl.innerHTML = `
			<span class="da-stats-item">
				Section: <span class="da-stats-value">${section.segname},${section.sectname}</span>
			</span>
			<span class="da-stats-item">
				Size: <span class="da-stats-value">${sizeKB} KB</span>
			</span>
			<span class="da-stats-item">
				Loaded: <span class="da-stats-value">${loadedKB} KB</span>
			</span>
			<span class="da-stats-item">
				Base: <span class="da-stats-value">0x${addrStart}</span>
			</span>
			<span class="da-stats-item">
				Arch: <span class="da-stats-value">${section.arch.toUpperCase()}</span>
			</span>
		`;
	}

	/** Scroll to a specific address with precision. */
	async goToAddress(address: bigint): Promise<void> {
		if (!this.content) return;

		const section = this.opts.section;
		const sectionStart = BigInt(section.virtualAddr as unknown as number | bigint);
		const sectionEnd = sectionStart + BigInt(section.size);

		if (address < sectionStart || address >= sectionEnd) {
			return;
		}

		const relativeOffset = Number(address - sectionStart);

		// Ensure the chunk containing this address is loaded
		const chunkOffset = Math.floor(relativeOffset / CHUNK_SIZE) * CHUNK_SIZE;
		if (!this.chunks.has(chunkOffset) && !this.pendingChunks.has(chunkOffset)) {
			await this.loadChunk(chunkOffset);
		}

		// Use the index for precise row positioning
		const targetRow = this.byteOffsetToRow(relativeOffset);
		this.content.scrollTop = this.rowToScrollTop(targetRow);

		// Force render
		this.renderedStart = -1;
		this.renderedEnd = -1;
		await this.renderVisibleRows();

		// Fine-tune: find the exact instruction in the DOM and snap to it.
		// Run twice: adjust then stabilize after re-render.
		for (let pass = 0; pass < 2; pass++) {
			if (!this.rowContainer || !this.content) break;
			const rows = this.rowContainer.children;
			let found = false;
			for (let i = 0; i < rows.length; i++) {
				const row = rows[i] as HTMLElement;
				const addrEl = row.querySelector(".da-col-address");
				if (!addrEl?.textContent) continue;
				try {
					const rowAddr = BigInt(`0x${addrEl.textContent}`);
					if (rowAddr >= address) {
						const snapTarget =
							i > 0 && rows[i - 1]?.classList.contains("da-label-row")
								? (rows[i - 1] as HTMLElement)
								: row;
						const delta =
							snapTarget.getBoundingClientRect().top -
							this.content.getBoundingClientRect().top;
						if (Math.abs(delta) > 1) {
							this.content.scrollTop += delta;
							this.renderedStart = -1;
							this.renderedEnd = -1;
							await this.renderVisibleRows();
						}
						found = true;
						break;
					}
				} catch {
					// skip
				}
			}
			if (!found) break;
		}
	}

	/** Get the address of the first visible instruction (for navigation history). */
	getCurrentAddress(): bigint | null {
		if (!this.rowContainer) return null;
		const rows = this.rowContainer.children;
		for (let i = 0; i < rows.length; i++) {
			const addrEl = (rows[i] as HTMLElement).querySelector(".da-col-address");
			if (!addrEl?.textContent) continue;
			try {
				return BigInt(`0x${addrEl.textContent}`);
			} catch {
				// skip
			}
		}
		return null;
	}

	/** Focus the scroll container for keyboard navigation */
	focus(): void {
		this.content?.focus();
	}
}
