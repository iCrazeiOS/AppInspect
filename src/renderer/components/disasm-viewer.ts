/**
 * Disassembly Viewer — virtual scrolling disassembly display
 *
 * Displays disassembled instructions with:
 * - Virtual scrolling for large code sections
 * - Symbol labels at function boundaries
 * - Mnemonic type coloring
 * - Address click-to-copy
 */

import type { DisasmInstruction, DisasmSection } from "../../shared/types";
import { el } from "../utils/dom";

export interface DisasmViewerOptions {
	sessionId: string;
	section: DisasmSection;
	sectionIndex: number;
	onAddressClick?: (address: bigint, offset: number) => void;
}

const ROW_HEIGHT = 28;
const CHUNK_SIZE = 65536; // 64KB per fetch
const BUFFER_ROWS = 30;
const MAX_SPACER_PX = 30_000_000; // browsers cap scrollHeight around 33M

// Estimate instructions per chunk based on architecture
function getAvgInsnSize(arch: string): number {
	if (arch === "arm64") return 4; // Fixed 4-byte instructions
	if (arch === "arm") return 3; // Thumb mode: 2-4 byte mix
	return 5; // x86/x86_64: variable, ~5 average
}

export class DisasmViewer {
	private root: HTMLElement | null = null;
	private content: HTMLElement | null = null;
	private spacer: HTMLElement | null = null;
	private rowContainer: HTMLElement | null = null;
	private statsEl: HTMLElement | null = null;

	private opts: DisasmViewerOptions;
	private totalEstimatedRows: number;
	private spacerHeight: number;

	// Cache: byteOffset -> instructions
	private chunks = new Map<number, DisasmInstruction[]>();
	private pendingChunks = new Set<number>();

	// Track actual instruction density for better estimates
	private loadedBytes = 0;
	private loadedInsns = 0;

	private rafId = 0;
	private boundOnScroll: () => void;

	// Track rendered range
	private renderedStart = -1;
	private renderedEnd = -1;

	constructor(opts: DisasmViewerOptions) {
		this.opts = opts;
		// Start with an estimate; replaced by exact count once loaded
		const avgSize = getAvgInsnSize(opts.section.arch);
		this.totalEstimatedRows = Math.ceil(opts.section.size / avgSize);
		this.spacerHeight = this.calcSpacerHeight();
		this.boundOnScroll = this.onScroll.bind(this);

		// Fetch exact instruction count in the background
		window.api
			.getDisasmInsnCount(opts.sessionId, opts.sectionIndex)
			.then((count) => {
				if (count > 0 && count !== this.totalEstimatedRows) {
					this.totalEstimatedRows = count;
					this.spacerHeight = this.calcSpacerHeight();
					if (this.spacer) {
						this.spacer.style.height = `${this.spacerHeight}px`;
					}
				}
			})
			.catch(() => {});
	}

	/** Calculate spacer height, capping at MAX_SPACER_PX for large sections. */
	private calcSpacerHeight(): number {
		const natural = this.totalEstimatedRows * ROW_HEIGHT;
		return Math.min(natural, MAX_SPACER_PX);
	}

	/** Map scrollTop → row index, accounting for scaling. */
	private scrollTopToRow(scrollTop: number): number {
		const natural = this.totalEstimatedRows * ROW_HEIGHT;
		if (natural <= MAX_SPACER_PX) {
			return Math.floor(scrollTop / ROW_HEIGHT);
		}
		// Scaled: scrollTop / spacerHeight gives a 0..1 fraction
		const frac = this.spacerHeight > 0 ? scrollTop / this.spacerHeight : 0;
		return Math.floor(frac * this.totalEstimatedRows);
	}

	/** Map row index → pixel position within the spacer. */
	private rowToScrollTop(row: number): number {
		const natural = this.totalEstimatedRows * ROW_HEIGHT;
		if (natural <= MAX_SPACER_PX) {
			return row * ROW_HEIGHT;
		}
		const frac = this.totalEstimatedRows > 0 ? row / this.totalEstimatedRows : 0;
		return Math.floor(frac * this.spacerHeight);
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

		// Calculate visible row range using scaled coordinates
		const visibleRows = Math.ceil(viewportHeight / ROW_HEIGHT);
		const firstVisibleRow = this.scrollTopToRow(scrollTop);
		const startRow = Math.max(0, firstVisibleRow - BUFFER_ROWS);
		const endRow = Math.min(
			this.totalEstimatedRows,
			firstVisibleRow + visibleRows + BUFFER_ROWS
		);

		// Skip if range hasn't changed significantly
		if (startRow === this.renderedStart && endRow === this.renderedEnd) {
			return;
		}
		this.renderedStart = startRow;
		this.renderedEnd = endRow;

		// Calculate byte offset range we need
		// Map row range to byte range proportionally through the section
		const sectionSize = this.opts.section.size;
		const totalRows = this.totalEstimatedRows;
		const startByte = totalRows > 0 ? Math.floor((startRow / totalRows) * sectionSize) : 0;
		const endByte = totalRows > 0 ? Math.ceil((endRow / totalRows) * sectionSize) : sectionSize;

		// Load chunks that cover this range
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

		// Collect instructions in range
		const instructions: DisasmInstruction[] = [];
		const sortedOffsets = Array.from(this.chunks.keys()).sort((a, b) => a - b);

		for (const offset of sortedOffsets) {
			const chunk = this.chunks.get(offset);
			if (!chunk) continue;
			for (const insn of chunk) {
				const relOffset = insn.offset - this.opts.section.fileOffset;
				if (relOffset >= startByte && relOffset < endByte) {
					instructions.push(insn);
				}
			}
		}

		// Render rows
		this.rowContainer.innerHTML = "";

		// Position so firstVisibleRow aligns with scrollTop regardless of scaling
		// (Same approach as HexViewer)
		const currentY = scrollTop - (firstVisibleRow - startRow) * ROW_HEIGHT;
		this.rowContainer.style.transform = `translateY(${currentY}px)`;

		for (const insn of instructions) {
			// Label row if this instruction has a symbol
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

		// Operands
		const operandsEl = el("span", "da-col-operands", insn.operands);
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
				this.loadedInsns += result.instructions.length;
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
		// virtualAddr may come as number from IPC serialization
		const sectionStart = BigInt(section.virtualAddr as unknown as number | bigint);
		const sectionEnd = sectionStart + BigInt(section.size);

		if (address < sectionStart || address >= sectionEnd) {
			return; // Address out of range
		}

		const relativeOffset = Number(address - sectionStart);

		// Ensure the chunk containing this address is loaded
		const chunkOffset = Math.floor(relativeOffset / CHUNK_SIZE) * CHUNK_SIZE;
		if (!this.chunks.has(chunkOffset) && !this.pendingChunks.has(chunkOffset)) {
			await this.loadChunk(chunkOffset);
		}

		// Approximate scroll to get in the right neighbourhood
		const fraction = section.size > 0 ? relativeOffset / section.size : 0;
		const estimatedRow = Math.floor(fraction * this.totalEstimatedRows);
		this.content.scrollTop = this.rowToScrollTop(estimatedRow);

		// Force render at this position
		this.renderedStart = -1;
		this.renderedEnd = -1;
		await this.renderVisibleRows();

		// Fine-tune: find the target instruction in the rendered DOM and snap to it.
		// If the instruction has a label row above it, snap to the label instead.
		if (this.rowContainer && this.content) {
			const rows = this.rowContainer.children;
			for (let i = 0; i < rows.length; i++) {
				const row = rows[i] as HTMLElement;
				const addrEl = row.querySelector(".da-col-address");
				if (!addrEl?.textContent) continue; // skip label rows
				try {
					const rowAddr = BigInt(`0x${addrEl.textContent}`);
					if (rowAddr >= address) {
						// If the previous row is a label for this function, snap to it
						const snapTarget =
							i > 0 && rows[i - 1]?.classList.contains("da-label-row")
								? (rows[i - 1] as HTMLElement)
								: row;
						const rowRect = snapTarget.getBoundingClientRect();
						const containerRect = this.content.getBoundingClientRect();
						this.content.scrollTop += rowRect.top - containerRect.top;
						return;
					}
				} catch {
					// skip if address parsing fails
				}
			}
		}
	}

	/** Focus the scroll container for keyboard navigation */
	focus(): void {
		this.content?.focus();
	}
}
