/**
 * Disassembly tab renderer — section picker with disassembly viewer
 */

import type { DisasmSection, LoadCommand, SymbolEntry } from "../../shared/types";
import { DisasmViewer } from "../components/disasm-viewer";
import { EmptyState } from "../components/empty-state";
import { SearchBar } from "../components/search-bar";
import { registerSearchBar } from "../search-state";
import { el } from "../utils/dom";

interface SectionSymbol {
	name: string;
	address: bigint;
}

interface DisasmTabData {
	loadCommands: LoadCommand[];
}

let activeViewer: DisasmViewer | null = null;
let activeSearchBar: SearchBar | null = null;

export async function renderDisasm(
	container: HTMLElement,
	data: DisasmTabData | null,
	sessionId: string
): Promise<void> {
	container.innerHTML = "";

	// Cleanup previous viewer
	if (activeViewer) {
		activeViewer.unmount();
		activeViewer = null;
	}
	if (activeSearchBar) {
		activeSearchBar = null;
	}

	if (!data?.loadCommands || data.loadCommands.length === 0) {
		const empty = new EmptyState({
			icon: "\u{1F4BB}",
			message: "No binary loaded for disassembly."
		});
		empty.mount(container);
		return;
	}

	// Fetch disasm sections
	let sections: DisasmSection[];
	try {
		sections = await window.api.getDisasmSections(sessionId);
	} catch {
		const empty = new EmptyState({
			icon: "\u{26A0}",
			message: "Failed to get disassembly sections."
		});
		empty.mount(container);
		return;
	}

	if (sections.length === 0) {
		const empty = new EmptyState({
			icon: "\u{1F50D}",
			message: "No executable code sections found."
		});
		empty.mount(container);
		return;
	}

	const wrapper = el("div", "disasm-tab-wrapper");

	// Toolbar
	const toolbar = el("div", "da-toolbar");

	// Section picker
	const sectionPicker = el("div", "da-section-picker");
	const sectionBtn = el("button", "da-section-btn");
	let currentSectionIndex = 0;

	function updateSectionButton(): void {
		const s = sections[currentSectionIndex];
		if (s) {
			sectionBtn.textContent = `${s.segname},${s.sectname}`;
		}
	}
	updateSectionButton();

	let dropdownOpen = false;
	let dropdown: HTMLElement | null = null;

	function closeDropdown(): void {
		if (dropdown) {
			dropdown.remove();
			dropdown = null;
		}
		dropdownOpen = false;
	}

	function openDropdown(): void {
		if (dropdownOpen) {
			closeDropdown();
			return;
		}

		dropdown = el("div", "da-section-dropdown");
		sections.forEach((s, i) => {
			const option = el("button", "da-section-option");
			option.textContent = `${s.segname},${s.sectname} (${(s.size / 1024).toFixed(1)} KB)`;
			if (i === currentSectionIndex) {
				option.classList.add("da-section-option--active");
			}
			option.addEventListener("click", () => {
				currentSectionIndex = i;
				updateSectionButton();
				closeDropdown();
				openSection(i);
			});
			dropdown!.appendChild(option);
		});

		sectionPicker.appendChild(dropdown);
		dropdownOpen = true;

		// Close on outside click
		const closeHandler = (e: MouseEvent) => {
			if (!sectionPicker.contains(e.target as Node)) {
				closeDropdown();
				document.removeEventListener("click", closeHandler);
			}
		};
		setTimeout(() => document.addEventListener("click", closeHandler), 0);
	}

	sectionBtn.addEventListener("click", openDropdown);
	sectionPicker.appendChild(sectionBtn);
	toolbar.appendChild(sectionPicker);

	// Function picker
	const funcPicker = el("div", "da-func-picker");
	const funcBtn = el("button", "da-func-btn");
	const funcBtnText = el("span", "da-func-btn-text", "Functions...");
	funcBtn.appendChild(funcBtnText);

	let funcDropdownOpen = false;
	let funcDropdown: HTMLElement | null = null;
	let sectionSymbols: SectionSymbol[] = [];

	async function loadSectionSymbols(sectionIndex: number): Promise<void> {
		const section = sections[sectionIndex];
		if (!section) {
			sectionSymbols = [];
			return;
		}

		try {
			const data = await window.api.getTabData(sessionId, "symbols");
			if (data.tab !== "symbols") {
				sectionSymbols = [];
				return;
			}

			const allSymbols = data.data as SymbolEntry[];
			// virtualAddr comes as number from IPC serialization
			const sectionStart = BigInt(section.virtualAddr as unknown as number | bigint);
			const sectionEnd = sectionStart + BigInt(section.size);

			// Filter to symbols within section address range (exported and local only)
			// Symbol addresses also come as numbers from IPC
			sectionSymbols = allSymbols
				.filter((sym) => {
					if (sym.type === "imported") return false;
					const addr = BigInt(sym.address as unknown as number | bigint);
					return addr >= sectionStart && addr < sectionEnd;
				})
				.map((sym) => ({
					name: sym.name,
					address: BigInt(sym.address as unknown as number | bigint)
				}))
				.sort((a, b) => (a.address < b.address ? -1 : a.address > b.address ? 1 : 0));

			funcBtnText.textContent =
				sectionSymbols.length > 0 ? `Functions (${sectionSymbols.length})` : "No functions";
		} catch {
			sectionSymbols = [];
			funcBtnText.textContent = "Functions...";
		}
	}

	function closeFuncDropdown(): void {
		if (funcDropdown) {
			funcDropdown.remove();
			funcDropdown = null;
		}
		funcDropdownOpen = false;
	}

	function openFuncDropdown(): void {
		if (funcDropdownOpen) {
			closeFuncDropdown();
			return;
		}

		funcDropdown = el("div", "da-func-dropdown");

		// Search input
		const searchInput = document.createElement("input") as HTMLInputElement;
		searchInput.type = "text";
		searchInput.className = "da-func-search";
		searchInput.placeholder = "Search functions...";
		funcDropdown.appendChild(searchInput);

		// Function list
		const funcList = el("div", "da-func-list");

		function renderFuncList(filter: string): void {
			funcList.innerHTML = "";
			const lowerFilter = filter.toLowerCase();
			const filtered = filter
				? sectionSymbols.filter((s) => s.name.toLowerCase().includes(lowerFilter))
				: sectionSymbols;

			if (filtered.length === 0) {
				const empty = el("div", "da-func-empty", filter ? "No matches" : "No functions");
				funcList.appendChild(empty);
				return;
			}

			// Limit to first 200 for performance
			const toShow = filtered.slice(0, 200);
			for (const sym of toShow) {
				const option = el("button", "da-func-option");
				const addrStr = sym.address.toString(16).toUpperCase().padStart(12, "0");
				const addrEl = el("span", "da-func-addr", addrStr);
				const nameEl = el("span", "da-func-name", sym.name);
				option.appendChild(addrEl);
				option.appendChild(nameEl);
				option.addEventListener("click", () => {
					closeFuncDropdown();
					activeViewer?.goToAddress(sym.address);
					gotoInput.value = `0x${addrStr}`;
				});
				funcList.appendChild(option);
			}

			if (filtered.length > 200) {
				const more = el("div", "da-func-empty", `... and ${filtered.length - 200} more`);
				funcList.appendChild(more);
			}
		}

		renderFuncList("");

		searchInput.addEventListener("input", () => {
			renderFuncList(searchInput.value.trim());
		});

		funcDropdown.appendChild(funcList);
		funcPicker.appendChild(funcDropdown);
		funcDropdownOpen = true;

		// Focus search input
		setTimeout(() => searchInput.focus(), 0);

		// Close on outside click
		const closeHandler = (e: MouseEvent) => {
			if (!funcPicker.contains(e.target as Node)) {
				closeFuncDropdown();
				document.removeEventListener("click", closeHandler);
			}
		};
		setTimeout(() => document.addEventListener("click", closeHandler), 0);
	}

	funcBtn.addEventListener("click", openFuncDropdown);
	funcPicker.appendChild(funcBtn);
	toolbar.appendChild(funcPicker);

	// Go-to address input
	const gotoWrap = el("div", "da-goto-wrap");
	const gotoLabel = el("span", "da-goto-label", "Go to:");
	const gotoInput = document.createElement("input") as HTMLInputElement;
	gotoInput.type = "text";
	gotoInput.className = "da-goto-input";
	gotoInput.placeholder = "0x100004000";

	gotoInput.addEventListener("keydown", (e) => {
		if (e.key === "Enter") {
			const value = gotoInput.value.trim();
			let addr: bigint;
			try {
				if (value.startsWith("0x") || value.startsWith("0X")) {
					addr = BigInt(value);
				} else {
					addr = BigInt(`0x${value}`);
				}
			} catch {
				return;
			}
			activeViewer?.goToAddress(addr);
		}
	});

	gotoWrap.appendChild(gotoLabel);
	gotoWrap.appendChild(gotoInput);
	toolbar.appendChild(gotoWrap);

	// Search bar
	const searchWrap = el("div", "da-search-wrap");
	activeSearchBar = new SearchBar(async (query: string, isRegex: boolean) => {
		if (!query || !activeViewer) {
			activeSearchBar?.updateCount(0, 0);
			return;
		}

		try {
			const result = await window.api.searchDisasm(
				sessionId,
				currentSectionIndex,
				query,
				isRegex,
				100
			);

			const total = result.hasMore ? result.matches.length + 1 : result.matches.length;
			activeSearchBar?.updateCount(result.matches.length, total);

			// Jump to first match if any
			if (result.matches.length > 0 && result.matches[0]) {
				const firstMatch = result.matches[0];
				activeViewer?.goToAddress(BigInt(firstMatch.address));
			}
		} catch {
			activeSearchBar?.updateCount(0, 0);
		}
	});
	activeSearchBar.mount(searchWrap);
	toolbar.appendChild(searchWrap);

	wrapper.appendChild(toolbar);

	// Viewer mount point
	const viewerMount = el("div", "da-viewer-mount");
	viewerMount.style.flex = "1";
	viewerMount.style.minHeight = "0";
	wrapper.appendChild(viewerMount);

	container.appendChild(wrapper);

	// Register search bar for Ctrl/Cmd+F
	registerSearchBar(sessionId, "disasm", { focus: () => activeSearchBar?.focus() });

	// Open section
	async function openSection(index: number): Promise<void> {
		const section = sections[index];
		if (!section) return;

		if (activeViewer) {
			activeViewer.unmount();
			activeViewer = null;
		}

		viewerMount.innerHTML = "";

		activeViewer = new DisasmViewer({
			sessionId,
			section,
			sectionIndex: index,
			onAddressClick: (address) => {
				// Copy address to clipboard (already handled in viewer)
				gotoInput.value = `0x${address.toString(16).toUpperCase()}`;
			}
		});
		activeViewer.mount(viewerMount);

		// Load symbols for this section
		await loadSectionSymbols(index);
	}

	// Auto-open first section
	openSection(0);
}
