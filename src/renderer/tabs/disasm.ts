/**
 * Disassembly tab renderer — section picker with disassembly viewer
 */

import type { DisasmSection, LoadCommand } from "../../shared/types";
import { DisasmViewer } from "../components/disasm-viewer";
import { EmptyState } from "../components/empty-state";
import { SearchBar } from "../components/search-bar";
import { registerSearchBar } from "../search-state";
import { el } from "../utils/dom";

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
	function openSection(index: number): void {
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
	}

	// Auto-open first section
	openSection(0);
}
