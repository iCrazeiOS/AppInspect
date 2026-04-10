/**
 * Files tab: directory tree view of extracted IPA contents.
 * Expandable/collapsible folders, search/filter, and file-type badges.
 */

import type { FileEntry } from "../../shared/types";
import { SearchBar } from "../components";
import { getSearchState, registerSearchBar, saveSearchState } from "../search-state";

// ── Helpers ──

function formatSize(bytes: number): string {
	if (bytes < 1024) return `${bytes} B`;
	if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
	if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
	return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function countFiles(entries: FileEntry[]): { count: number; totalSize: number } {
	let count = 0;
	let totalSize = 0;
	for (const e of entries) {
		if (e.isDirectory) {
			if (e.children) {
				const sub = countFiles(e.children);
				count += sub.count;
				totalSize += sub.totalSize;
			}
		} else {
			count++;
			totalSize += e.size;
		}
	}
	return { count, totalSize };
}

type FileType = "binary" | "plist" | "provision" | "framework" | "default";

function classifyFile(entry: FileEntry): FileType {
	const name = entry.name;
	const path = entry.path;

	if (entry.isDirectory && name.endsWith(".framework")) return "framework";
	if (name.endsWith(".plist")) return "plist";
	if (name.endsWith(".mobileprovision")) return "provision";

	// Mach-O heuristic: no extension in .app root or inside Frameworks/
	if (!entry.isDirectory && !name.includes(".")) {
		if (/\.app\/[^/]*$/.test(path) || /Frameworks\//.test(path)) {
			return "binary";
		}
	}

	return "default";
}

const BADGE_CLASS: Record<FileType, string> = {
	binary: "ft-badge-binary",
	plist: "ft-badge-plist",
	provision: "ft-badge-provision",
	framework: "ft-badge-framework",
	default: ""
};

// ── Search: collect matching paths and their ancestors ──

function collectMatches(
	entries: FileEntry[],
	test: (name: string) => boolean,
	parentChain: string[] = []
): Set<string> {
	const result = new Set<string>();
	for (const entry of entries) {
		const chain = [...parentChain, entry.path];
		if (test(entry.name)) {
			// Add this entry and all ancestors
			for (const p of chain) result.add(p);
		}
		if (entry.isDirectory && entry.children) {
			const sub = collectMatches(entry.children, test, chain);
			for (const p of sub) result.add(p);
		}
	}
	return result;
}

// ── Context menu ──

let activeMenu: HTMLElement | null = null;

function removeActiveMenu(): void {
	if (activeMenu) {
		activeMenu.remove();
		activeMenu = null;
	}
	document.querySelector(".ft-row-focus")?.classList.remove("ft-row-focus");
}

let platformName: string | null = null;

function getFolderLabel(): string {
	if (platformName === "darwin") return "Show in Finder";
	if (platformName === "linux") return "Show in File Manager";
	return "Show in Explorer";
}

function showContextMenu(x: number, y: number, entry: FileEntry, row: HTMLElement): void {
	removeActiveMenu();

	row.classList.add("ft-row-focus");

	const menu = document.createElement("div");
	menu.className = "ft-ctx-menu";
	menu.style.left = `${x}px`;
	menu.style.top = `${y}px`;

	const items: { label: string; action: () => void }[] = [
		{ label: "Copy Path", action: () => navigator.clipboard.writeText(entry.path) },
		{ label: "Copy Name", action: () => navigator.clipboard.writeText(entry.name) },
		{ label: getFolderLabel(), action: () => window.api.showItemInFolder(entry.path) }
	];

	if (!entry.isDirectory) {
		items.push({ label: "Open File", action: () => window.api.openFile(entry.path) });
	}

	for (const item of items) {
		const el = document.createElement("div");
		el.className = "ft-ctx-item";
		el.textContent = item.label;
		el.addEventListener("click", () => {
			item.action();
			removeActiveMenu();
		});
		menu.appendChild(el);
	}

	document.body.appendChild(menu);
	activeMenu = menu;

	// Clamp to viewport
	requestAnimationFrame(() => {
		const rect = menu.getBoundingClientRect();
		if (rect.right > window.innerWidth)
			menu.style.left = `${window.innerWidth - rect.width - 4}px`;
		if (rect.bottom > window.innerHeight)
			menu.style.top = `${window.innerHeight - rect.height - 4}px`;
	});

	const dismiss = (e: MouseEvent) => {
		if (!menu.contains(e.target as Node)) {
			removeActiveMenu();
			document.removeEventListener("mousedown", dismiss);
		}
	};
	setTimeout(() => document.addEventListener("mousedown", dismiss), 0);
}

// ── Rendering ──

export function renderFiles(container: HTMLElement, data: unknown, sessionId: string = ""): void {
	container.innerHTML = "";

	// Cache platform for context menu labels
	if (platformName === null) {
		window.api.getPlatform().then((p) => {
			platformName = p;
		});
	}

	const entries = (Array.isArray(data) ? data : []) as FileEntry[];
	const { count, totalSize } = countFiles(entries);

	// -- Summary bar --
	const summaryEl = document.createElement("div");
	summaryEl.className = "ft-summary";
	summaryEl.textContent = `${count.toLocaleString()} files \u00B7 ${formatSize(totalSize)}`;
	container.appendChild(summaryEl);

	// -- Search bar --
	const searchWrap = document.createElement("div");
	container.appendChild(searchWrap);

	// -- Tree container --
	const treeEl = document.createElement("div");
	treeEl.className = "ft-tree";
	container.appendChild(treeEl);

	// Track expanded state by path — all collapsed by default
	const expandedSet = new Set<string>();

	// Track node elements by path for search
	const nodeMap = new Map<string, HTMLElement>();
	const childrenMap = new Map<string, HTMLElement>();

	let activeFilter: ((name: string) => boolean) | null = null;
	let matchSet: Set<string> | null = null;

	function renderTree(): void {
		treeEl.innerHTML = "";
		nodeMap.clear();
		childrenMap.clear();

		for (const entry of entries) {
			treeEl.appendChild(renderNode(entry, 0));
		}
	}

	function renderNode(entry: FileEntry, depth: number): HTMLElement {
		const wrap = document.createElement("div");
		wrap.className = "ft-node";
		nodeMap.set(entry.path, wrap);

		// If filtering and this entry is not in match set, hide
		if (matchSet && !matchSet.has(entry.path)) {
			wrap.style.display = "none";
			return wrap;
		}

		const row = document.createElement("div");
		row.className = "ft-row";
		row.style.paddingLeft = `${depth * 20 + 8}px`;

		// Expand/collapse toggle (only for directories)
		const toggle = document.createElement("span");
		toggle.className = "ft-toggle";
		if (entry.isDirectory && entry.children && entry.children.length > 0) {
			const isExpanded =
				expandedSet.has(entry.path) || (matchSet !== null && matchSet.has(entry.path));
			toggle.textContent = isExpanded ? "\u25BE" : "\u25B8";
			toggle.classList.add("ft-toggle-active");
		} else {
			toggle.textContent = " ";
		}
		row.appendChild(toggle);

		// Icon
		const icon = document.createElement("span");
		icon.className = "ft-icon";
		icon.textContent = entry.isDirectory ? "\uD83D\uDCC1" : "\uD83D\uDCC4";
		row.appendChild(icon);

		// Name
		const nameEl = document.createElement("span");
		nameEl.className = "ft-name";
		if (activeFilter && !entry.isDirectory && activeFilter(entry.name)) {
			nameEl.classList.add("ft-name-match");
		}
		nameEl.textContent = entry.name;
		row.appendChild(nameEl);

		// File type badge (after name)
		const fileType = classifyFile(entry);
		if (fileType !== "default") {
			const badge = document.createElement("span");
			badge.className = `ft-badge ${BADGE_CLASS[fileType]}`;
			row.appendChild(badge);
		}

		// Size (for files only)
		if (!entry.isDirectory) {
			const sizeEl = document.createElement("span");
			sizeEl.className = "ft-size";
			sizeEl.textContent = formatSize(entry.size);
			row.appendChild(sizeEl);
		}

		wrap.appendChild(row);

		// Context menu
		row.addEventListener("contextmenu", (e) => {
			e.preventDefault();
			showContextMenu(e.clientX, e.clientY, entry, row);
		});

		// Double-click to open file
		if (!entry.isDirectory) {
			row.addEventListener("dblclick", (e) => {
				e.stopPropagation();
				window.api.openFile(entry.path);
			});
		}

		// Children container
		if (entry.isDirectory && entry.children && entry.children.length > 0) {
			const childrenEl = document.createElement("div");
			childrenEl.className = "ft-children";
			childrenMap.set(entry.path, childrenEl);

			const isExpanded =
				expandedSet.has(entry.path) || (matchSet !== null && matchSet.has(entry.path));
			if (isExpanded) {
				childrenEl.classList.add("ft-children-open");
			}

			for (const child of entry.children) {
				childrenEl.appendChild(renderNode(child, depth + 1));
			}

			wrap.appendChild(childrenEl);

			// Click handler
			row.addEventListener("click", () => {
				const open = childrenEl.classList.contains("ft-children-open");
				if (open) {
					expandedSet.delete(entry.path);
					childrenEl.classList.remove("ft-children-open");
					toggle.textContent = "\u25B8";
				} else {
					expandedSet.add(entry.path);
					childrenEl.classList.add("ft-children-open");
					toggle.textContent = "\u25BE";
				}
			});

			row.style.cursor = "pointer";
		}

		return wrap;
	}

	// -- Search integration --
	const totalFileCount = count;

	const searchBar = new SearchBar((term: string, isRegex: boolean, _caseSensitive: boolean) => {
		saveSearchState(sessionId, "files", term, isRegex);

		if (!term) {
			activeFilter = null;
			matchSet = null;
			renderTree();
			searchBar.updateCount(totalFileCount, totalFileCount);
			return;
		}

		let testFn: (name: string) => boolean;
		if (isRegex) {
			try {
				const re = new RegExp(term, "i");
				testFn = (name) => re.test(name);
			} catch {
				return;
			}
		} else {
			const lower = term.toLowerCase();
			testFn = (name) => name.toLowerCase().includes(lower);
		}

		activeFilter = testFn;
		matchSet = collectMatches(entries, testFn);

		// Count matching files (non-directories)
		let matchingFiles = 0;
		const countMatching = (list: FileEntry[]) => {
			for (const e of list) {
				if (!e.isDirectory && testFn(e.name)) matchingFiles++;
				if (e.isDirectory && e.children) countMatching(e.children);
			}
		};
		countMatching(entries);

		renderTree();
		searchBar.updateCount(matchingFiles, totalFileCount);
	});

	searchBar.mount(searchWrap);
	registerSearchBar(sessionId, "files", searchBar);
	renderTree();
	searchBar.updateCount(totalFileCount, totalFileCount);

	// Restore saved search state
	const savedState = getSearchState(sessionId, "files");
	if (savedState && savedState.term) {
		searchBar.setValue(savedState.term, savedState.isRegex);
	}
}
