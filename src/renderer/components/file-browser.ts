/**
 * Reusable file browser: resizable tree sidebar with search and a preview pane.
 * Backend-agnostic — callers supply entries, badges, context menu and a preview
 * reader, so the Files and Electron tabs share one implementation.
 */

import type { FilePreviewContent } from "../../shared/types";
import { announce } from "../navigation";
import { getSearchState, registerSearchBar, saveSearchState } from "../search-state";
import { getTabState, setTabState } from "../tab-state";
import { el } from "../utils/dom";
import type { BrowserTreeNode, FileBadge, FileSortKey, SortDirection } from "../utils/file-browser";
import {
	collectMatchedPaths,
	compilePathMatcher,
	countMatchedFiles,
	countTreeFiles,
	fileIcon,
	findEntry,
	sortTree
} from "../utils/file-browser";
import { formatRelativeTime, formatSize } from "../utils/format";
import { initPanelResize } from "../utils/panel-resize";
import { FilePreviewPane } from "./file-preview";
import { SearchBar } from "./search-bar";

const SORT_LABELS: Record<FileSortKey, string> = {
	name: "Name",
	size: "Size",
	modified: "Modified"
};

const SORT_NAMES: Record<FileSortKey, string> = {
	name: "name",
	size: "size",
	modified: "modification time"
};

const SORT_DIRECTIONS: Record<FileSortKey, SortDirection> = {
	name: "asc",
	size: "desc",
	modified: "desc"
};

const SORT_ORDER_LABELS: Record<FileSortKey, Record<SortDirection, string>> = {
	name: { asc: "A to Z", desc: "Z to A" },
	size: { asc: "smallest first", desc: "largest first" },
	modified: { asc: "oldest first", desc: "newest first" }
};

export interface FilePreviewProvider {
	read(path: string, maxBytes: number, includeImage: boolean): Promise<FilePreviewContent | null>;
}

export interface FileContextMenuEntry {
	label: string;
	action: () => void;
}

export interface FileBrowserOptions<T extends BrowserTreeNode> {
	entries: T[];
	sessionId: string;
	/** Tab-state namespace: "files" or "electron". */
	stateKey: string;
	/** localStorage key for the sidebar width, e.g. "files-tree". */
	widthKey: string;
	preview: FilePreviewProvider;
	/** Optional path used for search; defaults to entry.path. */
	searchPath?: (entry: T) => string;
	badges?: (entry: T) => FileBadge[];
	/** Return [] to suppress the menu. May be async (e.g. platform lookup). */
	contextMenu?: (entry: T) => FileContextMenuEntry[] | Promise<FileContextMenuEntry[]>;
	/** Double-click for real filesystem entries. */
	onOpen?: (entry: T) => void;
	emptyMessage?: string;
}

export class FileBrowser<T extends BrowserTreeNode> {
	private options: FileBrowserOptions<T>;
	private treeEl: HTMLElement | null = null;
	private previewPane: FilePreviewPane | null = null;

	private expandedSet = new Set<string>();
	private selectedPath: string | null = null;
	private matchSet: Set<string> | null = null;
	private activeMatcher: ((value: string) => boolean) | null = null;
	private rowMap = new Map<string, HTMLElement>();
	private totalFileCount = 0;

	private sortedEntries: T[] = [];
	private sortKey: FileSortKey = "name";
	private sortDir: SortDirection = "asc";
	private supportsModified = false;
	private sortGroup: HTMLElement | null = null;

	private activeMenu: HTMLElement | null = null;
	private focusedRow: HTMLElement | null = null;
	private menuDismiss: ((event: MouseEvent) => void) | null = null;
	/** Invalidates a menu build that is still awaiting its async items. */
	private menuRequestId = 0;

	constructor(options: FileBrowserOptions<T>) {
		this.options = options;
	}

	mount(container: HTMLElement): void {
		const { entries, sessionId, stateKey, widthKey } = this.options;

		this.supportsModified = entries.some((entry) => typeof entry.mtimeMs === "number");
		const keys = this.sortKeys();
		const savedKey = getTabState<FileSortKey>(sessionId, stateKey, "sortKey");
		const savedDir = getTabState<SortDirection>(sessionId, stateKey, "sortDir");
		this.sortKey = savedKey && keys.includes(savedKey) ? savedKey : "name";
		this.sortDir =
			savedKey === this.sortKey && (savedDir === "asc" || savedDir === "desc")
				? savedDir
				: SORT_DIRECTIONS[this.sortKey];
		this.sortedEntries = sortTree(entries, this.sortKey, this.sortDir);

		const panes = el("div", "fb-panes");
		const sidebar = el("div", "fb-sidebar");
		const resizeHandle = el("div", "fb-resize-handle");
		const previewHost = el("div", "fb-preview");
		const searchWrap = el("div", "fb-search");
		const treeEl = el("div", "fb-tree");
		sidebar.appendChild(this.buildSortBar());
		sidebar.appendChild(searchWrap);
		sidebar.appendChild(treeEl);
		panes.appendChild(sidebar);
		panes.appendChild(resizeHandle);
		panes.appendChild(previewHost);
		container.appendChild(panes);

		// Menus live on document.body, so a whole-tab re-render can leave one behind.
		document.querySelectorAll(".fb-ctx-menu").forEach((menu) => {
			menu.remove();
		});
		document.querySelectorAll(".fb-tree-row--focus").forEach((row) => {
			row.classList.remove("fb-tree-row--focus");
		});

		this.treeEl = treeEl;
		this.totalFileCount = countTreeFiles(entries);

		initPanelResize(resizeHandle, () => sidebar, {
			side: "left",
			min: 280,
			max: () => Math.max(280, panes.getBoundingClientRect().width - 240),
			storageKey: widthKey,
			activeClass: "fb-resize-handle--active"
		});

		const previewPane = new FilePreviewPane({
			read: this.options.preview.read,
			onOpen: this.options.onOpen
				? (path) => {
						const entry = findEntry(entries, path);
						if (entry && !entry.isDirectory) this.options.onOpen?.(entry);
					}
				: undefined
		});
		previewPane.mount(previewHost);
		this.previewPane = previewPane;

		const savedExpanded = getTabState<string[]>(sessionId, stateKey, "expanded");
		this.expandedSet = new Set(Array.isArray(savedExpanded) ? savedExpanded : []);
		this.selectedPath = getTabState<string>(sessionId, stateKey, "selected") ?? null;
		const savedCase = getTabState<boolean>(sessionId, stateKey, "searchCase") ?? false;

		const searchBar = new SearchBar((term, isRegex, caseSensitive) => {
			saveSearchState(sessionId, stateKey, term, isRegex);
			setTabState(sessionId, stateKey, "searchCase", caseSensitive);

			if (!term) {
				this.matchSet = null;
				this.activeMatcher = null;
				this.renderTree();
				searchBar.updateCount(this.totalFileCount, this.totalFileCount);
				return;
			}

			const test = compilePathMatcher(term, isRegex, caseSensitive);
			// Invalid regex: leave the current tree untouched.
			if (!test) return;
			this.activeMatcher = test;
			this.matchSet = collectMatchedPaths(entries, (entry) => test(this.searchValue(entry)));
			this.renderTree();
			searchBar.updateCount(
				countMatchedFiles(entries, (entry) => test(this.searchValue(entry))),
				this.totalFileCount
			);
		});
		searchBar.mount(searchWrap);
		registerSearchBar(sessionId, stateKey, searchBar);

		// Render the unfiltered tree first so an invalid saved pattern cannot
		// leave the sidebar blank.
		this.renderTree();
		searchBar.updateCount(this.totalFileCount, this.totalFileCount);

		const savedSearch = getSearchState(sessionId, stateKey);
		if (savedSearch?.term || savedCase) {
			searchBar.setValue(savedSearch?.term ?? "", savedSearch?.isRegex ?? false, savedCase);
		}

		if (this.selectedPath) {
			const entry = findEntry(entries, this.selectedPath);
			if (entry && !entry.isDirectory) previewPane.show(entry);
		}
	}

	private searchValue(entry: T): string {
		const value = this.options.searchPath?.(entry) ?? entry.path;
		return value.replaceAll("\\", "/");
	}

	private sortKeys(): FileSortKey[] {
		return this.supportsModified ? ["name", "size", "modified"] : ["name", "size"];
	}

	private buildSortBar(): HTMLElement {
		const bar = el("div", "fb-sort");
		bar.appendChild(el("span", "fb-sort-label", "Sort by"));

		const group = el("div", "fb-sort-group");
		group.setAttribute("role", "group");
		group.setAttribute("aria-label", "Sort files by");
		this.sortGroup = group;

		for (const key of this.sortKeys()) {
			const button = el("button", "fb-sort-btn");
			button.type = "button";
			button.dataset.sort = key;
			button.addEventListener("click", () => this.changeSort(key));
			group.appendChild(button);
		}

		bar.appendChild(group);
		this.updateSortButtons();
		return bar;
	}

	private sortDescription(key: FileSortKey): string {
		if (key !== this.sortKey) return `Sort by ${SORT_NAMES[key]}`;
		return `Sorted ${SORT_ORDER_LABELS[key][this.sortDir]}, click to reverse`;
	}

	private updateSortButtons(): void {
		if (!this.sortGroup) return;
		this.sortGroup.querySelectorAll<HTMLButtonElement>(".fb-sort-btn").forEach((button) => {
			const key = button.dataset.sort as FileSortKey;
			const active = key === this.sortKey;
			const description = this.sortDescription(key);
			button.classList.toggle("fb-sort-btn--active", active);
			button.setAttribute("aria-pressed", String(active));
			button.setAttribute("aria-label", description);
			button.title = description;
			button.textContent = SORT_LABELS[key];
			if (active) {
				const arrow = el(
					"span",
					"fb-sort-arrow",
					this.sortDir === "asc" ? "\u25B2" : "\u25BC"
				);
				arrow.setAttribute("aria-hidden", "true");
				button.appendChild(arrow);
			}
		});
	}

	private changeSort(key: FileSortKey): void {
		if (key === this.sortKey) {
			this.sortDir = this.sortDir === "asc" ? "desc" : "asc";
		} else {
			this.sortKey = key;
			this.sortDir = SORT_DIRECTIONS[key];
		}
		setTabState(this.options.sessionId, this.options.stateKey, "sortKey", this.sortKey);
		setTabState(this.options.sessionId, this.options.stateKey, "sortDir", this.sortDir);
		this.sortedEntries = sortTree(this.options.entries, this.sortKey, this.sortDir);
		this.updateSortButtons();
		this.renderTree();
		announce(
			`Sorted by ${SORT_NAMES[this.sortKey]}, ${SORT_ORDER_LABELS[this.sortKey][this.sortDir]}`
		);
	}

	private renderTree(): void {
		const treeEl = this.treeEl;
		if (!treeEl) return;
		this.removeContextMenu();
		treeEl.innerHTML = "";
		this.rowMap.clear();
		if (this.sortedEntries.length === 0) {
			treeEl.appendChild(el("div", "fb-empty", this.options.emptyMessage ?? "No files."));
			return;
		}
		const fragment = document.createDocumentFragment();
		for (const entry of this.sortedEntries) {
			fragment.appendChild(this.renderNode(entry, 0));
		}
		treeEl.appendChild(fragment);
	}

	private renderNode(entry: T, depth: number): HTMLElement {
		const wrap = el("div");
		if (this.matchSet && !this.matchSet.has(entry.path)) {
			wrap.classList.add("hidden");
			return wrap;
		}

		const row = el("div", "fb-tree-row");
		row.style.paddingLeft = `${depth * 16 + 8}px`;
		this.rowMap.set(entry.path, row);

		const hasChildren =
			entry.isDirectory && entry.children !== undefined && entry.children.length > 0;
		const isExpanded =
			this.expandedSet.has(entry.path) || this.matchSet?.has(entry.path) === true;

		const toggle = el("span", "fb-tree-toggle");
		toggle.textContent = hasChildren ? (isExpanded ? "\u25BE" : "\u25B8") : " ";
		if (hasChildren) toggle.classList.add("fb-tree-toggle--active");
		row.appendChild(toggle);

		row.appendChild(el("span", "fb-tree-icon", fileIcon(entry.name, entry.isDirectory)));

		const nameEl = el("span", "fb-tree-name", entry.name);
		nameEl.title = entry.name;
		if (this.activeMatcher?.(entry.name)) nameEl.classList.add("fb-name-match");
		row.appendChild(nameEl);

		for (const badge of this.options.badges?.(entry) ?? []) {
			const badgeEl = el("span", `fb-tree-badge fb-tree-badge--${badge.tone}`);
			if (badge.label === undefined) {
				badgeEl.classList.add("fb-tree-badge--dot");
			} else {
				badgeEl.textContent = badge.label;
			}
			if (badge.title) badgeEl.title = badge.title;
			row.appendChild(badgeEl);
		}

		const meta = el("div", "fb-tree-meta");
		const sizeEl = el("span", "fb-tree-size", formatSize(entry.size));
		sizeEl.title = entry.isDirectory ? "Total size of folder contents" : "File size";
		meta.appendChild(sizeEl);
		if (this.supportsModified && typeof entry.mtimeMs === "number") {
			const modifiedEl = el("span", "fb-tree-modified", formatRelativeTime(entry.mtimeMs));
			modifiedEl.title = `${entry.isDirectory ? "Latest modification" : "Modified"}: ${new Date(entry.mtimeMs).toLocaleString()}`;
			meta.appendChild(modifiedEl);
		}
		row.appendChild(meta);

		row.classList.toggle("fb-tree-row--selected", entry.path === this.selectedPath);
		wrap.appendChild(row);

		row.addEventListener("contextmenu", (event) => {
			void this.showContextMenu(event, entry, row);
		});

		if (hasChildren && entry.children) {
			const childrenEl = el("div", "fb-children");
			if (isExpanded) childrenEl.classList.add("fb-children--open");
			for (const child of entry.children) {
				childrenEl.appendChild(this.renderNode(child as T, depth + 1));
			}
			wrap.appendChild(childrenEl);

			row.addEventListener("click", () => {
				const open = childrenEl.classList.contains("fb-children--open");
				if (open) {
					this.expandedSet.delete(entry.path);
					childrenEl.classList.remove("fb-children--open");
					toggle.textContent = "\u25B8";
				} else {
					this.expandedSet.add(entry.path);
					childrenEl.classList.add("fb-children--open");
					toggle.textContent = "\u25BE";
				}
				setTabState(this.options.sessionId, this.options.stateKey, "expanded", [
					...this.expandedSet
				]);
			});
			row.style.cursor = "pointer";
		} else if (!entry.isDirectory) {
			row.addEventListener("click", () => {
				this.selectedPath = entry.path;
				setTabState(this.options.sessionId, this.options.stateKey, "selected", entry.path);
				this.updateSelection();
				this.previewPane?.show(entry);
			});
			row.style.cursor = "pointer";
			row.addEventListener("dblclick", (event) => {
				event.stopPropagation();
				this.options.onOpen?.(entry);
			});
		}

		return wrap;
	}

	private updateSelection(): void {
		for (const [path, row] of this.rowMap) {
			row.classList.toggle("fb-tree-row--selected", path === this.selectedPath);
		}
	}

	private removeContextMenu(): void {
		this.menuRequestId++;
		if (this.activeMenu) {
			this.activeMenu.remove();
			this.activeMenu = null;
		}
		if (this.menuDismiss) {
			document.removeEventListener("mousedown", this.menuDismiss);
			this.menuDismiss = null;
		}
		this.focusedRow?.classList.remove("fb-tree-row--focus");
		this.focusedRow = null;
	}

	private async showContextMenu(event: MouseEvent, entry: T, row: HTMLElement): Promise<void> {
		event.preventDefault();
		this.removeContextMenu();
		if (!this.options.contextMenu) return;

		row.classList.add("fb-tree-row--focus");
		this.focusedRow = row;
		const requestId = this.menuRequestId;

		let items: FileContextMenuEntry[];
		try {
			items = await this.options.contextMenu(entry);
		} catch {
			if (requestId === this.menuRequestId) this.removeContextMenu();
			return;
		}
		// A newer menu (or a dismissal) happened while the items were loading.
		if (requestId !== this.menuRequestId) return;
		if (items.length === 0 || !row.isConnected) {
			this.removeContextMenu();
			return;
		}

		const menu = el("div", "fb-ctx-menu");
		menu.style.left = `${event.clientX}px`;
		menu.style.top = `${event.clientY}px`;
		for (const item of items) {
			const menuItem = el("div", "fb-ctx-item", item.label);
			menuItem.addEventListener("click", () => {
				item.action();
				this.removeContextMenu();
			});
			menu.appendChild(menuItem);
		}
		document.body.appendChild(menu);
		this.activeMenu = menu;

		// Clamp to viewport
		requestAnimationFrame(() => {
			if (!menu.isConnected) return;
			const rect = menu.getBoundingClientRect();
			if (rect.right > window.innerWidth) {
				menu.style.left = `${window.innerWidth - rect.width - 4}px`;
			}
			if (rect.bottom > window.innerHeight) {
				menu.style.top = `${window.innerHeight - rect.height - 4}px`;
			}
		});

		const dismiss = (dismissEvent: MouseEvent): void => {
			if (this.activeMenu && !this.activeMenu.contains(dismissEvent.target as Node)) {
				this.removeContextMenu();
			}
		};
		this.menuDismiss = dismiss;
		setTimeout(() => {
			if (this.menuDismiss === dismiss) document.addEventListener("mousedown", dismiss);
		}, 0);
	}
}
