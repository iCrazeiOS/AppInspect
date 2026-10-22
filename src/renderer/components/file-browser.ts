/**
 * Reusable file browser: resizable tree sidebar with search and a preview pane.
 * Backend-agnostic — callers supply entries, badges, context menu and a preview
 * reader, so the Files and Electron tabs share one implementation.
 */

import type { FilePreviewContent } from "../../shared/types";
import { getSearchState, registerSearchBar, saveSearchState } from "../search-state";
import { getTabState, setTabState } from "../tab-state";
import { el } from "../utils/dom";
import type { BrowserTreeNode, FileBadge } from "../utils/file-browser";
import {
	collectMatchedPaths,
	compilePathMatcher,
	countMatchedFiles,
	countTreeFiles,
	fileIcon,
	findEntry
} from "../utils/file-browser";
import { formatSize } from "../utils/format";
import { initPanelResize } from "../utils/panel-resize";
import { FilePreviewPane } from "./file-preview";
import { SearchBar } from "./search-bar";

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

		const panes = el("div", "fb-panes");
		const sidebar = el("div", "fb-sidebar");
		const resizeHandle = el("div", "fb-resize-handle");
		const previewHost = el("div", "fb-preview");
		const searchWrap = el("div", "fb-search");
		const treeEl = el("div", "fb-tree");
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
			min: 240,
			max: () => Math.max(240, panes.getBoundingClientRect().width - 240),
			storageKey: widthKey,
			activeClass: "fb-resize-handle--active"
		});

		const previewPane = new FilePreviewPane({
			read: this.options.preview.read
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

	private renderTree(): void {
		const treeEl = this.treeEl;
		if (!treeEl) return;
		this.removeContextMenu();
		treeEl.innerHTML = "";
		this.rowMap.clear();
		if (this.options.entries.length === 0) {
			treeEl.appendChild(el("div", "fb-empty", this.options.emptyMessage ?? "No files."));
			return;
		}
		const fragment = document.createDocumentFragment();
		for (const entry of this.options.entries) {
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

		if (!entry.isDirectory) {
			row.appendChild(el("span", "fb-tree-size", formatSize(entry.size)));
		}
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
