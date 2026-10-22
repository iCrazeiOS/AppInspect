/**
 * Electron tab: browse the app.asar virtual filesystem and inspect the
 * package metadata, fuses and ASAR integrity recorded for the bundle.
 */

import { compileSafeRegex } from "../../shared/safe-regex";
import type {
	AsarEntry,
	AsarFileContent,
	ElectronAsarIntegrity,
	ElectronFuse,
	ElectronFuseState,
	ElectronInfo,
	PlistValue
} from "../../shared/types";
import { EmptyState, SearchBar } from "../components";
import { getSearchState, registerSearchBar, saveSearchState } from "../search-state";
import { getTabState, setTabState } from "../tab-state";
import { copyText } from "../utils/clipboard";
import { el } from "../utils/dom";
import { formatCount, formatSize } from "../utils/format";
import { initPanelResize } from "../utils/panel-resize";

/** Archive preview cap, matching the main-process handler's clamp. */
const PREVIEW_MAX_BYTES = 512 * 1024;

type ElectronView = "files" | "package";

const FUSE_STATE_CLASS: Record<ElectronFuseState, string> = {
	enabled: "el-fuse-state--enabled",
	disabled: "el-fuse-state--disabled",
	removed: "el-fuse-state--removed"
};

const INTEGRITY_FUSE = "EnableEmbeddedAsarIntegrityValidation";

/** The hash only proves tamper-resistance when the integrity fuse enforces it. */
function integrityEnforced(info: ElectronInfo): boolean {
	return info.fuses.some((fuse) => fuse.name === INTEGRITY_FUSE && fuse.state === "enabled");
}

function integrityBadge(info: ElectronInfo): HTMLElement | null {
	if (!info.integrity) return null;
	if (!info.integrity.valid) return el("span", "el-badge el-badge--bad", "Integrity mismatch");
	return integrityEnforced(info)
		? el("span", "el-badge el-badge--ok", "Integrity verified")
		: el("span", "el-badge el-badge--warn", "Hash matches (not enforced)");
}

// ── Pure helpers (also unit-tested) ──

/** Build a path matcher for the tree filter, or null for an invalid pattern. */
export function compilePathMatcher(
	term: string,
	isRegex: boolean,
	caseSensitive: boolean
): ((path: string) => boolean) | null {
	if (!term) return null;
	if (isRegex) {
		const re = compileSafeRegex(term, caseSensitive ? "" : "i");
		return re ? (path) => re.test(path) : null;
	}
	if (caseSensitive) return (path) => path.includes(term);
	const lower = term.toLowerCase();
	return (path) => path.toLowerCase().includes(lower);
}

/** Ancestor archive paths of a file, e.g. "a/b/c.js" -> ["a", "a/b"]. */
export function ancestorPaths(path: string): string[] {
	const segments = path.split("/");
	const out: string[] = [];
	for (let i = 1; i < segments.length; i++) {
		out.push(segments.slice(0, i).join("/"));
	}
	return out;
}

/** Matching entry paths plus every ancestor, so a filtered tree keeps its structure. */
export function collectMatchedPaths(
	entries: AsarEntry[],
	test: (path: string) => boolean,
	parentChain: string[] = []
): Set<string> {
	const result = new Set<string>();
	for (const entry of entries) {
		const chain = [...parentChain, entry.path];
		if (test(entry.path)) {
			for (const path of chain) result.add(path);
		}
		if (entry.isDirectory && entry.children) {
			const sub = collectMatchedPaths(entry.children, test, chain);
			for (const path of sub) result.add(path);
		}
	}
	return result;
}

/** Re-serialise JSON text with indentation, or null when it does not parse. */
export function prettyPrintJson(text: string): string | null {
	const trimmed = text.trimStart();
	if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return null;
	try {
		return JSON.stringify(JSON.parse(text), null, 2);
	} catch {
		return null;
	}
}

// ── Value formatting ──

/** Render a package.json/PlistValue scalar, including npm's object-shaped author. */
function textValue(value: PlistValue | undefined): string | undefined {
	if (value === undefined) return undefined;
	if (typeof value === "string") return value;
	if (typeof value === "number" || typeof value === "boolean") return String(value);
	if (Array.isArray(value)) {
		const parts = value.map((item) => textValue(item)).filter((item) => item !== undefined);
		return parts.length > 0 ? parts.join(", ") : undefined;
	}
	const name = value.name;
	if (typeof name === "string") {
		const email = value.email;
		return typeof email === "string" ? `${name} <${email}>` : name;
	}
	return undefined;
}

// ── Card builders ──

function buildCard(title: string, ...children: HTMLElement[]): HTMLElement {
	const card = el("div", "el-card");
	card.appendChild(el("h3", "el-card-title", title));
	const body = el("div", "el-card-body");
	for (const child of children) body.appendChild(child);
	card.appendChild(body);
	return card;
}

function buildKV(label: string, value: string, mono = false): HTMLElement {
	const row = el("div", "el-kv");
	row.appendChild(el("span", "el-kv-label", label));
	row.appendChild(el("span", mono ? "el-kv-value el-kv-value--mono" : "el-kv-value", value));
	return row;
}

function buildPackageCard(info: ElectronInfo): HTMLElement | null {
	const pkg = info.packageJson;
	if (!pkg) return null;

	const items: HTMLElement[] = [];
	const add = (label: string, value: string | undefined): void => {
		if (value !== undefined && value !== "") items.push(buildKV(label, value));
	};

	add("Name", textValue(pkg.name));
	add("Version", textValue(pkg.version));
	add("License", textValue(pkg.license));
	add("Author", textValue(pkg.author));
	add("Main", textValue(pkg.main));
	add("Description", textValue(pkg.description));
	add("Electron Version", info.electronVersion);
	add("ASAR Size", info.asarSize != null ? formatSize(info.asarSize) : undefined);
	add("Files", String(info.fileCount));

	return buildCard("Package", ...items);
}

function buildFusesCard(fuses: ElectronFuse[]): HTMLElement {
	const rows: HTMLElement[] = [];
	for (const fuse of fuses) {
		const row = el("div", "el-fuse-row");
		row.appendChild(el("span", "el-fuse-name", fuse.name));
		row.appendChild(el("span", `el-fuse-state ${FUSE_STATE_CLASS[fuse.state]}`, fuse.state));
		rows.push(row);
	}
	if (rows.length === 0) rows.push(el("p", "el-muted", "No fuse wire found."));
	return buildCard(`Fuses (${fuses.length})`, ...rows);
}

function buildIntegrityCard(integrity: ElectronAsarIntegrity, enforced: boolean): HTMLElement {
	const status = el("div", "el-kv");
	status.appendChild(el("span", "el-kv-label", "Status"));
	status.appendChild(
		el(
			"span",
			integrity.valid ? "el-badge el-badge--ok" : "el-badge el-badge--bad",
			integrity.valid ? "Valid" : "Invalid"
		)
	);

	const enforcedRow = el("div", "el-kv");
	enforcedRow.appendChild(el("span", "el-kv-label", "Enforced"));
	enforcedRow.appendChild(
		el(
			"span",
			enforced ? "el-badge el-badge--ok" : "el-badge el-badge--warn",
			enforced ? "Yes" : "No (fuse disabled)"
		)
	);

	return buildCard(
		"ASAR Integrity",
		buildKV("Algorithm", integrity.algorithm),
		buildKV("Expected", integrity.expected, true),
		buildKV("Actual", integrity.actual, true),
		status,
		enforcedRow
	);
}

function buildDependencyCard(title: string, value: PlistValue | undefined): HTMLElement | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const entries = Object.entries(value);
	if (entries.length === 0) return null;
	const rows = entries.map(([name, version]) => buildKV(name, textValue(version) ?? "—", true));
	return buildCard(`${title} (${entries.length})`, ...rows);
}

function buildPathCard(
	title: string,
	paths: string[],
	onOpen: (path: string) => void
): HTMLElement {
	if (paths.length === 0) return buildCard(title, el("p", "el-muted", "None."));
	const rows = paths.map((path) => {
		const button = el("button", "el-path-btn", path);
		button.title = path;
		button.addEventListener("click", () => onOpen(path));
		return button;
	});
	return buildCard(`${title} (${paths.length})`, ...rows);
}

function buildMissingArchive(info: ElectronInfo): HTMLElement {
	const wrap = el("div", "el-fallback");
	const empty = new EmptyState({
		icon: "\u{1F4E6}",
		message:
			"No readable app.asar was found in this Electron bundle. The archive may be missing, " +
			"unpacked as a plain resources/app directory, or malformed."
	});
	empty.mount(wrap);

	const cards = el("div", "el-cards");
	const packageCard = buildPackageCard(info);
	if (packageCard) cards.appendChild(packageCard);

	const fuses = Array.isArray(info.fuses) ? info.fuses : [];
	if (fuses.length > 0) cards.appendChild(buildFusesCard(fuses));
	if (info.integrity)
		cards.appendChild(buildIntegrityCard(info.integrity, integrityEnforced(info)));
	if (cards.childElementCount > 0) wrap.appendChild(cards);

	return wrap;
}

// ── Package view ──

function renderPackageView(
	container: HTMLElement,
	info: ElectronInfo,
	onOpenPath: (path: string) => void
): void {
	const cards = el("div", "el-cards");
	const pkg = info.packageJson;
	const packageCard = buildPackageCard(info);

	if (packageCard) {
		cards.appendChild(packageCard);
	} else {
		const empty = el("div", "el-package-empty");
		new EmptyState({
			icon: "\u{1F4E6}",
			message: "No package.json found in app.asar."
		}).mount(empty);
		cards.appendChild(empty);
	}

	if (pkg) {
		const dependencies = buildDependencyCard("Dependencies", pkg.dependencies);
		if (dependencies) cards.appendChild(dependencies);
		const optional = buildDependencyCard("Optional Dependencies", pkg.optionalDependencies);
		if (optional) cards.appendChild(optional);
		const dev = buildDependencyCard("Dev Dependencies", pkg.devDependencies);
		if (dev) cards.appendChild(dev);
	}

	const fuses = Array.isArray(info.fuses) ? info.fuses : [];
	cards.appendChild(buildFusesCard(fuses));

	if (info.integrity)
		cards.appendChild(buildIntegrityCard(info.integrity, integrityEnforced(info)));

	const sourceMaps = Array.isArray(info.sourceMaps) ? info.sourceMaps : [];
	cards.appendChild(buildPathCard("Source Maps", sourceMaps, onOpenPath));

	const nativeAddons = Array.isArray(info.nativeAddons) ? info.nativeAddons : [];
	cards.appendChild(buildPathCard("Native Addons", nativeAddons, onOpenPath));

	container.appendChild(cards);
}

// ── Files view ──

function findEntry(entries: AsarEntry[], path: string): AsarEntry | null {
	for (const entry of entries) {
		if (entry.path === path) return entry;
		if (entry.children) {
			const found = findEntry(entry.children, path);
			if (found) return found;
		}
	}
	return null;
}

function countArchiveFiles(entries: AsarEntry[]): number {
	let count = 0;
	for (const entry of entries) {
		if (entry.isDirectory) {
			if (entry.children) count += countArchiveFiles(entry.children);
		} else {
			count++;
		}
	}
	return count;
}

function countMatchedFiles(entries: AsarEntry[], test: (path: string) => boolean): number {
	let count = 0;
	for (const entry of entries) {
		if (entry.isDirectory) {
			if (entry.children) count += countMatchedFiles(entry.children, test);
		} else if (test(entry.path)) {
			count++;
		}
	}
	return count;
}

// ── Main render ──

export function renderElectron(
	container: HTMLElement,
	data: { info: ElectronInfo; files: AsarEntry[] } | null,
	sessionId: string = ""
): void {
	container.innerHTML = "";
	container.classList.add("el-container");

	if (!data?.info) {
		new EmptyState({
			icon: "\u{1F4E6}",
			message: "No Electron data available for this bundle."
		}).mount(container);
		return;
	}

	const info = data.info;
	const files = Array.isArray(data.files) ? data.files : [];
	const sourceMaps = Array.isArray(info.sourceMaps) ? info.sourceMaps : [];

	const wrapper = el("div", "el-wrapper");

	// ── Summary strip ──
	const summary = el("div", "el-summary");
	const stat = (value: string, label: string): HTMLElement => {
		const item = el("div", "el-stat");
		item.appendChild(el("span", "el-stat-value", value));
		item.appendChild(el("span", "el-stat-label", label));
		return item;
	};

	summary.appendChild(
		stat(
			formatCount(info.fileCount, "file"),
			info.asarSize != null ? formatSize(info.asarSize) : "Archive size unknown"
		)
	);
	summary.appendChild(stat(String(info.unpackedCount), "unpacked"));
	summary.appendChild(stat(String(sourceMaps.length), "source maps"));

	const badges = el("div", "el-summary-badges");
	if (info.electronVersion) {
		badges.appendChild(
			el("span", "el-badge el-badge--version", `Electron ${info.electronVersion}`)
		);
	}
	if (info.integrity) {
		const badge = integrityBadge(info);
		if (badge) badges.appendChild(badge);
	}
	if (badges.childElementCount > 0) summary.appendChild(badges);
	wrapper.appendChild(summary);

	if (!info.asarPath) {
		wrapper.appendChild(buildMissingArchive(info));
		container.appendChild(wrapper);
		return;
	}

	// ── View toggle ──
	const toggle = el("div", "el-view-toggle");
	const filesBtn = el("button", "el-toggle-btn", "Files");
	const packageBtn = el("button", "el-toggle-btn", "Package");
	toggle.appendChild(filesBtn);
	toggle.appendChild(packageBtn);
	wrapper.appendChild(toggle);

	const content = el("div", "el-content");
	wrapper.appendChild(content);
	container.appendChild(wrapper);

	let view: ElectronView = getTabState<ElectronView>(sessionId, "electron", "view") ?? "files";
	let previewRequest = 0;
	let previewPath: string | null = null;

	function show(next: ElectronView): void {
		view = next;
		setTabState(sessionId, "electron", "view", next);
		filesBtn.classList.toggle("el-toggle-btn--active", next === "files");
		packageBtn.classList.toggle("el-toggle-btn--active", next === "package");
		if (next !== "files") previewRequest++;
		content.innerHTML = "";
		if (next === "files") renderFilesView(content);
		else renderPackageView(content, info, openPathFromPackage);
	}

	filesBtn.addEventListener("click", () => show("files"));
	packageBtn.addEventListener("click", () => show("package"));

	function openPathFromPackage(path: string): void {
		const saved = getTabState<string[]>(sessionId, "electron", "expanded");
		const expanded = new Set<string>(Array.isArray(saved) ? saved : []);
		for (const ancestor of ancestorPaths(path)) expanded.add(ancestor);
		setTabState(sessionId, "electron", "expanded", [...expanded]);
		setTabState(sessionId, "electron", "selected", path);
		// Drop any filter so the jump target is visible in the recreated tree.
		saveSearchState(sessionId, "electron", "", false);
		show("files");
	}

	function renderFilesView(target: HTMLElement): void {
		const panels = el("div", "el-panels");
		const sidebar = el("div", "el-sidebar");
		const handle = el("div", "el-resize-handle");
		const preview = el("div", "el-preview");
		panels.appendChild(sidebar);
		panels.appendChild(handle);
		panels.appendChild(preview);

		// ── Tree state ──
		const savedExpanded = getTabState<string[]>(sessionId, "electron", "expanded");
		const expandedSet = new Set<string>(Array.isArray(savedExpanded) ? savedExpanded : []);
		let selectedPath = getTabState<string>(sessionId, "electron", "selected") ?? null;
		let matchSet: Set<string> | null = null;
		const rowMap = new Map<string, HTMLElement>();
		const totalFileCount = countArchiveFiles(files);

		// ── Search ──
		const searchWrap = el("div", "el-search");
		sidebar.appendChild(searchWrap);

		// ── Tree ──
		const treeEl = el("div", "el-tree");
		sidebar.appendChild(treeEl);

		// ── Preview ──
		const header = el("div", "el-preview-header");
		const pathEl = el("span", "el-preview-path", "Select a file to preview");
		const sizeEl = el("span", "el-preview-size");
		const copyBtn = el("button", "el-preview-copy", "Copy path");
		copyBtn.disabled = true;
		copyBtn.addEventListener("click", () => {
			if (previewPath) copyText(previewPath, "Copied path");
		});
		header.appendChild(pathEl);
		header.appendChild(sizeEl);
		header.appendChild(copyBtn);

		const notices = el("div", "el-preview-notices");
		const body = el("div", "el-preview-body");
		const placeholder = el("div", "el-preview-empty", "Select a file to preview.");
		body.appendChild(placeholder);
		preview.appendChild(header);
		preview.appendChild(notices);
		preview.appendChild(body);

		initPanelResize(handle, () => sidebar, {
			side: "left",
			min: 240,
			max: () => Math.max(240, panels.getBoundingClientRect().width - 240),
			storageKey: "electron-tree",
			activeClass: "el-resize-handle--active"
		});

		function updateSelection(): void {
			for (const [path, row] of rowMap) {
				row.classList.toggle("el-tree-row--selected", path === selectedPath);
			}
		}

		function renderPreviewContent(result: AsarFileContent): void {
			notices.innerHTML = "";
			body.innerHTML = "";
			sizeEl.textContent = formatSize(result.size);

			if (result.binary) {
				notices.appendChild(
					el(
						"div",
						"el-notice el-notice--binary",
						`Binary file \u2014 preview not available (${formatSize(result.size)}).`
					)
				);
				return;
			}

			if (result.truncated) {
				notices.appendChild(
					el(
						"div",
						"el-notice el-notice--warn",
						`Showing the first ${formatSize(PREVIEW_MAX_BYTES)} of ${formatSize(result.size)}.`
					)
				);
			}

			const text = result.text ?? "";
			const pretty = prettyPrintJson(text);
			body.appendChild(el("pre", "el-code", pretty ?? text));
		}

		async function loadPreview(entry: AsarEntry): Promise<void> {
			const requestId = ++previewRequest;
			previewPath = entry.path;
			pathEl.textContent = entry.path;
			sizeEl.textContent = formatSize(entry.size);
			copyBtn.disabled = false;
			notices.innerHTML = "";
			body.innerHTML = "";
			body.appendChild(el("div", "el-preview-loading", "Loading\u2026"));

			try {
				const result = await window.api.readAsarFile(
					sessionId,
					entry.path,
					PREVIEW_MAX_BYTES
				);
				if (requestId !== previewRequest || !body.isConnected) return;
				if (!result) {
					body.innerHTML = "";
					body.appendChild(
						el("div", "el-preview-empty", "Could not read this archive entry.")
					);
					return;
				}
				renderPreviewContent(result);
			} catch (err) {
				if (requestId !== previewRequest || !body.isConnected) return;
				body.innerHTML = "";
				body.appendChild(
					el(
						"div",
						"el-preview-empty",
						`Could not read this archive entry: ${err instanceof Error ? err.message : String(err)}`
					)
				);
			}
		}

		function renderNode(entry: AsarEntry, depth: number): HTMLElement {
			const wrap = el("div", "el-tree-node");
			if (matchSet && !matchSet.has(entry.path)) {
				wrap.classList.add("hidden");
				return wrap;
			}

			const row = el("div", "el-tree-row");
			row.style.paddingLeft = `${depth * 16 + 8}px`;
			rowMap.set(entry.path, row);

			const hasChildren =
				entry.isDirectory && entry.children !== undefined && entry.children.length > 0;
			const isExpanded = expandedSet.has(entry.path) || matchSet?.has(entry.path) === true;

			const toggle = el("span", "el-tree-toggle");
			toggle.textContent = hasChildren ? (isExpanded ? "\u25BE" : "\u25B8") : " ";
			if (hasChildren) toggle.classList.add("el-tree-toggle--active");
			row.appendChild(toggle);

			row.appendChild(
				el("span", "el-tree-icon", entry.isDirectory ? "\u{1F4C1}" : "\u{1F4C4}")
			);
			row.appendChild(el("span", "el-tree-name", entry.name));

			if (entry.unpacked) {
				row.appendChild(el("span", "el-tree-badge el-tree-badge--unpacked", "unpacked"));
			}
			if (entry.link) {
				const badge = el("span", "el-tree-badge el-tree-badge--link", "link");
				badge.title = `Links to ${entry.link}`;
				row.appendChild(badge);
			}
			if (entry.executable) {
				row.appendChild(el("span", "el-tree-badge el-tree-badge--exec", "executable"));
			}

			if (!entry.isDirectory) {
				row.appendChild(el("span", "el-tree-size", formatSize(entry.size)));
			}
			wrap.appendChild(row);

			if (hasChildren && entry.children) {
				const childrenEl = el("div", "el-children");
				if (isExpanded) childrenEl.classList.add("el-children--open");
				for (const child of entry.children) {
					childrenEl.appendChild(renderNode(child, depth + 1));
				}
				wrap.appendChild(childrenEl);

				row.addEventListener("click", () => {
					const open = childrenEl.classList.contains("el-children--open");
					if (open) {
						expandedSet.delete(entry.path);
						childrenEl.classList.remove("el-children--open");
						toggle.textContent = "\u25B8";
					} else {
						expandedSet.add(entry.path);
						childrenEl.classList.add("el-children--open");
						toggle.textContent = "\u25BE";
					}
					setTabState(sessionId, "electron", "expanded", [...expandedSet]);
				});
				row.style.cursor = "pointer";
			} else if (!entry.isDirectory) {
				row.classList.toggle("el-tree-row--selected", entry.path === selectedPath);
				row.addEventListener("click", () => {
					selectedPath = entry.path;
					setTabState(sessionId, "electron", "selected", entry.path);
					updateSelection();
					void loadPreview(entry);
				});
				row.style.cursor = "pointer";
			}

			return wrap;
		}

		function renderTree(): void {
			treeEl.innerHTML = "";
			rowMap.clear();
			const fragment = document.createDocumentFragment();
			for (const entry of files) fragment.appendChild(renderNode(entry, 0));
			treeEl.appendChild(fragment);
		}

		const searchBar = new SearchBar((term, isRegex, caseSensitive) => {
			saveSearchState(sessionId, "electron", term, isRegex);

			if (!term) {
				matchSet = null;
				renderTree();
				searchBar.updateCount(totalFileCount, totalFileCount);
				return;
			}

			const test = compilePathMatcher(term, isRegex, caseSensitive);
			if (!test) return;
			matchSet = collectMatchedPaths(files, test);
			renderTree();
			searchBar.updateCount(countMatchedFiles(files, test), totalFileCount);
		});
		searchBar.mount(searchWrap);
		registerSearchBar(sessionId, "electron", searchBar);

		renderTree();
		searchBar.updateCount(totalFileCount, totalFileCount);

		const savedSearch = getSearchState(sessionId, "electron");
		if (savedSearch?.term) {
			searchBar.setValue(savedSearch.term, savedSearch.isRegex);
		}

		if (selectedPath) {
			const entry = findEntry(files, selectedPath);
			if (entry) void loadPreview(entry);
		}

		target.appendChild(panels);
	}

	show(view);
}
