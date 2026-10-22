/**
 * Swift tab: Swift 5 nominal types, stored properties, protocols, and
 * conformances parsed from the binary's Swift metadata sections.
 */

import type {
	BinaryInfo,
	SwiftMetadata,
	SwiftProtocol,
	SwiftType,
	SwiftTypeKind
} from "../../shared/types";
import { EmptyState, SearchBar } from "../components";
import { getSearchState, registerSearchBar, saveSearchState } from "../search-state";
import { copyText } from "../utils/clipboard";
import {
	addAllBinariesToggle,
	binaryTypeBadge,
	buildShowAllLink,
	createCrossBinaryState,
	doCrossBinarySearch
} from "../utils/cross-binary-search";
import { formatCount, plural } from "../utils/format";
import { initPanelResize } from "../utils/panel-resize";

const ROW_HEIGHT = 28;
const CROSS_ROW_HEIGHT = 44; // taller rows for cross-binary results
const BUFFER = 20;

/** Type name queued by a cross-binary click on a different binary. */
let pendingSwiftSelect: string | null = null;

const KIND_LABEL: Record<SwiftTypeKind, string> = {
	class: "class",
	struct: "struct",
	enum: "enum"
};

const KIND_BADGE: Record<SwiftTypeKind, string> = {
	class: "C",
	struct: "S",
	enum: "E"
};

type KindFilter = SwiftTypeKind | "all";

const KIND_FILTERS: Array<{ id: KindFilter; label: string }> = [
	{ id: "all", label: "All" },
	{ id: "class", label: "Classes" },
	{ id: "struct", label: "Structs" },
	{ id: "enum", label: "Enums" }
];

const HIDE_MODULE_PREFIX_KEY = "appinspect:swift:hide-module-prefix";

function loadHideModulePrefix(): boolean {
	try {
		return localStorage.getItem(HIDE_MODULE_PREFIX_KEY) === "true";
	} catch {
		return false;
	}
}

function saveHideModulePrefix(value: boolean): void {
	try {
		localStorage.setItem(HIDE_MODULE_PREFIX_KEY, String(value));
	} catch {}
}

function countByKind(types: SwiftType[], kind: SwiftTypeKind): number {
	return types.reduce((total, type) => total + (type.kind === kind ? 1 : 0), 0);
}

export function renderSwift(
	container: HTMLElement,
	data: SwiftMetadata | null,
	sessionId: string,
	binary?: BinaryInfo,
	binaryCount: number = 1
): void {
	container.innerHTML = "";
	container.classList.add("cls-container", "swift-container");

	if (!data?.present || (data.types.length === 0 && data.protocols.length === 0)) {
		const empty = new EmptyState({
			icon: "\u{1F9E9}",
			message: data?.present
				? "Swift metadata sections are present, but no types or protocols were decoded."
				: "No Swift metadata found. This binary may be Objective-C/C++ only, or built without Swift reflection metadata."
		});
		empty.mount(container);
		pendingSwiftSelect = null;
		return;
	}

	const allTypes = data.types;
	const allConformances = data.conformances;
	// Folder binaries are named by relative path, so compare only the basename.
	const binaryBaseName = binary?.name.split(/[\\/]/).pop() ?? "";
	const mainModuleName =
		binary?.type === "main"
			? binaryBaseName.replace(/\.(?:dylib|so|app|framework|bundle)$/i, "")
			: "";
	const conformanceByType = new Map<string, SwiftType>();
	for (const type of allTypes) conformanceByType.set(type.fullName, type);

	const protocolByFullName = new Map<string, SwiftProtocol>();
	for (const protocol of data.protocols) protocolByFullName.set(protocol.fullName, protocol);

	const typesByModule = new Map<string, number>();
	for (const type of allTypes) {
		const module = type.module || "";
		typesByModule.set(module, (typesByModule.get(module) ?? 0) + 1);
	}
	const modules = [...typesByModule.keys()].sort((a, b) => {
		if (a === "") return 1;
		if (b === "") return -1;
		return a.localeCompare(b);
	});

	let kindFilter: KindFilter = "all";
	let moduleFilter = "";
	let hideModulePrefix = loadHideModulePrefix();
	let filteredTypes = allTypes;
	let selectedType: SwiftType | null = null;
	let selectedProtocol: SwiftProtocol | null = null;
	let selectedIndex = -1;
	const xbin = createCrossBinaryState();

	// ── Stats ──
	const statsBar = document.createElement("div");
	statsBar.className = "cls-stats-bar";
	const stats = document.createElement("div");
	stats.className = "cls-stats";
	const external = data.unresolvedConformances;
	stats.textContent =
		`${formatCount(allTypes.length, "type")} \u00B7 ` +
		`${formatCount(countByKind(allTypes, "class"), "class", "classes")} \u00B7 ` +
		`${formatCount(countByKind(allTypes, "struct"), "struct")} \u00B7 ` +
		`${formatCount(countByKind(allTypes, "enum"), "enum")} \u00B7 ` +
		`${formatCount(data.protocols.length, "protocol")} \u00B7 ` +
		`${formatCount(allConformances.length, "conformance")}`;
	if (external > 0) {
		stats.title = `${formatCount(external, "additional conformance record")} ${
			external === 1 ? "references" : "reference"
		} protocols in other images and cannot be resolved offline.`;
	}
	statsBar.appendChild(stats);
	container.appendChild(statsBar);

	// ── Panels ──
	const wrapper = document.createElement("div");
	wrapper.className = "cls-panels";
	container.appendChild(wrapper);

	const leftPanel = document.createElement("div");
	leftPanel.className = "cls-left";
	wrapper.appendChild(leftPanel);

	const leftHandle = document.createElement("div");
	leftHandle.className = "cls-resize-handle";
	wrapper.appendChild(leftHandle);

	const rightPanel = document.createElement("div");
	rightPanel.className = "cls-right";
	wrapper.appendChild(rightPanel);

	/** Minimum width the detail panel is allowed to shrink to. */
	const MIN_DETAIL = 360;

	function leftPanelMax(): number {
		// ~10px accounts for the resize handles
		return Math.max(180, wrapper.getBoundingClientRect().width - MIN_DETAIL - 10);
	}

	initPanelResize(leftHandle, () => leftPanel, {
		side: "left",
		max: leftPanelMax,
		storageKey: "panels:swift:left",
		activeClass: "cls-resize-handle--active"
	});

	// Re-clamp the list when the container resizes (e.g. window resize)
	new ResizeObserver(() => {
		const max = leftPanelMax();
		if (leftPanel.getBoundingClientRect().width > max) {
			leftPanel.style.width = `${max}px`;
		}
	}).observe(wrapper);

	// ── Search ──
	const searchBar = new SearchBar((term, isRegex, caseSensitive) => {
		if (xbin.active) {
			doCrossBinarySearch(
				sessionId,
				term,
				"swift",
				xbin,
				() => {
					if (!xbin.active) return;
					searchBar.updateCount(xbin.results.length, xbin.results.length);
					renderList();
				},
				isRegex,
				caseSensitive
			);
			return;
		}
		filterTerm = term;
		filterRegex = isRegex;
		filterCase = caseSensitive;
		saveSearchState(sessionId, "swift", term, isRegex);
		applyFilters();
	});
	searchBar.mount(leftPanel);
	registerSearchBar(sessionId, "swift", searchBar);

	addAllBinariesToggle(searchBar, binaryCount, xbin, (active) => {
		updateFilterBarDisabled();
		if (!active) selectedIndex = selectedType ? filteredTypes.indexOf(selectedType) : -1;
		else selectedIndex = -1;
		searchBar.setValue(
			searchBar.getValue(),
			searchBar.isRegexMode(),
			searchBar.isCaseSensitive()
		);
	});

	// ── Filters ──
	const filterBar = document.createElement("div");
	filterBar.className = "swift-filter-bar";
	leftPanel.appendChild(filterBar);

	const kindButtons: HTMLButtonElement[] = [];
	for (const filter of KIND_FILTERS) {
		const button = document.createElement("button");
		button.className = "swift-filter-btn";
		button.textContent = filter.label;
		button.classList.toggle("swift-filter-btn--active", filter.id === "all");
		button.addEventListener("click", () => {
			kindFilter = filter.id;
			for (const btn of kindButtons) {
				btn.classList.toggle("swift-filter-btn--active", btn === button);
			}
			applyFilters();
		});
		kindButtons.push(button);
		filterBar.appendChild(button);
	}

	const moduleSelect = document.createElement("select");
	moduleSelect.className = "swift-module-select";
	moduleSelect.title = "Filter by Swift module";
	const allOption = document.createElement("option");
	allOption.value = "";
	allOption.textContent = "All modules";
	moduleSelect.appendChild(allOption);
	for (const module of modules) {
		const option = document.createElement("option");
		option.value = module;
		const label = module || "(no module)";
		const isMain =
			mainModuleName !== "" && module.toLowerCase() === mainModuleName.toLowerCase();
		option.textContent = `${label} (${typesByModule.get(module) ?? 0})${
			isMain ? "\u00A0\u00A0[Main]" : ""
		}`;
		moduleSelect.appendChild(option);
	}
	const prefixToggle = document.createElement("button");
	prefixToggle.type = "button";
	prefixToggle.className = "swift-filter-btn swift-prefix-toggle";
	prefixToggle.addEventListener("click", () => {
		if (!moduleFilter) return;
		hideModulePrefix = !hideModulePrefix;
		saveHideModulePrefix(hideModulePrefix);
		updatePrefixToggle();
		renderVisibleRows();
	});

	function updatePrefixToggle(): void {
		const hidePrefix = hideModulePrefix && moduleFilter !== "";
		prefixToggle.disabled = xbin.active || moduleFilter === "";
		prefixToggle.textContent = "Hide prefix";
		prefixToggle.classList.toggle("swift-filter-btn--active", hidePrefix);
		prefixToggle.title = hidePrefix
			? "Show the selected module name in type names"
			: moduleFilter
				? "Hide the selected module name from type names"
				: "Select a module to hide its name prefix";
	}

	function updateFilterBarDisabled(): void {
		for (const btn of kindButtons) btn.disabled = xbin.active;
		moduleSelect.disabled = xbin.active;
		updatePrefixToggle();
	}

	moduleSelect.addEventListener("change", () => {
		moduleFilter = moduleSelect.value;
		updatePrefixToggle();
		applyFilters();
	});
	const moduleGroup = document.createElement("div");
	moduleGroup.className = "swift-module-group";
	moduleGroup.appendChild(prefixToggle);
	moduleGroup.appendChild(moduleSelect);
	filterBar.appendChild(moduleGroup);
	updatePrefixToggle();

	// ── Type list ──
	const scrollContainer = document.createElement("div");
	scrollContainer.className = "cls-scroll";
	scrollContainer.tabIndex = 0;
	leftPanel.appendChild(scrollContainer);

	const spacer = document.createElement("div");
	spacer.className = "cls-spacer";
	scrollContainer.appendChild(spacer);

	const rowContainer = document.createElement("div");
	rowContainer.className = "cls-rows";
	scrollContainer.appendChild(rowContainer);

	let filterTerm = "";
	let filterRegex = false;
	let filterCase = false;

	function buildMatcher(): ((value: string) => boolean) | null {
		if (!filterTerm) return null;
		try {
			if (filterRegex) {
				const re = new RegExp(filterTerm, filterCase ? "" : "i");
				return (value) => re.test(value);
			}
			if (filterCase) return (value) => value.includes(filterTerm);
			const lower = filterTerm.toLowerCase();
			return (value) => value.toLowerCase().includes(lower);
		} catch {
			return null;
		}
	}

	function listTypeName(fullName: string): string {
		if (!hideModulePrefix || !moduleFilter) return fullName;
		const prefix = `${moduleFilter}.`;
		return fullName.startsWith(prefix) ? fullName.slice(prefix.length) : fullName;
	}

	function applyFilters(): void {
		const matcher = buildMatcher();
		filteredTypes = allTypes.filter((type) => {
			if (kindFilter !== "all" && type.kind !== kindFilter) return false;
			if (moduleFilter && type.module !== moduleFilter) return false;
			return matcher ? matcher(type.fullName) : true;
		});
		searchBar.updateCount(filteredTypes.length, allTypes.length);
		if (selectedType) {
			const index = filteredTypes.indexOf(selectedType);
			if (index === -1) {
				selectedType = null;
				selectedIndex = -1;
			} else {
				selectedIndex = index;
			}
		}
		renderList();
		renderDetail();
	}

	function renderList(): void {
		const rowHeight = xbin.active ? CROSS_ROW_HEIGHT : ROW_HEIGHT;
		const total = xbin.active ? xbin.results.length : filteredTypes.length;
		spacer.style.height = `${total * rowHeight}px`;
		renderVisibleRows();
	}

	function renderCrossBinaryRows(): void {
		if (xbin.loading) {
			rowContainer.innerHTML = "";
			rowContainer.style.transform = "";
			const loading = document.createElement("div");
			loading.className = "cls-cross-loading";
			loading.textContent = "Indexing binaries\u2026";
			rowContainer.appendChild(loading);
			return;
		}

		if (xbin.results.length === 0) {
			rowContainer.innerHTML = "";
			rowContainer.style.transform = "";
			const hint = document.createElement("div");
			hint.className = "cls-cross-loading";
			if (searchBar.getValue()) {
				hint.textContent = "No Swift types found across binaries.";
			} else {
				hint.textContent = "Type a Swift type name to search across all binaries.";
				const showAll = buildShowAllLink(sessionId, "Swift types", "swift", xbin, () => {
					searchBar.updateCount(xbin.results.length, xbin.results.length);
					renderList();
				});
				hint.appendChild(document.createElement("br"));
				hint.appendChild(showAll);
			}
			rowContainer.appendChild(hint);
			return;
		}

		const scrollTop = scrollContainer.scrollTop;
		const viewportHeight = scrollContainer.clientHeight;
		const total = xbin.results.length;
		const startIndex = Math.max(0, Math.floor(scrollTop / CROSS_ROW_HEIGHT) - BUFFER);
		const visibleCount = Math.ceil(viewportHeight / CROSS_ROW_HEIGHT);
		const endIndex = Math.min(total, startIndex + visibleCount + BUFFER * 2);

		rowContainer.style.transform = `translateY(${startIndex * CROSS_ROW_HEIGHT}px)`;

		const fragment = document.createDocumentFragment();
		for (let i = startIndex; i < endIndex; i++) {
			const result = xbin.results[i];
			if (!result) continue;

			const row = document.createElement("div");
			row.className = "cls-row cls-cross-row";
			if (i === selectedIndex) row.classList.add("cls-row-active");
			row.style.height = `${CROSS_ROW_HEIGHT}px`;
			row.title = `${result.match} in ${result.binaryName}`;

			const nameSpan = document.createElement("span");
			nameSpan.className = "cls-cross-name";
			nameSpan.textContent = result.match;
			row.appendChild(nameSpan);

			const binSpan = document.createElement("span");
			binSpan.className = "cls-cross-binary";
			binSpan.textContent = `${result.binaryName}  [${binaryTypeBadge(result.binaryType)}]`;
			row.appendChild(binSpan);

			row.addEventListener("click", () => activateCrossResult(i));
			fragment.appendChild(row);
		}
		rowContainer.innerHTML = "";
		rowContainer.appendChild(fragment);
	}

	function activateCrossResult(index: number): void {
		const result = xbin.results[index];
		if (!result) return;
		const dropdown = document.getElementById("binary-dropdown") as HTMLSelectElement | null;
		const sameBinary = !dropdown || dropdown.value === String(result.binaryIndex);

		if (sameBinary) {
			const type = allTypes.find((t) => t.fullName === result.match);
			if (!type) return;
			xbin.active = false;
			leftPanel
				.querySelector(".sb-extra-toggle--active")
				?.classList.remove("sb-extra-toggle--active");
			// Reset filters so the selected type cannot be filtered out of the list.
			kindFilter = "all";
			moduleFilter = "";
			for (const [i, btn] of kindButtons.entries()) {
				btn.classList.toggle("swift-filter-btn--active", KIND_FILTERS[i]?.id === "all");
			}
			moduleSelect.value = "";
			updateFilterBarDisabled();
			searchBar.setValue("", false);
			filterTerm = "";
			filterRegex = false;
			filterCase = false;
			applyFilters();
			selectType(type);
			const idx = filteredTypes.indexOf(type);
			selectedIndex = idx;
			if (idx >= 0) scrollContainer.scrollTop = idx * ROW_HEIGHT;
			renderVisibleRows();
		} else if (dropdown) {
			pendingSwiftSelect = result.match;
			dropdown.value = String(result.binaryIndex);
			dropdown.dispatchEvent(new Event("change", { bubbles: true }));
		}
	}

	function renderVisibleRows(): void {
		if (xbin.active) {
			renderCrossBinaryRows();
			return;
		}

		const scrollTop = scrollContainer.scrollTop;
		const viewportHeight = scrollContainer.clientHeight;
		const total = filteredTypes.length;
		const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - BUFFER);
		const visibleCount = Math.ceil(viewportHeight / ROW_HEIGHT);
		const endIndex = Math.min(total, startIndex + visibleCount + BUFFER * 2);

		rowContainer.style.transform = `translateY(${startIndex * ROW_HEIGHT}px)`;

		const fragment = document.createDocumentFragment();
		for (let i = startIndex; i < endIndex; i++) {
			const type = filteredTypes[i];
			if (!type) continue;

			const row = document.createElement("div");
			row.className = "cls-row swift-row";
			if (selectedType === type) row.classList.add("cls-row-active");
			row.style.height = `${ROW_HEIGHT}px`;
			row.title = type.fullName;

			const badge = document.createElement("span");
			badge.className = `swift-kind-badge swift-kind-${type.kind}`;
			badge.textContent = KIND_BADGE[type.kind];
			row.appendChild(badge);

			const name = document.createElement("span");
			name.className = "swift-row-name";
			name.textContent = listTypeName(type.fullName);
			row.appendChild(name);

			const meta = document.createElement("span");
			meta.className = "swift-row-meta";
			meta.textContent = type.fieldCount > 0 ? String(type.fieldCount) : "";
			meta.title = type.fieldCount > 0 ? formatCount(type.fieldCount, "field") : "";
			row.appendChild(meta);

			row.addEventListener("click", () => {
				selectedIndex = i;
				selectType(type);
			});

			fragment.appendChild(row);
		}
		rowContainer.innerHTML = "";
		rowContainer.appendChild(fragment);
	}

	let rafId = 0;
	scrollContainer.addEventListener(
		"scroll",
		() => {
			if (rafId) return;
			rafId = requestAnimationFrame(() => {
				rafId = 0;
				renderVisibleRows();
			});
		},
		{ passive: true }
	);

	// ── Detail panel ──
	const detailHeader = document.createElement("div");
	detailHeader.className = "cls-detail-header";
	rightPanel.appendChild(detailHeader);

	const detailScroll = document.createElement("div");
	detailScroll.className = "cls-method-scroll swift-detail-scroll";
	rightPanel.appendChild(detailScroll);

	function renderDetail(): void {
		detailHeader.innerHTML = "";
		detailScroll.innerHTML = "";

		if (selectedProtocol) {
			renderProtocolDetail(selectedProtocol);
			return;
		}

		if (!selectedType) {
			const hint = document.createElement("div");
			hint.className = "cls-detail-hint";
			hint.textContent =
				"Select a Swift type to inspect its stored properties and conformances";
			detailScroll.appendChild(hint);
			return;
		}

		const type = selectedType;

		const heading = document.createElement("h3");
		heading.className = "cls-detail-name swift-detail-name";
		const badge = document.createElement("span");
		badge.className = `swift-kind-badge swift-kind-${type.kind}`;
		badge.textContent = KIND_BADGE[type.kind];
		heading.appendChild(badge);
		heading.appendChild(document.createTextNode(type.fullName));
		detailHeader.appendChild(heading);

		const meta = document.createElement("div");
		meta.className = "cls-detail-count";
		const parts = [KIND_LABEL[type.kind], type.module || "(no module)"];
		if (type.generic) parts.push("generic");
		meta.textContent = parts.join(" \u00B7 ");
		detailHeader.appendChild(meta);

		if (type.superclass) {
			const superLine = document.createElement("div");
			superLine.className = "swift-superclass";
			const label = document.createElement("span");
			label.className = "swift-superclass-label";
			label.textContent = "Inherits:";
			superLine.appendChild(label);
			const value = document.createElement("span");
			value.className = "swift-superclass-value";
			value.textContent = type.superclass;
			superLine.appendChild(value);
			detailHeader.appendChild(superLine);
		}

		if (type.protocols.length > 0) {
			const protoLine = document.createElement("div");
			protoLine.className = "cls-detail-protos";
			const label = document.createElement("span");
			label.className = "cls-detail-protos-label";
			label.textContent = "Conforms to:";
			protoLine.appendChild(label);
			for (const protocolName of type.protocols) {
				const protoBadge = document.createElement("span");
				protoBadge.className = "cls-proto-badge";
				protoBadge.textContent = protocolName;
				protoBadge.title = `View ${protocolName}`;
				protoBadge.addEventListener("click", () => {
					const protocol = protocolByFullName.get(protocolName);
					if (protocol) selectProtocol(protocol);
				});
				protoLine.appendChild(protoBadge);
			}
			detailHeader.appendChild(protoLine);
		}

		const fieldsTitle = document.createElement("div");
		fieldsTitle.className = "swift-section-title";
		fieldsTitle.textContent =
			type.kind === "enum"
				? `${plural(type.fields.length, "Case")} (${type.fields.length})`
				: `${plural(type.fields.length, "Stored Property", "Stored Properties")} (${type.fields.length})`;
		detailScroll.appendChild(fieldsTitle);

		if (type.fields.length === 0) {
			const none = document.createElement("div");
			none.className = "swift-empty-line";
			none.textContent = type.kind === "enum" ? "No enum cases." : "No stored properties.";
			detailScroll.appendChild(none);
		} else {
			const list = document.createElement("div");
			list.className = "swift-field-list";
			for (const field of type.fields) {
				const row = document.createElement("div");
				row.className = "swift-field-row";
				const fieldName = document.createElement("span");
				fieldName.className = "swift-field-name";
				fieldName.textContent = field.name;
				row.appendChild(fieldName);

				const fieldType = document.createElement("span");
				fieldType.className = "swift-field-type";
				fieldType.textContent = field.type ?? "";
				row.appendChild(fieldType);

				if (field.indirect) {
					const indirect = document.createElement("span");
					indirect.className = "swift-field-indirect";
					indirect.textContent = "indirect";
					row.appendChild(indirect);
				}

				row.title = field.type ? `${field.name}: ${field.type}` : field.name;
				row.addEventListener("dblclick", () => {
					copyText(
						field.type ? `${field.name}: ${field.type}` : field.name,
						"Copied field"
					);
				});
				list.appendChild(row);
			}
			detailScroll.appendChild(list);
		}

		const prefix = `${type.fullName}.`;
		const nested = allTypes.filter(
			(candidate) =>
				candidate.fullName.startsWith(prefix) &&
				!candidate.fullName.slice(prefix.length).includes(".")
		);
		if (nested.length > 0) {
			const nestedTitle = document.createElement("div");
			nestedTitle.className = "swift-section-title";
			nestedTitle.textContent = `${plural(nested.length, "Nested Type")} (${nested.length})`;
			detailScroll.appendChild(nestedTitle);

			const nestedList = document.createElement("div");
			nestedList.className = "swift-nested-list";
			for (const child of nested) {
				const item = document.createElement("button");
				item.className = "swift-nested-item";
				const childBadge = document.createElement("span");
				childBadge.className = `swift-kind-badge swift-kind-${child.kind}`;
				childBadge.textContent = KIND_BADGE[child.kind];
				item.appendChild(childBadge);
				item.appendChild(document.createTextNode(child.name));
				item.addEventListener("click", () => {
					selectedType = child;
					selectedProtocol = null;
					clearProtocolHighlight();
					renderDetail();
				});
				nestedList.appendChild(item);
			}
			detailScroll.appendChild(nestedList);
		}
	}

	function renderProtocolDetail(protocol: SwiftProtocol): void {
		const heading = document.createElement("h3");
		heading.className = "cls-detail-name swift-detail-name";
		const badge = document.createElement("span");
		badge.className = "swift-kind-badge swift-kind-protocol";
		badge.textContent = "P";
		heading.appendChild(badge);
		heading.appendChild(document.createTextNode(protocol.fullName));
		detailHeader.appendChild(heading);

		const meta = document.createElement("div");
		meta.className = "cls-detail-count";
		meta.textContent =
			`protocol \u00B7 ${protocol.module || "(no module)"} \u00B7 ` +
			`${protocol.requirementCount.toLocaleString()} ${plural(protocol.requirementCount, "requirement")}`;
		detailHeader.appendChild(meta);

		const title = document.createElement("div");
		title.className = "swift-section-title";
		title.textContent = `${plural(protocol.conformingTypes.length, "Conforming Type")} (${protocol.conformingTypes.length})`;
		detailScroll.appendChild(title);

		if (protocol.conformingTypes.length === 0) {
			const none = document.createElement("div");
			none.className = "swift-empty-line";
			none.textContent = "No in-binary conforming types were resolved.";
			detailScroll.appendChild(none);
			return;
		}

		const list = document.createElement("div");
		list.className = "swift-nested-list";
		for (const typeName of protocol.conformingTypes) {
			const type = conformanceByType.get(typeName);
			const item = document.createElement("button");
			item.className = "swift-nested-item";
			if (type) {
				const typeBadge = document.createElement("span");
				typeBadge.className = `swift-kind-badge swift-kind-${type.kind}`;
				typeBadge.textContent = KIND_BADGE[type.kind];
				item.appendChild(typeBadge);
			}
			item.appendChild(document.createTextNode(typeName));
			if (type) {
				item.addEventListener("click", () => {
					selectedType = type;
					selectedProtocol = null;
					clearProtocolHighlight();
					renderDetail();
				});
			}
			list.appendChild(item);
		}
		detailScroll.appendChild(list);
	}

	function selectType(type: SwiftType): void {
		selectedType = type;
		selectedProtocol = null;
		clearProtocolHighlight();
		renderDetail();
		renderVisibleRows();
	}

	function selectProtocol(protocol: SwiftProtocol): void {
		selectedProtocol = protocol;
		selectedType = null;
		selectedIndex = -1;
		highlightProtocol(protocol.fullName);
		renderVisibleRows();
		renderDetail();
	}

	// ── Protocol list ──
	let protocolExpanded = false;
	let protocolHeader: HTMLButtonElement | null = null;
	let protocolList: HTMLDivElement | null = null;
	let protocolItemsBuilt = false;
	const protocolItems = new Map<string, HTMLDivElement>();

	function buildProtocolItems(): void {
		if (protocolItemsBuilt || !protocolList) return;
		protocolItemsBuilt = true;
		for (const protocol of data!.protocols) {
			const item = document.createElement("div");
			item.className = "cls-proto-item";
			item.textContent = protocol.fullName;
			item.title = `${protocol.fullName} \u2014 ${formatCount(protocol.conformingTypes.length, "conforming type")}`;
			item.addEventListener("click", () => selectProtocol(protocol));
			protocolList.appendChild(item);
			protocolItems.set(protocol.fullName, item);
		}
		if (selectedProtocol) {
			protocolItems.get(selectedProtocol.fullName)?.classList.add("cls-proto-item-active");
		}
	}

	function highlightProtocol(fullName: string): void {
		for (const [name, el] of protocolItems) {
			el.classList.toggle("cls-proto-item-active", name === fullName);
		}
	}

	function clearProtocolHighlight(): void {
		for (const el of protocolItems.values()) {
			el.classList.remove("cls-proto-item-active");
		}
	}

	if (data.protocols.length > 0) {
		const section = document.createElement("div");
		section.className = "cls-proto-section";

		protocolHeader = document.createElement("button");
		protocolHeader.className = "cls-proto-header";
		protocolHeader.textContent = `\u25B6 ${plural(data.protocols.length, "Protocol")} (${data.protocols.length})`;

		protocolList = document.createElement("div");
		protocolList.className = "cls-proto-list";
		protocolList.style.display = "none";

		protocolHeader.addEventListener("click", () => {
			protocolExpanded = !protocolExpanded;
			buildProtocolItems();
			protocolHeader!.textContent = `${protocolExpanded ? "\u25BC" : "\u25B6"} ${plural(data!.protocols.length, "Protocol")} (${data!.protocols.length})`;
			protocolList!.style.display = protocolExpanded ? "block" : "none";
		});

		section.appendChild(protocolHeader);
		section.appendChild(protocolList);
		leftPanel.appendChild(section);
	}

	// ── Keyboard navigation ──
	function listLength(): number {
		return xbin.active ? xbin.results.length : filteredTypes.length;
	}

	function setSelection(next: number): void {
		const total = listLength();
		if (total === 0) return;
		const index = Math.max(0, Math.min(total - 1, next));
		selectedIndex = index;
		const type = xbin.active ? null : filteredTypes[index];
		if (!xbin.active && !type) return;

		const rowHeight = xbin.active ? CROSS_ROW_HEIGHT : ROW_HEIGHT;
		const top = index * rowHeight;
		const bottom = top + rowHeight;
		if (top < scrollContainer.scrollTop) {
			scrollContainer.scrollTop = top;
		} else if (bottom > scrollContainer.scrollTop + scrollContainer.clientHeight) {
			scrollContainer.scrollTop = bottom - scrollContainer.clientHeight;
		}

		if (type) selectType(type);
		else renderVisibleRows();
	}

	function moveSelection(delta: number): void {
		const total = listLength();
		if (total === 0) return;
		if (selectedIndex === -1) {
			setSelection(delta > 0 ? 0 : total - 1);
			return;
		}
		let next = selectedIndex + delta;
		if (next < 0) next = total - 1;
		if (next >= total) next = 0;
		setSelection(next);
	}

	scrollContainer.addEventListener("keydown", (event: KeyboardEvent) => {
		if (listLength() === 0) return;
		const rowHeight = xbin.active ? CROSS_ROW_HEIGHT : ROW_HEIGHT;
		switch (event.key) {
			case "Enter":
				if (xbin.active && selectedIndex >= 0) {
					event.preventDefault();
					activateCrossResult(selectedIndex);
				}
				break;
			case "ArrowDown":
				event.preventDefault();
				moveSelection(1);
				break;
			case "ArrowUp":
				event.preventDefault();
				moveSelection(-1);
				break;
			case "Home":
				event.preventDefault();
				setSelection(0);
				break;
			case "End":
				event.preventDefault();
				setSelection(listLength() - 1);
				break;
			case "PageDown": {
				event.preventDefault();
				const page = Math.max(1, Math.floor(scrollContainer.clientHeight / rowHeight));
				moveSelection(page);
				break;
			}
			case "PageUp": {
				event.preventDefault();
				const page = Math.max(1, Math.floor(scrollContainer.clientHeight / rowHeight));
				moveSelection(-page);
				break;
			}
		}
	});

	searchBar.onEscape = () => scrollContainer.focus();

	// Restore saved search state
	const saved = getSearchState(sessionId, "swift");
	if (saved?.term) {
		searchBar.setValue(saved.term, saved.isRegex);
	} else {
		searchBar.updateCount(allTypes.length, allTypes.length);
	}

	renderList();
	renderDetail();

	// Pending selection from a cross-binary click on a different binary.
	if (pendingSwiftSelect) {
		const type = allTypes.find((t) => t.fullName === pendingSwiftSelect);
		pendingSwiftSelect = null;
		if (type) {
			selectedIndex = filteredTypes.indexOf(type);
			selectType(type);
			if (selectedIndex >= 0) {
				// Defer so the jump wins over the tab's stored scroll restoration.
				const top = selectedIndex * ROW_HEIGHT;
				requestAnimationFrame(() => {
					scrollContainer.scrollTop = top;
				});
			}
		}
	}
}
