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

const ROW_HEIGHT = 28;
const BUFFER = 20;

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
	binary?: BinaryInfo
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

	// ── Stats ──
	const statsBar = document.createElement("div");
	statsBar.className = "cls-stats-bar";
	const stats = document.createElement("div");
	stats.className = "cls-stats";
	const external = data.unresolvedConformances;
	stats.textContent =
		`${allTypes.length.toLocaleString()} types \u00B7 ` +
		`${countByKind(allTypes, "class").toLocaleString()} classes \u00B7 ` +
		`${countByKind(allTypes, "struct").toLocaleString()} structs \u00B7 ` +
		`${countByKind(allTypes, "enum").toLocaleString()} enums \u00B7 ` +
		`${data.protocols.length.toLocaleString()} protocols \u00B7 ` +
		`${allConformances.length.toLocaleString()} conformances`;
	if (external > 0) {
		stats.title = `${external.toLocaleString()} additional conformance records reference protocols in other images and cannot be resolved offline.`;
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

	const rightPanel = document.createElement("div");
	rightPanel.className = "cls-right";
	wrapper.appendChild(rightPanel);

	// ── Search ──
	const searchBar = new SearchBar((term, isRegex, caseSensitive) => {
		filterTerm = term;
		filterRegex = isRegex;
		filterCase = caseSensitive;
		saveSearchState(sessionId, "swift", term, isRegex);
		applyFilters();
	});
	searchBar.mount(leftPanel);
	registerSearchBar(sessionId, "swift", searchBar);

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
		prefixToggle.disabled = moduleFilter === "";
		prefixToggle.textContent = "Hide prefix";
		prefixToggle.classList.toggle("swift-filter-btn--active", hidePrefix);
		prefixToggle.title = hidePrefix
			? "Show the selected module name in type names"
			: moduleFilter
				? "Hide the selected module name from type names"
				: "Select a module to hide its name prefix";
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
		spacer.style.height = `${filteredTypes.length * ROW_HEIGHT}px`;
		renderVisibleRows();
	}

	function renderVisibleRows(): void {
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
			meta.title = type.fieldCount > 0 ? `${type.fieldCount} fields` : "";
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
				? `Cases (${type.fields.length})`
				: `Stored Properties (${type.fields.length})`;
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
			nestedTitle.textContent = `Nested Types (${nested.length})`;
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
			`${protocol.requirementCount.toLocaleString()} requirement${protocol.requirementCount === 1 ? "" : "s"}`;
		detailHeader.appendChild(meta);

		const title = document.createElement("div");
		title.className = "swift-section-title";
		title.textContent = `Conforming Types (${protocol.conformingTypes.length})`;
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
			item.title = `${protocol.fullName} \u2014 ${protocol.conformingTypes.length} conforming type(s)`;
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
		protocolHeader.textContent = `\u25B6 Protocols (${data.protocols.length})`;

		protocolList = document.createElement("div");
		protocolList.className = "cls-proto-list";
		protocolList.style.display = "none";

		protocolHeader.addEventListener("click", () => {
			protocolExpanded = !protocolExpanded;
			buildProtocolItems();
			protocolHeader!.textContent = `${protocolExpanded ? "\u25BC" : "\u25B6"} Protocols (${data!.protocols.length})`;
			protocolList!.style.display = protocolExpanded ? "block" : "none";
		});

		section.appendChild(protocolHeader);
		section.appendChild(protocolList);
		leftPanel.appendChild(section);
	}

	// ── Keyboard navigation ──
	function setSelection(next: number): void {
		const total = filteredTypes.length;
		if (total === 0) return;
		const index = Math.max(0, Math.min(total - 1, next));
		selectedIndex = index;
		const type = filteredTypes[index];
		if (!type) return;

		const top = index * ROW_HEIGHT;
		const bottom = top + ROW_HEIGHT;
		if (top < scrollContainer.scrollTop) {
			scrollContainer.scrollTop = top;
		} else if (bottom > scrollContainer.scrollTop + scrollContainer.clientHeight) {
			scrollContainer.scrollTop = bottom - scrollContainer.clientHeight;
		}

		selectType(type);
	}

	function moveSelection(delta: number): void {
		const total = filteredTypes.length;
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
		if (filteredTypes.length === 0) return;
		switch (event.key) {
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
				setSelection(filteredTypes.length - 1);
				break;
			case "PageDown": {
				event.preventDefault();
				const page = Math.max(1, Math.floor(scrollContainer.clientHeight / ROW_HEIGHT));
				moveSelection(page);
				break;
			}
			case "PageUp": {
				event.preventDefault();
				const page = Math.max(1, Math.floor(scrollContainer.clientHeight / ROW_HEIGHT));
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
}
