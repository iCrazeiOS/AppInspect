/**
 * Objective-C tab: three-panel layout — class/category/protocol list on the left,
 * a member list (properties, instance variables, instance + class methods) in the
 * middle, and a member detail sidebar on the right.
 */

import { EmptyState, SearchBar } from "../components";
import { showToast } from "../components/toast";
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
import { highlightLogos, highlightObjCMethod } from "../utils/highlight";
import { loadWidths } from "../utils/layout-store";
import { generateLogosHook, parseMethodSignature } from "../utils/logos-hook";
import { initPanelResize } from "../utils/panel-resize";

interface ObjCMethod {
	selector: string;
	signature: string;
	_isClassMethod?: boolean;
}

interface ObjCProperty {
	name: string;
	type: string;
	attributes: string;
	attributeList: string[];
	ivar?: string;
}

interface ObjCIvar {
	name: string;
	type: string;
	offset: number;
}

interface ObjCClass {
	name: string;
	superclass?: string;
	methods: ObjCMethod[];
	protocols?: string[];
	properties?: ObjCProperty[];
	ivars?: ObjCIvar[];
}

interface ObjCCategory {
	name: string;
	className: string;
	methods: ObjCMethod[];
	properties: ObjCProperty[];
	protocols: string[];
}

interface ObjCProtocol {
	name: string;
	instanceMethods: ObjCMethod[];
	classMethods: ObjCMethod[];
	optionalInstanceMethods: ObjCMethod[];
	optionalClassMethods: ObjCMethod[];
}

interface ObjCData {
	classes: ObjCClass[];
	categories: ObjCCategory[];
	protocols: string[];
	protocolDetails: ObjCProtocol[];
}

/** A property or ivar selected in the detail list, shown in the sidebar. */
type SelectedMember =
	| { kind: "property"; property: ObjCProperty; owner: string }
	| { kind: "ivar"; ivar: ObjCIvar; owner: string };

const ROW_HEIGHT = 28;
const BUFFER = 20;

/** Set externally (e.g. by cross-binary click) to auto-select a class after render. */
let pendingClassSelect: string | null = null;

// ── Main render ──

export function renderObjC(
	container: HTMLElement,
	data: ObjCData | null,
	binaryCount: number = 1,
	sessionId: string = ""
): void {
	container.innerHTML = "";
	container.classList.add("cls-container");

	const objcData = data;
	if (
		!objcData ||
		(!objcData.classes?.length && !objcData.categories?.length && !objcData.protocols?.length)
	) {
		const empty = new EmptyState({
			icon: "\u{1F3D7}",
			message:
				"No Objective-C classes, categories, or protocols defined in this binary. " +
				"Hook tweaks that only call into existing classes define none of their own."
		});
		empty.mount(container);
		return;
	}

	const allClasses = [...(objcData.classes ?? [])].sort((a, b) => a.name.localeCompare(b.name));
	const allCategories = [...(objcData.categories ?? [])].sort((a, b) =>
		`${a.className}+${a.name}`.localeCompare(`${b.className}+${b.name}`)
	);
	const allProtocols = [...(objcData.protocols ?? [])].sort((a, b) => a.localeCompare(b));
	const protocolDetailsMap = new Map<string, ObjCProtocol>();
	for (const p of objcData.protocolDetails ?? []) {
		protocolDetailsMap.set(p.name, p);
	}
	let filteredClasses = allClasses;
	let selectedClass: ObjCClass | null = null;
	let selectedMethod: ObjCMethod | null = null;
	let selectedMember: SelectedMember | null = null;
	let selectedClassIndex = -1;
	let selectedProtocol: ObjCProtocol | null = null;
	let selectedProtoMethod: { method: ObjCMethod; isClassMethod: boolean } | null = null;
	let selectedCategory: ObjCCategory | null = null;
	/** Member-group titles (e.g. "Properties") the user has collapsed; persists across re-renders. */
	const collapsedGroups = new Set<string>();

	/** Stable key for a category (className+name), used for nav + highlighting. */
	const categoryKey = (c: ObjCCategory): string => `${c.className}+${c.name}`;

	// Navigation history
	type NavState =
		| { type: "class"; name: string }
		| { type: "protocol"; name: string }
		| { type: "category"; name: string };
	const navHistory: NavState[] = [];
	let navIndex = -1;
	let isNavigating = false; // Prevent history push during back/forward

	// ── Cross-binary search state ──
	const xbin = createCrossBinaryState();

	// Stats bar with navigation
	const statsBar = document.createElement("div");
	statsBar.className = "cls-stats-bar";
	container.appendChild(statsBar);

	// Navigation buttons
	const navBtns = document.createElement("div");
	navBtns.className = "cls-nav-btns";
	statsBar.appendChild(navBtns);

	const backBtn = document.createElement("button");
	backBtn.className = "cls-nav-btn";
	backBtn.textContent = "\u276E";
	backBtn.title = "Back";
	backBtn.disabled = true;
	navBtns.appendChild(backBtn);

	const forwardBtn = document.createElement("button");
	forwardBtn.className = "cls-nav-btn";
	forwardBtn.textContent = "\u276F";
	forwardBtn.title = "Forward";
	forwardBtn.disabled = true;
	navBtns.appendChild(forwardBtn);

	const stats = document.createElement("div");
	stats.className = "cls-stats";
	const totalMethods = allClasses.reduce((s, c) => s + c.methods.length, 0);
	const statParts = [
		formatCount(allClasses.length, "class", "classes"),
		...(allCategories.length > 0
			? [formatCount(allCategories.length, "category", "categories")]
			: []),
		formatCount(totalMethods, "method"),
		formatCount(allProtocols.length, "protocol")
	];
	stats.textContent = statParts.join(" \u00B7 ");
	statsBar.appendChild(stats);

	const exportBtn = document.createElement("button");
	exportBtn.type = "button";
	exportBtn.className = "cls-export-btn";
	exportBtn.textContent = "Export Headers";
	exportBtn.title =
		"Write .h files for every class, category, and protocol in this binary to a folder";
	exportBtn.addEventListener("click", async () => {
		exportBtn.disabled = true;
		try {
			const result = await window.api.exportHeaders(sessionId);
			if (result.success) {
				showToast(
					`Exported ${formatCount(result.files ?? 0, "header file")} to ${result.path}`,
					"success"
				);
			}
		} catch (err) {
			console.error("[AppInspect] Header export failed:", err);
			showToast("Header export failed", "error");
		} finally {
			exportBtn.disabled = false;
		}
	});
	statsBar.appendChild(exportBtn);

	// Navigation functions
	function updateNavButtons(): void {
		backBtn.disabled = navIndex <= 0;
		forwardBtn.disabled = navIndex >= navHistory.length - 1;
	}

	function pushNav(state: NavState): void {
		if (isNavigating) return;
		// Remove forward history when pushing new state
		if (navIndex < navHistory.length - 1) {
			navHistory.splice(navIndex + 1);
		}
		navHistory.push(state);
		navIndex = navHistory.length - 1;
		updateNavButtons();
	}

	function navigateTo(state: NavState): void {
		isNavigating = true;
		if (state.type === "class") {
			const cls = allClasses.find((c) => c.name === state.name);
			if (cls) {
				const idx = filteredClasses.indexOf(cls);
				selectedClassIndex = idx >= 0 ? idx : -1;
				selectedClass = cls;
				selectedCategory = null;
				selectedMethod = null;
				selectedMember = null;
				selectedProtocol = null;
				selectedProtoMethod = null;
				clearListHighlights();
				renderList();
				renderDetail();
				renderSidebar();
				if (idx >= 0) scrollContainer.scrollTop = idx * ROW_HEIGHT;
			}
		} else if (state.type === "protocol") {
			selectProtocol(state.name);
		} else if (state.type === "category") {
			const cat = allCategories.find((c) => categoryKey(c) === state.name);
			if (cat) selectCategory(cat);
		}
		isNavigating = false;
		updateNavButtons();
	}

	/** Clear active highlighting on protocol and category list items. */
	function clearListHighlights(): void {
		for (const el of protoItems.values()) el.classList.remove("cls-proto-item-active");
		for (const el of categoryItems.values()) el.classList.remove("cls-proto-item-active");
	}

	function goBack(): void {
		if (navIndex > 0) {
			navIndex--;
			navigateTo(navHistory[navIndex]!);
		}
	}

	function goForward(): void {
		if (navIndex < navHistory.length - 1) {
			navIndex++;
			navigateTo(navHistory[navIndex]!);
		}
	}

	backBtn.addEventListener("click", goBack);
	forwardBtn.addEventListener("click", goForward);

	// Mouse button 4/5 for back/forward
	container.addEventListener("mouseup", (e) => {
		if (e.button === 3) {
			// Mouse back button
			e.preventDefault();
			goBack();
		} else if (e.button === 4) {
			// Mouse forward button
			e.preventDefault();
			goForward();
		}
	});

	// Three-panel layout wrapper
	const wrapper = document.createElement("div");
	wrapper.className = "cls-panels";
	container.appendChild(wrapper);

	// ── Left panel ──
	const leftPanel = document.createElement("div");
	leftPanel.className = "cls-left";
	wrapper.appendChild(leftPanel);

	// ── Resize handle: left ↔ middle ──
	const leftHandle = document.createElement("div");
	leftHandle.className = "cls-resize-handle";
	wrapper.appendChild(leftHandle);

	// Search bar
	const searchBar = new SearchBar((term, isRegex, caseSensitive) => {
		if (xbin.active) {
			doCrossBinarySearch(
				sessionId,
				term,
				"objc",
				xbin,
				() => {
					searchBar.updateCount(xbin.results.length, xbin.results.length);
					renderList();
				},
				isRegex,
				caseSensitive
			);
			return;
		}

		selectedClassIndex = -1;
		if (!term) {
			filteredClasses = allClasses;
		} else {
			try {
				const flags = caseSensitive ? "" : "i";
				const re = isRegex ? new RegExp(term, flags) : null;
				if (caseSensitive) {
					filteredClasses = allClasses.filter((c) =>
						re ? re.test(c.name) : c.name.includes(term)
					);
				} else {
					const lower = term.toLowerCase();
					filteredClasses = allClasses.filter((c) =>
						re ? re.test(c.name) : c.name.toLowerCase().includes(lower)
					);
				}
			} catch {
				return;
			}
		}
		saveSearchState(sessionId, "objc", term, isRegex);
		searchBar.updateCount(filteredClasses.length, allClasses.length);
		renderList();
	});
	searchBar.mount(leftPanel);
	registerSearchBar(sessionId, "objc", searchBar);
	searchBar.updateCount(filteredClasses.length, allClasses.length);

	addAllBinariesToggle(searchBar, binaryCount, xbin, () => {
		const t = searchBar.getValue();
		searchBar.setValue(t, searchBar.isRegexMode(), searchBar.isCaseSensitive());
	});

	// Virtual scroll container for class list
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

	const CROSS_ROW_HEIGHT = 44; // taller rows for cross-binary results

	function renderList(): void {
		if (xbin.active) {
			const rh = CROSS_ROW_HEIGHT;
			spacer.style.height = `${xbin.results.length * rh}px`;
		} else {
			spacer.style.height = `${filteredClasses.length * ROW_HEIGHT}px`;
		}
		renderVisibleRows();
	}

	function renderVisibleRows(): void {
		if (xbin.active) {
			renderCrossBinaryRows();
			return;
		}

		const scrollTop = scrollContainer.scrollTop;
		const viewportHeight = scrollContainer.clientHeight;
		const total = filteredClasses.length;

		const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - BUFFER);
		const visibleCount = Math.ceil(viewportHeight / ROW_HEIGHT);
		const endIndex = Math.min(total, startIndex + visibleCount + BUFFER * 2);

		rowContainer.style.transform = `translateY(${startIndex * ROW_HEIGHT}px)`;

		const fragment = document.createDocumentFragment();
		for (let i = startIndex; i < endIndex; i++) {
			const cls = filteredClasses[i];
			if (!cls) continue;
			const row = document.createElement("div");
			row.className = "cls-row";
			if (selectedClass && selectedClass.name === cls.name) {
				row.classList.add("cls-row-active");
			}
			row.style.height = `${ROW_HEIGHT}px`;
			row.textContent = cls.name;
			row.title = cls.name;
			row.addEventListener("click", () => {
				pushNav({ type: "class", name: cls.name });
				selectedClassIndex = i;
				selectedClass = cls;
				selectedCategory = null;
				selectedProtocol = null;
				selectedProtoMethod = null;
				selectedMethod = null;
				selectedMember = null;
				clearListHighlights();
				scrollContainer.focus();
				renderVisibleRows();
				renderDetail();
				renderSidebar();
			});
			fragment.appendChild(row);
		}
		rowContainer.innerHTML = "";
		rowContainer.appendChild(fragment);
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
				hint.textContent = "No classes found across binaries.";
			} else {
				hint.textContent = "Type a class name to search across all binaries.";
				const showAll = buildShowAllLink(sessionId, "classes", "objc", xbin, () => {
					searchBar.updateCount(xbin.results.length, xbin.results.length);
					renderList();
				});
				hint.appendChild(document.createElement("br"));
				hint.appendChild(showAll);
			}
			rowContainer.appendChild(hint);
			return;
		}

		const rh = CROSS_ROW_HEIGHT;
		const scrollTop = scrollContainer.scrollTop;
		const viewportHeight = scrollContainer.clientHeight;
		const total = xbin.results.length;

		const startIndex = Math.max(0, Math.floor(scrollTop / rh) - BUFFER);
		const visibleCount = Math.ceil(viewportHeight / rh);
		const endIndex = Math.min(total, startIndex + visibleCount + BUFFER * 2);

		rowContainer.style.transform = `translateY(${startIndex * rh}px)`;

		const fragment = document.createDocumentFragment();
		for (let i = startIndex; i < endIndex; i++) {
			const result = xbin.results[i];
			if (!result) continue;

			const row = document.createElement("div");
			row.className = "cls-row cls-cross-row";
			row.style.height = `${rh}px`;
			row.title = `${result.match} in ${result.binaryName}`;

			const nameSpan = document.createElement("span");
			nameSpan.className = "cls-cross-name";
			nameSpan.textContent = result.match;
			row.appendChild(nameSpan);

			const binSpan = document.createElement("span");
			binSpan.className = "cls-cross-binary";
			binSpan.textContent = `${result.binaryName}  [${binaryTypeBadge(result.binaryType)}]`;
			row.appendChild(binSpan);

			row.addEventListener("click", () => {
				const dropdown = document.getElementById(
					"binary-dropdown"
				) as HTMLSelectElement | null;
				const sameBinary = !dropdown || dropdown.value === String(result.binaryIndex);

				if (sameBinary) {
					// Same binary — find the class locally, disable xbin mode, select it
					const cls = allClasses.find((c) => c.name === result.match);
					if (cls) {
						xbin.active = false;
						// Visually deactivate the "All" toggle button
						const toggleBtn = leftPanel.querySelector(".sb-extra-toggle--active");
						if (toggleBtn) toggleBtn.classList.remove("sb-extra-toggle--active");
						searchBar.setValue("", false);
						selectedClass = cls;
						selectedMethod = null;
						filteredClasses = allClasses;
						searchBar.updateCount(filteredClasses.length, allClasses.length);
						renderList();
						renderDetail();
						renderSidebar();
						// Scroll the selected class into view
						const idx = filteredClasses.indexOf(cls);
						if (idx >= 0) scrollContainer.scrollTop = idx * ROW_HEIGHT;
					}
				} else if (dropdown) {
					// Different binary — queue the class name, then switch
					pendingClassSelect = result.match;
					dropdown.value = String(result.binaryIndex);
					dropdown.dispatchEvent(new Event("change", { bubbles: true }));
				}
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

	// ── Class list keyboard navigation ──

	function moveClassSelection(delta: number): void {
		const total = xbin.active ? xbin.results.length : filteredClasses.length;
		if (total === 0) return;
		let next = selectedClassIndex + delta;
		if (selectedClassIndex === -1) next = delta > 0 ? 0 : total - 1;
		if (next < 0) next = total - 1;
		if (next >= total) next = 0;
		setClassSelection(next);
	}

	function setClassSelection(index: number): void {
		if (index === selectedClassIndex) return;
		selectedClassIndex = index;

		// Scroll into view
		const rh = xbin.active ? CROSS_ROW_HEIGHT : ROW_HEIGHT;
		const rowTop = index * rh;
		const rowBottom = rowTop + rh;
		const viewTop = scrollContainer.scrollTop;
		const viewBottom = viewTop + scrollContainer.clientHeight;
		if (rowTop < viewTop) {
			scrollContainer.scrollTop = rowTop;
		} else if (rowBottom > viewBottom) {
			scrollContainer.scrollTop = rowBottom - scrollContainer.clientHeight;
		}

		// Auto-select the class on navigation
		if (!xbin.active) {
			const cls = filteredClasses[index];
			if (cls) {
				selectedClass = cls;
				selectedCategory = null;
				selectedProtocol = null;
				selectedProtoMethod = null;
				selectedMethod = null;
				selectedMember = null;
				clearListHighlights();
				renderDetail();
				renderSidebar();
			}
		}

		if (rafId) {
			cancelAnimationFrame(rafId);
			rafId = 0;
		}
		renderVisibleRows();
	}

	scrollContainer.addEventListener("keydown", (e: KeyboardEvent) => {
		const target = e.target as HTMLElement;
		if (
			target.tagName === "INPUT" ||
			target.tagName === "TEXTAREA" ||
			target.tagName === "SELECT"
		)
			return;
		const total = xbin.active ? xbin.results.length : filteredClasses.length;
		if (total === 0) return;

		switch (e.key) {
			case "ArrowDown":
				e.preventDefault();
				moveClassSelection(1);
				break;
			case "ArrowUp":
				e.preventDefault();
				moveClassSelection(-1);
				break;
			case "Home":
				e.preventDefault();
				setClassSelection(0);
				break;
			case "End":
				e.preventDefault();
				setClassSelection(total - 1);
				break;
			case "PageDown": {
				e.preventDefault();
				const rh = xbin.active ? CROSS_ROW_HEIGHT : ROW_HEIGHT;
				const page = Math.floor(scrollContainer.clientHeight / rh);
				moveClassSelection(page);
				break;
			}
			case "PageUp": {
				e.preventDefault();
				const rh = xbin.active ? CROSS_ROW_HEIGHT : ROW_HEIGHT;
				const page = Math.floor(scrollContainer.clientHeight / rh);
				moveClassSelection(-page);
				break;
			}
			case "Enter":
				if (selectedClassIndex >= 0 && !xbin.active) {
					const cls = filteredClasses[selectedClassIndex];
					if (cls) {
						selectedClass = cls;
						selectedCategory = null;
						selectedProtocol = null;
						selectedProtoMethod = null;
						selectedMethod = null;
						selectedMember = null;
						clearListHighlights();
						renderVisibleRows();
						renderDetail();
						renderSidebar();
					}
				}
				break;
		}
	});

	searchBar.onEscape = () => scrollContainer.focus();

	// Restore saved search state (must happen after spacer/rowContainer are created)
	const savedState = getSearchState(sessionId, "objc");
	if (savedState?.term) {
		searchBar.setValue(savedState.term, savedState.isRegex);
	}

	// Protocols collapsible section
	let protoExpanded = false;
	let protoHeader: HTMLButtonElement | null = null;
	let protoList: HTMLDivElement | null = null;
	const protoItems = new Map<string, HTMLDivElement>();

	if (allProtocols.length > 0) {
		const protoSection = document.createElement("div");
		protoSection.className = "cls-proto-section";

		protoHeader = document.createElement("button");
		protoHeader.className = "cls-proto-header";
		protoHeader.textContent = `\u25B6 ${plural(allProtocols.length, "Protocol")} (${allProtocols.length})`;

		protoList = document.createElement("div");
		protoList.className = "cls-proto-list";
		protoList.style.display = "none";

		for (const p of allProtocols) {
			const item = document.createElement("div");
			item.className = "cls-proto-item";
			item.textContent = p;
			item.addEventListener("click", () => selectProtocol(p));
			protoList.appendChild(item);
			protoItems.set(p, item);
		}

		protoHeader.addEventListener("click", () => {
			protoExpanded = !protoExpanded;
			protoHeader!.textContent = `${protoExpanded ? "\u25BC" : "\u25B6"} ${plural(allProtocols.length, "Protocol")} (${allProtocols.length})`;
			protoList!.style.display = protoExpanded ? "block" : "none";
		});

		protoSection.appendChild(protoHeader);
		protoSection.appendChild(protoList);
		leftPanel.appendChild(protoSection);
	}

	// Categories collapsible section
	let catExpanded = false;
	const categoryItems = new Map<string, HTMLDivElement>();

	if (allCategories.length > 0) {
		const catSection = document.createElement("div");
		catSection.className = "cls-proto-section";

		const catHeader = document.createElement("button");
		catHeader.className = "cls-proto-header";
		catHeader.textContent = `▶ ${plural(allCategories.length, "Category", "Categories")} (${allCategories.length})`;

		const catList = document.createElement("div");
		catList.className = "cls-proto-list";
		catList.style.display = "none";

		for (const cat of allCategories) {
			const item = document.createElement("div");
			item.className = "cls-proto-item";
			item.textContent = `${cat.className} (${cat.name})`;
			item.title = `${cat.className} (${cat.name})`;
			item.addEventListener("click", () => selectCategory(cat));
			catList.appendChild(item);
			categoryItems.set(categoryKey(cat), item);
		}

		catHeader.addEventListener("click", () => {
			catExpanded = !catExpanded;
			catHeader.textContent = `${catExpanded ? "▼" : "▶"} ${plural(allCategories.length, "Category", "Categories")} (${allCategories.length})`;
			catList.style.display = catExpanded ? "block" : "none";
		});

		catSection.appendChild(catHeader);
		catSection.appendChild(catList);
		leftPanel.appendChild(catSection);
	}

	function selectCategory(cat: ObjCCategory): void {
		clearListHighlights();
		const item = categoryItems.get(categoryKey(cat));
		if (item) item.classList.add("cls-proto-item-active");

		pushNav({ type: "category", name: categoryKey(cat) });
		selectedCategory = cat;
		selectedClass = null;
		selectedClassIndex = -1;
		selectedProtocol = null;
		selectedProtoMethod = null;
		selectedMethod = null;
		selectedMember = null;
		renderDetail();
		renderSidebar();
	}

	function selectProtocol(name: string): void {
		clearListHighlights();

		// Highlight selected
		const item = protoItems.get(name);
		if (item) {
			item.classList.add("cls-proto-item-active");
		}

		// Show protocol details
		const proto = protocolDetailsMap.get(name);
		if (proto) {
			pushNav({ type: "protocol", name });
			selectedProtocol = proto;
			selectedProtoMethod = null;
			selectedClass = null;
			selectedCategory = null;
			selectedMember = null;
			selectedClassIndex = -1;
			renderProtocolDetail();
			renderSidebar();
		}
	}

	function scrollToProtocol(name: string): void {
		if (!protoHeader || !protoList) return;
		const item = protoItems.get(name);
		if (!item) return;

		// Expand if collapsed
		if (!protoExpanded) {
			protoExpanded = true;
			protoHeader.textContent = `\u25BC ${plural(allProtocols.length, "Protocol")} (${allProtocols.length})`;
			protoList.style.display = "block";
		}

		// Select and scroll
		selectProtocol(name);
		item.scrollIntoView({ behavior: "smooth", block: "nearest" });
	}

	function renderProtocolDetail(): void {
		if (!selectedProtocol) return;

		methodListContainer.innerHTML = "";
		detailHeader.innerHTML = "";

		const heading = document.createElement("h3");
		heading.className = "cls-detail-name";
		heading.textContent = `@protocol ${selectedProtocol.name}`;
		detailHeader.appendChild(heading);

		const hasAnyMethods =
			selectedProtocol.instanceMethods.length > 0 ||
			selectedProtocol.classMethods.length > 0 ||
			selectedProtocol.optionalInstanceMethods.length > 0 ||
			selectedProtocol.optionalClassMethods.length > 0;

		if (!hasAnyMethods) {
			const hint = document.createElement("div");
			hint.className = "cls-detail-hint";
			hint.textContent = "No methods defined in this protocol.";
			methodListContainer.appendChild(hint);
			return;
		}

		const methodList = document.createElement("ul");
		methodList.className = "cls-method-list";

		const addMethodGroup = (title: string, methods: ObjCMethod[], isClassMethod: boolean) => {
			if (methods.length === 0) return;
			const groupHeader = document.createElement("li");
			groupHeader.className = "cls-proto-method-group";
			const singularTitle = title.replace(/ Methods$/, " Method");
			groupHeader.textContent = `${plural(methods.length, singularTitle, title)} (${methods.length})`;
			methodList.appendChild(groupHeader);

			for (const m of methods) {
				const li = document.createElement("li");
				li.className = "cls-method-item";
				if (selectedProtoMethod?.method === m) {
					li.classList.add("cls-method-active");
				}
				li.innerHTML = highlightObjCMethod(m.signature || m.selector);
				li.title = m.selector;
				li.addEventListener("click", () => {
					selectedProtoMethod = { method: m, isClassMethod };
					renderProtocolDetail();
					renderSidebar();
				});
				methodList.appendChild(li);
			}
		};

		addMethodGroup("Required Instance Methods", selectedProtocol.instanceMethods, false);
		addMethodGroup("Required Class Methods", selectedProtocol.classMethods, true);
		addMethodGroup(
			"Optional Instance Methods",
			selectedProtocol.optionalInstanceMethods,
			false
		);
		addMethodGroup("Optional Class Methods", selectedProtocol.optionalClassMethods, true);

		methodListContainer.appendChild(methodList);
	}

	// ── Middle panel (method list) ──
	const rightPanel = document.createElement("div");
	rightPanel.className = "cls-right";
	wrapper.appendChild(rightPanel);

	// Method search bar + scope toggle (persistent across re-renders)
	const methodSearchWrap = document.createElement("div");
	methodSearchWrap.className = "cls-method-search-wrap";
	rightPanel.appendChild(methodSearchWrap);

	let methodSearchTerm = "";
	let methodSearchRegex = false;
	let methodSearchCaseSensitive = true;
	let searchAllClasses = false;

	/** Re-render whichever detail view is active (protocol, class, category, or global). */
	function refreshDetail(): void {
		if (selectedProtocol) renderProtocolDetail();
		else renderDetail();
	}

	const methodSearchBar = new SearchBar((term, isRegex, caseSensitive) => {
		methodSearchTerm = term;
		methodSearchRegex = isRegex;
		methodSearchCaseSensitive = caseSensitive;
		refreshDetail();
	});
	methodSearchBar.mount(methodSearchWrap);

	const scopeToggle = document.createElement("button");
	scopeToggle.className = "cls-scope-toggle";
	scopeToggle.textContent = "All Classes";
	scopeToggle.title = "Search across all classes";
	scopeToggle.addEventListener("click", () => {
		searchAllClasses = !searchAllClasses;
		scopeToggle.classList.toggle("cls-scope-toggle--active", searchAllClasses);
		refreshDetail();
	});
	methodSearchWrap.appendChild(scopeToggle);

	// Header area (class name + method count) — re-rendered
	const detailHeader = document.createElement("div");
	detailHeader.className = "cls-detail-header";
	rightPanel.appendChild(detailHeader);

	// Scrollable method list area
	const methodListContainer = document.createElement("div");
	methodListContainer.className = "cls-method-scroll";
	rightPanel.appendChild(methodListContainer);

	// ── Resize handle: middle ↔ sidebar ──
	const rightHandle = document.createElement("div");
	rightHandle.className = "cls-resize-handle cls-resize-handle-right";
	rightHandle.style.display = "none"; // hidden until sidebar opens
	wrapper.appendChild(rightHandle);

	// ── Right sidebar (method detail) ──
	const sidebar = document.createElement("div");
	sidebar.className = "cls-sidebar";
	wrapper.appendChild(sidebar);

	// ── Panel resize drag logic ──
	/** Minimum width the middle (methods) panel is allowed to shrink to. */
	const MIN_MIDDLE = 360;

	/**
	 * Compute the maximum width a side panel may occupy right now,
	 * ensuring the methods pane always keeps at least MIN_MIDDLE px.
	 */
	function panelMax(side: "left" | "right"): number {
		const containerW = wrapper.getBoundingClientRect().width;
		const sidebarOpen = sidebar.classList.contains("cls-sidebar--open");
		const siblingW =
			side === "left"
				? sidebarOpen
					? sidebar.getBoundingClientRect().width
					: 0
				: leftPanel.getBoundingClientRect().width;
		// ~10px accounts for the resize handles
		return Math.max(180, containerW - siblingW - MIN_MIDDLE - 10);
	}

	initPanelResize(leftHandle, () => leftPanel, {
		side: "left",
		max: () => panelMax("left"),
		storageKey: "panels:classes:left",
		activeClass: "cls-resize-handle--active"
	});
	initPanelResize(rightHandle, () => sidebar, {
		side: "right",
		max: () => panelMax("right"),
		storageKey: "panels:classes:sidebar",
		activeClass: "cls-resize-handle--active",
		pinMinWidth: true,
		restore: false
	});

	// Re-clamp panels when the container resizes (e.g. window resize)
	new ResizeObserver(() => {
		const leftMax = panelMax("left");
		const leftW = leftPanel.getBoundingClientRect().width;
		if (leftW > leftMax) {
			leftPanel.style.width = `${leftMax}px`;
		}

		if (sidebar.classList.contains("cls-sidebar--open")) {
			const rightMax = panelMax("right");
			const sidebarW = sidebar.getBoundingClientRect().width;
			if (sidebarW > rightMax) {
				const w = `${rightMax}px`;
				sidebar.style.width = w;
				sidebar.style.minWidth = w;
			}
		}
	}).observe(wrapper);

	/** Build a matcher for the current method search term, or null (no filter). */
	function buildSearchMatcher(): ((s: string) => boolean) | null | false {
		if (!methodSearchTerm) return null;
		try {
			if (methodSearchRegex) {
				const flags = methodSearchCaseSensitive ? "" : "i";
				const re = new RegExp(methodSearchTerm, flags);
				return (s) => re.test(s);
			}
			if (methodSearchCaseSensitive) return (s) => s.includes(methodSearchTerm);
			const lower = methodSearchTerm.toLowerCase();
			return (s) => s.toLowerCase().includes(lower);
		} catch {
			return false; // invalid regex — match nothing
		}
	}

	/** Collect every method across all classes that matches the search term. */
	function getGlobalMethodMatches(
		matcher: ((s: string) => boolean) | null
	): { className: string; method: ObjCMethod }[] {
		const results: { className: string; method: ObjCMethod }[] = [];
		for (const cls of allClasses) {
			for (const m of cls.methods) {
				if (!matcher || matcher(m.signature)) {
					results.push({ className: cls.name, method: m });
				}
			}
		}
		return results;
	}

	/** `@property (attrs) Type name;` for list display. */
	function formatProperty(p: ObjCProperty): string {
		const attrs = p.attributeList.length > 0 ? ` (${p.attributeList.join(", ")})` : "";
		const type = p.type || "id";
		const sep = type.endsWith("*") ? "" : " ";
		return `@property${attrs} ${type}${sep}${p.name};`;
	}

	/** `Type name;` for ivar list display. */
	function formatIvar(iv: ObjCIvar): string {
		const type = iv.type || "id";
		const sep = type.endsWith("*") ? "" : " ";
		return `${type}${sep}${iv.name};`;
	}

	function renderDetail(): void {
		detailHeader.innerHTML = "";
		methodListContainer.innerHTML = "";

		if (selectedCategory) {
			renderCategoryDetail();
			return;
		}

		if (searchAllClasses && methodSearchTerm) {
			renderGlobalMethodSearch();
			return;
		}

		if (!selectedClass) {
			const hint = document.createElement("div");
			hint.className = "cls-detail-hint";
			hint.textContent = "Select a class to view its members";
			methodListContainer.appendChild(hint);
			methodSearchBar.updateCount(0, 0);
			return;
		}

		renderClassDetail(selectedClass);
	}

	/** Append a group header + items for a set of methods, properties, or ivars. */
	function appendMemberGroup(
		list: HTMLUListElement,
		title: string,
		entries: {
			text: string;
			title: string;
			active: boolean;
			onClick: () => void;
			highlight?: boolean;
		}[]
	): void {
		if (entries.length === 0) return;
		const groupHeader = document.createElement("li");
		groupHeader.className = "cls-member-group";
		const setLabel = () => {
			const arrow = collapsedGroups.has(title) ? "▶" : "▼";
			groupHeader.textContent = `${arrow} ${title} (${entries.length})`;
		};
		setLabel();
		list.appendChild(groupHeader);

		const items: HTMLLIElement[] = [];
		for (const entry of entries) {
			const li = document.createElement("li");
			li.className = "cls-method-item";
			if (entry.active) li.classList.add("cls-method-active");
			if (entry.highlight !== false) li.innerHTML = highlightObjCMethod(entry.text);
			else li.textContent = entry.text;
			li.title = entry.title;
			li.addEventListener("click", entry.onClick);
			if (collapsedGroups.has(title)) li.style.display = "none";
			items.push(li);
			list.appendChild(li);
		}

		groupHeader.addEventListener("click", () => {
			const collapsed = !collapsedGroups.has(title);
			if (collapsed) collapsedGroups.add(title);
			else collapsedGroups.delete(title);
			for (const li of items) li.style.display = collapsed ? "none" : "";
			setLabel();
		});
	}

	/** Render the grouped member list (properties, ivars, methods) for a class. */
	function renderClassDetail(cls: ObjCClass): void {
		const heading = document.createElement("h3");
		heading.className = "cls-detail-name";
		heading.textContent = cls.superclass ? `${cls.name} : ${cls.superclass}` : cls.name;
		detailHeader.appendChild(heading);

		const properties = cls.properties ?? [];
		const ivars = cls.ivars ?? [];
		const instanceMethods = cls.methods.filter((m) => !m._isClassMethod);
		const classMethods = cls.methods.filter((m) => m._isClassMethod);

		const matcher = buildSearchMatcher();
		const total = properties.length + ivars.length + cls.methods.length;

		const countEl = document.createElement("div");
		countEl.className = "cls-detail-count";
		countEl.textContent = [
			formatCount(cls.methods.length, "method"),
			...(properties.length > 0
				? [formatCount(properties.length, "property", "properties")]
				: []),
			...(ivars.length > 0 ? [formatCount(ivars.length, "ivar")] : [])
		].join(" · ");
		detailHeader.appendChild(countEl);

		if (cls.protocols && cls.protocols.length > 0) {
			detailHeader.appendChild(buildProtocolBadges(cls.protocols));
		}

		const list = document.createElement("ul");
		list.className = "cls-method-list";

		const propEntries = properties
			.filter((p) => !matcher || matcher(formatProperty(p)) || matcher(p.name))
			.map((p) => ({
				text: formatProperty(p),
				title: formatProperty(p),
				active: selectedMember?.kind === "property" && selectedMember.property === p,
				onClick: () => {
					selectedMethod = null;
					selectedMember = { kind: "property", property: p, owner: cls.name };
					renderDetail();
					renderSidebar();
				}
			}));

		const ivarEntries = ivars
			.filter((iv) => !matcher || matcher(formatIvar(iv)) || matcher(iv.name))
			.map((iv) => ({
				text: formatIvar(iv),
				title: `${formatIvar(iv)}  // offset ${iv.offset}`,
				active: selectedMember?.kind === "ivar" && selectedMember.ivar === iv,
				onClick: () => {
					selectedMethod = null;
					selectedMember = { kind: "ivar", ivar: iv, owner: cls.name };
					renderDetail();
					renderSidebar();
				}
			}));

		const methodEntry = (m: ObjCMethod) => ({
			text: m.signature,
			title: m.signature,
			active: selectedMethod === m,
			onClick: () => {
				selectedMember = null;
				selectedMethod = m;
				renderDetail();
				renderSidebar();
			}
		});
		const instanceEntries = instanceMethods
			.filter((m) => !matcher || matcher(m.signature))
			.map(methodEntry);
		const classEntries = classMethods
			.filter((m) => !matcher || matcher(m.signature))
			.map(methodEntry);

		appendMemberGroup(list, "Properties", propEntries);
		appendMemberGroup(list, "Instance variables", ivarEntries);
		appendMemberGroup(list, "Instance methods", instanceEntries);
		appendMemberGroup(list, "Class methods", classEntries);

		const shown =
			propEntries.length + ivarEntries.length + instanceEntries.length + classEntries.length;
		methodSearchBar.updateCount(shown, total);

		if (shown === 0) {
			const hint = document.createElement("div");
			hint.className = "cls-detail-hint";
			hint.textContent = methodSearchTerm
				? "No matching members."
				: "No members for this class.";
			methodListContainer.appendChild(hint);
			return;
		}

		methodListContainer.appendChild(list);
	}

	/** Render a category's members. */
	function renderCategoryDetail(): void {
		const cat = selectedCategory;
		if (!cat) return;

		const heading = document.createElement("h3");
		heading.className = "cls-detail-name";
		heading.textContent = `${cat.className} (${cat.name})`;
		detailHeader.appendChild(heading);

		const countEl = document.createElement("div");
		countEl.className = "cls-detail-count";
		countEl.textContent = [
			formatCount(cat.methods.length, "method"),
			...(cat.properties.length > 0
				? [formatCount(cat.properties.length, "property", "properties")]
				: [])
		].join(" · ");
		detailHeader.appendChild(countEl);

		if (cat.protocols.length > 0) {
			detailHeader.appendChild(buildProtocolBadges(cat.protocols));
		}

		const matcher = buildSearchMatcher();
		const instanceMethods = cat.methods.filter((m) => !m._isClassMethod);
		const classMethods = cat.methods.filter((m) => m._isClassMethod);

		const list = document.createElement("ul");
		list.className = "cls-method-list";

		const propEntries = cat.properties
			.filter((p) => !matcher || matcher(formatProperty(p)) || matcher(p.name))
			.map((p) => ({
				text: formatProperty(p),
				title: formatProperty(p),
				active: selectedMember?.kind === "property" && selectedMember.property === p,
				onClick: () => {
					selectedMethod = null;
					selectedMember = {
						kind: "property",
						property: p,
						owner: `${cat.className} (${cat.name})`
					};
					renderDetail();
					renderSidebar();
				}
			}));

		const methodEntry = (m: ObjCMethod) => ({
			text: m.signature,
			title: m.signature,
			active: selectedMethod === m,
			onClick: () => {
				selectedMember = null;
				selectedMethod = m;
				renderDetail();
				renderSidebar();
			}
		});

		appendMemberGroup(list, "Properties", propEntries);
		appendMemberGroup(
			list,
			"Instance methods",
			instanceMethods.filter((m) => !matcher || matcher(m.signature)).map(methodEntry)
		);
		appendMemberGroup(
			list,
			"Class methods",
			classMethods.filter((m) => !matcher || matcher(m.signature)).map(methodEntry)
		);

		if (list.childElementCount === 0) {
			const hint = document.createElement("div");
			hint.className = "cls-detail-hint";
			hint.textContent = methodSearchTerm
				? "No matching members."
				: "No members in this category.";
			methodListContainer.appendChild(hint);
		} else {
			methodListContainer.appendChild(list);
		}
	}

	/** Render the cross-class method search results (All Classes scope). */
	function renderGlobalMethodSearch(): void {
		const matcher = buildSearchMatcher();
		const filtered = matcher === false ? [] : getGlobalMethodMatches(matcher);

		const heading = document.createElement("h3");
		heading.className = "cls-detail-name";
		heading.textContent = "Method Search";
		detailHeader.appendChild(heading);

		const countEl = document.createElement("div");
		countEl.className = "cls-detail-count";
		countEl.textContent = `${filtered.length.toLocaleString()} ${plural(filtered.length, "result")} across all classes`;
		detailHeader.appendChild(countEl);
		methodSearchBar.updateCount(filtered.length, totalMethods);

		if (filtered.length === 0) {
			const hint = document.createElement("div");
			hint.className = "cls-detail-hint";
			hint.textContent = "No matching methods.";
			methodListContainer.appendChild(hint);
			return;
		}

		const list = document.createElement("ul");
		list.className = "cls-method-list";
		let lastClassName = "";
		for (const { className: clsName, method: m } of filtered) {
			if (clsName !== lastClassName) {
				lastClassName = clsName;
				const groupHeader = document.createElement("li");
				groupHeader.className = "cls-method-group";
				groupHeader.textContent = clsName;
				groupHeader.addEventListener("click", () => {
					const cls = allClasses.find((c) => c.name === clsName);
					if (cls) {
						selectedClass = cls;
						searchAllClasses = false;
						scopeToggle.classList.remove("cls-scope-toggle--active");
						methodSearchTerm = "";
						methodSearchBar.setValue("", false);
						renderVisibleRows();
						renderDetail();
						renderSidebar();
					}
				});
				list.appendChild(groupHeader);
			}

			const li = document.createElement("li");
			li.className = "cls-method-item";
			if (selectedMethod === m) li.classList.add("cls-method-active");
			li.innerHTML = highlightObjCMethod(m.signature);
			li.title = m.signature;
			li.addEventListener("click", () => {
				const cls = allClasses.find((c) => c.name === clsName);
				if (cls) selectedClass = cls;
				selectedMember = null;
				selectedMethod = m;
				renderDetail();
				renderSidebar();
			});
			list.appendChild(li);
		}
		methodListContainer.appendChild(list);
	}

	/** Build the "Conforms to:" protocol badge row. */
	function buildProtocolBadges(protocols: string[]): HTMLElement {
		const protoLine = document.createElement("div");
		protoLine.className = "cls-detail-protos";
		const label = document.createElement("span");
		label.className = "cls-detail-protos-label";
		label.textContent = "Conforms to:";
		protoLine.appendChild(label);
		for (const proto of protocols) {
			const badge = document.createElement("span");
			badge.className = "cls-proto-badge";
			badge.textContent = proto;
			badge.title = `Click to view ${proto}`;
			badge.addEventListener("click", () => scrollToProtocol(proto));
			protoLine.appendChild(badge);
		}
		return protoLine;
	}

	/** Open the sidebar and restore its persisted width. Returns the inner container. */
	function openSidebar(): HTMLDivElement {
		sidebar.classList.add("cls-sidebar--open");
		const saved = loadWidths("panels:classes:sidebar");
		if (saved?.width) {
			const max = panelMax("right");
			const parsed = parseInt(saved.width, 10);
			const clamped = Number.isFinite(parsed) ? Math.min(parsed, max) : parsed;
			const w = `${clamped}px`;
			sidebar.style.width = w;
			sidebar.style.minWidth = w;
		}
		rightHandle.style.display = "";
		const inner = document.createElement("div");
		inner.className = "cls-sb-inner";
		sidebar.appendChild(inner);
		return inner;
	}

	/** Close button that clears a selection and re-renders the detail list. */
	function makeCloseButton(onClose: () => void): HTMLButtonElement {
		const closeBtn = document.createElement("button");
		closeBtn.className = "cls-sb-close";
		closeBtn.textContent = "×";
		closeBtn.title = "Close";
		closeBtn.addEventListener("click", () => {
			onClose();
			sidebar.classList.remove("cls-sidebar--open");
			sidebar.style.width = "";
			sidebar.style.minWidth = "";
			sidebar.innerHTML = "";
			rightHandle.style.display = "none";
			refreshDetail();
		});
		return closeBtn;
	}

	function renderSidebar(): void {
		sidebar.innerHTML = "";

		// Handle protocol method selection
		if (selectedProtoMethod && selectedProtocol) {
			renderProtoMethodSidebar();
			return;
		}

		if (selectedMember) {
			renderMemberSidebar(selectedMember);
			return;
		}

		const hookClassName = selectedClass?.name ?? selectedCategory?.className ?? "";
		const displayOwner =
			selectedClass?.name ??
			(selectedCategory ? `${selectedCategory.className} (${selectedCategory.name})` : "");
		if (!selectedMethod || !hookClassName) {
			sidebar.classList.remove("cls-sidebar--open");
			sidebar.style.width = "";
			sidebar.style.minWidth = "";
			rightHandle.style.display = "none";
			return;
		}

		const inner = openSidebar();

		const sig = selectedMethod.signature;
		const className = hookClassName;
		const parsed = parseMethodSignature(sig);

		inner.appendChild(
			makeCloseButton(() => {
				selectedMethod = null;
			})
		);

		// Owner (class or category)
		const classLabel = document.createElement("div");
		classLabel.className = "cls-sb-class";
		classLabel.textContent = displayOwner;
		inner.appendChild(classLabel);

		// Full method signature (wrapping)
		const sigBlock = document.createElement("div");
		sigBlock.className = "cls-sb-sig";
		sigBlock.innerHTML = highlightObjCMethod(sig);
		inner.appendChild(sigBlock);

		// ── Copy buttons section ──
		const actions = document.createElement("div");
		actions.className = "cls-sb-actions";
		inner.appendChild(actions);

		// Copy class name
		const copyClassBtn = document.createElement("button");
		copyClassBtn.className = "cls-sb-btn";
		copyClassBtn.textContent = "Copy Class Name";
		copyClassBtn.addEventListener("click", () => copyText(className, "Copied class name"));
		actions.appendChild(copyClassBtn);

		if (parsed) {
			// Copy selector (e.g. "doA:withB:")
			const copySelectorBtn = document.createElement("button");
			copySelectorBtn.className = "cls-sb-btn";
			copySelectorBtn.textContent = "Copy Selector";
			copySelectorBtn.addEventListener("click", () =>
				copyText(parsed.selector, "Copied selector")
			);
			actions.appendChild(copySelectorBtn);

			// Copy full signature
			const copySigBtn = document.createElement("button");
			copySigBtn.className = "cls-sb-btn";
			copySigBtn.textContent = "Copy Signature";
			copySigBtn.addEventListener("click", () => copyText(sig, "Copied signature"));
			actions.appendChild(copySigBtn);

			// ── Logos Hook section ──
			const hookSection = document.createElement("div");
			hookSection.className = "cls-sb-hook-section";
			inner.appendChild(hookSection);

			const hookLabel = document.createElement("div");
			hookLabel.className = "cls-sb-section-title";
			hookLabel.textContent = "Logos Hook";
			hookSection.appendChild(hookLabel);

			const hookCode = generateLogosHook(className, parsed);

			const codeBlock = document.createElement("pre");
			codeBlock.className = "cls-sb-code";
			codeBlock.innerHTML = highlightLogos(hookCode);
			hookSection.appendChild(codeBlock);

			const copyHookBtn = document.createElement("button");
			copyHookBtn.className = "cls-sb-btn cls-sb-btn--accent";
			copyHookBtn.textContent = "Copy Logos Hook";
			copyHookBtn.addEventListener("click", () => copyText(hookCode, "Copied Logos hook"));
			hookSection.appendChild(copyHookBtn);
		} else {
			// Fallback: just copy the raw signature
			const copySigBtn = document.createElement("button");
			copySigBtn.className = "cls-sb-btn";
			copySigBtn.textContent = "Copy Signature";
			copySigBtn.addEventListener("click", () => copyText(sig, "Copied signature"));
			actions.appendChild(copySigBtn);
		}
	}

	function renderProtoMethodSidebar(): void {
		if (!selectedProtoMethod || !selectedProtocol) return;

		const inner = openSidebar();

		const m = selectedProtoMethod.method;
		const sig = m.signature || m.selector;

		inner.appendChild(
			makeCloseButton(() => {
				selectedProtoMethod = null;
			})
		);

		// Protocol name
		const protoLabel = document.createElement("div");
		protoLabel.className = "cls-sb-class";
		protoLabel.textContent = `@protocol ${selectedProtocol.name}`;
		inner.appendChild(protoLabel);

		// Method signature
		const sigBlock = document.createElement("div");
		sigBlock.className = "cls-sb-sig";
		sigBlock.innerHTML = highlightObjCMethod(sig);
		inner.appendChild(sigBlock);

		// Copy buttons
		const actions = document.createElement("div");
		actions.className = "cls-sb-actions";
		inner.appendChild(actions);

		// Copy protocol name
		const copyProtoBtn = document.createElement("button");
		copyProtoBtn.className = "cls-sb-btn";
		copyProtoBtn.textContent = "Copy Protocol Name";
		copyProtoBtn.addEventListener("click", () =>
			copyText(selectedProtocol!.name, "Copied protocol name")
		);
		actions.appendChild(copyProtoBtn);

		// Copy selector
		const copySelectorBtn = document.createElement("button");
		copySelectorBtn.className = "cls-sb-btn";
		copySelectorBtn.textContent = "Copy Selector";
		copySelectorBtn.addEventListener("click", () => copyText(m.selector, "Copied selector"));
		actions.appendChild(copySelectorBtn);

		// Copy full signature
		const copySigBtn = document.createElement("button");
		copySigBtn.className = "cls-sb-btn";
		copySigBtn.textContent = "Copy Signature";
		copySigBtn.addEventListener("click", () => copyText(sig, "Copied signature"));
		actions.appendChild(copySigBtn);
	}

	/** Sidebar for a selected property or instance variable. */
	function renderMemberSidebar(member: SelectedMember): void {
		const inner = openSidebar();

		inner.appendChild(
			makeCloseButton(() => {
				selectedMember = null;
			})
		);

		const ownerLabel = document.createElement("div");
		ownerLabel.className = "cls-sb-class";
		ownerLabel.textContent = member.owner;
		inner.appendChild(ownerLabel);

		const sigBlock = document.createElement("div");
		sigBlock.className = "cls-sb-sig";
		const declaration =
			member.kind === "property" ? formatProperty(member.property) : formatIvar(member.ivar);
		sigBlock.textContent = declaration;
		inner.appendChild(sigBlock);

		// Member facts (type, attributes, offset, backing ivar)
		const facts = document.createElement("div");
		facts.className = "cls-sb-facts";
		const addFact = (label: string, value: string) => {
			if (!value) return;
			const row = document.createElement("div");
			row.className = "cls-sb-fact";
			const k = document.createElement("span");
			k.className = "cls-sb-fact-key";
			k.textContent = label;
			const v = document.createElement("span");
			v.className = "cls-sb-fact-value";
			v.textContent = value;
			row.appendChild(k);
			row.appendChild(v);
			facts.appendChild(row);
		};

		if (member.kind === "property") {
			addFact("Type", member.property.type || "id");
			addFact("Attributes", member.property.attributeList.join(", "));
			if (member.property.ivar) addFact("Backing ivar", member.property.ivar);
		} else {
			addFact("Type", member.ivar.type || "id");
			addFact("Offset", `${member.ivar.offset} (0x${member.ivar.offset.toString(16)})`);
		}
		inner.appendChild(facts);

		const actions = document.createElement("div");
		actions.className = "cls-sb-actions";
		inner.appendChild(actions);

		const addCopyBtn = (label: string, text: string, toast: string) => {
			if (!text) return;
			const btn = document.createElement("button");
			btn.className = "cls-sb-btn";
			btn.textContent = label;
			btn.addEventListener("click", () => copyText(text, toast));
			actions.appendChild(btn);
		};

		if (member.kind === "property") {
			addCopyBtn("Copy Name", member.property.name, "Copied property name");
			addCopyBtn("Copy Declaration", declaration, "Copied declaration");
			addCopyBtn("Copy Attributes", member.property.attributes, "Copied attributes");
		} else {
			addCopyBtn("Copy Name", member.ivar.name, "Copied ivar name");
			addCopyBtn("Copy Declaration", declaration, "Copied declaration");
		}
	}

	// Check for pending class selection (from cross-binary click on a different binary)
	if (pendingClassSelect) {
		const cls = allClasses.find((c) => c.name === pendingClassSelect);
		pendingClassSelect = null;
		if (cls) {
			selectedClass = cls;
			selectedMethod = null;
			renderList();
			renderDetail();
			renderSidebar();
			const idx = filteredClasses.indexOf(cls);
			if (idx >= 0) {
				// Defer so the jump wins over the tab's stored scroll restoration.
				const top = idx * ROW_HEIGHT;
				requestAnimationFrame(() => {
					scrollContainer.scrollTop = top;
				});
			}
			return;
		}
	}

	// Initial render
	renderList();
	renderDetail();
	renderSidebar();
}
