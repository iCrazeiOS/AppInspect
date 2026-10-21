/**
 * Info.plist tab: key-facts summary + full collapsible JSON tree with search.
 */

import { EmptyState, JsonTree, SearchBar } from "../components";
import { getSearchState, registerSearchBar, saveSearchState } from "../search-state";
import { makeCopyable } from "../utils/clipboard";

interface PlistFact {
	label: string;
	value: string;
	mono?: boolean;
}

interface PlistChipGroup {
	label: string;
	items: string[];
	tone?: "default" | "warn" | "ok";
	titles?: string[];
	copyable?: boolean;
}

interface PlistSummary {
	facts: PlistFact[];
	chips: PlistChipGroup[];
}

const DEVICE_FAMILIES: Record<number, string> = {
	1: "iPhone",
	2: "iPad",
	3: "Apple TV",
	6: "Apple Watch",
	7: "Vision Pro"
};

function asStringArray(value: unknown): string[] {
	return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/** "UIInterfaceOrientationLandscapeLeft" -> "Landscape Left". */
function humaniseOrientation(raw: string): string {
	return raw.replace(/^UIInterfaceOrientation/, "").replace(/([a-z])([A-Z])/g, "$1 $2");
}

/** "NSAllowsLocalNetworking" -> "Allows Local Networking". */
function humaniseKey(raw: string): string {
	return raw.replace(/^NS/, "").replace(/([a-z])([A-Z])/g, "$1 $2");
}

/** Build the at-a-glance facts and chip groups for an Info.plist. */
function buildSummary(plist: Record<string, unknown>): PlistSummary {
	const facts: PlistFact[] = [];
	const chips: PlistChipGroup[] = [];

	const fact = (label: string, value: unknown, mono = false): void => {
		if (typeof value === "string" && value) facts.push({ label, value, mono });
	};

	fact("Bundle ID", plist.CFBundleIdentifier, true);
	fact("Display Name", plist.CFBundleDisplayName ?? plist.CFBundleName);
	fact("Version", plist.CFBundleShortVersionString);
	fact("Build", plist.CFBundleVersion);
	fact("Executable", plist.CFBundleExecutable, true);
	fact("Minimum OS", plist.MinimumOSVersion ?? plist.LSMinimumSystemVersion);
	fact("SDK", plist.DTSDKName, true);
	fact("Platform", plist.DTPlatformName, true);

	const families: string[] = [];
	const deviceFamily = Array.isArray(plist.UIDeviceFamily) ? plist.UIDeviceFamily : [];
	for (const raw of deviceFamily) {
		const name = DEVICE_FAMILIES[Number(raw)];
		if (name) families.push(name);
	}
	if (families.length > 0) facts.push({ label: "Device Family", value: families.join(", ") });

	fact("Category", plist.LSApplicationCategoryType);

	const requires = asStringArray(plist.UIRequiredDeviceCapabilities);
	if (requires.length > 0) facts.push({ label: "Requires", value: requires.join(", ") });

	const platforms = asStringArray(plist.CFBundleSupportedPlatforms);
	if (platforms.length > 0) {
		facts.push({ label: "Supported Platforms", value: platforms.join(", ") });
	}

	fact("Primary Language", plist.CFBundleDevelopmentRegion, true);

	const urlSchemes: string[] = [];
	for (const entry of Array.isArray(plist.CFBundleURLTypes) ? plist.CFBundleURLTypes : []) {
		urlSchemes.push(...asStringArray((entry as Record<string, unknown>)?.CFBundleURLSchemes));
	}
	if (urlSchemes.length > 0) chips.push({ label: "URL Schemes", items: urlSchemes });

	const backgroundModes = asStringArray(plist.UIBackgroundModes);
	if (backgroundModes.length > 0) {
		chips.push({ label: "Background Modes", items: backgroundModes });
	}

	const privacyItems: string[] = [];
	const privacyTitles: string[] = [];
	for (const [key, value] of Object.entries(plist)) {
		if (key.startsWith("NS") && key.endsWith("UsageDescription") && typeof value === "string") {
			privacyItems.push(humaniseKey(key.replace(/UsageDescription$/, "")));
			privacyTitles.push(value);
		}
	}
	if (privacyItems.length > 0) {
		chips.push({ label: "Privacy Strings", items: privacyItems, titles: privacyTitles });
	}

	const ats = plist.NSAppTransportSecurity as Record<string, unknown> | undefined;
	if (ats) {
		const atsItems: string[] = [];
		if (ats.NSAllowsArbitraryLoads === true) atsItems.push("Allows Arbitrary Loads");
		const domains = ats.NSExceptionDomains as Record<string, unknown> | undefined;
		if (domains) atsItems.push(...Object.keys(domains));
		if (ats.NSAllowsArbitraryLoadsInWebContent === true) {
			atsItems.push("Allows Arbitrary Loads In Web Content");
		}
		if (ats.NSAllowsLocalNetworking === true) atsItems.push("Allows Local Networking");
		if (atsItems.length > 0) {
			chips.push({ label: "ATS", items: atsItems, tone: "warn", copyable: true });
		}
	}

	const orientations: Array<[string, unknown]> = [
		["Orientations", plist.UISupportedInterfaceOrientations],
		["Orientations (iPad)", plist["UISupportedInterfaceOrientations~ipad"]]
	];
	for (const [label, raw] of orientations) {
		const decoded = asStringArray(raw).map(humaniseOrientation);
		if (decoded.length > 0 && decoded.length <= 6) chips.push({ label, items: decoded });
	}

	const documentTypes = new Set<string>();
	const docTypeEntries = Array.isArray(plist.CFBundleDocumentTypes)
		? plist.CFBundleDocumentTypes
		: [];
	for (const entry of docTypeEntries) {
		const name = (entry as Record<string, unknown>)?.CFBundleTypeName;
		if (typeof name === "string" && name) documentTypes.add(name);
	}
	if (documentTypes.size > 0) {
		chips.push({ label: "Document Types", items: [...documentTypes] });
	}

	return { facts, chips };
}

export function renderPlist(container: HTMLElement, data: unknown, sessionId: string = ""): void {
	container.innerHTML = "";

	// data may be the raw plist object directly, or { raw: {...}, extracted: {...} }
	const obj =
		data && typeof data === "object" && !Array.isArray(data)
			? (data as Record<string, unknown>)
			: null;
	const plist = (obj?.raw ?? obj?.plist ?? obj) as Record<string, unknown> | null;

	if (!plist || Object.keys(plist).length === 0) {
		const empty = new EmptyState({
			icon: "\u2699",
			message: "No Info.plist data available."
		});
		empty.mount(container);
		return;
	}

	// Key-facts summary
	const summary = buildSummary(plist);

	if (summary.facts.length > 0 || summary.chips.length > 0) {
		const quickSection = document.createElement("div");
		quickSection.className = "plist-quick";

		if (summary.facts.length > 0) {
			const factsEl = document.createElement("div");
			factsEl.className = "plist-facts";

			for (const item of summary.facts) {
				const row = document.createElement("div");
				row.className = "plist-fact";

				const label = document.createElement("span");
				label.className = "plist-fact-label";
				label.textContent = item.label;

				const value = document.createElement("span");
				value.className = item.mono
					? "plist-fact-value plist-fact-value--mono"
					: "plist-fact-value";
				value.textContent = item.value;
				makeCopyable(value, () => item.value);

				row.appendChild(label);
				row.appendChild(value);
				factsEl.appendChild(row);
			}

			quickSection.appendChild(factsEl);
		}

		for (const group of summary.chips) {
			const groupEl = document.createElement("div");
			groupEl.className = "plist-chip-group";

			const groupLabel = document.createElement("span");
			groupLabel.className = "plist-chip-label";
			groupLabel.textContent = group.label;
			groupEl.appendChild(groupLabel);

			group.items.forEach((text, index) => {
				const chip = document.createElement("span");
				chip.className = "plist-chip";
				if (group.tone === "warn") chip.classList.add("plist-chip--warn");
				chip.textContent = text;
				if (group.copyable) {
					makeCopyable(chip, () => text);
				} else {
					chip.title = group.titles?.[index] ?? text;
				}
				groupEl.appendChild(chip);
			});

			quickSection.appendChild(groupEl);
		}

		container.appendChild(quickSection);
	}

	// Search bar
	const searchWrap = document.createElement("div");
	searchWrap.className = "plist-search";
	container.appendChild(searchWrap);

	const treeContainer = document.createElement("div");
	treeContainer.className = "plist-tree";
	container.appendChild(treeContainer);

	const tree = new JsonTree({ sessionId, tabId: "plist" });
	tree.mount(treeContainer);
	tree.setData(plist);

	const totalKeys = Object.keys(plist).length;
	const searchBar = new SearchBar((term, isRegex, _caseSensitive) => {
		saveSearchState(sessionId, "plist", term, isRegex);
		tree.filter(term);
		// Update count based on visible nodes
		const visibleCount = treeContainer.querySelectorAll(".jt-node:not(.jt-hidden)").length;
		searchBar.updateCount(term ? visibleCount : totalKeys, totalKeys);
	});
	searchBar.mount(searchWrap);
	registerSearchBar(sessionId, "plist", searchBar);

	// Restore saved search state
	const savedState = getSearchState(sessionId, "plist");
	if (savedState?.term) {
		searchBar.setValue(savedState.term, savedState.isRegex);
	}
}
