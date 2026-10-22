/**
 * Security Scan tab renderer.
 */

import type { AnalysisResult, SecurityFinding } from "../../shared/types";
import { SearchBar } from "../components";
import { type NavigationTarget, navigateTo } from "../navigation";
import { getSearchState, registerSearchBar, saveSearchState } from "../search-state";
import { getTabState, setTabState } from "../tab-state";
import { copyText, makeCopyable } from "../utils/clipboard";
import {
	resolveFindingTargets,
	resolveHardeningTarget,
	type SecurityReferenceContext
} from "../utils/security-references";

// ── Types ──

interface BinaryHardening {
	pie: boolean;
	arc: boolean;
	stackCanaries: boolean;
	encrypted: boolean;
	stripped: boolean;
}

interface SecurityData {
	findings: SecurityFinding[];
	hardening: BinaryHardening;
}

// ── Constants ──

const SEVERITY_ORDER: Record<string, number> = { critical: 0, warning: 1, info: 2 };

const SEVERITY_LABELS: Record<string, string> = {
	critical: "CRITICAL",
	warning: "WARNING",
	info: "INFO"
};

const HARDENING_LABELS: { key: keyof BinaryHardening; label: string }[] = [
	{ key: "pie", label: "PIE" },
	{ key: "arc", label: "ARC" },
	{ key: "stackCanaries", label: "Stack Canaries" },
	{ key: "encrypted", label: "Encryption" },
	{ key: "stripped", label: "Stripped" }
];

const EVIDENCE_COLLAPSED_LEN = 200;

const TAB_LABELS: Record<string, string> = {
	strings: "Strings",
	hex: "Hex",
	symbols: "Symbols",
	files: "Files",
	electron: "Electron",
	entitlements: "Entitlements",
	overview: "Overview"
};

/**
 * Render one finding reference. Navigable references are real buttons so
 * Enter/Space work; a single click navigates and ⌥-click copies. Non-navigable
 * references keep the existing double-click copy affordance.
 */
function buildReference(
	sessionId: string,
	label: string,
	text: string,
	target: NavigationTarget | null,
	getCopy: () => string
): HTMLElement {
	const row = document.createElement("div");
	row.className = "sec-finding-reference";

	if (label) {
		const labelEl = document.createElement("span");
		labelEl.className = "sec-finding-function-label";
		labelEl.textContent = label;
		row.appendChild(labelEl);
	}

	if (!target) {
		const code = document.createElement("code");
		code.className = "sec-finding-function-name";
		code.textContent = text;
		makeCopyable(code, getCopy);
		row.appendChild(code);
		return row;
	}

	const link = document.createElement("button");
	link.type = "button";
	link.className = "sec-finding-function-name sec-reference";
	link.textContent = text;
	link.title = `Open in ${TAB_LABELS[target.sectionTab] ?? target.sectionTab} \u00B7 \u2325-click to copy`;
	// A button click fires for Enter/Space too, so keyboard users navigate.
	link.addEventListener("click", (event) => {
		if (event.altKey) {
			copyText(getCopy(), "Copied to clipboard");
			return;
		}
		navigateTo(sessionId, target);
	});
	row.appendChild(link);
	return row;
}

// ── Render ──

export function renderSecurity(
	container: HTMLElement,
	data: unknown,
	sessionId: string = "",
	result?: AnalysisResult | null,
	currentBinaryIndex: number = 0
): void {
	container.innerHTML = "";

	const obj = data && typeof data === "object" ? (data as Record<string, unknown>) : null;
	const sec: Partial<SecurityData> = (
		obj && "findings" in obj ? obj : (obj?.security ?? {})
	) as Partial<SecurityData>;
	const findings = sec.findings ?? [];
	const hardening = sec.hardening ?? ({} as BinaryHardening);

	const refCtx: SecurityReferenceContext = {
		binaries:
			result?.overview?.ipa?.binaries?.map((binary) => ({
				name: binary.name,
				type: binary.type
			})) ?? [],
		currentBinaryIndex,
		hasElectron: result?.electron != null,
		fuseNames: result?.electron?.fuses?.map((fuse) => fuse.name) ?? []
	};

	// State
	const savedFilters = getTabState<string[]>(sessionId, "security", "filters");
	const activeFilters = new Set<string>(savedFilters ?? ["critical", "warning", "info"]);
	let searchTerm = "";
	let searchRegex = false;

	// ── Root wrapper ──
	const root = document.createElement("div");
	root.className = "sec-root";

	// ── Summary badges ──
	const summaryRow = document.createElement("div");
	summaryRow.className = "sec-summary";
	const counts = { critical: 0, warning: 0, info: 0 };
	for (const f of findings) {
		if (f.severity in counts) counts[f.severity as keyof typeof counts]++;
	}
	for (const sev of ["critical", "warning", "info"] as const) {
		const badge = document.createElement("span");
		badge.className = `sec-badge sec-badge--${sev}`;
		badge.textContent = `${counts[sev]} ${SEVERITY_LABELS[sev]}`;
		summaryRow.appendChild(badge);
	}
	root.appendChild(summaryRow);

	// ── Binary hardening section ──
	const hardeningSection = document.createElement("div");
	hardeningSection.className = "sec-hardening";

	const hardeningTitle = document.createElement("h3");
	hardeningTitle.className = "sec-section-title";
	hardeningTitle.textContent = "Binary Hardening";
	hardeningSection.appendChild(hardeningTitle);

	const hardeningGrid = document.createElement("div");
	hardeningGrid.className = "sec-hardening-grid";

	for (const { key, label } of HARDENING_LABELS) {
		const cell = document.createElement("div");
		cell.className = "sec-hardening-cell";

		const icon = document.createElement("span");
		const enabled = !!hardening[key];
		icon.className = `sec-hardening-icon ${enabled ? "sec-hardening-pass" : "sec-hardening-fail"}`;
		icon.textContent = enabled ? "\u2713" : "\u2717";

		const text = document.createElement("span");
		text.className = "sec-hardening-label";
		text.textContent = label;

		cell.appendChild(icon);
		cell.appendChild(text);
		hardeningGrid.appendChild(cell);
	}
	hardeningSection.appendChild(hardeningGrid);
	root.appendChild(hardeningSection);

	// ── Filter buttons ──
	const filterRow = document.createElement("div");
	filterRow.className = "sec-filters";

	const filterLabel = document.createElement("span");
	filterLabel.className = "sec-filter-label";
	filterLabel.textContent = "Filter:";
	filterRow.appendChild(filterLabel);

	const filterButtons: Record<string, HTMLButtonElement> = {};
	for (const sev of ["critical", "warning", "info"] as const) {
		const btn = document.createElement("button");
		btn.className = `sec-filter-btn sec-filter-btn--${sev}${
			activeFilters.has(sev) ? " sec-filter-btn--active" : ""
		}`;
		btn.textContent = SEVERITY_LABELS[sev]!;
		btn.addEventListener("click", () => {
			if (activeFilters.has(sev)) {
				activeFilters.delete(sev);
				btn.classList.remove("sec-filter-btn--active");
			} else {
				activeFilters.add(sev);
				btn.classList.add("sec-filter-btn--active");
			}
			setTabState(sessionId, "security", "filters", [...activeFilters]);
			renderFindings();
		});
		filterButtons[sev] = btn;
		filterRow.appendChild(btn);
	}
	root.appendChild(filterRow);

	// ── Search bar ──
	const searchWrap = document.createElement("div");
	searchWrap.className = "sec-search";
	const searchBar = new SearchBar((term, isRegex, _caseSensitive) => {
		searchTerm = term;
		searchRegex = isRegex;
		saveSearchState(sessionId, "security", term, isRegex);
		renderFindings();
	});
	root.appendChild(searchWrap);

	// ── Findings list ──
	const findingsList = document.createElement("div");
	findingsList.className = "sec-findings";
	root.appendChild(findingsList);

	container.appendChild(root);

	// Mount search bar after root is in the DOM
	searchBar.mount(searchWrap);
	registerSearchBar(sessionId, "security", searchBar);

	// Restore saved search state
	const savedState = getSearchState(sessionId, "security");
	if (savedState?.term) {
		searchBar.setValue(savedState.term, savedState.isRegex);
	}

	// ── Filtering + rendering logic ──
	function getFilteredFindings(): SecurityFinding[] {
		let filtered = findings.filter((f) => activeFilters.has(f.severity));

		if (searchTerm) {
			if (searchRegex) {
				try {
					const re = new RegExp(searchTerm, "i");
					filtered = filtered.filter(
						(f) =>
							re.test(f.message) ||
							re.test(f.category) ||
							re.test(f.evidence) ||
							(f.location && re.test(f.location)) ||
							(f.functionName && re.test(f.functionName)) ||
							(f.source && re.test(f.source))
					);
				} catch {
					// Invalid regex, skip filtering
				}
			} else {
				const lower = searchTerm.toLowerCase();
				filtered = filtered.filter(
					(f) =>
						f.message.toLowerCase().includes(lower) ||
						f.category.toLowerCase().includes(lower) ||
						f.evidence.toLowerCase().includes(lower) ||
						f.location?.toLowerCase().includes(lower) ||
						f.functionName?.toLowerCase().includes(lower) ||
						f.source?.toLowerCase().includes(lower)
				);
			}
		}

		// Sort: critical first, then warning, then info
		filtered.sort(
			(a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
		);

		return filtered;
	}

	function renderFindings(): void {
		findingsList.innerHTML = "";
		const filtered = getFilteredFindings();
		searchBar.updateCount(filtered.length, findings.length);

		if (filtered.length === 0) {
			const empty = document.createElement("div");
			empty.className = "sec-no-findings";
			empty.textContent =
				findings.length === 0
					? "No security findings."
					: "No findings match the current filters.";
			findingsList.appendChild(empty);
			return;
		}

		for (const finding of filtered) {
			const card = document.createElement("div");
			card.className = "sec-finding-card";
			const targets = resolveFindingTargets(finding, refCtx);

			// Top row: severity badge + category
			const topRow = document.createElement("div");
			topRow.className = "sec-finding-top";

			const sevBadge = document.createElement("span");
			sevBadge.className = `sec-badge sec-badge--${finding.severity}`;
			sevBadge.textContent = SEVERITY_LABELS[finding.severity] ?? finding.severity;
			topRow.appendChild(sevBadge);

			const cat = document.createElement("span");
			cat.className = "sec-finding-category";
			cat.textContent = finding.category;
			topRow.appendChild(cat);

			if (finding.vendor) {
				const vendor = document.createElement("span");
				vendor.className = "sec-finding-vendor";
				vendor.textContent = "VENDOR";
				topRow.appendChild(vendor);
			}

			card.appendChild(topRow);

			// Message
			const msg = document.createElement("div");
			msg.className = "sec-finding-message";
			msg.textContent = finding.message;
			card.appendChild(msg);

			// Evidence (expandable if long, always copyable)
			if (finding.evidence) {
				const evi = document.createElement("div");
				evi.className = "sec-finding-evidence";

				const isLong = finding.evidence.length > EVIDENCE_COLLAPSED_LEN;
				let expanded = !isLong;

				const eviText = document.createElement("span");
				eviText.className = "sec-finding-evidence-text";
				eviText.textContent = isLong
					? `${finding.evidence.slice(0, EVIDENCE_COLLAPSED_LEN)}\u2026`
					: finding.evidence;
				makeCopyable(eviText, () => finding.evidence);
				evi.appendChild(eviText);

				if (isLong) {
					const expandBtn = document.createElement("button");
					expandBtn.className = "sec-evidence-toggle";
					expandBtn.textContent = "Show more";
					expandBtn.addEventListener("click", () => {
						expanded = !expanded;
						eviText.textContent = expanded
							? finding.evidence
							: `${finding.evidence.slice(0, EVIDENCE_COLLAPSED_LEN)}\u2026`;
						expandBtn.textContent = expanded ? "Show less" : "Show more";
					});
					evi.appendChild(expandBtn);
				}

				card.appendChild(evi);

				// Weak/unsafe API symbols and Electron fuses are navigable from
				// the evidence too, but the evidence text itself stays copyable.
				if (targets.evidence) {
					card.appendChild(
						buildReference(
							sessionId,
							"",
							`Open in ${TAB_LABELS[targets.evidence.sectionTab] ?? targets.evidence.sectionTab}`,
							targets.evidence,
							() => finding.evidence
						)
					);
				}
			}

			// Function name
			if (finding.functionName) {
				card.appendChild(
					buildReference(
						sessionId,
						"Referenced in: ",
						finding.functionName,
						targets.functionName ?? null,
						() => finding.functionName!
					)
				);
			}

			// Source
			if (finding.source) {
				card.appendChild(
					buildReference(
						sessionId,
						"Source: ",
						finding.source,
						targets.source ?? null,
						() => finding.source!
					)
				);
			}

			// Location
			if (finding.location) {
				if (targets.location) {
					card.appendChild(
						buildReference(
							sessionId,
							"Location: ",
							finding.location.replace(/^offset=/i, ""),
							targets.location,
							() => finding.location!
						)
					);
				} else {
					const loc = document.createElement("div");
					loc.className = "sec-finding-location";
					loc.textContent = finding.location;
					card.appendChild(loc);
				}
			}

			// Binary hardening findings live in the Overview card.
			const hardeningTarget = resolveHardeningTarget(finding);
			if (hardeningTarget) {
				card.appendChild(
					buildReference(
						sessionId,
						"",
						"View in Overview",
						hardeningTarget,
						() => finding.message
					)
				);
			}

			findingsList.appendChild(card);
		}
	}

	// Initial render
	renderFindings();
}
