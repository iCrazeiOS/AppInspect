/**
 * Size tab — where the active binary's bytes go, by module (Swift module,
 * ObjC class prefix, C++ namespace, Kotlin package, C library) or by
 * segment/section. Module rows expand to show their largest symbols.
 */

import type { SizeBreakdown, SizeModule, SizeModuleKind } from "../../shared/types";
import { EmptyState } from "../components";
import { showToast } from "../components/toast";
import { getTabState, setTabState } from "../tab-state";
import { el } from "../utils/dom";
import { formatSize } from "../utils/format";
import { mountTreemap } from "./size-treemap";
import { renderTreemapPng } from "./size-treemap-export";

/** Module rows shown before "Show all" — long tails are mostly tiny C prefix groups. */
const INITIAL_MODULE_ROWS = 50;

const KIND_LABELS: Record<SizeModuleKind, string> = {
	swift: "Swift",
	objc: "ObjC",
	cpp: "C++",
	c: "C",
	kotlin: "Kotlin",
	unattributed: "—"
};

type View = "modules" | "sections" | "blocks";

/** Disposes the mounted treemap's resize observer when the view changes. */
let disposeTreemap: (() => void) | null = null;

function percent(part: number, whole: number): string {
	if (whole <= 0) return "0%";
	const p = (part / whole) * 100;
	return p > 0 && p < 0.1 ? "<0.1%" : `${p.toFixed(1)}%`;
}

/** One ranked bar row: label, bar scaled to the largest row, size and share of the binary. */
function buildBarRow(
	label: HTMLElement,
	size: number,
	scaleMax: number,
	binarySize: number,
	muted = false
): HTMLElement {
	const row = el("div", "sz-row");
	row.appendChild(label);

	const track = el("div", "sz-bar-track");
	const bar = el("div", muted ? "sz-bar sz-bar--muted" : "sz-bar");
	bar.style.width = `${scaleMax > 0 ? Math.max((size / scaleMax) * 100, 0.5) : 0}%`;
	track.appendChild(bar);
	row.appendChild(track);

	row.appendChild(el("span", "sz-value", formatSize(size)));
	row.appendChild(el("span", "sz-percent", percent(size, binarySize)));
	row.title = `${size.toLocaleString()} bytes`;
	return row;
}

function buildModuleDetails(mod: SizeModule): HTMLElement {
	const details = el("div", "sz-details");
	if (mod.kind === "unattributed") {
		details.appendChild(
			el(
				"p",
				"sz-note",
				"Section bytes no symbol covers: string and constant pools, stubs, metadata, and " +
					"stripped code whose neighbours belong to different modules."
			)
		);
		return details;
	}

	const facts = el("div", "sz-facts");
	facts.appendChild(el("span", "", `Code ${formatSize(mod.codeSize)}`));
	facts.appendChild(el("span", "", `Data ${formatSize(mod.size - mod.codeSize)}`));
	if (mod.inferredSize > 0) {
		facts.appendChild(el("span", "", `Inferred ${formatSize(mod.inferredSize)}`));
	}
	facts.appendChild(
		el(
			"span",
			"",
			`${mod.symbolCount.toLocaleString()} symbol${mod.symbolCount === 1 ? "" : "s"}`
		)
	);
	details.appendChild(facts);

	if (mod.topFunctions.length > 0) {
		details.appendChild(el("div", "sz-subhead", "Largest functions"));
		const list = el("div", "sz-symbols");
		for (const fn of mod.topFunctions) {
			const row = el("div", "sz-symbol");
			const name = el("span", "sz-symbol-name", fn.name);
			name.title = fn.name;
			row.appendChild(name);
			row.appendChild(el("span", "sz-value", formatSize(fn.size)));
			list.appendChild(row);
		}
		details.appendChild(list);
	}
	return details;
}

function renderModules(container: HTMLElement, data: SizeBreakdown, sessionId: string): void {
	const expanded = getTabState<Set<string>>(sessionId, "size", "expanded") ?? new Set<string>();
	setTabState(sessionId, "size", "expanded", expanded);
	let showAll = getTabState<boolean>(sessionId, "size", "showAll") ?? false;

	const list = el("div", "sz-list");
	container.appendChild(list);
	const scaleMax = data.modules[0]?.size ?? 0;

	const draw = () => {
		list.innerHTML = "";
		const rows = showAll ? data.modules : data.modules.slice(0, INITIAL_MODULE_ROWS);
		for (const mod of rows) {
			const item = el("div", "sz-item");
			const label = el("button", "sz-label sz-label--toggle");
			label.setAttribute("aria-expanded", String(expanded.has(mod.name)));
			label.appendChild(el("span", "sz-caret", expanded.has(mod.name) ? "▾" : "▸"));
			label.appendChild(el("span", "sz-name", mod.name));
			if (mod.kind !== "unattributed") {
				label.appendChild(el("span", "sz-kind", KIND_LABELS[mod.kind]));
			}
			label.addEventListener("click", () => {
				if (expanded.has(mod.name)) expanded.delete(mod.name);
				else expanded.add(mod.name);
				draw();
			});

			item.appendChild(
				buildBarRow(label, mod.size, scaleMax, data.binarySize, mod.kind === "unattributed")
			);
			if (expanded.has(mod.name)) item.appendChild(buildModuleDetails(mod));
			list.appendChild(item);
		}

		if (!showAll && data.modules.length > INITIAL_MODULE_ROWS) {
			const more = el("button", "sz-show-all", `Show all ${data.modules.length} modules`);
			more.addEventListener("click", () => {
				showAll = true;
				setTabState(sessionId, "size", "showAll", true);
				draw();
			});
			list.appendChild(more);
		}
	};
	draw();
}

function renderSections(container: HTMLElement, data: SizeBreakdown): void {
	const list = el("div", "sz-list");
	const segments = [...data.segments]
		.filter((seg) => seg.fileSize > 0)
		.sort((a, b) => b.fileSize - a.fileSize);
	const scaleMax = segments[0]?.fileSize ?? 0;

	for (const seg of segments) {
		const group = el("div", "sz-group");
		const segLabel = el("div", "sz-label");
		segLabel.appendChild(el("span", "sz-name sz-name--segment", seg.name));
		group.appendChild(buildBarRow(segLabel, seg.fileSize, scaleMax, data.binarySize));

		for (const section of seg.sections) {
			if (section.size === 0) continue;
			const label = el("div", "sz-label sz-label--nested");
			label.appendChild(el("span", "sz-name", section.name));
			group.appendChild(buildBarRow(label, section.size, scaleMax, data.binarySize));
		}
		list.appendChild(group);
	}
	container.appendChild(list);
}

async function renderBlocks(container: HTMLElement, sessionId: string): Promise<void> {
	const stage = el("div", "sz-treemap");
	stage.appendChild(el("p", "sz-note", "Measuring bundle\u2026"));
	container.appendChild(stage);
	try {
		const tree = await window.api.getSizeTree(sessionId);
		if (!stage.isConnected) return;
		disposeTreemap = mountTreemap(stage, tree, async (root, chain) => {
			try {
				// Let the button repaint before the (synchronous) render blocks the thread
				await new Promise((resolve) => requestAnimationFrame(() => setTimeout(resolve, 0)));
				const png = await renderTreemapPng(root, chain);
				const saved = await window.api.savePNG(`${root.name}-size`, png);
				if (saved.success) showToast(`Saved ${saved.path}`, "success");
			} catch (err) {
				showToast(
					`PNG export failed: ${err instanceof Error ? err.message : err}`,
					"error"
				);
			}
		});
	} catch (err) {
		stage.innerHTML = "";
		stage.appendChild(
			el("p", "sz-note", `Could not read bundle: ${err instanceof Error ? err.message : err}`)
		);
	}
}

export function renderSize(
	container: HTMLElement,
	data: SizeBreakdown | null,
	sessionId = ""
): void {
	disposeTreemap?.();
	disposeTreemap = null;
	container.innerHTML = "";

	if (!data || data.binarySize === 0) {
		const empty = new EmptyState({
			icon: "\u{1F4CF}",
			message: "No size data available for this binary."
		});
		empty.mount(container);
		return;
	}

	const wrapper = el("div", "sz-wrapper");

	// ── Summary ──
	const summary = el("div", "sz-summary");
	const stat = (label: string, value: string) => {
		const s = el("div", "sz-stat");
		s.appendChild(el("span", "sz-stat-value", value));
		s.appendChild(el("span", "sz-stat-label", label));
		return s;
	};
	summary.appendChild(stat("Binary size", formatSize(data.binarySize)));
	summary.appendChild(
		stat("Attributed to modules", percent(data.attributedSize, data.sectionSize))
	);
	summary.appendChild(
		stat("Modules", String(data.modules.filter((m) => m.kind !== "unattributed").length))
	);
	wrapper.appendChild(summary);

	wrapper.appendChild(
		el(
			"p",
			"sz-note",
			"Sizes are for the selected architecture slice. Module attribution is a heuristic built " +
				"from the symbol table, export trie, ObjC method lists and function starts; stripped " +
				"code that sits between two functions of the same module is counted as inferred."
		)
	);

	// ── View toggle ──
	let view = getTabState<View>(sessionId, "size", "view") ?? "modules";
	const toggle = el("div", "lib-view-toggle");
	const modulesBtn = el("button", "lib-toggle-btn", "Modules");
	const sectionsBtn = el("button", "lib-toggle-btn", "Sections");
	const blocksBtn = el("button", "lib-toggle-btn", "Blocks");
	toggle.appendChild(modulesBtn);
	toggle.appendChild(sectionsBtn);
	toggle.appendChild(blocksBtn);
	wrapper.appendChild(toggle);

	const content = el("div", "sz-content");
	wrapper.appendChild(content);
	container.appendChild(wrapper);

	const show = (next: View) => {
		view = next;
		setTabState(sessionId, "size", "view", next);
		modulesBtn.classList.toggle("lib-toggle-btn--active", next === "modules");
		sectionsBtn.classList.toggle("lib-toggle-btn--active", next === "sections");
		blocksBtn.classList.toggle("lib-toggle-btn--active", next === "blocks");
		disposeTreemap?.();
		disposeTreemap = null;
		content.innerHTML = "";
		if (next === "modules") renderModules(content, data, sessionId);
		else if (next === "sections") renderSections(content, data);
		else void renderBlocks(content, sessionId);
	};
	modulesBtn.addEventListener("click", () => show("modules"));
	sectionsBtn.addEventListener("click", () => show("sections"));
	blocksBtn.addEventListener("click", () => show("blocks"));
	show(view);
}
