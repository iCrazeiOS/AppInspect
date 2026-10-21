/**
 * Cushion treemap of a bundle's size tree, in the style of Disk Inventory X:
 * squarified layout (Bruls et al.) shaded as van Wijk & van de Wetering
 * cushions, so nesting reads as ridges without drawing borders.
 *
 * Colour encodes role only — code, ML model, other file, binary overhead —
 * because a treemap puts any two categories side by side and only three
 * hues stay distinguishable for every pair (validated all-pairs). Names,
 * languages and sizes live in block labels, the hover tooltip and the legend.
 */

import type { SizeModuleKind, SizeTreeNode } from "../../shared/types";
import { el } from "../utils/dom";
import { formatSize } from "../utils/format";

export interface Rect {
	x: number;
	y: number;
	w: number;
	h: number;
}

/** A laid-out leaf, in device pixels, with its ancestors below the view root. */
export interface Block {
	node: SizeTreeNode;
	rect: Rect;
	ancestors: SizeTreeNode[];
	/** Groups only: `rect` is the header band reserved for the label */
	band?: boolean;
}

export type Role = "code" | "mlmodel" | "file" | "overhead";

/** Dark-surface categorical slots 1–3 plus a neutral for "not a category". */
export const ROLE_COLORS: Record<Role, [number, number, number]> = {
	code: [0x39, 0x87, 0xe5],
	mlmodel: [0xd9, 0x59, 0x26],
	file: [0x19, 0x9e, 0x70],
	overhead: [0x6e, 0x76, 0x81]
};

export const ROLE_LABELS: Record<Role, string> = {
	code: "Code",
	mlmodel: "ML models",
	file: "Other files",
	overhead: "Binary overhead"
};

const MODULE_KIND_LABELS: Record<SizeModuleKind, string> = {
	swift: "Swift module",
	objc: "Objective-C classes",
	cpp: "C++ namespace",
	c: "C library",
	kotlin: "Kotlin package",
	unattributed: "Unattributed"
};

// Cushion parameters (van Wijk): initial ridge height, per-level falloff,
// ambient / diffuse light and a light source up and to the left
const CUSHION_HEIGHT = 0.5;
const CUSHION_FALLOFF = 0.75;
const AMBIENT = 0.16;
const DIFFUSE = 0.84;
const LIGHT = (() => {
	const [x, y, z] = [-1, -2, 10];
	const len = Math.hypot(x, y, z);
	return [x / len, y / len, z / len] as const;
})();

const MIN_LABEL_WIDTH = 64;
const MIN_LABEL_HEIGHT = 18;

export function roleOf(node: SizeTreeNode): Role {
	if (node.kind === "module" || node.kind === "binary") return "code";
	if (node.kind === "mlmodel") return "mlmodel";
	if (node.kind === "overhead") return "overhead";
	return "file";
}

export function describe(node: SizeTreeNode): string {
	switch (node.kind) {
		case "module":
			return node.moduleKind ? MODULE_KIND_LABELS[node.moduleKind] : "Module";
		case "binary":
			return node.children ? "Binary (split into modules)" : "Binary";
		case "mlmodel":
			return "Core ML model";
		case "overhead":
			return "Binary overhead";
		case "directory":
			return "Folder";
		default:
			return "File";
	}
}

// ── Squarified layout ──

/** Worst aspect ratio of a row of areas laid along a side of length `side`. */
function worstRatio(row: number[], side: number): number {
	let sum = 0;
	let max = 0;
	let min = Number.POSITIVE_INFINITY;
	for (const a of row) {
		sum += a;
		if (a > max) max = a;
		if (a < min) min = a;
	}
	const s2 = side * side;
	const sum2 = sum * sum;
	return Math.max((s2 * max) / sum2, sum2 / (s2 * min));
}

/** Lay out `nodes` (sorted by size, descending) to fill `rect`. */
export function squarify(nodes: SizeTreeNode[], rect: Rect): Rect[] {
	const total = nodes.reduce((sum, n) => sum + n.size, 0);
	if (total <= 0 || rect.w <= 0 || rect.h <= 0) return nodes.map(() => ({ ...rect, w: 0, h: 0 }));

	const scale = (rect.w * rect.h) / total;
	const areas = nodes.map((n) => n.size * scale);
	const out: Rect[] = [];
	const free = { ...rect };
	let i = 0;

	while (i < areas.length) {
		const side = Math.min(free.w, free.h);
		const row = [areas[i]!];
		let worst = worstRatio(row, side);
		let j = i + 1;
		while (j < areas.length) {
			row.push(areas[j]!);
			const next = worstRatio(row, side);
			if (next > worst) {
				row.pop();
				break;
			}
			worst = next;
			j++;
		}

		const rowArea = row.reduce((a, b) => a + b, 0);
		const thickness = side > 0 ? rowArea / side : 0;
		if (free.w >= free.h) {
			// Column along the left edge
			let y = free.y;
			for (const a of row) {
				const h = thickness > 0 ? a / thickness : 0;
				out.push({ x: free.x, y, w: thickness, h });
				y += h;
			}
			free.x += thickness;
			free.w -= thickness;
		} else {
			// Row along the top edge
			let x = free.x;
			for (const a of row) {
				const w = thickness > 0 ? a / thickness : 0;
				out.push({ x, y: free.y, w, h: thickness });
				x += w;
			}
			free.y += thickness;
			free.h -= thickness;
		}
		i = j;
	}
	return out;
}

// ── Cushion rendering ──

interface Surface {
	x1: number;
	x2: number;
	y1: number;
	y2: number;
}

function addRidge(s: Surface, rect: Rect, h: number): Surface {
	const next = { ...s };
	if (rect.w > 0) {
		const x2 = rect.x + rect.w;
		next.x1 += (4 * h * (x2 + rect.x)) / rect.w;
		next.x2 -= (4 * h) / rect.w;
	}
	if (rect.h > 0) {
		const y2 = rect.y + rect.h;
		next.y1 += (4 * h * (y2 + rect.y)) / rect.h;
		next.y2 -= (4 * h) / rect.h;
	}
	return next;
}

function shadeLeaf(
	image: ImageData,
	rect: Rect,
	s: Surface,
	color: [number, number, number]
): void {
	const { data, width, height } = image;
	const x0 = Math.max(0, Math.round(rect.x));
	const x1 = Math.min(width, Math.round(rect.x + rect.w));
	const y0 = Math.max(0, Math.round(rect.y));
	const y1 = Math.min(height, Math.round(rect.y + rect.h));
	const [lx, ly, lz] = LIGHT;
	for (let py = y0; py < y1; py++) {
		const ny = -(2 * s.y2 * (py + 0.5) + s.y1);
		for (let px = x0; px < x1; px++) {
			const nx = -(2 * s.x2 * (px + 0.5) + s.x1);
			const cos = (nx * lx + ny * ly + lz) / Math.sqrt(nx * nx + ny * ny + 1);
			const intensity = AMBIENT + DIFFUSE * Math.max(0, cos);
			const o = (py * width + px) * 4;
			data[o] = Math.min(255, color[0] * intensity);
			data[o + 1] = Math.min(255, color[1] * intensity);
			data[o + 2] = Math.min(255, color[2] * intensity);
			data[o + 3] = 255;
		}
	}
}

/** Lay out and collect leaf blocks under `root` (device pixels), shading as we go. */
/** Fill a rectangle of an ImageData with a flat colour. */
function fillImageRect(image: ImageData, rect: Rect, color: [number, number, number]): void {
	const { data, width, height } = image;
	const x0 = Math.max(0, Math.round(rect.x));
	const x1 = Math.min(width, Math.round(rect.x + rect.w));
	const y0 = Math.max(0, Math.round(rect.y));
	const y1 = Math.min(height, Math.round(rect.y + rect.h));
	for (let py = y0; py < y1; py++) {
		for (let px = x0; px < x1; px++) {
			const o = (py * width + px) * 4;
			data[o] = color[0];
			data[o + 1] = color[1];
			data[o + 2] = color[2];
			data[o + 3] = 255;
		}
	}
}

/** Colour of the header band reserved above a group's children (export only). */
const GROUP_BAND_COLOR: [number, number, number] = [0x1c, 0x22, 0x2b];

export interface TreemapLayout {
	leaves: Block[];
	/** Folders and split binaries; `rect` is the header band when bands are reserved. */
	groups: Block[];
}

/**
 * Lay out and collect blocks under `root`, shading leaves into `image`.
 * With `bandHeight` > 0, every group below the root that is big enough gets
 * a header band of that height for its label, and its children fill the rest.
 */
export function layoutAndShade(
	root: SizeTreeNode,
	rect: Rect,
	image: ImageData | null,
	bandHeight = 0
): TreemapLayout {
	const leaves: Block[] = [];
	const groups: Block[] = [];
	const visit = (
		node: SizeTreeNode,
		r: Rect,
		depth: number,
		surface: Surface,
		ancestors: SizeTreeNode[]
	) => {
		if (r.w < 0.5 || r.h < 0.5) return;
		const s = addRidge(surface, r, CUSHION_HEIGHT * CUSHION_FALLOFF ** depth);
		if (!node.children || node.children.length === 0) {
			leaves.push({ node, rect: r, ancestors });
			if (image) shadeLeaf(image, r, s, ROLE_COLORS[roleOf(node)]);
			return;
		}

		let inner = r;
		if (bandHeight > 0 && depth > 0 && r.h > bandHeight * 3 && r.w > bandHeight * 4) {
			const band = { x: r.x, y: r.y, w: r.w, h: bandHeight };
			groups.push({ node, rect: band, ancestors, band: true });
			if (image) fillImageRect(image, band, GROUP_BAND_COLOR);
			inner = { x: r.x, y: r.y + bandHeight, w: r.w, h: r.h - bandHeight };
		} else if (depth > 0) {
			groups.push({ node, rect: r, ancestors });
		}

		const rects = squarify(node.children, inner);
		const chain = [...ancestors, node];
		node.children.forEach((child, i) => {
			visit(child, rects[i]!, depth + 1, s, chain);
		});
	};
	visit(root, rect, 0, { x1: 0, x2: 0, y1: 0, y2: 0 }, []);
	return { leaves, groups };
}

// ── Mount ──

/** Total bytes per role under `node`, for the legend. */
/** "Headers 169.6 KB, Modules 1.2 KB" — what the tree leaves out as not embedded. */
export function excludedSummary(tree: SizeTreeNode): string | null {
	if (!tree.excluded?.length) return null;
	const total = tree.excluded.reduce((sum, e) => sum + e.size, 0);
	const items = tree.excluded.map((e) => `${e.path} ${formatSize(e.size)}`).join(", ");
	return `As embedded in an app \u2014 not counted (${formatSize(total)}): ${items}`;
}

export function roleTotals(node: SizeTreeNode, totals: Record<Role, number>): Record<Role, number> {
	if (!node.children || node.children.length === 0) totals[roleOf(node)] += node.size;
	else for (const child of node.children) roleTotals(child, totals);
	return totals;
}

export function mountTreemap(
	container: HTMLElement,
	tree: SizeTreeNode,
	onExport?: (root: SizeTreeNode, chain: SizeTreeNode[]) => Promise<void>
): () => void {
	container.innerHTML = "";
	let viewRoot = tree;
	let viewChain: SizeTreeNode[] = [];

	const header = el("div", "sz-tm-header");
	const breadcrumb = el("div", "sz-tm-breadcrumb");
	const legend = el("div", "sz-tm-legend");
	header.appendChild(breadcrumb);
	const headerRight = el("div", "sz-tm-header-right");
	headerRight.appendChild(legend);
	if (onExport) {
		const exportBtn = el("button", "sz-show-all sz-tm-export", "Export PNG");
		exportBtn.title = "Save the current view as a full-size, fully labelled PNG";
		exportBtn.addEventListener("click", async () => {
			exportBtn.disabled = true;
			exportBtn.textContent = "Rendering\u2026";
			try {
				await onExport(viewRoot, viewChain);
			} finally {
				exportBtn.disabled = false;
				exportBtn.textContent = "Export PNG";
			}
		});
		headerRight.appendChild(exportBtn);
	}
	header.appendChild(headerRight);
	const excludedNote = excludedSummary(tree);
	container.appendChild(header);
	if (excludedNote) container.appendChild(el("p", "sz-note", excludedNote));

	const stage = el("div", "sz-tm-stage");
	const canvas = el("canvas", "sz-tm-canvas");
	canvas.setAttribute("role", "img");
	const overlay = el("canvas", "sz-tm-overlay");
	const tooltip = el("div", "sz-tm-tooltip hidden");
	stage.appendChild(canvas);
	stage.appendChild(overlay);
	stage.appendChild(tooltip);
	container.appendChild(stage);

	let leaves: Block[] = [];
	let hovered: Block | null = null;
	let dpr = 1;

	const renderLegend = () => {
		legend.innerHTML = "";
		const totals = roleTotals(viewRoot, { code: 0, mlmodel: 0, file: 0, overhead: 0 });
		for (const role of Object.keys(ROLE_LABELS) as Role[]) {
			if (totals[role] === 0) continue;
			const item = el("span", "sz-tm-legend-item");
			const swatch = el("span", "sz-tm-swatch");
			swatch.style.background = `rgb(${ROLE_COLORS[role].join(",")})`;
			item.appendChild(swatch);
			item.appendChild(el("span", "", ROLE_LABELS[role]));
			item.appendChild(el("span", "sz-tm-legend-size", formatSize(totals[role])));
			legend.appendChild(item);
		}
	};

	const renderBreadcrumb = () => {
		breadcrumb.innerHTML = "";
		const chain = [...viewChain, viewRoot];
		chain.forEach((node, i) => {
			if (i > 0) breadcrumb.appendChild(el("span", "sz-tm-sep", "/"));
			const isCurrent = i === chain.length - 1;
			const crumb = el(
				"button",
				isCurrent ? "sz-tm-crumb sz-tm-crumb--current" : "sz-tm-crumb",
				node.name
			);
			crumb.disabled = isCurrent;
			crumb.addEventListener("click", () => zoomTo(chain.slice(0, i), node));
			breadcrumb.appendChild(crumb);
		});
		breadcrumb.appendChild(el("span", "sz-tm-crumb-size", formatSize(viewRoot.size)));
	};

	const drawLabels = (ctx: CanvasRenderingContext2D) => {
		ctx.save();
		ctx.scale(dpr, dpr);
		ctx.font = "11px -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif";
		ctx.textBaseline = "top";
		ctx.fillStyle = "#ffffff";
		ctx.shadowColor = "rgba(0, 0, 0, 0.75)";
		ctx.shadowBlur = 3;
		for (const leaf of leaves) {
			const x = leaf.rect.x / dpr;
			const y = leaf.rect.y / dpr;
			const w = leaf.rect.w / dpr;
			const h = leaf.rect.h / dpr;
			if (w < MIN_LABEL_WIDTH || h < MIN_LABEL_HEIGHT) continue;
			ctx.save();
			ctx.beginPath();
			ctx.rect(x, y, w, h);
			ctx.clip();
			ctx.fillText(leaf.node.name, x + 5, y + 4, w - 10);
			if (h >= MIN_LABEL_HEIGHT * 2) {
				ctx.globalAlpha = 0.8;
				ctx.fillText(formatSize(leaf.node.size), x + 5, y + 18, w - 10);
			}
			ctx.restore();
		}
		ctx.restore();
	};

	const render = () => {
		const { width, height } = stage.getBoundingClientRect();
		if (width === 0 || height === 0) return;
		dpr = window.devicePixelRatio || 1;
		for (const c of [canvas, overlay]) {
			c.width = Math.round(width * dpr);
			c.height = Math.round(height * dpr);
			c.style.width = `${width}px`;
			c.style.height = `${height}px`;
		}
		const ctx = canvas.getContext("2d");
		if (!ctx) return;
		const image = ctx.createImageData(canvas.width, canvas.height);
		leaves = layoutAndShade(
			viewRoot,
			{ x: 0, y: 0, w: canvas.width, h: canvas.height },
			image
		).leaves;
		ctx.putImageData(image, 0, 0);
		drawLabels(ctx);
		canvas.setAttribute(
			"aria-label",
			`Treemap of ${viewRoot.name}, ${formatSize(viewRoot.size)}, ${leaves.length} blocks`
		);
		hovered = null;
		drawHover();
	};

	const drawHover = () => {
		const ctx = overlay.getContext("2d");
		if (!ctx) return;
		ctx.clearRect(0, 0, overlay.width, overlay.height);
		if (!hovered) return;
		const { x, y, w, h } = hovered.rect;
		ctx.lineWidth = 2 * dpr;
		ctx.strokeStyle = "#ffffff";
		ctx.strokeRect(x + dpr, y + dpr, Math.max(0, w - 2 * dpr), Math.max(0, h - 2 * dpr));
	};

	const zoomTo = (chain: SizeTreeNode[], node: SizeTreeNode) => {
		viewChain = chain;
		viewRoot = node;
		renderBreadcrumb();
		renderLegend();
		render();
	};

	const hitTest = (event: MouseEvent): Block | null => {
		const bounds = canvas.getBoundingClientRect();
		const px = (event.clientX - bounds.left) * dpr;
		const py = (event.clientY - bounds.top) * dpr;
		for (const leaf of leaves) {
			const r = leaf.rect;
			if (px >= r.x && px < r.x + r.w && py >= r.y && py < r.y + r.h) return leaf;
		}
		return null;
	};

	canvas.addEventListener("mousemove", (event) => {
		const hit = hitTest(event);
		if (hit !== hovered) {
			hovered = hit;
			drawHover();
		}
		if (!hit) {
			tooltip.classList.add("hidden");
			return;
		}
		const pathNames = [...viewChain, ...hit.ancestors, hit.node].map((n) => n.name);
		tooltip.innerHTML = "";
		tooltip.appendChild(el("div", "sz-tm-tip-name", hit.node.name));
		tooltip.appendChild(el("div", "sz-tm-tip-path", pathNames.slice(0, -1).join(" / ")));
		const facts = el("div", "sz-tm-tip-facts");
		facts.appendChild(el("span", "", formatSize(hit.node.size)));
		facts.appendChild(
			el("span", "", `${((hit.node.size / tree.size) * 100).toFixed(1)}% of ${tree.name}`)
		);
		facts.appendChild(el("span", "", describe(hit.node)));
		tooltip.appendChild(facts);
		tooltip.classList.remove("hidden");

		// Keep the tooltip inside the stage
		const stageBounds = stage.getBoundingClientRect();
		const tipBounds = tooltip.getBoundingClientRect();
		let left = event.clientX - stageBounds.left + 14;
		let top = event.clientY - stageBounds.top + 14;
		if (left + tipBounds.width > stageBounds.width) left -= tipBounds.width + 28;
		if (top + tipBounds.height > stageBounds.height) top -= tipBounds.height + 28;
		tooltip.style.left = `${Math.max(0, left)}px`;
		tooltip.style.top = `${Math.max(0, top)}px`;
	});

	canvas.addEventListener("mouseleave", () => {
		hovered = null;
		drawHover();
		tooltip.classList.add("hidden");
	});

	// Click zooms into the top-level block under the cursor (if it has children)
	canvas.addEventListener("click", (event) => {
		const hit = hitTest(event);
		if (!hit) return;
		const target = hit.ancestors[1] ?? (hit.node.children ? hit.node : null);
		if (target?.children && target !== viewRoot) {
			zoomTo([...viewChain, viewRoot], target);
		}
	});

	let frame = 0;
	const observer = new ResizeObserver(() => {
		cancelAnimationFrame(frame);
		frame = requestAnimationFrame(render);
	});
	observer.observe(stage);

	renderBreadcrumb();
	renderLegend();
	render();

	return () => {
		observer.disconnect();
		cancelAnimationFrame(frame);
	};
}
