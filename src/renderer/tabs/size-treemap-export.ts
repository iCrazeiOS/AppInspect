/**
 * Full-size PNG export of the size treemap, with every block labelled.
 *
 * The map is drawn at a fixed large resolution with a header band above each
 * folder and split binary. Leaves whose name fits are labelled in place;
 * the rest get a number that refers to a key printed under the map, so every
 * block is named somewhere in the image.
 */

import type { SizeTreeNode } from "../../shared/types";
import { formatCount, formatSize } from "../utils/format";
import {
	type Block,
	describe,
	excludedSummary,
	layoutAndShade,
	nodeKey,
	ROLE_COLORS,
	ROLE_LABELS,
	type Role,
	roleOf,
	roleTotals
} from "./size-treemap";

const MAP_WIDTH = 6000;
const MAP_HEIGHT = 4000;
const PADDING = 48;
const BAND_HEIGHT = 22;
const MAX_LABEL_FONT = 18;
const MIN_LABEL_FONT = 8;
const MIN_NUMBER_FONT = 6;
const KEY_COLUMNS = 4;
const KEY_ROW_HEIGHT = 22;
/** Chromium's canvas side limit is 32767; stay well clear of it. */
const MAX_CANVAS_HEIGHT = 30000;

const FONT_FAMILY = "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif";
const SURFACE = "#0d1117";
const TEXT = "#e6edf3";
const TEXT_MUTED = "#8b949e";

interface KeyEntry {
	number: number;
	block: Block;
	/** False when the block is too small to show its number */
	marked: boolean;
}

/** Largest font (≤ MAX_LABEL_FONT) at which `text` fits in `w` × `h`, or null. */
function fitFont(ctx: CanvasRenderingContext2D, text: string, w: number, h: number, min: number) {
	for (let size = MAX_LABEL_FONT; size >= min; size--) {
		if (size + 4 > h) continue;
		ctx.font = `${size}px ${FONT_FAMILY}`;
		if (ctx.measureText(text).width <= w - 8) return size;
	}
	return null;
}

function drawShadowedText(
	ctx: CanvasRenderingContext2D,
	text: string,
	x: number,
	y: number,
	size: number,
	alpha = 1
): void {
	ctx.save();
	ctx.font = `${size}px ${FONT_FAMILY}`;
	ctx.fillStyle = "#ffffff";
	ctx.globalAlpha = alpha;
	ctx.shadowColor = "rgba(0, 0, 0, 0.8)";
	ctx.shadowBlur = Math.max(2, size / 5);
	ctx.fillText(text, x, y);
	ctx.restore();
}

function pathOf(block: Block, chain: SizeTreeNode[]): string {
	return [...chain, ...block.ancestors].map((n) => n.name).join(" / ");
}

/**
 * Render `root` (with `chain` naming its ancestors for the title) to a PNG.
 * Resolves to the encoded bytes.
 */
export async function renderTreemapPng(
	root: SizeTreeNode,
	chain: SizeTreeNode[],
	hidden: Set<string> = new Set<string>()
): Promise<Uint8Array> {
	// The exclusion list lives on the tree's top node, which is the chain's first entry when zoomed
	const excludedNote = excludedSummary(chain[0] ?? root);
	const isHidden = (ancestors: SizeTreeNode[], node: SizeTreeNode) =>
		hidden.has(nodeKey([...chain, ...ancestors], node));
	// ── Lay out and shade the map off-screen ──
	const mapCanvas = document.createElement("canvas");
	mapCanvas.width = MAP_WIDTH;
	mapCanvas.height = MAP_HEIGHT;
	const mapCtx = mapCanvas.getContext("2d");
	if (!mapCtx) throw new Error("Canvas unavailable");
	const image = mapCtx.createImageData(MAP_WIDTH, MAP_HEIGHT);
	const { leaves, groups } = layoutAndShade(
		root,
		{ x: 0, y: 0, w: MAP_WIDTH, h: MAP_HEIGHT },
		image,
		BAND_HEIGHT,
		isHidden
	);
	mapCtx.putImageData(image, 0, 0);
	mapCtx.textBaseline = "top";

	// Hairline between leaves so small neighbours stay distinct in print
	mapCtx.strokeStyle = "rgba(0, 0, 0, 0.45)";
	mapCtx.lineWidth = 1;
	for (const leaf of leaves) {
		const { x, y, w, h } = leaf.rect;
		mapCtx.strokeRect(x + 0.5, y + 0.5, w - 1, h - 1);
	}

	// ── Group bands: folder / binary name and size ──
	for (const group of groups) {
		const { x, y, w, h } = group.rect;
		if (!group.band) continue; // too small for a band; its leaves' key entries carry the path
		const label = `${group.node.name}  ${formatSize(group.node.size)}`;
		const size = fitFont(mapCtx, label, w, h, MIN_LABEL_FONT) ?? 12;
		mapCtx.save();
		mapCtx.beginPath();
		mapCtx.rect(x, y, w, h);
		mapCtx.clip();
		mapCtx.font = `600 ${size}px ${FONT_FAMILY}`;
		mapCtx.fillStyle = TEXT;
		mapCtx.fillText(label, x + 6, y + (h - size) / 2);
		mapCtx.restore();
	}

	// ── Leaf labels, or a number into the key ──
	const key: KeyEntry[] = [];
	const ordered = [...leaves].sort((a, b) => b.node.size - a.node.size);
	for (const leaf of ordered) {
		const { x, y, w, h } = leaf.rect;
		const nameSize = fitFont(mapCtx, leaf.node.name, w, h, MIN_LABEL_FONT);
		if (nameSize !== null) {
			drawShadowedText(mapCtx, leaf.node.name, x + 4, y + 3, nameSize);
			const sizeText = formatSize(leaf.node.size);
			const lineHeight = Math.round(nameSize * 1.25);
			if (h >= lineHeight * 2 + 6) {
				mapCtx.font = `${nameSize}px ${FONT_FAMILY}`;
				if (mapCtx.measureText(sizeText).width <= w - 8) {
					drawShadowedText(mapCtx, sizeText, x + 4, y + 3 + lineHeight, nameSize, 0.8);
				}
			}
			continue;
		}
		const number = key.length + 1;
		const numberSize = fitFont(mapCtx, String(number), w, h, MIN_NUMBER_FONT);
		if (numberSize !== null) drawShadowedText(mapCtx, String(number), x + 3, y + 2, numberSize);
		key.push({ number, block: leaf, marked: numberSize !== null });
	}

	// ── Compose the page: title, legend, map, key ──
	const titleHeight = 120;
	const keyHeaderHeight = key.length > 0 ? 70 : 0;
	const keyRows = Math.ceil(key.length / KEY_COLUMNS);
	const width = MAP_WIDTH + PADDING * 2;
	const fullHeight =
		PADDING + titleHeight + MAP_HEIGHT + keyHeaderHeight + keyRows * KEY_ROW_HEIGHT + PADDING;
	const height = Math.min(fullHeight, MAX_CANVAS_HEIGHT);
	const visibleRows = Math.max(
		0,
		Math.floor(
			(height - PADDING * 2 - titleHeight - MAP_HEIGHT - keyHeaderHeight) / KEY_ROW_HEIGHT
		) - (height < fullHeight ? 1 : 0)
	);

	const page = document.createElement("canvas");
	page.width = width;
	page.height = height;
	const ctx = page.getContext("2d");
	if (!ctx) throw new Error("Canvas unavailable");
	ctx.fillStyle = SURFACE;
	ctx.fillRect(0, 0, width, height);
	ctx.textBaseline = "top";

	// Title
	ctx.fillStyle = TEXT;
	ctx.font = `600 40px ${FONT_FAMILY}`;
	ctx.fillText([...chain, root].map((n) => n.name).join(" / "), PADDING, PADDING);
	ctx.fillStyle = TEXT_MUTED;
	ctx.font = `22px ${FONT_FAMILY}`;
	ctx.fillText(
		`${formatSize(root.size)} · ${formatCount(leaves.length, "block")} · exported from AppInspect ${new Date().toISOString().slice(0, 10)}`,
		PADDING,
		PADDING + 52
	);
	if (excludedNote) {
		ctx.font = `18px ${FONT_FAMILY}`;
		ctx.fillText(excludedNote, PADDING, PADDING + 84, MAP_WIDTH / 2);
	}

	// Legend, right-aligned with the title
	const totals = roleTotals(root, { code: 0, mlmodel: 0, file: 0, overhead: 0 }, isHidden);
	ctx.font = `22px ${FONT_FAMILY}`;
	let legendX = width - PADDING;
	for (const role of (Object.keys(ROLE_LABELS) as Role[]).reverse()) {
		if (totals[role] === 0) continue;
		const text = `${ROLE_LABELS[role]}  ${formatSize(totals[role])}`;
		legendX -= ctx.measureText(text).width;
		ctx.fillStyle = TEXT;
		ctx.fillText(text, legendX, PADDING + 56);
		legendX -= 28;
		ctx.fillStyle = `rgb(${ROLE_COLORS[role].join(",")})`;
		ctx.fillRect(legendX, PADDING + 58, 18, 18);
		legendX -= 40;
	}

	const mapY = PADDING + titleHeight;
	ctx.drawImage(mapCanvas, PADDING, mapY);

	// Key
	if (key.length > 0) {
		let keyY = mapY + MAP_HEIGHT + 28;
		ctx.fillStyle = TEXT;
		ctx.font = `600 24px ${FONT_FAMILY}`;
		ctx.fillText("Blocks too small to label", PADDING, keyY);
		keyY += keyHeaderHeight - 28;

		const columnWidth = MAP_WIDTH / KEY_COLUMNS;
		ctx.font = `15px ${FONT_FAMILY}`;
		key.slice(0, visibleRows * KEY_COLUMNS).forEach((entry, i) => {
			const column = Math.floor(i / visibleRows);
			const row = i % visibleRows;
			const x = PADDING + column * columnWidth;
			const y = keyY + row * KEY_ROW_HEIGHT;
			ctx.fillStyle = `rgb(${ROLE_COLORS[roleOf(entry.block.node)].join(",")})`;
			ctx.fillRect(x, y + 3, 12, 12);
			ctx.fillStyle = entry.marked ? TEXT : TEXT_MUTED;
			const sizeText = formatSize(entry.block.node.size);
			const prefix = entry.marked ? `${entry.number}` : `${entry.number} (unmarked)`;
			const line = `${prefix}  ${entry.block.node.name} — ${sizeText} · ${describe(entry.block.node)} · ${pathOf(entry.block, chain)}`;
			ctx.save();
			ctx.beginPath();
			ctx.rect(x, y, columnWidth - 16, KEY_ROW_HEIGHT);
			ctx.clip();
			ctx.fillText(line, x + 20, y + 1);
			ctx.restore();
		});
		const hidden = key.length - visibleRows * KEY_COLUMNS;
		if (hidden > 0) {
			ctx.fillStyle = TEXT_MUTED;
			ctx.fillText(
				`… and ${hidden.toLocaleString()} more (zoom into a folder and export it to see them)`,
				PADDING,
				keyY + visibleRows * KEY_ROW_HEIGHT
			);
		}
	}

	const blob = await new Promise<Blob | null>((resolve) => page.toBlob(resolve, "image/png"));
	if (!blob) throw new Error("PNG encoding failed");
	return new Uint8Array(await blob.arrayBuffer());
}
