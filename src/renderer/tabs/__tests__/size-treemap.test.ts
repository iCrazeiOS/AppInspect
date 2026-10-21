import { describe, expect, it } from "bun:test";
import type { SizeTreeNode } from "../../../shared/types";
import { squarify } from "../size-treemap";

const leaf = (size: number): SizeTreeNode => ({ name: String(size), size, kind: "file" });

describe("squarify", () => {
	const rect = { x: 10, y: 20, w: 600, h: 400 };
	// The canonical example from Bruls et al.
	const nodes = [6, 6, 4, 3, 2, 2, 1].map(leaf);
	const rects = squarify(nodes, rect);
	const total = nodes.reduce((sum, n) => sum + n.size, 0);

	it("gives every node an area proportional to its size", () => {
		rects.forEach((r, i) => {
			expect(r.w * r.h).toBeCloseTo((nodes[i]!.size / total) * rect.w * rect.h, 6);
		});
	});

	it("tiles the rectangle without overlap or overflow", () => {
		for (const r of rects) {
			expect(r.x).toBeGreaterThanOrEqual(rect.x - 1e-9);
			expect(r.y).toBeGreaterThanOrEqual(rect.y - 1e-9);
			expect(r.x + r.w).toBeLessThanOrEqual(rect.x + rect.w + 1e-9);
			expect(r.y + r.h).toBeLessThanOrEqual(rect.y + rect.h + 1e-9);
		}
		for (let i = 0; i < rects.length; i++) {
			for (let j = i + 1; j < rects.length; j++) {
				const a = rects[i]!;
				const b = rects[j]!;
				const overlapW = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x);
				const overlapH = Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y);
				expect(overlapW <= 1e-9 || overlapH <= 1e-9).toBe(true);
			}
		}
	});

	it("keeps blocks close to square", () => {
		const worst = Math.max(...rects.map((r) => Math.max(r.w / r.h, r.h / r.w)));
		expect(worst).toBeLessThan(3);
	});

	it("returns empty rectangles when there is nothing to lay out", () => {
		expect(squarify([leaf(0)], rect)).toEqual([{ ...rect, w: 0, h: 0 }]);
	});
});
