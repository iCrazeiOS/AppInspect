import { describe, expect, it } from "bun:test";
import type { SizeTreeNode } from "../../../shared/types";
import { layoutAndShade, nodeKey, roleTotals, squarify } from "../size-treemap";

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

describe("hidden blocks", () => {
	const rect = { x: 0, y: 0, w: 100, h: 100 };
	const a: SizeTreeNode = { name: "a", size: 6, kind: "file" };
	const b: SizeTreeNode = { name: "b", size: 4, kind: "file" };
	const folder: SizeTreeNode = {
		name: "folder",
		size: 10,
		kind: "directory",
		children: [a, b]
	};
	const root: SizeTreeNode = { name: "root", size: 10, kind: "directory", children: [folder] };

	it("keys nodes by their full path from the tree root", () => {
		expect(nodeKey([root, folder], a)).toBe("root\u0000folder\u0000a");
		expect(nodeKey([root, folder], a)).not.toBe(nodeKey([root], folder));
	});

	it("lays out only visible leaves and reflows them to fill the rect", () => {
		const { leaves } = layoutAndShade(root, rect, null, 0, (_anc, node) => node === b);
		expect(leaves).toHaveLength(1);
		expect(leaves[0]!.node).toBe(a);
		expect(leaves[0]!.rect.w * leaves[0]!.rect.h).toBeCloseTo(rect.w * rect.h, 6);
	});

	it("hides the whole subtree when a group is hidden", () => {
		const { leaves } = layoutAndShade(root, rect, null, 0, (_anc, node) => node === folder);
		expect(leaves).toHaveLength(0);
	});

	it("leaves hidden blocks out of role totals", () => {
		const totals = roleTotals(
			root,
			{ code: 0, mlmodel: 0, file: 0, overhead: 0 },
			(_anc, node) => node === b
		);
		expect(totals.file).toBe(6);
	});

	it("leaves a hidden group's whole subtree out of role totals", () => {
		const totals = roleTotals(
			root,
			{ code: 0, mlmodel: 0, file: 0, overhead: 0 },
			(_anc, node) => node === folder
		);
		expect(totals.file).toBe(0);
	});
});
