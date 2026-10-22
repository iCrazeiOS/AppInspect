import { describe, expect, it } from "bun:test";
import type { LibraryGraphData } from "../../shared/types";
import {
	bigintReplacer,
	buildHexSearchResult,
	buildLibraryGraphResult,
	buildPaginatedResult,
	parseHexPattern,
	sanitize
} from "../format";

describe("sanitize", () => {
	it("converts safe BigInts to numbers and unsafe ones to strings", () => {
		const out = sanitize({ a: 5n, b: 2n ** 70n });
		expect(out).toEqual({ a: 5, b: (2n ** 70n).toString() } as never);
		expect(bigintReplacer("k", 1n)).toBe(1);
	});
});

describe("buildPaginatedResult", () => {
	const symbols = [{ name: "alpha" }, { name: "Beta" }, { name: "alphabet" }];

	it("filters case-insensitively and paginates", () => {
		const r = buildPaginatedResult(symbols, "symbols", "ALPHA", 1, 1) as {
			total: number;
			returned: number;
			data: { name: string }[];
		};
		expect(r.total).toBe(2);
		expect(r.returned).toBe(1);
		expect(r.data[0]?.name).toBe("alphabet");
	});
});

describe("parseHexPattern", () => {
	it("parses spaced hex", () => {
		expect(parseHexPattern("de ad")).toEqual([0xde, 0xad]);
	});
	it("parses unspaced hex", () => {
		expect(parseHexPattern("deadbeef")).toEqual([0xde, 0xad, 0xbe, 0xef]);
	});
	it("parses text: patterns as UTF-8", () => {
		expect(parseHexPattern("text:Hi")).toEqual([0x48, 0x69]);
	});
	it("rejects an odd digit count", () => {
		expect(() => parseHexPattern("abc")).toThrow("odd");
	});
	it("rejects non-hex text without the prefix", () => {
		expect(() => parseHexPattern("hello")).toThrow("non-hex");
	});
	it("rejects empty patterns", () => {
		expect(() => parseHexPattern("")).toThrow("empty");
		expect(() => parseHexPattern("text:")).toThrow("empty");
	});
	it("rejects patterns over 256 bytes", () => {
		expect(() => parseHexPattern("00".repeat(257))).toThrow("256");
		expect(parseHexPattern("00".repeat(256))).toHaveLength(256);
	});
});

describe("buildHexSearchResult", () => {
	it("reports truncation when the match cap is hit", () => {
		const bin = { index: 0, name: "App" };
		expect(buildHexSearchResult(bin, 0, 10, [0xde], [1, 2], 2).truncated).toBe(true);
		const r = buildHexSearchResult(bin, 0, 10, [0xde, 0xad], [1], 2);
		expect(r).toMatchObject({ pattern: "dead", matchCount: 1, truncated: false });
	});
});

describe("buildLibraryGraphResult", () => {
	const graph: LibraryGraphData = {
		nodes: [
			{ id: "app", label: "App", type: "binary", binaryType: "main" },
			{ id: "fw", label: "Fw", type: "binary", binaryType: "framework" },
			{
				id: "/usr/lib/libSystem.B.dylib",
				label: "libSystem",
				type: "library",
				category: "system"
			},
			{ id: "Fw.framework/Fw", label: "Fw", type: "library", category: "framework" }
		],
		edges: [
			{ source: "app", target: "/usr/lib/libSystem.B.dylib", weak: false },
			{ source: "app", target: "fw", weak: false },
			{ source: "fw", target: "Fw.framework/Fw", weak: true }
		]
	};

	it("returns everything without a category", () => {
		const r = buildLibraryGraphResult(graph);
		expect(r).toMatchObject({ nodeCount: 4, edgeCount: 3 });
	});

	it("keeps matching nodes, touching edges and their endpoints", () => {
		const r = buildLibraryGraphResult(graph, "system");
		expect(r.edges).toEqual([
			{ source: "app", target: "/usr/lib/libSystem.B.dylib", weak: false }
		]);
		expect(r.nodes.map((n) => n.id).sort()).toEqual(["/usr/lib/libSystem.B.dylib", "app"]);
	});

	it("returns an empty graph when nothing matches", () => {
		const r = buildLibraryGraphResult(graph, "swift");
		expect(r).toEqual({ nodeCount: 0, edgeCount: 0, nodes: [], edges: [] });
	});

	it("handles an empty graph", () => {
		expect(buildLibraryGraphResult({ nodes: [], edges: [] }, "system").nodes).toEqual([]);
	});
});
