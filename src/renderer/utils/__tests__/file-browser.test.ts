import { describe, expect, it } from "bun:test";
import type { AsarEntry } from "../../../shared/types";
import {
	ancestorPaths,
	type BrowserTreeNode,
	collectMatchedPaths,
	compilePathMatcher,
	countMatchedFiles,
	countTreeFiles,
	fileIcon,
	findEntry,
	sortTree,
	treeTotals
} from "../file-browser";
import { formatRelativeTime } from "../format";

const file = (path: string): AsarEntry => ({
	name: path.split("/").pop() ?? path,
	path,
	size: 10,
	isDirectory: false
});

const dir = (path: string, children: AsarEntry[]): AsarEntry => ({
	name: path.split("/").pop() ?? path,
	path,
	size: 0,
	isDirectory: true,
	children
});

describe("compilePathMatcher", () => {
	it("matches case-insensitively by default", () => {
		const test = compilePathMatcher("MAIN", false, false);
		expect(test?.("dist/main.js")).toBe(true);
		expect(test?.("dist/renderer.js")).toBe(false);
	});

	it("respects case sensitivity in substring mode", () => {
		const test = compilePathMatcher("MAIN", false, true);
		expect(test?.("dist/main.js")).toBe(false);
		expect(test?.("dist/MAIN.js")).toBe(true);
	});

	it("supports safe regex mode with case-insensitive matching", () => {
		const test = compilePathMatcher("\\.(js|json)$", true, false);
		expect(test?.("dist/MAIN.JS")).toBe(true);
		expect(test?.("dist/main.css")).toBe(false);
	});

	it("returns null for an invalid or unsafe pattern", () => {
		expect(compilePathMatcher("(", true, false)).toBeNull();
		expect(compilePathMatcher("(a+)+$", true, false)).toBeNull();
	});
});

describe("ancestorPaths", () => {
	it("returns every parent directory of a nested file", () => {
		expect(ancestorPaths("a/b/c.js")).toEqual(["a", "a/b"]);
	});

	it("returns nothing for a root-level file", () => {
		expect(ancestorPaths("main.js")).toEqual([]);
	});
});

describe("collectMatchedPaths", () => {
	const entries = [
		dir("dist", [file("dist/main.js"), file("dist/renderer.js")]),
		dir("node_modules", [dir("node_modules/pkg", [file("node_modules/pkg/index.js")])]),
		file("package.json")
	];

	it("keeps matching files and their ancestors", () => {
		const matches = collectMatchedPaths(entries, (entry) => entry.path.includes("renderer"));
		expect(matches).toEqual(new Set(["dist", "dist/renderer.js"]));
	});

	it("keeps intermediate directories for deep matches", () => {
		const matches = collectMatchedPaths(entries, (entry) => entry.path.endsWith("index.js"));
		expect(matches).toEqual(
			new Set(["node_modules", "node_modules/pkg", "node_modules/pkg/index.js"])
		);
	});

	it("matches root-level files without adding ancestors", () => {
		const matches = collectMatchedPaths(entries, (entry) => entry.path === "package.json");
		expect(matches).toEqual(new Set(["package.json"]));
	});

	it("can match on entry names rather than paths", () => {
		const matches = collectMatchedPaths(entries, (entry) => entry.name === "main.js");
		expect(matches).toEqual(new Set(["dist", "dist/main.js"]));
	});
});

describe("countTreeFiles", () => {
	it("counts files recursively and ignores directories", () => {
		const entries = [
			dir("dist", [file("dist/main.js"), file("dist/renderer.js")]),
			dir("node_modules", [dir("node_modules/pkg", [file("node_modules/pkg/index.js")])]),
			file("package.json")
		];
		expect(countTreeFiles(entries)).toBe(4);
	});
});

describe("countMatchedFiles", () => {
	const entries = [
		dir("dist", [file("dist/main.js"), file("dist/renderer.js")]),
		dir("node_modules", [dir("node_modules/pkg", [file("node_modules/pkg/index.js")])]),
		file("package.json")
	];

	it("counts matching files recursively", () => {
		expect(countMatchedFiles(entries, (entry) => entry.path.includes("dist"))).toBe(2);
	});

	it("returns zero when nothing matches", () => {
		expect(countMatchedFiles(entries, () => false)).toBe(0);
	});
});

describe("treeTotals", () => {
	it("sums files and their sizes recursively", () => {
		const entries = [
			dir("dist", [file("dist/main.js"), file("dist/renderer.js")]),
			dir("node_modules", [dir("node_modules/pkg", [file("node_modules/pkg/index.js")])]),
			file("package.json")
		];
		expect(treeTotals(entries)).toEqual({ count: 4, totalSize: 40 });
	});

	it("returns zeroes for an empty tree", () => {
		expect(treeTotals([])).toEqual({ count: 0, totalSize: 0 });
	});
});

describe("findEntry", () => {
	const entries = [
		dir("dist", [file("dist/main.js"), file("dist/renderer.js")]),
		dir("node_modules", [dir("node_modules/pkg", [file("node_modules/pkg/index.js")])]),
		file("package.json")
	];

	it("finds a nested entry", () => {
		expect(findEntry(entries, "node_modules/pkg/index.js")?.size).toBe(10);
	});

	it("finds a root entry", () => {
		expect(findEntry(entries, "package.json")?.name).toBe("package.json");
	});

	it("returns null for a missing path", () => {
		expect(findEntry(entries, "missing.js")).toBeNull();
	});
});

describe("sortTree", () => {
	const node = (
		path: string,
		size: number,
		mtimeMs: number,
		children?: BrowserTreeNode[]
	): BrowserTreeNode => ({
		name: path.split("/").pop() ?? path,
		path,
		size,
		mtimeMs,
		isDirectory: children !== undefined,
		children
	});

	const tree = (): BrowserTreeNode[] => [
		node("z.txt", 10, 400),
		node("Docs", 100, 300, [node("Docs/b.txt", 1, 500), node("Docs/a.txt", 2, 600)]),
		node("a2.txt", 3, 200),
		node("a10.txt", 4, 100)
	];

	it("sorts names A to Z with directories first", () => {
		expect(sortTree(tree(), "name", "asc").map((entry) => entry.name)).toEqual([
			"Docs",
			"a2.txt",
			"a10.txt",
			"z.txt"
		]);
	});

	it("sorts names Z to A but keeps directories first", () => {
		expect(sortTree(tree(), "name", "desc").map((entry) => entry.name)).toEqual([
			"Docs",
			"z.txt",
			"a10.txt",
			"a2.txt"
		]);
	});

	it("sorts by size across files and folders", () => {
		expect(sortTree(tree(), "size", "desc").map((entry) => entry.name)).toEqual([
			"Docs",
			"z.txt",
			"a10.txt",
			"a2.txt"
		]);
		expect(sortTree(tree(), "size", "asc").map((entry) => entry.name)).toEqual([
			"a2.txt",
			"a10.txt",
			"z.txt",
			"Docs"
		]);
	});

	it("sorts by modification time across files and folders", () => {
		expect(sortTree(tree(), "modified", "desc").map((entry) => entry.name)).toEqual([
			"z.txt",
			"Docs",
			"a2.txt",
			"a10.txt"
		]);
		expect(sortTree(tree(), "modified", "asc").map((entry) => entry.name)).toEqual([
			"a10.txt",
			"a2.txt",
			"Docs",
			"z.txt"
		]);
	});

	it("sorts every level of the tree without mutating the input", () => {
		const original = tree();
		const sorted = sortTree(original, "name", "asc");
		expect(sorted[0]?.children?.map((entry) => entry.name)).toEqual(["a.txt", "b.txt"]);
		expect(original[1]?.children?.map((entry) => entry.name)).toEqual(["b.txt", "a.txt"]);
		expect(original.map((entry) => entry.name)).toEqual(["z.txt", "Docs", "a2.txt", "a10.txt"]);
	});

	it("keeps directories first when values tie", () => {
		const entries = [node("b.txt", 5, 1), node("a.txt", 5, 1), node("Dir", 5, 1, [])];
		expect(sortTree(entries, "size", "asc").map((entry) => entry.name)).toEqual([
			"Dir",
			"a.txt",
			"b.txt"
		]);
	});
});

describe("formatRelativeTime", () => {
	const now = Date.UTC(2026, 0, 1);
	const day = 86_400_000;

	it("formats recent timestamps", () => {
		expect(formatRelativeTime(now - 30_000, now)).toBe("just now");
		expect(formatRelativeTime(now - 5 * 60_000, now)).toBe("5m ago");
		expect(formatRelativeTime(now - 3 * 3_600_000, now)).toBe("3h ago");
	});

	it("formats days, weeks, months and years", () => {
		expect(formatRelativeTime(now - 2 * day, now)).toBe("2d ago");
		expect(formatRelativeTime(now - 22 * day, now)).toBe("3w ago");
		expect(formatRelativeTime(now - 65 * day, now)).toBe("2mo ago");
		expect(formatRelativeTime(now - 800 * day, now)).toBe("2y ago");
	});

	it("treats future timestamps as just now", () => {
		expect(formatRelativeTime(now + 5 * day, now)).toBe("just now");
	});
});

describe("fileIcon", () => {
	it("uses a folder icon for directories", () => {
		expect(fileIcon("dist", true)).toBe("\u{1F4C1}");
	});

	it("classifies images by MIME type", () => {
		expect(fileIcon("icon.png", false)).toBe("\u{1F5BC}\u{FE0F}");
		expect(fileIcon("photo.JPEG", false)).toBe("\u{1F5BC}\u{FE0F}");
	});

	it("classifies code and data files", () => {
		expect(fileIcon("main.ts", false)).toBe("\u{1F4DC}");
		expect(fileIcon("Icon.SVG", false)).toBe("\u{1F4DC}");
		expect(fileIcon("package.json", false)).toBe("\u{1F5C2}\u{FE0F}");
		expect(fileIcon("info.plist", false)).toBe("\u{1F5C2}\u{FE0F}");
	});

	it("classifies fonts, archives, media, binaries and docs", () => {
		expect(fileIcon("font.woff2", false)).toBe("\u{1F524}");
		expect(fileIcon("app.asar", false)).toBe("\u{1F4E6}");
		expect(fileIcon("clip.mp4", false)).toBe("\u{1F3B5}");
		expect(fileIcon("native.node", false)).toBe("\u2699\u{FE0F}");
		expect(fileIcon("README.md", false)).toBe("\u{1F4DD}");
	});

	it("falls back to a generic file icon", () => {
		expect(fileIcon("LICENSE", false)).toBe("\u{1F4C4}");
		expect(fileIcon("unknown.xyz", false)).toBe("\u{1F4C4}");
	});
});
