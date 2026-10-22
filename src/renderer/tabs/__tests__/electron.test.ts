import { describe, expect, it } from "bun:test";
import type { AsarEntry } from "../../../shared/types";
import { ancestorPaths, collectMatchedPaths, compilePathMatcher, fileIcon } from "../electron";

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
		const matches = collectMatchedPaths(entries, (path) => path.includes("renderer"));
		expect(matches).toEqual(new Set(["dist", "dist/renderer.js"]));
	});

	it("keeps intermediate directories for deep matches", () => {
		const matches = collectMatchedPaths(entries, (path) => path.endsWith("index.js"));
		expect(matches).toEqual(
			new Set(["node_modules", "node_modules/pkg", "node_modules/pkg/index.js"])
		);
	});

	it("matches root-level files without adding ancestors", () => {
		const matches = collectMatchedPaths(entries, (path) => path === "package.json");
		expect(matches).toEqual(new Set(["package.json"]));
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
