import { describe, expect, it } from "bun:test";
import type { AsarEntry } from "../../../shared/types";
import {
	ancestorPaths,
	collectMatchedPaths,
	compilePathMatcher,
	prettyPrintJson
} from "../electron";

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

describe("prettyPrintJson", () => {
	it("indents objects and arrays that parse", () => {
		expect(prettyPrintJson('{"name":"app","version":"1.0.0"}')).toBe(
			'{\n  "name": "app",\n  "version": "1.0.0"\n}'
		);
		expect(prettyPrintJson("[1,2]")).toBe("[\n  1,\n  2\n]");
	});

	it("returns null for non-JSON text and invalid JSON", () => {
		expect(prettyPrintJson("const x = 1;")).toBeNull();
		expect(prettyPrintJson('{"broken":')).toBeNull();
	});
});
